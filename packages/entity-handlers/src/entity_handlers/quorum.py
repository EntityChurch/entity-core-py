"""EXTENSION-QUORUM v1.1 — K-of-N node primitive.

Defines the K-of-N node entity (`system/quorum`) plus the validators
(`verify_k_of_n_signatures`, `current_signer_set`, `is_quorum_id`),
quorum self-event conventions (`quorum-update`, `quorum-publish` as
`system/attestation` entities), and the pluggable signer-resolution hook.

The `concrete` resolver is built in. Other extensions (notably
EXTENSION-IDENTITY's `identity-resolved` mode) register additional modes
at install time via `QuorumExtension.register_resolver`.

v1.1 absorbs cross-impl-feedback batch
(`PROPOSAL-IDENTITY-V3.2-MIGRATION-FIXES.md`):
- SI-6: cache-invalidation Mechanism A (sync-hook on emit_pathway fires
  on writes to system/quorum/*/event/*; validates inline; invalidates
  cache on success; leaves untouched on failure).
- SI-7/SI-22: path-as-resource MUST on `:create` / `:update` / `:publish`.
- SI-12: superseding `:publish` validated against prior publish's
  `properties.signers` snapshot, not `current_signer_set`-resolved.
- SI-15: validate-once-on-arrival trust model.
- SI-16: `current_signer_set` and resolver hook take optional `as_of`
  for full historical-state resolution.
- SI-17 / V7 PR-2: `IdentityResolver` → `PeerResolver` (`make_peer_resolver`).
- IDENTITY-2: `MAX_RESOLVER_DEPTH = 8`; `IdentityResolverMaxDepthExceeded`
  + `IdentityResolverCycle` errors for recursive-resolver chains.

Three-parallel-mechanisms invariant (§10 v1.1): cap-chain verification
MAY read attestation state via the `IdentityBindingChecker` hook
(read-only); cap-chain verification MUST NOT validate attestations as
caps. Quorum validation MUST NOT call `verify_capability_chain`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable

from entity_core.capability.delegation import find_signature_by_signer
from entity_core.handlers.context import HandlerContext
from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_handlers._common import (
    error_response as _error,
    normalize_hash as _normalize_hash,
    ok_response as _ok,
    params_data as _params_data,
    resource_target as _resource_target,
)
from entity_handlers.attestation import (
    ATTESTATION_TYPE,
    _verify_one_signature,
    collect_signatures_for,
    find_attestations_targeting,
    find_live_head,
    make_attestation,
    make_peer_resolver,
)

logger = logging.getLogger(__name__)


# -- Constants --------------------------------------------------------------

QUORUM_TYPE = "system/quorum"
QUORUM_HANDLER_PATTERN = "system/quorum"
QUORUM_ROOT = "system/quorum"
EVENT_SEGMENT = "event"

# Kinds owned by this extension (per ATTESTATION §3.2 ownership table).
KIND_QUORUM_UPDATE = "quorum-update"
KIND_QUORUM_PUBLISH = "quorum-publish"

# Built-in resolver-mode identifier (§5.1).
RESOLUTION_CONCRETE = "concrete"

# Resolver recursion bound per QUORUM §5.2 v1.1 (IDENTITY-2). Resolvers
# that recurse into other identity-resolved quorums MUST track depth
# and visited refs; on exceed return identity_resolver_max_depth_exceeded;
# on cycle return identity_resolver_cycle.
MAX_RESOLVER_DEPTH = 8

# Operations
_OP_CREATE = "create"
_OP_UPDATE = "update"
_OP_PUBLISH = "publish"
_OP_VERIFY = "verify"


# -- Type aliases -----------------------------------------------------------

# Resolver: given a signers[i] hash + ctx, optionally an as_of timestamp,
# returns the peer-identity hash (or list of acceptable hashes) that
# should sign K-of-N at that point in time. The built-in `concrete`
# resolver returns the input unchanged. Per §5.2 v1.1 a resolver MUST
# be deterministic, side-effect free, and honor `as_of` when provided.
ResolverFn = Callable[..., "bytes | list[bytes] | None"]


# =============================================================================
# Hash / path helpers
# =============================================================================


def encode_hash_segment(h: bytes) -> str:
    """Lowercase hex of full system/hash bytes (§7)."""
    return h.hex()


def quorum_entity_path(quorum_id: bytes) -> str:
    """Storage path for a quorum entity (§7)."""
    return f"{QUORUM_ROOT}/{encode_hash_segment(quorum_id)}"


def quorum_event_path(quorum_id: bytes, event_hash: bytes) -> str:
    """Storage path for a quorum-update / quorum-publish attestation (§7)."""
    return (
        f"{QUORUM_ROOT}/{encode_hash_segment(quorum_id)}/"
        f"{EVENT_SEGMENT}/{encode_hash_segment(event_hash)}"
    )


# =============================================================================
# QuorumExtension — per-peer state for resolvers + signer-set cache
# =============================================================================


class _QuorumEventHook:
    """Internal sync hook that fires on writes to `system/quorum/*/event/*`.
    Implements §4.2.1 Mechanism A: validate K-of-N inline + invalidate
    cache on success; leave cache untouched on validation failure."""

    def __init__(self, extension: "QuorumExtension") -> None:
        self._extension = extension

    def on_change_sync(self, event) -> int | None:
        # Filter: must be a system/attestation under a quorum event path.
        entity = event.entity
        if entity is None or entity.type != ATTESTATION_TYPE:
            return None
        props = entity.data.get("properties") or {}
        kind = props.get("kind")
        if kind not in (KIND_QUORUM_UPDATE, KIND_QUORUM_PUBLISH):
            return None
        # Path shape check: .../system/quorum/{q_hex}/event/{h_hex}
        if "/system/quorum/" not in event.uri or "/event/" not in event.uri:
            return None
        # Validate via process_quorum_attestation. Build a context-shape
        # carrier good enough for the validator (it only needs
        # emit_pathway).
        ctx = _HookCtx(self._extension._emit_pathway)
        try:
            process_quorum_attestation(entity, ctx)
        except Exception:
            # Validation failures from missing prerequisites (signatures
            # not yet present, predecessor missing) are non-fatal at
            # the hook layer — cache stays untouched per §4.2.1
            # NON-trigger #1.
            pass
        return None


class _HookCtx:
    """Minimal HandlerContext shim for hook-driven validation.
    Carries only the emit_pathway used by validators."""

    def __init__(self, emit_pathway) -> None:
        self.emit_pathway = emit_pathway


class QuorumExtension(Extension):
    """Per-peer resolver registry + `current_signer_set` cache.

    The extension is the seam through which other extensions (identity,
    group, cluster) register signer-resolution modes. The built-in
    `concrete` mode is installed during initialize.

    Cache invalidation contract (§4.2.1, v1.1):
    - Local `:update`/`:publish` op completion → invalidate.
    - Validated attestation arrival (any source — sync, envelope.included,
      L0 bootstrap, local op) → invalidate via the internal sync hook
      installed on `emit_pathway` (§4.2.1 Mechanism A).
    - Failed validation, raw tree:put bypass without K-of-N → MUST NOT
      invalidate. The hook validates inline; failures leave cache
      untouched.
    """

    def __init__(self) -> None:
        self._resolvers: dict[str, ResolverFn] = {}
        self._cache: dict[bytes, tuple[list[bytes], int, str]] = {}
        self._emit_pathway = None
        self._installed = False
        self._event_hook = None

    # --- Extension lifecycle ---

    def initialize(self, ctx: ExtensionContext) -> None:
        self._emit_pathway = ctx.emit_pathway
        self._resolvers[RESOLUTION_CONCRETE] = _concrete_resolver
        if ctx.emit_pathway is not None:
            # Surface this extension on the emit_pathway so other
            # extensions (identity in phase 3, plus standalone helpers)
            # can find it without changing HandlerContext.
            ctx.emit_pathway._quorum_extension = self  # type: ignore[attr-defined]
            # Install the §4.2.1 cache-invalidation sync hook.
            self._event_hook = _QuorumEventHook(self)
            ctx.emit_pathway._add_internal_hook(  # type: ignore[attr-defined]
                self._event_hook, pattern=None, name="quorum/cache-invalidation",
            )
        self._installed = True
        logger.info("QuorumExtension initialized (concrete resolver + sync hook)")

    def shutdown(self) -> None:
        self._cache.clear()
        if self._emit_pathway is not None:
            try:
                if self._event_hook is not None:
                    self._emit_pathway._remove_internal_hook(self._event_hook)
                delattr(self._emit_pathway, "_quorum_extension")
            except AttributeError:
                pass

    # --- Resolver registration (§5.2) ---

    def register_resolver(self, mode_name: str, resolver: ResolverFn) -> None:
        """Register a signer-resolution mode. `mode_name` becomes a valid
        value for `system/quorum.signer_resolution`. Resolver MUST be
        deterministic and side-effect-free.

        Per V7 PR-6 (substrate cleanup): registering a `mode_name` that is
        already taken raises `ResolverAlreadyRegistered`. Re-registering the
        SAME callable is permitted (no-op) to support hot-reload scenarios.
        Replacement of a handler with a different one requires explicit
        unregistration first; no `unregister_resolver` op is exposed in v2
        (no current consumer needs it).
        """
        if not isinstance(mode_name, str) or not mode_name:
            raise ValueError("mode_name must be a non-empty string")
        existing = self._resolvers.get(mode_name)
        if existing is not None and existing is not resolver:
            raise ResolverAlreadyRegistered(mode_name)
        self._resolvers[mode_name] = resolver

    def lookup_resolver(self, mode_name: str) -> ResolverFn | None:
        """Return the registered resolver for `mode_name`, or None.
        `concrete` is built in; absent strings return None (caller fails
        closed per §5.3.1)."""
        return self._resolvers.get(mode_name)

    def available_modes(self) -> list[str]:
        """Sorted list of currently-registered mode names."""
        return sorted(self._resolvers.keys())

    # --- Cache management (§4.2.1) ---

    def invalidate(self, quorum_id: bytes) -> None:
        """Drop the cached `current_signer_set` for `quorum_id`."""
        self._cache.pop(quorum_id, None)

    def cache_lookup(
        self, quorum_id: bytes,
    ) -> tuple[list[bytes], int, str] | None:
        return self._cache.get(quorum_id)

    def cache_store(
        self, quorum_id: bytes, signers: list[bytes], threshold: int, mode: str,
    ) -> None:
        self._cache[quorum_id] = (list(signers), threshold, mode)


def _concrete_resolver(
    signer: bytes, _ctx: HandlerContext,
    as_of: int | None = None, **_kwargs,
) -> bytes | list[bytes] | None:
    """The built-in `concrete` mode (§5.1): each signer entry is itself
    the peer-identity hash. The resolver returns the input unchanged.
    `as_of` is unused (concrete signers don't shift over time).
    Accepts extra kwargs to be compatible with the IDENTITY-2 depth/visited
    threading contract."""
    return signer


def get_quorum_extension(ctx: HandlerContext) -> QuorumExtension | None:
    """Look up the peer-installed QuorumExtension via the emit_pathway,
    or None when not installed (only `concrete` mode is available in that
    case, and no caching)."""
    pathway = getattr(ctx, "emit_pathway", None)
    if pathway is None:
        return None
    return getattr(pathway, "_quorum_extension", None)


# =============================================================================
# Quorum identification (§4.3)
# =============================================================================


def is_quorum_id(hash_value: bytes, ctx: HandlerContext) -> bool:
    """Per §4.3: True iff `hash_value` refers to a `system/quorum`
    entity bound at the canonical path `system/quorum/{hex(hash)}` in
    the local tree.

    Stateless — re-evaluates on each call so bootstrap / sync race cases
    self-resolve once the quorum entity is written.
    """
    if not isinstance(hash_value, bytes) or len(hash_value) == 0:
        return False
    full = ctx.emit_pathway.entity_tree.normalize_uri(
        quorum_entity_path(hash_value),
    )
    bound = ctx.emit_pathway.entity_tree.get(full)
    if bound is None or bound != hash_value:
        return False
    entity = ctx.emit_pathway.content_store.get(bound)
    if entity is None or entity.type != QUORUM_TYPE:
        return False
    return True


# =============================================================================
# Quorum entity lookup
# =============================================================================


def _resolve_quorum_entity(
    quorum_id: bytes, ctx: HandlerContext,
) -> Entity | None:
    full = ctx.emit_pathway.entity_tree.normalize_uri(
        quorum_entity_path(quorum_id),
    )
    bound = ctx.emit_pathway.entity_tree.get(full)
    if bound is None or bound != quorum_id:
        return None
    entity = ctx.emit_pathway.content_store.get(bound)
    if entity is None or entity.type != QUORUM_TYPE:
        return None
    return entity


# =============================================================================
# current_signer_set (§4.2)
# =============================================================================


class QuorumResolverUnavailable(Exception):
    """Raised by `current_signer_set` / `verify_k_of_n_signatures` when
    the quorum specifies a `signer_resolution` mode that is not
    registered (cases C2/C3/C4 per §5.3.1).

    Carries the spec's required diagnostic fields: `quorum_id`,
    `mode_name`, `available_modes`.
    """

    def __init__(
        self, quorum_id: bytes, mode_name: str, available_modes: list[str],
    ) -> None:
        super().__init__(
            f"quorum_resolver_unavailable: mode={mode_name!r} "
            f"available={available_modes!r}",
        )
        self.quorum_id = quorum_id
        self.mode_name = mode_name
        self.available_modes = available_modes


class IdentityResolverMaxDepthExceeded(Exception):
    """Raised when a resolver chain exceeds MAX_RESOLVER_DEPTH (IDENTITY-2)."""

    def __init__(self, depth: int) -> None:
        super().__init__(
            f"identity_resolver_max_depth_exceeded: depth={depth} "
            f"exceeds {MAX_RESOLVER_DEPTH}",
        )
        self.depth = depth


class IdentityResolverCycle(Exception):
    """Raised when a resolver chain revisits an identity reference
    within a single resolution invocation (IDENTITY-2)."""

    def __init__(self, ref: bytes) -> None:
        super().__init__(f"identity_resolver_cycle: ref={ref.hex()[:16]}…")
        self.ref = ref


class ResolverAlreadyRegistered(Exception):
    """Raised by `QuorumExtension.register_resolver` when the given
    `mode_name` is already taken by a different callable (V7 PR-6).

    Replacing a registered handler requires explicit unregistration; v2
    does not expose `unregister_resolver`. Re-registering the same
    callable is permitted as a no-op.
    """

    def __init__(self, mode_name: str) -> None:
        super().__init__(f"resolver_already_registered: mode={mode_name!r}")
        self.mode_name = mode_name
        self.code = "resolver_already_registered"


def _walk_live_quorum_update_head(
    quorum_id: bytes, ctx: HandlerContext,
    *, as_of: int | None = None,
) -> Entity | None:
    """Find the live quorum-update head for `quorum_id` at `as_of` (per
    §4.2 v1.1)."""
    candidates = find_attestations_targeting(
        quorum_id,
        lambda a, _c: (a.data.get("properties") or {}).get("kind") == KIND_QUORUM_UPDATE,
        ctx,
    )
    if not candidates:
        return None
    # Each chain's head at as_of; take the one whose live-head is itself.
    head: Entity | None = None
    for c in candidates:
        h = find_live_head(c, ctx, as_of=as_of)
        if h is None:
            continue
        if head is None or h.compute_hash() < head.compute_hash():
            head = h
    return head


def current_signer_set(
    quorum_id: bytes,
    ctx: HandlerContext,
    *,
    as_of: int | None = None,
    _depth: int = 0,
    _visited: frozenset[bytes] | None = None,
) -> tuple[list[bytes], int, str]:
    """Per §4.2 v1.1 (SI-16): walk the `quorum-update` chain to determine
    the effective `(signers, threshold, signer_resolution_mode)` AT
    the `as_of` timestamp. When `as_of` is None, returns the current
    state at the current time.

    Raises `QuorumResolverUnavailable` per §5.3.1 when the quorum's
    declared `signer_resolution` mode has no registered resolver.
    Raises `IdentityResolverMaxDepthExceeded` per §5.2 v1.1 (IDENTITY-2)
    when a recursive resolver chain exceeds `MAX_RESOLVER_DEPTH`.
    Raises `IdentityResolverCycle` when a quorum_id is revisited within
    a single resolution invocation.

    Cached per `quorum_id` per §4.2.1 when a QuorumExtension is
    installed AND `as_of` is None AND _depth is 0. Historical-state and
    nested resolution bypass the cache.
    """
    if _depth >= MAX_RESOLVER_DEPTH:
        raise IdentityResolverMaxDepthExceeded(_depth)
    visited = _visited or frozenset()
    if quorum_id in visited:
        raise IdentityResolverCycle(quorum_id)
    visited = visited | {quorum_id}

    ext = get_quorum_extension(ctx)
    if ext is not None and as_of is None and _depth == 0:
        cached = ext.cache_lookup(quorum_id)
        if cached is not None:
            return (list(cached[0]), cached[1], cached[2])

    quorum = _resolve_quorum_entity(quorum_id, ctx)
    if quorum is None:
        raise LookupError(f"quorum_not_found: {encode_hash_segment(quorum_id)}")

    base_signers_raw = quorum.data.get("signers") or []
    base_signers = [
        s for s in (_normalize_hash(x) for x in base_signers_raw) if s is not None
    ]
    base_threshold = quorum.data.get("threshold")
    if not isinstance(base_threshold, int) or base_threshold <= 0:
        raise ValueError(f"quorum_invalid: threshold {base_threshold!r}")
    mode = quorum.data.get("signer_resolution") or RESOLUTION_CONCRETE

    head = _walk_live_quorum_update_head(quorum_id, ctx, as_of=as_of)
    if head is not None:
        props = head.data.get("properties") or {}
        update_signers_raw = props.get("new_signers") or []
        update_signers = [
            s for s in (_normalize_hash(x) for x in update_signers_raw)
            if s is not None
        ]
        update_threshold = props.get("new_threshold")
        if (
            update_signers
            and isinstance(update_threshold, int)
            and update_threshold > 0
        ):
            base_signers = update_signers
            base_threshold = update_threshold

    # Resolver-mode dispatch (fail-closed for unknown modes per §5.3.1).
    if ext is None:
        if mode != RESOLUTION_CONCRETE:
            raise QuorumResolverUnavailable(
                quorum_id, mode, [RESOLUTION_CONCRETE],
            )
        # No extension installed — concrete is implicit; no resolver
        # call needed (signers pass through unchanged).
        result = (list(base_signers), base_threshold, mode)
        return result

    resolver = ext.lookup_resolver(mode)
    if resolver is None:
        raise QuorumResolverUnavailable(
            quorum_id, mode, ext.available_modes(),
        )

    # Resolution: each signer entry passes through `resolver` with
    # `as_of` so historical-state queries see the right peer.
    # Per IDENTITY-2: depth + visited propagate via kwargs so resolvers
    # that recurse into current_signer_set can trip the bound.
    resolved: list[bytes | list[bytes]] = []
    for s in base_signers:
        kwargs: dict[str, Any] = {}
        if as_of is not None:
            kwargs["as_of"] = as_of
        kwargs["_depth"] = _depth + 1
        kwargs["_visited"] = visited
        try:
            out = resolver(s, ctx, **kwargs)
        except TypeError:
            # Resolver doesn't accept depth/visited kwargs (e.g.,
            # `concrete` resolver). Fall back to the simple signature.
            out = resolver(s, ctx, as_of=as_of) if as_of is not None else resolver(s, ctx)
        if out is None:
            resolved.append(s)
        elif isinstance(out, bytes):
            resolved.append(out)
        elif isinstance(out, list):
            resolved.append(
                [b for b in out if isinstance(b, bytes)],
            )
        else:
            resolved.append(s)

    flat = [r if isinstance(r, bytes) else b"" for r in resolved]
    # Only cache when as_of is None AND we're at the top of the
    # resolution stack. Historical queries and nested resolution bypass
    # the cache to avoid polluting it with stale or partial state.
    if as_of is None and _depth == 0:
        ext.cache_store(quorum_id, flat, base_threshold, mode)
    return (flat, base_threshold, mode)


# =============================================================================
# verify_k_of_n_signatures (§4.1)
# =============================================================================


def verify_k_of_n_signatures(
    entity_hash: bytes,
    signer_set: list[bytes],
    threshold: int,
    ctx: HandlerContext,
    *,
    included: list[dict[str, Any]] | dict[bytes, dict[str, Any]] | None = None,
    resolver: ResolverFn | None = None,
) -> bool:
    """Per §4.1: K-of-N signature validation over `entity_hash`.

    For each candidate in `signer_set`, locate a matching `system/signature`
    entity and Ed25519-verify it. Returns True once `threshold` distinct
    valid signatures are accumulated.

    `signer_set` is the post-resolution flat list (concrete hashes); for
    pluggable resolution modes that expand one slot to multiple
    acceptable peers, callers pass `resolver` and the raw signer list,
    and we per-slot try every resolved candidate.
    """
    if threshold <= 0:
        return True
    if included is None:
        included = collect_signatures_for(ctx, entity_hash)
    identity_resolver = make_peer_resolver(ctx)

    seen: set[bytes] = set()
    signed: set[bytes] = set()

    for candidate in signer_set:
        slot_keys: list[bytes]
        if resolver is None:
            slot_keys = [candidate] if isinstance(candidate, bytes) and candidate else []
        else:
            out = resolver(candidate, ctx)
            if out is None:
                slot_keys = []
            elif isinstance(out, bytes):
                slot_keys = [out]
            elif isinstance(out, list):
                slot_keys = [b for b in out if isinstance(b, bytes)]
            else:
                slot_keys = []
        if not slot_keys:
            continue

        # Slot satisfied if any single resolved key signed; key-level
        # dedupe against `seen` prevents double-counting one peer
        # across two slots.
        slot_signed = False
        for key in slot_keys:
            if key in seen:
                continue
            sig = find_signature_by_signer(entity_hash, key, included)
            if sig is None:
                continue
            id_data = identity_resolver(key)
            if id_data is None:
                continue
            if _verify_one_signature(entity_hash, key, sig, id_data):
                seen.add(key)
                signed.add(key)
                slot_signed = True
                break
        if slot_signed and len(signed) >= threshold:
            return True

    return len(signed) >= threshold


# =============================================================================
# Quorum-attestation processing (§4.2.1 cache-invalidation point)
# =============================================================================


def process_quorum_attestation(
    att: Entity,
    ctx: HandlerContext,
) -> bool:
    """Validate a `quorum-update` or `quorum-publish` attestation and,
    on accept, invalidate the cache for the affected quorum.

    Per §4.2.1 cache contract: invalidation MUST happen on validate-
    accept, not on raw tree-write. This helper is the one accept point
    callers (consumers like identity, or a future cross-extension
    process_attestation) drive after a quorum-relevant attestation
    arrives.

    Returns True on accept, False on rejection. Does NOT re-bind the
    entity — the entity is already at its tree path; this is the
    semantic accept gate.
    """
    if att.type != ATTESTATION_TYPE:
        return False
    props = att.data.get("properties") or {}
    kind = props.get("kind")
    if kind not in (KIND_QUORUM_UPDATE, KIND_QUORUM_PUBLISH):
        return False

    quorum_id = _normalize_hash(att.data.get("attesting"))
    if quorum_id is None:
        return False
    attested = _normalize_hash(att.data.get("attested"))
    if attested != quorum_id:
        return False  # quorum self-events are self-attestations

    if kind == KIND_QUORUM_UPDATE:
        valid = _validate_quorum_update(att, ctx)
    else:
        valid = _validate_quorum_publish(att, ctx)
    if not valid:
        return False

    ext = get_quorum_extension(ctx)
    if ext is not None:
        ext.invalidate(quorum_id)
    return True


def _validate_quorum_update(att: Entity, ctx: HandlerContext) -> bool:
    """K-of-N from current effective signer set per §3.2."""
    quorum_id = _normalize_hash(att.data.get("attesting"))
    if quorum_id is None:
        return False
    try:
        signers, threshold, mode = current_signer_set(quorum_id, ctx)
    except (QuorumResolverUnavailable, LookupError, ValueError):
        return False
    ext = get_quorum_extension(ctx)
    resolver = ext.lookup_resolver(mode) if ext is not None else (
        _concrete_resolver if mode == RESOLUTION_CONCRETE else None
    )
    if resolver is None:
        return False
    return verify_k_of_n_signatures(
        att.compute_hash(), signers, threshold, ctx, resolver=resolver,
    )


def _validate_quorum_publish(att: Entity, ctx: HandlerContext) -> bool:
    """Per §3.3: initial publish K-of-N by current signer set;
    superseding publish K-of-N by PREVIOUS signer set."""
    quorum_id = _normalize_hash(att.data.get("attesting"))
    if quorum_id is None:
        return False
    supersedes = _normalize_hash(att.data.get("supersedes"))
    if supersedes is None:
        # Initial publish — signers is current effective set.
        try:
            signers, threshold, mode = current_signer_set(quorum_id, ctx)
        except (QuorumResolverUnavailable, LookupError, ValueError):
            return False
    else:
        # Superseding publish — must validate against the PREVIOUS
        # publish's snapshot, which is captured in `supersedes`'s own
        # `properties.signers` and `.threshold`.
        prev = ctx.emit_pathway.content_store.get(supersedes)
        if prev is None or prev.type != ATTESTATION_TYPE:
            return False
        prev_props = prev.data.get("properties") or {}
        if prev_props.get("kind") != KIND_QUORUM_PUBLISH:
            return False
        signers_raw = prev_props.get("signers") or []
        signers = [
            s for s in (_normalize_hash(x) for x in signers_raw) if s is not None
        ]
        threshold = prev_props.get("threshold")
        mode = RESOLUTION_CONCRETE  # cached snapshot is already concrete
        if not signers or not isinstance(threshold, int) or threshold <= 0:
            return False

    ext = get_quorum_extension(ctx)
    resolver = ext.lookup_resolver(mode) if ext is not None else (
        _concrete_resolver if mode == RESOLUTION_CONCRETE else None
    )
    if resolver is None:
        return False
    return verify_k_of_n_signatures(
        att.compute_hash(), signers, threshold, ctx, resolver=resolver,
    )


def _require_path_matches(
    ctx: HandlerContext, expected_path: str,
) -> dict[str, Any] | None:
    """Per SI-7/SI-22: substrate ops MUST receive a resource target
    matching the canonical path. Returns an error response or None."""
    rt = _resource_target(ctx)
    if rt is None:
        return _error(
            400, "path_required",
            "substrate quorum op requires a resource target (V7 §3.2)",
        )
    rt_norm = ctx.emit_pathway.entity_tree.normalize_uri(rt)
    ep_norm = ctx.emit_pathway.entity_tree.normalize_uri(expected_path)
    if rt_norm != ep_norm:
        return _error(
            400, "resource_target_mismatch",
            f"resource target {rt!r} does not match canonical path {expected_path!r}",
        )
    return None


# =============================================================================
# Handler operations (§6)
# =============================================================================


async def _handle_create(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per §6.1: instantiate a quorum entity at canonical path."""
    data = _params_data(params)

    raw_signers = data.get("signers")
    if not isinstance(raw_signers, list) or not raw_signers:
        return _error(400, "invalid_params", "signers must be a non-empty list")
    signers: list[bytes] = []
    for s in raw_signers:
        norm = _normalize_hash(s)
        if norm is None:
            return _error(400, "invalid_params", "signers must be hashes")
        signers.append(norm)

    threshold = data.get("threshold")
    if not isinstance(threshold, int) or threshold <= 0:
        return _error(400, "invalid_params", "threshold must be a positive integer")
    if threshold > len(signers):
        return _error(
            400, "invalid_params",
            "threshold must not exceed number of signers",
        )

    quorum_data: dict[str, Any] = {"signers": signers, "threshold": threshold}
    mode = data.get("signer_resolution")
    if isinstance(mode, str) and mode:
        quorum_data["signer_resolution"] = mode
    name = data.get("name")
    if isinstance(name, str):
        quorum_data["name"] = name
    if "metadata" in data:
        quorum_data["metadata"] = data["metadata"]

    quorum = Entity(type=QUORUM_TYPE, data=quorum_data)
    quorum_id = quorum.compute_hash()
    path = quorum_entity_path(quorum_id)

    err = _require_path_matches(ctx, path)
    if err is not None:
        return err

    emit_ctx = EmitContext.from_handler_grant(ctx, "create")
    ctx.emit_pathway.emit(path, quorum, emit_ctx)

    return _ok(
        "system/quorum/create-result",
        {"quorum_id": quorum_id, "stored_at": path},
    )


async def _handle_update(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per §6.2: produce an unsigned quorum-update attestation."""
    data = _params_data(params)
    quorum_id = _normalize_hash(data.get("quorum_id"))
    if quorum_id is None:
        return _error(400, "invalid_params", "quorum_id is required")
    if _resolve_quorum_entity(quorum_id, ctx) is None:
        return _error(404, "quorum_not_found", "quorum entity not bound at canonical path")

    raw_new = data.get("new_signers")
    if not isinstance(raw_new, list) or not raw_new:
        return _error(400, "invalid_params", "new_signers must be a non-empty list")
    new_signers: list[bytes] = []
    for s in raw_new:
        norm = _normalize_hash(s)
        if norm is None:
            return _error(400, "invalid_params", "new_signers must be hashes")
        new_signers.append(norm)

    new_threshold = data.get("new_threshold")
    if not isinstance(new_threshold, int) or new_threshold <= 0:
        return _error(400, "invalid_params", "new_threshold must be positive integer")
    if new_threshold > len(new_signers):
        return _error(
            400, "invalid_params",
            "new_threshold must not exceed number of new_signers",
        )

    properties: dict[str, Any] = {
        "kind": KIND_QUORUM_UPDATE,
        "new_signers": new_signers,
        "new_threshold": new_threshold,
    }
    supersedes = _normalize_hash(data.get("supersedes")) if data.get("supersedes") is not None else None
    att = make_attestation(
        attesting=quorum_id, attested=quorum_id,
        properties=properties, supersedes=supersedes,
    )
    att_hash = att.compute_hash()
    path = quorum_event_path(quorum_id, att_hash)

    err = _require_path_matches(ctx, path)
    if err is not None:
        return err

    emit_ctx = EmitContext.from_handler_grant(ctx, "update")
    ctx.emit_pathway.emit(path, att, emit_ctx)

    ext = get_quorum_extension(ctx)
    if ext is not None:
        ext.invalidate(quorum_id)

    return _ok(
        "system/quorum/update-result",
        {"update_hash": att_hash, "stored_at": path},
    )


async def _handle_publish(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per §6.3: produce an unsigned quorum-publish attestation."""
    data = _params_data(params)
    quorum_id = _normalize_hash(data.get("quorum_id"))
    if quorum_id is None:
        return _error(400, "invalid_params", "quorum_id is required")
    if _resolve_quorum_entity(quorum_id, ctx) is None:
        return _error(404, "quorum_not_found", "quorum entity not bound at canonical path")

    raw_signers = data.get("signers")
    if not isinstance(raw_signers, list) or not raw_signers:
        return _error(400, "invalid_params", "signers must be a non-empty list")
    signers: list[bytes] = []
    for s in raw_signers:
        norm = _normalize_hash(s)
        if norm is None:
            return _error(400, "invalid_params", "signers must be hashes")
        signers.append(norm)

    threshold = data.get("threshold")
    if not isinstance(threshold, int) or threshold <= 0:
        return _error(400, "invalid_params", "threshold must be positive integer")

    supersedes = _normalize_hash(data.get("supersedes")) if data.get("supersedes") is not None else None

    if supersedes is None:
        # Initial publish: signers/threshold MUST match current_signer_set.
        try:
            current_signers, current_threshold, _ = current_signer_set(
                quorum_id, ctx,
            )
        except QuorumResolverUnavailable as e:
            return _error(
                400, "quorum_resolver_unavailable",
                str(e),
                quorum_id=e.quorum_id,
                mode_name=e.mode_name,
                available_modes=e.available_modes,
            )
        except (LookupError, ValueError) as e:
            return _error(400, "current_signer_set_failed", str(e))
        if (
            current_threshold != threshold
            or set(current_signers) != set(signers)
        ):
            return _error(
                400, "publish_mismatch",
                "initial publish signers/threshold must match current_signer_set",
            )

    properties: dict[str, Any] = {
        "kind": KIND_QUORUM_PUBLISH,
        "signers": signers,
        "threshold": threshold,
    }
    published_handle = _normalize_hash(data.get("published_handle")) if data.get("published_handle") is not None else None
    if published_handle is not None:
        properties["published_handle"] = published_handle

    extra_props = data.get("properties")
    if isinstance(extra_props, dict):
        for key, value in extra_props.items():
            if key in properties:
                continue  # well-known keys take precedence
            properties[key] = value

    att = make_attestation(
        attesting=quorum_id, attested=quorum_id,
        properties=properties, supersedes=supersedes,
    )
    att_hash = att.compute_hash()
    path = quorum_event_path(quorum_id, att_hash)

    err = _require_path_matches(ctx, path)
    if err is not None:
        return err

    emit_ctx = EmitContext.from_handler_grant(ctx, "publish")
    ctx.emit_pathway.emit(path, att, emit_ctx)

    ext = get_quorum_extension(ctx)
    if ext is not None:
        ext.invalidate(quorum_id)

    return _ok(
        "system/quorum/publish-result",
        {"publish_hash": att_hash, "stored_at": path},
    )


async def _handle_verify(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per §6.4: K-of-N verification helper."""
    data = _params_data(params)
    entity_hash = _normalize_hash(data.get("entity_hash"))
    quorum_id = _normalize_hash(data.get("quorum_id"))
    if entity_hash is None or quorum_id is None:
        return _error(400, "invalid_params", "entity_hash and quorum_id are required")

    try:
        signers, threshold, mode = current_signer_set(quorum_id, ctx)
    except QuorumResolverUnavailable as e:
        return _error(
            400, "quorum_resolver_unavailable",
            str(e),
            quorum_id=e.quorum_id,
            mode_name=e.mode_name,
            available_modes=e.available_modes,
        )
    except LookupError as e:
        return _error(404, "quorum_not_found", str(e))
    except ValueError as e:
        return _error(400, "quorum_invalid", str(e))

    ext = get_quorum_extension(ctx)
    resolver = ext.lookup_resolver(mode) if ext is not None else (
        _concrete_resolver if mode == RESOLUTION_CONCRETE else None
    )
    if resolver is None:
        return _error(
            400, "quorum_resolver_unavailable",
            f"no resolver registered for mode {mode!r}",
            quorum_id=quorum_id, mode_name=mode,
            available_modes=ext.available_modes() if ext is not None else [RESOLUTION_CONCRETE],
        )

    valid = verify_k_of_n_signatures(
        entity_hash, signers, threshold, ctx, resolver=resolver,
    )

    # Best-effort `signed_by` enumeration: re-scan signers and report
    # which keys produced verifying signatures. Doesn't recompute the
    # K-of-N decision; just fills in the diagnostic.
    signed_by: list[bytes] = []
    if valid:
        included = collect_signatures_for(ctx, entity_hash)
        identity_resolver = make_peer_resolver(ctx)
        for candidate in signers:
            out = resolver(candidate, ctx) if resolver else candidate
            keys = []
            if isinstance(out, bytes):
                keys = [out]
            elif isinstance(out, list):
                keys = [b for b in out if isinstance(b, bytes)]
            for key in keys:
                sig = find_signature_by_signer(entity_hash, key, included)
                if sig is None:
                    continue
                id_data = identity_resolver(key)
                if id_data is None:
                    continue
                if _verify_one_signature(entity_hash, key, sig, id_data):
                    if key not in signed_by:
                        signed_by.append(key)
                    break

    return _ok(
        "system/quorum/verify-result",
        {"valid": valid, "signed_by": signed_by},
    )


async def quorum_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Dispatch `system/quorum:*` operations per EXTENSION-QUORUM v1.0 §6."""
    if operation == _OP_CREATE:
        return await _handle_create(ctx, params)
    if operation == _OP_UPDATE:
        return await _handle_update(ctx, params)
    if operation == _OP_PUBLISH:
        return await _handle_publish(ctx, params)
    if operation == _OP_VERIFY:
        return await _handle_verify(ctx, params)
    return _error(
        501, "unsupported_operation",
        f"quorum handler does not support {operation!r}",
    )


__all__ = [
    "QUORUM_TYPE",
    "QUORUM_HANDLER_PATTERN",
    "QUORUM_ROOT",
    "EVENT_SEGMENT",
    "KIND_QUORUM_UPDATE",
    "KIND_QUORUM_PUBLISH",
    "RESOLUTION_CONCRETE",
    "ResolverFn",
    # Path helpers
    "encode_hash_segment",
    "quorum_entity_path",
    "quorum_event_path",
    # Extension
    "QuorumExtension",
    "get_quorum_extension",
    "QuorumResolverUnavailable",
    "IdentityResolverMaxDepthExceeded",
    "IdentityResolverCycle",
    "MAX_RESOLVER_DEPTH",
    # Validators
    "is_quorum_id",
    "current_signer_set",
    "verify_k_of_n_signatures",
    "process_quorum_attestation",
    # Handler
    "quorum_handler",
]
