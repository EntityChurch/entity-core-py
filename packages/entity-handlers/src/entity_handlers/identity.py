"""EXTENSION-IDENTITY v3.3 — convention layer over ATTESTATION + QUORUM.

Identity is a cert-chain framework on top of the substrate primitives:
- A K-of-N `system/quorum` sits at the structural root.
- Controllers are certified by the quorum (top-level cert, K-of-N).
- Agents (and identifiers in 4-key advanced) are certified by a controller.
- Lifecycle events (`identity-rotation-handoff`, `identity-rotation-recovery`,
  `identity-retirement`) maintain the cert tree.

This module owns ONLY:
- `system/identity/peer-config` (per-agent local state)
- `system/identity/identity-binding` (helper inner type)
- The four identity-specific `properties.kind` values for `system/attestation`
- Identity-specific topology dispatch + chain-walk semantics
- Storage path conventions (per audience tier)
- Registration of `identity-resolved` resolver against EXTENSION-QUORUM

v3.3 absorbs cross-impl-feedback batch
(`PROPOSAL-IDENTITY-V3.2-MIGRATION-FIXES.md`):
- SI-5: `walk_cert_chain_to_current_controller` uses `find_attestations_by`.
- SI-9: self/authority-revocation overlap documented; both rules return
  the same outcome for quorum-issued certs.
- SI-10: `process_attestation` algorithm with fail-closed unbind on
  validation failure, deterministic side-effect dispatch per kind.
- SI-11: `envelope.included` signature ingestion at handler entry, before
  validation runs.
- SI-13: `identity_confers_function` helper; lifecycle kinds inherit
  function from target_cert in chain walks.
- SI-14: app-defined function topology defaults to single-sig; "may
  override" removed from spec, future hook deferred.
- SI-23: `identity_verify_cert` topology-first dispatch (sig validation
  is per-topology, not pre-dispatch).

All mechanics (signature verify, liveness, supersedes walks, K-of-N) come
from the substrate primitives. Identity attestations are NEVER routed
through V7's `verify_capability_chain` (three-parallel-mechanisms invariant
per §12.3 v3.3 — cap-chain MAY read attestation state via the
IdentityBindingChecker hook for grantee-binding lookup, but MUST NOT
validate attestations as caps).
"""

from __future__ import annotations

import time
from typing import Any, Callable

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.auth import (
    create_identity_entity,
    create_signature_entity,
)
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_core.utils.path import invariant_signature_path

from entity_handlers._common import (
    error_response as _error,
    normalize_hash as _normalize_hash,
    ok_response as _ok,
    params_data as _params_data,
    resource_target as _resource_target,
)
from entity_handlers.attestation import (
    ATTESTATION_TYPE,
    KIND_REVOCATION,
    find_attestations_by,
    find_attestations_targeting,
    find_revocations_for,
    is_attestation_live,
    make_attestation,
    make_peer_resolver,
    verify_attestation_signature,
    verify_specific_signer,
    walk_attesting_chain,
)
from entity_handlers.quorum import (
    KIND_QUORUM_PUBLISH,
    QUORUM_TYPE,
    QuorumResolverUnavailable,
    current_signer_set,
    encode_hash_segment as _qhex,
    get_quorum_extension,
    is_quorum_id,
    process_quorum_attestation,
    quorum_entity_path,
    quorum_event_path,
    verify_k_of_n_signatures,
)


# ---------------------------------------------------------------------------
# Constants (per §3, §4, §5)
# ---------------------------------------------------------------------------

IDENTITY_HANDLER_PATTERN = "system/identity"

# Identity-owned types
PEER_CONFIG_TYPE = "system/identity/peer-config"
IDENTITY_BINDING_TYPE = "system/identity/identity-binding"

# Path roots
IDENTITY_ROOT = "system/identity"
INTERNAL_ROOT = "system/identity/internal"
PUBLIC_ROOT = "system/identity/public"
RELATIONSHIPS_ROOT = "system/identity/relationships"
CONTACTS_ROOT = "system/identity/contacts"
PEER_CONFIG_PATH = "system/identity/peer-config"
CERT_SEGMENT = "cert"
QUORUM_PUBLISH_LEAF = "quorum-publish"

# Identity-specific properties.kind values (§3.3)
KIND_IDENTITY_CERT = "identity-cert"
KIND_ROTATION_HANDOFF = "identity-rotation-handoff"
KIND_ROTATION_RECOVERY = "identity-rotation-recovery"
KIND_RETIREMENT = "identity-retirement"
IDENTITY_LIFECYCLE_KINDS = frozenset({
    KIND_ROTATION_HANDOFF, KIND_ROTATION_RECOVERY, KIND_RETIREMENT,
})

# Per V7 PI-1: kinds where `:supersede_attestation` may legitimately rebind
# `attesting`/`attested` (rotation case — substrate `:create` is called
# directly with explicit `supersedes`). Other kinds follow substrate
# `:supersede` semantics (preserve predecessor attesting/attested). Future
# identity-context kinds requiring rotation behavior are added here via spec
# amendment.
REBIND_KINDS = frozenset({KIND_IDENTITY_CERT})

# Cert function values (§4.2)
FUNCTION_CONTROLLER = "controller"
FUNCTION_AGENT = "agent"
FUNCTION_IDENTIFIER = "identifier"
VALID_FUNCTIONS = frozenset({
    FUNCTION_CONTROLLER, FUNCTION_AGENT, FUNCTION_IDENTIFIER,
})

# Publication modes (§4.2a) — REQUIRED on all identity-certs
MODE_INTERNAL = "internal"
MODE_PUBLIC = "public"
MODE_PER_RELATIONSHIP = "per-relationship"
MODE_EMBEDDED = "embedded"
ALL_MODES = frozenset({
    MODE_INTERNAL, MODE_PUBLIC, MODE_PER_RELATIONSHIP, MODE_EMBEDDED,
})

# Identity-resolved signer-resolution mode (registered against QUORUM)
RESOLUTION_IDENTITY_RESOLVED = "identity-resolved"

# Per V7 PI-5 (controller-events stream, failure-subset for v2):
# `:process_attestation` phase-3 emits an event entity per failed phase-2
# handler. Recovery-signal events MUST NOT be pruned until cleared (the
# tombstone IS the recovery signal, per PI-3 / PI-13). Failure-observation
# events have implementation-defined retention.
EVENT_TYPE = "system/identity/event"
EVENT_SUBKIND_RECOVERY_SIGNAL = "recovery_signal"
EVENT_SUBKIND_FAILURE_OBSERVATION = "failure_observation"
EVENTS_ROOT = "system/identity/events"

# Phase-2 handler ids per the §6.3 dispatch table (Rev 3 PI-5). Stable
# strings: contracts naming them appear in the events stream and SHOULD
# survive across impls.
HANDLER_ID_MAYBE_ISSUE_LOCAL_CAP = "maybe_issue_local_cap"
HANDLER_ID_MAYBE_ISSUE_LOCAL_CONTROLLER_CAP = "maybe_issue_local_controller_cap"
HANDLER_ID_MAYBE_UPDATE_IDENTIFIER_HANDLE = "maybe_update_identifier_handle"
HANDLER_ID_HANDLE_DUAL_SIG_HANDOFF = "handle_dual_sig_handoff"
HANDLER_ID_UPDATE_HANDLE_CACHE_TO = "update_handle_cache_to"
HANDLER_ID_REVOKE_LOCAL_CAPS_FOR_ATTESTED = "revoke_local_caps_for_attested"
HANDLER_ID_SEED_CONTACTS_CACHE = "seed_contacts_cache"
# Non-§6.3 handler ids (used by PI-3 publish-MOVE recovery + PI-13 cascade).
HANDLER_ID_PUBLISH_ATTESTATION = "publish_attestation"
HANDLER_ID_REVOKE_ATTESTATION_CASCADE = "revoke_attestation_cascade"

# Flat hash format: 1 algorithm byte + 32 digest bytes. ZERO_HASH (0x00 + 32
# zero bytes) is used as the "no-tree-write" sentinel in embedded-mode
# create/publish results per IDENTITY §4.2.
ZERO_HASH = b"\x00" * 33

# Topology dispatch results
TOPOLOGY_K_OF_N = "k-of-n"
TOPOLOGY_SINGLE = "single"
TOPOLOGY_DUAL = "dual"

# Operations
_OP_CONFIGURE = "configure"
_OP_CREATE_QUORUM = "create_quorum"
_OP_CREATE_ATTESTATION = "create_attestation"
_OP_SUPERSEDE_ATTESTATION = "supersede_attestation"
_OP_REVOKE_ATTESTATION = "revoke_attestation"
_OP_PUBLISH_ATTESTATION = "publish_attestation"
_OP_PROCESS_ATTESTATION = "process_attestation"


# ---------------------------------------------------------------------------
# Hash + path helpers
# ---------------------------------------------------------------------------


def encode_hash_segment(h: bytes) -> str:
    return h.hex()


def cert_internal_path(content_hash: bytes) -> str:
    return f"{INTERNAL_ROOT}/{CERT_SEGMENT}/{encode_hash_segment(content_hash)}"


def cert_public_path(content_hash: bytes) -> str:
    return f"{PUBLIC_ROOT}/{CERT_SEGMENT}/{encode_hash_segment(content_hash)}"


def cert_relationship_path(contact_id: bytes, content_hash: bytes) -> str:
    return (
        f"{RELATIONSHIPS_ROOT}/{encode_hash_segment(contact_id)}/"
        f"{CERT_SEGMENT}/{encode_hash_segment(content_hash)}"
    )


def contacts_quorum_publish_path(handle: bytes) -> str:
    """Cache path for a contact identity's quorum-publish, keyed by the
    contact's published handle (§5.1)."""
    return f"{CONTACTS_ROOT}/{encode_hash_segment(handle)}/{QUORUM_PUBLISH_LEAF}"


def controller_event_path(
    timestamp_ms: int,
    handler_id: str,
    attestation_hash: bytes,
    event_content_hash: bytes,
) -> str:
    """Per V7 PI-5: canonical path for a controller-events stream entry.

    Format:
        system/identity/events/{timestamp_ms}/{handler_id}/{attestation_hex}/{event_hex}

    The trailing event-content-hash segment makes the path unique by
    construction — identical events at the same instant collapse to the
    same path (idempotent).
    """
    return (
        f"{EVENTS_ROOT}/{timestamp_ms}/{handler_id}/"
        f"{encode_hash_segment(attestation_hash)}/"
        f"{encode_hash_segment(event_content_hash)}"
    )


def _emit_controller_event(
    ctx: HandlerContext,
    *,
    event_subkind: str,
    handler_id: str,
    attestation_hash: bytes,
    attestation_kind: str | None,
    error_code: str,
    error_detail: str,
    operation: str,
    timestamp_ms: int | None = None,
) -> bytes:
    """Construct + bind a `system/identity/event` entity per V7 PI-5.

    `event_subkind` MUST be EVENT_SUBKIND_RECOVERY_SIGNAL when the failed
    op left orphaned/inconsistent state requiring controller action (PI-3
    publish-MOVE rebind failure; PI-13 cap-cleanup partial failure), or
    EVENT_SUBKIND_FAILURE_OBSERVATION otherwise. Recovery-signal events
    MUST NOT be pruned until cleared (the tombstone IS the recovery signal).

    Returns the bound event entity's content hash.
    """
    if event_subkind not in (
        EVENT_SUBKIND_RECOVERY_SIGNAL, EVENT_SUBKIND_FAILURE_OBSERVATION,
    ):
        raise ValueError(f"invalid event_subkind: {event_subkind!r}")
    ts = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)
    event = Entity(
        type=EVENT_TYPE,
        data={
            "event_subkind": event_subkind,
            "handler_id": handler_id,
            "attestation_hash": attestation_hash,
            "attestation_kind": attestation_kind or "",
            "error_code": error_code,
            "error_detail": error_detail,
            "timestamp_ms": ts,
        },
    )
    event_hash = event.compute_hash()
    path = controller_event_path(ts, handler_id, attestation_hash, event_hash)
    emit_ctx = EmitContext.from_handler_grant(ctx, operation)
    ctx.emit_pathway.emit(path, event, emit_ctx)
    return event_hash


# ---------------------------------------------------------------------------
# Canonical storage path (§5.3)
# ---------------------------------------------------------------------------


def canonical_storage_path(
    att: Entity, ctx: HandlerContext,
) -> str | None:
    """Resolve the canonical storage path for an identity-context
    attestation. Path resolution is purely a function of the attestation's
    own `properties` (§5.3) — no runtime shape lookup.

    Per V7 PI-12 (mode normative-job pin): `properties.mode` is a
    storage-path selector. The (kind, function, mode, [contact_id]) tuple
    deterministically computes this path. Audience semantics, sync semantics,
    and handle-bearing semantics are derived from path namespace and
    (kind, function), NOT from `mode` independently:

    | Path namespace                       | Audience              | Sync      | Handle-bearing                                                              |
    |--------------------------------------|-----------------------|-----------|-----------------------------------------------------------------------------|
    | `system/identity/internal/cert/...`  | own agents only       | none      | iff function=identifier (4-key) OR sub-controller chain terminates here     |
    | `system/identity/public/cert/...`    | all contacts          | two-tier  | iff function=controller (3-key default)                                     |
    | `system/identity/relationships/.../` | named contact only    | three-tier| no (relationship-mode certs are not handles)                                |
    | `embedded` (no tree path)            | cap-envelope holders  | none      | no (embedded certs are ephemeral)                                           |
    """
    props = att.data.get("properties") or {}
    kind = props.get("kind")

    if kind == KIND_IDENTITY_CERT:
        return _canonical_cert_path(att)

    if kind in IDENTITY_LIFECYCLE_KINDS or kind == KIND_REVOCATION:
        target_hash = _normalize_hash(props.get("target_cert"))
        if target_hash is None and kind == KIND_REVOCATION:
            # Revocations targeting non-cert entities don't have target_cert;
            # use att.attested as the target.
            target_hash = _normalize_hash(att.data.get("attested"))
        if target_hash is None:
            return None
        target = ctx.emit_pathway.content_store.get(target_hash)
        if target is None or target.type != ATTESTATION_TYPE:
            return None
        target_path = _canonical_cert_path(target)
        if target_path is None:
            return None
        # Inherit the target's audience tier; replace the trailing
        # `cert/{old_hex}` with `cert/{this_hex}`.
        prefix = target_path.rsplit(f"/{CERT_SEGMENT}/", 1)[0]
        return f"{prefix}/{CERT_SEGMENT}/{encode_hash_segment(att.compute_hash())}"

    return None


def _canonical_cert_path(att: Entity) -> str | None:
    """Per-mode dispatch for `kind=identity-cert` and (recursively) for
    lifecycle events resolving their target's tier."""
    props = att.data.get("properties") or {}
    h = att.compute_hash()
    mode = props.get("mode")
    if mode == MODE_INTERNAL:
        return cert_internal_path(h)
    if mode == MODE_PUBLIC:
        return cert_public_path(h)
    if mode == MODE_PER_RELATIONSHIP:
        contact_id = _normalize_hash(props.get("contact_id"))
        if contact_id is None:
            return None
        return cert_relationship_path(contact_id, h)
    if mode == MODE_EMBEDDED:
        return None  # embedded in cap envelope; no tree path
    return None


# ---------------------------------------------------------------------------
# Identity-specific helpers (§3.6)
# ---------------------------------------------------------------------------


def _validate_function_mode(
    function: str,
    mode: str,
    attesting: bytes | None,
    ctx: HandlerContext,
) -> dict[str, Any] | None:
    """V7 PI-11 — per-function valid-modes enforcement (§4.2 table).

    Per the EXTENSION-IDENTITY §4.2 normative table:
      - controller (top-level, attesting = quorum_id):  {public, internal}
      - controller (sub-controller, attesting = peer):   {internal}
      - agent:                                           {internal, public,
                                                          per-relationship, embedded}
      - identifier (4-key advanced only):                {internal}
      - <app-defined>:                                   per app convention;
                                                          identity does not enforce here

    Top-level vs sub-controller is determined by whether `attesting` resolves
    to a quorum-id in the local tree. App-defined functions skip this check;
    apps that ship custom function values declare valid modes in their own
    validator extension.

    Returns an `_error(...)` payload on invalid combination, or None on pass.
    The error envelope carries `function`, `attempted_mode`, and
    `valid_modes_for_function` for diagnostic clarity.
    """
    if function == FUNCTION_CONTROLLER:
        is_top_level = attesting is not None and is_quorum_id(attesting, ctx)
        if is_top_level:
            valid = (MODE_PUBLIC, MODE_INTERNAL)
        else:
            valid = (MODE_INTERNAL,)
    elif function == FUNCTION_AGENT:
        valid = (MODE_INTERNAL, MODE_PUBLIC, MODE_PER_RELATIONSHIP, MODE_EMBEDDED)
    elif function == FUNCTION_IDENTIFIER:
        valid = (MODE_INTERNAL,)
    else:
        # App-defined function: identity does not enforce; apps validate.
        return None

    if mode not in valid:
        return _error(
            400, "invalid_mode_for_function",
            f"function={function!r} does not allow mode={mode!r}",
            function=function,
            attempted_mode=mode,
            valid_modes_for_function=list(valid),
        )
    return None


def valid_functions() -> frozenset[str]:
    """Standard cert function values (§3.6). App-defined functions pass
    through the `identity-cert` validator's any-string fallback."""
    return VALID_FUNCTIONS


def identity_lifecycle_kinds() -> frozenset[str]:
    """Identity-context attestation kinds that are NOT identity-cert."""
    return IDENTITY_LIFECYCLE_KINDS


def lookup_target_cert(
    target_ref: Entity | bytes,
    ctx: HandlerContext,
) -> Entity | None:
    """Resolve a `properties.target_cert` reference (or a lifecycle
    attestation carrying one) to the cert entity it targets."""
    if isinstance(target_ref, Entity):
        props = target_ref.data.get("properties") or {}
        target_hash = _normalize_hash(props.get("target_cert"))
    else:
        target_hash = _normalize_hash(target_ref)
    if target_hash is None:
        return None
    return ctx.emit_pathway.content_store.get(target_hash)


def _is_top_level_controller_cert(att: Entity, ctx: HandlerContext) -> bool:
    """An identity-cert with function=controller whose `attesting` is a
    `system/quorum` entity in the local tree."""
    props = att.data.get("properties") or {}
    if props.get("kind") != KIND_IDENTITY_CERT:
        return False
    if props.get("function") != FUNCTION_CONTROLLER:
        return False
    attesting = _normalize_hash(att.data.get("attesting"))
    if attesting is None:
        return False
    return is_quorum_id(attesting, ctx)


def identity_confers_function(
    att: Entity, function_name: str, ctx: HandlerContext,
    *, _visited: frozenset[bytes] | None = None,
) -> bool:
    """Per IDENTITY §3.6 v3.3 (SI-13): does `att` confer `function_name`
    on `att.attested`? Handles both identity-cert (direct function field)
    and lifecycle kinds (function inherited from target_cert).

    Identity-retirement returns False — the function is being retired,
    not conferred."""
    h = att.compute_hash()
    visited = _visited or frozenset()
    if h in visited:
        return False
    visited = visited | {h}

    props = att.data.get("properties") or {}
    kind = props.get("kind")
    if kind == KIND_IDENTITY_CERT:
        return props.get("function") == function_name
    if kind in (KIND_ROTATION_HANDOFF, KIND_ROTATION_RECOVERY):
        target = lookup_target_cert(att, ctx)
        if target is None:
            return False
        return identity_confers_function(target, function_name, ctx, _visited=visited)
    if kind == KIND_RETIREMENT:
        return False
    return False


def walk_cert_chain_to_current_controller(
    quorum_id: bytes, ctx: HandlerContext,
    *, as_of: int | None = None,
) -> Entity | None:
    """Per IDENTITY §3.6 v3.3: live top-level controller cert under the
    given quorum_id at `as_of`. When `as_of` is None, returns the
    current live controller. Predicate uses `identity_confers_function`
    so rotation-handoff / rotation-recovery attestations ARE
    chain-walkable (they inherit the function from their target_cert).

    Multi-controller deployments (multiple concurrent live top-level
    controllers) tie-break by lowest content_hash.
    """
    candidates = find_attestations_by(
        quorum_id,
        lambda a, c: identity_confers_function(a, FUNCTION_CONTROLLER, c),
        ctx,
    )
    live = [c for c in candidates if is_attestation_live(c, ctx, as_of=as_of)]
    if not live:
        return None
    if len(live) == 1:
        return live[0]
    return min(live, key=lambda c: c.compute_hash())


def resolve_controller_for_grants(
    peer_config: Entity, ctx: HandlerContext,
) -> Entity | None:
    """Per §3.2 normative rule: the live top-level controller cert this
    peer's controller_grants apply to. Sub-controllers do NOT inherit;
    they get separate V7 caps."""
    trusted_quorum = _normalize_hash(peer_config.data.get("trusts_quorum"))
    if trusted_quorum is None:
        return None
    return walk_cert_chain_to_current_controller(trusted_quorum, ctx)


# ---------------------------------------------------------------------------
# Topology dispatch (§3.6)
# ---------------------------------------------------------------------------


class _Topology:
    __slots__ = ("mode", "signers", "threshold", "expected_signer", "reason")

    def __init__(
        self, mode: str,
        *, signers: list[bytes] | None = None,
        threshold: int | None = None,
        expected_signer: bytes | None = None,
        reason: str | None = None,
    ) -> None:
        self.mode = mode
        self.signers = signers
        self.threshold = threshold
        self.expected_signer = expected_signer
        self.reason = reason


def identity_topology_for(
    att: Entity, ctx: HandlerContext,
) -> _Topology | None:
    """Per §3.6 topology dispatch on `properties.kind` + `properties.function`
    + `is_quorum_id(att.attesting)`. Returns None on dispatch failure
    (caller surfaces it as a verification error)."""
    props = att.data.get("properties") or {}
    kind = props.get("kind")
    function = props.get("function")
    attesting = _normalize_hash(att.data.get("attesting"))
    if attesting is None:
        return None

    if kind == KIND_IDENTITY_CERT:
        attesting_is_quorum = is_quorum_id(attesting, ctx)
        if function == FUNCTION_CONTROLLER and attesting_is_quorum:
            try:
                signers, threshold, _mode = current_signer_set(attesting, ctx)
            except (QuorumResolverUnavailable, LookupError, ValueError) as e:
                return _Topology(TOPOLOGY_K_OF_N, reason=str(e))
            return _Topology(
                TOPOLOGY_K_OF_N, signers=signers, threshold=threshold,
            )
        # Sub-controller, agent, identifier, app-defined → single-sig.
        return _Topology(TOPOLOGY_SINGLE, expected_signer=attesting)

    if kind == KIND_ROTATION_HANDOFF:
        target = lookup_target_cert(att, ctx)
        if target is None:
            return None
        # Dual-sig: old key (= target.attested = att.attesting) AND new
        # key (= att.attested).
        old_key = _normalize_hash(target.data.get("attested"))
        new_key = _normalize_hash(att.data.get("attested"))
        if old_key is None or new_key is None:
            return None
        return _Topology(TOPOLOGY_DUAL, signers=[old_key, new_key])

    if kind in (KIND_ROTATION_RECOVERY, KIND_RETIREMENT):
        # K-of-N from quorum (att.attesting is the quorum_id).
        try:
            signers, threshold, _mode = current_signer_set(attesting, ctx)
        except (QuorumResolverUnavailable, LookupError, ValueError) as e:
            return _Topology(TOPOLOGY_K_OF_N, reason=str(e))
        return _Topology(
            TOPOLOGY_K_OF_N, signers=signers, threshold=threshold,
        )

    return None


def identity_is_quorum_link(att: Entity, ctx: HandlerContext) -> bool:
    """Terminate predicate for chain walks: True if `att.attesting` is a
    quorum_id (i.e., att is a top-level cert)."""
    attesting = _normalize_hash(att.data.get("attesting"))
    if attesting is None:
        return False
    return is_quorum_id(attesting, ctx)


def _identity_find_authorizing(
    peer_hash: bytes, ctx: HandlerContext,
) -> "Entity | None":
    """Identity-specific chain-walk hook (per §5.1 "Multi-context peers
    note"): find the live identity-cert attesting `peer_hash`, filtering
    by `kind == identity-cert` and skipping the substrate's single-sig
    pre-check. Topology-aware signature validation happens later when
    `identity_verify_cert` recursively validates each link.
    """
    candidates = find_attestations_targeting(
        peer_hash,
        lambda a, _c: (a.data.get("properties") or {}).get("kind") == KIND_IDENTITY_CERT,
        ctx,
    )
    live = [c for c in candidates if is_attestation_live(c, ctx)]
    if not live:
        return None
    if len(live) == 1:
        return live[0]
    return min(live, key=lambda c: c.compute_hash())


def identity_is_authorized_revoker(
    revoker: bytes, target_cert: Entity, ctx: HandlerContext,
) -> bool:
    """Per §3.6: identity rule — only the quorum at the root of
    target_cert's chain can authority-revoke it. (Self-revocation is
    handled at the primitive layer.)"""
    chain = walk_attesting_chain(
        target_cert, identity_is_quorum_link, ctx,
        find_authorizing_fn=_identity_find_authorizing,
    )
    if chain is None:
        return False
    quorum_id = _normalize_hash(chain[-1].data.get("attesting"))
    if quorum_id is None:
        return False
    return revoker == quorum_id


# ---------------------------------------------------------------------------
# Compromise-recovery validation (§9.4) — fail-closed against cached
# quorum-publish.
# ---------------------------------------------------------------------------


def _verify_recovery_against_cached_publish(
    att: Entity, ctx: HandlerContext,
) -> bool:
    """For `identity-rotation-recovery` targeting a handle-bearing cert,
    K-of-N MUST validate against the cached `quorum-publish` for the
    old handle (§9.4). Returns False on cache miss (fail-closed)."""
    props = att.data.get("properties") or {}
    old_handle = _normalize_hash(props.get("old_handle"))
    if old_handle is None:
        return False
    cache_path = ctx.emit_pathway.entity_tree.normalize_uri(
        contacts_quorum_publish_path(old_handle),
    )
    cached_hash = ctx.emit_pathway.entity_tree.get(cache_path)
    if cached_hash is None:
        return False
    cached = ctx.emit_pathway.content_store.get(cached_hash)
    if cached is None or cached.type != ATTESTATION_TYPE:
        return False
    cached_props = cached.data.get("properties") or {}
    if cached_props.get("kind") != KIND_QUORUM_PUBLISH:
        return False

    signers_raw = cached_props.get("signers") or []
    signers = [
        s for s in (_normalize_hash(x) for x in signers_raw) if s is not None
    ]
    threshold = cached_props.get("threshold")
    if not signers or not isinstance(threshold, int) or threshold <= 0:
        return False

    return verify_k_of_n_signatures(
        att.compute_hash(), signers, threshold, ctx,
    )


# ---------------------------------------------------------------------------
# identity_verify_cert orchestration (§3.6)
# ---------------------------------------------------------------------------


def identity_verify_cert(
    att: Entity, ctx: HandlerContext,
) -> tuple[bool, str | None]:
    """Sole identity validator. Composes substrate primitives + identity
    predicates. Returns (valid, error_code_or_None)."""
    if att.type != ATTESTATION_TYPE:
        return False, "not_attestation"

    props = att.data.get("properties") or {}
    kind = props.get("kind")
    if kind != KIND_IDENTITY_CERT and kind not in IDENTITY_LIFECYCLE_KINDS:
        return False, "not_identity_attestation"

    if kind == KIND_IDENTITY_CERT:
        function = props.get("function")
        if not isinstance(function, str) or not function:
            return False, "invalid_function"
        # Standard functions are checked against valid_functions();
        # app-defined functions accepted via any-string fallback. To
        # reject obviously wrong values (None, "", non-string) we check
        # for non-empty string only.
        mode = props.get("mode")
        if mode not in ALL_MODES:
            return False, "invalid_mode"
        if mode == MODE_PER_RELATIONSHIP:
            if _normalize_hash(props.get("contact_id")) is None:
                return False, "missing_contact_id"

    if kind in IDENTITY_LIFECYCLE_KINDS:
        if _normalize_hash(props.get("target_cert")) is None:
            return False, "missing_target_cert"

    # Generic liveness (no sig check here — topology dispatch is the
    # sole signature authority because K-of-N and dual-sig don't fit
    # the substrate's single-sig default).
    if not is_attestation_live(att, ctx):
        return False, "not_live"

    # Authority-revocation (identity-specific authority rules).
    for rev in find_revocations_for(att.compute_hash(), ctx):
        if not is_attestation_live(rev, ctx):
            continue
        revoker = _normalize_hash(rev.data.get("attesting"))
        if revoker is None:
            continue
        if identity_is_authorized_revoker(revoker, att, ctx):
            return False, "authority_revoked"

    # Topology dispatch + validation. Topology dispatch determines
    # which signature validator runs (single / dual / K-of-N).
    topology = identity_topology_for(att, ctx)
    if topology is None:
        return False, "topology_dispatch_failed"

    if topology.mode == TOPOLOGY_K_OF_N:
        if topology.signers is None or topology.threshold is None:
            return False, topology.reason or "topology_unavailable"

        # Compromise-recovery handle-bearing certs validate against the
        # CACHED quorum-publish for the old handle, NOT current state
        # (§9.4 fail-closed MUST).
        if kind == KIND_ROTATION_RECOVERY:
            target = lookup_target_cert(att, ctx)
            if target is not None:
                target_props = target.data.get("properties") or {}
                target_mode = target_props.get("mode")
                if target_mode == MODE_PUBLIC:
                    if not _verify_recovery_against_cached_publish(att, ctx):
                        return False, "recovery_against_cached_publish_failed"
                    return True, None

        ext = get_quorum_extension(ctx)
        attesting = _normalize_hash(att.data.get("attesting"))
        if attesting is None:
            return False, "missing_attesting"
        try:
            _signers, _threshold, mode_str = current_signer_set(attesting, ctx)
        except (QuorumResolverUnavailable, LookupError, ValueError) as e:
            return False, f"signer_set_unavailable:{e}"
        resolver = ext.lookup_resolver(mode_str) if ext is not None else None
        if not verify_k_of_n_signatures(
            att.compute_hash(), topology.signers, topology.threshold, ctx,
            resolver=resolver,
        ):
            return False, "k_of_n_failed"

    elif topology.mode == TOPOLOGY_SINGLE:
        attesting = _normalize_hash(att.data.get("attesting"))
        if attesting != topology.expected_signer:
            return False, "wrong_signer"
        if not verify_attestation_signature(att, ctx):
            return False, "invalid_signature"

    elif topology.mode == TOPOLOGY_DUAL:
        if not topology.signers or len(topology.signers) != 2:
            return False, "dual_signers_invalid"
        for signer in topology.signers:
            if not verify_specific_signer(att, signer, ctx):
                return False, f"missing_dual_sig:{signer.hex()[:16]}"

    else:
        return False, "unknown_topology"

    # Chain walk back to quorum (skip for top-level certs, lifecycle
    # events, and dual-sig — for those `identity_is_quorum_link` either
    # holds or doesn't apply).
    if not identity_is_quorum_link(att, ctx) and topology.mode == TOPOLOGY_SINGLE:
        chain = walk_attesting_chain(
            att, identity_is_quorum_link, ctx,
            find_authorizing_fn=_identity_find_authorizing,
        )
        if chain is None:
            return False, "chain_to_quorum_not_found"
        # Verify each link (skip self at index 0).
        for link in chain[1:]:
            ok, reason = identity_verify_cert(link, ctx)
            if not ok:
                return False, f"chain_link_invalid:{reason}"

    return True, None


# ---------------------------------------------------------------------------
# Operational-key confinement (§9.2)
# ---------------------------------------------------------------------------


def _live_top_level_controllers_for_quorum(
    quorum_id: bytes, ctx: HandlerContext,
) -> set[bytes]:
    """Live top-level controller peers for `quorum_id` — the keys that
    MUST NOT appear as signers under public/. Uses identity_confers_function
    per SI-13 so rotation kinds are walked correctly."""
    out: set[bytes] = set()
    candidates = find_attestations_by(
        quorum_id,
        lambda a, c: identity_confers_function(a, FUNCTION_CONTROLLER, c),
        ctx,
    )
    for cert in candidates:
        if not is_attestation_live(cert, ctx):
            continue
        attested = _normalize_hash(cert.data.get("attested"))
        if attested is not None:
            out.add(attested)
    return out


def _check_op_confinement(
    att: Entity, expected_path: str | None, ctx: HandlerContext,
) -> str | None:
    """Per §9.2: an entity bound under public/ MUST NOT carry signatures
    from any currently-live top-level controller of the trusted quorum.
    Returns an error code or None on pass."""
    if expected_path is None:
        return None
    if not expected_path.startswith(PUBLIC_ROOT + "/"):
        return None
    config = _load_peer_config(ctx)
    if config is None:
        return None
    trusted_quorum = _normalize_hash(config.data.get("trusts_quorum"))
    if trusted_quorum is None:
        return None
    live_controllers = _live_top_level_controllers_for_quorum(trusted_quorum, ctx)
    if not live_controllers:
        return None

    # Scan signature entities targeting att.compute_hash().
    target_hash = att.compute_hash()
    for _uri, h in ctx.emit_pathway.entity_tree.all_bindings():
        entity = ctx.emit_pathway.content_store.get(h)
        if entity is None or entity.type != "system/signature":
            continue
        sig_target = entity.data.get("target")
        if not isinstance(sig_target, bytes) or sig_target != target_hash:
            continue
        signer = _normalize_hash(entity.data.get("signer"))
        if signer in live_controllers:
            return "controller_signature_forbidden_under_public"
    return None


# ---------------------------------------------------------------------------
# Peer-config persistence (§3.2)
# ---------------------------------------------------------------------------


def _persist_peer_config(
    ctx: HandlerContext,
    *,
    trusts_quorum: bytes,
    controller_grants: list[dict[str, Any]],
    bindings: list[dict[str, Any]] | None = None,
    metadata: Any | None = None,
    operation: str = _OP_CONFIGURE,
) -> bytes:
    data: dict[str, Any] = {
        "trusts_quorum": trusts_quorum,
        "controller_grants": controller_grants,
    }
    if bindings:
        data["bindings"] = bindings
    if metadata is not None:
        data["metadata"] = metadata
    config = Entity(type=PEER_CONFIG_TYPE, data=data)
    emit_ctx = EmitContext.from_handler_grant(ctx, operation)
    return ctx.emit_pathway.emit(PEER_CONFIG_PATH, config, emit_ctx).hash


def _validate_bindings_structural(
    ctx: HandlerContext, bindings: list[Any],
) -> dict[str, Any] | None:
    """V7 PI-2 phase 1 (Rev 3): structural validation only — does NOT
    reference phase-2 enumeration output. Per IDENTITY §6 PR-8.4 binding
    error contract:

    | Failure mode                       | Status | Subcode                          |
    |------------------------------------|--------|----------------------------------|
    | handle_cert hash is zero/missing   | 400    | binding_missing_handle_cert      |
    | agent_cert hash is zero/missing    | 400    | binding_missing_agent_cert       |
    | Non-zero hash doesn't resolve      | 404    | binding_cert_not_found           |
    | Hash resolves but wrong shape      | 400    | binding_cert_wrong_kind          |

    Per Rev 3 PI-2 Phase 1 contract: handle_cert is function ∈
    {controller, identifier}; agent_cert is function=agent.

    Returns an `_error(...)` payload to short-circuit, or None on success.
    """
    for entry in bindings:
        if not isinstance(entry, dict):
            return _error(
                400, "invalid_params",
                "each binding entry must be a map "
                "{handle_cert, agent_cert, label?, metadata?}",
            )
        handle_cert_raw = entry.get("handle_cert")
        agent_cert_raw = entry.get("agent_cert")

        # Zero-hash / missing detection. A genuinely structurally-empty
        # hash is `b""` or absent, NOT just zero bytes — an all-zero
        # 33-byte hash is a structurally valid hash that happens to
        # not resolve, which falls under 404 binding_cert_not_found.
        handle_cert = _normalize_hash(handle_cert_raw)
        if handle_cert is None or handle_cert == b"":
            return _error(
                400, "binding_missing_handle_cert",
                "binding entry has a zero/missing handle_cert hash",
            )
        agent_cert = _normalize_hash(agent_cert_raw)
        if agent_cert is None or agent_cert == b"":
            return _error(
                400, "binding_missing_agent_cert",
                "binding entry has a zero/missing agent_cert hash",
            )

        for field, h, expected_functions in (
            (
                "handle_cert", handle_cert,
                (FUNCTION_CONTROLLER, FUNCTION_IDENTIFIER),
            ),
            ("agent_cert", agent_cert, (FUNCTION_AGENT,)),
        ):
            entity = ctx.emit_pathway.content_store.get(h)
            if entity is None:
                return _error(
                    404, "binding_cert_not_found",
                    f"binding {field} {h.hex()} does not resolve to a "
                    "system/attestation entity in the content store",
                )
            if entity.type != ATTESTATION_TYPE:
                return _error(
                    400, "binding_cert_wrong_kind",
                    f"binding {field} {h.hex()} resolves to a {entity.type!r} "
                    "entity, not system/attestation",
                )
            props = entity.data.get("properties") or {}
            if props.get("kind") != KIND_IDENTITY_CERT:
                return _error(
                    400, "binding_cert_wrong_kind",
                    f"binding {field} {h.hex()} resolves to attestation "
                    f"kind {props.get('kind')!r}, expected {KIND_IDENTITY_CERT!r}",
                )
            fn = props.get("function")
            if fn not in expected_functions:
                return _error(
                    400, "binding_cert_wrong_kind",
                    f"binding {field} {h.hex()} has function={fn!r}, "
                    f"expected one of {expected_functions!r}",
                )

    return None


def _enumerate_live_controller_certs(
    trusts_quorum: bytes, ctx: HandlerContext,
) -> tuple[list[Entity], set[bytes]]:
    """V7 PI-2 phase 2 (Rev 3): enumerate live + non-superseded top-level
    controller certs targeting `trusts_quorum`. Returns (certs, set of
    `attested` hashes — the controller-peer-ids).

    Used by both `:configure` (cap issuance) and `:revoke_attestation`
    cascade (PI-13) for live-state queries.
    """
    certs: list[Entity] = []
    live_controllers: set[bytes] = set()
    candidates = find_attestations_by(
        trusts_quorum,
        lambda a, c: identity_confers_function(a, FUNCTION_CONTROLLER, c),
        ctx,
    )
    for cert in candidates:
        if not is_attestation_live(cert, ctx):
            continue
        controller_hash = _normalize_hash(cert.data.get("attested"))
        if controller_hash is None:
            continue
        certs.append(cert)
        live_controllers.add(controller_hash)
    return certs, live_controllers


def _validate_bindings_against_live_controllers(
    ctx: HandlerContext,
    bindings: list[dict[str, Any]],
    live_controllers: set[bytes],
) -> dict[str, Any] | None:
    """V7 PI-2 phase 2 (Rev 3): for each binding, validate that the
    agent_cert chains to a live controller-cert in the trusted quorum.
    Prevents bindings to retired controllers. Phase 1 was structural;
    this check requires the live-controller enumeration output.

    Per Rev 3 (5): the binding-controller-liveness check moved from phase
    1 to phase 2 (post-enumeration) to keep phase boundaries clean and
    avoid duplicating the controller walk.
    """
    for entry in bindings:
        agent_cert_hash = _normalize_hash(entry.get("agent_cert"))
        if agent_cert_hash is None:
            # Phase 1 already rejected; defensive guard.
            continue
        agent_cert = ctx.emit_pathway.content_store.get(agent_cert_hash)
        if agent_cert is None:
            continue
        attesting = _normalize_hash(agent_cert.data.get("attesting"))
        if attesting is None:
            return _error(
                400, "binding_controller_not_live",
                f"agent_cert {agent_cert_hash.hex()} has no attesting field",
            )
        # Direct chain: agent_cert.attesting IS a live controller.
        if attesting in live_controllers:
            continue
        # Sub-controller chain: walk to a live top-level controller.
        chain_top = walk_cert_chain_to_current_controller(attesting, ctx)
        if chain_top is None:
            return _error(
                400, "binding_controller_not_live",
                f"agent_cert {agent_cert_hash.hex()} chains to attesting="
                f"{attesting.hex()}, which is not a live controller in the "
                "trusted quorum",
            )
        chain_attested = _normalize_hash(chain_top.data.get("attested"))
        if chain_attested not in live_controllers:
            return _error(
                400, "binding_controller_not_live",
                f"agent_cert {agent_cert_hash.hex()}'s controller chain does "
                "not terminate in a live top-level controller",
            )
    return None


def _load_peer_config(ctx: HandlerContext) -> Entity | None:
    full = ctx.emit_pathway.entity_tree.normalize_uri(PEER_CONFIG_PATH)
    h = ctx.emit_pathway.entity_tree.get(full)
    if h is None:
        return None
    entity = ctx.emit_pathway.content_store.get(h)
    if entity is None or entity.type != PEER_CONFIG_TYPE:
        return None
    return entity


# ---------------------------------------------------------------------------
# Local peer→controller cap (§3.2 controller_grants)
# ---------------------------------------------------------------------------


def _local_peer_to_controller_cap_path(controller_hash: bytes) -> str:
    """One slot per top-level controller (multi-controller deployments
    may have several concurrent)."""
    return (
        f"system/capability/grants/identity/peer-to-controller/"
        f"{encode_hash_segment(controller_hash)}"
    )


def _emit_signed_cap(
    ctx: HandlerContext,
    cap_entity: Entity,
    granter_identity: Entity,
    signature_entity: Entity,
    storage_path: str,
    operation: str,
) -> bytes:
    """Emit a cap at its storage path; bind its signature at the V7
    invariant pointer.

    Per EXTENSION-IDENTITY v3.6 §6.0e (I-7): the cap signature
    MUST be bound at `/{granter_peer_id}/system/signature/{cap_hash_hex}`
    — the §3.5 invariant pointer — NOT at the v3.5 sibling `{cap_path}/
    signature`. Discovery uses the invariant pointer (B) per v7.45 chain
    machinery (`collect_chain_bundle`, receiver resolver, envelope
    ingest); the sibling-path convention has been removed entirely.
    Symmetric to ROLE v2.0 Amendment 3 (CP-3).
    """
    emit_ctx = EmitContext.from_handler_grant(ctx, operation)
    pathway = ctx.emit_pathway
    pathway.content_store.put(granter_identity)
    cap_hash = pathway.emit(storage_path, cap_entity, emit_ctx).hash
    # v7.65 §2: peer_id no longer in entity data — derive from pubkey
    from entity_core.crypto.identity import peer_id_from_identity_entity
    granter_peer_id = peer_id_from_identity_entity(
        {"data": granter_identity.data},
    )
    if not granter_peer_id:
        raise RuntimeError(
            "granter identity entity is missing public_key; cannot bind cap "
            "signature at V7 invariant pointer",
        )
    sig_path = invariant_signature_path(granter_peer_id, cap_hash)
    pathway.emit(sig_path, signature_entity, emit_ctx)
    return cap_hash


def _issue_local_peer_to_controller_cap(
    ctx: HandlerContext,
    controller_hash: bytes,
    grants: list[dict[str, Any]],
    *,
    operation: str = _OP_CONFIGURE,
) -> bytes:
    """Issue a V7 cap from this peer to the top-level controller."""
    if ctx.keypair is None:
        raise RuntimeError(
            "identity handler requires keypair access to issue peer→controller cap",
        )
    granter_identity = create_identity_entity(ctx.keypair)
    granter_hash = granter_identity.compute_hash()
    cap_data: dict[str, Any] = {
        "grants": grants,
        "granter": granter_hash,
        "grantee": controller_hash,
        "created_at": int(time.time() * 1000),
    }
    cap_entity = Entity(type="system/capability/token", data=cap_data)
    cap_hash = cap_entity.compute_hash()
    signature_entity = create_signature_entity(
        ctx.keypair, cap_hash, granter_hash,
    )
    return _emit_signed_cap(
        ctx, cap_entity, granter_identity, signature_entity,
        _local_peer_to_controller_cap_path(controller_hash), operation,
    )


def _revoke_local_peer_to_controller_cap(
    ctx: HandlerContext,
    controller_hash: bytes,
    *,
    operation: str = _OP_PROCESS_ATTESTATION,
) -> bool:
    """Unbind the cap and its V7 invariant-pointer signature.

    Per EXTENSION-IDENTITY v3.6 (I-7): the signature lives at
    `/{local_peer_id}/system/signature/{cap_hash_hex}`, not at the
    v3.5 sibling `{cap_path}/signature`. Defensive: also unbind any
    legacy sibling-path signature so pre-v3.6 binding state cleans up.
    """
    storage_path = _local_peer_to_controller_cap_path(controller_hash)
    pathway = ctx.emit_pathway
    full = pathway.entity_tree.normalize_uri(storage_path)
    cap_hash = pathway.entity_tree.get(full)
    found = cap_hash is not None
    emit_ctx = EmitContext.from_handler_grant(ctx, operation)
    if found:
        # V7 invariant pointer (v3.6) — resolve granter_peer_id from the
        # local keypair (this peer was the granter).
        local_peer_id = ctx.keypair.peer_id if ctx.keypair else None
        if local_peer_id and cap_hash is not None:
            inv_sig_path = invariant_signature_path(local_peer_id, cap_hash)
            inv_sig_full = pathway.entity_tree.normalize_uri(inv_sig_path)
            if pathway.entity_tree.get(inv_sig_full) is not None:
                pathway.delete(inv_sig_path, emit_ctx)
        pathway.delete(storage_path, emit_ctx)
    # Legacy v3.5 sibling cleanup (no-op if the sibling was never written).
    legacy_sig_path = f"{storage_path}/signature"
    legacy_sig_full = pathway.entity_tree.normalize_uri(legacy_sig_path)
    if pathway.entity_tree.get(legacy_sig_full) is not None:
        pathway.delete(legacy_sig_path, emit_ctx)
    return found


_PEER_TO_CONTROLLER_PREFIX = (
    "system/capability/grants/identity/peer-to-controller/"
)


def _cascade_revoke_caps_for_grantee(
    ctx: HandlerContext,
    grantee_hash: bytes,
    *,
    triggering_attestation_hash: bytes,
    operation: str = _OP_REVOKE_ATTESTATION,
) -> tuple[list[bytes], list[Exception]]:
    """V7 PI-13 (Rev 3) — cascade cap cleanup on revocation.

    Walks `system/capability/grants/identity/peer-to-controller/*`, reads
    each cap entity's `grantee`, and unbinds caps whose grantee matches the
    revoked controller's `attested`. Per EXTENSION-IDENTITY v3.6 (I-7) the
    cap signature lives at the V7 invariant pointer
    `/{local_peer_id}/system/signature/{cap_hash_hex}` and is unbound
    alongside the cap entity; the v3.5 sibling `{cap_path}/signature` is
    swept defensively in case legacy state exists.

    Returns (unbound_cap_hashes, errors). On any per-cap failure the cascade
    continues for the rest (PI-5 handler-failure-isolation); after the walk
    completes, the caller emits a recovery_signal controller-event for any
    failures so the controller can resolve the orphaned cap state.

    Per Rev 3 PI-13 framing: this describes ideal-state behavior. In a
    distributed deployment, peers converge through normal message exchange.
    The convergence window is an adversarial surface; deployments wanting
    stricter enforcement MAY layer capability-validation-time re-checks
    (a deployment-policy decision; not enforced here).
    """
    pathway = ctx.emit_pathway
    full_prefix = pathway.entity_tree.normalize_uri(_PEER_TO_CONTROLLER_PREFIX)
    bound_uris = pathway.entity_tree.list_prefix(_PEER_TO_CONTROLLER_PREFIX)
    unbound: list[bytes] = []
    errors: list[Exception] = []
    emit_ctx = EmitContext.from_handler_grant(ctx, operation)
    for full_uri in bound_uris:
        rest = full_uri[len(full_prefix):]
        if "/" in rest:
            continue  # signature sibling — handled below
        cap_hash = pathway.entity_tree.get(full_uri)
        if cap_hash is None:
            continue
        cap_entity = pathway.content_store.get(cap_hash)
        if cap_entity is None:
            continue
        cap_grantee = _normalize_hash((cap_entity.data or {}).get("grantee"))
        if cap_grantee != grantee_hash:
            continue
        # Compute the relative storage path (V7 convention: the path bound
        # in the tree is the absolute one; emit_pathway.delete accepts the
        # relative path).
        cap_storage_path = (
            _PEER_TO_CONTROLLER_PREFIX + rest
        )
        try:
            # V7 invariant-pointer signature path (v3.6, I-7). Compute
            # BEFORE deleting the cap so we still have cap_hash for the
            # hex segment.
            local_peer_id = ctx.keypair.peer_id if ctx.keypair else None
            if local_peer_id:
                inv_sig_path = invariant_signature_path(local_peer_id, cap_hash)
                inv_sig_full = pathway.entity_tree.normalize_uri(inv_sig_path)
                if pathway.entity_tree.get(inv_sig_full) is not None:
                    pathway.delete(inv_sig_path, emit_ctx)
            pathway.delete(cap_storage_path, emit_ctx)
            # Defensive legacy sweep — v3.5 sibling sigs.
            legacy_sig_path = f"{cap_storage_path}/signature"
            legacy_sig_full = pathway.entity_tree.normalize_uri(legacy_sig_path)
            if pathway.entity_tree.get(legacy_sig_full) is not None:
                pathway.delete(legacy_sig_path, emit_ctx)
            unbound.append(cap_hash)
        except Exception as e:
            errors.append(e)

    # Partial-failure tombstone: a recovery_signal event so the controller
    # knows the cascade left orphaned cap state.
    if errors:
        _emit_controller_event(
            ctx,
            event_subkind=EVENT_SUBKIND_RECOVERY_SIGNAL,
            handler_id=HANDLER_ID_REVOKE_ATTESTATION_CASCADE,
            attestation_hash=triggering_attestation_hash,
            attestation_kind=KIND_REVOCATION,
            error_code="cascade_partial_failure",
            error_detail=(
                f"{len(errors)} cap(s) under peer-to-controller/* could not "
                f"be unbound for grantee={grantee_hash.hex()}; "
                f"first error: {errors[0]}"
            ),
            operation=operation,
        )

    return unbound, errors


def _reconcile_stale_peer_to_controller_caps(
    ctx: HandlerContext, live_controller_hashes: set[bytes],
) -> list[bytes]:
    """Per IDENTITY §6 + P-10 (cross-impl supersede semantics): walk the
    `peer-to-controller/{controller_hex}` subtree and revoke any cap
    whose grantee is no longer a live controller. Returns the list of
    controller hashes whose caps were revoked.

    This is the centralized cleanup that runs during `:configure` to
    keep peer-state consistent with current cert chains (rotation,
    retirement, revocation).
    """
    pathway = ctx.emit_pathway
    full_prefix = pathway.entity_tree.normalize_uri(_PEER_TO_CONTROLLER_PREFIX)
    bound_uris = pathway.entity_tree.list_prefix(_PEER_TO_CONTROLLER_PREFIX)
    revoked: list[bytes] = []
    seen_controllers: set[bytes] = set()
    for full_uri in bound_uris:
        # Each cap lives at `.../peer-to-controller/{hex}`; its signature
        # at `.../peer-to-controller/{hex}/signature`. Skip signature URIs
        # (they get cleaned up alongside the cap by the revoker).
        rest = full_uri[len(full_prefix):]
        if "/" in rest:
            continue  # sub-path (e.g., signature) — handled by revoker
        try:
            controller_hash = bytes.fromhex(rest)
        except ValueError:
            continue
        if controller_hash in seen_controllers:
            continue
        seen_controllers.add(controller_hash)
        if controller_hash in live_controller_hashes:
            continue  # still live — leave the cap in place
        if _revoke_local_peer_to_controller_cap(
            ctx, controller_hash, operation=_OP_CONFIGURE,
        ):
            revoked.append(controller_hash)
    return revoked


# ---------------------------------------------------------------------------
# identity-resolved resolver (§6.1) — registered against EXTENSION-QUORUM
# ---------------------------------------------------------------------------


def _make_identity_resolved_resolver(
    ctx_template: HandlerContext,
) -> Callable[..., "bytes | None"]:
    """Returns a closure suitable for QuorumExtension.register_resolver.

    Per QUORUM §5.2 v1.1 (SI-16): the resolver receives `(signer_ref,
    ctx, as_of=None)`. `signer_ref` is treated as a quorum_id (the
    canonical identity handle in identity-resolved mode); we walk to
    the live top-level controller cert at `as_of` and return its
    `attested` (the controller's peer hash). When `as_of` is None,
    returns the current controller.
    """
    def resolve(
        signer_ref: bytes, ctx: HandlerContext,
        as_of: int | None = None,
    ) -> bytes | None:
        cert = walk_cert_chain_to_current_controller(signer_ref, ctx, as_of=as_of)
        if cert is None:
            return None
        return _normalize_hash(cert.data.get("attested"))

    return resolve


def register_identity_resolved_resolver(ctx: HandlerContext) -> bool:
    """Per §6.1: register `identity-resolved` mode against the
    QuorumExtension. Idempotent — if the mode is already registered,
    keeps the existing resolver (per V7 PR-6 multi-registration semantics:
    re-registration of the same logical handler is a no-op; explicit
    replacement requires unregistration, which v2 does not expose)."""
    ext = get_quorum_extension(ctx)
    if ext is None:
        return False
    if ext.lookup_resolver(RESOLUTION_IDENTITY_RESOLVED) is not None:
        return True
    ext.register_resolver(
        RESOLUTION_IDENTITY_RESOLVED,
        _make_identity_resolved_resolver(ctx),
    )
    return True


# ---------------------------------------------------------------------------
# Signature ingestion from envelope.included (§6.2 v3.3 / SI-11)
# ---------------------------------------------------------------------------


def _ingest_envelope_signatures(
    ctx: HandlerContext, params: Any,
) -> dict[str, Any] | None:
    """Per IDENTITY §6.2 v3.3: extract `system/signature` (and supporting
    `system/identity`) entities from `envelope.included` (or, in the
    handler-call shape, an `included` field in params), persist to the
    content store, and bind each signature at its V7 invariant pointer
    path before validation runs.

    Idempotent on identical content_hash; rejects path conflicts (same
    path, different content_hash) with `signature_path_conflict`.

    Returns an error response on conflict, or None on success / no work.
    """
    if not isinstance(params, dict):
        return None
    included = params.get("included")
    if included is None and "data" in params and isinstance(params["data"], dict):
        included = params["data"].get("included")
    if not included or not isinstance(included, (list, dict)):
        return None

    entities = list(included.values()) if isinstance(included, dict) else list(included)

    # First pass: ingest all V7 peer-keypair entities (the resolver
    # needs these to recover signer_peer_id from signature.signer).
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        if ent.get("type") != "system/peer":
            continue
        try:
            entity = Entity.from_dict(ent)
        except (KeyError, TypeError):
            continue
        ctx.emit_pathway.content_store.put(entity)

    # Build a resolver from current tree state (post-ingest) so we can
    # look up signer peer_id for each signature.
    identity_resolver = make_peer_resolver(ctx)

    # Second pass: bind signatures at V7 invariant pointer paths.
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        if ent.get("type") != "system/signature":
            continue
        try:
            sig_entity = Entity.from_dict(ent)
        except (KeyError, TypeError):
            continue
        sig_data = sig_entity.data
        if not isinstance(sig_data, dict):
            continue
        target = _normalize_hash(sig_data.get("target"))
        signer = _normalize_hash(sig_data.get("signer"))
        if target is None or signer is None:
            continue

        # Recover signer_peer_id from the system/peer entity at
        # signature.signer. v7.65 §2: peer_id no longer in data — derive
        # canonical wire form from pubkey.
        identity_data = identity_resolver(signer)
        if identity_data is None:
            continue
        from entity_core.crypto.identity import peer_id_from_identity_entity
        signer_peer_id = peer_id_from_identity_entity({"data": identity_data})
        if not signer_peer_id:
            continue

        sig_hash = sig_entity.compute_hash()
        path = invariant_signature_path(signer_peer_id, target)
        full = ctx.emit_pathway.entity_tree.normalize_uri(path)
        existing = ctx.emit_pathway.entity_tree.get(full)
        if existing is not None and existing != sig_hash:
            return _error(
                400, "signature_path_conflict",
                f"existing signature at {path!r} differs from envelope-ingested",
            )
        if existing == sig_hash:
            continue  # idempotent
        ctx.emit_pathway.content_store.put(sig_entity)
        emit_ctx = EmitContext.from_handler_grant(ctx, "ingest")
        ctx.emit_pathway.emit_hash(path, sig_hash, emit_ctx)

    return None


# ---------------------------------------------------------------------------
# Quorum-publish caching (§5.1, §6 process_attestation)
# ---------------------------------------------------------------------------


def _seed_quorum_publish_cache(att: Entity, ctx: HandlerContext) -> None:
    """When a `quorum-publish` attestation arrives that carries a
    `published_handle`, cache its content hash at
    `contacts/{published_handle_hex}/quorum-publish` (§5.1) so future
    compromise-recovery validations have a trust anchor."""
    props = att.data.get("properties") or {}
    if props.get("kind") != KIND_QUORUM_PUBLISH:
        return
    handle = _normalize_hash(props.get("published_handle"))
    if handle is None:
        return
    emit_ctx = EmitContext.from_handler_grant(ctx, _OP_PROCESS_ATTESTATION)
    ctx.emit_pathway.emit_hash(
        contacts_quorum_publish_path(handle), att.compute_hash(), emit_ctx,
    )


# ---------------------------------------------------------------------------
# Side-effects (cap issuance / revocation / handle cache update)
# ---------------------------------------------------------------------------


def _apply_post_validation_side_effects(
    att: Entity, ctx: HandlerContext, *, operation: str,
) -> None:
    """Apply post-validate state updates per §6 process_attestation.

    Per V7 PI-5: each phase-2 handler runs independently; a handler failure
    MUST NOT propagate or affect other handlers. Failures are captured and
    emitted as controller-event entities (phase 3). Handler ids match the
    §6.3 dispatch table; event_subkind is RECOVERY_SIGNAL when the failure
    leaves orphaned state, FAILURE_OBSERVATION otherwise.
    """
    props = att.data.get("properties") or {}
    kind = props.get("kind")
    att_hash = att.compute_hash()

    if kind == KIND_IDENTITY_CERT and props.get("function") == FUNCTION_CONTROLLER:
        # (identity-cert, controller) → maybe_issue_local_controller_cap
        if not _is_top_level_controller_cert(att, ctx):
            return  # sub-controllers don't get peer→controller caps
        config = _load_peer_config(ctx)
        if config is None:
            return
        grants = config.data.get("controller_grants")
        if not isinstance(grants, list) or not grants:
            return
        controller_hash = _normalize_hash(att.data.get("attested"))
        if controller_hash is None:
            return
        try:
            _issue_local_peer_to_controller_cap(
                ctx, controller_hash, grants, operation=operation,
            )
        except Exception as e:
            # Cap-issue failure: cap not bound → consistent state.
            _emit_controller_event(
                ctx,
                event_subkind=EVENT_SUBKIND_FAILURE_OBSERVATION,
                handler_id=HANDLER_ID_MAYBE_ISSUE_LOCAL_CONTROLLER_CAP,
                attestation_hash=att_hash,
                attestation_kind=kind,
                error_code="cap_issue_failed",
                error_detail=str(e),
                operation=operation,
            )
        return

    if kind == KIND_RETIREMENT:
        # (identity-retirement, *) → revoke_local_caps_for_attested
        target = lookup_target_cert(att, ctx)
        if target is None:
            return
        target_props = target.data.get("properties") or {}
        if (
            target_props.get("kind") != KIND_IDENTITY_CERT
            or target_props.get("function") != FUNCTION_CONTROLLER
        ):
            return
        retired = _normalize_hash(target.data.get("attested"))
        if retired is None:
            return
        try:
            _revoke_local_peer_to_controller_cap(
                ctx, retired, operation=operation,
            )
        except Exception as e:
            # Cap-revocation failure: cap MAY remain bound → potential
            # orphan → recovery_signal (controller MUST act to clear).
            _emit_controller_event(
                ctx,
                event_subkind=EVENT_SUBKIND_RECOVERY_SIGNAL,
                handler_id=HANDLER_ID_REVOKE_LOCAL_CAPS_FOR_ATTESTED,
                attestation_hash=att_hash,
                attestation_kind=kind,
                error_code="cap_revoke_failed",
                error_detail=str(e),
                operation=operation,
            )


# ---------------------------------------------------------------------------
# Handler operations (§6)
# ---------------------------------------------------------------------------


async def handle_configure(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """V7 PI-2 (Rev 3) — :configure as a 5-phase ordered algorithm.

    Phases execute in order; failure at phase N short-circuits the rest.

    Phase 1: validate_inputs — structural only, does NOT reference phase 2
        output. Rejects malformed bindings with 400/404 error codes per
        IDENTITY §6 PR-8.4. Empty bindings is a valid shape (peer bound
        to a quorum with controller caps but no bindings yet).
    Phase 2: enumerate_live_controller_certs(trusts_quorum) AND validate
        binding-chain. Walks attestations targeting trusts_quorum, filters
        live + non-superseded. Then validates each binding's agent_cert
        chains to a live controller (400 binding_controller_not_live).
    Phase 3: verify_each_controller_cert — re-verifies each live cert's
        signature graph as defense-in-depth via identity_verify_cert
        (dispatches K-of-N for top-level, single-sig for sub-controller
        chains). On failure → 403 controller_invalid; configure aborts
        before phase 4 (no caps issued, no peer-config persisted).
    Phase 4: issue_local_caps — mint local-peer→controller caps + sign +
        bind at PI-9 path with PI-10 signature sibling. Reconciles stale
        peer→controller caps whose grantee is no longer live.
    Phase 5: register_bindings — persist peer-config (with bindings).
    """
    data = _params_data(params)
    trusts_quorum = _normalize_hash(data.get("trusts_quorum"))
    if trusts_quorum is None:
        return _error(400, "invalid_params", "trusts_quorum is required")

    if not is_quorum_id(trusts_quorum, ctx):
        return _error(
            404, "trusts_quorum_not_found",
            "no system/quorum entity bound at canonical path for trusts_quorum",
        )

    grants_raw = data.get("controller_grants") or []
    if not isinstance(grants_raw, list):
        return _error(
            400, "invalid_params", "controller_grants must be a list",
        )

    bindings = data.get("bindings")
    if bindings is not None and not isinstance(bindings, list):
        return _error(400, "invalid_params", "bindings must be a list")

    # ----- Phase 1: validate_inputs (structural) -----
    if bindings:
        err = _validate_bindings_structural(ctx, bindings)
        if err is not None:
            return err

    # ----- Phase 2: enumerate_live_controller_certs + binding-chain ----
    live_certs, live_controller_hashes = _enumerate_live_controller_certs(
        trusts_quorum, ctx,
    )
    if bindings:
        err = _validate_bindings_against_live_controllers(
            ctx, bindings, live_controller_hashes,
        )
        if err is not None:
            return err

    # ----- Phase 3: verify_each_controller_cert ----
    # Per Rev 3 PI-2 phase 3: re-verify each live controller cert's
    # signature graph as defense-in-depth against tree-corruption races
    # (the cert was already validated at arrival via :process_attestation,
    # but :configure is the convergence point that issues local caps off
    # these certs — verify before trusting). identity_verify_cert
    # dispatches per topology: K-of-N for top-level controllers, single-sig
    # for sub-controller chains. A controller cert that fails verification
    # aborts :configure with 403 controller_invalid (no caps issued, no
    # peer-config persisted).
    for cert in live_certs:
        ok, reason = identity_verify_cert(cert, ctx)
        if not ok:
            return _error(
                403, "controller_invalid",
                f"controller cert {cert.compute_hash().hex()} failed "
                f"signature verification: {reason or 'unspecified'}",
            )

    # ----- Phase 4: issue_local_caps (PI-9 path + PI-10 signature) ----
    # Register identity-resolved resolver against quorum extension before
    # cap issuance so any in-flight resolver lookups during emit see the
    # mode registered.
    register_identity_resolved_resolver(ctx)

    issued_caps: list[dict[str, Any]] = []
    if grants_raw:
        # Per EXTENSION-IDENTITY v3.7 §6.0a Phase 4 (A.4):
        # issue ONE local-peer→controller cap per **distinct verified
        # controller**, NOT per attestation. Multiple controller-cert
        # attestations may target the same controller peer (e.g., quorum
        # rotation, re-attestation); deduping by `attested` ensures the
        # cap-issuance count is bounded by the number of live controllers,
        # not by the attestation cardinality. Closes workbench
        # PERSISTENCE-FEEDBACK Finding 1 Q1.
        seen_controllers: set[bytes] = set()
        for cert in live_certs:
            controller_hash = _normalize_hash(cert.data.get("attested"))
            if controller_hash is None:
                continue
            if controller_hash in seen_controllers:
                continue
            seen_controllers.add(controller_hash)
            try:
                cap_hash = _issue_local_peer_to_controller_cap(
                    ctx, controller_hash, list(grants_raw),
                )
            except RuntimeError as e:
                return _error(500, "cap_issue_failed", str(e))
            cap_path = _local_peer_to_controller_cap_path(controller_hash)
            issued_caps.append({
                "controller_hex": encode_hash_segment(controller_hash),
                "cap_hash": cap_hash,
                "cap_path": ctx.emit_pathway.entity_tree.normalize_uri(cap_path),
            })

    # Reconcile: revoke any peer→controller cap whose grantee is not a
    # live controller. This handles supersede / retirement chains where
    # the predecessor cap would otherwise persist past the rotation.
    _reconcile_stale_peer_to_controller_caps(ctx, live_controller_hashes)

    # ----- Phase 5: register_bindings (persist peer-config) ----
    metadata = data.get("metadata")
    config_hash = _persist_peer_config(
        ctx,
        trusts_quorum=trusts_quorum,
        controller_grants=list(grants_raw),
        bindings=bindings,
        metadata=metadata,
    )

    peer_config_path_abs = ctx.emit_pathway.entity_tree.normalize_uri(
        PEER_CONFIG_PATH,
    )
    # Result per Go's IdentityConfigureResultData (cross-impl): caps list
    # carries (controller_hex, cap_hash, cap_path) per Rev 3 PI-2 result
    # shape. Backward-compat: legacy `local_peer_to_controller_caps`
    # remains as the flat list of cap hashes for clients on the older
    # shape.
    return _ok(
        "system/identity/configure-result",
        {
            "peer_config_path": peer_config_path_abs,
            "caps": issued_caps,
            "local_peer_to_controller_caps": [c["cap_hash"] for c in issued_caps],
            "peer_config": config_hash,
            "trusts_quorum": trusts_quorum,
        },
    )


async def handle_create_quorum(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per §6: delegate to QUORUM:create (substrate); identity does not
    duplicate the quorum-creation logic. Caller passes the quorum
    parameters; the identity handler returns the quorum_id and stored
    path. Optionally seeds peer-config.trusts_quorum if no peer-config
    exists yet (bootstrap convenience)."""
    from entity_handlers.quorum import quorum_handler  # local import; avoids cycle

    data = _params_data(params)
    sub_result = await quorum_handler(
        "system/quorum", "create", {"data": data}, ctx,
    )
    if sub_result["status"] != 200:
        return sub_result
    quorum_id = sub_result["result"]["data"]["quorum_id"]

    # Bootstrap: if no peer-config yet, seed trusts_quorum.
    if _load_peer_config(ctx) is None:
        bootstrap_grants = data.get("controller_grants") or []
        _persist_peer_config(
            ctx,
            trusts_quorum=quorum_id,
            controller_grants=list(bootstrap_grants) if isinstance(bootstrap_grants, list) else [],
        )

    return _ok(
        "system/identity/create-quorum-result",
        {"quorum_id": quorum_id},
    )


async def _handle_attestation_write(
    ctx: HandlerContext, params: dict[str, Any], *, supersede: bool,
) -> dict[str, Any]:
    """Shared body for create_attestation and supersede_attestation.

    Per EXTENSION-ATTESTATION §6.1 / EXTENSION-IDENTITY §6: params carry
    flat top-level fields `{attesting, attested, properties, supersedes?,
    not_before?, expires_at?}`. There is no envelope-wrapped
    `{attestation: <entity>}` form."""
    from entity_handlers.attestation import make_attestation  # avoid cycle

    # Per IDENTITY §6.2 v3.3 / SI-11: ingest signatures from envelope.included
    # before validation runs. Path conflicts are reported as 400.
    err = _ingest_envelope_signatures(ctx, params)
    if err is not None:
        return err

    data = _params_data(params)
    attesting = _normalize_hash(data.get("attesting"))
    attested = _normalize_hash(data.get("attested"))
    properties = data.get("properties")
    supersedes_raw = data.get("supersedes")
    supersedes = (
        _normalize_hash(supersedes_raw) if supersedes_raw is not None else None
    )
    not_before = data.get("not_before")
    expires_at = data.get("expires_at")

    if attesting is None:
        return _error(400, "invalid_params", "attesting is required")
    if attested is None:
        return _error(400, "invalid_params", "attested is required")
    if not isinstance(properties, dict):
        return _error(400, "invalid_params", "properties must be a map")
    if supersede and supersedes is None:
        return _error(
            400, "invalid_params",
            "supersede_attestation requires supersedes",
        )

    kind = properties.get("kind")
    if kind != KIND_IDENTITY_CERT and kind not in IDENTITY_LIFECYCLE_KINDS:
        return _error(400, "unknown_kind", f"unknown identity kind {kind!r}")

    # Structural validation (mode REQUIRED on all identity-certs; etc.)
    if kind == KIND_IDENTITY_CERT:
        function = properties.get("function")
        if not isinstance(function, str) or not function:
            return _error(400, "invalid_function", "function is required")
        mode = properties.get("mode")
        if mode not in ALL_MODES:
            return _error(400, "invalid_mode", f"mode {mode!r} not valid")
        if mode == MODE_PER_RELATIONSHIP:
            if _normalize_hash(properties.get("contact_id")) is None:
                return _error(
                    400, "missing_contact_id",
                    "contact_id is required for mode=per-relationship",
                )
        # V7 PI-11 — per-function valid-modes enforcement (§4.2 table).
        valid_modes_err = _validate_function_mode(
            function, mode, attesting, ctx,
        )
        if valid_modes_err is not None:
            return valid_modes_err

    if kind in IDENTITY_LIFECYCLE_KINDS:
        if _normalize_hash(properties.get("target_cert")) is None:
            return _error(
                400, "missing_target_cert",
                "target_cert is required on lifecycle attestations",
            )

    # Per V7 PI-1 (audit I-1 / R-8'): when `supersede=True`, only kinds in
    # REBIND_KINDS may legitimately rebind `attesting`/`attested` (rotation
    # case — controller key replacement changes the chain root). Other kinds
    # follow substrate `:supersede` semantics: attesting/attested MUST equal
    # the predecessor's (same-subject, same-attester supersession). Adding a
    # kind to the list is a future spec amendment.
    if supersede and supersedes is not None:
        predecessor = ctx.emit_pathway.content_store.get(supersedes)
        if predecessor is None or predecessor.type != ATTESTATION_TYPE:
            return _error(
                404, "predecessor_not_found",
                "supersedes hash does not resolve to a system/attestation",
            )
        pred_kind = (predecessor.data.get("properties") or {}).get("kind")
        if pred_kind not in REBIND_KINDS:
            pred_attesting = _normalize_hash(predecessor.data.get("attesting"))
            pred_attested = _normalize_hash(predecessor.data.get("attested"))
            if attesting != pred_attesting or attested != pred_attested:
                return _error(
                    400, "supersede_attesting_attested_mismatch",
                    "non-rebind kinds must preserve predecessor attesting/attested "
                    f"(predecessor.kind={pred_kind!r})",
                )

    att = make_attestation(
        attesting=attesting,
        attested=attested,
        properties=properties,
        supersedes=supersedes,
        not_before=not_before if isinstance(not_before, int) else None,
        expires_at=expires_at if isinstance(expires_at, int) else None,
    )
    props = properties

    # Persist to content store first so signature-lookup over the entity
    # hash works.
    ctx.emit_pathway.content_store.put(att)

    # Distinct result type per op aligns with the v3.3 manifest naming
    # surfaced in the v3.3 cross-impl review.
    result_type = (
        "system/identity/supersede-attestation-result"
        if supersede
        else "system/identity/create-attestation-result"
    )

    # Resolve canonical storage path. Embedded mode → no tree write.
    expected_path = canonical_storage_path(att, ctx)
    if expected_path is None:
        if (
            kind == KIND_IDENTITY_CERT
            and props.get("function") == FUNCTION_AGENT
            and props.get("mode") == MODE_EMBEDDED
        ):
            # Per IDENTITY §4.2: embedded mode lives inline in cap envelopes,
            # not in the tree. Result carries `embedded_attestation` (the
            # inline AttestationData — flat fields, NOT the wrapped Entity)
            # and `attestation_hash = ZERO_HASH` to signal "no tree write."
            # Go's CBOR decoder reads `embedded_attestation` directly as
            # AttestationData struct; returning the Entity wrapper hides
            # attesting/attested under a `data` key and breaks decode.
            return _ok(
                result_type,
                {
                    "attestation_hash": ZERO_HASH,
                    "embedded_attestation": att.data,
                },
            )
        return _error(
            400, "no_canonical_path",
            "could not resolve canonical path for attestation",
        )

    # Resource-target check (path-as-resource per V7 §3.2).
    rt = _resource_target(ctx)
    if rt is not None:
        rt_norm = ctx.emit_pathway.entity_tree.normalize_uri(rt)
        ep_norm = ctx.emit_pathway.entity_tree.normalize_uri(expected_path)
        if rt_norm != ep_norm:
            return _error(
                400, "resource_target_mismatch",
                f"resource target {rt!r} does not match canonical path {expected_path!r}",
            )

    # §9.2 op-confinement (structural; no-op when no signatures are bound).
    err_code = _check_op_confinement(att, expected_path, ctx)
    if err_code is not None:
        return _error(400, err_code, "operational-key signature on public/ path")

    # Per EXTENSION-ATTESTATION §6.1: the create handler does NOT validate
    # the signature graph or authority — those are the consumer's domain
    # (`:process_attestation`, `:configure`, `:verify`). Locally-created
    # attestations are bound unconditionally so callers can sign-after-create
    # (the natural ordering, since signatures target the attestation hash).
    # Cross-peer arrivals still fail-closed via `:process_attestation`.
    emit_ctx = EmitContext.from_handler_grant(
        ctx, _OP_SUPERSEDE_ATTESTATION if supersede else _OP_CREATE_ATTESTATION,
    )
    ctx.emit_pathway.emit(expected_path, att, emit_ctx)

    # Local state-update side effects (cap issue/revoke). Safe pre-validation
    # because these caps are local-only — if the cert later proves invalid,
    # consumers (`:process_attestation`) will trigger the corresponding
    # revocations.
    _apply_post_validation_side_effects(
        att, ctx,
        operation=_OP_SUPERSEDE_ATTESTATION if supersede else _OP_CREATE_ATTESTATION,
    )

    return _ok(
        result_type,
        {
            "attestation_hash": att.compute_hash(),
            "kind": kind,
            "stored_at": expected_path,
        },
    )


def _extract_attestation(raw: Any) -> Entity | None:
    if isinstance(raw, Entity):
        return raw
    if isinstance(raw, dict):
        try:
            return Entity.from_dict(raw)
        except (KeyError, TypeError):
            return None
    return None


async def handle_create_attestation(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    return await _handle_attestation_write(ctx, params, supersede=False)


async def handle_supersede_attestation(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    return await _handle_attestation_write(ctx, params, supersede=True)


async def handle_revoke_attestation(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per EXTENSION-IDENTITY §6 / TV-REVOKE-ATTESTATION-RESULT-HASH:
    mint a `system/attestation` entity with `kind=revocation` targeting
    the attestation identified by `target_hash`. The revocation entity
    is bound at the same audience-tier path as the target (via
    `canonical_storage_path`'s revocation rule that resolves the tier
    from the target). The result carries the revocation entity's
    content_hash as `revocation_hash` — downstream consumers
    (re-signing, liveness checks, etc.) need this hash.

    The target's tree binding is NOT removed — its liveness is
    determined by the chain walk (`_is_self_revoked`), which finds the
    minted revocation entity targeting it.

    Target may be identified by:
    - `params.target_hash`: the attestation's content hash (canonical
      wire form per EXTENSION-ATTESTATION §6.3).
    - `ctx.resource_targets[0]` or `params.path`: the canonical storage
      path (Python-internal convenience)."""
    from entity_handlers.attestation import KIND_REVOCATION, make_attestation

    data = _params_data(params)
    reason = data.get("reason")

    # Resolve the target entity (via target_hash or path).
    target_hash = _normalize_hash(data.get("target_hash"))
    if target_hash is not None:
        att = ctx.emit_pathway.content_store.get(target_hash)
        if att is None or att.type != ATTESTATION_TYPE:
            return _error(
                404, "attestation_not_found",
                "no system/attestation entity in content store at target_hash",
            )
    else:
        path = _resource_target(ctx)
        if path is None:
            path = data.get("path")
            if not isinstance(path, str):
                return _error(
                    400, "invalid_params",
                    "target_hash or resource target (attestation path) is required",
                )
        full = ctx.emit_pathway.entity_tree.normalize_uri(path)
        h = ctx.emit_pathway.entity_tree.get(full)
        if h is None:
            return _error(404, "attestation_not_found", "no entity bound at path")
        att = ctx.emit_pathway.content_store.get(h)
        if att is None or att.type != ATTESTATION_TYPE:
            return _error(
                400, "not_an_attestation", "bound entity is not an attestation",
            )
        target_hash = att.compute_hash()

    # Build the revocation attestation. `attesting` matches the target's
    # `attesting` so the substrate's self-revocation predicate fires
    # (`_is_self_revoked` requires same-attesting); `attested` points at
    # the target so `find_revocations_for(target_hash)` finds it.
    rev_attesting = _normalize_hash(att.data.get("attesting"))
    if rev_attesting is None:
        return _error(
            400, "missing_target_attesting",
            "target attestation has no `attesting` field",
        )
    rev_props: dict[str, Any] = {
        "kind": KIND_REVOCATION,
        "target_cert": target_hash,
    }
    if isinstance(reason, str) and reason:
        rev_props["reason"] = reason

    rev_att = make_attestation(
        attesting=rev_attesting,
        attested=target_hash,
        properties=rev_props,
    )
    revocation_hash = rev_att.compute_hash()
    ctx.emit_pathway.content_store.put(rev_att)

    # The revocation lives at the same audience-tier path as the target,
    # leaf-keyed by the revocation's own hash (per §5.3 path resolution
    # for KIND_REVOCATION).
    rev_path = canonical_storage_path(rev_att, ctx)
    if rev_path is None:
        return _error(
            400, "no_canonical_path",
            "could not resolve canonical path for the revocation attestation",
        )
    emit_ctx = EmitContext.from_handler_grant(ctx, _OP_REVOKE_ATTESTATION)
    ctx.emit_pathway.emit(rev_path, rev_att, emit_ctx)

    # V7 PI-13 (Rev 3) — cascade cap cleanup. When the revoked target is
    # a controller cert, walk the peer-to-controller/* subtree and unbind
    # any cap whose grantee matches the revoked controller's `attested`.
    # Cap signature siblings unbind alongside; partial-failure recovery is
    # captured via a recovery_signal controller-event.
    target_props = att.data.get("properties") or {}
    if (
        target_props.get("kind") == KIND_IDENTITY_CERT
        and target_props.get("function") == FUNCTION_CONTROLLER
    ):
        controller_hash = _normalize_hash(att.data.get("attested"))
        if controller_hash is not None:
            _cascade_revoke_caps_for_grantee(
                ctx,
                controller_hash,
                triggering_attestation_hash=revocation_hash,
                operation=_OP_REVOKE_ATTESTATION,
            )

    return _ok(
        "system/identity/revoke-attestation-result",
        {
            # Cross-impl: `revocation_hash` is the canonical Go-aligned
            # field; downstream callers re-sign / verify against it.
            "revocation_hash": revocation_hash,
            "kind": target_props.get("kind"),
            "stored_at": rev_path,
        },
    )


def _path_for_mode(
    mode: str, content_hash: bytes, contact_id: bytes | None = None,
) -> str | None:
    """Per IDENTITY §4.2a: resolve a cert's canonical storage path from the
    target audience-tier mode (NOT from the entity's intrinsic
    properties.mode — `:publish_attestation` chooses the audience tier
    explicitly via the `new_mode` parameter and rebinds the same entity
    there)."""
    if mode == MODE_INTERNAL:
        return cert_internal_path(content_hash)
    if mode == MODE_PUBLIC:
        return cert_public_path(content_hash)
    if mode == MODE_PER_RELATIONSHIP:
        if contact_id is None:
            return None
        return cert_relationship_path(contact_id, content_hash)
    if mode == MODE_EMBEDDED:
        return None  # no tree write
    return None


async def handle_publish_attestation(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per V7 PI-3 — :publish_attestation as a 3-phase MOVE with named
    contracts.

    Phase 1: validate_input
      - target_mode ∈ {internal, public, per-relationship}; embedded NOT
        movable (400 invalid_target_mode).
      - attestation must be kind=identity-cert + function=agent
        (400 not_publishable_kind otherwise).
    Phase 2: compute_paths
      - old_path = canonical_storage_path(att, current mode)
      - new_path = canonical_storage_path(att, target_mode)
    Phase 3: move (tombstone-style recovery per Rev 3 PI-3)
      - bind(new_path); on failure surface error (no orphan)
      - unbind(old_path); on failure SHOULD retry once; on retry failure
        emit a recovery_signal controller-event entity (per PI-5) — entity
        remains bound at BOTH paths until the controller acts.
    """
    data = _params_data(params)
    att_hash = _normalize_hash(data.get("attestation_hash"))
    new_mode = data.get("new_mode")
    contact_id = _normalize_hash(data.get("contact_id")) if data.get("contact_id") else None

    # Phase 1: validate_input.
    if att_hash is None:
        return _error(400, "invalid_params", "attestation_hash is required")
    if new_mode == MODE_EMBEDDED:
        # Per PI-3: embedded is NOT a movable target. The previous behavior
        # returned an inline embedded result here; that conflated "publish to
        # embedded mode" with "create_attestation in embedded mode."
        return _error(
            400, "invalid_target_mode",
            "embedded is not a movable target_mode for :publish_attestation",
        )
    if new_mode not in (MODE_INTERNAL, MODE_PUBLIC, MODE_PER_RELATIONSHIP):
        return _error(400, "invalid_params", f"invalid new_mode {new_mode!r}")

    att = ctx.emit_pathway.content_store.get(att_hash)
    if att is None or att.type != ATTESTATION_TYPE:
        return _error(404, "attestation_not_found", "attestation not in content store")

    props = att.data.get("properties") or {}
    if props.get("kind") != KIND_IDENTITY_CERT:
        return _error(
            400, "not_publishable_kind",
            ":publish_attestation only applies to identity-cert",
        )
    if props.get("function") != FUNCTION_AGENT:
        return _error(
            400, "not_publishable_kind",
            ":publish_attestation only applies to agent certs",
        )

    if new_mode == MODE_PER_RELATIONSHIP and contact_id is None:
        return _error(
            400, "missing_contact_id",
            "contact_id required for mode=per-relationship",
        )

    # Phase 2: compute_paths.
    new_path = _path_for_mode(new_mode, att.compute_hash(), contact_id=contact_id)
    if new_path is None:
        return _error(400, "no_canonical_path", "could not resolve new path")
    # Resolve the OLD binding via the entity's intrinsic canonical path.
    old_path = canonical_storage_path(att, ctx)

    # Phase 3: move.
    emit_ctx = EmitContext.from_handler_grant(ctx, _OP_PUBLISH_ATTESTATION)
    try:
        ctx.emit_pathway.emit(new_path, att, emit_ctx)
    except Exception as e:
        # bind(new_path) failed: old path remains bound. No orphan; no
        # tombstone needed. Surface the error.
        return _error(500, "bind_failed", str(e))

    # Unbind old, with a single retry, per PI-3 SHOULD-retry.
    if old_path is not None and old_path != new_path:
        old_full = ctx.emit_pathway.entity_tree.normalize_uri(old_path)
        if ctx.emit_pathway.entity_tree.get(old_full) == att.compute_hash():
            unbind_err: Exception | None = None
            for _attempt in range(2):
                try:
                    ctx.emit_pathway.delete(old_path, emit_ctx)
                    unbind_err = None
                    break
                except Exception as e:
                    unbind_err = e
            if unbind_err is not None:
                # Retry failed: entity bound at BOTH paths. Emit a
                # recovery_signal tombstone (per PI-5 retention: MUST NOT
                # be pruned until cleared) so the controller can resolve
                # the orphaned binding manually.
                _emit_controller_event(
                    ctx,
                    event_subkind=EVENT_SUBKIND_RECOVERY_SIGNAL,
                    handler_id=HANDLER_ID_PUBLISH_ATTESTATION,
                    attestation_hash=att.compute_hash(),
                    attestation_kind=KIND_IDENTITY_CERT,
                    error_code="unbind_failed_after_retry",
                    error_detail=(
                        f"orphaned binding: entity bound at both "
                        f"{old_path!r} and {new_path!r}; {unbind_err}"
                    ),
                    operation=_OP_PUBLISH_ATTESTATION,
                )

    new_path_abs = ctx.emit_pathway.entity_tree.normalize_uri(new_path)
    return _ok(
        "system/identity/publish-attestation-result",
        {
            # Per Go's IdentityPublishAttestationResultData (cross-impl):
            # `new_path` is absolute (V7 §1.4) and contains the SAME
            # `attestation_hash` segment as the input — the entity is
            # unchanged across the move.
            "new_path": new_path_abs,
            "attestation_hash": att.compute_hash(),
            "mode": new_mode,
            "stored_at": new_path,
        },
    )


async def handle_process_attestation(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per IDENTITY §6.3 v3.3: convergence point for any identity-context
    attestation entering the local tree at the named subtrees (regardless
    of source — sync, local create, L0, envelope.included).

    Three-phase algorithm:
    1. Validate via identity_verify_cert.
    2a. On validation failure, fail-closed unbind the path (per SI-10).
    2b. On success, dispatch side effects in deterministic order per kind.
    3. quorum-publish caching for arriving quorum-publish attestations.
    """
    # Per IDENTITY §6.2 v3.3 / SI-11: ingest envelope signatures before
    # validation.
    err = _ingest_envelope_signatures(ctx, params)
    if err is not None:
        return err

    data = _params_data(params)
    raw = data.get("attestation") or data
    att = _extract_attestation(raw)
    if att is None:
        return _error(400, "invalid_params", "attestation is required")
    if att.type != ATTESTATION_TYPE:
        return _error(400, "wrong_entity_type", "expected system/attestation")

    # Path-as-resource per V7 §3.2: process_attestation operates on the
    # path where the attestation is bound. The path is required so we
    # can fail-closed-unbind on validation failure.
    path = _resource_target(ctx)
    if path is None:
        # Backward-compat: accept `path` in params for callers that
        # haven't switched to resource_targets yet.
        path = data.get("path")
        if not isinstance(path, str):
            path = None

    props = att.data.get("properties") or {}
    kind = props.get("kind")

    # Quorum-publish: validate via QUORUM, seed cache; on failure, unbind.
    if kind == KIND_QUORUM_PUBLISH:
        accepted = process_quorum_attestation(att, ctx)
        if not accepted:
            _fail_closed_unbind(ctx, path)
            return _error(
                403, "quorum_publish_validation_failed",
                "quorum-publish failed substrate validation",
            )
        _seed_quorum_publish_cache(att, ctx)
        return _ok(
            "system/protocol/status",
            {"status": 200, "kind": kind, "cached": True},
        )

    # Quorum-update: validate via QUORUM; on failure, unbind.
    from entity_handlers.quorum import KIND_QUORUM_UPDATE
    if kind == KIND_QUORUM_UPDATE:
        accepted = process_quorum_attestation(att, ctx)
        if not accepted:
            _fail_closed_unbind(ctx, path)
            return _error(
                403, "quorum_update_validation_failed",
                "quorum-update failed substrate validation",
            )
        return _ok(
            "system/protocol/status", {"status": 200, "kind": kind},
        )

    # Identity-context attestations.
    if kind != KIND_IDENTITY_CERT and kind not in IDENTITY_LIFECYCLE_KINDS:
        return _error(400, "not_identity_attestation", f"kind {kind!r} not handled")

    valid, reason = identity_verify_cert(att, ctx)
    if not valid:
        # Phase 2a — fail-closed unbind on validation failure (§6.3).
        _fail_closed_unbind(ctx, path)
        return _error(403, "identity_verification_failed", reason or "")

    # Phase 2b — side-effect dispatch in deterministic order per kind.
    _apply_post_validation_side_effects(
        att, ctx, operation=_OP_PROCESS_ATTESTATION,
    )

    return _ok(
        "system/protocol/status",
        {"status": 200, "kind": kind, "attestation": att.compute_hash()},
    )


def _fail_closed_unbind(ctx: HandlerContext, path: str | None) -> None:
    """Per IDENTITY §6.3 v3.3: on validation failure, the attestation
    MUST be unbound from the tree. No-op when path is unknown (caller
    couldn't supply one — the entity remains in content store but isn't
    tree-bound; nothing to unbind)."""
    if path is None:
        return
    full = ctx.emit_pathway.entity_tree.normalize_uri(path)
    if ctx.emit_pathway.entity_tree.get(full) is None:
        return  # already unbound or never bound
    emit_ctx = EmitContext.from_handler_grant(ctx, _OP_PROCESS_ATTESTATION)
    ctx.emit_pathway.delete(path, emit_ctx)


async def identity_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Dispatch `system/identity:*` operations per EXTENSION-IDENTITY v3.2 §6."""
    if operation == _OP_CONFIGURE:
        return await handle_configure(ctx, params)
    if operation == _OP_CREATE_QUORUM:
        return await handle_create_quorum(ctx, params)
    if operation == _OP_CREATE_ATTESTATION:
        return await handle_create_attestation(ctx, params)
    if operation == _OP_SUPERSEDE_ATTESTATION:
        return await handle_supersede_attestation(ctx, params)
    if operation == _OP_REVOKE_ATTESTATION:
        return await handle_revoke_attestation(ctx, params)
    if operation == _OP_PUBLISH_ATTESTATION:
        return await handle_publish_attestation(ctx, params)
    if operation == _OP_PROCESS_ATTESTATION:
        return await handle_process_attestation(ctx, params)
    return _error(
        501, "unsupported_operation",
        f"identity handler does not support {operation!r}",
    )


__all__ = [
    "IDENTITY_HANDLER_PATTERN",
    # Identity-owned types
    "PEER_CONFIG_TYPE",
    "IDENTITY_BINDING_TYPE",
    # Path roots
    "IDENTITY_ROOT",
    "INTERNAL_ROOT",
    "PUBLIC_ROOT",
    "RELATIONSHIPS_ROOT",
    "CONTACTS_ROOT",
    "PEER_CONFIG_PATH",
    "CERT_SEGMENT",
    "QUORUM_PUBLISH_LEAF",
    # Kinds
    "KIND_IDENTITY_CERT",
    "KIND_ROTATION_HANDOFF",
    "KIND_ROTATION_RECOVERY",
    "KIND_RETIREMENT",
    "IDENTITY_LIFECYCLE_KINDS",
    # Functions / modes
    "FUNCTION_CONTROLLER",
    "FUNCTION_AGENT",
    "FUNCTION_IDENTIFIER",
    "VALID_FUNCTIONS",
    "MODE_INTERNAL",
    "MODE_PUBLIC",
    "MODE_PER_RELATIONSHIP",
    "MODE_EMBEDDED",
    "ALL_MODES",
    "RESOLUTION_IDENTITY_RESOLVED",
    # Path helpers
    "encode_hash_segment",
    "cert_internal_path",
    "cert_public_path",
    "cert_relationship_path",
    "contacts_quorum_publish_path",
    "canonical_storage_path",
    # Identity helpers
    "valid_functions",
    "identity_lifecycle_kinds",
    "lookup_target_cert",
    "identity_confers_function",
    "walk_cert_chain_to_current_controller",
    "resolve_controller_for_grants",
    # Validators
    "identity_topology_for",
    "identity_is_quorum_link",
    "identity_is_authorized_revoker",
    "identity_verify_cert",
    # Resolver
    "register_identity_resolved_resolver",
    # Handler
    "identity_handler",
    "handle_configure",
    "handle_create_quorum",
    "handle_create_attestation",
    "handle_supersede_attestation",
    "handle_revoke_attestation",
    "handle_publish_attestation",
    "handle_process_attestation",
]
