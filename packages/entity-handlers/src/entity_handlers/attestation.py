"""EXTENSION-ATTESTATION v1.1 — signed-graph substrate primitive.

Defines the edge type in the system's signed graph (`system/attestation`)
plus the generic graph operations consumers compose into their own
validators. The only `properties.kind` value owned by this primitive is
`"revocation"`; all other kinds are consumer-defined.

v1.1 absorbs cross-impl-feedback batch
(`PROPOSAL-IDENTITY-V3.2-MIGRATION-FIXES.md`):
- SI-1: substrate stays signature-agnostic (TV-A8 expected = "A").
- SI-2: transitive supersession (predecessor revival when descendant is
  revoked is intentional).
- SI-7: path-as-resource MUST on `:create` / `:supersede` / `:revoke`.
- SI-8: `walk_attesting_chain` chain[-1] termination semantics pinned.
- SI-17: `IdentityResolver` → `PeerResolver`.

Three-parallel-mechanisms invariant (§10 v1.1): three structurally
distinct entity-validation classes — V7 capability tokens (validated by
`verify_capability_chain`), `system/attestation` entities (validated by
EXTENSION-ATTESTATION helpers + consumer rules), `system/quorum`
entities (validated by EXTENSION-QUORUM's `verify_k_of_n_signatures`).
Cap-chain verification MAY read attestation state via the
`IdentityBindingChecker` hook (read-only, for grantee-binding lookup);
cap-chain verification MUST NOT validate attestations as caps.
Attestation validation MUST NOT call `verify_capability_chain`.
"""

from __future__ import annotations

from typing import Any, Callable, Iterator

from entity_core.capability.delegation import find_signature_by_signer
from entity_core.crypto.signing import public_key_from_bytes, verify_signature
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_handlers._common import (
    error_response as _error,
    normalize_hash as _normalize_hash,
    now_ms as _now_ms,
    ok_response as _ok,
    params_data as _params_data,
    resource_target as _resource_target,
)


# -- Constants --------------------------------------------------------------

ATTESTATION_TYPE = "system/attestation"
ATTESTATION_HANDLER_PATTERN = "system/attestation"

# The only kind owned by this primitive (§3.3). All other kinds are
# consumer-defined.
KIND_REVOCATION = "revocation"

# Default chain-walk depth bound (§5.1 / §9.2).
DEFAULT_MAX_DEPTH = 32

# Operations
_OP_CREATE = "create"
_OP_SUPERSEDE = "supersede"
_OP_REVOKE = "revoke"
_OP_VERIFY = "verify"


# -- Type aliases -----------------------------------------------------------

# Resolves a peer content hash to the corresponding `system/peer` entity
# data dict, or None when unresolvable. Per V7 PR-2: function returns the
# entity (not the pubkey directly); the caller reads .public_key from it.
PeerResolver = Callable[[bytes], "dict[str, Any] | None"]

# Predicate used by find_attestations_* lookups.
AttestationPredicate = Callable[[Entity, HandlerContext], bool]

# Terminate predicate for walk_attesting_chain (§5.1).
TerminatePredicate = Callable[[Entity, HandlerContext], bool]

# Authorization-finder hook for walk_attesting_chain (§5.1).
FindAuthorizingFn = Callable[[bytes, HandlerContext], "Entity | None"]


# =============================================================================
# Identity / signature resolution
# =============================================================================


def _build_identity_index(ctx: HandlerContext) -> dict[bytes, dict[str, Any]]:
    """Build a hash→data map of V7 peer-keypair entities (`system/peer`)
    for the Ed25519 resolver.

    Per IDENTITY v3.3 §6.2 (SI-11), peer-keypair entities arriving in
    `envelope.included` are persisted to the content store via
    `put_content_only` (no tree mapping) at the dispatcher layer. They
    must therefore be discoverable from the content store directly,
    not only from tree-bound entities. We index BOTH tree-bound and
    content-only entities so the resolver finds dispatcher-ingested
    peer-keypair entities even before any tree binding exists for them.
    """
    out: dict[bytes, dict[str, Any]] = {}
    # Tree-bound peer-keypair entities.
    for _uri, h in ctx.emit_pathway.entity_tree.all_bindings():
        entity = ctx.emit_pathway.content_store.get(h)
        if entity is None or entity.type != "system/peer":
            continue
        out[h] = entity.data
    # Content-store-only peer-keypair entities (dispatcher-ingested per SI-11).
    # iter_all yields (hash, entity) pairs.
    for h, entity in ctx.emit_pathway.content_store.iter_all():
        if entity.type != "system/peer":
            continue
        out.setdefault(h, entity.data)
    return out


def make_peer_resolver(ctx: HandlerContext) -> PeerResolver:
    """Build a PeerResolver from the current tree state.

    Per V7 PR-1 (system/identity → system/peer): the lookup is from
    peer_hash to peer's public key via the V7 `system/peer` entity. The
    "identity" in v3.2/v3.3 is a graph rooted at a quorum (EXTENSION-IDENTITY
    layer), not the V7 keypair entity — the substrate-attestation resolver
    operates over the V7 layer only.
    """
    index = _build_identity_index(ctx)

    def resolve(signer_hash: bytes) -> dict[str, Any] | None:
        return index.get(signer_hash)

    return resolve


def collect_signatures_for(
    ctx: HandlerContext, target_hash: bytes,
) -> list[dict[str, Any]]:
    """Scan tree-bound `system/signature` entities targeting
    `target_hash`. Per V7, signatures live at signer-relative paths
    matching the invariant pointer pattern; we accept any bound
    signature entity targeting `target_hash`."""
    sigs: list[dict[str, Any]] = []
    for _uri, h in ctx.emit_pathway.entity_tree.all_bindings():
        entity = ctx.emit_pathway.content_store.get(h)
        if entity is None or entity.type != "system/signature":
            continue
        sig_target = entity.data.get("target")
        if isinstance(sig_target, bytes) and sig_target == target_hash:
            sigs.append(entity.to_dict())
    return sigs


def _verify_one_signature(
    target_hash: bytes,
    signer_hash: bytes,
    signature_entity: dict[str, Any],
    identity_data: dict[str, Any],
) -> bool:
    """Cryptographically verify one signature entity over `target_hash`."""
    sig_data = signature_entity.get("data") if isinstance(signature_entity, dict) else None
    if not isinstance(sig_data, dict):
        return False

    if _normalize_hash(sig_data.get("target")) != target_hash:
        return False
    if _normalize_hash(sig_data.get("signer")) != signer_hash:
        return False
    if sig_data.get("algorithm") != "ed25519":
        return False

    sig_bytes = sig_data.get("signature")
    if not isinstance(sig_bytes, bytes):
        return False

    pub_bytes = identity_data.get("public_key")
    if not isinstance(pub_bytes, bytes):
        return False

    try:
        public_key = public_key_from_bytes(pub_bytes)
        return verify_signature(public_key, target_hash, sig_bytes)
    except Exception:
        return False


# =============================================================================
# Signature validation (§4.1, §4.2)
# =============================================================================


def verify_attestation_signature(
    att: Entity,
    ctx: HandlerContext,
    *,
    included: list[dict[str, Any]] | dict[bytes, dict[str, Any]] | None = None,
    resolver: PeerResolver | None = None,
) -> bool:
    """Default single-sig validation per §4.1: validates that `att` is
    signed by `att.attesting`. Locates the signature via the V7 invariant
    pointer pattern (signer-relative `system/signature/{target_hex}`)."""
    attesting = _normalize_hash(att.data.get("attesting"))
    if attesting is None:
        return False
    return verify_specific_signer(
        att, attesting, ctx, included=included, resolver=resolver,
    )


def verify_specific_signer(
    att: Entity,
    expected_signer: bytes,
    ctx: HandlerContext,
    *,
    included: list[dict[str, Any]] | dict[bytes, dict[str, Any]] | None = None,
    resolver: PeerResolver | None = None,
) -> bool:
    """Per §4.2: verify `att` carries a valid signature from
    `expected_signer`. Used by consumers composing multi-sig topologies
    (dual-sig, etc.) without baking multi-sig semantics into the
    primitive."""
    target_hash = att.compute_hash()
    if included is None:
        included = collect_signatures_for(ctx, target_hash)
    if resolver is None:
        resolver = make_peer_resolver(ctx)

    sig = find_signature_by_signer(target_hash, expected_signer, included)
    if sig is None:
        return False
    identity_data = resolver(expected_signer)
    if identity_data is None:
        return False
    return _verify_one_signature(target_hash, expected_signer, sig, identity_data)


# =============================================================================
# Index lookups (scan-based; satisfies I1–I5 by reading current tree state)
# =============================================================================


def _iter_bound_attestations(ctx: HandlerContext) -> Iterator[Entity]:
    """Yield every tree-bound `system/attestation` entity in the local
    tree. Scan-based; production impls SHOULD layer real indexes per
    §5.7 / §9.1. Indexes built off this scan automatically satisfy I1
    (write-then-read) and I2 (atomicity) because they read the
    post-commit tree."""
    seen: set[bytes] = set()
    for _uri, h in ctx.emit_pathway.entity_tree.all_bindings():
        if h in seen:
            continue
        seen.add(h)
        entity = ctx.emit_pathway.content_store.get(h)
        if entity is None or entity.type != ATTESTATION_TYPE:
            continue
        yield entity


def find_attestations_targeting(
    entity_hash: bytes,
    predicate: AttestationPredicate,
    ctx: HandlerContext,
) -> list[Entity]:
    """Per §5.4: all attestations where `attested == entity_hash`
    matching `predicate`."""
    out: list[Entity] = []
    for att in _iter_bound_attestations(ctx):
        if _normalize_hash(att.data.get("attested")) != entity_hash:
            continue
        if predicate(att, ctx):
            out.append(att)
    return out


def find_attestations_by(
    peer_hash: bytes,
    predicate: AttestationPredicate,
    ctx: HandlerContext,
) -> list[Entity]:
    """Per §5.5: all attestations where `attesting == peer_hash`
    matching `predicate`."""
    out: list[Entity] = []
    for att in _iter_bound_attestations(ctx):
        if _normalize_hash(att.data.get("attesting")) != peer_hash:
            continue
        if predicate(att, ctx):
            out.append(att)
    return out


def find_revocations_for(
    attestation_hash: bytes,
    ctx: HandlerContext,
) -> list[Entity]:
    """Per §5.6: all attestations with `properties.kind == "revocation"`
    targeting `attestation_hash`."""
    return find_attestations_targeting(
        attestation_hash,
        lambda a, _ctx: (a.data.get("properties") or {}).get("kind") == KIND_REVOCATION,
        ctx,
    )


def find_attestations_with_supersedes(
    predecessor_hash: bytes,
    ctx: HandlerContext,
) -> list[Entity]:
    """Per §5.6a: inverse of the supersedes pointer — attestations whose
    `supersedes` field equals `predecessor_hash`. Used by `find_live_head`
    and recursive liveness."""
    out: list[Entity] = []
    for att in _iter_bound_attestations(ctx):
        if _normalize_hash(att.data.get("supersedes")) == predecessor_hash:
            out.append(att)
    return out


def find_attestations_with_kind(
    kind_value: str,
    ctx: HandlerContext,
) -> list[Entity]:
    """Per §5.6b: attestations whose `properties.kind == kind_value`.
    Per I5, attestations without a `kind` key are NOT returned."""
    out: list[Entity] = []
    for att in _iter_bound_attestations(ctx):
        props = att.data.get("properties") or {}
        if "kind" not in props:
            continue
        if props.get("kind") == kind_value:
            out.append(att)
    return out


# =============================================================================
# Liveness (§4.3)
# =============================================================================
#
# The §4.3 pseudocode checks direct successors with a recursive call to
# is_attestation_live; that's bistable on chains of length > 2 (a
# grandchild superseding a child leaves the grandparent appearing live).
# We implement the spec's *intent* — "att is dead iff a non-revoked,
# non-expired transitive descendant exists" — by separating "terminally
# dead" (expired or self-revoked) from "superseded" (any transitive
# descendant is alive).


def _is_temporally_invalid(att: Entity, now: int) -> bool:
    expires_at = att.data.get("expires_at")
    if isinstance(expires_at, int) and now >= expires_at:
        return True
    not_before = att.data.get("not_before")
    if isinstance(not_before, int) and now < not_before:
        return True
    return False


def _is_self_revoked(
    att: Entity,
    ctx: HandlerContext,
    now: int,
    in_progress: frozenset[bytes],
) -> bool:
    """Self-revocation only — a non-self revoker is consumer-supplied
    authority and not handled at this layer."""
    self_hash = att.compute_hash()
    self_attesting = _normalize_hash(att.data.get("attesting"))
    for rev in find_revocations_for(self_hash, ctx):
        if _normalize_hash(rev.data.get("attesting")) != self_attesting:
            continue
        if rev.compute_hash() in in_progress:
            continue
        if _is_live(rev, ctx, now, in_progress | {rev.compute_hash()}):
            return True
    return False


def _is_terminally_dead(
    att: Entity,
    ctx: HandlerContext,
    now: int,
    in_progress: frozenset[bytes],
) -> bool:
    """Dead from expiration or self-revocation — supersession excluded."""
    if _is_temporally_invalid(att, now):
        return True
    if _is_self_revoked(att, ctx, now, in_progress):
        return True
    return False


def _is_superseded(
    att: Entity,
    ctx: HandlerContext,
    now: int,
    in_progress: frozenset[bytes],
) -> bool:
    """True iff some direct successor is itself non-terminally-dead, OR
    a transitive descendant past a dead direct successor is."""
    self_hash = att.compute_hash()
    for s in find_attestations_with_supersedes(self_hash, ctx):
        sh = s.compute_hash()
        if sh in in_progress:
            continue
        new_in_progress = in_progress | {sh}
        if not _is_terminally_dead(s, ctx, now, new_in_progress):
            return True
        if _is_superseded(s, ctx, now, new_in_progress):
            return True
    return False


def _is_live(
    att: Entity,
    ctx: HandlerContext,
    now: int,
    in_progress: frozenset[bytes],
) -> bool:
    if _is_terminally_dead(att, ctx, now, in_progress):
        return False
    if _is_superseded(att, ctx, now, in_progress):
        return False
    return True


def is_attestation_live(
    att: Entity,
    ctx: HandlerContext,
    *,
    as_of: int | None = None,
) -> bool:
    """Per §4.3: composite check — not expired, not superseded by a live
    descendant, not self-revoked. Self-revocation only at this layer;
    consumers apply authority-revocation rules separately (§4.4).

    `as_of` (epoch ms) supports time-traveling validation for cap-chain
    historical state.
    """
    now = as_of if as_of is not None else _now_ms()
    return _is_live(att, ctx, now, frozenset({att.compute_hash()}))


# =============================================================================
# Graph walks (§5.1, §5.2, §5.3)
# =============================================================================


def walk_supersedes_chain(
    start: Entity,
    ctx: HandlerContext,
) -> list[Entity]:
    """Per §5.2: walk back via `supersedes` to the original. Returns
    [start, prev, prev_prev, ..., original]. Stops when the chain
    breaks (predecessor not found in content store)."""
    chain = [start]
    current = start
    visited: set[bytes] = {current.compute_hash()}
    while True:
        prev_hash = _normalize_hash(current.data.get("supersedes"))
        if prev_hash is None:
            break
        if prev_hash in visited:
            break  # cycle protection
        prev = ctx.emit_pathway.content_store.get(prev_hash)
        if prev is None or prev.type != ATTESTATION_TYPE:
            break
        chain.append(prev)
        visited.add(prev_hash)
        current = prev
    return chain


def find_live_head(
    start: Entity,
    ctx: HandlerContext,
    *,
    as_of: int | None = None,
) -> Entity | None:
    """Per §5.3: walk supersedes-chain forward to the current live head.
    Returns the most recent live attestation in the chain, or None if
    none in the chain are live. On forks (multiple alive descendants),
    deterministic tie-break by `(not_before, content_hash)` per §5.3."""
    candidates: list[Entity] = [start]
    visited: set[bytes] = {start.compute_hash()}
    queue: list[Entity] = [start]
    while queue:
        current = queue.pop(0)
        for s in find_attestations_with_supersedes(current.compute_hash(), ctx):
            sh = s.compute_hash()
            if sh in visited:
                continue
            visited.add(sh)
            candidates.append(s)
            queue.append(s)

    alive = [c for c in candidates if is_attestation_live(c, ctx, as_of=as_of)]
    if not alive:
        return None
    return max(
        alive,
        key=lambda a: (a.data.get("not_before") or 0, a.compute_hash()),
    )


def default_find_authorizing(
    peer_hash: bytes,
    ctx: HandlerContext,
) -> Entity | None:
    """Per §5.1 (v1.1): returns the attestation that authorizes
    `peer_hash` within the attestation graph, or None.

    Per SI-1: the substrate stays signature-agnostic. Liveness does NOT
    include signature validation. Consumers requiring signature-aware
    authorization SHOULD pass a custom `find_authorizing_fn` that layers
    topology-appropriate signature validation, OR validate via the
    consumer's orchestration entry point (e.g., identity's
    `identity_verify_cert`) downstream of the chain walk.

    Algorithm:
    1. find_attestations_targeting(peer_hash, ...).
    2. Filter to those that are live (per is_attestation_live).
    3. Resolve each to its live head via find_live_head.
    4. Tie-break by lowest content_hash when multiple distinct heads
       remain (§5.1 normative).
    """
    candidates = find_attestations_targeting(peer_hash, lambda _a, _c: True, ctx)
    if not candidates:
        return None

    live = [att for att in candidates if is_attestation_live(att, ctx)]
    if not live:
        return None

    heads: list[Entity] = []
    seen_hashes: set[bytes] = set()
    for att in live:
        head = find_live_head(att, ctx)
        if head is None:
            continue
        h = head.compute_hash()
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        heads.append(head)

    if not heads:
        return None
    if len(heads) == 1:
        return heads[0]
    return min(heads, key=lambda a: a.compute_hash())


def walk_attesting_chain(
    start: Entity,
    terminate_predicate: TerminatePredicate,
    ctx: HandlerContext,
    *,
    find_authorizing_fn: FindAuthorizingFn | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> list[Entity] | None:
    """Per §5.1: walk back via `attesting` until `terminate_predicate`
    matches. Returns [start, ..., terminating_attestation] or None when
    the chain doesn't terminate within `max_depth`.

    The chain link is: each step, look up the attestation that
    authorizes `current.attesting` itself (via `find_authorizing_fn`,
    defaulting to `default_find_authorizing`). Consumers expecting
    multi-context peers SHOULD pass a custom `find_authorizing_fn` that
    filters by their own context (kind, storage path) — see §5.1
    "Multi-context peers note".
    """
    if find_authorizing_fn is None:
        find_authorizing_fn = default_find_authorizing

    chain: list[Entity] = [start]
    current = start
    visited: set[bytes] = {current.compute_hash()}
    depth = 0

    while depth < max_depth:
        if terminate_predicate(current, ctx):
            return chain
        attesting = _normalize_hash(current.data.get("attesting"))
        if attesting is None:
            return None
        parent = find_authorizing_fn(attesting, ctx)
        if parent is None:
            return None
        h = parent.compute_hash()
        if h in visited:
            return None  # cycle
        visited.add(h)
        chain.append(parent)
        current = parent
        depth += 1

    return None


# =============================================================================
# Entity construction
# =============================================================================


def make_attestation(
    *,
    attesting: bytes,
    attested: bytes,
    properties: dict[str, Any],
    supersedes: bytes | None = None,
    not_before: int | None = None,
    expires_at: int | None = None,
) -> Entity:
    """Construct an unsigned `system/attestation` entity. Optional
    fields are only included when set so the canonical encoding stays
    minimal."""
    data: dict[str, Any] = {
        "attesting": attesting,
        "attested": attested,
        "properties": properties,
    }
    if supersedes is not None:
        data["supersedes"] = supersedes
    if not_before is not None:
        data["not_before"] = not_before
    if expires_at is not None:
        data["expires_at"] = expires_at
    return Entity(type=ATTESTATION_TYPE, data=data)


# =============================================================================
# Handler operations (§6)
# =============================================================================


def _structurally_validate(
    ctx: HandlerContext,
    *,
    attesting: bytes | None,
    attested: bytes | None,
    properties: Any,
    supersedes: bytes | None,
) -> str | None:
    """Returns an error message or None on success."""
    if attesting is None:
        return "attesting is required and must be a valid hash"
    if attested is None:
        return "attested is required and must be a valid hash"
    if not isinstance(properties, dict):
        return "properties must be a map"
    if supersedes is not None:
        prev = ctx.emit_pathway.content_store.get(supersedes)
        if prev is None or prev.type != ATTESTATION_TYPE:
            return "supersedes must reference an existing system/attestation entity"
    return None


async def _handle_create(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per §6.1 (v1.1): produce an attestation entity. Validates
    structural invariants. Tree-binds at the resource target.

    Per SI-7/SI-22: path-as-resource is REQUIRED (V7 §3.2 architectural-
    side MUST). `:create` without a resource target returns
    `path_required`. Content-store-only writes (test fixtures, staging-
    without-tree-binding) use V7 kernel `tree:put` directly.

    Does NOT validate the signature or authority — those are the
    consumer's domain (or `:verify`'s).
    """
    data = _params_data(params)
    attesting = _normalize_hash(data.get("attesting"))
    attested = _normalize_hash(data.get("attested"))
    properties = data.get("properties")
    supersedes = _normalize_hash(data.get("supersedes")) if data.get("supersedes") is not None else None
    not_before = data.get("not_before")
    expires_at = data.get("expires_at")

    target_path = _resource_target(ctx)
    if target_path is None:
        return _error(
            400, "path_required",
            "system/attestation:create requires a resource target (V7 §3.2)",
        )

    err = _structurally_validate(
        ctx,
        attesting=attesting,
        attested=attested,
        properties=properties,
        supersedes=supersedes,
    )
    if err is not None:
        return _error(400, "invalid_params", err)

    att = make_attestation(
        attesting=attesting,
        attested=attested,
        properties=properties,
        supersedes=supersedes,
        not_before=not_before if isinstance(not_before, int) else None,
        expires_at=expires_at if isinstance(expires_at, int) else None,
    )

    emit_ctx = EmitContext.from_handler_grant(ctx, "create")
    ctx.emit_pathway.emit(target_path, att, emit_ctx)

    return _ok(
        "system/attestation/create-result",
        {
            "attestation_hash": att.compute_hash(),
            "stored_at": target_path,
        },
    )


async def _handle_supersede(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per §6.2: supersede a previous attestation. Looks up `previous_hash`,
    copies its `attesting` and `attested`, sets `supersedes = previous_hash`."""
    data = _params_data(params)
    previous_hash = _normalize_hash(data.get("previous_hash"))
    if previous_hash is None:
        return _error(400, "invalid_params", "previous_hash is required")

    prev = ctx.emit_pathway.content_store.get(previous_hash)
    if prev is None or prev.type != ATTESTATION_TYPE:
        return _error(404, "previous_not_found", "previous attestation not found")

    properties = data.get("properties")
    if not isinstance(properties, dict):
        return _error(400, "invalid_params", "properties must be a map")

    new_data = {
        "attesting": prev.data.get("attesting"),
        "attested": prev.data.get("attested"),
        "properties": properties,
        "supersedes": previous_hash,
    }
    not_before = data.get("not_before")
    if isinstance(not_before, int):
        new_data["not_before"] = not_before
    expires_at = data.get("expires_at")
    if isinstance(expires_at, int):
        new_data["expires_at"] = expires_at

    return await _handle_create(ctx, {"data": new_data})


async def _handle_revoke(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per §6.3: convenience wrapper producing a `kind=revocation`
    attestation targeting `target_hash`."""
    data = _params_data(params)
    target_hash = _normalize_hash(data.get("target_hash"))
    attesting = _normalize_hash(data.get("attesting"))
    if target_hash is None:
        return _error(400, "invalid_params", "target_hash is required")
    if attesting is None:
        return _error(400, "invalid_params", "attesting is required")

    properties: dict[str, Any] = {"kind": KIND_REVOCATION}
    reason = data.get("reason")
    if isinstance(reason, str):
        properties["reason"] = reason

    return await _handle_create(ctx, {
        "data": {
            "attesting": attesting,
            "attested": target_hash,
            "properties": properties,
        },
    })


async def _handle_verify(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Per §6.4: orchestration helper — single-sig verify + liveness.
    Returns `{valid, reason?}`. Does NOT validate consumer-specific
    authority rules (topology, function-specific, authority-revocation)."""
    data = _params_data(params)
    att_hash = _normalize_hash(data.get("attestation_hash"))
    if att_hash is None:
        return _error(400, "invalid_params", "attestation_hash is required")

    att = ctx.emit_pathway.content_store.get(att_hash)
    if att is None or att.type != ATTESTATION_TYPE:
        return _error(404, "attestation_not_found", "attestation not found")

    as_of = data.get("as_of") if isinstance(data.get("as_of"), int) else None

    if not verify_attestation_signature(att, ctx):
        return _ok(
            "system/attestation/verify-result",
            {"valid": False, "reason": "invalid_signature"},
        )
    if not is_attestation_live(att, ctx, as_of=as_of):
        return _ok(
            "system/attestation/verify-result",
            {"valid": False, "reason": "not_live"},
        )
    return _ok("system/attestation/verify-result", {"valid": True})


async def attestation_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Dispatch `system/attestation:*` operations per EXTENSION-ATTESTATION
    v1.0 §6."""
    if operation == _OP_CREATE:
        return await _handle_create(ctx, params)
    if operation == _OP_SUPERSEDE:
        return await _handle_supersede(ctx, params)
    if operation == _OP_REVOKE:
        return await _handle_revoke(ctx, params)
    if operation == _OP_VERIFY:
        return await _handle_verify(ctx, params)
    return _error(
        501, "unsupported_operation",
        f"attestation handler does not support {operation!r}",
    )


__all__ = [
    "ATTESTATION_TYPE",
    "ATTESTATION_HANDLER_PATTERN",
    "KIND_REVOCATION",
    "DEFAULT_MAX_DEPTH",
    # Type aliases
    "PeerResolver",
    "AttestationPredicate",
    "TerminatePredicate",
    "FindAuthorizingFn",
    # Resolver / sig helpers (consumer-reusable)
    "make_peer_resolver",
    "collect_signatures_for",
    # Validators
    "verify_attestation_signature",
    "verify_specific_signer",
    "is_attestation_live",
    # Graph walks
    "walk_attesting_chain",
    "walk_supersedes_chain",
    "find_live_head",
    "default_find_authorizing",
    # Lookups
    "find_attestations_targeting",
    "find_attestations_by",
    "find_revocations_for",
    "find_attestations_with_supersedes",
    "find_attestations_with_kind",
    # Construction
    "make_attestation",
    # Handler
    "attestation_handler",
]
