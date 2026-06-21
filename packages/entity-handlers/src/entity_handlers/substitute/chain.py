"""Chain-consultation orchestrator per PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-SOURCES §2.2.

On a local content miss, a consumer that knows the claimed source peer
consults a priority-sorted, peer-scoped list of substitute sources.
Each source dispatches its handler-typed `:try` op; cap-denied ABORTS
the chain, transient errors / hash mismatches ADVANCE, success returns
the verified entity to the caller.

Per the storage-substitute cross-impl rulings (Ruling 4): the
`claimed_source_peer_id` is **local dispatcher context** — callers that
hold a source-peer in local scope (Phase 2 dispatcher tree-walks, SDK
ensure_closure helpers, etc.) invoke `consult_substitute_chain()`
directly with that value. The `system/content:get` handler does NOT
auto-invoke the chain; there is no wire-field plumbing on get-request.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from entity_core.capability.checking import canonicalize, matches_pattern, matches_scope
from entity_core.capability.token import get_scope
from entity_core.crypto.signing import public_key_from_bytes, verify_signature
from entity_core.handlers.context import HandlerContext
from entity_core.utils.ecf import Hash, compute_ecf_hash, hash_equals

logger = logging.getLogger(__name__)

# Cap-axis ruling: the named cap `content-substitute-consult` reduces to a
# grant on the `(handler, operation, resource)` triple + (optional) constraints.
# Per the named-capability-mapping ruling §4 + §6, as amended by the
# transport-family chunk-C amendments §D2:
#   - check `system/substitute/sources` + operation `consult` via the
#     standard V7 §5.2 grant-scope check (never string-presence).
#   - **resource axis (D2)**: the grant's `resources` scope MUST cover the
#     triggering CONTENT EXECUTE's `resource_target` — the target namespace
#     the consumer is reading into. Without a target namespace in ctx, the
#     check fails closed (delegated consult grants are only meaningful when
#     both sides agree on the namespace they apply to). Python's earlier
#     constraints-only model is banned.
#   - per-cap narrowing lives in `constraints`:
#       `source_peer_id`:    byte-equal under delegation (V7 §5.6)
#       `substitute_types`:  per-entry filter
#   - fail closed: absent a matching grant denies consultation.
SUBSTITUTE_SOURCES_HANDLER = "system/substitute/sources"
CONSULT_OPERATION = "consult"

# Retained for callers that author legacy grants — still resolves through
# the same `(handler, op)` check above; the *name* is unchanged but the
# *check shape* is now cap-axis, not string-presence.
CHAIN_CONSULT_CAP = "system/capability/content-substitute-consult"

SUBSTITUTE_SOURCES_PREFIX = "system/substitute/sources/"


@dataclass
class _ChainOutcome:
    """Internal: orchestrator → caller verdict."""

    entity: dict[str, Any] | None = None  # success: the resolved entity dict
    aborted: bool = False                  # cap_denied: chain aborted
    last_error: str | None = None          # advance-trail for meta
    attempted: int = 0


@dataclass(frozen=True)
class OperatorTrustPolicy:
    """Per-deployment local trust override for unsigned substitute sources (D7).

    Wire/default: source entries MUST carry a valid signature by
    `source_peer_id` to be consultable. Operators MAY explicitly grant a
    LOCAL trust override for sources they authored themselves — e.g., a
    private-deployment operator running their own publisher and consumer
    side-by-side.

    The override is **default-closed**: an empty `OperatorTrustPolicy()`
    rejects all unsigned sources. To include a source publisher in the
    override, add their peer-id-as-hash bytes to
    `allow_unsigned_source_peer_ids`. Per RULING/D7 every skipped or
    overridden source emits a WARNING with the skip-reason so operators
    can see which entries are running under override vs strict.
    """

    allow_unsigned_source_peer_ids: tuple[bytes, ...] = field(default_factory=tuple)

    def is_unsigned_allowed(self, source_peer_id: bytes) -> bool:
        for allowed in self.allow_unsigned_source_peer_ids:
            if hash_equals(bytes(allowed), bytes(source_peer_id)):
                return True
        return False


# Closed policy — the default. Any unsigned source is rejected.
_DEFAULT_TRUST_POLICY = OperatorTrustPolicy()


async def consult_substitute_chain(
    ctx: HandlerContext,
    missed_hash: Hash,
    claimed_source_peer_id: Hash | None,
    *,
    now_ms: int | None = None,
    trust_policy: OperatorTrustPolicy | None = None,
) -> _ChainOutcome:
    """Consult the substitute chain for `missed_hash` (§2.2).

    Algorithm:
        if not cap_chain.has(CHAIN_CONSULT_CAP):       → 404 (no consult)
        if claimed_source_peer_id is None:             → 404 (v1: no wildcard)
        entries = list(SUBSTITUTE_SOURCES_PREFIX)
            .filter(enabled AND source_peer_id==claimed AND not expired)
            .sort_by(priority)
        for entry in entries:
            r = invoke(handler:try, {entry, hash})
            if r is cap_denied: ABORT
            if r is bytes/entity:
                if not verify(): continue (ADVANCE on mismatch)
                ingest(); return ok
            else: continue (ADVANCE)
        return 404
    """
    outcome = _ChainOutcome()

    if claimed_source_peer_id is None:
        # §2.2 / §3-RES.2: bare-hash queries do NOT trigger consultation.
        return outcome

    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)

    # Cap-axis check (RULING-NAMED-CAPABILITY-MAPPING §4 + §6) — replaces
    # the legacy string-presence check with a real (handler, operation)
    # grant lookup + `source_peer_id` constraint match. Fail-closed: no
    # matching grant → consultation denied (clean local miss to caller).
    matching_grants = _find_consult_grants(
        ctx, claimed_source_peer_id, now_ms=now_ms
    )
    if not matching_grants:
        return outcome

    sources = _list_active_sources(
        ctx,
        claimed_source_peer_id,
        now_ms=now_ms,
        trust_policy=trust_policy or _DEFAULT_TRUST_POLICY,
    )

    for source_entity in sources:
        outcome.attempted += 1
        substitute_type = source_entity["data"].get("substitute_type")
        if not substitute_type:
            continue
        # Per-entry `substitute_types` constraint (RULING §4). If no
        # matching grant permits this type, skip the entry. If every
        # matching grant constrains a disjoint type-set, this advances
        # past every source — the chain returns a clean miss.
        if not any(
            _grant_permits_substitute_type(g, substitute_type)
            for g in matching_grants
        ):
            outcome.last_error = "substitute_type_not_permitted"
            continue
        handler_uri = f"system/substitute/{substitute_type}"
        try:
            result = await ctx.execute(
                handler_uri,
                "try",
                params={"entry": source_entity, "hash": bytes(missed_hash)},
            )
        except Exception as exc:
            # Local dispatch failure is treated as a transient on this
            # entry; advance to the next source.
            outcome.last_error = f"dispatch_failed: {exc}"
            logger.debug("substitute chain dispatch failed: %s", exc)
            continue

        status = getattr(result, "status", None)
        if status is None and isinstance(result, dict):
            status = result.get("status")

        # cap_denied → ABORT chain entirely.
        if status == 403:
            outcome.aborted = True
            outcome.last_error = _extract_error_code(result) or "cap_denied"
            return outcome

        if status == 200:
            entity = _extract_returned_entity(result, missed_hash)
            if entity is None:
                # Handler claimed success but the body shape was off —
                # advance.
                outcome.last_error = "handler_returned_no_entity"
                continue
            # The :try handler already verified the hash; the orchestrator
            # ingests by writing into the local content store.
            _ingest_entity(ctx, missed_hash, entity)
            outcome.entity = entity
            return outcome

        # 4xx (non-403) / 5xx: ADVANCE on transient; for explicit
        # hash-mismatch the handler returned 404 with descriptive message.
        outcome.last_error = _extract_error_code(result) or f"status_{status}"
        continue

    return outcome


# -----------------------------------------------------------------------------
# Internals
# -----------------------------------------------------------------------------


def _find_consult_grants(
    ctx: HandlerContext,
    claimed_source_peer_id: Hash,
    *,
    now_ms: int,
) -> list[dict[str, Any]]:
    """Find grants permitting the consult op (RULING §4 + Chunk-C §D2).

    A grant matches iff:
      - it covers handler `system/substitute/sources` (handlers scope)
      - it covers operation `consult` (operations scope)
      - **its `resources` scope covers at least one of the consumer's
        target namespaces in `ctx.resource_targets`** (D2 — the resource
        axis pins what the delegated consult grant applies to)
      - if it carries a `source_peer_id` constraint, that value is
        byte-equal to `claimed_source_peer_id` (V7 §5.6 delegation
        byte-equality; mal-typed constraints fail closed)
      - the capability's temporal bounds (`expires_at` / `not_before`)
        are satisfied

    The `substitute_types` constraint is per-entry and applied by the
    caller against each source entity's `substitute_type` value.

    Returns:
        List of matching grant dicts. Empty list = no consultation
        permitted (fail-closed per §6). Notably: if `ctx.resource_targets`
        is empty or None, returns empty — the resource axis has nothing
        to match and the chain is denied.
    """
    cap = ctx.caller_capability or {}
    cap_data = cap.get("data") if isinstance(cap, dict) else None
    if not isinstance(cap_data, dict):
        return []

    expires_at = cap_data.get("expires_at")
    if isinstance(expires_at, int) and expires_at < now_ms:
        return []
    not_before = cap_data.get("not_before")
    if isinstance(not_before, int) and not_before > now_ms:
        return []

    # D2 — resource axis: target namespaces come from the triggering
    # CONTENT EXECUTE. Without targets we cannot establish what the
    # consult grant applies to, so we fail closed.
    targets = ctx.resource_targets or []
    if not targets:
        return []
    local_peer_id = ctx.local_peer_id
    canonical_targets = [canonicalize(t, local_peer_id) for t in targets]

    claimed_bytes = bytes(claimed_source_peer_id)
    matching: list[dict[str, Any]] = []
    for grant in cap_data.get("grants") or []:
        if not isinstance(grant, dict):
            continue
        handlers_scope = get_scope(grant, "handlers")
        if not matches_scope(handlers_scope, SUBSTITUTE_SOURCES_HANDLER):
            continue
        operations_scope = get_scope(grant, "operations")
        if not matches_scope(operations_scope, CONSULT_OPERATION):
            continue
        # D2: every target the consumer is reading into MUST be covered
        # by this grant's resources scope. (Any-one-uncovered = no match.)
        resources_scope = get_scope(grant, "resources")
        if not _grant_covers_all_targets(
            resources_scope, canonical_targets, local_peer_id
        ):
            continue
        constraints = grant.get("constraints") or {}
        constraint_peer = constraints.get("source_peer_id")
        if constraint_peer is not None:
            if not isinstance(constraint_peer, (bytes, bytearray)):
                # Mal-typed constraint → fail closed; do not promote a
                # malformed grant into a permissive one.
                continue
            if not hash_equals(bytes(constraint_peer), claimed_bytes):
                continue
        matching.append(grant)
    return matching


def _grant_covers_all_targets(
    resources_scope: Any,
    canonical_targets: list[str],
    local_peer_id: str,
) -> bool:
    """True iff `resources_scope` (V7 capability scope) covers every
    canonical target. Honors both `include` and `exclude` patterns.
    """
    include = list(getattr(resources_scope, "include", []) or [])
    exclude = list(getattr(resources_scope, "exclude", []) or [])
    if not include:
        return False
    for target in canonical_targets:
        included = False
        for pattern in include:
            canonical_pattern = canonicalize(pattern, local_peer_id)
            if matches_pattern(canonical_pattern, target):
                included = True
                break
        if not included:
            return False
        for pattern in exclude:
            canonical_pattern = canonicalize(pattern, local_peer_id)
            if matches_pattern(canonical_pattern, target):
                return False
    return True


def _grant_permits_substitute_type(
    grant: dict[str, Any], substitute_type: str
) -> bool:
    """Per-entry constraint check (RULING §4).

    If `grant.constraints.substitute_types` is absent, the grant is
    unconstrained on type. If present, it MUST be a list/tuple of strings
    and `substitute_type` MUST be a member. Mal-typed constraint values
    fail closed.
    """
    constraints = grant.get("constraints") or {}
    allowed = constraints.get("substitute_types")
    if allowed is None:
        return True
    if not isinstance(allowed, (list, tuple)):
        return False
    return substitute_type in allowed


def _list_active_sources(
    ctx: HandlerContext,
    claimed_source_peer_id: Hash,
    *,
    now_ms: int,
    trust_policy: OperatorTrustPolicy,
) -> list[dict[str, Any]]:
    """List + filter + verify + sort substitute-source entities (§2.2 + D7).

    Filter predicates:
      - enabled is True
      - source_peer_id matches the claimed publisher
      - expires_at is absent or > now
      - **D7 signature check**: the entry's ``refs.signature`` MUST resolve
        to a signature entity that verifies against `source_peer_id`'s
        public key (looked up in the local tree at
        ``system/peer/{source_peer_id}``). Unsigned / invalid entries
        are rejected UNLESS the operator has explicitly allowlisted
        ``source_peer_id`` in ``trust_policy`` — in which case the entry
        is admitted with a WARNING that names the skip-reason.

    Sort: by `priority` ascending (lower first).
    """
    pathway = ctx.emit_pathway
    tree = pathway.entity_tree
    store = pathway.content_store

    # Tree listing returns full URIs like "entity://<peer>/system/substitute/sources/<hash>"
    # `list_prefix` normalizes; we pass the same shape the caller stores under.
    candidates: list[dict[str, Any]] = []
    for uri in tree.list_prefix(SUBSTITUTE_SOURCES_PREFIX):
        h = tree.get(uri)
        if h is None:
            continue
        entity = store.get(h)
        if entity is None:
            continue
        entity_dict = entity.to_dict()
        data = entity_dict.get("data") or {}
        if data.get("enabled") is not True:
            continue
        source_peer = data.get("source_peer_id")
        if not isinstance(source_peer, (bytes, bytearray)):
            continue
        if not hash_equals(bytes(source_peer), bytes(claimed_source_peer_id)):
            continue
        expires_at = data.get("expires_at")
        if expires_at is not None and isinstance(expires_at, int) and expires_at <= now_ms:
            continue

        # D7 signature gate.
        verify_result = _verify_source_signature(
            entity_dict, source_peer_bytes=bytes(source_peer), ctx=ctx
        )
        if verify_result is None:
            # Verified — include unconditionally.
            candidates.append(entity_dict)
            continue
        # Unverified. Operator-trust override?
        if trust_policy.is_unsigned_allowed(bytes(source_peer)):
            logger.warning(
                "substitute source admitted via operator-trust override "
                "(D7): source_peer_id=%s reason=%s",
                bytes(source_peer).hex()[:16] + "...",
                verify_result,
            )
            candidates.append(entity_dict)
            continue
        logger.debug(
            "substitute source rejected (D7 signature MUST): "
            "source_peer_id=%s reason=%s",
            bytes(source_peer).hex()[:16] + "...",
            verify_result,
        )

    candidates.sort(key=lambda e: int(e.get("data", {}).get("priority", 0)))
    return candidates


def _verify_source_signature(
    source_entity_dict: dict[str, Any],
    *,
    source_peer_bytes: bytes,
    ctx: HandlerContext,
) -> str | None:
    """Verify a source entry's signature via the V7 invariant signature path.

    Python's V4 refless entity model carries no ``refs`` field; signatures
    are discovered at the invariant path
    ``{source_peer_id_str}/system/signature/{source_hash_hex}`` (see
    ``entity_core.utils.path.invariant_signature_path``). This matches
    the existing Python pattern for signed entities.

    Returns:
        None on success. A human-readable skip-reason string on failure
        (the operator-override log uses it).
    """
    source_hash = compute_ecf_hash(
        {"type": source_entity_dict["type"], "data": source_entity_dict["data"]}
    )
    peer_id_str = _peer_id_string_from_hash(source_peer_bytes)
    if peer_id_str is None:
        return "cannot_derive_publisher_peer_id_string"

    tree = ctx.emit_pathway.entity_tree
    store = ctx.emit_pathway.content_store
    sig_path = f"{peer_id_str}/system/signature/{source_hash.hex()}"
    sig_hash = tree.get(sig_path)
    if sig_hash is None:
        return "no_signature_at_invariant_path"
    sig_entity = store.get(sig_hash)
    if sig_entity is None:
        return "signature_entity_missing_from_store"
    sig_data = sig_entity.data if isinstance(sig_entity.data, dict) else {}
    sig_target = sig_data.get("target")
    sig_bytes = sig_data.get("signature")
    if not isinstance(sig_target, (bytes, bytearray)) or not isinstance(
        sig_bytes, (bytes, bytearray)
    ):
        return "signature_entity_malformed"
    if not hash_equals(bytes(sig_target), source_hash):
        return "signature_target_mismatch"

    pubkey_bytes = _lookup_peer_pubkey(ctx, source_peer_bytes)
    if pubkey_bytes is None:
        return "publisher_pubkey_not_in_local_tree"
    try:
        pk = public_key_from_bytes(pubkey_bytes)
    except Exception as exc:
        return f"invalid_publisher_pubkey: {exc}"
    if not verify_signature(pk, source_hash, bytes(sig_bytes)):
        return "ed25519_verify_failed"
    return None


def _lookup_peer_pubkey(
    ctx: HandlerContext, source_peer_bytes: bytes
) -> bytes | None:
    """Walk the local tree for ``system/peer/{peer_id_str}`` and return
    the public-key bytes. Returns None if the peer entity is not registered
    locally (the operator hasn't told us about this publisher yet).

    Note: `source_peer_bytes` is a ``system/hash`` (33 bytes:
    algorithm_byte + sha256-of-pubkey). We reconstruct the peer-id string
    by swapping the algorithm prefix for the V7 (key_type, hash_type)
    pair — see the cohort-feedback note on wire-shape impedance.
    """
    peer_id_str = _peer_id_string_from_hash(source_peer_bytes)
    if peer_id_str is None:
        return None

    tree = ctx.emit_pathway.entity_tree
    store = ctx.emit_pathway.content_store
    peer_path = f"system/peer/{peer_id_str}"
    full_uri = tree.normalize_uri(peer_path)
    h = tree.get(full_uri)
    if h is None:
        return None
    peer_entity = store.get(h)
    if peer_entity is None:
        return None
    pubkey = peer_entity.data.get("public_key")
    if not isinstance(pubkey, (bytes, bytearray)):
        return None
    return bytes(pubkey)


def _peer_id_string_from_hash(source_peer_id_bytes: bytes) -> str | None:
    """Convert a ``system/hash`` source_peer_id (33 bytes) to the peer-id
    Base58 string (34 bytes raw).

    Shape impedance flagged for the cohort: source entries type
    `source_peer_id` as `system/hash` (algorithm_byte || digest), while
    peer-ids are `key_type || hash_type || hash(pubkey)`. They share the
    32-byte digest but the 1-byte prefix differs.

    For Ed25519 + SHA256 (the only combo Python currently supports), we
    map ``0x00 || digest`` (`system/hash` ECFv1-SHA256) → ``0x01 || 0x01
    || digest`` (peer-id raw) → Base58. Other crypto combos would need
    a richer mapping.
    """
    import base58

    if len(source_peer_id_bytes) != 33 or source_peer_id_bytes[0] != 0x00:
        return None
    digest = source_peer_id_bytes[1:]
    raw = bytes([0x01, 0x01]) + digest
    return base58.b58encode(raw).decode("ascii")


def _extract_returned_entity(
    result: Any, expected_hash: Hash
) -> dict[str, Any] | None:
    """Pull the raw entity dict out of a `:try` handler's success result.

    Per RULINGS Ruling 3, the handler returns the raw entity dict
    directly in `result` (no `{entity, hash}` wrapper). Accepts the
    ExecuteResult shape (with `.result`) or the bare handler-dict shape
    (`{status, result, envelope_included}`). Falls back to
    `envelope_included` if the result body is missing the entity dict.
    """
    payload = result
    if not isinstance(payload, dict):
        payload = getattr(result, "result", None)

    # Unwrap ExecuteResult-style {status, result, ...}.
    if isinstance(payload, dict) and "status" in payload and "result" in payload:
        payload = payload["result"]

    # Ruling 3: payload is the raw entity dict — {type, data}.
    if isinstance(payload, dict) and isinstance(payload.get("type"), str):
        return payload

    # Fallback: dispatcher hoisted the entity into envelope_included.
    included = (
        result.envelope_included if hasattr(result, "envelope_included") else None
    )
    if isinstance(included, dict):
        for h, ent in included.items():
            if hash_equals(bytes(h), bytes(expected_hash)) and isinstance(ent, dict):
                return ent
    return None


def _ingest_entity(
    ctx: HandlerContext, expected_hash: Hash, entity_dict: dict[str, Any]
) -> None:
    """Write the verified entity into the local content store.

    The handler already hash-verified the body; here we simply key it by
    the trusted hash (§1.8 fidelity — trust the validated hash, do not
    recompute). `target_namespace` selection is deferred to the caller's
    cap scope; v1 stores in the local content store at the verified hash.
    """
    from entity_core.protocol.entity import Entity

    store = ctx.emit_pathway.content_store
    type_ = entity_dict.get("type")
    data_ = entity_dict.get("data")
    if not isinstance(type_, str) or not isinstance(data_, dict):
        logger.debug("skip ingest: entity dict missing type/data")
        return
    entity = Entity(type=type_, data=data_, content_hash=bytes(expected_hash))
    store.put(entity)


def _extract_error_code(result: Any) -> str | None:
    """Pull the error `code` field from a non-2xx handler response."""
    payload = result
    if hasattr(result, "result"):
        payload = result.result
    if isinstance(payload, dict):
        body = payload.get("result") if "result" in payload else payload
        if isinstance(body, dict):
            data = body.get("data") if "data" in body else body
            if isinstance(data, dict):
                code = data.get("code")
                if isinstance(code, str):
                    return code
    return None
