"""Delegation chain verification.

This module implements capability delegation chain verification per
the Core Protocol Spec.

V4 Delegation requirements:
1. Each capability references its parent via data.parent
2. Each granter must be the grantee of the parent capability
3. Delegated capabilities must be attenuated (equal or more restrictive)

V4 Changes:
- granter, grantee, parent are bytes (Hash), not strings

V6.0 Changes:
- handlers, resources, operations are now CapabilityScope objects
- Each scope has include/exclude arrays
- Added peers field for peer scope
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from entity_core.capability.checking import matches_pattern
from entity_core.capability.token import (
    CapabilityScope,
    MultiGranter,
    get_multi_granter,
    get_scope,
    is_multi_granter,
    validate_multi_granter,
)
from entity_core.utils.ecf import Hash, hash_equals, hash_to_display, normalize_hash

# Use shared normalize_hash from ecf module
_normalize_hash = normalize_hash


from entity_core.crypto.identity import peer_id_from_identity_entity as _peer_id_from_identity_entity  # noqa: E402


@dataclass
class DelegationResult:
    """Result of delegation chain verification."""

    valid: bool
    error: str | None = None
    chain_depth: int = 0
    # PR-3 (V7 v7.39 §3.6): subcode for chain-validation failures that
    # need a specific status code at the dispatch layer (e.g. 401
    # `unresolvable_grantee`). None falls back to the generic 403.
    error_code: str | None = None


# Type alias for entity lookup function
EntityLookup = Callable[[bytes | str], dict[str, Any] | None]


class ChainCollectStatus(Enum):
    """Outcome of collect_authority_chain.

    OK: chain walked successfully from leaf to root (root has parent=null).
    UNREACHABLE: a `parent` reference could not be resolved via the lookup.
    TOO_DEEP: chain exceeded max_depth before reaching root. The default
        max_depth (64) is load-bearing for the collect-before-validate
        pattern in verify_capability_chain — without it an attacker could
        force unbounded resolution before validation rejects.
    """

    OK = "ok"
    UNREACHABLE = "unreachable"
    TOO_DEEP = "too_deep"


@dataclass
class ChainCollectResult:
    """Result of collect_authority_chain.

    chain: leaf-to-root list of capability entities. Empty on failure.
    status: see ChainCollectStatus.
    unreachable_parent: hash of the parent that could not be resolved
        (only set when status == UNREACHABLE).
    """

    chain: list[dict[str, Any]]
    status: ChainCollectStatus
    unreachable_parent: bytes | None = None

    @property
    def ok(self) -> bool:
        return self.status == ChainCollectStatus.OK


def collect_authority_chain(
    capability: dict[str, Any],
    lookup: EntityLookup,
    max_depth: int = 64,
) -> ChainCollectResult:
    """Walk a capability's authority chain leaf-to-root.

    Per PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE (V7 §5.5): this is the SINGLE
    shared chain-walk primitive. All consumers (verify_capability_chain,
    check_creator_authority, is_revoked) use this walker — keeping the
    walking logic, max_depth, and reachability semantics in one place.

    The walker ALWAYS walks to root. It does not short-circuit on any
    condition other than reaching the root, hitting an unreachable parent,
    or exceeding max_depth. Consumers filter or validate the returned chain.

    Resolution is parameterized via `lookup`. Different consumers use
    different sources (envelope-only, envelope+content-store, store-first,
    etc.) — see proposal §8.3.

    Args:
        capability: The leaf capability entity to walk from.
        lookup: Resolves a parent hash to an entity (or None).
        max_depth: Safety bound. Default 64 per spec; required to bound
            collect-before-validate cost in verify_capability_chain.

    Returns:
        ChainCollectResult — chain (leaf-to-root) on OK; empty chain on
        UNREACHABLE/TOO_DEEP with diagnostics.
    """
    chain: list[dict[str, Any]] = []
    current: dict[str, Any] | None = capability
    depth = 0

    while current is not None:
        if depth > max_depth:
            return ChainCollectResult(
                chain=[],
                status=ChainCollectStatus.TOO_DEEP,
            )
        chain.append(current)

        parent_hash = current.get("data", {}).get("parent")
        if not parent_hash:
            return ChainCollectResult(
                chain=chain,
                status=ChainCollectStatus.OK,
            )

        parent_hash = _normalize_hash(parent_hash)
        parent = lookup(parent_hash)
        if parent is None:
            return ChainCollectResult(
                chain=[],
                status=ChainCollectStatus.UNREACHABLE,
                unreachable_parent=parent_hash,
            )

        current = parent
        depth += 1

    # Defensive — only reached if `capability` itself was None.
    return ChainCollectResult(
        chain=[],
        status=ChainCollectStatus.OK,
    )


# (signer_peer_id, target_hash_bytes) -> signature entity dict (or None).
# Resolves the signature bound at the V7 invariant pointer path
# `/{signer_peer_id}/system/signature/{target_hex}` that envelope ingest
# binds (peer._bind_envelope_signatures). Mirrors Go's findBoundSignature.
BoundSignatureLookup = Callable[[str, bytes], dict[str, Any] | None]


def collect_chain_bundle(
    leaf_cap: dict[str, Any],
    *,
    entity_lookup: EntityLookup,
    bound_signature_lookup: BoundSignatureLookup,
    max_depth: int = 64,
) -> list[dict[str, Any]]:
    """Gather every entity a remote verifier needs to validate `leaf_cap`'s
    authority chain: each capability from the leaf to its root, plus each
    link's granter identity entity and the granter's signature over that
    link (the bound signature at the V7 invariant pointer path).

    EXTENSION-CONTINUATION §4.3 / §8.2 dispatch chain-walk + bundle helper —
    the Python analog of Go `capability.CollectChainBundle`. The dispatching
    host peer MUST place this whole set in the cross-peer EXECUTE envelope's
    `included`: the general V7 §3.1/§3.2 rule carries only the leaf cap
    (referenced from EXECUTE data); the transitive chain is referenced from
    *within* the cap entities and must be bundled explicitly.

    Over-inclusion is intentional and free — content-addressing dedups any
    entity B already holds, eliminating the "B GC'd a parent → VerifyChain
    fails" mode at zero correctness cost (§4.2 "Chain transport"). Best
    effort per link: a link whose identity/signature is not locally
    resolvable is simply omitted; the verifier fails closed if it actually
    needed it. Returns a de-duplicated (by content hash) entity-dict list;
    empty if the leaf chain itself is unreachable.
    """
    from entity_core.protocol.entity import Entity

    result = collect_authority_chain(leaf_cap, entity_lookup, max_depth)
    if result.status != ChainCollectStatus.OK:
        return []

    bundle: dict[bytes, dict[str, Any]] = {}

    def _add(ent: dict[str, Any] | None) -> None:
        if not isinstance(ent, dict):
            return
        h = _normalize_hash(ent.get("content_hash"))
        if h is None:
            h = Entity.from_dict(ent).compute_hash()
        bundle[h] = ent

    for cap_ent in result.chain:
        _add(cap_ent)
        cap_hash = _normalize_hash(cap_ent.get("content_hash"))
        if cap_hash is None:
            cap_hash = Entity.from_dict(cap_ent).compute_hash()

        granter_value = cap_ent.get("data", {}).get("granter")
        if granter_value is None:
            continue
        # Single-sig: one granter identity. Multi-sig: every signer.
        multi = get_multi_granter(granter_value)
        if multi is not None:
            signer_hashes = [_normalize_hash(s) for s in multi.signers]
        else:
            signer_hashes = [_normalize_hash(granter_value)]

        for signer_hash in signer_hashes:
            if signer_hash is None:
                continue
            id_ent = entity_lookup(signer_hash)
            if not isinstance(id_ent, dict) or id_ent.get("type") != "system/peer":
                continue
            _add(id_ent)
            # v7.65 §2: peer_id no longer in entity data — derive from pubkey
            signer_peer_id = _peer_id_from_identity_entity(id_ent)
            if not signer_peer_id:
                continue
            sig_ent = bound_signature_lookup(signer_peer_id, cap_hash)
            if isinstance(sig_ent, dict) and sig_ent.get("type") == "system/signature":
                _add(sig_ent)

    return list(bundle.values())


@dataclass
class CreatorAuthorityResult:
    """Result of check_creator_authority.

    found: True if writer's identity appears as a granter in the chain.
    chain: collected chain (leaf-to-root). Empty on UNREACHABLE/TOO_DEEP.
    status: ChainCollectStatus from the underlying walker.
    unreachable_parent: set when status == UNREACHABLE.

    Caller maps statuses to HTTP-style errors:
      status != OK         → 404 chain_unreachable
      status == OK, !found → 403 embedded_cap_unauthorized
      status == OK, found  → proceed; persist chain
    """

    found: bool
    chain: list[dict[str, Any]]
    status: ChainCollectStatus
    unreachable_parent: bytes | None = None


def check_creator_authority(
    capability: dict[str, Any],
    identity_hash: bytes | str,
    lookup: EntityLookup,
    max_depth: int = 64,
    find_signature_by_signer: SignatureBySignerFinder | None = None,
    identity_lookup: EntityLookup | None = None,
) -> CreatorAuthorityResult:
    """R1 creator-authorization check.

    Per PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE §3.2: replaces the retired
    `identity_in_authority_chain`. Collects the full authority chain via
    `collect_authority_chain` (which handles reachability), then scans the
    chain for the writer's identity as a granter.

    The chain walk and the identity match are separate concerns. The
    walker returns a complete chain or an error; the identity scan is a
    pure function over the result. Reachability (§2 normative) is enforced
    by construction — the walker errors before identity-matching runs.

    The returned chain (when status == OK) is exactly what callers should
    persist to local content store after a successful check. No re-walk.

    Per §3.2: rejected requests (found=False) MUST NOT persist the chain.

    V7.35 (PROPOSAL-MULTISIG-CORE-PRIMITIVE M7) — strict-with-signature: a
    writer matches a multi-sig granter only when the writer is in `signers`
    AND has a verified signature on that link. A peer listed in `signers`
    but who never signed does not count. When `find_signature_by_signer` is
    None, multi-sig links are skipped (no match) — preserves backward
    compatibility for callers that don't have signature access.

    Args:
        capability: The embedded capability entity.
        identity_hash: Peer-identity hash of the writer (EXECUTE author).
        lookup: Resolves parent hashes — see collect_authority_chain.
        max_depth: Safety bound, default 64.
        find_signature_by_signer: Locator for (target, signer) signatures
            (M7 strict-with-signature path). When None, multi-sig links
            cannot match.
        identity_lookup: Resolves identity hashes to identity entities.
            Defaults to `lookup`. The proposal mirrors V7 §5.5 line 1986–1988
            with a dual-lookup pattern (`included` first, then content store);
            callers can pass a wrapped lookup that does both.

    Returns:
        CreatorAuthorityResult — see dataclass docstring for caller mapping.
    """
    collect_result = collect_authority_chain(capability, lookup, max_depth)
    if collect_result.status != ChainCollectStatus.OK:
        return CreatorAuthorityResult(
            found=False,
            chain=[],
            status=collect_result.status,
            unreachable_parent=collect_result.unreachable_parent,
        )

    target_hash = _normalize_hash(identity_hash)
    found = False
    if target_hash is not None:
        id_lookup = identity_lookup if identity_lookup is not None else lookup
        for entity in collect_result.chain:
            data = entity.get("data", {})
            granter_value = data.get("granter")
            multi = get_multi_granter(granter_value)

            if multi is None:
                # Single-sig: literal identity match (today's behavior).
                granter = _normalize_hash(granter_value)
                if granter is not None and hash_equals(granter, target_hash):
                    found = True
                    break
                continue

            # Multi-sig: writer must be in `signers` AND have signed.
            in_signers = False
            for candidate in multi.signers:
                candidate_hash = _normalize_hash(candidate)
                if candidate_hash is not None and hash_equals(candidate_hash, target_hash):
                    in_signers = True
                    break
            if not in_signers:
                continue

            if find_signature_by_signer is None:
                # No way to verify the writer signed; skip (don't count).
                continue

            cap_hash = _normalize_hash(entity.get("content_hash"))
            if cap_hash is None:
                continue
            sig = find_signature_by_signer(cap_hash, target_hash)
            if sig is None:
                continue
            writer_identity = id_lookup(target_hash)
            if writer_identity is None:
                continue
            if _verify_signer_signed_target(cap_hash, target_hash, sig, writer_identity):
                found = True
                break

    return CreatorAuthorityResult(
        found=found,
        chain=collect_result.chain,
        status=ChainCollectStatus.OK,
    )

# Type alias for signature finder function
SignatureFinder = Callable[[bytes], dict[str, Any] | None]

# By-signer signature finder (V7.35 §4.0). Returns a signature entity targeting
# `target_hash` whose `data.signer` equals `signer_hash`, or None.
SignatureBySignerFinder = Callable[[bytes, bytes], dict[str, Any] | None]


def find_signature_by_signer(
    target_hash: bytes,
    signer_hash: bytes,
    included: dict[bytes, dict[str, Any]] | list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Find a signature entity matching both target and signer.

    Per PROPOSAL-MULTISIG-CORE-PRIMITIVE §4.0. `find_signature(target, included)`
    returns the *first* signature targeting a given hash; multi-sig
    verification needs to locate signatures by *both* target and signer
    since multiple constituents sign the same target.

    Args:
        target_hash: Content hash being signed.
        signer_hash: Identity hash of the required signer.
        included: Either a hash→entity mapping or an iterable of entities.

    Returns:
        The matching signature entity dict, or None.
    """
    target = _normalize_hash(target_hash)
    signer = _normalize_hash(signer_hash)
    if target is None or signer is None:
        return None

    if isinstance(included, dict):
        entities: list[dict[str, Any]] = list(included.values())
    else:
        entities = list(included)

    for entity in entities:
        if not isinstance(entity, dict):
            continue
        if entity.get("type") != "system/signature":
            continue
        data = entity.get("data", {})
        sig_target = _normalize_hash(data.get("target"))
        sig_signer = _normalize_hash(data.get("signer"))
        if sig_target is None or sig_signer is None:
            continue
        if hash_equals(sig_target, target) and hash_equals(sig_signer, signer):
            return entity
    return None


def _decode_signature_bytes(sig_data: dict[str, Any]) -> bytes | None:
    """Decode a signature entity's signature bytes (raw bytes or base64 str)."""
    import base64

    raw = sig_data.get("signature")
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        try:
            return base64.b64decode(raw)
        except Exception:
            return None
    return None


def _decode_public_key_bytes(identity_data: dict[str, Any]) -> bytes | None:
    """Decode an identity entity's public_key bytes (raw bytes or base64 str)."""
    import base64

    raw = identity_data.get("public_key")
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        try:
            return base64.b64decode(raw)
        except Exception:
            return None
    return None


def _verify_signer_signed_target(
    target_hash: bytes,
    signer_hash: bytes,
    sig: dict[str, Any] | None,
    identity_entity: dict[str, Any] | None,
) -> bool:
    """Cryptographically verify `sig` was made by `signer_hash` over `target_hash`.

    Returns False on any decode failure or mismatch — fail-closed semantics.
    """
    from entity_core.crypto.identity import key_type_byte_from_entity_data
    from entity_core.crypto.signing import verify_for_key_type

    if sig is None or identity_entity is None:
        return False
    sig_data = sig.get("data", {})
    sig_target = _normalize_hash(sig_data.get("target"))
    sig_signer = _normalize_hash(sig_data.get("signer"))
    if sig_target is None or sig_signer is None:
        return False
    if not hash_equals(sig_target, target_hash):
        return False
    if not hash_equals(sig_signer, signer_hash):
        return False

    identity_data = identity_entity.get("data", {})
    pub_bytes = _decode_public_key_bytes(identity_data)
    sig_bytes = _decode_signature_bytes(sig_data)
    if pub_bytes is None or sig_bytes is None:
        return False
    try:
        # V7 v7.67 Phase 2 — dispatch on the signer's key_type so an Ed448
        # delegator's chain signature verifies with Ed448. Fail-closed on an
        # unknown key_type.
        key_type_byte = key_type_byte_from_entity_data(
            identity_data.get("key_type", "ed25519")
        )
        return verify_for_key_type(key_type_byte, pub_bytes, target_hash, sig_bytes)
    except Exception:
        return False


def _link_content_hash(cap_ent: dict[str, Any]) -> bytes | None:
    """V7 v7.66 §5.3 helper — return a chain link's own content_hash bytes.

    Reads ``content_hash`` from the entity dict if present and decodable
    as a flat bytestring; otherwise re-computes via
    :meth:`Entity.compute_hash`. Returns None for malformed links.
    """
    raw = cap_ent.get("content_hash")
    normalized = _normalize_hash(raw)
    if normalized is not None:
        return normalized
    try:
        return Entity.from_dict(cap_ent).compute_hash()
    except Exception:
        return None


def _check_chain_format_code_freeze(
    chain: list[dict[str, Any]],
) -> DelegationResult | None:
    """V7 v7.66 §5.3 / CAP-FREEZE-1 — verify chain-link format-code continuity.

    Returns ``None`` on success (all link content_hashes share the same
    leading format-code byte) or a :class:`DelegationResult` with
    ``error_code='cap_chain_format_code_freeze'`` describing the
    mismatch. Reading A — only the chain's own link hashes, not signed
    targets.
    """
    first_format: int | None = None
    for depth, link in enumerate(chain):
        h = _link_content_hash(link)
        if h is None or len(h) == 0:
            # Malformed link — let downstream validation surface the
            # specific reason; format-code check abstains.
            continue
        link_format = h[0]
        if first_format is None:
            first_format = link_format
            continue
        if link_format != first_format:
            return DelegationResult(
                valid=False,
                error=(
                    f"cap chain spans content_hash_format codes "
                    f"({first_format:#x} at root, {link_format:#x} at depth {depth}); "
                    "cross-format chains require continuous re-signing per v7.66 §5.3"
                ),
                error_code="cap_chain_format_code_freeze",
                chain_depth=len(chain),
            )
    return None


def verify_capability_chain(
    capability: dict[str, Any],
    lookup: EntityLookup,
    find_signature: SignatureFinder,
    local_peer_id: str,
    now: int | None = None,
    find_signature_by_signer: SignatureBySignerFinder | None = None,
) -> DelegationResult:
    """Verify a capability's full chain per V7 §5.5.

    Per PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE §3.1: collect-then-validate.
    The chain is fully resolved by `collect_authority_chain` first, then
    each level is validated. This means chain-reachability errors take
    precedence over per-level signature/temporal failures on compound
    failures — the walker errors before validation runs. The 64-link
    max_depth bound (enforced by collect_authority_chain) keeps the
    pre-validation cost bounded.

    Validations performed (preserved from V7 §5.5):
    - Every level: signature exists, sig.signer == cap.granter, signature
      cryptographically verifies, temporal bounds (not_before / expires_at).
    - Non-root levels: current.granter == parent.grantee, attenuation
      against parent, delegation caveats.
    - Root level: granter.peer_id == local_peer_id (local peer is the
      sole root authority).

    V7.35 (PROPOSAL-MULTISIG-CORE-PRIMITIVE):
    - M3 (chain-walk entry): every chain entry whose granter is a
      multi-granter struct must satisfy the validity constraints; rejected
      caps fail closed before any signature work.
    - M4 (Site 1): per-link signature check branches on granter shape.
      Multi-sig path verifies K signatures from `signers` (dedup, threshold
      short-circuit).
    - M6 (Site 3): root granter identity lookup branches on granter shape.
      Multi-sig roots require the local peer to be in `signers` AND have
      signed the cap.

    Args:
        capability: The leaf capability to verify.
        lookup: Resolves entity hashes to entities (envelope `included`).
        find_signature: Locates the signature for a given content hash
            (single-sig path; first signature targeting hash).
        local_peer_id: Local peer ID — must match root cap's granter.
        now: Current timestamp in ms (default: current time).
        find_signature_by_signer: Optional locator for a signature with both
            target and signer matched (V7.35 §4.0). Required when any chain
            entry uses a multi-granter; if None and the path needs it, the
            chain is rejected.

    Returns:
        DelegationResult indicating chain validity.
    """
    import time

    if now is None:
        now = int(time.time() * 1000)

    # Phase 1: collect the full chain via the unified walker. Reachability
    # and max-depth are handled here — we never look at signatures or
    # validity until we know the chain structure is complete.
    collect_result = collect_authority_chain(capability, lookup, max_depth=64)
    if collect_result.status == ChainCollectStatus.TOO_DEEP:
        # V7 §4.10(b) (v7.75 resource-bounds floor): a chain deeper than the
        # peer's declared max_chain_depth is a client-correctable STRUCTURAL
        # excess, not an authorization verdict. Surface a distinct error_code
        # so the dispatcher returns 400 chain_depth_exceeded — NOT 403 (which
        # conflates "chain too deep" with "you lack the capability";
        # Keystone V7.75 ruling).
        return DelegationResult(
            valid=False,
            error="Delegation chain too deep (>64)",
            chain_depth=64,
            error_code="chain_depth_exceeded",
        )
    if collect_result.status == ChainCollectStatus.UNREACHABLE:
        missing = collect_result.unreachable_parent
        return DelegationResult(
            valid=False,
            error=(
                f"Parent capability not found: "
                f"{hash_to_display(missing) if missing else 'None'}"
            ),
            chain_depth=len(collect_result.chain),
        )

    chain = collect_result.chain
    if not chain:
        return DelegationResult(valid=False, error="Empty chain", chain_depth=0)

    # V7 v7.66 §5.3 / CAP-FREEZE-1 — cap-chain format-code freeze (Reading A).
    # Every chain link's own content_hash MUST share the same format-code
    # byte. Cross-format chains require a continuous re-signing event by
    # the chain's effective signer set; absent that, refuse to verify.
    #
    # Reading A: the freeze applies to the chain's OWN link content_hashes,
    # not to signed targets referenced via system/hash fields. Signed-target
    # cross-format resolves via the V7 §1.2 format-code-in-hash interpretation
    # (v7.67 §2.4 errata rename of the prior "§5.2 prefix-routing dispatch"
    # framing — semantics unchanged; framing aligned to "system property" per
    # v7.67 §2.3).
    chain_format_check = _check_chain_format_code_freeze(chain)
    if chain_format_check is not None:
        return chain_format_check

    # PR-3 (V7 v7.39 §3.6): per-link grantee resolution. Every cap in the
    # chain has its own `grantee`, and each MUST resolve to a `system/identity`
    # entity via the same lookup used for granter resolution. Caps whose
    # grantee is unresolvable (zero-hash bearer caps, malformed hashes,
    # references to absent identities) are rejected with `unresolvable_grantee`
    # — closes the bearer-cap surface SEC-18 surfaced. Self-caps
    # (grantee == granter) trivially pass because granter resolution at
    # M4/M6 below requires the same identity to be present.
    for depth, current in enumerate(chain):
        current_data = current.get("data", {})
        grantee_value = current_data.get("grantee")
        grantee_hash = _normalize_hash(grantee_value)
        if grantee_hash is None:
            return DelegationResult(
                valid=False,
                error=f"Capability grantee is missing or malformed (depth {depth})",
                chain_depth=depth,
                error_code="unresolvable_grantee",
            )
        if lookup(grantee_hash) is None:
            return DelegationResult(
                valid=False,
                error=(
                    f"Capability grantee does not resolve to a system/identity "
                    f"entity (depth {depth}, hash={hash_to_display(grantee_hash)})"
                ),
                chain_depth=depth,
                error_code="unresolvable_grantee",
            )

    # M3 (PROPOSAL §3.3): MUST validate multi-granter constraints at chain-walk
    # entry, before any signature or temporal work. Multi-sig caps must also
    # have parent=null (root-only) and a single-hash grantee.
    for depth, current in enumerate(chain):
        current_data = current.get("data", {})
        granter_value = current_data.get("granter")
        if not is_multi_granter(granter_value):
            continue
        ok, err = validate_multi_granter(granter_value)
        if not ok:
            return DelegationResult(
                valid=False,
                error=f"Invalid multi-granter (depth {depth}): {err}",
                chain_depth=depth,
            )
        # M3 root-only: parent MUST be null.
        if current_data.get("parent"):
            return DelegationResult(
                valid=False,
                error=(
                    f"Multi-sig capability must be root (parent=null), "
                    f"got non-null parent (depth {depth})"
                ),
                chain_depth=depth,
            )
        # Grantee remains a single hash (M3); a non-bytes grantee here means a
        # malformed token slipped past schema — fail closed.
        grantee_value = current_data.get("grantee")
        if not isinstance(grantee_value, (bytes, bytearray)):
            return DelegationResult(
                valid=False,
                error=(
                    f"Multi-sig capability grantee must be a single hash "
                    f"(depth {depth})"
                ),
                chain_depth=depth,
            )

    # Phase 2: per-level validation. Index 0 is leaf, len-1 is root.
    last_index = len(chain) - 1
    for depth, current in enumerate(chain):
        current_data = current.get("data", {})
        current_hash = current.get("content_hash")
        if current_hash:
            current_hash = _normalize_hash(current_hash)

        granter_value = current_data.get("granter")
        multi = get_multi_granter(granter_value)

        # M4 (PROPOSAL §4.1) — Site 1: per-link signature verification.
        # Branch on granter shape; multi-sig path runs the K-of-N inner loop.
        if current_hash:
            if multi is not None:
                if find_signature_by_signer is None:
                    return DelegationResult(
                        valid=False,
                        error=(
                            f"Multi-sig capability requires by-signer signature "
                            f"finder (depth {depth})"
                        ),
                        chain_depth=depth,
                    )
                seen: set[bytes] = set()
                valid_count = 0
                for candidate in multi.signers:
                    candidate_hash = _normalize_hash(candidate)
                    if candidate_hash is None:
                        continue
                    if candidate_hash in seen:
                        continue  # defensive dedupe
                    seen.add(candidate_hash)
                    candidate_identity = lookup(candidate_hash)
                    if candidate_identity is None:
                        continue
                    sig = find_signature_by_signer(current_hash, candidate_hash)
                    if sig is None:
                        continue
                    if _verify_signer_signed_target(
                        current_hash, candidate_hash, sig, candidate_identity,
                    ):
                        valid_count += 1
                        if valid_count >= multi.threshold:
                            break
                if valid_count < multi.threshold:
                    return DelegationResult(
                        valid=False,
                        error=(
                            f"Multi-sig threshold not met: "
                            f"{valid_count}/{multi.threshold} valid signatures "
                            f"(depth {depth})"
                        ),
                        chain_depth=depth,
                    )
            else:
                # Single-sig path (unchanged from V7).
                sig = find_signature(current_hash)
                if sig is None:
                    return DelegationResult(
                        valid=False,
                        error=f"Signature for capability not found (depth {depth})",
                        chain_depth=depth,
                    )

                sig_data = sig.get("data", {})
                granter_hash = _normalize_hash(granter_value)
                sig_signer = _normalize_hash(sig_data.get("signer"))

                if not hash_equals(sig_signer, granter_hash):
                    return DelegationResult(
                        valid=False,
                        error=f"Signature signer doesn't match capability granter (depth {depth})",
                        chain_depth=depth,
                    )

                granter_identity = lookup(granter_hash)
                if granter_identity is None:
                    return DelegationResult(
                        valid=False,
                        error=f"Granter identity not found (depth {depth})",
                        chain_depth=depth,
                    )

                if not _verify_signer_signed_target(
                    current_hash, granter_hash, sig, granter_identity,
                ):
                    return DelegationResult(
                        valid=False,
                        error=f"Invalid capability signature (depth {depth})",
                        chain_depth=depth,
                    )

        # Temporal bounds (every level).
        expires_at = current_data.get("expires_at")
        if expires_at is not None and expires_at < now:
            return DelegationResult(
                valid=False,
                error=f"Capability expired (depth {depth})",
                chain_depth=depth,
            )
        not_before = current_data.get("not_before")
        if not_before is not None and not_before > now:
            return DelegationResult(
                valid=False,
                error=f"Capability not yet valid (depth {depth})",
                chain_depth=depth,
            )

        if depth == last_index:
            # Root level. M6 (PROPOSAL §4.3) — root granter must "be" the
            # local peer: single-sig means literal identity match; multi-sig
            # means local peer is in `signers` AND has signed.
            if multi is not None:
                # Multi-sig root: at least one signer must be the local peer
                # AND must have a verified signature.
                if find_signature_by_signer is None:
                    return DelegationResult(
                        valid=False,
                        error=(
                            "Multi-sig root requires by-signer signature finder"
                        ),
                        chain_depth=depth,
                    )
                local_in_validated_signers = False
                for candidate in multi.signers:
                    candidate_hash = _normalize_hash(candidate)
                    if candidate_hash is None:
                        continue
                    candidate_identity = lookup(candidate_hash)
                    if candidate_identity is None:
                        continue
                    # v7.65 §2: peer_id no longer in entity data — derive
                    candidate_peer_id = _peer_id_from_identity_entity(candidate_identity)
                    if candidate_peer_id != local_peer_id:
                        continue
                    sig = find_signature_by_signer(current_hash, candidate_hash) if current_hash else None
                    if sig is None:
                        continue
                    if _verify_signer_signed_target(
                        current_hash, candidate_hash, sig, candidate_identity,
                    ):
                        local_in_validated_signers = True
                        break
                if not local_in_validated_signers:
                    return DelegationResult(
                        valid=False,
                        error=(
                            f"Multi-sig root not granted by local peer: "
                            f"local peer must be in signers AND have signed "
                            f"(local={local_peer_id})"
                        ),
                        chain_depth=depth,
                    )
            else:
                granter_hash = _normalize_hash(granter_value)
                granter_identity = lookup(granter_hash)
                if granter_identity is None:
                    return DelegationResult(
                        valid=False,
                        error="Root capability granter identity not found",
                        chain_depth=depth,
                    )
                # v7.65 §2: peer_id no longer in entity data — derive
                granter_peer_id = _peer_id_from_identity_entity(granter_identity)
                if granter_peer_id != local_peer_id:
                    return DelegationResult(
                        valid=False,
                        error=(
                            f"Root capability not granted by local peer: "
                            f"granter={granter_peer_id}, local={local_peer_id}"
                        ),
                        chain_depth=depth,
                    )
            continue

        # Non-root level — verify delegation against parent at chain[depth+1].
        # M5 (PROPOSAL §4.2): chain linkage is unchanged. M3 guarantees that
        # `current.granter` here is always a single hash (multi-sig caps are
        # root-only and were caught above), so `hash_equals` works directly.
        parent = chain[depth + 1]
        parent_data = parent.get("data", {})

        current_granter = _normalize_hash(granter_value)
        parent_grantee = _normalize_hash(parent_data.get("grantee"))
        if not hash_equals(parent_grantee, current_granter):
            return DelegationResult(
                valid=False,
                error=(
                    f"Granter/grantee chain broken: "
                    f"parent.grantee={hash_to_display(parent_grantee) if parent_grantee else 'None'}, "
                    f"current.granter={hash_to_display(current_granter) if current_granter else 'None'}"
                ),
                chain_depth=depth,
            )

        # V7 §5.5 / PR-8: derive each cap's granter peer_id so the chain-walk
        # subset-check on resources canonicalizes per-link against the link's
        # OWN granter, not against the verifier's local_peer_id. Foreign-granted
        # caps need their bare `*` resolved to the granter's namespace, not the
        # verifier's. `granter_identity` was already loaded above for the
        # current (child) link; load the parent's likewise from `lookup`.
        # Multi-sig parents (root-only per M3) and missing identities fall back
        # to local_peer_id to preserve the self-issued frame for those edges.
        child_granter_peer_id = local_peer_id
        if granter_identity is not None:
            try:
                child_granter_peer_id = _peer_id_from_identity_entity(granter_identity)
            except Exception:
                child_granter_peer_id = local_peer_id
        parent_granter_peer_id = local_peer_id
        # Single-sig granter: hash → identity → peer_id. Multi-sig granter
        # (root-only per M3) returns None from _normalize_hash and falls back
        # to local_peer_id.
        parent_granter_hash = _normalize_hash(parent_data.get("granter"))
        if parent_granter_hash is not None:
            parent_granter_identity = lookup(parent_granter_hash)
            if parent_granter_identity is not None:
                try:
                    parent_granter_peer_id = _peer_id_from_identity_entity(
                        parent_granter_identity
                    )
                except Exception:
                    parent_granter_peer_id = local_peer_id

        attenuation_result = is_attenuated(
            current,
            parent,
            local_peer_id,
            child_granter_peer_id=child_granter_peer_id,
            parent_granter_peer_id=parent_granter_peer_id,
        )
        if not attenuation_result.valid:
            return DelegationResult(
                valid=False,
                error=f"Attenuation check failed: {attenuation_result.error}",
                chain_depth=depth,
            )

        caveat_result = check_caveats(parent, current, depth, now)
        if not caveat_result.valid:
            return DelegationResult(
                valid=False,
                error=f"Caveat check failed: {caveat_result.error}",
                chain_depth=depth,
            )

    return DelegationResult(valid=True, chain_depth=last_index)


@dataclass
class AttenuationResult:
    """Result of attenuation check."""

    valid: bool
    error: str | None = None


def is_attenuated(
    child: dict[str, Any],
    parent: dict[str, Any],
    local_peer_id: str = "",
    child_granter_peer_id: str | None = None,
    parent_granter_peer_id: str | None = None,
) -> AttenuationResult:
    """Check if child capability is properly attenuated from parent.

    V4 Per-grant exclude inheritance per spec ss5.6:
    - Child grants must inherit excludes from their covering parent grant
    - Child resources must be subset of parent resources
    - Child operations must be subset of parent operations
    - Child expires_at must be <= parent expires_at

    V7 §5.5 / PR-8: each cap's resource patterns canonicalize against ITS
    OWN granter's peer_id, not the verifier's. Pass `child_granter_peer_id`
    / `parent_granter_peer_id` for the chain-walk subset-check on a
    foreign-granted chain. Both default to `local_peer_id` (the
    self-issued frame), preserving existing behavior for callers that
    haven't been threaded through.

    Args:
        child: The child capability entity.
        parent: The parent capability entity.
        local_peer_id: Local peer ID — used for handler/operation/peers
            canonicalization (no §PR-8 there) and as the resource-frame
            fallback when granter peer_ids are not supplied.
        child_granter_peer_id: Peer ID whose namespace the child cap's
            peer-relative resource patterns canonicalize against (§PR-8).
            Defaults to `local_peer_id`.
        parent_granter_peer_id: Same, for parent cap.

    Returns:
        AttenuationResult indicating if attenuation is valid.
    """
    if child_granter_peer_id is None:
        child_granter_peer_id = local_peer_id
    if parent_granter_peer_id is None:
        parent_granter_peer_id = local_peer_id

    child_data = child.get("data", {})
    parent_data = parent.get("data", {})

    child_grants = child_data.get("grants", [])
    parent_grants = parent_data.get("grants", [])

    # Check each grant in child is covered by parent (includes per-grant exclude check)
    for child_grant in child_grants:
        if not grant_covered_by(
            child_grant,
            parent_grants,
            local_peer_id,
            child_granter_peer_id,
            parent_granter_peer_id,
        ):
            return AttenuationResult(
                valid=False,
                error="Child grant not covered by parent grants",
            )

    # Check expiration: child.expires_at <= parent.expires_at
    child_expires = child_data.get("expires_at")
    parent_expires = parent_data.get("expires_at")

    if parent_expires is not None:
        if child_expires is None:
            return AttenuationResult(
                valid=False,
                error="Child has no expiration but parent does",
            )
        if child_expires > parent_expires:
            return AttenuationResult(
                valid=False,
                error="Child expires after parent",
            )

    return AttenuationResult(valid=True)


def grant_covered_by(
    child_grant: dict[str, Any],
    parent_grants: list[dict[str, Any]],
    local_peer_id: str = "",
    child_granter_peer_id: str | None = None,
    parent_granter_peer_id: str | None = None,
) -> bool:
    """Check if a child grant is covered by at least one parent grant.

    V4 Per-grant checking per spec ss5.6:
    - Child resources are subset of parent resources
    - Child operations are subset of parent operations
    - Child inherits that parent grant's excludes

    Args:
        child_grant: The child grant to check.
        parent_grants: List of parent grants.
        local_peer_id: Local peer ID for path canonicalization.
        child_granter_peer_id: §PR-8 frame for the child's resources; defaults to local_peer_id.
        parent_granter_peer_id: §PR-8 frame for the parent's resources; defaults to local_peer_id.

    Returns:
        True if the child grant is covered.
    """
    if child_granter_peer_id is None:
        child_granter_peer_id = local_peer_id
    if parent_granter_peer_id is None:
        parent_granter_peer_id = local_peer_id
    for parent_grant in parent_grants:
        if grant_subset(
            child_grant,
            parent_grant,
            local_peer_id,
            child_granter_peer_id,
            parent_granter_peer_id,
        ):
            return True
    return False


def grant_subset(
    child_grant: dict[str, Any],
    parent_grant: dict[str, Any],
    local_peer_id: str = "",
    child_granter_peer_id: str | None = None,
    parent_granter_peer_id: str | None = None,
) -> bool:
    """Check if child grant is a proper subset of parent grant.

    V4 Per-grant exclude inheritance per spec ss5.6:
    - Child handlers are subset of parent handlers
    - Child operations are subset of parent operations
    - Child resources are covered by parent resources
    - Child inherits THIS parent grant's excludes (per scope)

    V6.0: Updated to handle CapabilityScope structure.

    Args:
        child_grant: The child grant.
        parent_grant: The parent grant.
        local_peer_id: Local peer ID for path canonicalization.

    Returns:
        True if child is a proper subset of parent.
    """
    from entity_core.capability.checking import canonicalize, matches_pattern

    if child_granter_peer_id is None:
        child_granter_peer_id = local_peer_id
    if parent_granter_peer_id is None:
        parent_granter_peer_id = local_peer_id

    # V6.0: Get scopes
    child_handlers = get_scope(child_grant, "handlers")
    child_resources = get_scope(child_grant, "resources")
    child_operations = get_scope(child_grant, "operations")
    parent_handlers = get_scope(parent_grant, "handlers")
    parent_resources = get_scope(parent_grant, "resources")
    parent_operations = get_scope(parent_grant, "operations")

    # Handlers: child's include must be covered by parent's include
    if not scope_includes_subset(child_handlers.include, parent_handlers.include):
        return False

    # Operations: per V7 §3.6 line 836 + §5.4 line 1868 + §5.6 scope_subset,
    # operations follow the SAME pattern-matching rule as handlers and
    # resources. `operations: ["*"]` parent covers any narrower child.
    # (Earlier code used `set.issubset` here, which treated `*` literally
    # — a bug per V7. Fixed in PROPOSAL-ROLE-V1.5-SPEC-FIXES SI-24.)
    if not scope_includes_subset(child_operations.include, parent_operations.include):
        return False

    # Resources: every child resource must be matched by some parent resource.
    # V7 §5.5 / PR-8: each side canonicalizes against its OWN granter's
    # peer_id. Doing this BEFORE scope_includes_subset means bare `*` in a
    # foreign-granted cap means `/{granter}/*` (its namespace), not a
    # universal-wildcard short-circuit. Conflating the two frames lets a
    # foreign-granted bare `*` falsely cover the verifier's namespace —
    # the V1' bug class arch named in the Go V7.73 Amendment 1 V1-prime
    # reconstruction.
    if child_granter_peer_id:
        child_resources_include = [
            canonicalize(r, child_granter_peer_id) for r in child_resources.include
        ]
    else:
        child_resources_include = list(child_resources.include)
    if parent_granter_peer_id:
        parent_resources_include = [
            canonicalize(r, parent_granter_peer_id) for r in parent_resources.include
        ]
    else:
        parent_resources_include = list(parent_resources.include)
    if not scope_includes_subset(child_resources_include, parent_resources_include):
        return False

    # Excludes: child must inherit all of parent's excludes for each scope
    # Per spec §5.6: Per-grant exclude inheritance

    # Handler excludes
    if parent_handlers.exclude:
        for parent_exclude in parent_handlers.exclude:
            if not scope_exclude_inherited(parent_exclude, child_handlers, local_peer_id):
                return False

    # Resource excludes — parent canonicalizes against parent_granter_peer_id,
    # child excludes against child_granter_peer_id (§PR-8 per-side).
    if parent_resources.exclude:
        for parent_exclude in parent_resources.exclude:
            canonical_exclude = (
                canonicalize(parent_exclude, parent_granter_peer_id)
                if parent_granter_peer_id
                else parent_exclude
            )
            if not scope_exclude_inherited(
                canonical_exclude, child_resources, child_granter_peer_id
            ):
                return False

    # Operation excludes
    if parent_operations.exclude:
        for parent_exclude in parent_operations.exclude:
            if not scope_exclude_inherited(parent_exclude, child_operations, local_peer_id):
                return False

    # V7.14: Constraint attenuation — key retention + byte equality
    parent_constraints = parent_grant.get("constraints") or {}
    child_constraints = child_grant.get("constraints") or {}

    # Reject non-map values defensively
    if not isinstance(parent_constraints, dict) or not isinstance(child_constraints, dict):
        return False

    # Constraint keys can't be dropped (dropping widens access)
    for key in parent_constraints:
        if key not in child_constraints:
            return False  # Key dropped — escalation
        if parent_constraints[key] != child_constraints[key]:
            return False  # Value changed — deny by default (byte equality)

    # V7.14: Allowance attenuation — key containment + byte equality
    child_allowances = child_grant.get("allowances") or {}
    parent_allowances = parent_grant.get("allowances") or {}

    if not isinstance(child_allowances, dict) or not isinstance(parent_allowances, dict):
        return False

    # Allowance keys can't be added (adding widens access)
    for key in child_allowances:
        if key not in parent_allowances:
            return False  # Key added — escalation
        if child_allowances[key] != parent_allowances[key]:
            return False  # Value changed — deny by default (byte equality)

    return True


def scope_includes_subset(child_includes: list[str], parent_includes: list[str]) -> bool:
    """Check if child include patterns are a subset of parent include patterns.

    Each child pattern must be covered by at least one parent pattern.

    Args:
        child_includes: Child include patterns.
        parent_includes: Parent include patterns.

    Returns:
        True if all child patterns are covered by parent.
    """
    for child_pattern in child_includes:
        covered = False
        for parent_pattern in parent_includes:
            if pattern_covers(parent_pattern, child_pattern):
                covered = True
                break
        if not covered:
            return False
    return True


def scope_exclude_inherited(
    parent_exclude: str,
    child_scope: CapabilityScope,
    local_peer_id: str = "",
) -> bool:
    """Check that child scope's excludes cover the parent exclude.

    Per spec §5.6: The child exclude must match at least everything
    the parent exclude matches. A broader child exclude (e.g. B/*
    covering B/private/*) is acceptable; a narrower is not.

    Args:
        parent_exclude: Parent exclude pattern (canonical for resources).
        child_scope: The child CapabilityScope.
        local_peer_id: Local peer ID for path canonicalization.

    Returns:
        True if child scope inherits the parent exclude.
    """
    from entity_core.capability.checking import canonicalize, matches_pattern

    if not child_scope.exclude:
        return False

    for child_exclude in child_scope.exclude:
        canonical_child_exclude = canonicalize(child_exclude, local_peer_id) if local_peer_id else child_exclude
        # Check if child exclude covers parent exclude
        # A broader child exclude covers a narrower parent exclude
        if matches_pattern(canonical_child_exclude, parent_exclude):
            return True

    return False


def pattern_covers(parent_pattern: str, child_pattern: str) -> bool:
    """Check if parent pattern covers (is equal to or more general than) child pattern.

    Per v7.18: patterns use leading / for absolute paths.
    Peer wildcard uses /*/ prefix instead of */.

    Args:
        parent_pattern: The parent pattern.
        child_pattern: The child pattern to check.

    Returns:
        True if parent covers child.
    """
    # Exact match
    if parent_pattern == child_pattern:
        return True

    # Universal wildcards cover everything
    if parent_pattern in ("*", "/*/*"):
        return True

    # Normalize entity:// prefix to absolute path
    if parent_pattern.startswith("entity://"):
        parent_pattern = "/" + parent_pattern[len("entity://"):]
    if child_pattern.startswith("entity://"):
        child_pattern = "/" + child_pattern[len("entity://"):]

    # For subtree patterns (ending in /*), check if child is under parent's subtree
    if parent_pattern.endswith("/*"):
        parent_prefix = parent_pattern[:-1]  # Remove trailing *
        # Child must start with parent prefix
        if child_pattern.startswith(parent_prefix):
            return True
        # Child subtree must be under parent subtree
        if child_pattern.endswith("/*"):
            child_prefix = child_pattern[:-1]
            if child_prefix.startswith(parent_prefix):
                return True

    # Handle wildcard in peer position: /*/path/* covers /specificpeer/path/*
    if parent_pattern.startswith("/*/"):
        parent_suffix = parent_pattern[3:]  # Remove /*/ prefix
        # Child: /peer/rest -> extract rest after peer segment
        if child_pattern.startswith("/"):
            child_parts = child_pattern[1:].split("/", 1)
            if len(child_parts) == 2:
                child_path = child_parts[1]
                if pattern_covers(parent_suffix, child_path):
                    return True

    return False


@dataclass
class CaveatResult:
    """Result of caveat check."""

    valid: bool
    error: str | None = None


def check_caveats(
    parent: dict[str, Any],
    child: dict[str, Any],
    depth: int,
    now: int,
) -> CaveatResult:
    """Check parent's delegation_caveats against the delegation.

    V4 §5.7: Delegation caveats is a flat struct with optional fields:
    - no_delegation: bool - if true, cannot delegate further
    - max_delegation_depth: uint - maximum chain depth from this capability
    - max_delegation_ttl: uint - maximum lifetime (ms) for delegated capabilities

    Args:
        parent: Parent capability entity.
        child: Child capability entity.
        depth: Current delegation depth.
        now: Current timestamp in milliseconds.

    Returns:
        CaveatResult indicating if caveats are satisfied.
    """
    parent_data = parent.get("data", {})
    child_data = child.get("data", {})

    # V4 §3.6: Field is named "delegation_caveats", not "caveats"
    # V4: It's a flat struct, not an array
    caveats = parent_data.get("delegation_caveats")
    if caveats is None:
        # No caveats - delegation allowed
        return CaveatResult(valid=True)

    # V4 §5.7: no_delegation - if true, cannot delegate further
    if caveats.get("no_delegation") is True:
        return CaveatResult(
            valid=False,
            error="Capability has no_delegation caveat",
        )

    # V4 §5.7: max_delegation_depth - maximum chain depth from this capability
    max_depth = caveats.get("max_delegation_depth")
    if max_depth is not None:
        if depth >= max_depth:
            return CaveatResult(
                valid=False,
                error=f"Delegation depth {depth} exceeds limit {max_depth}",
            )

    # V4 §5.7: max_delegation_ttl - maximum lifetime for delegated capabilities
    max_ttl = caveats.get("max_delegation_ttl")
    if max_ttl is not None:
        child_created = child_data.get("created_at", now)
        child_expires = child_data.get("expires_at")

        if child_expires is None:
            # Infinite lifetime exceeds any finite limit
            return CaveatResult(
                valid=False,
                error="Child has infinite TTL but parent limits delegation TTL",
            )

        child_ttl = child_expires - child_created
        if child_ttl > max_ttl:
            return CaveatResult(
                valid=False,
                error=f"Child TTL {child_ttl}ms exceeds limit {max_ttl}ms",
            )

    return CaveatResult(valid=True)


def validate_delegation(
    child: dict[str, Any],
    parent: dict[str, Any],
    now: int | None = None,
    local_peer_id: str = "",
) -> DelegationResult:
    """Validate a delegation at creation time.

    This is called when creating a delegated capability to ensure
    the delegation is valid before it's created.

    Args:
        child: The child capability being created.
        parent: The parent capability being delegated from.
        now: Current timestamp in milliseconds.
        local_peer_id: Local peer ID for path canonicalization.

    Returns:
        DelegationResult indicating if the delegation is valid.
    """
    import time

    if now is None:
        now = int(time.time() * 1000)

    # V4: Granter of child must be grantee of parent (bytes comparison)
    child_data = child.get("data", {})
    parent_data = parent.get("data", {})

    child_granter = _normalize_hash(child_data.get("granter"))
    parent_grantee = _normalize_hash(parent_data.get("grantee"))

    if not hash_equals(child_granter, parent_grantee):
        return DelegationResult(
            valid=False,
            error=f"Child granter must be parent grantee: child.granter={hash_to_display(child_granter) if child_granter else 'None'}, parent.grantee={hash_to_display(parent_grantee) if parent_grantee else 'None'}",
        )

    # Check attenuation (with per-grant exclude inheritance)
    attenuation_result = is_attenuated(child, parent, local_peer_id)
    if not attenuation_result.valid:
        return DelegationResult(
            valid=False,
            error=f"Attenuation failed: {attenuation_result.error}",
        )

    # Check caveats (depth 0 since this is a direct delegation)
    caveat_result = check_caveats(parent, child, 0, now)
    if not caveat_result.valid:
        return DelegationResult(
            valid=False,
            error=f"Caveat check failed: {caveat_result.error}",
        )

    return DelegationResult(valid=True)
