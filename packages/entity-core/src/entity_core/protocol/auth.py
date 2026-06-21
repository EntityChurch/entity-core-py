"""Authenticated request creation and verification.

This module handles creating signed EXECUTE requests and verifying them.
An authenticated request includes:
- The EXECUTE message with author/capability in data
- An identity entity (author)
- A signature entity (proof of authorship via target-matching)
- A capability token (authorization)

V4 Changes:
- Refless architecture: author and capability are in data, not refs
- Target-matching: signatures are found by scanning included for matching target
- Signatures sign full hash bytes (algorithm + digest), not strings
- Signature target is bytes, not string
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, TYPE_CHECKING

from entity_core.crypto.identity import Keypair
from entity_core.crypto.signing import verify_for_key_type
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.messages import Execute
from entity_core.utils.ecf import Hash, hash_equals, hash_to_display, normalize_hash

if TYPE_CHECKING:
    from entity_core.capability.revocation import RevocationContext

# Use shared normalize_hash from ecf module
_normalize_hash = normalize_hash


@dataclass
class AuthenticatedRequest:
    """An authenticated EXECUTE request with all supporting entities."""

    execute: Execute
    identity_entity: Entity
    signature_entity: Entity
    capability_dict: dict[str, Any]  # Keep as dict to preserve content_hash
    capability_chain: list[dict[str, Any]] | None = None  # Supporting entities (signature, granter identity)
    # V7 v7.69 §4.5a — the connection's active content_hash_format. The execute
    # root is re-serialized here for the wire, so it MUST hash under the same
    # format the signature targeted in create_authenticated_request.
    algorithm: int | None = None

    def to_envelope(self) -> Envelope:
        """Convert to wire envelope with included entities.

        V4 §5.8: Entire capability chain must be in included (capability, signature, granter identity).
        """
        included = [
            self.identity_entity.to_dict(),
            self.signature_entity.to_dict(),
            self.capability_dict,  # Already has content_hash from wire
        ]
        # Include capability chain entities (signature for capability, granter identity, etc.)
        if self.capability_chain:
            included.extend(self.capability_chain)
        return Envelope(
            root=self.execute.to_entity(self.algorithm),
            included=included,
        )


def create_identity_entity(keypair: Keypair, *, algorithm: int | None = None) -> Entity:
    """V7 v7.65 §2 — system/peer entity (canonical-form, no peer_id in data).

    content_hash(system/peer) is a pure function of (public_key, key_type)
    per the F amendment: peer_id has exited the hashable basis. The wire
    peer_id is a presentation/routing handle (§1.5) and is carried at the
    transport layer, not inside the entity.

    ``algorithm`` (V7 v7.69 §4.5a) is the connection's active
    content_hash_format. Connection-bound callers (handshake, ongoing
    authenticated requests) MUST pass it so the identity reference this
    entity yields matches what the peer authors elsewhere on the same
    connection (``grantee == author``, §1.8). ``None`` → process-global
    default.
    """
    return Entity(
        type="system/peer",
        data={
            "public_key": keypair.public_key_bytes(),
            "key_type": keypair.key_type,
        },
        hash_algorithm=algorithm,
    )


def create_peer_entity(public_key: bytes, key_type: str = "ed25519") -> Entity:
    """V7 v7.65 §2 — build a canonical system/peer entity from (pubkey, key_type).

    Used at sites that have a remote peer's pubkey but not their Keypair
    (e.g., handshake-completion, capability granter construction).

    V7 v7.66 §2 errata — the ``key_type`` parameter here is the
    *entity-data field surface*: a ``primitive/string`` (canonical
    ``"ed25519"`` for Ed25519; ``"experimental-test"`` for the v7.66
    stub cryptosystem). It is NOT the binary peer_id wire-format prefix
    (``uint8`` varint, ``0x01`` / ``0xFE``); see
    ``entity_core.crypto.identity`` for the wire-form surface.
    """
    return Entity(
        type="system/peer",
        data={
            "public_key": public_key,
            "key_type": key_type,
        },
    )


def compute_peer_identity_hash(
    peer_id: str | None = None,
    public_key: bytes | None = None,
    key_type: str = "ed25519",
) -> bytes:
    """V7 v7.65 §2/§3 — return the peer's ``system/peer`` content hash
    bytes (33 bytes: algorithm byte + 32-byte digest).

    Pure function of (public_key, key_type) under v7.65. ``peer_id`` is
    accepted as a convenience for callers holding only the wire handle:
    when ``public_key`` is omitted, pubkey is derived from a canonical
    (identity-multihash) ``peer_id`` via ``derive_peer_from_peer_id``.

    Callers post-handshake should have ``public_key`` in hand and pass
    it directly. The ``peer_id`` parameter is no longer in the hashable
    basis — it is consulted only as a decode source when pubkey is missing.
    """
    if public_key is None:
        if peer_id is None:
            raise ValueError("compute_peer_identity_hash: provide public_key or peer_id")
        from entity_core.crypto.identity import derive_peer_from_peer_id
        derived = derive_peer_from_peer_id(peer_id)
        if derived is None:
            raise ValueError(
                "public_key required for non-canonical-form PeerID "
                f"{peer_id[:16]}...; identity-form PeerIDs derive locally"
            )
        public_key, _key_type = derived
    return Entity(
        type="system/peer",
        data={
            "public_key": public_key,
            "key_type": key_type,
        },
    ).compute_hash()


def create_signature_entity(
    keypair: Keypair,
    target_hash: Hash,
    signer_identity_hash: Hash | None = None,
    *,
    algorithm: int | None = None,
) -> Entity:
    """Create a signature entity for a target.

    V4: Signs the full hash bytes (algorithm + digest).
    Target and signer are stored as bytes (content hashes).

    Args:
        keypair: The signer's keypair.
        target_hash: Content hash of the entity being signed (bytes).
        signer_identity_hash: Content hash of signer's identity entity (bytes).
            If None, creates identity entity and computes hash.
        algorithm: V7 v7.69 §4.5a active content_hash_format. The signature
            entity is itself authored under it (it rides in ``included``), and
            the internally-derived signer identity (when ``signer_identity_hash``
            is None) is authored under it too. ``None`` → process-global default.

    Returns:
        A signature entity.
    """
    # V4: signer is the content hash of the signer's identity entity, not peer_id
    if signer_identity_hash is None:
        identity_entity = create_identity_entity(keypair, algorithm=algorithm)
        signer_identity_hash = identity_entity.compute_hash()

    # V4: Sign the full hash bytes (algorithm + digest)
    signature = keypair.sign(target_hash)

    return Entity(
        type="system/signature",
        data={
            "target": target_hash,  # V4: bytes
            # V7 v7.67 Phase 2 — algorithm tracks the signing keypair's actual
            # key_type, not a hardcoded "ed25519". The cap-chain verifier
            # cross-checks this against the granter's system/peer.key_type
            # (see capability/grant_signing.py); a stale literal here is what
            # makes an Ed448 peer's grants self-verify as
            # unsupported_signature_algorithm.
            "algorithm": keypair.key_type,
            "signature": signature,  # V4: raw bytes
            "signer": signer_identity_hash,  # V4: bytes - content hash of identity entity
        },
        hash_algorithm=algorithm,
    )


def create_authenticated_request(
    keypair: Keypair,
    execute: Execute,
    capability_dict: dict[str, Any],
    capability_chain: list[dict[str, Any]] | None = None,
    *,
    algorithm: int | None = None,
) -> AuthenticatedRequest:
    """Create a fully authenticated EXECUTE request.

    V4: author and capability are set in execute.data, signature is
    found via target-matching in the envelope's included map.

    V4 §5.8: The entire capability chain must be in the envelope's included.

    Args:
        keypair: The requester's keypair.
        execute: The EXECUTE message.
        capability_dict: The capability token dict (with content_hash from wire).
        capability_chain: Supporting entities for the capability (signature, granter identity).

    Returns:
        An AuthenticatedRequest with all supporting entities.
    """
    # Create identity entity. V7 v7.69 §4.5a — author under the connection's
    # active format so execute.author matches the cap grantee (issued under the
    # same active format during the handshake).
    identity_entity = create_identity_entity(keypair, algorithm=algorithm)
    identity_hash = identity_entity.compute_hash()

    # Use capability hash from the received dict - don't recompute
    capability_hash = capability_dict.get("content_hash")
    if not capability_hash:
        # Fallback for locally created capabilities
        cap_entity = Entity.from_dict(capability_dict)
        capability_hash = cap_entity.compute_hash()
    capability_hash = _normalize_hash(capability_hash)

    # V4: Set author and capability in execute data (as bytes)
    execute.author = identity_hash
    execute.capability = capability_hash

    # Create a signable representation of the execute (with author/capability set)
    execute_wire = execute.to_entity(algorithm)
    execute_hash = execute_wire["content_hash"]
    execute_hash = _normalize_hash(execute_hash)

    # Create signature entity - signs hash bytes per V4
    # V4: Signature is found via target-matching, not refs
    # V4: signer is identity_hash (content hash of identity entity), not peer_id
    signature_entity = create_signature_entity(
        keypair, execute_hash, identity_hash, algorithm=algorithm,
    )

    return AuthenticatedRequest(
        execute=execute,
        identity_entity=identity_entity,
        signature_entity=signature_entity,
        capability_dict=capability_dict,
        capability_chain=capability_chain,
        algorithm=algorithm,
    )


@dataclass
class VerificationResult:
    """Result of verifying an authenticated request."""

    valid: bool
    error: str | None = None
    identity_entity: Entity | None = None
    capability_entity: Entity | None = None
    # PR-3 (V7 v7.39 §3.6): subcode propagated from chain validation so
    # the dispatcher can map to the right status code (e.g. 401
    # `unresolvable_grantee`). None falls back to the generic 403.
    error_code: str | None = None


# Type alias for entity lookup function (for delegation chain verification)
EntityLookup = Callable[[bytes | str], dict[str, Any] | None]


def verify_request_integrity(
    envelope: Envelope,
    now: int | None = None,
    entity_lookup: EntityLookup | None = None,
    local_peer_id: str = "",
    revocation_ctx: "RevocationContext | None" = None,
) -> VerificationResult:
    """Verify request integrity per V7 §5.2.

    First phase of two-level verification. Checks:
    1. Execute signature is valid (found via target-matching)
    2. sig.signer == execute.author
    3. Capability chain is valid (including root cap verification)
    4. Grantee matches author
    5. (F2 / V7 §5.2 v7.63) Revocation check when ``revocation_ctx`` is
       supplied AND ``revocation_ctx.supports_revocation`` is true: the
       MUST-level wire-in of ``is_revoked`` (§5.1). Catches caps revoked
       since issuance — including wire-only caps that only the marker
       mechanism can intercept.

    Does NOT check handler scope or path permission - those are separate.

    Args:
        envelope: The envelope containing the EXECUTE and included entities.
        now: Current timestamp in milliseconds.
        entity_lookup: Optional function to look up entities by hash (for delegation chains).
        local_peer_id: Local peer ID for root capability verification.
        revocation_ctx: Optional revocation context. When provided AND
            ``supports_revocation == True``, ``is_revoked`` is invoked on
            the capability after chain validation and its rejection is
            honored (V7 §5.2 v7.63 MUST). Pass ``None`` only when the
            peer genuinely does not support revocation.

    Returns:
        VerificationResult indicating validity. Rejection by ``is_revoked``
        surfaces as ``error_code = "revoked"`` so the dispatcher can route
        it to the right response code.
    """
    if now is None:
        now = int(time.time() * 1000)

    execute_dict = envelope.root
    if execute_dict.get("type") != Execute.TYPE:
        return VerificationResult(valid=False, error="Not an EXECUTE message")

    execute = Execute.from_entity(execute_dict)

    # V4: Get author and capability from data (as bytes)
    #
    # V7 v7.71 §3.3 verdict-to-status: §5.2 step-1/step-2 failures (content
    # hash + signature/author/identity resolution — the wire-side
    # authentication half) carry error_code="authentication_failed" so the
    # dispatcher maps them to 401. The authorization half (missing/absent
    # capability, grantee mismatch, chain DENY — step-3+) stays on the 403
    # default. A failed signature is "we cannot authenticate this author",
    # not "you are not authorized".
    if not execute.author:
        return VerificationResult(
            valid=False, error="Missing author in data",
            error_code="authentication_failed",
        )
    if not execute.capability:
        return VerificationResult(valid=False, error="Missing capability in data")

    # Normalize to bytes
    author_hash = _normalize_hash(execute.author)
    capability_hash = _normalize_hash(execute.capability)

    # Find included entities by hash
    identity_dict = envelope.find_included(author_hash)
    if not identity_dict:
        return VerificationResult(
            valid=False, error="Identity entity not found in included",
            error_code="authentication_failed",
        )

    capability_dict = envelope.find_included(capability_hash)
    if not capability_dict:
        return VerificationResult(valid=False, error="Capability entity not found in included")

    # V4: Find signature via target-matching
    execute_hash = envelope.root.get("content_hash")
    if not execute_hash:
        return VerificationResult(
            valid=False, error="Execute missing content_hash",
            error_code="authentication_failed",
        )

    execute_hash = _normalize_hash(execute_hash)

    signature_dict = envelope.find_signature_for_target(execute_hash)
    if not signature_dict:
        return VerificationResult(
            valid=False, error="Signature for execute not found in included",
            error_code="authentication_failed",
        )

    identity_entity = Entity.from_dict(identity_dict)
    signature_entity = Entity.from_dict(signature_dict)
    capability_entity = Entity.from_dict(capability_dict)

    # Verify signature target matches execute's content_hash
    sig_target = signature_entity.data.get("target")
    sig_target = _normalize_hash(sig_target)
    if not hash_equals(sig_target, execute_hash):
        return VerificationResult(
            valid=False, error="Signature target mismatch",
            error_code="authentication_failed",
        )

    # V4 §5.2: Verify signature.data.signer == execute.data.author
    sig_signer = signature_entity.data.get("signer")
    sig_signer = _normalize_hash(sig_signer)
    if not hash_equals(sig_signer, author_hash):
        return VerificationResult(
            valid=False,
            error=f"Signature signer doesn't match author: signer={hash_to_display(sig_signer) if sig_signer else 'None'}, author={hash_to_display(author_hash) if author_hash else 'None'}",
            error_code="authentication_failed",
        )

    # V4: Verify signature over hash bytes
    try:
        public_key_raw = identity_entity.data.get("public_key")
        if not isinstance(public_key_raw, bytes):
            return VerificationResult(
                valid=False, error=f"Invalid public_key format: {type(public_key_raw)}",
                error_code="authentication_failed",
            )
        public_key_bytes = public_key_raw

        signature_raw = signature_entity.data.get("signature")
        if not isinstance(signature_raw, bytes):
            return VerificationResult(
                valid=False, error=f"Invalid signature format: {type(signature_raw)}",
                error_code="authentication_failed",
            )
        signature_bytes = signature_raw

        # V7 v7.67 Phase 2 — dispatch the verifier on the author's key_type
        # (entity-data string on the signer's system/peer entity), so an
        # Ed448 author's request verifies with Ed448.
        from entity_core.crypto.identity import key_type_byte_from_entity_data
        author_key_type = identity_entity.data.get("key_type", "ed25519")
        key_type_byte = key_type_byte_from_entity_data(author_key_type)

        # V4: Signed message is the hash bytes
        if not verify_for_key_type(
            key_type_byte, public_key_bytes, execute_hash, signature_bytes,
        ):
            return VerificationResult(
                valid=False, error="Invalid signature",
                error_code="authentication_failed",
            )
    except Exception as e:
        return VerificationResult(
            valid=False, error=f"Signature verification error: {e}",
            error_code="authentication_failed",
        )

    # Verify capability grantee matches author
    cap_data = capability_dict.get("data", {})
    grantee_hash = cap_data.get("grantee")
    grantee_hash = _normalize_hash(grantee_hash)

    # V7 §5.2 / PR-3 (v7.39 §3.6) single 401 carve-out: grantee RESOLUTION
    # precedes grantee/author matching. A leaf cap whose grantee does not
    # resolve to an identity entity (zero/malformed hash, or a hash absent
    # from the wire envelope and store) is `unresolvable_grantee` → 401, NOT
    # the 403 grantee-mismatch verdict. This mirrors the per-link resolution
    # check verify_capability_chain runs over interior links; the leaf cap's
    # grantee was previously only seen by the == author test below, which
    # collapsed an unresolvable grantee into a generic 403. (AUTHZ-GRANTEE-1.)
    grantee_lookup = entity_lookup if entity_lookup else envelope.find_included
    if grantee_hash is None or grantee_lookup(grantee_hash) is None:
        return VerificationResult(
            valid=False,
            error="Capability grantee unresolvable",
            error_code="unresolvable_grantee",
        )

    if not hash_equals(grantee_hash, author_hash):
        return VerificationResult(
            valid=False,
            error=f"Capability grantee doesn't match author: grantee={hash_to_display(grantee_hash) if grantee_hash else 'None'}, author={hash_to_display(author_hash) if author_hash else 'None'}"
        )

    # V4 §5.2: Verify full capability chain (including root cap verification)
    # This verifies:
    # - Capability signatures at each level
    # - sig.signer == cap.granter at each level
    # - Temporal bounds at each level
    # - For root caps: granter.peer_id == local_peer_id
    # - For delegated caps: chain continuity, attenuation, caveats
    from entity_core.capability.delegation import verify_capability_chain

    # Use provided lookup or fall back to envelope lookup
    lookup = entity_lookup if entity_lookup else envelope.find_included

    # Create signature finders from envelope
    def find_signature(target_hash: bytes) -> dict[str, Any] | None:
        return envelope.find_signature_for_target(target_hash)

    def find_signature_by_signer(
        target_hash: bytes, signer_hash: bytes,
    ) -> dict[str, Any] | None:
        return envelope.find_signature_by_signer(target_hash, signer_hash)

    chain_result = verify_capability_chain(
        capability_dict,
        lookup,
        find_signature,
        local_peer_id,
        now,
        find_signature_by_signer=find_signature_by_signer,
    )
    if not chain_result.valid:
        return VerificationResult(
            valid=False,
            error=f"Capability chain invalid: {chain_result.error}",
            error_code=chain_result.error_code,
        )

    # F2 (V7 §5.2 v7.63): MUST wire `is_revoked` in when the peer advertises
    # `supports_revocation = true`. The marker mechanism is the only path
    # that catches wire-only cap revocation; an impl that writes the marker
    # on `revoke` but does not read it here silently fails open.
    if revocation_ctx is not None and revocation_ctx.supports_revocation:
        from entity_core.capability.revocation import is_revoked
        if is_revoked(capability_dict, revocation_ctx):
            return VerificationResult(
                valid=False,
                error="Capability revoked",
                error_code="revoked",
            )

    return VerificationResult(
        valid=True,
        identity_entity=identity_entity,
        capability_entity=capability_entity,
    )


