"""Connect protocol handler.

Connect uses EXECUTE messages for the handshake:
1. Initiator -> EXECUTE(uri="system/protocol/connect", op="hello", params={...})
2. Responder -> EXECUTE_RESPONSE with hello data
3. Initiator -> EXECUTE(uri="system/protocol/connect", op="authenticate", params={...})
4. Responder -> EXECUTE_RESPONSE with capability grant

Architecture:
- Refless architecture: signature found via target-matching
- Token in data, not refs
- nonce and public_key are primitive/bytes on wire
- Signatures sign full hash bytes (algorithm + digest)

Connect is special-cased in dispatch (per spec), not a normal handler.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any

from entity_core.capability.grant import (
    Grant,
    create_capability_token,
)
from entity_core.crypto.identity import Keypair, peer_id_from_public_key_bytes
from entity_core.protocol.entity import Entity as _Entity
from entity_core.utils.ecf import ecf_encode as _ecf_encode
from entity_core.crypto.signing import (
    public_key_from_bytes,
    verify_for_key_type,
    verify_signature,
)
from entity_core.primitives import Uint
from entity_core.protocol.auth import create_identity_entity, create_signature_entity
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.messages import Execute, ExecuteResponse
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    DEFAULT_ADVERTISED_KEY_TYPES,
    Hash,
    default_advertised_hash_formats,
    hash_equals,
    hash_format_name,
    negotiate_active_hash_format,
    normalize_hash,
)

logger = logging.getLogger(__name__)

CONNECT_URI = "system/protocol/connect"

# Use shared normalize_hash from ecf module
_normalize_hash = normalize_hash


@dataclass
class ConnectState:
    """State tracking for the connect handshake.

    Attributes:
        phase: Current phase - "awaiting_hello", "awaiting_authenticate", or "complete".
        our_nonce: The nonce we sent in our hello (for verifying their signature).
        their_nonce: The nonce they sent in their hello.
        remote_peer_id: Remote peer's ID from their hello.
        remote_public_key_bytes: Remote peer's public key bytes (set after authenticate).
    """

    phase: str = "awaiting_hello"
    our_nonce: bytes = b""
    their_nonce: bytes = b""
    remote_peer_id: str = ""
    remote_public_key_bytes: bytes = b""
    # V7 v7.69 §4.5/§4.5a — the connection's negotiated active
    # content_hash_format, computed at hello time (responder side) and read at
    # authenticate time so every entity authored for this connection (cap mint,
    # cap signature, our identity/authenticate) uses one format. Defaults to
    # SHA-256 (the §4.5 floor) until hello negotiation overwrites it.
    active_hash_format: int = ALG_ECFV1_SHA256

    @property
    def is_complete(self) -> bool:
        """Whether connect has completed."""
        return self.phase == "complete"


class ConnectError(Exception):
    """Connect handshake failed.

    ``code`` is the V7 §4.7 wire response code (defaults to
    ``"bad_request"``); call sites set it to a more specific value
    (e.g. ``"unsupported_key_type"``) so the wire-boundary handler
    in ``peer.py`` emits the canonical error code rather than
    collapsing every connect failure to ``bad_request``.
    """

    def __init__(self, message: str, *, code: str = "bad_request") -> None:
        super().__init__(message)
        self.code = code


def handle_connect_hello(
    state: ConnectState,
    params: dict[str, Any],
    local_keypair: Keypair,
    request_id: str = "",
) -> tuple[ConnectState, ExecuteResponse]:
    """Handle a connect hello from the remote peer (responder side).

    Validates the hello params, stores state, and returns an EXECUTE_RESPONSE
    with our hello data in the result.

    Connect uses request-response pattern throughout.
    Hello EXECUTE receives EXECUTE_RESPONSE with hello data as result.

    Args:
        state: Current connect state.
        params: Hello params from the remote peer.
        local_keypair: Our keypair.
        request_id: Request ID from the incoming EXECUTE.

    Returns:
        Tuple of (updated state, EXECUTE_RESPONSE with hello data).

    Raises:
        ConnectError: If state is invalid for receiving a hello.
    """
    logger.debug("[connect] op=hello phase=%s", state.phase)

    if state.phase != "awaiting_hello":
        raise ConnectError(f"Unexpected hello in phase: {state.phase}")

    # Params is a full entity per spec - data contains the actual fields
    params_data = params.get("data", {})
    remote_peer_id = params_data.get("peer_id", "")
    their_nonce = params_data.get("nonce", b"")
    protocols = params_data.get("protocols", [])
    timestamp = params_data.get("timestamp", 0)

    if not remote_peer_id:
        raise ConnectError("Missing peer_id in hello")
    if not their_nonce:
        raise ConnectError("Missing nonce in hello")

    # V7 v7.69 §4.5 — negotiate the connection's active content_hash_format and
    # check key_type mutual verifiability. Absent fields take the §4.5 floor
    # defaults (initiator that predates v7.69 advertises nothing → SHA-256 /
    # Ed25519). Our advertised sets derive from this peer's default format
    # (a SHA-384 peer advertises ["ecfv1-sha384","ecfv1-sha256"]).
    initiator_hash_formats = params_data.get("hash_formats") or ["ecfv1-sha256"]
    initiator_key_types = params_data.get("key_types") or ["ed25519"]
    our_hash_formats = default_advertised_hash_formats()
    our_key_types = DEFAULT_ADVERTISED_KEY_TYPES

    # Single active value (§4.5): first match in the INITIATOR's order.
    active_format = negotiate_active_hash_format(initiator_hash_formats, our_hash_formats)
    if active_format is None:
        raise ConnectError(
            f"no common hash format: initiator {initiator_hash_formats}, "
            f"responder {our_hash_formats}",
            code="incompatible_hash_format",
        )

    # Accept-set (§4.5): key_type is identity-bound — our own key_type MUST be
    # in the initiator's advertised verify-set (mutual verifiability). The
    # symmetric direction (initiator's key_type in ours) is structurally
    # satisfied because we advertise the full accept-set; a custom-set
    # initiator omitting an allocated key_type lands on the authenticate-side
    # reject (§4.6). Hello is the canonical earliest reject point (§4.5).
    if local_keypair.key_type not in initiator_key_types:
        raise ConnectError(
            f"key_type {local_keypair.key_type!r} not in initiator verify-set "
            f"{initiator_key_types}",
            code="unsupported_key_type",
        )

    # Generate our nonce (32 random bytes)
    our_nonce = secrets.token_bytes(32)
    now_ms = int(time.time() * 1000)

    # Update state
    state.remote_peer_id = remote_peer_id
    state.their_nonce = their_nonce
    state.our_nonce = our_nonce
    state.active_hash_format = active_format
    state.phase = "awaiting_authenticate"

    # Create hello entity as result — advertise our negotiation sets so the
    # initiator computes the same active format and authors its authenticate
    # under it.
    hello_entity = Entity(
        type="system/protocol/connect/hello",
        data={
            "peer_id": local_keypair.peer_id,
            "nonce": our_nonce,
            "protocols": ["entity-core/7.0"],
            "timestamp": Uint(now_ms),
            "hash_formats": our_hash_formats,
            "key_types": our_key_types,
        },
    )

    # Hello receives EXECUTE_RESPONSE with hello data as result
    hello_response = ExecuteResponse(
        request_id=request_id,
        status=Uint(200),
        result=hello_entity.to_dict(),
    )

    return state, hello_response


def _grants_fingerprint(grants: list[Grant]) -> bytes:
    """Deterministic SHA256 over ECF-encoded grant dicts.

    Used as a cache key for granter idempotency (R3a) — same `(grantee_peer_id,
    grants)` tuple → same minted token (rather than fresh `created_at: now()`
    each handshake). The fingerprint covers the full grant shape so a re-grant
    with widened/narrowed scope does NOT hit the cache and hand out a stale
    cap.
    """
    payload = [g.to_dict() for g in grants]
    return hashlib.sha256(_ecf_encode(payload)).digest()


def handle_connect_authenticate(
    state: ConnectState,
    params: dict[str, Any],
    envelope: Envelope,
    local_keypair: Keypair,
    grants: list[Grant],
    expires_in_ms: int | None = None,
    *,
    held_capability: tuple[_Entity, _Entity, _Entity] | None = None,
) -> tuple[ConnectState, ExecuteResponse, Envelope, tuple[_Entity, _Entity, _Entity], bool]:
    """Handle a connect authenticate from the remote peer (responder side).

    Verifies their signature over the AUTHENTICATE hash, creates our authenticate
    response with capability, and marks connect as complete.

    Uses target-matching to find signature (not refs).
    Signatures sign full hash bytes.

    Args:
        state: Current connect state.
        params: Authenticate params from the remote peer.
        envelope: The envelope containing the AUTHENTICATE (for signature lookup).
        local_keypair: Our keypair.
        grants: Permission grants for the connect capability.
        expires_in_ms: Optional capability expiration time in milliseconds.
            Default is None — connection cap omits `expires_at`, matching
            Go (`core/protocol/connect.go` issues caps with no `ExpiresAt`).
            A finite default would force callers minting chained caps with
            their own TTL to clamp below the connection cap's expiry, which
            cross-impl tests don't do (e.g. tv_rd_caller_expiry_inheritance
            mints `now + 1h`, parented at a connection cap also issued at
            `now + 1h` — the chained cap's expiry exceeds the parent by the
            connect→mint latency and V7 §5.6 attenuation rejects it).

    Args (continued):
        held_capability: Optional pre-fetched ``(capability_entity,
            granter_identity, cap_signature)`` triple. When the caller has a
            live cap for this peer (e.g. from the R6
            ``system/peer/session/{peer_id}`` tree entity), it SHOULD pass it
            here to honor R3a idempotency — same authorization, same entity,
            until expiry. When ``None``, a fresh cap is minted.

    Returns:
        Tuple of ``(updated state, ExecuteResponse, full Envelope,
        (capability_entity, granter_identity, cap_signature), minted_fresh)``.
        ``minted_fresh`` is ``True`` when this call minted a new cap (and the
        caller SHOULD persist the session entity), ``False`` when the
        ``held_capability`` was reused as-is.

    Raises:
        ConnectError: If verification fails or state is invalid.
    """
    logger.debug("[connect] op=authenticate phase=%s", state.phase)

    if state.phase != "awaiting_authenticate":
        raise ConnectError(f"Unexpected authenticate in phase: {state.phase}")

    # Params is a full entity per spec - data contains the actual fields
    params_data = params.get("data", {})
    params_hash = params.get("content_hash")
    remote_peer_id = params_data.get("peer_id", "")
    public_key_raw = params_data.get("public_key")
    key_type = params_data.get("key_type", "ed25519")
    nonce = params_data.get("nonce", b"")

    if not remote_peer_id or not public_key_raw:
        raise ConnectError("Missing required authenticate fields")

    # public_key is raw bytes
    if not isinstance(public_key_raw, bytes):
        raise ConnectError(f"Invalid public_key format: {type(public_key_raw)}")
    public_key_bytes = public_key_raw

    # Verify peer_id matches hello
    if remote_peer_id != state.remote_peer_id:
        raise ConnectError(
            f"Authenticate peer_id mismatch: expected {state.remote_peer_id}, got {remote_peer_id}"
        )

    # Verify peer_id is BOUND to the presented public_key (V7 v7.64 §1.5
    # construction: Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)).
    # Without this the self-consistency check above only proves hello and
    # authenticate name the same peer_id — an attacker can claim a victim's
    # peer_id, present their own public_key, echo the nonce and sign with their
    # own key, minting a connection authorized as the victim (G-A identity
    # spoofing). Derive with the SAME (key_type, hash_type) the presented
    # peer_id encodes so identity-form and SHA-256-form peers both pass.
    from entity_core.crypto.identity import (
        UnsupportedKeyTypeError,
        _peer_id_from_bytes,
        decode_peer_id as _decode_peer_id,
        validate_supported_key_type,
    )
    try:
        presented_key_type, presented_hash_type, _ = _decode_peer_id(remote_peer_id)
    except Exception as exc:
        raise ConnectError(
            f"identity_mismatch: peer_id {remote_peer_id} undecodable: {exc}"
        )
    # V7 v7.66 §4.4 surface 6 / AGILITY-UNKNOWN-1 — reject unallocated
    # key_type bytes at the handshake boundary. Protocol maps to
    # `400 unsupported_key_type` (V7 §4.7).
    try:
        validate_supported_key_type(presented_key_type)
    except UnsupportedKeyTypeError as exc:
        raise ConnectError(str(exc), code="unsupported_key_type")
    # V7 v7.66 §3.3 — wire-acceptance binding-verification re-derives the
    # presented (key_type, hash_type) pair to verify pubkey binding. Public
    # mint API is canonical-only; this verification path uses the internal
    # assembly helper.
    derived_peer_id = _peer_id_from_bytes(
        public_key_bytes,
        key_type=presented_key_type,
        hash_type=presented_hash_type,
    )
    if remote_peer_id != derived_peer_id:
        raise ConnectError(
            f"identity_mismatch: peer_id {remote_peer_id} does not derive from "
            f"presented public_key (derived {derived_peer_id})"
        )

    # Verify nonce echoes our nonce
    if nonce != state.our_nonce:
        raise ConnectError(
            f"Nonce mismatch: expected {state.our_nonce[:8].hex()}..., got {nonce[:8].hex() if nonce else 'empty'}..."
        )

    # Params is a full entity per spec - use its content_hash for verification
    if not params_hash:
        raise ConnectError("Missing content_hash in authenticate params")

    # Normalize hash to bytes
    authenticate_hash = _normalize_hash(params_hash)
    if not authenticate_hash:
        raise ConnectError("Invalid content_hash format")

    #Find signature via target-matching (not refs)
    signature_dict = envelope.find_signature_for_target(authenticate_hash)
    if not signature_dict:
        raise ConnectError("Signature for AUTHENTICATE not found in included")

    #Verify signature over hash bytes
    try:
        sig_data = signature_dict.get("data", {})
        signature_raw = sig_data.get("signature")

        #signature is raw bytes
        if not isinstance(signature_raw, bytes):
            raise ConnectError(f"Invalid signature format: {type(signature_raw)}")
        signature_bytes = signature_raw

        # Verify target matches the AUTHENTICATE entity hash
        sig_target = _normalize_hash(sig_data.get("target"))
        if not hash_equals(sig_target, authenticate_hash):
            raise ConnectError("Signature target doesn't match AUTHENTICATE hash")

        # V7 v7.67 Phase 2 — dispatch the verifier on the presented key_type
        # (decoded from the peer_id above) so an Ed448 peer is verified with
        # Ed448. Ed25519 remains the default for key_type=0x01.
        if not verify_for_key_type(
            presented_key_type, public_key_bytes, authenticate_hash, signature_bytes,
        ):
            raise ConnectError("Invalid signature in authenticate")
    except ConnectError:
        raise
    except Exception as e:
        raise ConnectError(f"Signature verification failed: {e}")

    state.remote_public_key_bytes = public_key_bytes

    # V7 v7.69 §4.5a — author every entity for this connection under the
    # negotiated active format (computed at hello). A SHA-384 home peer that
    # negotiated down to SHA-256 with a SHA-256-only initiator authors SHA-256
    # here, so grantee == author holds on this connection (§5.2).
    active_format = state.active_hash_format

    # Create our AUTHENTICATE entity for the response
    #Type is "system/protocol/connect/authenticate"
    #No refs - signature found via target-matching
    #nonce and public_key are raw bytes
    our_authenticate_entity = Entity(
        type="system/protocol/connect/authenticate",
        data={
            "peer_id": local_keypair.peer_id,
            "public_key": local_keypair.public_key_bytes(),
            "key_type": local_keypair.key_type,
            "nonce": state.their_nonce,
        },
        hash_algorithm=active_format,
    )
    our_authenticate_hash = our_authenticate_entity.compute_hash()

    # V7 v7.65 §2: system/peer data = (public_key, key_type) only
    our_identity_entity = create_identity_entity(local_keypair, algorithm=active_format)
    our_identity_hash = our_identity_entity.compute_hash()

    # Sign our AUTHENTICATE hash (V4: hash bytes, not string)
    #signer is identity hash, not peer_id
    our_signature_entity = create_signature_entity(
        local_keypair, our_authenticate_hash, our_identity_hash, algorithm=active_format,
    )

    # V7 v7.69 §1.8 (Task 1) — the capability grantee is the connecting peer's
    # *authored* identity hash, carried on the wire as the authenticate
    # signature's ``signer``. Use that entity verbatim; do NOT reconstruct the
    # grantee identity from wire (public_key, key_type) and re-hash it under a
    # local format — that manufactures a second content_hash form and is the
    # precise M3 cross-format mismatch (grantee ≠ author). Under §4.5a the
    # connecting peer authored its identity under this connection's active
    # format, so the authored grantee and our reconstruction would coincide;
    # using the wire form is the §1.8 safety rail that keeps them coincident.
    signer_hash = _normalize_hash(signature_dict.get("data", {}).get("signer"))
    grantee_identity = None
    if signer_hash:
        grantee_dict = envelope.find_included(signer_hash)
        if grantee_dict:
            grantee_identity, _ = Entity.from_wire_dict(grantee_dict)
    if grantee_identity is None:
        # Fallback (signer not in included): reconstruct under the active
        # format so it still matches the connecting peer's §4.5a authoring.
        grantee_identity = Entity(
            type="system/peer",
            data={
                "public_key": public_key_bytes,
                "key_type": key_type,
            },
            hash_algorithm=active_format,
        )

    # R3a — granter idempotency (PROPOSAL-TRANSPORT-FAMILY §7.3):
    # reuse a live cap for this grantee+grants rather than emitting a fresh
    # `created_at: now()` triple per handshake. R6: the held cap
    # lives in the tree at `system/peer/session/{remote_peer_id}` — the caller
    # passes it via `held_capability` (looked up via
    # `entity_core.peer.session_entity.read_held_capability`). When absent,
    # mint fresh and report ``minted_fresh=True`` so the caller persists the
    # session entity.
    minted_fresh = False
    if held_capability is not None:
        capability_entity, granter_identity, cap_signature = held_capability
    else:
        capability_entity, granter_identity, cap_signature = create_capability_token(
            local_keypair,
            grantee_identity,
            grants,
            expires_in_ms=expires_in_ms,
            algorithm=active_format,
        )
        minted_fresh = True

    cap_hash = capability_entity.compute_hash()

    state.phase = "complete"

    #result.data.token contains the capability token hash
    #result type is "system/capability/grant"
    grant_result_entity = Entity(
        type="system/capability/grant",
        data={
            "token": cap_hash,  #bytes - the capability token hash
        },
    )

    response = ExecuteResponse(
        request_id="",  # Caller will set this
        status=Uint(200),
        result=grant_result_entity.to_dict(),
    )

    # Build envelope with included entities
    #Signatures are found via target-matching
    included = [
        # Our authenticate entity and signature (for client verification)
        our_authenticate_entity.to_dict(),
        our_identity_entity.to_dict(),
        our_signature_entity.to_dict(),
        # Capability chain
        capability_entity.to_dict(),
        granter_identity.to_dict(),
        grantee_identity.to_dict(),
        cap_signature.to_dict(),
    ]

    response_envelope = Envelope(
        root=response.to_entity(),
        included=included,
    )

    return (
        state,
        response,
        response_envelope,
        (capability_entity, granter_identity, cap_signature),
        minted_fresh,
    )


def create_connect_hello_execute(keypair: Keypair) -> tuple[Execute, bytes]:
    """Create a connect hello EXECUTE message (initiator/client side).

    Args:
        keypair: Our keypair.

    Returns:
        Tuple of (Execute message, our nonce for later verification).
    """
    #nonce is raw bytes (32 bytes)
    nonce = secrets.token_bytes(32)
    now_ms = int(time.time() * 1000)

    # Create HELLO entity - params is a full entity per spec
    #type is system/protocol/connect/hello
    # V7 v7.69 §4.5 — advertise preference-ordered hash_formats (single active
    # value) and the key_types accept-set so the responder can negotiate.
    hello_entity = Entity(
        type="system/protocol/connect/hello",
        data={
            "peer_id": keypair.peer_id,
            "nonce": nonce,
            "protocols": ["entity-core/7.0"],
            "timestamp": Uint(now_ms),
            "hash_formats": default_advertised_hash_formats(),
            "key_types": DEFAULT_ADVERTISED_KEY_TYPES,
        },
    )

    execute = Execute.create(
        uri=CONNECT_URI,
        operation="hello",
        params=hello_entity.to_dict(),
    )

    return execute, nonce


def create_connect_authenticate_execute(
    keypair: Keypair,
    their_nonce: bytes,
    *,
    algorithm: int | None = None,
) -> tuple[Execute, Entity, Entity]:
    """Create a connect authenticate EXECUTE message (initiator/client side).

Signature is found via target-matching, not refs.
    Signature signs full hash bytes.
Type is "system/protocol/connect/authenticate".

    Args:
        keypair: Our keypair.
        their_nonce: The nonce from the responder's hello (bytes).
        algorithm: V7 v7.69 §4.5a — the connection's active
            content_hash_format (computed by the initiator from the responder's
            advertised hello sets). The authenticate entity, our identity
            entity, and the signature are all authored under it so the
            responder's grantee reference (= our authored identity hash) matches
            our ``author`` on subsequent EXECUTEs. ``None`` → process-global
            default.

    Returns:
        Tuple of (Execute message, signature entity, identity entity to include).
    """
    #nonce and public_key are raw bytes
    #Type is "system/protocol/connect/authenticate"
    authenticate_entity = Entity(
        type="system/protocol/connect/authenticate",
        data={
            "peer_id": keypair.peer_id,
            "public_key": keypair.public_key_bytes(),
            "key_type": keypair.key_type,
            "nonce": their_nonce,
        },
        hash_algorithm=algorithm,
    )
    authenticate_hash = authenticate_entity.compute_hash()

    # V7 v7.65 §2: system/peer data = (public_key, key_type) only
    identity_entity = create_identity_entity(keypair, algorithm=algorithm)
    identity_hash = identity_entity.compute_hash()

    #Sign the hash bytes (not string)
    #signer is identity hash, not peer_id
    signature_entity = create_signature_entity(
        keypair, authenticate_hash, identity_hash, algorithm=algorithm,
    )

    # Create Execute with params as full entity (per spec)
    #operation is "authenticate"
    execute = Execute.create(
        uri=CONNECT_URI,
        operation="authenticate",
        params=authenticate_entity.to_dict(),
    )

    #Caller includes signature and identity entities in envelope.included
    # Verifier finds signature via target-matching

    return execute, signature_entity, identity_entity


def verify_connect_authenticate_response(
    response_result: dict[str, Any],
    envelope: Envelope,
    our_nonce: bytes,
    expected_peer_id: str | None = None,
) -> tuple[str, bytes, Hash]:
    """Verify the authenticate response from the responder's EXECUTE_RESPONSE.

The result is system/capability/grant with token in data.
    The granter's identity is in the envelope's included entities (via capability.data.granter).

    The server's identity (peer_id, public_key) is extracted from the granter identity
    entity, since the server is the granter of the connect capability.

    Args:
        response_result: The result dict from the EXECUTE_RESPONSE (system/capability/grant).
        envelope: The response envelope (for capability and identity lookup).
        our_nonce: Our nonce (unused in new flow, kept for API compatibility).
        expected_peer_id: Optional expected peer ID for verification.

    Returns:
        Tuple of (remote_peer_id, remote_public_key_bytes, capability_token_hash).

    Raises:
        ConnectError: If verification fails.
    """
    #Result is system/capability/grant with token in data
    result_type = response_result.get("type", "")
    result_data = response_result.get("data", {})

    if result_type != "system/capability/grant":
        raise ConnectError(f"Expected result type system/capability/grant, got {result_type}")

    token_hash = result_data.get("token")
    if not token_hash:
        raise ConnectError("Missing token in authenticate response result")

    token_hash = _normalize_hash(token_hash)
    if not token_hash:
        raise ConnectError("Invalid token hash format")

    # Find the capability token in included
    capability_dict = envelope.find_included(token_hash)
    if not capability_dict:
        raise ConnectError("Capability token not found in included")

    capability_data = capability_dict.get("data", {})
    granter_hash = capability_data.get("granter")
    if not granter_hash:
        raise ConnectError("Capability missing granter field")

    granter_hash = _normalize_hash(granter_hash)
    if not granter_hash:
        raise ConnectError("Invalid granter hash format")

    # Find the granter's identity entity in included
    granter_identity = envelope.find_included(granter_hash)
    if not granter_identity:
        raise ConnectError("Granter identity not found in included")

    granter_data = granter_identity.get("data", {})
    public_key_raw = granter_data.get("public_key")
    if not public_key_raw:
        raise ConnectError("Missing public_key in granter identity")
    # v7.65 §2: peer_id no longer in entity data — derive canonical wire form
    from entity_core.crypto.identity import peer_id_from_identity_entity
    remote_peer_id = peer_id_from_identity_entity(granter_identity)
    if not remote_peer_id:
        raise ConnectError("Could not derive peer_id from granter identity")

    if expected_peer_id and remote_peer_id != expected_peer_id:
        raise ConnectError(
            f"Expected peer {expected_peer_id}, got {remote_peer_id}"
        )

    #public_key is raw bytes
    if not isinstance(public_key_raw, bytes):
        raise ConnectError(f"Invalid public_key format: {type(public_key_raw)}")
    public_key_bytes = public_key_raw

    # Optionally verify capability signature (granter signed the capability)
    capability_hash = capability_dict.get("content_hash")
    if capability_hash:
        capability_hash = _normalize_hash(capability_hash)
        signature_dict = envelope.find_signature_for_target(capability_hash)
        if signature_dict:
            try:
                sig_data = signature_dict.get("data", {})
                signature_raw = sig_data.get("signature")

                #signature is raw bytes
                if not isinstance(signature_raw, bytes):
                    raise ConnectError(f"Invalid signature format: {type(signature_raw)}")
                signature_bytes = signature_raw

                # V7 v7.67 Phase 2 — the granter (remote server) signed the
                # capability; dispatch the verifier on the server's key_type,
                # decoded from its peer_id.
                from entity_core.crypto.identity import decode_peer_id
                granter_key_type, _ht, _d = decode_peer_id(remote_peer_id)
                if not verify_for_key_type(
                    granter_key_type, public_key_bytes, capability_hash, signature_bytes,
                ):
                    raise ConnectError("Invalid capability signature")
            except ConnectError:
                raise
            except Exception as e:
                logger.warning(f"Capability signature verification failed: {e}")

    return remote_peer_id, public_key_bytes, token_hash
