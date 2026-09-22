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
from entity_core.protocol.auth import (
    create_identity_entity,
    create_peer_entity,
    create_signature_entity,
)
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

#: The connect-URI operations **this responder implements**, in any state.
#:
#: V7 §4.7 (0.8.2.4) splits what used to be one row on exactly this predicate:
#: *"an operation the responder implements, arriving in a forbidden state,
#: emits **409 `connection_sequence_error`**; an operation it does not
#: implement emits **400 `invalid_request`**"* — and the unknown-operation row
#: says **"in any state"**, so membership here, not the connection's phase, is
#: what picks the row. §4.6 step 1 / §4.7 row 6 carve the pre-hello
#: ``authenticate`` out of the 409 side and pin it to ``401 invalid_nonce``;
#: that carve-out lives at the raise in :func:`handle_connect_authenticate`,
#: not here, because it is a rule about one input rather than about the set.
#:
#: **This is a set, not a chain of ``==`` comparisons, because the two wire
#: boundaries were classifying by different means.** ``ping`` is served
#: post-connect in ``_handle_execute`` and was unnamed in ``_handle_connect``,
#: so a pre-hello ping fell through to the unknown-operation arm and answered
#: ``400 invalid_request`` — the row for an operation this peer *does*
#: implement (`entity-core-go`'s ``connect_ping_before_hello``, routed
#: 2026-09-02; go had the same defect wearing a different costume, ``403
#: connection_required``, a code in no spec). The next operation added to the
#: connect surface is classified by adding it here, once.
IMPLEMENTED_CONNECT_OPERATIONS = frozenset({"hello", "authenticate", "ping"})

#: V7 §8.4 *Protocol Version* — the wire identifier advertised in a hello's
#: ``protocols`` and echoed by the responder. §4.5 negotiates it as
#: *"Intersection, must be non-empty"*, so it is the one hello field whose
#: **string** is the contract rather than its meaning.
#:
#: **This peer advertised ``entity-core/7.0`` until 2026-09-01, and nothing
#: could see it.** The spec's own §8.4 and §4.4 hello example, `entity-core-go`
#: and `entity-core-rust` all say ``entity-core/1.0``; the "7" was almost
#: certainly read off the specification's *title* (``ENTITY-CORE-PROTOCOL-V7``,
#: §-cited as v7.69 throughout) — which is the same conflation this repo's own
#: `AGENTS.md` versioning section exists to refuse, arriving on the wire
#: instead of on a package. **A document's version and the identifier it pins
#: are two numbers, and one of them is a string a peer compares byte for byte.**
#:
#: It survived because §4.5's *"must be non-empty"* had no implementer: the
#: field was carried on every hello in the cohort and read by nobody, and a
#: dead field cannot diverge observably. Measured the day the first seat
#: implemented the check — a py initiator against an `entity-core-go` peer at
#: `7262f17` gets `400 incompatible_protocol`, i.e. the cohort partitions along
#: this constant.
#:
#: **One home, deliberately.** The value was four literals (both hellos, the
#: `system/peer` advertisement, a CLI help string) and the cost of a fifth is a
#: peer that negotiates one string and advertises another.
PROTOCOL_VERSION = "entity-core/1.0"

#: What we advertise. A list because §4.5 negotiates a set; one element because
#: one version exists. A second entry here is a wire commitment, not a default.
ADVERTISED_PROTOCOLS = [PROTOCOL_VERSION]

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
    ``"invalid_request"``, §3.3's declared generic 400 and the code
    0.8.2.4 names for a malformed connect request); call sites set it
    to a more specific value (e.g. ``"unsupported_key_type"``) so the
    wire-boundary handler in ``peer.py`` emits the canonical error code
    rather than collapsing every connect failure to the generic one.
    The default was ``"bad_request"`` — a synonym no spec code set
    contains — until 2026-09-02; see ``ExecuteResponse.bad_request``.

    **Both directions carry the code.** Responder-side that was fixed once
    already (the cohort sweep caught Python answering a generic
    ``bad_request`` for an unallocated key type). Dialer-side it was still
    collapsing: ``Connection.connect`` / ``HttpConnection.connect`` folded a
    refusal into a message string and dropped the remote's ``code`` and
    ``status`` entirely, so a check of a pinned handshake-refusal row could
    only ever assert that *something* was raised. Same defect class as
    core-go's R-7 extractor, on the other side of the same seam — which is
    why the audit had to reach past the checks to the layer beneath them.
    ``status`` is the §4.7 wire status of the refusal, and it reads the same
    way from both seats: dialer-side it is what the remote answered, ``None``
    when the failure was purely local (nothing was refused, so there is
    nothing to carry); responder-side it is what the wire boundary in
    ``peer.py`` will answer, ``None`` meaning §4.7's 400 default. It exists on
    the responder side because §4.7's table is a list of ``(failure, code,
    status)`` triples and three of its ten rows are 401 — a boundary that
    carried the code and hardcoded the status could only ever emit two thirds
    of a row (FM-1).
    """

    def __init__(
        self, message: str, *, code: str = "invalid_request", status: int | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def connect_refusal(prefix: str, response: "ExecuteResponse") -> ConnectError:
    """Build a ``ConnectError`` from a remote's non-200 handshake response,
    preserving what the remote actually said.

    The dialer-side extractor. Both transports route their refusals through
    here so neither can quietly go back to collapsing the answer into prose:
    the remote's ``code`` and ``status`` land on the exception AND in its
    message, so an assertion can reach either.
    """
    # The fallback is deliberately NOT a wire code. This value reports what the
    # *remote* said, so filling an absent `code` with a plausible one (the
    # generic `invalid_request`, say) would have this extractor fabricate a
    # claim about a peer that made none — and a non-conformant peer answering a
    # coded status with no code is exactly the case worth being able to see.
    # It was `"bad_request"`, which read as a code and is not one.
    code = ""
    message = ""
    if isinstance(response.result, dict):
        data = response.result.get("data")
        body = data if isinstance(data, dict) else response.result
        raw_code = body.get("code")
        if isinstance(raw_code, str) and raw_code:
            code = raw_code
        message = body.get("message", body.get("error", "")) or ""
    return ConnectError(
        f"{prefix} (status {int(response.status)} {code}): {message}",
        code=code,
        status=int(response.status),
    )


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
        # §4.7 row 10 — "Out-of-order operation — e.g. a second `hello` after
        # `hello_done`" is `connection_sequence_error`. A second hello on an
        # ESTABLISHED connection is row 9 instead and never reaches here: the
        # wire boundary answers `409 connection_already_established` first. So
        # the only phase arriving here is a re-hello mid-handshake, which is
        # row 10's own example.
        #
        # arch ruled 2026-09-01 (FM-2 Edit D) that this — a valid operation
        # arriving in a state that forbids it — is a STATE CONFLICT and takes
        # **409**, not the landed table's 400. Row 9's precedent is the
        # derivation: `connection_already_established` is already 409 for the
        # same class, and §4.6's Hardening block presumes 409 is what a state
        # conflict gets when it rules that a 409 *under-signals a replay*. The
        # unknown-operation half of row 10 is the opposite case — nothing is out
        # of order there — and stays 400, in `peer/peer.py`.
        #
        # Landed ahead of the FM-2 fold, matching `entity-core-go` (which has
        # emitted 409 here all along) and `entity-core-rust`. The code half was
        # never contested; `bad_request`, which this raise carried before G-28,
        # is in no §4.7 row at all.
        raise ConnectError(
            f"connection_sequence_error: unexpected hello in phase {state.phase}",
            code="connection_sequence_error",
            status=409,
        )

    # Params is a full entity per spec - data contains the actual fields
    params_data = params.get("data", {})
    remote_peer_id = params_data.get("peer_id", "")
    their_nonce = params_data.get("nonce", b"")
    timestamp = params_data.get("timestamp", 0)

    if not remote_peer_id:
        raise ConnectError("Missing peer_id in hello")
    if not their_nonce:
        raise ConnectError("Missing nonce in hello")

    # V7 §4.5 — the unsupported-`key_type` CANONICAL REJECT POINT, which this
    # peer was not honoring: §4.5 says in terms that "hello negotiation is the
    # canonical earliest reject point for an unsupported `key_type`" and that
    # "hello-time reject is the canonical guidance for new implementations
    # (matches Rust's choice)". Ours rejected at `authenticate` (§4.6 step 0)
    # and nowhere else, which the AGILITY-UNKNOWN-1 vector tolerated — it is
    # satisfied "at any handshake surface" — so the gap read as green for as
    # long as the hello let the frame through.
    #
    # **It stopped reading as green the moment the protocols check landed, and
    # that is the whole reason this is here.** go's probe sends a hello whose
    # `peer_id` encodes key_type 0xFD *and* whose `protocols` is
    # `entity-core/v7` — a THIRD spelling of the version string, in no spec and
    # no implementation. With the intersection checked and no hello-side
    # key-type gate, that frame is refused `incompatible_protocol` and the
    # key-type vector never gets a surface to be satisfied at. Adding a check
    # that should always have run is a behaviour change; this is the second
    # finding it exposed, and the fix is the one §4.5 already asked for rather
    # than a reordering to suit a probe.
    #
    # Ordered BEFORE the protocols check deliberately: a `peer_id` whose
    # key_type is unallocated is a statement about WHO is calling, and §4.5
    # gives that reject point a name and a "canonical earliest" status it gives
    # no other hello check. An undecodable peer_id is NOT refused here — that
    # is §4.6 step 3's identity binding (§4.7 row 8, a 401), and pulling it
    # forward would move a row nobody asked us to move.
    from entity_core.crypto.identity import (
        UnsupportedKeyTypeError,
        decode_peer_id as _decode_peer_id_hello,
        validate_supported_key_type as _validate_key_type_hello,
    )

    try:
        _hello_key_type, _, _ = _decode_peer_id_hello(remote_peer_id)
    except Exception:
        _hello_key_type = None  # §4.6 step 3's row, not this one.
    if _hello_key_type is not None:
        try:
            _validate_key_type_hello(_hello_key_type)
        except UnsupportedKeyTypeError as exc:
            raise ConnectError(str(exc), code="unsupported_key_type")

    # V7 §4.5 — `protocols` is "Intersection, must be non-empty"; §4.7 row 1
    # pins the refusal as `400 incompatible_protocol`. Both halves are LANDED
    # text (§4.5's negotiation table, §4.7's row), which is why this lands now
    # rather than with the rest of FM-2: arch's ruling records that the row
    # "needs no spec change — it needs the check §4.5 already requires", and
    # FM-2's Edit B leaves the row itself untouched. Nothing here is downstream
    # of the draft.
    #
    # **The absent case is RULED, and it went the other way from what we
    # shipped (0.8.2.4, §4.5 + §4.7; SA-PY-31 closed).** We shipped reading 1 —
    # an omitted or empty list is UNCONSTRAINED — matching `entity-core-go`,
    # and filed the gap rather than settling it, because on this surface a
    # divergence is a *refused connection* and two seats declining to widen it
    # is not the same as agreement.
    #
    # §4.5 now carries the arm in normative text: `protocols` is Required with
    # **no default**, so unlike `hash_formats` and `key_types` there is no floor
    # to fall back to, and "a hello carrying no `protocols` field, or an empty
    # list, MUST be rejected with `400 invalid_request`". §4.7's row 1 was
    # narrowed in the same fold to a **non-empty** disjoint set.
    #
    # Our filing's own argument is what carried it and it is worth keeping,
    # because it is the half a reader can re-derive: `incompatible_protocol`
    # says *"we compared and share nothing"*, which cannot be said to a caller
    # that named no version — the remedies differ (send the field vs. change the
    # version) and §4.7 exists so the code selects the remedy. That is arch's
    # row-10 split applied one row up. What the filing got wrong was the
    # *fallback*: we reasoned from the two ground-up seats and reading 1 was
    # never the cohort position — keystone's `csharp` and `typescript` peers
    # already required the field and passed conformance, so reading 1 would have
    # made 46 generated peers non-conformant.
    #
    # Ordered AFTER the key_type gate and BEFORE the intersection, matching
    # `entity-core-go`: the empty set is refused as malformed before anything
    # tries to compare it, so `incompatible_protocol` can only ever be answered
    # about a comparison that actually happened.
    #
    # Absent and empty are ONE input here by ruling ("no `protocols` field, or
    # an empty list") — the `or []` fold that used to be a silent second ruling
    # is now the ruled shape. Both arms keep their own row in the tests.
    initiator_protocols = params_data.get("protocols") or []
    if not initiator_protocols:
        raise ConnectError(
            "protocols is required and MUST be non-empty (§4.5): a hello that "
            "names no protocol version is a malformed request, not a version "
            "incompatibility",
            code="invalid_request",
        )
    if not (set(initiator_protocols) & set(ADVERTISED_PROTOCOLS)):
        raise ConnectError(
            f"no common protocol version: initiator {initiator_protocols}, "
            f"responder {ADVERTISED_PROTOCOLS}",
            code="incompatible_protocol",
        )

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
            "protocols": ADVERTISED_PROTOCOLS,
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
        # §4.7 row 6 / §4.6 step 1 / §4.2 (0.8.2.1, FM-1): an `authenticate`
        # arriving before any hello nonce was issued is `401 invalid_nonce`,
        # NOT §4.7's out-of-order row. §4.7 says so in terms — a captured
        # `authenticate` replayed onto a fresh connection IS this input, so it
        # is an authentication failure and not a malformed request, and it
        # takes the same status the Hardening block pins for the adjacent
        # same-connection replay (RT-6). The caller has already answered the
        # established-connection case, so the only phase reaching here is
        # `awaiting_hello`.
        #
        # The status is carried, not just the code: the wire boundary emits
        # whatever `ConnectError.status` says, and setting the code alone
        # would produce `400 invalid_nonce` — a pair in no §4.7 row, on the
        # surface whose entire defect was a pair in no §4.7 row.
        raise ConnectError(
            f"Unexpected authenticate in phase: {state.phase}",
            code="invalid_nonce",
            status=401,
        )

    # Params is a full entity per spec - data contains the actual fields
    params_data = params.get("data", {})
    params_hash = params.get("content_hash")
    remote_peer_id = params_data.get("peer_id", "")
    public_key_raw = params_data.get("public_key")
    key_type = params_data.get("key_type", "ed25519")
    nonce = params_data.get("nonce", b"")

    # Structurally undecodable authenticate params (this raise, the public_key
    # type check, and the two content_hash raises below) keep the §4.7 default
    # `400 bad_request`. The line drawn here, stated because it decides inputs
    # no probe has driven: a §4.6 numbered step names a failure, so its inputs
    # take that step's row; a frame that cannot be read far enough to REACH a
    # step is not any row of §4.7 and takes the table's 400 class. Widening the
    # 401 rows to cover frame shape would put an authentication verdict on a
    # caller who never presented a claim to authenticate.
    if not remote_peer_id or not public_key_raw:
        raise ConnectError("Missing required authenticate fields")

    # public_key is raw bytes
    if not isinstance(public_key_raw, bytes):
        raise ConnectError(f"Invalid public_key format: {type(public_key_raw)}")
    public_key_bytes = public_key_raw

    # Verify peer_id matches hello.
    #
    # §4.7 row 8 names TWO inputs — "`peer_id` not derived from `public_key`,
    # **or** `hello`/`authenticate` peer_id mismatch (§4.6 step 3)" — and pins
    # both to `401 identity_mismatch`. This is the second of them; the
    # derivation check below is the first. They are one row, so they carry one
    # pair: a peer that codes only the derivation half answers a §4.7 row for
    # one input and a generic 400 for the other.
    if remote_peer_id != state.remote_peer_id:
        raise ConnectError(
            f"identity_mismatch: authenticate peer_id {remote_peer_id} does not "
            f"match the hello peer_id {state.remote_peer_id} on this connection",
            code="identity_mismatch",
            status=401,
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
        # §4.6 step 3 / §4.7 row 8. An undecodable peer_id cannot equal the
        # peer-id derived from `public_key`, so it fails the identity binding
        # rather than being a separate malformed-frame class — and the message
        # here has claimed `identity_mismatch` since long before the code did.
        raise ConnectError(
            f"identity_mismatch: peer_id {remote_peer_id} undecodable: {exc}",
            code="identity_mismatch",
            status=401,
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
        # §4.6 step 3 / §4.7 row 8 — `401 identity_mismatch`. This is the
        # security-load-bearing half of the row: step 2 proves possession of
        # *some* private key, and only this check binds that proof to the
        # identity the caller claims.
        raise ConnectError(
            f"identity_mismatch: peer_id {remote_peer_id} does not derive from "
            f"presented public_key (derived {derived_peer_id})",
            code="identity_mismatch",
            status=401,
        )

    # Verify nonce echoes our nonce.
    #
    # §4.6 step 1 / §4.7 row 6 — "Nonce mismatch / absent / pre-hello" is one
    # row at `401 invalid_nonce`. FM-1 fixed the *pre-hello* input (the phase
    # check at the top of this function); the mismatch input is the same row
    # and was still answering a generic 400 here. A captured authenticate
    # replayed against a fresh nonce is exactly this input.
    if nonce != state.our_nonce:
        raise ConnectError(
            f"invalid_nonce: expected {state.our_nonce[:8].hex()}..., got "
            f"{nonce[:8].hex() if nonce else 'empty'}...",
            code="invalid_nonce",
            status=401,
        )

    # Params is a full entity per spec - use its content_hash for verification
    if not params_hash:
        raise ConnectError("Missing content_hash in authenticate params")

    # Normalize hash to bytes
    authenticate_hash = _normalize_hash(params_hash)
    if not authenticate_hash:
        raise ConnectError("Invalid content_hash format")

    # Find signature via target-matching (not refs).
    #
    # Everything from here to the end of the verification block is §4.6 step 2,
    # and §4.7 row 7 pins the whole step to `401 authentication_failed`. Step 2
    # says in terms that an **absent** signature and an **invalid** signature
    # take the SAME pair, so the not-found arm below is not a malformed-frame
    # 400 — it is the row's first named input. (§4.7 also records that
    # `invalid_signature`, the pre-v7.61 spelling, is superseded here; this peer
    # has never emitted it on this surface and MUST NOT start.)
    signature_dict = envelope.find_signature_for_target(authenticate_hash)
    if not signature_dict:
        raise ConnectError(
            "authentication_failed: no system/signature in `included` targets "
            "the authenticate entity (§4.6 step 2 — absent signature)",
            code="authentication_failed",
            status=401,
        )

    #Verify signature over hash bytes
    try:
        sig_data = signature_dict.get("data", {})
        signature_raw = sig_data.get("signature")

        #signature is raw bytes
        if not isinstance(signature_raw, bytes):
            # A signature entity whose `signature` is not bytes cannot be
            # verified against `authenticate.public_key`, which is step 2's
            # "invalid signature" arm — not a separate frame-shape class.
            raise ConnectError(
                f"authentication_failed: signature field is {type(signature_raw)}, "
                f"not bytes (§4.6 step 2 — unverifiable signature)",
                code="authentication_failed",
                status=401,
            )
        signature_bytes = signature_raw

        # Verify target matches the AUTHENTICATE entity hash
        sig_target = _normalize_hash(sig_data.get("target"))
        if not hash_equals(sig_target, authenticate_hash):
            raise ConnectError(
                "authentication_failed: signature target does not match the "
                "authenticate entity hash (§4.6 step 2)",
                code="authentication_failed",
                status=401,
            )

        # V7 v7.67 Phase 2 — dispatch the verifier on the presented key_type
        # (decoded from the peer_id above) so an Ed448 peer is verified with
        # Ed448. Ed25519 remains the default for key_type=0x01.
        if not verify_for_key_type(
            presented_key_type, public_key_bytes, authenticate_hash, signature_bytes,
        ):
            # §4.7 row 7's headline input: a well-formed authenticate whose
            # signature does not verify. `401 authentication_failed`.
            raise ConnectError(
                "authentication_failed: signature does not verify against "
                "authenticate.public_key (§4.6 step 2)",
                code="authentication_failed",
                status=401,
            )
    except ConnectError:
        raise
    except Exception as e:
        # A verifier that *raised* has not verified the signature; the outcome
        # for the caller is step 2's invalid-signature arm, and routing it to a
        # 400 would let a malformed key or a backend fault read as a malformed
        # request. Fail closed, on the row.
        raise ConnectError(
            f"authentication_failed: signature verification raised: {e}",
            code="authentication_failed",
            status=401,
        )

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
    # V7 v7.77 §4.5a item 1a: floor-pinned, not authored under active_format
    our_identity_entity = create_identity_entity(local_keypair)
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
        # Fallback (signer not in included): reconstruct at the floor, which
        # under §4.5a item 1a is where a conformant peer authored it — this is
        # the derive-to-meet route, and it now yields the authored bytes on
        # every connection rather than only floor-active ones.
        grantee_identity = create_peer_entity(public_key_bytes, key_type)

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
            "protocols": ADVERTISED_PROTOCOLS,
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
    # V7 v7.77 §4.5a item 1a: floor-pinned, not authored under `algorithm`
    identity_entity = create_identity_entity(keypair)
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
