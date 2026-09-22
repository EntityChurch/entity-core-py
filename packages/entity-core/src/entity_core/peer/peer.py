"""Main Peer implementation.

The Peer class provides a full Entity Core peer that can:
- Accept incoming connections
- Handle EXECUTE requests
- Dispatch to registered handlers

Connect uses EXECUTE messages for handshake.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from entity_core.capability.grant import (
    Grant,
    create_connect_grants,
    create_default_handler_self_grant,
    create_full_access_grant,
)
from entity_core.capability.token import CapabilityToken

if TYPE_CHECKING:
    from entity_core.handlers.registry import RegisteredHandler
    from entity_core.peer.builder import _BuilderState
    from entity_core.peer.extensions import Extension
from entity_core.crypto.identity import Keypair
from entity_core.handlers.connect import (
    CONNECT_URI,
    IMPLEMENTED_CONNECT_OPERATIONS,
    ConnectError,
    ConnectState,
    handle_connect_hello,
    handle_connect_authenticate,
    _grants_fingerprint,
)
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.handlers.registry import HandlerRegistry
from entity_core.peer.published_root import (
    PUBLISHER_HANDLER_PATTERN,
    PublishedRootRepublisher,
)
from entity_core.peer.reciprocal import is_reentry_grant
from entity_core.peer.session import Session
from entity_core.peer.session_entity import (
    read_minted_capability,
    write_session,
)
from entity_core.protocol.bounds import (
    Bounds,
    BUDGET_EXHAUSTED_CODE,
    BUDGET_EXHAUSTED_MESSAGE,
    TTL_EXHAUSTED_CODE,
    TTL_EXHAUSTED_MESSAGE,
)
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import recv_envelope, send_envelope
from entity_core.primitives import Uint
from entity_core.protocol.messages import Execute, ExecuteResponse
from entity_core.storage.content_store import ContentStore, NotifyingContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.types import register_types
from entity_core.types.registry import register_handlers

logger = logging.getLogger(__name__)


def _identity_hash_from_authenticate_params(
    params: dict[str, Any], remote_peer_id: str,
) -> bytes | None:
    """Recompute the connecting peer's `system/peer` content hash from
    the AUTHENTICATE params. Mirrors the entity construction in
    `handle_connect_authenticate` so the resolver and the cap-issuance
    path agree on the same hash. Returns None when params are
    malformed; the resolver treats that as "no identity to recognize.
    """
    params_data = params.get("data", params) if isinstance(params, dict) else None
    if not isinstance(params_data, dict):
        return None
    public_key_raw = params_data.get("public_key")
    key_type = params_data.get("key_type", "ed25519")
    if isinstance(public_key_raw, bytes):
        pkey = public_key_raw
    elif isinstance(public_key_raw, str):
        try:
            import base64
            pkey = base64.b64decode(public_key_raw)
        except Exception:
            return None
    else:
        return None
    if not remote_peer_id or not pkey:
        return None
    # V7 v7.65 §2: system/peer data = (public_key, key_type) only
    # §4.5a item 1a: floor-pinned via the one constructor.
    from entity_core.protocol.auth import create_peer_entity

    return create_peer_entity(pkey, key_type).compute_hash()


def _grantee_identity_hash(
    envelope: Envelope, params: dict[str, Any], remote_peer_id: str,
) -> bytes | None:
    """V7 v7.69 §1.8 — the connecting peer's *authored* identity hash.

    The authenticate signature's ``signer`` field is the authored content_hash
    of the connecting peer's ``system/peer`` entity, freshly verified in
    `handle_connect_authenticate`. That is the byte-exact hash used as the cap
    grantee (§4.5a), so the grant resolver and R6 session key MUST key on the
    same value — never on a local recompute, which would manufacture a second
    form under a different content_hash_format (the M3 mismatch).

    Falls back to the params recompute only when the signature is absent (a
    malformed envelope that the handshake will reject downstream anyway).
    """
    from entity_core.utils.ecf import normalize_hash as _nh

    params_data = params.get("data", params) if isinstance(params, dict) else None
    auth_hash = _nh(params.get("content_hash")) if isinstance(params, dict) else None
    if auth_hash:
        sig = envelope.find_signature_for_target(auth_hash)
        if sig:
            signer = _nh(sig.get("data", {}).get("signer"))
            if signer:
                return signer
    return _identity_hash_from_authenticate_params(params, remote_peer_id)


def _normalize_hash_value(value: Any) -> bytes | None:
    """Coerce a hash-shaped value (raw bytes, {algorithm, digest} dict,
    or hex string) to its canonical byte form. Used by SI-11 dispatcher-
    level signature binding."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, dict):
        algorithm = value.get("algorithm")
        digest = value.get("digest")
        if isinstance(algorithm, int) and isinstance(digest, bytes):
            return bytes([algorithm]) + digest
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return None
    return None


@dataclass
class _DispatchDenied:
    """A resolve/authorize-stage refusal: HTTP-style status + message.

    Returned by the shared dispatch helpers so each caller can map it onto
    its own response shape (a wire ExecuteResponse for the external request
    path, an ExecuteResult for internal handler-to-handler dispatch).
    """

    status: int
    message: str


def _pre_establishment_refusal(request_id: str) -> "ExecuteResponse":
    """The §4.2 third-bullet refusal: a non-connect EXECUTE before the handshake.

    **401 `authentication_failed`**, and the status is the half that carries the
    meaning. §4.2 bullet 3 routes this input to §5.2a: *"a missing/unverifiable
    `author` or signature is auth-class **401**; an authenticated request lacking
    a covering capability is authz-class **403**"*. A frame arriving before the
    handshake has no verified signer at all, so it is the first arm — §5.2a's
    *"Author absent → 401 `authentication_failed`"* row. 0.8.2.5 restates this
    under §4.7 and names the codes two seats were minting in its place
    (`connection_required`, `handshake_failed`) **non-conformant**.

    This peer answered **403 `capability_denied`** — the blanket 403 F32 retired
    at **0.8.1**, so the gap is two releases old — and it was not a chosen wrong
    answer but an *unchosen* one: both call sites reached
    ``ExecuteResponse.forbidden``, which hardcodes both halves, so nothing at
    either site named a status or a code. The same shape as the
    ``bad_request`` default one commit ago, in a helper rather than a default
    argument. A 403 here is a false claim about the input: it asserts the caller
    authenticated and then lacked authority, when the caller never authenticated.

    Shared by **both** boundaries deliberately. There are two — the TCP frame
    loop and the HTTP transport — and a conformance probe dials TCP, so the HTTP
    one is not reachable by any check in the cohort. Two hand-rolled copies of
    one refusal is how §4.7 row 10 came to be classified two different ways at
    two boundaries in this same file; the fix there was one shared set, and this
    is the same fix applied before the divergence rather than after it.
    """
    return ExecuteResponse.unauthorized(
        request_id=request_id,
        message=(
            "Connect required before sending requests: no verified signer "
            "(V7 §4.2 pre-authorization, §5.2a auth-class)"
        ),
        code="authentication_failed",
    )


def _forbidden_with_rejected_marker(
    request_id: str,
    message: str,
    rejected_marker_hash: bytes | None,
) -> "ExecuteResponse":
    """Build a 403 response with the optional ``rejected_marker`` mirror.

    Per EXTENSION-CONTINUATION v1.20 §3.10.4 mirror-pointer SHOULD: when
    the dispatcher binds a rejected marker (chain-dispatch cap rejection
    per §3.10.3), the marker's content hash rides on the wire response
    as ``ErrorData.rejected_marker`` so cross-peer audit can walk the
    pair. Python's response result is an untyped dict so the field is
    additive — older receivers ignore the unknown key. When
    ``rejected_marker_hash`` is None (non-chain rejection, or marker
    bind itself failed per §3.10.8), the response is byte-identical to
    a bare ``ExecuteResponse.forbidden``.
    """
    response = ExecuteResponse.forbidden(request_id=request_id, message=message)
    if rejected_marker_hash is not None and isinstance(response.result, dict):
        response.result["rejected_marker"] = rejected_marker_hash
    return response


def _collect_wire_included(
    result: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Drain the handler's ``envelope_included`` field for the wire.

    DOMAIN-LOCAL-FILES v1.2 §4.1 / §4.3 (and any handler that
    follows the spec's ``ctx.include(...)`` shape rather than
    Python's self-contained-``system/envelope`` shape) push entities
    into a top-level ``envelope_included`` field on the handler return
    dict. The peer dispatches lifts those entries into the outer wire
    envelope's ``included`` list at send time so cross-impl
    receivers (Go validate-peer, Rust ditto) find them in the wire
    envelope where the spec text places them.

    Accepts a dict-keyed-by-hash, a list of entity dicts, or None.
    Returns a list of entity dicts (the wire envelope's ``included``
    shape).
    """
    if not isinstance(result, dict):
        return []
    raw = result.get("envelope_included")
    if raw is None:
        return []
    out: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        for ent_dict in raw.values():
            if isinstance(ent_dict, dict):
                out.append(ent_dict)
    elif isinstance(raw, list):
        for ent_dict in raw:
            if isinstance(ent_dict, dict):
                out.append(ent_dict)
    return out


#: EXTENSION-REGISTRY §4 — where the resolver chain lives.
_RESOLVER_CONFIG_PATH = "system/registry/resolver-config"


def _install_peer_issued_registries(
    peer: "Peer", registries: list[tuple[str, str]],
) -> None:
    """Pin peer-issued registries: the trust root **and** the §4 chain entry.

    Split out because the two halves fail differently and only together mean
    "pinned". With the identity but no chain entry the registry is never
    dialed and every resolve is `chain_exhausted`; with the chain entry but no
    identity every binding it serves fails `signature_failed`, since §2.1 step
    3 verifies against the pinned key and there is nothing to verify against.

    The local-name store keeps priority 0 — a peer's own names win over a
    remote registry's — and pinned registries follow in declaration order.
    """
    from entity_core.crypto.identity import (
        KEY_TYPE_BYTE_TO_ENTITY_DATA,
        derive_peer_from_peer_id,
    )
    from entity_core.protocol.auth import create_peer_entity
    from entity_core.storage.emit import EmitContext

    ctx = EmitContext.bootstrap()
    chain: list[dict[str, Any]] = [
        {
            "backend_kind": "local-name",
            "priority": 0,
            "backend_id": peer.peer_id,
            "accepted_trust_anchors": ["local_name"],
        },
    ]
    for index, (registry_peer_id, endpoint) in enumerate(registries, start=1):
        derived = derive_peer_from_peer_id(registry_peer_id)
        if derived is None:
            # A SHA-256-form PeerID carries no public key, so there is nothing
            # to pin. Refusing loudly beats installing a chain entry whose
            # every answer would fail `signature_failed` for a reason that
            # looks like the registry's fault.
            raise ValueError(
                f"cannot pin peer-issued registry {registry_peer_id!r}: the "
                "PeerID is not identity-multihash form, so it carries no "
                "public key to verify bindings against"
            )
        public_key, key_type_byte = derived
        # `derive_peer_from_peer_id` returns the wire key-type BYTE; a
        # `system/peer`'s `key_type` is the entity-data STRING. Putting the
        # byte in would hash to a different identity than the one the registry
        # authored, so the pin would silently match nothing.
        key_type = KEY_TYPE_BYTE_TO_ENTITY_DATA.get(key_type_byte)
        if key_type is None:
            raise ValueError(
                f"cannot pin peer-issued registry {registry_peer_id!r}: "
                f"unknown key type byte {key_type_byte:#04x}"
            )
        identity = create_peer_entity(public_key, key_type)
        # The trust root goes to the CONTENT store: it is looked up by hash
        # (`_resolve_pubkey` / `_signer_peer_id`), not by path, and it is a
        # local pin rather than published tree state.
        peer.content_store.put(identity)
        chain.append({
            "backend_kind": "peer-issued",
            "priority": index,
            "backend_id": registry_peer_id,
            "accepted_trust_anchors": [f"peer_issued:{registry_peer_id}"],
            "hints": {"endpoint": endpoint},
        })
        logger.info(
            "peer-issued registry pinned: %s -> %s",
            registry_peer_id[:16], endpoint,
        )
    peer.emit_pathway.emit(
        _RESOLVER_CONFIG_PATH,
        Entity(
            type="system/registry/resolver-config",
            data={
                "resolver_chain": chain,
                "pinned_bindings": [],
                "name_format_dispatch": [],
            },
        ),
        ctx,
    )


def _peername_of(writer: asyncio.StreamWriter) -> str | None:
    """The transport source of an accepted connection, as ``"host:port"``.

    EXTENSION-NETWORK §6.7.1's whole mechanism: what the responder's transport
    reported as the source of this connection *is* the requester's public NAT
    mapping. IPv6 is bracketed so the string round-trips as a dialable
    authority (``[2001:db8::1]:51820``) — §6.7.2 dials this value back, and an
    unbracketed v6 literal is ambiguous at the colon.

    ``None`` when the transport reports nothing usable; callers answer 400
    rather than inventing an address.
    """
    try:
        peername = writer.get_extra_info("peername")
    except Exception:  # pragma: no cover - defensive; transport-dependent
        return None
    if not isinstance(peername, tuple) or len(peername) < 2:
        return None
    host, port = peername[0], peername[1]
    if not isinstance(host, str) or not isinstance(port, int):
        return None
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


@dataclass
class PeerConnectionState:
    """State for an active connection."""

    connect: ConnectState = field(default_factory=ConnectState)
    session: Session | None = None
    # Capability we granted to the remote peer
    granted_capability: Entity | None = None
    # Per V7 v7.48 §4.8 (A.2): serializes outbound frame writes so multiple
    # in-flight handler tasks on the same connection cannot interleave
    # bytes mid-frame. Constructed lazily on first send (must be created
    # inside the running event loop). The reader does NOT acquire it — it
    # only reads inbound frames; the lock guards the WRITER only.
    write_lock: asyncio.Lock | None = None
    # GUIDE-CONFORMANCE §7a.2a / V7 §6.11(b): demux slots for EXECUTE_RESPONSE
    # frames that arrive on this *accepted* (inbound) connection in reply to an
    # outbound EXECUTE this peer originated back over the same wire (reentry to
    # a caller that dialed us and has no listener — the conformance validator's
    # B-no-listener case). Keyed by request_id. Empty on connections that never
    # reenter; the serve loop falls back to log-and-drop when no slot matches.
    pending_reentry: dict[str, asyncio.Future[Envelope]] = field(
        default_factory=dict,
    )
    # Ruling C (full tier): content hash of the `system/connection` entity
    # this connection's authenticate-complete wrote — the close-transition's
    # no-clobber token (a re-handshake's fresh `active` write must not be
    # flipped `closed` by a stale handler's teardown).
    connection_entity_hash: bytes | None = None
    # EXTENSION-SIGNALING §6.5 (b) "Where the grant lives" [MUST] — the
    # connection-scoped originating authority. A reciprocal grant minted by
    # the counterpart for a rendezvous establishment lives HERE and nowhere
    # else: it is establishment-scoped and drop-on-disconnect, deliberately
    # NOT written to `system/peer/session/{peer}` (EXTENSION-NETWORK §6.6
    # records only the durable handshake cap). Not persisting IS the
    # security property — a stale grant reused on reconnect, without
    # re-meeting at the key, would authorize outside the establishment that
    # justified it. Distinct slot from the durable `held_capability`
    # (dialer-side reconnect-skip authority); where both exist, THIS one
    # wins, because a durable cap can predate the live establishment and
    # MUST NOT shadow it.
    originating_capability: dict[str, Any] | None = None
    #: Entities the far side needs to walk that cap's chain (its granter
    #: identity and the cap signature) — absent from either handshake,
    #: because the counterpart authored them after it.
    originating_included: list[dict[str, Any]] | None = None
    #: Set when a grant is installed, so an origination that races the
    #: ≈1-round-trip delivery window waits instead of dispatching under
    #: authority it does not yet hold.
    originating_ready: asyncio.Event | None = None
    # §6.5 (b) discriminator, acceptor side. Locally classified, never
    # wire-carried. Only a rendezvous-established acceptor expects a grant
    # and pays the bounded wait; a dial-by-address acceptor is asymmetric
    # and must not.
    established_via_rendezvous_key: bool = False
    # EXTENSION-NETWORK §6.7.1 — the transport-layer source address this peer
    # observed when it ACCEPTED this connection ("203.0.113.7:51820"), read
    # once from the socket at accept and held for the connection's life.
    #
    # This is the whole of the narrow, NETWORK-scoped accept-side path §6.7.1
    # calls for: the fact rides from the accepted connection to the handler,
    # so `observe-address` / `check-reachability` read no address from the
    # request body at all — which forecloses the body-supplied-address
    # laundering seam structurally rather than by a validation check. Mirrors
    # Go's `protocol.ConnectionState.ObservedAddress`.
    #
    # `None` on a DIALED connection: the observed source is a responder-side
    # fact, and the dialer observes nothing about itself. §6.7.1 MUST 2 — it
    # is never copied out of here into `system/connection.address`, a
    # `system/peer/transport/*` profile, or `system/peer/status`; those mean
    # "the endpoint I dial to reach this peer", and an ephemeral NAT source
    # port written there is a routable-LOOKING value that routes nowhere.
    observed_address: str | None = None

    def get_originating_ready(self) -> asyncio.Event:
        """Lazy in-loop accessor for the grant-received signal."""
        if self.originating_ready is None:
            self.originating_ready = asyncio.Event()
        return self.originating_ready

    def install_originating_capability(
        self,
        capability: dict[str, Any],
        supporting: list[dict[str, Any]] | None,
    ) -> None:
        """Install this connection's reciprocal grant (§6.5 (b))."""
        self.originating_capability = capability
        self.originating_included = list(supporting) if supporting else None
        self.get_originating_ready().set()

    @property
    def is_connected(self) -> bool:
        """Whether connect handshake has completed and session is established."""
        return self.connect.is_complete and self.session is not None

    def get_write_lock(self) -> asyncio.Lock:
        if self.write_lock is None:
            self.write_lock = asyncio.Lock()
        return self.write_lock


# Per-request deadline for an outbound-over-inbound reentry EXECUTE. The
# caller (validator) services the reentrant request on its own background
# reader; a stuck socket surfaces as a bounded timeout rather than parking
# the handler task. Mirrors Connection.DEFAULT_REQUEST_TIMEOUT_SECONDS.
REENTRY_REQUEST_TIMEOUT_SECONDS: float = 60.0


def _wire_bounds_for_dispatch(bounds: "Bounds | None") -> "Bounds | None":
    """PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION Delta 1 / §5 — which cross-peer
    dispatches carry ``system/bounds`` on the wire.

    Bounds ride the wire ONLY for a continuation advancement: the dispatch whose
    bounds carry a ``chain_depth`` (stamped at the §5 increment site,
    ``_step6_chain_context``). ``chain_depth`` presence is the O1 signal — not
    the trigger type. A causal advancement inherited a depth here; a standing
    continuation on a fresh trigger rooted at 0 and stamped depth 1; both carry
    their bounds so the receiver inherits the *global* count.

    Ordinary remote dispatch has no ``chain_depth`` → returns ``None`` → the
    wire EXECUTE is byte-identical to before (bounds dropped). This is Go's
    ``TestOrdinaryRemoteDispatchAddsNoBounds`` convergence anchor: no bounds are
    invented for a dispatch that was never part of a bounded chain.
    """
    if bounds is not None and bounds.chain_depth is not None:
        return bounds
    return None


@dataclass
class ReentryChannel:
    """V7 §6.11(b) / GUIDE-CONFORMANCE §7a.2a — outbound-over-inbound seam.

    Originates exactly one EXECUTE back over an *accepted* connection to the
    peer that dialed us. This is the only channel to a caller with no
    listener (the conformance validator playing B-role on the same wire it
    opened). The reply EXECUTE_RESPONSE is demuxed by the serve loop
    (:meth:`Peer._handle_connection`) into ``conn_state.pending_reentry`` and
    resolved on the Future this method awaits.

    This is NOT the normal outbound path: a peer reachable via a transport
    profile is dialed through :class:`RemoteConnectionPool` as before.
    Reentry fires only when pool resolution misses for the inbound peer, so
    a genuinely bidirectional peer keeps its pooled outbound connection
    (matches the Go §6.11(b) ruling — reentry fallback is pool-miss-only and
    does not disturb the bidirectional-pooled path).
    """

    remote_peer_id: str
    writer: asyncio.StreamWriter
    conn_state: PeerConnectionState
    keypair: Keypair
    active_hash_format: int

    async def execute(
        self,
        uri: str,
        operation: str,
        params: dict[str, Any] | None,
        *,
        capability: dict[str, Any] | None,
        capability_chain: list[dict[str, Any]] | None = None,
        resource_targets: list[str] | None = None,
        bounds: "Bounds | None" = None,
        included: list[dict[str, Any]] | None = None,
    ) -> ExecuteResponse:
        """Send one authenticated EXECUTE over the inbound wire; await reply.

        ``capability`` authorizes the EXECUTE (its grantee is this peer —
        the caller minted it for us); ``capability_chain`` (granter identity,
        cap signature) is bundled into the envelope ``included`` so the
        caller's verifier can resolve it.

        When the caller supplies none, the connection-scoped **reciprocal
        grant** is used (EXTENSION-SIGNALING §6.5 (b) "Where the grant
        lives"): on a symmetric rendezvous establishment the dialer minted
        exactly this authority for us and it is held with the live
        connection. It **wins** over any durable `held_capability` for the
        same peer — a durable cap can predate this establishment and MUST
        NOT shadow it. Absent both, there is no authority on the inbound
        direction (we never dialed the caller) and origination fails closed
        rather than dispatching something guaranteed to `401`.
        """
        if capability is None:
            capability = self.conn_state.originating_capability
            if capability is not None and capability_chain is None:
                capability_chain = self.conn_state.originating_included
        if capability is None:
            raise RuntimeError(
                "reentry EXECUTE requires a capability — no §6.5 (b) "
                "reciprocal grant is installed on this connection and the "
                "inbound (accepted) direction carries no connection cap of "
                "its own"
            )

        from entity_core.protocol.auth import create_authenticated_request
        from entity_core.protocol.messages import ResourceTarget

        resource_target = (
            ResourceTarget.from_dict({"targets": resource_targets})
            if resource_targets else None
        )
        execute = Execute.create(
            uri, operation, params, resource=resource_target, bounds=bounds,
        )
        auth_request = create_authenticated_request(
            self.keypair,
            execute,
            capability,
            capability_chain,
            algorithm=self.active_hash_format,
        )
        envelope = auth_request.to_envelope()
        if included:
            envelope.included.extend(included)

        loop = asyncio.get_running_loop()
        future: asyncio.Future[Envelope] = loop.create_future()
        request_id = execute.request_id
        if request_id in self.conn_state.pending_reentry:
            raise RuntimeError(
                f"duplicate reentry request_id {request_id!r} on this connection"
            )
        self.conn_state.pending_reentry[request_id] = future
        try:
            async with self.conn_state.get_write_lock():
                await send_envelope(self.writer, envelope)
            response_env = await asyncio.wait_for(
                future, timeout=REENTRY_REQUEST_TIMEOUT_SECONDS,
            )
        finally:
            self.conn_state.pending_reentry.pop(request_id, None)

        response = ExecuteResponse.from_entity(response_env.root)
        # Surface the wire envelope's `included` map on the response (mirror
        # Connection.execute) so the originating handler can resolve any
        # bundle the reentrant reply delivered.
        if response_env.included:
            included_map: dict[bytes, dict[str, Any]] = {}
            for ent_dict in response_env.included:
                if not isinstance(ent_dict, dict):
                    continue
                h = ent_dict.get("content_hash")
                if isinstance(h, (bytes, bytearray)) and h:
                    included_map[bytes(h)] = ent_dict
            response.envelope_included = included_map or None
        return response


class Peer:
    """Entity Core peer implementation.

    Attributes:
        keypair: This peer's cryptographic identity.
        content_store: Content-addressed storage.
        entity_tree: URI-based storage index.
        emit_pathway: Consolidated write entry point with change events.
        handlers: Handler registry for request dispatch.
        admin_peer_ids: Set of peer IDs with admin access.
        debug_mode: If True, grant full access to all peers (insecure).
        default_grants: Default grants to give connecting peers.

    Construction:
        Use PeerBuilder to construct peers:
            peer = PeerBuilder().with_keypair(kp).with_default_handlers().build()
    """

    def __init__(self) -> None:
        """Direct construction not supported - use PeerBuilder.

        Raises:
            TypeError: Always. Use PeerBuilder instead.
        """
        raise TypeError(
            "Direct Peer() construction is not supported. "
            "Use PeerBuilder().with_keypair(kp).with_default_handlers().build()"
        )

    @classmethod
    def _from_builder(cls, state: _BuilderState) -> Peer:
        """Internal constructor used by PeerBuilder.

        Args:
            state: Builder state with all configuration.

        Returns:
            Configured Peer instance.
        """
        # Create instance without calling __init__
        peer = object.__new__(cls)

        # Set required attributes
        assert state.keypair is not None
        peer.keypair = state.keypair
        peer.admin_peer_ids = state.admin_peer_ids
        peer.debug_mode = state.debug_mode
        peer.default_grants = state.default_grants or create_full_access_grant()

        # Optional grant resolver (post-construction wiring per
        # HANDOFF-RECOGNIZE-ON-ATTESTATION §4): consulted at AUTHENTICATE
        # time before the static fallback fires. Signature:
        # (peer_id, identity_hash) -> list[Grant] | None.
        peer._grant_resolver = state.grant_resolver

        # Initialize storage layers — NotifyingContentStore enables content-store events
        peer.content_store = NotifyingContentStore()
        peer.entity_tree = EntityTree(peer.keypair.peer_id)
        peer.emit_pathway = EmitPathway(peer.content_store, peer.entity_tree)

        # Initialize outbound connection pool. Pass `emit_pathway` so the
        # pool can persist client-side session entities at
        # `system/peer/session/{remote_peer_id}` after successful dials
        # (R6, PROPOSAL §7.1 #1).
        from entity_core.peer.remote import RemoteConnectionPool
        peer._remote_pool = RemoteConnectionPool(
            peer.keypair, peer.content_store, peer.entity_tree,
            emit_pathway=peer.emit_pathway,
            keepalive_config=state.keepalive_config,
        )
        # EXTENSION-SIGNALING §6.5 (b) reach-back serving [MUST] + the
        # reciprocal mint: every connection this peer DIALS gets a serving
        # path for inbound EXECUTE and, on a symmetric establishment, mints
        # the acceptor's grant. Wired as a hook so the pool keeps no
        # back-reference to the peer.
        peer._remote_pool.on_dialed = peer._attach_dialed_connection
        # §6.5 (b) discriminator, acceptor side: peer-ids whose establishment
        # this peer classified as "met at a §3 rendezvous key". Local, never
        # wire-read — see `mark_rendezvous_establishment`.
        peer._rendezvous_peers: set[str] = set()
        # V7 §6.11(b) origination seams: accepted connections, by peer-id.
        peer._inbound_reentry: dict[str, ReentryChannel] = {}

        # R3a (granter idempotency) — R6 (PROPOSAL §7.1 #1):
        # the held cap for a remote peer lives in the entity tree at
        # `system/peer/session/{remote_peer_id}` (`entity_core.peer.
        # session_entity`). Per-process state is now bounded to a small
        # fingerprint guard so we don't reuse a tree-cached cap when the
        # configured grants for a peer change at runtime.
        peer._session_grants_fingerprint: dict[str, bytes] = {}

        # Initialize handler registry
        peer.handlers = HandlerRegistry()

        # Server state
        peer._server = None
        peer._connections = set()
        # Per V7 v7.48 §4.8 (A.2): bounds concurrent inbound handler
        # tasks per peer process. The reader is never blocked by this
        # semaphore — only handler dispatch awaits a slot. A modest cap
        # keeps memory bounded; pushers experiencing back-pressure see
        # their next outbound frame's response queued, not lost. Created
        # lazily so it binds to the running event loop on first acquire.
        peer._inbound_semaphore_size = 64
        peer._inbound_semaphore_obj: asyncio.Semaphore | None = None

        # PROPOSAL-PEER-MANIFEST §4 republisher, installed by
        # `enable_root_republish()` when the operator asks for a signed root.
        peer._root_republisher = None

        # Extensions list
        peer._extensions: list[Extension] = []

        # Register handlers from builder state and process protocols
        type_providers = []
        manifest_providers = []
        handler_grants_to_create = []

        for handler_config in state.handlers:
            peer.handlers.register(
                handler_config.pattern,
                handler_config.handler,
                priority=handler_config.priority,
                name=handler_config.name,
                max_scope=handler_config.max_scope,
            )
            # Collect protocol implementations
            if handler_config.type_provider is not None:
                type_providers.append(handler_config.type_provider)
            if handler_config.manifest_provider is not None:
                manifest_providers.append(
                    (handler_config.name, handler_config.manifest_provider)
                )
            # Collect handler grant info for later creation
            handler_grants_to_create.append(
                (handler_config.pattern, handler_config.max_scope)
            )

        # EXTENSION-DURABILITY §4 / §8: the receiver's own durability
        # policy. Explicit config wins; otherwise auto-derive from this
        # peer's own configuration at acceptance time. A peer with an
        # inbox handler has a durable mailbox findable by
        # (author, request_id) (§6 — the inbox is *one example* of a
        # durable store, not the canonical store); that is the `stored`
        # self-determinable strength. A peer with no durable store
        # STILL answers a durability request observably (§8 — never
        # silently dropped); it just reports `applied: none`. The
        # extension is exploratory and optional; peers that don't ship
        # it are unaffected.
        from entity_core.protocol.durability import (
            DEFAULT_DURABILITY_POLICY,
            DurabilityPolicy,
            LEVEL_STORED,
        )

        if state.durability_policy is not None:
            peer.durability_policy = state.durability_policy
        else:
            handler_patterns = {hc.pattern for hc in state.handlers}
            if "system/inbox" in handler_patterns:
                peer.durability_policy = DurabilityPolicy(
                    self_levels=frozenset({LEVEL_STORED})
                )
            else:
                peer.durability_policy = DEFAULT_DURABILITY_POLICY

        # Register built-in types via emit pathway (unless disabled)
        if state.register_types:
            register_types(peer.emit_pathway)
            # Register handler manifests (decomposed into interface + handler entities)
            from entity_handlers import ALL_HANDLER_MANIFESTS
            register_handlers(peer.emit_pathway, ALL_HANDLER_MANIFESTS)

            # EXTENSION-DURABILITY §3 (MAY — loosened from SHOULD on
            # extraction): seed the durability advertisement at the
            # well-known path `system/durability` so a sender can
            # discover supported levels via an ordinary tree:get.
            # Absence does NOT change the response contract (§5);
            # probe-via-request is the canonical fallback.
            from entity_core.protocol.durability import (
                ADVERTISEMENT_PATH,
                ADVERTISEMENT_TYPE,
                advertise,
            )
            from entity_core.protocol.entity import Entity as _Entity
            from entity_core.storage.emit import EmitContext as _EmitContext
            advert = _Entity(
                type=ADVERTISEMENT_TYPE,
                data=advertise(peer.durability_policy),
            )
            peer.emit_pathway.emit(
                ADVERTISEMENT_PATH, advert, _EmitContext.bootstrap(),
            )

        # Process TypeProvider protocols - register custom types
        from entity_core.types.registry import TypeRegistry
        type_registry = TypeRegistry(peer.emit_pathway)
        for provider in type_providers:
            provider.register_types(type_registry)

        # Process ManifestProvider protocols - decompose manifests into
        # interface + handler entities per PROPOSAL-HANDLER-NORMALIZATION
        from entity_core.storage.emit import EmitContext
        for name, provider in manifest_providers:
            if not name:
                logger.warning("ManifestProvider without name - skipping manifest registration")
                continue
            manifest_entity = provider.manifest()
            register_handlers(peer.emit_pathway, [manifest_entity])

        # Create handler grants per IMPLEMENTATION-SPEC §5.3
        # Each handler gets a grant stored at system/capability/grants/{pattern}
        peer._create_handler_grants(handler_grants_to_create)

        # V7 §6.9a peer-authority-bootstrap (F27): materialize the
        # principal-level owner cap + any declared seed-policy entries at
        # L0, alongside (not replacing) the per-handler self-grants above
        # (§6.9a.4 coexistence). Read back at authenticate via the existing
        # v7.62 §8 / v7.64 dual-form policy path.
        peer._bootstrap_peer_authority(
            state.owner_identity_hash, state.seed_policy,
        )

        # PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §2: pin each declared registry
        # — the trust root AND the §4 chain entry that makes it consulted.
        if state.peer_issued_registries:
            _install_peer_issued_registries(peer, state.peer_issued_registries)

        # Initialize extensions
        if state.extensions:
            from entity_core.peer.extensions import ExtensionContext
            from entity_core.handlers.context import ExecuteResult

            # Create extension execute callback that uses a system grant
            async def extension_execute(
                uri: str,
                operation: str,
                params: dict[str, Any] | None = None,
                resource_targets: list[str] | None = None,
                bounds: Bounds | None = None,
                included: dict[bytes, dict[str, Any]] | None = None,
                *,
                reactive_trigger: bool = False,
            ) -> ExecuteResult:
                """Execute a request from an extension using system grant.

                Extensions use a full-access grant for internal operations
                like notification delivery. ``included`` carries request-side
                envelope entities (V7 §3.3 v7.51) — e.g. the subscription
                engine bundling an ``include_payload`` entity so the
                subscriber's continuation can ``deref_included`` it.

                ``reactive_trigger`` (STANDING-MODEL §3): an extension that
                advances a continuation as a delivery/timer poke (the network
                retry-timer re-arm, a subscription poke) declares it reactive,
                so the advance runs under the continuation's own authority
                rather than being treated as an administrative invoke.
                """
                # Use full access grant for extension operations
                system_grant = {
                    "grants": [g.to_dict() for g in create_full_access_grant()],
                    "granter": peer.keypair.peer_id,
                    "grantee": peer.keypair.peer_id,
                }
                return await peer._dispatch_local_execute(
                    uri, operation, params, system_grant, bounds, None,
                    resource_targets=resource_targets,
                    included=included,
                    reactive_trigger=reactive_trigger,
                )

            for ext_config in state.extensions:
                ctx = ExtensionContext(
                    keypair=peer.keypair,
                    max_scope=ext_config.max_scope,
                    emit_pathway=peer.emit_pathway,
                    execute=extension_execute,
                    peer=peer,
                )
                ext_config.extension.initialize(ctx)
                peer._extensions.append(ext_config.extension)

        # Register remote peers (TCP or HTTP profile per transport tag).
        # V7 v7.64 §1.4: peer_id_hex is derived locally for identity-form
        # PeerIDs (§1.5 hash_type = 0x00); public_key only required for
        # SHA-256-form PeerIDs.
        for remote in state.remotes:
            if remote.transport == "http":
                peer.register_remote_http(
                    remote.peer_id, remote.address,
                    public_key=remote.public_key,
                )
            else:
                peer.register_remote(
                    remote.peer_id, remote.address,
                    public_key=remote.public_key,
                )

        return peer

    @property
    def peer_id(self) -> str:
        """This peer's ID (Base58 — V7 §1.5 universal-tree-start form)."""
        return self.keypair.peer_id

    @property
    def peer_id_hex(self) -> str:
        """V7 v7.64 §1.4 ``peer_id_hex`` form — lowercase hex of this
        peer's ``system/peer`` content_hash. 66 chars starting with ``00``.
        Used as the path segment for every "peer reference inside a tree"
        surface: ``system/peer/session/{peer_id_hex}``,
        ``system/peer/transport/{peer_id_hex}/...`` etc."""
        return self._get_local_identity_hash().hex()

    def _create_handler_grants(
        self, handler_configs: list[tuple[str, list[Grant] | None]]
    ) -> None:
        """Create and store handler grants per IMPLEMENTATION-SPEC §5.3
        and spec-gap §S1.

        Each handler gets a capability grant stored at
        `system/capability/grants/{pattern}`, signed by the local peer
        (granter = grantee = local identity hash). A separate
        `system/signature` entity is emitted at the §3.5 invariant-pointer
        path `system/signature/{grant_hash}` (v7.74 v0.4 §3.4) so
        dispatch-time validation can verify it (spec-gap §S2).

        Args:
            handler_configs: List of (pattern, max_scope) tuples.
        """
        from entity_core.capability.grant_signing import (
            build_signed_handler_grant, grant_signature_path,
        )
        from entity_core.storage.emit import EmitContext

        ctx = EmitContext.bootstrap()

        # Ensure the local identity entity is in the content store so the
        # granter hash referenced by every grant resolves.
        self._ensure_local_identity_in_store()

        for pattern, max_scope in handler_configs:
            if max_scope:
                grants = max_scope
            else:
                # §6.2 default self-grant (pinned normatively at 0.8.2.3):
                # any handler, any operation, the whole LOCAL store including
                # the foreign-namespace regions it holds — and `peers`
                # OMITTED, so §5.2 Dimension 4 defaults it to the local peer
                # and still checks it. This lets a handler dispatch to other
                # handlers internally (the continuation handler resuming a
                # request, a follow-mirror write to `/{them}/…`) without
                # authorizing dispatch at a *foreign peer's* handlers.
                #
                # This used to be `create_full_access_grant()`, whose
                # `peers: ["*"]` the spec names as "specifically wrong … the
                # one direction that must not be widened". That helper stays
                # where cross-peer reach is the point; it is not the default
                # ceiling.
                grants = create_default_handler_self_grant()

            grant_dicts = [g.to_dict() for g in grants]
            grant_entity, signature_entity, _ = build_signed_handler_grant(
                self.keypair, grant_dicts,
            )

            grant_path = f"system/capability/grants/{pattern}"
            self.emit_pathway.emit(grant_path, grant_entity, ctx)
            self.emit_pathway.emit(
                grant_signature_path(grant_entity.compute_hash()),
                signature_entity, ctx,
            )

    def _bootstrap_peer_authority(
        self,
        owner_identity_hash: bytes | None,
        seed_policy: dict[str, list[Grant]] | None,
    ) -> None:
        """V7 §6.9a peer-authority-bootstrap (F27): materialize the
        principal-level owner capability + any declared seed-policy entries
        as L0 writes.

        The owner cap is a ``system/capability/policy-entry`` written at
        ``system/capability/policy/{owner_identity_hash_hex}`` (v7.64 hex
        form — the local peer always has its own public key, so the
        canonical form is written directly; §6.9a.1). Its grant is full
        authority over ``/{peer_id}/*`` (``create_owner_grant``). The owner
        identity defaults to this peer's own identity (axiom A1); an
        operator override may name a distinct identity.

        Read back at §4.6 authenticate-time by ``_get_grants_for_peer`` →
        ``_read_policy_grants_for`` (the existing v7.62 §8 + v7.64 dual-form
        substrate) when the key-holder operator connects over the wire. For
        in-process peers the entry is the L0 supply of operable authority
        regardless of any wire authenticate (§6.9a in-process clause).

        Per §6.9a.4 this COEXISTS with the per-handler self-grants written
        by ``_create_handler_grants`` — it does not replace or touch them.
        Eager declaration is mandatory (A5 inspectability); the entry is
        always present and queryable via ``tree:get system/capability/policy/``.

        Args:
            owner_identity_hash: Content hash of the owner's ``system/peer``
                identity entity. ``None`` → this peer's own identity (self).
            seed_policy: Optional operator-declared map of policy key
                (identity-hash hex, Base58 PeerID, or the literal
                ``"default"``) → list of grants. Materialized alongside the
                owner entry; a ``"default"`` key supplies the §6.9a default
                entry for un-named identities.
        """
        from entity_core.capability.grant import create_owner_grant
        from entity_core.storage.emit import EmitContext

        ctx = EmitContext.bootstrap()
        self._ensure_local_identity_in_store()

        # Owner entry: the self-owner cap, keyed by the owner identity hash
        # (hex form). Defaults to self per axiom A1.
        owner_hash = owner_identity_hash or self._get_local_identity_hash()
        entries: dict[str, list[Grant]] = {
            owner_hash.hex(): create_owner_grant(self.peer_id),
        }

        # Operator-declared seed-policy entries layer on top. An explicit
        # entry for the owner key overrides the default owner cap.
        if seed_policy:
            for key, grants in seed_policy.items():
                entries[key] = grants

        for key, grants in entries.items():
            entry_entity = Entity(
                type="system/capability/policy-entry",
                data={
                    "peer_pattern": key,
                    "grants": [g.to_dict() for g in grants],
                },
            )
            self.emit_pathway.emit(
                f"system/capability/policy/{key}", entry_entity, ctx,
            )

    def _ensure_local_identity_in_store(self) -> None:
        """Persist the local peer's identity entity so its content hash
        resolves at validation time. Idempotent."""
        from entity_core.protocol.auth import create_identity_entity

        identity_entity = create_identity_entity(self.keypair)
        self.content_store.put(identity_entity)
        self._local_identity_hash = identity_entity.compute_hash()

    def _get_handler_grant(self, handler_pattern: str) -> dict[str, Any] | None:
        """Resolve and validate a handler's grant from the tree.

        Per V7 §6.2 + spec-gap §S2: the grant entity at
        `system/capability/grants/{pattern}` MUST be signed by the local
        peer. Dispatch validates the granter, the signature, and
        temporal bounds. Any failure → caller MUST treat as
        permission_denied (same as §7.1 fail-closed).

        Returns the grant data dict on successful validation, or None
        on missing/invalid grant (rejection).
        """
        from entity_core.capability.grant_signing import (
            GrantValidationError, grant_signature_path, verify_handler_grant,
        )

        grant_path = f"system/capability/grants/{handler_pattern}"
        full_uri = self.entity_tree.normalize_uri(grant_path)
        hash_str = self.entity_tree.get(full_uri)
        if not hash_str:
            logger.debug("Handler grant missing for %s", handler_pattern)
            return None
        grant_entity = self.content_store.get(hash_str)
        if grant_entity is None:
            logger.debug("Handler grant entity not in content store for %s", handler_pattern)
            return None

        # v7.74 v0.4 §3.4: signature lives at the §3.5 invariant-pointer
        # path keyed by the grant's own content hash (the trusted tree
        # value, §1.8 — not recomputed), not colocated with the grant.
        sig_uri = self.entity_tree.normalize_uri(grant_signature_path(hash_str))
        sig_hash = self.entity_tree.get(sig_uri)
        signature_entity = self.content_store.get(sig_hash) if sig_hash else None

        granter = grant_entity.data.get("granter")
        granter_identity = (
            self.content_store.get(granter) if isinstance(granter, bytes) else None
        )

        local_identity_hash = self._get_local_identity_hash()

        try:
            verify_handler_grant(
                grant_entity, signature_entity, granter_identity,
                local_identity_hash,
            )
        except GrantValidationError as e:
            logger.warning(
                "Handler grant rejected for %s: %s", handler_pattern, e.message,
            )
            return None
        return grant_entity.data

    def _get_local_identity_hash(self) -> bytes:
        """Cached hash of the local peer's identity entity."""
        cached = getattr(self, "_local_identity_hash", None)
        if cached is not None:
            return cached
        from entity_core.protocol.auth import create_identity_entity

        identity = create_identity_entity(self.keypair)
        self._local_identity_hash = identity.compute_hash()
        return self._local_identity_hash

    def _resolve_handler(self, path: str):
        """Resolve a handler for `path` (V7 §6.6).

        Per spec: the tree is the source of truth. Resolution order:
          1. Tree walk — find longest-prefix `system/handler` entity. The
             tree carries the canonical handler entity for every registered
             handler, so this is the authoritative match.
          2. Look up the bound function in the in-memory registry by the
             tree-walked pattern. Compiled handlers (PeerBuilder) bind here.
          3. If no compiled function but the tree entity has
             `expression_path`: synthesize an entity-native wrapper.
          4. Tree walk failed → fall back to in-memory pattern matching for
             wildcard catchall handlers (`*`, `system/*`) which Python
             implements as in-memory-only conveniences.

        Returns a `RegisteredHandler` (possibly synthesized) or None.
        """
        from entity_core.handlers.registry import RegisteredHandler

        walked = self._tree_walk_resolve(path)
        if walked is not None:
            handler_entity, pattern = walked
            bound = self.handlers.find_exact(pattern)
            if bound is not None:
                return bound
            handler_fn = self._handler_for_tree_entity(handler_entity, pattern)
            if handler_fn is not None:
                return RegisteredHandler(
                    pattern=pattern,
                    priority=0,
                    handler=handler_fn,
                    name=f"tree-walked:{pattern}",
                )
            # Tree has manifest but no implementation can be bound.
            # Fall through — caller may still get a wildcard fallback.
            logger.warning(
                "Tree-walked handler at %s has no implementation "
                "(no compiled binding and no expression_path)", pattern,
            )

        return self.handlers.find_handler_info(path)

    def _tree_walk_resolve(self, path: str):
        """V7 §6.6 tree walk. Walks path segments backward, returns the
        longest-prefix `system/handler` entity (NOT `system/handler/interface`
        — those are discovery-index entries, not dispatch targets)."""
        from entity_core.utils.path import extract_handler_path

        handler_relative = extract_handler_path(path)
        if not handler_relative:
            return None
        segments = [s for s in handler_relative.split("/") if s]
        while segments:
            prefix = "/".join(segments)
            h = self.entity_tree.get(prefix)
            if h is not None:
                entity = self.content_store.get(h)
                if entity is not None and entity.type == "system/handler":
                    return entity, prefix
            segments = segments[:-1]
        return None

    def _handler_for_tree_entity(self, handler_entity: "Entity", pattern: str):
        """Build a callable handler for a tree-resolved handler entity.

        - Entity-native (`expression_path` set) → wrapper from a registered
          extension that provides `make_entity_native_handler` (the compute
          extension). The wrapper enforces V7 §7.1 fail-closed grant checks at
          dispatch time. Resolved by capability (duck-typed) rather than by
          importing the concrete extension class, so the core dispatch runtime
          carries no dependency on the handlers package.
        - Otherwise → no implementation bound; return None so dispatch
          can respond 501.
        """
        expression_path = handler_entity.data.get("expression_path")
        if expression_path is not None:
            for ext in self._extensions:
                make_native = getattr(ext, "make_entity_native_handler", None)
                if callable(make_native):
                    return make_native(expression_path)
            logger.warning(
                "Tree-walked handler at %s has expression_path but no "
                "entity-native handler factory (compute extension) is "
                "registered on this peer",
                pattern,
            )
            return None

        # No expression_path and not in in-memory registry → no implementation.
        logger.debug(
            "Tree-walked handler at %s has no expression_path and no "
            "in-memory binding — returning 501",
            pattern,
        )
        return None

    async def ensure_connected(self, peer_id: str) -> None:
        """Connect-if-needed seam (EXTENSION-NETWORK §4.1 step 1).

        Reuses the pooled outbound binding when one exists, else resolves
        the peer's transport profiles, dials, and handshakes. The establish
        path writes the §3.13 ``connected`` status and starts the §5.4
        keepalive loop — callers (the network handler's reconnect graph)
        double-build nothing (§A4). Raises ``ConnectionError`` when no
        profile connects.

        This is the impl-internal reconnect target the §4.1 graph uses
        instead of the pseudocode's ``system/protocol/connect hello``
        (which is the responder-side handshake op and cannot dial — Go
        spec-issue 4, converged on cohort-wide).
        """
        await self._remote_pool.get_connection(peer_id)

    def evict_remote_connection(self, peer_id: str) -> bool:
        """Evict the pooled outbound connection to ``peer_id``, if any.

        Cancels its keepalive loop; the next dispatch re-dials. Returns
        whether an eviction happened. Liveness writes are the caller's
        concern — this is the bare pool seam (§4.2/§4.4 close paths write
        their own terminal transitions).
        """
        return self._remote_pool.remove_connection(peer_id)

    def is_connected(self, peer_id: str) -> bool:
        """Whether an outbound connection to ``peer_id`` is currently pooled."""
        return peer_id in self._remote_pool._connections

    def register_remote(
        self,
        peer_id: str,
        address: str,
        *,
        public_key: bytes | None = None,
        profile_id: str = "primary",
        priority: int | None = None,
    ) -> None:
        """Register a remote peer's TCP transport profile.

        Writes a `system/peer/transport/tcp` profile entity to
        `system/peer/transport/{peer_id_hex}/{profile_id}` (V7 v7.64 §1.4 —
        hex of the remote peer's ``system/peer`` content_hash) per
        EXTENSION-NETWORK §6.5.1 + §6.5.1a (v1.4 Amendment 2 D1, v1.5
        path-encoding alignment).

        ``public_key`` is OPTIONAL for identity-multihash form PeerIDs
        (V7 v7.64 §1.5 ``hash_type = 0x00``): the key is decodable from
        the Base58 PeerID directly. Required only for SHA-256-form
        PeerIDs (legacy/privacy choice; key bytes can't be recovered
        from Base58 alone).
        """
        self._publish_tcp_profile(
            peer_id, address,
            public_key=public_key, profile_id=profile_id, priority=priority,
        )

    def _publish_tcp_profile(
        self,
        peer_id: str,
        address: str,
        *,
        public_key: bytes | None = None,
        profile_id: str,
        priority: int | None = None,
    ) -> None:
        """Emit a TCP profile entity at the §6.5.1 path
        (``system/peer/transport/{peer_id_hex}/{profile_id}`` per V7 v7.64 §1.4)."""
        import time

        from entity_core.protocol.auth import compute_peer_identity_hash
        from entity_core.protocol.transport_ops import EXECUTE

        data: dict[str, Any] = {
            "peer_id": peer_id,
            "transport_type": "tcp",
            "endpoint": {"url": f"tcp://{address}"},
            "supported_ops": [EXECUTE],
            "freshness": "live",
            "nonce_required": True,
            "cap_flow": "both",
            "advertised_at": int(time.time() * 1000),
        }
        # Q1 (PROPOSAL §8.9): optional uint priority; omit when None per
        # `omitempty`. Selection defaults handled by the consumer
        # (primary→0, others→100) so absence is meaningful.
        if priority is not None:
            data["priority"] = priority
        entity = Entity(type="system/peer/transport/tcp", data=data)
        ctx = EmitContext.bootstrap()
        peer_id_hex = compute_peer_identity_hash(peer_id, public_key).hex()
        self.emit_pathway.emit(
            f"system/peer/transport/{peer_id_hex}/{profile_id}", entity, ctx
        )

    def register_remote_http(
        self,
        peer_id: str,
        url: str,
        *,
        public_key: bytes | None = None,
        profile_id: str = "primary-http",
        priority: int | None = None,
    ) -> None:
        """Register a remote peer's HTTP transport profile (Chunk D).

        Writes a ``system/peer/transport/http`` profile entity at
        ``system/peer/transport/{peer_id_hex}/{profile_id}`` per §6.5.1 + D1
        (V7 v7.64 §1.4 / EXTENSION-NETWORK v1.5 path-encoding alignment).
        Mirrors ``register_remote`` (which is TCP) — the consumer-side
        selector treats `tcp` and `http` profiles as parallel transports;
        an operator/dispatcher policy picks which to dial when both are
        published for the same peer.

        Args:
            peer_id: The remote peer's Base58 ID (body field).
            url: Live HTTP endpoint URL (e.g., ``https://api.example.com/entity``
                or ``http://127.0.0.1:8080/entity`` for dev). Must use
                ``http://`` or ``https://`` scheme per D4.
            public_key: The remote peer's raw 32-byte Ed25519 public key
                (used to derive the ``peer_id_hex`` path segment).
            profile_id: Per-peer-unique profile identifier (D1). Defaults
                to ``primary-http`` — kept distinct from ``primary`` so a
                peer can publish both ``tcp`` (primary) and ``http``
                (primary-http) profiles without colliding.
        """
        self._publish_http_profile(
            peer_id, url,
            public_key=public_key, profile_id=profile_id, priority=priority,
        )

    def _publish_http_profile(
        self,
        peer_id: str,
        url: str,
        *,
        public_key: bytes | None = None,
        profile_id: str,
        priority: int | None = None,
    ) -> None:
        """Emit an HTTP profile entity at the §6.5.1 path
        (``system/peer/transport/{peer_id_hex}/{profile_id}`` per V7 v7.64 §1.4)."""
        import time

        from entity_core.protocol.auth import compute_peer_identity_hash
        from entity_core.protocol.transport_ops import EXECUTE

        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError(
                f"http endpoint url must use http:// or https:// scheme: {url}"
            )
        data: dict[str, Any] = {
            "peer_id": peer_id,
            "transport_type": "http",
            "endpoint": {"url": url},
            "supported_ops": [EXECUTE],
            "freshness": "live",
            "nonce_required": True,
            "cap_flow": "both",
            "advertised_at": int(time.time() * 1000),
        }
        if priority is not None:
            data["priority"] = priority
        entity = Entity(type="system/peer/transport/http", data=data)
        ctx = EmitContext.bootstrap()
        peer_id_hex = compute_peer_identity_hash(peer_id, public_key).hex()
        self.emit_pathway.emit(
            f"system/peer/transport/{peer_id_hex}/{profile_id}", entity, ctx
        )

    def _publish_http_poll_profile(
        self,
        peer_id: str,
        base_url: str,
        *,
        public_key: bytes | None = None,
        profile_id: str,
        tree_leaf_suffix: str = ".bin",
        priority: int | None = None,
    ) -> None:
        """Emit an http-poll profile entity at the §6.5.1 path (Chunk E E.2).

        Per CHUNK-E-IMPL-PLAN §5 E.2: the serving listener self-publishes a
        ``system/peer/transport/http-poll`` profile so peers (and the cohort
        validate-peer harness) can discover it via the standard transport
        resolver. supported_ops covers what the route answers for — CONTENT_GET
        (E.3 v1) + TREE_GET. MANIFEST_GET is reserved (§7 — pending
        EXTENSION-MANIFEST §4) and stays off `supported_ops` until then.

        Endpoint shape: the §6.5.3 / cross-impl rich `system/substitute/endpoint`
        (prefix-based), NOT the single-`{url}` shape the live `http`/`tcp`
        profiles carry (cross-impl matrix F3). The prefixes point
        at this peer's live GET routes:
          - ``tree_url_prefix``     = ``{base_url}`` (the §6.4 ``{prefix}/{X}/…``
                                      root; ``{X}`` is a peer-id or the reserved
                                      ``content`` / ``manifest`` word)
          - ``content_url_prefix``  = ``{base_url}/content`` (the flat
                                      ``/content/{hex33}`` route — would be the
                                      §6.4 default, emitted explicitly so a
                                      strict decoder needs no derivation)
          - ``content_layout``      = ``"flat"`` (the route is ``/content/{hash}``;
                                      no shard directories)
          - ``tree_leaf_suffix``    = the server's leaf suffix (default ``.bin``)

        ``freshness`` = ``"live"`` (this is the live serving mode, §6.5.6) and
        ``cap_flow`` = ``"egress"`` (the GET-class fetch/serving face). Both
        are within the ratified §6.5.1 enums — ``freshness ∈ {live, async,
        static-immutable+signed-pointer}``, ``cap_flow ∈ {egress, ingress,
        both}`` — per RULING-CYCLE-CLOSEOUT-0.3 R3 (which retired the
        pre-ruling ``cap_flow: "none"``). The two are orthogonal axes:
        ``freshness`` is the connection-liveness model (live vs static
        snapshot), ``cap_flow`` is the fetch direction; a live serving peer is
        still ``egress`` (it serves out, consumers fetch). There is no separate
        "live-poll" type — the same profile type carries either freshness.
        """
        import time

        from entity_core.protocol.auth import compute_peer_identity_hash

        if not (base_url.startswith("http://") or base_url.startswith("https://")):
            raise ValueError(
                "http-poll endpoint url must use http:// or https:// scheme: "
                f"{base_url}"
            )
        base = base_url.rstrip("/")
        data: dict[str, Any] = {
            "peer_id": peer_id,
            "transport_type": "http-poll",
            "endpoint": {
                "tree_url_prefix": base,
                "content_url_prefix": base + "/content",
                "content_layout": "flat",
                "tree_leaf_suffix": tree_leaf_suffix,
            },
            "supported_ops": ["CONTENT_GET", "TREE_GET"],
            # freshness "live" = live serving mode (§6.5.6); in the ratified
            # §6.5.1 enum {live, async, static-immutable+signed-pointer}.
            "freshness": "live",
            # Poll routes are uncapability-gated by nature (arch ruling
            # §1.1 Axis 1) — hash-knowledge IS the read authority. The
            # serving scope predicate is the lever (§1.2 Axis 2).
            "nonce_required": False,
            # cap_flow "egress" — the GET-class fetch/serving face: the
            # provider serves, consumers fetch (RULING-CYCLE-CLOSEOUT-0.3 R3;
            # §6.5.3 static example, L921). Ratified enum is {egress, ingress,
            # both} — the pre-ruling "none" was outside it. The egress/etc.
            # axis is the fetch direction, orthogonal to the freshness axis.
            "cap_flow": "egress",
            "advertised_at": int(time.time() * 1000),
        }
        if priority is not None:
            data["priority"] = priority
        entity = Entity(type="system/peer/transport/http-poll", data=data)
        ctx = EmitContext.bootstrap()
        peer_id_hex = compute_peer_identity_hash(peer_id, public_key).hex()
        self.emit_pathway.emit(
            f"system/peer/transport/{peer_id_hex}/{profile_id}", entity, ctx
        )

    def publish_root(self, root_hash: bytes | None = None) -> Entity:
        """Mint + bind a signed ``system/peer/published-root`` (Phase P / C1).

        ``root_hash`` lets a caller supply an already-computed trie root.
        `PublishedRootRepublisher` maintains one incrementally, because the
        default full rebuild is O(bindings) *and* persists an intermediate
        node at every insertion step — fine once at startup, ruinous per
        root change (measured: 300 writes → 22 s and 200 880 stored
        entities, against 0.01 s and 1 508 with no republishing).

        The producer half of `PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE.md`
        §4. Computes the CHAMP trie root over this peer's current bindings,
        mints a signed ``system/peer/published-root`` pointing at it, and
        binds:
          - the root at ``system/peer/published-root`` (served by
            ``MANIFEST_GET``), and
          - its signature at ``system/signature/{hex(pr_hash)}`` (the V7
            §989 invariant pointer, so a cold http-poll consumer can
            target-match it without round-tripping the publisher).

        Re-publishing after the tree changes advances ``seq`` monotonically
        and links ``predecessor`` to the prior root (rollback defence +
        chain audit, per snapshot-manifest §3-RES.4). The trie root is
        computed *before* the published-root binding is added, so the root
        anchors the tree state at publish time and never tries to commit to
        itself.

        Returns the published-root entity.
        """
        import time

        from entity_core.peer.published_root import (
            PUBLISHED_ROOT_TYPE,
            build_published_root,
            published_root_signature_path,
        )
        from entity_core.storage.trie import build_trie

        if root_hash is None:
            bindings = sorted(self.entity_tree.all_bindings())
            root_hash = build_trie(bindings, self.content_store)

        # Monotonic seq + predecessor chain from any prior published-root.
        prev_seq = -1
        predecessor: bytes | None = None
        prev_hash = self.entity_tree.get("system/peer/published-root")
        if prev_hash is not None:
            prev = self.content_store.get(prev_hash)
            if prev is not None and prev.type == PUBLISHED_ROOT_TYPE:
                prior_seq = prev.data.get("seq")
                if isinstance(prior_seq, int):
                    prev_seq = prior_seq
                predecessor = prev_hash
        seq = prev_seq + 1

        pr_entity, sig_entity = build_published_root(
            self.keypair,
            root_hash,
            seq,
            int(time.time() * 1000),
            predecessor=predecessor,
        )
        # Self-tag both writes so `PublishedRootRepublisher` can tell its own
        # bindings from an operator's. Without the tag the publisher's two
        # emits look like ordinary root changes, re-fire the hook, and the
        # seq counter runs away with no external traffic at all (Go measured
        # ~55/s before they added the same guard) — and each spin invalidates
        # the served closure before any consumer's CONTENT_GET can complete.
        ctx = EmitContext(
            source="bootstrap", handler_pattern=PUBLISHER_HANDLER_PATTERN
        )
        self.emit_pathway.emit("system/peer/published-root", pr_entity, ctx)
        self.emit_pathway.emit(
            published_root_signature_path(pr_entity.compute_hash()),
            sig_entity,
            ctx,
        )
        return pr_entity

    def enable_root_republish(self) -> PublishedRootRepublisher:
        """Republish the signed root on **every** tree-root change (§4).

        `PROPOSAL-PEER-MANIFEST` §4: the peer mints a signed
        ``system/peer/published-root`` *on every tree-root change*. Without
        this the root is minted once at startup, `seq` stays 0, no
        `predecessor` chain forms, and — under the §6.5.6 Amendment 10
        timing ruling — the served closure is frozen at boot, so every
        entity written afterwards is permanently unservable.

        Idempotent: calling twice installs one republisher.
        """
        if self._root_republisher is None:
            self._root_republisher = PublishedRootRepublisher(self)
            self.emit_pathway._add_internal_hook(
                self._root_republisher,
                pattern=None,
                name=PUBLISHER_HANDLER_PATTERN,
            )
        return self._root_republisher

    async def start_http(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        *,
        base_url: str | None = None,
        url_path: str = "/entity",
        poll_prefix: str | None = None,
        scope_predicate: "ScopePredicate | None" = None,  # noqa: F821
        poll_base_url: str | None = None,
    ) -> "HttpServer":  # noqa: F821 (forward ref to avoid top-level import)
        """Bind a live HTTP listener (Chunk D — POST EXECUTE / EXECUTE-RESPONSE).

        Self-publishes a ``system/peer/transport/http`` profile entity at
        the §6.5.1 path under profile-id ``primary-http`` (D1 SHOULD)
        unless an operator-provided profile already exists. The server
        may be operated alongside ``start()`` (the TCP listener) on the
        same peer — they share dispatch state.

        Chunk E (Posture 2): pass ``poll_prefix`` + ``scope_predicate`` to
        also serve GET poll routes on the SAME listener. Use
        ``start_http_poll()`` for Posture 1 (isolated port).

        Args:
            host: Bind address.
            port: Bind port.
            base_url: Public URL prefix to advertise in the live profile.
            url_path: Live POST path. Default ``/entity``.
            poll_prefix: Optional — mount poll routes under this prefix
                on the same listener. Default ``/poll`` per cohort plan §3
                when passed without an explicit value at the CLI.
            scope_predicate: Required iff ``poll_prefix`` is set.
            poll_base_url: Public URL advertised in the http-poll profile.

        Returns:
            The bound HttpServer (for ``await server.stop()`` on teardown).
        """
        from entity_core.peer.http_server import HttpServer

        http_server = HttpServer(
            self,
            base_url=base_url,
            url_path=url_path,
            poll_prefix=poll_prefix,
            scope_predicate=scope_predicate,
            poll_base_url=poll_base_url,
        )
        await http_server.start(host, port)
        if not hasattr(self, "_http_servers"):
            self._http_servers: list[HttpServer] = []
        self._http_servers.append(http_server)
        return http_server

    async def start_http_poll(
        self,
        host: str = "127.0.0.1",
        port: int = 9201,
        *,
        scope_predicate: "ScopePredicate",  # noqa: F821
        poll_prefix: str = "",
        poll_base_url: str | None = None,
    ) -> "HttpServer":  # noqa: F821
        """Bind a Chunk E serving listener on its OWN port (Posture 1).

        Per CHUNK-E-IMPL-PLAN §2 Posture 1 (RECOMMENDED): isolated port for
        serving — clean abstraction, CDN-friendly, trivial reverse-proxy
        fronting. Routes mount at the top level by default
        (`/content/{hex(H)}`, `/tree/{absolute-path}`).

        Use ``start_http(..., poll_prefix=...)`` for Posture 2 (mount on
        the live POST listener under a prefix like ``/poll``).
        """
        from entity_core.peer.http_server import HttpServer

        http_server = HttpServer(
            self,
            url_path=None,  # poll-only listener; no live POST route.
            poll_prefix=poll_prefix,
            scope_predicate=scope_predicate,
            poll_base_url=poll_base_url,
        )
        await http_server.start(host, port)
        if not hasattr(self, "_http_servers"):
            self._http_servers: list[HttpServer] = []
        self._http_servers.append(http_server)
        return http_server

    async def _http_dispatch_envelope(
        self,
        envelope: Envelope,
        conn_state: PeerConnectionState,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Dispatch a single envelope received over an HTTP POST.

        Mirrors the per-iteration body of ``_handle_connection``'s frame
        loop, but awaits any spawned handler task inline so the HTTP
        response is ready before the function returns. ``writer`` is a
        ``_CollectingWriter`` from the HTTP layer; bytes written here
        become the response body.
        """
        from entity_core.protocol.messages import Execute, ExecuteResponse
        from entity_core.utils.path import extract_handler_path

        self._store_included_entities(envelope)
        self._bind_envelope_signatures(envelope)

        msg_type = envelope.root.get("type", "")
        if msg_type != Execute.TYPE:
            # HTTP transport accepts only EXECUTE; respond with a clean error.
            logger.debug("HTTP: ignoring non-EXECUTE message type %s", msg_type)
            response = ExecuteResponse.error(
                request_id="",
                message=f"http transport accepts only EXECUTE, got {msg_type}",
            )
            await send_envelope(writer, Envelope(root=response.to_entity()))
            return

        data = envelope.root.get("data", {})
        path = extract_handler_path(data.get("uri", ""))

        if path == CONNECT_URI and not conn_state.is_connected:
            await self._handle_connect(envelope, conn_state, writer)
            return

        if not conn_state.is_connected:
            # V7 §4.2 bullet 3 / §5.2a — 401 `authentication_failed`. The HTTP
            # half of the pair; see `_pre_establishment_refusal`. No cohort
            # probe can reach this boundary (they all dial TCP), which is
            # exactly why it shares the TCP one's refusal rather than its own.
            request_id = data.get("request_id", "")
            response = _pre_establishment_refusal(request_id)
            await send_envelope(writer, Envelope(root=response.to_entity()))
            return

        # Authenticated EXECUTE — await inline so the HTTP response carries
        # the result. (TCP spawns this as a task for read-loop concurrency;
        # HTTP is one-envelope-per-request so we keep it serial.)
        await self._run_handler_task(envelope, conn_state, writer)

    def _is_remote_uri(self, uri: str) -> bool:
        """Check if a URI targets a different peer.

        Args:
            uri: Entity URI (entity://peer_id/path) or absolute path (/peer_id/path).

        Returns:
            True if the URI targets a peer other than this one.
        """
        if uri.startswith("entity://"):
            parts = uri[len("entity://"):].split("/", 1)
            target_peer_id = parts[0] if parts else ""
            return target_peer_id != "" and target_peer_id != self.peer_id
        if uri.startswith("/"):
            parts = uri[1:].split("/", 1)
            target_peer_id = parts[0] if parts else ""
            return target_peer_id != "" and target_peer_id != self.peer_id
        return False

    async def _remote_execute(
        self,
        uri: str,
        operation: str,
        params: dict[str, Any] | None,
        resource_targets: list[str] | None = None,
        *,
        dispatch_capability_entity: dict[str, Any] | None = None,
        dispatch_capability_chain: list[dict[str, Any]] | None = None,
        bounds: "Bounds | None" = None,
        included: dict[bytes, dict[str, Any]] | None = None,
        reentry: "ReentryChannel | None" = None,
    ) -> ExecuteResult:
        """Execute an operation on a remote peer.

        Resolves the peer from the URI, gets or creates a pooled connection,
        and sends the EXECUTE over the wire.

        Args:
            uri: Target URI (entity://peer_id/path).
            operation: Operation to perform.
            params: Operation parameters.
            resource_targets: Resource paths for the target handler.
            dispatch_capability_entity: EXTENSION-CONTINUATION §4.2 case 3
                cross-peer dispatch only — the scoped, B-rooted
                `dispatch_capability` entity that authorizes this EXECUTE
                (grantee = this host peer). When None (every non-continuation
                remote call) the wire EXECUTE is byte-identical to before:
                authorized by the connection cap.
            dispatch_capability_chain: full authority chain for the above
                (collect_chain_bundle output) → dispatched envelope
                `included` per §4.3. Ignored unless the entity is set.

        Returns:
            ExecuteResult with status and result/error.
        """
        # Parse peer_id from URI or absolute path
        if uri.startswith("entity://"):
            peer_id = uri[len("entity://"):].split("/", 1)[0]
        elif uri.startswith("/"):
            peer_id = uri[1:].split("/", 1)[0]
        else:
            peer_id = uri.split("/", 1)[0]

        # Build resource dict for wire format if targets provided
        resource = None
        if resource_targets:
            resource = {"targets": resource_targets}

        # PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION Delta 1 / §5 gate — see
        # _wire_bounds_for_dispatch: system/bounds ride the wire ONLY for a
        # continuation advancement (chain_depth present). Ordinary remote
        # dispatch stays byte-identical (bounds dropped).
        wire_bounds = _wire_bounds_for_dispatch(bounds)

        # Resolve a dialable outbound connection. Pool first: a peer reachable
        # via a transport profile (incl. a genuinely bidirectional one that
        # also dialed us) keeps its pooled outbound path unchanged.
        try:
            conn = await self._remote_pool.get_connection(peer_id)
        except Exception as e:
            # V7 §6.11(b) / GUIDE-CONFORMANCE §7a.2a reentry fallback: pool
            # resolution missed. If the target is the peer connected to us on
            # the inbound connection this dispatch descends from, originate the
            # EXECUTE back over that same wire — it is the only channel to a
            # caller that dialed us and has no listener (the conformance
            # validator's B-no-listener case).
            # The seam is either the inbound connection this dispatch
            # descends from (the conformance B-no-listener case) or — for a
            # §6.5 (b) acceptor originating spontaneously under its
            # reciprocal grant — any live accepted connection from the
            # target peer.
            if reentry is None or peer_id != reentry.remote_peer_id:
                reentry = self._inbound_for_reentry(peer_id)
            if reentry is not None and peer_id == reentry.remote_peer_id:
                logger.debug(
                    "[dispatch:reentry] no outbound route to %s; "
                    "originating over inbound connection", peer_id[:16],
                )
                # EXTENSION-SIGNALING §6.5 (b) "Delivery + timing": on a
                # symmetric rendezvous establishment our originating
                # authority IS the reciprocal grant, and it lands ≈1 round
                # trip after the channel opens. Originating inside that
                # window would dispatch under the cap we minted for THEM —
                # `grantee != author`, a guaranteed 401. So gate on
                # grant-received, bounded: on expiry we fall through and let
                # the dispatch fail closed rather than block. A counterpart
                # that never adopts the grant therefore degrades to
                # one-directional, not to a hang.
                #
                # Only on a rendezvous establishment: a dial-by-address
                # acceptor is asymmetric, expects no grant, and must not pay
                # the wait.
                await self._await_reciprocal_grant(reentry.conn_state, peer_id)
                try:
                    response = await reentry.execute(
                        uri, operation, params,
                        capability=dispatch_capability_entity,
                        capability_chain=dispatch_capability_chain,
                        resource_targets=resource_targets,
                        bounds=wire_bounds,
                        included=list(included.values()) if included else None,
                    )
                except Exception as re:
                    logger.warning(
                        "Reentry execute to %s failed: %s", peer_id[:16], re,
                    )
                    return ExecuteResult(
                        status=502, error=f"Reentry execute failed: {re}",
                    )
                result = response.result
                error = None
                if response.status >= 400 and isinstance(result, dict):
                    error = result.get("message", result.get("error", ""))
                return ExecuteResult(
                    status=response.status,
                    result=result if isinstance(result, dict) else None,
                    error=error,
                )
            logger.warning(
                "Remote execute to %s failed (no route): %s", peer_id[:16], e,
            )
            return ExecuteResult(status=502, error=f"Remote execute failed: {e}")

        try:
            response = await conn.execute(
                uri, operation, params, resource=resource,
                capability_override=dispatch_capability_entity,
                capability_chain_override=dispatch_capability_chain,
                bounds=wire_bounds,
                # V7 §3.3 v7.51: forward the request envelope's included to the
                # wire — a dispatcher routing locally-originated entities to a
                # remote peer MUST NOT drop them.
                included=list(included.values()) if included else None,
            )
            result = response.result
            error = None
            if response.status >= 400 and isinstance(result, dict):
                error = result.get("message", result.get("error", ""))
            # §5.4 adaptive suppression: a successful exchange counts as
            # liveness — keepalive pings are skipped while active.
            self._remote_pool.note_activity(peer_id)
            return ExecuteResult(
                status=response.status,
                result=result if isinstance(result, dict) else None,
                error=error,
            )
        except Exception as e:
            # Amendment 12 §A1: transport error on a connection believed
            # active — the §10-step-1 direct-dispatch seam. Evict the dead
            # conn AND demote peer liveness to `suspect` (idempotent under
            # the no-clobber guard). This is the seam that both observes
            # the send error and holds peer_id (seam rule); the RELAY
            # terminal-hop below MUST NOT demote (ruling E).
            self._remote_pool.demote_on_transport_error(peer_id, conn, e)
            logger.warning("Remote execute to %s failed: %s", peer_id[:16], e)
            return ExecuteResult(status=502, error=f"Remote execute failed: {e}")

    async def _relay_deliver_inner(self, destination: str, inner_entity: Any) -> bool:
        """EXTENSION-RELAY §3.1.1 terminal-hop delivery hookpoint — raw-frame.

        Push the source's *original inner-envelope bytes* to ``destination`` as
        a normal inbound frame — byte-identical to a direct connection (§9 /
        §10.4). Per §3.1 the inner is a ``system/envelope``-typed entity whose
        ``.data`` is the ECF-encoded ``{root, included}`` of the source's signed
        envelope; we write those bytes verbatim. We do NOT decode the inner as
        an entity, re-encode it, or re-sign — the destination verifies the
        source's signature + capability chain exactly as on a direct connection
        (§5.1) and needs **no RELAY extension to receive**. The async response,
        if any, rides via the inner envelope's INBOX ``deliver_to`` (§6.2), so
        this is fire-and-forget — the relay tracks no per-request correlation.

        Returns True on delivery over a live/dialable session, False when the
        destination is unreachable or the inner is malformed (→ the caller
        performs the Mode-S fallback, §6.2.1).

        Matches the Go reference ``peerwiring.PeerDispatcher.DeliverInner`` and
        Rust ``PeerRelayForwarder``: require ``inner.type == system/envelope``,
        forward ``inner.data`` verbatim, translate unreachable → fallback.
        """
        from entity_core.utils.ecf import ecf_encode

        # §3.1 invariant: the raw-frame terminal hop requires a materialized
        # system/envelope inner. Anything else is a malformed forward-request
        # (e.g. a bare EXECUTE that was never wrapped) — fail rather than
        # silently re-wrap (the prior double-wrap bug surfaced by mp2).
        if inner_entity is None or getattr(inner_entity, "type", None) != "system/envelope":
            logger.warning(
                "relay terminal-hop: inner type %r, expected system/envelope (§3.1)",
                getattr(inner_entity, "type", None),
            )
            return False

        # The frame is inner.data verbatim: ECF({root, included}). inner.data
        # was carried opaque in `included` and its content_hash validated on
        # receipt, so canonical re-encode reproduces the source's original
        # bytes (the same property entity-hash validation already depends on).
        try:
            frame = ecf_encode(inner_entity.data)
        except Exception as e:  # pragma: no cover - defensive
            logger.warning("relay terminal-hop: encode inner envelope failed: %s", e)
            return False
        if not frame:
            return False

        try:
            conn = await self._remote_pool.get_connection(destination)
        except Exception:
            # Unreachable (no live session + no dialable transport profile) →
            # caller does the §6.2.1 Mode-S fallback.
            return False
        send_raw = getattr(conn, "send_raw_frame", None)
        if send_raw is None:
            # Transport with no raw-frame primitive — treat as unreachable for
            # terminal delivery; the fallback queues at Mode-S. Both live
            # transports now expose it: TCP Connection (connection.py) and
            # HTTP-live HttpConnection (http_client.py). http-poll is a
            # read-only consumer profile and never yields a pooled live
            # connection here, so this rung is effectively defensive.
            return False
        try:
            await send_raw(frame)
            return True
        except Exception as e:
            # Ruling E (Amendment 12 §A1, pinned normative): the RELAY
            # terminal-hop forward MUST NOT demote peer liveness — a
            # store-and-forward target is not "a connection believed
            # active"; Mode-S fallback owns this path's failure semantics.
            # Guarded eviction only (no status write).
            self._remote_pool.remove_connection(destination, expected=conn)
            logger.warning(
                "relay terminal-hop deliver to %s failed: %s", destination[:16], e
            )
            return False

    async def start(self, host: str = "127.0.0.1", port: int = 9000) -> None:
        """Start listening for connections.

        Args:
            host: Host to bind to.
            port: Port to bind to.

        Per §6.5.1a D1 (SHOULD self-publication): also writes our own
        `system/peer/transport/tcp` profile at
        `system/peer/transport/{self.peer_id_hex}/primary` (V7 v7.64 §1.4)
        so consumers walking our tree can discover us. Operators MAY
        override the advertised address by registering a profile manually
        before ``start()`` (the bind address may differ from the
        externally reachable address — NAT, port-forwarding).
        """
        self._server = await asyncio.start_server(
            self._handle_connection,
            host,
            port,
        )
        # SHOULD per D1: self-publish if no operator-provided profile
        # already exists. Don't clobber a manually-registered profile,
        # since the operator may have set a public address.
        self_profile_uri = self.entity_tree.normalize_uri(
            f"system/peer/transport/{self.peer_id_hex}/primary"
        )
        if self.entity_tree.get(self_profile_uri) is None:
            self._publish_tcp_profile(
                self.peer_id, f"{host}:{port}",
                public_key=self.keypair.public_key_bytes(),
                profile_id="primary",
            )
        logger.info(f"Peer {self.peer_id[:8]}... listening on {host}:{port}")

    async def stop(self) -> None:
        """Stop the peer and close all connections."""
        # Shut down any live HTTP listeners first.
        if hasattr(self, "_http_servers"):
            for http_server in self._http_servers:
                try:
                    await http_server.stop()
                except Exception as e:
                    logger.warning(f"HTTP server stop error: {e}")
            self._http_servers.clear()

        if self._server:
            self._server.close()

        # Cancel all connection handlers BEFORE awaiting wait_closed():
        # on Python 3.12+ Server.wait_closed() waits for every live
        # connection handler to finish, so awaiting it first deadlocks
        # whenever a remote peer still holds an open connection — local
        # shutdown must never depend on remote goodwill. (Each handler's
        # finally closes its writer, so remotes observe EOF and their §A1
        # / §5.4 liveness paths demote us reactively.)
        for task in self._connections:
            task.cancel()
        if self._connections:
            await asyncio.gather(*self._connections, return_exceptions=True)
        self._connections.clear()

        if self._server:
            await self._server.wait_closed()

        # Close outbound connections
        if hasattr(self, "_remote_pool"):
            await self._remote_pool.close_all()

        # Shutdown extensions in reverse order
        for ext in reversed(self._extensions):
            try:
                ext.shutdown()
            except Exception as e:
                logger.warning(f"Extension shutdown error: {e}")

    async def serve_forever(self) -> None:
        """Serve until cancelled."""
        if self._server:
            await self._server.serve_forever()

    def _store_included_entities(self, envelope: Envelope) -> None:
        """Store all included entities in the content store.

        Per spec §1.5 (Provenance Model), implementations MUST store included
        entities from envelopes in the content store. This preserves:
        - Signature entities (for later cryptographic verification)
        - Identity entities (for peer ID verification)
        - Capability chain entities (for delegation verification)

        The content store is safe for this—it's inert (no events triggered).
        Entities are already hash-validated by the framing layer.

        Args:
            envelope: The received envelope with included entities.
        """
        for entity_dict in envelope.included:
            # §1.8: these entities were validated on receipt by the framing
            # layer, so carry the claimed hash + any unknown top-level fields
            # verbatim (trust the validated hash, MUST NOT recompute) rather
            # than reconstructing and re-hashing. Fall back to from_dict only
            # for an entity that somehow arrived without a content_hash.
            #
            # H-G3 / F2b Layer 2 receiver-side write-amp guard: peek the
            # wire content_hash (carried verbatim per §1.8) and skip the
            # whole reconstruct + put if the hash is already in the content
            # store. Identity + signature entities repeat across deliveries
            # on a subscription stream; without this each delivery would pay
            # `Entity.from_wire_dict` + `put_content_only` for entities we
            # already have. Layer 1 short-circuits the put itself; this
            # guard additionally skips the reconstruct work above it.
            #
            # Best-effort, inert ingestion (§1.5): a single malformed included
            # entity (an unexpected wire shape from another impl) MUST NOT
            # crash the connection — log and skip it. The request it rode with
            # is still validated downstream and rejected with a clean error.
            try:
                wire_hash = entity_dict.get("content_hash")
                if (
                    isinstance(wire_hash, (bytes, bytearray))
                    and self.content_store.has(bytes(wire_hash))
                ):
                    continue
                try:
                    entity, _ = Entity.from_wire_dict(entity_dict)
                except ValueError:
                    entity = Entity.from_dict(entity_dict)
                # Use put_content_only - no tree mapping, no events
                self.emit_pathway.put_content_only(entity)
            except Exception as e:
                logger.warning(
                    "skipping malformed included entity during ingestion: %s", e
                )

    def _bind_envelope_signatures(self, envelope: Envelope) -> None:
        """Per EXTENSION-IDENTITY v3.3 §6.2 (SI-11): bind signatures
        from envelope.included at V7 invariant pointer paths
        `/{signer_peer_id}/system/signature/{target_hash_hex}` BEFORE
        any handler body executes.

        This is the dispatcher-level ingestion point. By happening here
        (right after `_store_included_entities`, before `_handle_execute`)
        every handler — substrate (`system/attestation:verify`,
        `system/quorum:verify`) and consumer (`system/identity:*`) —
        observes ingested signatures via the standard
        `find_signature_by_signer` lookup at the V7 invariant path.

        Idempotent on identical content_hash; conflicts (same path,
        differing content_hash) are logged and skipped — the downstream
        validator surfaces the resulting signature mismatch.

        Args:
            envelope: The received envelope with included entities.
        """
        from entity_core.utils.path import invariant_signature_path

        # Build a hash → identity_data index from envelope.included.
        # Identities may also be in content store from earlier envelopes
        # on this connection; we fall back to that if needed.
        identity_index: dict[bytes, dict[str, Any]] = {}
        signature_entities: list[Entity] = []
        for entity_dict in envelope.included:
            etype = entity_dict.get("type")
            if etype not in ("system/peer", "system/signature"):
                continue
            try:
                entity = Entity.from_dict(entity_dict)
            except (KeyError, TypeError):
                continue
            if etype == "system/peer":
                identity_index[entity.compute_hash()] = entity.data
            else:
                signature_entities.append(entity)

        if not signature_entities:
            return

        emit_ctx = EmitContext.bootstrap()
        for sig_entity in signature_entities:
            # Best-effort, per-signature: a malformed signature/identity entry
            # (an unexpected wire shape) is logged and skipped — it MUST NOT
            # crash ingestion or fail the request it rode with; the downstream
            # validator surfaces any real signature problem as a clean 4xx.
            try:
                sig_data = sig_entity.data
                target = _normalize_hash_value(sig_data.get("target"))
                signer = _normalize_hash_value(sig_data.get("signer"))
                if target is None or signer is None:
                    continue

                # Recover signer_peer_id: prefer envelope.included identity
                # entries, fall back to content store.
                identity_data = identity_index.get(signer)
                if identity_data is None:
                    stored = self.content_store.get(signer)
                    if stored is not None and stored.type == "system/peer":
                        identity_data = stored.data
                if identity_data is None:
                    continue
                # v7.65 §2: peer_id no longer in entity data — derive from pubkey
                from entity_core.crypto.identity import peer_id_from_identity_entity
                signer_peer_id = peer_id_from_identity_entity({"data": identity_data})
                if not signer_peer_id:
                    continue

                sig_hash = sig_entity.compute_hash()
                path = invariant_signature_path(signer_peer_id, target)
                full = self.emit_pathway.entity_tree.normalize_uri(path)
                existing = self.emit_pathway.entity_tree.get(full)
                if existing is not None:
                    if existing != sig_hash:
                        # Per SI-11 §5: spec says reject the envelope. We log
                        # and skip — the downstream validator will surface
                        # the signature mismatch and that translates into a
                        # 4xx for the request being signed. Future: surface
                        # at dispatcher with `signature_path_conflict`.
                        logger.warning(
                            "signature_path_conflict at %s (existing %s != %s)",
                            path, existing.hex()[:16], sig_hash.hex()[:16],
                        )
                    continue  # idempotent (existing == sig_hash) or conflict
                self.emit_pathway.emit_hash(path, sig_hash, emit_ctx)
            except Exception as e:
                logger.warning("skipping malformed envelope signature: %s", e)

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle incoming connection.

        Uses EXECUTE-based connect for handshake.

        Per V7 v7.48 §4.8 (A.2): inbound frame processing MUST be
        concurrent with outbound dispatch initiated from handlers. EXECUTE
        handling for authenticated frames is spawned as a task so the
        reader immediately loops back to receive the next frame — without
        this, a handler that itself awaits an outbound dispatch on the
        same connection (cross-peer continuation, fetch-back, etc.)
        deadlocks because the response it's waiting on can't be read.
        Concurrency is bounded by ``self._inbound_semaphore``. The connect
        handshake remains strictly serial (it MUST complete before any
        authenticated EXECUTE can run).
        """
        task = asyncio.current_task()
        if task:
            self._connections.add(task)

        conn_state = PeerConnectionState()
        # EXTENSION-NETWORK §6.7.1: the observed transport source, captured at
        # accept. Read here — not at dispatch — because it is a property of
        # the socket, and by the time a handler runs the peer must not have to
        # ask the transport anything to answer honestly.
        conn_state.observed_address = _peername_of(writer)
        # Tracks in-flight handler tasks for this connection so we can
        # drain them on close (and so the GC doesn't reap them mid-run).
        pending_handlers: set[asyncio.Task[None]] = set()

        try:
            # Message loop - connect is handled inline
            while True:
                # Frame decode. A desynced/undecodable frame is fatal to the
                # stream — framing can no longer be trusted — so close.
                # Gap-B (PROPOSAL §8.6): log the close-reason at
                # INFO with the peer-id prefix so cross-impl runs (Rust↔Python
                # validate-peer) self-report what Python rejected rather than
                # leaving the other side with a bare broken-pipe.
                try:
                    envelope = await recv_envelope(reader)
                except asyncio.IncompleteReadError:
                    who = (
                        conn_state.session.remote_peer_id[:8]
                        if conn_state.session else "<pre-connect>"
                    )
                    logger.info(
                        "[conn-close] peer=%s reason=incomplete_read "
                        "(peer hung up cleanly)", who,
                    )
                    break
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    who = (
                        conn_state.session.remote_peer_id[:8]
                        if conn_state.session else "<pre-connect>"
                    )
                    logger.info(
                        "[conn-close] peer=%s reason=undecodable_frame "
                        "exc=%s msg=%s",
                        who, type(e).__name__, e,
                    )
                    break

                # Per-request processing. A single bad request — malformed
                # included entities, an unexpected cap-chain wire shape from
                # another impl, etc. — MUST NOT tear down the connection.
                # Recover with an error response and keep serving (a graceful
                # reject, not a broken pipe).
                try:
                    # Store all included entities in content store for provenance
                    # Per spec §1.5, this preserves signatures and identities for
                    # later verification. Content store is safe (inert, no events).
                    self._store_included_entities(envelope)
                    # Per EXTENSION-IDENTITY v3.3 §6.2 (SI-11): bind any
                    # envelope-included signatures at V7 invariant pointer
                    # paths BEFORE handler dispatch. Required so substrate
                    # ops (system/attestation:verify, system/quorum:verify)
                    # see signatures bound regardless of arrival path.
                    self._bind_envelope_signatures(envelope)

                    msg_type = envelope.root.get("type", "")

                    if msg_type == Execute.TYPE:
                        data = envelope.root.get("data", {})
                        uri = data.get("uri", "")

                        # Extract handler-relative path from URI
                        from entity_core.utils.path import extract_handler_path
                        path = extract_handler_path(uri)

                        # Connect path - special-cased per spec. Stays
                        # INLINE: connect must complete (and write the
                        # AUTH response) before authenticated EXECUTEs
                        # can race.
                        if path == CONNECT_URI and not conn_state.is_connected:
                            await self._handle_connect(
                                envelope, conn_state, writer
                            )
                        elif (
                            conn_state.is_connected
                            and is_reentry_grant(envelope)
                        ):
                            # EXTENSION-SIGNALING §6.5 (b): the dialer's
                            # reciprocal grant — the capability it minted FOR
                            # US, which is what lets this acceptor originate
                            # back over this same channel.
                            #
                            # Intercepted here rather than dispatched because
                            # the frame carries no author, capability or
                            # signature of its own. It CANNOT: it arrives
                            # before any authority relationship exists that
                            # would cover a deposit handler, and §4.4's
                            # default connection grants reach none. It
                            # self-verifies through the granter signature
                            # enclosed in the frame. (A departure from the
                            # folded carriage sentence, matching both shipped
                            # impls — see peer/reciprocal.py.)
                            #
                            # Best-effort by design: a malformed or
                            # mis-granted frame is logged and dropped,
                            # leaving us without originating authority — the
                            # pre-adoption state — and never breaks the
                            # connection. Fire-and-forget: no response.
                            self._accept_reciprocal_grant(envelope, conn_state)
                        elif not conn_state.is_connected:
                            # Not connected yet - reject (inline; nothing
                            # in flight, write is safe without the lock
                            # because the loop hasn't spawned yet).
                            #
                            # V7 §4.2 bullet 3 / §5.2a — 401
                            # `authentication_failed`. This is CE-1, measured
                            # three-way on the wire by `entity-core-go` and
                            # ruled at 0.8.2.5; see
                            # `_pre_establishment_refusal` for why the status
                            # is the half that moves.
                            request_id = data.get("request_id", "")
                            response = _pre_establishment_refusal(request_id)
                            await send_envelope(
                                writer, Envelope(root=response.to_entity())
                            )
                        else:
                            # Normal authenticated EXECUTE — spawn so the
                            # reader is free to consume the next frame
                            # concurrently. Bounded by the semaphore.
                            handler_task = asyncio.create_task(
                                self._run_handler_task(
                                    envelope, conn_state, writer,
                                )
                            )
                            pending_handlers.add(handler_task)
                            handler_task.add_done_callback(
                                pending_handlers.discard,
                            )

                    elif msg_type == ExecuteResponse.TYPE:
                        # V7 §6.11(b) / GUIDE-CONFORMANCE §7a.2a: a response on
                        # an accepted connection is the reply to a reentry
                        # EXECUTE this peer originated back over the same wire
                        # (outbound-to-a-caller-with-no-listener). Demux it to
                        # the waiting Future. Absent a matching slot it is a
                        # genuinely unexpected server-push — log and drop, as
                        # before, rather than tearing the connection down.
                        rid = envelope.root.get("data", {}).get("request_id", "")
                        fut = conn_state.pending_reentry.pop(rid, None)
                        if fut is not None:
                            if not fut.done():
                                fut.set_result(envelope)
                        else:
                            logger.warning(
                                "Received unexpected EXECUTE_RESPONSE "
                                "(request_id=%r; no pending reentry)", rid,
                            )

                    else:
                        # Unknown root message type. Gap-B (PROPOSAL §8.6):
                        # respond with a clean error envelope
                        # rather than silently dropping the connection — a
                        # validator probe should see "unknown_message_type"
                        # in the response, not a broken pipe. Stay on the
                        # connection: framing is intact; only the root type
                        # is unrecognized.
                        who = (
                            conn_state.session.remote_peer_id[:8]
                            if conn_state.session else "<pre-connect>"
                        )
                        logger.info(
                            "[conn-rx] peer=%s rejecting unknown root type=%s "
                            "(staying open)", who, msg_type,
                        )
                        data = envelope.root.get("data", {})
                        request_id = data.get("request_id", "") if isinstance(
                            data, dict,
                        ) else ""
                        response = ExecuteResponse.bad_request(
                            request_id=request_id,
                            message=f"unknown message type: {msg_type!r}",
                        )
                        try:
                            if conn_state.is_connected:
                                await self._send_locked(
                                    writer, conn_state,
                                    Envelope(root=response.to_entity()),
                                )
                            else:
                                await send_envelope(
                                    writer, Envelope(root=response.to_entity()),
                                )
                        except Exception as send_err:
                            logger.info(
                                "[conn-close] peer=%s reason=write_failed "
                                "while_responding_to=unknown_type exc=%s",
                                who, send_err,
                            )
                            break

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    # Recoverable: this request blew up in pre-dispatch
                    # processing. Log it, answer with a clean error so the
                    # peer is not left hanging on a broken pipe, and continue
                    # serving the connection.
                    logger.exception(
                        "Request processing error (responding with error): "
                        "%s: %s", type(e).__name__, e,
                    )
                    await self._reject_request_with_error(
                        writer, conn_state, envelope, e,
                    )
                    continue

        except Exception as e:
            logger.exception(f"Connection error: {type(e).__name__}: {e}")
        finally:
            # Wake any reentry waiter so an in-flight outbound-over-inbound
            # EXECUTE doesn't hang for its full deadline when the connection
            # drops (V7 §6.11(b)). Mirrors Connection._reader_loop's finally.
            for rid, fut in list(conn_state.pending_reentry.items()):
                if not fut.done():
                    fut.set_exception(
                        ConnectionError(
                            "connection closed before reentry response for "
                            f"request_id={rid!r}"
                        )
                    )
            conn_state.pending_reentry.clear()
            # The §6.11(b) seam and the §6.5 (b) connection-scoped grant it
            # carries both die with the connection.
            self._unregister_inbound_reentry(conn_state)
            # Drain pending handler tasks before tearing down the writer.
            # If a peer disconnects mid-dispatch we let the handler finish
            # (it may have already produced its result; the write will
            # simply fail through the closed writer and the task will log
            # and exit). A short cap keeps shutdown bounded.
            if pending_handlers:
                done, still = await asyncio.wait(
                    pending_handlers, timeout=5.0,
                )
                for t in still:
                    t.cancel()
                if still:
                    await asyncio.gather(*still, return_exceptions=True)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            # Ruling C (full tier): the responder's close transition —
            # flip `system/connection` to `closed` when the inbound
            # connection ends (EOF, error, cancel). CAS-guarded on the
            # entity this handler wrote at establish so a re-handshake's
            # fresh `active` is never clobbered. NOT a status demotion:
            # peer-status demotions stay at the §A1/§5.4 seams only.
            if (
                conn_state.session is not None
                and conn_state.connection_entity_hash is not None
            ):
                from entity_core.peer import liveness
                liveness.mark_connection_closed(
                    self.emit_pathway,
                    self.content_store,
                    self.entity_tree,
                    conn_state.session.remote_identity_hash,
                    expected_hash=conn_state.connection_entity_hash,
                )
            if task:
                self._connections.discard(task)

    def _inbound_sem(self) -> asyncio.Semaphore:
        """Lazy accessor for the per-peer inbound concurrency semaphore.

        Constructed inside the running event loop on first use so it
        binds to the correct loop.
        """
        if self._inbound_semaphore_obj is None:
            self._inbound_semaphore_obj = asyncio.Semaphore(
                self._inbound_semaphore_size,
            )
        return self._inbound_semaphore_obj

    async def _reject_request_with_error(
        self,
        writer: asyncio.StreamWriter,
        conn_state: PeerConnectionState,
        envelope: Envelope,
        exc: Exception,
    ) -> None:
        """Send a clean error response for a request that raised in
        pre-dispatch processing, so a single bad request yields a graceful
        rejection rather than a torn-down connection (broken pipe).

        Best-effort: only EXECUTE requests get a response (others have no
        request_id to answer); write failures are swallowed — the connection
        loop continues regardless.
        """
        try:
            root = envelope.root if isinstance(envelope.root, dict) else {}
            if root.get("type") != Execute.TYPE:
                return
            request_id = root.get("data", {}).get("request_id", "") if isinstance(
                root.get("data"), dict
            ) else ""
            response = ExecuteResponse.error(
                request_id=request_id,
                message=f"request processing failed: {type(exc).__name__}",
            )
            await self._send_locked(
                writer, conn_state, Envelope(root=response.to_entity())
            )
        except Exception:
            logger.debug(
                "failed to send error response for rejected request",
                exc_info=True,
            )

    async def _send_locked(
        self,
        writer: asyncio.StreamWriter,
        conn_state: PeerConnectionState,
        envelope: Envelope,
    ) -> None:
        """Serialized outbound write helper (V7 v7.48 §4.8, A.2).

        Acquires the per-connection write lock so multiple concurrent
        handler tasks cannot interleave bytes mid-frame on the same
        StreamWriter. Failures are logged at debug; the caller's task
        context decides whether to escalate.
        """
        async with conn_state.get_write_lock():
            await send_envelope(writer, envelope)

    async def _run_handler_task(
        self,
        envelope: Envelope,
        conn_state: PeerConnectionState,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Per-frame handler task wrapper (V7 v7.48 §4.8, A.2).

        Acquires the inbound semaphore to bound concurrent handler
        execution per peer, then dispatches. Exceptions are logged here
        so they don't propagate into the reader loop and tear the
        connection down.
        """
        sem = self._inbound_sem()
        try:
            async with sem:
                await self._handle_execute(envelope, conn_state, writer)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception(
                "inbound handler task failed: %s: %s",
                type(exc).__name__, exc,
            )

    async def _handle_connect(
        self,
        envelope: Envelope,
        conn_state: PeerConnectionState,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle connect EXECUTE messages.


        Args:
            envelope: The EXECUTE envelope.
            conn_state: Connection state with connect tracking.
            writer: Stream writer for sending responses.
        """
        data = envelope.root.get("data", {})
        request_id = data.get("request_id", "")
        operation = data.get("operation", "")
        # Per §3.4, params is entity-shaped on the wire. We keep it
        # entity-shaped for handlers — connect authenticate needs the
        # envelope (including content_hash) for signature verification,
        # and other handlers already use a ``params.get("data", params)``
        # shim to tolerate both forms.
        params = data.get("params", {})

        # V7 §4.7 row 10 (0.8.2.4) — "an operation name the responder does not
        # implement, **in any state**" is `400 invalid_request`. State-
        # independent, so it is classified before any phase is read: the
        # alternative is a peer that answers `invalid_request` for `frobnicate`
        # pre-hello and `connection_already_established` for the same frame one
        # round-trip later, which is two rows for one input.
        if operation not in IMPLEMENTED_CONNECT_OPERATIONS:
            response = ExecuteResponse.bad_request(
                request_id=request_id,
                message=f"Unknown connect operation: {operation}",
                code="invalid_request",
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        if conn_state.connect.is_complete:
            if operation == "authenticate":
                # V7 §4.6 Hardening / 0.8.1 RT-6 — same single-use-nonce
                # replay rejection as the post-established-connection path
                # in _handle_execute; see the comment there.
                response = ExecuteResponse.unauthorized(
                    request_id=request_id,
                    message="Connect nonce already consumed",
                    code="invalid_nonce",
                )
                await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
                return
            response = ExecuteResponse.conflict(
                request_id=request_id,
                message="Connect already complete",
                code="connection_already_established",
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        try:
            if operation == "hello":
                conn_state.connect, hello_response = handle_connect_hello(
                    conn_state.connect, params, self.keypair, request_id
                )
                # Send EXECUTE_RESPONSE with our hello data as result
                await send_envelope(
                    writer, Envelope(root=hello_response.to_entity())
                )
                logger.debug(
                    f"Connect hello from {conn_state.connect.remote_peer_id[:8]}..."
                )

            elif operation == "authenticate":
                # V7 v7.69 §1.8 — the connecting peer's authored identity hash
                # (the authenticate signature's `signer`). Keying the resolver
                # and R6 session on this wire-authored value (not a local
                # recompute) keeps it byte-equal to the cap grantee under §4.5a.
                remote_identity_hash = _grantee_identity_hash(
                    envelope, params, conn_state.connect.remote_peer_id,
                )
                # Determine grants based on peer identity. The §4.4 assembly
                # (floor ∪ policy, advertisement-filtered) — the SAME one the
                # §6.5 (b) reciprocal mint runs, keyed on its counterpart.
                grants = self.assemble_inbound_grants(
                    conn_state.connect.remote_peer_id,
                    remote_identity_hash,
                )

                if grants is None:
                    # No grants - connect fails
                    response = ExecuteResponse.forbidden(
                        request_id=request_id,
                        message="No capability grant for this peer",
                    )
                    await send_envelope(
                        writer, Envelope(root=response.to_entity())
                    )
                    return

                # R6 — granter-side R3a lookup. Read the cap we previously
                # minted for this peer from the session entity's
                # `minted_capability` field (§9.1 R6-a / R6-e). The
                # grants_fingerprint guard rejects a tree-cached cap whose
                # underlying grants no longer match what the resolver
                # returns now (so a runtime grants widen/narrow re-mints).
                #
                # §9.1 R6-d: the session entity's `chain` is the cap
                # delegation chain only (leaf→root) — it does NOT carry
                # the granter identity or cap signature. Reconstruct
                # those on reuse: granter identity is built from our own
                # keypair (we ARE the granter); cap signature is
                # deterministic ed25519 over the cap hash, so re-signing
                # produces a byte-identical signature entity.
                remote_peer_id = conn_state.connect.remote_peer_id
                grants_fp = _grants_fingerprint(grants)
                held_capability_arg = None
                # V7 v7.64 §1.4: session path is keyed on hex of the remote
                # `system/peer` content_hash. Both the read-cached-minted and
                # the later write_session below use the same identity-hash key.
                cached = (
                    read_minted_capability(
                        self.content_store, self.entity_tree, remote_identity_hash,
                    ) if remote_identity_hash else None
                )
                # V7 v7.69 §4.5a item 5 — a persistent cap cache does NOT
                # traverse a format downgrade. The connection's active format
                # was negotiated at hello; a cached cap authored under a
                # different format MUST NOT be reused (its chain is
                # format-self-consistent and cannot ride a connection whose
                # active value differs). Mint fresh under the active format.
                active_format = conn_state.connect.active_hash_format
                if cached is not None:
                    cap_entity_c, _chain_c, _session_c = cached
                    cached_format = cap_entity_c.compute_hash()[0]
                    cap_grants = cap_entity_c.data.get("grants", []) or []
                    from entity_core.capability.grant import Grant
                    from entity_core.protocol.auth import (
                        create_identity_entity,
                        create_signature_entity,
                    )
                    try:
                        cap_grant_objs = [Grant.from_dict(g) for g in cap_grants]
                        cap_fp = _grants_fingerprint(cap_grant_objs)
                    except Exception:
                        cap_fp = None
                    if cap_fp == grants_fp and cached_format == active_format:
                        # V7 v7.65 §2: system/peer data = (public_key, key_type) only.
                        # The cap signature is reconstructed under the cap's
                        # (== active) format; the granter identity is not —
                        # §4.5a item 1a floor-pins it whatever the active value.
                        granter_id_c = create_identity_entity(self.keypair)
                        cap_sig_c = create_signature_entity(
                            self.keypair,
                            cap_entity_c.compute_hash(),
                            granter_id_c.compute_hash(),
                            algorithm=active_format,
                        )
                        held_capability_arg = (cap_entity_c, granter_id_c, cap_sig_c)

                (
                    conn_state.connect,
                    response,
                    response_envelope,
                    cap_triple,
                    minted_fresh,
                ) = handle_connect_authenticate(
                    conn_state.connect,
                    params,
                    envelope,
                    self.keypair,
                    grants,
                    held_capability=held_capability_arg,
                )

                # R6 persistence: record the minted cap in the per-peer
                # session entity's `minted_capability` field (§9.1 R6-a
                # — granter side). Chain = [leaf] only (root cap has no
                # parent). Supporting entities (granter identity, cap
                # signature) are reconstructed on reuse — NOT in chain.
                if minted_fresh:
                    cap_entity, _granter_id, _cap_sig = cap_triple
                    write_session(
                        self.emit_pathway,
                        self.content_store,
                        self.entity_tree,
                        remote_peer_id=remote_peer_id,
                        remote_identity_hash=(remote_identity_hash or b""),
                        remote_public_key=conn_state.connect.remote_public_key_bytes,
                        minted_capability=(cap_entity, []),
                    )
                    self._session_grants_fingerprint[remote_peer_id] = grants_fp

                # Set request_id on the response
                response.request_id = request_id
                # Rebuild envelope with correct request_id
                response_envelope = Envelope(
                    root=response.to_entity(),
                    included=response_envelope.included,
                )

                await self._send_locked(writer, conn_state, response_envelope)

                # Create session from connect state
                conn_state.session = Session(
                    local_peer_id=self.keypair.peer_id,
                    remote_peer_id=conn_state.connect.remote_peer_id,
                    remote_public_key=conn_state.connect.remote_public_key_bytes,
                )
                # EXTENSION-SIGNALING §6.5 (b): our own local classification
                # of this establishment (see `mark_rendezvous_establishment`).
                # Read from what WE know about how we met this peer — never
                # from the wire. Only a rendezvous-established acceptor
                # expects a reciprocal grant and pays the bounded wait.
                conn_state.established_via_rendezvous_key = (
                    conn_state.connect.remote_peer_id in self._rendezvous_peers
                )
                # V7 §6.11(b): register this accepted connection as an
                # origination seam for its peer. Until now reentry only
                # existed for a dispatch DESCENDING from an inbound request
                # (the conformance validator's B-no-listener case); a §6.5 (b)
                # acceptor originates SPONTANEOUSLY under the reciprocal
                # grant, with no inbound request to descend from, so the
                # seam has to be findable by peer-id.
                self._register_inbound_reentry(conn_state, writer)

                # Amendment 12 §A3: `connected` on establish — the
                # responder end of the handshake (the dialer end writes
                # its own in RemoteConnectionPool). Soft-fail inside the
                # helpers; skipped when the identity hash isn't derivable.
                # Ruling C (full tier): the responder's `system/connection`
                # establish transition, written first so the status entity
                # can carry the path ref (mirrors the dialer's shape).
                from entity_core.peer import liveness
                ts = liveness.now_ms()
                # TCP hands us a real StreamWriter with a peername; the
                # HTTP layer hands a _CollectingWriter shim (no socket,
                # no peer address — one POST per envelope).
                peername = (
                    writer.get_extra_info("peername")
                    if hasattr(writer, "get_extra_info") else None
                )
                # `address` is EMPTY on the responder, deliberately.
                # EXTENSION-NETWORK §6.7.1 MUST 2: the observed transport
                # source MUST NOT be persisted to `system/connection.address`.
                # That field means *the endpoint I dial to reach this peer*
                # and is dialer-side state — the responder holds no dialable
                # address for the remote and correctly records nothing. An
                # accepted connection's ephemeral source port written here is
                # a routable-LOOKING value that routes nowhere, and both §10
                # dispatch and `system/peer/status` consume this field as
                # dialable. (This peer previously wrote `tcp://{peername}`
                # here; caught by the §6.7 MUST-2 vector. Go writes no
                # responder-side connection entity at all — we keep ours,
                # because the `active`→`closed` transition is a Ruling C
                # surface this peer ships, but it records no address.)
                conn_state.connection_entity_hash = (
                    liveness.write_connection_status(
                        self.emit_pathway,
                        remote_peer_id=conn_state.connect.remote_peer_id,
                        remote_identity_hash=(remote_identity_hash or b""),
                        transport="tcp" if peername else "http",
                        address="",
                        status="active",
                        established_at=ts,
                    )
                )
                liveness.write_peer_status(
                    self.emit_pathway,
                    local_peer_id=self.keypair.peer_id,
                    remote_peer_id=conn_state.connect.remote_peer_id,
                    remote_identity_hash=(remote_identity_hash or b""),
                    status=liveness.STATUS_CONNECTED,
                    connected_at=ts,
                    connection_ref=(
                        liveness.connection_path(remote_identity_hash)
                        if conn_state.connection_entity_hash is not None
                        and remote_identity_hash
                        else None
                    ),
                )

                logger.info(
                    f"Connect complete with {conn_state.session.remote_peer_id[:8]}..."
                )

            else:
                # V7 §4.7's out-of-order row — an operation this responder
                # IMPLEMENTS, arriving in a state that forbids it, is `409
                # connection_sequence_error`. Reaching this arm means exactly
                # that: the unknown-operation row was answered at the top of
                # this method (state-independently), and `hello` /
                # `authenticate` are handled above, so the only member of
                # `IMPLEMENTED_CONNECT_OPERATIONS` that lands here is a
                # pre-handshake `ping` — §5.1 keepalive, which this peer serves
                # on an ESTABLISHED connection (`_handle_execute`) and which is
                # gated the inverse way from the handshake ops.
                #
                # This arm previously did not exist: the unknown-operation
                # branch stood here, so a pre-hello ping answered `400
                # invalid_request` — the row for an operation we do not
                # implement, which is false of ping and misdirects the remedy
                # exactly as row 10's split says. Measured by `entity-core-go`'s
                # `connect_ping_before_hello` (routed 2026-09-02-e); go answered
                # `403 connection_required`, a code in no spec, and rust the
                # ruled 409.
                #
                # Written as a fall-through on the SET rather than `operation ==
                # "ping"`, so a connect operation added later is classified by
                # its membership — the two boundaries diverging on which
                # operations exist is what produced this bug.
                response = ExecuteResponse.conflict(
                    request_id=request_id,
                    message=(
                        f"connection_sequence_error: {operation} requires an "
                        f"established connection (phase "
                        f"{conn_state.connect.phase})"
                    ),
                    code="connection_sequence_error",
                )
                await send_envelope(
                    writer, Envelope(root=response.to_entity())
                )

        except ConnectError as e:
            logger.warning(f"Connect error: {e}")
            # V7 §4.7 — emit the canonical wire (status, code) PAIR. The code
            # half was fixed once already (e.g. "unsupported_key_type" for
            # v7.66 §4.4 surface 6, rather than collapsing every connect
            # failure to "bad_request"); the STATUS half was still collapsed
            # to 400 here, which is not a cosmetic difference — §4.7's table
            # is a list of (failure, code, status) triples and three of its
            # ten rows are 401. A pre-hello `authenticate` (FM-1, row 6) is
            # `401 invalid_nonce`, and emitting `400 invalid_nonce` for it
            # would be as non-conformant as the `400 bad_request` it replaced.
            #
            # Unset status keeps the §4.7 default: 400. A refusal that wants
            # another status says so at the raise, where the failure mode is
            # known — deriving it here from the code would put the §4.7 table
            # in two places.
            code = getattr(e, "code", "invalid_request")
            status = getattr(e, "status", None) or 400
            if status == 401:
                response = ExecuteResponse.unauthorized(
                    request_id=request_id, message=str(e), code=code,
                )
            elif status == 409:
                response = ExecuteResponse.conflict(
                    request_id=request_id, message=str(e), code=code,
                )
            else:
                response = ExecuteResponse.bad_request(
                    request_id=request_id, message=str(e), code=code,
                )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))

    async def establish_via_rendezvous(self, peer_id: str) -> Any:
        """Establish with ``peer_id`` as a §3-rendezvous-met counterpart.

        The EXTENSION-SIGNALING §6.5 (b) trigger-(b) entry point: both
        peers agreed a rendezvous key out of band, met at it, and *that*
        mutual bringing of the key is the authorization act — so after the
        channel opens either peer may originate, and this dial mints the
        acceptor's half of that authority.

        Classifies **both** roles locally, because either side may end up
        the dialer: the dial carries the discriminator (which fires the
        mint), and `mark_rendezvous_establishment` records the peer so a
        connection *they* open is classified the same way. Nothing about
        the classification is exchanged.

        Callers: the signaling meet driver today; the §7 punch at the same
        site when it lands.
        """
        self.mark_rendezvous_establishment(peer_id)
        return await self._remote_pool.get_connection(
            peer_id, established_via_rendezvous_key=True,
        )

    def _register_inbound_reentry(
        self,
        conn_state: PeerConnectionState,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Record an accepted connection as an origination seam (§6.11(b))."""
        session = conn_state.session
        if session is None or not session.remote_peer_id:
            return
        self._inbound_reentry[session.remote_peer_id] = ReentryChannel(
            remote_peer_id=session.remote_peer_id,
            writer=writer,
            conn_state=conn_state,
            keypair=self.keypair,
            active_hash_format=conn_state.connect.active_hash_format,
        )

    def _unregister_inbound_reentry(
        self,
        conn_state: PeerConnectionState,
    ) -> None:
        """Drop the seam when its connection ends.

        The connection-scoped reciprocal grant dies with it, by
        construction — nothing wrote it anywhere else, which is the §6.5 (b)
        security property, not an omission.
        """
        session = conn_state.session
        if session is None:
            return
        existing = self._inbound_reentry.get(session.remote_peer_id)
        if existing is not None and existing.conn_state is conn_state:
            self._inbound_reentry.pop(session.remote_peer_id, None)

    def _inbound_for_reentry(self, peer_id: str) -> "ReentryChannel | None":
        """The accepted connection from ``peer_id``, if one is live."""
        channel = self._inbound_reentry.get(peer_id)
        if channel is None:
            return None
        if channel.conn_state.session is None:
            return None
        return channel

    def mark_rendezvous_establishment(self, peer_id: str) -> None:
        """Classify establishments with ``peer_id`` as §3-rendezvous-met.

        EXTENSION-SIGNALING §6.5 (b) "The discriminator is the rendezvous
        key, locally-derived, never wire-carried" `[MUST]`. The test is
        **positive and on the key** — was a §3 rendezvous key mutually
        brought? — not "rendezvous-driven vs profile-driven" (not exclusive)
        and not on substrate: a §7 punch derives its `pair_key` from the two
        peer-ids and therefore mints; only a direct dial to a resolved
        transport endpoint does not.

        Whoever drives the establishment calls this — today the signaling
        meet driver, and the punch when it lands, at the same site. It is
        deliberately **not** a wire field the counterpart sets: that is the
        §7.4.1 one-sided-claim failure shape. It need not be, because
        meeting proves both peers brought the same key, so each classifies
        independently and they agree by construction.

        This is the acceptor half (an accepted connection reads it at
        authenticate-complete). The dialer half is
        ``Connection.connect(..., established_via_rendezvous_key=True)``,
        which is what actually fires the mint.
        """
        self._rendezvous_peers.add(peer_id)

    async def _await_reciprocal_grant(
        self,
        conn_state: PeerConnectionState,
        peer_id: str,
    ) -> bool:
        """Bounded wait for the §6.5 (b) grant. Never blocks indefinitely.

        Returns whether a grant is in hand. A rendezvous-established
        acceptor waits up to the implementation-local bound; anything else
        returns immediately, since only a symmetric establishment mints.
        """
        from entity_core.peer.reciprocal import RECIPROCAL_GRANT_WAIT_SECONDS

        if conn_state.originating_capability is not None:
            return True
        if not conn_state.established_via_rendezvous_key:
            return False
        try:
            await asyncio.wait_for(
                conn_state.get_originating_ready().wait(),
                timeout=RECIPROCAL_GRANT_WAIT_SECONDS,
            )
            return True
        except asyncio.TimeoutError:
            logger.debug(
                "[§6.5] reciprocal grant from %s not in hand within %ss — "
                "originating fails closed",
                peer_id[:16], RECIPROCAL_GRANT_WAIT_SECONDS,
            )
            return False

    async def _attach_dialed_connection(self, endpoint: Any) -> None:
        """Give a freshly dialed connection its serving half.

        EXTENSION-SIGNALING §6.5 (b) **reach-back serving** `[MUST]` /
        V7 §6.11(b) dialer-side reentry. A peer that serves inbound EXECUTE
        only on connections it *accepted* has built exactly half of a
        symmetric establishment: the counterpart's origination arrives on
        the wire we opened, finds no serving path, and is dropped as an
        orphan response — silently, with every step reporting success
        (`§11.5.1` loopback-invisible, the `fire_at` failure shape).

        So the dialed connection gets the same handler path an accepted one
        gets: the same per-peer inbound semaphore, the same included-entity
        storage and signature binding, and — critically — the **same write
        lock**, so a reach-back response cannot interleave bytes with an
        outbound EXECUTE of our own on that wire.

        On a §6.5 (b) *symmetric* establishment this is also where the
        reciprocal grant is minted and delivered (dialer → acceptor), at the
        handshake's tail, because the grantee we must name is the acceptor's
        authored identity hash and the authenticate-response is where we
        learn it.
        """
        from entity_core.peer.connection import Connection

        if not isinstance(endpoint, Connection):
            # HTTP / http-poll endpoints are request-response substrates:
            # there is no persistent inbound frame path to serve on, and no
            # §6.5 (b) establishment rides them.
            return
        if endpoint.session is None:
            return

        conn_state = PeerConnectionState()
        conn_state.session = endpoint.session
        conn_state.connect.phase = "complete"
        conn_state.connect.remote_peer_id = endpoint.session.remote_peer_id
        conn_state.connect.remote_public_key_bytes = (
            endpoint.session.remote_public_key
        )
        conn_state.connect.active_hash_format = endpoint.active_hash_format
        # ONE lock per wire, shared with Connection.execute (see
        # Connection.get_write_lock) — two locks over one writer is a
        # byte-interleaving bug that only shows under concurrency.
        conn_state.write_lock = endpoint.get_write_lock()
        endpoint.serving_state = conn_state

        writer = endpoint.writer

        async def _serve(envelope: Envelope) -> None:
            # Same pre-dispatch processing the accepted path runs: an
            # origination carries its own authority chain in `included`,
            # and the verifier resolves it from the store (§1.5 provenance,
            # EXTENSION-IDENTITY §6.2 signature binding).
            self._store_included_entities(envelope)
            self._bind_envelope_signatures(envelope)
            await self._run_handler_task(envelope, conn_state, writer)

        endpoint.inbound_dispatcher = _serve

        if endpoint.established_via_rendezvous_key:
            await self._send_reciprocal_grant(endpoint)

    def _get_grants_for_peer(
        self,
        remote_peer_id: str,
        remote_identity_hash: bytes | None = None,
    ) -> list[Grant] | None:
        """Determine what grants to give a peer.

        Resolution order (per HANDOFF-RECOGNIZE-ON-ATTESTATION §4
        "Static FIRST so explicit per-peer overrides win over policy"):

          1. admin_peer_ids → default_grants (explicit per-peer
             override; always wins).
          2. `_grant_resolver` returns non-None → those grants win,
             including over debug_mode so a deployed policy fires even
             when the peer is started with --debug for verbose logging.
          3. debug_mode → default_grants (dev-only full access for
             un-policied peers).
          4. Static fallback → V7 §4.4 SHOULD floor (read system/type/*,
             system/handler/*; system/capability:request) UNIONed with
             the policy-table entry for this caller per V7 §4.4 v7.62.

        Args:
            remote_peer_id: The connecting peer's Base58 ID.
            remote_identity_hash: The peer's `system/peer` content hash.
                Passed to the grant resolver (the role extension keys
                tree state by this hash, not the peer-id).

        Returns:
            List of grants, or None if no grants should be given.
        """
        if remote_peer_id in self.admin_peer_ids:
            return self.default_grants
        if self._grant_resolver is not None:
            resolved = self._grant_resolver(
                remote_peer_id, remote_identity_hash,
            )
            if resolved is not None:
                return resolved
        if self.debug_mode:
            return self.default_grants
        # V7 §4.4 v7.64: SHOULD floor ∪ matched policy-table entry
        # (dual-form resolution per PROPOSAL-V7-POLICY-DUAL-FORM §2.5).
        floor = create_connect_grants()
        policy_grants = self._read_policy_grants_for(
            remote_identity_hash, remote_peer_id,
        )
        if policy_grants:
            return floor + policy_grants
        return floor

    async def _send_reciprocal_grant(self, conn: Any) -> None:
        """Mint the §6.5 (b) reciprocal capability and put it on the wire.

        Dialer side only, at the handshake's tail: the grantee we must name
        is the acceptor's authored identity hash, and the
        authenticate-response is where we learn it — so the grant cannot
        ride the handshake's own `auth_included`.

        Every failure here is a log, never an error. The grant is an
        authority the counterpart does not yet have, so failing to send it
        leaves them exactly where a non-adopting peer sits — one-directional
        and fail-closed. Breaking a working connection over it would trade a
        degradation for an outage.
        """
        from entity_core.peer.reciprocal import (
            ReentryGrantError,
            build_reentry_grant_envelope,
        )

        who = conn.session.remote_peer_id
        try:
            if conn.remote_identity is None:
                # We never saw the acceptor's authored identity entity (it
                # granted us no cap, or the chain was absent). We cannot
                # name the grantee the way verify compares it, and naming it
                # any other way mints a cap that fails `grantee_mismatch`.
                logger.debug(
                    "[§6.5] reciprocal grant skipped for %s: no authored "
                    "grantee identity on this connection", who[:16],
                )
                return
            grantee_identity, _ = Entity.from_wire_dict(conn.remote_identity)
            grantee_hash = grantee_identity.compute_hash()
            # The contents are the grant we would issue this peer as an
            # INBOUND dialer — the same assembly, keyed on the counterpart,
            # not the flat §4.4 floor (Q2). Running the assembly rather than
            # copying our own §6.6 cap is the point: the mirror is symmetric
            # construction, and this peer's policy table governs what it
            # hands out in both directions.
            grants = self.assemble_inbound_grants(who, grantee_hash) or []
            envelope = build_reentry_grant_envelope(
                self.keypair, grantee_identity, grants, conn.active_hash_format,
            )
            # Keep what we authored. The ruled Wielding shape (§6.5 (b)
            # Carriage phase 2) has the acceptor cite the cap / granter /
            # signature by REFERENCE and the dialer resolve all three "from
            # its own content store, because it authored them" — which is
            # only true if we actually kept them. Costs three entities and
            # makes a reference-only origination verifiable here whether or
            # not the counterpart also inlines them.
            for entity_dict in envelope.included:
                stored, _ = Entity.from_wire_dict(entity_dict)
                self.content_store.put(stored)
            async with conn.get_write_lock():
                await send_envelope(conn.writer, envelope)
            logger.debug(
                "[§6.5] sent reciprocal reentry grant — %s may now "
                "originate to us", who[:16],
            )
        except ReentryGrantError as exc:
            logger.debug(
                "[§6.5] reciprocal grant not minted for %s: %s", who[:16], exc,
            )
        except Exception as exc:  # noqa: BLE001 — best-effort by design
            logger.debug(
                "[§6.5] reciprocal grant not sent to %s: %s", who[:16], exc,
            )

    def _accept_reciprocal_grant(
        self,
        envelope: Envelope,
        conn_state: PeerConnectionState,
    ) -> None:
        """Validate an inbound §6.5 (b) grant and install it. Acceptor side.

        The granter is checked against the peer we **authenticated** on this
        connection, not against anything the frame claims: a grant from any
        other granter is both useless (the far side roots the chain at its
        own identity) and dishonest to store.
        """
        from entity_core.peer.reciprocal import (
            ReentryGrantError,
            accept_reentry_grant,
        )

        session = conn_state.session
        if session is None or not session.remote_identity_hash:
            logger.debug(
                "[§6.5] reentry-grant before authentication — dropped",
            )
            return
        try:
            capability, supporting = accept_reentry_grant(
                envelope, session.remote_identity_hash,
            )
        except ReentryGrantError as exc:
            logger.debug("[§6.5] reentry-grant dropped: %s", exc)
            return
        conn_state.install_originating_capability(capability, supporting)
        logger.debug(
            "[§6.5] accepted reciprocal reentry grant — we may now "
            "originate to %s", session.remote_peer_id[:16],
        )

    def assemble_inbound_grants(
        self,
        remote_peer_id: str,
        remote_identity_hash: bytes | None = None,
    ) -> list[Grant] | None:
        """The grant set this peer issues a peer that dials IN.

        The §4.4 assembly — floor (or resolver/admin/debug override) ∪ that
        peer's policy-table entry — then **advertisement-filtered** (V7 §3;
        `entity_core.capability.advertisement`).

        It has exactly two callers, deliberately:

        * :meth:`_handle_connect` — the §6.6 handshake mint, acceptor →
          dialer;
        * :meth:`_send_reciprocal_grant` — the EXTENSION-SIGNALING §6.5 (b)
          mint, dialer → acceptor, on a symmetric rendezvous establishment.

        One assembly with two callers is the Q2 ruling itself. "The mirror
        of what an inbound dialer receives" names the grant an inbound
        dialer *actually* receives — this assembled set — not the flat §4.4
        floor. Minting the bare floor while an inbound dialer gets the
        assembled set gives the establishment *whose justification is
        symmetry* asymmetric authority: the reciprocal direction `403`s on
        anything out-of-floor (measured by `entity-core-go`, 2026-08-05 —
        both shipped impls had exactly that defect). A second copy of the
        assembly is how the two directions drifted apart in the first place.

        The mirror is symmetric **construction**, not identical grant sets:
        each peer runs its own assembly against the counterpart, so A→B and
        B→A differ exactly as A's and B's policy tables differ. That is
        correct — authority is target-owned.
        """
        grants = self._get_grants_for_peer(remote_peer_id, remote_identity_hash)
        if not grants:
            return grants
        from entity_core.capability.advertisement import filter_advertised_grants

        return filter_advertised_grants(
            grants, self.advertised_served_scope(), self.peer_id,
        )

    def advertised_served_scope(self) -> list[Grant]:
        """What this peer advertises it SERVES, as grant entries.

        One entry per registered handler: the handler's pattern, its
        interface's declared operations (`system/handler/interface`), and
        an **unconstraining** resource axis — a handler advertises its whole
        namespace and is narrowed by resources at grant time, not here.

        "Unconstraining" is why the axis carries `/*/*` alongside `*` and
        not `*` alone. `covers_four_axes` canonicalizes both sides (V7 §5.4),
        and bare `*` canonicalizes to `/{local_peer_id}/*` — the LOCAL
        namespace, not everything. Advertising `*` alone therefore said "I
        serve only my own namespace", which is false: this peer serves the
        universal address space (a `tree:put` at `/{other_peer}/foo` lands
        and is readable — the `universal_address_space` category exercises
        exactly that). The understatement was silent and had teeth: every
        assembled grant claiming cross-namespace resources failed the
        resource axis and was **dropped**, including the query-specific
        entry `create_full_access_grant()` mints to carry v7.14
        `constraints`/`allowances`. An open-access peer then handed its
        counterpart only the universal `handlers:["*"]` entry (retained by
        the carve-out, which skips the resource check), so the query
        constraint/allowance pathway was unreachable from the wire — and
        any delegation narrowed FROM those constraints read as a child
        adding keys its parent lacked, and 403'd.

        A handler whose interface is not resolvable (registered without a
        manifest, or before the tree is seeded) advertises `operations: *`:
        it is registered, so it serves *something*, and inventing a narrower
        set would drop grants for operations it does in fact serve. A
        handler that declares an interface with **no** operations advertises
        none — it names nothing callable, and keeping an `operations: *`
        entry there would re-open the axis this ruling closed.
        """
        from entity_core.types.registry import get_handler_interface

        scope: list[Grant] = []
        for registered in self.handlers.list_handlers():
            pattern = registered.pattern
            operations: list[str] = ["*"]
            try:
                interface = get_handler_interface(
                    pattern.rstrip("/*") if pattern.endswith("/*") else pattern,
                    self.content_store,
                    self.entity_tree,
                )
            except Exception:  # noqa: BLE001 — a lookup failure is "unknown"
                interface = None
            if interface is not None:
                declared = interface.data.get("operations")
                if isinstance(declared, dict):
                    operations = sorted(declared.keys())
            scope.append(
                Grant.create(
                    handlers=[pattern],
                    resources=["*", "/*/*"],
                    operations=operations,
                )
            )
        return scope

    def _read_policy_grants_for(
        self,
        remote_identity_hash: bytes | None,
        remote_peer_id: str | None = None,
    ) -> list[Grant]:
        """V7 §4.4 v7.64: consult ``system/capability/policy/{peer_pattern}``.

        Dual-form resolution per PROPOSAL-V7-POLICY-DUAL-FORM §2.2 / §2.5:
        try hex form first (canonical), then Base58 form
        (pre-configuration affordance), then ``default``. Returns the
        matched entry's grants (as ``Grant`` objects) or ``[]`` when no
        entry exists.
        """
        from entity_core.capability.grant import Grant as _Grant

        def _read(peer_pattern: str) -> list[Grant] | None:
            tree = self.entity_tree
            store = self.content_store
            h = tree.get(f"system/capability/policy/{peer_pattern}")
            if h is None:
                return None
            entity = store.get(h)
            if entity is None:
                return None
            data = entity.data
            if not isinstance(data, dict):
                return None
            grants_raw = data.get("grants")
            if not isinstance(grants_raw, list):
                return None
            return [_Grant.from_dict(g) if isinstance(g, dict) else g
                    for g in grants_raw]

        if isinstance(remote_identity_hash, bytes) and remote_identity_hash:
            specific = _read(remote_identity_hash.hex())
            if specific is not None:
                return specific
        if remote_peer_id:
            base58_match = _read(remote_peer_id)
            if base58_match is not None:
                return base58_match
        fallback = _read("default")
        if fallback is not None:
            return fallback
        return []

    def set_grant_resolver(
        self,
        resolver: "Callable[[str, bytes | None], list[Grant] | None] | None",
    ) -> None:
        """Install (or clear) the AUTHENTICATE-time grant resolver.

        Wired after peer construction because the role policy resolver
        needs the peer's EmitPathway. Setting `None` reverts to the
        static fallback (debug_mode / admin_peer_ids / connect-scope).
        """
        self._grant_resolver = resolver

    # ------------------------------------------------------------------
    # Shared dispatch core (used by both the external request path,
    # `_handle_execute`, and internal handler-to-handler dispatch,
    # `_dispatch_local_execute`). Keeping the resolve+authorize sequence in
    # one place means the dispatch authorization model has a single
    # definition rather than two copies that must be kept in lockstep.
    # ------------------------------------------------------------------

    def _resolve_for_dispatch(
        self,
        path: str,
        operation: str,
        caller_capability: dict[str, Any],
        *,
        target_peer: str,
    ) -> "RegisteredHandler | _DispatchDenied":
        """Resolve the handler for `path` (V7 §6.6) and check that
        `caller_capability` permits `operation` on the matched handler scope.

        Args:
            path: The **handler-relative** path (`system/tree`) — handlers
                register at peer-relative patterns.
            target_peer: V7 §5.2 `extract_peer(execute.uri, local)` — the peer
                whose namespace this dispatch names. **Required, and required
                separately from `path`**: by the time dispatch resolves a
                handler the peer segment has already been stripped
                (`extract_handler_path`), so deriving it here would read
                `system/tree` and answer "local" for every request, including
                the foreign-namespace ones this dimension exists to refuse.
                Keyword-only and non-defaulted so a new call site has to say
                which peer it means rather than silently getting a pass.

        Returns the resolved handler, or a `_DispatchDenied` (404 no handler,
        403 handler scope).
        """
        from entity_core.capability.checking import check_handler_scope

        registered = self._resolve_handler(path)
        if registered is None:
            return _DispatchDenied(404, f"No handler for path: {path}")

        if not check_handler_scope(
            caller_capability, registered.pattern, operation, self.peer_id,
            target_peer=target_peer,
        ):
            return _DispatchDenied(
                403,
                f"Capability doesn't allow {operation} on handler "
                f"{registered.pattern}/"
                + (
                    f" in peer {target_peer}'s namespace"
                    if target_peer != self.peer_id else ""
                ),
            )
        return registered

    def _resolve_identity_entity(self, h: bytes) -> dict[str, Any] | None:
        """Resolve an identity (system/peer) entity by hash for §PR-8 granter
        framing. Returns a dict carrying `data` (what peer_id_from_identity_entity
        consumes), or None if the hash is not in the content store.

        The granter identity is stored at dispatch via _store_included_entities
        (and chain verification already required it resolvable), so a lookup
        here is hot-path cheap and present whenever the chain verified.
        """
        ent = self.content_store.get(h)
        return {"data": ent.data} if ent is not None else None

    def _bind_chain_rejected_marker(
        self,
        *,
        bounds: "Bounds | None",
        request_id: str,
        message: str,
        requesting_peer_id: str | None,
        attempted_uri: str | None,
        code: str = "capability_denied",
    ) -> bytes | None:
        """Bind a WB-27 ``rejected`` chain-error marker per v1.20 §3.10.3.

        Gated on the spec scope rule: ONLY fires when the inbound EXECUTE
        carries ``Bounds.chain_id`` (i.e., is a chain dispatch). Ordinary
        point-to-point EXECUTE cap-rejections surface only via the 403
        response — the caller synchronously sees them, so no marker is
        needed. Chain dispatches are fire-and-forget at the originating
        step, so without the marker the rejection is silent on the
        originator's side (the WB-27 observability gap).

        Per §3.10.7 + Q-C: dispatcher-side bind uses Peer's own identity
        (the ``core/chain-errors`` internal_scope analog in Python), NOT
        the caller's propagated cap (which was just rejected; binding
        under it would also be rejected by definition).

        Returns the bound marker's ``content_hash`` for §3.10.4
        mirror-pointer inclusion in the response, or ``None`` when:
        the request was not a chain dispatch (gate failed), OR the bind
        itself failed (§3.10.8 best-effort; logged via F11 surface).
        """
        if bounds is None or not bounds.chain_id:
            return None
        # Defer import to call site so the peer module doesn't impose a
        # hard dependency on entity_handlers at import time (the SDK
        # registers continuation handlers lazily; bind is best-effort).
        from entity_handlers.continuation import bind_dispatcher_rejected_marker

        return bind_dispatcher_rejected_marker(
            self.emit_pathway,
            self.peer_id,
            chain_id=bounds.chain_id,
            request_id=request_id,
            code=code,
            status=403,
            requesting_peer_id=requesting_peer_id,
            attempted_uri=attempted_uri,
            extra_body={"message": message} if message else None,
        )

    def _authorize_handler_grant(
        self, handler_pattern: str,
    ) -> "tuple[dict[str, Any], bytes | None] | _DispatchDenied":
        """Resolve and validate the handler's own grant (V7 §6.2 + spec-gap
        §S2 — granter must be local, signature must verify) and compute its
        content hash for history recording (W1/W6).

        Returns `(grant, grant_hash)`, or a `_DispatchDenied` (403) when the
        grant is missing or invalid — the same fail-closed treatment as §7.1.
        """
        handler_grant = self._get_handler_grant(handler_pattern)
        if handler_grant is None:
            return _DispatchDenied(
                403,
                f"Handler grant missing or invalid for {handler_pattern} "
                "(V7 §6.2)",
            )
        grant_uri = self.emit_pathway.entity_tree.normalize_uri(
            f"system/capability/grants/{handler_pattern}"
        )
        return handler_grant, self.emit_pathway.entity_tree.get(grant_uri)

    def _make_execute_dispatcher(
        self,
        seed_caller_capability: dict[str, Any],
        seed_author_peer_id: str | None,
        seed_author_identity_hash: bytes | None,
        seed_included: dict[bytes, dict[str, Any]] | None = None,
        reentry: "ReentryChannel | None" = None,
    ) -> Callable[..., Any]:
        """Build the `_execute_dispatcher` closure handed to a HandlerContext.

        Per V7 §6.8, when a handler dispatches a sub-request the original
        caller's capability and identity propagate to the child context. The
        closure forwards explicit ``propagated_*`` values when a caller
        supplies them, otherwise falls back to the seed values (the external
        caller at the top level; the effective caller for nested dispatch).

        Per V7 §3.3 (v7.51) the request envelope's ``included`` map likewise
        propagates: a sub-dispatch defaults to the parent's ``included`` (so a
        downstream continuation can resolve a bundled entity), unless the
        caller passes its own ``included`` to bundle (e.g. the subscription
        engine attaching an ``include_payload`` entity).
        """

        async def execute_dispatcher(
            uri: str,
            operation: str,
            params: dict[str, Any] | None,
            capability: dict[str, Any],
            request_bounds: Bounds | None,
            request_chain_id: str | None,
            request_resource_targets: list[str] | None = None,
            *,
            propagated_caller_capability: dict[str, Any] | None = None,
            propagated_author_peer_id: str | None = None,
            propagated_author_identity_hash: bytes | None = None,
            dispatch_capability_entity: dict[str, Any] | None = None,
            dispatch_capability_chain: list[dict[str, Any]] | None = None,
            included: dict[bytes, dict[str, Any]] | None = None,
            reactive_trigger: bool = False,
        ) -> ExecuteResult:
            return await self._dispatch_local_execute(
                uri,
                operation,
                params,
                capability,
                request_bounds,
                request_chain_id,
                request_resource_targets,
                propagated_caller_capability=(
                    propagated_caller_capability
                    if propagated_caller_capability is not None
                    else seed_caller_capability
                ),
                propagated_author_peer_id=(
                    propagated_author_peer_id
                    if propagated_author_peer_id is not None
                    else seed_author_peer_id
                ),
                propagated_author_identity_hash=(
                    propagated_author_identity_hash
                    if propagated_author_identity_hash is not None
                    else seed_author_identity_hash
                ),
                dispatch_capability_entity=dispatch_capability_entity,
                dispatch_capability_chain=dispatch_capability_chain,
                included=included if included is not None else seed_included,
                reentry=reentry,
                reactive_trigger=reactive_trigger,
            )

        return execute_dispatcher

    async def _handle_execute(
        self,
        envelope: Envelope,
        conn_state: PeerConnectionState,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle EXECUTE request.

        The Execute Protocol Handler processes all EXECUTE messages:
        - get/put: Direct entity tree access (no handler dispatch)
        - other operations: Dispatch to path-matched handler
        """
        execute_entity = envelope.root
        data = execute_entity.get("data", {})
        request_id = data.get("request_id", "")
        uri = data.get("uri", "")
        operation = data.get("operation", "")
        # Per §3.4, params is entity-shaped on the wire. Handlers use a
        # ``params.get("data", params)`` shim to extract the payload.
        params = data.get("params", {})

        # V1: Validate dispatch path per R12
        # Canonicalize(normalize(uri)) then validate_absolute_path
        from entity_core.capability.checking import normalize as normalize_uri
        from entity_core.capability.checking import canonicalize
        from entity_core.capability.checking import extract_peer
        from entity_core.utils.path import extract_handler_path, validate_absolute_path

        # Canonicalize is a pure transform (§5.4); validate_absolute_path is the
        # rejection point — a reserved ./ ../ or bare */ request path passes
        # through canonicalize unchanged, then fails validate (not absolute) -> 400.
        canonical_path = canonicalize(normalize_uri(uri), self.peer_id)

        # Validate the canonicalized absolute path
        validation_error = validate_absolute_path(canonical_path)
        if validation_error is not None:
            response = ExecuteResponse.bad_request(
                request_id=request_id,
                message=f"Invalid path: {validation_error}",
                # §3.3 names `invalid_path` in its 400 set "where one applies",
                # and this is where. `entity-core-go` emits it at the same seam
                # (`core/protocol/execute.go`, `core/tree/handler.go`); we
                # emitted the generic here only because we never stated a code.
                code="invalid_path",
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        # V7 §5.2 peers dimension: the target peer is read from the request
        # URI, and it has to be read HERE — `extract_handler_path` below drops
        # the peer segment, so anything downstream sees `system/tree` and can
        # only ever answer "local".
        target_peer = extract_peer(canonical_path, self.peer_id)

        # §1.4 inbound-dispatch routing gate (PD-1h, 0.8.2.2). An inbound
        # EXECUTE whose HANDLER uri names a peer that is not us is refused
        # here, at canonicalization — before handler resolution and before
        # `check_permission`.
        #
        # §6.5 step 3 makes this a GATE, not an ordering preference: it MUST
        # NOT be reached by stripping the peer id, resolving the local handler
        # and letting §5.2 decide. That is what this peer did, and it is
        # observable — under a grant whose `peers` scope covered the named
        # peer we answered 200, having executed our own handler under someone
        # else's address; under a narrower grant we answered 403, which is the
        # right refusal for the wrong reason and from the wrong layer. §6.2
        # forbids `404 handler_not_found` here too: 404 asserts "this peer has
        # no such handler", which is false of a peer refusing the ADDRESS.
        #
        # Scope, and it is the whole design of the rule: this reads the
        # handler uri and nothing else. A foreign `resource.targets` entry
        # under a LOCAL handler uri is the §1.4 universal-address-space slot —
        # the store is one local address space keyed by peer id, so a write to
        # `/{them}/…` is a local write (a follow-mirror), not a remote reach,
        # and it stays conformant. 0.8.2.3 withdrew a proposed `resources`
        # narrowing on exactly that argument. In-process sub-dispatch does not
        # pass through here at all, so §5.2 Dimension 4 remains the decider on
        # §1.4's internal-dispatch class — which, post-gate, is the only class
        # in which that dimension is still live.
        if target_peer != self.peer_id:
            response = ExecuteResponse.bad_request(
                request_id=request_id,
                message=(
                    f"EXECUTE targets peer {target_peer}, not this peer "
                    f"{self.peer_id} (§1.4 inbound dispatch)"
                ),
                code="invalid_request",
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        # Extract handler-relative path for dispatch
        path = extract_handler_path(canonical_path)

        # Post-connect operations on the connection handler:
        # §5.1 keepalive is an EXECUTE/EXECUTE_RESPONSE exchange on
        # `system/protocol/connect` op `ping`. Like the handshake itself,
        # it is special-cased ahead of capability verification — protocol-
        # level liveness is a property of the established connection, not
        # of any granted resource. Everything else on the connect path is
        # rejected after connect is complete.
        if path == CONNECT_URI:
            # V7 §4.7 row 10 (0.8.2.4) — "in any state", and this is the other
            # state. An operation name this peer does not implement is `400
            # invalid_request` here exactly as it is pre-handshake; it fell
            # through to `connection_already_established` below, which says the
            # frame was refused for the connection's STATE when the defect is
            # its NAME — the misdirected remedy the row split exists to stop,
            # arriving on the established side where no probe drove it. The
            # classifier is the same set the pre-connect boundary reads, so the
            # two cannot disagree about which operations exist.
            if operation not in IMPLEMENTED_CONNECT_OPERATIONS:
                response = ExecuteResponse.bad_request(
                    request_id=request_id,
                    message=f"Unknown connect operation: {operation}",
                    code="invalid_request",
                )
                await self._send_locked(
                    writer, conn_state, Envelope(root=response.to_entity())
                )
                return
            if operation == "ping":
                payload = params.get("data", params) if isinstance(params, dict) else {}
                pong = {
                    "type": "system/network/pong",
                    "data": {
                        # §5.3: echo timestamp + sequence from the ping.
                        "timestamp": int(payload.get("timestamp", 0) or 0),
                        "sequence": int(payload.get("sequence", 0) or 0),
                        "server_time": int(time.time() * 1000),
                    },
                }
                response = ExecuteResponse.success(request_id, pong)
                await self._send_locked(
                    writer, conn_state, Envelope(root=response.to_entity())
                )
                return
            if operation == "authenticate":
                # V7 §4.6 Hardening / 0.8.1 RT-6 — the issued handshake nonce
                # is single-use; a second `authenticate` on an established
                # connection is a replay of the (now-consumed) nonce, not a
                # generic state conflict. MUST reject with 401 invalid_nonce,
                # not 409 (a 409/state-conflict status under-signals a
                # replay and is non-conformant per §4.6 Hardening).
                response = ExecuteResponse.unauthorized(
                    request_id=request_id,
                    message="Connect nonce already consumed",
                    code="invalid_nonce",
                )
                await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
                return
            # §4.7 row 9 — the only implemented operation left is `hello`, and a
            # hello on an established connection is the row-9 state conflict.
            response = ExecuteResponse.conflict(
                request_id=request_id,
                message="Connect already complete",
                code="connection_already_established",
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        # Build detailed execute log
        log_parts = [f"req={request_id[:16] if request_id else 'none'}", f"uri={uri}", f"op={operation}"]
        if data.get("resource"):
            res = data["resource"]
            if res.get("targets"):
                log_parts.append(f"targets={res['targets']}")
            if res.get("exclude"):
                log_parts.append(f"exclude={res['exclude']}")
        if data.get("deliver_to"):
            deliver = data["deliver_to"]
            log_parts.append(f"deliver_to={deliver.get('uri', '?')}")
        if params:
            param_keys = list(params.keys())[:5]  # First 5 keys
            if len(params) > 5:
                param_keys.append(f"...+{len(params)-5}")
            log_parts.append(f"params=[{', '.join(str(k) for k in param_keys)}]")
        logger.debug("[dispatch] execute: %s", " ".join(log_parts))

        # Parse and enforce bounds (V2 section 5.3)
        bounds_data = data.get("bounds")
        bounds = Bounds.from_dict(bounds_data) if bounds_data else Bounds()
        bounds.apply_defaults()

        if bounds_data:
            # chain_depth is the continuation causal-chain axis (§3.9), inherited
            # across the wire and independent of the per-hop TTL. Logged here so
            # the *inbound* depth is observable on the cross-peer path — without
            # it, a cross-impl probe cannot see the global depth accumulate vs.
            # TTL decrement (the Go↔Python anchor-1 "no chain_depth in the line").
            logger.debug("[dispatch] bounds: ttl=%s budget=%s chain=%s chain_depth=%s",
                        bounds.ttl, bounds.budget,
                        bounds.chain_id[:12] if bounds.chain_id else "none",
                        bounds.chain_depth if bounds.chain_depth is not None else "none")
            # Cross-peer cascade tracking (SYSTEM-COMPOSITION §3.4)
            if bounds.chain_id and bounds.cascade_depth is not None:
                self.emit_pathway.track_chain_depth(bounds.chain_id, bounds.cascade_depth)

        # Pre-dispatch check: reject if bounds exhausted.
        #
        # The wire response MUST name the bound that terminated the request
        # (`ttl_exhausted` / `budget_exhausted`), NOT a generic `bad_request`:
        # a cross-peer continuation chain that hits a bound at a peer's ingress
        # is refused *here*, before any handler runs, so this is the only site
        # that spells the terminal the *caller* observes. The sender-side lost
        # marker the continuation handler attributes (§4a O1) never reaches this
        # wire code. An unattributed `bad_request` is what left the Go↔Python
        # cross-impl anchor-1 probe unable to tell a bounds brake from a
        # malformed request (entity-core-go
        # 2026-07-18-crosspeer-continuation-bounds-anchor1-cohort.md, finding 2).
        # Same wire surface `relay.py` already emits for source-route `ttl_hops`.
        if bounds.ttl_exhausted:
            response = ExecuteResponse.bad_request(
                request_id=request_id,
                message=TTL_EXHAUSTED_MESSAGE,
                code=TTL_EXHAUSTED_CODE,
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        if bounds.budget_exhausted:
            response = ExecuteResponse.bad_request(
                request_id=request_id,
                message=BUDGET_EXHAUSTED_MESSAGE,
                code=BUDGET_EXHAUSTED_CODE,
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        # Decrement TTL on dispatch
        bounds.decrement_ttl()

        # Two-level verification
        # Step 1: Verify request integrity (signature, chain, grantee,
        # revocation — V7 §5.2 v7.63 Step 4 wired via revocation_ctx).
        from entity_core.protocol.auth import verify_request_integrity
        from entity_core.capability.revocation import DefaultRevocationContext

        # Build the envelope-included map (by content_hash) so is_revoked
        # can walk chains whose intermediate caps haven't been persisted yet.
        included_by_hash: dict[bytes, dict[str, Any]] = {}
        for ent in envelope.included:
            h = ent.get("content_hash")
            if isinstance(h, bytes) and h:
                included_by_hash[h] = ent

        revocation_ctx = DefaultRevocationContext(
            entity_tree=self.entity_tree,
            content_store=self.content_store,
            included=included_by_hash,
            supports_revocation=True,
        )
        verification = verify_request_integrity(
            envelope,
            local_peer_id=self.peer_id,
            revocation_ctx=revocation_ctx,
        )
        if not verification.valid:
            logger.warning("[dispatch] auth failed: %s", verification.error)
            # PR-3 (V7 v7.39 §3.3): chain-validation subcodes that need
            # a non-default status (e.g. `unresolvable_grantee` → 401)
            # come through verification.error_code.
            # V7 v7.71 §3.3 verdict-to-status discriminator. The §5.2 verdict
            # carries an error_code naming which half of the check failed:
            #   - authentication_failed → 401 (step-1/step-2: content hash +
            #     signature/author/identity resolution — the wire-side identity
            #     half; v7.71 §A4-AUTHZ Class B-Common).
            #   - unresolvable_grantee → 401 (PR-3 single 401 carve-out).
            #   - revoked → 403 capability_revoked (Class C / RULING-CLASS-C:
            #     the verifier KNOWS the cap was revoked, so it
            #     surfaces the defined code rather than the opaque default —
            #     v7.71 "don't catch-all where a defined code applies").
            #   - everything else → 403 capability_denied (authz default).
            if verification.error_code == "unresolvable_grantee":
                logger.debug("[dispatch] -> response status=401 code=unresolvable_grantee")
                response = ExecuteResponse(
                    request_id=request_id,
                    status=Uint(401),
                    result={
                        "code": "unresolvable_grantee",
                        "message": verification.error or "Capability grantee unresolvable",
                    },
                )
            elif verification.error_code == "authentication_failed":
                logger.debug("[dispatch] -> response status=401 code=authentication_failed")
                response = ExecuteResponse(
                    request_id=request_id,
                    status=Uint(401),
                    result={
                        "code": "authentication_failed",
                        "message": verification.error or "Authentication failed",
                    },
                )
            elif verification.error_code == "revoked":
                logger.debug("[dispatch] -> response status=403 code=capability_revoked")
                # WB-27 / v1.20 §3.10.3: rejected marker still fires for a
                # chain-dispatch rejection; only the surfaced code differs.
                msg = verification.error or "Capability revoked"
                marker_hash = self._bind_chain_rejected_marker(
                    bounds=bounds, request_id=request_id, message=msg,
                    requesting_peer_id=(
                        conn_state.session.remote_peer_id
                        if conn_state.session else None
                    ),
                    attempted_uri=path,
                )
                response = _forbidden_with_rejected_marker(
                    request_id, msg, marker_hash,
                )
                if isinstance(response.result, dict):
                    response.result["code"] = "capability_revoked"
            elif verification.error_code == "chain_depth_exceeded":
                # V7 §4.10(b) (v7.75 resource-bounds floor): a capability
                # chain deeper than the declared max_chain_depth is a
                # client-correctable structural excess, NOT an authz verdict.
                # Keystone V7.75 ruling: 400, not 403 — a 403
                # would conflate "chain too deep" with "you lack the cap" and
                # the caller couldn't distinguish them. No rejected marker:
                # this is a request-shape error, not a chain-dispatch denial.
                logger.debug("[dispatch] -> response status=400 code=chain_depth_exceeded")
                response = ExecuteResponse.bad_request(
                    request_id=request_id,
                    message=verification.error or "Capability chain too deep",
                    code="chain_depth_exceeded",
                )
            else:
                logger.debug("[dispatch] -> response status=403 code=capability_denied")
                # WB-27 / v1.20 §3.10.3: rejected marker fires only when
                # the rejected inbound EXECUTE is a chain dispatch.
                msg = verification.error or "Authentication failed"
                marker_hash = self._bind_chain_rejected_marker(
                    bounds=bounds, request_id=request_id, message=msg,
                    requesting_peer_id=(
                        conn_state.session.remote_peer_id
                        if conn_state.session else None
                    ),
                    attempted_uri=path,
                )
                response = _forbidden_with_rejected_marker(
                    request_id, msg, marker_hash,
                )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        capability_data: dict[str, Any] = {}
        capability_hash: bytes | None = None
        if verification.capability_entity:
            capability_data = verification.capability_entity.data
            capability_hash = verification.capability_entity.compute_hash()

        # The cryptographically-verified author of THIS EXECUTE
        # (`ctx.execute.data.author`, V7 §5.2). Distinct from the
        # connect-time session identity for cross-peer flows where the
        # connection is authenticated by one identity but the request is
        # authored by the in-chain cap holder (EXTENSION-CONTINUATION
        # §3.1a/§8.1 — the continuation install writer check).
        verified_author_hash: bytes | None = None
        if verification.identity_entity is not None:
            verified_author_hash = verification.identity_entity.compute_hash()

        # Log auth success with capability summary
        cap_summary = "none"
        if capability_data.get("grants"):
            grants = capability_data["grants"]
            cap_summary = f"{len(grants)} grant(s)"
            # Show first grant's scope for context
            if grants and isinstance(grants, list) and len(grants) > 0 and isinstance(grants[0], dict):
                g = grants[0]
                handlers = g.get("handlers", ["*"])
                ops = g.get("operations", ["*"])
                h_str = handlers[0] if isinstance(handlers, list) and handlers else "*"
                o_str = ops[0] if isinstance(ops, list) and ops else "*"
                cap_summary += f" [{h_str}:{o_str}]"
        logger.debug("[dispatch] auth ok: peer=%s cap=%s", conn_state.session.remote_peer_id[:12] if conn_state.session else "?", cap_summary)

        # Resolve handler first, then check handler scope.
        # V7 §6.6: in-memory dispatch index, falling back to tree walk
        # for runtime-registered handlers (entity-native handlers
        # installed via system/handler:register).
        assert conn_state.session is not None
        # check_handler_scope is also used below for the deliver_token check;
        # check_resource_scope for the resource-target check.
        from entity_core.capability.checking import (
            check_handler_scope,
            check_resource_scope,
            granter_frame_peer_id,
        )

        # V7 §PR-8: the presented (leaf) capability's own resource patterns are
        # peer-local to *its granter*, not to this verifier. Resolve the granter
        # frame once and use it for every grant-pattern match below; the request
        # targets stay framed on self.peer_id. For self-issued caps the two are
        # identical, so this is a no-op except in the foreign-granter case.
        granter_frame = granter_frame_peer_id(
            capability_data, self.peer_id, self._resolve_identity_entity
        )

        # Steps 1-2: resolve handler (V7 §6.6) + handler-scope check (shared).
        resolved = self._resolve_for_dispatch(
            path, operation, capability_data, target_peer=target_peer,
        )
        if isinstance(resolved, _DispatchDenied):
            if resolved.status == 404:
                logger.debug("[dispatch] -> response status=404 code=not_found")
                response = ExecuteResponse.not_found(
                    request_id=request_id, message=resolved.message,
                )
            else:
                logger.warning(
                    "[dispatch] handler scope denied: op=%s path=%s", operation, path
                )
                logger.debug("[dispatch] -> response status=403 code=capability_denied")
                marker_hash = self._bind_chain_rejected_marker(
                    bounds=bounds, request_id=request_id,
                    message=resolved.message,
                    requesting_peer_id=conn_state.session.remote_peer_id,
                    attempted_uri=path,
                )
                response = _forbidden_with_rejected_marker(
                    request_id, resolved.message, marker_hash,
                )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        handler = resolved.handler
        handler_pattern = resolved.pattern
        logger.debug("[dispatch] handler matched: pattern=%s name=%s", handler_pattern, resolved.name)

        # V7: Extract resource targets from EXECUTE
        resource_data = data.get("resource")
        resource_targets: list[str] | None = None
        if resource_data:
            resource_targets = resource_data.get("targets", [])
            resource_exclude = resource_data.get("exclude")

            # V2 (R12): Validate resource target paths
            if resource_targets:
                for i, target in enumerate(resource_targets):
                    # canonicalize is a pure transform; validate_absolute_path
                    # rejects a malformed request target (reserved/ambiguous
                    # prefixes pass through canonicalize, fail validate -> 400).
                    canonical_target = canonicalize(target, self.peer_id)
                    target_error = validate_absolute_path(canonical_target)
                    if target_error is not None:
                        response = ExecuteResponse.bad_request(
                            request_id=request_id,
                            message=f"Invalid resource target: {target_error}",
                            code="invalid_path",  # §3.3 — same seam, same code.
                        )
                        await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
                        return

            # V7 §5.2: Dispatch-level resource check when resource is present
            # The same grant must match handler, operation, AND resource
            if resource_targets:
                if not check_resource_scope(
                    capability_data, handler_pattern, operation, resource_targets,
                    resource_exclude, self.peer_id, granter_peer_id=granter_frame,
                    target_peer=target_peer,
                ):
                    logger.warning("[dispatch] resource scope denied: targets=%s", resource_targets)
                    logger.debug("[dispatch] -> response status=403 code=capability_denied")
                    msg = f"Capability doesn't grant {operation} on resource targets"
                    marker_hash = self._bind_chain_rejected_marker(
                        bounds=bounds, request_id=request_id, message=msg,
                        requesting_peer_id=conn_state.session.remote_peer_id,
                        attempted_uri=path,
                    )
                    response = _forbidden_with_rejected_marker(
                        request_id, msg, marker_hash,
                    )
                    await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
                    return

        # V7.8: Extract and validate deliver_to/deliver_token for async delivery
        from entity_core.protocol.delivery import DeliverySpec

        deliver_to_data = data.get("deliver_to")
        deliver_token = data.get("deliver_token")
        deliver_to: DeliverySpec | None = None

        if deliver_to_data:
            deliver_to = DeliverySpec.from_dict(deliver_to_data)

            # Validate deliver_token is required with deliver_to
            if deliver_token is None:
                logger.warning("[dispatch] deliver_to without deliver_token")
                # The log named `missing_deliver_token` and the wire carried the
                # generic code — a debug line stating a `(status, code)` pair the
                # response does not have is the first thing a cross-impl debug
                # reads, and no spec names that code. §3.3: an extension-surface
                # structural refusal is the generic `invalid_request`.
                logger.debug("[dispatch] -> response status=400 code=invalid_request")
                response = ExecuteResponse.bad_request(
                    request_id=request_id,
                    message="deliver_to requires deliver_token",
                )
                await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
                return

            # Validate deliver_token authorizes inbox access
            # Check if deliver_token is in content store and grants inbox access
            token_entity = self.content_store.get(deliver_token)
            if token_entity is None:
                logger.warning("[dispatch] deliver_token not found in content store")
                logger.debug("[dispatch] -> response status=400 code=invalid_request")
                response = ExecuteResponse.bad_request(
                    request_id=request_id,
                    message="deliver_token not found",
                )
                await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
                return

            # Check token authorizes inbox handler with receive operation
            token_data = token_entity.data
            inbox_path = deliver_to.uri
            from entity_core.utils.path import extract_handler_path
            inbox_path = extract_handler_path(inbox_path)

            if not check_handler_scope(token_data, "system/inbox", deliver_to.operation, self.peer_id):
                logger.warning("[dispatch] deliver_token doesn't authorize inbox handler")
                logger.debug("[dispatch] -> response status=403 code=capability_denied")
                msg = "deliver_token doesn't authorize inbox handler"
                marker_hash = self._bind_chain_rejected_marker(
                    bounds=bounds, request_id=request_id, message=msg,
                    requesting_peer_id=conn_state.session.remote_peer_id,
                    attempted_uri=path,
                )
                response = _forbidden_with_rejected_marker(
                    request_id, msg, marker_hash,
                )
                await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
                return

        # Step 2.5: Resolve and validate the handler's grant (V7 §6.2 +
        # spec-gap §S2 — granter must be local peer, signature must verify).
        # Missing or invalid grant → permission_denied (same fail-closed
        # treatment as §7.1).
        # Step 2.5: resolve + validate the handler's own grant (shared).
        authorized = self._authorize_handler_grant(handler_pattern)
        if isinstance(authorized, _DispatchDenied):
            logger.debug(
                "[dispatch] -> response status=403 code=capability_denied "
                "(handler grant missing or invalid)",
            )
            marker_hash = self._bind_chain_rejected_marker(
                bounds=bounds, request_id=request_id, message=authorized.message,
                requesting_peer_id=conn_state.session.remote_peer_id,
                attempted_uri=path,
            )
            response = _forbidden_with_rejected_marker(
                request_id, authorized.message, marker_hash,
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return
        handler_grant, handler_grant_hash = authorized

        # Step 3: Dispatch to handler (handler does path-level checks)
        # Extract chain_id/parent_chain_id from bounds for tracing
        chain_id = bounds.chain_id if bounds else None
        parent_chain_id = bounds.parent_chain_id if bounds else None

        # Create dispatcher closure for this request context.
        # Per V7 §6.8: when a handler dispatches a sub-request, the original
        # external caller's capability and identity propagate to the child
        # context. At this top-level entry point, the caller IS the external
        # caller — so we seed the dispatcher with the request's capability_data
        # and the verified remote peer identity.
        # V7 §3.3 v7.51: preserve the request envelope's `included` map and
        # make it available to the handler + its downstream sub-dispatches
        # (keyed by content_hash). A pure transform (deref_included) reads
        # this map, distinct from content-store ingestion.
        request_included = {
            ent["content_hash"]: ent
            for ent in envelope.included
            if isinstance(ent, dict) and "content_hash" in ent
        }
        # V7 §6.11(b) / GUIDE-CONFORMANCE §7a.2a: the inbound connection this
        # EXECUTE arrived on, available as the outbound channel if the handler
        # originates a reentry EXECUTE back to the caller (a peer that dialed
        # us and may have no listener). Built per-dispatch; cheap, no I/O.
        reentry_channel = ReentryChannel(
            remote_peer_id=conn_state.session.remote_peer_id,
            writer=writer,
            conn_state=conn_state,
            keypair=self.keypair,
            active_hash_format=conn_state.connect.active_hash_format,
        )
        execute_dispatcher = self._make_execute_dispatcher(
            capability_data,
            conn_state.session.remote_peer_id,
            conn_state.session.remote_identity_hash,
            request_included,
            reentry=reentry_channel,
        )

        ctx = HandlerContext(
            local_peer_id=self.peer_id,
            remote_peer_id=conn_state.session.remote_peer_id,
            handler_grant=handler_grant,
            caller_capability=capability_data,
            emit_pathway=self.emit_pathway,
            bounds=bounds,
            chain_id=chain_id,
            parent_chain_id=parent_chain_id,
            request_id=request_id,  # CONTINUATION v1.14: marker step_index source
            resource_targets=resource_targets,  # V7: pass to handler
            handler_pattern=handler_pattern,
            caller_capability_hash=capability_hash,
            caller_capability_granter_peer_id=granter_frame,  # V7 §PR-8
            remote_identity_hash=conn_state.session.remote_identity_hash,
            author_identity_hash=verified_author_hash,
            handler_grant_hash=handler_grant_hash,
            deliver_to=deliver_to,  # V7.8: pass to handler
            deliver_token=deliver_token,  # V7.8: pass to handler
            durability_policy=self.durability_policy,  # §10: advertise/reason
            # EXTENSION-NETWORK §6.7.1: the accept-side transport source. This
            # is the ONLY site that populates it — sub-dispatches built by
            # `_make_execute_dispatcher` and self-dispatch leave it None, so a
            # handler can never mistake an in-process call for an observation.
            observed_source_address=conn_state.observed_address,
            _execute_dispatcher=execute_dispatcher,
            keypair=self.keypair,
            included=request_included,
            relay_send=self._relay_deliver_inner,
        )

        # EXTENSION-DURABILITY §5 / §8: reconcile the durability request
        # (and any unsatisfiable deliver_to) BEFORE the handler runs. A
        # durability/deliver_to request is never silently discarded — it
        # is answered with a status + the pinned `durability` field.
        # 412 (refuse-at-acceptance) and 409 (duplicate) both refuse
        # before any handler runs — no run-then-fail, no double-execution.
        from entity_core.protocol.durability import (
            LEVEL_NONE,
            REASON_DUPLICATE_REQUEST_ID,
            REASON_NO_DURABLE_STORE,
            STATUS_CONFLICT,
            DurabilityRequest,
            DurabilityResult,
            reconcile_for_dispatch,
        )

        dr_data = data.get("durability_request")
        durability_request = (
            DurabilityRequest.from_dict(dr_data) if dr_data else None
        )
        # Precise check: an inbox handler registered at exactly
        # `system/inbox` — NOT a `system/*`/`*` catchall, which cannot
        # honor a delivered `receive`. Per EXTENSION-DURABILITY §6 the
        # inbox is *one example* of a durable store, not the canonical
        # store; this check is specifically for whether deliver_to can
        # be honored, not whether durability is possible.
        inbox_available = (
            deliver_to is None
            or self.handlers.find_exact("system/inbox") is not None
        )
        verdict = reconcile_for_dispatch(
            durability_request,
            self.durability_policy,
            async_completion=bool(deliver_to) and inbox_available,
            deliverable=inbox_available,
        )
        durability_field = verdict.result if verdict is not None else None

        # Sync durable case — the receiver-chosen preservation path. This
        # implementation places sync-durable entries under `system/inbox/`,
        # matching the Go reference; per §6 the receiver chooses the
        # layout and returns it as `handle`.
        durable_preserve_path: str | None = None
        if (
            verdict is not None
            and not verdict.refuse
            and deliver_to is None
            and durability_field is not None
            and durability_field.applied != LEVEL_NONE
        ):
            durable_preserve_path = f"system/inbox/{request_id}"

            # §5 row 8 / §8 MUST: a (author, request_id) pair that
            # matches a previously preserved entry → 409
            # duplicate_request_id. Operation NOT performed; the prior
            # entry stands. Uniqueness is enforced over the pair
            # regardless of storage layout; this impl checks the
            # preservation path it would have written to.
            existing_uri = self.emit_pathway.entity_tree.normalize_uri(
                durable_preserve_path
            )
            if self.emit_pathway.entity_tree.get(existing_uri) is not None:
                logger.debug(
                    "[dispatch] -> response status=409 duplicate_request_id"
                )
                conflict_durability = DurabilityResult(
                    requested=durability_field.requested,
                    applied=LEVEL_NONE,
                    reason=REASON_DUPLICATE_REQUEST_ID,
                )
                response = ExecuteResponse(
                    request_id=request_id,
                    status=STATUS_CONFLICT,
                    result={
                        "type": "system/protocol/error",
                        "data": {
                            "code": REASON_DUPLICATE_REQUEST_ID,
                            "message": (
                                f"(author, request_id={request_id}) already preserved"
                            ),
                        },
                    },
                    durability=conflict_durability,
                )
                await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
                return

            # §6: write-ahead preserve the originating EXECUTE so the
            # sender can find it via `handle`. If preservation fails,
            # downgrade `applied` to none with reason
            # ``no_durable_store`` rather than overclaim (§5 invariant:
            # `applied` MUST report only what is physically in place
            # at response time).
            try:
                preserve_entity = Entity(
                    type=execute_entity["type"],
                    data=execute_entity["data"],
                )
                self.emit_pathway.emit(
                    durable_preserve_path,
                    preserve_entity,
                    EmitContext.bootstrap(),
                )
                # §5 / §8 MUST: `handle` present when `applied != none`,
                # naming the sender's lookup address.
                durability_field = DurabilityResult(
                    requested=durability_field.requested,
                    applied=durability_field.applied,
                    committed=durability_field.committed,
                    max_available=durability_field.max_available,
                    handle=durable_preserve_path,
                    reason=durability_field.reason,
                )
            except Exception as exc:
                logger.warning(
                    "[dispatch] durability preserve failed for %s: %s",
                    request_id, exc,
                )
                durability_field = DurabilityResult(
                    requested=durability_field.requested,
                    applied=LEVEL_NONE,
                    reason=REASON_NO_DURABLE_STORE,
                )
                durable_preserve_path = None
        elif (
            verdict is not None
            and verdict.accepted_async
            and deliver_to is not None
        ):
            # §5 row 5 / §8: on 202, `handle` names where the committed
            # entry will land. The inbox handler stores delivered
            # results at `{deliver_to.uri}/{original_request_id}` —
            # see entity_handlers/inbox.py:_handle_receive.
            committed_handle = f"{deliver_to.uri.rstrip('/')}/{request_id}"
            durability_field = DurabilityResult(
                requested=durability_field.requested,
                applied=durability_field.applied,
                committed=durability_field.committed,
                max_available=durability_field.max_available,
                handle=committed_handle,
                reason=durability_field.reason,
            )

        def _honest(df: "DurabilityResult | None", status: int):
            """Never claim a durability not physically in place (§5 / §8
            invariant). A handler error / non-2xx means the synchronous
            store did not happen — downgrade an optimistic `applied` and
            drop the `handle` (no payload there to find)."""
            if df is None or df.applied == LEVEL_NONE or 200 <= status < 300:
                return df
            return DurabilityResult(
                requested=df.requested,
                applied=LEVEL_NONE,
                reason=df.reason or "operation_failed",
            )

        # §5 / §8: a *required* durability precondition that cannot be
        # met → the operation is NOT performed. Refused at acceptance,
        # before the handler runs (no run-then-fail / double-execution).
        if verdict is not None and verdict.refuse:
            logger.debug(
                "[dispatch] -> response status=412 (durability refused at acceptance)"
            )
            response = ExecuteResponse.precondition_failed(
                request_id=request_id, durability=durability_field,
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        # V7.8: Async delivery — return 202 immediately, process in
        # background. Only when an inbox handler can actually honor
        # deliver_to; otherwise fall through to a synchronous return so
        # the result stays observable (never the 202-then-silent-loss
        # class EXTENSION-DURABILITY §5 names).
        if deliver_to is not None and inbox_available:
            logger.debug("[dispatch] async delivery: returning 202, processing in background")
            response_202 = ExecuteResponse(
                request_id=request_id,
                status=202,
                result=None,
                durability=durability_field,
            )
            await self._send_locked(writer, conn_state, Envelope(root=response_202.to_entity()))

            # Launch async processing task
            asyncio.create_task(
                self._process_async_delivery(
                    handler, path, operation, params, ctx, request_id,
                )
            )
            return

        # Synchronous handler execution. Reached when: no deliver_to; OR
        # a deliver_to no inbox handler can honor (degrade to a sync
        # return + observable durability, never silent loss); OR a
        # replication-class "accepted" verdict (operation performed
        # locally; replication completes asynchronously & observably,
        # §5 / §6).
        try:
            result = await handler(path, operation, params, ctx)
            status = result.pop("status", 200)
            # A replication-class accepted verdict reports 202 (accepted;
            # completes asynchronously) over a 2xx handler status; it
            # never masks a handler error.
            if (
                verdict is not None
                and verdict.accepted_async
                and 200 <= status < 300
            ):
                status = 202
            # Log response with error details if present
            if status >= 400:
                error_info = result.get("error", result.get("result", {}).get("message", ""))
                logger.debug("[dispatch] -> response status=%d error=%s", status, error_info[:100] if error_info else "none")
            else:
                logger.debug("[dispatch] -> response status=%d", status)
            response = ExecuteResponse(
                request_id=request_id,
                status=status,
                result=result.get("result"),
                durability=_honest(durability_field, status),
            )
        except Exception as e:
            logger.exception("[dispatch] handler error: %s", e)
            logger.debug("[dispatch] -> response status=500 code=internal_error")
            response = ExecuteResponse.error(
                request_id=request_id,
                message=str(e),
            )
            response.durability = _honest(durability_field, 500)
            # On the exception path `result` was never assigned. Skip
            # the envelope-include drain (an error response has no
            # bundle); the wire envelope's `included` stays empty.
            result = None

        # V7 §3.3 wire shape: handlers MAY return a top-level
        # ``envelope_included`` field alongside ``result`` to push
        # entities into the outer wire envelope's ``included`` map —
        # the cross-impl convention the spec text uses for
        # multi-entity results (e.g. DOMAIN-LOCAL-FILES v1.2 §4.1's
        # ``ctx.include(blob_hash, blob)`` semantics, where the file
        # entity is ``result`` and the blob+chunks ride in the outer
        # envelope). Handlers without ``envelope_included`` keep
        # Python's prior "self-contained ``system/envelope`` packed
        # inside ``result``" shape — preserved across every internal
        # dispatch surface.
        wire_included_list = _collect_wire_included(result)
        await self._send_locked(
            writer,
            conn_state,
            Envelope(
                root=response.to_entity(),
                included=wire_included_list,
            ),
        )

    async def _process_async_delivery(
        self,
        handler: Any,
        path: str,
        operation: str,
        params: dict[str, Any],
        ctx: HandlerContext,
        request_id: str,
    ) -> None:
        """Process a handler asynchronously and deliver result to inbox.

        Called when an EXECUTE has deliver_to set. The 202 has already been
        sent on the wire. This runs the handler and delivers the result
        to the inbox via ctx.deliver_async().

        Args:
            handler: The handler to invoke.
            path: Handler path.
            operation: Operation name.
            params: Operation parameters.
            ctx: Handler context (contains deliver_to).
            request_id: Original request ID for correlation.
        """
        try:
            result = await handler(path, operation, params, ctx)
            status = result.pop("status", 200)
            logger.debug(
                "[dispatch:async] handler completed: status=%d request=%s",
                status, request_id[:16],
            )
        except Exception as e:
            logger.exception("[dispatch:async] handler error: %s", e)
            return

        # Deliver result to inbox
        try:
            delivery_result = await ctx.deliver_async(
                request_id, status, result.get("result"),
            )
            if not delivery_result.ok:
                logger.warning(
                    "[dispatch:async] inbox delivery failed: status=%d error=%s",
                    delivery_result.status, delivery_result.error,
                )
            else:
                logger.debug(
                    "[dispatch:async] delivered to inbox: request=%s",
                    request_id[:16],
                )
        except Exception as e:
            logger.exception("[dispatch:async] delivery error: %s", e)

    def _handle_get(
        self, request_id: str, path: str, params: dict[str, Any]
    ) -> ExecuteResponse:
        """Handle get operation - direct entity tree read.

        Args:
            request_id: Request ID for correlation.
            path: The path to get. Trailing slash returns tree listing.
            params: May contain 'hash' for direct content store lookup.

        Returns:
            ExecuteResponse with the entity or tree listing.
        """
        # Get by hash (direct content store lookup)
        if "hash" in params:
            entity = self.content_store.get(params["hash"])
            if entity is None:
                return ExecuteResponse.not_found(request_id, "Hash not found")
            return ExecuteResponse.success(request_id, entity.to_dict())

        # Trailing slash = tree listing
        if path.endswith("/"):
            return self._handle_tree_listing(request_id, path)

        # Get by URI (tree lookup)
        full_uri = self.entity_tree.normalize_uri(path)
        hash_str = self.entity_tree.get(full_uri)
        if hash_str is None:
            return ExecuteResponse.not_found(request_id, f"Not found: {path}")

        entity = self.content_store.get(hash_str)
        if entity is None:
            return ExecuteResponse.not_found(request_id, f"Entity missing: {hash_str}")

        return ExecuteResponse.success(request_id, entity.to_dict())

    def _handle_tree_listing(self, request_id: str, path: str) -> ExecuteResponse:
        """Handle tree listing for paths ending with /.

        Args:
            request_id: Request ID for correlation.
            path: The prefix path (ends with /).

        Returns:
            ExecuteResponse with tree/listing entity.
        """
        prefix = self.entity_tree.normalize_uri(path)
        uris = self.entity_tree.list_prefix(prefix)

        # Build entries: extract child names and their info
        entries: dict[str, dict[str, Any]] = {}
        seen_prefixes: set[str] = set()

        for uri in uris:
            # Get the part after the prefix
            suffix = uri[len(prefix) :]
            if not suffix:
                continue

            # Get immediate child name (first path segment)
            parts = suffix.split("/")
            child_name = parts[0]

            if child_name in seen_prefixes:
                continue
            seen_prefixes.add(child_name)

            # Check if this is a direct entity or a subtree
            child_uri = prefix + child_name
            hash_str = self.entity_tree.get(child_uri)
            has_children = len(parts) > 1 or any(
                u.startswith(child_uri + "/") for u in uris
            )

            entries[child_name] = {
                "hash": hash_str,
                "has_children": has_children,
            }

        result = {
            "type": "tree/listing",
            "data": {
                "path": path,
                "entries": entries,
                "count": len(entries),
            },
        }
        return ExecuteResponse.success(request_id, result)

    def _handle_put(
        self,
        request_id: str,
        path: str,
        params: dict[str, Any],
        remote_peer_id: str,
    ) -> ExecuteResponse:
        """Handle put operation - direct entity tree write.

        Args:
            request_id: Request ID for correlation.
            path: The path to put at.
            params: Must contain 'entity' with the entity to store.
            remote_peer_id: The peer making the request (for emit context).

        Returns:
            ExecuteResponse with the hash or error.
        """
        entity_data = params.get("entity")
        if not entity_data:
            return ExecuteResponse.bad_request(
                request_id=request_id,
                message="Missing entity in params",
                # §3.3's `invalid_params` — a required params field is absent,
                # which is what that code names. go answers it at the matching
                # seam (`execute.go`, "params entity missing type field").
                code="invalid_params",
            )

        entity = Entity.from_dict(entity_data)

        # Use emit pathway for writes (dispatches change events)
        ctx = EmitContext.protocol(author=remote_peer_id)
        full_uri = self.entity_tree.normalize_uri(path)
        hash_str = self.emit_pathway.emit(full_uri, entity, ctx).hash

        return ExecuteResponse.success(
            request_id,
            {"hash": hash_str, "uri": full_uri},
        )

    async def _dispatch_local_execute(
        self,
        uri: str,
        operation: str,
        params: dict[str, Any] | None,
        caller_capability: dict[str, Any],
        bounds: Bounds | None,
        chain_id: str | None,
        resource_targets: list[str] | None = None,
        *,
        propagated_caller_capability: dict[str, Any] | None = None,
        propagated_author_peer_id: str | None = None,
        propagated_author_identity_hash: bytes | None = None,
        dispatch_capability_entity: dict[str, Any] | None = None,
        dispatch_capability_chain: list[dict[str, Any]] | None = None,
        included: dict[bytes, dict[str, Any]] | None = None,
        reentry: "ReentryChannel | None" = None,
        reactive_trigger: bool = False,
    ) -> ExecuteResult:
        """Dispatch an internal execute request to handlers.

        This is used by ctx.execute() for handler-to-handler calls.
        Routes to remote peers when the URI targets a different peer,
        otherwise dispatches locally through the handler registry.

        Authority note: `caller_capability` is the AUTHORITY this dispatch is
        checked against (the calling handler's own grant, ctx.handler_grant).
        It is distinct from the `target_handler_grant` resolved below — the
        authority the *target* handler runs with (V7 §6.2). The two are
        opposite sides of the authorization and must not be conflated. The
        `propagated_*` values are attribution-only (V7 §6.8) and MUST NOT gate
        this dispatch — they seed the child context's identity for history,
        not the handler-scope/resource-scope decision.

        Args:
            uri: Target URI.
            operation: Operation to perform.
            params: Operation parameters.
            caller_capability: The calling handler's authority — checked
                against the resolved handler scope.
            bounds: Resource bounds.
            chain_id: Chain ID for tracing.
            resource_targets: Resource paths for the target handler.

        Returns:
            ExecuteResult with status and result/error.
        """
        # Route remote URIs through outbound connection pool
        if self._is_remote_uri(uri):
            logger.debug("[dispatch:remote] uri=%s op=%s", uri, operation)
            return await self._remote_execute(
                uri, operation, params, resource_targets,
                dispatch_capability_entity=dispatch_capability_entity,
                dispatch_capability_chain=dispatch_capability_chain,
                # PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION Delta 1: a continuation
                # advancement's cross-peer EXECUTE MUST carry system/bounds so
                # chain_depth is inherited (and the global count is tested, not a
                # per-peer one). Gated on chain_depth presence in _remote_execute
                # so ordinary remote dispatch stays byte-identical (no bounds
                # invented — Go's TestOrdinaryRemoteDispatchAddsNoBounds).
                bounds=bounds,
                # V7 §3.3 v7.51: forward the request envelope's included to the
                # remote peer — MUST NOT drop it before the wire.
                included=included,
                # V7 §6.11(b): the inbound connection this dispatch descends
                # from, used as the outbound channel when the target is the
                # caller and has no dialable route.
                reentry=reentry,
            )

        # Extract handler-relative path from URI or absolute path
        from entity_core.capability.checking import extract_peer
        from entity_core.utils.path import extract_handler_path
        # §5.2 peers: read the target peer before the peer segment is stripped
        # (see handle_execute). An in-process caller reaching a foreign
        # namespace is the same escalation as a wire one.
        target_peer = extract_peer(uri, self.peer_id)
        path = extract_handler_path(uri)

        logger.debug("[dispatch:internal] uri=%s op=%s params=[%s]",
                    uri, operation, ", ".join(list((params or {}).keys())[:5]))

        # Steps 1-2: resolve handler (V7 §6.6) + handler-scope check (shared).
        resolved = self._resolve_for_dispatch(
            path, operation, caller_capability, target_peer=target_peer,
        )
        if isinstance(resolved, _DispatchDenied):
            logger.debug(
                "[dispatch:internal] -> status=%d %s",
                resolved.status, resolved.message,
            )
            return ExecuteResult(status=resolved.status, error=resolved.message)

        handler = resolved.handler
        handler_pattern = resolved.pattern
        logger.debug("[dispatch:internal] handler matched: pattern=%s name=%s", handler_pattern, resolved.name)

        # Step 2.2: §5.2 resource dimension. The wire path has run this since
        # V7; this path accepted `resource_targets`, forwarded them into the
        # child context, and consulted `grant.resources` nowhere — so on an
        # internal sub-dispatch the check §5.2 calls *primary* was absent and
        # the only thing left was the handler's own optional secondary check,
        # which 7 of 76 handler modules implement. `system/handler:register` is
        # the sharp end: §6.2 assigns the authorization of the install path to
        # this check and the handler performs none, so a sub-dispatch could
        # install a handler at any pattern its own grant did not name.
        if resource_targets:
            from entity_core.capability.checking import (
                check_resource_scope,
                granter_frame_peer_id,
            )

            if not check_resource_scope(
                caller_capability, handler_pattern, operation, resource_targets,
                None, self.peer_id,
                granter_peer_id=granter_frame_peer_id(
                    caller_capability, self.peer_id, self._resolve_identity_entity,
                ),
                target_peer=target_peer,
            ):
                msg = (
                    f"Capability doesn't grant {operation} on resource targets"
                )
                logger.warning(
                    "[dispatch:internal] resource scope denied: targets=%s",
                    resource_targets,
                )
                return ExecuteResult(status=403, error=msg)

        # Step 2.5: resolve + validate the target handler's grant (shared).
        authorized = self._authorize_handler_grant(handler_pattern)
        if isinstance(authorized, _DispatchDenied):
            logger.debug(
                "[dispatch:internal] -> status=403 handler grant missing/invalid "
                "for %s",
                handler_pattern,
            )
            return ExecuteResult(status=authorized.status, error=authorized.message)
        target_handler_grant, target_handler_grant_hash = authorized

        # Check and decrement bounds
        if bounds is not None:
            bounds = bounds.copy()  # Don't mutate caller's bounds
            if bounds.ttl_exhausted:
                return ExecuteResult(status=400, error=TTL_EXHAUSTED_MESSAGE)
            if bounds.budget_exhausted:
                return ExecuteResult(status=400, error=BUDGET_EXHAUSTED_MESSAGE)
            bounds.decrement_ttl()

        # Compute local peer identity hash for internal dispatch author tracking
        local_identity_hash: bytes | None = None
        if self.keypair:
            # V7 v7.65 §2: system/peer data = (public_key, key_type) only
            # §4.5a item 1a: floor-pinned via the one constructor.
            from entity_core.protocol.auth import create_identity_entity

            local_identity_hash = create_identity_entity(self.keypair).compute_hash()

        # V7 §6.8 context propagation. When the caller passed propagated_*
        # values, the sub-handler sees the original external caller's
        # capability and identity. Otherwise we fall back to the legacy
        # behavior (calling handler's grant as caller_capability, local peer
        # as author).
        effective_caller_capability = (
            propagated_caller_capability
            if propagated_caller_capability is not None
            else caller_capability
        )
        effective_author_peer_id = (
            propagated_author_peer_id
            if propagated_author_peer_id is not None
            else self.peer_id
        )
        effective_author_identity_hash = (
            propagated_author_identity_hash
            if propagated_author_identity_hash is not None
            else local_identity_hash
        )

        # Compute caller capability hash for history recording (W6)
        caller_cap_hash: bytes | None = None
        caller_cap_granter_frame: str | None = None
        if effective_caller_capability:
            from entity_core.protocol.entity import Entity as _Entity
            caller_cap_entity = _Entity(
                type="system/capability/token", data=effective_caller_capability,
            )
            caller_cap_hash = caller_cap_entity.compute_hash()
            # V7 §PR-8: resolve the caller cap's granter frame for the
            # handler-level path check (propagated unchanged across surfaces).
            from entity_core.capability.checking import granter_frame_peer_id
            caller_cap_granter_frame = granter_frame_peer_id(
                effective_caller_capability, self.peer_id, self._resolve_identity_entity
            )

        # Nested dispatch propagates the effective author + caller cap unchanged.
        # V7 §3.3 v7.51: the request envelope's included reaches this handler
        # and propagates to its sub-dispatches (so a downstream continuation's
        # deref_included resolves a bundled entity from the map).
        sub_included = included or {}
        execute_dispatcher = self._make_execute_dispatcher(
            effective_caller_capability,
            effective_author_peer_id,
            effective_author_identity_hash,
            sub_included,
            reentry=reentry,
        )

        # Create context for handler with its own grant
        ctx = HandlerContext(
            local_peer_id=self.peer_id,
            remote_peer_id=effective_author_peer_id,
            handler_grant=target_handler_grant,
            caller_capability=effective_caller_capability,
            emit_pathway=self.emit_pathway,
            bounds=bounds,
            chain_id=chain_id,
            parent_chain_id=bounds.parent_chain_id if bounds else None,
            resource_targets=resource_targets,
            handler_pattern=handler_pattern,
            # STANDING-MODEL §3: the explicit reactive-trigger marker, sourced
            # per-dispatch from the caller (the inbox/subscription delivery
            # route sets it True on the advance it initiates). NOT inherited —
            # a fresh child context is built per sub-dispatch and defaults
            # False, so the marker tags only the one advance the delivery
            # mechanism initiated, never the continuation's onward dispatches.
            reactive_trigger=reactive_trigger,
            caller_capability_hash=caller_cap_hash,
            caller_capability_granter_peer_id=caller_cap_granter_frame,  # V7 §PR-8
            remote_identity_hash=effective_author_identity_hash,
            author_identity_hash=effective_author_identity_hash,
            handler_grant_hash=target_handler_grant_hash,
            _execute_dispatcher=execute_dispatcher,
            keypair=self.keypair,
            included=sub_included,
            relay_send=self._relay_deliver_inner,
        )

        try:
            result = await handler(path, operation, params or {}, ctx)
            status = result.pop("status", 200)
            if status >= 400:
                error_info = result.get("error", "")
                logger.debug("[dispatch:internal] -> status=%d error=%s", status, error_info[:100] if error_info else "none")
            else:
                logger.debug("[dispatch:internal] -> status=%d", status)
            # The result is carried unchanged across every dispatch surface
            # (V7 §3.3). A multi-entity result is a system/envelope whose own
            # data.included holds the bundle, so it rides inside `result` —
            # no out-of-band channel needed for surface-equivalence.
            # v3.6 F4-cycle: thread envelope_included through internal
            # dispatch so in-process consumers (compute expressions,
            # continuations) can resolve hash refs the result body
            # points at — same shape the wire path receives via the
            # outer envelope drain.
            return ExecuteResult(
                status=status,
                result=result.get("result"),
                envelope_included=result.get("envelope_included"),
                error=result.get("error"),
            )
        except Exception as e:
            logger.exception("[dispatch:internal] handler error: %s", e)
            return ExecuteResult(
                status=500,
                error=str(e),
            )
