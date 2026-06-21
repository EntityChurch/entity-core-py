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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from entity_core.capability.grant import (
    Grant,
    create_connect_grants,
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
    ConnectError,
    ConnectState,
    handle_connect_hello,
    handle_connect_authenticate,
    _grants_fingerprint,
)
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.handlers.registry import HandlerRegistry
from entity_core.peer.session import Session
from entity_core.peer.session_entity import (
    read_minted_capability,
    write_session,
)
from entity_core.protocol.bounds import Bounds
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
    identity_entity = Entity(
        type="system/peer",
        data={
            "public_key": pkey,
            "key_type": key_type,
        },
    )
    return identity_entity.compute_hash()


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
        included: list[dict[str, Any]] | None = None,
    ) -> ExecuteResponse:
        """Send one authenticated EXECUTE over the inbound wire; await reply.

        ``capability`` authorizes the EXECUTE (its grantee is this peer —
        the caller minted it for us); ``capability_chain`` (granter identity,
        cap signature) is bundled into the envelope ``included`` so the
        caller's verifier can resolve it. The reentry direction has no
        connection cap of its own — we never dialed the caller — so a
        capability MUST be supplied explicitly.
        """
        if capability is None:
            raise RuntimeError(
                "reentry EXECUTE requires an explicit capability — there is "
                "no connection cap on the inbound (accepted) direction"
            )

        from entity_core.protocol.auth import create_authenticated_request
        from entity_core.protocol.messages import ResourceTarget

        resource_target = (
            ResourceTarget.from_dict({"targets": resource_targets})
            if resource_targets else None
        )
        execute = Execute.create(uri, operation, params, resource=resource_target)
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
        )

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
            ) -> ExecuteResult:
                """Execute a request from an extension using system grant.

                Extensions use a full-access grant for internal operations
                like notification delivery. ``included`` carries request-side
                envelope entities (V7 §3.3 v7.51) — e.g. the subscription
                engine bundling an ``include_payload`` entity so the
                subscriber's continuation can ``deref_included`` it.
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
                )

            for ext_config in state.extensions:
                ctx = ExtensionContext(
                    keypair=peer.keypair,
                    max_scope=ext_config.max_scope,
                    emit_pathway=peer.emit_pathway,
                    execute=extension_execute,
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
                # Default: handler can access any handler and resource.
                # This allows handlers to dispatch to other handlers internally
                # (e.g., continuation handler resuming requests to any target).
                grants = create_full_access_grant()

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

    def publish_root(self) -> Entity:
        """Mint + bind a signed ``system/peer/published-root`` (Phase P / C1).

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
        ctx = EmitContext.bootstrap()
        self.emit_pathway.emit("system/peer/published-root", pr_entity, ctx)
        self.emit_pathway.emit(
            published_root_signature_path(pr_entity.compute_hash()),
            sig_entity,
            ctx,
        )
        return pr_entity

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
            request_id = data.get("request_id", "")
            response = ExecuteResponse.forbidden(
                request_id=request_id,
                message="Connect required before sending requests",
            )
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
            if reentry is not None and peer_id == reentry.remote_peer_id:
                logger.debug(
                    "[dispatch:reentry] no outbound route to %s; "
                    "originating over inbound connection", peer_id[:16],
                )
                try:
                    response = await reentry.execute(
                        uri, operation, params,
                        capability=dispatch_capability_entity,
                        capability_chain=dispatch_capability_chain,
                        resource_targets=resource_targets,
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
                # V7 §3.3 v7.51: forward the request envelope's included to the
                # wire — a dispatcher routing locally-originated entities to a
                # remote peer MUST NOT drop them.
                included=list(included.values()) if included else None,
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
        except Exception as e:
            self._remote_pool.remove_connection(peer_id)
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
            self._remote_pool.remove_connection(destination)
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
            await self._server.wait_closed()

        # Cancel all connection handlers
        for task in self._connections:
            task.cancel()
        if self._connections:
            await asyncio.gather(*self._connections, return_exceptions=True)
        self._connections.clear()

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
                        elif not conn_state.is_connected:
                            # Not connected yet - reject (inline; nothing
                            # in flight, write is safe without the lock
                            # because the loop hasn't spawned yet).
                            request_id = data.get("request_id", "")
                            response = ExecuteResponse.forbidden(
                                request_id=request_id,
                                message="Connect required before sending requests",
                            )
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

        if conn_state.connect.is_complete:
            response = ExecuteResponse.conflict(
                request_id=request_id,
                message="Connect already complete",
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
                # Determine grants based on peer identity
                grants = self._get_grants_for_peer(
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
                        # Reconstruct granter identity + cap signature under the
                        # cap's (== active) format so they match the cached cap.
                        granter_id_c = create_identity_entity(
                            self.keypair, algorithm=active_format,
                        )
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

                logger.info(
                    f"Connect complete with {conn_state.session.remote_peer_id[:8]}..."
                )

            else:
                response = ExecuteResponse.bad_request(
                    request_id=request_id,
                    message=f"Unknown connect operation: {operation}",
                )
                await send_envelope(
                    writer, Envelope(root=response.to_entity())
                )

        except ConnectError as e:
            logger.warning(f"Connect error: {e}")
            # V7 §4.7 — emit the canonical wire code (e.g.
            # "unsupported_key_type" for v7.66 §4.4 surface 6) rather
            # than collapsing every connect failure to "bad_request".
            response = ExecuteResponse.bad_request(
                request_id=request_id,
                message=str(e),
                code=getattr(e, "code", "bad_request"),
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))

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
    ) -> "RegisteredHandler | _DispatchDenied":
        """Resolve the handler for `path` (V7 §6.6) and check that
        `caller_capability` permits `operation` on the matched handler scope.

        Returns the resolved handler, or a `_DispatchDenied` (404 no handler,
        403 handler scope).
        """
        from entity_core.capability.checking import check_handler_scope

        registered = self._resolve_handler(path)
        if registered is None:
            return _DispatchDenied(404, f"No handler for path: {path}")

        if not check_handler_scope(
            caller_capability, registered.pattern, operation, self.peer_id
        ):
            return _DispatchDenied(
                403,
                f"Capability doesn't allow {operation} on handler "
                f"{registered.pattern}/",
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
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        # Extract handler-relative path for dispatch
        path = extract_handler_path(canonical_path)

        # Reject connect path after connect is complete
        if path == CONNECT_URI:
            response = ExecuteResponse.conflict(
                request_id=request_id,
                message="Connect already complete",
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
            logger.debug("[dispatch] bounds: ttl=%s budget=%s chain=%s",
                        bounds.ttl, bounds.budget, bounds.chain_id[:12] if bounds.chain_id else "none")
            # Cross-peer cascade tracking (SYSTEM-COMPOSITION §3.4)
            if bounds.chain_id and bounds.cascade_depth is not None:
                self.emit_pathway.track_chain_depth(bounds.chain_id, bounds.cascade_depth)

        # Pre-dispatch check: reject if bounds exhausted
        if bounds.ttl_exhausted:
            response = ExecuteResponse.bad_request(
                request_id=request_id,
                message="TTL exhausted",
            )
            await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
            return

        if bounds.budget_exhausted:
            response = ExecuteResponse.bad_request(
                request_id=request_id,
                message="Budget exhausted",
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
        resolved = self._resolve_for_dispatch(path, operation, capability_data)
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
                        )
                        await self._send_locked(writer, conn_state, Envelope(root=response.to_entity()))
                        return

            # V7 §5.2: Dispatch-level resource check when resource is present
            # The same grant must match handler, operation, AND resource
            if resource_targets:
                if not check_resource_scope(
                    capability_data, handler_pattern, operation, resource_targets,
                    resource_exclude, self.peer_id, granter_peer_id=granter_frame
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
                logger.debug("[dispatch] -> response status=400 code=missing_deliver_token")
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
                logger.debug("[dispatch] -> response status=400 code=invalid_deliver_token")
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
                # V7 §3.3 v7.51: forward the request envelope's included to the
                # remote peer — MUST NOT drop it before the wire.
                included=included,
                # V7 §6.11(b): the inbound connection this dispatch descends
                # from, used as the outbound channel when the target is the
                # caller and has no dialable route.
                reentry=reentry,
            )

        # Extract handler-relative path from URI or absolute path
        from entity_core.utils.path import extract_handler_path
        path = extract_handler_path(uri)

        logger.debug("[dispatch:internal] uri=%s op=%s params=[%s]",
                    uri, operation, ", ".join(list((params or {}).keys())[:5]))

        # Steps 1-2: resolve handler (V7 §6.6) + handler-scope check (shared).
        resolved = self._resolve_for_dispatch(path, operation, caller_capability)
        if isinstance(resolved, _DispatchDenied):
            logger.debug(
                "[dispatch:internal] -> status=%d %s",
                resolved.status, resolved.message,
            )
            return ExecuteResult(status=resolved.status, error=resolved.message)

        handler = resolved.handler
        handler_pattern = resolved.pattern
        logger.debug("[dispatch:internal] handler matched: pattern=%s name=%s", handler_pattern, resolved.name)

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
                return ExecuteResult(status=400, error="TTL exhausted")
            if bounds.budget_exhausted:
                return ExecuteResult(status=400, error="Budget exhausted")
            bounds.decrement_ttl()

        # Compute local peer identity hash for internal dispatch author tracking
        local_identity_hash: bytes | None = None
        if self.keypair:
            from entity_core.protocol.entity import Entity as _Entity
            # V7 v7.65 §2: system/peer data = (public_key, key_type) only
            local_identity = _Entity(
                type="system/peer",
                data={
                    "public_key": self.keypair.public_key_bytes(),
                    "key_type": self.keypair.key_type,
                },
            )
            local_identity_hash = local_identity.compute_hash()

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
