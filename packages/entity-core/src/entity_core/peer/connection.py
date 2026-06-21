"""Connection wrapper with EXECUTE-based connect handshake.

Uses EXECUTE messages with target-matching for signatures.
The Connection.connect() API remains the same - it returns a ready-to-use Connection.

Class G / F-WB28 — Transport-level multiplexing.

The post-handshake :meth:`Connection.execute` path multiplexes concurrent
callers over one wire by demultiplexing inbound ``EXECUTE_RESPONSE`` frames
on ``request_id`` into per-request ``asyncio.Future`` slots. Pre-fix shape
(``send`` then ``recv`` with no lock) had undefined behavior under
concurrent callers: bytes-write races (frame corruption) AND recv races
(responses delivered to the wrong caller's await). Same Class G root cause
that core-go fixed in ``6ebdd78`` Option A; different failure mode (Go
deadlocked on a per-connection mutex held across send+recv; Python had
no mutex at all and races opaquely).

Mechanism:

* A background reader task per :class:`Connection` reads frames and
  dispatches each ``EXECUTE_RESPONSE`` by ``request_id`` into the matching
  pending ``Future``. Unsolicited frames are logged and dropped (Python's
  outbound :class:`Connection` is not currently a target for inbound
  ``EXECUTE``; server-side framing lives in :meth:`Peer._handle_connection`).
* :meth:`execute` registers a ``Future`` keyed by ``request_id`` *before*
  sending the wire bytes, acquires the per-connection write lock so frame
  bytes don't interleave under concurrent writers, releases the lock, and
  awaits the ``Future`` with a per-request deadline (independent of any
  other inflight request on the same connection — no shared
  ``net.Conn.SetDeadline``-style cross-talk).
* :meth:`close` cancels the reader and fails every pending ``Future`` so
  callers don't hang on a closed connection.

The handshake itself stays serial (uses ``recv_envelope(reader)`` directly,
not the reader task); the reader is started at the end of :meth:`connect`
once handshake-time recv() calls are done.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from entity_core.crypto.identity import Keypair
from entity_core.handlers.connect import (
    ConnectError,
    create_connect_hello_execute,
    create_connect_authenticate_execute,
    verify_connect_authenticate_response,
)
from entity_core.peer.session import Session
from entity_core.protocol.auth import create_authenticated_request
from entity_core.protocol.envelope import Envelope
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    default_advertised_hash_formats,
    negotiate_active_hash_format,
)
from entity_core.protocol.framing import (
    recv_envelope,
    send_envelope,
    send_raw_frame,
)
from entity_core.protocol.messages import Execute, ExecuteResponse

logger = logging.getLogger(__name__)


# Default per-request deadline. Chosen to exceed the 15s connection-level
# i/o timeout that Class G's failure mode previously surfaced as, so a
# legitimately-slow handler doesn't false-positive as a timeout while a
# truly-stuck connection still surfaces within a bounded window.
DEFAULT_REQUEST_TIMEOUT_SECONDS: float = 60.0


@dataclass
class Connection:
    """Wrapper around an authenticated connection.

    Attributes:
        reader: AsyncIO stream reader.
        writer: AsyncIO stream writer.
        session: The authenticated session info.
        keypair: This peer's keypair (for signing requests).
        capability: Capability dict granted by the remote peer (preserves content_hash).
        capability_chain: All supporting entities for the capability (signature, granter identity).
    """

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    session: Session
    keypair: Keypair
    capability: dict[str, Any] | None = None
    capability_chain: list[dict[str, Any]] | None = None
    # V7 v7.69 §4.5a — the connection's negotiated active content_hash_format.
    # Every authenticated request on this connection is authored under it so
    # ``execute.author`` matches the cap grantee issued during the handshake.
    # Defaults to SHA-256 (§4.5 floor); `connect` overwrites it after hello.
    active_hash_format: int = ALG_ECFV1_SHA256
    # Class G / F-WB28 multiplexing state. Created lazily on first send
    # (must be inside the running event loop). Initialized by
    # :meth:`_ensure_reader_started`, which is called at the tail of
    # :meth:`connect` after the handshake-time recv() calls complete.
    _pending: dict[str, asyncio.Future[Envelope]] = field(default_factory=dict)
    _reader_task: asyncio.Task[None] | None = None
    _write_lock: asyncio.Lock | None = None
    _closed: bool = False  # signature, granter identity, etc.

    async def send(self, envelope: Envelope) -> None:
        """Send an envelope.

        Args:
            envelope: The envelope to send.
        """
        await send_envelope(self.writer, envelope)

    async def send_raw_frame(self, payload: bytes) -> None:
        """Write pre-encoded envelope bytes verbatim as one length-prefixed
        frame (EXTENSION-RELAY §3.1.1 / §10.4 terminal-hop raw-frame delivery).

        No decode, re-encode, or re-sign — the relay forwards the source's
        original inner-envelope bytes unchanged so the destination verifies the
        source's signature + capability chain exactly as on a direct connection
        (§9). Takes the per-connection write lock so the bytes don't interleave
        with concurrent :meth:`execute` writers on the same wire.
        """
        if self._write_lock is not None:
            async with self._write_lock:
                await send_raw_frame(self.writer, payload)
        else:
            await send_raw_frame(self.writer, payload)

    async def recv(self) -> Envelope:
        """Receive an envelope.

        Returns:
            The received envelope.
        """
        return await recv_envelope(self.reader)

    async def execute(
        self,
        uri: str,
        operation: str,
        params: dict[str, Any] | None = None,
        authenticated: bool = True,
        resource: dict[str, Any] | None = None,
        deliver_to: dict[str, Any] | None = None,
        deliver_token_entity: dict[str, Any] | None = None,
        deliver_token_chain: list[dict[str, Any]] | None = None,
        capability_override: dict[str, Any] | None = None,
        capability_chain_override: list[dict[str, Any]] | None = None,
        durability_request: dict[str, Any] | None = None,
        included: list[dict[str, Any]] | None = None,
    ) -> ExecuteResponse:
        """Send an EXECUTE request and wait for response.

        Args:
            uri: Target URI.
            operation: Operation to perform.
            params: Operation parameters.
            authenticated: Whether to send authenticated request.
            resource: Resource targets dict ({"targets": [...]}).
            deliver_to: Delivery spec dict ({"uri": ..., "operation": ...}).
            deliver_token_entity: Capability token entity for inbox delivery.
            deliver_token_chain: Chain entities for the deliver token.
            durability_request: Optional EXTENSION-DURABILITY §2 marker
                dict ({"level": ..., "must_have": bool}). Additive; unset
                = prior behavior unchanged. The extension is exploratory
                and optional; peers that don't install it are unaffected.
            capability_override: When set, the EXECUTE is authorized by THIS
                capability entity instead of the connection (session) cap —
                signed with our keypair so the EXECUTE author is this peer.
                This is the EXTENSION-CONTINUATION §4.2 case 3 cross-peer
                dispatch path: the scoped, B-rooted `dispatch_capability`
                whose grantee is this (the dispatching host) peer. NOT a
                silent fallback to the broad connection cap (V7 §6.8).
            capability_chain_override: The full authority chain for
                `capability_override` (leaf → B-recognized root: caps +
                granter identities + bound signatures, from
                collect_chain_bundle) — bundled into the dispatched
                envelope's `included` per §4.3. Ignored unless
                `capability_override` is set.

        Returns:
            The ExecuteResponse.

        Raises:
            RuntimeError: If no capability available for authenticated request.
        """
        from entity_core.protocol.messages import ResourceTarget

        # Build Execute with optional fields
        resource_target = ResourceTarget.from_dict(resource) if resource else None

        deliver_to_spec = None
        deliver_token_hash = None
        if deliver_to:
            from entity_core.protocol.delivery import DeliverySpec
            deliver_to_spec = DeliverySpec.from_dict(deliver_to)
            if deliver_token_entity:
                deliver_token_hash = deliver_token_entity.get("content_hash")

        durability_request_obj = None
        if durability_request:
            from entity_core.protocol.durability import DurabilityRequest
            durability_request_obj = DurabilityRequest.from_dict(durability_request)

        execute = Execute.create(
            uri, operation, params,
            resource=resource_target,
            deliver_to=deliver_to_spec,
            deliver_token=deliver_token_hash,
            durability_request=durability_request_obj,
        )

        if authenticated:
            # §4.2 case 3: a continuation cross-peer dispatch authorizes the
            # EXECUTE with its scoped dispatch_capability (override), NOT the
            # connection cap. Signed with our keypair either way, so the
            # EXECUTE author is this peer — which is exactly the grantee the
            # minted dispatch_capability requires (v1.11 §4.2 case 3 (iii)).
            if capability_override is not None:
                wire_capability = capability_override
                wire_capability_chain = capability_chain_override
            else:
                wire_capability = self.capability
                wire_capability_chain = self.capability_chain
            if wire_capability is None:
                raise RuntimeError("No capability available for authenticated request")
            # Include capability chain (signature, granter identity)
            auth_request = create_authenticated_request(
                self.keypair,
                execute,
                wire_capability,
                wire_capability_chain,
                algorithm=self.active_hash_format,
            )
            envelope = auth_request.to_envelope()

            # Include deliver token and its chain in the envelope
            if deliver_token_entity:
                envelope.included.append(deliver_token_entity)
            if deliver_token_chain:
                for chain_ent in deliver_token_chain:
                    envelope.included.append(chain_ent)
            # V7 §3.3 v7.51: forward the request envelope's included entities
            # (e.g. an include_payload-bundled entity) so they survive to the
            # remote handler + its continuations.
            if included:
                envelope.included.extend(included)

            wire_envelope = envelope
        else:
            wire_envelope = Envelope(root=execute.to_entity())
            if included:
                wire_envelope.included.extend(included)

        # Class G / F-WB28: register the pending Future BEFORE sending, so a
        # racing-fast remote can't deliver the response between send() and
        # the future registration. Demux by request_id; serialize only the
        # wire bytes write, not the await on the response.
        self._ensure_reader_started()
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Envelope] = loop.create_future()
        request_id = execute.request_id
        if request_id in self._pending:
            # Hash collision on request_id (UUID4 — astronomically unlikely)
            # or a caller reusing an in-flight ID. Surface explicitly rather
            # than silently overwriting the prior caller's future.
            raise RuntimeError(
                f"F-WB28: duplicate request_id {request_id!r} on this "
                f"Connection — refusing to clobber pending Future"
            )
        self._pending[request_id] = future

        try:
            # Per-connection write serialization so frame bytes from
            # concurrent callers don't interleave. The lock guards the
            # writer only (the read side is serial-by-construction via the
            # single reader task — there is no other reader to contend
            # with). Mirrors V7 v7.48 §4.8 (A.2) discipline on the
            # server-side write lock in PeerConnectionState.
            assert self._write_lock is not None
            async with self._write_lock:
                if self._closed:
                    raise ConnectionError("Connection is closed")
                await self.send(wire_envelope)

            response_env = await asyncio.wait_for(
                future, timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
            )
        except (asyncio.TimeoutError, asyncio.CancelledError):
            # Pop the pending entry so a late-arriving response is logged
            # as unmatched rather than silently fulfilling a cancelled
            # caller's future.
            self._pending.pop(request_id, None)
            raise
        except Exception:
            self._pending.pop(request_id, None)
            raise

        response = ExecuteResponse.from_entity(response_env.root)
        # v3.6 F4-cycle: surface the wire envelope's `included` map on
        # the response object so consumers (validate-peer, wire-level
        # tests) can read the bundle the handler delivered via the
        # envelope_included hoist. Mirrors ExecuteResult.envelope_included
        # on the in-process dispatch side; the receiver convention is
        # uniform across in-process and wire paths.
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

    # ---------------------------------------------------------------------
    # Class G / F-WB28 — reader task + Future demux
    # ---------------------------------------------------------------------

    def _ensure_reader_started(self) -> None:
        """Start the demuxer reader task. Idempotent.

        Called at the tail of :meth:`connect` (so it runs after the inline
        handshake recv()s) and again from :meth:`execute` as a defensive
        no-op for the back-compat case where a caller constructed a
        :class:`Connection` directly without going through :meth:`connect`.
        """
        if self._reader_task is not None:
            return
        if self._closed:
            raise ConnectionError("Connection is closed")
        self._write_lock = asyncio.Lock()
        self._reader_task = asyncio.create_task(
            self._reader_loop(),
            name=f"connection-reader-{id(self):x}",
        )

    async def _reader_loop(self) -> None:
        """Read frames; demux ``EXECUTE_RESPONSE`` by request_id.

        On clean EOF, cancel, or read error: fail every pending Future
        with a :class:`ConnectionError` so awaiters wake up immediately
        rather than waiting for their own per-request deadlines.
        """
        try:
            while True:
                env = await recv_envelope(self.reader)
                msg_type = env.root.get("type", "")
                if msg_type != ExecuteResponse.TYPE:
                    # Python's outbound :class:`Connection` only expects
                    # EXECUTE_RESPONSE frames; an inbound EXECUTE would be
                    # an unexpected server-push pattern this side doesn't
                    # implement today. Log and drop (rather than crash the
                    # reader and orphan every pending caller).
                    logger.warning(
                        "F-WB28: unexpected frame type %r on outbound "
                        "connection; discarding",
                        msg_type,
                    )
                    continue
                rid = env.root.get("data", {}).get("request_id", "")
                fut = self._pending.pop(rid, None)
                if fut is None:
                    # Unmatched response — caller may have timed out and
                    # cleaned up its pending entry, or the request_id is
                    # corrupted. Log; don't crash.
                    logger.warning(
                        "F-WB28: unmatched EXECUTE_RESPONSE request_id=%r "
                        "(no pending caller; likely timed out)", rid,
                    )
                    continue
                if not fut.done():
                    fut.set_result(env)
        except (asyncio.IncompleteReadError, asyncio.CancelledError):
            # Clean EOF or explicit cancel — both are normal shutdown.
            pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("F-WB28: reader loop error: %s", exc)
        finally:
            # Wake every pending caller so they don't hang on a closed
            # connection. Use ConnectionError so the failure mode is
            # uniform across "remote disconnected" and "we closed".
            for rid, fut in list(self._pending.items()):
                if not fut.done():
                    fut.set_exception(
                        ConnectionError(
                            "F-WB28: connection reader closed before "
                            f"response for request_id={rid!r}"
                        )
                    )
            self._pending.clear()

    def close(self) -> None:
        """Close the connection.

        Cancels the demuxer reader task (its ``finally`` block fails any
        pending Futures with :class:`ConnectionError`) and closes the
        underlying writer. Safe to call multiple times.
        """
        if self._closed:
            return
        self._closed = True
        if self._reader_task is not None and not self._reader_task.done():
            self._reader_task.cancel()
        self.writer.close()

    async def wait_closed(self) -> None:
        """Wait for the connection to fully close."""
        await self.writer.wait_closed()
        if self._reader_task is not None:
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                # Reader exit is best-effort drain; any leftover exception
                # has already been logged inside the reader loop's finally.
                pass

    async def aclose(self) -> None:
        """RemoteEndpoint protocol: close + wait. Used by RemoteConnectionPool."""
        self.close()
        await self.wait_closed()

    @property
    def is_closed(self) -> bool:
        """RemoteEndpoint protocol: has close() been called."""
        return self._closed

    @property
    def remote_peer_id(self) -> str:
        """RemoteEndpoint protocol: the peer this connection authenticated against."""
        return self.session.remote_peer_id

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        keypair: Keypair,
        expected_peer_id: str | None = None,
        wait_for_capability: bool = True,
    ) -> Connection:
        """Connect to a peer and complete EXECUTE-based connect handshake.

        V7 connect flow:
        1. Send EXECUTE hello (with our nonce)
        2. Recv EXECUTE hello (their nonce, peer_id)
        3. Send EXECUTE authenticate (sign their nonce, signature via target-matching)
        4. Recv EXECUTE_RESPONSE (their authenticate data + capability via token in data)

        Args:
            host: Host to connect to.
            port: Port to connect to.
            keypair: This peer's keypair.
            expected_peer_id: Optional expected remote peer ID.
            wait_for_capability: Whether to expect capability in connect response.

        Returns:
            An authenticated Connection.

        Raises:
            ConnectError: If connect fails.
            OSError: If connection fails.
        """
        reader, writer = await asyncio.open_connection(host, port)
        try:
            # Step 1: Send our hello
            hello_execute, our_nonce = create_connect_hello_execute(keypair)
            await send_envelope(writer, Envelope(root=hello_execute.to_entity()))

            # Step 2: Receive their hello response
            # Hello receives EXECUTE_RESPONSE with hello data as result
            their_hello_env = await recv_envelope(reader)
            their_hello_root = their_hello_env.root
            if their_hello_root.get("type") != ExecuteResponse.TYPE:
                raise ConnectError(
                    f"Expected EXECUTE_RESPONSE hello, got {their_hello_root.get('type')}"
                )

            their_hello_data = their_hello_root.get("data", {})
            their_hello_result = their_hello_data.get("result", {})
            # Result is a full entity (system/protocol/connect/hello) - data contains the actual fields
            their_hello_result_data = their_hello_result.get("data", {})
            their_peer_id = their_hello_result_data.get("peer_id", "")
            their_nonce = their_hello_result_data.get("nonce", "")

            if not their_peer_id or not their_nonce:
                raise ConnectError("Missing peer_id or nonce in hello response")

            # Verify expected peer ID if provided
            if expected_peer_id and their_peer_id != expected_peer_id:
                raise ConnectError(
                    f"Expected peer {expected_peer_id}, got {their_peer_id}"
                )

            # V7 v7.69 §4.5 — compute the connection's active content_hash_format
            # from the responder's advertised hello sets. We run the same
            # first-match-in-initiator-order intersection the responder ran, so
            # both converge on one active value (§4.5a) and author uniformly.
            our_hash_formats = default_advertised_hash_formats()
            their_hash_formats = (
                their_hello_result_data.get("hash_formats") or ["ecfv1-sha256"]
            )
            active_format = negotiate_active_hash_format(
                our_hash_formats, their_hash_formats,
            )
            if active_format is None:
                raise ConnectError(
                    f"no common hash format: ours {our_hash_formats}, "
                    f"theirs {their_hash_formats}",
                    code="incompatible_hash_format",
                )

            # Step 3: Send our authenticate (sign their nonce)
            # Signature found via target-matching, not refs
            # signer is identity hash, so identity entity must be included
            authenticate_execute, signature_entity, identity_entity = create_connect_authenticate_execute(
                keypair, their_nonce, algorithm=active_format,
            )

            # Send with signature and identity in included (found via target-matching)
            await send_envelope(
                writer,
                Envelope(
                    root=authenticate_execute.to_entity(),
                    included=[
                        signature_entity.to_dict(),
                        identity_entity.to_dict(),
                    ],
                ),
            )

            # Step 4: Receive their authenticate response
            authenticate_response_env = await recv_envelope(reader)
            authenticate_root = authenticate_response_env.root

            if authenticate_root.get("type") != ExecuteResponse.TYPE:
                raise ConnectError(
                    f"Expected EXECUTE_RESPONSE, got {authenticate_root.get('type')}"
                )

            response = ExecuteResponse.from_entity(authenticate_root)

            if response.status != 200:
                error_msg = ""
                if isinstance(response.result, dict):
                    error_msg = response.result.get("message", response.result.get("error", ""))
                raise ConnectError(
                    f"Connect authenticate failed (status {response.status}): {error_msg}"
                )

            # Verify their authenticate data (signature over AUTHENTICATE hash)
            # Token hash is returned from verify function
            remote_peer_id, remote_public_key_bytes, token_hash = verify_connect_authenticate_response(
                response.result,
                authenticate_response_env,
                our_nonce,
                expected_peer_id,
            )

            # Extract capability from included entities via token hash
            # Also extract capability chain (signature, granter identity)
            capability: dict[str, Any] | None = None
            capability_chain: list[dict[str, Any]] | None = None
            if token_hash and wait_for_capability:
                cap_dict = authenticate_response_env.find_included(token_hash)
                if cap_dict:
                    capability = cap_dict
                    # Extract capability chain: signature for capability, granter identity
                    cap_data = cap_dict.get("data", {})
                    granter_hash = cap_data.get("granter")
                    cap_content_hash = cap_dict.get("content_hash")

                    chain_entities = []
                    # Find capability signature (signature with target == capability hash)
                    cap_sig = authenticate_response_env.find_signature_for_target(cap_content_hash)
                    if cap_sig:
                        chain_entities.append(cap_sig)
                    # Find granter identity
                    if granter_hash:
                        granter_identity = authenticate_response_env.find_included(granter_hash)
                        if granter_identity:
                            chain_entities.append(granter_identity)
                    if chain_entities:
                        capability_chain = chain_entities

            session = Session(
                local_peer_id=keypair.peer_id,
                remote_peer_id=remote_peer_id,
                remote_public_key=remote_public_key_bytes,
            )

            conn = cls(
                reader, writer, session, keypair, capability, capability_chain,
                active_hash_format=active_format,
            )
            # Class G / F-WB28: bring up the demuxer reader task NOW that
            # the inline handshake recv()s are done. From this point on,
            # every inbound frame is read by `_reader_loop` and dispatched
            # via the pending-Future map; any other caller awaiting
            # `reader.read*()` directly would race the reader task.
            conn._ensure_reader_started()
            return conn

        except Exception:
            writer.close()
            await writer.wait_closed()
            raise
