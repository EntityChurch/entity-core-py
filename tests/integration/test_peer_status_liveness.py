"""EXTENSION-NETWORK Amendment 12 rungs 1-2 — the liveness slice (§A3).

Python's build of the cohort floor, converging on the Go reference shape
(`entity-core-go core/peer/peer_status_liveness_test.go` — read as interop
context, not copied):

- `connected` on establish, BOTH ends of the handshake;
- `suspect` (reason `transport-error`) at the direct-dispatch seam on a
  send failure over a connection believed active (§A1) — the ANCHOR
  VECTOR: two peers, drop one side, the survivor's status flips with no
  poll;
- `suspect → disconnected` (reason `keepalive-miss`) via the §5 keepalive
  loop (rung 2 — the floor is rungs 1+2 together, ruling B);
- the §A1 no-clobber guard is behavioral (endpoint object identity, the
  `Arc::ptr_eq` analog) and idempotent under concurrent re-entry;
- `system/peer/status` is the THREE-state §3.13 enum; put-sites are
  minimal writes (ruling D).

The tests poll the tree only as test instrumentation — the implementation
under test writes reactively, never by polling.
"""

from __future__ import annotations

import asyncio
import time

from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.peer.liveness import (
    STATUS_CONNECTED,
    STATUS_DISCONNECTED,
    STATUS_SUSPECT,
    connection_path,
    peer_status_path,
)
from entity_core.protocol.auth import create_identity_entity
from entity_core.protocol.entity import Entity


def _identity_hash(kp: Keypair) -> bytes:
    """The peer's `system/peer` content_hash (V7 v7.64 §1.4 path key)."""
    return create_identity_entity(kp).compute_hash()


def _read_status(peer: Peer, remote_kp: Keypair) -> Entity | None:
    """Read `system/peer/status/{remote_hex}` from a peer's tree."""
    uri = peer.entity_tree.normalize_uri(peer_status_path(_identity_hash(remote_kp)))
    h = peer.entity_tree.get(uri)
    return peer.content_store.get(h) if h is not None else None


def _read_connection(peer: Peer, remote_kp: Keypair) -> Entity | None:
    uri = peer.entity_tree.normalize_uri(connection_path(_identity_hash(remote_kp)))
    h = peer.entity_tree.get(uri)
    return peer.content_store.get(h) if h is not None else None


async def _wait_for(predicate, timeout: float = 3.0, interval: float = 0.01):
    """Test-side wait helper (the impl under test never polls)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        await asyncio.sleep(interval)
    return predicate()


def _build_server(kp: Keypair) -> Peer:
    return (
        PeerBuilder()
        .with_keypair(kp)
        .with_default_handlers()
        .debug_mode(True)
        .build()
    )


def _build_client(kp: Keypair, server: Peer, server_kp: Keypair, port: int, **keepalive) -> Peer:
    builder = PeerBuilder().with_keypair(kp).with_default_handlers().debug_mode(True)
    if keepalive:
        builder = builder.with_keepalive_config(**keepalive)
    client = builder.build()
    client.register_remote(
        server.peer_id, f"127.0.0.1:{port}",
        public_key=server_kp.public_key_bytes(),
    )
    return client


def _bound_port(peer: Peer) -> int:
    return peer._server.sockets[0].getsockname()[1]


class TestConnectedOnEstablish:
    """§A3 write 1 — `connected` on establish, both ends (§6.2)."""

    def test_both_ends_write_connected(self):
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(client_kp, server, server_kp, _bound_port(server))
            try:
                await client._remote_pool.get_connection(server.peer_id)

                # Dialer end: written synchronously at pool-establish.
                status = _read_status(client, server_kp)
                assert status is not None, "dialer wrote no peer-status entity"
                assert status.type == "system/peer/status"
                assert status.data["peer_id"] == server.peer_id
                assert status.data["status"] == STATUS_CONNECTED
                assert "connected_at" in status.data

                # Responder end: written at authenticate-complete.
                status = await _wait_for(lambda: _read_status(server, client_kp))
                assert status is not None, "responder wrote no peer-status entity"
                assert status.data["peer_id"] == client.peer_id
                assert status.data["status"] == STATUS_CONNECTED
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())

    def test_dialer_writes_connection_entity(self):
        """Ruling C surface (full conformance, NOT floor): the dialer's
        §3.13 `system/connection` entity, write-on-transition."""
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            port = _bound_port(server)
            client = _build_client(client_kp, server, server_kp, port)
            try:
                await client._remote_pool.get_connection(server.peer_id)

                conn_ent = _read_connection(client, server_kp)
                assert conn_ent is not None
                assert conn_ent.type == "system/connection"
                assert conn_ent.data["peer_id"] == server.peer_id
                assert conn_ent.data["transport"] == "tcp"
                assert conn_ent.data["address"] == f"tcp://127.0.0.1:{port}"
                assert conn_ent.data["status"] == "active"
                assert "established_at" in conn_ent.data

                # The status entity carries the §3.13 `connection` path ref.
                status = _read_status(client, server_kp)
                assert status.data.get("connection") == connection_path(
                    _identity_hash(server_kp)
                )
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())

    def test_responder_writes_connection_entity_and_close_transition(self):
        """Ruling C surface, responder end: `active` at authenticate-
        complete, flipped to `closed` when the inbound connection ends —
        establish-time fields preserved (read-modify-write)."""
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(client_kp, server, server_kp, _bound_port(server))
            try:
                await client._remote_pool.get_connection(server.peer_id)

                conn_ent = await _wait_for(lambda: _read_connection(server, client_kp))
                assert conn_ent is not None, (
                    "responder wrote no system/connection entity"
                )
                assert conn_ent.type == "system/connection"
                assert conn_ent.data["peer_id"] == client.peer_id
                assert conn_ent.data["transport"] == "tcp"
                assert conn_ent.data["status"] == "active"
                # EXTENSION-NETWORK §6.7.1 MUST 2: the responder records NO
                # address. `address` means "the endpoint I dial to reach this
                # peer" — dialer-side state — and the accepted connection's
                # ephemeral source port is not one. Writing it here yields a
                # routable-looking value that routes nowhere, which §10 and
                # `system/peer/status` would then consume as dialable.
                assert conn_ent.data["address"] == ""
                established_at = conn_ent.data["established_at"]

                # Responder status entity carries the path ref too.
                status = _read_status(server, client_kp)
                assert status.data.get("connection") == connection_path(
                    _identity_hash(client_kp)
                )

                # Drop the dialer: the responder's handler teardown flips
                # the connection entity to closed (a transition write,
                # preserving establish-time fields).
                await client.stop()
                closed = await _wait_for(
                    lambda: (
                        (c := _read_connection(server, client_kp)) is not None
                        and c.data["status"] == "closed"
                        and c
                    ),
                    timeout=5.0,
                )
                assert closed, "responder never flipped system/connection to closed"
                assert closed.data["established_at"] == established_at
                assert closed.data["transport"] == "tcp"
            finally:
                await client.stop()  # idempotent; body may already have
                await server.stop()

        asyncio.run(run())


class TestSuspectOnTransportError:
    """§A1 — the ANCHOR VECTOR (Go: TestLivenessSuspectOnTransportError).

    Two peers, drop one side; the survivor's next dispatch over the
    connection it believed active fails, and its `system/peer/status`
    flips connected → suspect (reason transport-error) with no poll.
    """

    def test_survivor_flips_to_suspect(self):
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(client_kp, server, server_kp, _bound_port(server))
            try:
                await client._remote_pool.get_connection(server.peer_id)
                assert _read_status(client, server_kp).data["status"] == STATUS_CONNECTED

                # Drop the remote side.
                await server.stop()

                # The survivor dispatches over the pooled connection it
                # believes active; the send error demotes reactively.
                result = await client._remote_execute(
                    f"entity://{server.peer_id}/system/status", "get", None
                )
                assert result.status == 502

                status = _read_status(client, server_kp)
                assert status.data["status"] == STATUS_SUSPECT
                assert status.data["reason"] == "transport-error"
                assert "last_error" in status.data

                # §A1: the dead conn was evicted so the next call re-dials.
                assert server.peer_id not in client._remote_pool._connections

                # Ruling C: the connection entity flipped to closed.
                conn_ent = _read_connection(client, server_kp)
                assert conn_ent is not None
                assert conn_ent.data["status"] == "closed"
                # Establish-time fields preserved on the close transition.
                assert conn_ent.data["transport"] == "tcp"
            finally:
                await client.stop()

        asyncio.run(run())

    def test_reconnection_returns_to_connected(self):
        """§3.13 transitions: reconnection returns to `connected`."""
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(client_kp, server, server_kp, _bound_port(server))
            try:
                conn = await client._remote_pool.get_connection(server.peer_id)
                client._remote_pool.demote_on_transport_error(
                    server.peer_id, conn, ConnectionError("injected")
                )
                assert _read_status(client, server_kp).data["status"] == STATUS_SUSPECT

                await client._remote_pool.get_connection(server.peer_id)
                assert _read_status(client, server_kp).data["status"] == STATUS_CONNECTED
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())


class TestNoClobberGuard:
    """§A1 no-clobber (behavioral, ruling C): demote only if the failed
    endpoint is still the currently-bound one; idempotent under
    concurrent re-entry (Go: TestLivenessNoClobber / Idempotency)."""

    def test_stale_endpoint_does_not_clobber_live_binding(self):
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(client_kp, server, server_kp, _bound_port(server))
            try:
                live = await client._remote_pool.get_connection(server.peer_id)

                # A stale endpoint (a concurrent re-dial replaced it) fails:
                # the demotion must not touch the live binding's liveness.
                stale = object()
                client._remote_pool.demote_on_transport_error(
                    server.peer_id, stale, ConnectionError("stale socket")
                )

                assert client._remote_pool._connections[server.peer_id] is live
                assert _read_status(client, server_kp).data["status"] == STATUS_CONNECTED
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())

    def test_double_demotion_is_idempotent(self):
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(client_kp, server, server_kp, _bound_port(server))
            try:
                conn = await client._remote_pool.get_connection(server.peer_id)
                err = ConnectionError("boom")
                client._remote_pool.demote_on_transport_error(server.peer_id, conn, err)
                # Concurrent identical failure: already evicted → no-op.
                client._remote_pool.demote_on_transport_error(server.peer_id, conn, err)

                status = _read_status(client, server_kp)
                assert status.data["status"] == STATUS_SUSPECT
                assert status.data["reason"] == "transport-error"
                assert server.peer_id not in client._remote_pool._connections
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())


class TestKeepalive:
    """Rung 2 — §5 keepalive: the ping op, the miss escalation, and the
    §A4 no-cadence-writes discipline. The floor (rungs 1+2, ruling B) is
    complete only with these."""

    def test_ping_pong_exchange(self):
        """§5.1-§5.3: EXECUTE `system/protocol/connect` op `ping` on an
        established connection echoes timestamp/sequence + server_time."""
        async def run():
            server_kp = Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            try:
                conn = await Connection.connect(
                    "127.0.0.1", _bound_port(server), Keypair.generate()
                )
                try:
                    before = int(time.time() * 1000)
                    response = await conn.execute(
                        "system/protocol/connect",
                        "ping",
                        params={
                            "type": "system/network/ping",
                            "data": {"timestamp": before, "sequence": 42},
                        },
                    )
                    assert response.status == 200
                    pong = response.result
                    assert pong["type"] == "system/network/pong"
                    assert pong["data"]["timestamp"] == before
                    assert pong["data"]["sequence"] == 42
                    assert pong["data"]["server_time"] >= before - 1000
                finally:
                    conn.close()
                    await conn.wait_closed()
            finally:
                await server.stop()

        asyncio.run(run())

    def test_keepalive_miss_escalates_to_disconnected(self):
        """§5.4: drop the remote, let the loop run — suspect, grace, then
        disconnected (reason keepalive-miss) within the envelope
        (interval_ms × max_missed + timeout_ms; short config injected)."""
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(
                client_kp, server, server_kp, _bound_port(server),
                interval_ms=50, timeout_ms=100, max_missed=1,
            )
            try:
                await client._remote_pool.get_connection(server.peer_id)
                await server.stop()

                # No dispatch happens; only the keepalive loop observes
                # the idle-dead connection. Envelope ≈ 50×1+100+100(grace)
                # = 250 ms; the wait below is test instrumentation.
                status = await _wait_for(
                    lambda: (
                        (s := _read_status(client, server_kp)) is not None
                        and s.data["status"] == STATUS_DISCONNECTED
                        and s
                    ),
                    timeout=5.0,
                )
                assert status, "keepalive loop never demoted the dead peer"
                assert status.data["status"] == STATUS_DISCONNECTED
                assert status.data["reason"] == "keepalive-miss"
                # §A4: the demotion write snapshots `last_seen` — the
                # demotion's evidence, not a cadence refresh.
                assert status.data["last_seen"] > 0
                # Evicted: the next dispatch would re-dial, not reuse.
                assert server.peer_id not in client._remote_pool._connections
            finally:
                await client.stop()

        asyncio.run(run())

    def test_keepalive_no_cadence_writes(self):
        """§A4 (rung-2 ruling 1): the status entity is transition-written
        ONLY. Pings flow (impl-internal freshness advances — proof the
        loop is alive), while the status binding stays byte-identical:
        no `last_seen` refresh stream, no fan-out, no CAS accretion.
        Inverse of the pre-§A4 refresh vector; Go analog
        `TestKeepaliveNoCadenceWrites`."""
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(
                client_kp, server, server_kp, _bound_port(server),
                interval_ms=50, timeout_ms=500, max_missed=3,
            )
            try:
                pool = client._remote_pool
                await pool.get_connection(server.peer_id)

                established_hash = client.entity_tree.get(
                    client.entity_tree.normalize_uri(
                        peer_status_path(_identity_hash(server_kp))
                    )
                )
                assert established_hash is not None

                # Wait for ≥2 pong-driven freshness advances — the loop
                # is demonstrably pinging.
                heard_at_establish = pool._last_heard_ms[server.peer_id]
                advanced = await _wait_for(
                    lambda: pool._last_heard_ms[server.peer_id]
                    > heard_at_establish,
                    timeout=5.0,
                )
                assert advanced, "keepalive loop never processed a pong"
                heard_after_first = pool._last_heard_ms[server.peer_id]
                await _wait_for(
                    lambda: pool._last_heard_ms[server.peer_id]
                    > heard_after_first,
                    timeout=5.0,
                )

                # The binding never moved: same content hash as at
                # establish, and no `last_seen` on the connected write.
                current_hash = client.entity_tree.get(
                    client.entity_tree.normalize_uri(
                        peer_status_path(_identity_hash(server_kp))
                    )
                )
                assert current_hash == established_hash, (
                    "status entity was rewritten at keepalive cadence "
                    "(§A4 violation: transition-writes only)"
                )
                status = client.content_store.get(current_hash)
                assert status.data["status"] == STATUS_CONNECTED
                assert "last_seen" not in status.data
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())


class TestEscalationOwedByTheEpisode:
    """§5.4a `[MUST]` — the `suspect → disconnected` escalation is owed by the
    **failure episode**, not by the connection.

    go found this in their own tree (`b55101f`) and then measured it against
    both siblings: `liveness_escalate_after_eviction` FAILed against py
    `2c1aa1b` and rust `21eb223` with identical text. py's defect was the same
    shape as theirs — `demote_on_transport_error` evicts the binding, eviction
    cancels the keepalive loop, and the loop was the only thing that owed the
    escalation. The peer stayed `suspect` forever, so the disconnect
    subscription never fired and **§4.1 reconnect never triggered on any
    transport-error-first path** — which is how a dead peer is usually noticed
    first, so the common case rather than a corner.

    Why nothing already here could see it: `test_keepalive_miss_escalates_to_
    disconnected` above arms a **fresh** counterpart, so it exercises the idle
    timer and says nothing about a peer already demoted at the §A1 seam. Our
    four-run negative control for go's flaky check was an honest pass over a
    surface it structurally could not reach. The composition of the two vectors
    we already had is the state no check occupied — the second gap of exactly
    that shape in two cycles, after the §5.5a granter frame.
    """

    def test_escalate_after_eviction(self):
        """`NET-LIVENESS-ESCALATE-AFTER-EVICTION-1` — establish, drop the
        remote, one dispatch (→ `suspect`/`transport-error`), then stay idle:
        the escalation still lands, and carries the episode's ORIGINATING
        reason rather than re-stamping to `keepalive-miss`."""
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(
                client_kp, server, server_kp, _bound_port(server),
                interval_ms=50, timeout_ms=100, max_missed=1,
            )
            try:
                await client._remote_pool.get_connection(server.peer_id)
                await server.stop()

                # One dispatch over the connection believed active: the §A1
                # seam demotes and evicts.
                result = await client._remote_execute(
                    f"entity://{server.peer_id}/system/status", "get", None
                )
                assert result.status == 502
                suspect = _read_status(client, server_kp)
                assert suspect.data["status"] == STATUS_SUSPECT
                assert suspect.data["reason"] == "transport-error"
                failing_since = suspect.data["failing_since"]

                # The escalation outlived the eviction that cancelled the
                # keepalive loop — the structural half of the rule. The two
                # live in separate maps precisely so this holds.
                pool = client._remote_pool
                assert server.peer_id not in pool._keepalive_tasks
                escalation = pool._escalation_tasks.get(server.peer_id)
                assert escalation is not None and not escalation.done(), (
                    "the §A1 eviction cancelled the pending §5.4 escalation"
                )

                # NOTHING further is dispatched — no ping is sent, no
                # counterpart is re-armed. The grace period alone owes this.
                status = await _wait_for(
                    lambda: (
                        (s := _read_status(client, server_kp)) is not None
                        and s.data["status"] == STATUS_DISCONNECTED
                        and s
                    ),
                    timeout=5.0,
                )
                assert status, (
                    "peer demoted to suspect at the §A1 seam never escalated "
                    "to disconnected — §4.1 reconnect can never fire"
                )
                # The RULED half: `keepalive-miss` here would assert pings
                # that were provably never sent (the connection was gone
                # before the loop could send one) and would destroy the only
                # signal distinguishing a transport-first episode.
                assert status.data["reason"] == "transport-error", (
                    "the escalation re-stamped the episode's originating reason"
                )
                # One episode, one `failing_since` — the escalation is a
                # transition inside it, not a new one (§2 retry-state).
                assert status.data["failing_since"] == failing_since
            finally:
                await client.stop()

        asyncio.run(run())

    def test_idle_path_still_escalates_with_its_own_reason(self):
        """The other entry point, unchanged by the §5.4a rework: an episode
        that opens at an idle keepalive miss escalates carrying
        `keepalive-miss`. Both reasons are preserved by the same code path,
        which is the point — the escalator reads the episode rather than
        assuming which timer armed it."""
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(
                client_kp, server, server_kp, _bound_port(server),
                interval_ms=50, timeout_ms=100, max_missed=1,
            )
            try:
                await client._remote_pool.get_connection(server.peer_id)
                await server.stop()
                status = await _wait_for(
                    lambda: (
                        (s := _read_status(client, server_kp)) is not None
                        and s.data["status"] == STATUS_DISCONNECTED
                        and s
                    ),
                    timeout=5.0,
                )
                assert status, "idle-dead peer never escalated"
                assert status.data["reason"] == "keepalive-miss"
                assert server.peer_id not in client._remote_pool._connections
            finally:
                await client.stop()

        asyncio.run(run())

    def test_reconnect_during_grace_writes_nothing(self):
        """§5.4a guard 2 — a peer that comes back during the grace period is
        `connected` again, and the pending escalation must not clobber the new
        binding's own write."""
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            port = _bound_port(server)
            client = _build_client(
                client_kp, server, server_kp, port,
                interval_ms=10_000, timeout_ms=300, max_missed=3,
            )
            try:
                conn = await client._remote_pool.get_connection(server.peer_id)
                # Demote without killing the server: the episode opens, the
                # escalation arms, and the peer is reachable the whole time.
                client._remote_pool.demote_on_transport_error(
                    server.peer_id, conn, ConnectionError("injected")
                )
                assert _read_status(client, server_kp).data["status"] == STATUS_SUSPECT

                # Re-dial inside the grace window.
                await client._remote_pool.get_connection(server.peer_id)
                assert _read_status(client, server_kp).data["status"] == STATUS_CONNECTED

                # Let the grace expire; the escalation reads a reconnected,
                # `connected` peer and writes nothing.
                await asyncio.sleep(0.5)
                final = _read_status(client, server_kp)
                assert final.data["status"] == STATUS_CONNECTED, (
                    "the escalation clobbered a recovered peer"
                )
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())


class TestNoEscalationWithoutEpisode:
    """`NET-LIVENESS-NO-ESCALATION-WITHOUT-EPISODE-1` — the §5.4a scope pin,
    and the negative half of the pair.

    **DECLARED EXCLUSION (§5.4a satisfaction mode; GUIDE-CONFORMANCE §5.2b).**
    This half is satisfied **in-process**, not at the wire, and no cross-impl
    result covers it. The state it requires — *unbound yet still `connected`* —
    is reachable only from the two paths §A1 deliberately excludes from
    demoting (§10.2 dispatch fallback, RELAY terminal hop), and py deploys
    neither, so a conformance client cannot construct it. §5.4a rejects the
    obvious wire proxy (a live idle counterpart) on the grounds that a bound
    counterpart exercises a timer-driven escalation and never the scope-pin
    defect: it would read as coverage while missing the case.

    **The mutation this is verified against, named as §5.4a requires:** remove
    the `status != suspect` guard in `RemoteConnectionPool._escalate_after_
    grace`. `test_mutation_removing_the_suspect_guard_fails_this` below does
    not merely name it — it executes it, and asserts the write appears. An
    unexecuted mutation claim is the same species of vacuous control we shipped
    on the §5.5a probe last cycle: it varied scope while holding form fixed,
    and could not have failed.

    Recorded in `docs/CONFORMANCE-EXCLUSIONS.md` as well, because an exclusion
    that lives only in a test docstring is one report away from being lost —
    and an in-process result reported as a cross-impl vector pass is a false
    conformance claim.
    """

    @staticmethod
    async def _armed_on_a_connected_peer(client, server, server_kp):
        """Arm the escalator against a peer that was evicted WITHOUT being
        demoted — the §10.2 / RELAY shape, in process."""
        conn = await client._remote_pool.get_connection(server.peer_id)
        assert _read_status(client, server_kp).data["status"] == STATUS_CONNECTED
        # The bare guarded evict: what the excluded paths use, and what
        # `demote_on_transport_error` calls before it writes anything.
        assert client._remote_pool.remove_connection(server.peer_id, expected=conn)
        client._remote_pool._schedule_escalation(
            server.peer_id, conn, originating_reason="transport-error",
        )
        task = client._remote_pool._escalation_tasks[server.peer_id]
        await asyncio.wait_for(asyncio.shield(task), timeout=5.0)

    def test_evict_without_demote_produces_no_disconnected_write(self):
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(
                client_kp, server, server_kp, _bound_port(server),
                interval_ms=10_000, timeout_ms=50, max_missed=3,
            )
            try:
                await self._armed_on_a_connected_peer(client, server, server_kp)
                status = _read_status(client, server_kp)
                assert status.data["status"] == STATUS_CONNECTED, (
                    "escalated a peer with no open failure episode — the scope "
                    "pin is what keeps §10.2 fallback and RELAY terminal-hop "
                    "evictions from manufacturing a demotion"
                )
                assert "reason" not in status.data
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())

    def test_mutation_removing_the_suspect_guard_fails_this(self):
        """The declared mutation, executed. With the guard's discriminating
        value neutralized, the same arrangement DOES write `disconnected` —
        so the assertion above has teeth and is not passing by construction.

        Escalating on any *unbound* peer rather than any *`suspect`* peer is
        precisely the defect that satisfies the positive vector while breaking
        the §A1 seam scope; this is the shape of it."""
        async def run():
            from entity_core.peer import liveness

            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_server(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_client(
                client_kp, server, server_kp, _bound_port(server),
                interval_ms=10_000, timeout_ms=50, max_missed=3,
            )
            original = liveness.STATUS_SUSPECT
            try:
                # `status != STATUS_SUSPECT → return` now admits `connected`:
                # the guard is present but no longer discriminates, which is
                # what "removing the suspect guard" means behaviorally.
                liveness.STATUS_SUSPECT = STATUS_CONNECTED
                await TestNoEscalationWithoutEpisode._armed_on_a_connected_peer(
                    client, server, server_kp
                )
                status = _read_status(client, server_kp)
                assert status.data["status"] == STATUS_DISCONNECTED, (
                    "the mutation did not reach the write — this negative "
                    "vector would pass against a peer with no scope pin at "
                    "all, which makes it worthless"
                )
            finally:
                liveness.STATUS_SUSPECT = original
                await client.stop()
                await server.stop()

        asyncio.run(run())


class TestStatusShape:
    """Ruling D: the §3.13 type is registered with the canonical field
    set; the enum is THREE states (no `reconnecting`)."""

    def test_type_registered_with_3_13_fields(self):
        from entity_core.types.definitions import (
            type_system_connection,
            type_system_peer_status,
        )

        status_type = type_system_peer_status()
        fields = status_type.data["fields"]
        assert set(fields) == {
            "peer_id", "status", "connected_at", "last_seen", "connection",
            "reason", "last_error",
        }
        assert not fields["peer_id"].get("optional")
        assert not fields["status"].get("optional")
        for optional in ("connected_at", "last_seen", "connection", "reason", "last_error"):
            assert fields[optional]["optional"] is True

        conn_type = type_system_connection()
        assert set(conn_type.data["fields"]) == {
            "peer_id", "transport", "address", "status", "established_at", "parameters",
        }

    def test_enum_is_three_states(self):
        from entity_core.peer import liveness

        assert STATUS_CONNECTED == "connected"
        assert STATUS_SUSPECT == "suspect"
        assert STATUS_DISCONNECTED == "disconnected"
        # Ruling D: `reconnecting` is a system/network/peer-summary value,
        # NOT a status-entity state — assert it never leaks in here.
        exported = {
            v for k, v in vars(liveness).items()
            if k.startswith("STATUS_") and isinstance(v, str)
        }
        assert exported == {"connected", "suspect", "disconnected"}
