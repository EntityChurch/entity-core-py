"""R1 + G1 mixed-transport coverage for the outbound pool.

PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY-AND-SESSION-LIFECYCLE §7.3
(Round-2 LOCKED):

- **G1 — profile-id collision:** ``register_remote`` (tcp) writes
  ``primary``; ``register_remote_http`` writes ``primary-http``. The two
  profile slots are distinct so a peer publishing both transports does
  NOT silently overwrite one with the other.
- **R1 — multi-profile outbound:** a peer with two live profiles (tcp +
  http) is dialable on either; ``RemoteConnectionPool`` walks both in
  D1 order (``primary`` lex-precedes ``primary-http``), so TCP is the
  first attempt; if TCP is down, HTTP succeeds on the next candidate.
- **Reconnect:** evicting the pooled endpoint forces a re-dial on the
  next ``get_connection`` call (transport doesn't matter for the
  semantics — the pool is just a cache).

These tests bypass R6 / cap-direction (handled separately) and only
pin the dispatcher mechanics.
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.peer.http_client import HttpConnection


@pytest.fixture
async def dual_transport_server():
    """A server peer running BOTH a TCP listener and an HTTP listener,
    each publishing its own §6.5.1 profile."""
    keypair = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(keypair)
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    await peer.start("127.0.0.1", 0)
    http = await peer.start_http("127.0.0.1", 0)
    tcp_bind = peer._server.sockets[0].getsockname()  # type: ignore[union-attr]
    http_bind = http.bound_socket()
    assert http_bind is not None
    yield peer, tcp_bind, http_bind
    await http.stop()
    await peer.stop()


@pytest.fixture
def client_peer():
    keypair = Keypair.generate()
    return PeerBuilder().with_keypair(keypair).with_all_handlers().build()


class TestMixedTransportProfileIds:
    """G1 — TCP and HTTP profiles for the same peer must live at distinct
    profile-id slots."""

    def test_register_both_does_not_overwrite(self, client_peer):
        from entity_core.protocol.auth import create_identity_entity
        remote_kp = Keypair.generate()
        remote_hex = create_identity_entity(remote_kp).compute_hash().hex()
        client_peer.register_remote(
            remote_kp.peer_id, "10.0.0.1:9000",
            public_key=remote_kp.public_key_bytes(),
        )
        client_peer.register_remote_http(
            remote_kp.peer_id, "http://10.0.0.1:8080/entity",
            public_key=remote_kp.public_key_bytes(),
        )

        tree = client_peer.entity_tree
        tcp_uri = tree.normalize_uri(
            f"system/peer/transport/{remote_hex}/primary"
        )
        http_uri = tree.normalize_uri(
            f"system/peer/transport/{remote_hex}/primary-http"
        )
        tcp_hash = tree.get(tcp_uri)
        http_hash = tree.get(http_uri)
        assert tcp_hash is not None, "tcp/primary slot empty after dual register"
        assert http_hash is not None, "http/primary-http slot empty after dual register"
        assert tcp_hash != http_hash, "both slots collapsed to one entity"

    def test_resolver_returns_both_d1_ordered(self, client_peer):
        from entity_core.peer.remote import RemoteConnectionPool

        remote_kp = Keypair.generate()
        client_peer.register_remote(
            remote_kp.peer_id, "10.0.0.1:9000",
            public_key=remote_kp.public_key_bytes(),
        )
        client_peer.register_remote_http(
            remote_kp.peer_id, "http://10.0.0.1:8080/entity",
            public_key=remote_kp.public_key_bytes(),
        )
        pool = RemoteConnectionPool(
            client_peer.keypair, client_peer.content_store, client_peer.entity_tree
        )
        cands = pool._list_profile_candidates(remote_kp.peer_id)
        assert [(p, t) for p, t, _ in cands] == [
            ("primary", "tcp"),
            ("primary-http", "http"),
        ]


class TestMultiProfileDial:
    """R1 — the dialer iterates candidates in D1 order; either transport
    can satisfy ``get_connection``."""

    @pytest.mark.asyncio
    async def test_dials_tcp_when_both_advertised(self, dual_transport_server):
        """With both profiles healthy, D1 lex order picks tcp/primary
        first; the pooled endpoint is a TCP ``Connection``."""
        server, tcp_bind, http_bind = dual_transport_server
        client_kp = Keypair.generate()
        client = (
            PeerBuilder()
            .with_keypair(client_kp)
            .with_all_handlers()
            .with_remote_peer(
                server.peer_id, f"{tcp_bind[0]}:{tcp_bind[1]}",
                public_key=server.keypair.public_key_bytes(),
            )
            .with_remote_peer_http(
                server.peer_id, f"http://{http_bind[0]}:{http_bind[1]}/entity",
                public_key=server.keypair.public_key_bytes(),
            )
            .build()
        )

        conn = await client._remote_pool.get_connection(server.peer_id)
        try:
            assert isinstance(conn, Connection), (
                f"D1 should pick tcp/primary first; got {type(conn).__name__}"
            )
        finally:
            await client._remote_pool.close_all()

    @pytest.mark.asyncio
    async def test_falls_through_to_http_when_tcp_unreachable(
        self, dual_transport_server
    ):
        """A peer with a stale TCP profile (port closed) and a working
        HTTP profile: the resolver walks past the TCP failure and
        successfully dials HTTP."""
        server, _tcp_bind, http_bind = dual_transport_server
        client_kp = Keypair.generate()
        client = (
            PeerBuilder()
            .with_keypair(client_kp)
            .with_all_handlers()
            # Deliberately point TCP at a closed port.
            .with_remote_peer(
                server.peer_id, "127.0.0.1:1",
                public_key=server.keypair.public_key_bytes(),
            )
            .with_remote_peer_http(
                server.peer_id, f"http://{http_bind[0]}:{http_bind[1]}/entity",
                public_key=server.keypair.public_key_bytes(),
            )
            .build()
        )

        conn = await client._remote_pool.get_connection(server.peer_id)
        try:
            assert isinstance(conn, HttpConnection), (
                f"TCP fallthrough should land on HttpConnection; got "
                f"{type(conn).__name__}"
            )
        finally:
            await client._remote_pool.close_all()


class TestReconnectAfterEviction:
    """The pool re-dials after eviction; transport choice is consistent
    on the second connect."""

    @pytest.mark.asyncio
    async def test_evict_then_redial_reuses_same_transport(
        self, dual_transport_server
    ):
        server, tcp_bind, _http_bind = dual_transport_server
        client_kp = Keypair.generate()
        client = (
            PeerBuilder()
            .with_keypair(client_kp)
            .with_all_handlers()
            .with_remote_peer(
                server.peer_id, f"{tcp_bind[0]}:{tcp_bind[1]}",
                public_key=server.keypair.public_key_bytes(),
            )
            .build()
        )

        conn1 = await client._remote_pool.get_connection(server.peer_id)
        assert isinstance(conn1, Connection)

        client._remote_pool.remove_connection(server.peer_id)
        # Tiny yield so the scheduled aclose task gets a chance to run
        # before the next dial races it. Not strictly required (pool is
        # already empty), but keeps the test deterministic.
        await asyncio.sleep(0.01)

        conn2 = await client._remote_pool.get_connection(server.peer_id)
        try:
            assert isinstance(conn2, Connection)
            assert conn2 is not conn1, "expected a fresh connection after evict"
        finally:
            await client._remote_pool.close_all()
