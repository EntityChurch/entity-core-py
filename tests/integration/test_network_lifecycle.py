"""EXTENSION-NETWORK Amendment 12 rung 3 — the §4.1 maintain-peer lifecycle.

In-process two-peer vectors for the system/network handler's reconnect
continuation graph, converging on the Go reference shape
(`entity-core-go ext/network/lifecycle_test.go` — read as interop context,
not copied). These double as the Python shape for
PROPOSAL-CONTINUATION-LOST-ERROR-MARKER-MUST §4's reconnect-chain vectors —
rung 3 is the proposal's named "natural test subject": the reconnect-failure
path MUST leave lost-error markers (no-on_error forward non-2xx, reason
``connection_failed``) bound under the continuation handler's own authority.

The tests poll the tree only as test instrumentation — the implementation
under test reacts to subscription-fired continuation advances, never by
polling.
"""

from __future__ import annotations

import asyncio
import socket
import time

from entity_core.capability.grant import create_full_access_grant
from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_core.peer.liveness import (
    STATUS_CONNECTED,
    STATUS_DISCONNECTED,
    peer_status_path,
)
from entity_core.protocol.auth import create_identity_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_handlers.network import (
    NetworkExtension,
    backoff_path,
    on_disconnect_path,
    on_reconnect_path,
)


def _identity_hash(kp: Keypair) -> bytes:
    return create_identity_entity(kp).compute_hash()


def _read_status(peer: Peer, remote_kp: Keypair) -> Entity | None:
    uri = peer.entity_tree.normalize_uri(peer_status_path(_identity_hash(remote_kp)))
    h = peer.entity_tree.get(uri)
    return peer.content_store.get(h) if h is not None else None


async def _wait_for(predicate, timeout: float = 5.0, interval: float = 0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        await asyncio.sleep(interval)
    return predicate()


def _build_lifecycle_peer(kp: Keypair, **keepalive) -> Peer:
    """The reactive stack the graph needs: inbox + continuation +
    subscription (handler + delivery extension) + network."""
    builder = (
        PeerBuilder()
        .with_keypair(kp)
        .with_default_handlers()
        .with_continuation_handler()
        .with_inbox_handler()
        .with_subscription_handler()
        .with_subscription_extension()
        .with_network_handler()
        .debug_mode(True)
    )
    if keepalive:
        builder = builder.with_keepalive_config(**keepalive)
    return builder.build()


def _network_ext(peer: Peer) -> NetworkExtension:
    for ext in peer._extensions:
        if isinstance(ext, NetworkExtension):
            return ext
    raise AssertionError("NetworkExtension not wired")


def _admin_grant(peer: Peer) -> dict:
    """§3.2 admin posture: the local admin drives system/network ops."""
    return {
        "grants": [g.to_dict() for g in create_full_access_grant()],
        "granter": peer.peer_id,
        "grantee": peer.peer_id,
    }


async def _exec_network(peer: Peer, operation: str, data: dict, *, params_type: str):
    return await peer._dispatch_local_execute(
        "system/network",
        operation,
        {"type": params_type, "data": data},
        _admin_grant(peer),
        None,
        None,
        resource_targets=["system/network"],
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _bound_port(peer: Peer) -> int:
    return peer._server.sockets[0].getsockname()[1]


def _lost_marker_uris(peer: Peer) -> list[str]:
    return peer.entity_tree.list_prefix("system/runtime/chain-errors/lost/")


class TestMaintainPeerEstablishesGraph:
    """§4.1 happy path: connect, install the three-continuation graph + two
    lifecycle subscriptions, return session info; idempotent re-entry."""

    def test_graph_installed_and_session_returned(self):
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_lifecycle_peer(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_lifecycle_peer(client_kp)
            try:
                result = await _exec_network(
                    client, "maintain-peer",
                    {
                        "peer_id": server.peer_id,
                        "address": f"127.0.0.1:{_bound_port(server)}",
                    },
                    params_type="system/network/maintain-request",
                )
                assert result.status == 200, result.error
                data = result.result["data"]
                assert data["peer_id"] == server.peer_id
                assert data["session_id"]
                assert data["chain_id"].startswith("network/maintain/")
                assert len(data["subscriptions"]) == 2

                # The graph is in the tree: two inbox residents + the
                # managed-namespace backoff resident, all system/continuation
                # entities carrying the handler grant as dispatch_capability
                # (§11 / the F2 pattern), none routing on_error anywhere
                # (marker-proposal §5: system/inbox/* targets forbidden).
                tree = client.entity_tree
                grant_hash = tree.get(tree.normalize_uri(
                    "system/capability/grants/system/network"
                ))
                assert grant_hash is not None, "network handler grant not bound"
                for path in (
                    on_disconnect_path(server.peer_id),
                    on_reconnect_path(server.peer_id),
                    backoff_path(server.peer_id),
                ):
                    h = tree.get(tree.normalize_uri(path))
                    assert h is not None, f"no continuation bound at {path}"
                    ent = client.content_store.get(h)
                    assert ent.type == "system/continuation", path
                    assert ent.data["dispatch_capability"] == grant_hash, (
                        f"continuation at {path} must ride the handler grant (§11)"
                    )
                    assert "on_error" not in ent.data, (
                        f"continuation at {path} carries on_error — a failed "
                        f"reconnect must bind the §3.10 lost marker instead"
                    )

                # Both ends observe connected (§A3 establish writes).
                status = await _wait_for(lambda: _read_status(client, server_kp))
                assert status.data["status"] == STATUS_CONNECTED

                # Idempotent re-entry: same params, same session.
                again = await _exec_network(
                    client, "maintain-peer",
                    {
                        "peer_id": server.peer_id,
                        "address": f"127.0.0.1:{_bound_port(server)}",
                    },
                    params_type="system/network/maintain-request",
                )
                assert again.status == 200
                assert again.result["data"]["session_id"] == data["session_id"]
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())

    def test_connect_failure_no_graph_no_session(self):
        """First imperative call to an unreachable peer → 502
        connection_failed, no graph, no session (§4.1 step 1)."""
        async def run():
            client_kp, ghost_kp = Keypair.generate(), Keypair.generate()
            ghost_id = ghost_kp.peer_id
            client = _build_lifecycle_peer(client_kp)
            try:
                result = await _exec_network(
                    client, "maintain-peer",
                    {
                        "peer_id": ghost_id,
                        "address": f"127.0.0.1:{_free_port()}",  # nothing listens
                    },
                    params_type="system/network/maintain-request",
                )
                assert result.status == 502, (result.status, result.result)
                assert result.result["data"]["code"] == "connection_failed"
                assert _network_ext(client).get_session(ghost_id) is None, (
                    "failed first maintain-peer left a session behind"
                )
                tree = client.entity_tree
                assert tree.get(
                    tree.normalize_uri(on_disconnect_path(ghost_id))
                ) is None, "failed first maintain-peer installed the graph"
            finally:
                await client.stop()

        asyncio.run(run())


class TestReconnectLifecycle:
    """The rung-3 anchor vector: establish → kill the remote → the floor
    demotes → the graph reconnects through backoff retries against the
    restarted peer → status returns to connected and restore-subscriptions
    ran (§7.2 first half: the seeded dead subscription is dropped). The
    failed attempts leave §3.10 lost-error markers keyed by reason
    ``connection_failed`` — the marker-proposal §4 reconnect-chain evidence."""

    def test_kill_restart_reconnects_and_leaves_markers(self):
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            fixed_port = _free_port()

            server = _build_lifecycle_peer(server_kp)
            await server.start("127.0.0.1", fixed_port)
            # Short §5.4 keepalive so demotion lands within ~1s.
            client = _build_lifecycle_peer(
                client_kp, interval_ms=100, timeout_ms=150, max_missed=1,
            )
            try:
                result = await _exec_network(
                    client, "maintain-peer",
                    {
                        "peer_id": server.peer_id,
                        "address": f"127.0.0.1:{fixed_port}",
                        "backoff": {"min_ms": 100, "max_ms": 400},
                    },
                    params_type="system/network/maintain-request",
                )
                assert result.status == 200, result.error

                # Seed a dead subscription delivering to the remote peer: its
                # token hash resolves to nothing, so §7.2 restoration must
                # drop it after the reconnect.
                dead_sub = Entity(
                    type="system/subscription",
                    data={
                        "subscription_id": "dead-sub-vector",
                        "pattern": "some/watched/path",
                        "events": ["updated"],
                        "deliver_uri": f"entity://{server.peer_id}/system/inbox/x",
                        "deliver_operation": "receive",
                        "subscriber_identity": b"\x00" + b"\x07" * 32,
                        "deliver_token": b"\x00" + b"\x09" * 32,  # not in store
                        "created_at": 0,
                    },
                )
                client.emit_pathway.emit(
                    client.entity_tree.normalize_uri(
                        "system/subscription/dead-sub-vector"
                    ),
                    dead_sub,
                    EmitContext.bootstrap(),
                )

                status = await _wait_for(lambda: _read_status(client, server_kp))
                assert status.data["status"] == STATUS_CONNECTED

                # Kill the server. The client's §5.4 keepalive demotes; the
                # lifecycle subscription fires the on-disconnect continuation.
                await server.stop()
                demoted = await _wait_for(
                    lambda: (
                        (s := _read_status(client, server_kp)) is not None
                        and s.data["status"] != STATUS_CONNECTED
                    ),
                    timeout=10.0,
                )
                assert demoted, "no demotion after killing the remote"

                # The graph retries against a dead address: failed reconnect
                # dispatches land as lost-error markers (no-on_error forward
                # non-2xx, reason connection_failed — the single-rule
                # code-as-reason convention).
                markers = await _wait_for(
                    lambda: [
                        u for u in _lost_marker_uris(client)
                        if "/connection_failed/" in u
                    ],
                    timeout=10.0,
                )
                assert markers, (
                    "failed reconnects left no connection_failed lost marker"
                )
                # Marker coordinate shape (§4 key-convergence input for the
                # cohort pass): reason = connection_failed (code-as-reason);
                # step_index falls back to the continuation-keyed synthesized
                # form because Python's LOCAL notification delivery is an
                # internal dispatch carrying no request_id (the F1 pin's
                # sanctioned fallback: "synthesized key only when the EXECUTE
                # carried none").
                marker_ent = client.content_store.get(
                    client.entity_tree.get(markers[0])
                )
                assert marker_ent.data["reason"] == "connection_failed"
                assert marker_ent.data["code"] == "connection_failed"
                assert marker_ent.data["step_index"] == (
                    f"cont-forward-{on_disconnect_path(server.peer_id)}"
                )

                # Restart the server: same keypair, same port — the retry
                # loop must find it and re-establish without operator help.
                server2 = _build_lifecycle_peer(server_kp)
                await server2.start("127.0.0.1", fixed_port)
                try:
                    reconnected = await _wait_for(
                        lambda: (
                            (s := _read_status(client, server_kp)) is not None
                            and s.data["status"] == STATUS_CONNECTED
                        ),
                        timeout=15.0,
                    )
                    assert reconnected, "never re-established after restart"

                    # The on-reconnect leg fired restore-subscriptions (§7.2
                    # first half): the dead subscription is gone…
                    dropped = await _wait_for(
                        lambda: client.entity_tree.get(
                            client.entity_tree.normalize_uri(
                                "system/subscription/dead-sub-vector"
                            )
                        ) is None,
                        timeout=10.0,
                    )
                    assert dropped, (
                        "restore-subscriptions did not drop the dead "
                        "subscription (token missing → §7.2 dead)"
                    )
                    # …while the two lifecycle subscriptions survived the
                    # outage.
                    live_subs = [
                        u for u in client.entity_tree.list_prefix(
                            "system/subscription/"
                        )
                        if (
                            (h := client.entity_tree.get(u)) is not None
                            and (e := client.content_store.get(h)) is not None
                            and e.type == "system/subscription"
                        )
                    ]
                    assert len(live_subs) == 2, (
                        f"expected the 2 lifecycle subscriptions to survive, "
                        f"found {len(live_subs)}"
                    )

                    # The backoff loop settled: attempt counter reset.
                    sess = _network_ext(client).get_session(server.peer_id)
                    assert sess is not None, "session lost across the outage"
                    assert sess.attempt == 0, (
                        f"attempt counter {sess.attempt} after successful "
                        f"re-establish, want 0"
                    )
                finally:
                    await server2.stop()
            finally:
                await client.stop()
                await server.stop()  # idempotent

        asyncio.run(run())


class TestReleasePeer:
    """§4.2: continuations deleted (real tree deletion), lifecycle
    subscriptions unsubscribed, terminal disconnected write on
    reason=shutdown."""

    def test_release_tears_down_graph(self):
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_lifecycle_peer(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_lifecycle_peer(client_kp)
            try:
                result = await _exec_network(
                    client, "maintain-peer",
                    {
                        "peer_id": server.peer_id,
                        "address": f"127.0.0.1:{_bound_port(server)}",
                    },
                    params_type="system/network/maintain-request",
                )
                assert result.status == 200, result.error

                released = await _exec_network(
                    client, "release-peer",
                    {"peer_id": server.peer_id},
                    params_type="system/network/release-request",
                )
                assert released.status == 200, released.error
                cleaned = released.result["data"]["cleaned_up"]
                expected_paths = {
                    on_disconnect_path(server.peer_id),
                    on_reconnect_path(server.peer_id),
                    backoff_path(server.peer_id),
                }
                assert expected_paths.issubset(set(cleaned)), cleaned

                tree = client.entity_tree
                for path in expected_paths:
                    assert tree.get(tree.normalize_uri(path)) is None, (
                        f"continuation still bound at {path} after release"
                    )
                # Lifecycle subscriptions unsubscribed (self-owned).
                remaining = [
                    u for u in tree.list_prefix("system/subscription/")
                    if (
                        (h := tree.get(u)) is not None
                        and (e := client.content_store.get(h)) is not None
                        and e.type == "system/subscription"
                    )
                ]
                assert remaining == [], (
                    f"lifecycle subscriptions survived release: {remaining}"
                )
                assert _network_ext(client).get_session(server.peer_id) is None

                # Terminal §3.13 write (reason=shutdown default).
                status = await _wait_for(
                    lambda: (
                        (s := _read_status(client, server_kp)) is not None
                        and s.data["status"] == STATUS_DISCONNECTED
                        and s
                    ),
                )
                assert status, "no terminal disconnected write after release"
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())


class TestStatusOp:
    """§4.3: the read-model over the §3.13 entities. pending_count is bare
    zero (no §8 outbox — Amendment 11; rung 4 stays optional)."""

    def test_status_reports_maintained_peer(self):
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _build_lifecycle_peer(server_kp)
            await server.start("127.0.0.1", 0)
            client = _build_lifecycle_peer(client_kp)
            try:
                maintained = await _exec_network(
                    client, "maintain-peer",
                    {
                        "peer_id": server.peer_id,
                        "address": f"127.0.0.1:{_bound_port(server)}",
                    },
                    params_type="system/network/maintain-request",
                )
                assert maintained.status == 200, maintained.error
                session_id = maintained.result["data"]["session_id"]

                result = await _exec_network(
                    client, "status", {}, params_type="primitive/any",
                )
                assert result.status == 200, result.error
                data = result.result["data"]
                assert data["pending_count"] == 0
                rows = [
                    r for r in data["maintained_peers"]
                    if r["peer_id"] == server.peer_id
                ]
                assert rows, f"status omitted maintained peer: {data}"
                assert rows[0]["session_id"] == session_id
                assert rows[0]["status"] == STATUS_CONNECTED
                assert rows[0]["pending_count"] == 0
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())
