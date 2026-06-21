"""R1 gate — cross-peer subscription delivery over HTTP.

PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY-AND-SESSION-LIFECYCLE §7.3
(Round-2 LOCKED): the single-peer-local subscription pass
does NOT pin Amendment 7's reachability claim. This file does:
publisher and subscriber are two distinct peers each running only
``HttpServer`` (no TCP listener); the publisher dispatches notifications
to the subscriber's HTTP listener via a fresh outbound POST, and the
subscriber drains its own ``system/inbox`` tree.

Validates:
- R1 multi-profile outbound: ``RemoteConnectionPool.get_connection``
  walks the HTTP profile and returns an ``HttpConnection``.
- ``HttpConnection.execute`` accepts ``capability_override`` /
  ``deliver_token_*`` (the per-delivery back-direction cap, INBOX §2).
- End-to-end subscription delivery has no TCP dependency.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext


def _count_inbox_deliveries(subscriber, subscription_id: str) -> int:
    tree = subscriber.emit_pathway.entity_tree
    prefix = tree.normalize_uri(f"system/inbox/{subscription_id}/")
    return sum(1 for uri in tree.list_prefix(prefix) if tree.get(uri) is not None)


async def _install_subscription(
    publisher, subscriber_peer_id: str, pattern: str
) -> str:
    """Write a subscription entity directly onto the publisher's tree —
    same shape the subscribe handler would land. Sidesteps the
    subscribe authorization path and focuses the test on delivery."""
    from entity_handlers.subscription import SubscriptionEntity

    subscription_id = f"http-xpeer-{int(time.time() * 1e6)}"

    token = Entity(type="system/capability/token", data={"grants": []})
    publisher.emit_pathway.content_store.put(token)
    token_hash = token.compute_hash()

    sub = SubscriptionEntity(
        subscription_id=subscription_id,
        pattern=pattern,
        events=["created", "updated", "deleted"],
        deliver_uri=f"entity://{subscriber_peer_id}/system/inbox/{subscription_id}",
        deliver_operation="receive",
        subscriber_identity=bytes([0x00]) + b"\x00" * 32,
        deliver_token=token_hash,
        created_at=int(time.time() * 1000),
    )
    sub_entity = Entity(type=SubscriptionEntity.TYPE, data=sub.to_dict())
    sub_uri = publisher.emit_pathway.entity_tree.normalize_uri(
        f"system/subscription/{subscription_id}"
    )
    publisher.emit_pathway.emit(
        sub_uri, sub_entity, EmitContext.protocol(author=publisher.peer_id)
    )
    return subscription_id


async def _wait_for_count(
    subscriber, subscription_id: str, target: int, timeout_s: float = 5.0
) -> int:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        n = _count_inbox_deliveries(subscriber, subscription_id)
        if n >= target:
            return n
        await asyncio.sleep(0.02)
    return _count_inbox_deliveries(subscriber, subscription_id)


@pytest.fixture
async def http_only_peer_pair():
    """Two peers each running ONLY an HTTP listener (no TCP). The
    publisher learns the subscriber's HTTP profile so outbound delivery
    resolves through the HTTP transport, not TCP."""
    pub_kp = Keypair.generate()
    sub_kp = Keypair.generate()

    publisher = (
        PeerBuilder()
        .with_keypair(pub_kp)
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    subscriber = (
        PeerBuilder()
        .with_keypair(sub_kp)
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )

    pub_http = await publisher.start_http("127.0.0.1", 0)
    sub_http = await subscriber.start_http("127.0.0.1", 0)

    sub_bind = sub_http.bound_socket()
    assert sub_bind is not None
    sub_host, sub_port = sub_bind
    sub_url = f"http://{sub_host}:{sub_port}/entity"

    publisher.register_remote_http(
        sub_kp.peer_id, sub_url,
        public_key=sub_kp.public_key_bytes(),
    )

    yield publisher, subscriber, sub_kp.peer_id

    await pub_http.stop()
    await sub_http.stop()


class TestCrossPeerSubscriptionOverHttp:

    @pytest.mark.asyncio
    async def test_small_burst_delivered_over_http(self, http_only_peer_pair):
        """Five entities emitted on the publisher land on the subscriber's
        HTTP-served inbox — no TCP path involved."""
        publisher, subscriber, sub_peer_id = http_only_peer_pair

        # Narrowed to `data/*` so the count isn't inflated by the
        # `system/peer/session/{peer_id}` write that the publisher's
        # outbound pool emits on first dial (PROPOSAL-TRANSPORT-FAMILY R6
        # — the session entity is a real tree entity and fires events).
        sub_id = await _install_subscription(publisher, sub_peer_id, pattern="data/*")
        await asyncio.sleep(0.05)  # let the subscription index settle

        N = 5
        for i in range(N):
            publisher.emit_pathway.emit(
                publisher.emit_pathway.entity_tree.normalize_uri(
                    f"data/http-xpeer-{i}"
                ),
                Entity(type="test/payload", data={"i": i}),
                EmitContext.protocol(author=publisher.peer_id),
            )

        delivered = await _wait_for_count(subscriber, sub_id, N, timeout_s=5.0)
        assert delivered == N, (
            f"expected {N} deliveries over HTTP; got {delivered}. "
            f"Outbound dispatch did not reach the subscriber's HTTP "
            f"listener — check RemoteConnectionPool.get_connection picked "
            f"the http profile, and HttpConnection.execute carried the "
            f"deliver_token through (INBOX §2 / R1)."
        )

    @pytest.mark.asyncio
    async def test_publisher_pool_holds_http_endpoint(self, http_only_peer_pair):
        """After a delivery completes, the publisher's outbound pool holds
        an HttpConnection (not a TCP Connection) for the subscriber."""
        from entity_core.peer.http_client import HttpConnection

        publisher, subscriber, sub_peer_id = http_only_peer_pair

        # Narrowed to `data/*` so the count isn't inflated by the
        # `system/peer/session/{peer_id}` write that the publisher's
        # outbound pool emits on first dial (PROPOSAL-TRANSPORT-FAMILY R6
        # — the session entity is a real tree entity and fires events).
        sub_id = await _install_subscription(publisher, sub_peer_id, pattern="data/*")
        await asyncio.sleep(0.05)

        publisher.emit_pathway.emit(
            publisher.emit_pathway.entity_tree.normalize_uri("data/probe-0"),
            Entity(type="test/payload", data={"i": 0}),
            EmitContext.protocol(author=publisher.peer_id),
        )
        await _wait_for_count(subscriber, sub_id, 1, timeout_s=5.0)

        pooled = publisher._remote_pool._connections.get(sub_peer_id)
        assert pooled is not None, "publisher pool missing subscriber entry"
        assert isinstance(pooled, HttpConnection), (
            f"pool resolved a non-HTTP endpoint: {type(pooled).__name__}; "
            f"R1 multi-profile outbound failed to select the http profile"
        )
