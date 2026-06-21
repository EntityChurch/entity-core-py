"""Real two-peer burst delivery test — reproduces F-CIMP-2 regression locally.

Workbench-go's CROSSIMPL feedback memo on the F-CIMP-2 regression
reports two failure
modes when the Python F1b pipeline runs against a real cross-impl
subscriber (workbench-go), neither of which the existing in-process
``fake_execute`` test exercises:

- **Mode A** — N=5 instantaneous burst, ``_subscription_worker`` never
  dispatches (no ``[dispatch:remote]`` log lines).
- **Mode B** — N=50+ instantaneous burst, worker dispatches but all K=16
  concurrent ``conn.execute`` calls fail at the receiver's framework
  layer.

The existing ``TestSingleSubscriptionPipelining`` test used
``fake_execute`` (no real ``Connection``, no real ``RemotePool``), so it
missed both. This file uses two real Python peers wired together via
``Connection`` + ``RemotePool``, exercising:

- Real ``Connection._write_lock`` contention under K concurrent dispatch
- Real ``RemotePool.get_connection`` race during burst (first delivery
  triggers connection establishment; subsequent deliveries hit the cache)
- Real cap validation on the subscriber side
- The full pipelined dispatch path through ``_dispatch_local_execute``

If these tests pass against Python-to-Python but the workbench-go probe
still fails, the divergence is cross-impl (wire-shape / cap-shape
mismatch with Go). If they fail locally, the regression is intrinsic to
Python's substrate (pipeline / pool / cap-cache race).
"""

from __future__ import annotations

import asyncio
import time

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity


# -----------------------------------------------------------------------------
# Two-peer fixture: publisher + subscriber, both running on loopback
# -----------------------------------------------------------------------------


# We verify deliveries via the subscriber's tree state. The default inbox
# handler (from with_all_handlers) stores notifications under
# system/inbox/{subscription_id}/* — we scan that subtree to count
# deliveries that actually landed. This approach has two advantages over a
# custom inbox handler: (1) it exercises the same wire-shape path
# workbench-go's probe uses (default inbox handler at the receiver), and
# (2) it avoids handler-priority shadowing concerns when registering a
# custom handler over the default.


def _count_inbox_deliveries(subscriber, subscription_id: str) -> int:
    """Count entities in the subscriber's tree under
    system/inbox/{subscription_id}/. Each successful delivery writes one
    entity at a request-id-keyed path under that subtree."""
    tree = subscriber.emit_pathway.entity_tree
    inbox_prefix = tree.normalize_uri(f"system/inbox/{subscription_id}/")
    count = 0
    for uri in tree.list_prefix(inbox_prefix):
        if tree.get(uri) is not None:
            count += 1
    return count


@pytest.fixture
async def two_peers():
    """Spin up publisher + subscriber on loopback ports.

    Returns (publisher_peer, subscriber_peer, subscriber_peer_id).
    Both peers use the default handler set (with_all_handlers) so the
    subscriber's inbox uses the same code path workbench-go's probe
    exercises against Python.
    """
    pub_kp = Keypair.generate()
    sub_kp = Keypair.generate()
    pub_port = 19501
    sub_port = 19502

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

    await publisher.start("127.0.0.1", pub_port)
    await subscriber.start("127.0.0.1", sub_port)

    # Register subscriber's transport address on publisher so outbound
    # delivery can resolve the peer ID → endpoint mapping. Uses the §6.5
    # `system/peer/transport/tcp` profile shape (v1.4 Amendment 2).
    publisher.register_remote(
        sub_kp.peer_id, f"127.0.0.1:{sub_port}",
        public_key=sub_kp.public_key_bytes(),
    )

    yield publisher, subscriber, sub_kp.peer_id
    await publisher.stop()
    await subscriber.stop()


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


async def _install_subscription(
    publisher,
    subscriber_peer_id: str,
    pattern: str,
) -> str:
    """Install a subscription on the publisher that delivers to subscriber's
    inbox. Returns the subscription_id.

    Subscription is installed by directly writing the subscription entity
    to the publisher's tree (the same path the subscribe-handler would
    write to). This sidesteps the subscribe authorization path and lets
    us focus on the burst-delivery path.
    """
    from entity_handlers.subscription import SubscriptionEntity
    from entity_core.storage.emit import EmitContext

    subscription_id = f"burst-test-{int(time.time() * 1e6)}"

    # Put a no-expiry deliver token in the publisher's content store.
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
    """Poll subscriber's tree until target deliveries land or timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        count = _count_inbox_deliveries(subscriber, subscription_id)
        if count >= target:
            return count
        await asyncio.sleep(0.02)
    return _count_inbox_deliveries(subscriber, subscription_id)


# -----------------------------------------------------------------------------
# Mode A reproducer — N=5 instantaneous burst, worker should fire
# -----------------------------------------------------------------------------


class TestBurstModeA:
    """N=5 instantaneous burst — Mode A regression seed.

    Workbench-go observed: 5 writes in 11ms, subscription registered, no
    `[dispatch:remote]` log lines, 0/5 delivered. If this reproduces
    locally, the bug is intrinsic to Python's substrate (worker never
    fires under tight-burst lazy-creation race).
    """

    @pytest.mark.asyncio
    async def test_n5_instantaneous_burst_all_delivered(self, two_peers):
        publisher, subscriber, sub_peer_id = two_peers
        from entity_core.storage.emit import EmitContext

        # Narrowed to `data/*` so the count isn't inflated by the
        # `system/peer/session/{peer_id}` write that the publisher's
        # outbound pool emits on first dial (PROPOSAL-TRANSPORT-FAMILY R6
        # — the session entity is a real tree entity and fires events).
        sub_id = await _install_subscription(publisher, sub_peer_id, pattern="data/*")
        # Brief settling time for the subscription index update to land
        # via the InternalHook BEFORE the burst begins. Without this,
        # we'd race the index updater with the first data write.
        await asyncio.sleep(0.05)

        N = 5
        for i in range(N):
            ent = Entity(type="test/payload", data={"i": i})
            publisher.emit_pathway.emit(
                publisher.emit_pathway.entity_tree.normalize_uri(
                    f"data/burst-{i}"
                ),
                ent,
                EmitContext.protocol(author=publisher.peer_id),
            )

        delivered = await _wait_for_count(subscriber, sub_id, N, timeout_s=5.0)
        assert delivered == N, (
            f"F-CIMP-2 Mode A regression: expected {N} deliveries, got "
            f"{delivered} after 5s. Worker likely never dispatched the "
            f"queued events under instantaneous burst.\n"
            f"  Audit: subscription.py::_subscription_worker — the worker "
            f"task is lazily created by _ensure_delivery_worker on the "
            f"FIRST matching event. If subsequent events arrive in the "
            f"same event-loop tick AND the worker is then cancelled (e.g., "
            f"by an early subscription removal via _drop_delivery_worker), "
            f"queued events are lost."
        )


# -----------------------------------------------------------------------------
# Mode B reproducer — N=50 burst, K=16 concurrent dispatch
# -----------------------------------------------------------------------------


class TestBurstModeB:
    """N=50 burst — Mode B regression seed.

    Workbench-go observed: 50 writes in 117ms, worker fires, all 50
    deliveries fail with empty error. wb-go user inbox never entered;
    rejection at framework layer.

    If THIS test passes against Python-to-Python but workbench-go's probe
    still fails, divergence is cross-impl (wb-go decode path or cap-shape
    mismatch with Go). If THIS test fails, the bug is intrinsic to
    Python's substrate (pool race, cap-cache contention, half-open conn).
    """

    @pytest.mark.asyncio
    async def test_n50_burst_all_delivered(self, two_peers):
        publisher, subscriber, sub_peer_id = two_peers
        from entity_core.storage.emit import EmitContext

        # Narrowed to `data/*` so the count isn't inflated by the
        # `system/peer/session/{peer_id}` write that the publisher's
        # outbound pool emits on first dial (PROPOSAL-TRANSPORT-FAMILY R6
        # — the session entity is a real tree entity and fires events).
        sub_id = await _install_subscription(publisher, sub_peer_id, pattern="data/*")
        await asyncio.sleep(0.05)  # settle the subscription index

        N = 50
        for i in range(N):
            ent = Entity(type="test/payload", data={"i": i})
            publisher.emit_pathway.emit(
                publisher.emit_pathway.entity_tree.normalize_uri(
                    f"data/burst-{i}"
                ),
                ent,
                EmitContext.protocol(author=publisher.peer_id),
            )

        delivered = await _wait_for_count(subscriber, sub_id, N, timeout_s=10.0)
        assert delivered >= N * 0.95, (
            f"F-CIMP-2 Mode B regression: expected ≥{int(N * 0.95)} "
            f"deliveries (95%); got {delivered}/{N} after 10s. "
            f"Under K=16 concurrent dispatch, some / all RPCs fail.\n"
            f"  Audit: subscription.py::_deliver_notification → "
            f"ctx.execute → _remote_pool.get_connection → conn.execute. "
            f"Check the failure log shape (status + body) added by the "
            f"F-CIMP-2 diagnostic instrumentation."
        )


# -----------------------------------------------------------------------------
# Working baseline (positive control): 20/sec inter-arrival
# -----------------------------------------------------------------------------


class TestBurstBaseline:
    """Workbench-go baseline that worked: 50 writes at 50ms inter-arrival
    (20/sec). If pipelining is broken at all, this still works because
    each RPC completes before the next event arrives.
    """

    @pytest.mark.asyncio
    async def test_n50_at_20_per_sec_all_delivered(self, two_peers):
        publisher, subscriber, sub_peer_id = two_peers
        from entity_core.storage.emit import EmitContext

        # Narrowed to `data/*` so the count isn't inflated by the
        # `system/peer/session/{peer_id}` write that the publisher's
        # outbound pool emits on first dial (PROPOSAL-TRANSPORT-FAMILY R6
        # — the session entity is a real tree entity and fires events).
        sub_id = await _install_subscription(publisher, sub_peer_id, pattern="data/*")
        await asyncio.sleep(0.05)

        N = 50
        for i in range(N):
            ent = Entity(type="test/payload", data={"i": i})
            publisher.emit_pathway.emit(
                publisher.emit_pathway.entity_tree.normalize_uri(
                    f"data/burst-{i}"
                ),
                ent,
                EmitContext.protocol(author=publisher.peer_id),
            )
            await asyncio.sleep(0.05)  # 20/sec inter-arrival

        delivered = await _wait_for_count(subscriber, sub_id, N, timeout_s=5.0)
        assert delivered == N, (
            f"Baseline regression: expected {N} deliveries at 20/sec "
            f"inter-arrival; got {delivered}. Even non-pipelined serial "
            f"delivery should hit 100% at this rate. Check whether the "
            f"basic delivery path is broken."
        )
