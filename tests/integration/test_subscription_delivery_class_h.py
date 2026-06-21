"""Class H pin tests for EXTENSION-SUBSCRIPTION v3.15 §5.2 / §11.2.

These tests are regression-blockers for the Stage 5 cycle's F1 fix
(parallel cross-subscription delivery via per-subscription drainer tasks).
They are also the Python-side portable fixture for the cross-impl Class H
audit prompt — Go's ``perfreview/saturation_multipeer_test.go`` is the
canonical reference shape; this file lives in the integration suite so the
contract is enforced on every CI run, not gated behind a perf tag.

Two contracts under test:

1. **Within-subscription ordering (§5.2 MUST).** For a single subscription,
   notifications arrive in tree-change order. A single per-subscription
   drainer task is the mechanism — racing tasks across events would
   reorder.

2. **Cross-subscription parallelism (§11.2 SHOULD; F1 fix).** When N
   subscribers match a single event, fan-out is non-blocking and the N
   deliveries proceed concurrently. Pre-fix shape (single ``_on_tree_change``
   task awaiting each delivery serially) would degrade per-subscriber
   throughput as 1/N; this test fails fast on that regression.

If either test fails after a delivery-path refactor, F1 has likely
re-entered Python. Read the failure message — it names the spec section and
file:line under audit.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult
from entity_core.peer.extensions import ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.utils.ecf import ALG_ECFV1_SHA256

from entity_handlers.subscription import (
    SubscriptionEntity,
    SubscriptionExtension,
)


HASH_IDENTITY = bytes([ALG_ECFV1_SHA256]) + b"identy" + b"\x00" * 26


@dataclass
class _DeliveryRecord:
    """One observed delivery call to ``ctx.execute``."""

    subscription_id: str
    event_uri: str
    started_at: float
    finished_at: float


def _put_token(content_store: ContentStore) -> bytes:
    """Put a no-expiry deliver token entity; return its hash.

    The subscription extension's ``_validate_deliver_token`` reads
    ``expires_at`` from the token entity; absence means "never expires".
    """
    token = Entity(type="system/capability/token", data={"grants": []})
    content_store.put(token)
    return token.compute_hash()


def _make_subscription(
    subscription_id: str, deliver_token_hash: bytes, pattern: str = "*"
) -> SubscriptionEntity:
    return SubscriptionEntity(
        subscription_id=subscription_id,
        pattern=pattern,
        events=["created", "updated", "deleted"],
        deliver_uri=f"entity://peer/inbox/{subscription_id}",
        deliver_operation="receive",
        subscriber_identity=HASH_IDENTITY,
        deliver_token=deliver_token_hash,
        created_at=int(time.time() * 1000),
    )


def _install_subscription(
    emit: EmitPathway,
    keypair: Keypair,
    subscription: SubscriptionEntity,
) -> None:
    """Emit a subscription entity so the internal hook indexes it."""
    sub_entity = Entity(type=SubscriptionEntity.TYPE, data=subscription.to_dict())
    uri = emit.entity_tree.normalize_uri(
        f"system/subscription/{subscription.subscription_id}"
    )
    emit.emit(uri, sub_entity, EmitContext.protocol(author=keypair.peer_id))


@pytest.fixture
def harness():
    """SubscriptionExtension wired with an instrumented ``ctx.execute`` stub.

    The stub records the order and timing of each delivery so the §5.2
    ordering MUST and the §11.2 / Class H F1 parallelism SHOULD can be
    asserted without a real peer transport.
    """
    keypair = Keypair.generate()
    content_store = ContentStore()
    entity_tree = EntityTree(keypair.peer_id)
    emit = EmitPathway(content_store, entity_tree)

    records: list[_DeliveryRecord] = []
    # The stub coroutine is set by each test (default: instant).
    delay_for_subscription: dict[str, float] = {}

    async def fake_execute(
        uri: str,
        operation: str,
        params,
        resource_targets=None,
        bounds=None,
        included=None,
        **kwargs,
    ) -> ExecuteResult:
        # subscription_id is in the params (InboxNotification.to_dict).
        sub_id = ""
        if isinstance(params, dict):
            data = params.get("data") if isinstance(params.get("data"), dict) else params
            if isinstance(data, dict):
                sub_id = data.get("subscription_id", "")
        event_uri = ""
        if isinstance(params, dict):
            data = params.get("data") if isinstance(params.get("data"), dict) else params
            if isinstance(data, dict):
                event_uri = data.get("uri", "")
        started = time.monotonic()
        delay = delay_for_subscription.get(sub_id, 0.0)
        if delay > 0:
            await asyncio.sleep(delay)
        finished = time.monotonic()
        records.append(
            _DeliveryRecord(
                subscription_id=sub_id,
                event_uri=event_uri,
                started_at=started,
                finished_at=finished,
            )
        )
        return ExecuteResult(
            ok=True,
            status=200,
            result={"type": "system/protocol/execute/response", "data": {}},
        )

    extension = SubscriptionExtension()
    ctx = ExtensionContext(keypair=keypair, emit_pathway=emit, execute=fake_execute)
    extension.initialize(ctx)

    yield extension, emit, keypair, records, delay_for_subscription
    extension.shutdown()


async def _drain(extension: SubscriptionExtension, expected: int, timeout: float = 5.0) -> None:
    """Wait until at least ``expected`` deliveries have completed.

    Polls the per-subscription queues + delivery records to bound the wait
    without timing-sensitive sleeps. Raises if the budget elapses.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        # Sum across all delivery queues — drained when all are empty
        # AND we've seen the expected count of records.
        all_empty = all(q.empty() for q in extension._delivery_queues.values())
        # Records is the source of truth; queues empty alone isn't enough
        # because the worker may still be in-flight on an await.
        # Caller compares records length itself; this helper just yields
        # to the loop so workers make progress.
        if all_empty:
            await asyncio.sleep(0.01)
            if all_empty and all(q.empty() for q in extension._delivery_queues.values()):
                return
        await asyncio.sleep(0.01)


class TestWithinSubscriptionOrdering:
    """§5.2 (v3.15) MUST: per-subscription delivery is tree-change-ordered."""

    @pytest.mark.asyncio
    async def test_single_subscription_sees_events_in_order(self, harness):
        """Ten writes to the same path → ten deliveries in the same order.

        Regression-blocker for §5.2 within-subscription ordering. If a
        future refactor races deliveries across events (e.g., spawning a
        task per event without the per-sub queue), this assertion fires.
        """
        extension, emit, keypair, records, delays = harness
        token_hash = _put_token(emit.content_store)
        _install_subscription(
            emit, keypair, _make_subscription("sub-order", token_hash)
        )
        # 20ms per delivery forces every delivery to suspend on the event
        # loop. Without this, instant deliveries can mask a per-event-task
        # race that would otherwise reorder when each task suspends. The
        # spec MUST is for tree-change order; this delay is what makes the
        # test a regression-blocker against future refactors that spawn a
        # task per event without a per-subscription serializing queue.
        delays["sub-order"] = 0.02

        # Publish 10 entities at distinct paths so each emit is non-no-op.
        paths = [f"data/item-{i}" for i in range(10)]
        for path in paths:
            ent = Entity(type="test/payload", data={"i": path[-1]})
            emit.emit(
                emit.entity_tree.normalize_uri(path),
                ent,
                EmitContext.protocol(author=keypair.peer_id),
            )

        # Wait until all 10 are delivered.
        deadline = time.monotonic() + 5.0
        while len(records) < 10 and time.monotonic() < deadline:
            await asyncio.sleep(0.01)

        assert len(records) == 10, (
            f"EXTENSION-SUBSCRIPTION v3.15 §5.2: expected 10 in-order "
            f"deliveries; got {len(records)}"
        )
        observed_paths = [r.event_uri for r in records]
        expected_uris = [emit.entity_tree.normalize_uri(p) for p in paths]
        assert observed_paths == expected_uris, (
            "EXTENSION-SUBSCRIPTION v3.15 §5.2 MUST violated: "
            "within-subscription deliveries are not in tree-change order.\n"
            "  Audit: packages/entity-handlers/src/entity_handlers/subscription.py"
            " (per-subscription drainer task / FIFO queue)\n"
            f"  expected: {expected_uris}\n"
            f"  observed: {observed_paths}"
        )


class TestCrossSubscriptionParallelism:
    """§11.2 (v3.15) / Class H F1: parallel cross-subscription delivery."""

    @pytest.mark.asyncio
    async def test_n_subscribers_deliver_in_parallel_not_serial(self, harness):
        """One publish to N=4 matching subscribers → ~1× delivery latency.

        The fake_execute stub sleeps 200ms per delivery. Pre-fix shape
        (serial await inside one ``_on_tree_change`` coroutine) would take
        ~800ms wall-clock for 4 deliveries — that's the 1/N degradation
        workbench-go's saturation probe measured in core-go. Post-fix
        (per-subscription drainer tasks) should complete in ~200ms +
        overhead. Budget is 3× per-delivery (600ms) — well clear of both
        the post-fix (~250ms) and the pre-fix (~800ms) profiles.

        FAILURE MESSAGE names the spec section and audit file so future
        bisects land on the right code path.
        """
        extension, emit, keypair, records, delays = harness
        token_hash = _put_token(emit.content_store)
        n = 4
        per_delivery_s = 0.2
        for i in range(n):
            sid = f"sub-parallel-{i}"
            delays[sid] = per_delivery_s
            _install_subscription(emit, keypair, _make_subscription(sid, token_hash))

        # One publish event matching all N subscriptions.
        ent = Entity(type="test/payload", data={"x": 1})
        t0 = time.monotonic()
        emit.emit(
            emit.entity_tree.normalize_uri("data/fanout"),
            ent,
            EmitContext.protocol(author=keypair.peer_id),
        )

        # Wait until all N deliveries are complete (or budget blows).
        budget_s = per_delivery_s * 3  # 600ms — well below 4×serial 800ms
        deadline = time.monotonic() + budget_s + 0.5
        while len(records) < n and time.monotonic() < deadline:
            await asyncio.sleep(0.005)

        elapsed_s = time.monotonic() - t0
        assert len(records) == n, (
            f"Class H F1 / EXTENSION-SUBSCRIPTION v3.15 §11.2: "
            f"expected {n} parallel deliveries; got {len(records)} in "
            f"{elapsed_s:.3f}s (budget {budget_s:.3f}s).\n"
            f"  Audit: packages/entity-handlers/src/entity_handlers/"
            f"subscription.py (per-subscription delivery worker)"
        )
        serial_s = per_delivery_s * n
        assert elapsed_s < budget_s, (
            f"Class H F1 / EXTENSION-SUBSCRIPTION v3.15 §11.2 regression: "
            f"4 subscribers took {elapsed_s:.3f}s — close to the {serial_s:.3f}s "
            f"serial-await profile (1/N degradation). Expected < {budget_s:.3f}s "
            f"under per-subscription parallel delivery.\n"
            f"  Audit: packages/entity-handlers/src/entity_handlers/"
            f"subscription.py::SubscriptionExtension._on_tree_change / "
            f"_subscription_worker"
        )

    @pytest.mark.asyncio
    async def test_slow_subscriber_does_not_block_fast_subscriber(self, harness):
        """A slow subscription must not gate deliveries to a fast peer.

        This is the cross-subscription isolation contract beyond F1: even
        if N=2 are dispatched, they must run on independent workers so a
        500ms-per-delivery subscriber can't queue up behind itself and
        starve a fast peer. Without per-subscription queues + workers, a
        single ``_on_tree_change`` task's per-event iteration would still
        serialize fast-behind-slow.
        """
        extension, emit, keypair, records, delays = harness
        token_hash = _put_token(emit.content_store)
        delays["sub-slow"] = 0.5
        delays["sub-fast"] = 0.0
        _install_subscription(
            emit, keypair, _make_subscription("sub-slow", token_hash)
        )
        _install_subscription(
            emit, keypair, _make_subscription("sub-fast", token_hash)
        )

        ent = Entity(type="test/payload", data={"x": 1})
        t0 = time.monotonic()
        emit.emit(
            emit.entity_tree.normalize_uri("data/once"),
            ent,
            EmitContext.protocol(author=keypair.peer_id),
        )

        # Wait until the fast subscriber's delivery records (should be
        # near-instant, well under the slow subscriber's 500ms).
        deadline = time.monotonic() + 0.3
        while time.monotonic() < deadline:
            if any(r.subscription_id == "sub-fast" for r in records):
                break
            await asyncio.sleep(0.005)

        fast_records = [r for r in records if r.subscription_id == "sub-fast"]
        elapsed_when_fast_done = (
            (fast_records[0].finished_at - t0) if fast_records else float("inf")
        )
        assert fast_records, (
            "Class H F1 isolation regression: fast subscriber's delivery "
            "did not arrive within 300ms; slow subscriber appears to be "
            "head-of-line-blocking.\n"
            "  Audit: packages/entity-handlers/src/entity_handlers/"
            "subscription.py::_on_tree_change (must enqueue + return, not "
            "await each delivery in sequence)"
        )
        assert elapsed_when_fast_done < 0.3, (
            f"Class H F1 isolation regression: fast subscriber delivered "
            f"after {elapsed_when_fast_done:.3f}s — slow subscriber "
            f"head-of-line-blocked it."
        )


class TestPipelinedSendOrder:
    """F-CIMP-2 / Class H F1b — §5.2 send-order under pipeline pressure.

    The pipelined drainer (`asyncio.Semaphore` + `asyncio.create_task`)
    relies on a load-bearing **sync-chain property**: all K in-flight
    tasks for one subscription must reach
    ``Connection._write_lock.acquire()`` in creation order. The chain
    that guarantees this in steady state:

    1. ``asyncio.create_task`` schedules tasks FIFO on the event loop's
       ready deque.
    2. Each task runs sync from entry through ``_deliver_notification``
       to ``await self._ctx.execute(...)`` — no real yield.
    3. ``ctx.execute`` → ``_execute_dispatcher`` → ``_dispatch_local_execute``
       → ``await self._remote_execute(...)`` — sync chain of async calls,
       no yield until ``_remote_execute`` body.
    4. ``_remote_execute`` body sync to
       ``await self._remote_pool.get_connection(peer_id)``. In
       steady-state cached-connection mode, the pool's cache-hit returns
       synchronously without yielding to the event loop (Python's
       ``await coro_no_yield`` does not round-trip).
    5. ``conn.execute`` body sync to ``async with self._write_lock`` —
       the first real suspension point, which serializes wire bytes
       FIFO.

    Cold-start ordering is also preserved: the pool's
    ``async with self._lock`` (``remote.py:92``) serializes connection
    establishment FIFO, so even when the first delivery to a peer is
    in flight, tasks 2..N wait FIFO on the pool lock and then see the
    cache hit on retry.

    Workbench-go's perf-stress probe substance-check
    flagged the load-bearing property: any future refactor introducing a
    real-yield await between task entry and write_lock.acquire BREAKS
    this ordering and MUST add explicit per-subscription send-order
    serialization. This test catches that regression directly by
    randomizing per-delivery completion latency so the in-flight tasks
    finish in **non-creation order**, then asserting the dispatch order
    (captured at ``ctx.execute`` entry, BEFORE any delay) still matches
    the publish order.

    If this test fails, the sync chain has grown a yield. Read the
    failure message — it names the diagnostic primitive.
    """

    @pytest.mark.asyncio
    async def test_dispatch_order_under_randomized_completion(self):
        """Publish N events; each fake_execute call records its index at
        entry (= dispatch time), then sleeps a randomized 1-30ms. With
        K=16 in-flight, completion order is randomized but dispatch
        order MUST equal publish order.
        """
        import random

        keypair = Keypair.generate()
        content_store = ContentStore()
        entity_tree = EntityTree(keypair.peer_id)
        emit = EmitPathway(content_store, entity_tree)

        dispatch_order: list[int] = []  # records at fake_execute ENTRY
        completion_order: list[int] = []  # records after the delay
        rng = random.Random(20260601)

        async def fake_execute(
            uri, operation, params, resource_targets=None, bounds=None,
            included=None, **kwargs,
        ) -> ExecuteResult:
            # Extract event-id from the InboxNotification's `uri` field —
            # the publisher tagged each event with `data/item-{i}`.
            event_uri = ""
            if isinstance(params, dict):
                data = params.get("data") if isinstance(params.get("data"), dict) else params
                if isinstance(data, dict):
                    event_uri = data.get("uri", "")
            # event_uri ends with "/data/item-{i}" — pull the integer
            try:
                idx = int(event_uri.rsplit("-", 1)[1])
            except (IndexError, ValueError):
                idx = -1
            # CRITICAL: capture dispatch order BEFORE the await — this
            # records the order in which write_lock.acquire would fire
            # under the real Connection path.
            dispatch_order.append(idx)
            await asyncio.sleep(rng.uniform(0.001, 0.030))
            completion_order.append(idx)
            return ExecuteResult(
                status=200,
                result={"type": "system/protocol/execute/response", "data": {}},
            )

        extension = SubscriptionExtension()
        ctx = ExtensionContext(
            keypair=keypair, emit_pathway=emit, execute=fake_execute
        )
        extension.initialize(ctx)
        try:
            token_hash = _put_token(content_store)
            _install_subscription(
                emit, keypair, _make_subscription("sub-order-pressure", token_hash)
            )

            N = 50
            for i in range(N):
                ent = Entity(type="test/payload", data={"i": i})
                emit.emit(
                    emit.entity_tree.normalize_uri(f"data/item-{i}"),
                    ent,
                    EmitContext.protocol(author=keypair.peer_id),
                )

            # Wait for all completions (well past worst-case 30ms × N / K)
            deadline = time.monotonic() + 5.0
            while len(completion_order) < N and time.monotonic() < deadline:
                await asyncio.sleep(0.005)

            assert len(dispatch_order) == N, (
                f"Expected {N} dispatches; got {len(dispatch_order)}"
            )
            assert dispatch_order == list(range(N)), (
                f"F-CIMP-2 / Class H F1b SYNC-CHAIN regression — dispatch order "
                f"diverged from publish order.\n"
                f"  Publish order:  {list(range(N))}\n"
                f"  Dispatch order: {dispatch_order}\n"
                f"  Mismatch implies the sync chain from task entry to "
                f"write_lock.acquire grew a real-yield await.\n"
                f"  Audit: trace the await chain from _subscription_worker → "
                f"_deliver_notification → ctx.execute → _dispatch_local_execute "
                f"→ _remote_execute → RemoteConnectionPool.get_connection → "
                f"conn.execute → write_lock.acquire. If a real yield landed "
                f"in any of those without compensating serialization, add a "
                f"per-subscription dispatch_lock held until write_lock is "
                f"acquired.\n"
                f"  See: subscription.py::_subscription_worker docstring + "
                f"this test class's docstring for the proof chain."
            )
            # Completion order should be randomized (probabilistic — with
            # N=50 + uniform 1-30ms delay + K=16 inflight, the probability
            # of dispatch_order == completion_order is ≪ 0.001%).
            assert completion_order != dispatch_order, (
                "Pipelining diagnostic: completion order equals dispatch "
                "order — randomized delay produced sorted completions. "
                "Either K=1 (pipelining broken — would manifest as throughput "
                "regression too) or the rng seeded a degenerate sequence. "
                "Re-seed the test if rng changed."
            )
        finally:
            extension.shutdown()


class TestSingleSubscriptionPipelining:
    """F-CIMP-2 / Class H F1b: per-subscription in-flight pipelining.

    Workbench-go's perf-stress probe §2.2 surfaced
    Python delivering 6% of 1000 events under a 518/sec publish rate when
    one subscription matched all writes. Root cause: the Stage 5 F1
    drainer was strict-serial-await-per-delivery, bounding throughput to
    1/RPC_latency per subscription (~200/sec at 5ms cross-peer roundtrip).

    The F1b fix pipelines up to ``per_subscription_inflight`` deliveries
    concurrently per subscription while preserving §5.2 ordering: the FIFO
    queue + FIFO semaphore + per-connection ``_write_lock`` guarantee
    that the wire send order is the tree-change order. This test enforces
    that the throughput cliff has lifted.

    Failure indicates either F1b regressed (back to serial-await), or the
    inflight default has dropped below the cliff threshold. Read the
    failure message — it names the spec section and the audit file.
    """

    @pytest.mark.asyncio
    async def test_single_subscription_high_throughput(self, harness):
        """100 events with 10ms per-delivery latency: serial would take
        ≥1.0s; pipelined (K=16) should complete in ~70ms (100/16 batches
        × 10ms each, plus overhead).

        Budget is 400ms — well clear of the 70ms post-fix profile but
        well below the 1000ms strict-serial profile. Sized to catch the
        regression without flakiness on a loaded CI runner.
        """
        extension, emit, keypair, records, delays = harness
        token_hash = _put_token(emit.content_store)
        _install_subscription(
            emit, keypair, _make_subscription("sub-throughput", token_hash)
        )
        # 10ms per delivery — the per-RPC cost on a healthy cross-peer link.
        # Under serial-await, 100 events = ≥1.0s. Under K=16 pipelining,
        # ~7 batches × 10ms = ~70ms.
        delays["sub-throughput"] = 0.01

        N = 100
        for i in range(N):
            ent = Entity(type="test/payload", data={"i": i})
            emit.emit(
                emit.entity_tree.normalize_uri(f"data/item-{i}"),
                ent,
                EmitContext.protocol(author=keypair.peer_id),
            )

        t0 = time.monotonic()
        deadline = t0 + 2.0
        while len(records) < N and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        elapsed = time.monotonic() - t0

        assert len(records) == N, (
            f"F-CIMP-2 / Class H F1b: expected {N} deliveries; got "
            f"{len(records)} in {elapsed:.3f}s. Pipeline broken or "
            f"throughput regression. See subscription.py "
            f"_subscription_worker."
        )
        # Serial-await profile would be N * 10ms = 1000ms. Anything close
        # to that means pipelining regressed. Budget 400ms gives headroom
        # for asyncio scheduling jitter while still catching the cliff.
        serial_s = N * 0.01
        assert elapsed < 0.4, (
            f"F-CIMP-2 / Class H F1b regression: 100 deliveries took "
            f"{elapsed*1000:.0f}ms — close to the {serial_s*1000:.0f}ms "
            f"strict-serial profile. Pipelining appears broken.\n"
            f"  Audit: packages/entity-handlers/src/entity_handlers/"
            f"subscription.py::_subscription_worker (the asyncio.Semaphore "
            f"+ asyncio.create_task pipeline)\n"
            f"  Workbench-go probe: CROSSIMPL-PERF-STRESS §2.2"
        )
