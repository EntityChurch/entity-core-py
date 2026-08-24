"""Change notification — `SDK-OPERATIONS` v0.8 §6, against a real peer.

Events are driven by real writes through the real dispatcher, so what is under
test is the actual emit pathway and not a hand-fed queue. §6.1-6.2 are the last
two entries on the §16.1 MUST list; §6.3 and §6.5 are the §16.2 SHOULD that
comes with them.
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.sdk import HandlerContextDispatcher

from entity_sdk import (
    BadRequest,
    ChangeEvent,
    EntityClient,
    LocalStore,
    TreeChangeEvent,
    validate_watch_pattern,
)

BLANKET = {
    "grants": [
        {
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }
    ]
}


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


@pytest.fixture
def client(peer) -> EntityClient:
    ctx = HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=BLANKET,
        caller_capability=BLANKET,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
    )
    return EntityClient.for_peer(peer, HandlerContextDispatcher(ctx))


async def _settle() -> None:
    """Let Phase-2 async delivery run.

    §6 delivery is Phase 2 (SYSTEM-COMPOSITION §1.3) — listeners are scheduled
    with ``create_task`` and never block the write. So a test that writes and
    immediately asserts is racing the spec, not the implementation.
    """
    for _ in range(3):
        await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# §6.1 pattern grammar — "two forms only"
# ---------------------------------------------------------------------------


class TestPatternGrammar:
    @pytest.mark.parametrize(
        "pattern",
        ["knowledge/articles/intro", "docs/x", "knowledge/articles/*", "docs/*"],
    )
    def test_the_two_specified_forms_are_accepted(self, pattern):
        validate_watch_pattern(pattern)

    @pytest.mark.parametrize(
        "pattern",
        [
            "knowledge/*/intro",  # interior wildcard — §6.1 reserves it
            "a/*/b/*",
            "*/intro",
            "doc*",  # partial-segment glob is not a form either
        ],
    )
    def test_unspecified_forms_are_rejected_with_400(self, pattern):
        """The peer would accept these and never match them — silently.

        `emit._pattern_matches` handles `*`, `prefix/*` and exact, and falls
        through to an exact string compare for anything else. So an interior
        wildcard registers happily and matches nothing for the life of the
        process. This is the case the SDK exists to convert into an error.
        """
        with pytest.raises(BadRequest) as exc:
            validate_watch_pattern(pattern)
        assert exc.value.status == 400
        assert exc.value.code == "invalid_pattern"

    def test_bare_star_is_redirected_to_the_designated_primitive(self):
        with pytest.raises(BadRequest) as exc:
            validate_watch_pattern("*")
        assert "subscribe_events" in str(exc.value)

    def test_empty_pattern_is_rejected(self):
        with pytest.raises(BadRequest):
            validate_watch_pattern("")

    async def test_client_watch_rejects_before_subscribing(self, client):
        with pytest.raises(BadRequest):
            client.watch("a/*/b")

    async def test_the_peer_really_does_accept_and_never_match(self, peer):
        """Pins the peer behaviour that justifies the SDK-side check.

        The rest of this class asserts the SDK *rejects* interior wildcards.
        That is only worth doing if the layer underneath would have accepted
        them silently — otherwise the validator is duplicated work. This test
        makes that premise a measured fact rather than a claim in a docstring,
        and it fails loudly if the peer ever starts rejecting (or supporting)
        the form, which is the moment to revisit the SDK check.
        """
        from entity_core.protocol.entity import Entity
        from entity_core.storage.emit import EmitContext

        received: list[object] = []

        class Listener:
            async def on_change(self, event):
                received.append(event)

        listener = Listener()
        # No exception: the emit pathway takes the reserved form happily.
        peer.emit_pathway.subscribe("docs/*/intro", listener)

        for path in ("docs/a/intro", "docs/intro", "docs/a/b/intro"):
            peer.emit_pathway.emit(
                path,
                Entity(type="primitive/any", data={}),
                EmitContext.bootstrap(),
            )
        await _settle()

        assert received == [], (
            "the peer matched an interior-wildcard pattern — the SDK's 400 may "
            "no longer be the right call; re-read §6.1"
        )


# ---------------------------------------------------------------------------
# §6.1 watch
# ---------------------------------------------------------------------------


class TestWatch:
    async def test_exact_pattern_delivers_a_put(self, client):
        stream = client.watch("docs/intro")
        await client.put("docs/intro", "primitive/any", {"v": 1})
        await _settle()

        event = await stream.next_event(timeout=1)
        assert isinstance(event, ChangeEvent)
        assert event.event_type == "put"
        assert event.path.endswith("docs/intro")
        assert isinstance(event.new_hash, bytes) and event.new_hash
        stream.unwatch()

    async def test_prefix_pattern_delivers_children(self, client):
        stream = client.watch("docs/*")
        await client.put("docs/a", "primitive/any", {})
        await client.put("docs/b", "primitive/any", {})
        await _settle()

        paths = {(await stream.next_event(timeout=1)).path for _ in range(2)}
        assert {p.rsplit("/", 1)[-1] for p in paths} == {"a", "b"}
        stream.unwatch()

    async def test_non_matching_writes_are_not_delivered(self, client):
        stream = client.watch("docs/*")
        await client.put("other/x", "primitive/any", {})
        await _settle()
        assert stream.pending() == 0
        stream.unwatch()

    async def test_remove_arrives_as_event_type_remove(self, client):
        await client.put("docs/intro", "primitive/any", {"v": 1})
        stream = client.watch("docs/intro")
        await client.remove("docs/intro")
        await _settle()

        event = await stream.next_event(timeout=1)
        assert event.event_type == "remove"
        assert event.new_hash is None
        stream.unwatch()

    async def test_create_and_update_both_report_put(self, client):
        """§6's vocabulary has two values; the peer's enum has three.

        `created` and `updated` are distinct internally and both mean "put" on
        the SDK surface. A projection that passed the enum name through would
        emit an event_type no other implementation recognises.
        """
        stream = client.watch("docs/intro")
        await client.put("docs/intro", "primitive/any", {"v": 1})  # created
        await client.put("docs/intro", "primitive/any", {"v": 2})  # updated
        await _settle()

        first = await stream.next_event(timeout=1)
        second = await stream.next_event(timeout=1)
        assert (first.event_type, second.event_type) == ("put", "put")
        assert first.new_hash != second.new_hash
        stream.unwatch()

    async def test_watch_yields_the_narrow_6_1_shape(self, client):
        """§6.1's ChangeEvent has three fields, not §6.3's four."""
        stream = client.watch("docs/intro")
        await client.put("docs/intro", "primitive/any", {})
        await _settle()

        event = await stream.next_event(timeout=1)
        assert type(event) is ChangeEvent
        assert not hasattr(event, "previous_hash")
        stream.unwatch()

    async def test_per_path_ordering_is_preserved(self, client):
        stream = client.watch("docs/seq")
        for i in range(5):
            await client.put("docs/seq", "primitive/any", {"i": i})
        await _settle()

        hashes = [(await stream.next_event(timeout=1)).new_hash for _ in range(5)]
        assert len(hashes) == 5
        assert len(set(hashes)) == 5, "each write is a distinct version"
        stream.unwatch()

    async def test_async_iteration_works(self, client):
        stream = client.watch("docs/*")
        await client.put("docs/a", "primitive/any", {})
        await _settle()

        async for event in stream:
            assert event.event_type == "put"
            break
        stream.unwatch()

    async def test_no_events_are_dropped_under_a_slow_consumer(self, client):
        """§6.1 MUST NOT silently drop changes without a configured rate_limit.

        The stream queue is unbounded for exactly this reason — a bounded queue
        with any drop policy fails here, and would fail only under load.
        """
        stream = client.watch("docs/*")
        for i in range(50):
            await client.put(f"docs/n{i}", "primitive/any", {"i": i})
        await _settle()

        assert stream.pending() == 50
        stream.unwatch()


# ---------------------------------------------------------------------------
# §6.2 unwatch
# ---------------------------------------------------------------------------


class TestUnwatch:
    async def test_explicit_unwatch_stops_delivery(self, client):
        stream = client.watch("docs/*")
        client.unwatch(stream)

        await client.put("docs/a", "primitive/any", {})
        await _settle()
        assert stream.pending() == 0

    async def test_unwatch_is_idempotent(self, client):
        stream = client.watch("docs/*")
        client.unwatch(stream)
        client.unwatch(stream)
        stream.unwatch()
        assert stream.closed

    async def test_context_manager_cancels_on_exit(self, client):
        async with client.watch("docs/*") as stream:
            await client.put("docs/a", "primitive/any", {})
            await _settle()
            assert stream.pending() == 1

        await client.put("docs/b", "primitive/any", {})
        await _settle()
        assert stream.pending() == 1, "no delivery after the scope closed"

    async def test_unwatch_wakes_a_parked_consumer(self, client):
        """A consumer blocked in `async for` must exit when the stream closes.

        The natural shape — one task iterating, another cancelling — deadlocks
        if `unwatch()` only sets a flag: the iterator is parked inside
        `queue.get()` and nothing ever wakes it, so the consuming task hangs
        forever. `unwatch()` therefore has to *push* something, not just mark.

        Written against a stream with an empty queue, because that is the only
        state where the bug is reachable and it is the common one — a consumer
        keeping up with events is parked almost all of the time.
        """
        stream = client.watch("docs/*")
        seen: list[object] = []

        async def consume() -> None:
            async for event in stream:
                seen.append(event)

        task = asyncio.create_task(consume())
        await _settle()  # let the consumer reach the park

        stream.unwatch()
        await asyncio.wait_for(task, timeout=1)
        assert seen == []

    async def test_unwatch_drains_what_was_already_queued(self, client):
        """Cancelling must not discard events the caller has already been sent.

        §6.1's MUST-NOT-drop applies to delivery, and an event sitting in the
        queue has been delivered to this stream. Closing is not a reason to
        lose it.
        """
        stream = client.watch("docs/*")
        await client.put("docs/a", "primitive/any", {})
        await _settle()

        stream.unwatch()

        seen = [event async for event in stream]
        assert len(seen) == 1
        assert seen[0].path.endswith("docs/a")

    async def test_cancel_detaches_from_the_emit_pathway(self, client, peer):
        """Not just "stops yielding" — the listener is actually unsubscribed.

        A stream that keeps receiving into a dead queue is a leak that a
        pending()-only assertion would not catch.
        """
        before = len(peer.emit_pathway._subscriptions)
        stream = client.watch("docs/*")
        assert len(peer.emit_pathway._subscriptions) == before + 1
        stream.unwatch()
        assert len(peer.emit_pathway._subscriptions) == before


# ---------------------------------------------------------------------------
# §6.5 the access-level boundary
# ---------------------------------------------------------------------------


class TestAccessLevelBoundary:
    def test_l0_lives_behind_its_own_accessor(self, client):
        """§6.5: the naming MUST carry the boundary."""
        assert isinstance(client.store, LocalStore)

    def test_client_has_no_l0_method_of_its_own(self, client):
        """§2.7's anti-pattern: two levels sharing one name.

        `client.get` is dispatched; direct store access is only ever reachable
        as `client.store...`, so a reader can see the level at the call site.
        """
        assert not hasattr(client, "content_store")
        assert not hasattr(client, "entity_tree")
        assert hasattr(client.store, "content_store")

    def test_a_remote_only_client_has_no_l0_surface(self):
        """L0 is local-only by construction, not by policy check."""

        class Dispatcher:
            async def execute(self, request):  # pragma: no cover - never called
                raise AssertionError

        remote = EntityClient(Dispatcher(), "peer-b")
        assert remote.has_local_store is False
        with pytest.raises(RuntimeError, match="no Level 0 surface"):
            _ = remote.store

    async def test_a_remote_only_client_cannot_watch_locally(self):
        class Dispatcher:
            async def execute(self, request):  # pragma: no cover - never called
                raise AssertionError

        remote = EntityClient(Dispatcher(), "peer-b")
        with pytest.raises(RuntimeError, match="no backend"):
            remote.watch("docs/*")

    async def test_l0_watch_needs_no_capability(self, peer):
        """§6.5: L0 observation is always available, no grant involved."""
        store = LocalStore(peer.emit_pathway, peer.keypair.peer_id)
        stream = store.watch("docs/*")

        from entity_core.protocol.entity import Entity
        from entity_core.storage.emit import EmitContext

        peer.emit_pathway.emit(
            "docs/direct",
            Entity(type="primitive/any", data={"v": 1}),
            EmitContext.bootstrap(),
        )
        await _settle()

        event = await stream.next_event(timeout=1)
        assert event.event_type == "put"
        stream.unwatch()


# ---------------------------------------------------------------------------
# §6.3 the raw stream
# ---------------------------------------------------------------------------


class TestRawEventStream:
    async def test_subscribe_events_is_unfiltered(self, client):
        stream = client.store.subscribe_events()
        await client.put("docs/a", "primitive/any", {})
        await client.put("other/b", "primitive/any", {})
        await _settle()

        assert stream.pending() >= 2, "both writes, regardless of prefix"
        stream.unwatch()

    async def test_raw_events_carry_previous_hash(self, client):
        """§6.3's TreeChangeEvent is the wider shape — four fields, not three."""
        first = await client.put("docs/x", "primitive/any", {"v": 1})
        stream = client.store.subscribe_events()
        await client.put("docs/x", "primitive/any", {"v": 2})
        await _settle()

        event = await stream.next_event(timeout=1)
        assert isinstance(event, TreeChangeEvent)
        assert event.previous_hash == first
        assert event.new_hash != first
        stream.unwatch()

    async def test_l0_watch_also_yields_the_wide_shape(self, client):
        stream = client.store.watch("docs/*")
        await client.put("docs/a", "primitive/any", {})
        await _settle()

        event = await stream.next_event(timeout=1)
        assert isinstance(event, TreeChangeEvent)
        stream.unwatch()

    def test_l0_watch_enforces_the_same_grammar(self, client):
        """One pattern language across both levels."""
        with pytest.raises(BadRequest):
            client.store.watch("a/*/b")
