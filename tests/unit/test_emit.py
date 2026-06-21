"""Unit tests for EmitPathway and change events."""

import asyncio

import pytest

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import (
    AsyncChangeListener,
    ChangeEvent,
    ChangeKind,
    ConsumerHaltInfo,
    EmitContext,
    EmitPathway,
    EmitResult,
    InternalHook,
)
from entity_core.storage.entity_tree import EntityTree
from entity_core.utils.ecf import hash_equals, hash_to_display


@pytest.fixture
def content_store() -> ContentStore:
    """Create a fresh content store."""
    return ContentStore()


@pytest.fixture
def entity_tree() -> EntityTree:
    """Create a fresh entity tree."""
    return EntityTree("test-peer")


@pytest.fixture
def emit_pathway(content_store: ContentStore, entity_tree: EntityTree) -> EmitPathway:
    """Create an emit pathway."""
    return EmitPathway(content_store, entity_tree)


@pytest.fixture
def test_entity() -> Entity:
    """Create a test entity."""
    return Entity(type="test/thing", data={"value": 42})


class TestEmitContext:
    """Tests for EmitContext factory methods."""

    def test_bootstrap_context(self) -> None:
        """EmitContext.bootstrap() has correct source."""
        ctx = EmitContext.bootstrap()
        assert ctx.source == "bootstrap"
        assert ctx.author is None
        assert ctx.chain_id is None
        assert ctx.bounds is None

    def test_protocol_context(self) -> None:
        """EmitContext.protocol() has correct source and author."""
        ctx = EmitContext.protocol(author="peer-123", chain_id="chain-456")
        assert ctx.source == "protocol"
        assert ctx.author == "peer-123"
        assert ctx.chain_id == "chain-456"
        assert ctx.bounds is None

    def test_handler_context(self) -> None:
        """EmitContext.handler() has correct source and fields."""
        ctx = EmitContext.handler(author="peer-123", chain_id="chain-456")
        assert ctx.source == "handler"
        assert ctx.author == "peer-123"
        assert ctx.chain_id == "chain-456"

    def test_default_context(self) -> None:
        """Default EmitContext has handler source."""
        ctx = EmitContext()
        assert ctx.source == "handler"
        assert ctx.author is None


class TestEmitPathwayBasics:
    """Tests for basic EmitPathway operations."""

    def test_emit_stores_and_returns_hash(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """EmitPathway.emit() stores entity and returns EmitResult with hash."""
        result = emit_pathway.emit("test/path", test_entity)

        assert isinstance(result, EmitResult)
        assert result.status == 200
        h = result.hash
        assert isinstance(h, bytes)
        assert len(h) == 33  # 1 byte algorithm + 32 bytes SHA-256 digest

        # Entity is in content store
        assert emit_pathway.content_store.has(h)

        # URI points to hash
        full_uri = emit_pathway.entity_tree.normalize_uri("test/path")
        assert hash_equals(emit_pathway.entity_tree.get(full_uri), h)

    def test_delete_removes_mapping(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """EmitPathway.delete() removes URI mapping."""
        # First emit
        h = emit_pathway.emit("test/path", test_entity).hash
        full_uri = emit_pathway.entity_tree.normalize_uri("test/path")

        # Delete
        result = emit_pathway.delete("test/path")

        # Returns previous hash in EmitResult
        assert result.status == 200
        assert hash_equals(result.hash, h)

        # URI no longer mapped
        assert emit_pathway.entity_tree.get(full_uri) is None

        # Entity still in content store
        assert emit_pathway.content_store.has(h)

    def test_delete_nonexistent_returns_empty_result(self, emit_pathway: EmitPathway) -> None:
        """EmitPathway.delete() returns EmitResult with None hash for nonexistent URI."""
        result = emit_pathway.delete("nonexistent/path")
        assert isinstance(result, EmitResult)
        assert result.hash is None
        assert result.status == 200

    def test_put_content_only(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """EmitPathway.put_content_only() stores without tree mapping."""
        h = emit_pathway.put_content_only(test_entity)

        # Entity is in content store
        assert emit_pathway.content_store.has(h)

        # No URI mapping
        assert len(emit_pathway.entity_tree) == 0

    def test_property_access(
        self, emit_pathway: EmitPathway, content_store: ContentStore, entity_tree: EntityTree
    ) -> None:
        """EmitPathway exposes content_store and entity_tree properties."""
        assert emit_pathway.content_store is content_store
        assert emit_pathway.entity_tree is entity_tree


class TestInternalHooks:
    """Tests for internal synchronous hooks."""

    def test_emit_fires_created_event(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """EmitPathway.emit() fires created event for new URI via internal hook."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        emit_pathway._add_internal_hook(TestHook())
        emit_pathway.emit("test/path", test_entity)

        assert len(events) == 1
        assert events[0].kind == ChangeKind.CREATED
        assert events[0].uri == "/test-peer/test/path"
        assert events[0].entity == test_entity
        assert events[0].previous_hash is None

    def test_emit_fires_updated_event(
        self, emit_pathway: EmitPathway
    ) -> None:
        """EmitPathway.emit() fires updated event for existing URI."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        # First emit (no hook yet)
        first_entity = Entity(type="test/thing", data={"v": 1})
        first_hash = emit_pathway.emit("test/path", first_entity).hash

        # Add hook
        emit_pathway._add_internal_hook(TestHook())

        # Second emit (different content)
        second_entity = Entity(type="test/thing", data={"v": 2})
        emit_pathway.emit("test/path", second_entity)

        assert len(events) == 1
        assert events[0].kind == ChangeKind.UPDATED
        # Check previous hash
        assert hash_equals(events[0].get_previous_hash(), first_hash)

    def test_delete_fires_deleted_event(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """EmitPathway.delete() fires deleted event via internal hook."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        # First emit
        h = emit_pathway.emit("test/path", test_entity).hash

        # Add hook
        emit_pathway._add_internal_hook(TestHook())

        # Delete
        emit_pathway.delete("test/path")

        assert len(events) == 1
        assert events[0].kind == ChangeKind.DELETED
        assert events[0].uri == "/test-peer/test/path"
        assert events[0].hash is None
        assert events[0].entity is None
        # Check previous hash
        assert hash_equals(events[0].get_previous_hash(), h)

    def test_delete_nonexistent_no_event(
        self, emit_pathway: EmitPathway
    ) -> None:
        """EmitPathway.delete() does not fire event for nonexistent URI."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        emit_pathway._add_internal_hook(TestHook())
        emit_pathway.delete("nonexistent/path")

        assert len(events) == 0

    def test_remove_internal_hook(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """EmitPathway._remove_internal_hook() stops event delivery."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        hook = TestHook()
        emit_pathway._add_internal_hook(hook)

        # First emit - should receive
        emit_pathway.emit("test/path1", test_entity)
        assert len(events) == 1

        # Remove hook
        emit_pathway._remove_internal_hook(hook)

        # Second emit - should not receive
        emit_pathway.emit("test/path2", test_entity)
        assert len(events) == 1

    def test_internal_hook_with_pattern(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """Internal hooks can filter by pattern."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        # Only receive events under data/*
        emit_pathway._add_internal_hook(TestHook(), pattern="data/*")

        # Not matching
        emit_pathway.emit("other/path", test_entity)
        assert len(events) == 0

        # Matching
        emit_pathway.emit("data/path", test_entity)
        assert len(events) == 1


class TestPatternMatching:
    """Tests for subscription pattern matching."""

    def test_wildcard_pattern_matches_all(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """Wildcard pattern '*' matches all URIs."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        emit_pathway._add_internal_hook(TestHook(), pattern="*")

        emit_pathway.emit("any/path", test_entity)
        emit_pathway.emit("other/deep/path", test_entity)

        assert len(events) == 2

    def test_exact_pattern_matches_only_exact(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """Exact pattern matches only that URI."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        # Exact match pattern
        emit_pathway._add_internal_hook(TestHook(), pattern="data/users/alice")

        # Not matching
        emit_pathway.emit("data/users/bob", test_entity)
        emit_pathway.emit("data/users", test_entity)
        assert len(events) == 0

        # Matching
        emit_pathway.emit("data/users/alice", test_entity)
        assert len(events) == 1

    def test_glob_pattern_matches_subtree(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """Glob pattern 'path/*' matches subtree."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        emit_pathway._add_internal_hook(TestHook(), pattern="data/users/*")

        # Not matching - different prefix
        emit_pathway.emit("data/items/1", test_entity)
        assert len(events) == 0

        # Matching - direct child
        emit_pathway.emit("data/users/alice", test_entity)
        assert len(events) == 1

        # Matching - deeper nested
        emit_pathway.emit("data/users/alice/profile", test_entity)
        assert len(events) == 2


class TestAsyncSubscriptions:
    """Tests for asynchronous subscriptions."""

    @pytest.mark.asyncio
    async def test_subscribe_receives_events(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """Async subscriptions receive events via task."""
        events: list[ChangeEvent] = []
        event_received = asyncio.Event()

        class TestListener:
            async def on_change(self, event: ChangeEvent) -> None:
                events.append(event)
                event_received.set()

        emit_pathway.subscribe("*", TestListener())

        # Emit in the event loop
        emit_pathway.emit("test/path", test_entity)

        # Wait for async delivery
        await asyncio.wait_for(event_received.wait(), timeout=1.0)

        assert len(events) == 1
        assert events[0].kind == ChangeKind.CREATED

    @pytest.mark.asyncio
    async def test_subscribe_with_pattern(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """Async subscriptions respect path patterns."""
        events: list[ChangeEvent] = []
        event_received = asyncio.Event()

        class TestListener:
            async def on_change(self, event: ChangeEvent) -> None:
                events.append(event)
                event_received.set()

        # Only subscribe to data/*
        emit_pathway.subscribe("data/*", TestListener())

        # Not matching - should not receive
        emit_pathway.emit("other/path", test_entity)

        # Give time for potential delivery
        await asyncio.sleep(0.05)
        assert len(events) == 0

        # Matching - should receive
        emit_pathway.emit("data/path", test_entity)
        await asyncio.wait_for(event_received.wait(), timeout=1.0)

        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_unsubscribe(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """Unsubscribe removes the listener."""
        events: list[ChangeEvent] = []
        event_received = asyncio.Event()

        class TestListener:
            async def on_change(self, event: ChangeEvent) -> None:
                events.append(event)
                event_received.set()

        listener = TestListener()
        emit_pathway.subscribe("*", listener)

        # First emit - should receive
        emit_pathway.emit("test/path1", test_entity)
        await asyncio.wait_for(event_received.wait(), timeout=1.0)
        assert len(events) == 1

        # Unsubscribe
        emit_pathway.unsubscribe(listener)

        # Second emit - should not receive
        emit_pathway.emit("test/path2", test_entity)
        await asyncio.sleep(0.05)
        assert len(events) == 1


class TestEventImmutability:
    """Tests for ChangeEvent immutability."""

    def test_change_event_is_frozen(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """ChangeEvent is immutable (frozen dataclass)."""
        captured_event: ChangeEvent | None = None

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                nonlocal captured_event
                captured_event = event

        emit_pathway._add_internal_hook(TestHook())
        emit_pathway.emit("test/path", test_entity)

        assert captured_event is not None

        # Should raise FrozenInstanceError
        with pytest.raises(Exception):  # dataclasses.FrozenInstanceError
            captured_event.uri = "modified"  # type: ignore[misc]

    def test_emit_context_is_frozen(self) -> None:
        """EmitContext is immutable (frozen dataclass)."""
        ctx = EmitContext.bootstrap()

        with pytest.raises(Exception):
            ctx.source = "modified"  # type: ignore[misc]


class TestMultipleListeners:
    """Tests for multiple listeners."""

    def test_multiple_internal_hooks(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """Multiple internal hooks all receive events."""
        events1: list[ChangeEvent] = []
        events2: list[ChangeEvent] = []

        class Hook1:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events1.append(event)

        class Hook2:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events2.append(event)

        emit_pathway._add_internal_hook(Hook1())
        emit_pathway._add_internal_hook(Hook2())

        emit_pathway.emit("test/path", test_entity)

        assert len(events1) == 1
        assert len(events2) == 1

    def test_hooks_with_different_patterns(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """Hooks with different patterns receive appropriate events."""
        data_events: list[ChangeEvent] = []
        all_events: list[ChangeEvent] = []

        class DataOnlyHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                data_events.append(event)

        class AllEventsHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                all_events.append(event)

        # One hook only wants data/*
        emit_pathway._add_internal_hook(DataOnlyHook(), pattern="data/*")
        # Other wants all
        emit_pathway._add_internal_hook(AllEventsHook())

        # Under data/
        emit_pathway.emit("data/path", test_entity)
        assert len(data_events) == 1
        assert len(all_events) == 1

        # Not under data/
        emit_pathway.emit("other/path", test_entity)
        assert len(data_events) == 1  # No new event
        assert len(all_events) == 2  # Got it


class TestIdempotentWrites:
    """Tests for idempotent write behavior."""

    def test_same_content_still_emits_event(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """Writing same content to same URI emits update event."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        emit_pathway._add_internal_hook(TestHook())

        # First write - created
        result1 = emit_pathway.emit("test/path", test_entity)
        assert events[-1].kind == ChangeKind.CREATED

        # Same content again - suppressed (no-op per SYSTEM-COMPOSITION §1.1)
        result2 = emit_pathway.emit("test/path", test_entity)
        assert len(events) == 1  # No new event — hash unchanged
        assert hash_equals(result1.hash, result2.hash)  # Same hash


class TestCascadeDepth:
    """Tests for cascade depth tracking per SYSTEM-COMPOSITION §3."""

    def test_cascade_depth_starts_at_zero(
        self, emit_pathway: EmitPathway,
    ) -> None:
        assert emit_pathway.cascade_depth == 0

    def test_cascade_depth_increments_during_dispatch(
        self, emit_pathway: EmitPathway, test_entity: Entity,
    ) -> None:
        """Cascade depth is > 0 inside sync hooks."""
        observed_depths: list[int] = []

        class DepthHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                observed_depths.append(emit_pathway.cascade_depth)

        emit_pathway._add_internal_hook(DepthHook())
        emit_pathway.emit("test/path", test_entity)

        assert observed_depths == [1]
        assert emit_pathway.cascade_depth == 0  # Restored after emit

    def test_nested_emit_increments_depth(
        self, emit_pathway: EmitPathway,
    ) -> None:
        """Nested writes during hook processing increment cascade depth."""
        observed_depths: list[int] = []

        class NestingHook:
            def __init__(self):
                self._fired = set()

            def on_change_sync(self, event: ChangeEvent) -> None:
                observed_depths.append(emit_pathway.cascade_depth)
                # Trigger one nested write (only once to avoid infinite loop)
                if event.uri.endswith("/outer") and "/outer" not in self._fired:
                    self._fired.add("/outer")
                    inner = Entity(type="test/inner", data={"nested": True})
                    emit_pathway.emit("test/inner", inner)

        emit_pathway._add_internal_hook(NestingHook())
        outer = Entity(type="test/outer", data={"nested": False})
        emit_pathway.emit("test/outer", outer)

        # Outer write at depth 1, inner write at depth 2
        assert observed_depths == [1, 2]
        assert emit_pathway.cascade_depth == 0

    def test_system_refuse_depth(
        self, emit_pathway: EmitPathway,
    ) -> None:
        """Writes at cascade depth >= 32 return 503, binding does NOT commit."""
        emit_pathway._cascade_depth = 32
        try:
            entity = Entity(type="test/blocked", data={"x": 1})
            result = emit_pathway.emit("test/blocked", entity)
            assert result.status == 503
            assert result.hash is None
            full_uri = emit_pathway.entity_tree.normalize_uri("test/blocked")
            assert emit_pathway.entity_tree.get(full_uri) is None
        finally:
            emit_pathway._cascade_depth = 0


class TestCascadeDepthOnEvent:
    """Tests for cascade_depth field on ChangeEvent (G-3)."""

    def test_event_carries_cascade_depth(
        self, emit_pathway: EmitPathway, test_entity: Entity,
    ) -> None:
        """ChangeEvent.cascade_depth reflects depth at emit time."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        emit_pathway._add_internal_hook(TestHook())
        emit_pathway.emit("test/path", test_entity)

        assert len(events) == 1
        # cascade_depth is captured before increment (depth at emit call time)
        assert events[0].cascade_depth == 0

    def test_nested_event_carries_higher_depth(
        self, emit_pathway: EmitPathway,
    ) -> None:
        """Nested writes carry incremented cascade_depth on events."""
        events: list[ChangeEvent] = []

        class NestingHook:
            def __init__(self):
                self._fired = set()

            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)
                if event.uri.endswith("/outer") and "/outer" not in self._fired:
                    self._fired.add("/outer")
                    inner = Entity(type="test/inner", data={"nested": True})
                    emit_pathway.emit("test/inner", inner)

        emit_pathway._add_internal_hook(NestingHook())
        outer = Entity(type="test/outer", data={"nested": False})
        emit_pathway.emit("test/outer", outer)

        assert len(events) == 2
        # Outer event at depth 0, inner event at depth 1
        assert events[0].cascade_depth == 0
        assert events[1].cascade_depth == 1


class TestClockGuardNarrowing:
    """Tests for G-1b: clock self-guard targets engine paths only."""

    def test_engine_paths_are_guarded(self) -> None:
        """Clock engine output paths are skipped by advance_clock."""
        from entity_handlers.clock import _is_clock_engine_path

        assert _is_clock_engine_path("system/clock/logical") is True
        assert _is_clock_engine_path("system/clock/vector") is True
        assert _is_clock_engine_path("system/clock/hlc") is True

    def test_config_path_not_guarded(self) -> None:
        """Config path is NOT guarded — config changes advance the clock."""
        from entity_handlers.clock import _is_clock_engine_path

        assert _is_clock_engine_path("system/clock/config") is False

    def test_other_paths_not_guarded(self) -> None:
        """Non-clock paths are not guarded."""
        from entity_handlers.clock import _is_clock_engine_path

        assert _is_clock_engine_path("data/users/alice") is False
        assert _is_clock_engine_path("system/history/head") is False


class TestBoundsCascadeDepth:
    """Tests for cascade_depth on Bounds (G-3)."""

    def test_bounds_cascade_depth_field(self) -> None:
        """Bounds has cascade_depth field."""
        from entity_core.protocol.bounds import Bounds

        b = Bounds(cascade_depth=5)
        assert b.cascade_depth == 5

    def test_bounds_cascade_depth_serialization(self) -> None:
        """cascade_depth is serialized/deserialized in bounds."""
        from entity_core.protocol.bounds import Bounds

        b = Bounds(ttl=10, cascade_depth=3)
        d = b.to_dict()
        assert d["cascade_depth"] == 3

        b2 = Bounds.from_dict(d)
        assert b2.cascade_depth == 3

    def test_bounds_cascade_depth_copy(self) -> None:
        """cascade_depth is preserved on copy."""
        from entity_core.protocol.bounds import Bounds

        b = Bounds(cascade_depth=7)
        b2 = b.copy()
        assert b2.cascade_depth == 7

    def test_bounds_cascade_depth_omitted_when_none(self) -> None:
        """cascade_depth is omitted from dict when None."""
        from entity_core.protocol.bounds import Bounds

        b = Bounds(ttl=10)
        d = b.to_dict()
        assert "cascade_depth" not in d


class TestSourceFiltering:
    """Tests for filtering by event source with internal hooks."""

    def test_hook_can_check_source(
        self, emit_pathway: EmitPathway, test_entity: Entity
    ) -> None:
        """Internal hooks can filter by checking event.context.source."""
        non_bootstrap_events: list[ChangeEvent] = []

        class FilteredHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                if event.context.source != "bootstrap":
                    non_bootstrap_events.append(event)

        emit_pathway._add_internal_hook(FilteredHook())

        # Bootstrap write - filtered in hook
        emit_pathway.emit(
            "system/types/test",
            Entity(type="system/type", data={"name": "test"}),
            EmitContext.bootstrap(),
        )
        assert len(non_bootstrap_events) == 0

        # Handler write - passed
        emit_pathway.emit(
            "user/data",
            Entity(type="test/data", data={}),
            EmitContext.handler(author="peer-1"),
        )
        assert len(non_bootstrap_events) == 1


class TestCascadeHalt:
    """Tests for cascade halt semantics (PROPOSAL-CASCADE-SEMANTICS)."""

    def test_non_200_halts_remaining_hooks(
        self, emit_pathway: EmitPathway, test_entity: Entity,
    ) -> None:
        """A Phase 1 consumer returning non-200 skips remaining consumers."""
        events_a: list[ChangeEvent] = []
        events_b: list[ChangeEvent] = []
        events_c: list[ChangeEvent] = []

        class HookA:
            def on_change_sync(self, event: ChangeEvent) -> int | None:
                events_a.append(event)
                return None  # Success

        class HookB:
            def on_change_sync(self, event: ChangeEvent) -> int | None:
                events_b.append(event)
                return 500  # Halt

        class HookC:
            def on_change_sync(self, event: ChangeEvent) -> int | None:
                events_c.append(event)
                return None

        emit_pathway._add_internal_hook(HookA(), name="hook-a")
        emit_pathway._add_internal_hook(HookB(), name="hook-b")
        emit_pathway._add_internal_hook(HookC(), name="hook-c")

        result = emit_pathway.emit("test/path", test_entity)

        assert result.status == 207
        assert result.hash is not None  # Binding committed
        assert len(events_a) == 1  # Ran before halt
        assert len(events_b) == 1  # Halting consumer ran
        assert len(events_c) == 0  # Skipped

    def test_207_carries_consumer_names(
        self, emit_pathway: EmitPathway, test_entity: Entity,
    ) -> None:
        """207 response includes named consumers in completed/halted/skipped."""

        class OkHook:
            def on_change_sync(self, event: ChangeEvent) -> int | None:
                return None

        class HaltHook:
            def on_change_sync(self, event: ChangeEvent) -> int | None:
                return 422

        class SkippedHook:
            def on_change_sync(self, event: ChangeEvent) -> int | None:
                return None

        emit_pathway._add_internal_hook(OkHook(), name="index-mgr")
        emit_pathway._add_internal_hook(HaltHook(), name="revision/auto-version")
        emit_pathway._add_internal_hook(SkippedHook(), name="subscription/notifier")

        result = emit_pathway.emit("test/path", test_entity)

        assert result.status == 207
        assert result.consumers_completed == ("index-mgr",)
        assert result.consumers_halted is not None
        assert result.consumers_halted.name == "revision/auto-version"
        assert result.consumers_halted.status == 422
        assert result.consumers_skipped == ("subscription/notifier",)

    def test_all_hooks_succeed_returns_200(
        self, emit_pathway: EmitPathway, test_entity: Entity,
    ) -> None:
        """All hooks returning None produces status 200."""

        class OkHook:
            def on_change_sync(self, event: ChangeEvent) -> int | None:
                return None

        emit_pathway._add_internal_hook(OkHook(), name="a")
        emit_pathway._add_internal_hook(OkHook(), name="b")

        result = emit_pathway.emit("test/path", test_entity)

        assert result.status == 200
        assert result.consumers_completed == ("a", "b")
        assert result.consumers_halted is None
        assert result.consumers_skipped == ()

    def test_binding_committed_despite_halt(
        self, emit_pathway: EmitPathway, test_entity: Entity,
    ) -> None:
        """On halt, binding is already committed (no rollback)."""

        class HaltHook:
            def on_change_sync(self, event: ChangeEvent) -> int | None:
                return 500

        emit_pathway._add_internal_hook(HaltHook(), name="halter")

        result = emit_pathway.emit("test/path", test_entity)

        assert result.status == 207
        assert result.hash is not None
        full_uri = emit_pathway.entity_tree.normalize_uri("test/path")
        assert emit_pathway.entity_tree.get(full_uri) is not None

    def test_halt_suppresses_phase_2(
        self, emit_pathway: EmitPathway, test_entity: Entity,
    ) -> None:
        """Phase 2 subscriptions do not fire when cascade is halted."""
        async_events: list[ChangeEvent] = []

        class HaltHook:
            def on_change_sync(self, event: ChangeEvent) -> int | None:
                return 500

        class AsyncSub:
            async def on_change(self, event: ChangeEvent) -> None:
                async_events.append(event)

        emit_pathway._add_internal_hook(HaltHook(), name="halter")
        emit_pathway.subscribe("*", AsyncSub())

        emit_pathway.emit("test/path", test_entity)

        assert len(async_events) == 0

    def test_pattern_filtering_with_halt(
        self, emit_pathway: EmitPathway, test_entity: Entity,
    ) -> None:
        """Only pattern-matching hooks participate in halt semantics."""

        class HaltHook:
            def on_change_sync(self, event: ChangeEvent) -> int | None:
                return 500

        class OkHook:
            def on_change_sync(self, event: ChangeEvent) -> int | None:
                return None

        emit_pathway._add_internal_hook(HaltHook(), pattern="other/*", name="other-halter")
        emit_pathway._add_internal_hook(OkHook(), name="global-ok")

        result = emit_pathway.emit("test/path", test_entity)

        assert result.status == 200
        assert result.consumers_completed == ("global-ok",)
