"""Integration tests for EmitPathway with Peer and HandlerContext."""

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import (
    ChangeEvent,
    ChangeKind,
    EmitContext,
    EmitPathway,
)
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree


class TestPeerEmitPathway:
    """Tests for Peer's EmitPathway integration."""

    def test_peer_creates_emit_pathway(self) -> None:
        """Peer creates EmitPathway on init."""
        keypair = Keypair.generate()
        peer = PeerBuilder().with_keypair(keypair).with_default_handlers().build()

        assert hasattr(peer, "emit_pathway")
        assert isinstance(peer.emit_pathway, EmitPathway)
        assert peer.emit_pathway.content_store is peer.content_store
        assert peer.emit_pathway.entity_tree is peer.entity_tree

    def test_peer_bootstrap_uses_emit_pathway(self) -> None:
        """Peer bootstrap writes use EmitPathway with bootstrap context."""
        events: list[ChangeEvent] = []

        class TestHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                events.append(event)

        # Create stores manually
        keypair = Keypair.generate()
        content_store = ContentStore()
        entity_tree = EntityTree(keypair.peer_id)
        emit_pathway = EmitPathway(content_store, entity_tree)

        # Add internal hook
        emit_pathway._add_internal_hook(TestHook())

        # Now trigger bootstrap through emit pathway
        from entity_core.types import register_types
        from entity_core.types.registry import register_handlers
        from entity_handlers import ALL_HANDLER_MANIFESTS

        register_types(emit_pathway)
        register_handlers(emit_pathway, ALL_HANDLER_MANIFESTS)

        # Should have received events
        assert len(events) > 0

        # All bootstrap events should have source="bootstrap"
        for event in events:
            assert event.context.source == "bootstrap"
            assert event.kind == ChangeKind.CREATED

    def test_peer_listener_receives_type_registration(self) -> None:
        """Listener can observe type registration during peer startup."""
        type_events: list[ChangeEvent] = []

        class TypeHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                # V7.7 singular namespace: system/type/
                if "/system/type/" in event.uri:
                    type_events.append(event)

        # Create emit pathway with hook first
        keypair = Keypair.generate()
        content_store = ContentStore()
        entity_tree = EntityTree(keypair.peer_id)
        emit_pathway = EmitPathway(content_store, entity_tree)
        emit_pathway._add_internal_hook(TypeHook())

        # Register types through pathway
        from entity_core.types import register_types
        register_types(emit_pathway)

        # Should have type events
        assert len(type_events) > 0
        for event in type_events:
            assert "/system/type/" in event.uri
            assert event.context.source == "bootstrap"


class TestExtensionPattern:
    """Tests demonstrating the extension pattern with subscriptions."""

    @pytest.mark.asyncio
    async def test_subscription_extension_pattern(self) -> None:
        """Demonstrates subscription extension pattern."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer")
        emit_pathway = EmitPathway(content_store, entity_tree)

        # Extension: track all writes to specific path
        writes_under_data: list[tuple[str, str]] = []
        event_received = asyncio.Event()

        class DataSubscription:
            """Extension that subscribes to writes under data/."""

            async def on_change(self, event: ChangeEvent) -> None:
                if event.hash and event.kind != ChangeKind.DELETED:
                    writes_under_data.append((event.uri, event.hash))
                    event_received.set()

        # Subscribe only to data/*
        emit_pathway.subscribe("data/*", DataSubscription())

        # Writes under data/ are tracked
        entity = Entity(type="test/record", data={"id": 1})
        emit_pathway.emit("data/records/1", entity)
        await asyncio.wait_for(event_received.wait(), timeout=1.0)

        event_received.clear()
        emit_pathway.emit("data/records/2", entity)
        await asyncio.wait_for(event_received.wait(), timeout=1.0)

        # Writes elsewhere are not tracked (subscription pattern filters them)
        emit_pathway.emit("other/path", entity)
        await asyncio.sleep(0.05)

        assert len(writes_under_data) == 2
        assert all("/data/" in uri for uri, _ in writes_under_data)

    def test_type_index_extension_pattern(self) -> None:
        """Demonstrates type index extension pattern with internal hook."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer")
        emit_pathway = EmitPathway(content_store, entity_tree)

        # Extension: index entities by type (uses internal hook for sync)
        type_index: dict[str, set[str]] = {}  # type -> set of URIs

        class TypeIndex:
            """Extension that indexes entities by type."""

            def on_change_sync(self, event: ChangeEvent) -> None:
                if event.kind == ChangeKind.DELETED:
                    # Remove from all type sets
                    for uris in type_index.values():
                        uris.discard(event.uri)
                elif event.entity:
                    entity_type = event.entity.type
                    if entity_type not in type_index:
                        type_index[entity_type] = set()
                    type_index[entity_type].add(event.uri)

        emit_pathway._add_internal_hook(TypeIndex())

        # Add some entities
        emit_pathway.emit("things/a", Entity(type="test/thing", data={"id": "a"}))
        emit_pathway.emit("things/b", Entity(type="test/thing", data={"id": "b"}))
        emit_pathway.emit("items/x", Entity(type="test/item", data={"id": "x"}))

        # Query by type
        assert len(type_index["test/thing"]) == 2
        assert len(type_index["test/item"]) == 1

        # Delete removes from index
        emit_pathway.delete("things/a")
        assert len(type_index["test/thing"]) == 1

    @pytest.mark.asyncio
    async def test_audit_log_extension_pattern(self) -> None:
        """Demonstrates audit log extension pattern with async subscription."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer")
        emit_pathway = EmitPathway(content_store, entity_tree)

        # Extension: audit log of all changes
        audit_log: list[dict] = []
        events_received = asyncio.Event()

        class AuditLog:
            """Extension that logs all changes."""

            def __init__(self, expected_count: int):
                self.expected = expected_count

            async def on_change(self, event: ChangeEvent) -> None:
                audit_log.append({
                    "kind": event.kind.value,
                    "uri": event.uri,
                    "author": event.context.author,
                    "source": event.context.source,
                })
                if len(audit_log) >= self.expected:
                    events_received.set()

        emit_pathway.subscribe("*", AuditLog(expected_count=2))

        # All changes are logged
        ctx = EmitContext.handler(author="user-123")
        emit_pathway.emit("data/record", Entity(type="test/record", data={}), ctx)
        emit_pathway.delete("data/record", ctx)

        await asyncio.wait_for(events_received.wait(), timeout=1.0)

        assert len(audit_log) == 2
        assert audit_log[0]["kind"] == "created"
        assert audit_log[0]["author"] == "user-123"
        assert audit_log[1]["kind"] == "deleted"


class TestSourceFiltering:
    """Tests for filtering by event source."""

    def test_skip_bootstrap_events_with_internal_hook(self) -> None:
        """Internal hooks can skip bootstrap events."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer")
        emit_pathway = EmitPathway(content_store, entity_tree)

        non_bootstrap_events: list[ChangeEvent] = []

        class SkipBootstrapHook:
            def on_change_sync(self, event: ChangeEvent) -> None:
                if event.context.source != "bootstrap":
                    non_bootstrap_events.append(event)

        emit_pathway._add_internal_hook(SkipBootstrapHook())

        # Bootstrap writes are skipped by hook logic
        emit_pathway.emit(
            "system/types/test",
            Entity(type="system/type", data={"name": "test"}),
            EmitContext.bootstrap(),
        )
        assert len(non_bootstrap_events) == 0

        # Handler writes are received
        emit_pathway.emit(
            "user/data",
            Entity(type="test/data", data={}),
            EmitContext.handler(author="peer-1"),
        )
        assert len(non_bootstrap_events) == 1

    @pytest.mark.asyncio
    async def test_only_protocol_events_with_subscription(self) -> None:
        """Subscriptions can filter for only protocol events in listener."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer")
        emit_pathway = EmitPathway(content_store, entity_tree)

        protocol_events: list[ChangeEvent] = []
        event_received = asyncio.Event()

        class ProtocolOnlyListener:
            async def on_change(self, event: ChangeEvent) -> None:
                if event.context.source == "protocol":
                    protocol_events.append(event)
                    event_received.set()

        emit_pathway.subscribe("*", ProtocolOnlyListener())

        # Handler write - filtered in listener
        emit_pathway.emit(
            "path/a",
            Entity(type="test/data", data={}),
            EmitContext.handler(author="peer-1"),
        )
        await asyncio.sleep(0.05)
        assert len(protocol_events) == 0

        # Protocol write - received
        emit_pathway.emit(
            "path/b",
            Entity(type="test/data", data={}),
            EmitContext.protocol(author="peer-1"),
        )
        await asyncio.wait_for(event_received.wait(), timeout=1.0)
        assert len(protocol_events) == 1
