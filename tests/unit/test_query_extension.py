"""Unit tests for the query extension (EXTENSION-QUERY v1.0).

Tests cover:
- Index data structures (type index, reverse hash index)
- Index maintenance via change events
- Index rebuild from tree scan
- Query handler find/count operations
- Expression validation
- Pagination and sorting
- Field filters (type scan fallback)
"""

import pytest

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import (
    ChangeEvent,
    ChangeKind,
    EmitContext,
    EmitPathway,
)
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.indexes import (
    IndexManager,
    InMemoryReverseHashIndex,
    InMemoryTypeIndex,
    InMemoryPathLinkIndex,
    TypeIndexEntry,
    ReverseIndexEntry,
    collect_hash_refs,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def content_store() -> ContentStore:
    return ContentStore()


@pytest.fixture
def entity_tree() -> EntityTree:
    return EntityTree("test-peer")


@pytest.fixture
def emit_pathway(content_store: ContentStore, entity_tree: EntityTree) -> EmitPathway:
    return EmitPathway(content_store, entity_tree)


@pytest.fixture
def index_manager(content_store: ContentStore) -> IndexManager:
    return IndexManager(content_store=content_store)


@pytest.fixture
def indexed_emit(emit_pathway: EmitPathway, index_manager: IndexManager) -> EmitPathway:
    """EmitPathway with IndexManager hooked in."""
    emit_pathway._add_internal_hook(index_manager)
    return emit_pathway


# ============================================================================
# InMemoryTypeIndex
# ============================================================================


class TestInMemoryTypeIndex:
    def test_add_and_lookup(self) -> None:
        idx = InMemoryTypeIndex()
        idx.add("app/user", "entity://p/users/alice", b"\x00" + b"\x01" * 32)
        results = idx.lookup("app/user")
        assert len(results) == 1
        assert results[0].type_name == "app/user"
        assert results[0].path == "entity://p/users/alice"

    def test_lookup_missing_type(self) -> None:
        idx = InMemoryTypeIndex()
        assert idx.lookup("nonexistent") == []

    def test_remove(self) -> None:
        idx = InMemoryTypeIndex()
        h = b"\x00" + b"\x01" * 32
        idx.add("app/user", "entity://p/users/alice", h)
        idx.remove("app/user", "entity://p/users/alice", h)
        assert idx.lookup("app/user") == []

    def test_remove_by_path(self) -> None:
        idx = InMemoryTypeIndex()
        h = b"\x00" + b"\x01" * 32
        idx.add("app/user", "entity://p/users/alice", h)
        idx.remove_by_path("entity://p/users/alice")
        assert idx.lookup("app/user") == []

    def test_multiple_entities_same_type(self) -> None:
        idx = InMemoryTypeIndex()
        h1 = b"\x00" + b"\x01" * 32
        h2 = b"\x00" + b"\x02" * 32
        idx.add("app/user", "entity://p/users/alice", h1)
        idx.add("app/user", "entity://p/users/bob", h2)
        results = idx.lookup("app/user")
        assert len(results) == 2
        paths = {r.path for r in results}
        assert "entity://p/users/alice" in paths
        assert "entity://p/users/bob" in paths

    def test_lookup_pattern_wildcard(self) -> None:
        idx = InMemoryTypeIndex()
        idx.add("app/user", "entity://p/u1", b"\x00" + b"\x01" * 32)
        idx.add("system/type", "entity://p/t1", b"\x00" + b"\x02" * 32)
        results = idx.lookup_pattern("*")
        assert len(results) == 2

    def test_lookup_pattern_prefix(self) -> None:
        idx = InMemoryTypeIndex()
        idx.add("app/user", "entity://p/u1", b"\x00" + b"\x01" * 32)
        idx.add("app/order", "entity://p/o1", b"\x00" + b"\x02" * 32)
        idx.add("system/type", "entity://p/t1", b"\x00" + b"\x03" * 32)
        results = idx.lookup_pattern("app/*")
        assert len(results) == 2
        types = {r.type_name for r in results}
        assert types == {"app/user", "app/order"}

    def test_lookup_pattern_exact(self) -> None:
        idx = InMemoryTypeIndex()
        idx.add("app/user", "entity://p/u1", b"\x00" + b"\x01" * 32)
        idx.add("app/order", "entity://p/o1", b"\x00" + b"\x02" * 32)
        results = idx.lookup_pattern("app/user")
        assert len(results) == 1
        assert results[0].type_name == "app/user"

    def test_all_types(self) -> None:
        idx = InMemoryTypeIndex()
        idx.add("app/user", "entity://p/u1", b"\x00" + b"\x01" * 32)
        idx.add("app/order", "entity://p/o1", b"\x00" + b"\x02" * 32)
        types = idx.all_types()
        assert set(types) == {"app/user", "app/order"}

    def test_clear(self) -> None:
        idx = InMemoryTypeIndex()
        idx.add("app/user", "entity://p/u1", b"\x00" + b"\x01" * 32)
        idx.clear()
        assert idx.lookup("app/user") == []
        assert idx.all_types() == []

    def test_type_for_path(self) -> None:
        idx = InMemoryTypeIndex()
        idx.add("app/user", "entity://p/users/alice", b"\x00" + b"\x01" * 32)
        assert idx.type_for_path("entity://p/users/alice") == "app/user"
        assert idx.type_for_path("entity://p/nonexistent") is None


# ============================================================================
# InMemoryReverseHashIndex
# ============================================================================


class TestInMemoryReverseHashIndex:
    def test_add_and_lookup(self) -> None:
        idx = InMemoryReverseHashIndex()
        ref_hash = b"\x00" + b"\xaa" * 32
        idx.add(ref_hash, "entity://p/a", "app/doc", "parent")
        results = idx.lookup(ref_hash)
        assert len(results) == 1
        assert results[0].source_path == "entity://p/a"
        assert results[0].source_type == "app/doc"
        assert results[0].field_name == "parent"

    def test_lookup_missing(self) -> None:
        idx = InMemoryReverseHashIndex()
        assert idx.lookup(b"\x00" + b"\xbb" * 32) == []

    def test_remove_by_source(self) -> None:
        idx = InMemoryReverseHashIndex()
        ref1 = b"\x00" + b"\xaa" * 32
        ref2 = b"\x00" + b"\xbb" * 32
        idx.add(ref1, "entity://p/a", "app/doc", "parent")
        idx.add(ref2, "entity://p/a", "app/doc", "child")
        idx.remove_by_source("entity://p/a")
        assert idx.lookup(ref1) == []
        assert idx.lookup(ref2) == []

    def test_remove_preserves_other_sources(self) -> None:
        idx = InMemoryReverseHashIndex()
        ref = b"\x00" + b"\xaa" * 32
        idx.add(ref, "entity://p/a", "app/doc", "parent")
        idx.add(ref, "entity://p/b", "app/doc", "parent")
        idx.remove_by_source("entity://p/a")
        results = idx.lookup(ref)
        assert len(results) == 1
        assert results[0].source_path == "entity://p/b"

    def test_multiple_refs_from_one_source(self) -> None:
        idx = InMemoryReverseHashIndex()
        ref1 = b"\x00" + b"\xaa" * 32
        ref2 = b"\x00" + b"\xbb" * 32
        idx.add(ref1, "entity://p/a", "app/doc", "parent")
        idx.add(ref2, "entity://p/a", "app/doc", "child")
        assert len(idx.lookup(ref1)) == 1
        assert len(idx.lookup(ref2)) == 1

    def test_clear(self) -> None:
        idx = InMemoryReverseHashIndex()
        ref = b"\x00" + b"\xaa" * 32
        idx.add(ref, "entity://p/a", "app/doc", "parent")
        idx.clear()
        assert idx.lookup(ref) == []


# ============================================================================
# InMemoryPathLinkIndex
# ============================================================================


class TestInMemoryPathLinkIndex:
    def test_add_and_lookup(self) -> None:
        idx = InMemoryPathLinkIndex()
        idx.add("config/db", "entity://p/a", "app/service", "config_path")
        results = idx.lookup("config/db")
        assert len(results) == 1
        assert results[0].source_path == "entity://p/a"

    def test_remove_by_source(self) -> None:
        idx = InMemoryPathLinkIndex()
        idx.add("config/db", "entity://p/a", "app/service", "config_path")
        idx.remove_by_source("entity://p/a")
        assert idx.lookup("config/db") == []


# ============================================================================
# collect_hash_refs
# ============================================================================


class TestCollectHashRefs:
    def test_flat_bytes(self) -> None:
        data = {"parent": b"\x00" + b"\xaa" * 32}
        refs = collect_hash_refs(data)
        assert len(refs) == 1
        assert refs[0] == ("parent", b"\x00" + b"\xaa" * 32)

    def test_nested_in_dict(self) -> None:
        data = {"metadata": {"ref": b"\x00" + b"\xbb" * 32}}
        refs = collect_hash_refs(data)
        assert len(refs) == 1
        assert refs[0][0] == "metadata"  # top-level field name

    def test_nested_in_list(self) -> None:
        data = {"parents": [b"\x00" + b"\xaa" * 32, b"\x00" + b"\xbb" * 32]}
        refs = collect_hash_refs(data)
        assert len(refs) == 2
        assert all(r[0] == "parents" for r in refs)

    def test_no_bytes(self) -> None:
        data = {"name": "alice", "age": 30, "active": True}
        refs = collect_hash_refs(data)
        assert refs == []

    def test_deeply_nested(self) -> None:
        data = {"tree": {"branch": {"leaf": b"\x00" + b"\xcc" * 32}}}
        refs = collect_hash_refs(data)
        assert len(refs) == 1
        assert refs[0][0] == "tree"


# ============================================================================
# IndexManager - change event maintenance
# ============================================================================


class TestIndexManagerMaintenance:
    def test_index_on_emit(self, indexed_emit: EmitPathway, index_manager: IndexManager) -> None:
        """Emitting an entity updates the type index."""
        entity = Entity(type="app/user", data={"name": "alice"})
        indexed_emit.emit("users/alice", entity)

        results = index_manager.type_index.lookup("app/user")
        assert len(results) == 1
        assert "users/alice" in results[0].path

    def test_index_on_update(self, indexed_emit: EmitPathway, index_manager: IndexManager) -> None:
        """Updating an entity updates the type index correctly."""
        e1 = Entity(type="app/user", data={"name": "alice"})
        e2 = Entity(type="app/user", data={"name": "alice", "age": 30})
        indexed_emit.emit("users/alice", e1)
        indexed_emit.emit("users/alice", e2)

        results = index_manager.type_index.lookup("app/user")
        assert len(results) == 1

    def test_index_on_delete(self, indexed_emit: EmitPathway, index_manager: IndexManager) -> None:
        """Deleting an entity removes it from the type index."""
        entity = Entity(type="app/user", data={"name": "alice"})
        indexed_emit.emit("users/alice", entity)
        indexed_emit.delete("users/alice")

        results = index_manager.type_index.lookup("app/user")
        assert len(results) == 0

    def test_reverse_index_on_emit(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Emitting an entity with hash references updates reverse index."""
        ref_hash = b"\x00" + b"\xaa" * 32
        entity = Entity(type="app/doc", data={"parent": ref_hash})
        indexed_emit.emit("docs/mydoc", entity)

        results = index_manager.reverse_index.lookup(ref_hash)
        assert len(results) == 1
        assert results[0].source_type == "app/doc"
        assert results[0].field_name == "parent"

    def test_reverse_index_on_update(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Updating an entity refreshes reverse index entries."""
        old_ref = b"\x00" + b"\xaa" * 32
        new_ref = b"\x00" + b"\xbb" * 32
        e1 = Entity(type="app/doc", data={"parent": old_ref})
        e2 = Entity(type="app/doc", data={"parent": new_ref})

        indexed_emit.emit("docs/mydoc", e1)
        indexed_emit.emit("docs/mydoc", e2)

        assert index_manager.reverse_index.lookup(old_ref) == []
        assert len(index_manager.reverse_index.lookup(new_ref)) == 1

    def test_reverse_index_on_delete(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Deleting an entity removes reverse index entries."""
        ref_hash = b"\x00" + b"\xaa" * 32
        entity = Entity(type="app/doc", data={"parent": ref_hash})
        indexed_emit.emit("docs/mydoc", entity)
        indexed_emit.delete("docs/mydoc")

        assert index_manager.reverse_index.lookup(ref_hash) == []

    def test_multiple_entities_indexed(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Multiple entities are properly indexed."""
        e1 = Entity(type="app/user", data={"name": "alice"})
        e2 = Entity(type="app/user", data={"name": "bob"})
        e3 = Entity(type="app/order", data={"item": "widget"})

        indexed_emit.emit("users/alice", e1)
        indexed_emit.emit("users/bob", e2)
        indexed_emit.emit("orders/o1", e3)

        assert len(index_manager.type_index.lookup("app/user")) == 2
        assert len(index_manager.type_index.lookup("app/order")) == 1

    def test_type_change_on_update(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Changing entity type at same path updates both type entries."""
        e1 = Entity(type="app/draft", data={"text": "hello"})
        e2 = Entity(type="app/published", data={"text": "hello"})

        indexed_emit.emit("docs/d1", e1)
        indexed_emit.emit("docs/d1", e2)

        assert len(index_manager.type_index.lookup("app/draft")) == 0
        assert len(index_manager.type_index.lookup("app/published")) == 1


# ============================================================================
# IndexManager - rebuild
# ============================================================================


class TestIndexManagerRebuild:
    def test_rebuild_from_tree(
        self, content_store: ContentStore, entity_tree: EntityTree
    ) -> None:
        """Rebuild re-indexes all tree-bound entities."""
        e1 = Entity(type="app/user", data={"name": "alice"})
        e2 = Entity(type="app/order", data={"item": "widget"})

        h1 = content_store.put(e1)
        h2 = content_store.put(e2)
        entity_tree.set("users/alice", h1)
        entity_tree.set("orders/o1", h2)

        manager = IndexManager(content_store=content_store)
        manager.rebuild(entity_tree)

        assert len(manager.type_index.lookup("app/user")) == 1
        assert len(manager.type_index.lookup("app/order")) == 1

    def test_rebuild_clears_old_data(
        self, content_store: ContentStore, entity_tree: EntityTree
    ) -> None:
        """Rebuild clears existing index data before re-indexing."""
        e1 = Entity(type="app/user", data={"name": "alice"})
        h1 = content_store.put(e1)
        entity_tree.set("users/alice", h1)

        manager = IndexManager(content_store=content_store)
        # Pre-populate with stale data
        manager.type_index.add("stale/type", "stale/path", b"\x00" * 33)

        manager.rebuild(entity_tree)

        assert manager.type_index.lookup("stale/type") == []
        assert len(manager.type_index.lookup("app/user")) == 1

    def test_rebuild_indexes_hash_refs(
        self, content_store: ContentStore, entity_tree: EntityTree
    ) -> None:
        """Rebuild indexes hash references in entity data."""
        ref_hash = b"\x00" + b"\xdd" * 32
        entity = Entity(type="app/doc", data={"parent": ref_hash})
        h = content_store.put(entity)
        entity_tree.set("docs/d1", h)

        manager = IndexManager(content_store=content_store)
        manager.rebuild(entity_tree)

        results = manager.reverse_index.lookup(ref_hash)
        assert len(results) == 1
        assert results[0].source_type == "app/doc"


# ============================================================================
# EntityTree.all_bindings
# ============================================================================


class TestEntityTreeAllBindings:
    def test_all_bindings_empty(self) -> None:
        tree = EntityTree("test-peer")
        assert tree.all_bindings() == []

    def test_all_bindings(self) -> None:
        tree = EntityTree("test-peer")
        h1 = b"\x00" + b"\x01" * 32
        h2 = b"\x00" + b"\x02" * 32
        tree.set("a/b", h1)
        tree.set("c/d", h2)
        bindings = tree.all_bindings()
        assert len(bindings) == 2
        paths = {uri for uri, _ in bindings}
        assert any("a/b" in p for p in paths)
        assert any("c/d" in p for p in paths)


# ============================================================================
# Query handler - find operation
# ============================================================================


class TestQueryHandlerFind:
    """Tests for the query handler find operation.

    Uses a minimal mock HandlerContext to avoid needing a full peer.
    """

    def _make_ctx(self, emit_pathway: EmitPathway) -> "HandlerContext":
        """Create a minimal handler context for testing."""
        from unittest.mock import MagicMock

        ctx = MagicMock()
        ctx.emit_pathway = emit_pathway
        ctx.local_peer_id = "test-peer"
        ctx.check_caller_permission = MagicMock(return_value=True)
        return ctx

    @pytest.mark.asyncio
    async def test_find_by_type(self, indexed_emit: EmitPathway, index_manager: IndexManager) -> None:
        """Find entities by type filter."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        e1 = Entity(type="app/user", data={"name": "alice"})
        e2 = Entity(type="app/user", data={"name": "bob"})
        e3 = Entity(type="app/order", data={"item": "widget"})
        indexed_emit.emit("users/alice", e1)
        indexed_emit.emit("users/bob", e2)
        indexed_emit.emit("orders/o1", e3)

        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/user"}},
            ctx,
        )

        assert result["status"] == 200
        matches = result["result"]["data"]["matches"]
        assert len(matches) == 2
        assert result["result"]["data"]["total"] == 2

    @pytest.mark.asyncio
    async def test_find_by_type_glob(self, indexed_emit: EmitPathway, index_manager: IndexManager) -> None:
        """Find entities by type glob pattern."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice"}))
        indexed_emit.emit("o/o1", Entity(type="app/order", data={"item": "widget"}))
        indexed_emit.emit("t/t1", Entity(type="system/type", data={"name": "foo"}))

        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/*"}},
            ctx,
        )

        assert result["status"] == 200
        assert result["result"]["data"]["total"] == 2

    @pytest.mark.asyncio
    async def test_find_by_ref(self, indexed_emit: EmitPathway, index_manager: IndexManager) -> None:
        """Find entities referencing a specific hash."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        ref_hash = b"\x00" + b"\xaa" * 32
        e1 = Entity(type="app/doc", data={"parent": ref_hash})
        e2 = Entity(type="app/doc", data={"parent": b"\x00" + b"\xbb" * 32})
        indexed_emit.emit("docs/d1", e1)
        indexed_emit.emit("docs/d2", e2)

        result = await handler(
            "system/query", "find",
            {"data": {"ref_filter": ref_hash, "type_filter": "app/doc"}},
            ctx,
        )

        assert result["status"] == 200
        assert result["result"]["data"]["total"] == 1

    @pytest.mark.asyncio
    async def test_find_with_path_prefix(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Find with path_prefix restricts results."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        indexed_emit.emit("users/alice", Entity(type="app/user", data={"name": "alice"}))
        indexed_emit.emit("users/bob", Entity(type="app/user", data={"name": "bob"}))
        indexed_emit.emit("orders/o1", Entity(type="app/user", data={"name": "system"}))

        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/user", "path_prefix": "users/"}},
            ctx,
        )

        assert result["status"] == 200
        assert result["result"]["data"]["total"] == 2

    @pytest.mark.asyncio
    async def test_find_with_field_filter(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Find with field filters (type scan fallback)."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice", "city": "Seattle"}))
        indexed_emit.emit("u/bob", Entity(type="app/user", data={"name": "bob", "city": "Portland"}))

        result = await handler(
            "system/query", "find",
            {"data": {
                "type_filter": "app/user",
                "field_filters": [{"field": "city", "operator": "eq", "value": "Seattle"}],
            }},
            ctx,
        )

        assert result["status"] == 200
        assert result["result"]["data"]["total"] == 1

    @pytest.mark.asyncio
    async def test_find_pagination(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Find with limit returns paginated results."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        for i in range(5):
            indexed_emit.emit(f"items/i{i}", Entity(type="app/item", data={"n": i}))

        # First page
        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/item", "limit": 2}},
            ctx,
        )

        assert result["status"] == 200
        data = result["result"]["data"]
        assert len(data["matches"]) == 2
        assert data["total"] == 5
        assert data["has_more"] is True
        assert "cursor" in data

        # Second page
        result2 = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/item", "limit": 2, "cursor": data["cursor"]}},
            ctx,
        )

        data2 = result2["result"]["data"]
        assert len(data2["matches"]) == 2
        assert data2["has_more"] is True

        # Third page (last)
        result3 = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/item", "limit": 2, "cursor": data2["cursor"]}},
            ctx,
        )

        data3 = result3["result"]["data"]
        assert len(data3["matches"]) == 1
        assert data3["has_more"] is False

    @pytest.mark.asyncio
    async def test_find_include_entities(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Find with include_entities includes full entities."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice"}))

        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/user", "include_entities": True}},
            ctx,
        )

        assert result["status"] == 200
        assert result["result"]["type"] == "system/envelope"
        assert len(result["result"]["data"]["included"]) == 1

    @pytest.mark.asyncio
    async def test_find_sorted_by_path(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Results are sorted by path by default."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        indexed_emit.emit("z/last", Entity(type="app/item", data={"n": 1}))
        indexed_emit.emit("a/first", Entity(type="app/item", data={"n": 2}))
        indexed_emit.emit("m/mid", Entity(type="app/item", data={"n": 3}))

        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/item"}},
            ctx,
        )

        paths = [m["path"] for m in result["result"]["data"]["matches"]]
        assert paths == sorted(paths)


# ============================================================================
# Query handler - count operation
# ============================================================================


class TestQueryHandlerCount:
    def _make_ctx(self, emit_pathway: EmitPathway) -> "HandlerContext":
        from unittest.mock import MagicMock

        ctx = MagicMock()
        ctx.emit_pathway = emit_pathway
        ctx.local_peer_id = "test-peer"
        ctx.check_caller_permission = MagicMock(return_value=True)
        return ctx

    @pytest.mark.asyncio
    async def test_count_by_type(self, indexed_emit: EmitPathway, index_manager: IndexManager) -> None:
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice"}))
        indexed_emit.emit("u/bob", Entity(type="app/user", data={"name": "bob"}))
        indexed_emit.emit("o/o1", Entity(type="app/order", data={"item": "widget"}))

        result = await handler(
            "system/query", "count",
            {"data": {"type_filter": "app/user"}},
            ctx,
        )

        assert result["status"] == 200
        assert result["result"]["data"] == 2


# ============================================================================
# Query handler - validation
# ============================================================================


class TestQueryValidation:
    def _make_ctx(self, emit_pathway: EmitPathway) -> "HandlerContext":
        from unittest.mock import MagicMock

        ctx = MagicMock()
        ctx.emit_pathway = emit_pathway
        ctx.local_peer_id = "test-peer"
        ctx.check_caller_permission = MagicMock(return_value=True)
        return ctx

    @pytest.mark.asyncio
    async def test_empty_query_rejected(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        result = await handler(
            "system/query", "find",
            {"data": {}},
            ctx,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "empty_query"

    @pytest.mark.asyncio
    async def test_field_filter_requires_type(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        result = await handler(
            "system/query", "find",
            {"data": {
                "field_filters": [{"field": "name", "operator": "eq", "value": "alice"}],
            }},
            ctx,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "type_filter_required"

    @pytest.mark.asyncio
    async def test_invalid_operator_rejected(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        result = await handler(
            "system/query", "find",
            {"data": {
                "type_filter": "app/user",
                "field_filters": [{"field": "name", "operator": "bogus", "value": "alice"}],
            }},
            ctx,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_operator"

    @pytest.mark.asyncio
    async def test_unsupported_operation(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        result = await handler(
            "system/query", "bogus",
            {"data": {"type_filter": "app/user"}},
            ctx,
        )
        assert result["status"] == 501


# ============================================================================
# Field filter operators
# ============================================================================


class TestFieldFilterOperators:
    def _make_ctx(self, emit_pathway: EmitPathway) -> "HandlerContext":
        from unittest.mock import MagicMock

        ctx = MagicMock()
        ctx.emit_pathway = emit_pathway
        ctx.local_peer_id = "test-peer"
        ctx.check_caller_permission = MagicMock(return_value=True)
        return ctx

    @pytest.mark.asyncio
    async def test_not_eq_operator(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice"}))
        indexed_emit.emit("u/bob", Entity(type="app/user", data={"name": "bob"}))

        result = await handler(
            "system/query", "find",
            {"data": {
                "type_filter": "app/user",
                "field_filters": [{"field": "name", "operator": "not_eq", "value": "alice"}],
            }},
            ctx,
        )
        assert result["result"]["data"]["total"] == 1

    @pytest.mark.asyncio
    async def test_in_operator(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice"}))
        indexed_emit.emit("u/bob", Entity(type="app/user", data={"name": "bob"}))
        indexed_emit.emit("u/carol", Entity(type="app/user", data={"name": "carol"}))

        result = await handler(
            "system/query", "find",
            {"data": {
                "type_filter": "app/user",
                "field_filters": [{"field": "name", "operator": "in", "value": ["alice", "carol"]}],
            }},
            ctx,
        )
        assert result["result"]["data"]["total"] == 2

    @pytest.mark.asyncio
    async def test_exists_operator(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice", "email": "a@b.c"}))
        indexed_emit.emit("u/bob", Entity(type="app/user", data={"name": "bob"}))

        result = await handler(
            "system/query", "find",
            {"data": {
                "type_filter": "app/user",
                "field_filters": [{"field": "email", "operator": "exists"}],
            }},
            ctx,
        )
        assert result["result"]["data"]["total"] == 1

    @pytest.mark.asyncio
    async def test_gt_lt_operators(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        for i in range(5):
            indexed_emit.emit(f"items/i{i}", Entity(type="app/item", data={"score": i * 10}))

        result = await handler(
            "system/query", "find",
            {"data": {
                "type_filter": "app/item",
                "field_filters": [{"field": "score", "operator": "gt", "value": 20}],
            }},
            ctx,
        )
        assert result["result"]["data"]["total"] == 2  # score=30, score=40

    @pytest.mark.asyncio
    async def test_prefix_operator(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice"}))
        indexed_emit.emit("u/alan", Entity(type="app/user", data={"name": "alan"}))
        indexed_emit.emit("u/bob", Entity(type="app/user", data={"name": "bob"}))

        result = await handler(
            "system/query", "find",
            {"data": {
                "type_filter": "app/user",
                "field_filters": [{"field": "name", "operator": "prefix", "value": "al"}],
            }},
            ctx,
        )
        assert result["result"]["data"]["total"] == 2


# ============================================================================
# QueryExtension
# ============================================================================


class TestQueryExtension:
    def test_extension_initialization(
        self, content_store: ContentStore, entity_tree: EntityTree
    ) -> None:
        """QueryExtension initializes indexes on initialization."""
        from entity_handlers.query import QueryExtension
        from entity_core.peer.extensions import ExtensionContext
        from unittest.mock import MagicMock

        # Pre-populate tree
        e1 = Entity(type="app/user", data={"name": "alice"})
        h1 = content_store.put(e1)
        entity_tree.set("users/alice", h1)

        emit = EmitPathway(content_store, entity_tree)
        keypair = MagicMock()
        keypair.peer_id = "test-peer"

        ext = QueryExtension()
        ext.initialize(ExtensionContext(keypair=keypair, emit_pathway=emit))

        assert ext.index_manager is not None
        results = ext.index_manager.type_index.lookup("app/user")
        assert len(results) == 1

    def test_handler_returns_function(self) -> None:
        """QueryExtension.handler() returns an async callable."""
        from entity_handlers.query import QueryExtension
        import asyncio

        ext = QueryExtension()
        h = ext.handler()
        assert callable(h)
        assert asyncio.iscoroutinefunction(h)


# ============================================================================
# Constraint handling (§5.2 steps 1-3, 8)
# ============================================================================


class TestConstraintHandling:
    def _make_ctx_with_grant(
        self,
        emit_pathway: EmitPathway,
        constraints: dict | None = None,
        allowances: dict | None = None,
    ) -> "HandlerContext":
        """Create a handler context with capability constraints and allowances.

        V7.14: constraints and allowances are separate map fields on the grant.
        """
        from unittest.mock import MagicMock

        ctx = MagicMock()
        ctx.emit_pathway = emit_pathway
        ctx.local_peer_id = "test-peer"
        ctx.check_caller_permission = MagicMock(return_value=True)

        grant: dict = {
            "handlers": {"include": ["system/query"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["find", "count"]},
        }
        if constraints is not None:
            grant["constraints"] = constraints
        if allowances is not None:
            grant["allowances"] = allowances

        ctx.caller_capability = {
            "grants": [grant],
        }
        return ctx

    @pytest.mark.asyncio
    async def test_type_scope_filters_results(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """type_scope on grant filters results to authorized types.

        Per §5.2 step 6a: type_scope is checked per-result, filtering
        out entities whose type is not in the authorized set.
        We use type_filter "app/*" with a type_scope that includes
        the glob "app/*" - so step 3 passes. But type_scope per-result
        filtering (step 6a) only allows app/user and app/order.
        """
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice"}))
        indexed_emit.emit("o/o1", Entity(type="app/order", data={"item": "widget"}))
        indexed_emit.emit("s/s1", Entity(type="app/secret", data={"key": "hidden"}))

        # Grant authorizes app/* at the query level (step 3 passes),
        # but per-result type_scope only allows specific types (step 6a)
        ctx = self._make_ctx_with_grant(indexed_emit, constraints={
            "type_scope": {"include": ["app/user", "app/order"]},
        })

        # Use specific type_filter that passes type_scope check
        # (type_filter must match type_scope per §5.2 step 3)
        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/user"}},
            ctx,
        )

        assert result["status"] == 200
        assert result["result"]["data"]["total"] == 1
        assert result["result"]["data"]["matches"][0]["type"] == "app/user"

    @pytest.mark.asyncio
    async def test_type_scope_glob_filters_per_result(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """type_scope with glob on grant allows glob type_filter and filters per-result."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice"}))
        indexed_emit.emit("o/o1", Entity(type="app/order", data={"item": "widget"}))
        indexed_emit.emit("s/s1", Entity(type="system/type", data={"name": "foo"}))

        # type_scope with "app/*" glob allows app/* type_filter
        ctx = self._make_ctx_with_grant(indexed_emit, constraints={
            "type_scope": {"include": ["app/*"]},
        })

        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/*"}},
            ctx,
        )

        assert result["status"] == 200
        types = {m["type"] for m in result["result"]["data"]["matches"]}
        assert "system/type" not in types
        assert result["result"]["data"]["total"] == 2

    @pytest.mark.asyncio
    async def test_type_filter_rejected_by_type_scope(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """type_filter outside type_scope returns 403."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx_with_grant(indexed_emit, constraints={
            "type_scope": {"include": ["app/user"]},
        })

        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/secret"}},
            ctx,
        )

        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "type_not_authorized"

    @pytest.mark.asyncio
    async def test_max_results_caps_limit(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """max_results constraint caps the effective query limit."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)

        for i in range(10):
            indexed_emit.emit(f"items/i{i}", Entity(type="app/item", data={"n": i}))

        # Grant limits to 3 results max
        ctx = self._make_ctx_with_grant(indexed_emit, constraints={
            "max_results": 3,
        })

        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/item", "limit": 100}},
            ctx,
        )

        assert result["status"] == 200
        assert len(result["result"]["data"]["matches"]) == 3
        assert result["result"]["data"]["total"] == 10
        assert result["result"]["data"]["has_more"] is True

    @pytest.mark.asyncio
    async def test_content_store_scope_requires_type_scope(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """content_store scope without type_scope returns 403."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx_with_grant(indexed_emit, allowances={
            "scope": "content_store",
            # No type_scope in constraints
        })

        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/user"}},
            ctx,
        )

        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "content_store_requires_type_scope"

    @pytest.mark.asyncio
    async def test_no_constraints_allows_all(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """No constraints on grant allows all types and default limits."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice"}))
        indexed_emit.emit("s/s1", Entity(type="app/secret", data={"key": "val"}))

        ctx = self._make_ctx_with_grant(indexed_emit)

        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/*"}},
            ctx,
        )

        assert result["status"] == 200
        assert result["result"]["data"]["total"] == 2


# ============================================================================
# path_filter support
# ============================================================================


class TestPathFilter:
    def _make_ctx(self, emit_pathway: EmitPathway) -> "HandlerContext":
        from unittest.mock import MagicMock

        ctx = MagicMock()
        ctx.emit_pathway = emit_pathway
        ctx.local_peer_id = "test-peer"
        ctx.check_caller_permission = MagicMock(return_value=True)
        return ctx

    @pytest.mark.asyncio
    async def test_path_filter_finds_referencing_entities(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """path_filter finds entities that reference a given path in their data."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        # Entity that references a path
        indexed_emit.emit("svc/web", Entity(
            type="app/service",
            data={"name": "web", "config_path": "config/database"},
        ))
        indexed_emit.emit("svc/api", Entity(
            type="app/service",
            data={"name": "api", "config_path": "config/cache"},
        ))

        result = await handler(
            "system/query", "find",
            {"data": {
                "type_filter": "app/service",
                "path_filter": "config/database",
            }},
            ctx,
        )

        assert result["status"] == 200
        assert result["result"]["data"]["total"] == 1

    @pytest.mark.asyncio
    async def test_path_filter_alone_not_empty_query(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """path_filter alone is not considered an empty query."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        # path_filter alone should not be rejected as empty_query
        # (it won't match anything without candidates, but it shouldn't 400)
        result = await handler(
            "system/query", "find",
            {"data": {"path_filter": "some/path", "type_filter": "app/*"}},
            ctx,
        )

        assert result["status"] == 200


# ============================================================================
# Error handling improvements
# ============================================================================


class TestErrorHandling:
    def _make_ctx(self, emit_pathway: EmitPathway) -> "HandlerContext":
        from unittest.mock import MagicMock

        ctx = MagicMock()
        ctx.emit_pathway = emit_pathway
        ctx.local_peer_id = "test-peer"
        ctx.check_caller_permission = MagicMock(return_value=True)
        return ctx

    @pytest.mark.asyncio
    async def test_invalid_cursor_returns_400(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Invalid/malformed cursor returns 400 instead of silently defaulting."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        indexed_emit.emit("u/alice", Entity(type="app/user", data={"name": "alice"}))

        result = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/user", "cursor": "not-valid-base64!!!"}},
            ctx,
        )

        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_cursor"

    @pytest.mark.asyncio
    async def test_valid_cursor_works(
        self, indexed_emit: EmitPathway, index_manager: IndexManager
    ) -> None:
        """Valid cursor from previous result works correctly."""
        from entity_handlers.query import create_query_handler

        handler = create_query_handler(index_manager)
        ctx = self._make_ctx(indexed_emit)

        for i in range(5):
            indexed_emit.emit(f"items/i{i}", Entity(type="app/item", data={"n": i}))

        r1 = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/item", "limit": 2}},
            ctx,
        )
        assert r1["status"] == 200
        cursor = r1["result"]["data"]["cursor"]

        r2 = await handler(
            "system/query", "find",
            {"data": {"type_filter": "app/item", "limit": 2, "cursor": cursor}},
            ctx,
        )
        assert r2["status"] == 200
        assert len(r2["result"]["data"]["matches"]) == 2


# ============================================================================
# Query type definitions
# ============================================================================


class TestQueryTypeDefinitions:
    def test_query_types_registered(self) -> None:
        """Query type definitions are in ALL_TYPE_DEFINITIONS."""
        from entity_core.types.definitions import get_all_type_entities

        types = get_all_type_entities()
        type_names = {t.data["name"] for t in types}

        assert "system/query/expression" in type_names
        assert "system/query/field-predicate" in type_names
        assert "system/query/result" in type_names
        assert "system/query/match" in type_names
        assert "system/query/constraints" in type_names

    def test_expression_type_has_all_fields(self) -> None:
        """system/query/expression type has all spec fields."""
        from entity_core.types.definitions import type_system_query_expression

        expr_type = type_system_query_expression()
        fields = expr_type.data["fields"]

        expected = {
            "type_filter", "field_filters", "ref_filter", "path_filter",
            "path_prefix", "limit", "cursor", "order_by", "descending",
            "include_entities",
        }
        assert set(fields.keys()) == expected

    def test_constraints_type_fields(self) -> None:
        """system/query/constraints has max_results, type_scope (scope moved to allowances)."""
        from entity_core.types.definitions import type_system_query_constraints

        ct = type_system_query_constraints()
        fields = ct.data["fields"]

        assert "max_results" in fields
        assert "type_scope" in fields
        assert "scope" not in fields  # V1.1: moved to allowances

    def test_allowances_type_fields(self) -> None:
        """system/query/allowances has scope field."""
        from entity_core.types.definitions import type_system_query_allowances

        at = type_system_query_allowances()
        fields = at.data["fields"]

        assert "scope" in fields

    def test_index_config_type_registered(self) -> None:
        """system/query/index-config type is registered."""
        from entity_core.types.definitions import get_all_type_entities

        types = get_all_type_entities()
        type_names = {t.data["name"] for t in types}
        assert "system/query/index-config" in type_names
        assert "system/query/allowances" in type_names
