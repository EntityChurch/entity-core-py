"""Unit tests for Tree Extension operations (EXTENSION-TREE.md v3.0).

Tests for:
- snapshot: Capture tree state
- diff: Compare two snapshots
- merge: Apply snapshot into tree
- extract: Bundle subtree as envelope
- create/destroy: Non-default tree management
"""

from __future__ import annotations

import pytest

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.tree_registry import TreeRegistry
from entity_handlers.tree import tree_handler


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
def tree_registry(entity_tree: EntityTree, content_store: ContentStore) -> TreeRegistry:
    """Create a tree registry."""
    return TreeRegistry(entity_tree, content_store)


@pytest.fixture
def handler_context(emit_pathway: EmitPathway, tree_registry: TreeRegistry) -> HandlerContext:
    """Create a handler context with permissive capability."""
    # Create a permissive capability that allows all operations on all paths
    # Note: check_path_permission expects the capability data directly, not wrapped in {"data": ...}
    permissive_capability = {
        "grants": [
            {
                "handlers": {"include": ["*"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["*"]},
            }
        ]
    }
    return HandlerContext(
        local_peer_id="test-peer",
        remote_peer_id="remote-peer",
        handler_grant=permissive_capability,
        caller_capability=permissive_capability,
        emit_pathway=emit_pathway,
        tree_registry=tree_registry,
        handler_pattern="system/tree",
    )


@pytest.fixture
def sample_entities(emit_pathway: EmitPathway) -> dict[str, bytes]:
    """Create sample entities in the tree and return their hashes."""
    entities = {
        "data/file1.txt": Entity(type="test/file", data={"content": "Hello"}),
        "data/file2.txt": Entity(type="test/file", data={"content": "World"}),
        "data/subdir/file3.txt": Entity(type="test/file", data={"content": "Nested"}),
    }
    hashes = {}
    for path, entity in entities.items():
        h = emit_pathway.emit(path, entity).hash
        hashes[path] = h
    return hashes


def _snap_entity(result: dict) -> dict:
    """The system/tree/snapshot entity dict from a snapshot/extract result.

    v3.6 F4-cycle wire shape: ``result["result"]`` IS the snapshot entity
    directly; bundled trie nodes ride in ``result["envelope_included"]``
    (drained to the outer wire envelope at send time).
    """
    return result["result"]


def _snap_included(result: dict) -> dict:
    """The bundled trie nodes from a snapshot/extract result."""
    return result.get("envelope_included") or {}


class TestTreeSnapshot:
    """Tests for snapshot operation."""

    @pytest.mark.asyncio
    async def test_snapshot_full_tree(
        self, handler_context: HandlerContext, sample_entities: dict[str, bytes]
    ) -> None:
        """Snapshot with empty prefix captures entire tree."""
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )

        assert result["status"] == 200
        snapshot = _snap_entity(result)
        assert snapshot["type"] == "system/tree/snapshot"
        # Per I3: snapshot has no prefix field — it's pure content
        assert "prefix" not in snapshot["data"]
        from entity_core.storage.trie import collect_all_bindings
        root_hash = snapshot["data"]["root"]
        bindings = dict(collect_all_bindings(root_hash, "", handler_context.emit_pathway.content_store))
        assert len(bindings) == 3

    @pytest.mark.asyncio
    async def test_snapshot_subtree(
        self, handler_context: HandlerContext, sample_entities: dict[str, bytes]
    ) -> None:
        """Snapshot with prefix captures only subtree."""
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": "data/subdir/"}}, handler_context
        )

        assert result["status"] == 200
        snapshot = _snap_entity(result)
        from entity_core.storage.trie import collect_all_bindings
        root_hash = snapshot["data"]["root"]
        bindings = dict(collect_all_bindings(root_hash, "", handler_context.emit_pathway.content_store))
        assert len(bindings) == 1
        assert "file3.txt" in bindings

    @pytest.mark.asyncio
    async def test_snapshot_invalid_prefix(
        self, handler_context: HandlerContext
    ) -> None:
        """Snapshot rejects non-empty prefix without trailing slash."""
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": "data/subdir"}}, handler_context
        )

        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_prefix"

    @pytest.mark.asyncio
    async def test_snapshot_empty_tree(
        self, handler_context: HandlerContext
    ) -> None:
        """Snapshot of empty tree returns empty bindings."""
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )

        assert result["status"] == 200
        from entity_core.storage.trie import collect_all_bindings
        root_hash = _snap_entity(result)["data"]["root"]
        bindings = dict(collect_all_bindings(root_hash, "", handler_context.emit_pathway.content_store))
        assert bindings == {}

    @pytest.mark.asyncio
    async def test_snapshot_deterministic(
        self, handler_context: HandlerContext, sample_entities: dict[str, bytes]
    ) -> None:
        """Same bindings produce same snapshot hash."""
        result1 = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        result2 = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )

        # Same content hash
        assert _snap_entity(result1)["content_hash"] == _snap_entity(result2)["content_hash"]


class TestTreeDiff:
    """Tests for diff operation."""

    @pytest.mark.asyncio
    async def test_diff_identical_snapshots(
        self, handler_context: HandlerContext, sample_entities: dict[str, bytes]
    ) -> None:
        """Diff of identical snapshots shows no changes."""
        # Create snapshot
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snapshot_hash = _snap_entity(result)["content_hash"]

        # Store snapshot in content store
        snapshot_entity = Entity(
            type="system/tree/snapshot",
            data=_snap_entity(result)["data"],
        )
        handler_context.emit_pathway.content_store.put(snapshot_entity)

        # Diff with itself
        result = await tree_handler(
            "system/tree",
            "diff",
            {"data": {"base": snapshot_hash, "target": snapshot_hash}},
            handler_context,
        )

        assert result["status"] == 200
        diff = result["result"]["data"]
        assert diff["added"] == {}
        assert diff["removed"] == {}
        assert diff["changed"] == {}
        assert diff["unchanged"] == 3

    @pytest.mark.asyncio
    async def test_diff_added_entries(
        self, handler_context: HandlerContext, emit_pathway: EmitPathway
    ) -> None:
        """Diff shows added entries between snapshots."""
        # Create empty snapshot
        result1 = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snap1 = Entity(type="system/tree/snapshot", data=_snap_entity(result1)["data"])
        h1 = emit_pathway.content_store.put(snap1)

        # Add entity
        emit_pathway.emit("data/new.txt", Entity(type="test/file", data={"content": "New"}))

        # Create second snapshot
        result2 = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snap2 = Entity(type="system/tree/snapshot", data=_snap_entity(result2)["data"])
        h2 = emit_pathway.content_store.put(snap2)

        # Diff
        result = await tree_handler(
            "system/tree", "diff", {"data": {"base": h1, "target": h2}}, handler_context
        )

        assert result["status"] == 200
        diff = result["result"]["data"]
        assert len(diff["added"]) == 1
        assert "data/new.txt" in diff["added"]
        assert diff["removed"] == {}
        assert diff["changed"] == {}

    @pytest.mark.asyncio
    async def test_diff_removed_entries(
        self, handler_context: HandlerContext, emit_pathway: EmitPathway, sample_entities: dict[str, bytes]
    ) -> None:
        """Diff shows removed entries between snapshots."""
        # Create snapshot with entities
        result1 = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snap1 = Entity(type="system/tree/snapshot", data=_snap_entity(result1)["data"])
        h1 = emit_pathway.content_store.put(snap1)

        # Remove an entity
        emit_pathway.delete("data/file1.txt")

        # Create second snapshot
        result2 = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snap2 = Entity(type="system/tree/snapshot", data=_snap_entity(result2)["data"])
        h2 = emit_pathway.content_store.put(snap2)

        # Diff
        result = await tree_handler(
            "system/tree", "diff", {"data": {"base": h1, "target": h2}}, handler_context
        )

        assert result["status"] == 200
        diff = result["result"]["data"]
        assert diff["added"] == {}
        assert len(diff["removed"]) == 1
        assert "data/file1.txt" in diff["removed"]

    @pytest.mark.asyncio
    async def test_diff_changed_entries(
        self, handler_context: HandlerContext, emit_pathway: EmitPathway, sample_entities: dict[str, bytes]
    ) -> None:
        """Diff shows changed entries between snapshots."""
        # Create snapshot
        result1 = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snap1 = Entity(type="system/tree/snapshot", data=_snap_entity(result1)["data"])
        h1 = emit_pathway.content_store.put(snap1)

        # Modify an entity
        emit_pathway.emit("data/file1.txt", Entity(type="test/file", data={"content": "Modified"}))

        # Create second snapshot
        result2 = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snap2 = Entity(type="system/tree/snapshot", data=_snap_entity(result2)["data"])
        h2 = emit_pathway.content_store.put(snap2)

        # Diff
        result = await tree_handler(
            "system/tree", "diff", {"data": {"base": h1, "target": h2}}, handler_context
        )

        assert result["status"] == 200
        diff = result["result"]["data"]
        assert diff["added"] == {}
        assert diff["removed"] == {}
        assert len(diff["changed"]) == 1
        assert "data/file1.txt" in diff["changed"]

    @pytest.mark.asyncio
    async def test_diff_snapshot_not_found(
        self, handler_context: HandlerContext
    ) -> None:
        """Diff returns error when snapshot not found."""
        fake_hash = bytes([0x00] + [0x42] * 32)  # Non-existent hash

        result = await tree_handler(
            "system/tree", "diff", {"data": {"base": fake_hash, "target": fake_hash}}, handler_context
        )

        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "snapshot_not_found"


class TestTreeMerge:
    """Tests for merge operation."""

    @pytest.mark.asyncio
    async def test_merge_into_empty_tree(
        self, handler_context: HandlerContext, emit_pathway: EmitPathway, sample_entities: dict[str, bytes]
    ) -> None:
        """Merge applies all bindings to empty tree."""
        # Create snapshot
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snap = Entity(type="system/tree/snapshot", data=_snap_entity(result)["data"])
        snap_hash = emit_pathway.content_store.put(snap)

        # Create empty target tree
        handler_context.tree_registry.create({
            "tree_id": "target",
            "root_structure": "peer-namespaced",
        })

        # Merge
        result = await tree_handler(
            "system/tree",
            "merge",
            {"data": {"source": snap_hash, "target_tree": "target"}},
            handler_context,
        )

        assert result["status"] == 200
        merge_result = result["result"]["data"]
        assert merge_result["applied"] == 3
        assert merge_result["skipped"] == 0
        assert merge_result["conflicts"] == {}
        assert merge_result["strategy"] == "no-overwrite"

    @pytest.mark.asyncio
    async def test_merge_no_overwrite_strategy(
        self, handler_context: HandlerContext, emit_pathway: EmitPathway, sample_entities: dict[str, bytes]
    ) -> None:
        """no-overwrite strategy reports conflicts without overwriting."""
        # Create snapshot
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snap = Entity(type="system/tree/snapshot", data=_snap_entity(result)["data"])
        snap_hash = emit_pathway.content_store.put(snap)

        # Modify entity in default tree
        emit_pathway.emit("data/file1.txt", Entity(type="test/file", data={"content": "Modified"}))

        # Merge back (will conflict)
        result = await tree_handler(
            "system/tree",
            "merge",
            {"data": {"source": snap_hash, "strategy": "no-overwrite"}},
            handler_context,
        )

        assert result["status"] == 200
        merge_result = result["result"]["data"]
        assert merge_result["applied"] == 0
        assert merge_result["skipped"] == 3  # 2 unchanged + 1 conflict skipped
        # Check conflict reported
        conflicts = merge_result["conflicts"]
        # Path with leading peer prefix
        assert any("file1.txt" in path for path in conflicts)
        # Conflict should be unresolved
        for conflict in conflicts.values():
            assert conflict["resolution"] == "unresolved"

    @pytest.mark.asyncio
    async def test_merge_source_wins_strategy(
        self, handler_context: HandlerContext, emit_pathway: EmitPathway, sample_entities: dict[str, bytes]
    ) -> None:
        """source-wins strategy overwrites conflicts."""
        # Get original hash
        original_hash = sample_entities["data/file1.txt"]

        # Create snapshot
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snap = Entity(type="system/tree/snapshot", data=_snap_entity(result)["data"])
        snap_hash = emit_pathway.content_store.put(snap)

        # Modify entity
        emit_pathway.emit("data/file1.txt", Entity(type="test/file", data={"content": "Modified"}))

        # Merge with source-wins
        result = await tree_handler(
            "system/tree",
            "merge",
            {"data": {"source": snap_hash, "strategy": "source-wins"}},
            handler_context,
        )

        assert result["status"] == 200
        merge_result = result["result"]["data"]
        # Conflict overwritten
        conflicts = merge_result["conflicts"]
        for conflict in conflicts.values():
            assert conflict["resolution"] == "used-incoming"

        # Verify entity was restored
        uri = emit_pathway.entity_tree.normalize_uri("data/file1.txt")
        current_hash = emit_pathway.entity_tree.get(uri)
        assert current_hash == original_hash

    @pytest.mark.asyncio
    async def test_merge_target_wins_strategy(
        self, handler_context: HandlerContext, emit_pathway: EmitPathway, sample_entities: dict[str, bytes]
    ) -> None:
        """target-wins strategy keeps existing values."""
        # Create snapshot
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snap = Entity(type="system/tree/snapshot", data=_snap_entity(result)["data"])
        snap_hash = emit_pathway.content_store.put(snap)

        # Modify entity
        modified_entity = Entity(type="test/file", data={"content": "Modified"})
        emit_pathway.emit("data/file1.txt", modified_entity)
        modified_hash = emit_pathway.entity_tree.get(
            emit_pathway.entity_tree.normalize_uri("data/file1.txt")
        )

        # Merge with target-wins
        result = await tree_handler(
            "system/tree",
            "merge",
            {"data": {"source": snap_hash, "strategy": "target-wins"}},
            handler_context,
        )

        assert result["status"] == 200
        merge_result = result["result"]["data"]
        conflicts = merge_result["conflicts"]
        for conflict in conflicts.values():
            assert conflict["resolution"] == "kept-existing"

        # Verify entity unchanged
        uri = emit_pathway.entity_tree.normalize_uri("data/file1.txt")
        current_hash = emit_pathway.entity_tree.get(uri)
        assert current_hash == modified_hash

    @pytest.mark.asyncio
    async def test_merge_dry_run(
        self, handler_context: HandlerContext, emit_pathway: EmitPathway, sample_entities: dict[str, bytes]
    ) -> None:
        """dry_run computes result without modifying tree."""
        # Create snapshot
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": ""}}, handler_context
        )
        snap = Entity(type="system/tree/snapshot", data=_snap_entity(result)["data"])
        snap_hash = emit_pathway.content_store.put(snap)

        # Create empty target tree
        handler_context.tree_registry.create({
            "tree_id": "target",
            "root_structure": "peer-namespaced",
        })
        target_tree = handler_context.tree_registry.get("target")

        # Dry run merge
        result = await tree_handler(
            "system/tree",
            "merge",
            {"data": {"source": snap_hash, "target_tree": "target", "dry_run": True}},
            handler_context,
        )

        assert result["status"] == 200
        merge_result = result["result"]["data"]
        # Cross-impl alignment with Go's `core/tree/operations.go`:
        # `applied` counts would-apply paths (the `!exists` branch
        # increments `applied++` even in dry-run). `conflicts` only
        # carries entries for actual conflicts (existing != incoming);
        # new-path additions are not reported as conflicts because Go's
        # MergeConflictData.ExistingHash is required-non-zero on the
        # wire — emitting None there would CBOR-decode as 0 bytes and
        # break wire compat.
        assert merge_result["applied"] == 3
        assert merge_result["conflicts"] == {}

        # Target tree should still be empty
        assert len(target_tree) == 0

    @pytest.mark.asyncio
    async def test_merge_prefix_remapping(
        self, handler_context: HandlerContext, emit_pathway: EmitPathway, sample_entities: dict[str, bytes]
    ) -> None:
        """Prefix remapping translates paths during merge."""
        # Create snapshot with data/ prefix
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": "data/"}}, handler_context
        )
        snap = Entity(type="system/tree/snapshot", data=_snap_entity(result)["data"])
        snap_hash = emit_pathway.content_store.put(snap)

        # Create target tree
        handler_context.tree_registry.create({
            "tree_id": "target",
            "root_structure": "peer-namespaced",
        })
        target_tree = handler_context.tree_registry.get("target")

        # Merge with prefix remapping
        result = await tree_handler(
            "system/tree",
            "merge",
            {
                "data": {
                    "source": snap_hash,
                    "target_tree": "target",
                    "source_prefix": "data/",
                    "target_prefix": "backup/",
                }
            },
            handler_context,
        )

        assert result["status"] == 200

        # Paths should be under backup/ in target tree
        uris = target_tree.list_prefix(target_tree.normalize_uri("backup/"))
        assert len(uris) > 0


class TestTreeExtract:
    """Tests for extract operation."""

    @pytest.mark.asyncio
    async def test_extract_full_subtree(
        self, handler_context: HandlerContext, sample_entities: dict[str, bytes]
    ) -> None:
        """Extract bundles snapshot with referenced entities."""
        result = await tree_handler(
            "system/tree", "extract", {"data": {"prefix": "data/"}}, handler_context
        )

        assert result["status"] == 200
        # extract's contract is system/envelope (the op IS the bundle).
        envelope = result["result"]
        assert envelope["type"] == "system/envelope"

        # Root is snapshot (no prefix per I3)
        root = envelope["data"]["root"]
        assert root["type"] == "system/tree/snapshot"
        assert "prefix" not in root["data"]

        # Included has entities
        included = envelope["data"]["included"]
        assert len(included) > 0

    @pytest.mark.asyncio
    async def test_extract_with_paths_filter(
        self, handler_context: HandlerContext, sample_entities: dict[str, bytes]
    ) -> None:
        """Extract with paths filter includes only specified paths."""
        result = await tree_handler(
            "system/tree",
            "extract",
            {"data": {"prefix": "data/", "paths": ["file1.txt"]}},
            handler_context,
        )

        assert result["status"] == 200
        # extract returns a system/envelope; snapshot is at data.root
        envelope = result["result"]
        root = envelope["data"]["root"]

        from entity_core.storage.trie import collect_all_bindings
        root_hash = root["data"]["root"]
        bindings = dict(collect_all_bindings(root_hash, "", handler_context.emit_pathway.content_store))
        assert len(bindings) == 1
        assert "file1.txt" in bindings

    @pytest.mark.asyncio
    async def test_extract_invalid_prefix(
        self, handler_context: HandlerContext
    ) -> None:
        """Extract rejects non-empty prefix without trailing slash."""
        result = await tree_handler(
            "system/tree", "extract", {"data": {"prefix": "data"}}, handler_context
        )

        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_prefix"


class TestTreeCreateDestroy:
    """Tests for create and destroy operations."""

    @pytest.mark.asyncio
    async def test_create_tree(
        self, handler_context: HandlerContext
    ) -> None:
        """Create operation creates a new tree."""
        result = await tree_handler(
            "system/tree",
            "create",
            {
                "data": {
                    "tree_id": "staging",
                    "root_structure": "peer-namespaced",
                    "purpose": "staging",
                }
            },
            handler_context,
        )

        assert result["status"] == 200
        config = result["result"]["data"]
        assert config["tree_id"] == "staging"

        # Tree should exist
        assert handler_context.tree_registry.exists("staging")

    @pytest.mark.asyncio
    async def test_create_duplicate_tree(
        self, handler_context: HandlerContext
    ) -> None:
        """Create returns error for duplicate tree_id."""
        # Create first
        await tree_handler(
            "system/tree",
            "create",
            {"data": {"tree_id": "staging", "root_structure": "peer-namespaced"}},
            handler_context,
        )

        # Try to create again
        result = await tree_handler(
            "system/tree",
            "create",
            {"data": {"tree_id": "staging", "root_structure": "peer-namespaced"}},
            handler_context,
        )

        assert result["status"] == 409
        assert result["result"]["data"]["code"] == "tree_exists"

    @pytest.mark.asyncio
    async def test_create_view_tree_requires_capability(
        self, handler_context: HandlerContext
    ) -> None:
        """Create view tree requires capability when source is present."""
        result = await tree_handler(
            "system/tree",
            "create",
            {
                "data": {
                    "tree_id": "view",
                    "root_structure": "peer-namespaced",
                    "source": "default",
                }
            },
            handler_context,
        )

        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_config"

    @pytest.mark.asyncio
    async def test_destroy_tree(
        self, handler_context: HandlerContext
    ) -> None:
        """Destroy removes tree and bindings."""
        # Create tree
        await tree_handler(
            "system/tree",
            "create",
            {"data": {"tree_id": "staging", "root_structure": "peer-namespaced"}},
            handler_context,
        )

        # Destroy
        result = await tree_handler(
            "system/tree", "destroy", {"data": "staging"}, handler_context
        )

        assert result["status"] == 200
        assert result["result"]["data"] is True
        assert not handler_context.tree_registry.exists("staging")

    @pytest.mark.asyncio
    async def test_destroy_nonexistent_tree(
        self, handler_context: HandlerContext
    ) -> None:
        """Destroy returns error for nonexistent tree."""
        result = await tree_handler(
            "system/tree", "destroy", {"data": "nonexistent"}, handler_context
        )

        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "tree_not_found"

    @pytest.mark.asyncio
    async def test_destroy_default_tree(
        self, handler_context: HandlerContext
    ) -> None:
        """Destroy returns error for default tree."""
        result = await tree_handler(
            "system/tree", "destroy", {"data": ""}, handler_context
        )

        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "default_tree"


class TestTreeRegistry:
    """Tests for TreeRegistry class."""

    def test_registry_get_default(
        self, tree_registry: TreeRegistry, entity_tree: EntityTree
    ) -> None:
        """get(None) returns default tree."""
        assert tree_registry.get(None) is entity_tree
        assert tree_registry.get("") is entity_tree

    def test_registry_create_and_get(
        self, tree_registry: TreeRegistry
    ) -> None:
        """Create and retrieve a non-default tree."""
        config = {"tree_id": "test", "root_structure": "peer-namespaced"}
        tree = tree_registry.create(config)

        assert tree is not None
        assert tree_registry.get("test") is tree
        assert tree_registry.exists("test")

    def test_registry_destroy(
        self, tree_registry: TreeRegistry
    ) -> None:
        """Destroy removes tree from registry."""
        tree_registry.create({"tree_id": "test", "root_structure": "peer-namespaced"})
        assert tree_registry.exists("test")

        tree_registry.destroy("test")
        assert not tree_registry.exists("test")
        assert tree_registry.get("test") is None

    def test_registry_list_trees(
        self, tree_registry: TreeRegistry
    ) -> None:
        """list_trees returns all non-default tree IDs."""
        tree_registry.create({"tree_id": "a", "root_structure": "peer-namespaced"})
        tree_registry.create({"tree_id": "b", "root_structure": "peer-namespaced"})

        trees = tree_registry.list_trees()
        assert set(trees) == {"a", "b"}

    def test_registry_get_config(
        self, tree_registry: TreeRegistry
    ) -> None:
        """get_config returns tree configuration."""
        config = {"tree_id": "test", "root_structure": "relaxed", "purpose": "staging"}
        tree_registry.create(config)

        retrieved = tree_registry.get_config("test")
        assert retrieved == config


class TestCapabilityChecks:
    """Tests for capability permission checks."""

    @pytest.mark.asyncio
    async def test_snapshot_forbidden_without_get_permission(
        self, emit_pathway: EmitPathway, tree_registry: TreeRegistry
    ) -> None:
        """Snapshot fails without get permission on prefix."""
        # Create restrictive capability
        restrictive_cap = {
            "grants": [
                {
                    "handlers": {"include": ["system/tree"]},
                    "resources": {"include": ["other/*"]},  # Not data/*
                    "operations": {"include": ["get"]},
                }
            ]
        }
        ctx = HandlerContext(
            local_peer_id="test-peer",
            remote_peer_id="remote-peer",
            handler_grant=restrictive_cap,
            caller_capability=restrictive_cap,
            emit_pathway=emit_pathway,
            tree_registry=tree_registry,
            handler_pattern="system/tree",
        )

        # Add entity under data/
        emit_pathway.emit("data/file.txt", Entity(type="test/file", data={"content": "test"}))

        # Try snapshot of data/
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": "data/"}}, ctx
        )

        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "forbidden"

    @pytest.mark.asyncio
    async def test_merge_forbidden_without_put_permission(
        self, emit_pathway: EmitPathway, tree_registry: TreeRegistry
    ) -> None:
        """Merge fails without put permission on target paths."""
        # Create permissive capability for snapshot
        permissive_cap = {
            "grants": [
                {
                    "handlers": {"include": ["*"]},
                    "resources": {"include": ["*"]},
                    "operations": {"include": ["*"]},
                }
            ]
        }
        permissive_ctx = HandlerContext(
            local_peer_id="test-peer",
            remote_peer_id="remote-peer",
            handler_grant=permissive_cap,
            caller_capability=permissive_cap,
            emit_pathway=emit_pathway,
            tree_registry=tree_registry,
            handler_pattern="system/tree",
        )

        # Add entity and create snapshot
        emit_pathway.emit("data/file.txt", Entity(type="test/file", data={"content": "test"}))
        result = await tree_handler(
            "system/tree", "snapshot", {"data": {"prefix": "data/"}}, permissive_ctx
        )
        snap = Entity(type="system/tree/snapshot", data=_snap_entity(result)["data"])
        snap_hash = emit_pathway.content_store.put(snap)

        # Create restrictive context without put permission
        restrictive_cap = {
            "grants": [
                {
                    "handlers": {"include": ["system/tree"]},
                    "resources": {"include": ["data/*"]},
                    "operations": {"include": ["get"]},  # No put
                }
            ]
        }
        restrictive_ctx = HandlerContext(
            local_peer_id="test-peer",
            remote_peer_id="remote-peer",
            handler_grant=restrictive_cap,
            caller_capability=restrictive_cap,
            emit_pathway=emit_pathway,
            tree_registry=tree_registry,
            handler_pattern="system/tree",
        )

        # Try merge
        result = await tree_handler(
            "system/tree", "merge", {"data": {"source": snap_hash}}, restrictive_ctx
        )

        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "capability_denied"
