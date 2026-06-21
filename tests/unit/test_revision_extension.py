"""Unit tests for Revision Extension (EXTENSION-REVISION v2.1).

Tests for structural version entries, sorted parents, trie-based snapshots,
oscillation detection, and all operations (including fetch-diff, v3.4 §4.4.19).
"""

from __future__ import annotations

import pytest

from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.tree_registry import TreeRegistry
from entity_core.storage.trie import build_trie, collect_all_bindings
from entity_handlers.revision import (
    REVISION_HANDLER_PATTERN,
    VERSION_ENTRY_TYPE,
    CONFLICT_TYPE,
    VersionRelationship,
    revision_handler,
    sorted_parents,
    _compute_prefix_hash,
    _head_path,
    _detect_oscillation,
    _normalize_merge_sides,
    _walk_history,
    _find_common_ancestor,
    _is_ancestor,
    _check_relationship,
    _collect_missing_pull_hashes,
)


def _unwrap_envelope(result: dict) -> dict:
    """Unwrap system/envelope if present (M3 compatibility).

    Returns a dict with 'status', 'result' (the actual domain result),
    and 'included' (entities from the envelope, if any).
    """
    r = result.get("result", {})
    if r.get("type") == "system/envelope":
        return {
            "status": result["status"],
            "result": r["data"]["root"],
            "included": r["data"].get("included", {}),
        }
    return result


@pytest.fixture
def content_store() -> ContentStore:
    return ContentStore()


@pytest.fixture
def entity_tree() -> EntityTree:
    return EntityTree("test-peer")


@pytest.fixture
def emit_pathway(content_store, entity_tree) -> EmitPathway:
    return EmitPathway(content_store, entity_tree)


@pytest.fixture
def tree_registry(entity_tree, content_store) -> TreeRegistry:
    return TreeRegistry(entity_tree, content_store)


@pytest.fixture
def handler_context(emit_pathway, tree_registry) -> HandlerContext:
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
        handler_pattern="system/revision",
    )


@pytest.fixture
def sample_entities(emit_pathway) -> dict[str, bytes]:
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


# =============================================================================
# Sorted Parents
# =============================================================================


class TestSortedParents:
    def test_empty(self):
        assert sorted_parents([]) == []

    def test_single(self):
        h = b"\x00" + b"\x01" * 32
        assert sorted_parents([h]) == [h]

    def test_sorted_by_binary(self):
        h1 = b"\x00" + b"\x01" * 32
        h2 = b"\x00" + b"\x02" * 32
        h3 = b"\x00" + b"\x03" * 32
        # Regardless of input order, output is sorted
        assert sorted_parents([h3, h1, h2]) == [h1, h2, h3]

    def test_deterministic(self):
        h1 = b"\x00" + b"\xaa" * 32
        h2 = b"\x00" + b"\xbb" * 32
        assert sorted_parents([h1, h2]) == sorted_parents([h2, h1])


# =============================================================================
# Merge Side Normalization
# =============================================================================


class TestNormalizeMergeSides:
    def test_caller_perspective(self):
        h1 = b"\x00" + b"\x01" * 32
        h2 = b"\x00" + b"\x02" * 32
        local, remote = _normalize_merge_sides(h1, h2, "caller-perspective")
        assert local == h1
        assert remote == h2

    def test_deterministic_already_ordered(self):
        h1 = b"\x00" + b"\x01" * 32
        h2 = b"\x00" + b"\x02" * 32
        local, remote = _normalize_merge_sides(h1, h2, "deterministic")
        assert local == h1  # lower hash
        assert remote == h2

    def test_deterministic_swaps(self):
        h1 = b"\x00" + b"\x01" * 32
        h2 = b"\x00" + b"\x02" * 32
        local, remote = _normalize_merge_sides(h2, h1, "deterministic")
        assert local == h1  # lower hash
        assert remote == h2


# =============================================================================
# Commit
# =============================================================================


class TestCommit:
    @pytest.mark.asyncio
    async def test_initial_commit(self, handler_context, sample_entities):
        result = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        assert result["status"] == 200
        data = result["result"]["data"]
        assert "version" in data
        assert "root" in data

        # Verify version entity is structural (root + parents only)
        version = handler_context.emit_pathway.content_store.get(data["version"])
        assert version.type == VERSION_ENTRY_TYPE
        assert "root" in version.data
        assert "parents" in version.data
        assert version.data["parents"] == []  # Initial commit has no parents
        # No metadata fields
        assert "timestamp" not in version.data
        assert "message" not in version.data
        assert "author" not in version.data
        assert "prefix" not in version.data
        assert "snapshot" not in version.data

    @pytest.mark.asyncio
    async def test_sequential_commits(self, handler_context, sample_entities):
        # First commit
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Add another entity
        handler_context.emit_pathway.emit(
            "data/file4.txt", Entity(type="test/file", data={"content": "New"}),
        )

        # Second commit
        r2 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v2 = r2["result"]["data"]["version"]
        assert v1 != v2

        # Second version has first as parent
        version2 = handler_context.emit_pathway.content_store.get(v2)
        assert version2.data["parents"] == [v1]

    @pytest.mark.asyncio
    async def test_commit_trie_round_trip(self, handler_context, sample_entities):
        """Commit creates a trie; flattening it recovers the original bindings."""
        result = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        root_hash = result["result"]["data"]["root"]
        cs = handler_context.emit_pathway.content_store

        # Flatten trie
        flat = dict(collect_all_bindings(root_hash, "", cs))
        # Should match tree bindings
        for path, h in sample_entities.items():
            assert flat.get(path) == h


# =============================================================================
# Log
# =============================================================================


class TestLog:
    @pytest.mark.asyncio
    async def test_empty_log(self, handler_context):
        result = await revision_handler(
            "system/revision", "log", {"data": {"prefix": ""}}, handler_context,
        )
        assert result["status"] == 200
        unwrapped = _unwrap_envelope(result)
        assert unwrapped["result"]["data"]["versions"] == []

    @pytest.mark.asyncio
    async def test_log_after_commits(self, handler_context, sample_entities):
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        r2 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]
        v2 = r2["result"]["data"]["version"]

        result = await revision_handler(
            "system/revision", "log", {"data": {"prefix": ""}}, handler_context,
        )
        unwrapped = _unwrap_envelope(result)
        versions = unwrapped["result"]["data"]["versions"]
        assert v2 in versions
        assert v1 in versions

    @pytest.mark.asyncio
    async def test_log_limit(self, handler_context, sample_entities):
        for _ in range(5):
            await revision_handler(
                "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
            )

        result = await revision_handler(
            "system/revision", "log", {"data": {"prefix": "", "limit": 2}}, handler_context,
        )
        unwrapped = _unwrap_envelope(result)
        data = unwrapped["result"]["data"]
        assert len(data["versions"]) == 2
        assert data.get("has_more") is True


# =============================================================================
# Status
# =============================================================================


class TestStatus:
    @pytest.mark.asyncio
    async def test_status_no_commits(self, handler_context):
        result = await revision_handler(
            "system/revision", "status", {"data": {"prefix": ""}}, handler_context,
        )
        data = result["result"]["data"]
        # Absent head is encoded as the 33-byte canonical zero hash
        # (algorithm byte 0x00 + 32 zero digest bytes) per the cross-impl
        # auto-version convention.
        assert data["head"] == b"\x00" + b"\x00" * 32
        assert data["conflicts"] == 0
        assert data["pending"] == 0

    @pytest.mark.asyncio
    async def test_status_after_commit(self, handler_context, sample_entities):
        r = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v = r["result"]["data"]["version"]

        result = await revision_handler(
            "system/revision", "status", {"data": {"prefix": ""}}, handler_context,
        )
        data = result["result"]["data"]
        assert data["head"] == v
        # After commit, pending should be small (may include system paths
        # created by the commit itself like HEAD pointer). Key check: head is set.
        # The exact pending count depends on whether system paths are excluded.

    @pytest.mark.asyncio
    async def test_status_pending_changes(self, handler_context, sample_entities):
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        # Add a new entity
        handler_context.emit_pathway.emit(
            "data/new.txt", Entity(type="test/file", data={"content": "New"}),
        )

        result = await revision_handler(
            "system/revision", "status", {"data": {"prefix": ""}}, handler_context,
        )
        assert result["result"]["data"]["pending"] > 0


# =============================================================================
# Branch
# =============================================================================


class TestBranch:
    @pytest.mark.asyncio
    async def test_branch_lifecycle(self, handler_context, sample_entities):
        # Commit first
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        # Create branch
        r = await revision_handler(
            "system/revision", "branch",
            {"data": {"prefix": "", "action": "create", "name": "feature"}},
            handler_context,
        )
        assert r["result"]["data"]["status"] == "created"

        # List branches
        r = await revision_handler(
            "system/revision", "branch",
            {"data": {"prefix": "", "action": "list"}},
            handler_context,
        )
        assert "feature" in r["result"]["data"]["branches"]

        # Duplicate rejection
        r = await revision_handler(
            "system/revision", "branch",
            {"data": {"prefix": "", "action": "create", "name": "feature"}},
            handler_context,
        )
        assert r["status"] == 409

        # Delete branch
        r = await revision_handler(
            "system/revision", "branch",
            {"data": {"prefix": "", "action": "delete", "name": "feature"}},
            handler_context,
        )
        assert r["result"]["data"]["status"] == "deleted"


# =============================================================================
# Tag
# =============================================================================


class TestTag:
    @pytest.mark.asyncio
    async def test_tag_lifecycle(self, handler_context, sample_entities):
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        # Create tag
        r = await revision_handler(
            "system/revision", "tag",
            {"data": {"prefix": "", "action": "create", "name": "v1.0"}},
            handler_context,
        )
        assert r["result"]["data"]["status"] == "created"

        # List tags
        r = await revision_handler(
            "system/revision", "tag",
            {"data": {"prefix": "", "action": "list"}},
            handler_context,
        )
        assert "v1.0" in r["result"]["data"]["tags"]

        # Immutability (duplicate rejection)
        r = await revision_handler(
            "system/revision", "tag",
            {"data": {"prefix": "", "action": "create", "name": "v1.0"}},
            handler_context,
        )
        assert r["status"] == 409

        # Delete tag
        r = await revision_handler(
            "system/revision", "tag",
            {"data": {"prefix": "", "action": "delete", "name": "v1.0"}},
            handler_context,
        )
        assert r["result"]["data"]["status"] == "deleted"


# =============================================================================
# Merge
# =============================================================================


class TestMerge:
    @pytest.mark.asyncio
    async def test_merge_already_in_sync(self, handler_context, sample_entities):
        r = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v = r["result"]["data"]["version"]

        result = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v}},
            handler_context,
        )
        assert result["result"]["data"]["status"] == "already_in_sync"

    @pytest.mark.asyncio
    async def test_merge_fast_forward(self, handler_context, sample_entities):
        # V1
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Create branch, commit on branch
        await revision_handler(
            "system/revision", "branch",
            {"data": {"prefix": "", "name": "feature"}},
            handler_context,
        )
        await revision_handler(
            "system/revision", "checkout",
            {"data": {"prefix": "", "branch": "feature"}},
            handler_context,
        )

        handler_context.emit_pathway.emit(
            "data/new.txt", Entity(type="test/file", data={"content": "New"}),
        )
        r2 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v2 = r2["result"]["data"]["version"]

        # Switch back and merge (fast-forward)
        await revision_handler(
            "system/revision", "checkout",
            {"data": {"prefix": "", "version": v1}},
            handler_context,
        )
        # Reset HEAD to v1
        head_entity = Entity(type="system/hash", data={"hash": v1})
        from entity_core.storage.emit import EmitContext
        emit_ctx = EmitContext.protocol(author="remote-peer")
        handler_context.emit_pathway.emit(_head_path(_compute_prefix_hash(handler_context, "")), head_entity, emit_ctx)

        result = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v2}},
            handler_context,
        )
        assert result["result"]["data"]["status"] == "fast_forward"

    @pytest.mark.asyncio
    async def test_merge_diverged_with_conflict(self, handler_context, content_store):
        """Diverged branches: remote edits shared file + adds a new file -> conflict + non-conflict changes.

        The remote adds a new file so the merged trie root differs from local's
        (avoids oscillation detection triggering on identical roots).
        """
        cs = handler_context.emit_pathway.content_store

        # Create initial state and commit
        handler_context.emit_pathway.emit(
            "data/shared.txt", Entity(type="test/file", data={"content": "Original"}),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Get base bindings
        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(
            base_version.data["root"], "", cs,
        ))

        # Create "local" edit
        handler_context.emit_pathway.emit(
            "data/shared.txt", Entity(type="test/file", data={"content": "Local edit"}),
        )
        r_local = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v_local = r_local["result"]["data"]["version"]

        # Create "remote" edit: different shared.txt AND a new file
        remote_shared = Entity(type="test/file", data={"content": "Remote edit"})
        remote_shared_h = cs.put(remote_shared)
        remote_new = Entity(type="test/file", data={"content": "Remote only"})
        remote_new_h = cs.put(remote_new)

        remote_bindings = dict(base_bindings)
        remote_bindings["data/shared.txt"] = remote_shared_h
        remote_bindings["data/remote_only.txt"] = remote_new_h
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)

        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        # Merge
        result = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote}},
            handler_context,
        )
        data = result["result"]["data"]
        assert data["status"] == "merged_with_conflicts"
        assert "data/shared.txt" in data.get("conflicts", [])

    @pytest.mark.asyncio
    async def test_merge_sorted_parents(self, handler_context, content_store):
        """Merge version must have sorted parents."""
        cs = handler_context.emit_pathway.content_store

        # Create initial state and commit
        handler_context.emit_pathway.emit(
            "data/a.txt", Entity(type="test/file", data={"content": "A"}),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Local commit
        handler_context.emit_pathway.emit(
            "data/b.txt", Entity(type="test/file", data={"content": "B"}),
        )
        r_local = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v_local = r_local["result"]["data"]["version"]

        # Remote commit (non-conflicting)
        remote_entity = Entity(type="test/file", data={"content": "C"})
        remote_hash = cs.put(remote_entity)
        remote_bindings = [
            ("data/a.txt", handler_context.emit_pathway.entity_tree.get(
                handler_context.emit_pathway.entity_tree.normalize_uri("data/a.txt")
            )),
            ("data/c.txt", remote_hash),
        ]
        remote_trie_root = build_trie(sorted(remote_bindings), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        # Merge
        result = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote}},
            handler_context,
        )
        data = result["result"]["data"]
        assert data["status"] == "merged"

        # Verify merge version has sorted parents
        merge_version = cs.get(data["version"])
        parents = merge_version.data["parents"]
        assert parents == sorted(parents)
        assert len(parents) == 2


# =============================================================================
# Resolve
# =============================================================================


class TestResolve:
    @pytest.mark.asyncio
    async def test_resolve_not_found(self, handler_context):
        result = await revision_handler(
            "system/revision", "resolve",
            {"data": {"prefix": "", "path": "nonexistent", "resolved": b"\x00" * 33}},
            handler_context,
        )
        assert result["status"] == 404


# =============================================================================
# Diff
# =============================================================================


class TestDiff:
    @pytest.mark.asyncio
    async def test_diff_between_versions(self, handler_context, sample_entities):
        # V1
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Add and modify
        handler_context.emit_pathway.emit(
            "data/new.txt", Entity(type="test/file", data={"content": "Added"}),
        )
        handler_context.emit_pathway.entity_tree.remove(
            handler_context.emit_pathway.entity_tree.normalize_uri("data/file1.txt")
        )

        # V2
        r2 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v2 = r2["result"]["data"]["version"]

        # Diff
        result = await revision_handler(
            "system/revision", "diff",
            {"data": {"prefix": "", "base": v1, "target": v2}},
            handler_context,
        )
        diff = result["result"]["data"]
        assert "data/new.txt" in diff["added"]
        assert "data/file1.txt" in diff["removed"]


# =============================================================================
# Cherry-pick and Revert
# =============================================================================


class TestCherryPickAndRevert:
    @pytest.mark.asyncio
    async def test_cherry_pick(self, handler_context, sample_entities):
        # V1
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        # Add entity and commit V2
        handler_context.emit_pathway.emit(
            "data/cherry.txt", Entity(type="test/file", data={"content": "Cherry"}),
        )
        r2 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v2 = r2["result"]["data"]["version"]

        # Cherry-pick V2's changes (single parent = current HEAD)
        result = await revision_handler(
            "system/revision", "cherry-pick",
            {"data": {"prefix": "", "version": v2}},
            handler_context,
        )
        assert result["result"]["data"]["status"] == "cherry_picked"

        # Verify the cherry-pick version has single parent
        cp_hash = result["result"]["data"]["version"]
        cp = handler_context.emit_pathway.content_store.get(cp_hash)
        assert len(cp.data["parents"]) == 1

    @pytest.mark.asyncio
    async def test_cherry_pick_merge_version_requires_parent(self, handler_context, content_store):
        """C7: cherry-pick of merge version without parent param returns 400."""
        cs = handler_context.emit_pathway.content_store

        # Create a merge version (2 parents) manually
        root = build_trie([], cs)
        p1 = Entity(type=VERSION_ENTRY_TYPE, data={"root": root, "parents": []})
        p1_h = cs.put(p1)
        p2 = Entity(type=VERSION_ENTRY_TYPE, data={"root": root, "parents": []})
        p2_h = cs.put(p2)
        merge_v = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": root, "parents": sorted_parents([p1_h, p2_h])},
        )
        merge_h = cs.put(merge_v)

        result = await revision_handler(
            "system/revision", "cherry-pick",
            {"data": {"prefix": "", "version": merge_h}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "ambiguous_parent"

    @pytest.mark.asyncio
    async def test_revert(self, handler_context, sample_entities):
        # V1
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        # Add entity and commit V2
        handler_context.emit_pathway.emit(
            "data/toremove.txt", Entity(type="test/file", data={"content": "Remove me"}),
        )
        r2 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v2 = r2["result"]["data"]["version"]

        # Revert V2
        result = await revision_handler(
            "system/revision", "revert",
            {"data": {"prefix": "", "version": v2}},
            handler_context,
        )
        assert result["result"]["data"]["status"] == "reverted"


# =============================================================================
# Oscillation Detection
# =============================================================================


class TestOscillationDetection:
    def test_no_oscillation_fresh(self, handler_context):
        assert _detect_oscillation(handler_context, b"\x00" * 33, None) is False

    def test_detects_repeated_root(self, handler_context):
        cs = handler_context.emit_pathway.content_store

        # Create a version with a known root
        root_hash = b"\x00" + b"\xaa" * 32
        v1 = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": root_hash, "parents": []},
        )
        v1_hash = cs.put(v1)

        # Proposing same root_hash should detect oscillation
        assert _detect_oscillation(handler_context, root_hash, v1_hash) is True

    def test_depth_limit(self, handler_context):
        cs = handler_context.emit_pathway.content_store

        root_hash = b"\x00" + b"\xbb" * 32

        # Build a chain: v1 (has root_hash) <- v2 <- v3 <- v4 <- v5
        v1 = Entity(type=VERSION_ENTRY_TYPE, data={"root": root_hash, "parents": []})
        v1_hash = cs.put(v1)

        prev = v1_hash
        for i in range(4):
            v = Entity(
                type=VERSION_ENTRY_TYPE,
                data={"root": b"\x00" + bytes([i]) * 32, "parents": [prev]},
            )
            prev = cs.put(v)

        # At depth 4, v1 (depth 4) should not be found
        assert _detect_oscillation(handler_context, root_hash, prev, depth_limit=4) is False
        # At depth 5, it would be found
        assert _detect_oscillation(handler_context, root_hash, prev, depth_limit=5) is True


# =============================================================================
# Fetch
# =============================================================================


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_empty(self, handler_context):
        result = await revision_handler(
            "system/revision", "fetch", {"data": {"prefix": ""}}, handler_context,
        )
        unwrapped = _unwrap_envelope(result)
        assert unwrapped["result"]["data"]["head"] is None
        assert unwrapped["result"]["data"]["versions"] == []

    @pytest.mark.asyncio
    async def test_fetch_returns_versions_and_trie_nodes(self, handler_context, sample_entities):
        r = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v = r["result"]["data"]["version"]
        root = r["result"]["data"]["root"]

        result = await revision_handler(
            "system/revision", "fetch", {"data": {"prefix": ""}}, handler_context,
        )
        unwrapped = _unwrap_envelope(result)
        assert unwrapped["result"]["data"]["head"] == v
        assert v in unwrapped["result"]["data"]["versions"]

        # Included should have version entity and root trie node
        included = unwrapped.get("included", {})
        assert v in included
        assert root in included


# =============================================================================
# Fetch-Entities
# =============================================================================


class TestFetchEntities:
    @pytest.mark.asyncio
    async def test_fetch_entities_validates_hashes(self, handler_context, sample_entities):
        r = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        root = r["result"]["data"]["root"]

        # Request a valid hash (one of the entity hashes)
        valid_hash = list(sample_entities.values())[0]

        result = await revision_handler(
            "system/revision", "fetch-entities",
            {"data": {"prefix": "", "snapshot": root, "hashes": [valid_hash]}},
            handler_context,
        )
        assert result["status"] == 200
        unwrapped = _unwrap_envelope(result)
        assert valid_hash in unwrapped["result"]["data"]["found"]

    @pytest.mark.asyncio
    async def test_fetch_entities_rejects_invalid_hash(self, handler_context, sample_entities):
        r = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        root = r["result"]["data"]["root"]

        # Request a hash not in the trie
        fake_hash = b"\x00" + b"\xff" * 32

        result = await revision_handler(
            "system/revision", "fetch-entities",
            {"data": {"prefix": "", "snapshot": root, "hashes": [fake_hash]}},
            handler_context,
        )
        assert result["status"] == 200
        unwrapped = _unwrap_envelope(result)
        assert fake_hash in unwrapped["result"]["data"]["missing"]

    @pytest.mark.asyncio
    async def test_fetch_entities_invalid_snapshot(self, handler_context, sample_entities):
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        result = await revision_handler(
            "system/revision", "fetch-entities",
            {"data": {"prefix": "", "snapshot": b"\x00" * 33, "hashes": [b"\x00" * 33]}},
            handler_context,
        )
        assert result["status"] == 403


class TestFetchDiff:
    """Tests for revision/fetch-diff (EXTENSION-REVISION v3.4 §4.4.19)."""

    @pytest.mark.asyncio
    async def test_no_local_state(self, handler_context):
        """No revision head at prefix → 404 no_local_state."""
        result = await revision_handler(
            "system/revision", "fetch-diff", {"data": {"prefix": ""}},
            handler_context,
        )
        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "no_local_state"

    @pytest.mark.asyncio
    async def test_invalid_params_missing_prefix(self, handler_context):
        result = await revision_handler(
            "system/revision", "fetch-diff", {"data": {}}, handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_params"

    @pytest.mark.asyncio
    async def test_full_closure_zero_base(self, handler_context, sample_entities):
        """base omitted (== full closure): envelope carries the snapshot root
        and every reachable entity under the head trie."""
        r = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        target_root = r["result"]["data"]["root"]

        result = await revision_handler(
            "system/revision", "fetch-diff", {"data": {"prefix": ""}},
            handler_context,
        )
        assert result["status"] == 200
        env = result["result"]
        assert env["type"] == "system/envelope"
        assert env["data"]["root"]["data"]["root"] == target_root
        included = env["data"]["included"]
        # All three leaf data entities are present in a full closure.
        for h in sample_entities.values():
            assert h in included

    @pytest.mark.asyncio
    async def test_incremental_bandwidth(self, handler_context, sample_entities):
        """base=v1 (caller's known version): the diff closure is strictly
        smaller than the full closure — only the changed leaf + spine ship."""
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        base_version = r1["result"]["data"]["version"]

        # Full-closure size for comparison.
        full = await revision_handler(
            "system/revision", "fetch-diff", {"data": {"prefix": ""}},
            handler_context,
        )
        full_count = len(full["result"]["data"]["included"])

        # Mutate one leaf and recommit.
        handler_context.emit_pathway.emit(
            "data/file1.txt", Entity(type="test/file", data={"content": "Hello v2"}),
        )
        r2 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        target_root = r2["result"]["data"]["root"]

        result = await revision_handler(
            "system/revision", "fetch-diff",
            {"data": {"prefix": "", "base": base_version}},
            handler_context,
        )
        assert result["status"] == 200
        env = result["result"]
        assert env["data"]["root"]["data"]["root"] == target_root
        included = env["data"]["included"]

        # Bandwidth proof: the incremental closure is strictly smaller.
        assert len(included) < full_count
        # The changed leaf MUST ship; the two untouched leaves MUST NOT.
        changed_leaf = handler_context.emit_pathway.content_store.put(
            Entity(type="test/file", data={"content": "Hello v2"})
        )
        assert changed_leaf in included
        assert sample_entities["data/file2.txt"] not in included
        assert sample_entities["data/subdir/file3.txt"] not in included

    @pytest.mark.asyncio
    async def test_base_not_found(self, handler_context, sample_entities):
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        result = await revision_handler(
            "system/revision", "fetch-diff",
            {"data": {"prefix": "", "base": b"\x00" + b"\xff" * 32}},
            handler_context,
        )
        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "base_not_found"

    @pytest.mark.asyncio
    async def test_base_not_a_version(self, handler_context, sample_entities):
        """base resolves to a non-version entity → 400 base_not_a_version."""
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        # A leaf data entity hash is in the store but is not a version entry.
        bad_base = next(iter(sample_entities.values()))
        result = await revision_handler(
            "system/revision", "fetch-diff",
            {"data": {"prefix": "", "base": bad_base}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "base_not_a_version"

    @pytest.mark.asyncio
    async def test_base_equal_head_yields_empty_diff(self, handler_context, sample_entities):
        """base == current head: nothing changed, so the closure carries no
        leaf data entities (everything is in the skip set)."""
        r = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        head_version = r["result"]["data"]["version"]
        result = await revision_handler(
            "system/revision", "fetch-diff",
            {"data": {"prefix": "", "base": head_version}},
            handler_context,
        )
        assert result["status"] == 200
        included = result["result"]["data"]["included"]
        for h in sample_entities.values():
            assert h not in included


class TestPull:
    """Tests for revision/pull (EXTENSION-REVISION §4.4.8)."""

    @pytest.mark.asyncio
    async def test_missing_prefix_rejected(self, handler_context):
        result = await revision_handler(
            "system/revision", "pull", {"data": {"remote": "peer-x"}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_params"

    @pytest.mark.asyncio
    async def test_missing_remote_rejected(self, handler_context):
        """Cross-impl probe MUST: pull with no `remote` → 400 invalid_params."""
        result = await revision_handler(
            "system/revision", "pull", {"data": {"prefix": "pull-no-remote/"}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_params"

    @pytest.mark.asyncio
    async def test_op_recognized_outbound_failure_is_502(self, handler_context):
        """Op is registered (not 501 unsupported_operation). With no
        dispatcher wired, the outbound fetch fails → 502 remote_fetch_failed,
        which still confirms recognition (cross-impl probe semantics)."""
        result = await revision_handler(
            "system/revision", "pull",
            {"data": {"prefix": "", "remote": "peer-x"}},
            handler_context,
        )
        assert result["status"] == 502
        assert result["result"]["data"]["code"] == "remote_fetch_failed"

    @pytest.mark.asyncio
    async def test_pull_end_to_end_fast_forward(self, tree_registry):
        """Full §4.4.8 flow: a follower with no local commits pulls a
        remote's head and fast-forwards. The mock dispatcher routes
        outbound fetch/fetch-entities to a second peer served by the REAL
        revision handlers (a true in-process round trip)."""
        # --- Remote peer: commit data so it has a head + closure. ---
        remote_cs = ContentStore()
        remote_tree = EntityTree("remote-peer")
        remote_emit = EmitPathway(remote_cs, remote_tree)
        remote_registry = TreeRegistry(remote_tree, remote_cs)
        permissive = {"grants": [{"handlers": {"include": ["*"]},
                                  "resources": {"include": ["*"]},
                                  "operations": {"include": ["*"]}}]}
        remote_ctx = HandlerContext(
            local_peer_id="remote-peer", remote_peer_id="follower",
            handler_grant=permissive, caller_capability=permissive,
            emit_pathway=remote_emit, tree_registry=remote_registry,
            handler_pattern="system/revision",
        )
        remote_emit.emit("data/a.txt", Entity(type="test/file", data={"c": "A"}))
        remote_emit.emit("data/b.txt", Entity(type="test/file", data={"c": "B"}))
        r = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, remote_ctx,
        )
        remote_head = r["result"]["data"]["version"]

        # --- Follower peer (empty) with a dispatcher that serves the remote. ---
        follower_cs = ContentStore()
        follower_tree = EntityTree("follower")
        follower_emit = EmitPathway(follower_cs, follower_tree)
        follower_ctx = HandlerContext(
            local_peer_id="follower", remote_peer_id="remote-peer",
            handler_grant=permissive, caller_capability=permissive,
            emit_pathway=follower_emit, tree_registry=tree_registry,
            handler_pattern="system/revision",
        )

        async def dispatcher(uri, op, params, cap, bounds, cid, rt=None, **kw):
            # Route the follower's outbound EXECUTE to the remote handlers.
            resp = await revision_handler("system/revision", op, params, remote_ctx)
            return ExecuteResult(status=resp["status"], result=resp.get("result"))

        follower_ctx._execute_dispatcher = dispatcher

        result = await revision_handler(
            "system/revision", "pull",
            {"data": {"prefix": "", "remote": "remote-peer"}}, follower_ctx,
        )
        assert result["status"] == 200, result
        # Follower fast-forwarded to the remote head.
        head_h = follower_tree.get(
            follower_tree.normalize_uri(_head_path(_compute_prefix_hash(follower_ctx, "")))
        )
        assert head_h is not None
        head_entity = follower_cs.get(head_h)
        assert head_entity.data.get("hash") == remote_head
        # The remote's data entities were transported into the follower store.
        assert follower_tree.get(follower_tree.normalize_uri("data/a.txt")) is not None
        assert follower_tree.get(follower_tree.normalize_uri("data/b.txt")) is not None


class TestCollectMissingPullHashes:
    """Unit tests for the pull trie-walk missing-hash collector."""

    def test_empty_root_returns_empty(self, content_store):
        assert _collect_missing_pull_hashes(content_store, None) == []

    def test_missing_root_node_requested(self, content_store):
        # A root hash not in the store is itself requested.
        fake_root = b"\x00" + b"\xab" * 32
        assert _collect_missing_pull_hashes(content_store, fake_root) == [fake_root]

    def test_full_local_closure_has_no_missing(self, emit_pathway, content_store):
        # Build a real trie fully in the store → nothing missing.
        e1 = Entity(type="test/file", data={"c": "1"})
        e2 = Entity(type="test/file", data={"c": "2"})
        h1 = content_store.put(e1)
        h2 = content_store.put(e2)
        root = build_trie(sorted({"a.txt": h1, "b.txt": h2}.items()), content_store)
        assert _collect_missing_pull_hashes(content_store, root) == []

    def test_missing_leaf_binding_requested(self, content_store):
        # Build a trie whose leaf data entity is absent from the store.
        h1 = b"\x00" + b"\x11" * 32  # not stored
        root = build_trie([("a.txt", h1)], content_store)
        missing = _collect_missing_pull_hashes(content_store, root)
        assert h1 in missing


class TestConfig:
    """Tests for revision/config operation (PROPOSAL-REVISION-CONFIG-OPERATION §3.1)."""

    @pytest.mark.asyncio
    async def test_missing_name_rejected(self, handler_context):
        result = await revision_handler(
            "system/revision", "config",
            {"data": {"action": "set"}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "config/missing-name"

    @pytest.mark.asyncio
    async def test_invalid_action_rejected(self, handler_context):
        result = await revision_handler(
            "system/revision", "config",
            {"data": {"name": "test", "action": "read"}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "config/invalid-action"

    @pytest.mark.asyncio
    async def test_set_and_delete(self, handler_context):
        config_data = {"prefix": "project/", "auto_version": False}
        result = await revision_handler(
            "system/revision", "config",
            {"data": {"name": "proj", "action": "set", "config": config_data}},
            handler_context,
        )
        assert result["status"] == 200
        assert result["result"]["type"] == "system/revision/config-result"
        assert result["result"]["data"]["config_path"].startswith("system/revision/")
        assert result["result"]["data"]["config_path"].endswith("/config")
        assert result["result"]["data"]["config_hash"] is not None
        # F-CIMP-1: on first set, `previous_hash` MUST be
        # ABSENT from the result envelope (omitzero per cross-impl wire
        # contract). Emitting `previous_hash: None` here caused Go's
        # decoder to reject the entire result with
        # "invalid hash: expected 33 bytes, got 0" — the bug that flew
        # under the conformance suite because validate-peer only checked
        # `resp.Status != 200`, never decoded the typed result envelope.
        # Workbench-go's cross-impl perf-stress probe surfaced this
        # at §2.1.
        assert "previous_hash" not in result["result"]["data"], (
            "F-CIMP-1 regression: `previous_hash` must be omitted on first "
            "set (no prior config exists). Emitting `previous_hash: None` "
            "breaks Go's omitzero-strict hash decoder. See revision.py "
            "_handle_config_set."
        )

        del_result = await revision_handler(
            "system/revision", "config",
            {"data": {"name": "proj", "action": "delete", "prefix": "project/"}},
            handler_context,
        )
        assert del_result["status"] == 200
        assert del_result["result"]["data"]["previous_hash"] is not None
        # F-CIMP-1: on delete, no new config is emitted → `config_hash` MUST
        # be absent from the result, not emitted as None.
        assert "config_hash" not in del_result["result"]["data"], (
            "F-CIMP-1 regression: `config_hash` must be omitted on delete "
            "(no new config emitted). See revision.py _handle_config_delete."
        )

    @pytest.mark.asyncio
    async def test_delete_nonexistent_returns_404(self, handler_context):
        result = await revision_handler(
            "system/revision", "config",
            {"data": {"name": "nope", "action": "delete", "prefix": "nonexistent/"}},
            handler_context,
        )
        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "config/not-found"

    @pytest.mark.asyncio
    async def test_set_invalid_config_rejected(self, handler_context):
        config_data = {"prefix": "/", "auto_version": True, "exclude": []}
        result = await revision_handler(
            "system/revision", "config",
            {"data": {"name": "bad", "action": "set", "config": config_data}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "config/missing-required-exclude"

    @pytest.mark.asyncio
    async def test_set_valid_auto_version_config(self, handler_context):
        config_data = {
            "prefix": "/",
            "auto_version": True,
            "exclude": [
                "system/revision/**",
                "system/tree/root/**",
                "system/tree/tracking-config/**",
                "system/history/**",
                "system/clock/**",
            ],
        }
        result = await revision_handler(
            "system/revision", "config",
            {"data": {"name": "root", "action": "set", "config": config_data}},
            handler_context,
        )
        assert result["status"] == 200
        assert "tracking_config_path" in result["result"]["data"]
        assert result["result"]["data"]["tracking_config_action"] == "created"

    @pytest.mark.asyncio
    async def test_v4_invalid_merge_order(self, handler_context):
        config_data = {"prefix": "p/", "merge_order": "random"}
        result = await revision_handler(
            "system/revision", "config",
            {"data": {"name": "v4", "action": "set", "config": config_data}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "config/invalid-merge-order"

    @pytest.mark.asyncio
    async def test_v5_oscillation_depth_below_minimum(self, handler_context):
        config_data = {"prefix": "p/", "oscillation_depth": 1}
        result = await revision_handler(
            "system/revision", "config",
            {"data": {"name": "v5", "action": "set", "config": config_data}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "config/oscillation-depth-below-minimum"

    @pytest.mark.asyncio
    async def test_cas_guard_mismatch(self, handler_context):
        config_data = {"prefix": "p/"}
        await revision_handler(
            "system/revision", "config",
            {"data": {"name": "cas", "action": "set", "config": config_data}},
            handler_context,
        )
        result = await revision_handler(
            "system/revision", "config",
            {"data": {"name": "cas", "action": "set", "config": config_data, "expected_hash": b"\x00" * 33}},
            handler_context,
        )
        assert result["status"] == 409
        assert result["result"]["data"]["code"] == "config/concurrent-modification"

    @pytest.mark.asyncio
    async def test_set_missing_config_field(self, handler_context):
        result = await revision_handler(
            "system/revision", "config",
            {"data": {"name": "test", "action": "set"}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "config/missing-config"

    @pytest.mark.asyncio
    async def test_v1_empty_prefix_rejected(self, handler_context):
        result = await revision_handler(
            "system/revision", "config",
            {"data": {"name": "test", "action": "set", "config": {"prefix": ""}}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "config/invalid-prefix"


# =============================================================================
# R1 — Revert parent field for merge versions
# =============================================================================


class TestRevertMergeParent:
    @pytest.mark.asyncio
    async def test_revert_merge_version_without_parent_rejected(self, handler_context, content_store):
        """R1: revert of merge version without parent param returns 400."""
        cs = handler_context.emit_pathway.content_store

        # Create two parent versions with different bindings
        e1 = Entity(type="test/file", data={"content": "Parent1"})
        e1_h = cs.put(e1)
        e2 = Entity(type="test/file", data={"content": "Parent2"})
        e2_h = cs.put(e2)

        root1 = build_trie([("data/a.txt", e1_h)], cs)
        root2 = build_trie([("data/a.txt", e2_h)], cs)
        p1 = Entity(type=VERSION_ENTRY_TYPE, data={"root": root1, "parents": []})
        p1_h = cs.put(p1)
        p2 = Entity(type=VERSION_ENTRY_TYPE, data={"root": root2, "parents": []})
        p2_h = cs.put(p2)

        merge_root = build_trie([("data/a.txt", e1_h)], cs)
        merge_v = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": merge_root, "parents": sorted_parents([p1_h, p2_h])},
        )
        merge_h = cs.put(merge_v)

        # Need a HEAD so revert can create its version
        head_entity = Entity(type="system/hash", data={"hash": merge_h})
        from entity_core.storage.emit import EmitContext
        emit_ctx = EmitContext.protocol(author="remote-peer")
        handler_context.emit_pathway.emit(_head_path(_compute_prefix_hash(handler_context, "")), head_entity, emit_ctx)

        result = await revision_handler(
            "system/revision", "revert",
            {"data": {"prefix": "", "version": merge_h}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "ambiguous_parent"

    @pytest.mark.asyncio
    async def test_revert_merge_version_with_valid_parent(self, handler_context, content_store):
        """R1: revert of merge version with explicit parent succeeds."""
        cs = handler_context.emit_pathway.content_store

        e1 = Entity(type="test/file", data={"content": "Parent1"})
        e1_h = cs.put(e1)
        e2 = Entity(type="test/file", data={"content": "Parent2"})
        e2_h = cs.put(e2)

        root1 = build_trie([("data/a.txt", e1_h)], cs)
        root2 = build_trie([("data/a.txt", e2_h)], cs)
        p1 = Entity(type=VERSION_ENTRY_TYPE, data={"root": root1, "parents": []})
        p1_h = cs.put(p1)
        p2 = Entity(type=VERSION_ENTRY_TYPE, data={"root": root2, "parents": []})
        p2_h = cs.put(p2)

        merge_root = build_trie([("data/a.txt", e1_h)], cs)
        merge_v = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": merge_root, "parents": sorted_parents([p1_h, p2_h])},
        )
        merge_h = cs.put(merge_v)

        head_entity = Entity(type="system/hash", data={"hash": merge_h})
        from entity_core.storage.emit import EmitContext
        emit_ctx = EmitContext.protocol(author="remote-peer")
        handler_context.emit_pathway.emit(_head_path(_compute_prefix_hash(handler_context, "")), head_entity, emit_ctx)
        handler_context.emit_pathway.emit("data/a.txt", Entity(type="test/file", data={"content": "Parent1"}), emit_ctx)

        result = await revision_handler(
            "system/revision", "revert",
            {"data": {"prefix": "", "version": merge_h, "parent": p1_h}},
            handler_context,
        )
        assert result["result"]["data"]["status"] == "reverted"

    @pytest.mark.asyncio
    async def test_revert_merge_version_with_invalid_parent(self, handler_context, content_store):
        """R1: revert with parent not in version's parent list returns 400."""
        cs = handler_context.emit_pathway.content_store

        root = build_trie([], cs)
        p1 = Entity(type=VERSION_ENTRY_TYPE, data={"root": root, "parents": []})
        p1_h = cs.put(p1)
        p2 = Entity(type=VERSION_ENTRY_TYPE, data={"root": root, "parents": []})
        p2_h = cs.put(p2)
        merge_v = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": root, "parents": sorted_parents([p1_h, p2_h])},
        )
        merge_h = cs.put(merge_v)

        head_entity = Entity(type="system/hash", data={"hash": merge_h})
        from entity_core.storage.emit import EmitContext
        emit_ctx = EmitContext.protocol(author="remote-peer")
        handler_context.emit_pathway.emit(_head_path(_compute_prefix_hash(handler_context, "")), head_entity, emit_ctx)

        bogus_parent = b"\x00" + b"\xff" * 32
        result = await revision_handler(
            "system/revision", "revert",
            {"data": {"prefix": "", "version": merge_h, "parent": bogus_parent}},
            handler_context,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_parent"

    @pytest.mark.asyncio
    async def test_revert_single_parent_still_works(self, handler_context, sample_entities):
        """R1: single-parent revert without parent field still works."""
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        handler_context.emit_pathway.emit(
            "data/toremove.txt", Entity(type="test/file", data={"content": "Remove me"}),
        )
        r2 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v2 = r2["result"]["data"]["version"]

        result = await revision_handler(
            "system/revision", "revert",
            {"data": {"prefix": "", "version": v2}},
            handler_context,
        )
        assert result["result"]["data"]["status"] == "reverted"


# =============================================================================
# R2 — Resolve: existence check + null resolved
# =============================================================================


class TestResolveR2:
    @pytest.mark.asyncio
    async def test_resolve_hash_not_in_content_store(self, handler_context, sample_entities):
        """R2: resolve with hash not in content store returns 404."""
        cs = handler_context.emit_pathway.content_store

        # Create a conflict to resolve
        handler_context.emit_pathway.emit(
            "data/file1.txt", Entity(type="test/file", data={"content": "Original"}),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Create a diverged edit and merge to produce conflict
        handler_context.emit_pathway.emit(
            "data/file1.txt", Entity(type="test/file", data={"content": "Local edit"}),
        )
        r_local = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v_local = r_local["result"]["data"]["version"]

        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(base_version.data["root"], "", cs))
        remote_entity = Entity(type="test/file", data={"content": "Remote edit"})
        remote_h = cs.put(remote_entity)
        remote_extra = Entity(type="test/file", data={"content": "Extra"})
        remote_extra_h = cs.put(remote_extra)
        remote_bindings = dict(base_bindings)
        remote_bindings["data/file1.txt"] = remote_h
        remote_bindings["data/extra.txt"] = remote_extra_h
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote}},
            handler_context,
        )

        bogus_hash = b"\x00" + b"\xde" * 32
        result = await revision_handler(
            "system/revision", "resolve",
            {"data": {"prefix": "", "path": "data/file1.txt", "resolved": bogus_hash}},
            handler_context,
        )
        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "resolved_not_found"

    @pytest.mark.asyncio
    async def test_resolve_null_deletes_path(self, handler_context, sample_entities):
        """R2: resolve with null removes the path (resolve-by-deletion)."""
        cs = handler_context.emit_pathway.content_store

        handler_context.emit_pathway.emit(
            "data/file1.txt", Entity(type="test/file", data={"content": "Original"}),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        handler_context.emit_pathway.emit(
            "data/file1.txt", Entity(type="test/file", data={"content": "Local edit"}),
        )
        r_local = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(base_version.data["root"], "", cs))
        remote_entity = Entity(type="test/file", data={"content": "Remote edit"})
        remote_h = cs.put(remote_entity)
        remote_extra = Entity(type="test/file", data={"content": "Extra"})
        remote_extra_h = cs.put(remote_extra)
        remote_bindings = dict(base_bindings)
        remote_bindings["data/file1.txt"] = remote_h
        remote_bindings["data/extra.txt"] = remote_extra_h
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote}},
            handler_context,
        )

        result = await revision_handler(
            "system/revision", "resolve",
            {"data": {"prefix": "", "path": "data/file1.txt", "resolved": None}},
            handler_context,
        )
        assert result["status"] == 200
        assert result["result"]["data"]["resolved"] is None

        # Verify the path is gone
        tree = handler_context.emit_pathway.entity_tree
        uri = tree.normalize_uri("data/file1.txt")
        assert tree.get(uri) is None


# =============================================================================
# R5 — Resolve: remaining_conflicts result field
# =============================================================================


class TestResolveRemainingConflicts:
    @pytest.mark.asyncio
    async def test_remaining_conflicts_decrements(self, handler_context):
        """R5: remaining_conflicts counts down as conflicts are resolved."""
        cs = handler_context.emit_pathway.content_store

        # Create initial state with two files
        handler_context.emit_pathway.emit(
            "data/a.txt", Entity(type="test/file", data={"content": "A"}),
        )
        handler_context.emit_pathway.emit(
            "data/b.txt", Entity(type="test/file", data={"content": "B"}),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Local: edit both files
        handler_context.emit_pathway.emit(
            "data/a.txt", Entity(type="test/file", data={"content": "A-local"}),
        )
        handler_context.emit_pathway.emit(
            "data/b.txt", Entity(type="test/file", data={"content": "B-local"}),
        )
        r_local = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        # Remote: edit both differently + extra file to avoid oscillation
        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(base_version.data["root"], "", cs))
        remote_a = Entity(type="test/file", data={"content": "A-remote"})
        remote_b = Entity(type="test/file", data={"content": "B-remote"})
        remote_extra = Entity(type="test/file", data={"content": "Extra"})
        remote_bindings = dict(base_bindings)
        remote_bindings["data/a.txt"] = cs.put(remote_a)
        remote_bindings["data/b.txt"] = cs.put(remote_b)
        remote_bindings["data/extra.txt"] = cs.put(remote_extra)
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote}},
            handler_context,
        )

        # Resolve first conflict
        resolved_a = Entity(type="test/file", data={"content": "A-resolved"})
        resolved_a_h = cs.put(resolved_a)
        r1 = await revision_handler(
            "system/revision", "resolve",
            {"data": {"prefix": "", "path": "data/a.txt", "resolved": resolved_a_h}},
            handler_context,
        )
        assert r1["status"] == 200
        assert r1["result"]["data"]["remaining_conflicts"] == 1

        # Resolve second conflict
        resolved_b = Entity(type="test/file", data={"content": "B-resolved"})
        resolved_b_h = cs.put(resolved_b)
        r2 = await revision_handler(
            "system/revision", "resolve",
            {"data": {"prefix": "", "path": "data/b.txt", "resolved": resolved_b_h}},
            handler_context,
        )
        assert r2["status"] == 200
        assert r2["result"]["data"]["remaining_conflicts"] == 0


# =============================================================================
# R4 — KeepBoth merge strategy
# =============================================================================


class TestKeepBoth:
    @pytest.mark.asyncio
    async def test_keep_both_edit_edit(self, handler_context):
        """R4: keep-both stores both versions for edit/edit conflicts."""
        cs = handler_context.emit_pathway.content_store

        handler_context.emit_pathway.emit(
            "data/shared.txt", Entity(type="test/file", data={"content": "Original"}),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Local edit
        handler_context.emit_pathway.emit(
            "data/shared.txt", Entity(type="test/file", data={"content": "Local edit"}),
        )
        r_local = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        # Remote edit + extra file to avoid oscillation
        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(base_version.data["root"], "", cs))
        remote_entity = Entity(type="test/file", data={"content": "Remote edit"})
        remote_h = cs.put(remote_entity)
        remote_extra = Entity(type="test/file", data={"content": "Extra"})
        remote_extra_h = cs.put(remote_extra)
        remote_bindings = dict(base_bindings)
        remote_bindings["data/shared.txt"] = remote_h
        remote_bindings["data/extra.txt"] = remote_extra_h
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        result = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote, "strategy": "keep-both"}},
            handler_context,
        )
        data = result["result"]["data"]
        assert data["status"] == "merged"
        assert "conflicts" not in data or len(data.get("conflicts", [])) == 0

        # Verify both versions exist in tree
        tree = handler_context.emit_pathway.entity_tree
        local_uri = tree.normalize_uri("data/shared.txt")
        assert tree.get(local_uri) is not None

        # Find the keep-both path
        prefix = tree.normalize_uri("")
        keep_both_found = False
        for uri in tree.list_prefix(prefix):
            relative = uri[len(prefix):]
            if relative.startswith("data/shared.txt.keep-both-"):
                keep_both_found = True
                assert tree.get(uri) is not None
                break
        assert keep_both_found, "Expected a keep-both path for data/shared.txt"

    @pytest.mark.asyncio
    async def test_keep_both_delete_edit_falls_to_conflict(self, handler_context):
        """R4 / EXTENSION-REVISION v3.1 §2.3 Amendment 4: delete-vs-edit
        is governed by `deletion_resolution`, not the generic `keep-both`
        strategy. Setting `deletion_resolution: three-way-fallthrough`
        preserves the conflict-entity outcome operators expected from
        pre-v3.1 keep-both."""
        from entity_core.storage.emit import EmitContext
        cs = handler_context.emit_pathway.content_store

        # Per Amendment 4: install a per-path merge-config with
        # `deletion_resolution: three-way-fallthrough`. The default
        # (`preserve-on-conflict`) would silently take the edit.
        merge_cfg = Entity(
            type="system/revision/merge-config",
            data={
                "pattern": "data/shared.txt",
                "deletion_resolution": "three-way-fallthrough",
            },
        )
        handler_context.emit_pathway.emit(
            "system/revision/config/merge/path/shared-txt",
            merge_cfg,
            EmitContext.bootstrap(),
        )

        handler_context.emit_pathway.emit(
            "data/shared.txt", Entity(type="test/file", data={"content": "Original"}),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Local: delete the file
        tree = handler_context.emit_pathway.entity_tree
        tree.remove(tree.normalize_uri("data/shared.txt"))

        # Add an extra file so the local trie differs from the remote
        handler_context.emit_pathway.emit(
            "data/local_only.txt", Entity(type="test/file", data={"content": "Local only"}),
        )
        r_local = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        # Remote: edit the file + extra to avoid oscillation
        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(base_version.data["root"], "", cs))
        remote_entity = Entity(type="test/file", data={"content": "Remote edit"})
        remote_h = cs.put(remote_entity)
        remote_extra = Entity(type="test/file", data={"content": "Extra"})
        remote_extra_h = cs.put(remote_extra)
        remote_bindings = dict(base_bindings)
        remote_bindings["data/shared.txt"] = remote_h
        remote_bindings["data/extra.txt"] = remote_extra_h
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        result = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote, "strategy": "keep-both"}},
            handler_context,
        )
        data = result["result"]["data"]
        assert data["status"] == "merged_with_conflicts"
        assert "data/shared.txt" in data.get("conflicts", [])

    @pytest.mark.asyncio
    async def test_keep_both_hash_prefix_correct(self, handler_context):
        """R4: keep-both path suffix uses first 8 hex chars of remote entity hash."""
        cs = handler_context.emit_pathway.content_store

        handler_context.emit_pathway.emit(
            "data/shared.txt", Entity(type="test/file", data={"content": "Original"}),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Local edit
        handler_context.emit_pathway.emit(
            "data/shared.txt", Entity(type="test/file", data={"content": "Local edit"}),
        )
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        # Remote edit + extra
        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(base_version.data["root"], "", cs))
        remote_entity = Entity(type="test/file", data={"content": "Remote edit"})
        remote_h = cs.put(remote_entity)
        remote_extra = Entity(type="test/file", data={"content": "Extra"})
        remote_extra_h = cs.put(remote_extra)
        remote_bindings = dict(base_bindings)
        remote_bindings["data/shared.txt"] = remote_h
        remote_bindings["data/extra.txt"] = remote_extra_h
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote, "strategy": "keep-both"}},
            handler_context,
        )

        # Under deterministic ordering, figure out which side is "remote"
        # and verify the hash prefix matches
        tree = handler_context.emit_pathway.entity_tree
        prefix = tree.normalize_uri("")
        for uri in tree.list_prefix(prefix):
            relative = uri[len(prefix):]
            if ".keep-both-" in relative:
                suffix = relative.split(".keep-both-")[1]
                assert len(suffix) == 8
                # Verify it's valid hex
                int(suffix, 16)
                # Per spec: hex(remote_hash)[0:8] — full hash including algorithm byte
                keep_both_hash = tree.get(uri)
                expected_prefix = keep_both_hash[0:4].hex()
                assert suffix == expected_prefix
                # For ECFv1-SHA256, prefix always starts with "00"
                assert suffix.startswith("00")
                break

    @pytest.mark.asyncio
    async def test_status_surfaces_keep_both_paths(self, handler_context):
        """R4: status includes keep_both_paths when present."""
        cs = handler_context.emit_pathway.content_store

        handler_context.emit_pathway.emit(
            "data/shared.txt", Entity(type="test/file", data={"content": "Original"}),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        handler_context.emit_pathway.emit(
            "data/shared.txt", Entity(type="test/file", data={"content": "Local edit"}),
        )
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(base_version.data["root"], "", cs))
        remote_entity = Entity(type="test/file", data={"content": "Remote edit"})
        remote_h = cs.put(remote_entity)
        remote_extra = Entity(type="test/file", data={"content": "Extra"})
        remote_extra_h = cs.put(remote_extra)
        remote_bindings = dict(base_bindings)
        remote_bindings["data/shared.txt"] = remote_h
        remote_bindings["data/extra.txt"] = remote_extra_h
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote, "strategy": "keep-both"}},
            handler_context,
        )

        status = await revision_handler(
            "system/revision", "status",
            {"data": {"prefix": ""}},
            handler_context,
        )
        status_data = status["result"]["data"]
        assert "keep_both_paths" in status_data
        assert len(status_data["keep_both_paths"]) == 1
        assert ".keep-both-" in status_data["keep_both_paths"][0]


# =============================================================================
# W5 — Per-path/per-type merge config cascade
# =============================================================================


class TestMergeConfigCascade:
    """Tests for §5.1 merge resolution cascade: type config → path config → default."""

    def _create_diverged_merge(self, handler_context, shared_path="data/shared.txt"):
        """Helper: sets up diverged branches that conflict on shared_path.

        Returns (v1, v_local, v_remote) where v_local and v_remote diverge on shared_path.
        """
        cs = handler_context.emit_pathway.content_store

        handler_context.emit_pathway.emit(
            shared_path, Entity(type="test/file", data={"content": "Original"}),
        )
        return cs, shared_path

    @pytest.mark.asyncio
    async def test_per_type_config_keep_both(self, handler_context):
        """W5: per-type merge config applies keep-both without request-level strategy."""
        cs = handler_context.emit_pathway.content_store
        emit = handler_context.emit_pathway

        # Store a per-type merge config for "test/file"
        from entity_core.storage.emit import EmitContext
        emit_ctx = EmitContext.protocol(author="remote-peer")
        type_config = Entity(
            type="system/revision/merge-config",
            data={"strategy": "keep-both"},
        )
        emit.emit("system/revision/config/merge/type/test/file", type_config, emit_ctx)

        # Create initial state
        emit.emit("data/shared.txt", Entity(type="test/file", data={"content": "Original"}))
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Local edit
        emit.emit("data/shared.txt", Entity(type="test/file", data={"content": "Local edit"}))
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        # Remote edit + extra file to avoid oscillation
        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(base_version.data["root"], "", cs))
        remote_entity = Entity(type="test/file", data={"content": "Remote edit"})
        remote_h = cs.put(remote_entity)
        remote_extra = Entity(type="test/file", data={"content": "Extra"})
        remote_extra_h = cs.put(remote_extra)
        remote_bindings = dict(base_bindings)
        remote_bindings["data/shared.txt"] = remote_h
        remote_bindings["data/extra.txt"] = remote_extra_h
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        # Merge WITHOUT specifying strategy — should discover keep-both from type config
        result = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote}},
            handler_context,
        )
        data = result["result"]["data"]
        assert data["status"] == "merged", f"Expected merged but got {data['status']}"
        assert "conflicts" not in data or len(data.get("conflicts", [])) == 0

        # Verify keep-both path was created
        tree = handler_context.emit_pathway.entity_tree
        prefix = tree.normalize_uri("")
        found_keep_both = any(
            ".keep-both-" in uri[len(prefix):]
            for uri in tree.list_prefix(prefix)
        )
        assert found_keep_both, "Expected keep-both binding from per-type config"

    @pytest.mark.asyncio
    async def test_per_path_config_source_wins(self, handler_context):
        """W5: per-path merge config applies source-wins for matching glob."""
        cs = handler_context.emit_pathway.content_store
        emit = handler_context.emit_pathway

        from entity_core.storage.emit import EmitContext
        emit_ctx = EmitContext.protocol(author="remote-peer")
        path_config = Entity(
            type="system/revision/merge-config",
            data={"pattern": "data/*.txt", "strategy": "source-wins"},
        )
        emit.emit("system/revision/config/merge/path/txt-files", path_config, emit_ctx)

        emit.emit("data/shared.txt", Entity(type="test/file", data={"content": "Original"}))
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        # Local edit
        emit.emit("data/shared.txt", Entity(type="test/file", data={"content": "Local edit"}))
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        # Remote edit + extra
        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(base_version.data["root"], "", cs))
        remote_entity = Entity(type="test/file", data={"content": "Remote edit"})
        remote_h = cs.put(remote_entity)
        remote_extra = Entity(type="test/file", data={"content": "Extra"})
        remote_extra_h = cs.put(remote_extra)
        remote_bindings = dict(base_bindings)
        remote_bindings["data/shared.txt"] = remote_h
        remote_bindings["data/extra.txt"] = remote_extra_h
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        result = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote}},
            handler_context,
        )
        data = result["result"]["data"]
        assert data["status"] == "merged"
        assert "conflicts" not in data or len(data.get("conflicts", [])) == 0

    @pytest.mark.asyncio
    async def test_type_config_takes_priority_over_path_config(self, handler_context):
        """W5: per-type config (step 1) takes priority over per-path config (step 2)."""
        cs = handler_context.emit_pathway.content_store
        emit = handler_context.emit_pathway

        from entity_core.storage.emit import EmitContext
        emit_ctx = EmitContext.protocol(author="remote-peer")

        # Per-path config: source-wins (would resolve without keep-both path)
        path_config = Entity(
            type="system/revision/merge-config",
            data={"pattern": "data/*", "strategy": "source-wins"},
        )
        emit.emit("system/revision/config/merge/path/data-files", path_config, emit_ctx)

        # Per-type config: keep-both (should take priority — produces .keep-both- path)
        type_config = Entity(
            type="system/revision/merge-config",
            data={"strategy": "keep-both"},
        )
        emit.emit("system/revision/config/merge/type/test/file", type_config, emit_ctx)

        emit.emit("data/shared.txt", Entity(type="test/file", data={"content": "Original"}))
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        emit.emit("data/shared.txt", Entity(type="test/file", data={"content": "Local edit"}))
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(base_version.data["root"], "", cs))
        remote_entity = Entity(type="test/file", data={"content": "Remote edit"})
        remote_h = cs.put(remote_entity)
        remote_extra = Entity(type="test/file", data={"content": "Extra"})
        remote_extra_h = cs.put(remote_extra)
        remote_bindings = dict(base_bindings)
        remote_bindings["data/shared.txt"] = remote_h
        remote_bindings["data/extra.txt"] = remote_extra_h
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        result = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote}},
            handler_context,
        )
        data = result["result"]["data"]
        assert data["status"] == "merged"

        # If type config won (keep-both), a .keep-both- path exists.
        # If path config won (source-wins), no keep-both path.
        tree = handler_context.emit_pathway.entity_tree
        prefix = tree.normalize_uri("")
        found_keep_both = any(
            ".keep-both-" in uri[len(prefix):]
            for uri in tree.list_prefix(prefix)
        )
        assert found_keep_both, "Type config (keep-both) should take priority over path config (source-wins)"

    @pytest.mark.asyncio
    async def test_no_config_defaults_to_conflict(self, handler_context):
        """W5: without any merge config, edit/edit conflict produces conflict entity."""
        cs = handler_context.emit_pathway.content_store

        handler_context.emit_pathway.emit(
            "data/shared.txt", Entity(type="test/file", data={"content": "Original"}),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )
        v1 = r1["result"]["data"]["version"]

        handler_context.emit_pathway.emit(
            "data/shared.txt", Entity(type="test/file", data={"content": "Local edit"}),
        )
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context,
        )

        base_version = cs.get(v1)
        base_bindings = dict(collect_all_bindings(base_version.data["root"], "", cs))
        remote_entity = Entity(type="test/file", data={"content": "Remote edit"})
        remote_h = cs.put(remote_entity)
        remote_extra = Entity(type="test/file", data={"content": "Extra"})
        remote_extra_h = cs.put(remote_extra)
        remote_bindings = dict(base_bindings)
        remote_bindings["data/shared.txt"] = remote_h
        remote_bindings["data/extra.txt"] = remote_extra_h
        remote_trie_root = build_trie(sorted(remote_bindings.items()), cs)
        remote_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_trie_root, "parents": sorted_parents([v1])},
        )
        v_remote = cs.put(remote_version)

        result = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v_remote}},
            handler_context,
        )
        data = result["result"]["data"]
        assert data["status"] == "merged_with_conflicts"
        assert "data/shared.txt" in data.get("conflicts", [])
