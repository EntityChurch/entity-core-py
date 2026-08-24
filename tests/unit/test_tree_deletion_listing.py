"""v7.72 §9.5a CORE-TREE-DELETE-1: tree:list omits deletion-marker children.

A direct child whose binding IS a system/deletion-marker is filtered from
the listing (O(1) format-relative hash test, no store I/O):

  - marker-bound leaf with NO nested children → drops entirely.
  - marker-bound path that STILL has nested children → stays as a
    directory-only entry (children visible, the marker-bound leaf hidden:
    hash suppressed to None).
  - a normal binding is unaffected.
"""

from __future__ import annotations

import pytest

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.tree_registry import TreeRegistry
from entity_core.types.deletion_marker import (
    deletion_marker_entity,
    deletion_marker_hash,
)

from entity_handlers.tree import tree_handler


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


def _ctx(emit_pathway, tree_registry, target_path):
    permissive = {
        "grants": [{
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }]
    }
    return HandlerContext(
        local_peer_id="test-peer",
        remote_peer_id="remote-peer",
        handler_grant=permissive,
        caller_capability=permissive,
        emit_pathway=emit_pathway,
        tree_registry=tree_registry,
        handler_pattern="system/tree",
        resource_targets=[target_path],
    )


def _bind_marker(emit_pathway, path):
    """Bind a system/deletion-marker at `path` (home-format hash)."""
    emit_pathway.content_store.put(deletion_marker_entity())
    uri = emit_pathway.entity_tree.normalize_uri(path)
    emit_pathway.entity_tree.set(uri, deletion_marker_hash())


async def _list(emit_pathway, tree_registry, prefix):
    ctx = _ctx(emit_pathway, tree_registry, prefix)
    result = await tree_handler("system/tree", "get", {"data": {}}, ctx)
    assert result["status"] == 200, result
    return result["result"]["data"]["entries"]


@pytest.mark.asyncio
async def test_marker_leaf_dropped(emit_pathway, tree_registry):
    """A marker-bound leaf with no children disappears from the listing."""
    emit_pathway.emit("app/keep", Entity.from_dict({"type": "test/blob", "data": {"v": 1}}))
    _bind_marker(emit_pathway, "app/gone")

    entries = await _list(emit_pathway, tree_registry, "app/")
    assert "keep" in entries
    assert "gone" not in entries


@pytest.mark.asyncio
async def test_marker_with_children_stays_as_directory(emit_pathway, tree_registry):
    """A marker-bound path that still has nested children stays as a
    directory-only entry: visible, has_children True, hash suppressed."""
    _bind_marker(emit_pathway, "app/dir")
    emit_pathway.emit("app/dir/child", Entity.from_dict({"type": "test/blob", "data": {"v": 2}}))

    entries = await _list(emit_pathway, tree_registry, "app/")
    assert "dir" in entries
    assert entries["dir"]["has_children"] is True
    assert entries["dir"]["hash"] is None


@pytest.mark.asyncio
async def test_count_reflects_filtered_set(emit_pathway, tree_registry):
    """The listing count is taken after the marker filter, not before."""
    emit_pathway.emit("app/keep", Entity.from_dict({"type": "test/blob", "data": {"v": 1}}))
    _bind_marker(emit_pathway, "app/gone")

    ctx = _ctx(emit_pathway, tree_registry, "app/")
    result = await tree_handler("system/tree", "get", {"data": {}}, ctx)
    assert result["result"]["data"]["count"] == 1


@pytest.mark.asyncio
async def test_unbind_emits_a_deleted_change_event(emit_pathway, tree_registry):
    """`tree:put` with a null entity MUST go through the emit pathway.

    The unbind used to mutate `entity_tree` directly, which emits no
    ChangeEvent, so every cascade consumer missed it — subscribers were
    never told the path was unbound, and the published-root republisher
    (PROPOSAL-PEER-MANIFEST §4, "on every tree-root change") went on
    advertising a signed root that still committed to the deleted
    binding. The binding removal was always correct; the silence about
    it was not.
    """
    from entity_core.storage.emit import ChangeKind

    emit_pathway.emit(
        "app/doomed", Entity.from_dict({"type": "test/blob", "data": {"v": 1}})
    )

    seen: list[tuple[str, object]] = []

    class _Spy:
        def on_change_sync(self, event):
            seen.append((event.uri, event.kind))
            return None

    emit_pathway._add_internal_hook(_Spy(), pattern=None, name="spy")

    ctx = _ctx(emit_pathway, tree_registry, "app/doomed")
    result = await tree_handler("system/tree", "put", {"data": {}}, ctx)
    assert result["status"] == 200, result
    assert result["result"]["data"]["removed"] is True

    full = emit_pathway.entity_tree.normalize_uri("app/doomed")
    assert (full, ChangeKind.DELETED) in seen, (
        f"unbind emitted no DELETED event; saw {seen}"
    )
    assert emit_pathway.entity_tree.get(full) is None
