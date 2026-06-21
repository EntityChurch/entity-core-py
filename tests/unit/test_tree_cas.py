"""Unit tests for tree put CAS via expected_hash.

Per ENTITY-CORE-PROTOCOL-V7 §3.9 (v7.22) and PROPOSAL-INCREMENTAL-TRIE-ROOT-TRACKING R8.

Conditional write semantics:
- expected_hash present + current binding hash matches -> succeeds
- expected_hash present + current binding hash differs -> 409 hash_mismatch
- expected_hash present + no binding exists -> 409 hash_mismatch
- expected_hash absent -> unconditional write (existing behavior)
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
    return ContentStore()


@pytest.fixture
def entity_tree() -> EntityTree:
    return EntityTree("test-peer")


@pytest.fixture
def emit_pathway(content_store: ContentStore, entity_tree: EntityTree) -> EmitPathway:
    return EmitPathway(content_store, entity_tree)


@pytest.fixture
def tree_registry(entity_tree: EntityTree, content_store: ContentStore) -> TreeRegistry:
    return TreeRegistry(entity_tree, content_store)


def _ctx(emit_pathway: EmitPathway, tree_registry: TreeRegistry, target_path: str) -> HandlerContext:
    permissive = {
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
        handler_grant=permissive,
        caller_capability=permissive,
        emit_pathway=emit_pathway,
        tree_registry=tree_registry,
        handler_pattern="system/tree",
        resource_targets=[target_path],
    )


def _entity(value: str) -> dict:
    return {"type": "test/blob", "data": {"value": value}}


@pytest.mark.asyncio
async def test_put_succeeds_when_expected_hash_matches(emit_pathway, tree_registry):
    """CAS succeeds when expected_hash equals the current binding hash."""
    path = "data/cas/k1"
    h0 = emit_pathway.emit(path, Entity.from_dict(_entity("v0"))).hash

    ctx = _ctx(emit_pathway, tree_registry, path)
    result = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": _entity("v1"), "expected_hash": h0}},
        ctx,
    )

    assert result["status"] == 200
    assert result["result"]["data"]["hash"] != h0


@pytest.mark.asyncio
async def test_put_409_when_expected_hash_mismatches(emit_pathway, tree_registry):
    """CAS fails with 409 hash_mismatch when expected_hash differs from current."""
    path = "data/cas/k2"
    emit_pathway.emit(path, Entity.from_dict(_entity("real")))
    stale_hash = bytes([0x00]) + b"\x11" * 32  # well-formed but wrong

    ctx = _ctx(emit_pathway, tree_registry, path)
    result = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": _entity("attempt"), "expected_hash": stale_hash}},
        ctx,
    )

    assert result["status"] == 409
    assert result["result"]["data"]["code"] == "hash_mismatch"
    # Existing binding must be untouched
    current = emit_pathway.entity_tree.get(
        emit_pathway.entity_tree.normalize_uri(path)
    )
    stored = emit_pathway.content_store.get(current).data["value"]
    assert stored == "real"


@pytest.mark.asyncio
async def test_put_409_when_no_binding_exists(emit_pathway, tree_registry):
    """CAS fails with 409 when caller expects a binding but none exists."""
    path = "data/cas/missing"
    expected = bytes([0x00]) + b"\x22" * 32

    ctx = _ctx(emit_pathway, tree_registry, path)
    result = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": _entity("v0"), "expected_hash": expected}},
        ctx,
    )

    assert result["status"] == 409
    assert result["result"]["data"]["code"] == "hash_mismatch"
    assert (
        emit_pathway.entity_tree.get(emit_pathway.entity_tree.normalize_uri(path))
        is None
    )


@pytest.mark.asyncio
async def test_put_rejects_control_char_in_path(emit_pathway, tree_registry):
    """v7.72 §9.5a CORE-TREE-PATH-FLEX-1: a NUL (or any C0/DEL) byte in the
    write path is rejected with 400 invalid_path before any binding."""
    path = "data/cas/n\x00ul"
    ctx = _ctx(emit_pathway, tree_registry, path)
    result = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": _entity("v0")}},
        ctx,
    )

    assert result["status"] == 400
    assert result["result"]["data"]["code"] == "invalid_path"
    # Nothing bound.
    assert (
        emit_pathway.entity_tree.get(emit_pathway.entity_tree.normalize_uri(path))
        is None
    )


@pytest.mark.asyncio
async def test_put_unconditional_when_expected_hash_absent(emit_pathway, tree_registry):
    """Without expected_hash, put is unconditional (backward-compat)."""
    path = "data/cas/k3"
    emit_pathway.emit(path, Entity.from_dict(_entity("v0")))

    ctx = _ctx(emit_pathway, tree_registry, path)
    result = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": _entity("v1")}},
        ctx,
    )

    assert result["status"] == 200


@pytest.mark.asyncio
async def test_remove_with_matching_expected_hash(emit_pathway, tree_registry):
    """CAS applies to remove (entity=null) too: matching hash succeeds."""
    path = "data/cas/k4"
    h0 = emit_pathway.emit(path, Entity.from_dict(_entity("v0"))).hash

    ctx = _ctx(emit_pathway, tree_registry, path)
    result = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": None, "expected_hash": h0}},
        ctx,
    )

    assert result["status"] == 200
    assert result["result"]["data"]["removed"] is True
    assert (
        emit_pathway.entity_tree.get(emit_pathway.entity_tree.normalize_uri(path))
        is None
    )


@pytest.mark.asyncio
async def test_remove_409_when_expected_hash_mismatches(emit_pathway, tree_registry):
    """CAS on remove fails with 409 when stored hash differs."""
    path = "data/cas/k5"
    emit_pathway.emit(path, Entity.from_dict(_entity("real")))
    wrong = bytes([0x00]) + b"\x33" * 32

    ctx = _ctx(emit_pathway, tree_registry, path)
    result = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": None, "expected_hash": wrong}},
        ctx,
    )

    assert result["status"] == 409
    assert result["result"]["data"]["code"] == "hash_mismatch"
    # Binding still present
    assert (
        emit_pathway.entity_tree.get(emit_pathway.entity_tree.normalize_uri(path))
        is not None
    )


# ---------------------------------------------------------------------------
# V7 §3.9 v7.50 — CAS-create (the zero hash means "expect path unbound")
# ---------------------------------------------------------------------------

# The reserved zero hash: never a valid content hash, distinct from omission.
ZERO_HASH = b"\x00" * 33


@pytest.mark.asyncio
async def test_cas_create_succeeds_when_path_unbound(emit_pathway, tree_registry):
    """Zero expected_hash on an unbound path succeeds (clean create)."""
    path = "data/cas/fresh"
    ctx = _ctx(emit_pathway, tree_registry, path)
    result = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": _entity("v0"), "expected_hash": ZERO_HASH}},
        ctx,
    )

    assert result["status"] == 200
    bound = emit_pathway.entity_tree.get(emit_pathway.entity_tree.normalize_uri(path))
    assert bound is not None


@pytest.mark.asyncio
async def test_cas_create_409_when_path_already_bound(emit_pathway, tree_registry):
    """Zero expected_hash on a bound path fails 409 (a stale created-lap dies).

    This is the bootstrap-amplification guard: a stale `created` lap arriving
    after the mirror path is already bound must NOT overwrite it.
    """
    path = "data/cas/taken"
    emit_pathway.emit(path, Entity.from_dict(_entity("already-here")))

    ctx = _ctx(emit_pathway, tree_registry, path)
    result = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": _entity("stale-create"), "expected_hash": ZERO_HASH}},
        ctx,
    )

    assert result["status"] == 409
    assert result["result"]["data"]["code"] == "hash_mismatch"
    # Existing binding untouched
    current = emit_pathway.entity_tree.get(emit_pathway.entity_tree.normalize_uri(path))
    assert emit_pathway.content_store.get(current).data["value"] == "already-here"


@pytest.mark.asyncio
async def test_cas_create_accepts_empty_bytes_as_zero(emit_pathway, tree_registry):
    """An empty-bytes expected_hash is also the zero sentinel (CAS-create)."""
    path = "data/cas/empty-zero"
    ctx = _ctx(emit_pathway, tree_registry, path)
    result = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": _entity("v0"), "expected_hash": b""}},
        ctx,
    )
    assert result["status"] == 200


@pytest.mark.asyncio
async def test_cas_create_then_replace_chain(emit_pathway, tree_registry):
    """Create with zero hash, then a stale create fails, then a real replace works."""
    path = "data/cas/lifecycle"
    ctx = _ctx(emit_pathway, tree_registry, path)

    # Create.
    r1 = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": _entity("v0"), "expected_hash": ZERO_HASH}}, ctx,
    )
    assert r1["status"] == 200
    h0 = emit_pathway.entity_tree.get(emit_pathway.entity_tree.normalize_uri(path))

    # A stale create-lap now fails (path is bound).
    r2 = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": _entity("stale"), "expected_hash": ZERO_HASH}}, ctx,
    )
    assert r2["status"] == 409

    # A real replace against the current head succeeds.
    r3 = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": _entity("v1"), "expected_hash": h0}}, ctx,
    )
    assert r3["status"] == 200
