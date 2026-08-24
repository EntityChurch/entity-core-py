"""Strict entity fidelity on the `tree:put` receipt path.

V7 §1.8 / v7.69 §4.5a, ENCRYPTION §16 `ENC-ROUNDTRIP-FORMAT-1`: a received
entity's `content_hash` is validated on receipt and then **trusted verbatim** —
never recomputed, and in particular never re-derived under the receiving peer's
*home* content_hash format.

Why this needed its own file rather than a line in `test_tree_cas.py`: the
defect it pins is invisible under the conditions every other tree test runs in.
When the author and the receiver share a hash format the recompute *coincides*
with the carried hash, so `Entity.from_dict` — which drops `content_hash` and
re-derives on demand — looks correct in every same-format test in the suite.
It rewrites the reference only when a foreign-format entity arrives, which is
exactly the case a single-format test corpus never constructs. The cross-impl
validator caught it; a same-home unit test never could.

The consequence is not cosmetic: the authored hash is the *name* other peers
hold. Re-deriving it means a peer stores the entity under a hash nobody
referenced, and every holder of the authored reference 404s.
"""

from __future__ import annotations

import pytest

from entity_core.handlers.context import HandlerContext
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.tree_registry import TreeRegistry
from entity_core.utils.ecf import ALG_ECFV1_SHA256, ALG_ECFV1_SHA384, compute_ecf_hash

from entity_handlers.tree import tree_handler


@pytest.fixture
def emit_pathway() -> EmitPathway:
    return EmitPathway(ContentStore(), EntityTree("test-peer"))


@pytest.fixture
def tree_registry(emit_pathway: EmitPathway) -> TreeRegistry:
    return TreeRegistry(emit_pathway.entity_tree, emit_pathway.content_store)


def _ctx(emit_pathway, tree_registry, target_path: str) -> HandlerContext:
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


def _wire_entity(value: str, algorithm: int) -> dict:
    """An entity as a peer on `algorithm` would have authored it: the
    content_hash is a real hash of `{type, data}` under that format."""
    body = {"type": "test/blob", "data": {"value": value}}
    return {**body, "content_hash": compute_ecf_hash(body, algorithm)}


async def _put(emit_pathway, tree_registry, path: str, entity: dict) -> dict:
    return await tree_handler(
        "system/tree", "put",
        {"data": {"entity": entity}},
        _ctx(emit_pathway, tree_registry, path),
    )


@pytest.mark.asyncio
async def test_put_preserves_foreign_format_content_hash(emit_pathway, tree_registry):
    """A SHA-384-authored entity put onto a SHA-256-home peer keeps its
    authored hash, both as the binding and in the stored entity."""
    path = "data/fidelity/foreign"
    wire = _wire_entity("cross-format", ALG_ECFV1_SHA384)
    authored = wire["content_hash"]
    assert authored[0] == ALG_ECFV1_SHA384
    assert len(authored) == 49  # 1 format byte + 48-byte digest

    result = await _put(emit_pathway, tree_registry, path, wire)
    assert result["status"] == 200
    assert result["result"]["data"]["hash"] == authored

    # The binding resolves to the AUTHORED hash — this is the reference other
    # peers hold, so a re-derived one strands every holder of it.
    full_uri = emit_pathway.entity_tree.normalize_uri(path)
    assert emit_pathway.entity_tree.get(full_uri) == authored

    # And the entity is retrievable under it, still carrying its own hash.
    stored = emit_pathway.content_store.get(authored)
    assert stored is not None
    assert stored.compute_hash() == authored
    assert stored.data == {"value": "cross-format"}


@pytest.mark.asyncio
async def test_put_preserves_home_format_content_hash(emit_pathway, tree_registry):
    """The same-format case, asserted explicitly so the foreign-format test
    above is known to be measuring format preservation rather than a lucky
    difference: a carried SHA-256 hash is also the one bound."""
    path = "data/fidelity/home"
    wire = _wire_entity("same-format", ALG_ECFV1_SHA256)
    result = await _put(emit_pathway, tree_registry, path, wire)
    assert result["status"] == 200
    assert result["result"]["data"]["hash"] == wire["content_hash"]


@pytest.mark.asyncio
async def test_put_rejects_a_lying_content_hash(emit_pathway, tree_registry):
    """§1.8 is validate-then-trust, not trust. A carried hash that does not
    match its own `{type, data}` is refused 400 — otherwise 'never recompute'
    would let any caller bind arbitrary content under a hash of its choosing,
    which is content-addressing defeated at the door."""
    path = "data/fidelity/liar"
    wire = _wire_entity("honest", ALG_ECFV1_SHA256)
    wire["data"] = {"value": "tampered"}  # hash now describes the old body

    result = await _put(emit_pathway, tree_registry, path, wire)
    assert result["status"] == 400
    assert result["result"]["data"]["code"] == "hash_mismatch"
    assert emit_pathway.entity_tree.get(
        emit_pathway.entity_tree.normalize_uri(path)
    ) is None


@pytest.mark.asyncio
async def test_put_authors_a_hash_when_none_is_carried(emit_pathway, tree_registry):
    """A locally-constructed entity carries no claimed hash, so the peer
    authors one under its own format. The trust rule is about *received*
    hashes; it does not mean an absent hash is an error."""
    path = "data/fidelity/local"
    result = await _put(
        emit_pathway, tree_registry, path,
        {"type": "test/blob", "data": {"value": "local"}},
    )
    assert result["status"] == 200
    assert result["result"]["data"]["hash"][0] == ALG_ECFV1_SHA256
