"""§1 — bare `lookup/tree` path canonicalization (EXTENSION-COMPUTE v3.20 / V7 §5.4).

Cross-impl check: a bare-path reactive dependency (a `compute/lookup/tree`
with `relative` false/absent and no leading slash) MUST trigger recompute
when that path is written. Go hit a "verbatim-no-track" footgun (the dep was
stored bare while the write produced a canonical path, so they never matched).

Python canonicalizes at the tree boundary: dependencies are indexed via
`entity_tree.normalize_uri`, and `EmitPathway.emit` records `ChangeEvent.uri`
in the same normalized form — so a bare-path dep and a write to it land on
the same key. This test proves both sides agree end-to-end.
"""

from __future__ import annotations

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import ChangeEvent, EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.compute import (
    DependencyIndex,
    DepEntry,
    EvalContext,
    walk_tree_lookups,
)


def test_bare_path_dependency_matches_write_event():
    peer_id = "test-peer"
    cs = ContentStore()
    tree = EntityTree(peer_id)
    ep = EmitPathway(cs, tree)

    # A bare-path lookup/tree: no `relative` flag, no leading slash.
    expr = Entity(type="compute/lookup/tree", data={"path": "app/data"})

    ctx = EvalContext(
        content_store=cs, entity_tree=tree, local_peer_id=peer_id, capability={}
    )
    deps = walk_tree_lookups(expr, ctx)
    assert deps == ["app/data"]  # collected verbatim from the expression...

    # ...and indexed canonically, exactly as install/rebuild do (line 2774/3047).
    index = DependencyIndex()
    entry = DepEntry(
        expression_uri="app/expr", subgraph_path="system/compute/processes/x"
    )
    for d in deps:
        index.add(tree.normalize_uri(d), entry)

    # Capture the real ChangeEvent.uri a write to the bare path produces.
    captured: dict[str, str] = {}

    class _Capture:
        def on_change_sync(self, event: ChangeEvent) -> int | None:
            captured["uri"] = event.uri
            return None

    ep._add_internal_hook(_Capture(), name="capture")
    ep.emit("app/data", Entity(type="test", data={"v": 1}), EmitContext.bootstrap())

    # The write event's URI is the canonical local-peer form...
    assert captured["uri"] == f"/{peer_id}/app/data"
    # ...and it matches the bare-path dependency — recompute would fire.
    assert index.match(captured["uri"]) == [entry]


def test_relative_flag_qualifies_against_subgraph_root():
    """A `relative:true` lookup/tree qualifies against the subgraph root,
    not the local-peer root — the other branch of V7 §5.4."""
    cs = ContentStore()
    tree = EntityTree("p")
    expr = Entity(
        type="compute/lookup/tree", data={"path": "leaf", "relative": True}
    )
    ctx = EvalContext(
        content_store=cs, entity_tree=tree, local_peer_id="p", capability={}
    )
    deps = walk_tree_lookups(expr, ctx, root_path="app/subgraph")
    assert deps == ["app/subgraph/leaf"]
