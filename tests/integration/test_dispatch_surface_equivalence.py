"""§2 dispatch-surface result equivalence (V7 v7.49 §3.3).

A handler's result MUST be identical across dispatch surfaces — external
EXECUTE, internal sub-dispatch (ctx.execute), remote dispatch. A multi-entity
result is a `system/envelope` whose own `data.included` carries the domain
entities (the cross-peer wire carrier), so the bundle rides *inside* `result`
and is preserved on every surface without an out-of-band channel.

Regression context: `tree:snapshot` bundles its trie nodes; the internal
ExecuteResult once dropped them (it had no `included` field). The fix is the
`system/envelope` carrier — the bundle is part of the result entity, so
internal/remote dispatch carry it unchanged by construction.
"""

from __future__ import annotations

import pytest

from entity_core.capability.grant import create_full_access_grant
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_core.storage.trie import collect_all_bindings


@pytest.fixture
def peer():
    return (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_default_handlers()
        .build()
    )


def _full_cap() -> dict:
    """A permissive capability token (full access) for the caller side."""
    return {"grants": [g.to_dict() for g in create_full_access_grant()]}


@pytest.mark.asyncio
async def test_internal_dispatch_result_is_self_contained_envelope(peer):
    """tree:snapshot dispatched internally returns a self-contained envelope."""
    ep = peer.emit_pathway
    for path, content in [
        ("data/a.txt", "A"),
        ("data/b.txt", "B"),
        ("data/sub/c.txt", "C"),
    ]:
        ep.emit(path, Entity(type="test/file", data={"content": content}),
                EmitContext.bootstrap())

    dispatcher = peer._make_execute_dispatcher(_full_cap(), peer.peer_id, None)
    result = await dispatcher(
        "system/tree", "snapshot", {"data": {"prefix": "data/"}},
        _full_cap(), None, None, None,
    )

    assert result.status == 200
    # v3.6 F4-cycle wire-shape: result IS the snapshot entity directly;
    # the bundle rides in envelope_included (threaded through internal
    # dispatch via ExecuteResult.envelope_included for surface
    # equivalence with the wire path).
    assert result.result["type"] == "system/tree/snapshot"
    assert result.envelope_included, (
        "envelope_included MUST carry the bundled trie nodes — "
        "the bundle is the out-of-band carrier matching the outer "
        "wire envelope's included on the wire path"
    )

    # The bundle alone reconstructs the snapshot bindings — no store access,
    # exactly what a compute read-back / remote consumer relies on.
    class _BundleStore:
        def __init__(self, included):
            self._m = {h: Entity.from_dict(d) for h, d in included.items()}

        def get(self, h):
            return self._m.get(h)

    root_hash = result.result["data"]["root"]
    bindings = dict(
        collect_all_bindings(root_hash, "", _BundleStore(result.envelope_included))
    )
    assert len(bindings) == 3


@pytest.mark.asyncio
async def test_internal_result_matches_external_handler_return(peer):
    """The internal ExecuteResult.result equals the handler's own result."""
    from entity_handlers import tree_handler
    from entity_core.handlers.context import HandlerContext

    ep = peer.emit_pathway
    for path, content in [("x/1", "1"), ("x/2", "2")]:
        ep.emit(path, Entity(type="test/file", data={"content": content}),
                EmitContext.bootstrap())

    # Direct handler call — the "external" shape the wire path forwards.
    ctx = HandlerContext(
        local_peer_id=peer.peer_id,
        remote_peer_id="remote",
        handler_grant=_full_cap(),
        caller_capability=_full_cap(),
        emit_pathway=ep,
        handler_pattern="system/tree",
    )
    direct = await tree_handler("system/tree", "snapshot", {"data": {"prefix": ""}}, ctx)

    # Internal sub-dispatch — the result (envelope + its included) is identical.
    dispatcher = peer._make_execute_dispatcher(_full_cap(), peer.peer_id, None)
    result = await dispatcher(
        "system/tree", "snapshot", {"data": {"prefix": ""}},
        _full_cap(), None, None, None,
    )

    assert result.result == direct["result"]
    assert result.result["type"] == "system/tree/snapshot"
    # Surface equivalence: the bundle carried in direct["envelope_included"]
    # is preserved through internal dispatch on ExecuteResult.envelope_included.
    assert result.envelope_included == direct.get("envelope_included")
    assert direct["envelope_included"], "snapshot bundles trie nodes"
