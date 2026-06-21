"""Regression: compute/apply (handler mode) → entity-native handler.

Mirrors the cross-impl validator vector `v314_compute_apply_to_entity_native`:
a caller compute expression applies to an entity-native handler whose body is
`params.x + 1`. This exercised a 500 — the unwrapped entity-native result is a
`primitive/any` entity whose `.data` is a bare value, which v3.19c's
materialize-at-the-crossing pass must handle without assuming dict `.data`.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

_WILDCARD = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": ["*"]},
    }],
    "allowances": {"content_store_access": True},
}


@pytest.mark.asyncio
async def test_compute_apply_to_entity_native_returns_wrapped_primitive():
    """apply("app/native", "compute", {x: 41}) → entity-native body params.x + 1
    → 42, wrapped in primitive/any. (Was a 500 in materialize-at-crossing.)"""
    kp = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(kp)
        .with_all_handlers()
        .with_entity_native_handler(
            "app/native",
            "app/native/expr",
            {"compute": {"input_type": "primitive/any", "output_type": "primitive/any"}},
        )
        .build()
    )
    ctx = EmitContext.bootstrap()

    def emit(path: str, ent: Entity) -> bytes:
        peer.emit_pathway.emit(path, ent, ctx)
        return peer.emit_pathway.entity_tree.get(path)

    # Entity-native handler body (tree-bound under the slot): params.x + 1.
    p_lookup = emit("app/native/p-lookup", Entity(type="compute/lookup/scope", data={"name": "params"}))
    field_x = emit("app/native/field-x", Entity(type="compute/field", data={"name": "x", "entity": p_lookup}))
    one = emit("app/native/one", Entity(type="compute/literal", data={"value": 1}))
    emit("app/native/expr", Entity(type="compute/arithmetic", data={"op": "add", "left": field_x, "right": one}))

    # Caller: apply("app/native", "compute", {x: 41}).
    x_lit = peer.emit_pathway.content_store.put(Entity(type="compute/literal", data={"value": 41}))
    emit("app/caller", Entity(type="compute/apply", data={
        "path": "app/native", "operation": "compute", "args": {"x": x_lit},
    }))

    result = await peer._dispatch_local_execute(
        f"entity://{peer.peer_id}/system/compute", "eval", {"data": {}},
        _WILDCARD, None, None, resource_targets=["app/caller"],
    )

    assert result.ok, result.error
    assert result.status == 200
    # Entity-native handlers wrap a bare primitive result in the declared
    # output_type (primitive/any); compute/apply returns the wrapper as-is.
    assert result.result["type"] == "primitive/any"
    assert result.result["data"] == 42
