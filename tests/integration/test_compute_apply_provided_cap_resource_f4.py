"""F4 / §2.1 — where compute's dual-check is actually enforced, and that it is.

Written as a suspected defect and kept as its refutation. The audit that
followed the in-process dispatch fix (`docs/status/AUDIT-2026-08-18-…`) flagged
`compute.py` as the most likely confused-deputy site: it forwards
caller-supplied resource targets into a sub-dispatch, and
`_make_sync_dispatch` says in as many words that it is relying on the check
that had been missing::

    # F4 — the dispatched EXECUTE carries the resolved resource targets
    # from compute/apply.resource. Without this, the dispatch-chain side
    # of the AND has no resource and the resource-scope check is skipped.

**The suspicion was wrong, and the mutation is what said so.** With the
dispatcher check mutated out, both rows below are unchanged: `compute/apply`'s
F2 block calls `check_resource_scope` **twice** before dispatching — once
against `ctx.capability` (the ambient ceiling) and once against the *provided*
capability — so §2.1's *"can only ever narrow"* is enforced in-handler and never
depended on the dispatch layer. F4's comment is about the dispatched EXECUTE
also carrying the resource downstream, not about the primary narrowing.

So these two rows pin the enforcement point rather than a fix: they are the
first tests here to drive a provided capability whose resources are **narrower
than the target**, which is the case that distinguishes "the narrowing was
applied" from "the narrowing was recorded and ignored". Q23's ruling turns on
exactly that distinction — a caller supplying a capability *"is asking for less
than ambient authority, and silently dropping that request runs the operation
wider than asked."*
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

#: The ambient ceiling — deliberately wide, so the F2 half of the AND passes and
#: whatever the assertions see is attributable to the *provided* capability.
_CEILING = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": ["*"]},
    }],
    "allowances": {"content_store_access": True},
}

TARGET = "app/data/secret"


def _peer():
    return (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_all_handlers()
        .with_entity_native_handler(
            "app/native",
            "app/native/expr",
            {"compute": {"input_type": "primitive/any", "output_type": "primitive/any"}},
        )
        .build()
    )


def _build(peer, provided_resources: list[str]):
    """An apply carrying `capability` + `resource`, with the cap scoped as given."""
    ctx = EmitContext.bootstrap()

    def emit(path: str, ent: Entity) -> bytes:
        peer.emit_pathway.emit(path, ent, ctx)
        return peer.emit_pathway.entity_tree.get(path)

    # Entity-native body: params.x + 1.
    p_lookup = emit("app/native/p-lookup",
                    Entity(type="compute/lookup/scope", data={"name": "params"}))
    field_x = emit("app/native/field-x",
                   Entity(type="compute/field", data={"name": "x", "entity": p_lookup}))
    one = emit("app/native/one", Entity(type="compute/literal", data={"value": 1}))
    emit("app/native/expr",
         Entity(type="compute/arithmetic", data={"op": "add", "left": field_x, "right": one}))

    store = peer.emit_pathway.content_store
    x_lit = store.put(Entity(type="compute/literal", data={"value": 41}))

    cap_hash = store.put(Entity(type="system/capability/token", data={
        "grants": [{
            "handlers": {"include": ["*"]},
            "operations": {"include": ["*"]},
            "resources": {"include": provided_resources},
        }],
    }))
    res_hash = store.put(Entity(
        type="system/protocol/resource-target", data={"targets": [TARGET]},
    ))

    emit("app/caller", Entity(type="compute/apply", data={
        "path": "app/native",
        "operation": "compute",
        "args": {"x": x_lit},
        "capability": cap_hash,
        "resource": res_hash,
    }))


async def _eval(peer):
    return await peer._dispatch_local_execute(
        f"entity://{peer.peer_id}/system/compute", "eval", {"data": {}},
        _CEILING, None, None, resource_targets=["app/caller"],
    )


@pytest.mark.asyncio
async def test_a_provided_capability_covering_the_target_still_runs():
    """The control. Without it, the refusal below would also hold for an apply
    that never reached the dispatch at all — and the whole point of this pair is
    that the *provided* cap is what decides."""
    peer = _peer()
    _build(peer, [TARGET])
    result = await _eval(peer)

    assert result.status == 200, (
        f"the control failed — an apply whose provided capability covers "
        f"{TARGET!r} did not run ({result.status}: {result.error})"
    )
    assert result.result["data"] == 42


@pytest.mark.asyncio
async def test_a_provided_capability_that_does_not_cover_the_target_is_refused():
    """The narrowing the caller asked for is applied, not merely recorded."""
    peer = _peer()
    _build(peer, ["app/data/public/*"])
    result = await _eval(peer)

    assert result.status != 200 or result.result.get("data") != 42, (
        f"an apply ran under a provided capability scoped to "
        f"['app/data/public/*'] while naming resource target {TARGET!r} — §2.1's "
        f"dual-check can only ever narrow, so the provided capability's resource "
        f"scope has to bind the dispatched EXECUTE. Running anyway means the "
        f"effective authority was the ambient ceiling's, i.e. wider than the "
        f"caller asked for, which is the direction Q23 calls the dangerous one"
    )
