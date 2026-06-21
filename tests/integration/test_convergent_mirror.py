"""convergent_mirror — the CAS-apply convergence properties.

PROPOSAL-CONVERGENT-MIRRORING: the cross-peer mirror amplifies unboundedly
when the mirror PUT is *unconditional* — a stale lap rolls state back, which
is itself a tree change that re-propagates. The fix is CAS on the local PUT:
apply each upstream transition with `expected_hash = notification.previous_hash`
(zero/absent on a created event → V7 §3.9 CAS-create). A stale lap then fails
409 instead of rolling back, terminating amplification.

This exercises the load-bearing property the `convergent_mirror` validate-peer
gate asserts, at the apply level (the cross-impl gate adds drop-injection over
a real ring):
  (i)  bounded amplification — out-of-order/stale laps fail CAS, no rollback;
  (ii) convergence — after a gap (dropped lap), a reconcile against the local
       head brings the mirror to the latest state.
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

ZERO_HASH = b"\x00" * 33
MIRROR_PATH = "mirror/x"


@pytest.fixture
def env():
    cs = ContentStore()
    tree = EntityTree("mirror-peer")
    ep = EmitPathway(cs, tree)
    reg = TreeRegistry(tree, cs)
    return cs, ep, reg


def _ctx(ep, reg) -> HandlerContext:
    permissive = {"grants": [{"handlers": {"include": ["*"]},
                              "resources": {"include": ["*"]},
                              "operations": {"include": ["*"]}}]}
    return HandlerContext(
        local_peer_id="mirror-peer", remote_peer_id="src-peer",
        handler_grant=permissive, caller_capability=permissive,
        emit_pathway=ep, tree_registry=reg, handler_pattern="system/tree",
        resource_targets=[MIRROR_PATH],
    )


async def _apply(ctx, entity: dict | None, expected_hash: bytes) -> int:
    """Apply one upstream transition to the mirror path under CAS.

    `expected_hash` = the notification's previous_hash (ZERO_HASH on create).
    Returns the put status (200 applied, 409 stale-lap-rejected).
    """
    r = await tree_handler(
        "system/tree", "put",
        {"data": {"entity": entity, "expected_hash": expected_hash}}, ctx,
    )
    return r["status"]


def _src_versions(n: int) -> list[Entity]:
    """A linear source lineage v0..v{n-1}."""
    return [Entity(type="mirror/v", data={"seq": i}) for i in range(n)]


def _head(ep) -> bytes | None:
    return ep.entity_tree.get(ep.entity_tree.normalize_uri(MIRROR_PATH))


@pytest.mark.asyncio
async def test_in_order_laps_converge_one_per_write(env):
    """N ordered transitions → N applied, mirror at the latest. (~1 lap/write.)"""
    cs, ep, reg = env
    ctx = _ctx(ep, reg)
    versions = _src_versions(20)

    applied = 0
    prev = ZERO_HASH  # created event bootstraps via CAS-create
    for v in versions:
        status = await _apply(ctx, v.to_dict(), prev)
        assert status == 200
        applied += 1
        prev = v.compute_hash()

    assert applied == 20
    assert _head(ep) == versions[-1].compute_hash()


@pytest.mark.asyncio
async def test_stale_lap_fails_cas_no_rollback(env):
    """A slow stale lap arriving after advance fails CAS — no rollback.

    This is the amplification bug: an UNCONDITIONAL put would rewrite the
    mirror back to the stale state (a real change → fresh propagation). Under
    CAS the stale lap dies at 409 and the mirror stays at the latest.
    """
    cs, ep, reg = env
    ctx = _ctx(ep, reg)
    versions = _src_versions(3)

    # Advance to v2 in order.
    prev = ZERO_HASH
    for v in versions:
        assert await _apply(ctx, v.to_dict(), prev) == 200
        prev = v.compute_hash()
    assert _head(ep) == versions[2].compute_hash()

    # A stale created-lap (seq=0, previous_hash zero) arrives late → CAS-create
    # rejects it because the path is bound.
    assert await _apply(ctx, versions[0].to_dict(), ZERO_HASH) == 409
    # A stale replace-lap (seq=1, previous_hash=hash(v0)) arrives late → the
    # local head is hash(v2) ≠ hash(v0), CAS rejects.
    assert await _apply(ctx, versions[1].to_dict(), versions[0].compute_hash()) == 409

    # No rollback: the mirror is still at the latest.
    assert _head(ep) == versions[2].compute_hash()


@pytest.mark.asyncio
async def test_reconcile_after_drop_converges_to_latest(env):
    """A dropped lap leaves a gap (CAS 409); a reconcile against the local head
    converges to the latest source state (the §5.5 reconcile, local-anchored)."""
    cs, ep, reg = env
    ctx = _ctx(ep, reg)
    versions = _src_versions(4)

    # Apply v0, v1 in order.
    assert await _apply(ctx, versions[0].to_dict(), ZERO_HASH) == 200
    assert await _apply(ctx, versions[1].to_dict(), versions[0].compute_hash()) == 200

    # v2's notification is DROPPED. v3 arrives: its previous_hash = hash(v2),
    # but the local head is hash(v1) → CAS 409 (the gap is detected, not
    # silently mis-applied).
    assert await _apply(ctx, versions[3].to_dict(), versions[2].compute_hash()) == 409
    assert _head(ep) == versions[1].compute_hash()

    # Reconcile (§5.5): fetch current source state (v3) and apply it against
    # the LOCAL head, read locally at the write site — never an anchor carried
    # from the dropped notification.
    local_head = _head(ep)
    assert await _apply(ctx, versions[3].to_dict(), local_head) == 200
    assert _head(ep) == versions[3].compute_hash()
