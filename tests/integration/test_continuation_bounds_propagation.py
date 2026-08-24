"""Cross-peer chain bound — `chain_depth` rides `system/bounds`.

PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION (arch, 2026-07-17), converged with
entity-core-go @ 964c3e7 (`ROUTING-2026-07-17-go-bounds-propagation-response`).

`chain_depth` is the continuation-axis mirror of `cascade_depth`: a
`system/bounds` wire field, inherited across the peer boundary, incremented
only at a *causal* advancement dispatch, and left untouched by TTL/budget
refill. The O1 signal (§5) the cohort MUST converge on is **inherited-bounds
presence** — a causal advancement inherits and +1's the triggering
`bounds.chain_depth`; a standing continuation on a fresh external trigger
arrives with no `chain_depth` and roots at 0. It is NOT a heuristic on trigger
type.

These are the proposal §8 convergence anchors, expressed as vectors:

1. runaway is bounded across the wire (causal depth accumulates + brake fires)
2. retry-forever is NOT bounded (standing continuation roots at 0 each firing)
3. bounds ride the cross-peer EXECUTE (Delta 1 — the remote branch stopped
   dropping bounds)
4. resume roots fresh (§7)
"""

from __future__ import annotations

import pytest

from entity_core.capability.grant import create_full_access_grant
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.protocol.bounds import Bounds
from entity_core.protocol.entity import Entity
from entity_core.protocol.messages import Execute
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.utils.ecf import ecf_encode
from entity_handlers.continuation import (
    BUDGET_EXHAUSTED_REASON,
    CHAIN_DEPTH_EXCEEDED_REASON,
    DEFAULT_MAX_CHAIN_DEPTH,
    TTL_EXHAUSTED_REASON,
    _advance_forward,
    _handle_resume,
    _resource_bound_reason,
)
from entity_core.protocol.bounds import (
    BUDGET_EXHAUSTED_MESSAGE,
    TTL_EXHAUSTED_MESSAGE,
)


def _make_ctx(bounds: Bounds | None):
    """Handler context whose triggering EXECUTE carried ``bounds``.

    ``bounds.chain_depth`` is the inherited causal depth (None = a fresh
    external trigger). Mirrors tests/integration/test_continuation_step6_chain_seed.
    """
    kp = Keypair.generate()
    content_store = ContentStore()
    emit_pathway = EmitPathway(content_store, EntityTree(kp.peer_id))
    cap = Entity(
        type="system/capability/token",
        data={
            "grants": [
                {
                    "handlers": {"include": ["*"]},
                    "resources": {"include": ["*"]},
                    "operations": {"include": ["*"]},
                },
            ],
            "granter": b"\x00" + b"\x00" * 32,
            "grantee": b"\x00" + b"\x01" * 32,
            "created_at": 0,
        },
    )
    cap_hash = content_store.put(cap)
    permissive = create_full_access_grant()

    async def _noop_dispatch(*a, **k) -> ExecuteResult:
        return ExecuteResult(status=200, result={})

    ctx = HandlerContext(
        local_peer_id=kp.peer_id,
        remote_peer_id="remote-peer-id",
        handler_grant=permissive,
        caller_capability=permissive,
        emit_pathway=emit_pathway,
        bounds=bounds,
        chain_id=bounds.chain_id if bounds else None,
        _execute_dispatcher=_noop_dispatch,
    )
    return emit_pathway, ctx, cap_hash


def _cont(cap_hash: bytes) -> dict:
    return {
        "target": "remote/handler",
        "operation": "do",
        "params": {},
        "remaining_executions": 1,
        "dispatch_capability": cap_hash,
    }


async def _advance_capturing_depth(ctx, cap_hash) -> int | None:
    """Run one forward advancement; return the chain_depth the dispatch carried."""
    seen: dict = {}
    orig = HandlerContext.execute_with_capability

    async def _patched(self, *a, **k) -> ExecuteResult:
        seen["chain_depth"] = self.bounds.chain_depth if self.bounds else None
        return ExecuteResult(status=200, result={})

    HandlerContext.execute_with_capability = _patched  # type: ignore[method-assign]
    try:
        await _advance_forward(
            cont_data=_cont(cap_hash),
            result={"data": {}},
            status=200,
            continuation_path="test-cont",
            full_uri="/peer/test-cont",
            content_hash=b"\x00" + b"\x02" * 32,
            ctx=ctx,
        )
    finally:
        HandlerContext.execute_with_capability = orig  # type: ignore[method-assign]
    return seen.get("chain_depth")


class TestO1CausalVsStanding:
    """Delta 3 / §5 — the load-bearing causal-vs-standing signal.

    The signal is inherited-bounds *presence*, not the trigger type.
    """

    @pytest.mark.asyncio
    async def test_fresh_trigger_roots_chain_depth_at_one(self) -> None:
        """No inherited chain_depth ⇒ this dispatch roots at 1."""
        _, ctx, cap_hash = _make_ctx(Bounds(chain_id="c1"))  # no chain_depth
        assert await _advance_capturing_depth(ctx, cap_hash) == 1

    @pytest.mark.asyncio
    async def test_no_bounds_at_all_roots_at_one(self) -> None:
        _, ctx, cap_hash = _make_ctx(None)
        assert await _advance_capturing_depth(ctx, cap_hash) == 1

    @pytest.mark.asyncio
    async def test_causal_advancement_inherits_and_increments(self) -> None:
        """Inherited chain_depth=3 (a causal advancement) ⇒ dispatch carries 4."""
        _, ctx, cap_hash = _make_ctx(Bounds(chain_id="c1", chain_depth=3))
        assert await _advance_capturing_depth(ctx, cap_hash) == 4

    @pytest.mark.asyncio
    async def test_standing_continuation_refires_root_at_one(self) -> None:
        """Anchor 2 (unit): a standing continuation re-firing on fresh triggers
        never accumulates depth — retry-forever stays unbounded on the depth
        axis while chain_id stays stable for correlation."""
        depths = []
        for _ in range(5):
            # Each firing arrives on a fresh external trigger: same chain_id
            # (correlation), no inherited chain_depth (a timer break severs
            # causality).
            _, ctx, cap_hash = _make_ctx(Bounds(chain_id="network-maintain-sess"))
            depths.append(await _advance_capturing_depth(ctx, cap_hash))
        assert depths == [1, 1, 1, 1, 1], (
            "a standing continuation must root at 1 every firing; a climbing "
            "chain_depth would suspend a correctly-retrying peer (§5 regression)."
        )

    @pytest.mark.asyncio
    async def test_inbound_bounds_untouched_by_seeding(self) -> None:
        """The caller's Bounds object is copied, not mutated, at the seed."""
        inbound = Bounds(chain_id="c1", chain_depth=2)
        _, ctx, cap_hash = _make_ctx(inbound)
        await _advance_capturing_depth(ctx, cap_hash)
        assert inbound.chain_depth == 2, "seeding mutated the inbound bounds"


class TestChainDepthCeilingBrake:
    """Delta 4 / §4 — anchor 1: a runaway is bounded (it suspends at the ceiling)."""

    @pytest.mark.asyncio
    async def test_at_ceiling_still_dispatches(self) -> None:
        """Inherited 63 ⇒ this advancement is depth 64 — the ceiling, still runs."""
        _, ctx, cap_hash = _make_ctx(
            Bounds(chain_id="c1", chain_depth=DEFAULT_MAX_CHAIN_DEPTH - 1)
        )
        resp = await _advance_forward(
            cont_data=_cont(cap_hash), result={"data": {}}, status=200,
            continuation_path="test-cont", full_uri="/peer/test-cont",
            content_hash=b"\x00" + b"\x02" * 32, ctx=ctx,
        )
        assert resp["status"] == 200
        assert resp["result"]["data"]["advanced"] is True

    @pytest.mark.asyncio
    async def test_past_ceiling_suspends_with_reason(self) -> None:
        """Inherited 64 ⇒ depth 65 > ceiling — suspend, do not dispatch."""
        emit_pathway, ctx, cap_hash = _make_ctx(
            Bounds(chain_id="chain-run", chain_depth=DEFAULT_MAX_CHAIN_DEPTH)
        )
        resp = await _advance_forward(
            cont_data=_cont(cap_hash), result={"data": {}}, status=200,
            continuation_path="test-cont", full_uri="/peer/test-cont",
            content_hash=b"\x00" + b"\x02" * 32, ctx=ctx,
        )
        assert resp["status"] == 429, "runaway must terminate, not recurse"
        assert resp["result"]["data"]["reason"] == "chain_depth_exceeded"
        # The suspend persisted a resumable entity keyed on the chain id.
        suspended_uri = emit_pathway.entity_tree.normalize_uri(
            "system/continuation/suspended/chain-run"
        )
        h = emit_pathway.entity_tree.get(suspended_uri)
        assert h is not None, "suspend must persist a resumable entity (§3.9)"
        ent = emit_pathway.content_store.get(h)
        assert ent.type == "system/continuation/suspended"
        assert ent.data["reason"] == "chain_depth_exceeded"

    @pytest.mark.asyncio
    async def test_brake_is_confirmed_capable_of_failing(self) -> None:
        """Stub the fix out: without inheritance the same input would NOT brake.

        A fresh-rooted advancement at the same nominal depth roots at 1 and
        dispatches — proving the brake keys on the *inherited* global count, the
        property that makes cross-peer termination real (not a per-peer reset).
        """
        _, ctx, cap_hash = _make_ctx(Bounds(chain_id="c1"))  # no inherited depth
        resp = await _advance_forward(
            cont_data=_cont(cap_hash), result={"data": {}}, status=200,
            continuation_path="test-cont", full_uri="/peer/test-cont",
            content_hash=b"\x00" + b"\x02" * 32, ctx=ctx,
        )
        assert resp["status"] == 200  # rooted at 1, nowhere near the ceiling


async def _advance_with_dispatch(ctx, cap_hash, dispatch_result: ExecuteResult):
    """Run one forward advancement whose dispatch returns ``dispatch_result``."""
    orig = HandlerContext.execute_with_capability

    async def _patched(self, *a, **k) -> ExecuteResult:
        return dispatch_result

    HandlerContext.execute_with_capability = _patched  # type: ignore[method-assign]
    try:
        return await _advance_forward(
            cont_data=_cont(cap_hash), result={"data": {}}, status=200,
            continuation_path="test-cont", full_uri="/peer/test-cont",
            content_hash=b"\x00" + b"\x02" * 32, ctx=ctx,
        )
    finally:
        HandlerContext.execute_with_capability = orig  # type: ignore[method-assign]


def _chain_error_markers(emit_pathway) -> list[dict]:
    """The chain-error-lost marker bodies currently in the tree."""
    tree = emit_pathway.entity_tree
    out = []
    for p in tree.list_prefix("system/runtime/chain-errors"):
        h = tree.get(p)
        if h is not None:
            out.append(emit_pathway.content_store.get(h).data)
    return out


class TestQ1DepthBrakeIsObservable:
    """PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION §4a (arch ruling 2026-07-18):
    the chain_depth brake is INDEPENDENT of TTL and OBSERVABLE.

    Before this cycle the depth suspension persisted a resumable entity but
    bound no chain-error-lost marker, so a cross-impl probe watching the lost
    sink could not confirm the *depth* brake fired. Go binds a `bounds_exceeded`
    marker at its 429 seam; Python now binds one with `{reason}` =
    `chain_depth_exceeded` (matching the suspend's own reason + proposal §8).
    """

    @pytest.mark.asyncio
    async def test_depth_suspend_binds_observable_marker(self) -> None:
        emit_pathway, ctx, cap_hash = _make_ctx(
            Bounds(chain_id="chain-run", chain_depth=DEFAULT_MAX_CHAIN_DEPTH)
        )
        resp = await _advance_forward(
            cont_data=_cont(cap_hash), result={"data": {}}, status=200,
            continuation_path="test-cont", full_uri="/peer/test-cont",
            content_hash=b"\x00" + b"\x02" * 32, ctx=ctx,
        )
        assert resp["status"] == 429
        markers = _chain_error_markers(emit_pathway)
        depth_markers = [
            m for m in markers if m.get("reason") == CHAIN_DEPTH_EXCEEDED_REASON
        ]
        assert len(depth_markers) == 1, (
            "the depth brake MUST leave an observable chain-error-lost marker "
            "(§4a) — a probe reads the lost sink to confirm depth, not TTL, "
            "terminated the chain"
        )
        assert depth_markers[0]["code"] == CHAIN_DEPTH_EXCEEDED_REASON

    @pytest.mark.asyncio
    async def test_no_depth_marker_when_rooted_fresh(self) -> None:
        """Confirm-capable-of-failing: a fresh-rooted advance does not brake, so
        no depth marker is bound — the marker keys on the *inherited* count."""
        emit_pathway, ctx, cap_hash = _make_ctx(Bounds(chain_id="c1"))
        await _advance_forward(
            cont_data=_cont(cap_hash), result={"data": {}}, status=200,
            continuation_path="test-cont", full_uri="/peer/test-cont",
            content_hash=b"\x00" + b"\x02" * 32, ctx=ctx,
        )
        assert not [
            m for m in _chain_error_markers(emit_pathway)
            if m.get("reason") == CHAIN_DEPTH_EXCEEDED_REASON
        ]


class TestQ1LocalBoundHonestlyAttributed:
    """§4a: TTL/budget exhaustion is an ADDITIONAL LOCAL bound — when it is what
    terminated the continuation causal chain, it is attributed honestly (not the
    misleading `protocol_error`), so depth vs. a local bound never collapse."""

    def test_resource_bound_reason_maps_ttl_and_budget(self) -> None:
        assert _resource_bound_reason(
            ExecuteResult(status=400, error=TTL_EXHAUSTED_MESSAGE)
        ) == TTL_EXHAUSTED_REASON
        assert _resource_bound_reason(
            ExecuteResult(status=400, error=BUDGET_EXHAUSTED_MESSAGE)
        ) == BUDGET_EXHAUSTED_REASON
        # A genuine downstream 400 (not a resource brake) is NOT reclassified.
        assert _resource_bound_reason(
            ExecuteResult(status=400, error="something else")
        ) is None
        assert _resource_bound_reason(ExecuteResult(status=200)) is None

    @pytest.mark.asyncio
    async def test_ttl_exhausted_dispatch_binds_honest_marker(self) -> None:
        """A dispatch refused for TTL exhaustion (no on_error) binds a
        `ttl_exhausted` marker — NOT `protocol_error`. Confirm-capable-of-
        failing: before §4a this same input bound `protocol_error` (the
        missing-downstream-code fallback), making a runaway's terminal look
        like a downstream protocol fault rather than the local resource brake."""
        emit_pathway, ctx, cap_hash = _make_ctx(Bounds(chain_id="c1"))
        await _advance_with_dispatch(
            ctx, cap_hash, ExecuteResult(status=400, error=TTL_EXHAUSTED_MESSAGE)
        )
        reasons = {m.get("reason") for m in _chain_error_markers(emit_pathway)}
        assert TTL_EXHAUSTED_REASON in reasons
        assert "protocol_error" not in reasons

    @pytest.mark.asyncio
    async def test_genuine_downstream_400_still_uses_its_code(self) -> None:
        """A DELIVERED non-2xx keeps the §3.4 v1.10 behavior: its own code is
        the marker reason (resource-brake reclassification is narrow)."""
        emit_pathway, ctx, cap_hash = _make_ctx(Bounds(chain_id="c1"))
        await _advance_with_dispatch(
            ctx, cap_hash,
            ExecuteResult(status=400, result={"data": {"code": "bad_request"}}),
        )
        reasons = {m.get("reason") for m in _chain_error_markers(emit_pathway)}
        assert "bad_request" in reasons
        assert TTL_EXHAUSTED_REASON not in reasons


class TestOrdinaryDispatchAddsNoBounds:
    """Delta 1 gate — Go's TestOrdinaryRemoteDispatchAddsNoBounds parity."""

    def test_ordinary_dispatch_carries_no_wire_bounds(self) -> None:
        from entity_core.peer.peer import _wire_bounds_for_dispatch

        # Ordinary dispatch: bounds with ttl/budget/chain_id but NO chain_depth.
        ordinary = Bounds(ttl=64, budget=100000, chain_id="c1")
        assert _wire_bounds_for_dispatch(ordinary) is None
        assert _wire_bounds_for_dispatch(None) is None

    def test_continuation_advancement_carries_wire_bounds(self) -> None:
        from entity_core.peer.peer import _wire_bounds_for_dispatch

        # A continuation advancement: chain_depth present ⇒ bounds ride the wire.
        chain = Bounds(ttl=63, budget=100000, chain_id="c1", chain_depth=1)
        assert _wire_bounds_for_dispatch(chain) is chain


class TestResumeRootsChainDepth:
    """Delta 5 / §7 — anchor 4: resume roots chain_depth at 0, does not re-suspend."""

    @pytest.mark.asyncio
    async def test_resume_clears_inherited_chain_depth(self) -> None:
        from entity_core.storage.emit import EmitContext

        emit_pathway, ctx, _ = _make_ctx(
            Bounds(chain_id="chain-run", chain_depth=DEFAULT_MAX_CHAIN_DEPTH)
        )
        # A suspended continuation (as the ceiling brake would have persisted).
        suspended = Entity(
            type="system/continuation/suspended",
            data={
                "target": "remote/handler",
                "operation": "do",
                "params": {},
                "reason": "chain_depth_exceeded",
                "chain_id": "chain-run",
                "suspended_at": 1,
            },
        )
        suspended_path = "system/continuation/suspended/chain-run"
        uri = emit_pathway.entity_tree.normalize_uri(suspended_path)
        emit_pathway.emit(uri, suspended, EmitContext.from_handler_grant(ctx, "install"))

        ctx.resource_targets = [suspended_path]
        resp = await _handle_resume({}, ctx)

        assert resp["status"] == 200
        assert resp["result"]["data"]["resumed"] is True
        # §7: the resume dispatch rooted fresh — a resumed chain that kept the
        # suspending depth would immediately re-suspend.
        assert ctx.bounds.chain_depth is None


class TestChainDepthWireField:
    """Delta 2 — `chain_depth` is a `system/bounds` field beside `cascade_depth`."""

    def test_chain_depth_round_trips_through_bounds_dict(self) -> None:
        b = Bounds(chain_id="c1", chain_depth=3, cascade_depth=1)
        restored = Bounds.from_dict(b.to_dict())
        assert restored.chain_depth == 3
        assert restored.cascade_depth == 1
        assert restored.chain_id == "c1"

    def test_chain_depth_absent_stays_absent_not_zero(self) -> None:
        """Absence is load-bearing: absent chain_depth = a fresh root, not 0-carried.

        `to_dict` omits it (omitempty parity with cascade_depth) so the wire
        distinguishes a genuinely-chainless trigger from an explicit depth 0.
        """
        b = Bounds(chain_id="c1")
        assert "chain_depth" not in b.to_dict()
        assert Bounds.from_dict(b.to_dict()).chain_depth is None

    def test_chain_depth_zero_is_preserved(self) -> None:
        b = Bounds(chain_depth=0)
        assert b.to_dict()["chain_depth"] == 0
        assert Bounds.from_dict(b.to_dict()).chain_depth == 0

    def test_chain_depth_survives_execute_det_cbor_round_trip(self) -> None:
        """Anchor 1 (wire half): chain_depth survives det-CBOR on the EXECUTE."""
        exec_ = Execute.create(
            uri="entity://peer-b/remote/handler",
            operation="do",
            params={"x": 1},
            bounds=Bounds(chain_id="c1", chain_depth=7, ttl=64, budget=100000),
        )
        wire = exec_.to_entity()
        assert wire["data"]["bounds"]["chain_depth"] == 7

        # Deterministic CBOR is stable, and the field survives a decode.
        encoded = ecf_encode(wire["data"]["bounds"])
        assert encoded == ecf_encode(wire["data"]["bounds"])
        restored = Execute.from_entity(wire)
        assert restored.bounds is not None
        assert restored.bounds.chain_depth == 7

    def test_copy_preserves_chain_depth(self) -> None:
        assert Bounds(chain_depth=5).copy().chain_depth == 5
