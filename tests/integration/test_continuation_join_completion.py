"""PROPOSAL-CONTINUATION-STANDING-MODEL §4/§4.1 — join completion policy.

Before this, `_advance_join` had no completion_deadline_ms/on_incomplete/
round_id at all: a standing join (`remaining_executions: null`) missing one
slot wedged forever, and — since only the finite-remaining branch ever reset
`received` — a standing join could never even reopen after firing once.

- Mechanism 2 (§4): a deadline-carrying join self-heals — a wedged round is
  abandoned (`join_abandoned` lost marker, `received` reset) the moment a
  later advance next touches the join (lazy reap-on-touch; this peer has no
  background sweep subsystem, so the wire-observable outcome is what's
  pinned, not the reaping mechanism).
- Mechanism 1 (§4): a delivered non-2xx slot is preserved as-is and binds a
  `join_error_slot` marker; the join still fires normally (the target/stitch
  decides whether to reject on it).
- §4.1: a deadline-carrying join carries a monotonic `round_id`; a
  round-tagged slot advance targeting a stale round is dropped loudly
  (`join_late` marker, 200 `{advanced: false, dropped: "stale_round", ...}`)
  and MUST NOT land in the new round — the straggler-bleed anchor (§6.5).
- Additive: a join without `completion_deadline_ms` never gets a `round_id`
  at all — byte-identical to a pre-§4 join.
"""

import time

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext, ExecuteResult
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitPathway, EmitContext
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree

from entity_handlers.continuation import (
    continuation_handler,
    CONTINUATION_JOIN_TYPE,
    _note_join_path,
)


@pytest.fixture
def setup_context() -> tuple[EmitPathway, HandlerContext, Keypair]:
    keypair = Keypair.generate()
    content_store = ContentStore()
    entity_tree = EntityTree(keypair.peer_id)
    emit_pathway = EmitPathway(content_store, entity_tree)

    dispatched_calls: list[dict] = []

    async def mock_execute(uri, operation, params, capability, bounds,
                            chain_id, resource_targets=None, **_kwargs) -> ExecuteResult:
        dispatched_calls.append({"uri": uri, "operation": operation, "params": params})
        return ExecuteResult(status=200, result={"dispatched": True})

    dispatch_cap = Entity(
        type="system/capability/token",
        data={"grants": [{"handlers": {"include": ["*"]},
                          "resources": {"include": ["*"]},
                          "operations": {"include": ["*"]}}]},
    )
    dispatch_cap_hash = content_store.put(dispatch_cap)

    ctx = HandlerContext(
        local_peer_id=keypair.peer_id,
        remote_peer_id="remote-peer-id",
        handler_grant={},
        caller_capability={},
        emit_pathway=emit_pathway,
        _execute_dispatcher=mock_execute,
    )
    ctx._dispatched_calls = dispatched_calls
    ctx._dispatch_cap_hash = dispatch_cap_hash
    return emit_pathway, ctx, keypair


def _put_install_cap(content_store, *, granter: bytes) -> bytes:
    data = {"granter": granter, "grantee": granter, "grants": []}
    return content_store.put(Entity(type="system/capability/token", data=data))


def _put_join(emit_pathway, keypair, path, **data) -> str:
    full_uri = emit_pathway.entity_tree.normalize_uri(path)
    continuation = Entity(type=CONTINUATION_JOIN_TYPE, data=data)
    emit_pathway.emit(full_uri, continuation, EmitContext.protocol(author=keypair.peer_id))
    return full_uri


def _read_join(emit_pathway, full_uri) -> dict:
    content_hash = emit_pathway.entity_tree.get(full_uri)
    return emit_pathway.content_store.get(content_hash).data


def _lost_markers(emit_pathway, code: str) -> list[dict]:
    prefix = emit_pathway.entity_tree.normalize_uri("system/runtime/chain-errors/lost/")
    matches = emit_pathway.entity_tree.list_prefix(prefix)
    out = []
    for path in matches:
        if f"/{code}/" not in path:
            continue
        marker_hash = emit_pathway.entity_tree.get(path)
        out.append(emit_pathway.content_store.get(marker_hash).data)
    return out


class TestInstallRoundIdAdditive:
    """§4.1 R1/R2 — round_id only exists for a deadline-carrying join."""

    @pytest.mark.asyncio
    async def test_join_without_deadline_never_gets_round_id(self, setup_context):
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, keypair = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = _put_install_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        install_path = "system/continuation/suspended/join-no-deadline"
        ctx.resource_targets = [install_path]

        params = {
            "type": CONTINUATION_JOIN_TYPE,
            "data": {
                "expected": ["slot-a", "slot-b"],
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": cap_hash,
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 200, response

        full_uri = emit_pathway.entity_tree.normalize_uri(install_path)
        data = _read_join(emit_pathway, full_uri)
        assert "round_id" not in data
        assert "round_started_at_ms" not in data

    @pytest.mark.asyncio
    async def test_join_with_deadline_installs_round_zero(self, setup_context):
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, keypair = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = _put_install_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        install_path = "system/continuation/suspended/join-deadline"
        ctx.resource_targets = [install_path]

        params = {
            "type": CONTINUATION_JOIN_TYPE,
            "data": {
                "expected": ["slot-a", "slot-b"],
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": cap_hash,
                "completion_deadline_ms": 5000,
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 200, response

        full_uri = emit_pathway.entity_tree.normalize_uri(install_path)
        data = _read_join(emit_pathway, full_uri)
        assert data["round_id"] == 0
        assert isinstance(data["round_started_at_ms"], int)

    @pytest.mark.asyncio
    async def test_install_rejects_unrecognized_on_incomplete(self, setup_context):
        """FP install gate: fail-closed on an unrecognized value — never
        silently defaulted to abandon at the deadline. Shares Go/rust's
        `invalid_continuation` code (cross-impl convergence, not a Python-
        invented spelling)."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, keypair = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = _put_install_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/join-bad-on-incomplete"]

        params = {
            "type": CONTINUATION_JOIN_TYPE,
            "data": {
                "expected": ["slot-a"],
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": cap_hash,
                "completion_deadline_ms": 5000,
                "on_incomplete": "retry_forever",
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 400
        assert response["result"]["data"]["code"] == "invalid_continuation"

    @pytest.mark.asyncio
    async def test_install_rejects_on_incomplete_without_deadline(self, setup_context):
        """A policy with no deadline can never fire — the round never ends."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, keypair = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = _put_install_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/join-inert-policy"]

        params = {
            "type": CONTINUATION_JOIN_TYPE,
            "data": {
                "expected": ["slot-a"],
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": cap_hash,
                "on_incomplete": "fire-partial",
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 400
        assert response["result"]["data"]["code"] == "invalid_continuation"

    @pytest.mark.asyncio
    async def test_install_accepts_fire_partial_with_deadline(self, setup_context):
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, keypair = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = _put_install_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        install_path = "system/continuation/suspended/join-fire-partial"
        ctx.resource_targets = [install_path]

        params = {
            "type": CONTINUATION_JOIN_TYPE,
            "data": {
                "expected": ["slot-a"],
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": cap_hash,
                "completion_deadline_ms": 5000,
                "on_incomplete": "fire-partial",
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 200, response

        full_uri = emit_pathway.entity_tree.normalize_uri(install_path)
        data = _read_join(emit_pathway, full_uri)
        assert data["on_incomplete"] == "fire-partial"
        assert data["round_id"] == 0

    @pytest.mark.asyncio
    async def test_install_rejects_non_positive_deadline(self, setup_context):
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, keypair = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = _put_install_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/join-bad-deadline"]

        params = {
            "type": CONTINUATION_JOIN_TYPE,
            "data": {
                "expected": ["slot-a"],
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": cap_hash,
                "completion_deadline_ms": 0,
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 400
        assert response["result"]["data"]["code"] == "invalid_completion_deadline_ms"


class TestStandingJoinSelfHeals:
    """§4 mechanism 2 — a wedged deadline-carrying round abandons and the
    join reopens, rather than wedging forever (the direct standing-model
    analogue of §3's "owns its liveness independent of any trigger")."""

    @pytest.mark.asyncio
    async def test_wedged_round_abandons_and_reopens_on_next_touch(self, setup_context):
        emit_pathway, ctx, keypair = setup_context
        path = "system/inbox/join-selfheal"
        full_uri = _put_join(
            emit_pathway, keypair, path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a0"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
            completion_deadline_ms=100,
            round_id=0,
            round_started_at_ms=0,  # epoch — already expired, no sleep needed
        )

        # A fresh round-1 slot-a arrival touches the join: round 0 abandons
        # (slot-b missing) and this arrival opens + fills round 1.
        response = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-a",
                "round_id": 1, "result": {"value": "a1"},
            }}, ctx,
        )
        assert response["status"] == 200
        assert response["result"]["data"]["advanced"] is False
        assert response["result"]["data"]["accumulated"] is True

        data = _read_join(emit_pathway, full_uri)
        assert data["round_id"] == 1
        assert data["received"] == {"slot-a": {"value": "a1"}}

        markers = _lost_markers(emit_pathway, "join_abandoned")
        assert markers, "join_abandoned marker not bound"
        assert markers[0]["missing_slots"] == ["slot-b"]
        assert markers[0]["abandoned_round"] == 0

        # Round 1 then fires clean.
        response2 = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-b",
                "round_id": 1, "result": {"value": "b1"},
            }}, ctx,
        )
        assert response2["result"]["data"]["advanced"] is True
        assert response2["result"]["data"]["join_complete"] is True
        assert ctx._dispatched_calls[-1]["params"] == {
            "slot-a": {"value": "a1"}, "slot-b": {"value": "b1"},
        }

    @pytest.mark.asyncio
    async def test_standing_join_reopens_after_firing(self, setup_context):
        """The pre-existing bug this also fixes: a standing join
        (remaining_executions=None) never reset `received` after firing —
        only the finite-remaining branch did — so it could fire exactly
        once and then wedge every round after. Round turnover must not
        require completion_deadline_ms to happen at all."""
        emit_pathway, ctx, keypair = setup_context
        path = "system/inbox/join-standing-reopen"
        full_uri = _put_join(
            emit_pathway, keypair, path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
        )

        first = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-b",
                "result": {"value": "b"},
            }}, ctx,
        )
        assert first["result"]["data"]["join_complete"] is True

        data = _read_join(emit_pathway, full_uri)
        assert data["received"] == {}, "standing join must reopen after firing"

        second = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-a",
                "result": {"value": "a2"},
            }}, ctx,
        )
        assert second["result"]["data"]["accumulated"] is True


class TestRoundIdStragglerGuard:
    """§4.1 anchor 5 — the straggler bleed from an abandoned round must be
    caught, not silently mixed into the next round."""

    async def _open_round_one_with_slot_a(self, emit_pathway, ctx, keypair, path):
        full_uri = _put_join(
            emit_pathway, keypair, path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a0"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
            completion_deadline_ms=100,
            round_id=0,
            round_started_at_ms=0,
        )
        await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-a",
                "round_id": 1, "result": {"value": "a1"},
            }}, ctx,
        )
        return full_uri

    @pytest.mark.asyncio
    async def test_straggler_of_abandoned_round_is_dropped_not_admitted(self, setup_context):
        emit_pathway, ctx, keypair = setup_context
        path = "system/inbox/join-straggler"
        full_uri = await self._open_round_one_with_slot_a(emit_pathway, ctx, keypair, path)

        # slot-b OF ROUND 0 arrives late.
        stale = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-b",
                "round_id": 0, "result": {"value": "b0-late"},
            }}, ctx,
        )
        assert stale["status"] == 200
        assert stale["result"]["data"]["advanced"] is False
        assert stale["result"]["data"]["dropped"] == "stale_round"
        assert stale["result"]["data"]["slot"] == "slot-b"  # O4
        assert stale["result"]["data"]["targeted_round"] == 0
        assert stale["result"]["data"]["current_round"] == 1

        data = _read_join(emit_pathway, full_uri)
        assert "slot-b" not in data["received"], (
            "the round-0 straggler MUST NOT fill round 1's slot-b"
        )

        markers = _lost_markers(emit_pathway, "join_late")
        assert markers, "join_late marker not bound"
        assert markers[0]["targeted_round"] == 0
        assert markers[0]["current_round"] == 1
        assert markers[0]["slot"] == "slot-b"

        # Round 1 then fires clean from a single generation.
        clean = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-b",
                "round_id": 1, "result": {"value": "b1"},
            }}, ctx,
        )
        assert clean["result"]["data"]["advanced"] is True
        assert clean["result"]["data"]["join_complete"] is True
        assert ctx._dispatched_calls[-1]["params"] == {
            "slot-a": {"value": "a1"}, "slot-b": {"value": "b1"},
        }

    @pytest.mark.asyncio
    async def test_untagged_advance_still_admitted(self, setup_context):
        """Additive / no-silent-change: an advance that doesn't tag
        round_id at all is admitted as before, even into a deadline-carrying
        join."""
        emit_pathway, ctx, keypair = setup_context
        path = "system/inbox/join-untagged"
        full_uri = _put_join(
            emit_pathway, keypair, path,
            expected=["slot-a", "slot-b"],
            received={},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
            completion_deadline_ms=100_000,
            round_id=0,
            round_started_at_ms=0,
        )
        # Deadline hasn't actually elapsed relative to round_started_at_ms
        # being "old" here on purpose — pick a deadline far larger than any
        # wall-clock time this test could take, so no reap fires.
        response = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-a",
                "result": {"value": "untagged"},
            }}, ctx,
        )
        assert response["result"]["data"]["accumulated"] is True
        data = _read_join(emit_pathway, full_uri)
        assert data["received"] == {"slot-a": {"value": "untagged"}}


class TestErrorSlotPreserved:
    """§4 mechanism 1 — a delivered non-2xx slot is preserved as-is (not
    coerced) and observably marked; the join still fires normally."""

    @pytest.mark.asyncio
    async def test_error_slot_preserved_and_marked_join_still_fires(self, setup_context):
        emit_pathway, ctx, keypair = setup_context
        path = "system/inbox/join-error-slot"
        _put_join(
            emit_pathway, keypair, path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
        )

        response = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-b",
                "status": 500, "result": {"error": "boom"},
            }}, ctx,
        )
        assert response["result"]["data"]["advanced"] is True
        assert response["result"]["data"]["join_complete"] is True
        assert ctx._dispatched_calls[-1]["params"]["slot-b"] == {"error": "boom"}

        markers = _lost_markers(emit_pathway, "join_error_slot")
        assert markers, "join_error_slot marker not bound"
        assert markers[0]["slot"] == "slot-b"
        assert markers[0]["status"] == 500


class TestOrdinaryCompletionDeletesExhaustedFiniteJoin:
    """Pre-existing asymmetry flagged in HANDOFF-2026-07-28-standing-model-
    s4-residuals-o4-fp-o5-python.md, ruled by arch: the *ordinary*
    (non-deadline, non-fire-partial) all-slots-filled completion path must
    delete a finite join at ``remaining_executions`` exhaustion exactly like
    ``_age_join_after_fire`` already does — mirrors Go's
    ``advanceJoinLifecycle`` / rust's ``finish_join_round``. Before this fix
    the ordinary path only ever decremented, leaving `remaining_executions:
    0` behind for the next touch to 410 on instead of deleting outright."""

    @pytest.mark.asyncio
    async def test_ordinary_completion_deletes_finite_join_at_exhaustion(
        self, setup_context,
    ):
        emit_pathway, ctx, keypair = setup_context
        path = "system/inbox/join-ordinary-exhaustion"
        full_uri = _put_join(
            emit_pathway, keypair, path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=1,
        )

        response = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-b",
                "result": {"value": "b"},
            }}, ctx,
        )
        assert response["status"] == 200
        assert response["result"]["data"]["advanced"] is True
        assert response["result"]["data"]["join_complete"] is True
        assert ctx._dispatched_calls[-1]["params"] == {
            "slot-a": {"value": "a"}, "slot-b": {"value": "b"},
        }

        assert emit_pathway.entity_tree.get(full_uri) is None, (
            "finite join must be deleted at remaining_executions exhaustion, "
            "not left behind with remaining_executions: 0"
        )

    @pytest.mark.asyncio
    async def test_ordinary_completion_persists_non_exhausted_finite_join(
        self, setup_context,
    ):
        """Sibling of the exhaustion case: a finite join with executions
        left after firing decrements and survives, unaffected by the
        exhaustion-delete fix."""
        emit_pathway, ctx, keypair = setup_context
        path = "system/inbox/join-ordinary-not-exhausted"
        full_uri = _put_join(
            emit_pathway, keypair, path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=2,
        )

        response = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-b",
                "result": {"value": "b"},
            }}, ctx,
        )
        assert response["result"]["data"]["join_complete"] is True

        data = _read_join(emit_pathway, full_uri)
        assert data["remaining_executions"] == 1
        assert data["received"] == {}


class TestFirePartial:
    """FP (STANDING-MODEL §4 mechanism 2, opt-in, HANDOFF-2026-07-28) — a
    deadline-carrying join installed with ``on_incomplete: fire-partial``
    dispatches a SHORT round instead of abandoning it: the partial
    ``received`` plus an explicit ``incomplete: {missing, expected}`` marker
    riding IN the same payload (mirrors Go's firePartialRound / rust's
    fire_partial_round)."""

    @pytest.mark.asyncio
    async def test_wedged_standing_join_fires_partial_and_reopens(self, setup_context):
        emit_pathway, ctx, keypair = setup_context
        path = "system/inbox/join-fire-partial-standing"
        full_uri = _put_join(
            emit_pathway, keypair, path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a0"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
            completion_deadline_ms=100,
            on_incomplete="fire-partial",
            round_id=0,
            round_started_at_ms=0,  # epoch — already expired, no sleep needed
        )

        response = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-a",
                "round_id": 1, "result": {"value": "a1"},
            }}, ctx,
        )
        assert response["status"] == 200
        assert response["result"]["data"]["accumulated"] is True

        # The fire-partial dispatch happened as part of the reap, BEFORE
        # this call's own round-1 slot-a accumulation.
        assert len(ctx._dispatched_calls) == 1
        fired = ctx._dispatched_calls[0]
        assert fired["uri"] == "system/tree"
        assert fired["operation"] == "put"
        assert fired["params"]["slot-a"] == {"value": "a0"}
        assert "slot-b" not in fired["params"]
        assert fired["params"]["incomplete"] == {
            "missing": ["slot-b"], "expected": ["slot-a", "slot-b"],
        }

        data = _read_join(emit_pathway, full_uri)
        assert data["round_id"] == 1
        assert data["received"] == {"slot-a": {"value": "a1"}}

        # No join_abandoned marker — fire-partial is a distinct outcome,
        # observable via the dispatched `incomplete` field, not a lost marker.
        assert not _lost_markers(emit_pathway, "join_abandoned")

    @pytest.mark.asyncio
    async def test_complete_round_stays_byte_identical_with_fire_partial_installed(
        self, setup_context,
    ):
        """A join that HAS on_incomplete: fire-partial installed but whose
        round completes cleanly (no expiry) fires exactly like any other
        complete round — no `incomplete` field, success path untouched."""
        emit_pathway, ctx, keypair = setup_context
        path = "system/inbox/join-fire-partial-clean"
        _put_join(
            emit_pathway, keypair, path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
            completion_deadline_ms=100_000,  # far in the future — no expiry
            on_incomplete="fire-partial",
            round_id=0,
            round_started_at_ms=int(time.time() * 1000),
        )

        response = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-b",
                "result": {"value": "b"},
            }}, ctx,
        )
        assert response["result"]["data"]["advanced"] is True
        assert response["result"]["data"]["join_complete"] is True
        assert ctx._dispatched_calls[-1]["params"] == {
            "slot-a": {"value": "a"}, "slot-b": {"value": "b"},
        }
        assert "incomplete" not in ctx._dispatched_calls[-1]["params"]

    @pytest.mark.asyncio
    async def test_fire_partial_exhausts_finite_join_and_deletes_it(self, setup_context):
        emit_pathway, ctx, keypair = setup_context
        path = "system/inbox/join-fire-partial-finite"
        full_uri = _put_join(
            emit_pathway, keypair, path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a0"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=1,
            completion_deadline_ms=100,
            on_incomplete="fire-partial",
            round_id=0,
            round_started_at_ms=0,
        )

        # slot-b's own arrival is what triggers the reap-on-touch check; the
        # fire-partial fires and deletes the join (remaining_executions=1)
        # before slot-b's own value could ever be accumulated into it.
        response = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": path, "slot": "slot-b",
                "round_id": 1, "result": {"value": "b1"},
            }}, ctx,
        )
        assert response["status"] == 200
        assert response["result"]["data"]["advanced"] is False
        assert response["result"]["data"]["reason"] == "no_continuation"

        assert len(ctx._dispatched_calls) == 1
        assert ctx._dispatched_calls[0]["params"]["incomplete"]["missing"] == ["slot-b"]

        assert emit_pathway.entity_tree.get(full_uri) is None


class TestSweepAll:
    """O5 (STANDING-MODEL §4, RULED 2026-07-28, HANDOFF-2026-07-28) — the
    sweep-all extension: a wedged join is reaped off ANY advance traffic on
    the peer, not only its own. Without this, a standing join that goes
    silent while the peer stays continuation-active would never self-heal
    at all — a permanent cross-peer divergence on the `join_incomplete`/
    `join_abandoned` liveness signal vs. Go, which already sweeps."""

    @pytest.mark.asyncio
    async def test_sweep_reaps_an_untouched_expired_join_on_other_advance(self, setup_context):
        emit_pathway, ctx, keypair = setup_context
        wedged_path = "system/inbox/join-sweep-untouched"
        wedged_uri = _put_join(
            emit_pathway, keypair, wedged_path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a0"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
            completion_deadline_ms=100,
            round_id=0,
            round_started_at_ms=0,  # already expired
        )
        # This test builds the join directly via _put_join rather than
        # through install — register it as sweepable the way install would.
        _note_join_path(ctx, wedged_path, 100)

        other_path = "system/inbox/join-sweep-other"
        _put_join(
            emit_pathway, keypair, other_path,
            expected=["x", "y"],
            received={},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
        )

        # Advance a COMPLETELY DIFFERENT, non-deadline-carrying join. The
        # wedged join above is never touched directly by this call.
        response = await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": other_path, "slot": "x",
                "result": {"value": "x0"},
            }}, ctx,
        )
        assert response["status"] == 200
        assert response["result"]["data"]["accumulated"] is True

        # The untouched wedged join was swept and abandoned anyway.
        data = _read_join(emit_pathway, wedged_uri)
        assert data["round_id"] == 1
        assert data["received"] == {}

        markers = _lost_markers(emit_pathway, "join_abandoned")
        assert markers, "sweep-all must reap an untouched expired join"
        assert markers[0]["missing_slots"] == ["slot-b"]

    @pytest.mark.asyncio
    async def test_sweep_is_throttled_within_the_floor(self, setup_context):
        """A second advance within the throttle floor does not re-sweep —
        cost stays amortized off the dispatch path (mirrors Go's
        joinSweepThrottle 1-minute floor)."""
        emit_pathway, ctx, keypair = setup_context
        wedged_path = "system/inbox/join-sweep-throttled"
        _put_join(
            emit_pathway, keypair, wedged_path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a0"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
            completion_deadline_ms=100,
            round_id=0,
            round_started_at_ms=0,
        )
        _note_join_path(ctx, wedged_path, 100)

        other_path = "system/inbox/join-sweep-throttled-other"
        _put_join(
            emit_pathway, keypair, other_path,
            expected=["x"], received={},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
        )

        # First advance sweeps (throttle window opens here).
        await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": other_path, "slot": "x",
                "result": {"value": "x0"},
            }}, ctx,
        )
        assert _lost_markers(emit_pathway, "join_abandoned"), "first sweep should reap"

        # Reset the wedged join back to a fresh-but-still-expired round,
        # bypassing the sweep (direct write, not an advance).
        wedged_full_uri = emit_pathway.entity_tree.normalize_uri(wedged_path)
        _put_join(
            emit_pathway, keypair, wedged_path,
            expected=["slot-a", "slot-b"],
            received={"slot-a": {"value": "a1"}},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
            completion_deadline_ms=100,
            round_id=1,
            round_started_at_ms=0,
        )

        # A second advance to yet another path, immediately after — still
        # inside the throttle floor, so this sweep pass is skipped and the
        # freshly-rewedged join is NOT reaped again.
        other_path2 = "system/inbox/join-sweep-throttled-other-2"
        _put_join(
            emit_pathway, keypair, other_path2,
            expected=["x"], received={},
            target="system/tree", operation="put",
            dispatch_capability=ctx._dispatch_cap_hash,
            remaining_executions=None,
        )
        await continuation_handler(
            "system/continuation", "advance", {"data": {
                "continuation_path": other_path2, "slot": "x",
                "result": {"value": "x0"},
            }}, ctx,
        )

        data = _read_join(emit_pathway, wedged_full_uri)
        assert data["round_id"] == 1, "throttled — second sweep pass must be a no-op"
        assert data["received"] == {"slot-a": {"value": "a1"}}
