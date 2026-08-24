"""PROPOSAL-CONTINUATION-LOST-ERROR-MARKER-MUST §4 vector 1 — the F2 vector.

Python's answer to the proposal's open feasibility check (option (ii),
adopted): a chain whose ``dispatch_capability`` does NOT cover
``system/runtime/chain-errors/**`` suffers an ``on_error`` dispatch
failure — the lost marker MUST land anyway, bound at the observing peer's
own tree under the CONTINUATION HANDLER'S OWN authority (never the
chain's propagated cap), keyed by the original request ID (F1
ratification), with the W6 attribution split recorded. This is what makes
MUST-bind unconditionally satisfiable: the backstop cannot be broken by
the very misconfiguration it exists to observe.

Mechanism under test (Python's analog of Go's ``selectCapability``
fallback): ``_bind_chain_error_marker`` builds its emit context with
``EmitContext.from_handler_grant`` — ``capability`` is the handler's own
grant hash, ``caller_capability`` records the (denied) caller cap
alongside it. Go reference shape:
``entity-core-go ext/continuation/f2_bind_under_denial_test.go``.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import ChangeEvent, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.continuation import _advance_forward


class _CaptureHook:
    """Sync-hook capture of marker binds (Go's named sync hook analog)."""

    def __init__(self) -> None:
        self.events: list[ChangeEvent] = []

    def on_change_sync(self, event: ChangeEvent) -> int | None:
        self.events.append(event)
        return None


def _cap_entity(content_store: ContentStore, grants: list[dict]) -> tuple[Entity, bytes]:
    """A real (decodable) system/capability/token entity, put in the store."""
    cap = Entity(
        type="system/capability/token",
        data={
            "grants": grants,
            "granter": b"\x00" + b"\x00" * 32,
            "grantee": b"\x00" + b"\x01" * 32,
            "created_at": 0,
        },
    )
    return cap, content_store.put(cap)


@pytest.mark.asyncio
async def test_f2_bind_under_denial_marker_rides_handler_authority() -> None:
    kp = Keypair.generate()
    content_store = ContentStore()
    entity_tree = EntityTree(kp.peer_id)
    emit_pathway = EmitPathway(content_store, entity_tree)

    capture = _CaptureHook()
    emit_pathway._add_internal_hook(
        capture, pattern="system/runtime/chain-errors/lost/*", name="f2-capture"
    )

    # The chain's cap covers system/inbox/* ONLY — the marker namespace is
    # explicitly outside it (the F11 misconfiguration, reproduced).
    narrow_grants = [
        {"handlers": {"include": ["system/continuation"]},
         "resources": {"include": ["system/inbox/*"]},
         "operations": {"include": ["*"]}},
    ]
    _, caller_cap_hash = _cap_entity(content_store, narrow_grants)

    # The continuation handler's own grant covers the managed namespace.
    full_grants = [
        {"handlers": {"include": ["*"]},
         "resources": {"include": ["*"]},
         "operations": {"include": ["*"]}},
    ]
    _, handler_cap_hash = _cap_entity(content_store, full_grants)

    # Count dispatches for the §4 non-reactivity assertion.
    dispatches = {"execute": 0, "deliver": 0}

    async def _counting_dispatcher(*a, **k) -> ExecuteResult:
        dispatches["execute"] += 1
        return ExecuteResult(status=200, result={})

    ctx = HandlerContext(
        local_peer_id=kp.peer_id,
        remote_peer_id="remote-peer-id",
        handler_grant={"grants": full_grants},
        caller_capability={"grants": narrow_grants},
        emit_pathway=emit_pathway,
        chain_id="chain-f2",
        request_id="req-f2",
        caller_capability_hash=caller_cap_hash,
        handler_grant_hash=handler_cap_hash,
        _execute_dispatcher=_counting_dispatcher,
    )

    async def _failing_deliver(*a, **k) -> ExecuteResult:
        dispatches["deliver"] += 1
        raise ConnectionError("simulated on_error delivery failure")

    ctx.deliver_async = _failing_deliver  # type: ignore[method-assign]

    cont_data = {
        "target": "system/tree",
        "operation": "put",
        "params": {},
        "remaining_executions": 1,
        "dispatch_capability": caller_cap_hash,
        "on_error": {"uri": "system/tree/error-log", "operation": "put"},
    }

    # Advance with a failed forward result (status 500) → §3.4 routes to
    # on_error → the delivery itself fails → marker MUST land.
    resp = await _advance_forward(
        cont_data=cont_data,
        result={"code": "boom"},
        status=500,
        continuation_path="system/inbox/f2-cb",
        full_uri="/peer/system/inbox/f2-cb",
        content_hash=b"\x00" + b"\x02" * 32,
        ctx=ctx,
    )
    assert resp["status"] == 200, (
        f"marker path must stay best-effort/non-blocking (200), got {resp['status']}"
    )

    # 1. The marker LANDED despite the cap not covering the namespace,
    #    keyed by the original request ID (F1 ratification).
    prefix = emit_pathway.entity_tree.normalize_uri(
        "system/runtime/chain-errors/lost/chain-f2/req-f2/on_error_dispatch_failed/"
    )
    matches = emit_pathway.entity_tree.list_prefix(prefix)
    assert len(matches) == 1, (
        f"bind-under-denial: expected exactly 1 marker under {prefix}, got "
        f"{len(matches)} — MUST-bind is not satisfiable under handler authority"
    )
    marker = content_store.get(entity_tree.get(matches[0]))
    assert marker is not None, "marker entity not in store"
    assert marker.data["chain_id"] == "chain-f2"
    assert marker.data["step_index"] == "req-f2", (
        f"marker key: got step={marker.data['step_index']!r}, want 'req-f2' "
        f"— F1 RequestID ratification (never a synthesized cont-error key "
        f"when the EXECUTE carried a request_id)"
    )

    # 2. Authority attribution (W6 split): the write was authorized by the
    #    HANDLER's grant; the denied caller cap is recorded alongside, not
    #    used.
    marker_events = [
        e for e in capture.events if e.uri.startswith(prefix)
    ]
    assert marker_events, (
        f"sync hook never saw the marker bind (captured {len(capture.events)} events)"
    )
    evt_ctx = marker_events[0].context
    assert evt_ctx is not None, "marker bind carried no mutation context"
    assert evt_ctx.capability == handler_cap_hash, (
        "marker bind not attributed to the handler grant — substrate "
        "surface rides substrate authority"
    )
    assert evt_ctx.caller_capability == caller_cap_hash, (
        "W6 attribution split lost: denied caller cap not recorded"
    )

    # 3. Non-reactivity (§4): the marker bind triggered nothing — the only
    #    dispatch was the failed on_error delivery itself.
    assert dispatches["deliver"] == 1, (
        f"expected exactly 1 delivery attempt (the failed on_error), "
        f"got {dispatches['deliver']}"
    )
    assert dispatches["execute"] == 0, (
        f"marker MUST NOT trigger reactive behavior — saw "
        f"{dispatches['execute']} dispatches after the failed on_error"
    )
