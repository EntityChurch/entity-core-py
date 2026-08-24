"""The advance-authority split — PROPOSAL-CONTINUATION-STANDING-MODEL §3.

Arch ruling 2026-07-18 (MUST): a standing continuation is subscription-shaped —
a trigger *reaches* it but does not *own* it.

- **Reactive** advance (a delivery mechanism: inbox route, subscription/timer
  poke) is gated by delivery-REACHABILITY and runs under the continuation's OWN
  `dispatch_capability`; it MUST NOT require the delivering caller to hold
  advance-cap on the continuation's path. This is what lets peer A trigger a
  continuation resident on B without holding rights over B's continuation state
  (the Q2 cross-peer return-leg defect Go surfaced).
- **Administrative** advance (a bare `advance` EXECUTE) stays capability-gated
  on the path.

Python pins the standing-model O1 signal as an EXPLICIT per-dispatch marker
(`ctx.reactive_trigger`), set by the delivery mechanism — mirroring Go's
`WithReactiveTrigger` / `HandlerContext.ReactiveTrigger` — never inferred from
caller identity, cap shape, or dispatch surface.
"""

from __future__ import annotations

import pytest

from entity_core.capability.grant import create_full_access_grant
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.bounds import Bounds
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.continuation import continuation_handler

CONT_PATH = "system/inbox/authz-cont"


def _narrow_receive_only() -> dict:
    """Grants receive on the inbox path but NOT advance on the continuation
    path — the shape of a cross-peer trigger's scoped dispatch_capability."""
    return {"grants": [{"handlers": {"include": ["system/inbox"]},
                        "resources": {"include": [CONT_PATH]},
                        "operations": {"include": ["receive"]}}]}


def _permissive() -> dict:
    return {"grants": [{"handlers": {"include": ["*"]},
                        "resources": {"include": ["*"]},
                        "operations": {"include": ["*"]}}]}


def _ctx_with_continuation(caller_capability: dict, *, reactive: bool):
    kp = Keypair.generate()
    content_store = ContentStore()
    emit_pathway = EmitPathway(content_store, EntityTree(kp.peer_id))
    dispatch_cap = Entity(type="system/capability/token", data=_permissive())
    cap_hash = content_store.put(dispatch_cap)
    cont = Entity(type="system/continuation", data={
        "target": "system/tree", "operation": "get",
        "resource": {"targets": ["data/probe"]},
        "params": {}, "dispatch_capability": cap_hash,
        "remaining_executions": 5,
    })
    emit_pathway.emit(CONT_PATH, cont, EmitContext.bootstrap())

    async def _noop_dispatch(*a, **k) -> ExecuteResult:
        return ExecuteResult(status=200, result={})

    ctx = HandlerContext(
        local_peer_id=kp.peer_id, remote_peer_id="trigger-peer",
        handler_grant=_permissive(), caller_capability=caller_capability,
        emit_pathway=emit_pathway, resource_targets=[CONT_PATH],
        handler_pattern="system/continuation", reactive_trigger=reactive,
        bounds=Bounds().apply_defaults(), _execute_dispatcher=_noop_dispatch,
    )
    return ctx


async def _advance(ctx) -> dict:
    return await continuation_handler(
        "system/continuation", "advance", {"data": {}}, ctx)


class TestReactiveAdvancesUnderOwnAuthority:
    """Anchor: the Q2 return leg. A trigger whose cap does NOT cover the
    continuation path still advances it — under the continuation's own
    authority — WHEN the advance is declared reactive."""

    @pytest.mark.asyncio
    async def test_reactive_advance_narrow_trigger_cap_succeeds(self) -> None:
        ctx = _ctx_with_continuation(_narrow_receive_only(), reactive=True)
        resp = await _advance(ctx)
        assert resp["status"] == 200, resp
        assert resp["result"]["data"]["advanced"] is True

    @pytest.mark.asyncio
    async def test_reactive_advance_empty_cap_succeeds(self) -> None:
        """A delivery route may advance with no caller cap at all (internal
        synthesized context) — reachability, not path-cap, is the gate."""
        ctx = _ctx_with_continuation({}, reactive=True)
        assert (await _advance(ctx))["status"] == 200


class TestAdministrativeStaysPathCapGated:
    """The other half of the split — and it MUST still deny, or the split is
    just un-gating. This is the standing-model §6 anchor's administrative half."""

    @pytest.mark.asyncio
    async def test_administrative_narrow_cap_denied(self) -> None:
        ctx = _ctx_with_continuation(_narrow_receive_only(), reactive=False)
        resp = await _advance(ctx)
        assert resp["status"] == 403, resp
        assert resp["result"]["data"]["code"] == "capability_denied"

    @pytest.mark.asyncio
    async def test_administrative_permissive_cap_succeeds(self) -> None:
        ctx = _ctx_with_continuation(_permissive(), reactive=False)
        assert (await _advance(ctx))["status"] == 200

    @pytest.mark.asyncio
    async def test_administrative_empty_cap_trusted(self) -> None:
        """An absent caller cap ({}) is an internal / dispatcher-authorized
        context — trusted here (defense-in-depth corrects a *present but
        insufficient* cap, it does not invent a gate). Otherwise every internal
        advance would 403."""
        ctx = _ctx_with_continuation({}, reactive=False)
        assert (await _advance(ctx))["status"] == 200

    @pytest.mark.asyncio
    async def test_the_marker_is_the_only_difference(self) -> None:
        """Identical setup, identical narrow cap — the ONLY difference is the
        reactive marker. Reactive advances; administrative is denied. That is
        the split (mirrors Go's TestAdvanceAuthoritySplit)."""
        narrow = _narrow_receive_only()
        reactive = await _advance(_ctx_with_continuation(narrow, reactive=True))
        admin = await _advance(_ctx_with_continuation(narrow, reactive=False))
        assert reactive["status"] == 200
        assert admin["status"] == 403


@pytest.mark.asyncio
async def test_reactive_marker_is_per_dispatch_not_inherited() -> None:
    """The marker tags ONLY the one advance the delivery mechanism initiated —
    never the continuation's onward chain dispatches. Driven end-to-end through
    a live peer's real inbox route; every internal dispatch's reactive_trigger
    is captured."""
    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().debug_mode(True).build()
    await peer.start("127.0.0.1", 19093)
    try:
        cap = Entity(type="system/capability/token", data=_permissive())
        cap_hash = peer.content_store.put(cap)
        inbox_path = "system/inbox/per-dispatch"
        # A continuation whose advancement dispatches to system/tree — so the
        # advance itself makes an onward internal dispatch we can inspect.
        cont = Entity(type="system/continuation", data={
            "target": "system/tree", "operation": "get",
            "resource": {"targets": ["data/probe"]},
            "params": {}, "dispatch_capability": cap_hash,
            "remaining_executions": 5,
        })
        peer.emit_pathway.emit(inbox_path, cont, EmitContext.bootstrap())

        # Spy: record (operation -> reactive_trigger) for each internal dispatch.
        seen: list[tuple[str, bool]] = []
        orig = peer._dispatch_local_execute

        async def _spy(uri, operation, *a, reactive_trigger=False, **k):
            seen.append((operation, reactive_trigger))
            return await orig(uri, operation, *a,
                              reactive_trigger=reactive_trigger, **k)

        peer._dispatch_local_execute = _spy

        from entity_handlers.inbox import inbox_handler

        async def _dispatcher(uri, op, params, cap_, bounds, chain_id,
                              resource_targets=None, **kwargs):
            return await peer._dispatch_local_execute(
                uri, op, params, cap_, bounds, chain_id, resource_targets, **kwargs)

        ctx = HandlerContext(
            local_peer_id=peer.peer_id, remote_peer_id="trigger-peer",
            handler_grant=_permissive(), caller_capability=_narrow_receive_only(),
            emit_pathway=peer.emit_pathway, resource_targets=[inbox_path],
            handler_pattern="system/inbox", keypair=peer.keypair,
            bounds=Bounds().apply_defaults(), _execute_dispatcher=_dispatcher,
        )
        await inbox_handler("system/inbox", "receive",
                            {"type": "system/inbox/delivery",
                             "data": {"original_request_id": "x", "status": 200,
                                      "result": {"v": 1}}}, ctx)

        advance_flags = [r for (op, r) in seen if op == "advance"]
        onward_flags = [r for (op, r) in seen if op not in ("advance", "receive")]
        assert advance_flags and all(advance_flags), (
            "the inbox-initiated advance MUST be reactive")
        assert onward_flags and not any(onward_flags), (
            "the continuation's onward dispatch MUST NOT inherit reactivity "
            "(per-dispatch marker) — else a reactive trigger would silently "
            "un-gate the whole onward chain")
    finally:
        peer._dispatch_local_execute = orig
        await peer.stop()
