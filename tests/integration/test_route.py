"""EXTENSION-ROUTE v1.0 + RELAY v1.1 source-routed multi-hop — behaviour pins.

Mirrors the Go cohort's conformance vectors (the RELAY v1.1 cohort-close
handoff §2.3): the `relay_source_route` family (srcr1-6) for v1.1
source-routed multi-hop, and the `route` family (route1-8) for the
EXTENSION-ROUTE storage-plane table-read resolver. Also pins the §6 cross-impl
traps:

- **trap #2** — the `next_hop`/`route` cross-field invariant fires PRE-DISPATCH
  (`route=[C,D]` + `next_hop=S`, S≠C → invalid_request/400 before any forward).
- **trap #3** — intermediate forwards MUST set `next_hop' = route'[0]` and pop
  the head (`route' = route[1:]`), inner envelope unchanged (§9 opacity).
- **trap #5** — the route-table resolver runs ONLY when both `route` and
  `next_hop` are absent (precedence: source-route > table > direct).

Multi-hop end-to-end byte convergence (A→B→C→D over wired peers) is the cohort
validate-peer gate; these own-peer pins exercise the per-hop algorithm and the
resolver match in isolation, capturing the outbound forward via a recording
dispatcher.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.peer.builder import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

from entity_handlers.relay import (
    FORWARD_REQUEST_TYPE,
    make_forward_request,
)
from entity_handlers.route import (
    ROUTE_ACTION_DELIVER,
    ROUTE_ACTION_FORWARD,
    ROUTE_MATCH_DEFAULT,
    make_route,
    resolve_from_table,
    route_storage_path,
)

_BLANKET = {
    "grants": [
        {
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }
    ]
}


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


def _peer_id() -> str:
    """A fresh ephemeral Base58 peer-id (distinct destinations per check so
    synthetic routes don't shadow each other — §6 trap #8)."""
    return Keypair.generate().peer_id


def _inner_entity():
    """A dummy opaque 'inner envelope' + (hash, included-map). Held opaque by
    the relay (§9); shape per §2.3 (full system/envelope-typed entity)."""
    ent = Entity(type="system/envelope", data={"root": {"x": 1}, "included": {}})
    h = ent.compute_hash()
    return ent, h, {h: ent.to_dict()}


def _ctx(peer, *, included=None, dispatcher=None) -> HandlerContext:
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=peer.keypair.peer_id,
        handler_grant=_BLANKET,
        caller_capability=_BLANKET,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=dispatcher or peer._dispatch_local_execute,
        handler_pattern="system/relay",
        included=included or {},
    )


async def _forward(peer, fr, *, included=None, dispatcher=None):
    """Invoke system/relay:forward with the given forward-request entity."""
    h = peer.handlers.find_handler("system/relay")
    ctx = _ctx(peer, included=included, dispatcher=dispatcher)
    return await h("system/relay", "forward", {"data": fr.data}, ctx)


def _recording_dispatcher(result: ExecuteResult | None = None):
    """A fake _execute_dispatcher that records outbound (intermediate-hop)
    forwards and returns a configurable ExecuteResult, so the per-hop
    pop/rewrite + reachability semantics can be asserted without a live remote
    relay. Defaults to 200 OK (reachable next that accepted the forward)."""
    calls: list[dict] = []
    ret = result if result is not None else ExecuteResult(
        status=200, result={"data": {"status": "forwarded"}}
    )

    async def disp(uri, operation, params, dispatch_capability, bounds,
                   chain_id, resource_targets, included=None):
        calls.append(
            {
                "uri": uri,
                "operation": operation,
                "params": params,
                "resource_targets": resource_targets,
                "included": included,
            }
        )
        return ret

    return disp, calls


def _seed_route(peer, **kwargs):
    """Author a system/route entity into the peer's local table (§2)."""
    route = make_route(**kwargs)
    peer.emit_pathway.emit(
        route_storage_path(route.compute_hash().hex()), route, EmitContext.bootstrap()
    )
    return route


# ===========================================================================
# RELAY v1.1 source-routed multi-hop (srcr1-6) + §6 traps
# ===========================================================================


@pytest.mark.asyncio
async def test_srcr3_single_element_route_equals_next_hop(peer):
    """srcr3 — `route=[D]` alone behaves identically to `next_hop=D`: terminal
    hop at D. Offline destination → §6.2.1 Mode-S fallback (queued-fallback)."""
    dest = _peer_id()
    ent, inner_hash, included = _inner_entity()
    fr = make_forward_request(
        destination=dest, envelope_inner=inner_hash, ttl_hops=4, route=[dest]
    )
    res = await _forward(peer, fr, included=included)
    assert res["status"] == 200
    assert res["result"]["data"]["status"] == "queued-fallback"
    assert res["result"]["data"]["stored_at"] == dest


@pytest.mark.asyncio
async def test_srcr4_source_route_ttl_exhausted(peer):
    """srcr4 — ttl_hops=0 on receipt → ttl_exhausted/400 (fail-closed, even
    with a source route present)."""
    dest = _peer_id()
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(
        destination=dest, envelope_inner=inner_hash, ttl_hops=0,
        route=[_peer_id(), dest],
    )
    res = await _forward(peer, fr, included=included)
    assert res["status"] == 400
    assert res["result"]["data"]["code"] == "ttl_exhausted"


@pytest.mark.asyncio
async def test_srcr2_intermediate_hop_pops_head_and_rewrites_next_hop(peer):
    """srcr2 + trap #3 — A→B→C→D with `route=[B,C,D]`: this relay (A) is at an
    intermediate hop (next = B ≠ D), forwards to B with `route' = [C,D]`,
    `next_hop' = C` (the new head), `ttl_hops−1`, and the inner envelope
    unchanged (§9 opacity)."""
    dest = _peer_id()
    b, c = _peer_id(), _peer_id()
    ent, inner_hash, included = _inner_entity()
    fr = make_forward_request(
        destination=dest, envelope_inner=inner_hash, ttl_hops=8, route=[b, c, dest]
    )
    disp, calls = _recording_dispatcher()
    res = await _forward(peer, fr, included=included, dispatcher=disp)

    assert res["status"] == 200
    assert res["result"]["data"]["next_hop"] == b  # forwarded to the head
    assert len(calls) == 1
    call = calls[0]
    assert call["uri"] == f"entity://{b}/system/relay"  # dispatched to B
    fdata = call["params"]["data"]
    assert fdata["route"] == [c, dest]  # head popped
    assert fdata["next_hop"] == c  # next_hop' = route'[0] (trap #3)
    assert fdata["ttl_hops"] == 7  # decremented
    assert fdata["destination"] == dest  # unchanged
    assert fdata["envelope_inner"] == inner_hash  # inner unchanged (§9)
    # §9 opacity: the inner entity rides verbatim in `included`, byte-identical.
    assert call["included"] == {inner_hash: ent.to_dict()}


@pytest.mark.asyncio
async def test_srcr5_intermediate_unreachable_falls_back_to_mode_s(peer):
    """srcr5 — `route=[X, D]` where the intermediate X is UNREACHABLE. B pops
    X as next; the forward to X fails for connectivity (a bodyless 502 — no
    response body, the analog of Go's isUnreachable). Per §3.1.1 + §6.2.1 this
    MUST trigger the Mode-S fallback (queued-fallback at namespace=D), NOT
    no_route. Regression pin for the cohort residual."""
    dest = _peer_id()
    unreachable_x = _peer_id()
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(
        destination=dest, envelope_inner=inner_hash, ttl_hops=4,
        route=[unreachable_x, dest],
    )
    # Transport failure: bodyless 502 (no result dict) — what the remote
    # dispatch returns when it can't dial / has no route to the next hop.
    disp, calls = _recording_dispatcher(
        ExecuteResult(status=502, error="Remote execute failed: no route to peer")
    )
    res = await _forward(peer, fr, included=included, dispatcher=disp)
    assert res["status"] == 200
    assert res["result"]["data"]["status"] == "queued-fallback"
    # Fallback namespace is the ultimate destination, NOT the unreachable hop.
    assert res["result"]["data"]["stored_at"] == dest
    assert calls and calls[0]["uri"] == f"entity://{unreachable_x}/system/relay"


@pytest.mark.asyncio
async def test_intermediate_reachable_but_errors_reports_forwarded(peer):
    """route3-shape — the resolved `next` is REACHABLE but responds with its own
    business error (e.g. it has no onward route to `destination`). B's hop is
    still done: it forwarded to `next`. Mirroring Go's ForwardToNextHop (err==nil
    whenever next responds), B reports forwarded/next_hop=next, NOT no_route. A
    reachable next always returns a response body (result dict)."""
    dest = _peer_id()
    via = _peer_id()
    _seed_route(peer, match=dest, action=ROUTE_ACTION_FORWARD, via=via)
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4)
    # Reachable next that responds with a no_route business error (has a body).
    disp, calls = _recording_dispatcher(
        ExecuteResult(
            status=502,
            result={"type": "system/protocol/error", "data": {"code": "no_route"}},
            error="no_route",
        )
    )
    res = await _forward(peer, fr, included=included, dispatcher=disp)
    assert res["status"] == 200
    assert res["result"]["data"]["status"] == "forwarded"
    assert res["result"]["data"]["next_hop"] == via
    assert calls and calls[0]["uri"] == f"entity://{via}/system/relay"


@pytest.mark.asyncio
async def test_trap2_route_next_hop_mismatch_rejects_pre_dispatch(peer):
    """trap #2 — `route=[C,D]` + `next_hop=S` (S ≠ C) → invalid_request/400
    PRE-DISPATCH (before any forward). An impl validating only one field would
    silently pick a hop and forward — wrong."""
    dest = _peer_id()
    c, s = _peer_id(), _peer_id()
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(
        destination=dest, envelope_inner=inner_hash, ttl_hops=8,
        route=[c, dest], next_hop=s,
    )
    disp, calls = _recording_dispatcher()
    res = await _forward(peer, fr, included=included, dispatcher=disp)
    assert res["status"] == 400
    assert res["result"]["data"]["code"] == "invalid_request"
    assert not calls  # rejected before any forward


@pytest.mark.asyncio
async def test_route_next_hop_match_ok(peer):
    """The cross-field invariant is satisfied when `next_hop == route[0]`:
    `route=[D]` + `next_hop=D` → terminal (Mode-S fallback), no rejection."""
    dest = _peer_id()
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(
        destination=dest, envelope_inner=inner_hash, ttl_hops=4,
        route=[dest], next_hop=dest,
    )
    res = await _forward(peer, fr, included=included)
    assert res["status"] == 200
    assert res["result"]["data"]["status"] == "queued-fallback"


# ===========================================================================
# EXTENSION-ROUTE table-read resolver (route1-8)
# ===========================================================================


@pytest.mark.asyncio
async def test_route3_exact_forward(peer):
    """route3 — exact `match` with action=forward → next_hop = via. Resolver
    fires because the forward-request carries no source route + no next_hop."""
    dest = _peer_id()
    via = _peer_id()
    _seed_route(peer, match=dest, action=ROUTE_ACTION_FORWARD, via=via)
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4)
    disp, calls = _recording_dispatcher()
    res = await _forward(peer, fr, included=included, dispatcher=disp)
    assert res["status"] == 200
    assert res["result"]["data"]["next_hop"] == via
    assert calls and calls[0]["uri"] == f"entity://{via}/system/relay"


@pytest.mark.asyncio
async def test_route6_default_route(peer):
    """route6 — `match: "*"` default route resolves when no exact match."""
    dest = _peer_id()
    via = _peer_id()
    _seed_route(peer, match=ROUTE_MATCH_DEFAULT, action=ROUTE_ACTION_FORWARD, via=via)
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4)
    disp, calls = _recording_dispatcher()
    res = await _forward(peer, fr, included=included, dispatcher=disp)
    assert res["status"] == 200
    assert res["result"]["data"]["next_hop"] == via


@pytest.mark.asyncio
async def test_route7_exact_beats_default(peer):
    """route7 — exact `match` outranks `*` default on ties (longest-match-wins),
    even when the default has a lower metric."""
    dest = _peer_id()
    exact_via, default_via = _peer_id(), _peer_id()
    _seed_route(peer, match=ROUTE_MATCH_DEFAULT, action=ROUTE_ACTION_FORWARD,
                via=default_via, metric=1)
    _seed_route(peer, match=dest, action=ROUTE_ACTION_FORWARD,
                via=exact_via, metric=99)
    next_hop, hit = resolve_from_table(_ctx(peer), dest)
    assert hit and next_hop == exact_via


@pytest.mark.asyncio
async def test_route4_metric_tiebreak(peer):
    """route4 — among same-cohort matches, lowest `metric` wins."""
    dest = _peer_id()
    lo_via, hi_via = _peer_id(), _peer_id()
    _seed_route(peer, match=dest, action=ROUTE_ACTION_FORWARD, via=hi_via, metric=10)
    _seed_route(peer, match=dest, action=ROUTE_ACTION_FORWARD, via=lo_via, metric=2)
    next_hop, hit = resolve_from_table(_ctx(peer), dest)
    assert hit and next_hop == lo_via


@pytest.mark.asyncio
async def test_route5_expired_skipped(peer):
    """route5 — a route past its `expires_at` is silently skipped (not surfaced
    as a match). With only an expired route, the table has no match."""
    dest = _peer_id()
    via = _peer_id()
    _seed_route(peer, match=dest, action=ROUTE_ACTION_FORWARD, via=via, expires_at=1)
    next_hop, hit = resolve_from_table(_ctx(peer), dest)
    assert not hit and next_hop is None


@pytest.mark.asyncio
async def test_route8_deliver_action(peer):
    """route8 — action=deliver → terminal hop at this relay (next == dest).
    Offline destination → §6.2.1 Mode-S fallback."""
    dest = _peer_id()
    _seed_route(peer, match=dest, action=ROUTE_ACTION_DELIVER)
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4)
    res = await _forward(peer, fr, included=included)
    assert res["status"] == 200
    assert res["result"]["data"]["status"] == "queued-fallback"
    assert res["result"]["data"]["stored_at"] == dest


@pytest.mark.asyncio
async def test_route2_absent_table_no_route(peer):
    """route2 — empty table + no source route + no next_hop → no_route/502
    (the trivial direct-or-no_route default)."""
    dest = _peer_id()
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4)
    res = await _forward(peer, fr, included=included)
    assert res["status"] == 502
    assert res["result"]["data"]["code"] == "no_route"


@pytest.mark.asyncio
async def test_route_noroute_no_matching_entry(peer):
    """No route entry matches the destination (and no `*` default) → no_route."""
    dest = _peer_id()
    _seed_route(peer, match=_peer_id(), action=ROUTE_ACTION_FORWARD, via=_peer_id())
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4)
    res = await _forward(peer, fr, included=included)
    assert res["status"] == 502
    assert res["result"]["data"]["code"] == "no_route"


@pytest.mark.asyncio
async def test_forward_route_without_via_skipped(peer):
    """A forward-action route with empty `via` is invalid and silently skipped
    (cross-field validity, §3). With only such a route, no match."""
    dest = _peer_id()
    # make_route omits empty via; emit a hand-built route to force the case.
    bad = Entity(type="system/route", data={"match": dest, "action": "forward"})
    peer.emit_pathway.emit(
        route_storage_path(bad.compute_hash().hex()), bad, EmitContext.bootstrap()
    )
    next_hop, hit = resolve_from_table(_ctx(peer), dest)
    assert not hit and next_hop is None


@pytest.mark.asyncio
async def test_trap5_source_route_precedence_over_table(peer):
    """trap #5 — the route table is consulted ONLY when both `route` and
    `next_hop` are absent. With a source route present, the table is NOT read,
    even if it would resolve to a different hop. `route=[D]` → terminal at D,
    NOT the table's forward-via."""
    dest = _peer_id()
    table_via = _peer_id()
    _seed_route(peer, match=dest, action=ROUTE_ACTION_FORWARD, via=table_via)
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(
        destination=dest, envelope_inner=inner_hash, ttl_hops=4, route=[dest]
    )
    disp, calls = _recording_dispatcher()
    res = await _forward(peer, fr, included=included, dispatcher=disp)
    # Source route wins → terminal (Mode-S fallback), not a forward to table_via.
    assert res["status"] == 200
    assert res["result"]["data"]["status"] == "queued-fallback"
    assert not calls  # table_via was never dispatched to


@pytest.mark.asyncio
async def test_trap5_next_hop_precedence_over_table(peer):
    """trap #5 (b) — an explicit `next_hop` also outranks the table. With
    `next_hop=D` and a table forward-route for D, the next_hop wins → terminal,
    not the table's via."""
    dest = _peer_id()
    table_via = _peer_id()
    _seed_route(peer, match=dest, action=ROUTE_ACTION_FORWARD, via=table_via)
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(
        destination=dest, envelope_inner=inner_hash, ttl_hops=4, next_hop=dest
    )
    disp, calls = _recording_dispatcher()
    res = await _forward(peer, fr, included=included, dispatcher=disp)
    assert res["status"] == 200
    assert res["result"]["data"]["status"] == "queued-fallback"
    assert not calls


# ===========================================================================
# Entity shape + byte-compat
# ===========================================================================


def test_v1_0_single_hop_encodes_without_route_field():
    """A v1.0 single-hop request (no `route`) MUST encode byte-identically —
    the `route` field is absent via omitempty."""
    fr = make_forward_request(
        destination=_peer_id(), envelope_inner=b"\x00" * 33, ttl_hops=5,
        next_hop=_peer_id(),
    )
    assert "route" not in fr.data


def test_route_entity_omitempty_shape():
    """make_route drops via/metric/expires_at when empty (omitempty — matches
    Go's RouteData byte shape)."""
    r = make_route(match="*", action="deliver")
    assert r.data == {"match": "*", "action": "deliver"}
    r2 = make_route(match="Q", action="forward", via="V", metric=0, expires_at=0)
    assert r2.data == {"match": "Q", "action": "forward", "via": "V"}
    r3 = make_route(match="Q", action="forward", via="V", metric=3, expires_at=99)
    assert r3.data == {
        "match": "Q", "action": "forward", "via": "V", "metric": 3, "expires_at": 99,
    }
