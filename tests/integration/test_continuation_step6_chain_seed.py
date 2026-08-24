"""EXTENSION-CONTINUATION §3.6 step 6 — chain_id seeding at the dispatch.

Step 6 reads ``chain_id: context.chain_id or generate_id()``. A continuation
whose trigger carried no chain (a timer advance; an inbox delivery that is not
itself a chain dispatch) MUST still dispatch under *some* chain id.

Pre-fix, Python passed ``ctx.chain_id`` straight through, so such a dispatch
went out with ``chain_id`` absent and every downstream marker binder fell down
its own fallback ladder onto a meaningless key — Python's was ``"unknown"``
(``_bind_chain_error_marker``), Rust's ``"internal"``, Go's the request id.
That divergence was read cross-impl as a marker-coordinate disagreement; the
root cause was this step being unimplemented on all three. Per Go's
``docs/validation/reports/2026-07-16-retry-survival-cohort.md`` §3 and
``docs/validation/spec-issues/2026-07-16-marker-coordinate-root-cause.md``.

The sentinels are NOT the bug and are deliberately not asserted away here:
they remain correct for a genuinely-absent chain, they simply stop firing once
step 6 seeds one.
"""

from __future__ import annotations

import pytest

from entity_core.capability.grant import create_full_access_grant
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.protocol.bounds import Bounds
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.continuation import _advance_forward


def _make_ctx(chain_id: str | None, bounds: Bounds | None = None):
    """Handler context whose trigger carries `chain_id` (None = no chain)."""
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
        chain_id=chain_id,
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


@pytest.mark.asyncio
async def test_absent_chain_id_is_generated_at_dispatch() -> None:
    """No chain on the trigger ⇒ step 6 generates one for the dispatch."""
    emit_pathway, ctx, cap_hash = _make_ctx(chain_id=None)
    seen: dict = {}

    # Read the chain off the dispatching context itself (`self`) — that is what
    # the child sees. Both carriers are captured; they MUST agree (they are read
    # from different sources downstream).
    orig = HandlerContext.execute_with_capability

    async def _patched(self, *a, **k) -> ExecuteResult:
        seen["chain_id"] = self.chain_id
        seen["bounds_chain_id"] = self.bounds.chain_id if self.bounds else None
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

    assert seen["chain_id"], (
        "§3.6 step 6 regression: a continuation whose trigger carried no chain "
        "dispatched with chain_id still absent. Step 6 reads "
        "`chain_id: context.chain_id or generate_id()` — generate on absence. "
        "See _step6_chain_context in "
        "packages/entity-handlers/src/entity_handlers/continuation.py."
    )
    assert seen["chain_id"] != "unknown", (
        "step 6 must generate a real id, not lean on the marker binder's "
        "`or \"unknown\"` fallback sentinel."
    )
    # §3.11: chain_id is a segment of the §3.10.6 marker path.
    assert "/" not in seen["chain_id"], (
        f"§3.11: chain_id MUST be a single path segment; a multi-segment value "
        f"forks the marker tree. Got {seen['chain_id']!r}."
    )
    # Both carriers agree — bounds.chain_id feeds the emit pathway's cascade
    # tracking and the §3.10.3 rejected-marker gate, ctx.chain_id feeds the
    # child context. A mismatch splits the chain across readers.
    assert seen["bounds_chain_id"] == seen["chain_id"]


@pytest.mark.asyncio
async def test_present_chain_id_is_preserved_verbatim() -> None:
    """A trigger that carries a chain keeps it — step 6 generates only on absence."""
    emit_pathway, ctx, cap_hash = _make_ctx(
        chain_id="inbound-chain", bounds=Bounds(chain_id="inbound-chain")
    )
    seen: dict = {}

    orig = HandlerContext.execute_with_capability

    async def _patched(self, *a, **k):
        seen["chain_id"] = self.chain_id
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

    assert seen["chain_id"] == "inbound-chain"


@pytest.mark.asyncio
async def test_marker_keys_on_the_generated_chain_not_the_sentinel() -> None:
    """The seeded chain reaches the marker path — the fallback stops firing.

    This is the cross-impl payoff: pre-fix a chainless trigger whose dispatch
    came back non-2xx bound its lost marker under `.../lost/unknown/...`, which
    is what Python reported as its marker coordinate.
    """
    emit_pathway, ctx, cap_hash = _make_ctx(chain_id=None)

    async def _failing(self, *a, **k):
        return ExecuteResult(
            status=503,
            result={
                "type": "system/protocol/error",
                "data": {"code": "service_unavailable", "message": "test"},
            },
        )

    orig = HandlerContext.execute_with_capability
    HandlerContext.execute_with_capability = _failing  # type: ignore[method-assign]
    try:
        ctx.request_id = "req-step6"  # type: ignore[attr-defined]
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

    prefix = emit_pathway.entity_tree.normalize_uri(
        "system/runtime/chain-errors/lost/"
    )
    markers = emit_pathway.entity_tree.list_prefix(prefix)
    assert markers, "expected a lost marker for the non-2xx forward dispatch"

    chain_segments = {
        uri.rstrip("/").split("/")[-4] for uri in markers
    }  # .../lost/{chain_id}/{step_index}/{reason}/{marker_hash}
    assert "unknown" not in chain_segments, (
        "§3.6 step 6 regression: the lost marker keyed on the `or \"unknown\"` "
        "fallback sentinel, which means the dispatch ran with chain_id absent. "
        "The sentinel is not the bug — step 6 not seeding a chain is."
    )
