"""EXTENSION-CONTINUATION v1.19 + v1.20 §3.10 pin tests.

Two regression-blockers per HANDOFF-STAGE-4-TO-IMPL-TEAMS §2.3 H-P1(e):

1. ``test_distinct_reason_per_status`` — guard against a future-touch
   reintroducing v1.13's ``forward_dispatch_non2xx`` catch-all reason.
   Distinct response codes at the same chain step MUST land at distinct
   ``{reason}`` sibling paths (v1.19 §3.10.5 single-rule:
   ``{reason}`` IS ``result.data.code`` verbatim).

2. ``test_distinct_marker_hash_per_occurrence`` — guard against a
   future-touch reintroducing v1.16/v1.19's "same-reason single-marker"
   claim. Three repeat occurrences of the same code MUST land at three
   distinct ``{marker_hash}`` terminal paths (v1.20 §3.10.1: tree IS
   the event log; ``timestamp`` body field captured at failure-origination
   makes each occurrence's content_hash differ).

Spec anchors:
- EXTENSION-CONTINUATION v1.20 §3.10.1 — per-occurrence path scheme
- EXTENSION-CONTINUATION v1.19 §3.10.5 — code-as-reason single rule
- EXTENSION-CONTINUATION v1.20 §3.10.6 — timestamp-capture discipline
- Proposal §1.2b (Unified Design) + §1.2c (per-occurrence Amendment 2)
"""

from __future__ import annotations

import asyncio
import time

import pytest

from entity_core.capability.grant import create_full_access_grant
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.continuation import (
    CODE_CAPABILITY_DENIED,
    CONTINUATION_TYPE,
    TRANSPORT_CODE_PROTOCOL_ERROR,
    _advance_forward,
)


def _make_ctx() -> tuple[EmitPathway, HandlerContext, bytes]:
    """Minimal handler context backed by an in-memory emit pathway."""
    kp = Keypair.generate()
    content_store = ContentStore()
    entity_tree = EntityTree(kp.peer_id)
    emit_pathway = EmitPathway(content_store, entity_tree)
    # Permissive cap (the dispatch path checks resolvability only).
    cap = Entity(
        type="system/capability/token",
        data={
            "grants": [
                {"handlers": {"include": ["*"]},
                 "resources": {"include": ["*"]},
                 "operations": {"include": ["*"]}},
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
        _execute_dispatcher=_noop_dispatch,
    )
    ctx.chain_id = "v120-test-chain"  # type: ignore[attr-defined]
    return emit_pathway, ctx, cap_hash


@pytest.mark.asyncio
async def test_distinct_reason_per_status() -> None:
    """v1.19 §3.10.5 single-rule pin: distinct response codes ⇒ distinct paths.

    Pre-fix (v1.13): all non-2xx responses bound under one
    ``forward_dispatch_non2xx`` reason — three different downstream
    codes clobbered each other at the same path. Post-fix: each code's
    marker lands at its own ``{reason}`` sibling.

    Regression failure message names v1.19 §3.10.5 + the deprecated
    catch-all so a future-touch traces straight to the spec text.
    """
    emit_pathway, ctx, cap_hash = _make_ctx()

    cont_data = {
        "target": "remote/handler",
        "operation": "do",
        "params": {},
        "remaining_executions": 1,
        "dispatch_capability": cap_hash,
        # No on_error — exercises the v1.19 §3.10.5 lost-marker path.
    }

    # Three different handler-side codes at the same chain step.
    test_codes = [
        ("internal_error", 500),
        ("service_unavailable", 503),
        ("not_found", 404),
    ]

    for code, status in test_codes:
        async def _stub_dispatch(*a, _code=code, _status=status, **k) -> ExecuteResult:
            return ExecuteResult(
                status=_status,
                result={
                    "type": "system/protocol/error",
                    "data": {"code": _code, "message": "test"},
                },
            )

        ctx.execute_with_capability = _stub_dispatch  # type: ignore[method-assign]
        ctx.request_id = f"req-{code}"  # type: ignore[attr-defined]
        await _advance_forward(
            cont_data=cont_data,
            result={"data": {}},
            status=200,
            continuation_path="test-cont",
            full_uri="/peer/test-cont",
            content_hash=b"\x00" + b"\x02" * 32,
            ctx=ctx,
        )

    # Walk the chain-errors subtree and bucket markers by {reason}.
    prefix = emit_pathway.entity_tree.normalize_uri(
        "system/runtime/chain-errors/lost/v120-test-chain/"
    )
    matches = emit_pathway.entity_tree.list_prefix(prefix)
    # v1.20 path: .../{step_index}/{reason}/{marker_hash} — three steps,
    # three reasons, three markers (one per code), all distinct paths.
    reasons_seen = set()
    for marker_uri in matches:
        # The {reason} segment is the second-to-last path component.
        parts = marker_uri.rstrip("/").split("/")
        if len(parts) >= 2:
            reasons_seen.add(parts[-2])

    expected = {code for code, _ in test_codes}
    assert expected.issubset(reasons_seen), (
        f"v1.19 §3.10.5 regression: expected distinct {{reason}} paths for "
        f"each handler-emitted code {expected}, got {reasons_seen}. "
        f"Likely a future-touch reintroduced v1.13's "
        f"'forward_dispatch_non2xx' catch-all in "
        f"packages/entity-handlers/src/entity_handlers/continuation.py "
        f"::_advance_forward — see EXTENSION-CONTINUATION v1.19 §3.10.5 "
        f"(canonical 1-rule: {{reason}} IS result.data.code verbatim)."
    )


@pytest.mark.asyncio
async def test_distinct_marker_hash_per_occurrence() -> None:
    """v1.20 §3.10.1 per-occurrence pin: N flaps ⇒ N distinct {marker_hash} paths.

    Pre-fix (v1.16/v1.19): the path terminated at ``{reason}``; repeat
    occurrences clobbered each other (the `timestamp` body field made
    each marker's content_hash differ, so naïve `tree:put` had three
    impls resolving the contradiction independently → silent divergence).
    Post-fix (v1.20): terminal ``{marker_hash}`` segment means each
    distinct observation lands at its own path; the tree IS the event
    log per §3.10.1.

    Regression failure message names v1.20 §3.10.1 + §1.2c so a
    future-touch traces straight to the spec text.
    """
    emit_pathway, ctx, cap_hash = _make_ctx()

    cont_data = {
        "target": "remote/handler",
        "operation": "do",
        "params": {},
        "remaining_executions": 5,
        "dispatch_capability": cap_hash,
    }

    async def _stub_dispatch(*a, **k) -> ExecuteResult:
        return ExecuteResult(
            status=500,
            result={"type": "system/protocol/error",
                    "data": {"code": "internal_error"}},
        )

    ctx.execute_with_capability = _stub_dispatch  # type: ignore[method-assign]
    ctx.request_id = "same-rid"  # type: ignore[attr-defined]

    # Three flaps with explicit time separation so the captured timestamps
    # genuinely differ at the millisecond resolution Python uses.
    for _ in range(3):
        await _advance_forward(
            cont_data=cont_data,
            result={"data": {}},
            status=200,
            continuation_path="test-cont",
            full_uri="/peer/test-cont",
            content_hash=b"\x00" + b"\x02" * 32,
            ctx=ctx,
        )
        # 2ms sleep guarantees the `int(time.time() * 1000)` capture
        # bumps even on the fastest machines.
        await asyncio.sleep(0.002)

    # All three markers share the same {kind}/{chain_id}/{step_index}/{reason}
    # prefix but have distinct {marker_hash} terminal segments per v1.20 §3.10.1.
    prefix = emit_pathway.entity_tree.normalize_uri(
        "system/runtime/chain-errors/lost/v120-test-chain/same-rid/internal_error/"
    )
    matches = emit_pathway.entity_tree.list_prefix(prefix)

    assert len(matches) == 3, (
        f"v1.20 §3.10.1 regression: 3 distinct flaps produced "
        f"{len(matches)} markers under {prefix} — expected 3 distinct "
        f"{{marker_hash}} terminal paths. Likely a future-touch reverted "
        f"to v1.16/v1.19's single-marker-per-reason claim (which was "
        f"structurally false because timestamp varies per occurrence; "
        f"v1.20 §3.10.1 + §1.2c closed the contradiction). See "
        f"packages/entity-handlers/src/entity_handlers/continuation.py "
        f"::_bind_chain_error_marker path construction (must append "
        f"`/{{marker_hash.hex()}}` per V7 §3.5 invariant-pointer form)."
    )

    # Confirm the three terminal segments are all valid 66-char ECF v1 SHA-256
    # hex strings starting with `00` (format-code byte), per V7 §3.5
    # invariant-pointer hex form pinned in v1.20 §3.10.1.
    terminals = [m.rstrip("/").rsplit("/", 1)[-1] for m in matches]
    for t in terminals:
        assert len(t) == 66, (
            f"v1.20 §3.10.1 / V7 §3.5: {{marker_hash}} terminal MUST be "
            f"V7 §3.5 hex form (66 chars for ECFv1-SHA-256, format-code "
            f"byte prefix `00`). Got {len(t)}-char segment {t!r}."
        )
        assert t.startswith("00"), (
            f"v1.20 §3.10.1 / V7 §3.5: {{marker_hash}} terminal MUST "
            f"include the format-code byte prefix (0x00 for ECFv1-SHA-256). "
            f"Got terminal {t!r}."
        )
    # And all three differ from each other (no aliasing).
    assert len(set(terminals)) == 3, (
        f"v1.20 §3.10.1: 3 occurrences MUST produce 3 distinct "
        f"{{marker_hash}} terminals. Got duplicates in {terminals!r}."
    )
