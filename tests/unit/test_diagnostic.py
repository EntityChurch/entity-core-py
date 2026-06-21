"""Tests for ``entity_core.diagnostic`` — the dispatch/content taps.

Also serves as documentation of how to wire the taps into a debugging
session. The F-CIMP-7 fixture (notification-form base threaded into
fetch-diff) is included to show the histogram naming the exact bug in
one line — the experience I want next time, not "read source for hours".
"""

from __future__ import annotations

import pytest

from entity_core.diagnostic import (
    BindingTap,
    ContentTap,
    DispatchTap,
    chain_trace,
)
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.tree_registry import TreeRegistry
from entity_handlers.revision import revision_handler


def _make_ctx() -> HandlerContext:
    cs = ContentStore()
    et = EntityTree("test-peer")
    emit = EmitPathway(cs, et)
    treg = TreeRegistry(et, cs)
    cap = {"grants": [{"handlers": {"include": ["*"]},
                       "resources": {"include": ["*"]},
                       "operations": {"include": ["*"]}}]}
    return HandlerContext(
        local_peer_id="test-peer",
        remote_peer_id="remote",
        handler_grant=cap,
        caller_capability=cap,
        emit_pathway=emit,
        tree_registry=treg,
        handler_pattern="system/revision",
    )


class TestDispatchTap:
    @pytest.mark.asyncio
    async def test_records_success_and_failure_distinctly(self):
        ctx = _make_ctx()
        tap = DispatchTap()
        wrapped = tap.wrap(revision_handler)

        # One success: commit on empty prefix.
        ctx.emit_pathway.emit("data/x", Entity(type="test/f", data={"v": 1}))
        r = await wrapped("system/revision", "commit", {"data": {"prefix": ""}}, ctx)
        assert r["status"] == 200

        # One failure: fetch-diff with no head present (after build a fresh ctx).
        ctx2 = _make_ctx()
        wrapped2 = tap.wrap(revision_handler)
        r2 = await wrapped2(
            "system/revision", "fetch-diff", {"data": {"prefix": ""}}, ctx2,
        )
        assert r2["status"] == 404

        hist = tap.histogram()
        # Two buckets, distinct by (op, status, error_code).
        assert len(hist) == 2
        codes = {h[3] for h in hist}
        assert "no_local_state" in codes  # named the failure
        statuses = {h[2] for h in hist}
        assert statuses == {200, 404}

    @pytest.mark.asyncio
    async def test_f_cimp_7_pattern_names_itself(self):
        """The histogram that would have ended yesterday's session in one line.

        Probe runs 1 bootstrap + 19 incrementals where every incremental
        threads the notification-form `previous_hash` (the system/hash
        wrapper) into fetch-diff. With yesterday's code that produces
        ``19 × base_not_a_version``; with today's fix it produces
        ``20 × status=200``.
        """
        ctx = _make_ctx()
        tap = DispatchTap()
        wrapped = tap.wrap(revision_handler)

        # Build a chain of 20 commits, each with the prior step's head
        # threaded as the notification-form base on the next fetch-diff.
        prev_wrapper_hash: bytes | None = None
        for step in range(20):
            ctx.emit_pathway.emit(
                "data/a", Entity(type="test/f", data={"v": step}),
            )
            commit = await wrapped(
                "system/revision", "commit", {"data": {"prefix": ""}}, ctx,
            )
            assert commit["status"] == 200
            new_version = commit["result"]["data"]["version"]

            base_param = (
                {"prefix": "", "base": prev_wrapper_hash}
                if prev_wrapper_hash is not None
                else {"prefix": ""}
            )
            await wrapped(
                "system/revision", "fetch-diff", {"data": base_param}, ctx,
            )

            # Materialize the system/hash wrapper that the next iteration
            # will thread as `previous_hash` — same shape the subscription
            # system emits.
            prev_wrapper_hash = ctx.emit_pathway.content_store.put(
                Entity(type="system/hash", data={"hash": new_version})
            )

        # Filter to fetch-diff outcomes only (commit successes drown them).
        fetch_diff_rows = [
            (status, code, count)
            for (pattern, op, status, code, count) in tap.histogram()
            if op == "fetch-diff"
        ]
        # With the fix in place: 20 × status=200, no error codes.
        assert fetch_diff_rows == [(200, None, 20)], (
            f"Expected 20 × status=200 for fetch-diff after the fix, got: "
            f"{fetch_diff_rows}\nFull summary:\n{tap.summary()}"
        )

    @pytest.mark.asyncio
    async def test_records_exception_as_500(self):
        tap = DispatchTap()

        async def bad_handler(path, op, params, ctx):
            raise RuntimeError("boom")

        wrapped = tap.wrap(bad_handler)
        with pytest.raises(RuntimeError):
            await wrapped("x", "y", {}, None)
        assert tap.records[-1].status == 500

    def test_summary_format(self):
        tap = DispatchTap()
        tap.records.append(
            __import__("entity_core.diagnostic", fromlist=["DispatchRecord"])
            .DispatchRecord(0.0, "system/revision", "fetch-diff", 400,
                            "base_not_a_version", "msg", "system/protocol/error")
        )
        s = tap.summary()
        assert "system/revision/fetch-diff" in s
        assert "status=400" in s
        assert "base_not_a_version" in s


class TestContentTap:
    def test_records_puts_with_types(self):
        cs = ContentStore()
        tap = ContentTap(cs)
        cs.put(Entity(type="test/a", data={"x": 1}))
        cs.put(Entity(type="test/a", data={"x": 2}))
        cs.put(Entity(type="test/b", data={}))
        hist = tap.histogram()
        assert hist == [("test/a", 2), ("test/b", 1)]

    def test_detach_restores_put(self):
        cs = ContentStore()
        tap = ContentTap(cs)
        # While taped: puts are recorded.
        cs.put(Entity(type="test/a", data={}))
        assert len(tap.records) == 1
        tap.detach()
        # After detach: puts no longer recorded (raw put is back).
        cs.put(Entity(type="test/b", data={}))
        assert len(tap.records) == 1

    def test_summary_empty(self):
        cs = ContentStore()
        tap = ContentTap(cs)
        assert tap.summary() == "(no puts recorded)"

    def test_uses_substrate_hook_when_available(self):
        """ContentTap on NotifyingContentStore uses add_content_hook (the
        proper citizenship path), not monkey-patching."""
        from entity_core.storage.content_store import NotifyingContentStore
        cs = NotifyingContentStore()
        original_put = cs.put
        tap = ContentTap(cs)
        # put is unchanged (we hooked, didn't replace).
        assert cs.put == original_put
        cs.put(Entity(type="test/a", data={"v": 1}))
        assert len(tap.records) == 1
        tap.detach()
        cs.put(Entity(type="test/b", data={"v": 2}))
        # Detached: hook removed, no further records.
        assert len(tap.records) == 1


class TestBindingTap:
    @pytest.mark.asyncio
    async def test_records_emit_pathway_changes(self):
        """BindingTap subscribes through the substrate's existing hook
        surface — no monkey-patching, no new substrate code."""
        ctx = _make_ctx()
        tap = BindingTap(ctx.emit_pathway, pattern="*")

        ctx.emit_pathway.emit(
            "data/x", Entity(type="test/f", data={"v": 1}),
        )
        ctx.emit_pathway.emit(
            "data/y", Entity(type="test/f", data={"v": 2}),
        )
        # Yield once so async listeners drain.
        import asyncio
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        # Both bindings observed.
        assert len(tap.records) >= 2
        uris = {r.uri for r in tap.records}
        assert any("data/x" in u for u in uris)
        assert any("data/y" in u for u in uris)
        # Kinds are populated.
        kinds = {r.kind for r in tap.records}
        assert "created" in kinds or "ChangeKind.CREATED" in kinds

    @pytest.mark.asyncio
    async def test_detach_stops_recording(self):
        ctx = _make_ctx()
        tap = BindingTap(ctx.emit_pathway, pattern="*")
        ctx.emit_pathway.emit("data/x", Entity(type="test/f", data={"v": 1}))
        import asyncio
        await asyncio.sleep(0)
        n_before = len(tap.records)
        tap.detach()
        ctx.emit_pathway.emit("data/y", Entity(type="test/f", data={"v": 2}))
        await asyncio.sleep(0)
        assert len(tap.records) == n_before


class TestChainTrace:
    """Test the composed §2.3 `chain_trace` capability.

    Validates the GUIDE'S claim that chain traces compose from substrate-
    observable state without new hooks. If the chain framework doesn't
    actually persist its state at the claimed paths, this test fails and
    the guide's claim needs revisiting.
    """

    def test_empty_chain_id_returns_empty_result(self):
        ctx = _make_ctx()
        result = chain_trace(
            "nonexistent-chain-id",
            content_store=ctx.emit_pathway.content_store,
            entity_tree=ctx.emit_pathway.entity_tree,
        )
        assert result.chain_id == "nonexistent-chain-id"
        assert result.continuation_entries == []
        assert result.error_markers == []
        assert result.related_uris == []

    def test_picks_up_chain_error_markers(self):
        """If a chain-error marker exists at the documented path, the
        trace surfaces it."""
        ctx = _make_ctx()
        # Materialize a chain-error marker at the path the chain framework
        # would write it — exact shape doesn't matter for this test,
        # we just want to confirm the trace finds artifacts at the path.
        chain_id = "test-chain-42"
        marker_path = (
            f"system/runtime/chain-errors/lost/{chain_id}/0/"
            f"base_not_a_version/marker-1"
        )
        ctx.emit_pathway.emit(
            marker_path,
            Entity(
                type="system/runtime/chain-error",
                data={
                    "code": "base_not_a_version",
                    "failed_uri": "system/revision",
                    "status": 400,
                },
            ),
        )
        result = chain_trace(
            chain_id,
            content_store=ctx.emit_pathway.content_store,
            entity_tree=ctx.emit_pathway.entity_tree,
        )
        assert len(result.error_markers) == 1
        uri, data = result.error_markers[0]
        assert "base_not_a_version" in uri
        assert data.get("code") == "base_not_a_version"
        # Summary mentions the error code.
        assert "base_not_a_version" in result.summary()
