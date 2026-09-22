"""`status.pending` as a capture oracle — the arm no fixture exercised.

Context: `entity-core-go`'s wire detector
`auto_version.burst_convergence_no_capture_loss` (2026-08-30) uses REVISION §6.1
`status.pending` as its oracle for the symmetric last-burst-write loss: it bursts
concurrent writes and asserts pending settles to 0, on the reasoning that a
non-zero pending is a write that reached the live tree and no version.

That reasoning holds only while a head exists. `_handle_status` computes pending
under `if local_hash:` — so with **no** head, pending is 0 no matter how many
live-tree paths are uncaptured. 0 therefore means two opposite things:
"everything captured" and "nothing captured at all". `entity-core-go` carries the
same guard (`if !headVal.IsZero()`, ext/revision/status.go), so this is a blind
spot in the shared oracle, not a py-vs-go divergence.

Why no existing test caught it: `TestStatus` covers (empty tree, no head) → 0,
which is correct, and (entities, head) → >0. The third combination — **entities
present, no head** — is the one the guard actually decides, and nothing drove it.
That is this file's subject. Same shape as the `min(binding.ttl, local_max)`
entry in AGENTS.md: a guard that reads as type hygiene while silently ruling the
absent case, with every fixture living on the arm that has an answer.
"""

from __future__ import annotations

import pytest

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.tree_registry import TreeRegistry
from entity_handlers.revision import revision_handler


@pytest.fixture
def handler_context() -> HandlerContext:
    content_store = ContentStore()
    entity_tree = EntityTree("test-peer")
    emit_pathway = EmitPathway(content_store, entity_tree)
    permissive = {
        "grants": [
            {
                "handlers": {"include": ["*"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["*"]},
            }
        ]
    }
    return HandlerContext(
        local_peer_id="test-peer",
        remote_peer_id="remote-peer",
        handler_grant=permissive,
        caller_capability=permissive,
        emit_pathway=emit_pathway,
        tree_registry=TreeRegistry(entity_tree, content_store),
        handler_pattern="system/revision",
    )


async def _status(ctx: HandlerContext, prefix: str = "") -> dict:
    result = await revision_handler(
        "system/revision", "status", {"data": {"prefix": prefix}}, ctx
    )
    return result["result"]["data"]


class TestPendingWithNoHead:
    """The arm `if local_hash:` decides, and the one nothing drove."""

    @pytest.mark.asyncio
    async def test_live_paths_with_no_head_are_uncaptured_but_pending_reports_zero(
        self, handler_context
    ):
        """Three live paths, no version anywhere — every one is uncaptured.

        A capture oracle MUST NOT answer 0 here. It does, and that is the
        finding: this is the state a peer is in when auto-version drops the
        capture from the very first write, which is exactly the failure the
        burst detector exists to catch.
        """
        for path in ("data/a.txt", "data/b.txt", "data/c.txt"):
            handler_context.emit_pathway.emit(
                path, Entity(type="test/file", data={"content": path})
            )

        data = await _status(handler_context)

        # Head really is absent (33-byte canonical zero), so this is the
        # no-head arm and not some other state.
        assert data["head"] == b"\x00" + b"\x00" * 32

        # The property the oracle needs: 3 live paths are captured by nothing.
        assert data["pending"] == 3, (
            "pending must count live-tree paths no version captured; reporting 0 "
            "with no head makes 'fully captured' and 'captured nothing' "
            "indistinguishable to any consumer using pending as a capture oracle"
        )

    @pytest.mark.asyncio
    async def test_empty_tree_with_no_head_is_a_real_zero(self, handler_context):
        """The control that keeps the row above honest.

        Without this, 'pending must be non-zero when head is absent' would be
        satisfied by a peer that hard-codes a non-zero constant. An empty tree
        under no head has genuinely nothing uncaptured, so 0 is correct — and
        this row is what makes the assertion above a count rather than a flag.
        """
        data = await _status(handler_context)
        assert data["head"] == b"\x00" + b"\x00" * 32
        assert data["pending"] == 0


class TestPendingWithHeadStillWorks:
    """Teeth control: the arm that already worked must keep working.

    A fix for the no-head arm that broke this one would trade a blind spot for
    a false alarm on every conformant peer.
    """

    @pytest.mark.asyncio
    async def test_commit_then_write_reports_the_uncaptured_path(
        self, handler_context
    ):
        for path in ("data/a.txt", "data/b.txt"):
            handler_context.emit_pathway.emit(
                path, Entity(type="test/file", data={"content": path})
            )
        await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, handler_context
        )

        # NOT asserted as 0: `commit` writes the head pointer into the live
        # tree, and that binding is itself a live path the new version does not
        # contain, so a correct peer reports a small non-zero baseline here.
        # Predicting 0 was wrong on first run (measured 1) — recorded because
        # the pre-existing `test_status_after_commit` skips the count for the
        # same reason, and the delta below is the claim that survives it.
        before = await _status(handler_context)

        handler_context.emit_pathway.emit(
            "data/new.txt", Entity(type="test/file", data={"content": "new"})
        )
        after = await _status(handler_context)
        assert after["pending"] > before["pending"], (
            "the head arm must still count a newly written uncaptured path"
        )
