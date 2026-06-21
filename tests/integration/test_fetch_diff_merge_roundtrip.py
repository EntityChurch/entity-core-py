"""Cross-impl-shaped reproducer: revision:fetch-diff → tree:merge round-trip.

Context — workbench-go reports the follow chain `subscribe head →
revision:fetch-diff → tree:merge` converges 20/20 against Rust and 1/20
against Python, where the 1 success is the bootstrap (`base=zero`) and the
19 failures are incrementals (`base != zero`) returning 404
`snapshot_not_found` at wb-go's tree:merge.

This test isolates the question: does Python's own fetch-diff result
envelope round-trip cleanly through Python's own tree:merge for both
bootstrap and incrementals?

- If yes: the wire bytes Python emits are self-consistent under Python's
  reader, so the cross-impl gap is in wb-go's interpretation (Python
  produces what the spec says; wb-go's merge consumer is stricter than
  Python's loose unwrap). Routing goes to core-go.
- If no: Python's incremental envelope is structurally broken on its own
  terms — fix lives here. The failing assertion names which step.

Run: ``uv run pytest tests/integration/test_fetch_diff_merge_roundtrip.py -v``
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
from entity_handlers.tree import tree_handler


def _make_ctx(peer_id: str, handler_pattern: str) -> HandlerContext:
    """Build a standalone handler context (own cs/tree, permissive cap)."""
    cs = ContentStore()
    et = EntityTree(peer_id)
    emit = EmitPathway(cs, et)
    treg = TreeRegistry(et, cs)
    cap = {
        "grants": [
            {
                "handlers": {"include": ["*"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["*"]},
            }
        ]
    }
    return HandlerContext(
        local_peer_id=peer_id,
        remote_peer_id="remote",
        handler_grant=cap,
        caller_capability=cap,
        emit_pathway=emit,
        tree_registry=treg,
        handler_pattern=handler_pattern,
    )


async def _commit_one(ctx: HandlerContext, path: str, content: str) -> bytes:
    """Emit one leaf, commit a revision, return the new version hash."""
    ctx.emit_pathway.emit(path, Entity(type="test/file", data={"content": content}))
    r = await revision_handler(
        "system/revision", "commit", {"data": {"prefix": ""}}, ctx,
    )
    assert r["status"] == 200, r
    return r["result"]["data"]["version"]


async def _fetch_diff(ctx: HandlerContext, base: bytes | None) -> dict:
    """Call fetch-diff on `ctx`; return the result envelope (the typed wrap)."""
    params = {"prefix": ""}
    if base is not None:
        params["base"] = base
    r = await revision_handler(
        "system/revision", "fetch-diff", {"data": params}, ctx,
    )
    assert r["status"] == 200, r
    assert r["result"]["type"] == "system/envelope", r["result"]
    return r["result"]  # {"type": "system/envelope", "data": {root, included}}


async def _merge_on(receiver: HandlerContext, fetch_diff_result: dict) -> dict:
    """Feed the fetch-diff result envelope as source_envelope to tree:merge.

    Mirrors the chain framework: whatever fetch-diff returns as `result` is
    what gets bound to mergeReq.SourceEnvelope downstream.
    """
    # The chain framework binds the typed envelope to source_envelope.
    # Python's tree:merge unwraps system/envelope; this exercises that path.
    # Omit target_tree: receiver merges into the default tree (matches the
    # chain framework's default behavior).
    merge_params = {"source_envelope": fetch_diff_result}
    return await tree_handler(
        "system/tree", "merge", {"data": merge_params}, receiver,
    )


def _ingest_included(receiver: HandlerContext, env_result: dict) -> None:
    """Ingest all `included` entities into the receiver's content store.

    Simulates the receiver having absorbed prior closure(s) — required
    before an incremental fetch-diff result is interpretable.
    """
    inner = env_result["data"]
    included = inner.get("included", {})
    cs = receiver.emit_pathway.content_store
    for ent_dict in included.values():
        cs.put(Entity.from_dict(ent_dict))


class TestFetchDiffMergeRoundtrip:
    """Source emits revisions; receiver follows via fetch-diff + tree:merge."""

    @pytest.mark.asyncio
    async def test_bootstrap_only(self):
        """Single bootstrap (base=zero) → receiver merge succeeds."""
        source = _make_ctx("source", "system/revision")
        receiver = _make_ctx("receiver", "system/tree")

        await _commit_one(source, "data/a", "v1")

        env = await _fetch_diff(source, base=None)
        # `included` carries the snapshot's reachable closure; ingest before merge.
        _ingest_included(receiver, env)
        merge_result = await _merge_on(receiver, env)
        assert merge_result["status"] == 200, (
            f"\nBOOTSTRAP MERGE FAILED\n"
            f"  status: {merge_result['status']}\n"
            f"  result: {merge_result.get('result')}\n"
            f"  envelope inner keys: {list(env['data'].keys())}\n"
            f"  included count: {len(env['data'].get('included', {}))}\n"
            f"  root: {env['data']['root']}\n"
        )

    @pytest.mark.asyncio
    async def test_one_incremental(self):
        """Bootstrap then one incremental — the failing case in cross-impl."""
        source = _make_ctx("source", "system/revision")
        receiver = _make_ctx("receiver", "system/tree")

        v1 = await _commit_one(source, "data/a", "v1")

        # Step 1: bootstrap (base=zero).
        env_boot = await _fetch_diff(source, base=None)
        _ingest_included(receiver, env_boot)
        m1 = await _merge_on(receiver, env_boot)
        assert m1["status"] == 200, m1

        # Step 2: source advances; receiver follows with base=v1.
        await _commit_one(source, "data/a", "v2")
        env_inc = await _fetch_diff(source, base=v1)
        _ingest_included(receiver, env_inc)
        m2 = await _merge_on(receiver, env_inc)
        assert m2["status"] == 200, (
            f"INCREMENTAL MERGE FAILED: {m2}\n"
            f"  incremental envelope inner keys: "
            f"{list(env_inc['data'].keys())}\n"
            f"  included count: {len(env_inc['data'].get('included', {}))}\n"
            f"  root entity type: "
            f"{env_inc['data']['root'].get('type')!r}\n"
        )

    @pytest.mark.asyncio
    async def test_twenty_step_follow(self):
        """20-step chain mirroring the workbench-go probe (1 bootstrap + 19
        incrementals). Records pass/fail per step; reports the failure
        distribution exactly the way wb-go reported it (1/20 vs 19/20).
        """
        source = _make_ctx("source", "system/revision")
        receiver = _make_ctx("receiver", "system/tree")

        prev_version: bytes | None = None
        results: list[tuple[int, str, int]] = []  # (step, kind, status)

        for step in range(20):
            new_version = await _commit_one(source, "data/a", f"v{step+1}")
            kind = "bootstrap" if prev_version is None else "incremental"
            env = await _fetch_diff(source, base=prev_version)
            _ingest_included(receiver, env)
            merge_result = await _merge_on(receiver, env)
            results.append((step, kind, merge_result["status"]))
            # Next step: receiver advertises the version it just merged as
            # its known base. Matches the canonical follower 2-step chain.
            prev_version = new_version

        passes = sum(1 for _, _, s in results if s == 200)
        failures = [(i, k, s) for (i, k, s) in results if s != 200]
        assert passes == 20, (
            f"Follow chain converged {passes}/20 under Python↔Python "
            f"round-trip. Failures: {failures}\n"
            f"All steps: {results}"
        )

    @pytest.mark.asyncio
    async def test_notification_form_base_threading(self):
        """F-CIMP-7 reproducer — base threaded as `previous_hash` from the
        notification (not the raw version-entry hash).

        EXTENSION-SUBSCRIPTION notification carries ``previous_hash`` =
        content hash of the entity at the changed URI. For the canonical
        follow chain the URI is ``system/revision/<ph>/head``, whose
        stored entity is a ``system/hash`` wrapper around the version-
        entry hash — not the version entry itself.

        wb-go's diagnostic tap recorded 19/20 incrementals failing with
        ``base_not_a_version`` because Python's fetch-diff did not deref
        the wrapper (asymmetric with the target side which already does).
        """
        source = _make_ctx("source", "system/revision")

        # Make two commits, then derive the wrapper hash for v1 the same way
        # the subscription system would emit it as `previous_hash` after the
        # second commit advances the head path's stored entity.
        v1 = await _commit_one(source, "data/a", "v1")
        await _commit_one(source, "data/a", "v2")

        # The wrapper at the head URI is `{type: "system/hash", data: {"hash": v1}}`.
        # Its content hash is what `previous_hash` carries on the wire.
        v1_wrapper_hash = source.emit_pathway.content_store.put(
            Entity(type="system/hash", data={"hash": v1})
        )

        r = await revision_handler(
            "system/revision",
            "fetch-diff",
            {"data": {"prefix": "", "base": v1_wrapper_hash}},
            source,
        )
        assert r["status"] == 200, (
            "fetch-diff must accept the notification-form base (system/hash "
            "wrapper) symmetrically with how it derefs target=head. "
            f"Got: {r}"
        )
