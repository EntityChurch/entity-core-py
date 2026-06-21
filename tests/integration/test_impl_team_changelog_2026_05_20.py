"""Validation tests for the impl-team changelog (durability extraction).

One test (or a few) per cross-impl action item the changelog landed
behaviorally for Python:

- A.2 — Inbound dispatch concurrency (V7 v7.48 §4.8)
- A.3 — Version-transcription invariants (REVISION v3.2 §4.4.4 / §4.4.12)
- A.4 — Phase 4 dedupe-by-distinct-controller (IDENTITY v3.7 §6.0a)
- A.8 — Deletion markers (REVISION v3.1 + NATIVE-TYPE v4.2.0 §4.9)
- I-7 — Cap-signature → V7 invariant pointer (IDENTITY v3.6 §6.0e)
- I-8 — No-`on_error` forward-dispatch non-2xx marker (CONTINUATION v1.13)

These are integration-style: spin up the actual handler / pathway, drive
the behavior end-to-end, assert the observable state on disk / wire.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.trie import build_trie
from entity_core.types.deletion_marker import (
    CANONICAL_DELETION_MARKER_HASH,
    DELETION_MARKER_ENTITY,
    is_deletion_marker,
)
from entity_handlers.revision import (
    VERSION_ENTRY_TYPE,
    DELETION_RESOLUTION_REJECTED,
    DELETION_RESOLUTION_VALID,
    revision_handler,
    sorted_parents,
    validate_merge_config,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_handler_context(pattern: str = "system/revision") -> HandlerContext:
    kp = Keypair.generate()
    cs = ContentStore()
    tree = EntityTree(kp.peer_id)
    pathway = EmitPathway(cs, tree)
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
        local_peer_id=kp.peer_id,
        remote_peer_id=kp.peer_id,
        handler_grant=permissive,
        caller_capability=permissive,
        emit_pathway=pathway,
        handler_pattern=pattern,
        keypair=kp,
    )


# ---------------------------------------------------------------------------
# A.8 — Deletion markers (canonical hash + type definition)
# ---------------------------------------------------------------------------


class TestDeletionMarkerCanonical:
    def test_canonical_hash_matches_spec(self) -> None:
        """Per ENTITY-NATIVE-TYPE-SYSTEM v4.2.0 §4.9: any ECF-conforming
        impl MUST produce `ecf-sha256:689ae4...`. Asserted on import (in
        ``entity_core.types.deletion_marker``) and again here for the
        record."""
        assert CANONICAL_DELETION_MARKER_HASH.hex() == (
            "00689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6"
        ), "ECF-encoded zero-field type must hash to the spec-pinned value"
        assert (
            DELETION_MARKER_ENTITY.compute_hash() == CANONICAL_DELETION_MARKER_HASH
        )
        # CBOR empty map `0xa0` is the canonical encoding of zero-field
        # `data` — NOT `0x40` (empty bytes) and NOT `0xf6` (null).
        from entity_core.utils.ecf import ecf_encode
        assert ecf_encode({}).hex() == "a0"

    def test_is_deletion_marker_helper(self) -> None:
        assert is_deletion_marker(CANONICAL_DELETION_MARKER_HASH)
        assert not is_deletion_marker(None)
        assert not is_deletion_marker(b"\x00" + b"\x42" * 32)

    def test_type_registered_as_core(self) -> None:
        from entity_core.types.canonical import CORE_TYPE_PATHS
        from entity_core.types.definitions import get_all_type_entities

        assert "system/deletion-marker" in CORE_TYPE_PATHS
        names = {e.data.get("name") for e in get_all_type_entities()}
        assert "system/deletion-marker" in names


# ---------------------------------------------------------------------------
# A.8 — merge-config deletion_resolution validation (Amendment 4)
# ---------------------------------------------------------------------------


class TestMergeConfigValidation:
    @pytest.mark.parametrize("rejected", DELETION_RESOLUTION_REJECTED)
    def test_rejects_lww_and_keep_both(self, rejected: str) -> None:
        """§2.3 Amendment 4 §217–219: lww and keep-both MUST be rejected
        at config-write time with `invalid_strategy`."""
        errors = validate_merge_config({"deletion_resolution": rejected})
        assert errors, f"deletion_resolution={rejected!r} must be rejected"
        assert "invalid_strategy" in errors[0]

    @pytest.mark.parametrize("ok", DELETION_RESOLUTION_VALID)
    def test_accepts_valid_strategies(self, ok: str) -> None:
        assert validate_merge_config({"deletion_resolution": ok}) == []

    def test_absent_field_is_valid(self) -> None:
        assert validate_merge_config({"pattern": "*"}) == []

    def test_unknown_value_is_rejected(self) -> None:
        errors = validate_merge_config(
            {"deletion_resolution": "made-up-strategy"}
        )
        assert errors and "unknown" in errors[0]


# ---------------------------------------------------------------------------
# A.8 — Commit-time marker emission (§6.1 Amendment 2)
# ---------------------------------------------------------------------------


class TestCommitTimeMarkerEmission:
    @pytest.mark.asyncio
    async def test_unbound_parent_path_gets_marker_in_new_version(self) -> None:
        """At commit, every path bound in parent's trie MUST have an
        explicit entry in the new version's trie: live binding if still
        bound, or the canonical deletion marker if unbound."""
        ctx = _make_handler_context()
        pathway = ctx.emit_pathway

        pathway.emit(
            "data/keep.txt",
            Entity(type="test/file", data={"v": 1}),
            EmitContext.bootstrap(),
        )
        pathway.emit(
            "data/gone.txt",
            Entity(type="test/file", data={"v": 1}),
            EmitContext.bootstrap(),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, ctx,
        )
        assert r1["status"] == 200

        # Unbind `data/gone.txt` directly at the tree layer (skipping
        # auto-version — we want to assert manual-commit behavior).
        pathway.entity_tree.remove(
            pathway.entity_tree.normalize_uri("data/gone.txt"),
        )

        r2 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, ctx,
        )
        assert r2["status"] == 200

        # The new version's trie MUST bind the canonical marker at the
        # unbound path. We assert by walking the version's bindings.
        v2 = r2["result"]["data"]["version"]
        from entity_handlers.revision import _get_version_bindings  # noqa: PLC0415
        v2_bindings = _get_version_bindings(ctx, v2) or {}
        assert v2_bindings.get("data/gone.txt") == CANONICAL_DELETION_MARKER_HASH
        # The retained path keeps its live binding (no marker).
        assert "data/keep.txt" in v2_bindings
        assert not is_deletion_marker(v2_bindings["data/keep.txt"])


# ---------------------------------------------------------------------------
# A.8 — Apply translation (§4.4.4 Amendment 3): marker → live unbind
# ---------------------------------------------------------------------------


class TestApplyTranslation:
    @pytest.mark.asyncio
    async def test_checkout_marker_translates_to_unbind(self) -> None:
        """A version whose trie binds the canonical marker at a path MUST,
        on checkout, translate to a live-tree unbind — the marker MUST
        NOT appear in the live location index."""
        ctx = _make_handler_context()
        pathway = ctx.emit_pathway

        # Commit v1 with two paths bound.
        pathway.emit(
            "data/keep.txt",
            Entity(type="test/file", data={"v": 1}),
            EmitContext.bootstrap(),
        )
        pathway.emit(
            "data/gone.txt",
            Entity(type="test/file", data={"v": 1}),
            EmitContext.bootstrap(),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, ctx,
        )
        v1 = r1["result"]["data"]["version"]

        # Now delete gone.txt and commit v2 — v2's trie should have the
        # marker bound at data/gone.txt.
        pathway.entity_tree.remove(
            pathway.entity_tree.normalize_uri("data/gone.txt"),
        )
        r2 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, ctx,
        )
        v2 = r2["result"]["data"]["version"]

        # Manually re-bind data/gone.txt at the tree (simulating live
        # state where the path exists) — checkout v2 should unbind it.
        pathway.emit(
            "data/gone.txt",
            Entity(type="test/file", data={"v": "manual-restore"}),
            EmitContext.bootstrap(),
        )
        gone_uri = pathway.entity_tree.normalize_uri("data/gone.txt")
        assert pathway.entity_tree.get(gone_uri) is not None

        co = await revision_handler(
            "system/revision", "checkout",
            {"data": {"prefix": "", "version": v2}},
            ctx,
        )
        assert co["status"] == 200

        # Live invariant: the marker hash MUST NOT be the live binding.
        live_binding = pathway.entity_tree.get(gone_uri)
        assert live_binding != CANONICAL_DELETION_MARKER_HASH, (
            "deletion marker leaked into the live location index"
        )
        assert live_binding is None, (
            "marker binding in v2's trie must translate to a live unbind"
        )


# ---------------------------------------------------------------------------
# A.3 — Version-transcription invariants
# ---------------------------------------------------------------------------


class TestTranscriptionInvariants:
    @pytest.mark.asyncio
    async def test_checkout_force_state_removes_source_only_paths(self) -> None:
        """Validator's `checkout_file3_removed` contract: checkout is a
        force-state operation, not auto-converge. Paths present in the
        source-version's trie but absent from the target-version's trie
        MUST be unbound from the live tree. (Paths in neither version
        are preserved — that's tested separately below.)"""
        ctx = _make_handler_context()
        pathway = ctx.emit_pathway

        # v1: tracked.txt + file3 bound.
        pathway.emit(
            "data/tracked.txt",
            Entity(type="test/file", data={"v": 1}),
            EmitContext.bootstrap(),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, ctx,
        )
        v1 = r1["result"]["data"]["version"]

        # v2: add file3.
        pathway.emit(
            "data/file3.txt",
            Entity(type="test/file", data={"v": 2}),
            EmitContext.bootstrap(),
        )
        r2 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, ctx,
        )
        assert r2["status"] == 200

        # Checkout v1. file3 is present in source (v2) but not target (v1).
        co = await revision_handler(
            "system/revision", "checkout",
            {"data": {"prefix": "", "version": v1}},
            ctx,
        )
        assert co["status"] == 200

        # FORCE-STATE: file3 MUST be unbound.
        file3_uri = pathway.entity_tree.normalize_uri("data/file3.txt")
        assert pathway.entity_tree.get(file3_uri) is None, (
            "checkout MUST unbind paths in source-version but absent "
            "from target-version (force-state semantics, REVISION v3.2 "
            "§4.4.12 — Python validator's `checkout_file3_removed`)"
        )

    @pytest.mark.asyncio
    async def test_checkout_preserves_in_flight_writes(self) -> None:
        """Per REVISION v3.2 §4.4.12 (A.3): checkout MUST NOT wipe live
        paths that are outside the target version's purview. Operations
        transcribing a version into the live tree only touch paths the
        version itself names — in-flight unversioned writes (pending AV
        capture, untracked paths, prior app state) are preserved."""
        ctx = _make_handler_context()
        pathway = ctx.emit_pathway

        pathway.emit(
            "data/tracked.txt",
            Entity(type="test/file", data={"v": 1}),
            EmitContext.bootstrap(),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, ctx,
        )
        v1 = r1["result"]["data"]["version"]

        # Simulate an unversioned in-flight write OUTSIDE the version's
        # scope. Under pre-A.3 semantics checkout would wipe it.
        pathway.emit(
            "data/in-flight.txt",
            Entity(type="test/file", data={"content": "untracked"}),
            EmitContext.bootstrap(),
        )

        co = await revision_handler(
            "system/revision", "checkout",
            {"data": {"prefix": "", "version": v1}},
            ctx,
        )
        assert co["status"] == 200

        # In-flight write MUST survive checkout.
        in_flight_uri = pathway.entity_tree.normalize_uri("data/in-flight.txt")
        assert pathway.entity_tree.get(in_flight_uri) is not None, (
            "checkout wiped an in-flight live write outside the version's "
            "purview — violates v3.2 §4.4.12 transcription invariant"
        )

    @pytest.mark.asyncio
    async def test_fast_forward_preserves_in_flight_writes(self) -> None:
        """REVISION v3.2 §4.4.4: fast-forward (BEHIND branch) uses the
        committed-local-head trie as baseline, not the live tree."""
        ctx = _make_handler_context()
        pathway = ctx.emit_pathway
        cs = pathway.content_store

        # Commit v1.
        pathway.emit(
            "data/shared.txt",
            Entity(type="test/file", data={"v": 1}),
            EmitContext.bootstrap(),
        )
        r1 = await revision_handler(
            "system/revision", "commit", {"data": {"prefix": ""}}, ctx,
        )
        v1 = r1["result"]["data"]["version"]

        # Hand-construct a remote v2 descending from v1 with a single
        # new path bound.
        v1_entity = cs.get(v1)
        from entity_core.storage.trie import collect_all_bindings  # noqa: PLC0415
        base_bindings = dict(collect_all_bindings(v1_entity.data["root"], "", cs))
        new_h = cs.put(Entity(type="test/file", data={"v": "added"}))
        remote_bindings = dict(base_bindings)
        remote_bindings["data/added.txt"] = new_h
        remote_root = build_trie(sorted(remote_bindings.items()), cs)
        v2 = cs.put(Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": remote_root, "parents": sorted_parents([v1])},
        ))

        # In-flight unversioned write before the FF.
        pathway.emit(
            "data/in-flight.txt",
            Entity(type="test/file", data={"content": "untracked"}),
            EmitContext.bootstrap(),
        )

        result = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": v2}},
            ctx,
        )
        assert result["result"]["data"]["status"] == "fast_forward"
        # In-flight write survives.
        in_flight_uri = pathway.entity_tree.normalize_uri("data/in-flight.txt")
        assert pathway.entity_tree.get(in_flight_uri) is not None


# ---------------------------------------------------------------------------
# I-8 — CONTINUATION lost-error marker (v1.20 §3.10: code-as-reason)
# ---------------------------------------------------------------------------


class TestContinuationLostErrorForwardNon2xxE2E:
    """Mirrors the Go validator's `no_onerror_marker_bound` probe (the
    Python WARN). Forward continuation with no `on_error`, real
    dispatcher, target returns a handler-level non-2xx. The v1.20 marker
    MUST fire under the same chain_id the probe used.

    v1.19 §3.10.5: ``{reason}`` IS ``result.data.code`` verbatim (replaces
    the v1.13 ``forward_dispatch_non2xx`` catch-all). v1.20 §3.10.1:
    terminal ``{marker_hash}`` segment for per-occurrence addressing.
    """

    @pytest.mark.asyncio
    async def test_validator_style_unknown_op_probe_binds_marker(self) -> None:
        """End-to-end via the actual peer + dispatcher. Install a forward
        continuation with no on_error, target=system/tree,
        op=no_such_op_for_v113_probe; advance; the marker MUST land under
        ``system/runtime/chain-errors/lost/{chain_id}/{step_index}/{reason}/{marker_hash}``
        where ``{reason}`` is the canonical handler-emitted code (not the
        deprecated v1.13 catch-all)."""
        from entity_core.peer import PeerBuilder
        from entity_core.capability.grant import create_full_access_grant

        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
            .build()
        )

        # Build a dispatch_capability that grants full access (so the
        # cap check doesn't short-circuit before reaching the handler).
        from entity_core.protocol.auth import create_identity_entity
        identity = create_identity_entity(peer.keypair)
        identity_hash = identity.compute_hash()
        cap_entity = Entity(
            type="system/capability/token",
            data={
                "grants": [
                    {
                        "handlers": {"include": ["*"]},
                        "resources": {"include": ["*"]},
                        "operations": {"include": ["*"]},
                    }
                ],
                "granter": identity_hash,
                "grantee": identity_hash,
                "created_at": 0,
            },
        )
        cap_hash = peer.content_store.put(cap_entity)
        peer.content_store.put(identity)

        # Install a forward continuation directly into the tree (avoids
        # going through the full install/auth chain for this probe).
        cont_path = "system/inbox/v113-probe"
        cont = Entity(
            type="system/continuation",
            data={
                "target": "system/tree",
                "operation": "no_such_op_for_v113_probe",
                "params": {},
                "dispatch_capability": cap_hash,
                "remaining_executions": 1,
                # No on_error — the I-8 / v1.13 case.
            },
        )
        peer.emit_pathway.emit(cont_path, cont, EmitContext.bootstrap())

        # Manually invoke _handle_advance via the continuation handler
        # entry point. The HandlerContext mirrors what peer._handle_execute
        # would build — including request_id and chain_id.
        from entity_handlers.continuation import continuation_handler

        permissive = {
            "grants": [
                {
                    "handlers": {"include": ["*"]},
                    "resources": {"include": ["*"]},
                    "operations": {"include": ["*"]},
                }
            ]
        }

        # Bind a dispatcher onto the context (mirror peer's wiring).
        async def real_dispatcher(uri, op, params, cap, bounds, chain_id,
                                   resource_targets=None, **kwargs):
            # Reuse the peer's dispatcher.
            return await peer._dispatch_local_execute(
                uri, op, params, cap, bounds, chain_id,
                resource_targets, **kwargs,
            )

        ctx = HandlerContext(
            local_peer_id=peer.peer_id,
            remote_peer_id=peer.peer_id,
            handler_grant=permissive,
            caller_capability=permissive,
            emit_pathway=peer.emit_pathway,
            chain_id="validate-probe-chain",
            request_id="validate-probe-req-1",
            resource_targets=[cont_path],
            handler_pattern="system/continuation",
            keypair=peer.keypair,
            _execute_dispatcher=real_dispatcher,
        )

        r = await continuation_handler(
            "system/continuation", "advance", {"data": {}}, ctx,
        )
        # advance itself returns 200 regardless of downstream status —
        # forward dispatch is fire-and-forget.
        assert r["status"] == 200, r

        # The marker MUST be bound under chain_id="validate-probe-chain".
        prefix = peer.emit_pathway.entity_tree.normalize_uri(
            "system/runtime/chain-errors/lost/validate-probe-chain/",
        )
        matches = peer.emit_pathway.entity_tree.list_prefix(prefix)
        assert matches, (
            f"v1.13 marker did not fire under {prefix} — predicate or "
            "binding site issue (validator's no_onerror_marker_bound WARN)"
        )

        # The marker entity MUST carry reason matching the canonical
        # handler-emitted code (v1.19 §3.10.5 single-rule: {reason} IS
        # result.data.code). The default-storage handler's
        # `unknown_operation` code is what reaches the marker — NOT the
        # v1.13 catch-all `forward_dispatch_non2xx` (deprecated by v1.19).
        marker_uri = matches[0]
        marker_hash = peer.emit_pathway.entity_tree.get(marker_uri)
        marker = peer.emit_pathway.content_store.get(marker_hash)
        assert marker is not None
        assert marker.type == "system/runtime/chain-error-lost"
        reason_value = marker.data.get("reason")
        # Whatever code the handler emitted at the per-handler appendix
        # surfaces here verbatim — assert it's NOT the deprecated catch-all.
        assert reason_value != "forward_dispatch_non2xx", (
            "v1.13 catch-all 'forward_dispatch_non2xx' regression: v1.19 "
            "§3.10.5 deprecated it in favor of code-as-reason (each handler's "
            "actual emitted code becomes {reason}). See proposal §1.2b + "
            "EXTENSION-CONTINUATION v1.19 §3.10.5."
        )
        # v1.20 §3.10.1 path scheme: .../{step_index}/{reason}/{marker_hash}.
        # step_index is the original request_id (v1.14); reason and
        # marker_hash are siblings under the (chain_id, step_index) prefix.
        assert f"/validate-probe-req-1/{reason_value}/" in marker_uri, (
            f"v1.20 path MUST contain /{{request_id}}/{{reason}}/{{marker_hash}}; "
            f"got {marker_uri}"
        )


class TestContinuationLostErrorForwardNon2xx:
    @pytest.mark.asyncio
    async def test_forward_dispatch_non2xx_binds_marker(self) -> None:
        """EXTENSION-CONTINUATION v1.19 §3.10.5 + v1.20 §3.10.1: a
        forward continuation whose target returns ≥400 with NO on_error
        configured MUST bind a lost marker. {reason} IS the response's
        result.data.code verbatim (replaces the v1.13
        `forward_dispatch_non2xx` catch-all). Each distinct observation
        lands at its own path (terminal {marker_hash} per v1.20)."""
        from entity_handlers.continuation import (
            LOST_ERROR_MARKER_TYPE,
            _advance_forward,
        )

        ctx = _make_handler_context()

        async def _stub_dispatch(*args: Any, **kwargs: Any) -> ExecuteResult:
            return ExecuteResult(
                status=503,
                result={"type": "system/protocol/error",
                        "data": {"code": "service_unavailable"}},
            )

        ctx.execute_with_capability = _stub_dispatch  # type: ignore[method-assign]
        ctx.chain_id = "test-chain"  # type: ignore[attr-defined]

        # Capability entity is required by the dispatch path; put one
        # into the content store so dispatch_capability resolves.
        cap = Entity(type="system/capability/token", data={
            "grants": [{"path": "*", "ops": ["*"]}],
            "granter": b"\x00" + b"\x00" * 32,
            "grantee": b"\x00" + b"\x01" * 32,
            "created_at": 0,
        })
        cap_hash = ctx.emit_pathway.content_store.put(cap)

        cont_data = {
            "target": "remote/handler",
            "operation": "do",
            "params": {"v": 1},
            "remaining_executions": 1,
            "dispatch_capability": cap_hash,
            # No on_error configured — the I-8 case.
        }

        await _advance_forward(
            cont_data=cont_data,
            result={"data": {}},
            status=200,
            continuation_path="cont-test",
            full_uri="/peer/cont-test",
            content_hash=b"\x00" + b"\x02" * 32,
            ctx=ctx,
        )

        # The marker MUST appear in the tree under chain-errors/lost.
        prefix = ctx.emit_pathway.entity_tree.normalize_uri(
            "system/runtime/chain-errors/lost/test-chain/",
        )
        matches = ctx.emit_pathway.entity_tree.list_prefix(prefix)
        assert matches, (
            "no lost marker bound for the non-2xx response — v1.19 §3.10.5 "
            "requires bind under code-as-reason path"
        )
        marker_uri = matches[0]
        marker_hash = ctx.emit_pathway.entity_tree.get(marker_uri)
        marker = ctx.emit_pathway.content_store.get(marker_hash)
        assert marker is not None
        assert marker.type == LOST_ERROR_MARKER_TYPE
        # v1.19 §3.10.5: {reason} IS the response's result.data.code.
        # Stub returned code=`service_unavailable`; the marker carries it
        # verbatim — NOT the deprecated `forward_dispatch_non2xx` catch-all.
        assert marker.data.get("reason") == "service_unavailable", marker.data
        # v1.20 §3.10.1 path scheme: terminal {marker_hash} segment.
        assert "/service_unavailable/" in marker_uri, marker_uri
        # §3.10.6 body-fields registry: reserved field is `status` (was
        # `original_status` in pre-v1.19 Python).
        assert marker.data.get("status") == 503


# ---------------------------------------------------------------------------
# A.2 — Inbound dispatch concurrency (V7 v7.48 §4.8)
# ---------------------------------------------------------------------------


class TestMergeConfigOperation:
    """EXTENSION-REVISION v3.3 §4.4.18: `merge-config` is the canonical
    write path. The op enforces the §2.3 strategy-rejection contract at
    config-write time — `lww`/`keep-both` for `deletion_resolution` MUST
    surface as 400 `invalid_strategy` before any binding lands."""

    @pytest.mark.asyncio
    async def test_op_rejects_lww_deletion_resolution(self) -> None:
        ctx = _make_handler_context()
        r = await revision_handler(
            "system/revision", "merge-config",
            {"data": {
                "scope": "path",
                "name": "shared-lock",
                "action": "set",
                "config": {
                    "type": "system/revision/merge-config",
                    "data": {
                        "pattern": "**/*.lock",
                        "strategy": "source-wins",
                        "deletion_resolution": "lww",
                    },
                },
            }},
            ctx,
        )
        assert r["status"] == 400, r
        assert r["result"]["data"]["code"] == "invalid_strategy"
        assert "lww" in r["result"]["data"]["message"]
        # No binding landed.
        tree = ctx.emit_pathway.entity_tree
        assert tree.get(tree.normalize_uri(
            "system/revision/config/merge/path/shared-lock"
        )) is None

    @pytest.mark.asyncio
    async def test_op_rejects_keep_both_deletion_resolution(self) -> None:
        ctx = _make_handler_context()
        r = await revision_handler(
            "system/revision", "merge-config",
            {"data": {
                "scope": "path",
                "name": "docs",
                "action": "set",
                "config": {
                    "type": "system/revision/merge-config",
                    "data": {
                        "pattern": "docs/**",
                        "strategy": "three-way",
                        "deletion_resolution": "keep-both",
                    },
                },
            }},
            ctx,
        )
        assert r["status"] == 400, r
        assert r["result"]["data"]["code"] == "invalid_strategy"

    @pytest.mark.asyncio
    async def test_op_accepts_all_valid_deletion_resolutions(self) -> None:
        for dr in (
            "preserve-on-conflict", "deletion-wins",
            "three-way-fallthrough", "deterministic",
        ):
            ctx = _make_handler_context()
            r = await revision_handler(
                "system/revision", "merge-config",
                {"data": {
                    "scope": "path",
                    "name": f"dr-{dr}",
                    "action": "set",
                    "config": {
                        "type": "system/revision/merge-config",
                        "data": {
                            "pattern": f"dr-{dr}/**",
                            "strategy": "three-way",
                            "deletion_resolution": dr,
                        },
                    },
                }},
                ctx,
            )
            assert r["status"] == 200, (dr, r)
            data = r["result"]["data"]
            assert data["status"] == "set"
            assert data["path"] == f"system/revision/config/merge/path/dr-{dr}"

    @pytest.mark.asyncio
    async def test_op_idempotent_set_returns_no_change(self) -> None:
        ctx = _make_handler_context()
        cfg_data = {
            "scope": "path",
            "name": "idem",
            "action": "set",
            "config": {
                "type": "system/revision/merge-config",
                "data": {
                    "pattern": "idem/**",
                    "strategy": "three-way",
                    "deletion_resolution": "preserve-on-conflict",
                },
            },
        }
        r1 = await revision_handler(
            "system/revision", "merge-config", {"data": cfg_data}, ctx,
        )
        assert r1["status"] == 200
        assert r1["result"]["data"]["status"] == "set"
        first_hash = r1["result"]["data"]["hash"]
        r2 = await revision_handler(
            "system/revision", "merge-config", {"data": cfg_data}, ctx,
        )
        assert r2["status"] == 200
        assert r2["result"]["data"]["status"] == "no_change"
        assert r2["result"]["data"]["hash"] == first_hash

    @pytest.mark.asyncio
    async def test_op_accepts_per_type_scope(self) -> None:
        ctx = _make_handler_context()
        r = await revision_handler(
            "system/revision", "merge-config",
            {"data": {
                "scope": "type",
                "name": "app/note",
                "action": "set",
                "config": {
                    "type": "system/revision/merge-config",
                    "data": {"strategy": "source-wins"},
                },
            }},
            ctx,
        )
        assert r["status"] == 200, r
        assert r["result"]["data"]["status"] == "set"
        assert r["result"]["data"]["path"] == (
            "system/revision/config/merge/type/app/note"
        )

    @pytest.mark.asyncio
    async def test_op_deletes_merge_config(self) -> None:
        ctx = _make_handler_context()
        await revision_handler(
            "system/revision", "merge-config",
            {"data": {
                "scope": "path",
                "name": "x",
                "action": "set",
                "config": {
                    "type": "system/revision/merge-config",
                    "data": {"pattern": "x/**", "strategy": "source-wins"},
                },
            }},
            ctx,
        )
        r = await revision_handler(
            "system/revision", "merge-config",
            {"data": {"scope": "path", "name": "x", "action": "delete"}},
            ctx,
        )
        assert r["status"] == 200, r
        assert r["result"]["data"]["status"] == "deleted"
        tree = ctx.emit_pathway.entity_tree
        assert tree.get(tree.normalize_uri(
            "system/revision/config/merge/path/x"
        )) is None

    @pytest.mark.asyncio
    async def test_op_cas_guard_rejects_stale_hash(self) -> None:
        ctx = _make_handler_context()
        r = await revision_handler(
            "system/revision", "merge-config",
            {"data": {
                "scope": "path",
                "name": "guarded",
                "action": "set",
                "config": {
                    "type": "system/revision/merge-config",
                    "data": {"pattern": "guarded/**", "strategy": "three-way"},
                },
                "expected_hash": b"\x00" + b"\xff" * 32,
            }},
            ctx,
        )
        assert r["status"] == 409, r
        assert r["result"]["data"]["code"] == "stale_expected_hash"

    @pytest.mark.asyncio
    async def test_op_rejects_invalid_scope(self) -> None:
        ctx = _make_handler_context()
        r = await revision_handler(
            "system/revision", "merge-config",
            {"data": {
                "scope": "neither",
                "name": "x",
                "action": "set",
                "config": {
                    "type": "system/revision/merge-config",
                    "data": {"strategy": "source-wins"},
                },
            }},
            ctx,
        )
        assert r["status"] == 400, r
        assert r["result"]["data"]["code"] == "invalid_scope"


class TestOscillationFullIdentity:
    """REVISION v3.2 invariant 3 (A.3): oscillation is detected on the
    full identity `{root, sorted_parents}`, NOT root alone. Same root +
    different parents is a legitimate cross-link version (CRDT
    convergence) and MUST NOT be flagged as oscillation."""

    def test_same_root_different_parents_is_not_oscillation(self) -> None:
        from entity_handlers.revision import (
            VERSION_ENTRY_TYPE,
            _detect_oscillation,
        )

        ctx = _make_handler_context()
        cs = ctx.emit_pathway.content_store
        shared_root = b"\x00" + b"\xaa" * 32

        # An existing version with this root and one parent set.
        existing = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": shared_root, "parents": [b"\x00" + b"\x01" * 32]},
        )
        existing_hash = cs.put(existing)

        # Propose a NEW version with same root but DIFFERENT parents.
        # Pre-v3.2 (root-only compare) would flag this as oscillation;
        # under v3.2 it MUST be allowed as legitimate cross-link.
        assert _detect_oscillation(
            ctx, shared_root, existing_hash,
            proposed_parents=[b"\x00" + b"\x02" * 32],
        ) is False

    def test_same_root_same_parents_is_oscillation(self) -> None:
        from entity_handlers.revision import (
            VERSION_ENTRY_TYPE,
            _detect_oscillation,
        )

        ctx = _make_handler_context()
        cs = ctx.emit_pathway.content_store
        shared_root = b"\x00" + b"\xbb" * 32
        parents = [b"\x00" + b"\x03" * 32, b"\x00" + b"\x04" * 32]

        existing = Entity(
            type=VERSION_ENTRY_TYPE,
            data={"root": shared_root, "parents": parents},
        )
        existing_hash = cs.put(existing)

        # Full identity match → true oscillation.
        assert _detect_oscillation(
            ctx, shared_root, existing_hash,
            proposed_parents=parents,
        ) is True


class TestInboundConcurrency:
    def test_peer_constructs_inbound_semaphore_lazily(self) -> None:
        """A.2 semaphore is created in the running loop on first use —
        unit-level sanity that the wiring exists."""
        from entity_core.peer import PeerBuilder
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .build()
        )
        assert peer._inbound_semaphore_obj is None
        assert peer._inbound_semaphore_size >= 1

        async def _check() -> None:
            sem = peer._inbound_sem()
            assert isinstance(sem, asyncio.Semaphore)
            assert peer._inbound_sem() is sem  # idempotent

        asyncio.run(_check())

    def test_conn_state_write_lock_lazy(self) -> None:
        """Per-connection write lock initialized inside the loop."""
        from entity_core.peer.peer import PeerConnectionState
        state = PeerConnectionState()
        assert state.write_lock is None

        async def _check() -> None:
            lock = state.get_write_lock()
            assert isinstance(lock, asyncio.Lock)
            assert state.get_write_lock() is lock  # idempotent

        asyncio.run(_check())
