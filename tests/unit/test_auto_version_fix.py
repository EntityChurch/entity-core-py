"""Tests for PROPOSAL-REVISION-AUTO-VERSION-FIX (EXTENSION-REVISION v2.4→v2.5,
EXTENSION-TREE v3.8→v3.9).

Covers Groups A/B/C/E of the proposal:
  A. Config shape: auto_sync/remotes removed; merge_order default flipped;
     checkout_under_auto_version added.
  B. Multi-path operation ordering (head advance BEFORE binding application)
     in merge, checkout, cherry-pick, revert.
  C. Canonical tracked-root storage path substitution.
  E. validate_revision_config() rejects configs with auto_version: true
     whose prefix encompasses required-exclude paths without those excludes.
"""

from __future__ import annotations

import pytest

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.tree_registry import TreeRegistry
from entity_core.types.definitions import type_system_revision_config
from entity_handlers.revision import (
    REQUIRED_EXCLUDE_PATHS,
    _compute_prefix_hash,
    _head_path,
    _normalize_merge_sides,
    revision_handler,
    validate_revision_config,
)
from entity_handlers.root_tracker import TrackingConfig, _root_binding_path


# =============================================================================
# Group A — config shape
# =============================================================================


class TestRevisionConfigShape:
    def test_auto_sync_removed(self):
        fields = type_system_revision_config().data["fields"]
        assert "auto_sync" not in fields

    def test_remotes_removed(self):
        fields = type_system_revision_config().data["fields"]
        assert "remotes" not in fields

    def test_checkout_under_auto_version_present(self):
        fields = type_system_revision_config().data["fields"]
        assert "checkout_under_auto_version" in fields

    def test_merge_order_default_is_deterministic(self):
        # Distinct-prefix hashes: caller-perspective keeps them in the caller's
        # order; deterministic swaps to lower-hash-first. The default is
        # exercised via _normalize_merge_sides caller — but the effective
        # default lives in _handle_merge's config.get fallback, which we
        # verify by reading the module source at lines around merge handling.
        import entity_handlers.revision as rev
        import inspect
        src = inspect.getsource(rev._handle_merge)
        assert 'merge_order", "deterministic"' in src


# =============================================================================
# Group B — head advance BEFORE bindings
# =============================================================================


@pytest.fixture
def content_store() -> ContentStore:
    return ContentStore()


@pytest.fixture
def entity_tree() -> EntityTree:
    return EntityTree("test-peer")


@pytest.fixture
def emit_pathway(content_store, entity_tree) -> EmitPathway:
    return EmitPathway(content_store, entity_tree)


@pytest.fixture
def tree_registry(entity_tree, content_store) -> TreeRegistry:
    return TreeRegistry(entity_tree, content_store)


@pytest.fixture
def handler_context(emit_pathway, tree_registry) -> HandlerContext:
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
        tree_registry=tree_registry,
        handler_pattern="system/revision",
    )


async def _commit(ctx, prefix=""):
    res = await revision_handler(
        "system/revision", "commit", {"data": {"prefix": prefix}}, ctx,
    )
    assert res["status"] == 200
    return res["result"]["data"]["version"]


class TestOrderingHooks:
    """The structural rule (§6A): head advance MUST precede binding application.

    We verify by attaching an emit-path hook that records the sequence of
    writes and checking that `system/revision/head/...` appears before any
    non-revision tree write within the same operation.
    """

    @pytest.fixture
    def recorder(self, emit_pathway):
        events: list[str] = []

        class _Recorder:
            def on_change_sync(self, event):
                events.append(event.uri)

        emit_pathway._add_internal_hook(_Recorder())
        return events

    @pytest.mark.asyncio
    async def test_merge_fast_forward_head_before_bindings(
        self, handler_context, emit_pathway, recorder,
    ):
        # Peer A has no commits. Peer B has one commit with a file.
        # Simulate by crafting a version on peer A with one file, then
        # resetting head and merging back.
        entity = Entity(type="test/file", data={"content": "v1"})
        emit_pathway.emit("data/f.txt", entity)
        source_hash = await _commit(handler_context, "")

        # Clear HEAD to simulate "no local commits" fast-forward path.
        head_uri = emit_pathway.entity_tree.normalize_uri(
            _head_path(_compute_prefix_hash(handler_context, ""))
        )
        emit_pathway.entity_tree.remove(head_uri)
        # Clear data too so the fast-forward actually applies bindings.
        emit_pathway.entity_tree.remove(
            emit_pathway.entity_tree.normalize_uri("data/f.txt")
        )

        recorder.clear()
        res = await revision_handler(
            "system/revision", "merge",
            {"data": {"prefix": "", "remote_version": source_hash}},
            handler_context,
        )
        assert res["status"] == 200

        head_idx = next(
            i for i, u in enumerate(recorder) if "system/revision/" in u and "/head" in u
        )
        data_idx = next(
            (i for i, u in enumerate(recorder) if "/data/f.txt" in u), None
        )
        if data_idx is not None:
            assert head_idx < data_idx, (
                "head advance must precede binding application"
            )

    @pytest.mark.asyncio
    async def test_checkout_head_before_bindings(
        self, handler_context, emit_pathway, recorder,
    ):
        # Create two versions with different file contents.
        emit_pathway.emit("data/f.txt", Entity(type="test/file", data={"c": "a"}))
        v1 = await _commit(handler_context, "")
        emit_pathway.emit("data/f.txt", Entity(type="test/file", data={"c": "b"}))
        v2 = await _commit(handler_context, "")
        assert v1 != v2

        recorder.clear()
        res = await revision_handler(
            "system/revision", "checkout",
            {"data": {"prefix": "", "version": v1}}, handler_context,
        )
        assert res["status"] == 200

        head_idx = next(
            i for i, u in enumerate(recorder) if "system/revision/" in u and "/head" in u
        )
        data_idx = next(
            (i for i, u in enumerate(recorder) if "/data/f.txt" in u), None
        )
        if data_idx is not None:
            assert head_idx < data_idx

    @pytest.mark.asyncio
    async def test_cherry_pick_head_before_bindings(
        self, handler_context, emit_pathway, recorder,
    ):
        emit_pathway.emit("data/a.txt", Entity(type="test/file", data={"c": "a"}))
        await _commit(handler_context, "")
        emit_pathway.emit("data/b.txt", Entity(type="test/file", data={"c": "b"}))
        v2 = await _commit(handler_context, "")

        # Remove b.txt and cherry-pick it back.
        emit_pathway.entity_tree.remove(
            emit_pathway.entity_tree.normalize_uri("data/b.txt")
        )
        await _commit(handler_context, "")

        recorder.clear()
        res = await revision_handler(
            "system/revision", "cherry-pick",
            {"data": {"prefix": "", "version": v2}}, handler_context,
        )
        assert res["status"] == 200

        head_idx = next(
            i for i, u in enumerate(recorder) if "system/revision/" in u and "/head" in u
        )
        data_idx = next(
            (i for i, u in enumerate(recorder) if "/data/b.txt" in u), None
        )
        if data_idx is not None:
            assert head_idx < data_idx

    @pytest.mark.asyncio
    async def test_revert_head_before_bindings(
        self, handler_context, emit_pathway, recorder,
    ):
        emit_pathway.emit("data/a.txt", Entity(type="test/file", data={"c": "a"}))
        await _commit(handler_context, "")
        emit_pathway.emit("data/a.txt", Entity(type="test/file", data={"c": "b"}))
        v2 = await _commit(handler_context, "")

        recorder.clear()
        res = await revision_handler(
            "system/revision", "revert",
            {"data": {"prefix": "", "version": v2}}, handler_context,
        )
        assert res["status"] == 200

        head_idx = next(
            i for i, u in enumerate(recorder) if "system/revision/" in u and "/head" in u
        )
        data_idx = next(
            (i for i, u in enumerate(recorder) if "/data/a.txt" in u), None
        )
        if data_idx is not None:
            assert head_idx < data_idx


# =============================================================================
# Group C — tracked-root storage path canonicalization
# =============================================================================


class TestTrackedRootPath:
    def test_universal_tree_prefix(self):
        assert _root_binding_path("/") == "system/tree/root"

    def test_peer_relative_subtree(self):
        assert _root_binding_path("project/") == "system/tree/root/project"

    def test_nested_subtree(self):
        assert _root_binding_path("project/src/") == "system/tree/root/project/src"

    def test_peer_qualified(self):
        assert _root_binding_path("/alice/data/") == "system/tree/root/alice/data"

    def test_tracking_config_accepts_slash(self):
        config = TrackingConfig.from_dict({"prefix": "/", "enabled": True})
        assert config.prefix == "/"

    def test_tracking_config_rejects_empty_string(self):
        with pytest.raises(ValueError):
            TrackingConfig.from_dict({"prefix": "", "enabled": True})

    def test_tracking_config_rejects_missing_trailing_slash(self):
        with pytest.raises(ValueError):
            TrackingConfig.from_dict({"prefix": "project", "enabled": True})


# =============================================================================
# Group E — config-time validation
# =============================================================================


class TestCommitDedup:
    @pytest.mark.asyncio
    async def test_noop_commit_returns_current_head(self, handler_context, emit_pathway):
        # Use a specific prefix so bindings don't pick up the
        # system/revision/head/... writes from the prior commit.
        emit_pathway.emit("data/a.txt", Entity(type="test/file", data={"c": "a"}))
        first = await _commit(handler_context, "data/")

        # No tree changes between commits; second commit must return
        # the current head without creating a new entry.
        second = await _commit(handler_context, "data/")

        assert second == first, "no-op commit should return current head"

    @pytest.mark.asyncio
    async def test_real_change_creates_new_version(self, handler_context, emit_pathway):
        emit_pathway.emit("data/a.txt", Entity(type="test/file", data={"c": "a"}))
        first = await _commit(handler_context, "data/")

        emit_pathway.emit("data/b.txt", Entity(type="test/file", data={"c": "b"}))
        second = await _commit(handler_context, "data/")

        assert second != first


class TestValidateRevisionConfig:
    def test_auto_version_off_skips_validation(self):
        assert validate_revision_config({"prefix": "/", "auto_version": False}) == []

    def test_universal_tree_requires_excludes(self):
        errors = validate_revision_config({
            "prefix": "/", "auto_version": True,
        })
        assert errors
        # The single error mentions all required paths.
        joined = errors[0]
        for req in REQUIRED_EXCLUDE_PATHS:
            assert req.rstrip("/") in joined

    def test_universal_tree_with_system_shorthand(self):
        # `system/**` covers all required paths.
        errors = validate_revision_config({
            "prefix": "/",
            "auto_version": True,
            "exclude": ["system/**"],
        })
        assert errors == []

    def test_universal_tree_with_explicit_excludes(self):
        errors = validate_revision_config({
            "prefix": "/",
            "auto_version": True,
            "exclude": [
                "system/revision/**",
                "system/tree/root/**",
                "system/tree/tracking-config/**",
                "system/history/**",
                "system/clock/**",
            ],
        })
        assert errors == []

    def test_universal_tree_missing_one_exclude(self):
        errors = validate_revision_config({
            "prefix": "/",
            "auto_version": True,
            "exclude": [
                "system/revision/**",
                "system/tree/tracking-config/**",
                "system/history/**",
                "system/clock/**",
                # omit system/tree/root/**
            ],
        })
        assert errors
        assert "system/tree/root" in errors[0]

    def test_application_prefix_doesnt_need_system_excludes(self):
        # A tracked prefix distinct from system/** is self-excluding.
        errors = validate_revision_config({
            "prefix": "project/",
            "auto_version": True,
        })
        assert errors == []

    def test_invalid_prefix_reported(self):
        errors = validate_revision_config({
            "prefix": "project",  # missing trailing slash
            "auto_version": True,
        })
        assert errors
        assert "prefix" in errors[0]
