"""Unit tests for the trie root tracker extension.

Covers EXTENSION-TREE v3.8 §3.4, §3.4.1, §3.4.1a (PROPOSAL R1-R5).

- Root binding stays in sync with `build_trie` over current bindings
- Hot-reload on tracking-config writes
- Disable removes stale root
- Startup discovery from existing tracking-config entries
- Self-guard on system/tree/root/* prevents recursion
- Multiple tracked prefixes update independently
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.extensions import ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.trie import build_trie

from entity_core.storage.trie import TRIE_NODE_TYPE, collect_all_bindings

from entity_handlers.root_tracker import (
    ROOT_BINDING_PREFIX,
    TRACKING_CONFIG_PREFIX,
    TRACKING_CONFIG_TYPE,
    RootTrackerExtension,
    TrackingConfig,
    _is_root_binding_path,
    _root_binding_path,
)


@pytest.fixture
def keypair() -> Keypair:
    return Keypair.generate()


@pytest.fixture
def content_store() -> ContentStore:
    return ContentStore()


@pytest.fixture
def entity_tree(keypair: Keypair) -> EntityTree:
    return EntityTree(keypair.peer_id)


@pytest.fixture
def emit(content_store: ContentStore, entity_tree: EntityTree) -> EmitPathway:
    return EmitPathway(content_store, entity_tree)


@pytest.fixture
def peer_id(keypair: Keypair) -> str:
    return keypair.peer_id


def _put(emit: EmitPathway, path: str, value: str) -> bytes:
    return emit.emit(path, Entity(type="test/blob", data={"value": value}))


def _put_config(
    emit: EmitPathway, name: str, prefix: str, enabled: bool = True
) -> None:
    emit.emit(
        f"{TRACKING_CONFIG_PREFIX}{name}",
        Entity(
            type=TRACKING_CONFIG_TYPE,
            data={"prefix": prefix, "enabled": enabled},
        ),
    )


def _initialize(emit: EmitPathway, keypair: Keypair) -> RootTrackerExtension:
    ext = RootTrackerExtension()
    ext.initialize(ExtensionContext(keypair=keypair, emit_pathway=emit))
    return ext


def _expected_root(emit: EmitPathway, abs_prefix: str, peer_id: str) -> bytes:
    """Reference: build_trie over current bindings under prefix."""
    bindings: list[tuple[str, bytes]] = []
    for uri in emit.entity_tree.list_prefix(abs_prefix):
        if _is_root_binding_path(uri, peer_id):
            continue
        h = emit.entity_tree.get(uri)
        if h is None:
            continue
        bindings.append((uri[len(abs_prefix):], h))
    bindings.sort(key=lambda b: b[0])
    return build_trie(bindings, emit.content_store)


def _read_root(emit: EmitPathway, prefix: str) -> bytes | None:
    """Return the trie root hash bound at system/tree/root/{prefix}.

    Per §3.4.1 the binding IS the trie root hash directly (no wrapper).
    """
    binding_path = _root_binding_path(prefix)
    return emit.entity_tree.get(emit.entity_tree.normalize_uri(binding_path))


# ============================================================================
# Path helpers
# ============================================================================


class TestPathHelpers:
    def test_root_binding_path_strips_trailing_slash(self):
        assert _root_binding_path("data/users/") == "system/tree/root/data/users"

    def test_root_binding_path_empty_prefix(self):
        assert _root_binding_path("/") == ROOT_BINDING_PREFIX.rstrip("/")

    def test_self_guard_matches_root_paths(self):
        assert _is_root_binding_path("/peer/system/tree/root/x", "peer")
        assert _is_root_binding_path("/peer/system/tree/root/data/users", "peer")

    def test_self_guard_rejects_other_paths(self):
        assert not _is_root_binding_path("/peer/data/users/alice", "peer")
        assert not _is_root_binding_path("/peer/system/tree/snapshot/x", "peer")


# ============================================================================
# TrackingConfig
# ============================================================================


class TestTrackingConfig:
    def test_from_dict(self):
        c = TrackingConfig.from_dict({"prefix": "data/", "enabled": True})
        assert c.prefix == "data/"
        assert c.enabled is True

    def test_from_dict_disabled_default(self):
        c = TrackingConfig.from_dict({"prefix": "data/"})
        assert c.enabled is False


# ============================================================================
# Root maintenance
# ============================================================================


class TestRootMaintenance:
    def test_root_written_on_config_create(self, emit, keypair, peer_id):
        _put(emit, "data/users/alice", "a")
        _put(emit, "data/users/bob", "b")
        _initialize(emit, keypair)

        _put_config(emit, "users", "data/users/")

        abs_prefix = f"/{peer_id}/data/users/"
        expected = _expected_root(emit, abs_prefix, peer_id)
        assert _read_root(emit, "data/users/") == expected

    def test_root_updated_on_subsequent_write(self, emit, keypair, peer_id):
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/")

        _put(emit, "data/users/alice", "a")
        first = _read_root(emit, "data/users/")
        assert first is not None

        _put(emit, "data/users/bob", "b")
        second = _read_root(emit, "data/users/")
        assert second is not None
        assert second != first

        abs_prefix = f"/{peer_id}/data/users/"
        assert second == _expected_root(emit, abs_prefix, peer_id)

    def test_root_excludes_paths_outside_prefix(self, emit, keypair, peer_id):
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/")

        _put(emit, "data/users/alice", "a")
        _put(emit, "data/posts/p1", "x")  # outside tracked prefix

        abs_prefix = f"/{peer_id}/data/users/"
        assert _read_root(emit, "data/users/") == _expected_root(
            emit, abs_prefix, peer_id
        )

    def test_root_binding_points_at_trie_node_directly(
        self, emit, keypair, peer_id
    ):
        """Per §3.4.1 and Go's reference impl: the binding at
        system/tree/root/{prefix} is the trie root hash directly (no
        wrapper entity). The entity at that hash is the trie root
        node."""
        _put(emit, "data/users/alice", "a")
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/")

        binding_path = _root_binding_path("data/users/")
        binding_hash = emit.entity_tree.get(
            emit.entity_tree.normalize_uri(binding_path)
        )
        entity = emit.content_store.get(binding_hash)
        assert entity.type == TRIE_NODE_TYPE
        # And its bindings match what we put in.
        collected = dict(
            collect_all_bindings(binding_hash, "", emit.content_store)
        )
        assert set(collected.keys()) == {"alice"}


# ============================================================================
# Hot-reload and disable
# ============================================================================


class TestHotReload:
    def test_disable_removes_root_binding(self, emit, keypair, peer_id):
        _put(emit, "data/users/alice", "a")
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/")
        assert _read_root(emit, "data/users/") is not None

        _put_config(emit, "users", "data/users/", enabled=False)

        binding_path = _root_binding_path("data/users/")
        assert (
            emit.entity_tree.get(emit.entity_tree.normalize_uri(binding_path)) is None
        )

    def test_writes_after_disable_do_not_revive_root(self, emit, keypair, peer_id):
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/", enabled=True)
        _put(emit, "data/users/alice", "a")
        _put_config(emit, "users", "data/users/", enabled=False)

        _put(emit, "data/users/charlie", "c")

        binding_path = _root_binding_path("data/users/")
        assert (
            emit.entity_tree.get(emit.entity_tree.normalize_uri(binding_path)) is None
        )


# ============================================================================
# Startup discovery
# ============================================================================


class TestStartupDiscovery:
    def test_initial_build_from_existing_configs(self, emit, keypair, peer_id):
        # Pre-existing state: bindings + enabled config, then bring extension up.
        _put(emit, "data/users/alice", "a")
        _put(emit, "data/users/bob", "b")
        _put_config(emit, "users", "data/users/", enabled=True)
        # Sanity: root not yet present
        binding_path = _root_binding_path("data/users/")
        assert (
            emit.entity_tree.get(emit.entity_tree.normalize_uri(binding_path)) is None
        )

        _initialize(emit, keypair)

        abs_prefix = f"/{peer_id}/data/users/"
        assert _read_root(emit, "data/users/") == _expected_root(
            emit, abs_prefix, peer_id
        )

    def test_disabled_configs_skipped_at_startup(self, emit, keypair):
        _put(emit, "data/x/k", "v")
        _put_config(emit, "x", "data/x/", enabled=False)

        _initialize(emit, keypair)

        binding_path = _root_binding_path("data/x/")
        assert (
            emit.entity_tree.get(emit.entity_tree.normalize_uri(binding_path)) is None
        )


# ============================================================================
# Self-guard
# ============================================================================


class TestSelfGuard:
    def test_root_writes_do_not_recurse(self, emit, keypair, peer_id):
        _put(emit, "data/users/alice", "a")
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/")

        # Cascade depth must be back to 0 after the chain settles.
        assert emit.cascade_depth == 0

        # And another write must still update cleanly (not crash from recursion).
        _put(emit, "data/users/bob", "b")
        abs_prefix = f"/{peer_id}/data/users/"
        assert _read_root(emit, "data/users/") == _expected_root(
            emit, abs_prefix, peer_id
        )


# ============================================================================
# Multi-prefix
# ============================================================================


class TestIncrementalCharacteristic:
    """Lock in O(depth) per-write behavior. Catches regression to full rebuild."""

    def test_per_event_update_creates_only_O_depth_new_nodes(
        self, emit, keypair, peer_id
    ):
        # Seed a wide tree so a full rebuild would touch many nodes.
        for i in range(20):
            _put(emit, f"data/users/u{i:02d}", f"v{i}")
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/")

        cs = emit.content_store
        nodes_before = len(cs._store)  # type: ignore[attr-defined]

        # A single deep update should add at most O(depth) nodes:
        # one new leaf entity (the test/blob) + O(depth) new trie nodes
        # + one new system/hash root entity. With ~20 children at the
        # "users" level the tree depth is small (~2-3 trie nodes), so
        # the budget here is comfortably under a full rebuild (~21 nodes).
        _put(emit, "data/users/u05", "v5-updated")

        nodes_after = len(cs._store)  # type: ignore[attr-defined]
        added = nodes_after - nodes_before
        # Full rebuild for 20 leaves builds ~21+ trie nodes plus the
        # leaf and the root entity. Incremental should be far fewer.
        assert added < 10, (
            f"Per-write added {added} nodes; expected O(depth) < 10. "
            "Did the tracker regress to full rebuild?"
        )


class TestDefensiveExceptionHandling:
    """Per the Go validator report: a tracker bug MUST NOT 500 the
    user's tree put. Hooks swallow exceptions and log them."""

    def test_exception_in_root_updater_does_not_fail_write(
        self, emit, keypair, peer_id, monkeypatch
    ):
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/")
        _put(emit, "data/users/alice", "a")  # baseline

        import entity_handlers.root_tracker as rt

        def boom(*args, **kwargs):
            raise RuntimeError("synthetic tracker bug")

        monkeypatch.setattr(rt, "_apply_change_to_root", boom)

        # User write MUST still succeed despite the tracker failure.
        emit.emit(
            "data/users/bob",
            Entity(type="test/blob", data={"value": "b"}),
        )
        assert (
            emit.entity_tree.get(
                emit.entity_tree.normalize_uri("data/users/bob")
            )
            is not None
        )

    def test_exception_in_config_watcher_does_not_fail_config_write(
        self, emit, keypair, monkeypatch
    ):
        _initialize(emit, keypair)
        import entity_handlers.root_tracker as rt

        def boom(*args, **kwargs):
            raise RuntimeError("synthetic tracker bug")

        monkeypatch.setattr(rt, "_initial_build_for_prefix", boom)

        # Writing the tracking-config MUST NOT raise despite the bug.
        emit.emit(
            f"{TRACKING_CONFIG_PREFIX}users",
            Entity(
                type=TRACKING_CONFIG_TYPE,
                data={"prefix": "data/users/", "enabled": True},
            ),
        )
        assert (
            emit.entity_tree.get(
                emit.entity_tree.normalize_uri(
                    f"{TRACKING_CONFIG_PREFIX}users"
                )
            )
            is not None
        )


class TestValidatorParity:
    """Mirror the four checks from the Go validator tree_operations
    category (per the root-tracking diagnosis)."""

    def test_tracked_root_present(self, emit, keypair, peer_id):
        _put(emit, "data/users/alice", "a")
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/")
        binding = emit.entity_tree.get(
            emit.entity_tree.normalize_uri(_root_binding_path("data/users/"))
        )
        assert binding is not None

    def test_tracked_root_updates_on_second_write(self, emit, keypair, peer_id):
        _put(emit, "data/users/alice", "a")
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/")
        first = _read_root(emit, "data/users/")

        _put(emit, "data/users/bob", "b")
        second = _read_root(emit, "data/users/")

        assert first is not None and second is not None
        assert first != second

    def test_tracked_snapshot_matches_root_binding(
        self, emit, keypair, peer_id
    ):
        """snapshot(prefix).root == binding at system/tree/root/{prefix}."""
        _put(emit, "data/users/alice", "a")
        _put(emit, "data/users/bob", "b")
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/")

        abs_prefix = f"/{peer_id}/data/users/"
        snapshot_root = _expected_root(emit, abs_prefix, peer_id)
        tracked_root = _read_root(emit, "data/users/")
        assert snapshot_root == tracked_root

    def test_tracked_root_cleared_on_disable(self, emit, keypair, peer_id):
        _put(emit, "data/users/alice", "a")
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/", enabled=True)
        assert _read_root(emit, "data/users/") is not None

        _put_config(emit, "users", "data/users/", enabled=False)
        assert (
            emit.entity_tree.get(
                emit.entity_tree.normalize_uri(_root_binding_path("data/users/"))
            )
            is None
        )


class TestMultiPrefix:
    def test_multiple_prefixes_tracked_independently(self, emit, keypair, peer_id):
        _initialize(emit, keypair)
        _put_config(emit, "users", "data/users/")
        _put_config(emit, "posts", "data/posts/")

        _put(emit, "data/users/alice", "a")
        _put(emit, "data/posts/p1", "x")

        users_root = _read_root(emit, "data/users/")
        posts_root = _read_root(emit, "data/posts/")
        assert users_root is not None
        assert posts_root is not None
        assert users_root != posts_root

        # Update under one prefix should not change the other root.
        before_posts = posts_root
        _put(emit, "data/users/bob", "b")
        assert _read_root(emit, "data/posts/") == before_posts
        assert _read_root(emit, "data/users/") != users_root
