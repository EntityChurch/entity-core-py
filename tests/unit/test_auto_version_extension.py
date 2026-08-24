"""Tests for AutoVersionExtension (PROPOSAL-REVISION-AUTO-VERSION-FIX §6.1).

Covers:
- Per-write creation of version entries
- Dedup suppression when tracked root already matches head's root
- Exclude patterns honored
- Self-guard on engine paths (no infinite cascade)
- Tracking-config coordination: missing tracking-config → no version
- Invalid config (missing required excludes) → not enabled
- Ordering: auto-version fires BEFORE subscription (position 7 < 8)
- Active-branch advance
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.extensions import ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import ChangeEvent, EmitPathway
from entity_core.storage.entity_tree import EntityTree

from entity_core.utils.ecf import compute_ecf_hash

from entity_handlers.auto_version import (
    AutoVersionExtension,
    REVISION_CONFIG_TYPE,
    _exclude_matches,
)
from entity_handlers.revision import (
    VERSION_ENTRY_TYPE,
    _active_branch_path,
    _branch_path,
    _config_path_for_prefix,
    _head_path,
)
from entity_handlers.root_tracker import (
    TRACKING_CONFIG_PREFIX,
    TRACKING_CONFIG_TYPE,
    RootTrackerExtension,
    _root_binding_path,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def keypair() -> Keypair:
    return Keypair.generate()


@pytest.fixture
def peer_id(keypair: Keypair) -> str:
    return keypair.peer_id


@pytest.fixture
def content_store() -> ContentStore:
    return ContentStore()


@pytest.fixture
def entity_tree(peer_id: str) -> EntityTree:
    return EntityTree(peer_id)


@pytest.fixture
def emit(content_store: ContentStore, entity_tree: EntityTree) -> EmitPathway:
    return EmitPathway(content_store, entity_tree)


def _put_tracking_config(emit: EmitPathway, name: str, prefix: str) -> None:
    emit.emit(
        f"{TRACKING_CONFIG_PREFIX}{name}",
        Entity(
            type=TRACKING_CONFIG_TYPE,
            data={"prefix": prefix, "enabled": True},
        ),
    )


def _prefix_hash(emit: EmitPathway, prefix: str) -> str:
    absolute = emit.entity_tree.normalize_uri(prefix)
    return compute_ecf_hash({"type": "system/tree/path", "data": absolute}).hex()


def _put_revision_config(
    emit: EmitPathway, prefix: str, auto_version: bool = True,
    exclude: list[str] | None = None,
) -> None:
    data = {"prefix": prefix, "auto_version": auto_version}
    if exclude is not None:
        data["exclude"] = exclude
    ph = _prefix_hash(emit, prefix)
    emit.emit(
        _config_path_for_prefix(ph),
        Entity(type=REVISION_CONFIG_TYPE, data=data),
    )


def _setup_peer(
    emit: EmitPathway, keypair: Keypair,
) -> tuple[RootTrackerExtension, AutoVersionExtension]:
    rt = RootTrackerExtension()
    av = AutoVersionExtension()
    ctx = ExtensionContext(keypair=keypair, emit_pathway=emit)
    rt.initialize(ctx)
    av.initialize(ctx)
    return rt, av


def _read_head(emit: EmitPathway, prefix: str) -> bytes | None:
    ph = _prefix_hash(emit, prefix)
    uri = emit.entity_tree.normalize_uri(_head_path(ph))
    h = emit.entity_tree.get(uri)
    if h is None:
        return None
    entity = emit.content_store.get(h)
    if entity is None or entity.type != "system/hash":
        return None
    return entity.data.get("hash")


def _count_versions(content_store: ContentStore) -> int:
    return sum(
        1 for e in content_store._store.values()
        if e.type == VERSION_ENTRY_TYPE
    )


# ============================================================================
# Basic per-write behavior
# ============================================================================


class TestPerWriteCreation:
    def test_write_produces_version(self, emit, keypair, content_store):
        _put_tracking_config(emit, "project", "project/")
        _put_revision_config(emit, "project/", auto_version=True)
        _setup_peer(emit, keypair)

        before = _count_versions(content_store)
        emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 1}))
        after = _count_versions(content_store)

        assert after == before + 1, "one version per tracked write"
        assert _read_head(emit, "project/") is not None

    def test_second_write_chains_from_first(self, emit, keypair, content_store):
        _put_tracking_config(emit, "project", "project/")
        _put_revision_config(emit, "project/", auto_version=True)
        _setup_peer(emit, keypair)

        emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 1}))
        v1 = _read_head(emit, "project/")

        emit.emit("project/b.txt", Entity(type="test/blob", data={"v": 2}))
        v2 = _read_head(emit, "project/")

        assert v1 != v2, "head advances on each write"
        version = content_store.get(v2)
        assert version.type == VERSION_ENTRY_TYPE
        assert version.data["parents"] == [v1], "parent is prior head"

    def test_untracked_prefix_produces_no_version(
        self, emit, keypair, content_store,
    ):
        _put_tracking_config(emit, "project", "project/")
        _put_revision_config(emit, "project/", auto_version=True)
        _setup_peer(emit, keypair)

        before = _count_versions(content_store)
        emit.emit("other/a.txt", Entity(type="test/blob", data={"v": 1}))
        assert _count_versions(content_store) == before

    def test_auto_version_off_produces_no_version(
        self, emit, keypair, content_store,
    ):
        _put_tracking_config(emit, "project", "project/")
        _put_revision_config(emit, "project/", auto_version=False)
        _setup_peer(emit, keypair)

        before = _count_versions(content_store)
        emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 1}))
        assert _count_versions(content_store) == before


# ============================================================================
# Dedup
# ============================================================================


class TestDedup:
    def test_no_op_rewrite_deduped(self, emit, keypair, content_store):
        _put_tracking_config(emit, "project", "project/")
        _put_revision_config(emit, "project/", auto_version=True)
        _setup_peer(emit, keypair)

        ent = Entity(type="test/blob", data={"v": 1})
        emit.emit("project/a.txt", ent)
        count_after_first = _count_versions(content_store)

        # Same entity → same hash → EmitPathway suppresses the change
        # event (tree no-op). Even if an event fires, our dedup catches it.
        emit.emit("project/a.txt", ent)
        assert _count_versions(content_store) == count_after_first


# ============================================================================
# Excludes
# ============================================================================


class TestExclude:
    def test_exclude_pattern_honored(self, emit, keypair, content_store):
        _put_tracking_config(emit, "project", "project/")
        _put_revision_config(
            emit, "project/", auto_version=True,
            exclude=["ephemeral/*"],
        )
        _setup_peer(emit, keypair)

        before = _count_versions(content_store)
        emit.emit(
            "project/ephemeral/cache.txt",
            Entity(type="test/blob", data={"v": 1}),
        )
        assert _count_versions(content_store) == before, \
            "excluded path produces no version"

        emit.emit(
            "project/real.txt",
            Entity(type="test/blob", data={"v": 2}),
        )
        assert _count_versions(content_store) == before + 1


def test_the_emission_gate_uses_the_subtree_form():
    assert _exclude_matches(["system/revision/*"], "system/revision/head/p")
    assert not _exclude_matches(["system/revision/*"], "system/tree/root/x")
    # The retained "/" means the bare prefix is NOT covered by its own subtree
    # pattern. `system/revision` is a path, not a directory, and §2.4 form 2
    # is `starts_with(subject, "system/revision/")`.
    assert not _exclude_matches(["system/revision/*"], "system/revision")


def test_the_gate_and_the_trie_filter_agree_at_depth():
    """§6.1's emission gate ran a *second* matcher until the four-forms ruling,
    and that matcher read `/*` as segment-scoped — so `build/*` suppressed the
    version for `build/out` but not for `build/a/b`, while the trie filter kept
    both out. One peer disagreeing with itself about which writes are excluded.

    Form 2 crosses `/`. This is the row that used to assert the opposite.
    """
    assert _exclude_matches(["build/*"], "build/out")
    assert _exclude_matches(["build/*"], "build/a/b")
    assert _exclude_matches(["build/*"], "build/a/b/c/d")
    assert not _exclude_matches(["build/*"], "buildings/x")


# ============================================================================
# Engine-path self-guard (reentrancy)
# ============================================================================


class TestSelfGuard:
    def test_universal_tree_with_system_excludes_does_not_loop(
        self, emit, keypair, content_store,
    ):
        _put_tracking_config(emit, "univ", "/")
        _put_revision_config(
            emit, "/", auto_version=True, exclude=["system/*"],
        )
        _setup_peer(emit, keypair)

        # Write should produce exactly one version (not a cascade).
        before = _count_versions(content_store)
        emit.emit("data/foo.txt", Entity(type="test/blob", data={"v": 1}))
        assert _count_versions(content_store) == before + 1


# ============================================================================
# Tracking-config coordination
# ============================================================================


class TestTrackingConfigCoordination:
    def test_tracking_config_enables_auto_version(
        self, emit, keypair, content_store,
    ):
        """Writing a tracking-config (as the config operation does) enables
        auto-versioning. The auto-versioner reads the revision config from
        the hash-addressed path for exclude patterns."""
        _setup_peer(emit, keypair)

        # Write revision config at hash-addressed path, then tracking-config.
        # This is what the config operation does.
        _put_revision_config(emit, "project/", auto_version=True)
        _put_tracking_config(emit, "project", "project/")

        # The first tracked write produces a version.
        emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 1}))
        assert _read_head(emit, "project/") is not None

    def test_startup_loads_from_tracking_config(
        self, emit, keypair, content_store,
    ):
        """If tracking-config exists BEFORE the extension initializes,
        _load_existing_configs discovers it and enables auto-versioning."""
        _put_revision_config(emit, "project/", auto_version=True)
        _put_tracking_config(emit, "project", "project/")
        _setup_peer(emit, keypair)

        emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 1}))
        assert _read_head(emit, "project/") is not None

    def test_tracking_config_delete_disables_auto_version(
        self, emit, keypair, content_store,
    ):
        """Deleting tracking-config (as config operation does on disable)
        removes the auto-version config from the in-memory index."""
        _setup_peer(emit, keypair)
        _put_revision_config(emit, "project/", auto_version=True)
        _put_tracking_config(emit, "project", "project/")

        emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 1}))
        before = _count_versions(content_store)

        # Delete tracking-config — auto-version should stop.
        emit.delete(f"{TRACKING_CONFIG_PREFIX}project")
        root_uri = emit.entity_tree.normalize_uri("system/tree/root/project")
        emit.entity_tree.remove(root_uri)

        emit.emit("project/b.txt", Entity(type="test/blob", data={"v": 2}))
        assert _count_versions(content_store) == before

    def test_tracking_config_delete_stops_versioning(
        self, emit, keypair, content_store,
    ):
        """Deleting tracking-config removes the config from both the root
        tracker and the auto-versioner — no more versions created."""
        _setup_peer(emit, keypair)
        _put_revision_config(emit, "project/", auto_version=True)
        _put_tracking_config(emit, "project", "project/")

        emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 1}))
        assert _read_head(emit, "project/") is not None
        before = _count_versions(content_store)

        # Delete tracking-config — both root tracker and auto-versioner stop.
        emit.delete(f"{TRACKING_CONFIG_PREFIX}project")

        emit.emit("project/b.txt", Entity(type="test/blob", data={"v": 2}))
        assert _count_versions(content_store) == before


# ============================================================================
# Invalid config rejection (§6D.4)
# ============================================================================


class TestConfigValidation:
    def test_universal_config_without_excludes_refused(
        self, emit, keypair, content_store, caplog,
    ):
        _put_tracking_config(emit, "univ", "/")
        _put_revision_config(emit, "/", auto_version=True, exclude=[])
        with caplog.at_level(logging.ERROR, logger="entity_handlers.auto_version"):
            _setup_peer(emit, keypair)

        before = _count_versions(content_store)
        emit.emit("data/foo.txt", Entity(type="test/blob", data={"v": 1}))
        assert _count_versions(content_store) == before, \
            "invalid config must NOT enable auto-version"
        assert any(
            "refusing to enable" in rec.message or "invalid" in rec.message
            for rec in caplog.records
        )


# ============================================================================
# Ordering: auto-version fires BEFORE subscription
# ============================================================================


@pytest.mark.asyncio
async def test_auto_version_fires_before_subscription(
    emit, keypair, content_store,
):
    """Subscribers on tracked-prefix paths must see the settled head."""
    _put_tracking_config(emit, "project", "project/")
    _put_revision_config(emit, "project/", auto_version=True)
    _setup_peer(emit, keypair)

    # Subscription that checks head state at the moment it fires.
    observed_head_at_subscribe: list[bytes | None] = []

    class _Listener:
        async def on_change(self, event: ChangeEvent) -> None:
            observed_head_at_subscribe.append(_read_head(emit, "project/"))

    listener = _Listener()
    emit.subscribe("project/a.txt", listener)

    emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 1}))
    # Give async tasks a chance to run.
    await asyncio.sleep(0.01)

    assert observed_head_at_subscribe, "subscription fired"
    assert observed_head_at_subscribe[0] is not None, \
        "head was set by auto-version BEFORE subscription fired"


# ============================================================================
# Active-branch advance
# ============================================================================


class TestActiveBranchAdvance:
    def test_auto_version_advances_active_branch(
        self, emit, keypair, content_store,
    ):
        _put_tracking_config(emit, "project", "project/")
        _put_revision_config(emit, "project/", auto_version=True)
        _setup_peer(emit, keypair)

        # Set an active branch.
        ph = _prefix_hash(emit, "project/")
        emit.emit(
            _active_branch_path(ph),
            Entity(type="primitive/string", data="main"),
        )

        emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 1}))

        head_version_hash = _read_head(emit, "project/")
        assert head_version_hash is not None

        bp = _branch_path(ph, "main")
        branch_uri = emit.entity_tree.normalize_uri(bp)
        branch_binding = emit.entity_tree.get(branch_uri)
        assert branch_binding is not None
        branch_entity = content_store.get(branch_binding)
        assert branch_entity.type == "system/hash"
        assert branch_entity.data["hash"] == head_version_hash


# ============================================================================
# §6.1 D1 — the version root is the exclude-filtered trie, not the tracked root
# ============================================================================


class TestTheVersionRootIsExcludeFiltered:
    """`ROUTING-2026-08-18-c` §3: a version entry's `root` MUST be the
    exclude-filtered trie **on every path that emits one**.

    The tracked structural root is not that trie. It comes from
    `EXTENSION-TREE` §3.4.1a, driven by a `system/tree/tracking-config` that
    has no knowledge of any revision `exclude`, and TREE calls the binding "a
    direct pointer" with no filtering stage — so §2.4 and §6.1 name two
    different roots rather than two readings of one.

    The failure this closes is one write wide, which is why suppressing the
    version *entry* for an excluded write looked sufficient for as long as it
    did: suppression does not remove that path's contribution to the tracked
    root, so the next non-excluded write emitted a version committing to data
    the config says is not versioned. **On this path the exclude did not work
    at all, one write late.**
    """

    def _bindings_of_head(self, emit, content_store, prefix: str) -> dict:
        from entity_core.storage.trie import collect_all_bindings

        head = _read_head(emit, prefix)
        assert head is not None, "no version was emitted"
        version = content_store.get(head)
        assert version is not None and version.type == VERSION_ENTRY_TYPE
        return dict(collect_all_bindings(version.data["root"], "", content_store))

    def test_an_excluded_path_never_enters_a_version_root(
        self, emit, keypair, content_store,
    ):
        _put_tracking_config(emit, "project", "project/")
        _put_revision_config(
            emit, "project/", auto_version=True, exclude=["ephemeral/*"],
        )
        _setup_peer(emit, keypair)

        # The excluded write emits no version of its own (pre-existing
        # behaviour) but does move the tracked root.
        emit.emit("project/ephemeral/scratch", Entity(type="test/blob", data={"v": 1}))
        # The *next* write is the one that used to leak it.
        emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 2}))

        bindings = self._bindings_of_head(emit, content_store, "project/")
        assert "ephemeral/scratch" not in bindings, (
            f"the version root commits to an excluded path — the tracked root "
            f"was used verbatim instead of the filtered trie: {sorted(bindings)}"
        )
        assert "a.txt" in bindings, (
            f"the filtered trie dropped a path the exclude does not name: "
            f"{sorted(bindings)}"
        )

    def test_with_no_excludes_the_root_is_still_the_tracked_root(
        self, emit, keypair, content_store,
    ):
        """The O(1) fast path, kept deliberately.

        With `exclude` and `exclude_types` both empty the filtered trie **is**
        the tracked root, so the version takes it directly rather than
        rebuilding a trie on every write. If this ever fails, the D1 change has
        started paying full snapshot cost for prefixes that configured nothing.
        """
        _put_tracking_config(emit, "project", "project/")
        _put_revision_config(emit, "project/", auto_version=True)
        _setup_peer(emit, keypair)

        emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 1}))

        head = _read_head(emit, "project/")
        version = content_store.get(head)
        tracked = emit.entity_tree.get(
            emit.entity_tree.normalize_uri(_root_binding_path("project/"))
        )
        assert version.data["root"] == tracked

    def test_the_two_paths_agree_on_the_root_REV_AUTOVERSION_EXCLUDE_PARITY_1(
        self, emit, keypair, content_store,
    ):
        """D5's vector — the two-peer divergence reduced to a single peer.

        `root` is the version entry's identity, so a root that depends on
        *which path emitted it* forks the DAG with no content difference:
        two peers over identical tree state and identical config produce
        different `system/revision/entry` hashes, and entity exchange cannot
        converge them. Nothing errors at either end.

        The check is the one no existing vector reached — build the filtered
        trie the way `commit` does, over the same live state, and require the
        auto-version entry's root to equal it byte for byte. Write an excluded
        path first, because that is the state in which the two computations
        used to differ.
        """
        from entity_core.storage.trie import build_trie
        from entity_handlers.revision import compute_versioned_bindings

        _put_tracking_config(emit, "project", "project/")
        _put_revision_config(
            emit, "project/", auto_version=True, exclude=["ephemeral/*"],
        )
        _setup_peer(emit, keypair)

        emit.emit("project/ephemeral/scratch", Entity(type="test/blob", data={"v": 1}))
        emit.emit("project/a.txt", Entity(type="test/blob", data={"v": 2}))

        auto_root = content_store.get(_read_head(emit, "project/")).data["root"]
        commit_root = build_trie(
            sorted(compute_versioned_bindings(
                emit.entity_tree, content_store, "project/",
                {"exclude": ["ephemeral/*"], "exclude_types": []},
            ).items()),
            content_store,
        )

        assert auto_root == commit_root, (
            "the auto-version root and the commit root disagree over identical "
            "live state — the version DAG forks on arrival path, not content"
        )
