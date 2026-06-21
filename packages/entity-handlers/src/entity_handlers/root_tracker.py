"""Trie root tracking extension (EXTENSION-TREE v3.8 §3.4, §3.4.1, §3.4.1a).

Maintains an incremental trie root for each prefix that has an enabled
`system/tree/tracking-config` entity. The root hash for prefix `P` is
written to `system/tree/root/{P}` so it is discoverable, subscribable,
and syncable.

Position 6 in the SYSTEM-COMPOSITION emit ordering: structural summary,
bounded reactive, self-guarded against its own output paths.

Per EXTENSION-TREE §3.4.2 maintenance is incremental: each change applies
`trie_put` or `trie_remove` to the previous root, producing O(depth) new
trie nodes per write. The result is hash-equivalent to `build_trie` over
the updated binding set. Startup discovery uses `build_trie` once for
each enabled prefix.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.storage.emit import ChangeEvent, ChangeKind, EmitContext
from entity_core.storage.trie import build_trie, empty_trie, trie_put, trie_remove

if TYPE_CHECKING:
    from entity_core.storage.emit import EmitPathway

logger = logging.getLogger(__name__)

TRACKING_CONFIG_TYPE = "system/tree/tracking-config"
TRACKING_CONFIG_PREFIX = "system/tree/tracking-config/"
ROOT_BINDING_PREFIX = "system/tree/root/"


@dataclass
class TrackingConfig:
    """A single trie root tracking configuration.

    Attributes:
        prefix: Subtree prefix to track. MUST end with "/" per §3.4.1a.
        enabled: When false, tracking is suspended and the root binding
            is removed.
    """

    prefix: str
    enabled: bool

    @classmethod
    def from_dict(cls, data: dict) -> TrackingConfig:
        prefix = data["prefix"]
        if not prefix or not prefix.endswith("/"):
            raise ValueError(
                "tracking-config prefix must be non-empty and end with '/' "
                "(use '/' for the universal tree); got %r" % prefix
            )
        return cls(prefix=prefix, enabled=bool(data.get("enabled", False)))


def _root_binding_path(prefix: str) -> str:
    """Storage path for the tracked root hash, per EXTENSION-TREE §3.4.1.

    Strip leading AND trailing "/" to compute canonical form P:
      - `"/"` (universal tree) → P = "" → `system/tree/root`
      - `"project/"` → P = "project" → `system/tree/root/project`
      - `"/alice/data/"` → P = "alice/data" → `system/tree/root/alice/data`
    """
    canonical = prefix.strip("/")
    if not canonical:
        return ROOT_BINDING_PREFIX.rstrip("/")
    return f"{ROOT_BINDING_PREFIX}{canonical}"


def _is_root_binding_path(uri: str, local_peer_id: str) -> bool:
    """Self-guard: True if the URI is one of our root output paths."""
    prefix = f"/{local_peer_id}/{ROOT_BINDING_PREFIX}"
    return uri.startswith(prefix) or uri == prefix.rstrip("/")


class _ConfigIndex:
    """In-memory index of tracking configs keyed by config name."""

    def __init__(self, local_peer_id: str) -> None:
        self._configs: dict[str, TrackingConfig] = {}
        self._local_peer_id = local_peer_id

    def update(self, name: str, config: TrackingConfig | None) -> None:
        if config is None:
            self._configs.pop(name, None)
        else:
            self._configs[name] = config

    def enabled_items(self) -> list[tuple[str, TrackingConfig]]:
        return [(n, c) for n, c in self._configs.items() if c.enabled]

    def absolute_prefix(self, prefix: str) -> str:
        """Convert a peer-relative tracked prefix to an absolute URI prefix."""
        if prefix.startswith("/"):
            return prefix
        return f"/{self._local_peer_id}/{prefix}"


def _absolute_prefix(prefix: str, local_peer_id: str) -> str:
    return prefix if prefix.startswith("/") else f"/{local_peer_id}/{prefix}"


def _read_current_root(
    emit: EmitPathway,
    prefix: str,
) -> bytes | None:
    """Read the currently-stored root hash for a prefix, if any.

    Per §3.4.1 the binding at `system/tree/root/{prefix}` is the trie
    root node's hash directly — there is no wrapping entity.
    """
    binding_path = _root_binding_path(prefix)
    return emit.entity_tree.get(emit.entity_tree.normalize_uri(binding_path))


def _write_root(emit: EmitPathway, prefix: str, root_hash: bytes) -> None:
    """Bind `system/tree/root/{prefix}` to the trie root hash.

    Per §3.4.1: "The root entity is a system/hash value — the content
    hash of the root trie node." The trie root node is already in the
    content store from `trie_put` / `build_trie`; we re-emit it so the
    write goes through the emit pathway (subscribability) without
    creating a wrapper entity.
    """
    trie_node = emit.content_store.get(root_hash)
    if trie_node is None:
        logger.error(
            "RootTracker: trie root %s missing from content store; skipping write",
            root_hash.hex() if isinstance(root_hash, bytes) else root_hash,
        )
        return
    emit.emit(_root_binding_path(prefix), trie_node, EmitContext.bootstrap())


def _initial_build_for_prefix(
    emit: EmitPathway,
    config: TrackingConfig,
    local_peer_id: str,
) -> None:
    """One-shot O(N) trie build for a prefix at startup or first enable.

    Per §3.4.1a: "Adding a config triggers an initial trie build for the
    prefix (O(N) one-time cost)."
    """
    abs_prefix = _absolute_prefix(config.prefix, local_peer_id)
    bindings: list[tuple[str, bytes]] = []
    for uri in emit.entity_tree.list_prefix(abs_prefix):
        if _is_root_binding_path(uri, local_peer_id):
            continue
        h = emit.entity_tree.get(uri)
        if h is None:
            continue
        bindings.append((uri[len(abs_prefix):], h))
    bindings.sort(key=lambda b: b[0])
    root_hash = build_trie(bindings, emit.content_store)
    _write_root(emit, config.prefix, root_hash)


def _apply_change_to_root(
    emit: EmitPathway,
    config: TrackingConfig,
    local_peer_id: str,
    event: ChangeEvent,
) -> None:
    """Per §3.4.2: O(depth) incremental update of the tracked root."""
    abs_prefix = _absolute_prefix(config.prefix, local_peer_id)
    if not event.uri.startswith(abs_prefix):
        return
    relative = event.uri[len(abs_prefix):]
    cs = emit.content_store

    current = _read_current_root(emit, config.prefix)
    if current is None:
        current = empty_trie(cs)

    if event.kind == ChangeKind.DELETED:
        new_root = trie_remove(current, relative, cs)
    else:
        # CREATED or UPDATED: event.hash is non-None
        if event.hash is None:
            return
        new_root = trie_put(current, relative, event.hash, cs)

    if new_root != current:
        _write_root(emit, config.prefix, new_root)


def _remove_root_for_prefix(
    emit: EmitPathway,
    prefix: str,
) -> None:
    """Remove the root binding for a no-longer-tracked prefix."""
    emit.delete(_root_binding_path(prefix), EmitContext.bootstrap())


class _ConfigWatcher:
    """Hook on `system/tree/tracking-config/*` to maintain the index.

    On config create/update: refresh index entry, rebuild trie if enabled,
    or remove root binding if disabled.
    On config delete: remove index entry and remove root binding.
    """

    def __init__(self, extension: RootTrackerExtension) -> None:
        self._ext = extension

    def on_change_sync(self, event: ChangeEvent) -> None:
        try:
            self._handle(event)
        except Exception:
            # Per §3.4 the tracker is a bounded reactive consumer; a bug
            # here MUST NOT take down the user's write. Log and swallow.
            logger.exception("RootTracker config watcher failed on %s", event.uri)

    def _handle(self, event: ChangeEvent) -> None:
        ext = self._ext
        if ext._config_index is None or ext._emit_pathway is None:
            return

        parts = event.uri.split(f"/{TRACKING_CONFIG_PREFIX}", 1)
        if len(parts) != 2 or not parts[1]:
            return
        name = parts[1]

        if event.kind == ChangeKind.DELETED:
            old = ext._config_index._configs.get(name)
            ext._config_index.update(name, None)
            if old is not None:
                _remove_root_for_prefix(ext._emit_pathway, old.prefix)
            return

        if event.entity is None or event.entity.type != TRACKING_CONFIG_TYPE:
            return

        try:
            config = TrackingConfig.from_dict(event.entity.data)
        except (KeyError, TypeError, ValueError):
            return

        old = ext._config_index._configs.get(name)
        ext._config_index.update(name, config)

        if config.enabled:
            # New or re-enabled config: one-time O(N) build.
            _initial_build_for_prefix(
                ext._emit_pathway, config, ext._local_peer_id
            )
        else:
            # Disabled: drop stale root per §3.4.1a
            target_prefix = old.prefix if old is not None else config.prefix
            _remove_root_for_prefix(ext._emit_pathway, target_prefix)


class _RootUpdater:
    """Hook on every change. For each tracked prefix that contains the
    changed path, rebuild and re-emit the root binding.

    Self-guards by skipping events at `system/tree/root/*` to prevent
    recursion when the root hash itself is written.
    """

    def __init__(self, extension: RootTrackerExtension) -> None:
        self._ext = extension

    def on_change_sync(self, event: ChangeEvent) -> None:
        try:
            self._handle(event)
        except Exception:
            # Defensive: never let a tracker bug fail the user's write.
            logger.exception("RootTracker root updater failed on %s", event.uri)

    def _handle(self, event: ChangeEvent) -> None:
        ext = self._ext
        if ext._config_index is None or ext._emit_pathway is None:
            return

        # Self-guard (§3.4.1a)
        if _is_root_binding_path(event.uri, ext._local_peer_id):
            return

        # Skip config-path events; the config watcher handles those (it
        # rebuilds explicitly). Rebuilding here would double-process.
        config_prefix_abs = f"/{ext._local_peer_id}/{TRACKING_CONFIG_PREFIX}"
        if event.uri.startswith(config_prefix_abs):
            return

        for _, config in ext._config_index.enabled_items():
            abs_prefix = ext._config_index.absolute_prefix(config.prefix)
            if event.uri.startswith(abs_prefix):
                _apply_change_to_root(
                    ext._emit_pathway, config, ext._local_peer_id, event
                )


class RootTrackerExtension(Extension):
    """Maintains incremental trie roots per EXTENSION-TREE §3.4.

    Watches `system/tree/tracking-config/*` for tracked prefixes and
    keeps `system/tree/root/{prefix}` in sync with the trie root for
    each enabled prefix.

    No handler operations — tracking configs are written via the
    standard tree `put` operation.

    Usage:
        builder.with_extension(RootTrackerExtension())
    """

    def __init__(self) -> None:
        self._config_index: _ConfigIndex | None = None
        self._emit_pathway: EmitPathway | None = None
        self._local_peer_id: str = ""
        self._config_watcher: _ConfigWatcher | None = None
        self._root_updater: _RootUpdater | None = None

    def initialize(self, ctx: ExtensionContext) -> None:
        if ctx.emit_pathway is None:
            logger.warning("RootTrackerExtension: no emit_pathway, tracking disabled")
            return

        self._emit_pathway = ctx.emit_pathway
        self._local_peer_id = ctx.peer_id
        self._config_index = _ConfigIndex(ctx.peer_id)

        # Hooks first so the initial build's emit() activity is observable
        # in tests, and any concurrent writes during startup are caught.
        self._config_watcher = _ConfigWatcher(self)
        ctx.emit_pathway._add_internal_hook(
            self._config_watcher,
            pattern=f"/{ctx.peer_id}/{TRACKING_CONFIG_PREFIX}*",
            name="tree/root-tracker/config-watcher",
        )
        self._root_updater = _RootUpdater(self)
        ctx.emit_pathway._add_internal_hook(self._root_updater, name="tree/root-tracker/root-updater")

        # Startup discovery (§3.4.1a)
        self._load_existing_configs(ctx.emit_pathway)

        logger.info("RootTrackerExtension initialized")

    def _load_existing_configs(self, emit: EmitPathway) -> None:
        """Scan tracking-config/* and rebuild tries for enabled prefixes."""
        prefix = emit.entity_tree.normalize_uri(TRACKING_CONFIG_PREFIX)
        for uri in emit.entity_tree.list_prefix(prefix):
            h = emit.entity_tree.get(uri)
            if h is None:
                continue
            entity = emit.content_store.get(h)
            if entity is None or entity.type != TRACKING_CONFIG_TYPE:
                continue
            try:
                config = TrackingConfig.from_dict(entity.data)
            except (KeyError, TypeError, ValueError):
                continue
            parts = uri.split(f"/{TRACKING_CONFIG_PREFIX}", 1)
            if len(parts) != 2 or not parts[1]:
                continue
            name = parts[1]
            self._config_index.update(name, config)
            if config.enabled:
                _initial_build_for_prefix(emit, config, self._local_peer_id)

    def shutdown(self) -> None:
        if self._emit_pathway is not None:
            if self._root_updater is not None:
                self._emit_pathway._remove_internal_hook(self._root_updater)
            if self._config_watcher is not None:
                self._emit_pathway._remove_internal_hook(self._config_watcher)
        self._config_index = None
        self._root_updater = None
        self._config_watcher = None
