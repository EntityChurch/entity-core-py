"""Auto-version extension (PROPOSAL-REVISION-AUTO-VERSION-FIX §6.1).

Per-write CRDT-style auto-versioning: for each tree write to a path under a
tracked prefix (where the revision config has `auto_version: true`) and not
matching the config's `exclude`, produces one `system/revision/entry` and
advances `system/revision/{prefix_hash}/head`.

Emit position: 7 (after structural summaries at position 6, before
subscription at position 8). See SYSTEM-COMPOSITION §2.2.

Key properties (§3):
- Per-write creation.
- Content-addressed DAG convergence across peers.
- No orphans: every version entry is reachable from some head.
- Single-writer serialization is used (Python's asyncio model);
  CAS+retry is unnecessary under this concurrency model.
- Dedup: if the current head's root already matches the new tracked root,
  skip version creation.

Tracking-config coordination (§4 "Trie root tracking coordination"):
MUST-level — when a revision config with `auto_version: true` is present
but no corresponding `system/tree/tracking-config` exists (or it's
disabled), auto-version errors on emit rather than silently falling back.
Here we log + skip rather than raising, to keep the tree write landing,
but we surface the condition via a logger.error call that tests can
assert on.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import ChangeEvent, ChangeKind, EmitContext

from entity_core.utils.ecf import compute_ecf_hash

from entity_handlers.revision import (
    VERSION_ENTRY_TYPE,
    _active_branch_path,
    _branch_path,
    _config_path_for_prefix,
    _head_path,
    sorted_parents,
    validate_revision_config,
)
from entity_handlers.root_tracker import (
    ROOT_BINDING_PREFIX,
    TRACKING_CONFIG_PREFIX,
    _root_binding_path,
)

if TYPE_CHECKING:
    from entity_core.storage.emit import EmitPathway

logger = logging.getLogger(__name__)


REVISION_CONFIG_TYPE = "system/revision/config"
TRACKING_CONFIG_TYPE = "system/tree/tracking-config"


def _prefix_hash_from_emit(emit: EmitPathway, prefix: str) -> str:
    """Compute hash-addressed prefix segment from an EmitPathway."""
    absolute = emit.entity_tree.normalize_uri(prefix)
    return compute_ecf_hash({"type": "system/tree/path", "data": absolute}).hex()


@dataclass
class _AutoVersionConfig:
    """Parsed revision config relevant to auto-version."""

    prefix: str
    auto_version: bool
    exclude: list[str]


def _parse_config(data: dict) -> _AutoVersionConfig | None:
    prefix = data.get("prefix")
    if not isinstance(prefix, str) or not prefix.endswith("/"):
        return None
    return _AutoVersionConfig(
        prefix=prefix,
        auto_version=bool(data.get("auto_version", False)),
        exclude=list(data.get("exclude") or []),
    )


def _absolute_prefix(prefix: str, local_peer_id: str) -> str:
    return prefix if prefix.startswith("/") else f"/{local_peer_id}/{prefix}"


def _exclude_matches(patterns: list[str], relative_path: str) -> bool:
    """Simple glob-style match against the relative path (below prefix).

    Supports trailing `**` and `*` as prefix wildcards, and exact matches.
    This is intentionally narrow — the spec's §4 excludes use either
    `system/revision/**` style or exact paths; both fall under this.
    """
    for pat in patterns:
        if pat.endswith("/**"):
            base = pat[:-3]
            if relative_path == base or relative_path.startswith(base + "/"):
                return True
        elif pat.endswith("/*"):
            base = pat[:-2]
            tail = relative_path[len(base) + 1:] if relative_path.startswith(base + "/") else None
            if tail is not None and "/" not in tail:
                return True
        elif pat == relative_path:
            return True
    return False


def _is_engine_write(relative_path: str) -> bool:
    """Self-guard: our own writes (revision/head, revision/branches, etc.)
    must never re-trigger auto-version to avoid infinite cascades. The
    spec's exclude list handles this at config-write time (§6D.4), but
    we also guard at runtime as defense-in-depth.

    Also guards `system/tree/root/**` (structural summaries at position 6
    writes these as part of every tracked-prefix update) and
    `system/tree/tracking-config/**`.
    """
    for engine_prefix in (
        "system/revision/",
        ROOT_BINDING_PREFIX,
        TRACKING_CONFIG_PREFIX,
    ):
        if relative_path == engine_prefix.rstrip("/") or relative_path.startswith(engine_prefix):
            return True
    return False


class _ConfigWatcher:
    """Watches tracking-config changes to maintain auto-version config index.

    The revision handler's config operation writes both the revision config
    (at the hash-addressed path) and the tracking-config. We watch
    tracking-config changes and read the revision config on demand.
    """

    def __init__(self, ext: AutoVersionExtension) -> None:
        self._ext = ext

    def on_change_sync(self, event: ChangeEvent) -> None:
        try:
            self._handle(event)
        except Exception:
            logger.exception("AutoVersion config watcher failed on %s", event.uri)

    def _handle(self, event: ChangeEvent) -> None:
        ext = self._ext
        if ext._emit is None:
            return

        marker = f"/{TRACKING_CONFIG_PREFIX}"
        parts = event.uri.split(marker, 1)
        if len(parts) != 2 or not parts[1]:
            return
        key = parts[1]

        if event.kind == ChangeKind.DELETED:
            ext._configs.pop(key, None)
            return

        if event.entity is None or event.entity.type != TRACKING_CONFIG_TYPE:
            return

        prefix = event.entity.data.get("prefix", "")
        enabled = bool(event.entity.data.get("enabled", False))

        if not enabled or not prefix:
            ext._configs.pop(key, None)
            return

        config = _load_revision_config(ext._emit, prefix)
        if config is None:
            return

        ext._configs[key] = config


def _load_revision_config(emit: EmitPathway, prefix: str) -> _AutoVersionConfig | None:
    """Read revision config from hash-addressed path and parse for auto-version."""
    ph = _prefix_hash_from_emit(emit, prefix)
    config_path = _config_path_for_prefix(ph)
    uri = emit.entity_tree.normalize_uri(config_path)
    h = emit.entity_tree.get(uri)
    if h is None:
        return _AutoVersionConfig(prefix=prefix, auto_version=True, exclude=[])
    entity = emit.content_store.get(h)
    if entity is None or entity.type != REVISION_CONFIG_TYPE:
        return _AutoVersionConfig(prefix=prefix, auto_version=True, exclude=[])
    config = _parse_config(entity.data)
    if config is None:
        return None
    if config.auto_version:
        errors = validate_revision_config(entity.data)
        if errors:
            logger.error("AutoVersion: config for prefix %r is invalid: %s", prefix, "; ".join(errors))
            return None
    return config


class _TreeWriteHook:
    """Fires on every tree write; produces version entries per enabled config."""

    def __init__(self, ext: AutoVersionExtension) -> None:
        self._ext = ext

    def on_change_sync(self, event: ChangeEvent) -> None:
        try:
            self._handle(event)
        except Exception:
            logger.exception("AutoVersion tree write hook failed on %s", event.uri)

    def _handle(self, event: ChangeEvent) -> None:
        ext = self._ext
        if ext._emit is None:
            return

        # Strip the peer prefix to get the logical path.
        peer_prefix = f"/{ext._peer_id}/"
        if not event.uri.startswith(peer_prefix):
            return
        relative = event.uri[len(peer_prefix):]

        # Self-guard: never re-trigger on our own engine paths.
        if _is_engine_write(relative):
            return

        # Snapshot configs (copy to avoid mutation during iteration).
        for config in list(ext._configs.values()):
            if not config.auto_version:
                continue
            ext._fire_for_config(config, relative, event)


class AutoVersionExtension(Extension):
    """Per-write auto-version emit consumer (position 7)."""

    def __init__(self) -> None:
        self._configs: dict[str, _AutoVersionConfig] = {}
        self._emit: EmitPathway | None = None
        self._peer_id: str = ""
        self._config_watcher: _ConfigWatcher | None = None
        self._tree_write_hook: _TreeWriteHook | None = None

    def initialize(self, ctx: ExtensionContext) -> None:
        if ctx.emit_pathway is None:
            logger.warning("AutoVersionExtension: no emit_pathway; disabled")
            return

        self._emit = ctx.emit_pathway
        self._peer_id = ctx.peer_id

        self._config_watcher = _ConfigWatcher(self)
        ctx.emit_pathway._add_internal_hook(
            self._config_watcher,
            pattern=f"/{ctx.peer_id}/{TRACKING_CONFIG_PREFIX}*",
            name="revision/auto-version/config-watcher",
        )

        self._tree_write_hook = _TreeWriteHook(self)
        ctx.emit_pathway._add_internal_hook(self._tree_write_hook, name="revision/auto-version/tree-write")

        # Load existing configs.
        self._load_existing_configs()

        logger.info("AutoVersionExtension initialized at position 7")

    def _load_existing_configs(self) -> None:
        if self._emit is None:
            return
        tc_prefix = self._emit.entity_tree.normalize_uri(TRACKING_CONFIG_PREFIX)
        for uri in self._emit.entity_tree.list_prefix(tc_prefix):
            h = self._emit.entity_tree.get(uri)
            if h is None:
                continue
            entity = self._emit.content_store.get(h)
            if entity is None or entity.type != TRACKING_CONFIG_TYPE:
                continue
            prefix = entity.data.get("prefix", "")
            enabled = bool(entity.data.get("enabled", False))
            if not enabled or not prefix:
                continue
            marker = f"/{TRACKING_CONFIG_PREFIX}"
            key = uri.split(marker, 1)[-1]
            config = _load_revision_config(self._emit, prefix)
            if config is not None:
                self._configs[key] = config

    def shutdown(self) -> None:
        if self._emit is not None:
            if self._tree_write_hook is not None:
                self._emit._remove_internal_hook(self._tree_write_hook)
            if self._config_watcher is not None:
                self._emit._remove_internal_hook(self._config_watcher)
        self._configs.clear()
        self._tree_write_hook = None
        self._config_watcher = None

    # -------------------------------------------------------------------------
    # Per-write algorithm (§6.1)
    # -------------------------------------------------------------------------

    def _fire_for_config(
        self,
        config: _AutoVersionConfig,
        event_relative_path: str,
        event: ChangeEvent,
    ) -> None:
        """Produce a version entry for one tracked config, if applicable."""
        emit = self._emit
        if emit is None:
            return

        # Canonical prefix (strip leading/trailing '/')
        canonical = config.prefix.strip("/")

        # Does this event's path fall under the tracked prefix?
        if canonical:
            if not event_relative_path.startswith(canonical + "/"):
                return
            path_in_prefix = event_relative_path[len(canonical) + 1:]
        else:
            # Universal tree
            path_in_prefix = event_relative_path

        # Match exclude patterns against the in-prefix path.
        if _exclude_matches(config.exclude, path_in_prefix):
            return

        # Read tracked root via canonical storage path (§6B).
        root_binding_path = _root_binding_path(config.prefix)
        root_uri = emit.entity_tree.normalize_uri(root_binding_path)
        tracked_root = emit.entity_tree.get(root_uri)

        # Tracking-config coordination (§4 MUST-level): if auto_version is on
        # for a prefix but no tracked root is being maintained, we cannot
        # safely produce a version entry. Log and skip — the write has
        # already landed; per §4 "Internal failure handling" the version
        # entry MUST eventually land too, but absent a tracking config we
        # have no way to produce a correct one. Surfacing via logger.error
        # (an operator signal) rather than silent fall-back.
        if tracked_root is None:
            logger.error(
                "AutoVersion: tracking-config missing or disabled for prefix %r;"
                " cannot produce version entry for write to %s",
                config.prefix, event.uri,
            )
            return

        # Compute hash-addressed prefix segment (§3.1).
        absolute_prefix = emit.entity_tree.normalize_uri(config.prefix)
        ph = compute_ecf_hash({"type": "system/tree/path", "data": absolute_prefix}).hex()

        # Read current head.
        head_path = _head_path(ph)
        head_uri = emit.entity_tree.normalize_uri(head_path)
        head_hash = emit.entity_tree.get(head_uri)
        current_head_entity = None
        if head_hash is not None:
            current_head_entity = emit.content_store.get(head_hash)

        # Dedup: suppress when the current head already describes this root.
        if (
            current_head_entity is not None
            and current_head_entity.type == VERSION_ENTRY_TYPE
            and current_head_entity.data.get("root") == tracked_root
        ):
            return

        # Build parents list from current head (if any).
        parents: list[bytes] = []
        if head_hash is not None:
            # The head binding may wrap the version hash in a `system/hash`
            # entity (see revision._update_head_and_branch). Resolve to the
            # actual version entry hash.
            parents_hash = _resolve_head_to_version_hash(emit, head_hash)
            if parents_hash is not None:
                parents.append(parents_hash)

        # Create version entry (structural: root + sorted parents).
        version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={
                "root": tracked_root,
                "parents": sorted_parents(parents),
            },
        )
        version_hash = emit.content_store.put(version)

        # Advance head. Use the same wire shape as _update_head_and_branch
        # (a `system/hash` wrapper entity) so revision handlers can read it
        # uniformly. Single-writer serialization under asyncio means CAS is
        # unnecessary here.
        ectx = EmitContext(author=self._peer_id, source="handler")
        head_entity = Entity(type="system/hash", data={"hash": version_hash})
        emit.emit(head_path, head_entity, ectx)

        # Advance active-branch if configured.
        ab_path = _active_branch_path(ph)
        ab_uri = emit.entity_tree.normalize_uri(ab_path)
        ab_hash = emit.entity_tree.get(ab_uri)
        if ab_hash is not None:
            ab_entity = emit.content_store.get(ab_hash)
            if ab_entity is not None and ab_entity.type == "primitive/string":
                branch_name = ab_entity.data
                emit.emit(_branch_path(ph, branch_name), head_entity, ectx)


def _resolve_head_to_version_hash(
    emit: EmitPathway, head_binding_hash: bytes,
) -> bytes | None:
    """The head binding points at a `system/hash` wrapper (current revision
    handler convention); unwrap to the actual version entry hash.
    """
    entity = emit.content_store.get(head_binding_hash)
    if entity is None:
        return None
    if entity.type == VERSION_ENTRY_TYPE:
        return head_binding_hash
    if entity.type == "system/hash":
        h = entity.data.get("hash")
        if isinstance(h, bytes):
            return h
    return None
