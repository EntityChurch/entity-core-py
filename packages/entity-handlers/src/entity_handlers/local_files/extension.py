"""Extension shell — root mappings, type registration, reverse-write hook.

The :class:`LocalFilesExtension` plays three jobs:

1. **Root-mapping store.** In-memory dict ``{name → RootMapping}`` that
   the handler reads on every dispatch. Repopulated on peer build from
   any ``local/files/root-config`` entities already in the tree, so a
   restart resumes mappings without re-running ``add_root_mapping``.

2. **Type registration.** Installs the eight ``local/files/*`` type
   entities at ``system/type/local/files/*`` during ``initialize`` so
   peer introspection and the cross-impl validate-peer ``type_*``
   checks resolve.

3. **Reverse-write subscription.** Hooks the EmitPathway via
   :func:`install_reverse_write_hook` so any tree change under a
   configured root prefix projects to disk (spec §5).

The handler dispatcher (in :mod:`entity_handlers.local_files.handler`)
holds a reference to the extension so it can read root mappings and the
recent-write tracker. The extension reference is wired through a
closure at peer-build time (:meth:`LocalFilesExtension.handler`),
mirroring the QueryExtension / ComputeExtension idiom.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from entity_core.handlers.context import HandlerContext
from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

from entity_handlers.local_files.config import (
    ROOT_CONFIG_PREFIX,
    RootMapping,
)
from entity_handlers.local_files.reverse import (
    RecentWriteTracker,
    install_reverse_write_hook,
)
from entity_handlers.local_files.stat_cache import StatCache
from entity_handlers.local_files.types import (
    LOCAL_FILES_TYPE_DEFS,
    TYPE_ROOT_CONFIG,
)

if TYPE_CHECKING:
    from entity_core.storage.emit import EmitPathway

logger = logging.getLogger(__name__)


HandlerFn = Callable[
    [str, str, dict[str, Any], HandlerContext], Awaitable[dict[str, Any]]
]


class LocalFilesExtension(Extension):
    """Owns root mappings, the recent-write tracker, and the reverse-
    write hook on the EmitPathway.

    Configured roots at ``LocalFilesExtension.add_root(...)`` time;
    persistent across peer restarts via the ``local/files/root-config``
    entities at ``system/config/local/files/{name}``.
    """

    def __init__(self) -> None:
        self.roots: dict[str, RootMapping] = {}
        self.reverse_tracker: RecentWriteTracker = RecentWriteTracker()
        # Stat-cache per v1.3 §10.2 L7 — turns the reverse-write
        # circuit breaker's full-file FastCDC rechunk into a stat-only
        # fast path when the on-disk file is unchanged. See
        # entity_handlers.local_files.stat_cache.
        self.stat_cache: StatCache = StatCache()
        self.emit_pathway: "EmitPathway | None" = None
        self.local_peer_id: str | None = None
        self._reverse_hook = None
        self._ctx: ExtensionContext | None = None

    # ------------------------------------------------------------------
    # Extension lifecycle
    # ------------------------------------------------------------------

    def initialize(self, ctx: ExtensionContext) -> None:
        """Install types, rehydrate roots from the tree, hook reverse-write."""
        self._ctx = ctx
        self.local_peer_id = ctx.peer_id

        if ctx.emit_pathway is None:
            logger.warning(
                "LocalFilesExtension initialized without emit_pathway — "
                "reverse-write will not fire"
            )
            return
        self.emit_pathway = ctx.emit_pathway

        self._register_types()
        self._rehydrate_roots_from_tree()
        self._reverse_hook = install_reverse_write_hook(self)

    def shutdown(self) -> None:
        emit = self.emit_pathway
        if emit is not None and self._reverse_hook is not None:
            emit.unsubscribe(self._reverse_hook)
        self._reverse_hook = None
        self.roots.clear()

    # ------------------------------------------------------------------
    # Handler factory
    # ------------------------------------------------------------------

    def handler(self) -> HandlerFn:
        """Return the dispatch function bound to this extension.

        The PeerBuilder calls ``with_handler(LOCAL_FILES_HANDLER_PATTERN,
        ext.handler(), priority=…)`` so the dispatch sees a plain
        function while still having access to root mappings via the
        captured ``self``.
        """
        from entity_handlers.local_files.handler import build_handler

        return build_handler(self)

    # ------------------------------------------------------------------
    # Root-mapping management
    # ------------------------------------------------------------------

    def add_root(
        self,
        name: str,
        *,
        prefix: str,
        filesystem_root: str,
        read_only: bool = False,
        exclude: list[str] | None = None,
        include: list[str] | None = None,
        publish_descriptors: bool = False,
    ) -> RootMapping:
        """Configure a filesystem root and persist its root-config entity.

        See :func:`entity_handlers.local_files.config.add_root_mapping`
        — this is the extension-bound entry point that uses the
        peer's own emit pathway.
        """
        from entity_handlers.local_files.config import add_root_mapping

        if self.emit_pathway is None:
            raise RuntimeError(
                "LocalFilesExtension.add_root called before extension "
                "initialization"
            )
        return add_root_mapping(
            self.roots,
            self.emit_pathway,
            name,
            prefix=prefix,
            filesystem_root=filesystem_root,
            read_only=read_only,
            exclude=exclude,
            include=include,
            publish_descriptors=publish_descriptors,
        )

    # ------------------------------------------------------------------
    # Bootstrap helpers
    # ------------------------------------------------------------------

    def _register_types(self) -> None:
        """Install ``local/files/*`` type entities at ``system/type/*``.

        Mirrors :func:`entity_handlers.handlers._register_type_defs` —
        same bootstrap context, same path layout, idempotent against
        the content store.
        """
        emit = self.emit_pathway
        if emit is None:
            return
        ctx = EmitContext.bootstrap()
        for type_def in LOCAL_FILES_TYPE_DEFS:
            type_entity = Entity(type="system/type", data=type_def)
            emit.emit(f"system/type/{type_def['name']}", type_entity, ctx)

    def _rehydrate_roots_from_tree(self) -> None:
        """Rebuild in-memory roots from already-persisted root-configs.

        Mirrors the Go reference's ``Handler.Load`` flow — a peer
        restart with persistent storage resumes its configured roots
        without re-running ``add_root``. Watcher configs live one level
        deeper under ``watch/`` and are skipped here (they're managed
        by the watch operation, not the root-mapping table).
        """
        emit = self.emit_pathway
        if emit is None:
            return
        prefix = emit.entity_tree.normalize_uri(ROOT_CONFIG_PREFIX)
        for uri in emit.entity_tree.list_prefix(prefix):
            tail = uri[len(prefix):]
            if not tail or "/" in tail:
                # Skip watch/* and any nested namespaces — only direct
                # children of system/config/local/files/ are root configs.
                continue
            content_hash = emit.entity_tree.get(uri)
            if content_hash is None:
                continue
            entity = emit.content_store.get(content_hash)
            if entity is None or entity.type != TYPE_ROOT_CONFIG:
                continue
            name = tail
            try:
                self.roots[name] = RootMapping(
                    name=name,
                    prefix=entity.data.get("prefix", ""),
                    filesystem_root=entity.data.get("filesystem_root", ""),
                    read_only=bool(entity.data.get("read_only", False)),
                    exclude=list(entity.data.get("exclude") or []),
                    include=list(entity.data.get("include") or []),
                    publish_descriptors=bool(
                        entity.data.get("publish_descriptors", False)
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "local/files: skipping malformed root config %s: %s",
                    uri,
                    exc,
                )


__all__ = ["LocalFilesExtension"]
