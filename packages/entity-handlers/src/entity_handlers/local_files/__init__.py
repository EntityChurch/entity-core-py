"""DOMAIN-LOCAL-FILES v1.2 — host filesystem ↔ entity tree bridge.

The handler maps a host filesystem subtree into the entity tree, making
filesystem content accessible through the entity protocol. Files become
entities; directories become listings. Content lives in the CONTENT v3.5
substrate as a blob + chunks; file entities carry only a ``system/hash``
reference into the content store, so the same bytes through any handler
produce structurally-shared chunks (cross-handler dedup).

This package exports:

* :data:`LOCAL_FILES_HANDLER_PATTERN` — registration pattern (``local/files``).
* :func:`local_files_handler` — the EXECUTE dispatcher (``read`` / ``write`` /
  ``list`` / ``delete`` / ``watch``).
* :class:`LocalFilesExtension` — root-mapping store, reverse-write
  subscription, type registration. Initialized via ``PeerBuilder``.
* :data:`LOCAL_FILES_TYPE_DEFS` — the eight domain types installed at
  ``system/type/local/files/*``.
* :func:`add_root_mapping` — convenience for tests / CLI: configure a
  filesystem root and persist its ``local/files/root-config`` entity.

See ``../entity-core-architecture/.../specs/domains/DOMAIN-LOCAL-FILES.md``
for the normative spec. The Go reference impl lives at
``../entity-core-go/ext/localfiles``.
"""

from entity_handlers.local_files.types import (
    LOCAL_FILES_TYPE_DEFS,
    TYPE_DELETED,
    TYPE_DIRECTORY,
    TYPE_DIRECTORY_ENTRY,
    TYPE_FILE,
    TYPE_ROOT_CONFIG,
    TYPE_WATCH_REQUEST,
    TYPE_WATCHER_CONFIG,
    TYPE_WRITE_REQUEST,
)
from entity_handlers.local_files.config import (
    ROOT_CONFIG_PREFIX,
    RootMapping,
    add_root_mapping,
)
from entity_handlers.local_files.handler import (
    LOCAL_FILES_HANDLER_PATTERN,
    local_files_handler,
)
from entity_handlers.local_files.extension import LocalFilesExtension

__all__ = [
    "LOCAL_FILES_HANDLER_PATTERN",
    "LOCAL_FILES_TYPE_DEFS",
    "ROOT_CONFIG_PREFIX",
    "LocalFilesExtension",
    "RootMapping",
    "TYPE_DELETED",
    "TYPE_DIRECTORY",
    "TYPE_DIRECTORY_ENTRY",
    "TYPE_FILE",
    "TYPE_ROOT_CONFIG",
    "TYPE_WATCH_REQUEST",
    "TYPE_WATCHER_CONFIG",
    "TYPE_WRITE_REQUEST",
    "add_root_mapping",
    "local_files_handler",
]
