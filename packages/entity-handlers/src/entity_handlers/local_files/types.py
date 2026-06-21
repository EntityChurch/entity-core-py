"""Type names + type-definition entities for DOMAIN-LOCAL-FILES v1.2.

The eight type entities here are installed at ``system/type/local/files/*``
by the :class:`LocalFilesExtension` at peer build. The shapes mirror the
spec §2 field-by-field; field types reference the V7 primitives.

Note on naming: the spec spells the directory-entry type as
``local/files/directory/entry`` (slash, not hyphen). We register it that
way so the validate-peer ``type_directory_entry`` check at
``system/type/local/files/directory/entry`` resolves.
"""

from __future__ import annotations

from typing import Any

TYPE_FILE: str = "local/files/file"
TYPE_DIRECTORY: str = "local/files/directory"
TYPE_DIRECTORY_ENTRY: str = "local/files/directory/entry"
TYPE_DELETED: str = "local/files/deleted"
TYPE_ROOT_CONFIG: str = "local/files/root-config"
TYPE_WATCHER_CONFIG: str = "local/files/watcher-config"
TYPE_WRITE_REQUEST: str = "local/files/write-request"
TYPE_WATCH_REQUEST: str = "local/files/watch-request"


# Per DOMAIN-LOCAL-FILES v1.2 §2. ``optional: true`` flags follow the
# spec verbatim; the handler decides absence-vs-default at the call site.
LOCAL_FILES_TYPE_DEFS: list[dict[str, Any]] = [
    {
        "name": TYPE_FILE,
        "description": "File metadata entity carrying a system/content/blob hash (v1.2 §2.1).",
        "fields": {
            "path": {"type_ref": "primitive/string"},
            "size": {"type_ref": "primitive/uint"},
            "modified_at": {"type_ref": "primitive/uint", "optional": True},
            "content": {"type_ref": "system/hash"},
            "media_type": {"type_ref": "primitive/string", "optional": True},
            "written": {"type_ref": "primitive/bool", "optional": True},
        },
    },
    {
        "name": TYPE_DIRECTORY,
        "description": "Directory listing (v1.2 §2.2).",
        "fields": {
            "path": {"type_ref": "primitive/string"},
            "children": {
                "array_of": {"type_ref": TYPE_DIRECTORY_ENTRY},
                "optional": True,
            },
            "modified_at": {"type_ref": "primitive/uint", "optional": True},
        },
    },
    {
        "name": TYPE_DIRECTORY_ENTRY,
        "description": "Directory entry within a listing (v1.2 §2.3).",
        "fields": {
            "name": {"type_ref": "primitive/string"},
            "entity_path": {"type_ref": "system/tree/path"},
            "entry_type": {"type_ref": "primitive/string"},
            "size": {"type_ref": "primitive/uint", "optional": True},
            "modified_at": {"type_ref": "primitive/uint", "optional": True},
        },
    },
    {
        "name": TYPE_DELETED,
        "description": "Delete confirmation entity (v1.2 §2.4).",
        "fields": {
            "path": {"type_ref": "primitive/string"},
            "existed": {"type_ref": "primitive/bool"},
        },
    },
    {
        "name": TYPE_ROOT_CONFIG,
        "description": "Root mapping configuration (v1.2 §2.5).",
        "fields": {
            "prefix": {"type_ref": "system/tree/path"},
            "filesystem_root": {"type_ref": "primitive/string"},
            "read_only": {"type_ref": "primitive/bool", "optional": True},
            "exclude": {
                "array_of": {"type_ref": "primitive/string"},
                "optional": True,
            },
            "include": {
                "array_of": {"type_ref": "primitive/string"},
                "optional": True,
            },
            "publish_descriptors": {
                "type_ref": "primitive/bool",
                "optional": True,
            },
        },
    },
    {
        "name": TYPE_WATCHER_CONFIG,
        "description": "File watcher state (v1.2 §2.6).",
        "fields": {
            "root_name": {"type_ref": "primitive/string"},
            "status": {"type_ref": "primitive/string"},
            "debounce_ms": {"type_ref": "primitive/uint", "optional": True},
            "error_message": {
                "type_ref": "primitive/string",
                "optional": True,
            },
        },
    },
    {
        "name": TYPE_WRITE_REQUEST,
        "description": "Write operation parameters (v1.2 §3.2 two-mode).",
        "fields": {
            "bytes": {"type_ref": "primitive/bytes", "optional": True},
            "content": {"type_ref": "system/hash", "optional": True},
            "media_type": {"type_ref": "primitive/string", "optional": True},
            "create_dirs": {"type_ref": "primitive/bool", "optional": True},
        },
    },
    {
        "name": TYPE_WATCH_REQUEST,
        "description": "Watch operation parameters (v1.2 §3.3).",
        "fields": {
            "root_name": {"type_ref": "primitive/string"},
            "action": {"type_ref": "primitive/string", "optional": True},
            "debounce_ms": {"type_ref": "primitive/uint", "optional": True},
        },
    },
]


__all__ = [
    "LOCAL_FILES_TYPE_DEFS",
    "TYPE_DELETED",
    "TYPE_DIRECTORY",
    "TYPE_DIRECTORY_ENTRY",
    "TYPE_FILE",
    "TYPE_ROOT_CONFIG",
    "TYPE_WATCH_REQUEST",
    "TYPE_WATCHER_CONFIG",
    "TYPE_WRITE_REQUEST",
]
