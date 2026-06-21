"""Root mapping registry + path translation + glob filters.

A root mapping binds one tree prefix (e.g. ``local/files/shared/``) to
one filesystem directory (e.g. ``/home/alice/shared/``). Multiple roots
are allowed; their tree prefixes MUST NOT overlap (the spec §1.2 root-
isolation rule).

The handler keeps an in-memory dict keyed by mapping name; the source-
of-truth representation is a ``local/files/root-config`` entity at
``system/config/local/files/{name}`` so a peer restart can rehydrate the
mapping from the tree alone. ``add_root_mapping`` is the create path
(persists + maps); a future ``load`` will be the rehydrate path
(rebuilds the in-memory map from already-persisted configs, mirroring
the Go reference's ``Handler.Load`` flow).
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

from entity_handlers.local_files.types import TYPE_ROOT_CONFIG

if TYPE_CHECKING:
    from entity_core.storage.emit import EmitPathway

# All persisted root configs live under this tree prefix. Watcher configs
# live one level deeper at ``system/config/local/files/watch/{name}`` —
# the rehydrate-from-tree filter skips the watch/ subnamespace.
ROOT_CONFIG_PREFIX: str = "system/config/local/files/"


@dataclass
class RootMapping:
    """In-memory representation of one configured filesystem root.

    The fields mirror the persisted ``local/files/root-config`` entity
    with the filesystem root resolved to an absolute path so path-
    translation work doesn't have to redo the resolution on each call.
    """

    name: str
    prefix: str  # Tree prefix, always ends with "/"
    filesystem_root: str  # Absolute filesystem path
    read_only: bool = False
    exclude: list[str] = field(default_factory=list)
    include: list[str] = field(default_factory=list)
    publish_descriptors: bool = False


def _normalize_prefix(prefix: str) -> str:
    """Ensure tree prefixes end with ``/`` so prefix matching is
    unambiguous (``local/files/shared/foo`` startswith
    ``local/files/shared/`` but NOT ``local/files/shared`` if that prefix
    is ``local/files/sharedstuff/``).
    """
    if prefix and not prefix.endswith("/"):
        return prefix + "/"
    return prefix


def find_root_mapping(
    roots: dict[str, RootMapping], tree_path: str
) -> RootMapping | None:
    """Return the root mapping covering ``tree_path`` (longest-prefix wins)."""
    best: RootMapping | None = None
    for root in roots.values():
        if tree_path.startswith(root.prefix):
            if best is None or len(root.prefix) > len(best.prefix):
                best = root
    return best


def resolve_fs_path(root: RootMapping, tree_path: str) -> tuple[str, str]:
    """Translate a tree path into ``(absolute_fs_path, relative_path)``.

    Path-traversal protection: the resolved canonical path MUST stay
    within ``root.filesystem_root`` after symlink expansion. ``..``
    segments that would escape the root raise ``PermissionError`` —
    callers map that to a 403 ``path_traversal_rejected`` response per
    spec §8.3.

    The relative-path component is what the file entity's ``path``
    field carries (spec §2.1) — the suffix below the tree prefix, not
    the full tree path.
    """
    relative_path = tree_path[len(root.prefix):]
    fs_path = os.path.join(root.filesystem_root, relative_path)

    # Canonicalize both sides for the containment check. ``realpath``
    # collapses ``..`` and follows symlinks; if either side doesn't
    # exist yet we fall back to ``abspath`` (write/create flows write
    # the file last — the parent dir must still resolve inside the root).
    try:
        canonical_root = os.path.realpath(root.filesystem_root)
    except OSError:
        canonical_root = os.path.abspath(root.filesystem_root)

    parent = os.path.dirname(fs_path) or fs_path
    try:
        canonical_parent = os.path.realpath(parent)
    except OSError:
        canonical_parent = os.path.abspath(parent)
    resolved = os.path.join(canonical_parent, os.path.basename(fs_path))

    canonical_root_with_sep = canonical_root.rstrip(os.sep) + os.sep
    if not (
        resolved == canonical_root
        or resolved.startswith(canonical_root_with_sep)
    ):
        raise PermissionError(
            f"path traversal rejected: {tree_path!r} escapes root "
            f"{root.filesystem_root!r}"
        )

    return fs_path, relative_path


def matches_exclude(name: str, patterns: list[str]) -> bool:
    """True iff ``name`` matches any of the exclude glob patterns."""
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def matches_include(name: str, patterns: list[str]) -> bool:
    """True iff the include filter admits ``name`` (or is empty).

    Empty include list = no positive filter — all non-excluded files
    are admitted. Non-empty = ``name`` must match at least one pattern
    (spec §2.5 admission rule).
    """
    if not patterns:
        return True
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def file_admitted(name: str, exclude: list[str], include: list[str]) -> bool:
    """Spec §2.5 file admission: ``!exclude AND (include empty || include)``.

    Used by the list operation (file filter) and the file watcher (event
    filter). Directory descent is governed by exclude alone.
    """
    if matches_exclude(name, exclude):
        return False
    return matches_include(name, include)


def root_config_path(name: str) -> str:
    """Tree path where the ``local/files/root-config`` entity for
    mapping ``name`` is persisted.
    """
    return f"{ROOT_CONFIG_PREFIX}{name}"


def add_root_mapping(
    roots: dict[str, RootMapping],
    emit_pathway: "EmitPathway",
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

    Mutates ``roots`` in place. Persists a ``local/files/root-config``
    entity at ``system/config/local/files/{name}`` so a peer restart can
    rehydrate the mapping from the tree alone (the bootstrap flow the
    Go reference's ``Handler.Load`` implements; the Python build flow
    follows the same persistence layout).

    Raises ``ValueError`` on overlapping prefixes (spec §1.2 root-
    isolation rule).
    """
    abs_root = os.path.abspath(filesystem_root)
    norm_prefix = _normalize_prefix(prefix)

    for existing in roots.values():
        if existing.name == name:
            continue
        if norm_prefix.startswith(existing.prefix) or existing.prefix.startswith(
            norm_prefix
        ):
            raise ValueError(
                f"prefix {norm_prefix!r} overlaps with existing root "
                f"{existing.name!r} (prefix {existing.prefix!r})"
            )

    mapping = RootMapping(
        name=name,
        prefix=norm_prefix,
        filesystem_root=abs_root,
        read_only=read_only,
        exclude=list(exclude or []),
        include=list(include or []),
        publish_descriptors=publish_descriptors,
    )
    roots[name] = mapping

    config_data: dict = {
        "prefix": norm_prefix,
        "filesystem_root": abs_root,
    }
    if read_only:
        config_data["read_only"] = True
    if exclude:
        config_data["exclude"] = list(exclude)
    if include:
        config_data["include"] = list(include)
    if publish_descriptors:
        config_data["publish_descriptors"] = True

    config_entity = Entity(type=TYPE_ROOT_CONFIG, data=config_data)
    emit_pathway.emit(
        root_config_path(name), config_entity, EmitContext.bootstrap()
    )

    return mapping


__all__ = [
    "ROOT_CONFIG_PREFIX",
    "RootMapping",
    "add_root_mapping",
    "file_admitted",
    "find_root_mapping",
    "matches_exclude",
    "matches_include",
    "resolve_fs_path",
    "root_config_path",
]
