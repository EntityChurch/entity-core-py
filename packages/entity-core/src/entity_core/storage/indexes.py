"""Secondary indexes for the query extension (EXTENSION-QUERY v1.0).

Provides abstract index protocols and in-memory implementations for:
- Type index: entity type → set of (path, hash)
- Reverse hash index: referenced hash → set of (source_path, source_type, field_name)
- Path link index: referenced path → set of (source_path, source_type, field_name)

Index maintenance is driven by tree change events via the InternalHook protocol.
Indexes are synchronous with writes per §3.3.

The abstract base classes allow swapping backends (in-memory, SQLite, filesystem)
without changing the IndexManager or query handler.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from entity_core.protocol.entity import Entity
    from entity_core.storage.content_store import ContentStore
    from entity_core.storage.entity_tree import EntityTree

from entity_core.storage.emit import ChangeEvent, ChangeKind

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TypeIndexEntry:
    """A single entry in the type index."""

    type_name: str
    path: str
    hash: bytes


@dataclass(frozen=True)
class ReverseIndexEntry:
    """A single entry in the reverse hash or path link index."""

    source_path: str
    source_type: str
    field_name: str


# ---------------------------------------------------------------------------
# Abstract index protocols
# ---------------------------------------------------------------------------

class TypeIndex(ABC):
    """Maps entity type names to (path, hash) pairs.

    Conformance: MUST (Level 1).
    """

    @abstractmethod
    def add(self, type_name: str, path: str, hash_val: bytes) -> None:
        """Add an entry to the index."""
        ...

    @abstractmethod
    def remove(self, type_name: str, path: str, hash_val: bytes) -> None:
        """Remove a specific entry from the index."""
        ...

    @abstractmethod
    def remove_by_path(self, path: str) -> None:
        """Remove all entries for a given path."""
        ...

    @abstractmethod
    def lookup(self, type_name: str) -> list[TypeIndexEntry]:
        """Look up entries by exact type name."""
        ...

    @abstractmethod
    def lookup_pattern(self, pattern: str) -> list[TypeIndexEntry]:
        """Look up entries by type pattern (exact, glob, or wildcard)."""
        ...

    @abstractmethod
    def all_types(self) -> list[str]:
        """Return all indexed type names."""
        ...

    @abstractmethod
    def clear(self) -> None:
        """Remove all entries."""
        ...


class ReverseHashIndex(ABC):
    """Maps content hashes to the entities that reference them.

    Tracks all bytes values found in entity data at any nesting depth.
    Conformance: MUST (Level 1).
    """

    @abstractmethod
    def add(
        self,
        referenced_hash: bytes,
        source_path: str,
        source_type: str,
        field_name: str,
    ) -> None:
        """Add a reverse reference entry."""
        ...

    @abstractmethod
    def remove_by_source(self, source_path: str) -> None:
        """Remove all entries originating from a source path."""
        ...

    @abstractmethod
    def lookup(self, referenced_hash: bytes) -> list[ReverseIndexEntry]:
        """Find all entities referencing a given hash."""
        ...

    @abstractmethod
    def clear(self) -> None:
        """Remove all entries."""
        ...


class PathLinkIndex(ABC):
    """Maps tree paths to the entities that reference them.

    Tracks system/tree/path values identified by type definition.
    Conformance: SHOULD (Level 1).
    """

    @abstractmethod
    def add(
        self,
        referenced_path: str,
        source_path: str,
        source_type: str,
        field_name: str,
    ) -> None:
        """Add a path link entry."""
        ...

    @abstractmethod
    def remove_by_source(self, source_path: str) -> None:
        """Remove all entries originating from a source path."""
        ...

    @abstractmethod
    def lookup(self, referenced_path: str) -> list[ReverseIndexEntry]:
        """Find all entities referencing a given path."""
        ...

    @abstractmethod
    def clear(self) -> None:
        """Remove all entries."""
        ...


# ---------------------------------------------------------------------------
# In-memory implementations
# ---------------------------------------------------------------------------

class InMemoryTypeIndex(TypeIndex):
    """In-memory type index using dicts.

    O(1) lookup by exact type, O(types) for glob patterns.
    """

    def __init__(self) -> None:
        # type_name → set of (path, hash_bytes)
        self._by_type: dict[str, set[tuple[str, bytes]]] = {}
        # path → type_name (for efficient removal by path)
        self._path_to_type: dict[str, str] = {}

    def add(self, type_name: str, path: str, hash_val: bytes) -> None:
        if type_name not in self._by_type:
            self._by_type[type_name] = set()
        self._by_type[type_name].add((path, hash_val))
        self._path_to_type[path] = type_name

    def remove(self, type_name: str, path: str, hash_val: bytes) -> None:
        entries = self._by_type.get(type_name)
        if entries:
            entries.discard((path, hash_val))
            if not entries:
                del self._by_type[type_name]
        self._path_to_type.pop(path, None)

    def remove_by_path(self, path: str) -> None:
        type_name = self._path_to_type.pop(path, None)
        if type_name is not None:
            entries = self._by_type.get(type_name)
            if entries:
                entries = {(p, h) for p, h in entries if p != path}
                if entries:
                    self._by_type[type_name] = entries
                else:
                    del self._by_type[type_name]

    def lookup(self, type_name: str) -> list[TypeIndexEntry]:
        entries = self._by_type.get(type_name, set())
        return [TypeIndexEntry(type_name=type_name, path=p, hash=h) for p, h in entries]

    def lookup_pattern(self, pattern: str) -> list[TypeIndexEntry]:
        if pattern == "*":
            results = []
            for tn, entries in self._by_type.items():
                results.extend(TypeIndexEntry(type_name=tn, path=p, hash=h) for p, h in entries)
            return results

        if pattern.endswith("/*"):
            prefix = pattern[:-1]  # "app/" for "app/*"
            results = []
            for tn, entries in self._by_type.items():
                if tn.startswith(prefix) or tn == prefix.rstrip("/"):
                    results.extend(TypeIndexEntry(type_name=tn, path=p, hash=h) for p, h in entries)
            return results

        return self.lookup(pattern)

    def all_types(self) -> list[str]:
        return list(self._by_type.keys())

    def clear(self) -> None:
        self._by_type.clear()
        self._path_to_type.clear()

    def type_for_path(self, path: str) -> str | None:
        """Get the type name of the entity at a path (auxiliary lookup)."""
        return self._path_to_type.get(path)


class InMemoryReverseHashIndex(ReverseHashIndex):
    """In-memory reverse hash index with dual bookkeeping.

    Maintains both by-hash and by-source mappings for O(1) lookup
    in either direction.
    """

    def __init__(self) -> None:
        # referenced_hash → set of (source_path, source_type, field_name)
        self._by_hash: dict[bytes, set[tuple[str, str, str]]] = {}
        # source_path → set of referenced_hashes (for efficient removal)
        self._by_source: dict[str, set[bytes]] = {}

    def add(
        self,
        referenced_hash: bytes,
        source_path: str,
        source_type: str,
        field_name: str,
    ) -> None:
        if referenced_hash not in self._by_hash:
            self._by_hash[referenced_hash] = set()
        self._by_hash[referenced_hash].add((source_path, source_type, field_name))

        if source_path not in self._by_source:
            self._by_source[source_path] = set()
        self._by_source[source_path].add(referenced_hash)

    def remove_by_source(self, source_path: str) -> None:
        refs = self._by_source.pop(source_path, set())
        for ref_hash in refs:
            entries = self._by_hash.get(ref_hash)
            if entries:
                entries = {e for e in entries if e[0] != source_path}
                if entries:
                    self._by_hash[ref_hash] = entries
                else:
                    del self._by_hash[ref_hash]

    def lookup(self, referenced_hash: bytes) -> list[ReverseIndexEntry]:
        entries = self._by_hash.get(referenced_hash, set())
        return [
            ReverseIndexEntry(source_path=p, source_type=t, field_name=f)
            for p, t, f in entries
        ]

    def clear(self) -> None:
        self._by_hash.clear()
        self._by_source.clear()


class InMemoryPathLinkIndex(PathLinkIndex):
    """In-memory path link index with dual bookkeeping.

    Same structure as reverse hash index but keyed by path strings.
    """

    def __init__(self) -> None:
        # referenced_path → set of (source_path, source_type, field_name)
        self._by_path: dict[str, set[tuple[str, str, str]]] = {}
        # source_path → set of referenced_paths
        self._by_source: dict[str, set[str]] = {}

    def add(
        self,
        referenced_path: str,
        source_path: str,
        source_type: str,
        field_name: str,
    ) -> None:
        if referenced_path not in self._by_path:
            self._by_path[referenced_path] = set()
        self._by_path[referenced_path].add((source_path, source_type, field_name))

        if source_path not in self._by_source:
            self._by_source[source_path] = set()
        self._by_source[source_path].add(referenced_path)

    def remove_by_source(self, source_path: str) -> None:
        refs = self._by_source.pop(source_path, set())
        for ref_path in refs:
            entries = self._by_path.get(ref_path)
            if entries:
                entries = {e for e in entries if e[0] != source_path}
                if entries:
                    self._by_path[ref_path] = entries
                else:
                    del self._by_path[ref_path]

    def lookup(self, referenced_path: str) -> list[ReverseIndexEntry]:
        entries = self._by_path.get(referenced_path, set())
        return [
            ReverseIndexEntry(source_path=p, source_type=t, field_name=f)
            for p, t, f in entries
        ]

    def clear(self) -> None:
        self._by_path.clear()
        self._by_source.clear()


# ---------------------------------------------------------------------------
# Entity data walking utilities
# ---------------------------------------------------------------------------

def collect_hash_refs(data: dict[str, Any]) -> list[tuple[str, bytes]]:
    """Walk entity data recursively to find all bytes values (hash references).

    In the V4 refless architecture, system/hash values are stored as raw
    bytes in entity data. This walks all nested dicts, lists, and tuples
    to collect (top_level_field_name, hash_bytes) pairs.

    Args:
        data: Entity data dict.

    Returns:
        List of (field_name, hash_bytes) tuples.
    """
    if not isinstance(data, dict):
        return []
    results: list[tuple[str, bytes]] = []
    for field_name, value in data.items():
        _walk_for_bytes(value, field_name, results)
    return results


def _walk_for_bytes(
    value: Any,
    field_name: str,
    results: list[tuple[str, bytes]],
) -> None:
    """Recursively walk a value, collecting bytes objects."""
    if isinstance(value, bytes):
        results.append((field_name, value))
    elif isinstance(value, dict):
        for v in value.values():
            _walk_for_bytes(v, field_name, results)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk_for_bytes(item, field_name, results)


# ---------------------------------------------------------------------------
# IndexManager - coordinates indexes, implements InternalHook
# ---------------------------------------------------------------------------

class IndexManager:
    """Coordinates secondary indexes and maintains them via tree change events.

    Implements the InternalHook protocol for synchronous index updates.
    Provides query methods used by the query handler.

    Args:
        content_store: Content store for resolving entities by hash.
        type_index: Type index implementation (default: InMemoryTypeIndex).
        reverse_index: Reverse hash index implementation (default: InMemoryReverseHashIndex).
        path_link_index: Optional path link index implementation.
    """

    def __init__(
        self,
        content_store: "ContentStore",
        type_index: TypeIndex | None = None,
        reverse_index: ReverseHashIndex | None = None,
        path_link_index: PathLinkIndex | None = None,
    ) -> None:
        self._content_store = content_store
        self.type_index: TypeIndex = type_index or InMemoryTypeIndex()
        self.reverse_index: ReverseHashIndex = reverse_index or InMemoryReverseHashIndex()
        self.path_link_index: PathLinkIndex | None = path_link_index

    # -- InternalHook protocol --

    def on_change_sync(self, event: ChangeEvent) -> None:
        """Update indexes on tree change. Called synchronously by EmitPathway."""
        if event.kind in (ChangeKind.UPDATED, ChangeKind.DELETED):
            self._remove_entries(event.uri, event.previous_hash)

        if event.kind in (ChangeKind.CREATED, ChangeKind.UPDATED):
            self._add_entries(event.uri, event.hash, event.entity)

    # -- Rebuild --

    def rebuild(self, entity_tree: "EntityTree") -> None:
        """Rebuild all indexes from full tree scan (§3.4).

        Clears existing indexes and re-indexes every tree-bound entity.
        O(all tree-bound entities). Use for startup or recovery.
        """
        self.type_index.clear()
        self.reverse_index.clear()
        if self.path_link_index:
            self.path_link_index.clear()

        for uri, hash_val in entity_tree.all_bindings():
            entity = self._content_store.get(hash_val)
            if entity is not None:
                self._index_entity(uri, hash_val, entity)

        logger.debug(
            "Index rebuild complete: %d types indexed",
            len(self.type_index.all_types()),
        )

    # -- Internal helpers --

    def _remove_entries(self, uri: str, previous_hash: bytes | None) -> None:
        """Remove index entries for an entity being updated or deleted."""
        if previous_hash is None:
            return

        old_entity = self._content_store.get(previous_hash)
        if old_entity is not None:
            self.type_index.remove(old_entity.type, uri, previous_hash)
        else:
            # Entity not in content store (shouldn't happen), remove by path
            self.type_index.remove_by_path(uri)

        self.reverse_index.remove_by_source(uri)
        if self.path_link_index:
            self.path_link_index.remove_by_source(uri)

    def _add_entries(
        self,
        uri: str,
        hash_val: bytes | None,
        entity: "Entity | None",
    ) -> None:
        """Add index entries for a new or updated entity."""
        if hash_val is None:
            return

        if entity is None:
            entity = self._content_store.get(hash_val)
        if entity is None:
            return

        self._index_entity(uri, hash_val, entity)

    def _index_entity(self, uri: str, hash_val: bytes, entity: "Entity") -> None:
        """Index a single entity across all indexes."""
        self.type_index.add(entity.type, uri, hash_val)

        for field_name, ref_hash in collect_hash_refs(entity.data):
            self.reverse_index.add(ref_hash, uri, entity.type, field_name)
