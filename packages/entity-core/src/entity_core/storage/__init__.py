"""Storage layer for Entity Core.

Two-layer storage:
- ContentStore: Hash -> Entity (immutable, content-addressed)
- EntityTree: URI -> Hash (mutable, location index)
- EmitPathway: Consolidated write entry point with change events
- TreeRegistry: Manages non-default trees (EXTENSION-TREE.md)

Secondary indexes (EXTENSION-QUERY v1.0):
- IndexManager: Coordinates secondary indexes via InternalHook
- TypeIndex / InMemoryTypeIndex: Entity type → (path, hash)
- ReverseHashIndex / InMemoryReverseHashIndex: Referenced hash → referrers
- PathLinkIndex / InMemoryPathLinkIndex: Referenced path → referrers
"""

from entity_core.storage.content_store import (
    ContentStore,
    ContentStoreEvent,
    ContentStoreHook,
    NotifyingContentStore,
)
from entity_core.storage.emit import (
    AsyncChangeListener,
    ChangeEvent,
    ChangeKind,
    ConsumerHaltInfo,
    EmitContext,
    EmitPathway,
    EmitResult,
    InternalHook,
)
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.indexes import (
    IndexManager,
    InMemoryPathLinkIndex,
    InMemoryReverseHashIndex,
    InMemoryTypeIndex,
    PathLinkIndex,
    ReverseHashIndex,
    ReverseIndexEntry,
    TypeIndex,
    TypeIndexEntry,
)
from entity_core.storage.tree_registry import TreeRegistry

__all__ = [
    "ContentStore",
    "ContentStoreEvent",
    "ContentStoreHook",
    "NotifyingContentStore",
    "EntityTree",
    "EmitPathway",
    "ChangeKind",
    "ChangeEvent",
    "EmitContext",
    "EmitResult",
    "ConsumerHaltInfo",
    "AsyncChangeListener",
    "InternalHook",
    "TreeRegistry",
    # Secondary indexes (EXTENSION-QUERY v1.0)
    "IndexManager",
    "TypeIndex",
    "InMemoryTypeIndex",
    "ReverseHashIndex",
    "InMemoryReverseHashIndex",
    "PathLinkIndex",
    "InMemoryPathLinkIndex",
    "TypeIndexEntry",
    "ReverseIndexEntry",
]
