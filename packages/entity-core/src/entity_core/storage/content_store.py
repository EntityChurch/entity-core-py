"""Hash -> Entity immutable content store.

The content store is one of the two storage layers in Entity Core.
It maps content hashes to entities and is immutable (same hash = same content forever).

Key properties:
- Content-addressed (hash -> entity)
- Immutable (content never changes for a given hash)
- Deduplicated (same content stored once)
- Not namespaced (shared across all peers)

V4 Changes:
- Hash is now bytes (algorithm byte + digest)
- Keys are bytes directly (hashable)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import Hash


class ContentStore:
    """Immutable content-addressed storage.

    Maps hash -> Entity. Content never changes for a given hash.
    This is an in-memory implementation for testing.
    """

    def __init__(self) -> None:
        self._store: dict[bytes, Entity] = {}

    def put(self, entity: Entity) -> Hash:
        """Store entity, return its hash.

        Content addressing is idempotent: a hash already in the store cannot
        refer to different content, so re-putting is a no-op. Skip the dict
        write so receiver-side ingestion (envelopes carrying identity +
        signature entities seen across many deliveries) doesn't pay redundant
        write cost — Go-side H-G3 / F2b Layer 1 (`NotifyingContentStore.Put`
        has-before-Put short-circuit; ~60% receiver-side write reduction in
        Go, smaller in Python because this layer is in-memory).

        Args:
            entity: The entity to store.

        Returns:
            The content hash bytes.
        """
        h = entity.compute_hash()
        if h in self._store:
            return h
        self._store[h] = entity
        return h

    def get(self, h: Hash) -> Entity | None:
        """Retrieve entity by hash.

        Args:
            h: The content hash bytes.

        Returns:
            The entity if found, None otherwise.
        """
        return self._store.get(h)

    def has(self, h: Hash) -> bool:
        """Check if hash exists in store.

        Args:
            h: The content hash bytes.

        Returns:
            True if the hash exists in the store.
        """
        return h in self._store

    def __len__(self) -> int:
        """Return number of entities in store."""
        return len(self._store)

    def __contains__(self, h: Hash) -> bool:
        """Support 'hash in store' syntax."""
        return self.has(h)

    def iter_all(self):
        """Iterate over all (hash, entity) pairs. Used by rebuild."""
        yield from self._store.items()


# -------------------------------------------------------------------------
# Content-Store Events (PROPOSAL-CONTENT-STORE-EVENTS / SYSTEM-COMPOSITION v1.2)
# -------------------------------------------------------------------------

_cs_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ContentStoreEvent:
    """Event emitted when a new entity is stored in the content store.

    Only fires when the hash is genuinely new (not already present).
    Distinct from tree-change events (ChangeEvent).
    """

    hash: Hash
    entity: Entity


@runtime_checkable
class ContentStoreHook(Protocol):
    """Synchronous hook for content-store events.

    Content-store consumers at positions 0 (persistence) and 1 (query content indexes).
    """

    def on_content_stored(self, event: ContentStoreEvent) -> None:
        """Handle a new entity being stored."""
        ...


class NotifyingContentStore(ContentStore):
    """ContentStore wrapper that emits events on new entity storage.

    Per PROPOSAL-CONTENT-STORE-EVENTS: fires ContentStoreEvent on put()
    when the hash is genuinely new. Enables content-only writes (envelope
    ingestion, merge material) to become observable.
    """

    def __init__(self) -> None:
        super().__init__()
        self._content_hooks: list[tuple[str, ContentStoreHook]] = []

    def add_content_hook(self, hook: ContentStoreHook, name: str = "") -> None:
        """Register a content-store event hook.

        Hooks fire synchronously in registration order when a new entity
        is stored. Position 0 = persistence, position 1 = query content indexes.
        """
        self._content_hooks.append((name, hook))

    def remove_content_hook(self, hook: ContentStoreHook) -> None:
        """Remove a content-store event hook."""
        self._content_hooks = [(n, h) for n, h in self._content_hooks if h is not hook]

    def put(self, entity: Entity) -> Hash:
        """Store entity and emit event if hash is new.

        Short-circuits on pre-existing hashes (H-G3 / F2b Layer 1) — mirrors
        Go's `NotifyingContentStore.Put` early-return. Hooks already only
        fire when the hash was genuinely new; the short-circuit additionally
        skips the dict write + iteration.
        """
        h = entity.compute_hash()
        if h in self._store:
            return h
        self._store[h] = entity
        if self._content_hooks:
            event = ContentStoreEvent(hash=h, entity=entity)
            for name, hook in self._content_hooks:
                try:
                    hook.on_content_stored(event)
                except Exception:
                    _cs_logger.exception("Content-store hook %r failed", name)
        return h
