"""Emit Pathway for consolidated entity writes with change event hooks.

The EmitPathway provides a single entry point for all entity writes,
enabling extensions (subscriptions, indexes, compute, GC) to tap into
tree changes without modifying EntityCore.

Architecture:
    EntityCore exposes hooks, extensions register listeners.
    All writes flow through EmitPathway, which dispatches ChangeEvents
    to registered listeners based on path patterns.

Key concepts:
- ChangeKind: created/updated/deleted
- EmitContext: metadata about the write (author, chain_id, source)
- ChangeEvent: immutable event describing what changed
- Subscriptions: async listeners registered at path patterns
- Internal hooks: sync hooks for core infrastructure (indexes, etc.)

V4 Changes:
- hash and previous_hash are now bytes (algorithm byte + digest)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from entity_core.protocol.bounds import Bounds

from entity_core.utils.ecf import Hash, hash_equals


class ChangeKind(Enum):
    """Kind of change to an entity in the tree."""

    CREATED = "created"  # New URI (no previous hash)
    UPDATED = "updated"  # Existing URI changed (new hash differs from previous)
    DELETED = "deleted"  # URI removed from tree


@dataclass(frozen=True)
class EmitContext:
    """Metadata for a write operation.

    Attributes:
        author: Peer ID of the entity that initiated the write.
        chain_id: Request chain identifier for tracing.
        source: Where the write originated from ("handler", "protocol", "bootstrap").
        bounds: Resource bounds context (if from a request).
        capability: Content hash of the grant that authorized this specific write.
            For caller-authorized writes, the caller's capability.
            For handler-authorized writes, the handler's own grant.
        handler_pattern: Handler pattern that processed the operation (e.g., "system/tree").
        operation: Operation name (e.g., "put", "get").
        author_hash: Content hash of the author's identity entity (system/hash bytes).
        caller_capability: Content hash of the original caller's capability (W6).
            Present only for handler-authorized writes where it differs from capability.
    """

    author: str | None = None
    chain_id: str | None = None
    parent_chain_id: str | None = None
    source: str = "handler"
    bounds: "Bounds | None" = None
    capability: bytes | None = None
    handler_pattern: str | None = None
    operation: str | None = None
    author_hash: bytes | None = None
    caller_capability: bytes | None = None

    @classmethod
    def bootstrap(cls) -> EmitContext:
        """Create context for bootstrap/startup writes."""
        return cls(author=None, chain_id=None, source="bootstrap")

    @classmethod
    def protocol(
        cls,
        author: str,
        chain_id: str | None = None,
        capability: bytes | None = None,
        handler_pattern: str | None = None,
        operation: str | None = None,
    ) -> EmitContext:
        """Create context for protocol-level writes (e.g., direct put)."""
        return cls(
            author=author,
            chain_id=chain_id,
            source="protocol",
            capability=capability,
            handler_pattern=handler_pattern,
            operation=operation,
        )

    @classmethod
    def handler(
        cls,
        author: str,
        chain_id: str | None = None,
        bounds: "Bounds | None" = None,
        capability: bytes | None = None,
        handler_pattern: str | None = None,
        operation: str | None = None,
    ) -> EmitContext:
        """Create context for handler-initiated writes."""
        return cls(
            author=author,
            chain_id=chain_id,
            source="handler",
            bounds=bounds,
            capability=capability,
            handler_pattern=handler_pattern,
            operation=operation,
        )

    @classmethod
    def from_handler_context(cls, ctx: Any, operation: str) -> EmitContext:
        """Create EmitContext for caller-authorized writes.

        Uses the caller's capability as the authorizing grant. For writes
        to paths determined by the caller's request (e.g., tree put).
        caller_capability is None because capability IS the caller's grant.

        Args:
            ctx: A HandlerContext instance.
            operation: The operation name (e.g., "put").
        """
        return cls(
            author=ctx.remote_peer_id,
            chain_id=ctx.chain_id,
            parent_chain_id=getattr(ctx, "parent_chain_id", None),
            source="handler",
            bounds=ctx.bounds,
            capability=getattr(ctx, "caller_capability_hash", None),
            handler_pattern=ctx.handler_pattern,
            operation=operation,
            author_hash=getattr(ctx, "remote_identity_hash", None),
            # caller_capability=None: capability IS the caller's grant (W6)
        )

    @classmethod
    def from_handler_grant(cls, ctx: Any, operation: str) -> EmitContext:
        """Create EmitContext for handler-authorized writes.

        Uses the handler's own grant as the authorizing capability. For writes
        to the handler's managed namespace (e.g., system/subscription/*).
        Includes caller_capability when a caller triggered the chain (W6).

        Args:
            ctx: A HandlerContext instance.
            operation: The operation name (e.g., "subscribe").
        """
        caller_cap = getattr(ctx, "caller_capability_hash", None)
        handler_cap = getattr(ctx, "handler_grant_hash", None)
        # W6: Only include caller_capability when it differs from capability
        include_caller = caller_cap if (caller_cap and caller_cap != handler_cap) else None
        return cls(
            author=ctx.remote_peer_id,
            chain_id=ctx.chain_id,
            parent_chain_id=getattr(ctx, "parent_chain_id", None),
            source="handler",
            bounds=ctx.bounds,
            capability=handler_cap,
            handler_pattern=ctx.handler_pattern,
            operation=operation,
            author_hash=getattr(ctx, "remote_identity_hash", None),
            caller_capability=include_caller,
        )


# Import Entity after EmitContext to avoid circular import issues
from entity_core.protocol.entity import Entity


@dataclass(frozen=True)
class ChangeEvent:
    """Immutable event describing a change to the entity tree.

    V4: hash and previous_hash are bytes (already hashable and immutable).

    Attributes:
        kind: Type of change (created/updated/deleted).
        uri: Full normalized URI that changed.
        hash: Content hash bytes (None for deleted).
        entity: The entity itself (None for deleted).
        previous_hash: Previous hash bytes at this URI (None for created).
        context: Metadata about who/why the change happened.
    """

    kind: ChangeKind
    uri: str
    hash: Hash | None  # V4: bytes, already hashable
    entity: Entity | None
    previous_hash: Hash | None  # V4: bytes, already hashable
    context: EmitContext
    cascade_depth: int = 0

    def get_hash(self) -> Hash | None:
        """Get the content hash (for API compatibility)."""
        return self.hash

    def get_previous_hash(self) -> Hash | None:
        """Get the previous hash (for API compatibility)."""
        return self.previous_hash


@dataclass(frozen=True)
class ConsumerHaltInfo:
    """Information about a consumer that halted the cascade.

    Attributes:
        name: The consumer's registered name.
        status: The status code returned.
        intentional: True if the consumer deliberately halted (returned non-200).
            False if the halt was due to an internal error (exception caught).
    """

    name: str
    status: int
    intentional: bool = True


@dataclass(frozen=True)
class EmitResult:
    """Result from emit(), carrying both hash and cascade status.

    status 200 = fully complete, 207 = binding landed but cascade
    incomplete, 503 = system refusal (binding did NOT commit).
    """

    hash: Hash | None
    status: int = 200
    consumers_completed: tuple[str, ...] = ()
    consumers_halted: ConsumerHaltInfo | None = None
    consumers_skipped: tuple[str, ...] = ()
    cascade_depth: int = 0


@runtime_checkable
class AsyncChangeListener(Protocol):
    """Protocol for asynchronous change listeners.

    All public subscriptions use async listeners to avoid blocking
    the emit pathway. Listeners are scheduled via asyncio.create_task().
    """

    async def on_change(self, event: ChangeEvent) -> None:
        """Handle a change event asynchronously.

        Args:
            event: The change event to handle.
        """
        ...


@runtime_checkable
class InternalHook(Protocol):
    """Protocol for internal synchronous hooks.

    Internal hooks are called inline during emit() and must be fast.
    Return None or 200 for success. Return non-200 to halt the cascade
    (remaining Phase 1 consumers are skipped). Non-200 is the
    intentional-halt signal — internal errors MUST be handled inside
    the consumer, not returned as non-200.
    """

    def on_change_sync(self, event: ChangeEvent) -> int | None:
        """Handle a change event synchronously.

        IMPORTANT: Must be fast. Blocks all writes while executing.

        Returns:
            None or 200 for success. Non-200 to halt the cascade.
        """
        ...


# Import storage classes after other definitions to avoid circular imports
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree


def _pattern_matches(pattern: str, uri: str) -> bool:
    """Check if a subscription pattern matches an absolute path.

    Patterns:
    - Exact: "/peer/data/users/alice" matches only that path
    - Glob: "/peer/data/users/*" matches anything under data/users/
    - Wildcard: "*" matches everything

    Args:
        pattern: The subscription pattern (absolute path or "*").
        uri: The full absolute path to match against.

    Returns:
        True if the pattern matches the URI.
    """
    if pattern == "*":
        return True

    # Handle trailing wildcard as prefix match
    if pattern.endswith("/*"):
        prefix = pattern[:-1]  # Keep the trailing slash
        return uri.startswith(prefix) or uri == prefix[:-1]

    # Exact match
    return pattern == uri


@dataclass
class _Subscription:
    """Internal entry for a registered subscription."""

    pattern: str
    listener: AsyncChangeListener


@dataclass
class _InternalHookEntry:
    """Internal entry for a registered internal hook."""

    hook: InternalHook
    pattern: str | None  # None means all events
    name: str = ""  # Stable identifier for cascade reporting


class EmitPathway:
    """Single entry point for entity writes with change event dispatch.

    Wraps ContentStore and EntityTree to provide atomic write + event
    dispatch. Extensions subscribe to path patterns to receive ChangeEvents.

    Public API (for extensions/handlers):
    - subscribe(pattern, listener) - async listener at path pattern
    - unsubscribe(listener) - remove subscription

    Internal API (for core infrastructure):
    - _add_internal_hook(hook, pattern) - sync hook for indexes etc.
    - _remove_internal_hook(hook) - remove internal hook

    Attributes:
        content_store: The underlying content-addressed store.
        entity_tree: The underlying URI -> hash index.
    """

    def __init__(
        self,
        content_store: ContentStore,
        entity_tree: EntityTree,
    ) -> None:
        """Initialize EmitPathway.

        Args:
            content_store: Content store for immutable entity storage.
            entity_tree: Entity tree for URI -> hash mapping.
        """
        self._content_store = content_store
        self._entity_tree = entity_tree
        self._subscriptions: list[_Subscription] = []
        self._internal_hooks: list[_InternalHookEntry] = []
        # Cascade depth: shared counter per SYSTEM-COMPOSITION §3.1
        self._cascade_depth: int = 0
        # Extension-contributed context fields per SYSTEM-COMPOSITION §1.5.
        # Stack-scoped: each nesting level of emit() gets its own dict.
        # Extensions write at their position; downstream consumers read.
        self._context_stack: list[dict[str, Any]] = []
        # Field ownership: field_name → owner_name (single-owner write discipline)
        self._context_field_owners: dict[str, str] = {}
        # Cross-peer cascade tracking: chain_id → highest cascade_depth seen.
        # Per SYSTEM-COMPOSITION §3.4: supplementary mechanism to prevent
        # chain_id from accumulating N×32 total depth across N peers.
        self._chain_cascade_depth: dict[str, int] = {}

    # Cascade depth thresholds per SYSTEM-COMPOSITION §3.2
    SUBSCRIPTION_SUPPRESS_DEPTH = 8
    COMPUTE_FREEZE_DEPTH = 16
    SYSTEM_REFUSE_DEPTH = 32

    @property
    def cascade_depth(self) -> int:
        """Current cascade depth (nesting level of recursive emit calls)."""
        return self._cascade_depth

    @property
    def cascade_context(self) -> dict[str, Any]:
        """Extension-contributed context for the current cascade level.

        Per SYSTEM-COMPOSITION §1.5: extensions write fields at their
        consumer position; downstream consumers read them. Each nesting
        level of emit() has its own context dict. Prefer set_context_field()
        for writes (enforces ownership); direct read via this property is fine.
        """
        if self._context_stack:
            return self._context_stack[-1]
        return {}

    def register_context_field(self, field_name: str, owner: str) -> None:
        """Register an extension-contributed context field.

        Per SYSTEM-COMPOSITION §1.5.1: extensions register fields at peer init.
        Each field has a single owner; only the owner may write it.

        Args:
            field_name: The context field name (e.g., "clock").
            owner: The owning extension name (e.g., "clock/advancement").

        Raises:
            ValueError: If the field is already registered to a different owner.
        """
        existing = self._context_field_owners.get(field_name)
        if existing is not None and existing != owner:
            raise ValueError(
                f"Context field {field_name!r} already registered to {existing!r}, "
                f"cannot register to {owner!r}"
            )
        self._context_field_owners[field_name] = owner

    def set_context_field(self, field_name: str, value: Any, owner: str) -> None:
        """Write an extension-contributed context field.

        Per SYSTEM-COMPOSITION §1.5.2-3: only the registered owner may write,
        and only at its consumer position during the cascade.

        Args:
            field_name: The context field name.
            value: The value to set.
            owner: The caller's identity (must match registered owner).

        Raises:
            ValueError: If the caller is not the registered owner.
        """
        registered = self._context_field_owners.get(field_name)
        if registered is not None and registered != owner:
            raise ValueError(
                f"Context field {field_name!r} owned by {registered!r}, "
                f"not writable by {owner!r}"
            )
        if self._context_stack:
            self._context_stack[-1][field_name] = value

    def effective_cascade_depth(self, ctx: EmitContext | None = None) -> int:
        """Compute effective cascade depth considering cross-peer tracking.

        Per SYSTEM-COMPOSITION §3.4: uses max(bounds.cascade_depth, tracked_depth)
        for the current chain_id, plus the local cascade nesting depth.
        """
        cross_peer = 0
        if ctx and ctx.bounds:
            chain_id = ctx.bounds.chain_id
            bounds_depth = ctx.bounds.cascade_depth or 0
            tracked = self._chain_cascade_depth.get(chain_id, 0) if chain_id else 0
            cross_peer = max(bounds_depth, tracked)
        return cross_peer + self._cascade_depth

    def track_chain_depth(self, chain_id: str, depth: int) -> None:
        """Record the highest cascade depth seen for a chain_id.

        Called when receiving a cross-peer notification with cascade_depth
        in its bounds. Stores max(current, depth) for the chain.
        """
        if chain_id:
            current = self._chain_cascade_depth.get(chain_id, 0)
            if depth > current:
                self._chain_cascade_depth[chain_id] = depth

    @property
    def content_store(self) -> ContentStore:
        """Access the underlying content store."""
        return self._content_store

    @property
    def entity_tree(self) -> EntityTree:
        """Access the underlying entity tree."""
        return self._entity_tree

    # -------------------------------------------------------------------------
    # Public API - Async subscriptions at path patterns
    # -------------------------------------------------------------------------

    def subscribe(
        self,
        pattern: str,
        listener: AsyncChangeListener,
    ) -> None:
        """Subscribe to changes matching a path pattern.

        Subscriptions are always async - listeners are scheduled via
        asyncio.create_task() and never block writes.

        Patterns:
        - Exact: "/peer/path" or "path" (normalized automatically)
        - Glob: "path/*" matches anything under path/
        - Wildcard: "*" matches all events

        Args:
            pattern: Path pattern to match (will be normalized to absolute path).
            listener: Async listener to receive matching events.
        """
        # Normalize pattern to absolute path format if it's not already
        if pattern != "*" and not pattern.startswith("/"):
            pattern = self._entity_tree.normalize_uri(pattern)

        self._subscriptions.append(_Subscription(pattern=pattern, listener=listener))

    def unsubscribe(self, listener: AsyncChangeListener) -> None:
        """Remove a subscription.

        Args:
            listener: The listener to unsubscribe.
        """
        self._subscriptions = [
            sub for sub in self._subscriptions if sub.listener is not listener
        ]

    # -------------------------------------------------------------------------
    # Internal API - Sync hooks for core infrastructure
    # -------------------------------------------------------------------------

    def _add_internal_hook(
        self,
        hook: InternalHook,
        pattern: str | None = None,
        name: str = "",
    ) -> None:
        """Add an internal synchronous hook.

        INTERNAL USE ONLY. For core infrastructure like indexes.
        Hooks are called inline during emit() and must be fast.

        Args:
            hook: The internal hook to add.
            pattern: Optional pattern to filter events. None means all events.
            name: Stable identifier for cascade reporting (e.g. "query/index-manager").
        """
        # Normalize pattern if provided
        if pattern is not None and pattern != "*" and not pattern.startswith("/"):
            pattern = self._entity_tree.normalize_uri(pattern)

        self._internal_hooks.append(_InternalHookEntry(hook=hook, pattern=pattern, name=name))

    def _remove_internal_hook(self, hook: InternalHook) -> None:
        """Remove an internal hook.

        Args:
            hook: The hook to remove.
        """
        self._internal_hooks = [
            entry for entry in self._internal_hooks if entry.hook is not hook
        ]

    # -------------------------------------------------------------------------
    # Write operations
    # -------------------------------------------------------------------------

    def emit(
        self,
        uri: str,
        entity: Entity,
        ctx: EmitContext | None = None,
    ) -> EmitResult:
        """Store entity at URI and emit change event.

        This is the primary write method. It:
        1. Stores the entity in the content store
        2. Gets the previous hash at the URI (if any)
        3. Updates the URI -> hash mapping
        4. Dispatches events to matching subscribers

        Returns:
            EmitResult with hash and cascade status (200, 207, or 503).
        """
        if ctx is None:
            ctx = EmitContext()

        # Cascade depth check: refuse writes at system threshold (§3.2).
        # Binding does NOT commit — this is a pre-write rejection.
        if self._cascade_depth >= self.SYSTEM_REFUSE_DEPTH:
            logger.error(
                "Cascade depth limit exceeded (%d >= %d) for %s",
                self._cascade_depth, self.SYSTEM_REFUSE_DEPTH, uri,
            )
            return EmitResult(
                hash=None,
                status=503,
                cascade_depth=self._cascade_depth,
            )

        # Store in content store
        h = self._content_store.put(entity)

        # Get previous hash (before update)
        full_uri = self._entity_tree.normalize_uri(uri)
        previous_hash = self._entity_tree.get(full_uri)

        # Update tree — binding commits here, before cascade fires
        self._entity_tree.set(full_uri, h)

        # Determine change kind
        if previous_hash is None:
            kind = ChangeKind.CREATED
        elif not hash_equals(previous_hash, h):
            kind = ChangeKind.UPDATED
        else:
            # No-op: same hash at same path. Suppress event per
            # SYSTEM-COMPOSITION §1.1 — prevents spurious cascading.
            return EmitResult(hash=h, status=200)

        # Create and dispatch event with cascade depth tracking
        event = ChangeEvent(
            kind=kind,
            uri=full_uri,
            hash=h,
            entity=entity,
            previous_hash=previous_hash,
            context=ctx,
            cascade_depth=self._cascade_depth,
        )
        self._context_stack.append({})
        self._cascade_depth += 1
        try:
            completed, halted, skipped = self._dispatch(event)
        finally:
            self._cascade_depth -= 1
            self._context_stack.pop()

        if halted is not None:
            return EmitResult(
                hash=h,
                status=207,
                consumers_completed=tuple(completed),
                consumers_halted=halted,
                consumers_skipped=tuple(skipped),
                cascade_depth=event.cascade_depth,
            )
        return EmitResult(
            hash=h,
            status=200,
            consumers_completed=tuple(completed),
            cascade_depth=event.cascade_depth,
        )

    def emit_hash(
        self,
        uri: str,
        h: Hash,
        ctx: EmitContext | None = None,
    ) -> EmitResult:
        """Bind an existing content-store hash to a URI and emit change event.

        Like emit(), but for entities already in the content store (e.g.,
        revision bindings applied during merge/checkout/cherry-pick/revert).
        The entity is looked up from the content store for the ChangeEvent.

        Returns:
            EmitResult with hash and cascade status.
        """
        if ctx is None:
            ctx = EmitContext()

        if self._cascade_depth >= self.SYSTEM_REFUSE_DEPTH:
            return EmitResult(hash=None, status=503, cascade_depth=self._cascade_depth)

        full_uri = self._entity_tree.normalize_uri(uri)
        previous_hash = self._entity_tree.get(full_uri)
        self._entity_tree.set(full_uri, h)

        if previous_hash is None:
            kind = ChangeKind.CREATED
        elif not hash_equals(previous_hash, h):
            kind = ChangeKind.UPDATED
        else:
            return EmitResult(hash=h, status=200)

        entity = self._content_store.get(h)

        event = ChangeEvent(
            kind=kind,
            uri=full_uri,
            hash=h,
            entity=entity,
            previous_hash=previous_hash,
            context=ctx,
            cascade_depth=self._cascade_depth,
        )
        self._context_stack.append({})
        self._cascade_depth += 1
        try:
            completed, halted, skipped = self._dispatch(event)
        finally:
            self._cascade_depth -= 1
            self._context_stack.pop()

        if halted is not None:
            return EmitResult(
                hash=h,
                status=207,
                consumers_completed=tuple(completed),
                consumers_halted=halted,
                consumers_skipped=tuple(skipped),
                cascade_depth=event.cascade_depth,
            )
        return EmitResult(
            hash=h,
            status=200,
            consumers_completed=tuple(completed),
            cascade_depth=event.cascade_depth,
        )

    def delete(
        self,
        uri: str,
        ctx: EmitContext | None = None,
    ) -> EmitResult:
        """Remove URI mapping and emit deleted event.

        Does not remove the entity from the content store (it may be
        referenced elsewhere).

        Returns:
            EmitResult with previous hash and cascade status.
        """
        if ctx is None:
            ctx = EmitContext()

        full_uri = self._entity_tree.normalize_uri(uri)
        previous_hash = self._entity_tree.remove(full_uri)

        if previous_hash is None:
            return EmitResult(hash=None, status=200)

        event = ChangeEvent(
            kind=ChangeKind.DELETED,
            uri=full_uri,
            hash=None,
            entity=None,
            previous_hash=previous_hash,
            context=ctx,
        )
        completed, halted, skipped = self._dispatch(event)

        if halted is not None:
            return EmitResult(
                hash=previous_hash,
                status=207,
                consumers_completed=tuple(completed),
                consumers_halted=halted,
                consumers_skipped=tuple(skipped),
            )
        return EmitResult(hash=previous_hash, status=200, consumers_completed=tuple(completed))

    def put_content_only(self, entity: Entity) -> Hash:
        """Store entity in content store only (no tree, no event).

        Use this for content chunks or entities that don't need
        a URI mapping. Since there's no tree change, no event is
        dispatched.

        Args:
            entity: The entity to store.

        Returns:
            The content hash bytes.
        """
        return self._content_store.put(entity)

    # -------------------------------------------------------------------------
    # Internal dispatch
    # -------------------------------------------------------------------------

    def _dispatch(self, event: ChangeEvent) -> tuple[list[str], ConsumerHaltInfo | None, list[str]]:
        """Dispatch event to matching subscribers and internal hooks.

        Phase 1: Internal hooks called synchronously. A non-200 return
        halts the cascade (remaining Phase 1 consumers skipped).
        Phase 2: Subscriptions scheduled async if cascade not halted.

        Returns:
            (completed, halted, skipped) — consumer names.
        """
        completed: list[str] = []
        halted: ConsumerHaltInfo | None = None
        skipped: list[str] = []

        # Phase 1: Internal hooks (sync)
        matching = [
            entry for entry in self._internal_hooks
            if entry.pattern is None or _pattern_matches(entry.pattern, event.uri)
        ]
        for i, entry in enumerate(matching):
            try:
                status = entry.hook.on_change_sync(event)
            except Exception:
                logger.exception(
                    "Consumer %r raised exception for %s (depth=%d)",
                    entry.name, event.uri, event.cascade_depth,
                )
                halted = ConsumerHaltInfo(name=entry.name, status=500, intentional=False)
                skipped = [e.name for e in matching[i + 1:]]
                break
            if status is None or 200 <= status < 300:
                completed.append(entry.name)
            else:
                halted = ConsumerHaltInfo(name=entry.name, status=status, intentional=True)
                skipped = [e.name for e in matching[i + 1:]]
                logger.info(
                    "Cascade halt: consumer %r returned %d for %s (depth=%d)",
                    entry.name, status, event.uri, event.cascade_depth,
                )
                break

        # Phase 2: Subscriptions (async, never block)
        # Skip if cascade was halted or depth exceeds threshold (§3.2)
        if halted is None and self._cascade_depth < self.SUBSCRIPTION_SUPPRESS_DEPTH:
            for sub in self._subscriptions:
                if _pattern_matches(sub.pattern, event.uri):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(sub.listener.on_change(event))
                    except RuntimeError:
                        pass

        return completed, halted, skipped
