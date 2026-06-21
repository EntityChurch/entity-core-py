"""Subscription Extension for entity change notifications.

The Subscription Extension enables clients to subscribe to entity tree changes
and receive notifications via callbacks. It depends on the Callback Extension.

Components:
- SubscriptionEntity: Stored at system/subscription/{id}
- SubscriptionLimits: Resource limits for subscriptions
- SubscribeRequest: Request to create a subscription
- UnsubscribeRequest: Request to cancel a subscription
- SubscriptionExtension: Manages subscription lifecycle and notifications
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.protocol.delivery import InboxNotification, DeliverySpec
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import (
    AsyncChangeListener,
    ChangeEvent,
    ChangeKind,
    EmitContext,
    InternalHook,
)
from entity_core.capability.delegation import (
    ChainCollectStatus,
    check_creator_authority,
)
from entity_core.handlers.context import HandlerContext
from entity_core.utils.ecf import Hash, hash_equals
from entity_handlers.manifest import error_response as _error_response

if TYPE_CHECKING:
    from entity_core.storage.emit import EmitPathway

logger = logging.getLogger(__name__)


# =============================================================================
# Subscription Data Types
# =============================================================================


@dataclass
class SubscriptionLimits:
    """Resource limits for a subscription.

    Attributes:
        max_events: Maximum notifications before subscription terminates.
        max_duration_ms: Maximum subscription lifetime in milliseconds.
        rate_limit: Maximum notifications per minute (excess dropped, not terminated).
        notification_budget: Budget for each notification EXECUTE (independent of writer).
    """

    max_events: int | None = None
    max_duration_ms: int | None = None
    rate_limit: int | None = None
    notification_budget: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to wire format."""
        result: dict[str, Any] = {}
        if self.max_events is not None:
            result["max_events"] = self.max_events
        if self.max_duration_ms is not None:
            result["max_duration_ms"] = self.max_duration_ms
        if self.rate_limit is not None:
            result["rate_limit"] = self.rate_limit
        if self.notification_budget is not None:
            result["notification_budget"] = self.notification_budget
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> SubscriptionLimits | None:
        """Parse from wire format."""
        if data is None:
            return None
        return cls(
            max_events=data.get("max_events"),
            max_duration_ms=data.get("max_duration_ms"),
            rate_limit=data.get("rate_limit"),
            notification_budget=data.get("notification_budget"),
        )

    def merge_with_server_limits(
        self, server_limits: SubscriptionLimits | None
    ) -> SubscriptionLimits:
        """Merge with server limits, taking the more restrictive values.

        Server limits can only tighten, not loosen, client-requested limits.

        Args:
            server_limits: Server-enforced limits.

        Returns:
            Merged limits taking the more restrictive of each field.
        """
        if server_limits is None:
            return self

        def min_non_none(a: int | None, b: int | None) -> int | None:
            if a is None:
                return b
            if b is None:
                return a
            return min(a, b)

        return SubscriptionLimits(
            max_events=min_non_none(self.max_events, server_limits.max_events),
            max_duration_ms=min_non_none(
                self.max_duration_ms, server_limits.max_duration_ms
            ),
            rate_limit=min_non_none(self.rate_limit, server_limits.rate_limit),
            notification_budget=min_non_none(
                self.notification_budget, server_limits.notification_budget
            ),
        )


@dataclass
class SubscriptionEntity:
    """Subscription stored at system/subscription/{id}.

    Per SUBSCRIPTION v3.3:
    - deliver_uri: Where to deliver notifications (renamed from callback_uri).
    - deliver_operation: Operation to invoke ("notify" or "receive").
    - deliver_token: Hash of capability token authorizing inbox delivery.

    Attributes:
        subscription_id: Unique identifier for this subscription.
        pattern: URI pattern to match for notifications.
        events: Event types to notify on ("created", "updated", "deleted").
        deliver_uri: Where to deliver notifications.
        deliver_operation: Operation to invoke ("notify" or "receive").
        subscriber_identity: Hash of subscriber's identity entity.
        deliver_token: Hash of capability token authorizing inbox delivery.
        created_at: Unix timestamp (ms) when subscription was created.
        limits: Resource limits for this subscription.
    """

    TYPE = "system/subscription"

    subscription_id: str
    pattern: str
    events: list[str]
    deliver_uri: str
    deliver_operation: str
    subscriber_identity: Hash
    deliver_token: Hash
    created_at: int
    limits: SubscriptionLimits | None = None
    # EXTENSION-SUBSCRIPTION v3.14 §2.1: when set, the engine bundles the
    # changed entity into the delivery envelope's `included` (§4.2). Persisted
    # from the subscribe request only after the read-authorization check
    # (§2.3); default false keeps notifications lean (hashes only).
    include_payload: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to wire format."""
        result: dict[str, Any] = {
            "subscription_id": self.subscription_id,
            "pattern": self.pattern,
            "events": self.events,
            "deliver_uri": self.deliver_uri,
            "deliver_operation": self.deliver_operation,
            "subscriber_identity": self.subscriber_identity,
            "deliver_token": self.deliver_token,
            "created_at": self.created_at,
        }
        if self.limits is not None:
            result["limits"] = self.limits.to_dict()
        if self.include_payload:
            result["include_payload"] = True
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubscriptionEntity:
        """Parse from wire format."""
        return cls(
            subscription_id=data["subscription_id"],
            pattern=data["pattern"],
            events=data["events"],
            deliver_uri=data["deliver_uri"],
            deliver_operation=data["deliver_operation"],
            subscriber_identity=data["subscriber_identity"],
            deliver_token=data["deliver_token"],
            created_at=data["created_at"],
            limits=SubscriptionLimits.from_dict(data.get("limits")),
            include_payload=bool(data.get("include_payload", False)),
        )


@dataclass
class SubscribeRequest:
    """Request to create a subscription.

    Per SUBSCRIPTION v3.3:
    - deliver_to: Where and how to deliver notifications (DeliverySpec).
    - deliver_token: Hash of capability token authorizing inbox delivery.

    Attributes:
        events: Event types to subscribe to. Defaults to ["created", "updated", "deleted"].
        deliver_to: Where and how to deliver notifications (DeliverySpec).
        deliver_token: Hash of capability token authorizing inbox delivery.
        limits: Requested resource limits (may be tightened by server).
    """

    TYPE = "system/subscription/request"

    deliver_to: DeliverySpec
    deliver_token: Hash
    events: list[str] | None = None
    limits: SubscriptionLimits | None = None
    # EXTENSION-SUBSCRIPTION v3.14 §2.3: opt-in (default false). When set, the
    # subscribe handler requires the caller hold tree `get` on the resource
    # (read-authorization, §2.3 v3.13) and then bundles the changed entity into
    # each delivery's `included`.
    include_payload: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to wire format."""
        result: dict[str, Any] = {
            "deliver_to": self.deliver_to.to_dict(),
            "deliver_token": self.deliver_token,
        }
        if self.events is not None:
            result["events"] = self.events
        if self.limits is not None:
            result["limits"] = self.limits.to_dict()
        if self.include_payload:
            result["include_payload"] = True
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubscribeRequest:
        """Parse from wire format."""
        return cls(
            deliver_to=DeliverySpec.from_dict(data["deliver_to"]),
            deliver_token=data["deliver_token"],
            events=data.get("events"),
            limits=SubscriptionLimits.from_dict(data.get("limits")),
            include_payload=bool(data.get("include_payload", False)),
        )


@dataclass
class UnsubscribeRequest:
    """Request to cancel a subscription.

    Attributes:
        subscription_id: ID of subscription to cancel.
    """

    TYPE = "system/subscription/cancel"

    subscription_id: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to wire format."""
        return {"subscription_id": self.subscription_id}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnsubscribeRequest:
        """Parse from wire format."""
        return cls(subscription_id=data["subscription_id"])


# =============================================================================
# Subscription Index Entry
# =============================================================================


@dataclass
class _SubscriptionEntry:
    """Internal entry in the subscription index."""

    subscription: SubscriptionEntity
    event_count: int = 0
    last_notification_times: list[int] = field(default_factory=list)

    def check_rate_limit(self, now_ms: int) -> bool:
        """Check if notification would exceed rate limit.

        Args:
            now_ms: Current time in milliseconds.

        Returns:
            True if notification is allowed, False if rate limited.
        """
        if self.subscription.limits is None:
            return True
        if self.subscription.limits.rate_limit is None:
            return True

        # Keep only notifications from the last minute
        one_minute_ago = now_ms - 60_000
        self.last_notification_times = [
            t for t in self.last_notification_times if t > one_minute_ago
        ]

        # Check if we're at the limit
        return len(self.last_notification_times) < self.subscription.limits.rate_limit

    def record_notification(self, now_ms: int) -> None:
        """Record that a notification was sent."""
        self.event_count += 1
        self.last_notification_times.append(now_ms)

    def is_expired(self, now_ms: int) -> bool:
        """Check if subscription has expired due to limits."""
        limits = self.subscription.limits
        if limits is None:
            return False

        # Check max_events
        if limits.max_events is not None and self.event_count >= limits.max_events:
            return True

        # Check max_duration_ms
        if limits.max_duration_ms is not None:
            expires_at = self.subscription.created_at + limits.max_duration_ms
            if now_ms >= expires_at:
                return True

        return False


# =============================================================================
# Subscription Handler (EXTENSION-SUBSCRIPTION.md §3.1)
# =============================================================================

SUBSCRIPTION_HANDLER_PATTERN = "system/subscription"


async def subscription_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle subscription operations (subscribe, unsubscribe).

    Per EXTENSION-SUBSCRIPTION.md §3.1, the subscription handler is at
    system/subscription with subscribe and unsubscribe operations.

    Args:
        path: The full path (should be "system/subscription").
        operation: The operation (subscribe or unsubscribe).
        params: Operation parameters.
        ctx: Handler context.

    Returns:
        Response dict with status and result.
    """
    # Extract params data (params is a full entity per spec)
    params_data = params.get("data", params) if isinstance(params, dict) else {}

    if operation == "subscribe":
        return await _handle_subscribe(params_data, ctx)
    elif operation == "unsubscribe":
        return await _handle_unsubscribe(params_data, ctx)
    else:
        return {
            "status": 501,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "unsupported_operation",
                    "message": f"Subscription handler does not support operation: {operation}",
                },
            },
        }


def _get_prefix_capacity(emit_pathway: "EmitPathway", pattern: str) -> int | None:
    """Read max_subscribers_per_prefix from system/config/subscription.

    Per SUBSCRIPTION v3.5 §S1: capacity configuration.

    Returns:
        The capacity limit, or None if not configured (unlimited).
    """
    config_uri = emit_pathway.entity_tree.normalize_uri("system/config/subscription")
    config_hash = emit_pathway.entity_tree.get(config_uri)
    if config_hash is None:
        return None
    config = emit_pathway.content_store.get(config_hash)
    if config is None:
        return None
    return config.data.get("max_subscribers_per_prefix")


def _count_subscriptions_for_prefix(emit_pathway: "EmitPathway", pattern: str) -> int:
    """Count active subscriptions matching a pattern prefix.

    Per SUBSCRIPTION v3.5 §S1: subscriber count tracking per prefix.
    """
    count = 0
    prefix = emit_pathway.entity_tree.normalize_uri("system/subscription/")
    for uri in emit_pathway.entity_tree.list_prefix(prefix):
        content_hash = emit_pathway.entity_tree.get(uri)
        if content_hash is None:
            continue
        entity = emit_pathway.content_store.get(content_hash)
        if entity is None or entity.type != SubscriptionEntity.TYPE:
            continue
        try:
            sub = SubscriptionEntity.from_dict(entity.data)
            if sub.pattern == pattern:
                count += 1
        except (KeyError, TypeError):
            continue
    return count


def _find_existing_subscription(
    emit_pathway: "EmitPathway",
    subscriber_identity: Hash,
    pattern: str,
    deliver_uri: str,
) -> str | None:
    """Find existing subscription matching (subscriber, pattern, deliver_uri).

    Per SUBSCRIPTION §5.3: Subscription renewal detection by this triple
    prevents duplicates when re-subscribing.

    Args:
        emit_pathway: Emit pathway for tree access.
        subscriber_identity: Hash of subscriber's identity.
        pattern: Subscription pattern.
        deliver_uri: Delivery URI.

    Returns:
        The existing subscription_id if found, None otherwise.
    """
    # List all subscriptions under system/subscription/
    prefix = emit_pathway.entity_tree.normalize_uri("system/subscription/")
    for uri in emit_pathway.entity_tree.list_prefix(prefix):
        content_hash = emit_pathway.entity_tree.get(uri)
        if content_hash is None:
            continue

        entity = emit_pathway.content_store.get(content_hash)
        if entity is None or entity.type != SubscriptionEntity.TYPE:
            continue

        try:
            sub = SubscriptionEntity.from_dict(entity.data)

            # Normalize hashes to bytes for comparison (wire format may vary)
            stored_identity = sub.subscriber_identity
            if isinstance(stored_identity, list):
                stored_identity = bytes(stored_identity)
            caller_identity = subscriber_identity
            if isinstance(caller_identity, list):
                caller_identity = bytes(caller_identity)

            # Check for match on all three fields
            if (
                stored_identity == caller_identity
                and sub.pattern == pattern
                and sub.deliver_uri == deliver_uri
            ):
                return sub.subscription_id
        except (KeyError, TypeError):
            continue

    return None


async def _handle_subscribe(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle subscribe operation - create a subscription.

    Per EXTENSION-SUBSCRIPTION.md §3.1:
    - Pattern comes from params.pattern (or resource_targets for V7 compat)
    - Validates deliver_token exists and grants inbox access
    - Applies server limits (can tighten, not loosen)
    - Creates SubscriptionEntity at system/subscription/{id}

    Args:
        params: Subscribe request parameters.
        ctx: Handler context.

    Returns:
        Response dict with subscription details.
    """
    # Parse request
    try:
        request = SubscribeRequest.from_dict(params)
    except (KeyError, TypeError) as e:
        return _error_response(400, "invalid_request", f"Invalid subscribe request: {e}")

    # Get pattern from params (per spec §3.1) or resource_targets (V7 compat)
    pattern = params.get("pattern")
    if pattern is None and ctx.resource_targets:
        pattern = ctx.resource_targets[0]
    if pattern is None:
        return _error_response(400, "missing_pattern", "Pattern is required")

    # include_payload read-authorization (EXTENSION-SUBSCRIPTION §2.3 v3.13):
    # subscribing is distinct from reading. A caller may hold `subscribe`
    # without tree `get`. When the subscription would push entity content
    # (include_payload), the caller MUST also be authorized to read it —
    # otherwise the option is a capability bypass. Enforce here, before the
    # content is ever attached at delivery (§4.2).
    if request.include_payload and not ctx.check_caller_permission("get", pattern):
        return _error_response(
            403,
            "payload_unauthorized",
            "include_payload requires tree:get on the subscribed resource",
        )

    # Validate deliver_token exists in content store
    deliver_token_hash = request.deliver_token
    if not ctx.emit_pathway.content_store.has(deliver_token_hash):
        return _error_response(400, "missing_deliver_token", "Deliver token not in content store")

    # Validate deliver_token grants access to deliver URI
    token_entity = ctx.emit_pathway.content_store.get(deliver_token_hash)
    if token_entity is None:
        return _error_response(404, "token_not_found", "Deliver token not found")

    # Check token is not expired
    now_ms = int(time.time() * 1000)
    expires_at = token_entity.data.get("expires_at")
    if expires_at is not None and now_ms >= expires_at:
        return _error_response(403, "token_expired", "Deliver token has expired")

    # Validate token grants access to deliver URI with deliver operation
    token_valid = _validate_deliver_token(
        token_entity,
        request.deliver_to.uri,
        request.deliver_to.operation,
    )
    if not token_valid:
        return _error_response(
            403,
            "deliver_token_insufficient",
            "Deliver token does not grant access to deliver URI",
        )

    # SB1 (EXTENSION-SUBSCRIPTION §3.1) — R1 creator-authorization on
    # deliver_token. Unified walker per PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE
    # §3.2: one call handles reachability + identity match + chain
    # collection. The subscriber must be in the token's authority chain —
    # otherwise an actor could embed someone else's deliver_token and force
    # unsolicited deliveries to that party's inbox. Distinct from the
    # dispatch-time integrity check at the receiving peer (V7 §5.2, unchanged).
    if ctx.remote_identity_hash is None:
        return _error_response(
            403, "no_identity", "Author identity not available for chain check"
        )

    def _chain_lookup(h: Hash) -> dict[str, Any] | None:
        ent = ctx.emit_pathway.content_store.get(h)
        return ent.to_dict() if ent is not None else None

    auth = check_creator_authority(
        token_entity.to_dict(), ctx.remote_identity_hash, _chain_lookup,
    )
    if auth.status != ChainCollectStatus.OK:
        return _error_response(
            404,
            "chain_unreachable",
            "Deliver token authority chain incomplete in envelope and content store",
        )
    if not auth.found:
        return _error_response(
            403,
            "embedded_cap_unauthorized",
            "Subscriber identity not in deliver_token authority chain",
        )

    # Persist deliver_token + full authority chain so future async
    # notification dispatch can resolve the cap by hash. Walker already
    # collected the chain; no re-walk.
    for chain_dict in auth.chain:
        chain_entity = Entity.from_dict(chain_dict)
        if not ctx.emit_pathway.content_store.has(chain_entity.compute_hash()):
            ctx.emit_pathway.put_content_only(chain_entity)

    # Get caller identity hash from capability (grantee field per spec §3.1)
    # Note: caller_capability is already the .data of the capability entity
    caller_identity = ctx.caller_capability.get("grantee")
    if caller_identity is None:
        # Also check author field on execute
        caller_identity = params.get("author")
    if caller_identity is None:
        return _error_response(403, "no_identity", "Caller identity not available")

    # S1-S2: Check per-prefix capacity before accepting (SUBSCRIPTION v3.5)
    capacity = _get_prefix_capacity(ctx.emit_pathway, pattern)
    if capacity is not None:
        current_count = _count_subscriptions_for_prefix(ctx.emit_pathway, pattern)
        # Only check capacity for NEW subscriptions, not renewals
        existing_check = _find_existing_subscription(
            ctx.emit_pathway, caller_identity, pattern, request.deliver_to.uri,
        )
        if existing_check is None and current_count >= capacity:
            return {
                "status": 303,
                "result": {
                    "type": "system/subscription/redirect",
                    "data": {
                        "reason": "at_capacity",
                        "prefix": pattern,
                        "capacity": capacity,
                        "alternatives": [],
                    },
                },
            }

    # Per SUBSCRIPTION §5.3: Check for existing subscription to renew
    # Deduplication key: (subscriber_identity, pattern, deliver_uri)
    existing_subscription_id = _find_existing_subscription(
        ctx.emit_pathway,
        caller_identity,
        pattern,
        request.deliver_to.uri,
    )

    # Use existing subscription ID if renewing, otherwise generate new
    subscription_id = existing_subscription_id or str(uuid.uuid4())

    # Apply server limits (tighten client-requested limits). F-CIMP-6:
    # no hardcoded server cap — Python now matches Go/Rust (no implicit
    # ceiling). Operators who want a server-side cap supply one via
    # SubscriptionExtension(server_limits=...). EXTENSION-SUBSCRIPTION §2.4
    # permits but does not mandate server defaults.
    client_limits = request.limits or SubscriptionLimits()
    effective_limits = client_limits.merge_with_server_limits(None)

    # Default events if not specified
    events = request.events or ["created", "updated", "deleted"]

    # Create subscription entity
    subscription = SubscriptionEntity(
        subscription_id=subscription_id,
        pattern=pattern,
        events=events,
        deliver_uri=request.deliver_to.uri,
        deliver_operation=request.deliver_to.operation,
        subscriber_identity=caller_identity,
        deliver_token=deliver_token_hash,
        created_at=now_ms,
        limits=effective_limits,
        # Persisted only after the read-auth check above passed (§2.3).
        include_payload=request.include_payload,
    )

    # Store at system/subscription/{id}
    storage_path = f"system/subscription/{subscription_id}"
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(storage_path)

    subscription_entity = Entity(
        type=SubscriptionEntity.TYPE,
        data=subscription.to_dict(),
    )

    emit_ctx = EmitContext.from_handler_grant(ctx, "subscribe")
    content_hash = ctx.emit_pathway.emit(full_uri, subscription_entity, emit_ctx).hash

    return {
        "status": 200,
        "result": {
            "type": "system/subscription/result",
            "data": {
                "subscription_id": subscription_id,
                "pattern": pattern,
                "events": events,
                "limits": effective_limits.to_dict() if effective_limits else None,
            },
        },
    }


def _validate_deliver_token(
    token_entity: Entity,
    deliver_uri: str,
    deliver_operation: str,
) -> bool:
    """Validate that a delivery token grants access to an inbox URI.

    Per SUBSCRIPTION v3.3 §4.2: Validates the deliver_token grants access
    to the deliver_uri with the specified operation. Uses the same pattern
    matching as dispatch-level capability checking (spec §5.4).

    Args:
        token_entity: The capability token entity.
        deliver_uri: The inbox URI to validate.
        deliver_operation: The operation to validate (receive/notify).

    Returns:
        True if token grants access, False otherwise.
    """
    from entity_core.capability.checking import matches_pattern, matches_scope
    from entity_core.capability.token import Grant

    grants = token_entity.data.get("grants", [])

    for grant_data in grants:
        try:
            grant = Grant.from_dict(grant_data)

            # Check handler scope — must cover system/inbox.
            if not matches_scope(grant.handlers, "system/inbox"):
                continue

            # Check resource scope — uses spec §5.4 pattern matching
            # which handles entity:// normalization, wildcards, subtree matching.
            if not matches_scope(grant.resources, deliver_uri):
                continue

            # Check operation scope.
            if not matches_scope(grant.operations, deliver_operation):
                continue

            return True

        except (KeyError, TypeError):
            continue

    return False


async def _handle_unsubscribe(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle unsubscribe operation - cancel a subscription.

    Per EXTENSION-SUBSCRIPTION.md §3.2:
    - Loads subscription from system/subscription/{id}
    - Verifies caller is the subscriber (or admin)
    - Deletes subscription entity

    Args:
        params: Unsubscribe request parameters.
        ctx: Handler context.

    Returns:
        Response dict with success status.
    """
    # Parse request
    try:
        request = UnsubscribeRequest.from_dict(params)
    except (KeyError, TypeError) as e:
        return _error_response(400, "invalid_request", f"Invalid unsubscribe request: {e}")

    subscription_id = request.subscription_id

    # Load subscription from tree
    storage_path = f"system/subscription/{subscription_id}"
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(storage_path)
    content_hash = ctx.emit_pathway.entity_tree.get(full_uri)

    if content_hash is None:
        return _error_response(404, "subscription_not_found", f"Subscription not found: {subscription_id}")

    subscription_entity = ctx.emit_pathway.content_store.get(content_hash)
    if subscription_entity is None:
        return _error_response(404, "subscription_not_found", f"Subscription entity missing: {subscription_id}")

    # Parse subscription
    try:
        subscription = SubscriptionEntity.from_dict(subscription_entity.data)
    except (KeyError, TypeError) as e:
        return _error_response(500, "invalid_subscription", f"Failed to parse subscription: {e}")

    # Verify caller is the subscriber
    # Note: caller_capability is already the .data of the capability entity
    caller_identity = ctx.caller_capability.get("grantee")
    if caller_identity is None:
        return _error_response(403, "no_identity", "Caller identity not available")

    if not hash_equals(subscription.subscriber_identity, caller_identity):
        return _error_response(403, "not_subscription_owner", "Only the subscriber can unsubscribe")

    # Delete subscription (put null per spec §3.2)
    emit_ctx = EmitContext.from_handler_grant(ctx, "unsubscribe")
    ctx.emit_pathway.delete(full_uri, emit_ctx)

    return {
        "status": 200,
        "result": None,
    }


# =============================================================================
# Subscription Extension
# =============================================================================


# Per-subscription delivery queue size. When full, oldest pending notifications
# for that subscription are dropped (§5.5 gap detection covers gaps). Sized to
# absorb a few seconds of bursty publishing against a slow consumer at typical
# cross-peer delivery rates (~1000/sec) without dropping; tuneable per peer if
# saturation harnesses surface workloads that warrant a larger budget.
_DEFAULT_PER_SUBSCRIPTION_QUEUE_SIZE = 1024

# F-CIMP-2 / Class H F1b — per-subscription in-flight pipeline
# depth. With strict serial-await-per-delivery (pre-fix), throughput is bounded
# by 1/RPC_latency: at ~5ms cross-peer roundtrip, max ~200/sec per subscription.
# Workbench-go's perf-stress probe §2.2 observed Python
# delivering 6% of 1000 events in 3s under a 518/sec publish rate — the cliff
# this constant addresses. With pipelined deliveries (this default), the
# drainer dispatches up to K concurrent in-flight RPCs while preserving §5.2
# within-subscription ordering: the send order is enforced by the queue's FIFO
# drain + Connection._write_lock (single wire writer per connection); response
# order is irrelevant since responses are ack-only. The receiver observes
# deliveries in tree-change order regardless of response interleaving.
# K=16 yields ~16× the serial bound (~3200/sec at 5ms RPC) — comfortably above
# Go's 2274/sec single-spoke baseline. Tuneable per peer if a saturation
# harness surfaces a workload that warrants a different budget.
_DEFAULT_PER_SUBSCRIPTION_INFLIGHT = 16


class SubscriptionExtension(Extension):
    """Manages subscription notification delivery.

    The extension:
    1. Maintains an index of active subscriptions (internal hook on system/subscription/*)
    2. Listens to all tree changes (async subscription on *)
    3. Delivers notifications via per-subscription worker tasks (Class H F1 /
       EXTENSION-SUBSCRIPTION v3.15 §5.2): each subscription has its own
       asyncio.Queue + drainer Task. Within-subscription ordering is preserved
       (queue is FIFO; F-CIMP-2 / Class H F1b pipelines up to K deliveries
       in-flight per subscription — send order is still tree-change order
       because the drain is FIFO and Connection._write_lock serializes wire
       bytes per connection); cross-subscription parallelism is realized by
       concurrent drainer tasks whose cross-peer RPC awaits interleave on the
       event loop. This is the asyncio analog of the spec-recommended
       shard-by-subscription_id worker pool (§11.2 SHOULD) plus the per-shard
       pipelining that lifts single-sub throughput off the 1/RPC_latency
       cliff.

    Critical: Notifications use independent budget, NOT the writer's remaining budget.
    """

    def __init__(
        self,
        server_limits: SubscriptionLimits | None = None,
        *,
        per_subscription_queue_size: int = _DEFAULT_PER_SUBSCRIPTION_QUEUE_SIZE,
        per_subscription_inflight: int = _DEFAULT_PER_SUBSCRIPTION_INFLIGHT,
    ) -> None:
        """Initialize the subscription extension.

        Args:
            server_limits: Default limits applied to all subscriptions.
            per_subscription_queue_size: Max pending notifications per
                subscription before drops (§5.5 gap detection recovers).
            per_subscription_inflight: F-CIMP-2 / Class H F1b — max
                concurrent in-flight deliveries per subscription. Lifts the
                1/RPC_latency cliff while preserving §5.2 send-order via
                FIFO drain + connection write-lock.
        """
        self._index: dict[str, _SubscriptionEntry] = {}
        self._ctx: ExtensionContext | None = None
        self._server_limits = server_limits
        self._index_updater: _IndexUpdater | None = None
        self._notification_trigger: _NotificationTrigger | None = None
        # Class H F1: per-subscription delivery infrastructure. Lazily
        # populated on first matching event for a given subscription_id.
        self._delivery_queues: dict[str, asyncio.Queue[tuple[ChangeEvent, int]]] = {}
        self._delivery_workers: dict[str, asyncio.Task[None]] = {}
        self._queue_size = per_subscription_queue_size
        self._inflight = per_subscription_inflight

    @property
    def server_limits(self) -> SubscriptionLimits | None:
        """Server-enforced limits for subscriptions."""
        return self._server_limits

    def initialize(self, ctx: ExtensionContext) -> None:
        """Initialize the extension with peer context.

        Sets up:
        1. Internal hook to maintain subscription index
        2. Async listener to trigger notifications on tree changes

        Args:
            ctx: Extension context with emit_pathway.
        """
        self._ctx = ctx

        if ctx.emit_pathway is None:
            logger.warning(
                "SubscriptionExtension initialized without emit_pathway - "
                "subscriptions will not work"
            )
            return

        emit = ctx.emit_pathway

        # Load existing subscriptions from tree
        self._load_existing_subscriptions(emit)

        # Internal hook: update index on subscription changes (sync, fast)
        self._index_updater = _IndexUpdater(self)
        emit._add_internal_hook(self._index_updater, pattern="system/subscription/*", name="subscription/index-updater")

        # Async listener: trigger notifications on tree changes
        self._notification_trigger = _NotificationTrigger(self)
        emit.subscribe("*", self._notification_trigger)

    def _load_existing_subscriptions(self, emit: EmitPathway) -> None:
        """Load existing subscriptions from the tree.

        Called during initialization to restore subscription state.
        """
        prefix = emit.entity_tree.normalize_uri("system/subscription/")
        for uri in emit.entity_tree.list_prefix(prefix):
            h = emit.entity_tree.get(uri)
            if h is None:
                continue
            entity = emit.content_store.get(h)
            if entity is None or entity.type != SubscriptionEntity.TYPE:
                continue
            try:
                sub = SubscriptionEntity.from_dict(entity.data)
                self._index[sub.subscription_id] = _SubscriptionEntry(subscription=sub)
                logger.debug(f"Loaded subscription: {sub.subscription_id}")
            except (KeyError, TypeError) as e:
                logger.warning(f"Failed to load subscription from {uri}: {e}")

    def shutdown(self) -> None:
        """Clean up extension resources."""
        if self._ctx is not None and self._ctx.emit_pathway is not None:
            emit = self._ctx.emit_pathway
            if self._index_updater is not None:
                emit._remove_internal_hook(self._index_updater)
            if self._notification_trigger is not None:
                emit.unsubscribe(self._notification_trigger)
        # Class H F1: cancel all per-subscription delivery workers. We
        # can't await here (sync method); cancellation is observed at the
        # next worker await — the event loop drains them on the next tick.
        for subscription_id in list(self._delivery_workers.keys()):
            self._drop_delivery_worker(subscription_id)
        self._index.clear()

    def get_subscription(self, subscription_id: str) -> SubscriptionEntity | None:
        """Get a subscription by ID.

        Args:
            subscription_id: The subscription ID.

        Returns:
            The subscription entity if found.
        """
        entry = self._index.get(subscription_id)
        return entry.subscription if entry else None

    def list_subscriptions(self) -> list[SubscriptionEntity]:
        """List all active subscriptions.

        Returns:
            List of subscription entities.
        """
        return [entry.subscription for entry in self._index.values()]

    def _on_subscription_change(self, event: ChangeEvent) -> None:
        """Handle subscription entity changes (sync, must be fast).

        Called by _IndexUpdater for changes under system/subscription/*.
        """
        # Extract subscription_id from URI
        # URI format: entity://peer/system/subscription/{id}
        uri = event.uri
        parts = uri.split("/")
        if len(parts) < 2:
            return
        subscription_id = parts[-1]

        if event.kind == ChangeKind.DELETED:
            # Remove from index
            if subscription_id in self._index:
                del self._index[subscription_id]
                logger.debug(f"Removed subscription: {subscription_id}")
            # Class H F1: tear down the delivery worker so we don't leak a
            # task per ever-created subscription.
            self._drop_delivery_worker(subscription_id)
        else:
            # Created or updated - add/update in index
            if event.entity is None:
                return
            if event.entity.type != SubscriptionEntity.TYPE:
                return
            try:
                sub = SubscriptionEntity.from_dict(event.entity.data)
                self._index[sub.subscription_id] = _SubscriptionEntry(subscription=sub)
                logger.debug(f"Added/updated subscription: {subscription_id}")
            except (KeyError, TypeError) as e:
                logger.warning(f"Failed to parse subscription: {e}")

    async def _on_tree_change(self, event: ChangeEvent) -> None:
        """Fan tree changes out to per-subscription delivery queues.

        Called by ``_NotificationTrigger`` for every tree change. For each
        subscription whose pattern + event-type filter matches, the event is
        enqueued on the subscription's own delivery queue; a dedicated
        drainer task awaits each delivery serially (preserving §5.2
        within-subscription ordering MUST). The fan-out itself is
        non-blocking, so a slow consumer on one subscription does not back
        up deliveries to other subscriptions (Class H F1).

        Token/expiration/rate-limit checks happen in the drainer at
        delivery time so the snapshot reflects the moment of delivery, not
        the moment of fan-out — matters when queues sit briefly under burst.
        Subscription-self-change events are skipped to avoid loops with the
        internal index updater.
        """
        if "system/subscription/" in event.uri:
            return

        now_ms = int(time.time() * 1000)

        for subscription_id, entry in list(self._index.items()):
            # Cheap structural filters first (no I/O, no auth lookups) so
            # the drainer isn't woken for events it would never deliver.
            if not self._pattern_matches(entry.subscription.pattern, event.uri):
                continue
            if event.kind.value not in entry.subscription.events:
                continue

            queue = self._ensure_delivery_worker(subscription_id)
            if queue is None:
                continue
            try:
                queue.put_nowait((event, now_ms))
            except asyncio.QueueFull:
                # §5.5 gap detection covers this: subscribers reconcile via
                # `previous_hash` mismatch + GET. Log loud so operators can
                # diagnose chronic saturation; do not block fan-out.
                logger.warning(
                    "Class H F1: dropping notification for subscription %s "
                    "(queue full, size=%d) — gap detection (§5.5) recovers",
                    subscription_id, self._queue_size,
                )

    def _ensure_delivery_worker(
        self, subscription_id: str
    ) -> "asyncio.Queue[tuple[ChangeEvent, int]] | None":
        """Lazily spawn a per-subscription delivery worker.

        Returns the subscription's delivery queue, creating it + the drainer
        task on first call. Idempotent across calls. Returns ``None`` if the
        subscription is no longer indexed (race with deletion). The drainer
        is named so saturation probes / pprof traces can attribute work to a
        specific subscription_id.
        """
        if subscription_id not in self._index:
            return None
        queue = self._delivery_queues.get(subscription_id)
        if queue is not None:
            return queue
        queue = asyncio.Queue(maxsize=self._queue_size)
        self._delivery_queues[subscription_id] = queue
        task = asyncio.create_task(
            self._subscription_worker(subscription_id, queue),
            name=f"sub-deliver-{subscription_id}",
        )
        self._delivery_workers[subscription_id] = task
        return queue

    async def _subscription_worker(
        self,
        subscription_id: str,
        queue: "asyncio.Queue[tuple[ChangeEvent, int]]",
    ) -> None:
        """Drain one subscription's delivery queue in FIFO order with
        bounded in-flight pipelining (Class H F1 + F-CIMP-2 / F1b).

        §5.2 within-subscription ordering MUST: the drainer takes events
        off the FIFO queue in tree-change order, runs the cheap
        per-delivery preflight (expiry / rate-limit / token), then
        dispatches each delivery as an asyncio task gated by a
        per-subscription Semaphore. The semaphore is FIFO under asyncio
        (waiters wake in arrival order), so dispatch order = enqueue order
        = tree-change order. Each spawned task awaits
        ``self._deliver_notification`` which goes through
        ``Connection.execute`` — that path serializes wire bytes per
        connection via ``_write_lock``, so the bytes the receiver observes
        on the wire are in dispatch order (= tree-change order). Response
        order is irrelevant: responses are ack-only and the subscriber's
        view of "what was delivered" is fixed by what arrived on the wire.

        SYNC-CHAIN LOAD-BEARING PROPERTY (workbench-go substance-check).
        The above ordering claim is correct iff sibling
        delivery tasks reach ``Connection._write_lock.acquire()`` in
        creation order. ``asyncio.create_task`` schedules tasks FIFO on
        the ready deque, so they START running in creation order. They
        REACH the lock in creation order iff the path from task entry
        through to the lock is purely synchronous (no real-yield await).
        The current chain is sync in steady state:

          _deliver_one → _deliver_notification → await ctx.execute
            ctx.execute → await _dispatch_local_execute
              _dispatch_local_execute → if remote: await _remote_execute
                _remote_execute → await _remote_pool.get_connection
                  steady-state cache hit: returns sync (no yield)
                _remote_execute → await conn.execute
                  conn.execute → async with self._write_lock  ← FIRST YIELD

        Cold-start (first delivery to a peer) ordering is also preserved:
        the pool's ``async with self._lock`` (``remote.py:92``)
        serializes connection establishment FIFO. Tasks 2..N wait FIFO on
        the pool lock, then see the cache hit on retry. The pool's lock
        + connection's write_lock together cover establishment + steady
        state.

        ANY future refactor that introduces a real-yield await between
        ``_deliver_one`` entry and ``write_lock.acquire()`` (e.g.,
        per-call async cap resolution, async route lookup, async
        authorization side-effect, scheduling a coroutine via
        ``loop.run_in_executor``) BREAKS this ordering and MUST add an
        explicit per-subscription send-order serialization (the cleanest
        shape is a per-sub ``dispatch_lock`` held across the new yield
        and released after ``write_lock.acquire`` returns, so the in-flight
        pipeline only opens AFTER send order is committed). The
        ``test_dispatch_order_under_randomized_completion`` test in
        ``test_subscription_delivery_class_h.py`` is the regression
        backstop — it injects randomized completion latency so the chain
        is exercised under reorder pressure.

        Pre-F-CIMP-2 (Stage 5 F1) shape: the drainer awaited each
        ``_deliver_notification`` before pulling the next event, so
        throughput was bounded by 1/RPC_latency (~200/sec at 5ms cross-
        peer roundtrip). Workbench-go's perf-stress probe §2.2 observed
        Python delivering 6%/1000 events under a
        518/sec publish rate as a direct consequence. With pipelining,
        K=16 concurrent in-flight deliveries lift throughput to ~16× the
        serial bound (~3200/sec at 5ms RPC).

        The worker exits on terminal subscription state (expired /
        token-expired / removed); ``_drop_delivery_worker`` cleans the
        bookkeeping. Cancellation (shutdown) is observed at the next await.
        In-flight tasks are tracked in ``inflight`` so shutdown can drain
        cleanly without leaking pending RPCs.
        """
        inflight: set[asyncio.Task[None]] = set()
        sem = asyncio.Semaphore(self._inflight)

        async def _deliver_one(
            entry_snap: "_SubscriptionEntry",
            event_snap: ChangeEvent,
            now_ms_snap: int,
        ) -> None:
            """Run one delivery + release the inflight permit on completion.

            Exceptions are swallowed + logged here so one failed delivery
            (timeout, peer down, capability rejection) cannot kill the
            drainer or starve the pipeline.
            """
            try:
                await self._deliver_notification(entry_snap, event_snap, now_ms_snap)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "Class H F1: delivery raised for subscription %s; "
                    "pipeline continues",
                    subscription_id,
                )
            finally:
                sem.release()

        try:
            while True:
                event, _observed_now_ms = await queue.get()
                entry = self._index.get(subscription_id)
                if entry is None:
                    break
                now_ms = int(time.time() * 1000)
                if entry.is_expired(now_ms):
                    await self._terminate_subscription(
                        subscription_id, "limits_exceeded"
                    )
                    break
                if not entry.check_rate_limit(now_ms):
                    logger.debug(
                        "Rate limited notification for subscription %s",
                        subscription_id,
                    )
                    continue
                if not await self._validate_deliver_token(
                    entry.subscription.deliver_token
                ):
                    await self._terminate_subscription(
                        subscription_id, "token_expired"
                    )
                    break

                # F-CIMP-2 / F1b: bound the in-flight pipeline. Semaphore
                # acquire is FIFO; combined with the FIFO queue drain and
                # the connection's _write_lock, send order on the wire
                # matches tree-change order — §5.2 preserved.
                await sem.acquire()
                task = asyncio.create_task(
                    _deliver_one(entry, event, now_ms),
                    name=f"sub-deliver-task-{subscription_id}",
                )
                inflight.add(task)
                task.add_done_callback(inflight.discard)
        except asyncio.CancelledError:
            pass
        finally:
            # On exit (terminal state or shutdown), await any pending
            # in-flight tasks so the pipeline drains cleanly. Cancellation
            # of the worker propagates to in-flight only if the harness
            # cancels them externally — we don't cancel here because the
            # spec says deliveries already in-flight should complete.
            if inflight:
                await asyncio.gather(*inflight, return_exceptions=True)

    def _drop_delivery_worker(self, subscription_id: str) -> None:
        """Cancel + drop a subscription's delivery worker (best effort).

        Safe to call from sync contexts (internal hook, shutdown):
        ``task.cancel()`` only sets a flag — the worker observes it at its
        next await. No awaiting here.
        """
        task = self._delivery_workers.pop(subscription_id, None)
        if task is not None and not task.done():
            task.cancel()
        self._delivery_queues.pop(subscription_id, None)

    def _pattern_matches(self, pattern: str, uri: str) -> bool:
        """Check if a subscription pattern matches an absolute path.

        Patterns:
        - Exact: "/peer/path" matches only that path
        - Glob: "path/*" matches anything under path/
        - Wildcard: "*" matches everything
        """
        if pattern == "*":
            return True

        # Normalize pattern to absolute path if needed
        if self._ctx and self._ctx.emit_pathway:
            if not pattern.startswith("/"):
                pattern = self._ctx.emit_pathway.entity_tree.normalize_uri(pattern)

        # Handle trailing wildcard as prefix match
        if pattern.endswith("/*"):
            prefix = pattern[:-1]  # Keep the trailing slash
            return uri.startswith(prefix) or uri == prefix[:-1]

        # Exact match
        return pattern == uri

    async def _validate_deliver_token(self, token_hash: Hash) -> bool:
        """Validate that a deliver token is still valid.

        Args:
            token_hash: Hash of the capability token.

        Returns:
            True if token exists and is not expired.
        """
        if self._ctx is None or self._ctx.emit_pathway is None:
            return False

        entity = self._ctx.emit_pathway.content_store.get(token_hash)
        if entity is None:
            return False

        # Check expiration
        expires_at = entity.data.get("expires_at")
        if expires_at is not None:
            now_ms = int(time.time() * 1000)
            if now_ms >= expires_at:
                return False

        return True

    async def _deliver_notification(
        self,
        entry: _SubscriptionEntry,
        event: ChangeEvent,
        now_ms: int,
    ) -> None:
        """Deliver a notification for a change event via inbox (v7.8).

        Per EXTENSION-SUBSCRIPTION v3.3:
        - Notifications delivered via inbox receive operation (not direct callback)
        - Uses independent notification budget (not writer's budget)
        - Constructs InboxNotification with subscription_id, event, uri, hash
        - Notification bounds inherit cascade_depth from emission context (G-3)

        Args:
            entry: Subscription entry.
            event: The change event.
            now_ms: Current time in milliseconds.
        """
        sub = entry.subscription

        # V7.8: Create inbox notification (not callback notification)
        notification = InboxNotification(
            subscription_id=sub.subscription_id,
            event=event.kind.value,
            uri=event.uri,
            hash=event.hash,
            previous_hash=event.previous_hash,
        )

        # include_payload (EXTENSION-SUBSCRIPTION §2.2/§4.2): when the
        # subscription opted in (and passed the §2.3 read-auth check at
        # subscribe time), the changed entity rides with the notification so
        # the receiver applies it without a follow-up GET. Removed events
        # (hash absent) bundle nothing. Source-side resolution failure MUST be
        # hash-only + debug-log, never fail-stop.
        #
        # The bundled entity rides in the delivery's request-side `included`
        # map (V7 §3.3 v7.51), threaded through the dispatch surface so the
        # subscriber's continuation can `deref_included` it (a pure transform
        # reads the map, not the store). Removed events bundle nothing.
        payload_included: dict[bytes, dict[str, Any]] | None = None
        if sub.include_payload and event.hash is not None:
            cs = self._ctx.emit_pathway.content_store if self._ctx else None
            changed = cs.get(event.hash) if cs is not None else None
            if changed is not None:
                payload_included = {event.hash: changed.to_dict()}
            else:
                logger.debug(
                    "[subscription] include_payload: changed entity %s "
                    "unresolved at delivery; falling back to hash-only "
                    "notification (sub=%s)",
                    event.hash.hex()[:16] if event.hash else "?",
                    sub.subscription_id,
                )

        # Record notification
        entry.record_notification(now_ms)

        # Dispatch notification via execute (if available)
        # V7.8: Uses inbox handler receive operation
        if self._ctx is not None and self._ctx.execute is not None:
            try:
                # Create notification entity with v7.8 inbox type
                notification_entity = Entity(
                    type=InboxNotification.TYPE,
                    data=notification.to_dict(),
                )

                # G-3: Build notification bounds with cascade_depth from emission
                # context. Per EXTENSION-SUBSCRIPTION §4.5: notification bounds
                # inherit cascade_depth so receiving peers can continue tracking.
                from entity_core.protocol.bounds import Bounds
                notification_budget = sub.limits.notification_budget if sub.limits else None
                notification_bounds = Bounds(
                    budget=notification_budget,
                    chain_id=event.context.chain_id,
                    parent_chain_id=event.context.parent_chain_id,
                    cascade_depth=event.cascade_depth,
                )

                # V7.8: Deliver to inbox via receive operation
                # Uses independent budget per spec (not writer's budget)
                # Per EXTENSION-SUBSCRIPTION §4.2: resource target is deliver_uri
                # without suffix — inbox handler uses it to locate continuations
                result = await self._ctx.execute(
                    sub.deliver_uri,
                    sub.deliver_operation,
                    notification_entity.to_dict(),
                    resource_targets=[sub.deliver_uri],
                    bounds=notification_bounds,
                    included=payload_included,
                )
                if not result.ok:
                    # F-CIMP-2 regression diag — workbench-go
                    # round 2 observed wb-go-side returns 307-byte error
                    # responses on every K=16 concurrent dispatch under
                    # real cross-impl burst, but Python swallowed status.
                    # Status + result-shape are first-pass essentials for
                    # framework-vs-user-handler attribution; result body
                    # often carries the error code + detail.
                    result_payload = getattr(result, "result", None)
                    result_summary: str
                    if isinstance(result_payload, dict):
                        # Trim large bundles; just show shape + error code
                        # if the response is a `system/protocol/error`.
                        data = result_payload.get("data") if isinstance(
                            result_payload.get("data"), dict
                        ) else None
                        if isinstance(data, dict):
                            result_summary = (
                                f"type={result_payload.get('type')!r} "
                                f"code={data.get('code')!r} "
                                f"message={data.get('message')!r}"
                            )
                        else:
                            result_summary = (
                                f"type={result_payload.get('type')!r} "
                                f"data_keys={list(result_payload.get('data', {}).keys()) if isinstance(result_payload.get('data'), dict) else type(result_payload.get('data')).__name__}"
                            )
                    else:
                        result_summary = f"<no result body, type={type(result_payload).__name__}>"
                    logger.warning(
                        f"Notification delivery failed for subscription "
                        f"{sub.subscription_id}: status={getattr(result, 'status', '?')} "
                        f"error={result.error!r} {result_summary} "
                        f"deliver_uri={sub.deliver_uri!r} "
                        f"deliver_op={sub.deliver_operation!r}"
                    )
                    # WB-27 / v1.20 §3.10.2 sender-side mirror: when the
                    # cap-rejected response carries `rejected_marker` per
                    # §3.10.4, bind the matching `lost/capability_denied`
                    # marker so cross-peer audit walkers can follow the
                    # pair from either side. {reason} = `capability_denied`
                    # (same code both sides; kind tells you which side
                    # observed it). Best-effort: any failure to bind is
                    # logged via F11 surface, never affects subscription
                    # lifecycle.
                    self._bind_sender_side_rejected_mirror(
                        sub, event, result, notification_bounds,
                    )
            except Exception as e:
                logger.error(
                    f"Error delivering notification for subscription "
                    f"{sub.subscription_id}: {e}"
                )
        else:
            logger.debug(
                f"Notification not delivered (no execute): {sub.subscription_id}"
            )

    def _bind_sender_side_rejected_mirror(
        self,
        sub: "Subscription",
        event: ChangeEvent,
        result: Any,
        notification_bounds: Any,
    ) -> None:
        """Bind the WB-27 sender-side ``lost`` mirror per v1.20 §3.10.2.

        Only fires when the failed delivery returned 403 with the
        receiver-side ``rejected_marker`` mirror-pointer (§3.10.4). All
        other failure paths (timeouts, 5xx, missing mirror field) are
        out of scope here — they bind under the continuation-engine path
        if/when they reach it.
        """
        if self._ctx is None:
            return
        if getattr(result, "status", 0) != 403:
            return
        # Pull rejected_marker from the response's error metadata. The
        # ExecuteResult.error is a str message; the full result lives in
        # .result. We need the dict result to read .rejected_marker.
        result_payload = getattr(result, "result", None)
        rejected_marker_hash: bytes | None = None
        if isinstance(result_payload, dict):
            val = result_payload.get("rejected_marker")
            if isinstance(val, (bytes, bytearray)) and val:
                rejected_marker_hash = bytes(val)
        # Defer import — subscription module loads before continuation
        # in package init order.
        from entity_handlers.continuation import (
            CODE_CAPABILITY_DENIED,
            _bind_lost_marker,
        )
        # Build a minimal ctx-like for _bind_lost_marker. The function
        # only uses: emit_pathway, chain_id, request_id. Construct a
        # bare shim with those fields.
        chain_id = getattr(notification_bounds, "chain_id", None) or "unknown"
        request_id = sub.subscription_id  # subscription_id is the chain-step identity for delivery
        class _Shim:
            emit_pathway = self._ctx.emit_pathway
        shim = _Shim()
        shim.chain_id = chain_id  # type: ignore[attr-defined]
        shim.request_id = request_id  # type: ignore[attr-defined]
        _bind_lost_marker(
            shim,  # type: ignore[arg-type]
            code=CODE_CAPABILITY_DENIED,
            status=403,
            request_id=request_id,
            target_uri=sub.deliver_uri,
            target_peer_id=getattr(sub, "subscriber_peer_id", None),
            rejected_marker_hash=rejected_marker_hash,
            extra_body={
                "subscription_id": sub.subscription_id,
                "event_uri": event.uri,
            },
        )

    async def _terminate_subscription(
        self, subscription_id: str, reason: str
    ) -> None:
        """Terminate a subscription.

        Args:
            subscription_id: The subscription to terminate.
            reason: Why the subscription is being terminated.
        """
        logger.info(f"Terminating subscription {subscription_id}: {reason}")

        # Remove from index
        if subscription_id in self._index:
            del self._index[subscription_id]

        # Class H F1: drop the delivery worker (the caller is typically the
        # worker itself; ``cancel()`` after we return is observed as a no-op
        # because the worker has already ``return``ed).
        self._drop_delivery_worker(subscription_id)

        # Delete from tree
        if self._ctx is not None and self._ctx.emit_pathway is not None:
            uri = self._ctx.emit_pathway.entity_tree.normalize_uri(
                f"system/subscription/{subscription_id}"
            )
            ctx = EmitContext.protocol(author=self._ctx.peer_id)
            self._ctx.emit_pathway.delete(uri, ctx)


class _IndexUpdater(InternalHook):
    """Internal hook to maintain subscription index."""

    def __init__(self, extension: SubscriptionExtension) -> None:
        self._extension = extension

    def on_change_sync(self, event: ChangeEvent) -> None:
        """Handle subscription entity changes synchronously."""
        self._extension._on_subscription_change(event)


class _NotificationTrigger(AsyncChangeListener):
    """Async listener to trigger notifications on tree changes."""

    def __init__(self, extension: SubscriptionExtension) -> None:
        self._extension = extension

    async def on_change(self, event: ChangeEvent) -> None:
        """Handle tree changes and deliver notifications."""
        await self._extension._on_tree_change(event)
