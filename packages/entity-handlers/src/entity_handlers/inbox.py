"""Inbox handler for async result delivery (v7.8).

The inbox handler receives async operation results and subscription
notifications at inbox URIs. Results are stored in the entity tree
for later retrieval. Supports continuation advancement when a
continuation entity exists at the inbox path.

Pattern: system/inbox/*
Operations: receive

The single `receive` operation accepts any entity type. The entity's
type carries semantic information:
- system/protocol/inbox/delivery: Async operation results
- system/protocol/inbox/notification: Subscription notifications

Example inbox URI: entity://peer/system/inbox/my-request

V7.8 changes from callback handler:
- Renamed pattern: system/callback -> system/inbox
- Renamed operation: deliver -> receive
- Write-ahead processing: stores delivery before processing
- Continuation integration: checks for continuation at inbox path
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from entity_core.capability.grant import Grant, create_capability_token
from entity_core.capability.token import DelegationCaveats
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.delivery import InboxDelivery, InboxNotification, DeliverySpec
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

logger = logging.getLogger(__name__)

INBOX_HANDLER_PATTERN = "system/inbox"


async def _advance_continuation_if_present(
    continuation_path: str,
    advance_params: dict[str, Any],
    ctx: HandlerContext,
):
    """If a continuation is bound at ``continuation_path``, dispatch
    ``system/continuation/advance`` with ``advance_params`` and return
    the ExecuteResult. Returns ``None`` when no continuation exists or
    the entity at that path is the wrong type.

    Per EXTENSION-INBOX §3.2 continuation integration applies to every
    receive invocation, not only structured deliveries. Notifications
    that land on an inbox with a registered continuation MUST advance
    it (reference: the inbox notification-skips-advance regression).
    """
    tree = ctx.emit_pathway.entity_tree
    continuation_hash = tree.get(tree.normalize_uri(continuation_path))
    if not continuation_hash:
        return None

    continuation_entity = ctx.emit_pathway.content_store.get(continuation_hash)
    if continuation_entity is None or continuation_entity.type not in (
        "system/continuation",
        "system/continuation/join",
    ):
        return None

    try:
        return await ctx.execute(
            "system/continuation",
            "advance",
            advance_params,
            resource_targets=[continuation_path],
        )
    except Exception as e:
        logger.warning(
            "Error advancing continuation at %s: %s", continuation_path, e
        )
        return None


def _resolve_inbox_target(path: str, ctx: HandlerContext) -> str:
    """Resolve the absolute (peer-relative) tree path where the delivery is
    stored / where the bound continuation is looked up.

    V7 §1.4/§5.2: ``resource_targets`` is authoritative for the resource
    path; the URI only identifies the handler. The resource target IS the
    storage location — `receive` stores at ``{target}/{id}`` (matching the
    Go reference). It is NOT re-nested under ``system/inbox/``; callers
    that want the mailbox simply target ``system/inbox/{sub}`` and get
    ``system/inbox/{sub}/{id}`` (identical to the prior behavior). An
    arbitrary resource (e.g. a path produced by transform_ops /
    resource_extract per EXTENSION-CONTINUATION §2.2) stores there
    directly, observable at that path — the prior code force-prefixed
    ``system/inbox/`` and double-nested it, which made it invisible to a
    readback at the resource path (cross-impl divergence vs Go).

    The URI-derived form remains a fallback for legacy callers that encode
    the subpath in the handler URI itself
    (``entity://{peer}/system/inbox/{sub}``).

    Reference: the inbox-path-from-resource-target regression;
    GoValidator continuations/transform_ops_apply.
    """
    if ctx.resource_targets:
        target = ctx.resource_targets[0]
        full_target_uri = ctx.emit_pathway.entity_tree.normalize_uri(target)
        local_prefix = f"/{ctx.local_peer_id}/"
        if full_target_uri.startswith(local_prefix):
            bare = full_target_uri[len(local_prefix):]
        else:
            bare = target.lstrip("/")
    else:
        bare = path.lstrip("/")

    bare = bare.strip("/")
    # Preserve the legacy default-mailbox mapping: a bare `system/inbox`
    # (no subpath) historically stored under `system/inbox/default`.
    if bare in ("", "system/inbox"):
        bare = "system/inbox/default"
    return bare


async def inbox_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle inbox receive operation.

    Inbox endpoints receive async results and subscription notifications,
    storing them in the tree for later retrieval.

    Per EXTENSION-INBOX v5.0:
    - Single `receive` operation accepts any entity type
    - Entity type carries semantics (delivery vs notification)
    - Write-ahead: Store in tree BEFORE processing
    - Continuation check: If continuation exists at inbox path, advance it
    - If no continuation: delivery persists in tree (mailbox)

    Args:
        path: The full path (including system/inbox/ prefix).
        operation: The operation (must be "receive").
        params: Operation parameters (any entity).
        ctx: Handler context.

    Returns:
        Response dict with status and result.
    """
    # Extract params data (params is a full entity per spec)
    params_data = params.get("data", params) if isinstance(params, dict) else {}

    if operation == "receive":
        return await _handle_receive(path, params_data, ctx)
    # Legacy support: allow "deliver" as alias for "receive"
    elif operation == "deliver":
        return await _handle_receive(path, params_data, ctx)
    else:
        return {
            "status": 501,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "unsupported_operation",
                    "message": f"Inbox handler does not support operation: {operation}",
                },
            },
        }


async def _handle_receive(
    path: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle receive operation - store async result with write-ahead.

    Write-ahead processing (EXTENSION-INBOX v5.0 §3):
    1. Store delivery in tree at system/inbox/{path}/{request_id}
    2. Check for continuation entity at inbox path
    3. If continuation exists: delegate to continuation advance operation
    4. If no continuation: delivery persists (mailbox mode)

    Per INBOX §3.1: The receive operation accepts ANY entity as params.
    If params match InboxDelivery format, extract fields. If params match
    InboxNotification format (subscription notification), delegate to notify.
    Otherwise treat the entire params as the message to store.

    Args:
        path: The inbox path (e.g., "system/inbox/my-request").
        params: Delivery parameters (any entity).
        ctx: Handler context.

    Returns:
        Response dict with status and result.
    """
    # Check if this is a subscription notification (has subscription_id field).
    # Notifications are stored as raw notification entities (not wrapped in
    # InboxDelivery) so the validator can read them back with the correct type.
    if "subscription_id" in params:
        return await _handle_notification(path, params, ctx)

    # Try to parse as InboxDelivery for structured deliveries, but accept anything
    try:
        delivery = InboxDelivery.from_dict(params)
        original_request_id = delivery.original_request_id
        delivery_status = delivery.status
        delivery_result = delivery.result
    except (KeyError, TypeError):
        original_request_id = str(uuid.uuid4())
        delivery_status = 200
        delivery_result = params

    inbox_target = _resolve_inbox_target(path, ctx)

    # G-3: Read cascade_depth from incoming bounds for cross-peer propagation.
    # Per SYSTEM-COMPOSITION §3.4: receiving peer uses bounds.cascade_depth
    # as initial cascade depth for resulting tree writes.
    if ctx.bounds and ctx.bounds.cascade_depth is not None:
        ctx.emit_pathway._cascade_depth = max(
            ctx.emit_pathway._cascade_depth, ctx.bounds.cascade_depth
        )

    # Step 1: Write-ahead - store delivery at the resource target itself
    # (NOT re-nested under system/inbox/; see _resolve_inbox_target).
    storage_path = f"{inbox_target}/{original_request_id}"
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(storage_path)

    # Create delivery entity - store the actual message
    delivery_data = {
        "original_request_id": original_request_id,
        "status": delivery_status,
        "result": delivery_result,
    }
    delivery_entity = Entity(
        type=InboxDelivery.TYPE,
        data=delivery_data,
    )

    # Store via emit pathway (handler-authorized: inbox manages system/inbox/*)
    emit_ctx = EmitContext.from_handler_grant(ctx, "receive")
    content_hash = ctx.emit_pathway.emit(full_uri, delivery_entity, emit_ctx).hash

    # Step 2-3: Per EXTENSION-INBOX §3.2, delegate to continuation advance
    # when one is registered at the (resource-target) inbox path.
    continuation_path = inbox_target
    advance_result = await _advance_continuation_if_present(
        continuation_path,
        {"result": delivery_result, "status": delivery_status or 200},
        ctx,
    )
    if advance_result is not None:
        if advance_result.ok:
            # Step 4: Clean up stored delivery on success (§3.2 step 5)
            ctx.emit_pathway.delete(full_uri, emit_ctx)
            return {
                "status": 200,
                "result": {
                    "type": "system/inbox/receive-result",
                    "data": {
                        "stored_at": storage_path,
                        "hash": content_hash,
                        "continuation_advanced": True,
                        "continuation_path": continuation_path,
                        "cleaned_up": True,
                    },
                },
            }
        logger.warning(
            "Continuation advance failed: %s", advance_result.error
        )

    # Step 3b: No continuation or continuation failed - mailbox mode
    return {
        "status": 200,
        "result": {
            "type": "system/inbox/receive-result",
            "data": {
                "stored_at": storage_path,
                "hash": content_hash,
            },
        },
    }


async def _handle_notification(
    path: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Store a subscription notification.

    Called internally from _handle_receive when params contain subscription_id.
    Notifications are stored at a subscription-grouped path to enable
    listing all notifications for a subscription via prefix query.

    Storage path: system/inbox/{inbox_path}/{subscription_id}/{timestamp}

    Args:
        path: The inbox path (e.g., "system/inbox/my-subscription").
        params: Notification parameters (must include subscription_id).
        ctx: Handler context.

    Returns:
        Response dict with status and result.
    """
    try:
        notification = InboxNotification.from_dict(params)
    except (KeyError, TypeError) as e:
        return {
            "status": 400,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "invalid_params",
                    "message": f"Invalid notification params: {e}",
                },
            },
        }

    inbox_target = _resolve_inbox_target(path, ctx)

    # Per EXTENSION-INBOX §3.2: store_path = {resource target} + "/" + id
    # (resource target as given; not re-nested under system/inbox/).
    storage_path = f"{inbox_target}/{uuid.uuid4()}"
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(storage_path)

    # Create notification entity
    notification_entity = Entity(
        type=InboxNotification.TYPE,
        data=notification.to_dict(),
    )

    # Store via emit pathway (handler-authorized: inbox manages system/inbox/*)
    emit_ctx = EmitContext.from_handler_grant(ctx, "notify")
    content_hash = ctx.emit_pathway.emit(full_uri, notification_entity, emit_ctx).hash

    # Per EXTENSION-INBOX §3.2: advance a continuation bound at the
    # inbox path if present. Notifications are valid continuation
    # triggers — this is what drives subscription-fired chains
    # (chain_sync, psync, filesync, bisync). Do not delete the stored
    # notification on success: mailbox listing MAY still need it.
    continuation_path = inbox_target
    advance_result = await _advance_continuation_if_present(
        continuation_path,
        {"result": params, "status": 200},
        ctx,
    )

    response_data: dict[str, Any] = {
        "stored_at": storage_path,
        "hash": content_hash,
    }
    if advance_result is not None and advance_result.ok:
        response_data["continuation_advanced"] = True
        response_data["continuation_path"] = continuation_path

    return {
        "status": 200,
        "result": {
            "type": "system/inbox/receive-result",
            "data": response_data,
        },
    }


# NOTE: Durability lookup and advertise operations are NOT handled here.
# Per EXTENSION-DURABILITY v0.1 (extracted from EXTENSION-INBOX):
# - The sender's lookup address is returned in the response as
#   ``durability.handle`` (§5 / §6); the sender follows the handle with
#   an ordinary ``system/tree:get``. No inbox-specific lookup op needed.
# - The advertisement (§3, MAY) is seeded at peer bootstrap as an entity
#   at the well-known path ``system/durability``; senders read it with
#   ``system/tree:get``. No inbox-specific advertise op needed.
# Keeping inbox isolated from durability concerns is the v5.9 surface.


def create_inbox_token(
    granter_keypair: Keypair,
    grantee_identity: Entity,
    inbox_uri: str,
    inbox_operation: str = "receive",
    ttl_ms: int | None = None,
) -> tuple[Entity, Entity, Entity]:
    """Create a capability token authorizing inbox delivery.

    Creates a token that grants the grantee permission to deliver results
    to a specific inbox URI. The token is restricted to the inbox
    handler and the receive operation.

    Args:
        granter_keypair: The granter's keypair (inbox receiver).
        grantee_identity: The grantee's identity entity (inbox sender).
        inbox_uri: The inbox URI to authorize (e.g., "entity://peer/system/inbox/path").
        inbox_operation: The operation to authorize (typically "receive").
        ttl_ms: Optional time-to-live in milliseconds.

    Returns:
        Tuple of (capability_entity, granter_identity, signature_entity).

    Example:
        # Create token allowing peer to deliver to my inbox
        cap, identity, sig = create_inbox_token(
            my_keypair,
            their_identity,
            f"entity://{my_peer_id}/system/inbox/my-request",
            "receive",
            ttl_ms=60000,  # 1 minute
        )
    """
    # Parse the resource path from inbox_uri
    from entity_core.utils.path import extract_handler_path
    resource_path = extract_handler_path(inbox_uri)

    # Create grant for inbox handler with restricted scope
    grants = [
        Grant.create(
            handlers=["system/inbox/*"],
            resources=[resource_path],
            operations=[inbox_operation],
        ),
    ]

    # Use standard token creation
    capability_entity, granter_identity, signature_entity = create_capability_token(
        granter_keypair,
        grantee_identity,
        grants,
        expires_in_ms=ttl_ms,
    )

    # Add no_delegation caveat to the capability
    from entity_core.protocol.auth import create_signature_entity

    cap_data = capability_entity.data.copy()
    cap_data["delegation_caveats"] = DelegationCaveats(no_delegation=True).to_dict()

    capability_entity = Entity(
        type="system/capability/token",
        data=cap_data,
    )

    # Re-sign with updated data
    granter_hash = granter_identity.compute_hash()
    cap_hash = capability_entity.compute_hash()
    signature_entity = create_signature_entity(granter_keypair, cap_hash, granter_hash)

    return capability_entity, granter_identity, signature_entity
