"""Entity Core Protocol types and messages.

This module exports all protocol message types used in Entity Core.
"""

from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.messages import (
    Execute,
    ExecuteResponse,
    ResourceTarget,
    compute_content_hash,
)
from entity_core.protocol.bounds import Bounds
from entity_core.protocol.auth import (
    create_signature_entity,
)
from entity_core.protocol.framing import (
    send_envelope,
    recv_envelope,
)
from entity_core.protocol.delivery import (
    DeliverySpec,
    InboxDelivery,
    InboxNotification,
)
from entity_core.protocol.transport_ops import (
    ACTIVE_OPS,
    CONTENT_GET,
    EXECUTE,
    GET_CLASS_OPS,
    KNOWN_OPS,
    MANIFEST_GET,
    SUBSCRIBE_RESERVED,
    TREE_GET,
    is_active_op,
    is_known_op,
    validate_http_poll_ops,
    validate_live_ops,
    validate_supported_ops,
)
from entity_core.protocol.durability import (
    ADVERTISEMENT_PATH,
    ADVERTISEMENT_TYPE,
    DEFAULT_DURABILITY_POLICY,
    LEVEL_NONE,
    LEVEL_REPLICATED,
    LEVEL_STORED,
    REASON_DUPLICATE_REQUEST_ID,
    REASON_NO_DURABLE_STORE,
    REASON_NO_INBOX_HANDLER,
    REASON_REQUIRED_UNMET,
    REASON_UNKNOWN_LEVEL,
    STATUS_ACCEPTED,
    STATUS_CONFLICT,
    STATUS_PRECONDITION_FAILED,
    DurabilityPolicy,
    DurabilityRequest,
    DurabilityResult,
    DurabilityVerdict,
    advertise,
    is_known_level,
    reconcile,
    reconcile_for_dispatch,
)

__all__ = [
    # Entity and Envelope
    "Entity",
    "Envelope",
    # Messages
    "Execute",
    "ExecuteResponse",
    "ResourceTarget",
    "compute_content_hash",
    # Bounds
    "Bounds",
    # Auth
    "create_signature_entity",
    # Framing
    "send_envelope",
    "recv_envelope",
    # Inbox
    "DeliverySpec",
    "InboxDelivery",
    "InboxNotification",
    # Durability (EXTENSION-DURABILITY v0.1 — exploratory, optional)
    "DurabilityRequest",
    "DurabilityResult",
    "DurabilityPolicy",
    "DurabilityVerdict",
    "DEFAULT_DURABILITY_POLICY",
    "LEVEL_NONE",
    "LEVEL_STORED",
    "LEVEL_REPLICATED",
    "REASON_NO_DURABLE_STORE",
    "REASON_NO_INBOX_HANDLER",
    "REASON_REQUIRED_UNMET",
    "REASON_UNKNOWN_LEVEL",
    "REASON_DUPLICATE_REQUEST_ID",
    "STATUS_ACCEPTED",
    "STATUS_PRECONDITION_FAILED",
    "STATUS_CONFLICT",
    "is_known_level",
    "reconcile",
    "reconcile_for_dispatch",
    "advertise",
    "ADVERTISEMENT_PATH",
    "ADVERTISEMENT_TYPE",
    # D-13 supported_ops vocabulary (EXTENSION-NETWORK §6.5)
    "EXECUTE",
    "TREE_GET",
    "CONTENT_GET",
    "MANIFEST_GET",
    "SUBSCRIBE_RESERVED",
    "ACTIVE_OPS",
    "GET_CLASS_OPS",
    "KNOWN_OPS",
    "is_active_op",
    "is_known_op",
    "validate_supported_ops",
    "validate_http_poll_ops",
    "validate_live_ops",
]
