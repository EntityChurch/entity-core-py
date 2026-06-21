"""Inbox Extension message types (v7.8).

The Inbox Extension provides async result delivery for long-running operations.
Renamed from Callback Extension in v7.8:
- CallbackSpec -> DeliverySpec
- CallbackDelivery -> InboxDelivery
- CallbackNotification -> InboxNotification
- system/callback/* -> system/protocol/inbox/*
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from entity_core.utils.ecf import Hash


@dataclass
class DeliverySpec:
    """Specifies where to deliver async results (v7.8 inbox).

    Used in EXECUTE requests via deliver_to field to indicate where
    the result should be delivered when the operation completes.

    Attributes:
        uri: The inbox URI (e.g., "entity://peer/system/inbox/my-path").
        operation: The operation to invoke (typically "receive").
    """

    TYPE = "system/delivery-spec"

    uri: str
    operation: str = "receive"

    def to_dict(self) -> dict[str, Any]:
        """Convert to wire format."""
        return {
            "uri": self.uri,
            "operation": self.operation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeliverySpec:
        """Parse from wire format."""
        return cls(
            uri=data["uri"],
            operation=data.get("operation", "receive"),
        )


def _ensure_entity_hash(value: Any) -> Any:
    """Ensure a value that looks like an entity has content_hash.

    Per EXTENSION-INBOX v5.1 §4.1 (I1): the result field in inbox delivery
    carries the handler's result as a full inline entity {type, data, content_hash}.
    If the value has type and data but no content_hash, compute and add it.

    Args:
        value: Any value — only dicts with type+data are modified.

    Returns:
        The value with content_hash ensured if it's an entity.
    """
    if isinstance(value, dict) and "type" in value and "data" in value:
        if "content_hash" not in value:
            from entity_core.utils.ecf import compute_ecf_hash
            value = dict(value)  # Don't mutate the original
            value["content_hash"] = compute_ecf_hash(
                {"type": value["type"], "data": value["data"]}
            )
    return value


@dataclass
class InboxDelivery:
    """Params for system/protocol/inbox/delivery (v7.8).

    Delivers the result of a completed async operation to an inbox endpoint.

    Per EXTENSION-INBOX v5.1 §4.1: the result field carries the handler's
    result as a full inline entity {type, data, content_hash}, preserving
    entity identity through the delivery chain. The result is encoded as
    inline CBOR (map within map), not byte-string wrapped.

    Attributes:
        original_request_id: The request_id of the original EXECUTE request.
        status: HTTP-style status code (200=success, 404=not found, etc.).
        result: The operation result as a full entity {type, data, content_hash}.
    """

    TYPE = "system/protocol/inbox/delivery"

    original_request_id: str
    status: int
    result: Any

    def to_dict(self) -> dict[str, Any]:
        """Convert to wire format.

        Ensures the result field is a full inline entity with content_hash
        when it has entity structure (type + data fields).
        """
        return {
            "original_request_id": self.original_request_id,
            "status": self.status,
            "result": _ensure_entity_hash(self.result),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InboxDelivery:
        """Parse from wire format."""
        return cls(
            original_request_id=data["original_request_id"],
            status=data["status"],
            result=data.get("result"),
        )


@dataclass
class InboxNotification:
    """Params for system/protocol/inbox/notification (v7.8).

    Delivers a subscription notification to an inbox endpoint.

    Attributes:
        subscription_id: ID of the subscription that generated this notification.
        event: The type of event ("created", "updated", "deleted").
        uri: The URI that changed.
        hash: The new content hash (None for deleted).
        previous_hash: The previous content hash (None for created).
    """

    TYPE = "system/protocol/inbox/notification"

    subscription_id: str
    event: str
    uri: str
    hash: Hash | None = None
    previous_hash: Hash | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to wire format."""
        result: dict[str, Any] = {
            "subscription_id": self.subscription_id,
            "event": self.event,
            "uri": self.uri,
        }
        if self.hash is not None:
            result["hash"] = self.hash
        if self.previous_hash is not None:
            result["previous_hash"] = self.previous_hash
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InboxNotification:
        """Parse from wire format."""
        return cls(
            subscription_id=data["subscription_id"],
            event=data["event"],
            uri=data["uri"],
            hash=data.get("hash"),
            previous_hash=data.get("previous_hash"),
        )
