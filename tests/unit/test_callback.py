"""Tests for inbox/delivery message types (v7.8)."""

from entity_core.protocol.delivery import (
    DeliverySpec,
    InboxDelivery,
    InboxNotification,
)
from entity_core.utils.ecf import ALG_ECFV1_SHA256


HASH_ENTITY = bytes([ALG_ECFV1_SHA256]) + b"entity" + b"\x00" * 26  # 33 bytes
HASH_PREV = bytes([ALG_ECFV1_SHA256]) + b"prev__" + b"\x00" * 26  # 33 bytes


class TestDeliverySpec:
    """Tests for DeliverySpec (v7.8 inbox)."""

    def test_type_constant(self):
        assert DeliverySpec.TYPE == "system/delivery-spec"

    def test_to_dict(self):
        spec = DeliverySpec(
            uri="entity://peer/system/inbox/my-request",
            operation="receive",
        )
        d = spec.to_dict()
        assert d["uri"] == "entity://peer/system/inbox/my-request"
        assert d["operation"] == "receive"

    def test_from_dict(self):
        d = {
            "uri": "entity://peer/system/inbox/test",
            "operation": "receive",
        }
        spec = DeliverySpec.from_dict(d)
        assert spec.uri == "entity://peer/system/inbox/test"
        assert spec.operation == "receive"

    def test_default_operation(self):
        spec = DeliverySpec(uri="entity://peer/system/inbox/test")
        assert spec.operation == "receive"

    def test_roundtrip(self):
        original = DeliverySpec(
            uri="entity://peer/system/inbox/roundtrip",
            operation="receive",
        )
        d = original.to_dict()
        restored = DeliverySpec.from_dict(d)
        assert restored.uri == original.uri
        assert restored.operation == original.operation


class TestInboxDelivery:
    """Tests for InboxDelivery (v7.8)."""

    def test_type_constant(self):
        assert InboxDelivery.TYPE == "system/protocol/inbox/delivery"

    def test_to_dict(self):
        delivery = InboxDelivery(
            original_request_id="req-123",
            status=200,
            result={"type": "file", "data": {"name": "test.txt"}},
        )
        d = delivery.to_dict()
        assert d["original_request_id"] == "req-123"
        assert d["status"] == 200
        assert d["result"]["data"]["name"] == "test.txt"

    def test_from_dict(self):
        d = {
            "original_request_id": "req-456",
            "status": 404,
            "result": {"code": "not_found", "message": "Not found"},
        }
        delivery = InboxDelivery.from_dict(d)
        assert delivery.original_request_id == "req-456"
        assert delivery.status == 404
        assert delivery.result["code"] == "not_found"

    def test_from_dict_none_result(self):
        d = {
            "original_request_id": "req-789",
            "status": 204,
        }
        delivery = InboxDelivery.from_dict(d)
        assert delivery.original_request_id == "req-789"
        assert delivery.status == 204
        assert delivery.result is None

    def test_roundtrip(self):
        original = InboxDelivery(
            original_request_id="roundtrip-test",
            status=200,
            result={"success": True},
        )
        d = original.to_dict()
        restored = InboxDelivery.from_dict(d)
        assert restored.original_request_id == original.original_request_id
        assert restored.status == original.status
        assert restored.result == original.result


class TestInboxNotification:
    """Tests for InboxNotification (v7.8)."""

    def test_type_constant(self):
        assert InboxNotification.TYPE == "system/protocol/inbox/notification"

    def test_to_dict_full(self):
        notification = InboxNotification(
            subscription_id="sub-123",
            event="updated",
            uri="entity://peer/data/files/doc.txt",
            hash=HASH_ENTITY,
            previous_hash=HASH_PREV,
        )
        d = notification.to_dict()
        assert d["subscription_id"] == "sub-123"
        assert d["event"] == "updated"
        assert d["uri"] == "entity://peer/data/files/doc.txt"
        assert d["hash"] == HASH_ENTITY
        assert d["previous_hash"] == HASH_PREV

    def test_to_dict_created(self):
        notification = InboxNotification(
            subscription_id="sub-456",
            event="created",
            uri="entity://peer/data/new-file.txt",
            hash=HASH_ENTITY,
        )
        d = notification.to_dict()
        assert d["subscription_id"] == "sub-456"
        assert d["event"] == "created"
        assert d["hash"] == HASH_ENTITY
        assert "previous_hash" not in d

    def test_to_dict_deleted(self):
        notification = InboxNotification(
            subscription_id="sub-789",
            event="deleted",
            uri="entity://peer/data/removed.txt",
            previous_hash=HASH_PREV,
        )
        d = notification.to_dict()
        assert d["subscription_id"] == "sub-789"
        assert d["event"] == "deleted"
        assert d["previous_hash"] == HASH_PREV
        assert "hash" not in d

    def test_from_dict(self):
        d = {
            "subscription_id": "sub-test",
            "event": "updated",
            "uri": "entity://peer/path",
            "hash": HASH_ENTITY,
            "previous_hash": HASH_PREV,
        }
        notification = InboxNotification.from_dict(d)
        assert notification.subscription_id == "sub-test"
        assert notification.event == "updated"
        assert notification.uri == "entity://peer/path"
        assert notification.hash == HASH_ENTITY
        assert notification.previous_hash == HASH_PREV

    def test_from_dict_minimal(self):
        d = {
            "subscription_id": "sub-min",
            "event": "created",
            "uri": "entity://peer/path",
        }
        notification = InboxNotification.from_dict(d)
        assert notification.subscription_id == "sub-min"
        assert notification.hash is None
        assert notification.previous_hash is None

    def test_roundtrip(self):
        original = InboxNotification(
            subscription_id="roundtrip-sub",
            event="updated",
            uri="entity://peer/data/roundtrip",
            hash=HASH_ENTITY,
            previous_hash=HASH_PREV,
        )
        d = original.to_dict()
        restored = InboxNotification.from_dict(d)
        assert restored.subscription_id == original.subscription_id
        assert restored.event == original.event
        assert restored.uri == original.uri
        assert restored.hash == original.hash
        assert restored.previous_hash == original.previous_hash
