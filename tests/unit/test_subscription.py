"""Tests for subscription types."""

from entity_core.utils.ecf import ALG_ECFV1_SHA256
from entity_core.protocol.delivery import DeliverySpec

from entity_handlers.subscription import (
    SubscriptionLimits,
    SubscriptionEntity,
    SubscribeRequest,
    UnsubscribeRequest,
)


# Test hash values (bytes format for V4)
HASH_IDENTITY = bytes([ALG_ECFV1_SHA256]) + b"identy" + b"\x00" * 26  # 33 bytes
HASH_TOKEN = bytes([ALG_ECFV1_SHA256]) + b"token_" + b"\x00" * 26  # 33 bytes


class TestSubscriptionLimits:
    """Tests for SubscriptionLimits."""

    def test_to_dict_full(self):
        """SubscriptionLimits converts all fields."""
        limits = SubscriptionLimits(
            max_events=100,
            max_duration_ms=3600000,
            rate_limit=10,
            notification_budget=50,
        )
        d = limits.to_dict()
        assert d["max_events"] == 100
        assert d["max_duration_ms"] == 3600000
        assert d["rate_limit"] == 10
        assert d["notification_budget"] == 50

    def test_to_dict_partial(self):
        """SubscriptionLimits omits None fields."""
        limits = SubscriptionLimits(max_events=50)
        d = limits.to_dict()
        assert d == {"max_events": 50}
        assert "max_duration_ms" not in d

    def test_to_dict_empty(self):
        """SubscriptionLimits with no limits returns empty dict."""
        limits = SubscriptionLimits()
        d = limits.to_dict()
        assert d == {}

    def test_from_dict(self):
        """SubscriptionLimits parses from dict."""
        d = {
            "max_events": 200,
            "max_duration_ms": 7200000,
            "rate_limit": 20,
            "notification_budget": 100,
        }
        limits = SubscriptionLimits.from_dict(d)
        assert limits.max_events == 200
        assert limits.max_duration_ms == 7200000
        assert limits.rate_limit == 20
        assert limits.notification_budget == 100

    def test_from_dict_none(self):
        """SubscriptionLimits.from_dict handles None."""
        limits = SubscriptionLimits.from_dict(None)
        assert limits is None

    def test_merge_with_server_limits_tighter(self):
        """Server limits tighten client limits."""
        client = SubscriptionLimits(max_events=1000, rate_limit=100)
        server = SubscriptionLimits(max_events=500, rate_limit=50)
        merged = client.merge_with_server_limits(server)
        assert merged.max_events == 500  # Server is tighter
        assert merged.rate_limit == 50  # Server is tighter

    def test_merge_with_server_limits_looser(self):
        """Server cannot loosen client limits."""
        client = SubscriptionLimits(max_events=100, rate_limit=10)
        server = SubscriptionLimits(max_events=500, rate_limit=50)
        merged = client.merge_with_server_limits(server)
        assert merged.max_events == 100  # Client is tighter
        assert merged.rate_limit == 10  # Client is tighter

    def test_merge_with_server_limits_fills_gaps(self):
        """Server limits fill in client gaps."""
        client = SubscriptionLimits(max_events=100)
        server = SubscriptionLimits(rate_limit=60, max_duration_ms=86400000)
        merged = client.merge_with_server_limits(server)
        assert merged.max_events == 100  # Client specified
        assert merged.rate_limit == 60  # Server fills gap
        assert merged.max_duration_ms == 86400000  # Server fills gap

    def test_merge_with_none_server_limits(self):
        """Merge with None server limits returns client limits."""
        client = SubscriptionLimits(max_events=100)
        merged = client.merge_with_server_limits(None)
        assert merged.max_events == 100


class TestSubscriptionEntity:
    """Tests for SubscriptionEntity."""

    def test_type_constant(self):
        """SubscriptionEntity has correct TYPE."""
        assert SubscriptionEntity.TYPE == "system/subscription"

    def test_to_dict(self):
        """SubscriptionEntity converts to dict."""
        sub = SubscriptionEntity(
            subscription_id="sub-123",
            pattern="data/files/*",
            events=["created", "updated"],
            deliver_uri="entity://peer/system/inbox/my-sub",
            deliver_operation="notify",
            subscriber_identity=HASH_IDENTITY,
            deliver_token=HASH_TOKEN,
            created_at=1700000000000,
            limits=SubscriptionLimits(max_events=100),
        )
        d = sub.to_dict()
        assert d["subscription_id"] == "sub-123"
        assert d["pattern"] == "data/files/*"
        assert d["events"] == ["created", "updated"]
        assert d["deliver_uri"] == "entity://peer/system/inbox/my-sub"
        assert d["deliver_operation"] == "notify"
        assert d["subscriber_identity"] == HASH_IDENTITY
        assert d["deliver_token"] == HASH_TOKEN
        assert d["created_at"] == 1700000000000
        assert d["limits"]["max_events"] == 100

    def test_to_dict_no_limits(self):
        """SubscriptionEntity omits limits if None."""
        sub = SubscriptionEntity(
            subscription_id="sub-456",
            pattern="*",
            events=["deleted"],
            deliver_uri="entity://peer/system/inbox/test",
            deliver_operation="notify",
            subscriber_identity=HASH_IDENTITY,
            deliver_token=HASH_TOKEN,
            created_at=1700000000000,
        )
        d = sub.to_dict()
        assert "limits" not in d

    def test_from_dict(self):
        """SubscriptionEntity parses from dict."""
        d = {
            "subscription_id": "sub-parsed",
            "pattern": "system/*",
            "events": ["created", "updated", "deleted"],
            "deliver_uri": "entity://peer/system/inbox",
            "deliver_operation": "notify",
            "subscriber_identity": HASH_IDENTITY,
            "deliver_token": HASH_TOKEN,
            "created_at": 1700000001000,
            "limits": {"max_events": 50, "rate_limit": 10},
        }
        sub = SubscriptionEntity.from_dict(d)
        assert sub.subscription_id == "sub-parsed"
        assert sub.pattern == "system/*"
        assert sub.events == ["created", "updated", "deleted"]
        assert sub.limits.max_events == 50
        assert sub.limits.rate_limit == 10

    def test_roundtrip(self):
        """SubscriptionEntity survives roundtrip."""
        original = SubscriptionEntity(
            subscription_id="roundtrip-sub",
            pattern="data/*",
            events=["updated"],
            deliver_uri="entity://peer/system/inbox/rt",
            deliver_operation="notify",
            subscriber_identity=HASH_IDENTITY,
            deliver_token=HASH_TOKEN,
            created_at=1700000002000,
            limits=SubscriptionLimits(max_events=1000, rate_limit=60),
        )
        d = original.to_dict()
        restored = SubscriptionEntity.from_dict(d)
        assert restored.subscription_id == original.subscription_id
        assert restored.pattern == original.pattern
        assert restored.events == original.events
        assert restored.deliver_uri == original.deliver_uri
        assert restored.limits.max_events == original.limits.max_events


class TestSubscribeRequest:
    """Tests for SubscribeRequest."""

    def test_type_constant(self):
        """SubscribeRequest has correct TYPE."""
        assert SubscribeRequest.TYPE == "system/subscription/request"

    def test_to_dict(self):
        """SubscribeRequest converts to dict."""
        request = SubscribeRequest(
            deliver_to=DeliverySpec(
                uri="entity://peer/system/inbox/test",
                operation="notify",
            ),
            deliver_token=HASH_TOKEN,
            events=["created", "updated"],
            limits=SubscriptionLimits(max_events=100),
        )
        d = request.to_dict()
        assert d["deliver_to"]["uri"] == "entity://peer/system/inbox/test"
        assert d["deliver_to"]["operation"] == "notify"
        assert d["deliver_token"] == HASH_TOKEN
        assert d["events"] == ["created", "updated"]
        assert d["limits"]["max_events"] == 100

    def test_to_dict_minimal(self):
        """SubscribeRequest omits optional fields."""
        request = SubscribeRequest(
            deliver_to=DeliverySpec(
                uri="entity://peer/system/inbox",
                operation="notify",
            ),
            deliver_token=HASH_TOKEN,
        )
        d = request.to_dict()
        assert "events" not in d
        assert "limits" not in d

    def test_from_dict(self):
        """SubscribeRequest parses from dict."""
        d = {
            "deliver_to": {
                "uri": "entity://peer/system/inbox",
                "operation": "notify",
            },
            "deliver_token": HASH_TOKEN,
            "events": ["deleted"],
            "limits": {"rate_limit": 10},
        }
        request = SubscribeRequest.from_dict(d)
        assert request.deliver_to.uri == "entity://peer/system/inbox"
        assert request.deliver_to.operation == "notify"
        assert request.deliver_token == HASH_TOKEN
        assert request.events == ["deleted"]
        assert request.limits.rate_limit == 10


class TestUnsubscribeRequest:
    """Tests for UnsubscribeRequest."""

    def test_type_constant(self):
        """UnsubscribeRequest has correct TYPE."""
        assert UnsubscribeRequest.TYPE == "system/subscription/cancel"

    def test_to_dict(self):
        """UnsubscribeRequest converts to dict."""
        request = UnsubscribeRequest(subscription_id="sub-to-cancel")
        d = request.to_dict()
        assert d["subscription_id"] == "sub-to-cancel"

    def test_from_dict(self):
        """UnsubscribeRequest parses from dict."""
        d = {"subscription_id": "sub-456"}
        request = UnsubscribeRequest.from_dict(d)
        assert request.subscription_id == "sub-456"

    def test_roundtrip(self):
        """UnsubscribeRequest survives roundtrip."""
        original = UnsubscribeRequest(subscription_id="roundtrip-cancel")
        d = original.to_dict()
        restored = UnsubscribeRequest.from_dict(d)
        assert restored.subscription_id == original.subscription_id
