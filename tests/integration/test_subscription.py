"""Integration tests for subscription extension."""

import asyncio
import time

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.extensions import ExtensionContext
from entity_core.protocol.delivery import InboxNotification
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import (
    ChangeEvent,
    ChangeKind,
    EmitContext,
    EmitPathway,
)
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree
from entity_core.utils.ecf import ALG_ECFV1_SHA256

from entity_handlers.subscription import (
    SubscriptionEntity,
    SubscriptionExtension,
    SubscriptionLimits,
)


# Test hash values
HASH_IDENTITY = bytes([ALG_ECFV1_SHA256]) + b"identy" + b"\x00" * 26
HASH_TOKEN = bytes([ALG_ECFV1_SHA256]) + b"token_" + b"\x00" * 26


class TestSubscriptionExtension:
    """Integration tests for SubscriptionExtension."""

    @pytest.fixture
    def setup_extension(self) -> tuple[SubscriptionExtension, EmitPathway, Keypair]:
        """Create test extension with emit pathway."""
        keypair = Keypair.generate()
        content_store = ContentStore()
        entity_tree = EntityTree(keypair.peer_id)
        emit_pathway = EmitPathway(content_store, entity_tree)

        extension = SubscriptionExtension()
        ctx = ExtensionContext(
            keypair=keypair,
            emit_pathway=emit_pathway,
        )
        extension.initialize(ctx)

        return extension, emit_pathway, keypair

    def test_extension_initializes(self, setup_extension):
        """Extension initializes without error."""
        extension, emit_pathway, keypair = setup_extension
        assert extension is not None
        assert extension.list_subscriptions() == []

    def test_subscription_loaded_from_tree(self, setup_extension):
        """Extension loads existing subscriptions from tree."""
        extension, emit_pathway, keypair = setup_extension

        # Manually add a subscription to tree
        sub = SubscriptionEntity(
            subscription_id="existing-sub",
            pattern="data/*",
            events=["created", "updated"],
            deliver_uri="entity://peer/callback",
            deliver_operation="notify",
            subscriber_identity=HASH_IDENTITY,
            deliver_token=HASH_TOKEN,
            created_at=int(time.time() * 1000),
        )
        sub_entity = Entity(type=SubscriptionEntity.TYPE, data=sub.to_dict())
        uri = emit_pathway.entity_tree.normalize_uri(f"system/subscription/{sub.subscription_id}")
        emit_pathway.emit(uri, sub_entity, EmitContext.bootstrap())

        # Re-initialize to load from tree
        extension2 = SubscriptionExtension()
        ctx2 = ExtensionContext(keypair=keypair, emit_pathway=emit_pathway)
        extension2.initialize(ctx2)

        subs = extension2.list_subscriptions()
        assert len(subs) == 1
        assert subs[0].subscription_id == "existing-sub"

    def test_subscription_index_updated_on_create(self, setup_extension):
        """Index updates when subscription is created."""
        extension, emit_pathway, keypair = setup_extension

        # Create subscription via emit
        sub = SubscriptionEntity(
            subscription_id="new-sub",
            pattern="files/*",
            events=["created"],
            deliver_uri="entity://peer/callback",
            deliver_operation="notify",
            subscriber_identity=HASH_IDENTITY,
            deliver_token=HASH_TOKEN,
            created_at=int(time.time() * 1000),
        )
        sub_entity = Entity(type=SubscriptionEntity.TYPE, data=sub.to_dict())
        uri = emit_pathway.entity_tree.normalize_uri(f"system/subscription/{sub.subscription_id}")
        emit_pathway.emit(uri, sub_entity, EmitContext.protocol(author=keypair.peer_id))

        # Check index is updated
        assert extension.get_subscription("new-sub") is not None
        assert extension.get_subscription("new-sub").pattern == "files/*"

    def test_subscription_index_updated_on_delete(self, setup_extension):
        """Index updates when subscription is deleted."""
        extension, emit_pathway, keypair = setup_extension

        # Create subscription
        sub = SubscriptionEntity(
            subscription_id="to-delete",
            pattern="*",
            events=["deleted"],
            deliver_uri="entity://peer/callback",
            deliver_operation="notify",
            subscriber_identity=HASH_IDENTITY,
            deliver_token=HASH_TOKEN,
            created_at=int(time.time() * 1000),
        )
        sub_entity = Entity(type=SubscriptionEntity.TYPE, data=sub.to_dict())
        uri = emit_pathway.entity_tree.normalize_uri(f"system/subscription/{sub.subscription_id}")
        emit_pathway.emit(uri, sub_entity, EmitContext.protocol(author=keypair.peer_id))

        assert extension.get_subscription("to-delete") is not None

        # Delete subscription
        emit_pathway.delete(uri, EmitContext.protocol(author=keypair.peer_id))

        assert extension.get_subscription("to-delete") is None

    def test_extension_shutdown(self, setup_extension):
        """Extension cleans up on shutdown."""
        extension, emit_pathway, keypair = setup_extension

        # Add a subscription
        sub = SubscriptionEntity(
            subscription_id="shutdown-test",
            pattern="*",
            events=["created"],
            deliver_uri="entity://peer/callback",
            deliver_operation="notify",
            subscriber_identity=HASH_IDENTITY,
            deliver_token=HASH_TOKEN,
            created_at=int(time.time() * 1000),
        )
        sub_entity = Entity(type=SubscriptionEntity.TYPE, data=sub.to_dict())
        uri = emit_pathway.entity_tree.normalize_uri(f"system/subscription/{sub.subscription_id}")
        emit_pathway.emit(uri, sub_entity, EmitContext.protocol(author=keypair.peer_id))

        assert len(extension.list_subscriptions()) == 1

        # Shutdown
        extension.shutdown()

        assert len(extension.list_subscriptions()) == 0


class TestSubscriptionLimitEnforcement:
    """Tests for subscription limit enforcement."""

    @pytest.fixture
    def setup_extension(self) -> tuple[SubscriptionExtension, EmitPathway, Keypair]:
        """Create test extension with emit pathway."""
        keypair = Keypair.generate()
        content_store = ContentStore()
        entity_tree = EntityTree(keypair.peer_id)
        emit_pathway = EmitPathway(content_store, entity_tree)

        extension = SubscriptionExtension()
        ctx = ExtensionContext(
            keypair=keypair,
            emit_pathway=emit_pathway,
        )
        extension.initialize(ctx)

        return extension, emit_pathway, keypair

    def test_subscription_entry_rate_limit(self, setup_extension):
        """Subscription entry tracks rate limiting."""
        from entity_handlers.subscription import _SubscriptionEntry

        sub = SubscriptionEntity(
            subscription_id="rate-limited",
            pattern="*",
            events=["created"],
            deliver_uri="entity://peer/callback",
            deliver_operation="notify",
            subscriber_identity=HASH_IDENTITY,
            deliver_token=HASH_TOKEN,
            created_at=int(time.time() * 1000),
            limits=SubscriptionLimits(rate_limit=2),  # 2 per minute
        )
        entry = _SubscriptionEntry(subscription=sub)

        now = int(time.time() * 1000)

        # First two should be allowed
        assert entry.check_rate_limit(now)
        entry.record_notification(now)
        assert entry.check_rate_limit(now + 100)
        entry.record_notification(now + 100)

        # Third should be rejected
        assert not entry.check_rate_limit(now + 200)

        # After a minute, should be allowed again
        one_minute_later = now + 61000
        assert entry.check_rate_limit(one_minute_later)

    def test_subscription_entry_expiration_by_events(self, setup_extension):
        """Subscription expires after max_events."""
        from entity_handlers.subscription import _SubscriptionEntry

        sub = SubscriptionEntity(
            subscription_id="limited-events",
            pattern="*",
            events=["created"],
            deliver_uri="entity://peer/callback",
            deliver_operation="notify",
            subscriber_identity=HASH_IDENTITY,
            deliver_token=HASH_TOKEN,
            created_at=int(time.time() * 1000),
            limits=SubscriptionLimits(max_events=3),
        )
        entry = _SubscriptionEntry(subscription=sub)

        now = int(time.time() * 1000)

        # Send 3 notifications
        for i in range(3):
            assert not entry.is_expired(now)
            entry.record_notification(now + i * 100)

        # Now should be expired
        assert entry.is_expired(now + 1000)

    def test_subscription_entry_expiration_by_duration(self, setup_extension):
        """Subscription expires after max_duration_ms."""
        from entity_handlers.subscription import _SubscriptionEntry

        now = int(time.time() * 1000)
        sub = SubscriptionEntity(
            subscription_id="time-limited",
            pattern="*",
            events=["created"],
            deliver_uri="entity://peer/callback",
            deliver_operation="notify",
            subscriber_identity=HASH_IDENTITY,
            deliver_token=HASH_TOKEN,
            created_at=now,
            limits=SubscriptionLimits(max_duration_ms=5000),  # 5 seconds
        )
        entry = _SubscriptionEntry(subscription=sub)

        # Not expired initially
        assert not entry.is_expired(now + 1000)

        # Expired after duration
        assert entry.is_expired(now + 6000)


class TestSubscriptionPatternMatching:
    """Tests for subscription pattern matching."""

    @pytest.fixture
    def extension_with_emit(self) -> tuple[SubscriptionExtension, EmitPathway, Keypair]:
        """Create extension for pattern matching tests."""
        keypair = Keypair.generate()
        content_store = ContentStore()
        entity_tree = EntityTree(keypair.peer_id)
        emit_pathway = EmitPathway(content_store, entity_tree)

        extension = SubscriptionExtension()
        ctx = ExtensionContext(
            keypair=keypair,
            emit_pathway=emit_pathway,
        )
        extension.initialize(ctx)

        return extension, emit_pathway, keypair

    def test_pattern_wildcard_matches_all(self, extension_with_emit):
        """Wildcard pattern * matches all URIs."""
        extension, emit_pathway, _ = extension_with_emit

        assert extension._pattern_matches("*", "/peer/data/file.txt")
        assert extension._pattern_matches("*", "/peer/system/status")

    def test_pattern_exact_match(self, extension_with_emit):
        """Exact pattern matches only exact path."""
        extension, emit_pathway, keypair = extension_with_emit

        path = f"/{keypair.peer_id}/data/file.txt"
        assert extension._pattern_matches(path, path)
        assert not extension._pattern_matches(path, f"/{keypair.peer_id}/data/other.txt")

    def test_pattern_glob_matches_subtree(self, extension_with_emit):
        """Glob pattern matches subtree."""
        extension, emit_pathway, keypair = extension_with_emit

        pattern = "data/*"
        assert extension._pattern_matches(pattern, f"/{keypair.peer_id}/data/file.txt")
        assert extension._pattern_matches(pattern, f"/{keypair.peer_id}/data/subdir/file.txt")
        assert not extension._pattern_matches(pattern, f"/{keypair.peer_id}/other/file.txt")


class TestPeerBuilderWithSubscriptions:
    """Tests for PeerBuilder with subscription extension."""

    def test_peer_with_subscription_extension(self):
        """PeerBuilder can register SubscriptionExtension."""
        keypair = Keypair.generate()
        extension = SubscriptionExtension()

        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_default_handlers()
            .with_extension(extension)
            .build()
        )

        assert peer is not None
        # Extension should have been initialized with emit_pathway
        # (We can't easily check this without exposing internals)

    def test_register_standard_handlers_with_subscriptions(self):
        """register_standard_handlers_with_subscriptions includes extension."""
        from entity_handlers import register_standard_handlers_with_subscriptions

        keypair = Keypair.generate()
        builder = PeerBuilder().with_keypair(keypair)
        builder = register_standard_handlers_with_subscriptions(builder)
        peer = builder.build()

        assert peer is not None
        # Should have callback and subscription handlers registered
        assert peer.handlers.find_handler("system/callback/test") is not None
        assert peer.handlers.find_handler("system/subscription") is not None
