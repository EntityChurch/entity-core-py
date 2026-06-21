"""Integration tests for inbox handler (v7.8)."""

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.delivery import InboxDelivery, InboxNotification, DeliverySpec
from entity_core.storage.emit import EmitPathway
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree

from entity_handlers.inbox import inbox_handler, INBOX_HANDLER_PATTERN


class TestInboxHandler:
    """Integration tests for v7.8 inbox handler operations."""

    @pytest.fixture
    def setup_context(self) -> tuple[EmitPathway, HandlerContext]:
        """Create test context with emit pathway."""
        keypair = Keypair.generate()
        content_store = ContentStore()
        entity_tree = EntityTree(keypair.peer_id)
        emit_pathway = EmitPathway(content_store, entity_tree)

        ctx = HandlerContext(
            local_peer_id=keypair.peer_id,
            remote_peer_id="remote-peer-id",
            handler_grant={},
            caller_capability={},
            emit_pathway=emit_pathway,
        )
        return emit_pathway, ctx

    @pytest.mark.asyncio
    async def test_receive_stores_result(self, setup_context):
        """Receive operation stores inbox delivery in tree."""
        emit_pathway, ctx = setup_context

        params = {
            "data": {
                "original_request_id": "req-12345",
                "status": 200,
                "result": {"type": "file", "data": {"name": "test.txt"}},
            }
        }

        response = await inbox_handler(
            "system/inbox/my-request",
            "receive",
            params,
            ctx,
        )

        assert response["status"] == 200
        assert "stored_at" in response["result"]["data"]
        stored_at = response["result"]["data"]["stored_at"]
        assert "my-request" in stored_at
        assert "req-12345" in stored_at

        # Verify it's stored in tree
        full_uri = emit_pathway.entity_tree.normalize_uri(stored_at)
        content_hash = emit_pathway.entity_tree.get(full_uri)
        assert content_hash is not None

        entity = emit_pathway.content_store.get(content_hash)
        assert entity is not None
        assert entity.type == InboxDelivery.TYPE
        assert entity.data["original_request_id"] == "req-12345"
        assert entity.data["status"] == 200

    @pytest.mark.asyncio
    async def test_receive_with_error_result(self, setup_context):
        """Receive operation stores error results."""
        emit_pathway, ctx = setup_context

        params = {
            "data": {
                "original_request_id": "req-error",
                "status": 404,
                "result": {"code": "not_found", "message": "File not found"},
            }
        }

        response = await inbox_handler(
            "system/inbox/errors",
            "receive",
            params,
            ctx,
        )

        assert response["status"] == 200
        stored_at = response["result"]["data"]["stored_at"]

        # Verify error is stored
        full_uri = emit_pathway.entity_tree.normalize_uri(stored_at)
        content_hash = emit_pathway.entity_tree.get(full_uri)
        entity = emit_pathway.content_store.get(content_hash)
        assert entity.data["status"] == 404
        assert entity.data["result"]["code"] == "not_found"

    @pytest.mark.asyncio
    async def test_legacy_deliver_operation(self, setup_context):
        """Legacy deliver operation works as alias for receive."""
        emit_pathway, ctx = setup_context

        params = {
            "data": {
                "original_request_id": "req-legacy",
                "status": 200,
                "result": {"success": True},
            }
        }

        response = await inbox_handler(
            "system/inbox/legacy-test",
            "deliver",  # Legacy operation name
            params,
            ctx,
        )

        assert response["status"] == 200
        assert "stored_at" in response["result"]["data"]

    @pytest.mark.asyncio
    async def test_receive_stores_notification(self, setup_context):
        """Receive operation stores notification in tree with subscription grouping."""
        emit_pathway, ctx = setup_context

        params = {
            "data": {
                "subscription_id": "sub-789",
                "event": "created",
                "uri": "entity://peer/data/new-file.txt",
            }
        }

        response = await inbox_handler(
            "system/inbox/my-subscription",
            "receive",
            params,
            ctx,
        )

        assert response["status"] == 200
        stored_at = response["result"]["data"]["stored_at"]
        assert "my-subscription" in stored_at

        # Verify notification is stored
        full_uri = emit_pathway.entity_tree.normalize_uri(stored_at)
        content_hash = emit_pathway.entity_tree.get(full_uri)
        entity = emit_pathway.content_store.get(content_hash)
        assert entity.type == InboxNotification.TYPE
        assert entity.data["subscription_id"] == "sub-789"
        assert entity.data["event"] == "created"

    @pytest.mark.asyncio
    async def test_receive_notification_with_hashes(self, setup_context):
        """Receive operation stores notification with hash fields."""
        emit_pathway, ctx = setup_context
        from entity_core.utils.ecf import ALG_ECFV1_SHA256

        hash_new = bytes([ALG_ECFV1_SHA256]) + b"newhsh" + b"\x00" * 26
        hash_old = bytes([ALG_ECFV1_SHA256]) + b"oldhsh" + b"\x00" * 26

        params = {
            "data": {
                "subscription_id": "sub-update",
                "event": "updated",
                "uri": "entity://peer/data/updated-file.txt",
                "hash": hash_new,
                "previous_hash": hash_old,
            }
        }

        response = await inbox_handler(
            "system/inbox/updates",
            "receive",
            params,
            ctx,
        )

        assert response["status"] == 200
        stored_at = response["result"]["data"]["stored_at"]

        full_uri = emit_pathway.entity_tree.normalize_uri(stored_at)
        content_hash = emit_pathway.entity_tree.get(full_uri)
        entity = emit_pathway.content_store.get(content_hash)
        assert entity.data["event"] == "updated"
        assert entity.data["hash"] == hash_new
        assert entity.data["previous_hash"] == hash_old

    @pytest.mark.asyncio
    async def test_receive_accepts_any_params(self, setup_context):
        """Receive operation accepts any entity as params per INBOX §3.1."""
        peer, ctx = setup_context

        # Per INBOX §3.1: receive accepts ANY entity as params (the message to store)
        # Even incomplete delivery-like params should be accepted
        params = {"data": {"status": 200, "message": "hello"}}

        response = await inbox_handler(
            "system/inbox/test",
            "receive",
            params,
            ctx,
        )

        # Should succeed - any entity is valid
        assert response["status"] == 200
        result = response["result"]
        assert result["type"] == "system/inbox/receive-result"
        assert "stored_at" in result["data"]

    @pytest.mark.asyncio
    async def test_receive_handles_notification_params(self, setup_context):
        """Receive operation correctly handles notification params (subscription_id).

        This is the key fix for notification_delivered validator test:
        When subscription extension delivers notifications via 'receive' operation,
        the inbox handler should recognize the subscription_id field and store
        at the notification path: {inbox_path}/{subscription_id}/{timestamp}.
        """
        emit_pathway, ctx = setup_context

        # Subscription extension sends notification via 'receive' operation
        # when subscriber requests deliver_operation="receive"
        params = {
            "data": {
                "subscription_id": "sub-validator-test",
                "event": "created",
                "uri": "entity://peer/system/validate/sub-test/entity-1",
            }
        }

        response = await inbox_handler(
            "system/inbox/validate-sub-test",
            "receive",  # Not "notify" - subscription uses deliver_operation from subscribe request
            params,
            ctx,
        )

        assert response["status"] == 200
        stored_at = response["result"]["data"]["stored_at"]

        # Key assertion: notification stored at flat path under inbox
        # Path: system/inbox/{inbox_path}/{generated_id}
        assert "validate-sub-test" in stored_at

        # Verify notification entity is stored correctly
        full_uri = emit_pathway.entity_tree.normalize_uri(stored_at)
        content_hash = emit_pathway.entity_tree.get(full_uri)
        assert content_hash is not None

        entity = emit_pathway.content_store.get(content_hash)
        assert entity is not None
        assert entity.type == InboxNotification.TYPE
        assert entity.data["subscription_id"] == "sub-validator-test"
        assert entity.data["event"] == "created"

        # Verify listing at the inbox prefix returns the notification
        # This is what the Go validator polls for
        listing_prefix = emit_pathway.entity_tree.normalize_uri(
            "system/inbox/validate-sub-test/"
        )
        listing = list(emit_pathway.entity_tree.list_prefix(listing_prefix))
        assert len(listing) == 1

    @pytest.mark.asyncio
    async def test_invalid_notification_params(self, setup_context):
        """Receive rejects invalid notification params (missing required fields)."""
        _, ctx = setup_context

        # Has subscription_id (triggers notification path) but missing required 'uri' field
        params = {"data": {"subscription_id": "sub-invalid", "event": "created"}}

        response = await inbox_handler(
            "system/inbox/test",
            "receive",
            params,
            ctx,
        )

        assert response["status"] == 400
        assert "invalid_params" in response["result"]["data"]["code"]

    @pytest.mark.asyncio
    async def test_unsupported_operation(self, setup_context):
        """Handler rejects unsupported operations."""
        _, ctx = setup_context

        response = await inbox_handler(
            "system/inbox/test",
            "unknown",
            {},
            ctx,
        )

        assert response["status"] == 501
        assert "unsupported_operation" in response["result"]["data"]["code"]

    @pytest.mark.asyncio
    async def test_default_inbox_path(self, setup_context):
        """Empty inbox path uses 'default' prefix."""
        emit_pathway, ctx = setup_context

        params = {
            "data": {
                "original_request_id": "req-default",
                "status": 200,
                "result": None,
            }
        }

        response = await inbox_handler(
            "system/inbox/",  # Empty path after prefix
            "receive",
            params,
            ctx,
        )

        assert response["status"] == 200
        stored_at = response["result"]["data"]["stored_at"]
        assert "default" in stored_at


class TestInboxResourceTargetPath:
    """Regression for inbox path-from-resource-target handling.

    V7 §1.4/§5.2: the URI identifies the handler; resource_targets carries
    the authoritative message path. Prior behavior reconstructed the path
    from the URI and silently fell through to mailbox mode when the URI
    was the bare handler URI (``system/inbox``). The Go cross-peer
    remote-execute test surfaced this as a hang.
    """

    @pytest.fixture
    def setup_context_with_dispatcher(self):
        """Context with a recording execute dispatcher."""
        from entity_core.protocol.entity import Entity

        keypair = Keypair.generate()
        content_store = ContentStore()
        entity_tree = EntityTree(keypair.peer_id)
        emit_pathway = EmitPathway(content_store, entity_tree)

        dispatcher_calls: list[dict] = []

        async def recording_dispatcher(
            uri, operation, params, grant, bounds, chain_id, resource_targets,
            **kwargs,
        ):
            dispatcher_calls.append(
                {
                    "uri": uri,
                    "operation": operation,
                    "params": params,
                    "resource_targets": resource_targets,
                }
            )
            from entity_core.handlers.context import ExecuteResult

            return ExecuteResult(status=200, result={}, error=None)

        ctx = HandlerContext(
            local_peer_id=keypair.peer_id,
            remote_peer_id="remote-peer-id",
            handler_grant={},
            caller_capability={},
            emit_pathway=emit_pathway,
            _execute_dispatcher=recording_dispatcher,
        )
        return emit_pathway, ctx, dispatcher_calls, keypair

    @pytest.mark.asyncio
    async def test_continuation_advanced_when_path_comes_from_resource_target(
        self, setup_context_with_dispatcher
    ):
        """Validator's exact scenario: URI=system/inbox,
        resource_targets=[system/inbox/rexec-X], continuation at rexec-X
        must be advanced (not swallowed by mailbox mode)."""
        from entity_core.protocol.entity import Entity

        emit_pathway, ctx, calls, _ = setup_context_with_dispatcher

        continuation_path = "system/inbox/rexec-fetch-rexec-1234"
        continuation = Entity(
            type="system/continuation",
            data={
                "chain_id": "rexec-1234",
                "next_uri": "entity://peer-b/data/target",
                "operation": "get",
                "remaining_executions": 1,
            },
        )
        emit_pathway.emit(continuation_path, continuation)

        ctx.resource_targets = [continuation_path]
        response = await inbox_handler(
            "system/inbox",
            "receive",
            {"data": {"original_request_id": "trig-1", "status": 200, "result": {}}},
            ctx,
        )

        assert response["status"] == 200
        # The handler MUST have dispatched to continuation.advance at the
        # resource-target path — not synthesized "system/inbox/system/inbox".
        assert len(calls) == 1, (
            f"Expected exactly one continuation advance, got {len(calls)}: {calls}"
        )
        assert calls[0]["uri"] == "system/continuation"
        assert calls[0]["operation"] == "advance"
        assert calls[0]["resource_targets"] == [continuation_path]
        # And the response reflects advancement, not mailbox mode.
        assert response["result"]["data"]["continuation_advanced"] is True

    @pytest.mark.asyncio
    async def test_resource_target_takes_precedence_over_uri(
        self, setup_context_with_dispatcher
    ):
        """When both URI and resource_targets carry inbox paths, the
        resource target wins."""
        from entity_core.protocol.entity import Entity

        emit_pathway, ctx, calls, _ = setup_context_with_dispatcher

        # Pre-stash continuation at the resource-target path. Write a
        # decoy at the URI-derived path to catch regressions that
        # silently use the URI instead.
        real_path = "system/inbox/from-resource"
        decoy_path = "system/inbox/from-uri"
        emit_pathway.emit(
            real_path,
            Entity(
                type="system/continuation",
                data={"chain_id": "x", "next_uri": "entity://b/x", "operation": "get"},
            ),
        )
        emit_pathway.emit(
            decoy_path,
            Entity(type="test/decoy", data={"not": "a continuation"}),
        )

        ctx.resource_targets = [real_path]
        await inbox_handler(
            "system/inbox/from-uri",
            "receive",
            {"data": {"original_request_id": "r", "status": 200, "result": {}}},
            ctx,
        )

        assert len(calls) == 1
        assert calls[0]["resource_targets"] == [real_path]

    @pytest.mark.asyncio
    async def test_falls_back_to_uri_when_resource_targets_absent(
        self, setup_context_with_dispatcher
    ):
        """Backward compat: legacy callers that encode the subpath in the
        URI (``entity://peer/system/inbox/{sub}``) still work."""
        emit_pathway, ctx, _, _ = setup_context_with_dispatcher

        ctx.resource_targets = None
        response = await inbox_handler(
            "system/inbox/legacy-sub",
            "receive",
            {"data": {"original_request_id": "r", "status": 200, "result": {}}},
            ctx,
        )
        assert response["status"] == 200
        stored_at = response["result"]["data"]["stored_at"]
        assert "legacy-sub" in stored_at


class TestInboxNotificationAdvancesContinuation:
    """Regression for inbox notification skipping continuation advance.

    EXTENSION-INBOX §3.2 continuation-integration applies to every
    receive invocation, not only structured deliveries. A subscription
    notification that lands on an inbox with a registered continuation
    MUST advance it — this is what drives subscription-fired chains
    (chain_sync, psync, filesync, bisync) on the A-role peer. Prior
    behavior short-circuited to mailbox storage when ``subscription_id``
    appeared in params, and the continuation never ran.
    """

    @pytest.fixture
    def setup_context_with_dispatcher(self):
        from entity_core.handlers.context import ExecuteResult

        keypair = Keypair.generate()
        content_store = ContentStore()
        entity_tree = EntityTree(keypair.peer_id)
        emit_pathway = EmitPathway(content_store, entity_tree)

        dispatcher_calls: list[dict] = []

        async def recording_dispatcher(
            uri, operation, params, grant, bounds, chain_id, resource_targets,
            **kwargs,
        ):
            dispatcher_calls.append(
                {
                    "uri": uri,
                    "operation": operation,
                    "params": params,
                    "resource_targets": resource_targets,
                }
            )
            return ExecuteResult(status=200, result={}, error=None)

        ctx = HandlerContext(
            local_peer_id=keypair.peer_id,
            remote_peer_id="remote-peer-id",
            handler_grant={},
            caller_capability={},
            emit_pathway=emit_pathway,
            _execute_dispatcher=recording_dispatcher,
        )
        return emit_pathway, ctx, dispatcher_calls

    @pytest.mark.asyncio
    async def test_notification_on_inbox_with_continuation_advances_it(
        self, setup_context_with_dispatcher
    ):
        from entity_core.protocol.entity import Entity

        emit_pathway, ctx, calls = setup_context_with_dispatcher

        continuation_path = "system/inbox/chain-sync-sub-1"
        continuation = Entity(
            type="system/continuation",
            data={
                "chain_id": "chain-sync-1",
                "target": "entity://peer-b/data/target",
                "operation": "get",
                "remaining_executions": 1,
            },
        )
        emit_pathway.emit(continuation_path, continuation)

        # Subscription notification (has subscription_id -> used to hit
        # the notification branch and dead-end in mailbox storage).
        notification_params = {
            "subscription_id": "sub-1",
            "event": "created",
            "uri": "/peer-b/data/source",
            "hash": bytes([0x00]) + b"\xaa" * 32,
        }
        ctx.resource_targets = [continuation_path]

        response = await inbox_handler(
            "system/inbox",
            "receive",
            {"data": notification_params},
            ctx,
        )

        assert response["status"] == 200
        assert response["result"]["data"]["continuation_advanced"] is True
        # Exactly one advance dispatched, at the correct continuation path.
        assert len(calls) == 1
        assert calls[0]["uri"] == "system/continuation"
        assert calls[0]["operation"] == "advance"
        assert calls[0]["resource_targets"] == [continuation_path]
        # The notification itself flows to the continuation as its result.
        advance_params = calls[0]["params"]
        assert advance_params["status"] == 200
        assert advance_params["result"]["subscription_id"] == "sub-1"

    @pytest.mark.asyncio
    async def test_notification_without_continuation_still_stored(
        self, setup_context_with_dispatcher
    ):
        """Without a registered continuation, notifications must still
        be stored in the mailbox (existing behavior unchanged)."""
        _, ctx, calls = setup_context_with_dispatcher

        response = await inbox_handler(
            "system/inbox/bare-sub",
            "receive",
            {
                "data": {
                    "subscription_id": "sub-2",
                    "event": "updated",
                    "uri": "/peer/x",
                }
            },
            ctx,
        )

        assert response["status"] == 200
        assert "stored_at" in response["result"]["data"]
        # No continuation existed — nothing dispatched.
        assert calls == []
        assert "continuation_advanced" not in response["result"]["data"]


class TestInboxHandlerPattern:
    """Tests for inbox handler pattern."""

    def test_handler_pattern(self):
        """Inbox handler pattern is correct."""
        assert INBOX_HANDLER_PATTERN == "system/inbox"


class TestDeliverySpec:
    """Tests for DeliverySpec (v7.8)."""

    def test_default_operation(self):
        """DeliverySpec defaults to receive operation."""
        spec = DeliverySpec(uri="entity://peer/system/inbox/test")
        assert spec.operation == "receive"

    def test_roundtrip(self):
        """DeliverySpec survives roundtrip."""
        spec = DeliverySpec(uri="entity://peer/system/inbox/test", operation="notify")
        data = spec.to_dict()
        restored = DeliverySpec.from_dict(data)
        assert restored.uri == spec.uri
        assert restored.operation == spec.operation
