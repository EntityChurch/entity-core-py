"""Integration tests for continuation handler (v7.8)."""

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext, ExecuteResult
from entity_core.protocol.entity import Entity
from entity_core.utils.path import is_safe_path_segment
from entity_core.storage.emit import EmitPathway, EmitContext
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree

from entity_handlers.continuation import (
    continuation_handler,
    CONTINUATION_HANDLER_PATTERN,
    CONTINUATION_TYPE,
    CONTINUATION_JOIN_TYPE,
    CONTINUATION_SUSPENDED_TYPE,
    _synthesized_step_key,
)


class TestContinuationHandler:
    """Integration tests for continuation handler operations."""

    @pytest.fixture
    def setup_context(self) -> tuple[EmitPathway, HandlerContext, Keypair]:
        """Create test context with emit pathway and mock execute."""
        keypair = Keypair.generate()
        content_store = ContentStore()
        entity_tree = EntityTree(keypair.peer_id)
        emit_pathway = EmitPathway(content_store, entity_tree)

        # Track dispatched calls
        dispatched_calls = []

        async def mock_execute(
            uri: str,
            operation: str,
            params,
            capability,
            bounds,
            chain_id,
            resource_targets=None,
            **_kwargs,
        ) -> ExecuteResult:
            """Mock execute dispatcher.

            Accepts **_kwargs to swallow propagated_caller_capability +
            propagated_author_* added by Phase C V7 §6.8 propagation.
            """
            dispatched_calls.append({
                "uri": uri,
                "operation": operation,
                "params": params,
                "resource_targets": resource_targets,
            })
            return ExecuteResult(status=200, result={"dispatched": True})

        # Create a full-access dispatch capability for test continuations (W9)
        dispatch_cap = Entity(
            type="system/capability/token",
            data={
                "grants": [{"handlers": {"include": ["*"]},
                            "resources": {"include": ["*"]},
                            "operations": {"include": ["*"]}}],
            },
        )
        dispatch_cap_hash = content_store.put(dispatch_cap)

        ctx = HandlerContext(
            local_peer_id=keypair.peer_id,
            remote_peer_id="remote-peer-id",
            handler_grant={},
            caller_capability={},
            emit_pathway=emit_pathway,
            _execute_dispatcher=mock_execute,
        )
        ctx._dispatched_calls = dispatched_calls  # For test verification
        ctx._dispatch_cap_hash = dispatch_cap_hash  # For building continuations
        return emit_pathway, ctx, keypair

    @pytest.mark.asyncio
    async def test_advance_no_continuation(self, setup_context):
        """Advance returns no-op when no continuation exists."""
        emit_pathway, ctx, _ = setup_context

        params = {
            "continuation_path": "system/inbox/test",
            "result": {"value": 42},
        }

        response = await continuation_handler(
            "system/continuation",
            "advance",
            {"data": params},
            ctx,
        )

        assert response["status"] == 200
        assert response["result"]["data"]["advanced"] is False
        assert response["result"]["data"]["reason"] == "no_continuation"

    @pytest.mark.asyncio
    async def test_advance_forward_continuation(self, setup_context):
        """Advance dispatches forward continuation to target."""
        emit_pathway, ctx, keypair = setup_context

        # Create a forward continuation
        continuation = Entity(
            type=CONTINUATION_TYPE,
            data={
                "target": "system/tree",
                "operation": "put",
                "params": {"tree_id": "default"},
                "result_field": "entity",
                "dispatch_capability": ctx._dispatch_cap_hash,
            },
        )

        # Store continuation at inbox path
        cont_path = "system/inbox/my-cont"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        emit_pathway.emit(full_uri, continuation, emit_ctx)

        # Advance with a result
        params = {
            "continuation_path": cont_path,
            "result": {"type": "file", "data": {"name": "test.txt"}},
        }

        response = await continuation_handler(
            "system/continuation",
            "advance",
            {"data": params},
            ctx,
        )

        assert response["status"] == 200
        assert response["result"]["data"]["advanced"] is True
        assert response["result"]["data"]["target"] == "system/tree"
        assert response["result"]["data"]["operation"] == "put"

        # Verify dispatch was called
        assert len(ctx._dispatched_calls) == 1
        call = ctx._dispatched_calls[0]
        assert call["uri"] == "system/tree"
        assert call["operation"] == "put"
        assert "entity" in call["params"]

    @pytest.mark.asyncio
    async def test_v110_delivered_non2xx_is_completed_forward_dispatch(
        self, setup_context,
    ):
        """§3.4 forward-dispatch outcome classification (v1.10, normative).

        A *delivered* dispatch whose downstream handler returns a non-2xx
        (here 403) is a COMPLETED forward dispatch — fire-and-forget
        closure invocation, the response is NOT threaded back. It MUST:
          - return {status: 200, result.data.advanced: true}
          - decrement remaining_executions (counts completed attempts)
          - NOT be promoted to transient/permanent, retried, or suspended
          - NOT be routed to on_error on the basis of the downstream status
        The downstream status is surfaced only as observational
        `dispatch_status`.
        """
        emit_pathway, ctx, keypair = setup_context

        # Dispatcher DELIVERS (returns, does not raise) but the downstream
        # handler verdict is 403.
        async def deliver_then_403(*_a, **_k) -> ExecuteResult:
            return ExecuteResult(status=403, result={"code": "denied"})

        ctx._execute_dispatcher = deliver_then_403

        # on_error is configured — it MUST NOT fire for a delivered
        # downstream non-2xx (only for an inbound error or a dispatch
        # delivery failure).
        on_error_calls: list = []

        async def _record_deliver(*a, **k):
            on_error_calls.append((a, k))
            return ExecuteResult(status=200, result={})

        ctx.deliver_async = _record_deliver

        continuation = Entity(
            type=CONTINUATION_TYPE,
            data={
                "target": "system/tree",
                "operation": "put",
                "params": {"tree_id": "default"},
                "result_field": "entity",
                "remaining_executions": 2,
                "on_error": {"uri": "system/inbox/errs", "operation": "receive"},
                "dispatch_capability": ctx._dispatch_cap_hash,
            },
        )
        cont_path = "system/inbox/v110-class"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_pathway.emit(
            full_uri, continuation, EmitContext.protocol(author=keypair.peer_id)
        )

        # Inbound status is success (200) — routes to the dispatch path,
        # not the early inbound-error on_error path.
        response = await continuation_handler(
            "system/continuation",
            "advance",
            {"data": {"continuation_path": cont_path,
                      "result": {"type": "file", "data": {}}}},
            ctx,
        )

        # Completed forward dispatch: advance succeeded, status 200.
        assert response["status"] == 200, response
        assert response["result"]["data"]["advanced"] is True
        # Downstream verdict is observational only — NOT the advance status.
        assert response["result"]["data"]["dispatch_status"] == 403

        # remaining_executions decremented (2 -> 1); entity not exhausted.
        stored_hash = emit_pathway.entity_tree.get(full_uri)
        assert stored_hash is not None, "continuation must not be deleted"
        stored = emit_pathway.content_store.get(stored_hash)
        assert stored.data["remaining_executions"] == 1

        # NOT routed to on_error, NOT suspended, NOT marked.
        # v1.20 §3.10.2: when on_error IS configured, the lost marker is
        # NOT bound for delivered non-2xx (the on_error path is the
        # observability surface); the v1.13 §3.4 I-8 lost-marker bind fires
        # only when on_error is absent. Here on_error is wired, so no marker.
        # Scan the full lost subtree (v1.20 paths terminate at /{marker_hash}
        # — listing the prefix tells us whether ANY marker bound).
        assert on_error_calls == [], "downstream non-2xx must not hit on_error"
        suspended = emit_pathway.entity_tree.get(
            emit_pathway.entity_tree.normalize_uri(
                "system/continuation/suspended"
            )
        )
        assert suspended is None
        lost_prefix = emit_pathway.entity_tree.normalize_uri(
            "system/runtime/chain-errors/lost/"
        )
        lost_matches = emit_pathway.entity_tree.list_prefix(lost_prefix)
        assert lost_matches == [], (
            "no lost marker bound for delivered non-2xx when on_error is "
            "configured (v1.20 §3.10.2)"
        )

    @pytest.mark.asyncio
    async def test_advance_with_result_transform(self, setup_context):
        """Advance applies result_transform before dispatch."""
        emit_pathway, ctx, keypair = setup_context

        # Create continuation with transform (inject mode: params + result_field)
        # Per EXTENSION-CONTINUATION §3.3: result_field requires params to be set
        continuation = Entity(
            type=CONTINUATION_TYPE,
            data={
                "target": "system/tree",
                "operation": "put",
                "result_transform": "data.value",
                "result_field": "extracted",
                "params": {"entity_type": "test"},  # Base params for inject mode
                "dispatch_capability": ctx._dispatch_cap_hash,
            },
        )

        cont_path = "system/inbox/transform-test"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        emit_pathway.emit(full_uri, continuation, emit_ctx)

        # Advance with nested result
        params = {
            "continuation_path": cont_path,
            "result": {"data": {"value": {"nested": "content"}}},
        }

        response = await continuation_handler(
            "system/continuation",
            "advance",
            {"data": params},
            ctx,
        )

        assert response["status"] == 200
        assert response["result"]["data"]["advanced"] is True

        # Verify transform was applied and injected into base params
        call = ctx._dispatched_calls[0]
        assert call["params"]["extracted"] == {"nested": "content"}
        assert call["params"]["entity_type"] == "test"

    @pytest.mark.asyncio
    async def test_advance_rejects_result_field_without_params(self, setup_context):
        """Advance rejects result_field without params (invalid dispatch mode)."""
        emit_pathway, ctx, keypair = setup_context

        # Per EXTENSION-CONTINUATION §3.3: result_field without params is invalid
        continuation = Entity(
            type=CONTINUATION_TYPE,
            data={
                "target": "system/tree",
                "operation": "put",
                "result_field": "data",
                "dispatch_capability": ctx._dispatch_cap_hash,
                # No params - invalid
            },
        )

        cont_path = "system/inbox/invalid-mode-test"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        emit_pathway.emit(full_uri, continuation, emit_ctx)

        params = {
            "continuation_path": cont_path,
            "result": {"value": 42},
        }

        response = await continuation_handler(
            "system/continuation",
            "advance",
            {"data": params},
            ctx,
        )

        assert response["status"] == 400
        assert "invalid_dispatch_mode" in response["result"]["data"]["code"]

    @pytest.mark.asyncio
    async def test_advance_decrements_remaining_executions(self, setup_context):
        """Advance decrements remaining_executions counter."""
        emit_pathway, ctx, keypair = setup_context

        # Create continuation with limited executions
        continuation = Entity(
            type=CONTINUATION_TYPE,
            data={
                "target": "system/tree",
                "operation": "get",
                "remaining_executions": 3,
                "dispatch_capability": ctx._dispatch_cap_hash,
            },
        )

        cont_path = "system/inbox/limited-cont"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        emit_pathway.emit(full_uri, continuation, emit_ctx)

        # Advance
        params = {
            "continuation_path": cont_path,
            "result": {"test": True},
        }

        response = await continuation_handler(
            "system/continuation",
            "advance",
            {"data": params},
            ctx,
        )

        assert response["status"] == 200
        assert response["result"]["data"]["advanced"] is True

        # Verify counter was decremented
        updated_hash = emit_pathway.entity_tree.get(full_uri)
        updated_entity = emit_pathway.content_store.get(updated_hash)
        assert updated_entity.data["remaining_executions"] == 2

    @pytest.mark.asyncio
    async def test_advance_exhausted_continuation(self, setup_context):
        """Advance rejects exhausted continuation."""
        emit_pathway, ctx, keypair = setup_context

        # Create exhausted continuation
        continuation = Entity(
            type=CONTINUATION_TYPE,
            data={
                "target": "system/tree",
                "operation": "get",
                "remaining_executions": 0,
                "dispatch_capability": ctx._dispatch_cap_hash,
            },
        )

        cont_path = "system/inbox/exhausted"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        emit_pathway.emit(full_uri, continuation, emit_ctx)

        params = {
            "continuation_path": cont_path,
            "result": {},
        }

        response = await continuation_handler(
            "system/continuation",
            "advance",
            {"data": params},
            ctx,
        )

        assert response["status"] == 410
        assert "exhausted" in response["result"]["data"]["code"]

    @pytest.mark.asyncio
    async def test_join_accumulates_slots(self, setup_context):
        """Join continuation accumulates results in slots."""
        emit_pathway, ctx, keypair = setup_context

        # Create join continuation
        continuation = Entity(
            type=CONTINUATION_JOIN_TYPE,
            data={
                "expected": ["slot-a", "slot-b"],
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": ctx._dispatch_cap_hash,
            },
        )

        cont_path = "system/inbox/join-test"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        emit_pathway.emit(full_uri, continuation, emit_ctx)

        # Advance with first slot
        params = {
            "continuation_path": cont_path,
            "slot": "slot-a",
            "result": {"value": "a"},
        }

        response = await continuation_handler(
            "system/continuation",
            "advance",
            {"data": params},
            ctx,
        )

        assert response["status"] == 200
        assert response["result"]["data"]["advanced"] is False
        assert response["result"]["data"]["accumulated"] is True
        assert "slot-a" in response["result"]["data"]["received_slots"]

        # Verify no dispatch yet
        assert len(ctx._dispatched_calls) == 0

    @pytest.mark.asyncio
    async def test_join_dispatches_when_complete(self, setup_context):
        """Join continuation dispatches when all slots filled."""
        emit_pathway, ctx, keypair = setup_context

        # Create join continuation with one slot already filled
        continuation = Entity(
            type=CONTINUATION_JOIN_TYPE,
            data={
                "expected": ["slot-a", "slot-b"],
                "received": {"slot-a": {"value": "a"}},
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": ctx._dispatch_cap_hash,
            },
        )

        cont_path = "system/inbox/join-complete"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        emit_pathway.emit(full_uri, continuation, emit_ctx)

        # Advance with second slot
        params = {
            "continuation_path": cont_path,
            "slot": "slot-b",
            "result": {"value": "b"},
        }

        response = await continuation_handler(
            "system/continuation",
            "advance",
            {"data": params},
            ctx,
        )

        assert response["status"] == 200
        assert response["result"]["data"]["advanced"] is True
        assert response["result"]["data"]["join_complete"] is True

        # Verify dispatch was called with both slot values
        assert len(ctx._dispatched_calls) == 1
        call = ctx._dispatched_calls[0]
        assert call["params"]["slot-a"] == {"value": "a"}
        assert call["params"]["slot-b"] == {"value": "b"}

    @pytest.mark.asyncio
    async def test_join_rejects_duplicate_slot(self, setup_context):
        """Join continuation rejects duplicate slot submissions."""
        emit_pathway, ctx, keypair = setup_context

        # Create join with one slot already filled
        continuation = Entity(
            type=CONTINUATION_JOIN_TYPE,
            data={
                "expected": ["slot-a", "slot-b"],
                "received": {"slot-a": {"value": "original"}},
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": ctx._dispatch_cap_hash,
            },
        )

        cont_path = "system/inbox/join-dup"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        emit_pathway.emit(full_uri, continuation, emit_ctx)

        # Try to fill slot-a again
        params = {
            "continuation_path": cont_path,
            "slot": "slot-a",
            "result": {"value": "duplicate"},
        }

        response = await continuation_handler(
            "system/continuation",
            "advance",
            {"data": params},
            ctx,
        )

        assert response["status"] == 409
        assert "slot_already_filled" in response["result"]["data"]["code"]

    @pytest.mark.asyncio
    async def test_abandon_deletes_suspended(self, setup_context):
        """Abandon operation deletes suspended continuation."""
        emit_pathway, ctx, keypair = setup_context

        # Create suspended state
        suspended = Entity(
            type=CONTINUATION_SUSPENDED_TYPE,
            data={
                "continuation_path": "system/inbox/my-cont",
                "suspended_at": 1234567890,
            },
        )

        suspended_path = "system/continuation/suspended/test-suspend"
        full_uri = emit_pathway.entity_tree.normalize_uri(suspended_path)
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        emit_pathway.emit(full_uri, suspended, emit_ctx)

        # Verify it exists
        assert emit_pathway.entity_tree.get(full_uri) is not None

        # Abandon
        params = {"suspension_id": "test-suspend"}

        response = await continuation_handler(
            "system/continuation",
            "abandon",
            {"data": params},
            ctx,
        )

        assert response["status"] == 200
        assert response["result"]["data"]["abandoned"] is True

        # Verify it's deleted
        assert emit_pathway.entity_tree.get(full_uri) is None

    @pytest.mark.asyncio
    async def test_abandon_not_found(self, setup_context):
        """Abandon returns 404 for non-existent suspension."""
        _, ctx, _ = setup_context

        params = {"suspension_id": "nonexistent"}

        response = await continuation_handler(
            "system/continuation",
            "abandon",
            {"data": params},
            ctx,
        )

        assert response["status"] == 404
        assert "not_found" in response["result"]["data"]["code"]

    @pytest.mark.asyncio
    async def test_unsupported_operation(self, setup_context):
        """Handler rejects unsupported operations."""
        _, ctx, _ = setup_context

        response = await continuation_handler(
            "system/continuation",
            "unknown",
            {},
            ctx,
        )

        assert response["status"] == 501
        assert "unsupported_operation" in response["result"]["data"]["code"]


class TestContinuationResourceTargets:
    """Regression for the continuation resource-targets handling.

    Per EXTENSION-CONTINUATION v1.2 §3: the continuation's `target` field
    is the handler URI; `resource.targets` carries the resource path.
    Prior Python behavior passed `target` as `resource_targets` when
    dispatching, which caused receiving peers to reject the EXECUTE with
    400 invalid_params.
    """

    @pytest.fixture
    def setup_context(self):
        """Reuse the fixture from TestContinuationHandler."""
        return TestContinuationHandler.setup_context.__wrapped__(self)

    @pytest.mark.asyncio
    async def test_forward_uses_resource_targets_from_resource_field(
        self, setup_context
    ):
        emit_pathway, ctx, keypair = setup_context

        continuation = Entity(
            type=CONTINUATION_TYPE,
            data={
                "target": "entity://peer-b/system/tree",
                "operation": "get",
                "resource": {"targets": ["system/validate/rexec-src/item"]},
                "dispatch_capability": ctx._dispatch_cap_hash,
            },
        )

        cont_path = "system/inbox/rexec-fetch"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_pathway.emit(
            full_uri, continuation, EmitContext.protocol(author=keypair.peer_id)
        )

        await continuation_handler(
            "system/continuation",
            "advance",
            {
                "data": {
                    "continuation_path": cont_path,
                    "result": {"trigger": "go"},
                }
            },
            ctx,
        )

        assert len(ctx._dispatched_calls) == 1
        call = ctx._dispatched_calls[0]
        # The dispatch URI is the handler identifier.
        assert call["uri"] == "entity://peer-b/system/tree"
        # Resource targets come from continuation.resource.targets — NOT
        # from `target`. Prior bug set this to [target].
        assert call["resource_targets"] == ["system/validate/rexec-src/item"]

    @pytest.mark.asyncio
    async def test_forward_omits_resource_targets_when_no_resource_field(
        self, setup_context
    ):
        """Continuations without a `resource` field dispatch with
        resource_targets=None, matching Go's WithResource(nil) path."""
        emit_pathway, ctx, keypair = setup_context

        continuation = Entity(
            type=CONTINUATION_TYPE,
            data={
                "target": "system/tree",
                "operation": "put",
                "params": {"entity_type": "test"},
                "dispatch_capability": ctx._dispatch_cap_hash,
            },
        )

        cont_path = "system/inbox/no-resource"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_pathway.emit(
            full_uri, continuation, EmitContext.protocol(author=keypair.peer_id)
        )

        await continuation_handler(
            "system/continuation",
            "advance",
            {"data": {"continuation_path": cont_path, "result": {"v": 1}}},
            ctx,
        )

        assert len(ctx._dispatched_calls) == 1
        assert ctx._dispatched_calls[0]["resource_targets"] is None

    @pytest.mark.asyncio
    async def test_join_uses_resource_targets_from_resource_field(
        self, setup_context
    ):
        emit_pathway, ctx, keypair = setup_context

        continuation = Entity(
            type=CONTINUATION_JOIN_TYPE,
            data={
                "expected": ["slot-a", "slot-b"],
                "received": {"slot-a": {"value": "a"}},
                "target": "system/tree",
                "operation": "put",
                "resource": {"targets": ["system/validate/join-dest"]},
                "dispatch_capability": ctx._dispatch_cap_hash,
            },
        )

        cont_path = "system/inbox/join-cont"
        full_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_pathway.emit(
            full_uri, continuation, EmitContext.protocol(author=keypair.peer_id)
        )

        # Fill the last slot; join dispatches on completion.
        await continuation_handler(
            "system/continuation",
            "advance",
            {
                "data": {
                    "continuation_path": cont_path,
                    "slot": "slot-b",
                    "result": {"value": "b"},
                }
            },
            ctx,
        )

        assert len(ctx._dispatched_calls) == 1
        call = ctx._dispatched_calls[0]
        assert call["resource_targets"] == ["system/validate/join-dest"]


class TestContinuationHandlerPattern:
    """Tests for continuation handler pattern."""

    def test_handler_pattern(self):
        """Continuation handler pattern is correct."""
        assert CONTINUATION_HANDLER_PATTERN == "system/continuation"


class TestContinuationTypes:
    """Tests for continuation type constants."""

    def test_type_constants(self):
        """Continuation type constants are correct."""
        assert CONTINUATION_TYPE == "system/continuation"
        assert CONTINUATION_JOIN_TYPE == "system/continuation/join"
        assert CONTINUATION_SUSPENDED_TYPE == "system/continuation/suspended"


class TestContinuationInstall:
    """CT1 + CT2: install operation with R1 chain-root check.

    PROPOSAL-COHERENT-CAPABILITY-AUTHORITY (EXTENSION-CONTINUATION v1.6).
    """

    @pytest.fixture
    def setup_context(self) -> tuple[EmitPathway, HandlerContext, Keypair]:
        from entity_core.utils.ecf import ALG_ECFV1_SHA256

        keypair = Keypair.generate()
        content_store = ContentStore()
        entity_tree = EntityTree(keypair.peer_id)
        emit_pathway = EmitPathway(content_store, entity_tree)

        async def mock_execute(*_args, **_kwargs) -> ExecuteResult:
            return ExecuteResult(status=200, result={})

        ctx = HandlerContext(
            local_peer_id=keypair.peer_id,
            remote_peer_id="remote-peer-id",
            handler_grant={},
            caller_capability={},
            emit_pathway=emit_pathway,
            _execute_dispatcher=mock_execute,
        )
        return emit_pathway, ctx, keypair

    @staticmethod
    def _put_cap(content_store, *, granter: bytes, parent: bytes | None = None) -> bytes:
        data = {"granter": granter, "grantee": granter, "grants": []}
        if parent is not None:
            data["parent"] = parent
        return content_store.put(Entity(type="system/capability/token", data=data))

    @pytest.mark.asyncio
    async def test_install_self_rooted_capability_succeeds(self, setup_context):
        """Author-rooted dispatch_capability: 200 + continuation persisted."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, _ = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = self._put_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/install-test"]

        # Per P-CONTINUATION-1: caller passes a system/continuation entity
        # directly as params; install path comes from resource.
        params = {
            "type": "system/continuation",
            "data": {
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": cap_hash,
                "params": {"entity_type": "test"},
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 200, response
        assert response["result"]["data"]["path"] == "system/continuation/suspended/install-test"

        # Continuation entity is now persisted at the path.
        full_uri = emit_pathway.entity_tree.normalize_uri(
            "system/continuation/suspended/install-test"
        )
        stored_hash = emit_pathway.entity_tree.get(full_uri)
        assert stored_hash is not None
        stored = emit_pathway.content_store.get(stored_hash)
        assert stored is not None
        assert stored.type == CONTINUATION_TYPE
        assert stored.data["dispatch_capability"] == cap_hash

    @pytest.mark.asyncio
    async def test_install_foreign_rooted_capability_rejected(self, setup_context):
        """Cap rooted at someone else: 403 embedded_cap_unauthorized."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, _ = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        adversary = bytes([ALG_ECFV1_SHA256]) + b"advrsy" + b"\x00" * 26
        cap_hash = self._put_cap(emit_pathway.content_store, granter=adversary)
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/foreign"]

        params = {
            "type": "system/continuation",
            "data": {
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": cap_hash,
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 403
        assert response["result"]["data"]["code"] == "embedded_cap_unauthorized"

    @pytest.mark.asyncio
    async def test_install_chain_unreachable_returns_404(self, setup_context):
        """Cap with parent missing from content store: 404 chain_unreachable."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, _ = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        adversary = bytes([ALG_ECFV1_SHA256]) + b"advrsy" + b"\x00" * 26
        missing = bytes([ALG_ECFV1_SHA256]) + b"missin" + b"\x00" * 26
        cap_hash = self._put_cap(
            emit_pathway.content_store, granter=adversary, parent=missing,
        )
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/broken"]

        params = {
            "type": "system/continuation",
            "data": {
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": cap_hash,
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 404
        assert response["result"]["data"]["code"] == "chain_unreachable"

    @pytest.mark.asyncio
    async def test_install_chain_unreachable_when_leaf_granter_matches_writer(
        self, setup_context,
    ):
        """Vector 4 regression (Go validator §10): the install handler MUST
        surface chain_unreachable when the embedded cap's `parent` is
        absent from envelope/store, even if the leaf's `granter` matches
        the writer. Otherwise a caller could fabricate a leaf claiming
        granter=writer with parent pointing at any hash, and the install
        would accept based on the leaf alone.
        """
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, _ = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        fabricated_parent = bytes([ALG_ECFV1_SHA256]) + b"fabric" + b"\x00" * 26
        # Leaf: granter is the WRITER (would match R1) but parent is missing.
        leaf_hash = self._put_cap(
            emit_pathway.content_store,
            granter=author,
            parent=fabricated_parent,
        )
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/validate-r1-unreach"]

        params = {
            "type": "system/continuation",
            "data": {
                "target": "system/inbox",
                "operation": "receive",
                "dispatch_capability": leaf_hash,
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 404, response
        assert response["result"]["data"]["code"] == "chain_unreachable"

    @pytest.mark.asyncio
    async def test_install_missing_required_fields(self, setup_context):
        """Missing target/operation on the continuation entity: 400 invalid_params."""
        emit_pathway, ctx, _ = setup_context
        ctx.remote_identity_hash = b"\x00" * 33
        ctx.resource_targets = ["system/continuation/suspended/x"]
        response = await continuation_handler(
            "system/continuation",
            "install",
            {"type": "system/continuation", "data": {}},
            ctx,
        )
        assert response["status"] == 400
        assert response["result"]["data"]["code"] == "invalid_params"

    @pytest.mark.asyncio
    async def test_install_missing_resource(self, setup_context):
        """Missing resource: 400 ambiguous_resource (P-CONTINUATION-1)."""
        emit_pathway, ctx, _ = setup_context
        ctx.remote_identity_hash = b"\x00" * 33
        ctx.resource_targets = None
        response = await continuation_handler(
            "system/continuation",
            "install",
            {"type": "system/continuation", "data": {
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": b"\x00" * 33,
            }},
            ctx,
        )
        assert response["status"] == 400
        # 0.8.2.18, §3.3's 400 row: this row asserted `ambiguous_resource`
        # until the two inputs were split. ABSENT is `path_required` — *supply
        # a resource* is a different instruction from *name only one*, and the
        # code is what selects the remedy. This test's own name says `missing`
        # and it was pinning the code for the other input.
        assert response["result"]["data"]["code"] == "path_required"

    @pytest.mark.asyncio
    async def test_install_with_two_resource_targets_is_ambiguous_not_missing(
        self, setup_context,
    ):
        """The other half of the pair, which nothing drove — so the collapse
        was invisible from this file: one row, one code, and the row that
        existed was on the arm the spec moved.
        """
        emit_pathway, ctx, _ = setup_context
        ctx.remote_identity_hash = b"\x00" * 33
        ctx.resource_targets = ["app/one", "app/two"]
        response = await continuation_handler(
            "system/continuation",
            "install",
            {"type": "system/continuation", "data": {
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": b"\x00" * 33,
            }},
            ctx,
        )
        assert response["status"] == 400
        assert response["result"]["data"]["code"] == "ambiguous_resource", (
            "both resource inputs now answer the same code — the pair has "
            "re-collapsed and the absent case is non-conformant again"
        )

    @pytest.mark.asyncio
    async def test_install_rejects_non_continuation_params_type(self, setup_context):
        """Per P-CONTINUATION-1: params.type must be system/continuation
        or system/continuation/join. Other types → 400 invalid_params."""
        emit_pathway, ctx, _ = setup_context
        ctx.remote_identity_hash = b"\x00" * 33
        ctx.resource_targets = ["system/continuation/suspended/x"]
        response = await continuation_handler(
            "system/continuation",
            "install",
            {"type": "primitive/any", "data": {
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": b"\x00" * 33,
            }},
            ctx,
        )
        assert response["status"] == 400
        assert response["result"]["data"]["code"] == "invalid_params"

    @pytest.mark.asyncio
    async def test_install_missing_dispatch_capability(self, setup_context):
        """Missing dispatch_capability: 400 missing_dispatch_capability."""
        emit_pathway, ctx, _ = setup_context
        ctx.remote_identity_hash = b"\x00" * 33
        ctx.resource_targets = ["system/continuation/suspended/x"]
        response = await continuation_handler(
            "system/continuation",
            "install",
            {
                "type": "system/continuation",
                "data": {
                    "target": "system/tree",
                    "operation": "put",
                },
            },
            ctx,
        )
        assert response["status"] == 400
        assert response["result"]["data"]["code"] == "missing_dispatch_capability"

    @pytest.mark.asyncio
    async def test_install_join_continuation(self, setup_context):
        """Install with params.type=system/continuation/join produces
        a join entity. Per P-CONTINUATION-1: caller passes the join
        entity directly with `expected` already populated."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, _ = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = self._put_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/join-test"]

        params = {
            "type": "system/continuation/join",
            "data": {
                "expected": ["left", "right"],
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": cap_hash,
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 200, response
        full_uri = emit_pathway.entity_tree.normalize_uri(
            "system/continuation/suspended/join-test"
        )
        stored = emit_pathway.content_store.get(emit_pathway.entity_tree.get(full_uri))
        assert stored.type == CONTINUATION_JOIN_TYPE
        assert sorted(stored.data["expected"]) == ["left", "right"]

    @pytest.mark.asyncio
    async def test_install_delegated_chain_terminating_at_author(self, setup_context):
        """Delegated cap whose root chain terminates at author: 200."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, _ = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        delegate = bytes([ALG_ECFV1_SHA256]) + b"delegt" + b"\x00" * 26

        root_hash = self._put_cap(emit_pathway.content_store, granter=author)
        leaf_hash = self._put_cap(
            emit_pathway.content_store, granter=delegate, parent=root_hash,
        )
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/delegated"]

        params = {
            "type": "system/continuation",
            "data": {
                "target": "system/tree",
                "operation": "put",
                "dispatch_capability": leaf_hash,
            },
        }
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 200, response

    # ---- EXTENSION-CONTINUATION v1.9 ----

    @pytest.mark.asyncio
    async def test_v19_dynamic_execute_field_extraction(self, setup_context):
        """*_extract overrides static target/operation/resource at dispatch;
        falls back to static when the path misses (§2.2 / §3.6)."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, keypair = setup_context
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        cap_hash = self._put_cap(
            emit_pathway.content_store,
            granter=bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26,
        )

        continuation = Entity(type=CONTINUATION_TYPE, data={
            "target": "static/target",
            "operation": "static-op",
            "result_transform": {
                "target_extract": "route.to",
                "operation_extract": "route.op",
                "resource_extract": "route.path",
            },
            "dispatch_capability": cap_hash,
        })
        path = "system/inbox/v19-extract"
        uri = emit_pathway.entity_tree.normalize_uri(path)
        emit_pathway.emit(uri, continuation, emit_ctx)

        calls: list[dict] = []

        async def _rec(u, op, p, cap, bnds, cid, rt=None, **_k):
            calls.append({"uri": u, "operation": op, "params": p,
                          "resource_targets": rt})
            return ExecuteResult(status=200, result={"ok": True})

        ctx._execute_dispatcher = _rec

        await continuation_handler("system/continuation", "advance", {"data": {
            "continuation_path": path,
            "result": {"route": {"to": "system/tree", "op": "put",
                                  "path": "data/x"}},
        }}, ctx)

        call = calls[-1]
        assert call["uri"] == "system/tree"          # target_extract won
        assert call["operation"] == "put"            # operation_extract won
        assert call["resource_targets"] == ["data/x"]  # resource_extract wrapped

        # Path miss -> static fallback.
        calls.clear()
        await continuation_handler("system/continuation", "advance", {"data": {
            "continuation_path": path,
            "result": {"unrelated": True},
        }}, ctx)
        call = calls[-1]
        assert call["uri"] == "static/target"
        assert call["operation"] == "static-op"

    @pytest.mark.asyncio
    async def test_v19_transform_ops_notification_rewrite(self, setup_context):
        """G1: strip_prefix+prepend rewrite a field before dispatch."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, keypair = setup_context
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        cap_hash = self._put_cap(
            emit_pathway.content_store,
            granter=bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26,
        )

        continuation = Entity(type=CONTINUATION_TYPE, data={
            "target": "system/tree",
            "operation": "put",
            "result_transform": {
                "transform_ops": [
                    {"op": "strip_prefix", "field": "path", "prefix": "peer-b/"},
                    {"op": "prepend", "field": "path", "literal": "local/mirror/"},
                ],
            },
            "dispatch_capability": cap_hash,
        })
        path = "system/inbox/v19-ops"
        uri = emit_pathway.entity_tree.normalize_uri(path)
        emit_pathway.emit(uri, continuation, emit_ctx)

        calls: list[dict] = []

        async def _rec(u, op, p, cap, bnds, cid, rt=None, **_k):
            calls.append({"params": p})
            return ExecuteResult(status=200, result={"ok": True})

        ctx._execute_dispatcher = _rec

        await continuation_handler("system/continuation", "advance", {"data": {
            "continuation_path": path,
            "result": {"path": "peer-b/data/shared/doc.txt"},
        }}, ctx)

        assert calls[-1]["params"]["path"] == "local/mirror/data/shared/doc.txt"

    @pytest.mark.asyncio
    async def test_v116_merge_mode_shallow_union(self, setup_context):
        """v1.16 §3.6: Merge mode shallow-unions the transformed map into
        static params; dynamic keys win on collision. This is the
        fetch-diff assembly path: static {prefix} + dynamic {base}."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, keypair = setup_context
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        cap_hash = self._put_cap(
            emit_pathway.content_store,
            granter=bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26,
        )

        continuation = Entity(type=CONTINUATION_TYPE, data={
            "target": "system/revision",
            "operation": "fetch-diff",
            "params": {"prefix": "project/"},
            "result_merge": True,
            # select pulls previous_hash from the notification into `base`.
            "result_transform": {"select": {"base": "data.previous_hash"}},
            "dispatch_capability": cap_hash,
        })
        path = "system/inbox/v116-merge"
        uri = emit_pathway.entity_tree.normalize_uri(path)
        emit_pathway.emit(uri, continuation, emit_ctx)

        calls: list[dict] = []

        async def _rec(u, op, p, cap, bnds, cid, rt=None, **_k):
            calls.append({"params": p})
            return ExecuteResult(status=200, result={"ok": True})

        ctx._execute_dispatcher = _rec

        await continuation_handler("system/continuation", "advance", {"data": {
            "continuation_path": path,
            "result": {"data": {"previous_hash": "v-base-123"}},
        }}, ctx)

        # Static scaffold + dynamic field, flat (not nested under a key).
        assert calls[-1]["params"] == {"prefix": "project/", "base": "v-base-123"}

    @pytest.mark.asyncio
    async def test_v116_merge_mode_non_map_binds_marker(self, setup_context):
        """v1.16 §3.4: a non-map post-transform value under result_merge
        degrades to static-only params and binds a merge_value_not_map
        marker at the per-reason path. Dispatch still proceeds."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, keypair = setup_context
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        cap_hash = self._put_cap(
            emit_pathway.content_store,
            granter=bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26,
        )

        continuation = Entity(type=CONTINUATION_TYPE, data={
            "target": "system/revision",
            "operation": "fetch-diff",
            "params": {"prefix": "project/"},
            "result_merge": True,
            # extract navigates to a scalar — a non-map value reaches assembly.
            "result_transform": {"extract": "data.scalar"},
            "dispatch_capability": cap_hash,
        })
        path = "system/inbox/v116-merge-nonmap"
        uri = emit_pathway.entity_tree.normalize_uri(path)
        emit_pathway.emit(uri, continuation, emit_ctx)

        calls: list[dict] = []

        async def _rec(u, op, p, cap, bnds, cid, rt=None, **_k):
            calls.append({"params": p})
            return ExecuteResult(status=200, result={"ok": True})

        ctx._execute_dispatcher = _rec

        await continuation_handler("system/continuation", "advance", {"data": {
            "continuation_path": path,
            "result": {"data": {"scalar": "not-a-map"}},
        }}, ctx)

        # Degrades to static-only params; dispatch still happens.
        assert calls[-1]["params"] == {"prefix": "project/"}
        # The merge_value_not_map marker is bound at the per-reason subpath.
        # v1.20 §3.10.1: path now terminates at /{marker_hash}, so the
        # /merge_value_not_map/ segment is between {step_index} and the
        # terminal hash rather than at the path tail.
        prefix = emit_pathway.entity_tree.normalize_uri(
            "system/runtime/chain-errors/lost/",
        )
        matches = emit_pathway.entity_tree.list_prefix(prefix)
        marker_paths = [m for m in matches if "/merge_value_not_map/" in m]
        assert marker_paths, "merge_value_not_map marker not bound"
        marker_hash = emit_pathway.entity_tree.get(marker_paths[0])
        marker = emit_pathway.content_store.get(marker_hash)
        assert marker.type == "system/runtime/chain-error-lost"
        assert marker.data["reason"] == "merge_value_not_map"
        # §3.4 capture list: produced value's type + dispatched target URI.
        assert marker.data["value_type"] == "str"
        assert marker.data["target_uri"] == "system/revision"

    @pytest.mark.asyncio
    async def test_v19_install_rejects_unknown_transform_op(self, setup_context):
        """G1 fail-closed (§2.2/§8.1): unknown transform op rejected at
        install with 400 unknown_transform_op — never silently skipped."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, _ = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = self._put_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/badop"]

        params = {"type": "system/continuation", "data": {
            "target": "system/tree",
            "operation": "put",
            "dispatch_capability": cap_hash,
            "result_transform": {
                "transform_ops": [{"op": "rm -rf", "field": "x"}],
            },
        }}
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 400
        assert response["result"]["data"]["code"] == "unknown_transform_op"

    @pytest.mark.asyncio
    async def test_v115_install_rejects_collect_keys_mutex(self, setup_context):
        """v1.15 §2.2: collect_keys MUST NOT carry both `field` and
        `fields`. Reject at install with the pinned cross-impl code
        `400 invalid_transform_args`."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, _ = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = self._put_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/mutex"]

        params = {"type": "system/continuation", "data": {
            "target": "system/tree",
            "operation": "put",
            "dispatch_capability": cap_hash,
            "result_transform": {
                "transform_ops": [{
                    "op": "collect_keys",
                    "field": "added",
                    "fields": ["added", "changed"],
                    "into": "paths",
                }],
            },
        }}
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 400
        assert response["result"]["data"]["code"] == "invalid_transform_args"

    @pytest.mark.asyncio
    async def test_v116_install_rejects_result_merge_with_result_field(
        self, setup_context,
    ):
        """v1.16 §3.2: result_merge and result_field are mutually exclusive
        (Merge mode vs Inject mode). Reject at install with the pinned code
        `400 invalid_continuation`."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, _ = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = self._put_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/merge-mutex"]

        params = {"type": "system/continuation", "data": {
            "target": "system/tree",
            "operation": "put",
            "dispatch_capability": cap_hash,
            "params": {"prefix": "project/"},
            "result_merge": True,
            "result_field": "value",
        }}
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 400
        assert response["result"]["data"]["code"] == "invalid_continuation"

    @pytest.mark.asyncio
    async def test_v116_install_accepts_result_merge(self, setup_context):
        """v1.16 §2.1: result_merge alone (no result_field) installs."""
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        emit_pathway, ctx, _ = setup_context
        author = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
        cap_hash = self._put_cap(emit_pathway.content_store, granter=author)
        ctx.remote_identity_hash = author
        ctx.resource_targets = ["system/continuation/suspended/merge-ok"]

        params = {"type": "system/continuation", "data": {
            "target": "system/revision",
            "operation": "fetch-diff",
            "dispatch_capability": cap_hash,
            "params": {"prefix": "project/"},
            "result_merge": True,
            "result_transform": {"select": {"base": "data.previous_hash"}},
        }}
        response = await continuation_handler(
            "system/continuation", "install", params, ctx,
        )
        assert response["status"] == 200, response

    @pytest.mark.asyncio
    async def test_v19_lost_error_marker_bound_on_on_error_failure(
        self, setup_context,
    ):
        """A.1 (§3.4): when an on_error dispatch itself fails, an
        informational marker is bound under system/runtime/chain-errors/
        lost/. Observation only — advancement is unaffected."""
        emit_pathway, ctx, keypair = setup_context
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)

        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        cap_hash = self._put_cap(
            emit_pathway.content_store,
            granter=bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26,
        )

        async def _boom(*a, **k):
            raise RuntimeError("inbox unreachable")

        ctx.deliver_async = _boom  # force on_error delivery to fail

        continuation = Entity(type=CONTINUATION_TYPE, data={
            "target": "system/tree",
            "operation": "put",
            "on_error": {"uri": "system/inbox/errs", "operation": "receive"},
            "dispatch_capability": cap_hash,
        })
        path = "system/inbox/v19-a1"
        uri = emit_pathway.entity_tree.normalize_uri(path)
        emit_pathway.emit(uri, continuation, emit_ctx)

        # Inbound error status -> early on_error path -> delivery raises.
        resp = await continuation_handler("system/continuation", "advance", {
            "data": {"continuation_path": path, "result": {"e": 1},
                     "status": 503},
        }, ctx)

        # Advancement still returns (best-effort; no reactive behavior).
        assert resp["status"] == 200
        # v1.20 §3.10.1 path: .../{kind}/{chain_id}/{step_index}/{reason}/{marker_hash}
        # — reason is the canonical engine code `on_error_dispatch_failed`
        # (Appendix A); the {marker_hash} terminal varies per-occurrence so we
        # scan the prefix.
        #
        # {chain_id} was pinned to the literal "unknown" until §3.6 step 6 was
        # implemented: this advance's trigger carries no chain, so pre-step-6
        # the dispatch ran chainless and the binder's `or "unknown"` fallback
        # supplied the coordinate. That sentinel was never the contract — it
        # was the symptom cross-impl marker-coordinate reconciliation chased
        # (Rust pinned "internal", Go the request id). Step 6 generates a chain
        # on absence, so the marker keys on a real one; the id is opaque and
        # freshly generated per advance, hence scan-and-assert rather than a
        # literal.
        base = emit_pathway.entity_tree.normalize_uri(
            "system/runtime/chain-errors/lost/"
        )
        matches = [
            uri for uri in emit_pathway.entity_tree.list_prefix(base)
            if "/on_error_dispatch_failed/" in uri
        ]
        assert matches, (
            f"A.1 lost marker not bound under {base}<chain_id>/<step_index>/"
            f"on_error_dispatch_failed/ (v1.20 path scheme)"
        )
        chain_segment = matches[0][len(base):].split("/")[0]
        assert chain_segment != "unknown", (
            "§3.6 step 6 regression: the marker keyed on the binder's "
            "`or \"unknown\"` fallback, meaning the advance dispatched with "
            "chain_id absent. Step 6 must generate on absence."
        )
        marker_uri = matches[0]
        marker_hash = emit_pathway.entity_tree.get(marker_uri)
        marker = emit_pathway.content_store.get(marker_hash)
        # Type is pinned for cross-impl marker-hash agreement.
        assert marker.type == "system/runtime/chain-error-lost"
        # §3.10.6 body-fields registry: `status` (was `original_status`).
        assert marker.data["status"] == 503
        # Impl-specific extras per §3.10.6 "impls MAY add additional fields".
        assert marker.data["on_error_uri"] == "system/inbox/errs"
        # §3.10.6 `step_index` + arch ruling 14: a step with no request_id gets
        # a SINGLE-SEGMENT synthesized key, with the natural key in the body.
        # This previously interpolated a tree path into a one-segment slot, so
        # our own sanitizer quarantined our own legitimate coordinate — the
        # measurement that made the spelling ruling urgent. Hashing the path
        # restores the index; `continuation_path` keeps the semantic readable.
        step_key = _synthesized_step_key("error", "system/inbox/v19-a1")
        assert marker.data["step_index"] == step_key
        assert is_safe_path_segment(step_key)
        assert f"/{step_key}/" in marker_uri, (
            f"the synthesized key must reach the PATH unquarantined: {marker_uri}"
        )
        assert marker.data["continuation_path"] == "system/inbox/v19-a1", (
            "ruling 14's natural key must survive in the body"
        )

    @pytest.mark.asyncio
    async def test_lost_error_marker_logs_emit_status_failure(
        self, setup_context, caplog,
    ):
        """F11 / Class B (BUG-CLASSES.md): the lost-error marker bind path
        MUST surface failure regardless of failure shape. The exception path
        already logged; the EmitResult-status path previously silently
        ignored a 503 (cascade-depth refusal — binding did NOT commit) or a
        207 (cascade halted by consumer). Without this surface an operator
        chasing a stalled chain has no observability for the
        observability-write itself.

        Audit prompt: "For every place your impl writes to observability/audit
        paths from inside a handler, prove the bind result is checked and any
        failure is surfaced." Pin: a 503 from emit MUST log a warning
        identifiable as the F11 surface.
        """
        import logging
        from entity_handlers.continuation import _bind_lost_marker
        from entity_core.storage.emit import EmitResult

        emit_pathway, ctx, _ = setup_context

        # Force emit() to return a refusal status without raising — the exact
        # shape Class B masks. Use a 503: emit's SYSTEM_REFUSE_DEPTH path
        # returns this when cascade depth is exhausted (binding did NOT
        # commit), which is the canonical "best-effort write failed silently"
        # shape that motivated F11.
        original_emit = emit_pathway.emit
        def fake_emit(*a, **k):
            return EmitResult(hash=None, status=503)
        emit_pathway.emit = fake_emit

        try:
            caplog.set_level(logging.WARNING, logger="entity_handlers.continuation")
            # v1.19/v1.20 surface: helper renamed _bind_lost_error_marker →
            # _bind_lost_marker; signature uses code-as-reason (no separate
            # reason= parameter).
            _bind_lost_marker(
                ctx,
                code="some_handler_code",
                status=500,
                request_id="req-1",
                continuation_path="system/inbox/test",
            )
        finally:
            emit_pathway.emit = original_emit

        # The F11 surface is identifiable in the log. Avoid pinning on
        # exact phrasing beyond the marker name + status — those are the
        # operator-visible needles. "FAILED" + "503" together are enough to
        # detect regression to silent-ignore.
        f11_records = [
            r for r in caplog.records
            if r.levelno >= logging.WARNING
            and "F11" in r.getMessage()
            and "FAILED" in r.getMessage()
            and "503" in r.getMessage()
        ]
        assert f11_records, (
            "F11: lost-error marker bind returned status=503 but no warning "
            "was logged — Class B silent-failure regression. Got log records: "
            f"{[r.getMessage() for r in caplog.records]}"
        )

    @pytest.mark.asyncio
    async def test_v19_transform_ops_end_to_end_real_inbox(self, setup_context):
        """G1 readback (mirrors GoValidator transform_ops_apply): a forward
        continuation rewrites a field via transform_ops, resource_extract
        drives the dispatched inbox:receive to the rewritten path, and the
        delivery MUST be observable at that rewritten resource path.

        This is the test the mocked-dispatcher v1.9 tests should have been —
        it exercises the REAL inbox handler so the dispatch side-effect (not
        just a status 200) is the oracle.
        """
        from entity_core.utils.ecf import ALG_ECFV1_SHA256
        from entity_handlers.inbox import inbox_handler

        emit_pathway, ctx, keypair = setup_context
        emit_ctx = EmitContext.protocol(author=keypair.peer_id)
        cap_hash = self._put_cap(
            emit_pathway.content_store,
            granter=bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26,
        )

        # Real dispatcher: bridge system/inbox -> the real inbox_handler,
        # sharing the same emit_pathway, honoring resource_targets.
        async def real_dispatch(uri, operation, params, capability, bounds,
                                chain_id, resource_targets=None, **_k):
            if uri.endswith("system/inbox"):
                inbox_ctx = HandlerContext(
                    local_peer_id=keypair.peer_id,
                    remote_peer_id="remote",
                    handler_grant={},
                    caller_capability={},
                    emit_pathway=emit_pathway,
                    resource_targets=resource_targets,
                    _execute_dispatcher=real_dispatch,
                )
                resp = await inbox_handler("system/inbox", operation,
                                           params, inbox_ctx)
                return ExecuteResult(status=resp["status"],
                                     result=resp.get("result"))
            return ExecuteResult(status=200, result={"ok": True})

        ctx._execute_dispatcher = real_dispatch

        cont = Entity(type=CONTINUATION_TYPE, data={
            "target": "system/inbox",
            "operation": "receive",
            "resource": {"targets": ["system/validate/tops-mirror/*"]},
            "result_transform": {
                "transform_ops": [
                    {"op": "strip_prefix", "field": "dst", "prefix": "raw/in/"},
                    {"op": "prepend", "field": "dst",
                     "literal": "system/validate/tops-mirror/"},
                ],
                "resource_extract": "dst",
            },
            "dispatch_capability": cap_hash,
            "remaining_executions": 1,
        })
        cont_path = "system/inbox/validate-tops"
        cont_uri = emit_pathway.entity_tree.normalize_uri(cont_path)
        emit_pathway.emit(cont_uri, cont, emit_ctx)

        await continuation_handler("system/continuation", "advance", {"data": {
            "continuation_path": cont_path,
            "result": {"dst": "raw/in/item-7", "payload": "probe"},
        }}, ctx)

        # The oracle (same as the GoValidator): the delivery MUST be
        # observable under the ops-rewritten resource path.
        rewritten = emit_pathway.entity_tree.list_prefix(
            "system/validate/tops-mirror/item-7"
        )
        all_paths = emit_pathway.entity_tree.list_prefix("")
        assert rewritten, (
            "transform_ops+resource_extract not observable at the rewritten "
            f"path. Tree contents: {all_paths}"
        )


class TestTheCrossPeerAdvanceGatesOnTheHandlerGrant:
    """§1.4 PD-2 (0.8.2.19) — *a credential is not a grant*, at the one site
    that passed the same object as both.

    .. rubric:: Why this is a SOURCE row and not a behavioural one

    The seam is cross-peer, and every continuation cross-peer test in this
    repo drives a **stub** dispatcher — so no local run can see a change to
    it. That is the standing law (*a second dispatch path is a second
    boundary, and the in-process one is the untested half*), and it is why
    this defect was found by `convergence.rexec_delivered` against a live go
    peer rather than by 4382 green tests.

    .. rubric:: What was measured

    The advance passed `capability_data=dispatch_cap_entity.data` — the
    B-rooted credential — as the gate, *and* the same credential as the
    presented one. While the presented arm short-circuited, the duplicate was
    inert: the credential was only ever read in the target's frame. Composing
    the gate (F67's fix) made it fatal, because §1.4 evaluates the handler's
    grant in the **LOCAL** frame:

        request target  `system/validate/rexec-src-.../item`
                        -> canonicalizes in OUR frame  -> `/{A}/...`
        grant pattern   `/{B}/system/validate/rexec-src-.../item`

    A B-rooted credential's resource patterns are authored in B's namespace,
    so read as a local grant they can never match a target naming B. §1.4's
    *"looks implemented and denies everything"*, reached through Dimension 3.

    Measured: `rexec_delivered` FAIL, bisected by restoring the bypass (PASS),
    then PASS again with this fix — 1638 · 0 F @ core-go `6dc6506`.
    """

    def test_the_cross_peer_arm_hands_the_gate_the_handler_grant(self):
        """The credential goes in as the CREDENTIAL and the handler's grant
        goes in as the GATE. A seat that re-collapses them gets a green local
        suite and a red cohort run, which is the trade this row exists to
        stop.
        """
        import inspect

        from entity_handlers import continuation as continuation_module

        src = inspect.getsource(continuation_module)
        assert "gate_capability = ctx.handler_grant" in src, (
            "the cross-peer continuation advance no longer gates on the "
            "executing handler's grant — if it passes the dispatch_capability "
            "as `capability_data` again, §1.4's frame rule refuses every "
            "cross-peer advance and `convergence.rexec_delivered` goes red"
        )
        assert "capability_data=gate_capability" in src, (
            "the advance's dispatch no longer reads the gate variable"
        )

    def test_and_the_local_arm_still_spends_the_credential(self):
        """The control, and the reason this is not a blanket change.

        §4.2 case 3 scopes the credential to the **cross-peer** dispatch;
        local/system targets are unchanged and still drive the local scope
        check off the stored capability. A fix that hoisted
        `ctx.handler_grant` out of the `if` would widen every local advance
        from the continuation's narrow stored capability to the handler's
        `*` self-grant — strictly more authority, on the arm nobody was
        looking at.
        """
        import inspect

        from entity_handlers import continuation as continuation_module

        src = inspect.getsource(continuation_module)
        default = src.index("gate_capability = dispatch_cap_entity.data")
        override = src.index("gate_capability = ctx.handler_grant")
        assert default < override, (
            "the credential default no longer precedes the cross-peer "
            "override; the local arm may have lost its narrow capability"
        )
