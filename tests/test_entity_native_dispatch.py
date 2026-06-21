"""Unit tests for V7 §6.6 entity-native handler dispatch.

Covers:
  - ComputeExtension.dispatch_entity_native: scope injection, result unwrap
  - ComputeExtension.make_entity_native_handler: V7 §7.1 fail-closed
    handler-grant check
  - V7 §6.8 context propagation: caller_capability + author flow into
    sub-dispatches
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult
from entity_core.peer.extensions import ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.compute import ComputeExtension


WILDCARD_CAP = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": ["*"]},
    }],
}


def _grant(handlers, operations, resources):
    return {
        "grants": [{
            "handlers": {"include": handlers},
            "operations": {"include": operations},
            "resources": {"include": resources},
        }],
    }


@pytest.fixture
def setup():
    keypair = Keypair.generate()
    cs = ContentStore()
    et = EntityTree(keypair.peer_id)
    ep = EmitPathway(cs, et)
    ext = ComputeExtension()
    ext_ctx = ExtensionContext(keypair=keypair, emit_pathway=ep)
    ext.initialize(ext_ctx)
    return ext, cs, et, ep, keypair


def _handler_ctx(
    ep, peer_id, *,
    handler_grant=None,
    handler_grant_hash=b"\x00" * 33,  # default: present
    caller_capability=None,
    handler_pattern="app/foo",
    resource_targets=None,
    remote_peer_id=None,
    remote_identity_hash=None,
    execute_dispatcher=None,
):
    """Build a minimal HandlerContext for entity-native dispatch tests."""
    ctx = MagicMock()
    ctx.emit_pathway = ep
    ctx.local_peer_id = peer_id
    ctx.handler_grant = handler_grant if handler_grant is not None else WILDCARD_CAP
    ctx.handler_grant_hash = handler_grant_hash
    ctx.caller_capability = caller_capability if caller_capability is not None else WILDCARD_CAP
    ctx.handler_pattern = handler_pattern
    ctx.resource_targets = resource_targets
    ctx.remote_peer_id = remote_peer_id or peer_id
    ctx.remote_identity_hash = remote_identity_hash
    ctx.bounds = None
    ctx._execute_dispatcher = execute_dispatcher

    if execute_dispatcher is not None:
        async def _ewc(uri, operation, params=None, capability_data=None,
                       resource_targets=None, **kwargs):
            return await execute_dispatcher(
                uri, operation, params, capability_data,
                None, None, resource_targets, **kwargs,
            )
        ctx.execute_with_capability = _ewc
    return ctx


def _store_lit(cs, value) -> bytes:
    return cs.put(Entity(type="compute/literal", data={"value": value}))


def _store(cs, entity: Entity) -> bytes:
    return cs.put(entity)


# ============================================================================
# dispatch_entity_native — happy paths
# ============================================================================

class TestEntityNativeDispatch:

    @pytest.mark.asyncio
    async def test_returns_wrapped_primitive_from_literal(self, setup):
        """V7 §6.6 step 5: bare primitive results MUST be wrapped as
        primitive/any so the wire response carries a typed entity."""
        ext, cs, et, ep, keypair = setup
        et.set("app/foo/expr", _store_lit(cs, 42))

        ctx = _handler_ctx(ep, keypair.peer_id)

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={
                "operation": "compute", "params": {},
                "resource": [], "caller_capability": {},
            },
            eval_capability=WILDCARD_CAP,
            handler_ctx=ctx,
        )
        assert result == {
            "status": 200,
            "result": {"type": "primitive/any", "data": 42},
        }

    @pytest.mark.asyncio
    async def test_unwraps_compute_result_then_wraps_primitive(self, setup):
        """compute/result(value=primitive) → extract value, then wrap per §6.6
        step 5. The unwrap is sequential — an inner primitive still gets
        wrapped at the dispatch boundary."""
        ext, cs, et, ep, keypair = setup

        wrapper_value = {"type": "compute/result", "data": {"value": "hello"}}
        et.set("app/foo/expr", _store_lit(cs, wrapper_value))

        ctx = _handler_ctx(ep, keypair.peer_id)

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={},
            eval_capability=WILDCARD_CAP,
            handler_ctx=ctx,
        )
        assert result == {
            "status": 200,
            "result": {"type": "primitive/any", "data": "hello"},
        }

    @pytest.mark.asyncio
    async def test_compute_error_yields_200(self, setup):
        """F10 (PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE): an
        evaluator-produced compute/error is a *value* — handler-mode dispatch
        returns it at status 200 with the compute/error body, detected by
        result type, not by a transport 4xx."""
        ext, cs, et, ep, keypair = setup

        # compute/lookup/scope on a missing binding produces compute/error.
        scope_lookup = Entity(
            type="compute/lookup/scope",
            data={"name": "missing-binding"},
        )
        et.set("app/foo/expr", _store(cs, scope_lookup))

        ctx = _handler_ctx(ep, keypair.peer_id)

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={},  # no bindings
            eval_capability=WILDCARD_CAP,
            handler_ctx=ctx,
        )
        assert result["status"] == 200
        assert result["result"]["type"] == "compute/error"
        assert result["result"]["data"]["code"] == "not_found"

    @pytest.mark.asyncio
    async def test_missing_expression_path_404(self, setup):
        ext, cs, et, ep, keypair = setup
        ctx = _handler_ctx(ep, keypair.peer_id)

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/missing",
            scope_bindings={},
            eval_capability=WILDCARD_CAP,
            handler_ctx=ctx,
        )
        assert result["status"] == 404

    @pytest.mark.asyncio
    async def test_non_compute_entity_at_expression_path_400(self, setup):
        ext, cs, et, ep, keypair = setup
        not_compute = Entity(type="app/data", data={"x": 1})
        et.set("app/foo/expr", _store(cs, not_compute))

        ctx = _handler_ctx(ep, keypair.peer_id)

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={},
            eval_capability=WILDCARD_CAP,
            handler_ctx=ctx,
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_expression"


# ============================================================================
# E1: scope injection
# ============================================================================

class TestScopeInjection:
    """The expression accesses request context via compute/lookup/scope."""

    def _scope_lookup_at(self, cs, et, name: str, expression_path: str):
        expr = Entity(type="compute/lookup/scope", data={"name": name})
        et.set(expression_path, _store(cs, expr))

    @pytest.mark.asyncio
    async def test_lookup_scope_operation(self, setup):
        ext, cs, et, ep, keypair = setup
        self._scope_lookup_at(cs, et, "operation", "app/foo/expr")

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={
                "operation": "compute",
                "params": {},
                "resource": [],
                "caller_capability": {},
            },
            eval_capability=WILDCARD_CAP,
            handler_ctx=_handler_ctx(ep, keypair.peer_id),
        )
        assert result == {
            "status": 200,
            "result": {"type": "primitive/any", "data": "compute"},
        }

    @pytest.mark.asyncio
    async def test_lookup_scope_params(self, setup):
        ext, cs, et, ep, keypair = setup
        self._scope_lookup_at(cs, et, "params", "app/foo/expr")

        params_value = {"data": {"x": 42, "y": "hi"}}
        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={
                "operation": "compute",
                "params": params_value,
                "resource": [],
                "caller_capability": {},
            },
            eval_capability=WILDCARD_CAP,
            handler_ctx=_handler_ctx(ep, keypair.peer_id),
        )
        assert result == {"status": 200, "result": params_value}

    @pytest.mark.asyncio
    async def test_lookup_scope_resource(self, setup):
        ext, cs, et, ep, keypair = setup
        self._scope_lookup_at(cs, et, "resource", "app/foo/expr")

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={
                "operation": "compute",
                "params": {},
                "resource": ["app/data/item-1"],
                "caller_capability": {},
            },
            eval_capability=WILDCARD_CAP,
            handler_ctx=_handler_ctx(ep, keypair.peer_id),
        )
        assert result == {"status": 200, "result": ["app/data/item-1"]}

    @pytest.mark.asyncio
    async def test_lookup_scope_caller_capability(self, setup):
        ext, cs, et, ep, keypair = setup
        self._scope_lookup_at(cs, et, "caller_capability", "app/foo/expr")

        narrow_cap = _grant(["system/tree"], ["get"], ["app/data/public/*"])

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={
                "operation": "compute",
                "params": {},
                "resource": [],
                "caller_capability": narrow_cap,
            },
            eval_capability=WILDCARD_CAP,
            handler_ctx=_handler_ctx(ep, keypair.peer_id),
        )
        assert result == {"status": 200, "result": narrow_cap}


# ============================================================================
# §7.1: fail-closed handler grant
# ============================================================================

class TestFailClosedHandlerGrant:
    """make_entity_native_handler enforces V7 §7.1: missing/empty handler
    grant MUST yield permission_denied. The fallback full-access grant
    returned by Peer._get_handler_grant when the grant entity is absent
    cannot serve as the ceiling — that would invert the security model."""

    @pytest.mark.asyncio
    async def test_missing_grant_hash_denied(self, setup):
        ext, cs, et, ep, keypair = setup
        et.set("app/foo/expr", _store_lit(cs, 99))

        wrapper = ext.make_entity_native_handler("app/foo/expr")
        ctx = _handler_ctx(
            ep, keypair.peer_id,
            handler_grant_hash=None,  # grant entity absent in tree
            handler_grant=WILDCARD_CAP,  # fallback full-access (the trap)
        )

        result = await wrapper("app/foo", "compute", {}, ctx)
        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "permission_denied"
        assert "missing" in result["result"]["data"]["message"].lower()

    @pytest.mark.asyncio
    async def test_empty_grants_denied(self, setup):
        ext, cs, et, ep, keypair = setup
        et.set("app/foo/expr", _store_lit(cs, 99))

        wrapper = ext.make_entity_native_handler("app/foo/expr")
        ctx = _handler_ctx(
            ep, keypair.peer_id,
            handler_grant={"grants": []},  # present but empty
        )

        result = await wrapper("app/foo", "compute", {}, ctx)
        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "permission_denied"
        assert "empty" in result["result"]["data"]["message"].lower()

    @pytest.mark.asyncio
    async def test_present_grant_proceeds(self, setup):
        ext, cs, et, ep, keypair = setup
        et.set("app/foo/expr", _store_lit(cs, 99))

        wrapper = ext.make_entity_native_handler("app/foo/expr")
        ctx = _handler_ctx(ep, keypair.peer_id)

        result = await wrapper("app/foo", "compute", {}, ctx)
        assert result == {
            "status": 200,
            "result": {"type": "primitive/any", "data": 99},
        }


# ============================================================================
# §6.8: context propagation
# ============================================================================

class TestContextPropagation:
    """When an entity-native handler dispatches a sub-request via
    compute/apply, the original external caller's capability and identity
    propagate to the sub-handler — V7 §6.8."""

    @pytest.mark.asyncio
    async def test_caller_capability_and_author_propagate_to_subdispatch(self, setup):
        ext, cs, et, ep, keypair = setup

        # Build expression: compute/apply to system/tree:get with one arg.
        path_arg_h = _store_lit(cs, "app/data/x")

        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {"path": path_arg_h},
        })
        et.set("app/foo/expr", _store(cs, apply_expr))

        # Record the propagated kwargs the dispatcher receives.
        captured: dict = {}

        async def recording_dispatcher(
            uri, operation, params, capability,
            bounds, chain_id, resource_targets,
            *, propagated_caller_capability=None,
            propagated_author_peer_id=None,
            propagated_author_identity_hash=None,
        ):
            captured["uri"] = uri
            captured["operation"] = operation
            captured["dispatch_capability"] = capability
            captured["caller_capability"] = propagated_caller_capability
            captured["author_peer_id"] = propagated_author_peer_id
            captured["author_identity_hash"] = propagated_author_identity_hash
            return ExecuteResult(status=200, result={"value": "ok"})

        external_caller_cap = _grant(["*"], ["*"], ["*"])
        external_author = "external-peer-xyz"
        external_author_hash = b"\xab" * 33
        # Handler grant has content_store_access so the test can resolve
        # sub-entities of the apply expression. Production handlers would
        # tree-bind their sub-entities; this is a unit-test simplification
        # that doesn't affect the propagation behavior under test.
        handler_grant = {
            **_grant(["system/tree"], ["get"], ["app/data/*"]),
            "allowances": {"content_store_access": True},
        }

        wrapper = ext.make_entity_native_handler("app/foo/expr")
        ctx = _handler_ctx(
            ep, keypair.peer_id,
            handler_grant=handler_grant,
            caller_capability=external_caller_cap,
            remote_peer_id=external_author,
            remote_identity_hash=external_author_hash,
            execute_dispatcher=recording_dispatcher,
        )

        result = await wrapper("app/foo", "compute", {}, ctx)
        assert result["status"] == 200, result

        # The sub-dispatch's authorization uses the handler grant (default),
        # but the propagated caller_capability + author come from the
        # external request — not from the entity-native handler.
        assert captured["dispatch_capability"] == handler_grant
        assert captured["caller_capability"] == external_caller_cap
        assert captured["author_peer_id"] == external_author
        assert captured["author_identity_hash"] == external_author_hash

    @pytest.mark.asyncio
    async def test_compute_apply_capability_field_overrides_dispatch_cap(self, setup):
        """When compute/apply has `capability` and `resource`, the dispatch
        uses the provided cap (after the full-resolution dual-check) and
        forwards the resolved resource targets. caller_capability + author
        propagate unchanged.

        Per PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING (F1/F2/F4/F5):
        capability MUST be paired with resource; both ctx.capability (handler
        grant ceiling) and provided_cap MUST cover handler+operation+resource.
        """
        ext, cs, et, ep, keypair = setup

        # Provided cap (caller's). Will be bound in scope.
        provided = _grant(["system/tree"], ["get"], ["app/data/*"])

        # Cap field: lookup/scope("caller_capability")
        cap_lookup = Entity(type="compute/lookup/scope",
                            data={"name": "caller_capability"})
        cap_lookup_h = _store(cs, cap_lookup)

        # Resource: literal {targets: ["app/data/x"]} per F1/F4.
        resource_lit_h = _store_lit(cs, {"targets": ["app/data/x"]})

        path_arg_h = _store_lit(cs, "app/data/x")

        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {"path": path_arg_h},
            "resource": resource_lit_h,
            "capability": cap_lookup_h,
        })
        et.set("app/foo/expr", _store(cs, apply_expr))

        captured: dict = {}

        async def recording_dispatcher(
            uri, operation, params, capability,
            bounds, chain_id, resource_targets,
            *, propagated_caller_capability=None,
            propagated_author_peer_id=None,
            propagated_author_identity_hash=None,
        ):
            captured["dispatch_capability"] = capability
            captured["resource_targets"] = resource_targets
            captured["caller_capability"] = propagated_caller_capability
            captured["author_peer_id"] = propagated_author_peer_id
            return ExecuteResult(status=200, result={"value": "ok"})

        # Handler grant must also cover system/tree:get on app/data/* per
        # the dual-check. external_caller_cap is what's bound in scope for
        # caller_capability — and what compute/apply.capability resolves to.
        # content_store_access is a unit-test simplification (see the
        # other propagation test).
        handler_grant = {
            **_grant(["system/tree"], ["get"], ["app/data/*"]),
            "allowances": {"content_store_access": True},
        }

        wrapper = ext.make_entity_native_handler("app/foo/expr")
        ctx = _handler_ctx(
            ep, keypair.peer_id,
            handler_grant=handler_grant,
            caller_capability=provided,
            remote_peer_id="external-peer",
            execute_dispatcher=recording_dispatcher,
        )

        result = await wrapper("app/foo", "compute", {}, ctx)
        assert result["status"] == 200, result
        # Dispatch uses the provided cap (voluntary restriction).
        assert captured["dispatch_capability"] == provided
        # F4 — the resolved resource is propagated to the dispatched EXECUTE.
        assert captured["resource_targets"] == ["app/data/x"]
        # Caller capability and author propagate from the outer call —
        # the wrapper builds scope_bindings from ctx, and the propagated
        # caller_capability is the same value that's now in dispatch_capability.
        assert captured["caller_capability"] == provided
        assert captured["author_peer_id"] == "external-peer"


# ============================================================================
# E3 / V7 §6.6 step 5: result-shape rules at the dispatch boundary
# ============================================================================

class TestResultShape:
    """The dispatch boundary normalizes the evaluator's result so the wire
    response carries a typed entity. Bare primitives wrap as primitive/any;
    entity-shaped results pass through; compute/result is unwrapped first
    and the inner value re-evaluated under the same rules."""

    @pytest.mark.parametrize("value", [
        42, -1, 0, 3.14, "hi", "", True, False,
    ])
    @pytest.mark.asyncio
    async def test_primitive_results_wrapped_as_primitive_any(self, setup, value):
        ext, cs, et, ep, keypair = setup
        et.set("app/foo/expr", _store_lit(cs, value))

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={},
            eval_capability=WILDCARD_CAP,
            handler_ctx=_handler_ctx(ep, keypair.peer_id),
        )
        assert result == {
            "status": 200,
            "result": {"type": "primitive/any", "data": value},
        }

    @pytest.mark.asyncio
    async def test_entity_shaped_result_passes_through(self, setup):
        """A literal whose value is already a typed entity dict is returned
        as-is — no re-wrapping."""
        ext, cs, et, ep, keypair = setup
        entity_value = {
            "type": "app/record",
            "data": {"name": "alice", "n": 7},
        }
        et.set("app/foo/expr", _store_lit(cs, entity_value))

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={},
            eval_capability=WILDCARD_CAP,
            handler_ctx=_handler_ctx(ep, keypair.peer_id),
        )
        # Entity dicts pass through without primitive wrapping.
        assert result["status"] == 200
        assert result["result"] == entity_value

    @pytest.mark.asyncio
    async def test_compute_result_with_entity_value_passes_through(self, setup):
        """compute/result(value=<entity>) — extract value, return as-is."""
        ext, cs, et, ep, keypair = setup
        entity_value = {"type": "app/record", "data": {"k": 1}}
        wrapper_value = {
            "type": "compute/result",
            "data": {"value": entity_value},
        }
        et.set("app/foo/expr", _store_lit(cs, wrapper_value))

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={},
            eval_capability=WILDCARD_CAP,
            handler_ctx=_handler_ctx(ep, keypair.peer_id),
        )
        assert result == {"status": 200, "result": entity_value}

    @pytest.mark.asyncio
    async def test_none_value_passes_through(self, setup):
        """None is not in the spec's primitive set (number/string/boolean) —
        leave it for the wire-side shim to normalize."""
        ext, cs, et, ep, keypair = setup
        et.set("app/foo/expr", _store_lit(cs, None))

        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={},
            eval_capability=WILDCARD_CAP,
            handler_ctx=_handler_ctx(ep, keypair.peer_id),
        )
        assert result == {"status": 200, "result": None}


class TestInEvalPermissionDenied:
    """v3.19c §3.2 (the 4xx→200 residual ruling): an impure-op permission_denied
    that occurs *during* evaluation is an error VALUE — status 200 +
    compute/error{permission_denied}, NOT a transport 4xx. 4xx is reserved for
    request-level / install authorization *before* eval. Mirrors the validator
    vectors lookup_tree_outside_scope (§7.2) and dual_check_handler_grant_blocks
    (§3.2), where all three impls return 200."""

    @pytest.mark.asyncio
    async def test_out_of_scope_tree_read_returns_200_error_value(self, setup):
        ext, cs, et, ep, keypair = setup
        et.set("secret/value", cs.put(Entity(type="primitive/any", data={"v": 1})))
        et.set("app/foo/expr", cs.put(Entity(type="compute/lookup/tree", data={"path": "secret/value"})))

        ctx = _handler_ctx(ep, keypair.peer_id)
        # Handler grant (eval ceiling) covers tree:get only on app/foo/* — NOT secret/value.
        restricted = {"grants": [{
            "handlers": {"include": ["system/tree"]},
            "operations": {"include": ["get"]},
            "resources": {"include": ["app/foo/*"]},
        }]}
        result = await ext.dispatch_entity_native(
            expression_path="app/foo/expr",
            scope_bindings={"operation": "compute", "params": {}, "resource": [], "caller_capability": {}},
            eval_capability=restricted,
            handler_ctx=ctx,
        )
        assert result["status"] == 200
        assert result["result"]["type"] == "compute/error"
        assert result["result"]["data"]["code"] == "permission_denied"
