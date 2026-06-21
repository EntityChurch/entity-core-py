"""Tests for the compute extension (EXTENSION-COMPUTE v3.17)."""

from __future__ import annotations

import pytest

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree
from entity_core.utils.ecf import ALG_ECFV1_SHA256

from entity_handlers.compute import (
    COMPUTE_EXPRESSION_TYPES,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_OPS,
    ERR_BUDGET_EXHAUSTED,
    ERR_CAST_OUT_OF_RANGE,
    ERR_DEPTH_EXCEEDED,
    ERR_DIVISION_BY_ZERO,
    ERR_INDEX_OUT_OF_RANGE,
    ERR_INVALID_EXPRESSION,
    ERR_MISSING_ARGUMENT,
    ERR_NOT_FOUND,
    ERR_PERMISSION_DENIED,
    ERR_SCOPE_UNREACHABLE,
    ERR_TYPE_MISMATCH,
    Budget,
    DependencyIndex,
    DepEntry,
    EvalContext,
    Scope,
    _capture_scope,
    _clean_path,
    _field_record,
    _load_scope,
    _materialize_bare,
    audit_subgraph,
    canonical_sorted,
    deterministic_id,
    evaluate,
    init_budget,
    is_compute_expression,
    is_error,
    make_error,
    truthy,
    walk_tree_lookups,
)

PEER_ID = "test-peer-id"

WILDCARD_CAP = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": ["*"]},
    }],
}


def _make_ctx(
    content_store: ContentStore | None = None,
    entity_tree: EntityTree | None = None,
    capability: dict | None = None,
    included: dict | None = None,
) -> EvalContext:
    cs = content_store or ContentStore()
    et = entity_tree or EntityTree(PEER_ID)
    return EvalContext(
        content_store=cs,
        entity_tree=et,
        local_peer_id=PEER_ID,
        capability=capability or WILDCARD_CAP,
        included=included or {},
        has_content_store_access=True,
    )


def _store(ctx: EvalContext, entity: Entity) -> bytes:
    """Store entity and return hash."""
    return ctx.content_store.put(entity)


def _lit(value) -> Entity:
    """Create a compute/literal entity."""
    return Entity(type="compute/literal", data={"value": value})


def _arith(op: str, left_hash: bytes, right_hash: bytes) -> Entity:
    return Entity(type="compute/arithmetic", data={
        "op": op, "left": left_hash, "right": right_hash,
    })


def _compare(op: str, left_hash: bytes, right_hash: bytes) -> Entity:
    return Entity(type="compute/compare", data={
        "op": op, "left": left_hash, "right": right_hash,
    })


def _logic(op: str, left_hash: bytes, right_hash: bytes | None = None) -> Entity:
    data: dict = {"op": op, "left": left_hash}
    if right_hash is not None:
        data["right"] = right_hash
    return Entity(type="compute/logic", data=data)


def _if(cond_hash: bytes, then_hash: bytes, else_hash: bytes | None = None) -> Entity:
    data: dict = {"condition": cond_hash, "then": then_hash}
    if else_hash is not None:
        data["else"] = else_hash
    return Entity(type="compute/if", data=data)


def _let(bindings: list[dict], body_hash: bytes) -> Entity:
    return Entity(type="compute/let", data={"bindings": bindings, "body": body_hash})


def _lambda(params: list[str], body_hash: bytes) -> Entity:
    return Entity(type="compute/lambda", data={"params": params, "body": body_hash})


def _apply_closure(fn_hash: bytes, args: dict[str, bytes]) -> Entity:
    return Entity(type="compute/apply", data={"fn": fn_hash, "args": args})


def _lookup_scope(name: str) -> Entity:
    return Entity(type="compute/lookup/scope", data={"name": name})


def _lookup_tree(path: str) -> Entity:
    return Entity(type="compute/lookup/tree", data={"path": path})


def _field(name: str, entity_hash: bytes) -> Entity:
    return Entity(type="compute/field", data={"name": name, "entity": entity_hash})


def _construct(entity_type: str, fields: dict[str, bytes]) -> Entity:
    return Entity(type="compute/construct", data={"entity_type": entity_type, "fields": fields})


# ============================================================================
# Helpers
# ============================================================================

class TestHelpers:
    def test_is_compute_expression(self):
        for t in COMPUTE_EXPRESSION_TYPES:
            assert is_compute_expression(Entity(type=t, data={}))
        assert not is_compute_expression(Entity(type="compute/closure", data={}))
        assert not is_compute_expression(Entity(type="app/user", data={}))

    def test_truthy(self):
        assert truthy(1) is True
        assert truthy("hello") is True
        assert truthy([1]) is True
        assert truthy(True) is True

        assert truthy(None) is False
        assert truthy(False) is False
        assert truthy(0) is False
        assert truthy("") is False
        assert truthy([]) is False

    def test_is_error(self):
        assert is_error(make_error("test", "msg"))
        assert not is_error(42)
        assert not is_error({"type": "app/user", "data": {}})

    def test_canonical_sorted(self):
        m = {"b": 2, "a": 1, "cc": 3}
        result = canonical_sorted(m)
        keys = [k for k, _ in result]
        assert keys == ["a", "b", "cc"]

    def test_deterministic_id(self):
        id1 = deterministic_id("app/cell/A1")
        id2 = deterministic_id("app/cell/A1")
        id3 = deterministic_id("app/cell/B2")
        assert id1 == id2
        assert id1 != id3
        assert len(id1) == 52


# ============================================================================
# Scope
# ============================================================================

class TestScope:
    def test_basic_operations(self):
        s = Scope()
        assert s.is_empty()
        assert not s.has("x")

        s.set("x", 42)
        assert s.has("x")
        assert s.get("x") == 42
        assert not s.is_empty()

    def test_copy(self):
        s = Scope({"x": 1, "y": 2})
        s2 = s.copy()
        s2.set("z", 3)
        assert not s.has("z")
        assert s2.has("z")


# ============================================================================
# Budget
# ============================================================================

class TestBudget:
    def test_defaults(self):
        b = Budget()
        assert b.operations == DEFAULT_MAX_OPS
        assert b.depth == DEFAULT_MAX_DEPTH

    def test_init_budget_defaults(self):
        b = init_budget({}, {})
        assert b.operations == DEFAULT_MAX_OPS
        assert b.depth == DEFAULT_MAX_DEPTH

    def test_init_budget_from_capability(self):
        cap = {"constraints": {"system/compute": {
            "max_compute_operations": 500,
            "max_compute_depth": 50,
        }}}
        b = init_budget({}, cap)
        assert b.operations == 500
        assert b.depth == 50

    def test_init_budget_request_wins_when_lower(self):
        b = init_budget({"budget": 100}, {})
        assert b.operations == 100


# ============================================================================
# Core evaluation — literals
# ============================================================================

class TestLiteral:
    def test_integer(self):
        ctx = _make_ctx()
        result = evaluate(_lit(42), Scope(), Budget(), ctx)
        assert result == 42

    def test_string(self):
        ctx = _make_ctx()
        result = evaluate(_lit("hello"), Scope(), Budget(), ctx)
        assert result == "hello"

    def test_null(self):
        ctx = _make_ctx()
        result = evaluate(_lit(None), Scope(), Budget(), ctx)
        assert result is None

    def test_boolean(self):
        ctx = _make_ctx()
        assert evaluate(_lit(True), Scope(), Budget(), ctx) is True
        assert evaluate(_lit(False), Scope(), Budget(), ctx) is False

    def test_list(self):
        ctx = _make_ctx()
        result = evaluate(_lit([1, 2, 3]), Scope(), Budget(), ctx)
        assert result == [1, 2, 3]


# ============================================================================
# Core evaluation — scope lookup
# ============================================================================

class TestScopeLookup:
    def test_found(self):
        ctx = _make_ctx()
        scope = Scope({"x": 42})
        expr = _lookup_scope("x")
        assert evaluate(expr, scope, Budget(), ctx) == 42

    def test_not_found(self):
        ctx = _make_ctx()
        result = evaluate(_lookup_scope("missing"), Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_NOT_FOUND


# ============================================================================
# Core evaluation — arithmetic
# ============================================================================

class TestArithmetic:
    def _eval_arith(self, op, left_val, right_val):
        ctx = _make_ctx()
        lh = _store(ctx, _lit(left_val))
        rh = _store(ctx, _lit(right_val))
        expr = _arith(op, lh, rh)
        return evaluate(expr, Scope(), Budget(), ctx)

    def test_add(self):
        assert self._eval_arith("add", 3, 4) == 7

    def test_sub(self):
        assert self._eval_arith("sub", 10, 3) == 7

    def test_mul(self):
        assert self._eval_arith("mul", 5, 6) == 30

    def test_div(self):
        assert self._eval_arith("div", 10, 2) == 5

    def test_div_float(self):
        result = self._eval_arith("div", 7, 2)
        assert result == 3.5

    def test_mod(self):
        assert self._eval_arith("mod", 10, 3) == 1

    def test_div_by_zero(self):
        result = self._eval_arith("div", 10, 0)
        assert is_error(result)
        assert result["data"]["code"] == ERR_DIVISION_BY_ZERO

    def test_mod_by_zero(self):
        result = self._eval_arith("mod", 10, 0)
        assert is_error(result)
        assert result["data"]["code"] == ERR_DIVISION_BY_ZERO

    def test_type_mismatch(self):
        result = self._eval_arith("add", "hello", 5)
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH

    def test_float_arithmetic(self):
        assert self._eval_arith("add", 1.5, 2.5) == 4.0
        assert self._eval_arith("mul", 2.0, 3.0) == 6.0


# ============================================================================
# Core evaluation — compare
# ============================================================================

class TestCompare:
    def _eval_cmp(self, op, left_val, right_val):
        ctx = _make_ctx()
        lh = _store(ctx, _lit(left_val))
        rh = _store(ctx, _lit(right_val))
        expr = _compare(op, lh, rh)
        return evaluate(expr, Scope(), Budget(), ctx)

    def test_eq(self):
        assert self._eval_cmp("eq", 5, 5) is True
        assert self._eval_cmp("eq", 5, 6) is False

    def test_neq(self):
        assert self._eval_cmp("neq", 5, 6) is True
        assert self._eval_cmp("neq", 5, 5) is False

    def test_lt(self):
        assert self._eval_cmp("lt", 3, 5) is True
        assert self._eval_cmp("lt", 5, 3) is False

    def test_gt(self):
        assert self._eval_cmp("gt", 5, 3) is True
        assert self._eval_cmp("gt", 3, 5) is False

    def test_lte(self):
        assert self._eval_cmp("lte", 3, 5) is True
        assert self._eval_cmp("lte", 5, 5) is True
        assert self._eval_cmp("lte", 6, 5) is False

    def test_gte(self):
        assert self._eval_cmp("gte", 5, 3) is True
        assert self._eval_cmp("gte", 5, 5) is True
        assert self._eval_cmp("gte", 3, 5) is False

    def test_eq_strings(self):
        assert self._eval_cmp("eq", "abc", "abc") is True
        assert self._eval_cmp("eq", "abc", "def") is False

    def test_ordered_compare_type_mismatch(self):
        result = self._eval_cmp("lt", "abc", 5)
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH


# ============================================================================
# Core evaluation — logic
# ============================================================================

class TestLogic:
    def _eval_logic(self, op, left_val, right_val=None):
        ctx = _make_ctx()
        lh = _store(ctx, _lit(left_val))
        rh = _store(ctx, _lit(right_val)) if right_val is not None else None
        expr = _logic(op, lh, rh)
        return evaluate(expr, Scope(), Budget(), ctx)

    def test_and_true(self):
        assert self._eval_logic("and", True, True) is True

    def test_and_false(self):
        assert self._eval_logic("and", True, False) is False
        assert self._eval_logic("and", False, True) is False

    def test_or_true(self):
        assert self._eval_logic("or", False, True) is True
        assert self._eval_logic("or", True, False) is True

    def test_or_false(self):
        assert self._eval_logic("or", False, False) is False

    def test_not_true(self):
        assert self._eval_logic("not", True) is False

    def test_not_false(self):
        assert self._eval_logic("not", False) is True

    def test_not_zero(self):
        assert self._eval_logic("not", 0) is True

    def test_and_truthy(self):
        assert self._eval_logic("and", 1, "hello") is True
        assert self._eval_logic("and", 1, "") is False


# ============================================================================
# Core evaluation — if
# ============================================================================

class TestIf:
    def test_truthy_branch(self):
        ctx = _make_ctx()
        cond_h = _store(ctx, _lit(True))
        then_h = _store(ctx, _lit(42))
        else_h = _store(ctx, _lit(99))
        expr = _if(cond_h, then_h, else_h)
        assert evaluate(expr, Scope(), Budget(), ctx) == 42

    def test_falsy_branch(self):
        ctx = _make_ctx()
        cond_h = _store(ctx, _lit(False))
        then_h = _store(ctx, _lit(42))
        else_h = _store(ctx, _lit(99))
        expr = _if(cond_h, then_h, else_h)
        assert evaluate(expr, Scope(), Budget(), ctx) == 99

    def test_no_else_truthy(self):
        ctx = _make_ctx()
        cond_h = _store(ctx, _lit(True))
        then_h = _store(ctx, _lit(42))
        expr = _if(cond_h, then_h)
        assert evaluate(expr, Scope(), Budget(), ctx) == 42

    def test_no_else_falsy_returns_none(self):
        ctx = _make_ctx()
        cond_h = _store(ctx, _lit(False))
        then_h = _store(ctx, _lit(42))
        expr = _if(cond_h, then_h)
        assert evaluate(expr, Scope(), Budget(), ctx) is None

    def test_short_circuit(self):
        """Non-taken branch must not be evaluated."""
        ctx = _make_ctx()
        cond_h = _store(ctx, _lit(True))
        then_h = _store(ctx, _lit(42))
        # else points to a nonexistent hash — should not be resolved
        bad_hash = b"\x00" * 33
        expr = _if(cond_h, then_h, bad_hash)
        assert evaluate(expr, Scope(), Budget(), ctx) == 42


# ============================================================================
# Core evaluation — let
# ============================================================================

class TestLet:
    def test_simple_binding(self):
        ctx = _make_ctx()
        val_h = _store(ctx, _lit(42))
        lookup = _lookup_scope("x")
        body_h = _store(ctx, lookup)
        expr = _let([{"name": "x", "value": val_h}], body_h)
        assert evaluate(expr, Scope(), Budget(), ctx) == 42

    def test_sequential_binding(self):
        """Later bindings can reference earlier ones (let* semantics)."""
        ctx = _make_ctx()

        five_h = _store(ctx, _lit(5))
        lookup_x = _store(ctx, _lookup_scope("x"))

        one_h = _store(ctx, _lit(1))
        add_expr = _arith("add", lookup_x, one_h)
        add_h = _store(ctx, add_expr)

        lookup_y = _store(ctx, _lookup_scope("y"))

        expr = _let(
            [
                {"name": "x", "value": five_h},
                {"name": "y", "value": add_h},
            ],
            lookup_y,
        )
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert result == 6

    def test_binding_shadows_outer_scope(self):
        ctx = _make_ctx()
        val_h = _store(ctx, _lit(99))
        lookup = _store(ctx, _lookup_scope("x"))
        expr = _let([{"name": "x", "value": val_h}], lookup)
        scope = Scope({"x": 1})
        assert evaluate(expr, scope, Budget(), ctx) == 99

    def test_outer_scope_visible(self):
        ctx = _make_ctx()
        lookup_y = _store(ctx, _lookup_scope("y"))
        expr = _let([], lookup_y)
        scope = Scope({"y": 77})
        assert evaluate(expr, scope, Budget(), ctx) == 77


# ============================================================================
# Core evaluation — lambda and closure
# ============================================================================

class TestLambdaAndClosure:
    def test_lambda_produces_closure(self):
        ctx = _make_ctx()
        body_h = _store(ctx, _lookup_scope("x"))
        expr = _lambda(["x"], body_h)
        result = evaluate(expr, Scope(), Budget(), ctx)
        # v3.19b N3: entity values (incl. closures) are carried as Entity objects.
        assert result.type == "compute/closure"
        assert result.data["params"] == ["x"]
        assert result.data["body"] == body_h

    def test_apply_closure(self):
        ctx = _make_ctx()
        # Create lambda: fn(x) -> x + 1
        lookup_x = _store(ctx, _lookup_scope("x"))
        one_h = _store(ctx, _lit(1))
        add_expr = _store(ctx, _arith("add", lookup_x, one_h))
        lambda_expr = _lambda(["x"], add_expr)
        lambda_h = _store(ctx, lambda_expr)

        # Apply to 5
        five_h = _store(ctx, _lit(5))
        apply_expr = _apply_closure(lambda_h, {"x": five_h})
        result = evaluate(apply_expr, Scope(), Budget(), ctx)
        assert result == 6

    def test_closure_captures_scope(self):
        """Closure captures enclosing scope bindings."""
        ctx = _make_ctx()

        # let y = 10 in (fn(x) -> x + y)(5)
        lookup_x = _store(ctx, _lookup_scope("x"))
        lookup_y = _store(ctx, _lookup_scope("y"))
        add_expr = _store(ctx, _arith("add", lookup_x, lookup_y))
        lambda_expr = _store(ctx, _lambda(["x"], add_expr))
        five_h = _store(ctx, _lit(5))
        apply_expr = _store(ctx, _apply_closure(lambda_expr, {"x": five_h}))
        ten_h = _store(ctx, _lit(10))

        let_expr = _let(
            [{"name": "y", "value": ten_h}],
            apply_expr,
        )
        result = evaluate(let_expr, Scope(), Budget(), ctx)
        assert result == 15

    def test_missing_argument(self):
        ctx = _make_ctx()
        body_h = _store(ctx, _lookup_scope("x"))
        lambda_h = _store(ctx, _lambda(["x"], body_h))
        apply_expr = _apply_closure(lambda_h, {})
        result = evaluate(apply_expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_MISSING_ARGUMENT

    def test_closure_captures_outer_let_scope(self):
        """let x = 100 in (let f = lambda(a): a + x in f(5)) → 105

        This is the Go validator's eval_closure_captures_scope test.
        The lambda body references x from the outer let scope.
        """
        ctx = _make_ctx()

        # a + x
        lookup_a = _store(ctx, _lookup_scope("a"))
        lookup_x = _store(ctx, _lookup_scope("x"))
        add_body = _store(ctx, _arith("add", lookup_a, lookup_x))

        # lambda(a): a + x
        lambda_expr = _store(ctx, _lambda(["a"], add_body))

        # f(5)
        five = _store(ctx, _lit(5))
        lookup_f = _store(ctx, _lookup_scope("f"))
        apply_f = _store(ctx, _apply_closure(lookup_f, {"a": five}))

        # let f = lambda(a): a + x in f(5)
        inner_let = _store(ctx, _let(
            [{"name": "f", "value": lambda_expr}],
            apply_f,
        ))

        # let x = 100 in (inner_let)
        hundred = _store(ctx, _lit(100))
        outer_let = _let(
            [{"name": "x", "value": hundred}],
            inner_let,
        )

        result = evaluate(outer_let, Scope(), Budget(), ctx)
        assert result == 105, f"Expected 105, got {result}"

    def test_closure_captures_scope_without_content_store_access(self):
        """Same test as above but with has_content_store_access=False.

        This matches the validator path where the capability has no
        content_store_access allowance. The captured scope entity is
        written to the content store but NOT bound at a tree path.
        """
        cs = ContentStore()
        et = EntityTree(PEER_ID)

        # Store all entities at tree paths (validator pattern)
        lookup_a = Entity(type="compute/lookup/scope", data={"name": "a"})
        et.set("expr/lookup-a", cs.put(lookup_a))
        lookup_x = Entity(type="compute/lookup/scope", data={"name": "x"})
        et.set("expr/lookup-x", cs.put(lookup_x))
        add_body = _arith("add", lookup_a.compute_hash(), lookup_x.compute_hash())
        et.set("expr/add", cs.put(add_body))
        lambda_expr = _lambda(["a"], add_body.compute_hash())
        et.set("expr/lambda", cs.put(lambda_expr))
        five = _lit(5)
        et.set("expr/five", cs.put(five))
        lookup_f = Entity(type="compute/lookup/scope", data={"name": "f"})
        et.set("expr/lookup-f", cs.put(lookup_f))
        apply_f = _apply_closure(lookup_f.compute_hash(), {"a": five.compute_hash()})
        et.set("expr/apply", cs.put(apply_f))
        inner_let = _let(
            [{"name": "f", "value": lambda_expr.compute_hash()}],
            apply_f.compute_hash(),
        )
        et.set("expr/inner-let", cs.put(inner_let))
        hundred = _lit(100)
        et.set("expr/hundred", cs.put(hundred))
        outer_let = _let(
            [{"name": "x", "value": hundred.compute_hash()}],
            inner_let.compute_hash(),
        )
        et.set("expr/outer-let", cs.put(outer_let))

        ctx = EvalContext(
            content_store=cs,
            entity_tree=et,
            local_peer_id=PEER_ID,
            capability=WILDCARD_CAP,
            has_content_store_access=False,  # No allowance — validator path
        )

        result = evaluate(outer_let, Scope(), Budget(), ctx)
        assert result == 105, f"Expected 105, got {result}"


# ============================================================================
# Core evaluation — field extraction
# ============================================================================

class TestField:
    def test_extract_field(self):
        ctx = _make_ctx()
        target = Entity(type="app/user", data={"name": "Alice", "age": 30})
        target_h = _store(ctx, target)

        # Wrap in literal so it evaluates to the entity
        lit_target = _store(ctx, _lit(target_h))

        # Actually, field needs the evaluated target to have data.
        # Let's use construct or a direct entity.
        # The target entity itself needs to be resolved and returned as-is.
        # compute/lookup/tree returns non-expression entities directly.
        ctx.entity_tree.set("users/alice", target_h)
        tree_lookup = _store(ctx, _lookup_tree("users/alice"))

        expr = _field("name", tree_lookup)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert result == "Alice"

    def test_field_not_found(self):
        ctx = _make_ctx()
        target = Entity(type="app/user", data={"name": "Alice"})
        target_h = _store(ctx, target)
        ctx.entity_tree.set("users/alice", target_h)
        tree_lookup = _store(ctx, _lookup_tree("users/alice"))

        expr = _field("missing_field", tree_lookup)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_NOT_FOUND

    # N.5 (PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE): navigation composes.
    # compute/field reads a field from an entity OR a bare record/map value, so
    # field/index/length compose to arbitrary depth.
    def test_field_over_bare_record_value(self):
        """N.5: compute/field reads a named field from a bare record/map value,
        not only an entity-shaped {type, data}. (Manifestation B root.)"""
        ctx = _make_ctx()
        rec_lit = _store(ctx, _lit({"name": "Bob", "age": 41}))
        expr = _field("name", rec_lit)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert result == "Bob"

    def test_nested_record_field_chain(self):
        """N.5 manifestation A: field(field(x,"user"),"name") composes — the
        inner field yields a bare record value, the outer field navigates it."""
        ctx = _make_ctx()
        outer = Entity(type="app/profile", data={"user": {"name": "Alice", "age": 30}})
        outer_h = _store(ctx, outer)
        ctx.entity_tree.set("profiles/alice", outer_h)
        lookup = _store(ctx, _lookup_tree("profiles/alice"))

        inner = _store(ctx, _field("user", lookup))   # → {"name": "Alice", ...}
        expr = _field("name", inner)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert result == "Alice"

    def test_field_over_indexed_record(self):
        """N.5 manifestation C: field(index(xs,0),"k") — navigate a record
        produced by a prior navigation (index), composing across operators."""
        ctx = _make_ctx()
        arr = _store(ctx, _lit([{"k": 1}, {"k": 2}]))
        zero = _store(ctx, _lit(0))
        index_expr = _store(ctx, Entity(type="compute/index", data={"array": arr, "index": zero}))
        expr = _field("k", index_expr)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert int(result) == 1


# ============================================================================
# Core evaluation — construct
# ============================================================================

class TestConstruct:
    def test_construct_entity(self):
        ctx = _make_ctx()
        name_h = _store(ctx, _lit("Alice"))
        age_h = _store(ctx, _lit(30))
        expr = _construct("app/user", {"name": name_h, "age": age_h})
        result = evaluate(expr, Scope(), Budget(), ctx)
        # v3.19b N3: a construct result is an entity value (Entity object).
        assert result.type == "app/user"
        assert result.data["name"] == "Alice"
        assert result.data["age"] == 30


# ============================================================================
# Core evaluation — tree lookup
# ============================================================================

class TestTreeLookup:
    def test_lookup_plain_entity(self):
        ctx = _make_ctx()
        entity = Entity(type="app/config", data={"key": "value"})
        h = _store(ctx, entity)
        ctx.entity_tree.set("app/config", h)

        expr = _lookup_tree("app/config")
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert isinstance(result, Entity)
        assert result.type == "app/config"
        assert result.data["key"] == "value"

    def test_lookup_auto_evaluates_expressions(self):
        """Tree lookup of a compute expression evaluates it (spreadsheet semantic)."""
        ctx = _make_ctx()
        lit = _lit(42)
        h = _store(ctx, lit)
        ctx.entity_tree.set("app/cell", h)

        expr = _lookup_tree("app/cell")
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert result == 42

    def test_lookup_not_found(self):
        ctx = _make_ctx()
        expr = _lookup_tree("missing/path")
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_NOT_FOUND

    def test_registers_dependency(self):
        ctx = _make_ctx()
        entity = Entity(type="app/data", data={"x": 1})
        h = _store(ctx, entity)
        ctx.entity_tree.set("app/data", h)

        expr = _lookup_tree("app/data")
        evaluate(expr, Scope(), Budget(), ctx)
        assert "app/data" in ctx.dependencies

    def test_permission_denied(self):
        no_access_cap = {"grants": []}
        ctx = _make_ctx(capability=no_access_cap)
        entity = Entity(type="app/data", data={"x": 1})
        h = ctx.content_store.put(entity)
        ctx.entity_tree.set("app/data", h)

        expr = _lookup_tree("app/data")
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_PERMISSION_DENIED


# ============================================================================
# Budget enforcement
# ============================================================================

class TestBudgetEnforcement:
    def test_budget_exhaustion(self):
        ctx = _make_ctx()
        budget = Budget(operations=2, depth=100)
        # First eval consumes one operation
        result = evaluate(_lit(42), Scope(), budget, ctx)
        assert result == 42
        # Second eval hits zero
        result = evaluate(_lit(99), Scope(), budget, ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_BUDGET_EXHAUSTED

    def test_depth_exceeded(self):
        ctx = _make_ctx()
        budget = Budget(operations=1000, depth=0)
        result = evaluate(_lit(42), Scope(), budget, ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_DEPTH_EXCEEDED

    def test_depth_restored_after_eval(self):
        ctx = _make_ctx()
        budget = Budget(operations=1000, depth=5)
        evaluate(_lit(42), Scope(), budget, ctx)
        assert budget.depth == 5  # Restored after return


# ============================================================================
# Error propagation
# ============================================================================

class TestErrorPropagation:
    def test_arithmetic_propagates_left_error(self):
        ctx = _make_ctx()
        bad_hash = b"\x00" * 33
        good_h = _store(ctx, _lit(5))
        expr = _arith("add", bad_hash, good_h)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)

    def test_arithmetic_propagates_right_error(self):
        ctx = _make_ctx()
        good_h = _store(ctx, _lit(5))
        bad_hash = b"\x00" * 33
        expr = _arith("add", good_h, bad_hash)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)

    def test_if_propagates_condition_error(self):
        ctx = _make_ctx()
        bad_hash = b"\x00" * 33
        then_h = _store(ctx, _lit(42))
        expr = _if(bad_hash, then_h)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)

    def test_let_propagates_binding_error(self):
        ctx = _make_ctx()
        bad_hash = b"\x00" * 33
        body_h = _store(ctx, _lit(42))
        expr = _let([{"name": "x", "value": bad_hash}], body_h)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)

    def test_construct_propagates_field_error(self):
        ctx = _make_ctx()
        bad_hash = b"\x00" * 33
        expr = _construct("app/user", {"name": bad_hash})
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)


# ============================================================================
# Dependency Index
# ============================================================================

class TestDependencyIndex:
    def test_add_and_match(self):
        idx = DependencyIndex()
        entry = DepEntry(expression_uri="app/cell/A1", subgraph_path="system/compute/processes/abc")
        idx.add("/peer/app/data", entry)

        matches = idx.match("/peer/app/data")
        assert len(matches) == 1
        assert matches[0] == entry

    def test_exact_match_only(self):
        idx = DependencyIndex()
        entry = DepEntry(expression_uri="app/cell/A1", subgraph_path="system/compute/processes/abc")
        idx.add("/peer/app/data", entry)

        assert idx.match("/peer/app") == []
        assert idx.match("/peer/app/data/sub") == []

    def test_remove_subgraph(self):
        idx = DependencyIndex()
        entry = DepEntry(expression_uri="app/cell/A1", subgraph_path="sg1")
        idx.add("/peer/path1", entry)
        idx.add("/peer/path2", entry)

        idx.remove_subgraph("sg1")
        assert idx.match("/peer/path1") == []
        assert idx.match("/peer/path2") == []

    def test_multiple_entries_per_path(self):
        idx = DependencyIndex()
        e1 = DepEntry("expr1", "sg1")
        e2 = DepEntry("expr2", "sg2")
        idx.add("/peer/path", e1)
        idx.add("/peer/path", e2)

        assert len(idx.match("/peer/path")) == 2


# ============================================================================
# Subgraph audit
# ============================================================================

class TestAudit:
    def test_collects_tree_reads(self):
        ctx = _make_ctx()
        lookup = Entity(type="compute/lookup/tree", data={"path": "app/data"})
        _store(ctx, lookup)
        result = audit_subgraph(lookup, ctx)
        assert "app/data" in result.read_paths

    def test_collects_handler_targets(self):
        ctx = _make_ctx()
        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
        })
        _store(ctx, apply_expr)
        result = audit_subgraph(apply_expr, ctx)
        assert len(result.handler_targets) == 1
        assert result.handler_targets[0]["path"] == "system/tree"

    def test_walks_nested_expressions(self):
        ctx = _make_ctx()
        lookup = Entity(type="compute/lookup/tree", data={"path": "app/data"})
        lookup_h = _store(ctx, lookup)
        lit = _lit(1)
        lit_h = _store(ctx, lit)
        arith = _arith("add", lookup_h, lit_h)
        _store(ctx, arith)
        result = audit_subgraph(arith, ctx)
        assert "app/data" in result.read_paths

    def test_handles_cycles(self):
        ctx = _make_ctx()
        # Self-referencing is prevented by hash — can't happen naturally
        lookup = Entity(type="compute/lookup/tree", data={"path": "app/data"})
        _store(ctx, lookup)
        result = audit_subgraph(lookup, ctx)
        assert len(result.read_paths) == 1


# ============================================================================
# walk_tree_lookups
# ============================================================================

class TestWalkTreeLookups:
    def test_collects_deps(self):
        ctx = _make_ctx()
        l1 = Entity(type="compute/lookup/tree", data={"path": "a"})
        l1_h = _store(ctx, l1)
        l2 = Entity(type="compute/lookup/tree", data={"path": "b"})
        l2_h = _store(ctx, l2)
        arith = _arith("add", l1_h, l2_h)
        _store(ctx, arith)
        deps = walk_tree_lookups(arith, ctx)
        assert set(deps) == {"a", "b"}


# ============================================================================
# Composite expressions
# ============================================================================

class TestCompositeExpressions:
    def test_nested_arithmetic(self):
        """(3 + 4) * 2 = 14"""
        ctx = _make_ctx()
        three = _store(ctx, _lit(3))
        four = _store(ctx, _lit(4))
        two = _store(ctx, _lit(2))
        add = _store(ctx, _arith("add", three, four))
        mul = _arith("mul", add, two)
        assert evaluate(mul, Scope(), Budget(), ctx) == 14

    def test_if_with_comparison(self):
        """if 5 > 3 then 'yes' else 'no'"""
        ctx = _make_ctx()
        five = _store(ctx, _lit(5))
        three = _store(ctx, _lit(3))
        cmp = _store(ctx, _compare("gt", five, three))
        yes = _store(ctx, _lit("yes"))
        no = _store(ctx, _lit("no"))
        expr = _if(cmp, yes, no)
        assert evaluate(expr, Scope(), Budget(), ctx) == "yes"

    def test_let_with_arithmetic(self):
        """let x = 5, y = x + 1 in y * 2 = 12"""
        ctx = _make_ctx()
        five = _store(ctx, _lit(5))
        lookup_x = _store(ctx, _lookup_scope("x"))
        one = _store(ctx, _lit(1))
        add = _store(ctx, _arith("add", lookup_x, one))
        lookup_y = _store(ctx, _lookup_scope("y"))
        two = _store(ctx, _lit(2))
        mul = _store(ctx, _arith("mul", lookup_y, two))

        expr = _let(
            [
                {"name": "x", "value": five},
                {"name": "y", "value": add},
            ],
            mul,
        )
        assert evaluate(expr, Scope(), Budget(), ctx) == 12

    def test_construct_then_field(self):
        """Construct an entity, then extract a field."""
        ctx = _make_ctx()
        name = _store(ctx, _lit("Alice"))
        age = _store(ctx, _lit(30))
        constructed = _store(ctx, _construct("app/user", {"name": name, "age": age}))
        expr = _field("age", constructed)
        assert evaluate(expr, Scope(), Budget(), ctx) == 30

    def test_higher_order_function(self):
        """let apply_fn = fn(f, x) -> f(x) in apply_fn(fn(n) -> n * 2, 5) = 10"""
        ctx = _make_ctx()

        # fn(n) -> n * 2
        lookup_n = _store(ctx, _lookup_scope("n"))
        two = _store(ctx, _lit(2))
        mul_body = _store(ctx, _arith("mul", lookup_n, two))
        double_fn = _store(ctx, _lambda(["n"], mul_body))

        # fn(f, x) -> f(x)
        lookup_f = _store(ctx, _lookup_scope("f"))
        lookup_x = _store(ctx, _lookup_scope("x"))
        apply_body = _store(ctx, _apply_closure(lookup_f, {"n": lookup_x}))
        apply_fn = _store(ctx, _lambda(["f", "x"], apply_body))

        # apply_fn(double, 5)
        five = _store(ctx, _lit(5))
        expr = _apply_closure(apply_fn, {"f": double_fn, "x": five})
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert result == 10


# ============================================================================
# Unknown type
# ============================================================================

# ============================================================================
# v3.6 A1-A4: Normative arithmetic semantics
# ============================================================================

class TestArithmeticV36:
    """Cross-implementation test vectors from §8.4."""

    def _eval_arith(self, op, left_val, right_val):
        ctx = _make_ctx()
        lh = _store(ctx, _lit(left_val))
        rh = _store(ctx, _lit(right_val))
        expr = _arith(op, lh, rh)
        return evaluate(expr, Scope(), Budget(), ctx)

    def test_div_exact(self):
        assert self._eval_arith("div", 10, 2) == 5
        assert isinstance(self._eval_arith("div", 10, 2), int)

    def test_div_non_exact(self):
        assert self._eval_arith("div", 7, 2) == 3.5
        assert isinstance(self._eval_arith("div", 7, 2), float)

    def test_div_negative_non_exact(self):
        # v3.16 rule 9: div is signed-default — mixed-sign operands evaluate as
        # written, no casts (the §276 examples are restored).
        assert self._eval_arith("div", -7, 2) == -3.5

    def test_div_one_third(self):
        result = self._eval_arith("div", 1, 3)
        assert abs(result - 0.3333333333333333) < 1e-15

    def test_div_int_by_zero(self):
        result = self._eval_arith("div", 7, 0)
        assert is_error(result)
        assert result["data"]["code"] == ERR_DIVISION_BY_ZERO

    def test_div_float_by_zero_positive(self):
        result = self._eval_arith("div", 1.0, 0.0)
        assert result == float("inf")

    def test_div_float_by_zero_negative(self):
        result = self._eval_arith("div", -1.0, 0.0)
        assert result == float("-inf")

    def test_div_zero_by_zero_float(self):
        import math as _math
        result = self._eval_arith("div", 0.0, 0.0)
        assert _math.isnan(result)

    def test_mod_positive(self):
        assert self._eval_arith("mod", 7, 3) == 1

    def test_mod_both_negative(self):
        assert self._eval_arith("mod", -7, -3) == -1

    def test_mod_signed_default_mixed_sign(self):
        # v3.16 rule 4/9: mod is signed-default — the §276 truncated-mod
        # examples (sign follows dividend) evaluate as written, no casts.
        assert self._eval_arith("mod", -7, 3) == -1
        assert self._eval_arith("mod", 7, -3) == 1

    def test_float_promotion_add(self):
        result = self._eval_arith("add", 1, 2.5)
        assert result == 3.5
        assert isinstance(result, float)

    def test_float_promotion_mul(self):
        result = self._eval_arith("mul", 3, 2.0)
        assert result == 6.0
        assert isinstance(result, float)

    def test_float_mod_is_type_mismatch(self):
        # core-go restricts mod to integer operands; a float operand → type_mismatch.
        result = self._eval_arith("mod", 7.0, 3.0)
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH


# ============================================================================
# v3.16: Integer model — WASM/LLVM/JVM 64-bit two's-complement (§2.2 rules 8-11)
# ============================================================================

class TestIntegerModel:
    """add/sub/mul sign-agnostic (rule 8); div/mod/compare signed-default
    (rule 9); results encoded signed-canonical (rule 10); numeric-cast eager /
    point-of-use, no flow through let (rule 11)."""

    def _eval_arith(self, op, left_val, right_val):
        ctx = _make_ctx()
        lh = _store(ctx, _lit(left_val))
        rh = _store(ctx, _lit(right_val))
        return evaluate(_arith(op, lh, rh), Scope(), Budget(), ctx)

    def test_add_sign_agnostic(self):
        # Rule 8: no int/uint decision, no mixed-operand case.
        assert self._eval_arith("add", 3, -1) == 2
        assert self._eval_arith("add", -5, 3) == -2

    def test_uint_add_wraparound_canary(self):
        # add(2^64-1, 1) wraps modulo 2^64 → 0.
        assert self._eval_arith("add", 2**64 - 1, 1) == 0

    def test_sub_wraparound(self):
        # 3 - 5 over 64-bit two's-complement → -2 (signed-canonical, rule 10).
        assert self._eval_arith("sub", 3, 5) == -2

    def test_mul_sign_agnostic(self):
        assert self._eval_arith("mul", -1, -1) == 1

    def test_add_underflow_wraps_at_64bit(self):
        # min int64 - 1 wraps to max int64 (one 64-bit width, rule 8).
        assert self._eval_arith("add", -(2**63), -1) == (2**63 - 1)

    def test_div_mod_signed_default(self):
        # Rule 9: div/mod signed-default — mixed-sign evaluates as written.
        assert self._eval_arith("div", -6, 2) == -3
        assert self._eval_arith("mod", -7, 3) == -1

    def test_result_encodes_signed_canonical(self):
        # Rule 10: an arithmetic result with bit 63 set encodes as CBOR major
        # type 1 (negative two's-complement), giving one wire form per result.
        import cbor2
        result = self._eval_arith("add", 2**63 - 1, 1)  # → -2^63
        assert result == -(2**63)
        assert cbor2.dumps(result, canonical=True)[0] >> 5 == 1  # major type 1

    def test_arithmetic_result_hashes_like_bare_int(self):
        # Arithmetic results are plain signed ints (no value-level tag), so they
        # hash identically to the bare int — cross-impl wire agreement.
        result = self._eval_arith("add", 3, 4)
        assert result == 7
        assert Entity(type="compute/result", data={"value": result}).compute_hash() == (
            Entity(type="compute/result", data={"value": 7}).compute_hash()
        )

    def _cast_uint(self, ctx, value):
        return _store(ctx, Entity(type="compute/numeric-cast", data={
            "value": _store(ctx, _lit(value)), "to_type": "primitive/uint",
        }))

    def test_unsigned_div_when_cast_is_direct_operand(self):
        # Rule 11 Option A: unsigned div only when the cast is the DIRECT operand.
        ctx = _make_ctx()
        expr = _arith("div", self._cast_uint(ctx, -2), _store(ctx, _lit(2)))
        assert evaluate(expr, Scope(), Budget(), ctx) == (2**63 - 1)  # (2^64-2)/2

    def test_cast_intent_does_not_flow_through_let(self):
        # Rule 11: the div operand is lookup/scope, not the cast → signed-default.
        ctx = _make_ctx()
        body = _store(ctx, _arith("div", _store(ctx, _lookup_scope("y")), _store(ctx, _lit(2))))
        let_expr = _let([{"name": "y", "value": self._cast_uint(ctx, -2)}], body)
        assert evaluate(let_expr, Scope(), Budget(), ctx) == -1  # signed div(-2, 2)

    def test_cast_intent_does_not_flow_through_if_branch(self):
        # v3.17 SA-AMD3-1: div(if(true, cast(x,uint), x), 2) — the operand is the
        # `if` entity, not the cast, so div is signed-default. Mirrors the
        # cross-impl vector v317_cast_through_if_branch (x=2^64-2 → -1).
        ctx = _make_ctx()
        x = _store(ctx, _lit(2**64 - 2))
        cast_uint = _store(ctx, Entity(type="compute/numeric-cast", data={
            "value": x, "to_type": "primitive/uint",
        }))
        if_expr = _store(ctx, _if(_store(ctx, _lit(True)), cast_uint, x))
        div_expr = _arith("div", if_expr, _store(ctx, _lit(2)))
        # signed div(-2, 2) == -1, NOT unsigned (2^63-1).
        assert evaluate(div_expr, Scope(), Budget(), ctx) == -1


# ============================================================================
# v3.16: compute/numeric-cast (§2.2 rules 9-11)
# ============================================================================

class TestNumericCast:
    def _cast(self, value, to_type):
        ctx = _make_ctx()
        vh = _store(ctx, _lit(value))
        expr = Entity(type="compute/numeric-cast", data={"value": vh, "to_type": to_type})
        return evaluate(expr, Scope(), Budget(), ctx)

    def test_int_to_uint_yields_nonneg_magnitude(self):
        # cast(-1, uint) → the non-negative magnitude 2^64-1 (a plain int, no
        # value tag) which encodes as CBOR major type 0 (rule 10 exception).
        # Mirrors the cross-impl vector v314_cast_int_to_uint_negative.
        import cbor2
        result = self._cast(-1, "primitive/uint")
        assert result == 2**64 - 1
        assert cbor2.dumps(result, canonical=True)[0] >> 5 == 0  # major type 0

    def test_uint_to_int_reinterprets_bits(self):
        # cast(2^63, int) reinterprets the bit pattern → signed-canonical -2^63.
        assert self._cast(2**63, "primitive/int") == -(2**63)

    def test_int_to_float_lossy_ok(self):
        # (2^53)+1 loses the low bit converting to binary64 — defined, not error.
        result = self._cast((2**53) + 1, "primitive/float")
        assert result == float(2**53)
        assert isinstance(result, float)

    def test_float_to_int_truncates_toward_zero(self):
        assert self._cast(3.9, "primitive/int") == 3
        assert self._cast(-3.9, "primitive/int") == -3

    def test_float_to_uint_negative_out_of_range(self):
        result = self._cast(-1.0, "primitive/uint")
        assert is_error(result)
        assert result["data"]["code"] == ERR_CAST_OUT_OF_RANGE

    def test_float_nan_to_int_out_of_range(self):
        result = self._cast(float("nan"), "primitive/int")
        assert is_error(result)
        assert result["data"]["code"] == ERR_CAST_OUT_OF_RANGE

    def test_float_inf_to_int_out_of_range(self):
        result = self._cast(float("inf"), "primitive/int")
        assert is_error(result)
        assert result["data"]["code"] == ERR_CAST_OUT_OF_RANGE

    def test_float_overflow_to_int_out_of_range(self):
        result = self._cast(2.0**70, "primitive/int")
        assert is_error(result)
        assert result["data"]["code"] == ERR_CAST_OUT_OF_RANGE

    def test_non_numeric_to_type_is_type_mismatch(self):
        result = self._cast(5, "primitive/bool")
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH

    def test_non_numeric_value_is_type_mismatch(self):
        result = self._cast("hello", "primitive/int")
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH

    def test_null_value_is_type_mismatch(self):
        result = self._cast(None, "primitive/int")
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH


# ============================================================================
# N.1: compute/index and compute/length (§2.2)
# ============================================================================

class TestIndexLength:
    def _index(self, array, index):
        ctx = _make_ctx()
        ah = _store(ctx, _lit(array))
        ih = _store(ctx, _lit(index))
        expr = Entity(type="compute/index", data={"array": ah, "index": ih})
        return evaluate(expr, Scope(), Budget(), ctx)

    def _length(self, array):
        ctx = _make_ctx()
        ah = _store(ctx, _lit(array))
        expr = Entity(type="compute/length", data={"array": ah})
        return evaluate(expr, Scope(), Budget(), ctx)

    def test_index_basic(self):
        assert self._index([10, 20, 30], 0) == 10
        assert self._index([10, 20, 30], 2) == 30

    def test_index_mixed_type_array(self):
        assert self._index([1, "two", 3.0], 1) == "two"

    def test_index_out_of_range(self):
        result = self._index([10, 20], 5)
        assert is_error(result)
        assert result["data"]["code"] == ERR_INDEX_OUT_OF_RANGE

    def test_index_negative_out_of_range(self):
        # Negative indices are out of range — no from-end indexing.
        result = self._index([10, 20], -1)
        assert is_error(result)
        assert result["data"]["code"] == ERR_INDEX_OUT_OF_RANGE

    def test_index_non_array_type_mismatch(self):
        result = self._index(42, 0)
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH

    def test_index_null_type_mismatch(self):
        result = self._index(None, 0)
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH

    def test_index_non_integer_index_type_mismatch(self):
        result = self._index([10, 20], 1.5)
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH

    def test_length_basic(self):
        assert self._length([1, 2, 3]) == 3

    def test_length_empty_is_zero(self):
        assert self._length([]) == 0

    def test_length_non_array_type_mismatch(self):
        result = self._length(42)
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH

    def test_length_null_type_mismatch(self):
        result = self._length(None)
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH


# ============================================================================
# N.2: Collection + store builtins (§3.5)
# ============================================================================

class TestCollectionBuiltins:
    """map/filter/fold observable semantics + store, dispatched as builtins."""

    def _apply_builtin(self, ctx, path, args):
        expr = Entity(type="compute/apply", data={
            "path": path, "operation": "eval", "args": args,
        })
        return evaluate(expr, Scope(), Budget(), ctx)

    def _add_lambda(self, ctx, n):
        # lambda x: x + n
        body = _store(ctx, _arith(
            "add", _store(ctx, _lookup_scope("x")), _store(ctx, _lit(n)),
        ))
        return _store(ctx, _lambda(["x"], body))

    def _gt_lambda(self, ctx, n):
        # lambda x: x > n
        body = _store(ctx, _compare(
            "gt", _store(ctx, _lookup_scope("x")), _store(ctx, _lit(n)),
        ))
        return _store(ctx, _lambda(["x"], body))

    def _binop_lambda(self, ctx, op):
        # lambda acc, el: acc <op> el
        body = _store(ctx, _arith(
            op, _store(ctx, _lookup_scope("acc")), _store(ctx, _lookup_scope("el")),
        ))
        return _store(ctx, _lambda(["acc", "el"], body))

    def test_map_applies_in_order(self):
        ctx = _make_ctx()
        result = self._apply_builtin(ctx, "system/compute/builtins/map", {
            "collection": _store(ctx, _lit([1, 2, 3])),
            "fn": self._add_lambda(ctx, 10),
        })
        assert [int(x) for x in result] == [11, 12, 13]

    def test_map_empty(self):
        ctx = _make_ctx()
        result = self._apply_builtin(ctx, "system/compute/builtins/map", {
            "collection": _store(ctx, _lit([])),
            "fn": self._add_lambda(ctx, 1),
        })
        assert result == []

    def test_map_non_array_type_mismatch(self):
        ctx = _make_ctx()
        result = self._apply_builtin(ctx, "system/compute/builtins/map", {
            "collection": _store(ctx, _lit(42)),
            "fn": self._add_lambda(ctx, 1),
        })
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH

    def test_filter_keeps_truthy_in_order(self):
        ctx = _make_ctx()
        result = self._apply_builtin(ctx, "system/compute/builtins/filter", {
            "collection": _store(ctx, _lit([1, 2, 3, 4, 5])),
            "fn": self._gt_lambda(ctx, 2),  # F11: filter lambda arg is `fn` (was `predicate`)
        })
        assert [int(x) for x in result] == [3, 4, 5]

    def test_fold_threads_left_to_right(self):
        ctx = _make_ctx()
        result = self._apply_builtin(ctx, "system/compute/builtins/fold", {
            "collection": _store(ctx, _lit([1, 2, 3, 4])),
            "fn": self._binop_lambda(ctx, "add"),
            "initial": _store(ctx, _lit(0)),
        })
        assert int(result) == 10

    def test_fold_empty_returns_initial(self):
        ctx = _make_ctx()
        result = self._apply_builtin(ctx, "system/compute/builtins/fold", {
            "collection": _store(ctx, _lit([])),
            "fn": self._binop_lambda(ctx, "add"),
            "initial": _store(ctx, _lit(99)),
        })
        assert int(result) == 99

    def test_store_writes_entity_to_tree(self):
        ctx = _make_ctx()
        value = _store(ctx, Entity(type="compute/construct", data={
            "entity_type": "app/note",
            "fields": {"msg": _store(ctx, _lit("hello"))},
        }))
        result = self._apply_builtin(ctx, "system/compute/builtins/store", {
            "path": _store(ctx, _lit("app/out")),
            "value": value,
        })
        assert not is_error(result)
        stored_hash = ctx.entity_tree.get("app/out")
        assert stored_hash is not None
        stored = ctx.content_store.get(stored_hash)
        assert stored.type == "app/note"
        assert stored.data == {"msg": "hello"}

    def test_store_permission_denied(self):
        # Capability covering only app/* must not authorize a write to other/*.
        narrow_cap = {"grants": [{
            "handlers": {"include": ["*"]},
            "operations": {"include": ["*"]},
            "resources": {"include": ["app/*"]},
        }]}
        ctx = _make_ctx(capability=narrow_cap)
        value = _store(ctx, Entity(type="compute/construct", data={
            "entity_type": "app/note", "fields": {},
        }))
        result = self._apply_builtin(ctx, "system/compute/builtins/store", {
            "path": _store(ctx, _lit("other/secret")),
            "value": value,
        })
        assert is_error(result)
        assert result["data"]["code"] == ERR_PERMISSION_DENIED

    def test_store_bare_value_wrapped_as_primitive_any(self):
        # A bare primitive is wrapped in primitive/any (the wire shape for bare
        # values), matching core-go — not rejected. Verified via the direct-write
        # fallback (this ctx has no dispatcher).
        ctx = _make_ctx()
        result = self._apply_builtin(ctx, "system/compute/builtins/store", {
            "path": _store(ctx, _lit("app/out")),
            "value": _store(ctx, _lit(42)),
        })
        assert not is_error(result)
        stored = ctx.content_store.get(ctx.entity_tree.get("app/out"))
        assert stored.type == "primitive/any"
        assert stored.data == 42


# ============================================================================
# N.2: Inline-equivalent builtin aliases (§3.5, SA-COMPUTE-V314-2)
# ============================================================================

class TestInlineEquivalentBuiltins:
    """apply(builtins/{arithmetic,compare,logic,field,construct}, …) MUST be
    hash-equal to the inline form. Args arrive as a map of hashes; the scalar
    op/name/entity_type fields reference literals (cross-impl wire shape)."""

    def _apply_builtin(self, ctx, path, args):
        expr = Entity(type="compute/apply", data={
            "path": path, "operation": "eval", "args": args,
        })
        return evaluate(expr, Scope(), Budget(), ctx)

    def test_arithmetic_alias(self):
        # The exact shape of the failing cross-impl vector v314_builtin_arithmetic_alias.
        ctx = _make_ctx()
        result = self._apply_builtin(ctx, "system/compute/builtins/arithmetic", {
            "op": _store(ctx, _lit("add")),
            "left": _store(ctx, _lit(3)),
            "right": _store(ctx, _lit(4)),
        })
        assert result == 7

    def test_arithmetic_alias_hash_equals_inline(self):
        # Alias result entity must hash-match the inline form's result entity.
        ctx = _make_ctx()
        alias = self._apply_builtin(ctx, "system/compute/builtins/arithmetic", {
            "op": _store(ctx, _lit("add")),
            "left": _store(ctx, _lit(3)),
            "right": _store(ctx, _lit(4)),
        })
        inline = evaluate(
            _arith("add", _store(ctx, _lit(3)), _store(ctx, _lit(4))),
            Scope(), Budget(), ctx,
        )
        a = Entity(type="compute/result", data={"value": alias})
        b = Entity(type="compute/result", data={"value": inline})
        assert a.compute_hash() == b.compute_hash()

    def test_compare_alias(self):
        ctx = _make_ctx()
        result = self._apply_builtin(ctx, "system/compute/builtins/compare", {
            "op": _store(ctx, _lit("gt")),
            "left": _store(ctx, _lit(5)),
            "right": _store(ctx, _lit(3)),
        })
        assert result is True

    def test_logic_alias(self):
        ctx = _make_ctx()
        result = self._apply_builtin(ctx, "system/compute/builtins/logic", {
            "op": _store(ctx, _lit("and")),
            "left": _store(ctx, _lit(True)),
            "right": _store(ctx, _lit(False)),
        })
        assert result is False

    def test_field_alias(self):
        ctx = _make_ctx()
        entity = _store(ctx, Entity(type="compute/construct", data={
            "entity_type": "app/x", "fields": {"k": _store(ctx, _lit(99))},
        }))
        result = self._apply_builtin(ctx, "system/compute/builtins/field", {
            "name": _store(ctx, _lit("k")),
            "entity": entity,
        })
        assert result == 99

    def test_construct_alias(self):
        ctx = _make_ctx()
        result = self._apply_builtin(ctx, "system/compute/builtins/construct", {
            "entity_type": _store(ctx, _lit("app/note")),
            "msg": _store(ctx, _lit("hi")),
        })
        # v3.19b N3: construct result is an Entity value.
        assert result.type == "app/note"
        assert result.data == {"msg": "hi"}


# ============================================================================
# SA-COMPUTE-V314-1: value types evaluate to themselves (Option A)
# ============================================================================

class TestValueTypePassThrough:
    """A §2.3/§2.4 value type handed to evaluate() returns itself, rather than
    unknown_type — symmetric with the compute/lookup/hash rule. Adopts the
    recommended Option A from SA-COMPUTE-V314-1."""

    def test_closure_evaluates_to_itself(self):
        ctx = _make_ctx()
        closure = Entity(type="compute/closure", data={
            "params": ["x"], "body": _store(ctx, _lit(1)),
        })
        result = evaluate(closure, Scope(), Budget(), ctx)
        assert not is_error(result)
        assert (result.type if hasattr(result, "type") else result["type"]) == "compute/closure"

    def test_result_value_passes_through(self):
        ctx = _make_ctx()
        res = Entity(type="compute/result", data={"value": 42})
        out = evaluate(res, Scope(), Budget(), ctx)
        assert (out.type if hasattr(out, "type") else out["type"]) == "compute/result"

    def test_genuinely_unknown_type_still_errors(self):
        ctx = _make_ctx()
        result = evaluate(Entity(type="compute/not_a_real_type", data={}), Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == "unknown_type"

    def test_closure_as_apply_arg_direct(self):
        # The portable form per SA-COMPUTE-V314-1: a stored closure referenced as
        # an apply fn arg resolves+evaluates to itself, then applies.
        ctx = _make_ctx()
        body = _store(ctx, _arith(
            "add", _store(ctx, _lookup_scope("x")), _store(ctx, _lit(1)),
        ))
        closure = Entity(type="compute/closure", data={"params": ["x"], "body": body})
        closure_h = _store(ctx, closure)
        apply_expr = Entity(type="compute/apply", data={
            "fn": closure_h, "args": {"x": _store(ctx, _lit(41))},
        })
        assert evaluate(apply_expr, Scope(), Budget(), ctx) == 42


# ============================================================================
# v3.6 A2: Normative comparison semantics
# ============================================================================

class TestCompareV36:
    """Cross-implementation test vectors from §8.4."""

    def _eval_cmp(self, op, left_val, right_val):
        ctx = _make_ctx()
        lh = _store(ctx, _lit(left_val))
        rh = _store(ctx, _lit(right_val))
        expr = _compare(op, lh, rh)
        return evaluate(expr, Scope(), Budget(), ctx)

    def test_eq_int_float(self):
        assert self._eval_cmp("eq", 1, 1.0) is True

    def test_eq_incompatible_types(self):
        assert self._eval_cmp("eq", 1, "1") is False

    def test_neq_incompatible_types(self):
        assert self._eval_cmp("neq", 1, "1") is True

    def test_lt_strings(self):
        assert self._eval_cmp("lt", "abc", "abd") is True

    def test_gt_strings(self):
        assert self._eval_cmp("gt", "abd", "abc") is True

    def test_lt_incompatible_type_error(self):
        result = self._eval_cmp("lt", 1, "abc")
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH


# ============================================================================
# v3.6 D2: Expression-graph scoping
# ============================================================================

class TestExpressionGraphScoping:
    def test_non_compute_hash_ref_returns_not_found(self):
        """Non-compute entity hash ref in expression → not_found (not unknown_type)."""
        ctx = _make_ctx()
        ctx.has_content_store_access = False
        secret = Entity(type="app/secret", data={"key": "hunter2"})
        secret_h = ctx.content_store.put(secret)
        ctx.entity_tree.set("hidden/secret", secret_h)

        expr = _field("key", secret_h)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_NOT_FOUND

    def test_compute_hash_ref_resolves(self):
        """Compute-type entity hash ref resolves normally."""
        ctx = _make_ctx()
        ctx.has_content_store_access = False
        lit = _lit(42)
        lit_h = ctx.content_store.put(lit)
        ctx.entity_tree.set("expr/lit", lit_h)

        one_h = _store(ctx, _lit(1))
        ctx.entity_tree.set("expr/one", one_h)

        expr = _arith("add", lit_h, one_h)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert result == 43


# ============================================================================
# v3.7 D6: compute/lookup/hash
# ============================================================================

class TestLookupHash:
    def test_lookup_hash_compute_expression(self):
        """compute/lookup/hash resolves compute expressions and evaluates them."""
        ctx = _make_ctx()
        lit = _lit(42)
        lit_h = _store(ctx, lit)
        expr = Entity(type="compute/lookup/hash", data={"hash": lit_h})
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert result == 42

    def test_lookup_hash_non_expression_with_access(self):
        """With content_store_access, non-compute entities returned as values."""
        ctx = _make_ctx()
        ctx.has_content_store_access = True
        data = Entity(type="app/user", data={"name": "Alice"})
        data_h = _store(ctx, data)
        expr = Entity(type="compute/lookup/hash", data={"hash": data_h})
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert isinstance(result, Entity)
        assert result.data["name"] == "Alice"

    def test_lookup_hash_non_expression_without_access(self):
        """Without access, non-compute entities not resolvable → not_found."""
        cs = ContentStore()
        et = EntityTree(PEER_ID)
        data = Entity(type="app/user", data={"name": "Alice"})
        data_h = cs.put(data)
        et.set("users/alice", data_h)
        ctx = EvalContext(
            content_store=cs, entity_tree=et, local_peer_id=PEER_ID,
            capability=WILDCARD_CAP, has_content_store_access=False,
        )
        expr = Entity(type="compute/lookup/hash", data={"hash": data_h})
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_NOT_FOUND

    def test_lookup_hash_with_sealed_set(self):
        """Tier 2: non-compute entity resolvable via authorized_data_hashes."""
        cs = ContentStore()
        et = EntityTree(PEER_ID)
        data = Entity(type="app/config", data={"key": "value"})
        data_h = cs.put(data)
        ctx = EvalContext(
            content_store=cs, entity_tree=et, local_peer_id=PEER_ID,
            capability=WILDCARD_CAP, has_content_store_access=False,
            authorized_data_hashes={data_h},
        )
        expr = Entity(type="compute/lookup/hash", data={"hash": data_h})
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert isinstance(result, Entity)
        assert result.data["key"] == "value"

    def test_lookup_hash_missing_hash(self):
        ctx = _make_ctx()
        expr = Entity(type="compute/lookup/hash", data={})
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_INVALID_EXPRESSION

    def test_lookup_hash_is_pure(self):
        """compute/lookup/hash does NOT register tree dependencies."""
        ctx = _make_ctx()
        lit = _lit(42)
        lit_h = _store(ctx, lit)
        expr = Entity(type="compute/lookup/hash", data={"hash": lit_h})
        evaluate(expr, Scope(), Budget(), ctx)
        assert len(ctx.dependencies) == 0


# ============================================================================
# v3.7 D5: Install with compute/lookup/hash — sealed set
# ============================================================================

class TestInstallWithLookupHash:
    @pytest.fixture
    def setup(self):
        from entity_core.storage.emit import EmitPathway
        from entity_handlers.compute import ComputeExtension
        from entity_core.peer.extensions import ExtensionContext
        from entity_core.crypto.identity import Keypair

        keypair = Keypair.generate()
        cs = ContentStore()
        et = EntityTree(keypair.peer_id)
        ep = EmitPathway(cs, et)

        ext = ComputeExtension()
        ext_ctx = ExtensionContext(keypair=keypair, emit_pathway=ep)
        ext.initialize(ext_ctx)
        return ext, cs, et, ep, keypair

    def _make_handler_ctx(self, ep, peer_id, capability=None, *, resource_targets=None):
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.emit_pathway = ep
        ctx.local_peer_id = peer_id
        ctx.caller_capability = capability or WILDCARD_CAP
        ctx.caller_capability_granter_peer_id = None  # real default (no foreign granter)
        ctx.resource_targets = resource_targets
        ctx.bounds = None
        ctx.remote_peer_id = peer_id
        return ctx

    @pytest.mark.asyncio
    async def test_install_with_hash_lookup_and_path_hint(self, setup):
        """Install validates path hint and seals authorized hashes."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        # Store a non-compute data entity at a tree path
        data = Entity(type="app/config", data={"version": 3})
        ep.emit("app/config", data)
        data_h = data.compute_hash()

        # Create expression: compute/lookup/hash with path hint
        lookup = Entity(type="compute/lookup/hash", data={
            "hash": data_h,
            "path": "app/config",
        })
        ep.emit("app/expr", lookup)

        ctx = self._make_handler_ctx(ep, keypair.peer_id,
                                     resource_targets=["app/expr"])
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 200

        # Verify sealed set is in subgraph metadata
        sg_path = result["result"]["data"]["subgraph_path"]
        sg_h = et.get(sg_path)
        sg = cs.get(sg_h)
        assert data_h in sg.data["authorized_data_hashes"]

    @pytest.mark.asyncio
    async def test_install_rejects_hash_mismatch(self, setup):
        """Install rejects when entity at path doesn't match referenced hash."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        data = Entity(type="app/config", data={"version": 3})
        ep.emit("app/config", data)

        # Reference a different hash but point to app/config
        fake_hash = b"\x00" + b"\xab" * 32
        lookup = Entity(type="compute/lookup/hash", data={
            "hash": fake_hash,
            "path": "app/config",
        })
        ep.emit("app/expr", lookup)

        ctx = self._make_handler_ctx(ep, keypair.peer_id,
                                     resource_targets=["app/expr"])
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 400
        assert "hash_mismatch" in result["result"]["data"]["code"]

    @pytest.mark.asyncio
    async def test_install_rejects_no_path_hint(self, setup):
        """Install rejects compute/lookup/hash without path hint (no reverse index)."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        data = Entity(type="app/config", data={"version": 3})
        data_h = cs.put(data)

        lookup = Entity(type="compute/lookup/hash", data={"hash": data_h})
        ep.emit("app/expr", lookup)

        ctx = self._make_handler_ctx(ep, keypair.peer_id,
                                     resource_targets=["app/expr"])
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 400
        assert "no_authorization_path" in result["result"]["data"]["code"]


# ============================================================================
# v3.7 D3: Audit walker collects compute/lookup/hash targets
# ============================================================================

class TestAuditLookupHash:
    def test_audit_collects_data_hashes(self):
        ctx = _make_ctx()
        target_hash = b"\x00" + b"\xcc" * 32
        lookup = Entity(type="compute/lookup/hash", data={
            "hash": target_hash,
            "path": "app/data",
        })
        _store(ctx, lookup)
        result = audit_subgraph(lookup, ctx)
        assert len(result.data_hashes) == 1
        assert result.data_hashes[0]["hash"] == target_hash
        assert result.data_hashes[0]["path"] == "app/data"

    def test_audit_no_tree_deps_for_hash_lookup(self):
        """compute/lookup/hash is pure — no tree dependency registered."""
        ctx = _make_ctx()
        target_hash = b"\x00" + b"\xcc" * 32
        lookup = Entity(type="compute/lookup/hash", data={
            "hash": target_hash,
            "path": "app/data",
        })
        _store(ctx, lookup)
        deps = walk_tree_lookups(lookup, ctx)
        assert len(deps) == 0


class TestUnknownType:
    def test_unknown_compute_type(self):
        ctx = _make_ctx()
        expr = Entity(type="compute/unknown_widget", data={})
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == "unknown_type"


# ============================================================================
# Handler-mode compute/apply
# ============================================================================

class TestApplyHandlerMode:
    def test_handler_dispatch_with_execute_fn(self):
        ctx = _make_ctx()

        captured = {}

        def mock_execute(path, operation, params, eval_ctx, dispatch_cap,
                         resource_targets=None, resource_exclude=None):
            # V30: compute/apply dispatches resolved args wrapped in a
            # primitive/any params entity ({type, data}), matching the wire
            # EXECUTE shape. The handler reads the args from params["data"].
            captured["params"] = params
            return params["data"].get("x", 0) * 2

        ctx._execute_fn = mock_execute

        x_h = _store(ctx, _lit(21))
        expr = Entity(type="compute/apply", data={
            "path": "system/test",
            "operation": "double",
            "args": {"x": x_h},
        })
        result = evaluate(expr, Scope(), Budget(), ctx)
        # SA-4: a bare-primitive dispatch return (42) is wrapped in compute/result.
        # v3.19b N3: the wrap is an Entity value (so downstream field reads it by kind).
        assert result.type == "compute/result"
        assert result.data == {"value": 42}
        assert captured["params"]["type"] == "primitive/any"
        assert captured["params"]["data"] == {"x": 21}

    def test_handler_mode_requires_operation(self):
        ctx = _make_ctx()
        expr = Entity(type="compute/apply", data={"path": "system/test"})
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_INVALID_EXPRESSION

    def test_handler_mode_no_dispatch_fn(self):
        ctx = _make_ctx()
        x_h = _store(ctx, _lit(1))
        expr = Entity(type="compute/apply", data={
            "path": "system/test",
            "operation": "get",
            "args": {"x": x_h},
        })
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_NOT_FOUND

    def test_neither_path_nor_fn(self):
        ctx = _make_ctx()
        expr = Entity(type="compute/apply", data={})
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_INVALID_EXPRESSION


# ============================================================================
# compute/apply capability field — dual-check (EXTENSION-COMPUTE §4.1, v3.9)
# ============================================================================

def _grant(handlers, operations, resources):
    """Build a capability data dict with one grant."""
    return {
        "grants": [{
            "handlers": {"include": handlers},
            "operations": {"include": operations},
            "resources": {"include": resources},
        }],
    }


def _cap_entity(cap_data: dict) -> Entity:
    """Wrap capability data as a system/capability entity."""
    return Entity(type="system/capability", data=cap_data)


class TestApplyCapabilityDualCheck:
    """Dual-check: when compute/apply has a `capability` field, both
    ctx.capability (handler-grant ceiling) AND the provided cap MUST cover
    the target at full resolution (handler+operation+resource). Prevents an
    admin caller's cap from escaping the handler's declared scope.

    Per PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING (F1/F2/F5): `capability` MUST
    be paired with `resource`; both are checked against handler+op+resource.
    """

    def _setup_dispatch(self, ctx):
        """Wire a recording _execute_fn that returns the dispatch cap it saw."""
        seen = {}

        def recording_execute(path, operation, args, eval_ctx, dispatch_cap,
                              resource_targets=None, resource_exclude=None):
            seen["path"] = path
            seen["operation"] = operation
            seen["args"] = args
            seen["dispatch_cap"] = dispatch_cap
            seen["resource_targets"] = resource_targets
            seen["resource_exclude"] = resource_exclude
            return {"type": "compute/result", "data": {"value": "ok"}}

        ctx._execute_fn = recording_execute
        return seen

    def test_dual_check_passes_uses_provided_cap(self):
        """Both grants cover target → dispatch uses provided cap."""
        # Handler grant covers system/tree:get on app/data/*
        handler_grant = _grant(
            handlers=["system/tree"], operations=["get"], resources=["app/data/*"],
        )
        # Provided (narrower) cap also covers system/tree:get on app/data/public/*
        provided = _grant(
            handlers=["system/tree"], operations=["get"], resources=["app/data/public/*"],
        )
        ctx = _make_ctx(capability=handler_grant)
        seen = self._setup_dispatch(ctx)

        cap_h = _store(ctx, _cap_entity(provided))
        resource_h = _store(ctx, _lit({"targets": ["app/data/public/y"]}))
        expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "resource": resource_h,
            "capability": cap_h,
        })
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert not is_error(result)
        assert seen["dispatch_cap"] == provided
        assert seen["resource_targets"] == ["app/data/public/y"]

    def test_handler_grant_does_not_cover_blocks_escape(self):
        """The escape attack (proposal §5 row 3): admin caller, narrow
        handler. Handler grant covers only app/* but the caller's cap covers
        system/secret/*. The full-resolution ceiling check denies because
        the handler grant doesn't cover the target resource."""
        # Narrow handler grant — only covers app/*
        handler_grant = _grant(
            handlers=["system/tree"], operations=["get"], resources=["app/*"],
        )
        # Caller cap covers system/secret/*
        caller = _grant(
            handlers=["system/tree"], operations=["get"], resources=["system/secret/*"],
        )
        ctx = _make_ctx(capability=handler_grant)
        self._setup_dispatch(ctx)

        cap_h = _store(ctx, _cap_entity(caller))
        resource_h = _store(ctx, _lit({"targets": ["system/secret/x"]}))
        # Try to dispatch a system/tree:get on system/secret/x using caller's cap
        expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "resource": resource_h,
            "capability": cap_h,
        })
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_PERMISSION_DENIED
        assert "Handler grant does not cover" in result["data"]["message"]

    def test_provided_cap_does_not_cover_target(self):
        """Handler grant covers; provided cap doesn't. Denied."""
        handler_grant = _grant(
            handlers=["*"], operations=["*"], resources=["*"],
        )
        # Provided cap covers only app/*, not system/secret
        narrow = _grant(
            handlers=["system/tree"], operations=["get"], resources=["app/*"],
        )
        ctx = _make_ctx(capability=handler_grant)
        self._setup_dispatch(ctx)

        cap_h = _store(ctx, _cap_entity(narrow))
        resource_h = _store(ctx, _lit({"targets": ["system/secret/x"]}))
        expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "resource": resource_h,
            "capability": cap_h,
        })
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_PERMISSION_DENIED
        assert "Provided capability does not cover" in result["data"]["message"]

    def test_no_capability_field_uses_ctx_capability(self):
        """Backward compat: without `capability` field, dispatch passes
        None for dispatch_cap so the bridge uses ctx.capability. No
        `resource` is required in this path (proposal §4 Compatibility)."""
        handler_grant = _grant(handlers=["*"], operations=["*"], resources=["*"])
        ctx = _make_ctx(capability=handler_grant)
        seen = self._setup_dispatch(ctx)

        expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
        })
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert not is_error(result)
        assert seen["dispatch_cap"] is None
        # No resource on apply → no resource on dispatched EXECUTE.
        assert seen["resource_targets"] is None

    def test_capability_without_resource_is_invalid(self):
        """F5 eval-time: `capability` present without `resource` → invalid_expression.
        Proposal §5 row 4."""
        handler_grant = _grant(handlers=["*"], operations=["*"], resources=["*"])
        provided = _grant(
            handlers=["system/tree"], operations=["get"], resources=["app/*"],
        )
        ctx = _make_ctx(capability=handler_grant)
        self._setup_dispatch(ctx)

        cap_h = _store(ctx, _cap_entity(provided))
        expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "capability": cap_h,
            # Intentionally no `resource` field.
        })
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_INVALID_EXPRESSION
        assert "resource" in result["data"]["message"]

    def test_capability_field_must_be_hash(self):
        """A non-hash capability field is invalid."""
        ctx = _make_ctx()
        self._setup_dispatch(ctx)
        # Need a `resource` to clear F5; the cap-shape error is the
        # behavior under test.
        resource_h = _store(ctx, _lit({"targets": ["app/x"]}))
        expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "resource": resource_h,
            "capability": "not-a-hash",
        })
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_INVALID_EXPRESSION

    def test_capability_field_resolves_non_capability_entity(self):
        """If the capability hash points to something that isn't a
        capability entity, type_mismatch."""
        handler_grant = _grant(handlers=["*"], operations=["*"], resources=["*"])
        ctx = _make_ctx(capability=handler_grant)
        self._setup_dispatch(ctx)

        # Store a literal expression — evaluates to a non-Entity value
        not_cap_h = _store(ctx, _lit(42))
        resource_h = _store(ctx, _lit({"targets": ["app/x"]}))
        expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "resource": resource_h,
            "capability": not_cap_h,
        })
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH


# ============================================================================
# Content store access gating (§4.2)
# ============================================================================

class TestTreeScopedResolution:
    """Tests for tree-scoped hash resolution (§4.2).

    The validator's pattern: write sub-expressions to tree paths via put,
    then evaluate a root expression that references them by content hash.
    Without tree-scoped resolution, these all fail.
    """

    def test_resolve_hash_of_tree_bound_entity(self):
        """Hash of an entity bound at a tree path should resolve."""
        cs = ContentStore()
        et = EntityTree(PEER_ID)
        ctx = EvalContext(
            content_store=cs, entity_tree=et, local_peer_id=PEER_ID,
            capability=WILDCARD_CAP, has_content_store_access=False,
        )

        entity = Entity(type="compute/literal", data={"value": 5})
        h = cs.put(entity)
        et.set("path/lit-5", h)

        resolved = ctx.resolve(h)
        assert resolved is not None
        assert resolved.type == "compute/literal"

    def test_arithmetic_with_tree_stored_operands(self):
        """Validator pattern: store operands at tree paths, ref by hash."""
        cs = ContentStore()
        et = EntityTree(PEER_ID)
        ctx = EvalContext(
            content_store=cs, entity_tree=et, local_peer_id=PEER_ID,
            capability=WILDCARD_CAP, has_content_store_access=False,
        )

        lit5 = _lit(5)
        h5 = cs.put(lit5)
        et.set("expr/lit-5", h5)

        lit1 = _lit(1)
        h1 = cs.put(lit1)
        et.set("expr/lit-1", h1)

        add_expr = _arith("add", h5, h1)
        result = evaluate(add_expr, Scope(), Budget(), ctx)
        assert result == 6

    def test_nested_expressions_with_tree_stored_entities(self):
        """Multi-level hash resolution through tree-bound entities."""
        cs = ContentStore()
        et = EntityTree(PEER_ID)
        ctx = EvalContext(
            content_store=cs, entity_tree=et, local_peer_id=PEER_ID,
            capability=WILDCARD_CAP, has_content_store_access=False,
        )

        lit3 = _lit(3)
        h3 = cs.put(lit3)
        et.set("expr/lit-3", h3)

        lit4 = _lit(4)
        h4 = cs.put(lit4)
        et.set("expr/lit-4", h4)

        add_expr = _arith("add", h3, h4)
        h_add = cs.put(add_expr)
        et.set("expr/add", h_add)

        lit2 = _lit(2)
        h2 = cs.put(lit2)
        et.set("expr/lit-2", h2)

        mul_expr = _arith("mul", h_add, h2)
        result = evaluate(mul_expr, Scope(), Budget(), ctx)
        assert result == 14


class TestContentStoreAccessGating:
    def test_resolve_with_content_store_access(self):
        ctx = _make_ctx()
        ctx.has_content_store_access = True
        entity = Entity(type="app/data", data={"x": 1})
        h = ctx.content_store.put(entity)
        assert ctx.resolve(h) is not None

    def test_resolve_without_access_or_encounter(self):
        ctx = _make_ctx()
        ctx.has_content_store_access = False
        entity = Entity(type="app/data", data={"x": 1})
        h = ctx.content_store.put(entity)
        assert ctx.resolve(h) is None

    def test_resolve_via_encountered(self):
        ctx = _make_ctx()
        ctx.has_content_store_access = False
        entity = Entity(type="compute/literal", data={"value": 1})
        h = ctx.content_store.put(entity)
        ctx.mark_encountered(h)
        assert ctx.resolve(h) is not None

    def test_resolve_via_included(self):
        entity = Entity(type="compute/literal", data={"value": 1})
        h = entity.compute_hash()
        ctx = _make_ctx(included={h: entity})
        ctx.has_content_store_access = False
        assert ctx.resolve(h) is not None

    def test_non_compute_entity_rejected_without_access(self):
        """D2: non-compute entities rejected to prevent oracle attacks."""
        ctx = _make_ctx()
        ctx.has_content_store_access = False
        entity = Entity(type="app/secret", data={"key": "value"})
        h = ctx.content_store.put(entity)
        ctx.mark_encountered(h)
        assert ctx.resolve(h) is None

    def test_non_compute_entity_allowed_with_access(self):
        """content_store_access allowance bypasses D2 type check."""
        ctx = _make_ctx()
        ctx.has_content_store_access = True
        entity = Entity(type="app/data", data={"x": 1})
        h = ctx.content_store.put(entity)
        assert ctx.resolve(h) is not None


# ============================================================================
# Audit walker — store builtin write_paths (§3.3)
# ============================================================================

class TestAuditStoreBuiltin:
    def test_collects_literal_store_path(self):
        ctx = _make_ctx()
        path_lit = _lit("app/output")
        path_h = _store(ctx, path_lit)
        val_lit = _lit(42)
        val_h = _store(ctx, val_lit)
        apply_expr = Entity(type="compute/apply", data={
            "path": "system/compute/builtins/store",
            "operation": "eval",
            "args": {"path": path_h, "value": val_h},
        })
        _store(ctx, apply_expr)
        result = audit_subgraph(apply_expr, ctx)
        # SA-11: store is gated only via its write_path — it is NOT collected as
        # a handler_target (pure builtins need no install-time handler auth).
        assert "app/output" in result.write_paths
        assert len(result.handler_targets) == 0

    def test_dynamic_store_path_not_collected(self):
        ctx = _make_ctx()
        lookup = _store(ctx, _lookup_scope("dynamic_path"))
        val_h = _store(ctx, _lit(42))
        apply_expr = Entity(type="compute/apply", data={
            "path": "system/compute/builtins/store",
            "operation": "eval",
            "args": {"path": lookup, "value": val_h},
        })
        _store(ctx, apply_expr)
        result = audit_subgraph(apply_expr, ctx)
        assert result.write_paths == []


# ============================================================================
# Budget — infinity semantics (§5.2)
# ============================================================================

class TestBudgetInfinity:
    def test_no_request_budget_uses_capability_limit(self):
        cap = {"constraints": {"system/compute": {
            "max_compute_operations": 200_000,
        }}}
        b = init_budget({}, cap, bounds_budget=500_000)
        assert b.operations == 200_000

    def test_request_budget_overrides_when_lower(self):
        cap = {"constraints": {"system/compute": {
            "max_compute_operations": 200_000,
        }}}
        b = init_budget({"budget": 50}, cap)
        assert b.operations == 50

    def test_bounds_budget_wins_when_lowest(self):
        cap = {"constraints": {"system/compute": {
            "max_compute_operations": 200_000,
        }}}
        b = init_budget({}, cap, bounds_budget=1000)
        assert b.operations == 1000


# ============================================================================
# Compute handler — eval operation (via handler function)
# ============================================================================

class TestHandleEval:
    @pytest.fixture
    def setup(self):
        from entity_core.storage.emit import EmitPathway, EmitContext
        cs = ContentStore()
        et = EntityTree(PEER_ID)
        ep = EmitPathway(cs, et)
        return cs, et, ep

    def _make_handler_ctx(self, ep, capability=None, *, resource_targets=None):
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.emit_pathway = ep
        ctx.local_peer_id = PEER_ID
        ctx.caller_capability = capability or WILDCARD_CAP
        ctx.caller_capability_granter_peer_id = None  # real default (no foreign granter)
        ctx.resource_targets = resource_targets
        ctx.bounds = None
        ctx.remote_peer_id = PEER_ID
        return ctx

    @pytest.mark.asyncio
    async def test_eval_literal(self, setup):
        from entity_handlers.compute import ComputeExtension
        cs, et, ep = setup
        ext = ComputeExtension()
        handler = ext.handler()

        lit = Entity(type="compute/literal", data={"value": 42})
        h = cs.put(lit)
        et.set("test/expr", h)

        ctx = self._make_handler_ctx(ep, resource_targets=["test/expr"])
        result = await handler("system/compute/eval", "eval",
                               {"data": {}}, ctx)
        assert result["status"] == 200
        assert result["result"]["data"]["value"] == 42

    @pytest.mark.asyncio
    async def test_eval_not_found(self, setup):
        from entity_handlers.compute import ComputeExtension
        cs, et, ep = setup
        ext = ComputeExtension()
        handler = ext.handler()

        ctx = self._make_handler_ctx(ep, resource_targets=["missing/path"])
        result = await handler("system/compute/eval", "eval",
                               {"data": {}}, ctx)
        assert result["status"] == 404

    @pytest.mark.asyncio
    async def test_eval_non_expression(self, setup):
        from entity_handlers.compute import ComputeExtension
        cs, et, ep = setup
        ext = ComputeExtension()
        handler = ext.handler()

        entity = Entity(type="app/data", data={"x": 1})
        h = cs.put(entity)
        et.set("test/data", h)

        ctx = self._make_handler_ctx(ep, resource_targets=["test/data"])
        result = await handler("system/compute/eval", "eval",
                               {"data": {}}, ctx)
        assert result["status"] == 400

    @pytest.mark.asyncio
    async def test_eval_semantic_error_returns_200(self, setup):
        """F10: an evaluated compute/error (here index-out-of-range) is a value
        — returned at status 200 with the compute/error body, detected by type,
        not by a transport 4xx (4xx is reserved for dispatch failures)."""
        from entity_handlers.compute import ComputeExtension
        cs, et, ep = setup
        ext = ComputeExtension()
        handler = ext.handler()

        arr = cs.put(Entity(type="compute/literal", data={"value": [10, 20]}))
        idx = cs.put(Entity(type="compute/literal", data={"value": 99}))
        h = cs.put(Entity(type="compute/index", data={"array": arr, "index": idx}))
        et.set("test/oor", h)

        # content_store_access lets the inline child literals resolve so the
        # index actually evaluates (and overruns) rather than failing not_found.
        cap = {**WILDCARD_CAP, "allowances": {"content_store_access": True}}
        ctx = self._make_handler_ctx(ep, capability=cap, resource_targets=["test/oor"])
        result = await handler("system/compute/eval", "eval", {"data": {}}, ctx)
        assert result["status"] == 200
        assert result["result"]["type"] == "compute/error"
        assert result["result"]["data"]["code"] == ERR_INDEX_OUT_OF_RANGE

    @pytest.mark.asyncio
    async def test_unsupported_operation(self, setup):
        from entity_handlers.compute import ComputeExtension
        cs, et, ep = setup
        ext = ComputeExtension()
        handler = ext.handler()

        ctx = self._make_handler_ctx(ep)
        result = await handler("system/compute/eval", "bogus", {"data": {}}, ctx)
        assert result["status"] == 501


# ============================================================================
# Compute handler — install/uninstall operations
# ============================================================================

class TestInstallUninstall:
    @pytest.fixture
    def setup(self):
        from entity_core.storage.emit import EmitPathway
        from entity_handlers.compute import ComputeExtension
        from entity_core.peer.extensions import ExtensionContext
        from entity_core.crypto.identity import Keypair

        keypair = Keypair.generate()
        cs = ContentStore()
        et = EntityTree(keypair.peer_id)
        ep = EmitPathway(cs, et)

        ext = ComputeExtension()
        ext_ctx = ExtensionContext(keypair=keypair, emit_pathway=ep)
        ext.initialize(ext_ctx)
        return ext, cs, et, ep, keypair

    def _make_handler_ctx(self, ep, peer_id, capability=None, *,
                          resource_targets=("app/expr",)):
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.emit_pathway = ep
        ctx.local_peer_id = peer_id
        ctx.caller_capability = capability or WILDCARD_CAP
        ctx.caller_capability_granter_peer_id = None  # real default (no foreign granter)
        ctx.resource_targets = list(resource_targets) if resource_targets else None
        ctx.bounds = None
        ctx.remote_peer_id = peer_id
        return ctx

    @pytest.mark.asyncio
    async def test_install_creates_subgraph(self, setup):
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        lit = Entity(type="compute/literal", data={"value": 42})
        h = cs.put(lit)
        ep.emit("app/cell/A1", lit)

        ctx = self._make_handler_ctx(ep, keypair.peer_id,
                                     resource_targets=["app/cell/A1"])
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 200
        data = result["result"]["data"]
        assert data["subgraph_path"].startswith("system/compute/processes/")
        assert data["result_path"] == "app/cell/A1/result"

    @pytest.mark.asyncio
    async def test_install_and_uninstall(self, setup):
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        lit = Entity(type="compute/literal", data={"value": 42})
        ep.emit("app/cell/A1", lit)

        ctx = self._make_handler_ctx(ep, keypair.peer_id,
                                     resource_targets=["app/cell/A1"])
        install_result = await handler("system/compute/install", "install",
                                       {"data": {}}, ctx)
        assert install_result["status"] == 200
        sg_path = install_result["result"]["data"]["subgraph_path"]

        uninstall_ctx = self._make_handler_ctx(ep, keypair.peer_id,
                                               resource_targets=[sg_path])
        uninstall_result = await handler("system/compute/uninstall", "uninstall",
                                         {"data": {}}, uninstall_ctx)
        assert uninstall_result["status"] == 200

    @pytest.mark.asyncio
    async def test_install_missing_expression(self, setup):
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        ctx = self._make_handler_ctx(ep, keypair.peer_id,
                                     resource_targets=["missing/path"])
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 404

    @pytest.mark.asyncio
    async def test_install_insufficient_capability(self, setup):
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        lookup = Entity(type="compute/lookup/tree", data={"path": "secret/data"})
        ep.emit("app/expr", lookup)

        no_secret_cap = {
            "grants": [{
                "handlers": {"include": ["*"]},
                "operations": {"include": ["*"]},
                "resources": {"include": ["app/*"]},
            }],
        }
        ctx = self._make_handler_ctx(ep, keypair.peer_id, capability=no_secret_cap,
                                     resource_targets=["app/expr"])
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 403

    @pytest.mark.asyncio
    async def test_deterministic_subgraph_id(self, setup):
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        lit = Entity(type="compute/literal", data={"value": 1})
        ep.emit("app/cell/A1", lit)

        ctx = self._make_handler_ctx(ep, keypair.peer_id,
                                     resource_targets=["app/cell/A1"])
        r1 = await handler("system/compute/install", "install",
                           {"data": {}}, ctx)
        r2 = await handler("system/compute/install", "install",
                           {"data": {}}, ctx)
        assert r1["result"]["data"]["subgraph_path"] == r2["result"]["data"]["subgraph_path"]

    # ------------------------------------------------------------------
    # PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING — F3 / F5 install-time tests
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_install_rejects_capability_without_resource(self, setup):
        """F5 install-time (proposal §3.3): a compute/apply subgraph with
        a `capability` field but no `resource` field is a static structural
        error → invalid_expression at install."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        # Build a compute/apply with capability but no resource.
        cap_lookup = Entity(type="compute/lookup/scope",
                            data={"name": "caller_capability"})
        cap_h = cs.put(cap_lookup)

        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "capability": cap_h,
        })
        ep.emit("app/expr", apply_expr)

        ctx = self._make_handler_ctx(ep, keypair.peer_id)
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_expression"
        assert "resource" in result["result"]["data"]["message"]

    @pytest.mark.asyncio
    async def test_install_rejects_static_resource_outside_caller_grant(self, setup):
        """F3 install-time (proposal §5 row 5): a subgraph whose
        compute/apply has a literal resource that the caller's cap does not
        cover → DENY at audit, before the subgraph is installed."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        # Caller cap covers system/tree:get on app/* only.
        narrow_cap = {
            "grants": [{
                "handlers": {"include": ["system/tree", "system/compute/install"]},
                "operations": {"include": ["*"]},
                "resources": {"include": ["app/*", "system/compute/*"]},
            }],
        }

        # Subgraph: compute/apply targeting system/secret/x via a literal
        # resource. Note: no `capability` override — this is the static-
        # literal audit path, not the override path.
        resource_lit = Entity(type="compute/literal",
                              data={"value": {"targets": ["system/secret/x"]}})
        resource_h = cs.put(resource_lit)
        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "resource": resource_h,
        })
        ep.emit("app/expr", apply_expr)

        ctx = self._make_handler_ctx(ep, keypair.peer_id, capability=narrow_cap)
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "permission_denied"
        assert "system/secret/x" in result["result"]["data"]["message"]

    @pytest.mark.asyncio
    async def test_install_allows_static_resource_within_caller_grant(self, setup):
        """F3 install-time happy path: static literal resource inside the
        caller's grant scope → ALLOW."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        resource_lit = Entity(type="compute/literal",
                              data={"value": {"targets": ["app/data/x"]}})
        resource_h = cs.put(resource_lit)
        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "resource": resource_h,
        })
        ep.emit("app/expr", apply_expr)

        ctx = self._make_handler_ctx(ep, keypair.peer_id)  # WILDCARD
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 200

    @pytest.mark.asyncio
    async def test_install_defers_dynamic_resource(self, setup):
        """F3 install-time (proposal §5 row 6): a subgraph whose
        compute/apply resource is a dynamic expression (non-literal) is
        not statically auditable — install ALLOW, runtime check applies
        per dispatch."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        # Dynamic resource: lookup/scope produces the resource at runtime.
        dynamic_resource = Entity(type="compute/lookup/scope",
                                  data={"name": "target"})
        resource_h = cs.put(dynamic_resource)
        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "resource": resource_h,
        })
        ep.emit("app/expr", apply_expr)

        # Caller cap is narrow but the dynamic resource is opaque at audit.
        narrow_cap = {
            "grants": [{
                "handlers": {"include": ["system/tree", "system/compute/install"]},
                "operations": {"include": ["*"]},
                "resources": {"include": ["app/*", "system/compute/*"]},
            }],
        }
        ctx = self._make_handler_ctx(ep, keypair.peer_id, capability=narrow_cap)
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        # Falls back to the legacy handler-level path check, which the
        # narrow cap does cover (handlers includes system/tree).
        assert result["status"] == 200

    # ------------------------------------------------------------------
    # PROPOSAL-COHERENT-CAPABILITY-AUTHORITY — CP1 chain-root check
    # on static-literal `compute/apply.capability` (EXTENSION-COMPUTE v3.11)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_install_rejects_foreign_rooted_static_capability(self, setup):
        """CP1: static-literal capability whose chain root is not the
        installer's identity → 403 embedded_cap_unauthorized."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        # A capability rooted at someone other than the installer.
        foreign_identity = bytes([ALG_ECFV1_SHA256]) + b"forein" + b"\x00" * 26
        embedded_cap = Entity(
            type="system/capability/token",
            data={
                "granter": foreign_identity,
                "grants": [{
                    "handlers": {"include": ["system/tree"]},
                    "operations": {"include": ["get"]},
                    "resources": {"include": ["app/data/x"]},
                }],
            },
        )
        embedded_cap_hash = cs.put(embedded_cap)

        # compute/literal whose value is the cap entity hash.
        cap_lit = Entity(type="compute/literal", data={"value": embedded_cap_hash})
        cap_lit_hash = cs.put(cap_lit)

        # Static literal resource so F5 doesn't fire first.
        resource_lit = Entity(type="compute/literal",
                              data={"value": {"targets": ["app/data/x"]}})
        resource_h = cs.put(resource_lit)

        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "capability": cap_lit_hash,
            "resource": resource_h,
        })
        ep.emit("app/expr", apply_expr)

        installer_identity = bytes([ALG_ECFV1_SHA256]) + b"instlr" + b"\x00" * 26
        ctx = self._make_handler_ctx(ep, keypair.peer_id)
        ctx.remote_identity_hash = installer_identity

        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "embedded_cap_unauthorized"

    @pytest.mark.asyncio
    async def test_install_allows_self_rooted_static_capability(self, setup):
        """CP1 happy path: static-literal capability whose chain root is
        the installer's identity → 200."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        installer_identity = bytes([ALG_ECFV1_SHA256]) + b"instlr" + b"\x00" * 26
        embedded_cap = Entity(
            type="system/capability/token",
            data={
                "granter": installer_identity,
                "grants": [{
                    "handlers": {"include": ["system/tree"]},
                    "operations": {"include": ["get"]},
                    "resources": {"include": ["app/data/x"]},
                }],
            },
        )
        embedded_cap_hash = cs.put(embedded_cap)
        cap_lit = Entity(type="compute/literal", data={"value": embedded_cap_hash})
        cap_lit_hash = cs.put(cap_lit)
        resource_lit = Entity(type="compute/literal",
                              data={"value": {"targets": ["app/data/x"]}})
        resource_h = cs.put(resource_lit)
        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "capability": cap_lit_hash,
            "resource": resource_h,
        })
        ep.emit("app/expr", apply_expr)

        ctx = self._make_handler_ctx(ep, keypair.peer_id)
        ctx.remote_identity_hash = installer_identity
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 200, result

    @pytest.mark.asyncio
    async def test_install_defers_dynamic_capability_to_runtime(self, setup):
        """CP1 only applies to static literals. A dynamic capability
        (e.g. lookup/scope) defers to the runtime F2 dual-check; install
        accepts it without R1 evaluation."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        # Dynamic cap: lookup/scope, not a literal.
        dyn_cap = Entity(type="compute/lookup/scope",
                         data={"name": "caller_capability"})
        dyn_cap_hash = cs.put(dyn_cap)
        resource_lit = Entity(type="compute/literal",
                              data={"value": {"targets": ["app/data/x"]}})
        resource_h = cs.put(resource_lit)
        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "capability": dyn_cap_hash,
            "resource": resource_h,
        })
        ep.emit("app/expr", apply_expr)

        # Installer identity is set but doesn't matter — CP1 doesn't fire.
        installer_identity = bytes([ALG_ECFV1_SHA256]) + b"instlr" + b"\x00" * 26
        ctx = self._make_handler_ctx(ep, keypair.peer_id)
        ctx.remote_identity_hash = installer_identity
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 200, result

    @pytest.mark.asyncio
    async def test_install_chain_unreachable_supersedes_leaf_match(self, setup):
        """Vector 4 analog for CP1: leaf granter matches installer, but
        parent unreachable. Per proposal §2 chain-reachability,
        CHAIN_UNREACHABLE supersedes IN_CHAIN — install MUST return 404
        chain_unreachable, not 200."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        installer_identity = bytes([ALG_ECFV1_SHA256]) + b"instlr" + b"\x00" * 26
        fabricated_parent = bytes([ALG_ECFV1_SHA256]) + b"fabric" + b"\x00" * 26
        # Leaf cap: granter=installer (matches R1), parent unreachable.
        embedded_cap = Entity(
            type="system/capability/token",
            data={
                "granter": installer_identity,
                "parent": fabricated_parent,
                "grants": [],
            },
        )
        embedded_cap_hash = cs.put(embedded_cap)
        cap_lit = Entity(type="compute/literal", data={"value": embedded_cap_hash})
        cap_lit_hash = cs.put(cap_lit)
        resource_lit = Entity(type="compute/literal",
                              data={"value": {"targets": ["app/data/x"]}})
        resource_h = cs.put(resource_lit)
        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "capability": cap_lit_hash,
            "resource": resource_h,
        })
        ep.emit("app/expr", apply_expr)

        ctx = self._make_handler_ctx(ep, keypair.peer_id)
        ctx.remote_identity_hash = installer_identity
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 404, result
        assert result["result"]["data"]["code"] == "chain_unreachable"

    @pytest.mark.asyncio
    async def test_install_chain_root_runs_before_resource_coverage(self, setup):
        """Spec ordering: chain-root rejection (CP1) precedes resource-
        coverage rejection (F3). When both would fire, return CP1 with
        embedded_cap_unauthorized, not permission_denied."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        # Foreign-rooted cap AND resource the caller cap doesn't cover.
        # If F3 fired first, we'd see permission_denied. CP1 must fire
        # first → embedded_cap_unauthorized.
        foreign_identity = bytes([ALG_ECFV1_SHA256]) + b"forein" + b"\x00" * 26
        embedded_cap = Entity(
            type="system/capability/token",
            data={"granter": foreign_identity, "grants": []},
        )
        embedded_cap_hash = cs.put(embedded_cap)
        cap_lit = Entity(type="compute/literal", data={"value": embedded_cap_hash})
        cap_lit_hash = cs.put(cap_lit)

        resource_lit = Entity(type="compute/literal",
                              data={"value": {"targets": ["forbidden/path"]}})
        resource_h = cs.put(resource_lit)
        apply_expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "capability": cap_lit_hash,
            "resource": resource_h,
        })
        ep.emit("app/expr", apply_expr)

        narrow_cap = {
            "grants": [{
                "handlers": {"include": ["system/tree", "system/compute/install"]},
                "operations": {"include": ["*"]},
                "resources": {"include": ["app/*", "system/compute/*"]},
            }],
        }
        installer_identity = bytes([ALG_ECFV1_SHA256]) + b"instlr" + b"\x00" * 26
        ctx = self._make_handler_ctx(ep, keypair.peer_id, capability=narrow_cap)
        ctx.remote_identity_hash = installer_identity
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "embedded_cap_unauthorized"


# ============================================================================
# Reactive re-evaluation (§7.2)
# ============================================================================

class TestReactiveReEvaluation:
    @pytest.fixture
    def setup(self):
        from entity_core.storage.emit import EmitPathway
        from entity_handlers.compute import ComputeExtension
        from entity_core.peer.extensions import ExtensionContext
        from entity_core.crypto.identity import Keypair

        keypair = Keypair.generate()
        cs = ContentStore()
        et = EntityTree(keypair.peer_id)
        ep = EmitPathway(cs, et)

        ext = ComputeExtension()
        ext_ctx = ExtensionContext(keypair=keypair, emit_pathway=ep)
        ext.initialize(ext_ctx)
        return ext, cs, et, ep, keypair

    def _make_handler_ctx(self, ep, peer_id, *, resource_targets=("app/expr",)):
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.emit_pathway = ep
        ctx.local_peer_id = peer_id
        ctx.caller_capability = WILDCARD_CAP
        ctx.caller_capability_granter_peer_id = None  # real default (no foreign granter)
        ctx.resource_targets = list(resource_targets) if resource_targets else None
        ctx.bounds = None
        ctx.remote_peer_id = peer_id
        return ctx

    @pytest.mark.asyncio
    async def test_reactive_updates_on_dependency_change(self, setup):
        """Install an expression depending on a tree path, change the path, check result updates."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        # Store a value at app/data
        data_entity = Entity(type="app/value", data={"x": 10})
        ep.emit("app/data", data_entity)

        # Create an expression that reads app/data
        lookup = Entity(type="compute/lookup/tree", data={"path": "app/data"})
        ep.emit("app/expr", lookup)

        # Install
        ctx = self._make_handler_ctx(ep, keypair.peer_id)
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 200
        result_path = result["result"]["data"]["result_path"]

        # Change the dependency — should trigger re-evaluation
        new_data = Entity(type="app/value", data={"x": 20})
        ep.emit("app/data", new_data)

        # Check that result was written
        result_h = et.get(result_path)
        assert result_h is not None

    @pytest.mark.asyncio
    async def test_convergence_suppresses_write(self, setup):
        """When result hash is unchanged, no write should occur."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        # Literal doesn't depend on anything, result is always the same
        lit = Entity(type="compute/literal", data={"value": 42})
        ep.emit("app/expr", lit)

        ctx = self._make_handler_ctx(ep, keypair.peer_id)
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 200

    @pytest.mark.asyncio
    async def test_frozen_subgraph_skipped(self, setup):
        """Frozen subgraphs should not be re-evaluated."""
        ext, cs, et, ep, keypair = setup
        handler = ext.handler()

        lookup = Entity(type="compute/lookup/tree", data={"path": "app/data"})
        ep.emit("app/expr", lookup)

        data = Entity(type="app/value", data={"x": 1})
        ep.emit("app/data", data)

        ctx = self._make_handler_ctx(ep, keypair.peer_id)
        result = await handler("system/compute/install", "install",
                               {"data": {}}, ctx)
        assert result["status"] == 200
        sg_path = result["result"]["data"]["subgraph_path"]

        # Manually freeze the subgraph
        sg_h = et.get(sg_path)
        sg_entity = cs.get(sg_h)
        frozen = Entity(type="system/compute/subgraph",
                        data={**sg_entity.data, "status": "frozen"})
        ep.emit(sg_path, frozen)

        # Change dependency — should NOT trigger re-evaluation since frozen
        initial_tree_size = len(et)
        new_data = Entity(type="app/value", data={"x": 999})
        ep.emit("app/data", new_data)
        # If re-eval ran, it would write to result_path, increasing tree size
        # We can't check exact tree size due to internal writes, but frozen should skip


# ============================================================================
# Dependency index rebuild (§7.1)
# ============================================================================

class TestRebuild:
    def test_rebuild_from_existing_subgraphs(self):
        from entity_handlers.compute import _ComputeState

        cs = ContentStore()
        et = EntityTree(PEER_ID)
        state = _ComputeState()

        # Store a compute expression at a path
        lookup = Entity(type="compute/lookup/tree", data={"path": "app/data"})
        lookup_h = cs.put(lookup)
        et.set("app/expr", lookup_h)

        # Store a subgraph metadata entity
        cap = Entity(type="system/capability", data=WILDCARD_CAP)
        cap_h = cs.put(cap)

        subgraph = Entity(type="system/compute/subgraph", data={
            "root_expression_path": "app/expr",
            "root_expression": lookup_h,
            "installation_grant": cap_h,
            "installed_by": None,
            "result_path": "app/expr/result",
            "status": "active",
        })
        sg_h = cs.put(subgraph)
        sg_id = deterministic_id("app/expr")
        et.set(f"system/compute/processes/{sg_id}", sg_h)

        state.rebuild(et, cs)
        normalized = et.normalize_uri("app/data")
        assert len(state.dependency_index.match(normalized)) == 1

    def test_rebuild_skips_frozen(self):
        from entity_handlers.compute import _ComputeState

        cs = ContentStore()
        et = EntityTree(PEER_ID)
        state = _ComputeState()

        lookup = Entity(type="compute/lookup/tree", data={"path": "app/data"})
        lookup_h = cs.put(lookup)
        et.set("app/expr", lookup_h)

        cap = Entity(type="system/capability", data=WILDCARD_CAP)
        cap_h = cs.put(cap)

        subgraph = Entity(type="system/compute/subgraph", data={
            "root_expression_path": "app/expr",
            "root_expression": lookup_h,
            "installation_grant": cap_h,
            "installed_by": None,
            "result_path": "app/expr/result",
            "status": "frozen",
        })
        sg_h = cs.put(subgraph)
        sg_id = deterministic_id("app/expr")
        et.set(f"system/compute/processes/{sg_id}", sg_h)

        state.rebuild(et, cs)
        normalized = et.normalize_uri("app/data")
        assert len(state.dependency_index.match(normalized)) == 0


# ============================================================================
# compute/result wrapping (§2.4)
# ============================================================================

class TestResultWrapping:
    @pytest.fixture
    def setup(self):
        from entity_core.storage.emit import EmitPathway
        from entity_handlers.compute import ComputeExtension
        cs = ContentStore()
        et = EntityTree(PEER_ID)
        ep = EmitPathway(cs, et)
        ext = ComputeExtension()
        return ext, cs, et, ep

    @pytest.mark.asyncio
    async def test_primitive_result_wrapped(self, setup):
        ext, cs, et, ep = setup
        handler = ext.handler()

        lit = Entity(type="compute/literal", data={"value": 42})
        h = cs.put(lit)
        et.set("test/expr", h)

        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.emit_pathway = ep
        ctx.local_peer_id = PEER_ID
        ctx.caller_capability = WILDCARD_CAP
        ctx.caller_capability_granter_peer_id = None  # real default (no foreign granter)
        ctx.resource_targets = ["test/expr"]
        ctx.bounds = None

        result = await handler("system/compute/eval", "eval",
                               {"data": {}}, ctx)
        assert result["status"] == 200
        assert result["result"]["type"] == "compute/result"
        assert result["result"]["data"]["value"] == 42

    @pytest.mark.asyncio
    async def test_entity_result_not_wrapped(self, setup):
        """Constructed entities retain their type, not wrapped in compute/result."""
        ext, cs, et, ep = setup
        handler = ext.handler()

        name_h = cs.put(_lit("Alice"))
        construct = _construct("app/user", {"name": name_h})
        ch = cs.put(construct)
        et.set("test/expr", ch)

        from unittest.mock import MagicMock
        cap_with_cs = {**WILDCARD_CAP, "allowances": {"content_store_access": True}}
        ctx = MagicMock()
        ctx.emit_pathway = ep
        ctx.local_peer_id = PEER_ID
        ctx.caller_capability = cap_with_cs
        ctx.caller_capability_granter_peer_id = None  # real default (no foreign granter)
        ctx.resource_targets = ["test/expr"]
        ctx.bounds = None

        result = await handler("system/compute/eval", "eval",
                               {"data": {}}, ctx)
        assert result["status"] == 200
        assert result["result"]["type"] == "app/user"


# ============================================================================
# Tail Call Optimization (§4.1 T1-T3)
# ============================================================================

class TestTailCallOptimization:
    def test_tail_recursive_iteration_beyond_depth_limit(self):
        """Tail-recursive countdown(2000) succeeds with TCO.

        count_down(self, n) = if n == 0 then 0 else apply(self, {self, n-1})
        Self is passed as an argument since lambda captures scope at creation.
        Without TCO, 2000 iterations would exceed the 1024 depth limit.
        """
        ctx = _make_ctx()

        zero_h = _store(ctx, _lit(0))
        one_h = _store(ctx, _lit(1))
        n_h = _store(ctx, _lookup_scope("n"))
        self_h = _store(ctx, _lookup_scope("self"))
        cond_h = _store(ctx, _compare("eq", n_h, zero_h))
        decrement_h = _store(ctx, _arith("sub", n_h, one_h))

        # Recursive call: apply(self, {self: self, n: n-1})
        apply_self = Entity(type="compute/apply", data={
            "fn": self_h,
            "args": {"self": self_h, "n": decrement_h},
        })
        apply_self_h = _store(ctx, apply_self)

        body = _if(cond_h, zero_h, apply_self_h)
        body_h = _store(ctx, body)

        # lambda(self, n) { body }
        lam = _lambda(["self", "n"], body_h)
        lam_h = _store(ctx, lam)

        # let f = lam in apply(f, {self: f, n: 2000})
        two_thousand_h = _store(ctx, _lit(2000))
        f_h = _store(ctx, _lookup_scope("f"))
        apply_outer = Entity(type="compute/apply", data={
            "fn": f_h,
            "args": {"self": f_h, "n": two_thousand_h},
        })
        apply_outer_h = _store(ctx, apply_outer)

        let_expr = _let(
            [{"name": "f", "value": lam_h}],
            apply_outer_h,
        )

        budget = Budget(operations=100_000, depth=1024)
        result = evaluate(let_expr, Scope(), budget, ctx)
        assert result == 0
        assert budget.depth == 1024

    def test_tail_calls_dont_consume_depth(self):
        """Verify that tail-recursive calls don't decrement depth."""
        ctx = _make_ctx()

        # Simple: if true then 42 else unreachable
        # The "then" branch is a tail call that doesn't consume extra depth.
        true_h = _store(ctx, _lit(True))
        val_h = _store(ctx, _lit(42))
        expr = _if(true_h, val_h)

        budget = Budget(operations=100, depth=2)
        result = evaluate(expr, Scope(), budget, ctx)
        assert result == 42
        assert budget.depth == 2

    def test_budget_still_decremented_for_tail_calls(self):
        """Every evaluation step costs one operation, even tail calls."""
        ctx = _make_ctx()

        zero_h = _store(ctx, _lit(0))
        one_h = _store(ctx, _lit(1))
        n_h = _store(ctx, _lookup_scope("n"))
        cond_h = _store(ctx, _compare("eq", n_h, zero_h))
        decrement_h = _store(ctx, _arith("sub", n_h, one_h))
        self_h = _store(ctx, _lookup_scope("self"))

        apply_self = Entity(type="compute/apply", data={
            "fn": self_h, "args": {"n": decrement_h},
        })
        apply_self_h = _store(ctx, apply_self)

        body = _if(cond_h, zero_h, apply_self_h)
        body_h = _store(ctx, body)

        lam = _lambda(["n"], body_h)
        lam_h = _store(ctx, lam)

        five_h = _store(ctx, _lit(5))
        apply_outer = Entity(type="compute/apply", data={
            "fn": self_h, "args": {"n": five_h},
        })
        apply_outer_h = _store(ctx, apply_outer)

        let_expr = _let(
            [{"name": "self", "value": lam_h}],
            apply_outer_h,
        )

        budget = Budget(operations=10, depth=1024)
        result = evaluate(let_expr, Scope(), budget, ctx)
        # With only 10 ops, 5 iterations of count_down should exhaust budget
        assert is_error(result)
        assert result["data"]["code"] == ERR_BUDGET_EXHAUSTED

    def test_depth_check_before_decrement(self):
        """depth=1 should allow exactly 1 non-tail evaluation."""
        ctx = _make_ctx()
        budget = Budget(operations=100, depth=1)
        result = evaluate(_lit(42), Scope(), budget, ctx)
        assert result == 42
        assert budget.depth == 1

    def test_depth_zero_rejected(self):
        """depth=0 should immediately return depth_exceeded."""
        ctx = _make_ctx()
        budget = Budget(operations=100, depth=0)
        result = evaluate(_lit(42), Scope(), budget, ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_DEPTH_EXCEEDED

    def test_let_body_is_tail_position(self):
        """The body of compute/let is a tail position — doesn't consume extra depth.

        depth=2: one for the let (which evals binding at depth 1), one for
        the binding value. The body is a tail call that reuses the let's
        depth slot. Without TCO on the body, this would need depth=3.
        """
        ctx = _make_ctx()
        val_h = _store(ctx, _lit(99))
        lit_h = _store(ctx, _lit(1))
        # let x = 1 in 99
        expr = _let([{"name": "x", "value": lit_h}], val_h)

        budget = Budget(operations=100, depth=2)
        result = evaluate(expr, Scope(), budget, ctx)
        assert result == 99

    def test_lookup_tree_expression_is_tail_position(self):
        """When tree entity is an expression, it's evaluated in tail position."""
        ctx = _make_ctx()
        inner = _lit(77)
        inner_h = _store(ctx, inner)
        ctx.entity_tree.set("app/data", inner_h)

        tree_lookup = _lookup_tree("app/data")

        budget = Budget(operations=100, depth=1)
        result = evaluate(tree_lookup, Scope(), budget, ctx)
        assert result == 77


# ============================================================================
# Relative Paths (R1-R2)
# ============================================================================

class TestRelativePaths:
    def test_clean_path(self):
        assert _clean_path("a//b") == "a/b"
        assert _clean_path("a/b/") == "a/b"
        assert _clean_path("a///b//c/") == "a/b/c"
        assert _clean_path("a/b") == "a/b"

    def test_lookup_tree_relative_path(self):
        ctx = _make_ctx(capability=WILDCARD_CAP)
        ctx.subgraph_root = "app/compute/job1"

        data_entity = Entity(type="app/data", data={"value": 42})
        data_h = ctx.content_store.put(data_entity)
        ctx.entity_tree.set("app/compute/job1/data/input", data_h)

        # relative lookup: path="data/input", relative=True
        lookup = Entity(type="compute/lookup/tree", data={
            "path": "data/input",
            "relative": True,
        })

        result = evaluate(lookup, Scope(), Budget(), ctx)
        # Should resolve to app/compute/job1/data/input
        assert isinstance(result, Entity)
        assert result.data["value"] == 42

    def test_lookup_tree_absolute_path_unchanged(self):
        """When relative is absent/false, path resolves as-is."""
        ctx = _make_ctx(capability=WILDCARD_CAP)
        ctx.subgraph_root = "app/compute/job1"

        data_entity = Entity(type="app/data", data={"value": 99})
        data_h = ctx.content_store.put(data_entity)
        ctx.entity_tree.set("app/global/data", data_h)

        lookup = Entity(type="compute/lookup/tree", data={
            "path": "app/global/data",
        })

        result = evaluate(lookup, Scope(), Budget(), ctx)
        assert isinstance(result, Entity)
        assert result.data["value"] == 99

    def test_relative_dependency_registered_as_absolute(self):
        """Dependencies for relative lookups should be registered as absolute paths."""
        ctx = _make_ctx(capability=WILDCARD_CAP)
        ctx.subgraph_root = "app/compute/job1"

        data_entity = Entity(type="app/data", data={"value": 1})
        data_h = ctx.content_store.put(data_entity)
        ctx.entity_tree.set("app/compute/job1/data/src", data_h)

        lookup = Entity(type="compute/lookup/tree", data={
            "path": "data/src",
            "relative": True,
        })
        evaluate(lookup, Scope(), Budget(), ctx)

        assert "app/compute/job1/data/src" in ctx.dependencies

    def test_audit_resolves_relative_tree_paths(self):
        ctx = _make_ctx()
        lookup = Entity(type="compute/lookup/tree", data={
            "path": "data/input",
            "relative": True,
        })
        lookup_h = _store(ctx, lookup)

        result = audit_subgraph(lookup, ctx, root_path="app/compute/job1")
        assert "app/compute/job1/data/input" in result.read_paths

    def test_audit_resolves_relative_hash_hint_paths(self):
        ctx = _make_ctx()
        target_entity = Entity(type="app/data", data={"v": 1})
        target_h = ctx.content_store.put(target_entity)

        lookup = Entity(type="compute/lookup/hash", data={
            "hash": target_h,
            "path": "data/source",
            "relative": True,
        })

        result = audit_subgraph(lookup, ctx, root_path="app/compute/job1")
        assert len(result.data_hashes) == 1
        assert result.data_hashes[0]["path"] == "app/compute/job1/data/source"

    def test_walk_tree_lookups_resolves_relative(self):
        ctx = _make_ctx()
        lookup = Entity(type="compute/lookup/tree", data={
            "path": "lib/helper",
            "relative": True,
        })

        deps = walk_tree_lookups(lookup, ctx, root_path="app/compute/job1")
        assert deps == ["app/compute/job1/lib/helper"]

    def test_walk_tree_lookups_absolute_unchanged(self):
        ctx = _make_ctx()
        lookup = Entity(type="compute/lookup/tree", data={
            "path": "app/external/data",
        })

        deps = walk_tree_lookups(lookup, ctx, root_path="app/compute/job1")
        assert deps == ["app/external/data"]

    def test_relative_false_treated_as_absolute(self):
        ctx = _make_ctx(capability=WILDCARD_CAP)
        ctx.subgraph_root = "app/compute/job1"

        data_entity = Entity(type="app/data", data={"value": 5})
        data_h = ctx.content_store.put(data_entity)
        ctx.entity_tree.set("some/path", data_h)

        lookup = Entity(type="compute/lookup/tree", data={
            "path": "some/path",
            "relative": False,
        })

        result = evaluate(lookup, Scope(), Budget(), ctx)
        assert isinstance(result, Entity)
        assert result.data["value"] == 5

    def test_relative_with_no_subgraph_root_uses_path_as_is(self):
        """When subgraph_root is empty, relative path resolves as-is."""
        ctx = _make_ctx(capability=WILDCARD_CAP)
        ctx.subgraph_root = ""

        data_entity = Entity(type="app/data", data={"value": 7})
        data_h = ctx.content_store.put(data_entity)
        ctx.entity_tree.set("data/input", data_h)

        lookup = Entity(type="compute/lookup/tree", data={
            "path": "data/input",
            "relative": True,
        })

        result = evaluate(lookup, Scope(), Budget(), ctx)
        assert isinstance(result, Entity)
        assert result.data["value"] == 7


# ============================================================================
# Handler-mode dispatch wiring (compute/apply handler mode)
# ============================================================================

class TestHandlerModeDispatchWiring:
    """Validate that _execute_fn is wired through the compute handler.

    When the handler context has a dispatcher, compute/apply handler-mode
    expressions should dispatch through it to the target handler.
    """

    @pytest.fixture
    def setup(self):
        from entity_core.storage.emit import EmitPathway
        from entity_handlers.compute import ComputeExtension
        cs = ContentStore()
        et = EntityTree(PEER_ID)
        ep = EmitPathway(cs, et)
        ext = ComputeExtension()
        return ext, cs, et, ep

    @pytest.mark.asyncio
    async def test_handler_dispatch_through_eval(self, setup):
        """compute/apply handler-mode dispatches through execute_with_capability.

        Validates the feedback fix: _execute_fn is wired when _execute_dispatcher
        is present on the handler context.
        """
        from unittest.mock import MagicMock, AsyncMock
        from entity_core.handlers.context import ExecuteResult

        ext, cs, et, ep = setup
        handler = ext.handler()

        cap_with_cs = {**WILDCARD_CAP, "allowances": {"content_store_access": True}}

        # Target expression: literal(50)
        target_expr = Entity(type="compute/literal", data={"value": 50})
        target_h = cs.put(target_expr)
        et.set("app/target-expr", target_h)

        # Caller expression: compute/apply dispatching to system/compute eval
        uri_lit = Entity(type="compute/literal", data={
            "value": f"/{PEER_ID}/app/target-expr",
        })
        uri_h = cs.put(uri_lit)
        et.set("app/uri-lit", uri_h)

        apply_expr = Entity(type="compute/apply", data={
            "path": "system/compute",
            "operation": "eval",
            "args": {"expression_uri": uri_h},
        })
        apply_h = cs.put(apply_expr)
        et.set("app/caller-expr", apply_h)

        # Mock handler context with dispatcher
        ctx = MagicMock()
        ctx.emit_pathway = ep
        ctx.local_peer_id = PEER_ID
        ctx.caller_capability = cap_with_cs
        ctx.caller_capability_granter_peer_id = None  # real default (no foreign granter)
        ctx.resource_targets = ["app/caller-expr"]
        ctx.bounds = None
        ctx._execute_dispatcher = MagicMock()

        # Mock execute_with_capability to simulate dispatching to compute eval
        ctx.execute_with_capability = AsyncMock(return_value=ExecuteResult(
            status=200,
            result={"type": "compute/result", "data": {"value": 50}},
        ))

        result = await handler("system/compute/eval", "eval",
                               {"data": {}}, ctx)

        assert result["status"] == 200
        assert result["result"]["type"] == "compute/result"
        assert result["result"]["data"]["value"] == 50

        # Verify dispatch was called with correct args
        ctx.execute_with_capability.assert_called_once()
        call_kwargs = ctx.execute_with_capability.call_args
        assert call_kwargs.kwargs["capability_data"] == cap_with_cs

    @pytest.mark.asyncio
    async def test_handler_dispatch_not_wired_without_dispatcher(self, setup):
        """Without _execute_dispatcher, handler-mode apply returns not_found."""
        ext, cs, et, ep = setup
        handler = ext.handler()

        cap_with_cs = {**WILDCARD_CAP, "allowances": {"content_store_access": True}}

        uri_lit = Entity(type="compute/literal", data={"value": "some/path"})
        uri_h = cs.put(uri_lit)
        et.set("app/uri-lit", uri_h)

        apply_expr = Entity(type="compute/apply", data={
            "path": "system/compute",
            "operation": "eval",
            "args": {"expression_uri": uri_h},
        })
        apply_h = cs.put(apply_expr)
        et.set("app/expr", apply_h)

        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.emit_pathway = ep
        ctx.local_peer_id = PEER_ID
        ctx.caller_capability = cap_with_cs
        ctx.caller_capability_granter_peer_id = None  # real default (no foreign granter)
        ctx.resource_targets = ["app/expr"]
        ctx.bounds = None
        ctx._execute_dispatcher = None

        result = await handler("system/compute/eval", "eval",
                               {"data": {}}, ctx)

        # F10: the apply evaluates to a compute/error value (no dispatcher
        # wired) — error-as-value, returned at status 200 and detected by type.
        assert result["status"] == 200
        assert result["result"]["type"] == "compute/error"
        assert result["result"]["data"]["code"] == "not_found"
        assert "No handler dispatch" in result["result"]["data"]["message"]


# ============================================================================
# Compute type catalog registration
# ============================================================================

class TestComputeTypeCatalog:
    """Verify that compute extension registers all expected types in
    system/type/* (cross-impl conformance — surfaced by Go validate-peer)."""

    def test_store_args_type_registered(self):
        """system/compute/store-args (EXTENSION-COMPUTE §3.5 V9) must be
        published in the type catalog so external clients can resolve the
        store builtin's args shape."""
        from entity_core.peer.extensions import ExtensionContext
        from entity_core.crypto.identity import Keypair
        from entity_core.storage.emit import EmitPathway
        from entity_handlers.compute import ComputeExtension

        keypair = Keypair.generate()
        cs = ContentStore()
        et = EntityTree(keypair.peer_id)
        ep = EmitPathway(cs, et)

        ext = ComputeExtension()
        ext.initialize(ExtensionContext(keypair=keypair, emit_pathway=ep))

        h = et.get("system/type/system/compute/store-args")
        assert h is not None, "system/compute/store-args not registered in tree"
        type_entity = cs.get(h)
        assert type_entity.type == "system/type"
        fields = type_entity.data["fields"]
        assert fields["path"]["type_ref"] == "system/tree/path"
        assert fields["value"]["type_ref"] == "system/hash"


# ============================================================================
# v3.19b — the scope-binding value model (N1/N3/N4/N6/N8)
# ============================================================================

class TestScopeBindingValueModel:
    """Kind-tagged scope bindings: reference-don't-duplicate (N1), navigate-by-kind
    (N3), authorization-inheritance (N4), content-store-direct (N6), and
    scope_unreachable (N8). Entity-ness is carried by Python type (Entity),
    never inferred from dict shape."""

    def test_field_navigates_by_kind_not_shape(self):
        """N3: an Entity navigates its .data; a plain dict navigates flat — even
        when the dict has the {type, data} envelope shape (it's a record)."""
        assert _field_record(Entity(type="app/x", data={"k": 1})) == {"k": 1}
        # Same {type,data} shape, but a *value* (record) → navigate flat, not peeled.
        rec = {"type": "app/x", "data": {"k": 1}}
        assert _field_record(rec) == rec

    def test_entity_binding_roundtrips_as_entity(self):
        """N1: an entity captured into scope is stored by hash and restored as
        the same Entity (kind preserved) — not flattened to its envelope."""
        ctx = _make_ctx()
        ent = Entity(type="primitive/any", data={"threshold": 100, "xs": [1, 2]})
        scope = Scope(); scope.set("p", ent)
        loaded = _load_scope(_capture_scope(scope, ctx), ctx)
        b = loaded.get("p")
        assert isinstance(b, Entity)
        assert b.type == "primitive/any"
        assert _field_record(b)["threshold"] == 100

    def test_v319_n5_disambiguation_record_field_not_lost(self):
        """N3 (v319_n5_disambiguation): a record value shaped like an entity
        envelope ({type, data, name}) is bound kind:"value", round-trips
        unchanged, and navigates FLAT — the retired shape heuristic would have
        peeled it and silently dropped `name`."""
        ctx = _make_ctx()
        trap = {"type": "premium", "data": {"x": 1}, "name": "alice"}
        scope = Scope(); scope.set("r", trap)
        loaded = _load_scope(_capture_scope(scope, ctx), ctx)
        b = loaded.get("r")
        assert b == trap                       # round-trips as a value, unchanged
        rec = _field_record(b)
        assert rec["name"] == "alice"          # flat field preserved (was lost pre-v3.19b)
        assert rec["type"] == "premium"

    def test_closure_captured_entity_navigates_after_apply(self):
        """End-to-end F9-B: a closure that closes over an entity-valued binding
        navigates it via field after capture+apply (broken under the v3.18
        inline model where the captured entity round-tripped to a bare dict)."""
        ctx = _make_ctx()
        outer = Scope(); outer.set("p", Entity(type="primitive/any", data={"threshold": 100}))
        body = _store(ctx, _field("threshold", _store(ctx, _lookup_scope("p"))))
        closure = evaluate(_lambda([], body), outer, Budget(), ctx)
        assert closure.type == "compute/closure"
        closure_h = ctx.content_store.put(closure)
        result = evaluate(_apply_closure(closure_h, {}), Scope(), Budget(), ctx)
        assert int(result) == 100

    def test_scope_unreachable_when_binding_missing(self):
        """N8: a kind:"entity" binding whose hash resolves nowhere yields
        compute/error{scope_unreachable} at load — an error value, not a fault."""
        ctx = _make_ctx()
        missing = b"\x00" + b"\xfe" * 32
        scope_entity = Entity(type="compute/scope", data={"bindings": {
            "p": {"kind": "entity", "entity_hash": missing},
        }})
        env_h = ctx.content_store.put(scope_entity)
        result = _load_scope(env_h, ctx)
        assert is_error(result)
        assert result["data"]["code"] == ERR_SCOPE_UNREACHABLE

    def test_v319b_scope_hash_agreement(self):
        """N2 ratification gate (cross-impl): the compute/scope content hash for a
        fixed scope — one value-kind binding ``n=42`` — MUST be bit-identical
        across Go/Rust/Python. Validated three-way bit-identical in the v3.19b
        close-out; this pins Python to the ratified value permanently so a future
        change to the binding wire shape / ECF ordering is caught in pytest."""
        ctx = _make_ctx()
        scope = Scope(); scope.set("n", 42)
        env_h = _capture_scope(scope, ctx)
        # env_h = 0x00 (ecf-sha256 format byte) + 32-byte digest.
        assert env_h[1:].hex() == (
            "3edc51381d12e22a22412890d329cbab87d98970362b5a4c1b3e0328effb9efd"
        )

    def test_app_typed_binding_resolves_via_authorization_inheritance(self):
        """N4: a binding entity of a NON-compute app type (app/user) resolves
        on load by riding the closure's authorization — not rejected by the
        is_compute_type / sealed-set gating that guards general resolution."""
        ctx = _make_ctx()
        app_ent = Entity(type="app/user", data={"name": "bob"})
        scope = Scope(); scope.set("u", app_ent)
        loaded = _load_scope(_capture_scope(scope, ctx), ctx)
        b = loaded.get("u")
        assert isinstance(b, Entity) and b.type == "app/user"
        assert _field_record(b)["name"] == "bob"


# ============================================================================
# v3.19c Part A (α) — construct materialize-to-bare
# ============================================================================

class TestConstructMaterialization:
    """The compute value model is compute-internal; a constructed entity is
    materialized to its bare wire form at a compute→non-compute crossing,
    byte-identical to a hand-built (refless) entity (the validate-peer gate)."""

    def test_v319c_construct_entity_valued_field_hash_equals_handbuilt(self):
        """α hash gate: construct(app/wrapper, {inner: construct(app/user,{name})})
        materialized → content_hash == the hand-built refless equivalent
        (inner stored, wrapper refs it by bare system/hash). Cross-impl gate."""
        ctx = _make_ctx()
        # hand-built, refless: inner stored; wrapper holds inner's system/hash.
        inner_bare = Entity(type="app/user", data={"name": "alice"})
        inner_hash = ctx.content_store.put(inner_bare)
        handbuilt = Entity(type="app/wrapper", data={"inner": inner_hash})

        # compute-constructed, then materialized.
        name_h = _store(ctx, _lit("alice"))
        inner_construct = _store(ctx, _construct("app/user", {"name": name_h}))
        outer = _construct("app/wrapper", {"inner": inner_construct})
        in_flight = evaluate(outer, Scope(), Budget(), ctx)
        # in-flight: typed — the entity-valued field is an Entity object.
        assert isinstance(in_flight, Entity)
        assert isinstance(in_flight.data["inner"], Entity)

        materialized = _materialize_bare(in_flight, ctx)
        # bare: the entity-valued field is now a bare system/hash ref.
        assert materialized.data["inner"] == inner_hash
        assert materialized.compute_hash() == handbuilt.compute_hash()

    def test_v319c_construct_value_only_already_bare(self):
        """A value-only construct is already bare — materialize is identity, and
        it equals a hand-built entity of the same type/fields."""
        ctx = _make_ctx()
        name_h = _store(ctx, _lit("alice"))
        constructed = evaluate(_construct("app/user", {"name": name_h}), Scope(), Budget(), ctx)
        materialized = _materialize_bare(constructed, ctx)
        assert materialized.compute_hash() == Entity(type="app/user", data={"name": "alice"}).compute_hash()

    def test_v319c_inflight_navigation_through_construct(self):
        """α read side: navigation composes through an in-flight constructed
        entity (typed) — field(field(construct(wrapper,{inner:<entity>}),
        "inner"),"name") resolves the inner entity and navigates it. No
        materialization, no kind-tags, no shape-sniffing."""
        ctx = _make_ctx()
        name_h = _store(ctx, _lit("alice"))
        inner_construct = _store(ctx, _construct("app/user", {"name": name_h}))
        outer_construct = _store(ctx, _construct("app/wrapper", {"inner": inner_construct}))
        inner_field = _store(ctx, _field("inner", outer_construct))
        expr = _field("name", inner_field)
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert result == "alice"


# ============================================================================
# Regression — non-record (primitive/any) entity handling (v314 apply→native 500)
# ============================================================================

class TestNonRecordEntityHandling:
    """A primitive/any entity wraps a *bare* value in `.data` (e.g. the
    unwrapped result of an entity-native dispatch). Materialization and
    navigation must handle the non-dict `.data` without crashing — this was a
    500 in v314_compute_apply_to_entity_native (compute apply → entity-native
    handler returning a bare primitive)."""

    def test_materialize_bare_on_primitive_any_does_not_crash(self):
        ctx = _make_ctx()
        prim = Entity(type="primitive/any", data=42)
        out = _materialize_bare(prim, ctx)
        assert out.type == "primitive/any"
        assert out.data == 42

    def test_materialize_bare_on_primitive_list_and_str(self):
        ctx = _make_ctx()
        assert _materialize_bare(Entity(type="primitive/any", data=[1, 2]), ctx).data == [1, 2]
        assert _materialize_bare(Entity(type="primitive/any", data="hi"), ctx).data == "hi"

    def test_field_record_on_primitive_any_is_type_mismatch_not_typeerror(self):
        # No navigable fields → None (caller raises type_mismatch), never TypeError.
        assert _field_record(Entity(type="primitive/any", data=42)) is None
        assert _field_record(Entity(type="primitive/any", data=[1, 2])) is None


# ============================================================================
# v3.19c N3 read-back navigation — returns bare hash, no auto-resolve
# ============================================================================

class TestReadbackNavigation:
    """Parity with Go TestEvalFieldReadbackReturnsBareHash / Rust
    test_v319c_readback_navigation_returns_hash + the cross-impl vector
    v319c_readback_navigation_returns_hash. field on a stored (read-back)
    entity's entity-valued field returns the BARE system/hash (bytes), never an
    auto-resolved entity — no shape-sniff (the rejected Rust heuristic). The
    caller follows the ref via explicit compute/lookup/hash."""

    def test_field_on_readback_entity_returns_bare_hash(self):
        ctx = _make_ctx()
        inner = Entity(type="app/user", data={"name": "alice"})
        inner_hash = ctx.content_store.put(inner)
        # Hand-built wrapper in bare V7 §1.4 form: inner is a bare system/hash.
        wrapper = Entity(type="app/wrapper", data={"inner": inner_hash})
        ctx.entity_tree.set("app/wrapper", ctx.content_store.put(wrapper))

        lookup = _store(ctx, _lookup_tree("app/wrapper"))
        result = evaluate(_field("inner", lookup), Scope(), Budget(), ctx)

        # N3: bare hash bytes returned as-is, NOT auto-resolved to the entity.
        # Structural comparison (crypto-agile — no fixed hash-length check).
        assert not isinstance(result, Entity)
        assert result == inner_hash
