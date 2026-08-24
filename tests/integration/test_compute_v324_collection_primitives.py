"""EXTENSION-COMPUTE v3.24 / v3.25 / v3.26 — the collection primitives, their
error-code corrections, and the CONTAINED-error boundary form.

Routed by `entity-core-go` as `2026-08-21-a` (`-f`); ruled at arch `bded94c`
(COMPUTE v3.26 §2.3 N1 / §3.5). **The routing report says rust and py "are not
yet on v3.26"; this repo was on v3.23** — v3.24 and v3.25 were never routed
here at all, so the three §3.5 contained positions the ruling carves out did
not exist to carve. Verified in-tree before building (`git log -S assoc` over
`packages/` is empty across all refs), which is the standing rule: a routed
report's claims about *our* repo are hearsay.

The file is organised as the spec's own three layers, because they fail
differently:

  * **v3.24** — the four primitives exist and compute the right arrays.
  * **v3.25** — the four corner cases that determine boundary *bytes* (the
    group shape, `assoc`'s code, `range`'s code, error flow-through).
  * **v3.26** — where a CONTAINED error's bytes come from, and the guard that
    says a NON-contained one is still a defect.
"""

from __future__ import annotations

import pytest

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree
from entity_core.utils.ecf import ecf_encode

from entity_handlers.compute import (
    BUILTIN_ASSOC,
    BUILTIN_CONCAT,
    BUILTIN_GROUP_BY,
    BUILTIN_MAP,
    BUILTIN_RANGE,
    ERR_BUDGET_EXHAUSTED,
    ERR_COUNT_OUT_OF_RANGE,
    ERR_INDEX_OUT_OF_RANGE,
    ERR_MISSING_ARGUMENT,
    ERR_TYPE_MISMATCH,
    MAX_ARRAY_LENGTH,
    TYPE_COMPUTE_GROUP,
    Budget,
    EvalContext,
    Scope,
    _materialize_bare,
    error_data,
    evaluate,
    is_error,
)

PEER_ID = "test-peer-id"

WILDCARD_CAP = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": ["*"]},
    }],
}


# --- harness -----------------------------------------------------------------

def _ctx() -> EvalContext:
    return EvalContext(
        content_store=ContentStore(),
        entity_tree=EntityTree(PEER_ID),
        local_peer_id=PEER_ID,
        capability=WILDCARD_CAP,
        included={},
        has_content_store_access=True,
    )


def _put(ctx: EvalContext, entity: Entity) -> bytes:
    return ctx.content_store.put(entity)


def _lit(ctx: EvalContext, value) -> bytes:
    return _put(ctx, Entity(type="compute/literal", data={"value": value}))


def _err_literal(ctx: EvalContext, code: str, message: str = "prose") -> bytes:
    """A STORED `compute/error` — the `Entity` representation.

    Deliberately not `make_error`'s dict form: the two representations are the
    repo's oldest recurring bug class, and the `Entity` one is the half that
    reaches the encoder. Rows here that place an error into an array use this
    form so the materialization assertions are about the shape that bites.
    """
    return _put(ctx, Entity(
        type="compute/error", data={"code": code, "message": message},
    ))


def _builtin(ctx: EvalContext, path: str, args: dict[str, bytes], budget=None):
    expr = Entity(type="compute/apply", data={
        "path": path, "operation": "eval", "args": args,
    })
    return evaluate(expr, Scope(), budget or Budget(), ctx)


def _lambda(ctx: EvalContext, params: list[str], body: bytes) -> bytes:
    return _put(ctx, Entity(type="compute/lambda", data={"params": params, "body": body}))


def _scope_ref(ctx: EvalContext, name: str) -> bytes:
    return _put(ctx, Entity(type="compute/lookup/scope", data={"name": name}))


def _const_lambda(ctx: EvalContext, value) -> bytes:
    return _lambda(ctx, ["x"], _lit(ctx, value))


def _parity_lambda(ctx: EvalContext) -> bytes:
    """`lambda x: x % 2` — a real key function, so grouping is observable."""
    body = _put(ctx, Entity(type="compute/arithmetic", data={
        "op": "mod", "left": _scope_ref(ctx, "x"), "right": _lit(ctx, 2),
    }))
    return _lambda(ctx, ["x"], body)


def _array_carrying_a_live_error(
    ctx: EvalContext, base: list, index: int, code: str, message: str = "prose"
) -> bytes:
    """Hash of an expression evaluating to an array with a LIVE `compute/error`
    at `index`, built with `assoc` — the production path.

    A stored `compute/literal` cannot carry one (a round-trip degrades the
    error to a generic map and never reaches the contained path), and a scope
    binding cannot carry one *into a closure* either — capturing an array of
    entities is itself a crossing, so the binding holds bare hashes by the time
    the closure loads it. `assoc` is how such an array actually arises, which
    is also how go's CV-5 corner vector builds it.
    """
    return _put(ctx, Entity(type="compute/apply", data={
        "path": BUILTIN_ASSOC, "operation": "eval",
        "args": {
            "collection": _lit(ctx, base),
            "index": _lit(ctx, index),
            "value": _err_literal(ctx, code, message),
        },
    }))


def _code(result) -> str:
    assert is_error(result), f"expected an error-as-value, got {result!r}"
    return error_data(result).get("code", "")


# ============================================================================
# v3.24 — the four primitives (§3.5 "The v3.24 collection primitives")
# ============================================================================

class TestRange:
    def test_range_n_is_zero_through_n_minus_one(self):
        ctx = _ctx()
        assert _builtin(ctx, BUILTIN_RANGE, {"n": _lit(ctx, 5)}) == [0, 1, 2, 3, 4]

    def test_range_zero_is_the_empty_array(self):
        ctx = _ctx()
        assert _builtin(ctx, BUILTIN_RANGE, {"n": _lit(ctx, 0)}) == []


class TestGroupBy:
    def test_groups_by_derived_key_in_first_appearance_order(self):
        """Groups are ordered by **first appearance of their key**, not by key
        sort order — a key sort would need a total order over arbitrary key
        types this extension does not define.

        The fixture is chosen so the two orders DISAGREE: first appearance is
        `1, 0` (the collection starts odd) while a key sort would give `0, 1`.
        A fixture starting with an even element cannot tell the two apart, and
        is the fixture anyone writes first.
        """
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_GROUP_BY, {
            "collection": _lit(ctx, [1, 2, 3, 4]),
            "fn": _parity_lambda(ctx),
        })
        assert [g.type for g in out] == [TYPE_COMPUTE_GROUP] * 2
        assert [g.data["key"] for g in out] == [1, 0], (
            "groups must be ordered by first appearance, not by key sort"
        )
        assert [g.data["members"] for g in out] == [[1, 3], [2, 4]]

    def test_members_keep_input_index_order(self):
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_GROUP_BY, {
            "collection": _lit(ctx, [10, 1, 12, 3, 14]),
            "fn": _parity_lambda(ctx),
        })
        assert out[0].data["members"] == [10, 12, 14]
        assert out[1].data["members"] == [1, 3]

    def test_the_key_is_carried_in_the_result(self):
        """v3.25 C-1 `[MUST]`: the result is `system/compute/group{key,
        members}`, not a bare array of arrays.

        The key is in the result because the shapes this primitive exists to
        serve — a histogram, a bucketed aggregation, a router — are exactly the
        ones whose output is unreadable without its labels. v3.24's
        array-of-arrays lost it, and both go and this implementation had to be
        corrected to carry it.
        """
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_GROUP_BY, {
            "collection": _lit(ctx, [1, 2]),
            "fn": _const_lambda(ctx, "same"),
        })
        assert len(out) == 1
        assert set(out[0].data) == {"key", "members"}
        assert out[0].data["key"] == "same"
        assert out[0].data["members"] == [1, 2]

    def test_key_equality_is_ecf_byte_identity_not_python_identity(self):
        """Key equality is byte-identity over the canonical ECF encoding — the
        protocol's own value identity, defined for every key type `fn` may
        return.

        The teeth: a **list** key. Python lists are unhashable, so an
        implementation that reached for a `dict` keyed on the raw value would
        raise `TypeError` here rather than group; and two structurally equal
        but distinct list objects must land in ONE group, which object identity
        would split into two.
        """
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_GROUP_BY, {
            "collection": _lit(ctx, [1, 2, 3]),
            "fn": _const_lambda(ctx, [7, 8]),
        })
        assert len(out) == 1, "one key value ⇒ one group, by bytes not by identity"
        assert out[0].data["key"] == [7, 8]
        assert out[0].data["members"] == [1, 2, 3]


class TestConcat:
    def test_joins_order_preserving(self):
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_CONCAT, {
            "collections": _lit(ctx, [[1, 2], [3], [], [4, 5]]),
        })
        assert out == [1, 2, 3, 4, 5]

    def test_no_collections_is_the_empty_array(self):
        ctx = _ctx()
        assert _builtin(ctx, BUILTIN_CONCAT, {"collections": _lit(ctx, [])}) == []

    def test_one_collection_is_that_collection(self):
        ctx = _ctx()
        assert _builtin(ctx, BUILTIN_CONCAT, {
            "collections": _lit(ctx, [[1, 2, 3]]),
        }) == [1, 2, 3]

    def test_one_level_only_no_recursive_flatten(self):
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_CONCAT, {
            "collections": _lit(ctx, [[[1]], [[2]]]),
        })
        assert out == [[1], [2]], "concat joins one level; it does not flatten"

    def test_element_type_mismatch_is_an_error_as_value(self):
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_CONCAT, {
            "collections": _lit(ctx, [[1], ["x"]]),
        })
        assert _code(out) == ERR_TYPE_MISMATCH

    def test_int_and_uint_are_one_element_type(self):
        """§2.2: `int`/`uint` are **annotations, not distinct value types**, so
        a `concat` across them is not a mismatch. This is the row that stops
        `_element_type_tag` from being written as `type(v).__name__`."""
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_CONCAT, {
            "collections": _lit(ctx, [[1, 2], [3]]),
        })
        assert out == [1, 2, 3]

    def test_bool_is_not_an_integer_for_the_element_check(self):
        """`bool` is an `int` subclass in Python and a distinct value type on
        the wire. A tag function testing `isinstance(v, int)` first would
        silently accept `concat([1], [True])`, which is a mismatch."""
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_CONCAT, {
            "collections": _lit(ctx, [[1], [True]]),
        })
        assert _code(out) == ERR_TYPE_MISMATCH


class TestAssoc:
    def test_replaces_at_index(self):
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_ASSOC, {
            "collection": _lit(ctx, [10, 20, 30]),
            "index": _lit(ctx, 1),
            "value": _lit(ctx, 99),
        })
        assert out == [10, 99, 30]

    def test_the_input_collection_is_not_mutated(self):
        """`assoc` returns a NEW array. The input is a resolved literal shared
        with the content store, so mutating it in place would corrupt every
        later read of the same hash — a bug that shows up arbitrarily far from
        this function."""
        ctx = _ctx()
        coll = _lit(ctx, [10, 20, 30])
        _builtin(ctx, BUILTIN_ASSOC, {
            "collection": coll, "index": _lit(ctx, 1), "value": _lit(ctx, 99),
        })
        again = _builtin(ctx, BUILTIN_ASSOC, {
            "collection": coll, "index": _lit(ctx, 0), "value": _lit(ctx, 7),
        })
        assert again == [7, 20, 30], "the second assoc saw a mutated collection"

    def test_missing_value_arg_is_missing_argument(self):
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_ASSOC, {
            "collection": _lit(ctx, [1]), "index": _lit(ctx, 0),
        })
        assert _code(out) == ERR_MISSING_ARGUMENT


# ============================================================================
# v3.25 — the four corners that determine boundary bytes (§3.5, §9.1)
# ============================================================================

class TestV325ErrorCodeCorrections:
    """Two v3.24 clauses were corrected in v3.25 because they contradicted
    §2.2's cross-impl ruling that **an out-of-domain magnitude is not a type
    error**. Both are `[MUST]` and both are observable on the wire, so a peer
    answering the old code is divergent."""

    @pytest.mark.parametrize("index", [3, 4, 100, -1, -100])
    def test_assoc_out_of_range_index_is_index_out_of_range(self, index):
        """v3.25 C-2: the SAME code and the SAME condition as `compute/index`.
        One document must not answer one malformed program with two codes
        depending on which array operation it reached."""
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_ASSOC, {
            "collection": _lit(ctx, [10, 20, 30]),
            "index": _lit(ctx, index),
            "value": _lit(ctx, 0),
        })
        assert _code(out) == ERR_INDEX_OUT_OF_RANGE

    def test_assoc_and_compute_index_agree_on_the_code(self):
        """The teeth for the row above, stated as the property: `assoc` and
        `compute/index` must produce the same code for the same out-of-range
        magnitude. Asserting the constant twice would pass against two
        implementations that happen to share a typo."""
        ctx = _ctx()
        coll = _lit(ctx, [10, 20, 30])
        via_assoc = _builtin(ctx, BUILTIN_ASSOC, {
            "collection": coll, "index": _lit(ctx, 9), "value": _lit(ctx, 0),
        })
        via_index = evaluate(
            Entity(type="compute/index", data={
                "array": coll, "index": _lit(ctx, 9),
            }),
            Scope(), Budget(), ctx,
        )
        assert _code(via_assoc) == _code(via_index)

    def test_assoc_non_integer_index_is_still_a_type_mismatch(self):
        """The correction narrowed `type_mismatch` to the case that really is
        one. A *string* index is a type error; an out-of-range *integer* is
        not. Without this row the correction reads as "assoc never answers
        type_mismatch", which is a different and wrong rule."""
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_ASSOC, {
            "collection": _lit(ctx, [1, 2]),
            "index": _lit(ctx, "1"),
            "value": _lit(ctx, 0),
        })
        assert _code(out) == ERR_TYPE_MISMATCH

    def test_assoc_boolean_index_is_a_type_mismatch(self):
        """`True` is an `int` subclass in Python and `[1,2][True]` is a legal
        Python expression. Nothing in the wire model makes a bool an index, so
        an implementation that forgets the bool exclusion silently accepts a
        malformed program and answers `[1, 99]` instead of an error."""
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_ASSOC, {
            "collection": _lit(ctx, [1, 2]),
            "index": _lit(ctx, True),
            "value": _lit(ctx, 99),
        })
        assert _code(out) == ERR_TYPE_MISMATCH

    @pytest.mark.parametrize("n", [-1, -100])
    def test_range_negative_n_is_count_out_of_range(self, n):
        """v3.25 C-3: `count_out_of_range`, following `cast_out_of_range`'s
        precedent rather than overloading either neighbour — and **not**
        clamped to `[]`. `n` is a loop bound, so a silent empty propagates
        through every downstream `map`/`filter`/`fold` and yields a well-formed
        wrong answer carrying no error."""
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_RANGE, {"n": _lit(ctx, n)})
        assert _code(out) == ERR_COUNT_OUT_OF_RANGE

    def test_range_negative_n_is_not_clamped_to_empty(self):
        """Stated as the property the code protects, because `[]` and an error
        are both 'no elements' to a careless assertion."""
        ctx = _ctx()
        assert _builtin(ctx, BUILTIN_RANGE, {"n": _lit(ctx, -1)}) != []

    @pytest.mark.parametrize(
        "n",
        [MAX_ARRAY_LENGTH + 1, 2**64, 2**64 + 1000, 2**200],
        ids=["just-over", "u64", "u64-plus", "astronomically-over"],
    )
    def test_range_n_above_the_representable_ceiling_is_count_out_of_range(self, n):
        """**The Python-specific half, and the reason this row exists at all.**

        In go and rust an `n` above the index type's range fails the decode and
        never reaches the comparison — the language fails closed for them.
        `cbor2` hands back an arbitrary-precision `int`, so `n < 0` answers
        `False` and the next line tries to build the list. Same class as the
        CAP-6a temporal-bounds defect: *where a peer language fails closed by
        decoding, we have to fail closed by checking.*

        This runs fast only because the check precedes the allocation. If it
        ever hangs, that IS the failure.
        """
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_RANGE, {"n": _lit(ctx, n)})
        assert _code(out) == ERR_COUNT_OUT_OF_RANGE

    def test_range_at_the_ceiling_is_refused_by_budget_not_by_count(self):
        """The boundary row: `MAX_ARRAY_LENGTH` itself is *representable*, so
        it is not a `count_out_of_range` — it is refused by the budget, which
        is the mechanism that stops `range(huge)` from OOMing.

        Keeping the two refusals distinct is the point: collapsing them would
        make the ceiling untestable (every large `n` would answer the same
        code) and would hide a peer that had no budget charge at all.
        """
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_RANGE, {"n": _lit(ctx, MAX_ARRAY_LENGTH)})
        assert _code(out) == ERR_BUDGET_EXHAUSTED

    def test_range_non_integer_n_is_a_type_mismatch(self):
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_RANGE, {"n": _lit(ctx, "5")})
        assert _code(out) == ERR_TYPE_MISMATCH

    def test_range_charges_the_budget_per_produced_element(self):
        ctx = _ctx()
        budget = Budget(operations=100)
        _builtin(ctx, BUILTIN_RANGE, {"n": _lit(ctx, 50)}, budget=budget)
        assert budget.operations <= 50, (
            "range must charge per produced element, or range(huge) OOMs "
            "instead of exhausting"
        )


class TestV325FlowThrough:
    """§3.5's flow-through table `[v3.25]`, which is §7.2's consumed-operand
    `[MUST]` applied to all seven positions so no implementer re-derives it.

    Every row names its class, because the two classes are one word apart in
    the table and opposite in effect."""

    # --- consumed positions: short-circuit ---------------------------------

    def test_range_n_error_short_circuits(self):
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_RANGE, {"n": _err_literal(ctx, "n_error")})
        assert _code(out) == "n_error"

    def test_assoc_index_error_short_circuits(self):
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_ASSOC, {
            "collection": _lit(ctx, [1, 2, 3]),
            "index": _err_literal(ctx, "idx_error"),
            "value": _lit(ctx, 0),
        })
        assert _code(out) == "idx_error"

    def test_group_by_derived_key_error_short_circuits(self):
        """The key short-circuits even though the key now has an OUTPUT slot
        (`system/compute/group.key`) — the one row where "has an output
        position" does not imply "contained".

        The reason is byte-identity: grouping by an error would make its
        `message` string structurally load-bearing, so two failures worded
        differently would become two groups and one reworded message would
        change the result's *shape*. That is a stronger divergence than a
        forked hash, which is why it outranks the output-position argument.
        """
        ctx = _ctx()
        err_returning = _lambda(ctx, ["x"], _err_literal(ctx, "key_error"))
        out = _builtin(ctx, BUILTIN_GROUP_BY, {
            "collection": _lit(ctx, [1, 2]),
            "fn": err_returning,
        })
        assert _code(out) == "key_error"

    def test_concat_a_collection_that_is_an_error_short_circuits(self):
        """§3.5's table: each `collection` is CONSUMED — *"its length is read
        to copy"* — so an error there short-circuits.

        The tempting alternative is to let it fall through to the
        array-shape check and answer `type_mismatch`. That discards the
        original code and substitutes a verdict about the *shape* for one about
        the *value*, which is exactly the substitution §7.2 forbids for a
        consumed operand.

        **`entity-core-go` answers `type_mismatch` here** (`builtinConcat`
        reaches `c.([]interface{})` before any error test). Routed as an
        observation with this citation rather than matched — see the session's
        routing report.
        """
        ctx = _ctx()
        scope = Scope()
        scope.set("colls", [
            [1, 2],
            Entity(type="compute/error", data={"code": "sub_error", "message": "x"}),
        ])
        expr = Entity(type="compute/apply", data={
            "path": BUILTIN_CONCAT, "operation": "eval",
            "args": {"collections": _scope_ref(ctx, "colls")},
        })
        out = evaluate(expr, scope, Budget(), ctx)
        assert _code(out) == "sub_error"

    @pytest.mark.parametrize(
        ("path", "args_extra"),
        [
            (BUILTIN_ASSOC, {"index": "lit0", "value": "lit0"}),
            (BUILTIN_GROUP_BY, {"fn": "const"}),
        ],
        ids=["assoc", "group-by"],
    )
    def test_a_collection_arg_that_is_an_error_short_circuits(self, path, args_extra):
        """A `collection` arg is consumed — its elements are read to copy — so
        an error there short-circuits to **its own code**.

        The tempting alternative is to answer `type_mismatch` on the ground
        that a `compute/error` is not an array. That substitutes a verdict
        about the SHAPE for one about the VALUE and discards the caller's
        code, so a poisoned collection becomes indistinguishable from a
        malformed program.

        **`entity-core-go` answers `type_mismatch` at both call sites**
        (`resolveCollection`, `ext/compute/builtins.go`, go `f14cc2c`, uses
        `Evaluate` where `evalOperand` is required) — confirmed on the wire by
        `tests/interop/test_go_peer_compute_v324.py`, which passes all six rows
        against a py peer and fails three against a go peer. Routed, not
        matched.

        Both call sites get a row because a fix applied at one would leave the
        other open and a single-site test would not notice.
        """
        ctx = _ctx()
        args = {"collection": _err_literal(ctx, "coll_error")}
        for k, v in args_extra.items():
            args[k] = _lit(ctx, 0) if v == "lit0" else _const_lambda(ctx, "k")
        out = _builtin(ctx, path, args)
        assert _code(out) == "coll_error"

    def test_a_collection_arg_of_the_wrong_shape_is_still_a_type_mismatch(self):
        """The discriminating control for the row above: a collection that
        really is the wrong shape IS `type_mismatch`. Without it, "short-
        circuits the error" is consistent with an implementation that answers
        the caller's code for every bad collection."""
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_ASSOC, {
            "collection": _lit(ctx, 7), "index": _lit(ctx, 0), "value": _lit(ctx, 0),
        })
        assert _code(out) == ERR_TYPE_MISMATCH

    # --- contained positions: flow in --------------------------------------

    def test_assoc_value_error_flows_in_and_does_not_short_circuit(self):
        """`assoc`'s `value` is the SA-9 `store` case one primitive over: a
        value the caller asked to place, not an operand the primitive reads."""
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_ASSOC, {
            "collection": _lit(ctx, [10, 20, 30]),
            "index": _lit(ctx, 0),
            "value": _err_literal(ctx, "placed_error"),
        })
        assert not is_error(out), f"assoc must not short-circuit, got {out!r}"
        assert isinstance(out, list) and len(out) == 3
        assert is_error(out[0]) and error_data(out[0])["code"] == "placed_error"
        assert out[1:] == [20, 30]

    def test_concat_error_element_is_type_transparent(self):
        """v3.25 C-4 `[MUST]`: a `compute/error` element **neither matches nor
        mismatches** the element-type check — it flows through untouched.

        Per §1.5 an error is *"the same model as NaN propagation in IEEE
        754"* — a poisoned value **of** the array's element type, not a value
        of a different type. The teeth are that an error among integers must
        NOT raise `type_mismatch`: an implementation that tags it as
        `entity:compute/error` and compares would reject the whole concat.
        """
        ctx = _ctx()
        scope = Scope()
        scope.set("colls", [[
            1,
            Entity(type="compute/error", data={"code": "poisoned", "message": "loud"}),
            2,
        ]])
        expr = Entity(type="compute/apply", data={
            "path": BUILTIN_CONCAT, "operation": "eval",
            "args": {"collections": _scope_ref(ctx, "colls")},
        })
        out = evaluate(expr, scope, Budget(), ctx)
        assert not is_error(out), f"concat must not short-circuit, got {out!r}"
        assert len(out) == 3
        assert is_error(out[1])
        assert out[0] == 1 and out[2] == 2

    def test_group_by_error_element_is_contained_in_members(self):
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_GROUP_BY, {
            "collection": _array_carrying_a_live_error(ctx, [1, 0], 1, "member_error"),
            "fn": _const_lambda(ctx, "k"),
        })
        assert not is_error(out), f"group-by must not short-circuit, got {out!r}"
        assert len(out) == 1
        members = out[0].data["members"]
        assert members[0] == 1
        assert is_error(members[1])
        assert error_data(members[1])["code"] == "member_error"


# ============================================================================
# v3.26 — how a CONTAINED error materializes (§2.3 N1, §3.5)
# ============================================================================

class TestV326ContainedErrorMaterializesCodeOnly:
    """The ruling this session was routed to build.

    A CONTAINED `compute/error` materializes **code-only** — content-hashed
    over `code` alone per §2.4, with `message`/`at`/`expression` excluded as
    in-flight diagnostics — and is referenced by a **bare `system/hash`** like
    any other entity-valued element.
    """

    def _assoc_with_error(self, ctx: EvalContext, message: str):
        return _builtin(ctx, BUILTIN_ASSOC, {
            "collection": _lit(ctx, [10, 20, 30]),
            "index": _lit(ctx, 1),
            "value": _err_literal(ctx, "contained", message),
        })

    def test_the_contained_error_becomes_a_bare_system_hash(self):
        ctx = _ctx()
        materialized = _materialize_bare(self._assoc_with_error(ctx, "prose"), ctx)
        assert materialized[0] == 10 and materialized[2] == 30
        assert isinstance(materialized[1], bytes), (
            "a contained error must be referenced by a bare system/hash, "
            f"got {materialized[1]!r}"
        )

    def test_the_referenced_entity_carries_code_alone(self):
        ctx = _ctx()
        materialized = _materialize_bare(self._assoc_with_error(ctx, "prose"), ctx)
        stored = ctx.content_store.get(materialized[1])
        assert stored is not None, "the contained error must be PUT, not dangling"
        assert stored.type == "compute/error"
        assert stored.data == {"code": "contained"}, (
            "message/at/expression are in-flight diagnostics and MUST NOT enter "
            f"the content-addressed bytes, got {stored.data!r}"
        )

    def test_two_messages_one_code_give_the_same_containing_array_bytes(self):
        """**The load-bearing row — the reason code-only is a `[MUST]` and not
        tidiness.**

        If the contained element carried `message`, two conformant peers whose
        diagnostics differ would produce different bytes for the *containing
        array*, so the array's content hash would fork cross-impl on a string
        no spec pins. The assertion is on the containing array's ECF bytes, not
        on the error entity's own — the fork happens one container out, which
        is where a test written against the error alone would miss it.
        """
        ctx_a, ctx_b = _ctx(), _ctx()
        a = ecf_encode(_materialize_bare(self._assoc_with_error(ctx_a, "peer A prose"), ctx_a))
        b = ecf_encode(_materialize_bare(self._assoc_with_error(ctx_b, "totally different"), ctx_b))
        assert a == b, (
            "the containing array's bytes fork on the error's message — the "
            "contained form is not code-only"
        )

    def test_a_different_code_does_change_the_containing_array_bytes(self):
        """The teeth control for the row above. Without it, an implementation
        that dropped the error entirely — or replaced every contained error
        with one constant — passes the message-independence assertion
        perfectly."""
        ctx_a, ctx_b = _ctx(), _ctx()
        a = ecf_encode(_materialize_bare(self._assoc_with_error(ctx_a, "m"), ctx_a))
        b = ecf_encode(_materialize_bare(_builtin(ctx_b, BUILTIN_ASSOC, {
            "collection": _lit(ctx_b, [10, 20, 30]),
            "index": _lit(ctx_b, 1),
            "value": _err_literal(ctx_b, "a_different_code", "m"),
        }), ctx_b))
        assert a != b

    @pytest.mark.parametrize("position", ["assoc-value", "concat-element", "group-by-members"])
    def test_all_three_contained_positions_reach_the_code_only_form(self, position):
        """§3.5: *"the contained set is exactly three positions"*. One
        carve-out at the array-element boundary is supposed to cover all
        three uniformly — `members` is an array field of each group, so it is
        a direct element of a materialized array like the other two.

        This row is what makes that claim testable rather than argued. A
        per-primitive carve-out would pass one row and fail the others.
        """
        ctx = _ctx()
        live_err = Entity(
            type="compute/error", data={"code": "contained", "message": "prose"},
        )
        if position == "assoc-value":
            value = self._assoc_with_error(ctx, "prose")
            probe = _materialize_bare(value, ctx)[1]
        elif position == "concat-element":
            scope = Scope()
            scope.set("colls", [[1, live_err]])
            value = evaluate(Entity(type="compute/apply", data={
                "path": BUILTIN_CONCAT, "operation": "eval",
                "args": {"collections": _scope_ref(ctx, "colls")},
            }), scope, Budget(), ctx)
            probe = _materialize_bare(value, ctx)[1]
        else:
            value = _builtin(ctx, BUILTIN_GROUP_BY, {
                "collection": _array_carrying_a_live_error(ctx, [0], 0, "contained"),
                "fn": _const_lambda(ctx, "k"),
            })
            group_hash = _materialize_bare(value, ctx)[0]
            probe = ctx.content_store.get(group_hash).data["members"][0]

        assert isinstance(probe, bytes), (
            f"{position}: contained error must be a bare system/hash, got {probe!r}"
        )
        assert ctx.content_store.get(probe).data == {"code": "contained"}

    def test_a_group_materializes_to_a_bare_entity_with_no_kind_tags(self):
        """§2.3 N1 / §4.1: a constructed entity is encoded by the **runtime
        kind** of the evaluated value, never by the declared schema — so a peer
        with no type extension produces byte-identical groups. The group's
        `members` array must therefore materialize element-wise like any other
        array field."""
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_GROUP_BY, {
            "collection": _lit(ctx, [1, 2]),
            "fn": _const_lambda(ctx, "k"),
        })
        hashes = _materialize_bare(out, ctx)
        assert all(isinstance(h, bytes) for h in hashes)
        group = ctx.content_store.get(hashes[0])
        assert group.type == TYPE_COMPUTE_GROUP
        assert group.data == {"key": "k", "members": [1, 2]}


class TestV326TheGuardIsScopedNotRemoved:
    """*"Add the carve-out, not remove the guard."* — arch, v3.26.

    v3.23's ruling B is a **consumption-site** invariant and stays exactly as
    strict. An error reaching materialization anywhere that is NOT a contained
    array element means a §4.1 short-circuit was missed upstream.
    """

    def test_a_scalar_error_reaching_materialization_raises(self):
        """The tell that the carve-out was scoped wrong is a NON-element error
        materializing **quietly**. So this fails loudly: a `compute/error`
        silently re-embedded into a construct field is a wrong answer that
        hashes, sends, and is believed."""
        ctx = _ctx()
        err = Entity(type="compute/error", data={"code": "scalar", "message": "m"})
        with pytest.raises(RuntimeError, match="SCALAR"):
            _materialize_bare(err, ctx)

    def test_an_error_in_a_construct_field_still_short_circuits(self):
        """The guard must never actually fire in practice, because the
        consumption site short-circuits first. This row proves the upstream
        short-circuit is what handles it — if it regressed, the row above would
        start passing for the wrong reason."""
        ctx = _ctx()
        out = evaluate(
            Entity(type="compute/construct", data={
                "entity_type": "example/thing",
                "fields": {"f": _err_literal(ctx, "field_error")},
            }),
            Scope(), Budget(), ctx,
        )
        assert _code(out) == "field_error"

    def test_the_evaluator_hands_a_top_level_error_out_unmaterialized(self):
        """**This row does NOT prove the crossing ordering — read on.**

        The v3.26 guard makes the ordering at each compute→non-compute crossing
        load-bearing: `is_error` is now checked *before* materializing, so a
        legitimate top-level error-as-value leaves by the F10 status-200 door
        instead of tripping the guard. Before v3.26 that ordering was free.

        What this row actually establishes is the two halves the ordering sits
        between: the evaluator really does hand a top-level error out as an
        error-as-value, and `_materialize_bare` really does refuse it. It is
        the *premise*, not the conclusion.

        **The ordering itself is discriminated by four PRE-EXISTING
        handler-level rows**, verified by mutation (restoring the pre-v3.26
        order turns exactly these red and leaves this row green):

          - `test_compute_error_literal_v323.py::TestTheCrashTheEntityFormReachesTheWire`
            `::test_eval_returns_the_error_in_dict_form_not_as_an_entity_object`
          - `…::test_the_returned_shape_survives_the_wire_encoder`
          - `test_compute_result_path_error_code_only.py::test_a_value_form_error_materializes_code_only`
          - `…::test_changing_only_the_prose_does_not_move_the_result_hash`

        Written down because the prediction was wrong the obvious way: a row
        *named* for the ordering, sitting at the evaluator seam, cannot see it
        — only a row that drives the handler can. An over-claiming docstring
        here is how a later reader deletes the tests doing the work.
        """
        ctx = _ctx()
        result = evaluate(
            Entity(type="compute/lookup/hash", data={"hash": _err_literal(ctx, "top")}),
            Scope(), Budget(), ctx,
        )
        assert is_error(result)
        with pytest.raises(RuntimeError):
            _materialize_bare(result, ctx)


class TestArraysMaterializeElementWise:
    """The boundary v3.24 forced open, independent of errors.

    Before the collection primitives, no evaluator path produced an
    array-of-entities, so `_materialize_bare` had no array branch and an
    `Entity` inside a list reached the encoder alive. That is the
    `error_to_wire` failure shape one container out: `cbor2` raises inside the
    inbound handler task, the peer answers *nothing*, and the caller sees an
    i/o timeout — a serialization bug wearing a network bug's costume.
    """

    def test_entity_elements_become_bare_hashes(self):
        ctx = _ctx()
        inner = Entity(type="example/thing", data={"n": 1})
        out = _materialize_bare([inner, 2], ctx)
        assert isinstance(out[0], bytes) and out[1] == 2
        assert ctx.content_store.get(out[0]).data == {"n": 1}

    def test_the_materialized_array_is_encodable(self):
        """Stated as the property, because 'is a bytes' and 'survives the
        encoder' are two claims and only the second is the bug."""
        ctx = _ctx()
        out = _materialize_bare([Entity(type="example/thing", data={"n": 1})], ctx)
        ecf_encode(out)  # must not raise

    def test_a_live_entity_in_an_array_would_not_encode(self):
        """The teeth control: the pre-fix value really is unencodable, so the
        row above is measuring the fix and not a tautology."""
        with pytest.raises(Exception):
            ecf_encode([Entity(type="example/thing", data={"n": 1})])

    def test_capturing_an_array_of_entities_into_a_closure_is_a_crossing(self):
        """`let g = group-by(…) in map(g, fn)` — the shape v3.24 makes routine,
        and the second place the missing array boundary was fatal.

        Capturing a scope binding writes it to the content store, which is a
        compute→non-compute crossing; the `Entity`-valued branch already
        materialized (α) and the **array**-valued branch did not, so a binding
        holding a list of `system/compute/group` entities reached the encoder
        alive and killed the handler task. Found by this session's group-by
        containment row, which could not deliver its fixture until it was
        fixed — the defect is upstream of the ruling being implemented, not
        part of it.
        """
        ctx = _ctx()
        groups = _builtin(ctx, BUILTIN_GROUP_BY, {
            "collection": _lit(ctx, [1, 2]), "fn": _const_lambda(ctx, "k"),
        })
        scope = Scope()
        scope.set("g", groups)
        # Evaluating a lambda captures the enclosing scope into a
        # `compute/scope` entity — the crossing under test.
        closure = evaluate(
            Entity(type="compute/lambda", data={
                "params": ["x"], "body": _scope_ref(ctx, "g"),
            }),
            scope, Budget(), ctx,
        )
        assert not is_error(closure), f"scope capture failed: {closure!r}"
        env = ctx.content_store.get(closure.data["env"])
        binding = env.data["bindings"]["g"]
        assert binding["kind"] == "value"
        assert all(isinstance(el, bytes) for el in binding["value"]), (
            "an entity ELEMENT must be stored and referenced by its bare "
            f"system/hash, like an entity FIELD; got {binding['value']!r}"
        )
        # And the captured scope round-trips through the encoder, which is the
        # property the bare form buys.
        ecf_encode({"type": env.type, "data": env.data})

    def test_a_map_closure_returning_a_construct_materializes(self):
        """The reachable production path for the row above — `map` over a
        closure that constructs. This existed before v3.24 and was already
        broken; the collection primitives are what made it common."""
        ctx = _ctx()
        fn = _lambda(ctx, ["x"], _put(ctx, Entity(
            type="compute/construct", data={
                "entity_type": "example/wrapped",
                "fields": {"v": _scope_ref(ctx, "x")},
            },
        )))
        out = _builtin(ctx, BUILTIN_MAP, {
            "collection": _lit(ctx, [1, 2]), "fn": fn,
        })
        materialized = _materialize_bare(out, ctx)
        assert all(isinstance(h, bytes) for h in materialized)
        assert ctx.content_store.get(materialized[0]).data == {"v": 1}
        ecf_encode(materialized)


class TestCanonicalArgOrder:
    """§8.2: *"`compute/apply` arguments MUST be evaluated in ECF canonical map
    key order"* — keys sorted by encoded byte length, then lexicographically.

    For `assoc` that is `index` (5), `value` (5), `collection` (10). The rule
    is only *observable* when two args would each produce a different error, so
    that is the fixture.

    **`entity-core-go` evaluates the v3.24 builtins positionally**
    (`builtinAssoc` takes `collection` first), so it answers `coll_error` where
    this answers `idx_error`. Routed as an observation — §8.2 is a `[MUST]` and
    the divergence is on the returned code, i.e. on the bytes.
    """

    def test_the_first_canonical_arg_wins_when_two_would_error(self):
        ctx = _ctx()
        out = _builtin(ctx, BUILTIN_ASSOC, {
            "collection": _err_literal(ctx, "coll_error"),
            "index": _err_literal(ctx, "idx_error"),
            "value": _lit(ctx, 0),
        })
        assert _code(out) == "idx_error", (
            "args must be evaluated in ECF canonical key order (index < value "
            "< collection), not in the order the primitive reads them"
        )
