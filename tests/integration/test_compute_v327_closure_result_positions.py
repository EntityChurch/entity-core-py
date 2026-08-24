"""EXTENSION-COMPUTE C-8 — the closure-result positions of `map`/`filter`/`fold`.

Ruled by arch 2026-08-21 (`entity-system-architecture` `172589e`,
`PROPOSAL-COMPUTE-CLOSURE-RESULT-POSITIONS-AND-CONCAT-ARGS-SHAPE`), routed to
this seat by `entity-core-go` (`2026-08-21-c`, go `9ad0110`). **The normative
text is still v3.26 and still says the contained set is "exactly three"** — the
C-8 deltas target v3.27 and are not folded in, so this file cites the ruling and
the SA that chases the spec text (SA-PY-26).

The three positions and why they differ (arch §2.3), which is one rule:

    A position is CONTAINED when the primitive PLACES the value without reading
    it, and CONSUMED when it READS the value to decide control flow, ordering,
    membership, or a write location.

  * `map`'s output element — placed → **contain** (§1.5's NaN model is
    element-wise: `[a, E, c]`, not one `E`).
  * `filter`'s predicate result — read for truthiness → **short-circuit**
    (containing it coerces an error to a truth value and silently drops the
    element).
  * `fold`'s accumulator — bound into the next invocation → **contain**, so a
    closure that ignores its accumulator **recovers**. Arch names this the one
    of the three with the widest blast radius if wrong, because it is the only
    one where the other reading produces a different *value* rather than a
    different cost.

**What this file is really guarding is a nothing-broke.** Landing all three
positions changed py's behaviour at `map` and `fold` and broke **zero** of the
3998 pre-existing tests. That is not reassurance, it is the finding: the whole
suite, plus a 352-vector corpus cross-blessed byte-identical three ways, never
once put an error in a closure-result position. Same law as the collection
operand one position over — *two readings that agree everywhere your fixtures
live are one reading* — with the corpus as the fixture set.

Every row is written to fail under the OTHER reading. The provenance pairs are
the point of the pairs: arch's ruling is that a `compute/error` behaves
identically however it came to exist (§2.4), so each disposition is asserted
twice — once for an error MINTED by a failing op inside the closure, once for a
value-form error the closure merely returns.
"""

from __future__ import annotations

import pytest

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree

from entity_handlers.compute import (
    _COMPUTE_TYPE_DEFS,
    _CONTAINED_ARGS,
    _EVAL_LIMIT_CODES,
    BUILTIN_CONCAT,
    BUILTIN_FILTER,
    BUILTIN_FOLD,
    BUILTIN_MAP,
    BUILTIN_STORE,
    ERR_BUDGET_EXHAUSTED,
    ERR_CASCADE_LIMIT,
    ERR_DEPTH_EXCEEDED,
    ERR_DIVISION_BY_ZERO,
    ERR_TYPE_MISMATCH,
    Budget,
    EvalContext,
    Scope,
    _materialize_bare,
    error_data,
    evaluate,
    is_error,
    is_eval_limit,
)

PEER_ID = "test-peer-id"

WILDCARD_CAP = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": ["*"]},
    }],
}

SEEDED = "seeded_error"


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


def _scope_ref(ctx: EvalContext, name: str) -> bytes:
    return _put(ctx, Entity(type="compute/lookup/scope", data={"name": name}))


def _lambda(ctx: EvalContext, params: list[str], body: bytes) -> bytes:
    return _put(ctx, Entity(type="compute/lambda", data={"params": params, "body": body}))


def _builtin(ctx: EvalContext, path: str, args: dict[str, bytes], budget=None):
    expr = Entity(type="compute/apply", data={
        "path": path, "operation": "eval", "args": args,
    })
    return evaluate(expr, Scope(), budget or Budget(), ctx)


def _code(result) -> str:
    assert is_error(result), f"expected an error-as-value, got {result!r}"
    return error_data(result).get("code", "")


# --- the two representations, as closure BODIES ------------------------------
#
# `minted` and `value_form` below are the pair every disposition row is
# parametrized over. They are the whole reason this file exists: arch's ruling
# is that the two must be indistinguishable, and the defect it names is an
# implementation letting them diverge.

def _body_minted_error(ctx: EvalContext) -> bytes:
    """`1 / 0` — an error the evaluator MINTS inside the closure body."""
    return _put(ctx, Entity(type="compute/arithmetic", data={
        "op": "div", "left": _lit(ctx, 1), "right": _lit(ctx, 0),
    }))


def _body_value_form_error(ctx: EvalContext, code: str = SEEDED) -> bytes:
    """A `compute/lookup/hash` onto a STORED `compute/error` — SA-1 returns it
    unchanged, so the closure's result is an error-kind `Entity` that never
    passed through a failure path."""
    stored = _put(ctx, Entity(
        type="compute/error", data={"code": code, "message": "prose"},
    ))
    return _put(ctx, Entity(type="compute/lookup/hash", data={"hash": stored}))


def _err_body(ctx: EvalContext, form: str, code: str = SEEDED) -> tuple[bytes, str]:
    """(body hash, the code it yields) for either representation."""
    if form == "minted":
        return _body_minted_error(ctx), ERR_DIVISION_BY_ZERO
    return _body_value_form_error(ctx, code), code


BOTH_FORMS = pytest.mark.parametrize("form", ["minted", "value_form"])


# ============================================================================
# map — the output element CONTAINS
# ============================================================================

class TestMapContainsTheClosureResult:
    """go's CV-8a, arch's CV-8a/CV-8b pair."""

    @BOTH_FORMS
    def test_every_element_erroring_yields_an_array_of_errors_not_one_error(
        self, form: str,
    ):
        """The discriminator. An implementation that short-circuits yields a
        single error; one that contains yields an array of the same length.

        Length is the assertion that separates them, so it is asserted before
        the codes: a row that only checked `is_error(result[0])` passes against
        a peer that returns `[E]` for a two-element input.
        """
        ctx = _ctx()
        body, code = _err_body(ctx, form)
        result = _builtin(ctx, BUILTIN_MAP, {
            "collection": _lit(ctx, [1, 2]),
            "fn": _lambda(ctx, ["x"], body),
        })

        assert not is_error(result), (
            "map short-circuited the closure result — the pre-C-8 behaviour"
        )
        assert isinstance(result, list) and len(result) == 2
        assert [_code(el) for el in result] == [code, code]

    @BOTH_FORMS
    def test_a_failing_element_does_not_disturb_its_neighbours_positions(
        self, form: str,
    ):
        """§1.5: *"the same model as NaN propagation in IEEE 754"* — and that
        model is **element-wise**. `map(f, [1,2,3])` where `f` fails only on
        element 2 is `[a, E, c]`.

        This is the row the "exactly three positions" sentence cost us: it is
        not a corner, it is the ordinary use of `map` over data that has a hole
        in it, and under the old behaviour the two good elements were discarded
        along with their positions.
        """
        ctx = _ctx()
        bad, code = _err_body(ctx, form)
        # lambda x: if x == 0 then <error> else 100
        body = _put(ctx, Entity(type="compute/if", data={
            "condition": _put(ctx, Entity(type="compute/compare", data={
                "op": "eq", "left": _scope_ref(ctx, "x"), "right": _lit(ctx, 0),
            })),
            "then": bad,
            "else": _lit(ctx, 100),
        }))
        result = _builtin(ctx, BUILTIN_MAP, {
            "collection": _lit(ctx, [1, 0, 2]),
            "fn": _lambda(ctx, ["x"], body),
        })

        assert isinstance(result, list) and len(result) == 3
        assert result[0] == 100 and result[2] == 100
        assert _code(result[1]) == code

    def test_the_two_representations_give_the_identical_shape(self):
        """§2.4's `[MUST]` stated directly, rather than inferred from the two
        parametrized rows passing separately.

        The defect arch ruled on is not "map is wrong"; it is that two closures
        producing the same `code` gave different results depending only on how
        the error came to exist. A pair of green rows in different files is not
        that assertion — an implementation can satisfy each and still be
        provenance-dependent if the two use different codes. Here both arms are
        forced to `division_by_zero` so the comparison is exact.
        """
        ctx = _ctx()
        minted = _builtin(ctx, BUILTIN_MAP, {
            "collection": _lit(ctx, [1, 2]),
            "fn": _lambda(ctx, ["x"], _body_minted_error(ctx)),
        })
        value_form = _builtin(ctx, BUILTIN_MAP, {
            "collection": _lit(ctx, [1, 2]),
            "fn": _lambda(
                ctx, ["x"], _body_value_form_error(ctx, ERR_DIVISION_BY_ZERO),
            ),
        })

        assert [_code(e) for e in minted] == [_code(e) for e in value_form]
        assert len(minted) == len(value_form) == 2

    def test_the_contained_element_materializes_code_only(self):
        """The v3.26 boundary, reached from the new position — and it needed no
        new carve-out.

        `_materialize_element` puts the carve-out at the ARRAY ELEMENT rather
        than per-primitive, so `map`'s output element was already covered before
        the position existed. That was the stated reason for the placement
        ("the fourth container is silently uncovered otherwise"); this row is
        what turns the reason into evidence.

        Code-only is load-bearing: a contained `message` would fork the
        containing array's bytes between two peers whose prose differs.
        """
        ctx = _ctx()
        result = _builtin(ctx, BUILTIN_MAP, {
            "collection": _lit(ctx, [1]),
            "fn": _lambda(ctx, ["x"], _body_value_form_error(ctx)),
        })
        bare = _materialize_bare(result, ctx)

        assert isinstance(bare[0], bytes), "a contained entity element is a bare hash"
        stored = ctx.content_store.get(bare[0])
        assert stored.type == "compute/error"
        assert stored.data == {"code": SEEDED}, (
            f"diagnostics leaked into content-addressed bytes: {stored.data!r}"
        )

    def test_the_collection_operand_still_short_circuits(self):
        """The guard, not the carve-out. `map`'s *collection* is consumed —
        its length is read — so an error there is unchanged by C-8.

        Without this row, "map contains errors now" is a sentence a later reader
        can apply one arg over.
        """
        ctx = _ctx()
        result = _builtin(ctx, BUILTIN_MAP, {
            "collection": _body_value_form_error(ctx),
            "fn": _lambda(ctx, ["x"], _lit(ctx, 1)),
        })
        assert _code(result) == SEEDED


# ============================================================================
# filter — the predicate result is CONSUMED
# ============================================================================

class TestFilterShortCircuitsThePredicateResult:
    """go's CV-8b, arch's CV-8c."""

    @BOTH_FORMS
    def test_an_erroring_predicate_short_circuits(self, form: str):
        ctx = _ctx()
        body, code = _err_body(ctx, form)
        result = _builtin(ctx, BUILTIN_FILTER, {
            "collection": _lit(ctx, [1, 2]),
            "fn": _lambda(ctx, ["x"], body),
        })
        assert _code(result) == code

    def test_the_empty_array_is_a_reachable_answer_so_dropping_is_silent(self):
        """The teeth. The failure mode arch names for a contained reading is not
        a crash — it is `[]`, *a well-formed wrong answer carrying no error*.

        This row exists to prove `[]` is a value `filter` genuinely returns, so
        the row above is distinguishing "short-circuited" from "silently dropped
        every element" and not from "raised". Without it, the assertion above is
        satisfied by any implementation that fails loudly for any reason.

        Same argument §3.5 used to refuse clamping `range(-1)` to `[]`.
        """
        ctx = _ctx()
        result = _builtin(ctx, BUILTIN_FILTER, {
            "collection": _lit(ctx, [1, 2]),
            "fn": _lambda(ctx, ["x"], _lit(ctx, False)),
        })
        assert result == [], "a contained-error reading would produce exactly this"


# ============================================================================
# fold — the accumulator is CONTAINED, so a closure can recover
# ============================================================================

class TestFoldContainsTheAccumulator:
    """arch's CV-8d — *"deliberately the shape where contain and short-circuit
    produce different **values**"*.

    go's CV-8c (`fold(λacc x.E, 0, [1])`) is NOT this shape: with one element
    and a closure that returns the error, both readings answer with that same
    error, so the vector cannot see the disposition it is named for. The
    discriminating shape is a closure that **ignores** its accumulator.
    """

    @BOTH_FORMS
    def test_a_closure_ignoring_an_error_accumulator_recovers(self, form: str):
        """The CV-8d row. `initial` is an error; the closure returns its element
        and never reads `acc`; the fold answers with a plain integer.

        Under a short-circuit reading this is an error — which is why arch calls
        it the widest blast radius: the two readings disagree about the *answer*,
        not about how much work was done.
        """
        ctx = _ctx()
        body, _ = _err_body(ctx, form)
        initial = _put(ctx, Entity(type="compute/apply", data={
            # `initial` must arrive as a live error VALUE. Evaluating the error
            # body in the arg position is how that happens; the arg loop is what
            # decides whether it survives, which is the thing under test.
            "path": BUILTIN_MAP, "operation": "eval",
            "args": {
                "collection": _lit(ctx, [0]),
                "fn": _lambda(ctx, ["x"], body),
            },
        }))
        # fn = lambda acc, el: el   (ignores acc entirely)
        result = _builtin(ctx, BUILTIN_FOLD, {
            "collection": _lit(ctx, [7]),
            "fn": _lambda(ctx, ["acc", "el"], _scope_ref(ctx, "el")),
            "initial": _put(ctx, Entity(type="compute/index", data={
                "collection": initial, "index": _lit(ctx, 0),
            })),
        })

        assert not is_error(result), (
            "the fold short-circuited an accumulator it never read — a closure "
            "that ignores `acc` MUST recover (arch C-8 §2.3)"
        )
        assert result == 7

    @BOTH_FORMS
    def test_an_error_accumulator_mid_fold_does_not_stop_the_fold(self, form: str):
        """The other half, and the row that separates *contained* from
        *propagated-meaning-aborted* — the two words go's report uses
        interchangeably.

        The closure errors on the first step and answers `99` on the second, so
        a fold that keeps going overwrites the error and returns `99`, while one
        that stops returns the error. Both readings answer identically for a
        SINGLE-element fold whose closure returns the error — which is exactly
        go's CV-8c, and why that vector cannot see this.
        """
        ctx = _ctx()
        body, _ = _err_body(ctx, form)
        # fn = lambda acc, el: if el == 2 then 99 else <error>
        body_expr = _put(ctx, Entity(type="compute/if", data={
            "condition": _put(ctx, Entity(type="compute/compare", data={
                "op": "eq", "left": _scope_ref(ctx, "el"), "right": _lit(ctx, 2),
            })),
            "then": _lit(ctx, 99),
            "else": body,
        }))
        result = _builtin(ctx, BUILTIN_FOLD, {
            "collection": _lit(ctx, [1, 2]),
            "fn": _lambda(ctx, ["acc", "el"], body_expr),
            "initial": _lit(ctx, 0),
        })

        assert not is_error(result), (
            "the fold stopped at an accumulator it never read — the second step "
            "was never invoked"
        )
        assert result == 99

    @BOTH_FORMS
    def test_the_final_accumulator_being_an_error_is_the_folds_answer(
        self, form: str,
    ):
        """go's CV-8c shape, kept as a row and labelled as the NON-discriminator.

        It passes under both readings. It is here so nobody reintroduces it as
        the coverage for the class — *a control-only fixture at a call site is
        not coverage* — and so the corpus vector go asks us to bless has a named
        counterpart in-tree.
        """
        ctx = _ctx()
        body, code = _err_body(ctx, form)
        result = _builtin(ctx, BUILTIN_FOLD, {
            "collection": _lit(ctx, [1]),
            "fn": _lambda(ctx, ["acc", "el"], body),
            "initial": _lit(ctx, 0),
        })
        assert _code(result) == code

    def test_initial_is_registered_as_a_contained_arg(self):
        """The enforcement point for the arg-axis half, read off the table
        rather than inferred from behaviour.

        `fold`'s `initial` short-circuited at the generic arg loop before C-8,
        which is *upstream* of `_eval_builtin` — so a reader fixing only the
        loop body would have left the recovery row failing for a reason nothing
        in `_eval_builtin` explains.
        """
        assert "initial" in _CONTAINED_ARGS[BUILTIN_FOLD]
        assert "collection" not in _CONTAINED_ARGS[BUILTIN_FOLD]
        assert "fn" not in _CONTAINED_ARGS[BUILTIN_FOLD]


# ============================================================================
# The evaluation-limit carve-out — go's lead call, py concurs on the outcome
# and diverges on the discriminator
# ============================================================================

class TestEvalLimitCodesPropagate:
    def test_a_real_budget_exhaustion_inside_a_map_aborts_the_map(self):
        """The reason for the carve-out, measured rather than argued.

        `evaluate` decrements once per call, so a contained `budget_exhausted`
        that let the loop continue would yield `[be, be, …]` — one stop-point
        turned into N, at a shifted budget, and two conformant peers forking on
        the array's bytes.
        """
        ctx = _ctx()
        result = _builtin(
            ctx, BUILTIN_MAP,
            {
                "collection": _lit(ctx, [1, 2, 3, 4]),
                "fn": _lambda(ctx, ["x"], _scope_ref(ctx, "x")),
            },
            budget=Budget(operations=6),
        )
        assert is_error(result), f"expected an abort, got {result!r}"
        assert _code(result) == ERR_BUDGET_EXHAUSTED
        assert not isinstance(result, list)

    def test_a_value_form_limit_code_propagates_too_and_that_is_the_divergence(
        self,
    ):
        """**Named divergence from `entity-core-go` `9ad0110`.**

        go checks `isEvalLimitCode` only on its MINTED arm (`err != nil` in
        `builtinMap`), so a closure returning a stored
        `compute/error{code: "budget_exhausted"}` is CONTAINED there and
        propagated here. That is the §2.4 provenance asymmetry the same ruling
        closed, narrowed to three codes — and the narrowing is what makes it
        easy to miss.

        py cannot express that split: it carries one representation, and the
        discriminator is the code, read through `error_data`. This row is the
        claim go is asked to concur with or refute; the arm above is the one
        both seats already agree on.
        """
        ctx = _ctx()
        result = _builtin(ctx, BUILTIN_MAP, {
            "collection": _lit(ctx, [1, 2]),
            "fn": _lambda(
                ctx, ["x"], _body_value_form_error(ctx, ERR_BUDGET_EXHAUSTED),
            ),
        })
        assert is_error(result) and _code(result) == ERR_BUDGET_EXHAUSTED

    def test_the_carve_out_is_exactly_the_three_limit_codes(self):
        """A carve-out that grows silently stops being a carve-out.

        `division_by_zero` is the control: it is the code go's CV-8a uses
        precisely because it is uncontested under every reading, so a seat that
        "helpfully" widened the limit set would fail here rather than at the
        wire.
        """
        assert _EVAL_LIMIT_CODES == {
            ERR_BUDGET_EXHAUSTED, ERR_DEPTH_EXCEEDED, ERR_CASCADE_LIMIT,
        }
        assert not is_eval_limit(
            {"type": "compute/error", "data": {"code": ERR_DIVISION_BY_ZERO}}
        )
        assert not is_eval_limit({"type": "primitive/any", "data": ERR_BUDGET_EXHAUSTED}), (
            "the predicate is kind-AND-code, so a plain string is not a limit"
        )

    def test_the_predicate_reads_the_code_and_not_the_representation(self):
        """The whole objection to go's shape, as an assertion.

        Both representations of the same code MUST answer identically — that is
        §2.4, and a discriminator that reads the representation re-opens it.
        """
        as_dict = {"type": "compute/error", "data": {"code": ERR_BUDGET_EXHAUSTED}}
        as_entity = Entity(type="compute/error", data={"code": ERR_BUDGET_EXHAUSTED})
        assert is_eval_limit(as_dict) is is_eval_limit(as_entity) is True


# ============================================================================
# C-12 — store's `path` is a consumed operand (confirming core-go's sweep)
# ============================================================================

class TestStorePathIsConsumed:
    """`entity-core-go` `4519554` found this by their own enforcement sweep and
    asked all three seats to confirm rather than seeding a vector unilaterally.
    arch confirmed the reading (C-12).

    py agrees **by construction**: `path` is absent from `_CONTAINED_ARGS`, so
    it short-circuits at the generic arg loop and never reaches the
    `isinstance(path_val, str)` shape check that would answer `type_mismatch`.
    Confirmed here rather than asserted from reading the table, because the
    table is upstream of the function whose guard would mask it.
    """

    def test_an_error_path_short_circuits_rather_than_type_mismatching(self):
        ctx = _ctx()
        result = _builtin(ctx, BUILTIN_STORE, {
            "path": _body_value_form_error(ctx),
            "value": _lit(ctx, 42),
        })
        assert _code(result) == SEEDED, (
            "a `type_mismatch` here means the error reached store's own shape "
            "check — go's pre-4519554 behaviour, and it discards the code"
        )

    def test_a_non_error_non_string_path_is_still_a_type_mismatch(self):
        """The control that keeps the row above attributable: the shape check
        still fires for something that genuinely is the wrong shape."""
        ctx = _ctx()
        result = _builtin(ctx, BUILTIN_STORE, {
            "path": _lit(ctx, 42),
            "value": _lit(ctx, 42),
        })
        assert _code(result) == ERR_TYPE_MISMATCH

    def test_value_remains_the_one_contained_position(self):
        assert _CONTAINED_ARGS[BUILTIN_STORE] == ("value",)


# ============================================================================
# C-8 D3 — `concat-args.collections` is ONE hash, not an array of them
# ============================================================================

class TestConcatArgsDeclaredShape:
    def test_collections_is_a_scalar_hash(self):
        """All three seats EVALUATED the scalar shape while DECLARING the array
        shape. arch ruled the evaluated shape normative — and explicitly not
        because three seats agreed, which is cohort-consistency.

        The derivation is §7.1: the reactive `walk` descends on scalar
        `system/hash` field values and does not enter arrays, so the declared
        shape leaves every `lookup/tree` inside every `concat` sub-collection
        unregistered. The expression evaluates correctly once and is then never
        woken again — the quietest failure mode there is.
        """
        decl = next(
            d for d in _COMPUTE_TYPE_DEFS
            if d["name"] == "system/compute/concat-args"
        )
        assert decl["fields"]["collections"] == {"type_ref": "system/hash"}

    def test_no_builtin_ARGS_type_declares_an_array_of_hashes(self):
        """The rule behind D3, not just the one row it moved.

        `concat-args` was the only array-of-hashes among the **args** types, and
        arch's D5 records that §7.1's walk stays array-blind regardless — so a
        future `array_of: system/hash` arg re-opens the same silent reactive
        hole with no ruling attached to it. This row makes adding one a
        deliberate act.

        **Scoped to `*-args`, and the scope is a correction the gate made to its
        author.** The first draft swept every compute type declaration and
        failed on `system/compute/subgraph.authorized_data_hashes` — which is an
        authorization *allowlist*, not a reference the walk should follow, so
        sweeping it would have been the D5 hole's opposite: a gate demanding a
        change that makes nothing better. §7.1's walk enters an expression's arg
        references; that is the unit the rule binds, so that is the unit
        measured. (*When a rule is scoped by an inventory, the inventory's unit
        must be the thing the rule binds.*)
        """
        offenders = [
            (d["name"], field)
            for d in _COMPUTE_TYPE_DEFS
            if d["name"].endswith("-args")
            for field, spec in (d.get("fields") or {}).items()
            if isinstance(spec, dict)
            and spec.get("array_of") == {"type_ref": "system/hash"}
        ]
        assert offenders == [], (
            "an array-valued reference arg is invisible to §7.1's walk: "
            f"{offenders}"
        )
        assert any(d["name"].endswith("-args") for d in _COMPUTE_TYPE_DEFS), (
            "the sweep matched nothing — a gate over an empty set is not a gate"
        )
