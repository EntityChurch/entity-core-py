"""CV-9a in-tree, at the corpus vector's exact shape — and why the corpus
cannot drive it over the wire.

`worked/v325-corner/cv9a-map-depth-exceeded-contains` is the §6.1 vector for
the §8.3 ruling (`depth_exceeded` CONTAINS). Shape, from `entity-core-go`
`cmd/internal/compute-corpus/worked_v325.go`:

    f(k)  = if k <= 0 then 0 else 1 + f(k-1)      (non-tail; depth grows per level)
    probe = construct app/corpus/probe { value: map(λx. f(x), [1, 60, 1]) }
    budget = {operations: 100000, depth: 24}

f(1) is one level and f(60) is sixty, so at depth 24 the trip point has a wide
margin both ways: the answer is `[1, E, 1]`.

**Why this file exists, and it is a finding rather than extra coverage.**
Cross-blessing py's wire emission against go's *in-process* emission reported
CV-9a as the one non-agreeing vector of 362. It is not a divergence. The wire
profile sends `params.budget` as a **scalar operations count** — `peeremit.go`
encodes `{"budget": uint64(v.Budget.Operations)}` and there is no wire field
for `depth` at all — so a route-B emission answers under the *peer's default*
depth (1024 here), where f(60) simply succeeds and the array is `[1, 60, 1]`.
Route A answers under the vector's depth 24 and gets `[1, E, 1]`. Two routes,
two correct answers, one manufactured red.

Measured both ways, which is what turns that from an argument into a result:

  * go-wire ↔ py-wire cross-bless: **LOCKED, 362/362 byte-identical**
    (corpus `333de571b27c513c`, go `e777412`, 2026-08-22).
  * py in-process at the vector's real budget produces boundary
    `0028…2017f`, which is **go's in-process emission for CV-9a, byte for
    byte** — pinned below.

**The half that matters for the ruling:** over the wire CV-9a produces no error
at all. So on the route both siblings actually use to cross-bless, *the vector
for the depth ruling does not exercise the depth ruling* — it locks green while
measuring nothing. That is the deceptive-green shape, and the discriminating
rows for §8.3 live in `test_compute_v327_closure_result_positions.py` where the
budget is ours to set. Routed to core-go.
"""

from __future__ import annotations

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree

from entity_handlers.compute import (
    BUILTIN_MAP,
    ERR_DEPTH_EXCEEDED,
    Budget,
    EvalContext,
    Scope,
    _materialize_bare,
    error_data,
    evaluate,
    is_error,
)

PEER_ID = "test-peer"
FN_PATH = "corpus/fn/depth"

#: `entity-core-go`'s in-process emission for CV-9a, measured 2026-08-22 at go
#: `e777412` over wire corpus `333de571b27c513c`. This is an ORACLE PIN, not a
#: value read off our own output: it is what the sibling answered, and the row
#: below asserts we produce the same bytes at the vector's real budget.
GO_CV9A_BOUNDARY = (
    "00289092cbaba3250e385cecca471fe3437c781f3463c08d95426494000972017f"
)


def _ctx() -> EvalContext:
    return EvalContext(
        content_store=ContentStore(),
        entity_tree=EntityTree(PEER_ID),
        local_peer_id=PEER_ID,
        capability={"grants": [{
            "handlers": {"include": ["*"]},
            "operations": {"include": ["*"]},
            "resources": {"include": ["*"]},
        }]},
        included={},
        has_content_store_access=True,
    )


def _put(ctx: EvalContext, e: Entity) -> bytes:
    return ctx.content_store.put(e)


def _lit(ctx: EvalContext, v: object) -> bytes:
    return _put(ctx, Entity(type="compute/literal", data={"value": v}))


def _scope(ctx: EvalContext, name: str) -> bytes:
    return _put(ctx, Entity(type="compute/lookup/scope", data={"name": name}))


def _tree(ctx: EvalContext, path: str) -> bytes:
    return _put(ctx, Entity(type="compute/lookup/tree", data={"path": path}))


def _arith(ctx: EvalContext, op: str, left: bytes, right: bytes) -> bytes:
    return _put(ctx, Entity(type="compute/arithmetic", data={
        "op": op, "left": left, "right": right,
    }))


def _cmp(ctx: EvalContext, op: str, left: bytes, right: bytes) -> bytes:
    return _put(ctx, Entity(type="compute/compare", data={
        "op": op, "left": left, "right": right,
    }))


def _if(ctx: EvalContext, cond: bytes, then_: bytes, else_: bytes) -> bytes:
    return _put(ctx, Entity(type="compute/if", data={
        "condition": cond, "then": then_, "else": else_,
    }))


def _lambda(ctx: EvalContext, params: list[str], body: bytes) -> bytes:
    return _put(ctx, Entity(type="compute/lambda", data={
        "params": params, "body": body,
    }))


def _apply_closure(ctx: EvalContext, fn: bytes, args: dict[str, bytes]) -> bytes:
    return _put(ctx, Entity(type="compute/apply", data={"fn": fn, "args": args}))


def _build_recursive_depth_fn(ctx: EvalContext) -> None:
    """`f(k) = if k <= 0 then 0 else 1 + f(k-1)`, bound at `corpus/fn/depth`."""
    recur = _arith(ctx, "add", _lit(ctx, 1), _apply_closure(
        ctx, _tree(ctx, FN_PATH),
        {"k": _arith(ctx, "sub", _scope(ctx, "k"), _lit(ctx, 1))},
    ))
    guard = _cmp(ctx, "lte", _scope(ctx, "k"), _lit(ctx, 0))
    f = _lambda(ctx, ["k"], _if(ctx, guard, _lit(ctx, 0), recur))
    ctx.entity_tree.set(FN_PATH, f)


def _map_over(ctx: EvalContext, collection: list[int]) -> bytes:
    map_fn = _lambda(ctx, ["x"], _apply_closure(
        ctx, _tree(ctx, FN_PATH), {"k": _scope(ctx, "x")},
    ))
    return _put(ctx, Entity(type="compute/apply", data={
        "path": BUILTIN_MAP,
        "operation": "eval",
        "args": {"collection": _lit(ctx, collection), "fn": map_fn},
    }))


def _probe(ctx: EvalContext, value: bytes) -> Entity:
    return Entity(type="compute/construct", data={
        "entity_type": "app/corpus/probe",
        "fields": {"value": value},
    })


class TestCv9aAtTheVectorsRealBudget:
    def test_the_array_is_one_error_one(self):
        ctx = _ctx()
        _build_recursive_depth_fn(ctx)
        result = evaluate(
            ctx.content_store.get(_map_over(ctx, [1, 60, 1])),
            Scope(), Budget(operations=100_000, depth=24), ctx,
        )

        assert isinstance(result, list), f"short-circuited: {result!r}"
        assert len(result) == 3, f"wrong arity: {result!r}"
        assert result[0] == 1 and result[2] == 1, f"neighbours moved: {result!r}"
        assert is_error(result[1])
        assert error_data(result[1]).get("code") == ERR_DEPTH_EXCEEDED

    def test_the_boundary_is_byte_identical_to_core_gos_emission(self):
        """The cross-impl assertion, oracle-pinned rather than self-measured.

        The boundary is the **constructed entity's** hash, so a contained
        error's bytes are in it — which is why §2.4's code-only materialization
        is load-bearing here and not tidiness: `message` would put each seat's
        prose into the hash. Note the reduction happens at the crossing
        (`_materialize_bare`), **not** in `evaluate`'s return — a row that reads
        the raw result sees `{code, message}` and concludes we diverge, which is
        a mistake this file made once before it read the right stage.
        """
        ctx = _ctx()
        _build_recursive_depth_fn(ctx)
        built = evaluate(
            _probe(ctx, _map_over(ctx, [1, 60, 1])),
            Scope(), Budget(operations=100_000, depth=24), ctx,
        )
        boundary = _materialize_bare(built, ctx)

        assert boundary.compute_hash().hex() == GO_CV9A_BOUNDARY
        contained = ctx.content_store.get(boundary.data["value"][1])
        assert dict(contained.data) == {"code": ERR_DEPTH_EXCEEDED}, (
            "the contained error carries prose into the hashed bytes"
        )


class TestWhyRouteBCannotDriveThisVector:
    """The vector's answer is a function of `depth`, and `depth` has no wire
    field. Pinned so nobody re-derives the false red from a mixed cross-bless.
    """

    def test_at_the_peers_default_depth_the_error_never_happens(self):
        ctx = _ctx()
        _build_recursive_depth_fn(ctx)
        result = evaluate(
            ctx.content_store.get(_map_over(ctx, [1, 60, 1])),
            Scope(), Budget(operations=100_000), ctx,  # default depth
        )
        assert result == [1, 60, 1], (
            "if this ever errors, the default depth has dropped below 60 and "
            "the wire route starts exercising §8.3 by accident — which would "
            "be worth knowing, not worth relying on"
        )

    def test_so_a_wire_emission_of_cv9a_asserts_nothing_about_the_ruling(self):
        """Stated as an assertion so it is not just a comment: the two budgets
        give different answers, therefore an emission that does not carry the
        budget cannot be compared against one that does."""
        ctx = _ctx()
        _build_recursive_depth_fn(ctx)
        at_vector = evaluate(
            ctx.content_store.get(_map_over(ctx, [1, 60, 1])),
            Scope(), Budget(operations=100_000, depth=24), ctx,
        )
        ctx2 = _ctx()
        _build_recursive_depth_fn(ctx2)
        at_default = evaluate(
            ctx2.content_store.get(_map_over(ctx2, [1, 60, 1])),
            Scope(), Budget(operations=100_000), ctx2,
        )
        assert at_vector != at_default
