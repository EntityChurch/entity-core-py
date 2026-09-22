"""§2.1 Q23 — a builtin-path apply carrying `capability`/`resource` is invalid.

Ruled 2026-08-16 (arch `7fdeea7`, `ROUTING-2026-08-16-i`) on `entity-core-go`'s
spec-issue `2026-08-16-c`. **All three seats changed**, including the one that
filed it — the text decided this, not a count.

**The rule.** `capability` and `resource` are defined in §2.1 *only* as
parameters of the **dispatched EXECUTE** — `capability` "replaces
`ctx.capability` when present in handler mode", `resource` "carries the resource
target for the dispatched EXECUTE". A `system/compute/builtins/*` path is
evaluated **inline** (§3.5) and dispatches **no EXECUTE**, so neither field has a
referent. The expression is malformed and the disposition is to say so:
`invalid_expression`.

**Why reject and not ignore — the load-bearing half.** The dual-check can only
ever **narrow**: a provided capability is honored *and* `ctx.capability` must
still cover the target. So a caller supplying one is asking for **less** than
ambient authority, and silently dropping that request runs the operation
**wider** than asked. The builtin where that lands is `store` — the one impure
builtin (§6.2), writing to a caller-specified path. Ignoring is the single
disposition that fails quietly in the dangerous direction. Nothing legitimate is
lost: §6.2 already fixes `store`'s authority at the caller's capability or the
installation grant, never at a field on the expression.

**Why the check sits before the fields are evaluated.** §4.1's pseudocode places
it *after* the resource-evaluation block, so a pseudocode-faithful implementation
would answer a builtin apply with an **error-valued resource** with that error
rather than `invalid_expression`. All three per-seat actions reject early, and
go landed it early; go filed the ordering as spec-issue `2026-08-16-d`.
`test_an_error_valued_resource_still_answers_invalid_expression` is the pin on
that choice — it is the one case where the two placements are distinguishable,
and it is what keeps the three seats byte-identical while the pseudocode is
fixed.

**Install time enforces it too** (arch `67708b1`, `ROUTING-2026-08-16-j`, closing
go spec-issue `2026-08-16-e`) — where `path` is a **static literal** under the
builtin prefix the whole condition is decidable without evaluating anything, so
the audit MUST reject it beside the F5 fail-fast. Where `path` is dynamic, the
eval-time rejection is the whole enforcement. See
`TestInstallTimeRejectsTheStaticLiteralBuiltinShape`.
"""

from __future__ import annotations

import pytest

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.compute import (
    BUILTIN_FILTER,
    BUILTIN_FOLD,
    BUILTIN_MAP,
    BUILTIN_STORE,
    ERR_INVALID_EXPRESSION,
    ERR_NOT_FOUND,
    Budget,
    EvalContext,
    Scope,
    evaluate,
    is_error,
)

# 46 Base58 characters — §5.4's minimum, and the alphabet excludes `0 O I l`,
# which is why this reads `Bui1tin`/`App1y`/`PeerJd`. It was 44 characters and
# carried three illegal ones, i.e. a "peer id" no conformant peer could hold,
# and nothing noticed until 0.8.2.20's G6 rule put `validate_absolute_path` on
# the authorization path: `app/data/y` qualifies to `/{PEER_ID}/app/data/y`,
# whose first segment was then not a peer_id, so the handler-grant ceiling
# check refused a target the wildcard grant covers.
PEER_ID = "2KTestBui1tinApp1yQ23PeerJdaaaaaaaaaaaaaaaaaaa"

WILDCARD_CAP = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": ["*"]},
    }],
    "allowances": {"content_store_access": True},
}

#: Every builtin path shape this evaluator routes differently. `arithmetic` is
#: an INLINE ALIAS, intercepted before the generic arg loop; `map`/`filter`/
#: `fold` are collection builtins, intercepted after it; `store` is the impure
#: one. The routing note named two of the three intercepts — a check placed at
#: either of them alone would leave the third reachable, so the parametrization
#: is the guard on placement, not thoroughness for its own sake.
BUILTIN_PATHS = [
    "system/compute/builtins/arithmetic",
    "system/compute/builtins/construct",
    BUILTIN_MAP,
    BUILTIN_FILTER,
    BUILTIN_FOLD,
    BUILTIN_STORE,
]


def _ctx() -> EvalContext:
    return EvalContext(
        content_store=ContentStore(),
        entity_tree=EntityTree(PEER_ID),
        local_peer_id=PEER_ID,
        capability=WILDCARD_CAP,
        included={},
        has_content_store_access=True,
    )


def _lit(value) -> Entity:
    return Entity(type="compute/literal", data={"value": value})


def _cap_entity(grant: dict) -> Entity:
    return Entity(type="system/capability/grant", data=grant)


def _apply(path: str, args: dict, **fields) -> Entity:
    data = {"path": path, "operation": "eval", "args": args}
    data.update(fields)
    return Entity(type="compute/apply", data=data)


def _assert_q23_rejection(result) -> None:
    assert is_error(result), "a builtin apply carrying either field is malformed"
    data = result["data"] if isinstance(result, dict) else result.data
    assert data["code"] == ERR_INVALID_EXPRESSION
    assert "capability or resource" in data["message"], (
        "the message must name the defect — an impl that answers "
        "invalid_expression for some unrelated reason is not conformant here"
    )


@pytest.mark.parametrize("path", BUILTIN_PATHS)
class TestEveryBuiltinPathRejects:
    """All three field shapes, across all three of this evaluator's intercepts."""

    def test_capability_and_resource(self, path: str):
        ctx = _ctx()
        result = evaluate(
            _apply(
                path, {},
                capability=ctx.content_store.put(_cap_entity(WILDCARD_CAP)),
                resource=ctx.content_store.put(_lit({"targets": ["app/out"]})),
            ),
            Scope(), Budget(), ctx,
        )
        _assert_q23_rejection(result)

    def test_resource_alone(self, path: str):
        ctx = _ctx()
        result = evaluate(
            _apply(
                path, {},
                resource=ctx.content_store.put(_lit({"targets": ["app/out"]})),
            ),
            Scope(), Budget(), ctx,
        )
        _assert_q23_rejection(result)

    def test_capability_alone_the_f5_shape(self, path: str):
        """F5 (*capability without resource*) is an install-time structural
        error, and arch asked each seat to confirm before remediating it. It is
        **subsumed** here: the Q23 rejection fires first and answers the same
        `invalid_expression`, so no separate F5 fix is owed on the builtin path.
        """
        ctx = _ctx()
        result = evaluate(
            _apply(
                path, {},
                capability=ctx.content_store.put(_cap_entity(WILDCARD_CAP)),
            ),
            Scope(), Budget(), ctx,
        )
        _assert_q23_rejection(result)


class TestTheRejectionIsStructuralAndEarly:
    """The placement pin. §4.1's pseudocode would answer these differently."""

    def test_an_error_valued_resource_still_answers_invalid_expression(self):
        """The only case where "reject early" and "reject after evaluating the
        resource" are distinguishable. Early wins: the fields are meaningless on
        this path, so there is nothing to evaluate and no error of theirs to
        propagate. Pinned because the normative pseudocode says otherwise and a
        fourth implementation reading it would diverge here (go spec-issue
        2026-08-16-d)."""
        ctx = _ctx()
        div_by_zero = ctx.content_store.put(Entity(
            type="compute/arithmetic",
            data={
                "op": "div",
                "left": ctx.content_store.put(_lit(1)),
                "right": ctx.content_store.put(_lit(0)),
            },
        ))

        result = evaluate(
            _apply(BUILTIN_STORE, {}, resource=div_by_zero), Scope(), Budget(), ctx,
        )

        _assert_q23_rejection(result)

    def test_an_unresolvable_resource_hash_still_answers_invalid_expression(self):
        """Same property from the other side: nothing about the meaningless
        field is resolved either, so a dangling reference in it cannot turn the
        answer into `not_found`."""
        ctx = _ctx()
        result = evaluate(
            _apply(BUILTIN_STORE, {}, resource=b"\x00" * 33), Scope(), Budget(), ctx,
        )
        _assert_q23_rejection(result)


class TestTheScopeIsExactlyBuiltinPaths:
    """What a too-broad rejection would break, and no existing test would catch:
    `capability`/`resource` are legal and load-bearing on a HANDLER apply."""

    def test_a_handler_apply_carrying_both_is_untouched(self):
        ctx = _ctx()
        seen: dict = {}

        def recording_execute(path, operation, args, eval_ctx, dispatch_cap,
                              resource_targets=None, resource_exclude=None):
            seen["path"] = path
            seen["dispatch_cap"] = dispatch_cap
            seen["resource_targets"] = resource_targets
            return {"type": "compute/result", "data": {"value": "ok"}}

        ctx._execute_fn = recording_execute
        expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "capability": ctx.content_store.put(_cap_entity(WILDCARD_CAP)),
            "resource": ctx.content_store.put(_lit({"targets": ["app/data/y"]})),
        })

        result = evaluate(expr, Scope(), Budget(), ctx)

        assert not is_error(result), (
            "the F1/F2/F4 dual-check path is where these fields MEAN something — "
            "rejecting by field presence alone would delete the resource ceiling"
        )
        assert seen["resource_targets"] == ["app/data/y"]

    def test_a_path_merely_starting_like_a_handler_is_untouched(self):
        """`system/compute/builtinsomething` is not a builtin path. The prefix
        is `system/compute/builtins/`, with the separator — matching go's
        `IsBuiltinPath`."""
        ctx = _ctx()
        result = evaluate(
            _apply(
                "system/compute/builtinsomething", {},
                resource=ctx.content_store.put(_lit({"targets": ["app/out"]})),
            ),
            Scope(), Budget(), ctx,
        )
        assert is_error(result)
        assert result["data"]["code"] == ERR_NOT_FOUND, (
            "no dispatcher is wired, so this reaches the ordinary handler-mode "
            "terminal — not the Q23 rejection"
        )


class TestInstallTimeRejectsTheStaticLiteralBuiltinShape:
    """The question this file left open is answered: arch `67708b1` /
    `ROUTING-2026-08-16-j`, closing go spec-issue `2026-08-16-e`.

    F5's sibling defect — `capability` without `resource` — was already caught
    at *install* as a static structural error, while this equally static shape
    (a path prefix plus field presence) installed clean and then answered
    `invalid_expression` on every re-evaluation. **An audit that fail-fasts one
    and installs the other is internally inconsistent**; both are structural and
    neither is value-dependent.

    The rule is scoped by the same conservative-static/dynamic-runtime split
    §2.1 already applies to `store` builtin paths: where `path` is a **static
    literal** under `system/compute/builtins/` the condition is decidable
    without evaluating anything, so install MUST reject; where `path` is
    dynamic, the eval-time rejection above is the whole enforcement.

    (The class this replaces characterized the pre-ruling behaviour and said it
    was *expected to flip if arch rules the static error owed*. It did.)
    """

    @staticmethod
    def _static_error_codes(result) -> list[str]:
        return [e["code"] for e in result.static_errors]

    @pytest.mark.parametrize("path", BUILTIN_PATHS)
    def test_capability_and_resource_is_rejected_at_install(self, path: str):
        """The shape that installed clean before the ruling and that F5 could
        never have caught — `resource` is present, so F5's condition is false."""
        from entity_handlers.compute import audit_subgraph

        ctx = _ctx()
        expr = _apply(
            path,
            {"path": ctx.content_store.put(_lit("app/out"))},
            capability=ctx.content_store.put(_cap_entity(WILDCARD_CAP)),
            resource=ctx.content_store.put(_lit({"targets": ["app/out"]})),
        )

        result = audit_subgraph(expr, ctx)

        assert ERR_INVALID_EXPRESSION in self._static_error_codes(result)
        assert "capability or resource" in result.static_errors[0]["message"], (
            "the message must name the defect, and match the eval-time one — "
            "one rule, two enforcement points"
        )

    @pytest.mark.parametrize("path", BUILTIN_PATHS)
    def test_resource_alone_is_rejected_at_install(self, path: str):
        """The other shape outside F5's reach: no `capability` at all."""
        from entity_handlers.compute import audit_subgraph

        ctx = _ctx()
        expr = _apply(
            path,
            {"path": ctx.content_store.put(_lit("app/out"))},
            resource=ctx.content_store.put(_lit({"targets": ["app/out"]})),
        )

        result = audit_subgraph(expr, ctx)

        assert ERR_INVALID_EXPRESSION in self._static_error_codes(result)

    @pytest.mark.parametrize("path", BUILTIN_PATHS)
    def test_capability_alone_is_rejected_at_install(self, path: str):
        """F5's own shape on a builtin path — subsumed here, same code, so no
        separate F5 fix is owed on this branch (mirrors eval time)."""
        from entity_handlers.compute import audit_subgraph

        ctx = _ctx()
        expr = _apply(
            path,
            {"path": ctx.content_store.put(_lit("app/out"))},
            capability=ctx.content_store.put(_cap_entity(WILDCARD_CAP)),
        )

        result = audit_subgraph(expr, ctx)

        assert ERR_INVALID_EXPRESSION in self._static_error_codes(result)

    def test_a_builtin_carrying_neither_field_still_installs_clean(self):
        """The legal shape — and the `store` write_path collection the check now
        sits in front of must survive, or the rejection has broken install-time
        write authorization instead of adding to it."""
        from entity_handlers.compute import audit_subgraph

        ctx = _ctx()
        expr = _apply(
            BUILTIN_STORE, {"path": ctx.content_store.put(_lit("app/out"))},
        )

        result = audit_subgraph(expr, ctx)

        assert result.static_errors == []
        assert result.write_paths == ["app/out"], (
            "the early return must not swallow the literal write_path — that is "
            "the one thing §3.3 gates `store` on"
        )

    def test_a_handler_apply_carrying_both_still_installs(self):
        """Negative control on breadth. `capability`+`resource` is the legal,
        load-bearing F1/F2/F4 shape on a HANDLER path — a check keyed on field
        presence alone rather than on the builtin prefix would delete the
        resource ceiling at install time, and nothing else here would notice."""
        from entity_handlers.compute import audit_subgraph

        ctx = _ctx()
        expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "capability": ctx.content_store.put(_cap_entity(WILDCARD_CAP)),
            "resource": ctx.content_store.put(_lit({"targets": ["app/data/y"]})),
        })

        result = audit_subgraph(expr, ctx)

        assert result.static_errors == []
        assert result.handler_targets and result.handler_targets[0]["resource"] == {
            "targets": ["app/data/y"],
        }

    def test_a_path_merely_starting_like_a_builtin_still_installs(self):
        """`system/compute/builtinsomething` is not a builtin path — the prefix
        carries its separator. Pinned at install as it already is at eval."""
        from entity_handlers.compute import audit_subgraph

        ctx = _ctx()
        expr = _apply(
            "system/compute/builtinsomething", {},
            capability=ctx.content_store.put(_cap_entity(WILDCARD_CAP)),
            resource=ctx.content_store.put(_lit({"targets": ["app/out"]})),
        )

        result = audit_subgraph(expr, ctx)

        assert result.static_errors == []

    def test_the_f5_shape_on_a_handler_path_is_still_caught_at_install(self):
        """The control: F5's install-time check is alive and this is not a
        report that install-time validation is broken generally."""
        from entity_handlers.compute import audit_subgraph

        ctx = _ctx()
        expr = Entity(type="compute/apply", data={
            "path": "system/tree",
            "operation": "get",
            "args": {},
            "capability": ctx.content_store.put(_cap_entity(WILDCARD_CAP)),
        })

        result = audit_subgraph(expr, ctx)

        assert any(
            e["code"] == ERR_INVALID_EXPRESSION for e in result.static_errors
        ), "F5 install-time enforcement must still fire on a handler apply"


class TestLegalBuiltinAppliesAreUnchanged:
    """The clean path, so the rejection cannot be read as disabling builtins."""

    def test_a_builtin_store_without_the_fields_still_writes(self):
        ctx = _ctx()
        result = evaluate(
            _apply(BUILTIN_STORE, {
                "path": ctx.content_store.put(_lit("app/out")),
                "value": ctx.content_store.put(_lit(42)),
            }),
            Scope(), Budget(), ctx,
        )

        assert not is_error(result)
        written = ctx.content_store.get(
            ctx.entity_tree.get(ctx.entity_tree.normalize_uri("app/out")),
        )
        assert written.data == 42

    def test_a_builtin_arithmetic_without_the_fields_still_evaluates(self):
        """The inline-alias intercept, whose §3.5 guarantee is *hash-identity
        with the inline form* — the property go's fall-through to handler
        dispatch broke, and the second reason this ruling exists."""
        ctx = _ctx()
        inline = Entity(type="compute/arithmetic", data={
            "op": "add",
            "left": ctx.content_store.put(_lit(2)),
            "right": ctx.content_store.put(_lit(3)),
        })
        as_apply = _apply("system/compute/builtins/arithmetic", {
            "op": ctx.content_store.put(_lit("add")),
            "left": ctx.content_store.put(_lit(2)),
            "right": ctx.content_store.put(_lit(3)),
        })

        assert int(evaluate(as_apply, Scope(), Budget(), ctx)) == 5
        assert int(evaluate(as_apply, Scope(), Budget(), ctx)) == int(
            evaluate(inline, Scope(), Budget(), ctx),
        )
