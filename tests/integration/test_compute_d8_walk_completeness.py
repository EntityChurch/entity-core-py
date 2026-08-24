"""EXTENSION-COMPUTE D8 — §7.1's `walk` registers EVERY reachable tree lookup.

**Ruled 2026-08-21** (arch `PROPOSAL-COMPUTE-CLOSURE-RESULT-POSITIONS-AND-CONCAT-ARGS-SHAPE`
§10.3, routed as `ROUTING-2026-08-21-h` §4b/§5.4). §7.1 contradicts itself: its
pseudocode recurses on scalar `system/hash` field values and therefore enters no
container, while its own *"Conservative static collection"* paragraph states the
property normatively —

    all `compute/lookup/tree` paths reachable in the expression graph are
    registered

**The prose is the normative `[MUST]`; the pseudocode is the wrong half**, and it
cannot achieve the prose rule on the grammar that exists: `compute/apply.args` is
`{map_of: system/hash}` and `compute/let.bindings` is an array of
`{name, value: system/hash}`, so a walk entering no container registers nothing
inside any function argument or any `let` binding.

**Why this seat owned the fix.** All three implementations exceed the pseudocode
and they were not equivalent: go's `walkDepValue` and rust's `walk_hash_fields`
recurse to unbounded depth; py's `_walk_deps` was **hand-rolled and not
recursive** — a scalar; a list of hashes; a list of dicts keyed on the literal
field name `"value"`; a dict, one level. *Correct by enumeration of the current
grammar, not by rule*, which arch states plainly is the spec's fault and not
py's: the pseudocode enumerated, so py enumerated.

**Why no corpus vector can see it** (§6.2, class declared per L19): dependency
registration produces **no boundary**. §7c's shape is
`(IR, root bindings, budget) → {boundary-hash | error{code}}`, and this decides
whether a *later* re-evaluation happens. Three walkers of three different
strengths passed every vector. The failure mode is a reactive expression that
evaluates correctly once and is never woken again — the quietest there is.

So this file has two jobs, and the second is the one that outlives go's wire
check (`d8_reeval_dep_in_let_binding` / `d8_reeval_dep_in_apply_arg`, which
measured PASS against this peer even before the fix):

1. Rows (a) and (b) pin the two grammar shapes the wire check covers.
2. **Rows (c)–(e) pin the RULE**, at nesting the current grammar cannot express
   and the wire check therefore cannot reach. Those are the rows that fail
   against the enumeration this seat shipped through `f09ae70`, and they are the
   reason clause 3 exists as a grep rather than as a vector.

Plus the second site: `_audit_walk` was a hand-rolled copy of the same
enumeration, and there a reference nested past the enumerated shapes skips a
`compute/apply` — an install-time capability/resource check that never runs.
Nobody named that site; arch measured `_walk_deps` alone.
"""

from __future__ import annotations

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree

from entity_handlers.compute import (
    _COMPUTE_TYPE_DEFS,
    EvalContext,
    audit_subgraph,
    walk_tree_lookups,
)

PEER_ID = "test-peer"


def _ctx() -> EvalContext:
    return EvalContext(
        content_store=ContentStore(),
        entity_tree=EntityTree(PEER_ID),
        local_peer_id=PEER_ID,
        capability={},
        has_content_store_access=True,
    )


def _put(ctx: EvalContext, entity: Entity) -> bytes:
    return ctx.content_store.put(entity)


def _lookup(ctx: EvalContext, path: str) -> bytes:
    return _put(ctx, Entity(type="compute/lookup/tree", data={"path": path}))


def _lit(ctx: EvalContext, value: object) -> bytes:
    return _put(ctx, Entity(type="compute/literal", data={"value": value}))


# ============================================================================
# Rows (a) and (b) — the two shapes in today's grammar
# ============================================================================

class TestTheGrammarsTwoContainers:
    def test_row_a_a_lookup_inside_a_let_binding_is_registered(self):
        """`compute/let.bindings` — an array of `{name, value: system/hash}`.

        A walker covering `let.bindings` alone passes this row, which is why
        arch names row (b) as the discriminator and not this one.
        """
        ctx = _ctx()
        expr = Entity(type="compute/let", data={
            "bindings": [{"name": "v", "value": _lookup(ctx, "app/watched")}],
            "body": _lit(ctx, 1),
        })
        assert walk_tree_lookups(expr, ctx) == ["app/watched"]

    def test_row_b_a_lookup_inside_an_apply_arg_is_registered(self):
        """`compute/apply.args` — `{map_of: system/hash}`, arch's discriminator
        for a `let.bindings`-only walker.

        This one already passed against the enumerated walker (its fourth case
        was "a dict, one level"), which is exactly what go measured on the wire
        and reported as *"no defect observable on the current grammar."* That
        report is correct and it is **not** evidence about the rule — see the
        rows below.
        """
        ctx = _ctx()
        expr = Entity(type="compute/apply", data={
            "path": "system/compute/builtins/field",
            "operation": "eval",
            "args": {"name": _lit(ctx, "x"), "value": _lookup(ctx, "app/arg")},
        })
        assert walk_tree_lookups(expr, ctx) == ["app/arg"]


# ============================================================================
# Rows (c)–(e) — the RULE, past what the grammar can express today
# ============================================================================

class TestTheRuleAndNotTheEnumeration:
    """Each row constructs a container shape the current grammar does not
    produce. That is the point: §10.3 clause 1 measures an implementation
    against the prose sentence, and clause 3 exists precisely because the
    grammar can grow one of these shapes in a single field edit.

    All three were RED against the enumerated walker.
    """

    def test_row_c_a_lookup_nested_two_containers_deep_is_registered(self):
        """A list inside a list. The old walker entered one level of list and
        looked for a hash or a dict with a `"value"` key; a second list is
        neither, so the reference was dropped in silence."""
        ctx = _ctx()
        expr = Entity(type="compute/apply", data={
            "path": "system/compute/builtins/map",
            "operation": "eval",
            "args": {"nested": [[_lookup(ctx, "app/deep")]]},
        })
        assert walk_tree_lookups(expr, ctx) == ["app/deep"]

    def test_row_d_a_binding_style_dict_not_keyed_value_is_registered(self):
        """The literal `"value"` key was the sharpest part of the enumeration:
        it matched `compute/let.bindings` **by field name**. A binding-shaped
        entry whose reference field is called anything else registered nothing.
        """
        ctx = _ctx()
        expr = Entity(type="compute/let", data={
            "bindings": [{"name": "v", "expr": _lookup(ctx, "app/renamed")}],
            "body": _lit(ctx, 1),
        })
        assert walk_tree_lookups(expr, ctx) == ["app/renamed"]

    def test_row_e_a_lookup_inside_a_map_inside_a_map_is_registered(self):
        """A dict inside a dict — the old walker read one level of dict values
        and stopped."""
        ctx = _ctx()
        expr = Entity(type="compute/apply", data={
            "path": "system/compute/builtins/field",
            "operation": "eval",
            "args": {"outer": {"inner": _lookup(ctx, "app/nested-map")}},
        })
        assert walk_tree_lookups(expr, ctx) == ["app/nested-map"]

    def test_a_deep_reference_that_is_not_a_lookup_still_recurses_through(self):
        """The traversal is over *references*, not over lookups — an
        intermediate expression nested in a container has to be entered too, or
        the lookup beneath it is unreachable for a different reason than the
        one the rows above fix."""
        ctx = _ctx()
        inner = _put(ctx, Entity(type="compute/let", data={
            "bindings": [{"name": "v", "value": _lookup(ctx, "app/leaf")}],
            "body": _lit(ctx, 1),
        }))
        expr = Entity(type="compute/apply", data={
            "path": "system/compute/builtins/map",
            "operation": "eval",
            "args": {"wrapped": [{"any_key": inner}]},
        })
        assert walk_tree_lookups(expr, ctx) == ["app/leaf"]

    def test_a_string_field_is_not_walked_as_a_container(self):
        """The control. `str` is iterable, so a traversal written as
        *"descend into anything iterable"* recurses character-by-character and
        turns a path field into work proportional to its length. A byte string
        that is not a valid reference is a leaf for the same reason.
        """
        ctx = _ctx()
        expr = Entity(type="compute/apply", data={
            "path": "system/compute/builtins/field",
            "operation": "eval",
            "args": {"name": _lit(ctx, "a" * 64), "raw": b"\x99not-a-hash"},
        })
        assert walk_tree_lookups(expr, ctx) == []


# ============================================================================
# The second site — `_audit_walk`, where the same gap skips an authz check
# ============================================================================

class TestTheAuditWalkerSharesTheTraversal:
    """`audit_subgraph` collects the install-time static audit: impure write
    paths, `compute/apply` handler targets and their static resources, and the
    F5 structural errors. It walked with its own copy of the same enumeration.

    So the D8 defect had **two** sites with different consequences — a missed
    dependency at `_walk_deps` (a reactive expression never woken) and a missed
    `compute/apply` at `_audit_walk` (an install-time capability/resource check
    that never runs). Only the first was measured. They now share
    `_referenced_entities`; these rows are what keeps them from drifting apart
    again.
    """

    def test_an_apply_nested_past_the_old_enumeration_is_still_audited(self):
        ctx = _ctx()
        nested_apply = _put(ctx, Entity(type="compute/apply", data={
            "path": "app/handler",
            "operation": "write",
            "args": {},
        }))
        expr = Entity(type="compute/let", data={
            "bindings": [{"name": "v", "nested": [nested_apply]}],
            "body": _lit(ctx, 1),
        })
        result = audit_subgraph(expr, ctx)
        assert [t["path"] for t in result.handler_targets] == ["app/handler"]

    def test_the_f5_structural_error_is_found_at_the_same_depth(self):
        """The F5 check (`capability` without `resource` is a static error) is
        the one with teeth: an audit that never reaches the `compute/apply`
        reports a clean install for an expression that carries a malformed
        authorization declaration.
        """
        ctx = _ctx()
        nested_apply = _put(ctx, Entity(type="compute/apply", data={
            "path": "app/handler",
            "operation": "write",
            "args": {},
            "capability": _lit(ctx, "cap"),
        }))
        expr = Entity(type="compute/let", data={
            "bindings": [{"name": "v", "nested": [nested_apply]}],
            "body": _lit(ctx, 1),
        })
        result = audit_subgraph(expr, ctx)
        assert result.static_errors, (
            "the audit did not reach the nested apply, so an expression with a "
            "capability and no resource installs clean"
        )


# ============================================================================
# §10.3 clause 3 — the greppable grammar invariant
# ============================================================================

class TestEveryReferenceFieldIsAScalarHash:
    """Clause 3, and it is a **grep, not a vector**, by arch's own declaration:
    the deeper-nesting case is not expressible in today's grammar, so no wire
    check can discriminate it. This is that grep — and **running it found two
    defects in the clause itself**, both filed as `SA-PY-27`.

    Widened from the `*-args`-only sweep the C-8 pass shipped, which is the
    inventory-unit law again: clause 3 binds *every reference field in the
    expression grammar*, so `*-args` was the wrong unit and `construct` was
    structurally invisible to the measurement that set the old scope.
    """

    # The container-valued reference fields the grammar actually has.
    #
    # **Arch's §10.3 clause 3 enumerates TWO** — `compute/apply.args` and
    # `compute/let.bindings`. **There are three.** `compute/construct.fields`
    # is `{map_of: {type_ref: "system/hash"}}` in the shipping spec
    # (`EXTENSION-COMPUTE` §2.1, `compute/construct`), it is an ordinary
    # reference container the walk must enter, and it predates the ruling. So
    # clause 3 as written flags a legitimate long-shipping field — SA-PY-27(a).
    # Listed here with that fact attached rather than quietly added, because a
    # silently-grown exception list is how a clause stops meaning anything.
    ENUMERATED_CONTAINER_REFS = {
        ("compute/apply", "args"),        # §2.1, arch-enumerated
        ("compute/let", "bindings"),      # §2.1, arch-enumerated (but see below)
        ("compute/construct", "fields"),  # §2.1, NOT enumerated — SA-PY-27(a)
    }

    # NOT a reference the walk follows: an authorization allowlist consulted by
    # value, on the `system/compute/subgraph` metadata entity, which is not an
    # expression and is never walked (`audit_subgraph` and `walk_tree_lookups`
    # are both called on the expression). Listed rather than silently excluded.
    NOT_A_REFERENCE = {
        ("system/compute/subgraph", "authorized_data_hashes"),
    }

    def test_no_expression_type_declares_an_unenumerated_container_of_hashes(
        self,
    ):
        offenders = [
            (d["name"], field)
            for d in _COMPUTE_TYPE_DEFS
            for field, spec in (d.get("fields") or {}).items()
            if isinstance(spec, dict)
            and (
                spec.get("array_of") == {"type_ref": "system/hash"}
                or spec.get("map_of") == {"type_ref": "system/hash"}
            )
            and (d["name"], field) not in self.ENUMERATED_CONTAINER_REFS
            and (d["name"], field) not in self.NOT_A_REFERENCE
        ]
        assert offenders == [], (
            "a container-valued reference field outside the enumerated set: "
            f"{offenders}. Either make it a scalar `system/hash` (D3's shape) "
            "or add it to §2.1 and to ENUMERATED_CONTAINER_REFS in the same "
            "edit — clause 3 is what keeps the walker's rule and the grammar "
            "from drifting"
        )

    def test_the_clause_3_grep_cannot_see_let_bindings_at_all(self):
        """**SA-PY-27(b), and it is the sharper half.**

        Clause 3's enforcement point is *"an `array_of`/`map_of` whose
        `type_ref` is `system/hash`."* `compute/let.bindings` is declared
        `{array_of: {type_ref: "primitive/any"}}` — the `value: system/hash`
        lives inside an untyped struct described only in the prose sub-block
        beneath the declaration. **So the grep cannot see the one shape that
        motivated D8**, and a future field hiding a reference inside a
        `primitive/any` container passes clause 3 while breaking the walker in
        exactly the way `let.bindings` would have.

        This row asserts the blind spot rather than working around it, so that
        the thing actually protecting us stays legible: it is the **recursive
        traversal** (`_hash_refs_in`, rows (c)–(e) above), not the grep. Clause
        3 is a secondary tripwire over the declarations, and it is porous.
        """
        let_decl = next(d for d in _COMPUTE_TYPE_DEFS if d["name"] == "compute/let")
        bindings = let_decl["fields"]["bindings"]
        assert bindings == {"array_of": {"type_ref": "primitive/any"}}
        assert bindings.get("array_of") != {"type_ref": "system/hash"}, (
            "if this ever becomes a declared hash container, clause 3's grep "
            "gains a row it previously could not see — update SA-PY-27"
        )

    def test_the_sweep_actually_matches_the_grammar(self):
        """A gate over an empty set is not a gate — and the exception list
        must name fields that exist, or it is cover for nothing."""
        declared = {
            (d["name"], field)
            for d in _COMPUTE_TYPE_DEFS
            for field in (d.get("fields") or {})
        }
        assert len(declared) > 20
        for row in self.ENUMERATED_CONTAINER_REFS | self.NOT_A_REFERENCE:
            assert row in declared, f"{row} is not in the grammar any more"
