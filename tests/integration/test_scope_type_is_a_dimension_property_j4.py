"""J4 — the scope type is a property of the DIMENSION (§5.2).

**Clause 1 stands. Clause 2 was WITHDRAWN at 0.8.2.24 (N1), and this file was
inverted rather than deleted.**

The ruling landed at 0.8.2.22 with two clauses:

1. *"The scope type is a property of the DIMENSION and is supplied by the call
   site ``[MUST]``. … An implementation MUST NOT take the dispatch type from a
   received entity's ``scope.type`` field."* — **stands.**
2. *"A received ``scope`` whose declared ``type`` contradicts its dimension is
   a malformed token and MUST be refused ``403 capability_denied``."* —
   **WITHDRAWN 0.8.2.24.**

.. rubric:: Why clause 2 went away, since nothing fails when a rule is withdrawn

This seat built clause 2 (SA-PY-60) on the argument that *dropping is not
refusing*: clause 1 is satisfied structurally by any peer that never plumbed
the field, and a peer that silently ignores a contradicting type *accepts* a
token the spec called malformed. The argument was internally sound and the
premise it rested on was wrong.

**A peer that does not read ``scope.type`` cannot observe a contradiction in
it.** So clause 2 obliged re-introducing the exact field whose absence IS the
safety property — plus a targeted MUST-ignore exception — in order to reject a
shape no conformant implementation produces. A rule satisfiable only by undoing
the rule beside it is mechanism-shaped. Arch's §0, now a named failure mode with
three instances in three days: *"when a finding says nobody validates X, the fix
is a rule about who SUPPLIES X — and the temptation is to also demand a refusal
when X arrives wrong. The refusal is what puts the mechanism back."*

Three parties reached the withdrawal independently, by three methods, none
having read the others: keystone's 45-peer wire census (``403`` on **zero** of
40 driven), go's three-way source read (all three ground-up seats structurally
immune), and arch's own line-reads taken before either packet was opened.

**The replacement is a ``MAY`` at admission** (``put``, §6.3) — where a caller
still exists to answer and the field has not yet been dropped. Not built here:
it is a MAY, its cohort cost is zero, and a refusal go and rust do not make is a
divergence this seat would be manufacturing out of an optional clause.

.. rubric:: What this file pins now

The rows below are the 0.8.2.22 rows **inverted in place**. A reader who found
the class simply deleted would have no way to learn that the refusal was built,
driven, and retracted — and *"we should refuse a mistyped token"* is exactly the
hardening a later seat re-invents, because it reads as obviously correct and
nothing in the tree contradicts it. It is a conformance defect: it refuses a
token go and rust accept.

**The evidence is not wasted.** Building clause 2 is what reached the real
boundaries — absent ≠ contradiction, and the unit of malformedness is the token
rather than the axis — and it is what showed the clause was mechanism-shaped
from the inside. Those boundaries are still pinned below, now as the shape the
admission-time ``MAY`` would have to respect if anyone ever builds it.
"""

from __future__ import annotations

import pytest

from entity_core.capability import checking
from entity_core.capability.checking import (
    ID_SCOPE,
    PATH_SCOPE,
    check_path_permission,
    scope_type_for_dimension,
)

PEER = "1" * 46


def _grant(**scope_types: str) -> dict:
    """A grant that authorizes ``get`` on ``data/*``, optionally declaring a
    ``type`` on named dimensions."""
    grant = {
        "handlers": {"include": ["*"]},
        "operations": {"include": ["get"]},
        "resources": {"include": ["data/*"]},
    }
    for dimension, declared in scope_types.items():
        # `peers` is absent by default (an omitted `peers` is §5.2's
        # local-only default), so name it only when a row asks for it.
        grant.setdefault(dimension, {"include": ["*"]})["type"] = declared
    return grant


class TestTheTypeComesFromTheDimension:
    """Clause 1 — stands, satisfied structurally here, pinned so it stays."""

    def test_the_mapping_is_fixed_by_the_specification(self):
        assert scope_type_for_dimension("handlers") == PATH_SCOPE
        assert scope_type_for_dimension("resources") == PATH_SCOPE
        assert scope_type_for_dimension("operations") == ID_SCOPE
        assert scope_type_for_dimension("peers") == ID_SCOPE

    def test_an_unknown_dimension_raises_rather_than_defaulting(self):
        """*"a grant does not get to restate it"* — and neither does a new
        dimension inheriting a matcher by accident. There is no correct
        default: a path dimension matched literally over-refuses, an id
        dimension canonicalized over-grants."""
        with pytest.raises(ValueError):
            scope_type_for_dimension("something_new")


class TestClauseTwoIsWithdrawn:
    """⭐ 0.8.2.24 (N1) — these rows asserted the OPPOSITE until the withdrawal.

    Every row here failed before the retraction. That is the point of inverting
    rather than deleting: the file is the only artifact that says the refusal
    was real, was driven, and was taken back for a reason.
    """

    @pytest.mark.parametrize("dimension,wrong", [
        ("operations", PATH_SCOPE),
        ("peers", PATH_SCOPE),
        ("handlers", ID_SCOPE),
        ("resources", ID_SCOPE),
    ])
    def test_a_contradicting_type_does_NOT_refuse_at_the_matcher(
        self, dimension, wrong,
    ):
        """The headline inversion. A grant whose declared ``type`` contradicts
        its dimension still authorizes, because the matcher never reads the
        field — which is clause 1 working, not clause 2 failing."""
        malformed = {"grants": [_grant(**{dimension: wrong})]}
        assert check_path_permission(
            malformed, "get", "data/file", PEER, handler_pattern="system/tree",
        ) is True, (
            "0.8.2.24 (N1) withdrew the clause-2 refusal; refusing here "
            "diverges from go and rust, which cannot observe the field at all"
        )

    def test_the_refusal_helper_is_GONE_and_must_not_come_back(self):
        """Structural, and deliberately so.

        A behavioural row cannot distinguish *"we removed the refusal"* from
        *"we kept the refusal and this input does not reach it"*. A withdrawn
        rule leaves no failing test behind, so the enforcement point for a
        withdrawal has to be the absence of the mechanism itself.
        """
        assert not hasattr(
            checking, "grant_declares_a_contradicting_scope_type",
        ), (
            "the clause-2 refusal helper is back. 0.8.2.24 (N1) WITHDREW that "
            "clause: a peer that does not read `scope.type` cannot observe a "
            "contradiction in it, so the refusal obliges re-introducing the "
            "very field whose absence is the safety property. The disposition, "
            "where one is wanted, is a MAY at admission (`put`, §6.3) — not a "
            "matcher-side refusal. See the module docstring."
        )

    def test_the_boundary_clause_2_taught_us_still_holds_absent_is_not_contradiction(self):
        """Kept from the pre-withdrawal class, re-pointed.

        Every capability this cohort mints OMITS ``type``. Under clause 2 this
        row stopped a *"be stricter"* fix from reading silence as contradiction
        and refusing the entire ecosystem. It survives the withdrawal as the
        boundary an admission-time ``MAY`` would have to respect.
        """
        assert check_path_permission(
            {"grants": [_grant()]}, "get", "data/file", PEER,
            handler_pattern="system/tree",
        ) is True

    def test_teeth_a_grant_that_authorizes_NOTHING_still_refuses(self):
        """Without this, every row above passes on a peer whose check is simply
        broken open. The refusal path must still work; it is the *trigger* that
        was withdrawn, not the mechanism."""
        assert check_path_permission(
            {"grants": [_grant()]}, "get", "other/file", PEER,
            handler_pattern="system/tree",
        ) is False


class TestACorrectlyTypedGrantIsUnaffected:
    """A sender that spells the field correctly was always conformant, and the
    withdrawal does not change that — it only removes the obligation to punish
    one that spells it wrong."""

    def test_a_grant_declaring_every_type_correctly_still_authorizes(self):
        fully_typed = {"grants": [_grant(
            handlers=PATH_SCOPE, operations=ID_SCOPE, resources=PATH_SCOPE,
        )]}
        assert check_path_permission(
            fully_typed, "get", "data/file", PEER, handler_pattern="system/tree",
        ) is True
