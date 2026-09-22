"""J4 — the scope type is a property of the DIMENSION (§5.2, 0.8.2.22).

The ruling has **two clauses**, and they need different things from an
implementation:

1. *"The scope type is a property of the DIMENSION and is supplied by the call
   site ``[MUST]``. … An implementation MUST NOT take the dispatch type from a
   received entity's ``scope.type`` field."*
2. *"**A received ``scope`` whose declared ``type`` contradicts its dimension
   is a malformed token and MUST be refused ``403 capability_denied``
   ``[MUST]``**."*

.. rubric:: Why clause 2 is the one that needed building at two seats

Clause 1 is satisfied *structurally* by any peer that never plumbed the field:
this tree derives the type from the dimension name
(``_SCOPE_TYPE_BY_DIMENSION``), and `entity-core-go`'s ``types.CapabilityScope``
has no ``Type`` field at all, so a wire ``scope.type`` is dropped at decode.
go filed J4 as **CONFORMS, no code change** and added a regression guard.

**Dropping is not refusing.** A peer that silently ignores a contradicting type
*accepts* a token the spec calls malformed — clause 2 has its own status and
its own code, and nothing about clause 1 produces them. Two ground-up seats
landing on clause 1 is the standing law that cohort agreement is evidence about
the reading implementers reach, not about the text; the more so here, because
the clause they both satisfied is the one that comes with a mechanism and the
one they missed is the one that comes with a bare obligation.

Routed as **SA-PY-60**: the disagreement is about whether *"drop the field"*
discharges *"refuse the token"*, and the answer decides whether go owes a
change. Implemented in the refusing direction here because clause 2 is written
as a ``[MUST]`` with an explicit pair, and the standing posture is to build the
ruling and report what building it finds.

.. rubric:: The refusal is produced by failing the grant closed

There is no second error path: a grant carrying a contradicting type is skipped
by every check's grant loop, so no grant matches and the caller is answered
``403 capability_denied`` — which is the pair the ruling names. The alternative
(a dedicated raise) would have to be threaded through four call sites and would
give the same answer.

.. rubric:: What the rule protects, and why an ABSENT type must stay legal

The mistyping that matters is an ``operations`` or ``peers`` dimension declared
as ``path-scope``: under clause 1's violation that value reaches the
canonicalizing matcher, which *"over-grants on ``include`` and inverts the
intent on ``exclude``."* An **absent** ``type`` is the ordinary shape of every
capability this cohort mints — pinned below, because a guard that refused an
absent type would refuse every token in the ecosystem while reading as strict.
"""

from __future__ import annotations

import pytest

from entity_core.capability.checking import (
    ID_SCOPE,
    PATH_SCOPE,
    check_path_permission,
    grant_declares_a_contradicting_scope_type,
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
    """Clause 1 — satisfied structurally here, pinned so it stays that way."""

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


class TestAContradictingTypeIsRefused:
    """⭐ Clause 2 — the half neither ground-up seat had."""

    @pytest.mark.parametrize("dimension,wrong", [
        ("operations", PATH_SCOPE),
        ("peers", PATH_SCOPE),
        ("handlers", ID_SCOPE),
        ("resources", ID_SCOPE),
    ])
    def test_every_dimension_declared_as_the_other_type_is_malformed(
        self, dimension, wrong,
    ):
        assert grant_declares_a_contradicting_scope_type(
            _grant(**{dimension: wrong}),
        ) is True

    def test_the_grant_authorizes_NOTHING(self):
        """The behavioural half. A malformed token grants nothing, so the check
        finds no matching grant and the caller is answered
        ``403 capability_denied``."""
        malformed = {"grants": [_grant(operations=PATH_SCOPE)]}
        assert check_path_permission(
            malformed, "get", "data/file", PEER, handler_pattern="system/tree",
        ) is False

    def test_teeth_the_same_grant_without_the_bad_type_is_GRANTED(self):
        """Without this the row above passes on a peer that refuses every
        path, and the guard would be indistinguishable from a broken check."""
        well_formed = {"grants": [_grant()]}
        assert check_path_permission(
            well_formed, "get", "data/file", PEER, handler_pattern="system/tree",
        ) is True

    def test_one_bad_dimension_poisons_the_whole_GRANT_not_just_that_axis(self):
        """*"a malformed token"* — the unit is the token, not the dimension.

        A peer that refused only the mistyped axis would still evaluate the
        other three from a grant the spec says it must refuse.
        """
        malformed = {"grants": [_grant(peers=PATH_SCOPE)]}
        assert check_path_permission(
            malformed, "get", "data/file", PEER, handler_pattern="system/tree",
        ) is False, (
            "a grant whose `peers` dimension is mistyped still authorized a "
            "RESOURCE read — the refusal was scoped to the axis rather than "
            "to the token"
        )

    def test_a_sound_grant_BESIDE_a_malformed_one_still_authorizes(self):
        """The refusal is per-grant, and §5.2 evaluates grants independently.

        This is the boundary of the row above: poisoning the token is not
        poisoning the capability, or one malformed entry would silently revoke
        every other grant a caller holds.
        """
        mixed = {"grants": [_grant(operations=PATH_SCOPE), _grant()]}
        assert check_path_permission(
            mixed, "get", "data/file", PEER, handler_pattern="system/tree",
        ) is True


class TestAnAbsentTypeIsTheOrdinaryShape:
    """The non-obvious half: silence is not a contradiction.

    Every capability this cohort mints omits ``type`` — the field exists in
    §3.6's schema and no minter writes it. A guard that treated absence as
    malformed would refuse the entire ecosystem while reading as strict, which
    is the direction a "be stricter" fix errs in.
    """

    def test_no_declared_type_is_not_a_contradiction(self):
        assert grant_declares_a_contradicting_scope_type(_grant()) is False

    @pytest.mark.parametrize("dimension,right", [
        ("operations", ID_SCOPE),
        ("peers", ID_SCOPE),
        ("handlers", PATH_SCOPE),
        ("resources", PATH_SCOPE),
    ])
    def test_a_type_that_AGREES_with_its_dimension_is_fine(self, dimension, right):
        """A sender that spells the field correctly is conformant, not merely
        tolerated — the rule is about contradiction, not about presence."""
        assert grant_declares_a_contradicting_scope_type(
            _grant(**{dimension: right}),
        ) is False

    def test_a_grant_declaring_every_type_correctly_still_authorizes(self):
        fully_typed = {"grants": [_grant(
            handlers=PATH_SCOPE, operations=ID_SCOPE, resources=PATH_SCOPE,
        )]}
        assert check_path_permission(
            fully_typed, "get", "data/file", PEER, handler_pattern="system/tree",
        ) is True
