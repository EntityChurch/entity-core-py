"""0.8.2.16 — the id-scope pin reaches `scope_subset`, and `peers` is attenuated.

§5.2 has said since 0.8.1 (F40) that a grant dimension is matched **by its
§3.6 scope type**: `handlers`/`resources` are `path-scope` and canonicalize;
`operations`/`peers` are `id-scope` and compare as literal identifiers. Both
normative code blocks — §5.2 `matches_scope` and §5.5a `scope_subset` —
canonicalized unconditionally with no type branch until 0.8.2.16 corrected
them, and this implementation was written from the pseudocode.

Two defects, and arch flagged the second surface as *"the one to look at
twice"* because it governs **delegation**, where a wrongly-widened grant is
re-checked by nobody:

1. **`operations` was matched with the path matcher.** `pattern_covers` reads
   `/*/*` as a universal wildcard, rewrites an `entity://` prefix into a path,
   and recurses through a `/*/` peer position. Applied to an operation name,
   all three over-grant.
2. **`peers` was not checked in the subset at all** — in any form. A child
   grant could name a peer scope its parent never held.

`entity-core-go` found both independently in their own `grantCovers` and
routed them for us to check; both are in both trees. Defect 2 was **latent**
until 0.8.2.17 made Dimension 4 a live decision on the outbound path — which
is the ordering worth noticing: the attenuation hole and the enforcement point
that makes it reachable landed in the same protocol revision pair.

.. rubric:: What the suite could see before this file

Nothing. 4297 tests passed with both defects present and passed unchanged with
both fixed — the fixture-count reading of a rule landing on a dimension no row
has ever asserted. Every delegation fixture in the tree writes `operations`
with bare identifiers or `*`, which is the arm on which the two matchers
agree, and none writes `peers` at all.

.. rubric:: One arm of the spec's pseudocode is not implementable here, by
   construction

§5.5a opens `scope_subset` with *"a child and parent whose types differ is a
malformed grant and MUST be rejected."* That arm reads a `type` off the scope
entity. Our scopes carry no type — the type is fixed by the **dimension**
(§3.6's `type_ref`), which is where the spec's own scope entity gets it from,
so child and parent are the same dimension and cannot differ. The rule is
unobservable here rather than unimplemented, and it is named here rather than
left to read as covered.
"""

from __future__ import annotations

import inspect

import pytest

from entity_core.capability.checking import (
    ID_SCOPE,
    PATH_SCOPE,
    matches_id_scope,
    scope_type_for_dimension,
)
from entity_core.capability.delegation import grant_subset, is_attenuated

LOCAL = "1LocalPeerRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
FOREIGN = "1FZfarForeignPeerRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
OTHER = "1OtherPeerRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"


def _grant(**dims):
    """A grant with every dimension a scope dict. `peers` only when named."""
    out = {
        "handlers": {"include": dims.pop("handlers", ["*"])},
        "resources": {"include": dims.pop("resources", ["*"])},
        "operations": {"include": dims.pop("operations", ["*"])},
    }
    for name in ("operations_exclude", "peers_exclude", "handlers_exclude"):
        if name in dims:
            out[name.split("_")[0]]["exclude"] = dims.pop(name)
    if "peers" in dims:
        out["peers"] = {"include": dims.pop("peers")}
    if "peers_scope" in dims:
        out["peers"] = dims.pop("peers_scope")
    assert not dims, f"unused: {dims}"
    return out


def _covered(child_grant, parent_grant) -> bool:
    return grant_subset(child_grant, parent_grant, LOCAL)


class TestOperationsAreMatchedLiterally:
    """The id-scope grammar has exactly two wildcard forms and no transforms."""

    @pytest.mark.parametrize(
        "parent_pattern",
        [
            "/*/*",       # the path matcher's second universal wildcard
            "/*/get",     # interior peer-wildcard
            "entity://get",  # the path matcher rewrites this to /get
            "/get",       # leading-/ universal-scope reading
        ],
    )
    def test_a_path_form_operation_pattern_covers_nothing(self, parent_pattern):
        """Under the ruled grammar each of these is a literal, and `get` is
        not any of them.

        **Measured: only `/*/*` discriminates.** `pattern_covers` short-
        circuits on it as a universal wildcard, so a parent grant carrying it
        covered **every** child operation — an escalation reached by writing a
        pattern that looks like a scoped one. Reverting operations to the path
        matcher reddens this parametrization at `/*/*` **and nowhere else**:
        the other three already returned False there, because the §5.4
        transforms they exercise need a leading `/` on the *value* and `get`
        has none.

        They are kept, and labelled, as **controls rather than coverage** —
        they pin that the ruled grammar refuses the path forms, which is a
        claim about the new matcher even though it was already true of the
        old one. A later reader must not count them as three more rows
        guarding the defect; there is one.
        """
        parent = _grant(operations=[parent_pattern])
        child = _grant(operations=["get"])
        assert not _covered(child, parent), (
            f"parent operations {parent_pattern!r} covered child 'get' — "
            "the path matcher is back on an id dimension"
        )

    def test_but_the_two_ruled_wildcards_still_cover(self):
        """The teeth control: the fix is a narrower grammar, not a refusal.

        Without this row, an implementation that returns False for every
        operation subset passes every row above.
        """
        assert _covered(_grant(operations=["get"]), _grant(operations=["*"]))
        assert _covered(
            _grant(operations=["compute/apply"]),
            _grant(operations=["compute/*"]),
        )
        assert _covered(_grant(operations=["get"]), _grant(operations=["get"]))

    def test_and_a_literal_segment_prefix_does_not_reach_a_sibling_namespace(self):
        assert not _covered(
            _grant(operations=["computed/apply"]),
            _grant(operations=["compute/*"]),
        )


class TestOperationExcludesAreNotCanonicalized:
    def test_a_child_inheriting_the_parents_operation_exclude_is_covered(self):
        """This is the arm that was fail-**closed** rather than open, and it is
        why it never surfaced as a security row.

        `scope_exclude_inherited` was called with `local_peer_id`, so a child
        exclude of `write` became `/{local}/write` and was compared against a
        parent exclude of `write`. They never matched, so a parent grant
        carrying **any** operation exclude could not be delegated at all —
        including to a child that inherited the exclude verbatim.
        """
        parent = _grant(operations=["*"], operations_exclude=["write"])
        child = _grant(operations=["*"], operations_exclude=["write"])
        assert _covered(child, parent), (
            "a child inheriting its parent's operation exclude verbatim is "
            "still judged not to inherit it"
        )

    def test_dropping_the_parents_operation_exclude_is_still_refused(self):
        parent = _grant(operations=["*"], operations_exclude=["write"])
        child = _grant(operations=["*"])
        assert not _covered(child, parent)

    def test_a_broader_child_exclude_covers_a_narrower_parent_exclude(self):
        """`compute/*` excludes at least everything `compute/apply` excludes."""
        parent = _grant(operations=["*"], operations_exclude=["compute/apply"])
        child = _grant(operations=["*"], operations_exclude=["compute/*"])
        assert _covered(child, parent)


class TestPeersIsAttenuated:
    """The dimension that was not checked here in any form.

    Each row states what a child could do before: name a peer scope its parent
    never held, and have the chain walk accept it.
    """

    def test_a_child_cannot_name_a_peer_its_parent_did_not(self):
        parent = _grant()  # no `peers` -> defaults to {include: [LOCAL]}
        child = _grant(peers=[FOREIGN])
        assert not _covered(child, parent), (
            "a child grant widened `peers` past a parent that carries the "
            "0.8.2.3 default — the escalation Dimension 4 exists to close, "
            "reached by delegating instead of by dispatching"
        )

    def test_nor_widen_a_named_peer_scope(self):
        assert not _covered(
            _grant(peers=[FOREIGN, OTHER]), _grant(peers=[FOREIGN]),
        )
        assert not _covered(_grant(peers=["*"]), _grant(peers=[FOREIGN]))

    def test_the_absent_default_is_the_local_peer_on_both_sides(self):
        """Control. Two grants that both omit `peers` still delegate — the
        default is `{include: [local_peer_id]}`, not the empty set, and a
        subset check with no arm for the absent case would refuse every
        ordinary delegation in the tree.
        """
        assert _covered(_grant(), _grant())
        assert _covered(_grant(peers=[LOCAL]), _grant())
        assert _covered(_grant(), _grant(peers=[LOCAL]))

    def test_a_narrowing_or_equal_peer_scope_is_covered(self):
        assert _covered(_grant(peers=[FOREIGN]), _grant(peers=["*"]))
        assert _covered(_grant(peers=[FOREIGN]), _grant(peers=[FOREIGN, OTHER]))

    def test_peers_is_an_id_scope_here_too(self):
        """A peer id is a flat identifier, so the only patterns that reach it
        are a literal and `*`. `/*/*` is not a wildcard on this dimension.
        """
        assert not _covered(_grant(peers=[FOREIGN]), _grant(peers=["/*/*"]))

    def test_the_parents_peer_excludes_are_inherited(self):
        parent = _grant(peers_scope={"include": ["*"], "exclude": [FOREIGN]})
        assert not _covered(_grant(peers=["*"]), parent)
        assert _covered(
            _grant(peers_scope={"include": ["*"], "exclude": [FOREIGN]}), parent,
        )


class TestTheChainWalkCarriesIt:
    """Driven through `is_attenuated`, the relation a delegation chain
    actually walks — `grant_subset` above is the unit, this is the seam.

    Without this class the fix is only asserted at the helper, and the helper
    is not what a chain calls.
    """

    def _cap(self, grants):
        return {"data": {"grants": grants}}

    def test_a_peers_widening_child_fails_the_chain_walk(self):
        result = is_attenuated(
            self._cap([_grant(peers=[FOREIGN])]),
            self._cap([_grant()]),
            LOCAL,
        )
        assert not result.valid
        assert "not covered" in (result.error or "")

    def test_an_operations_path_form_child_fails_the_chain_walk(self):
        result = is_attenuated(
            self._cap([_grant(operations=["get"])]),
            self._cap([_grant(operations=["/*/*"])]),
            LOCAL,
        )
        assert not result.valid

    def test_an_ordinary_narrowing_delegation_still_walks(self):
        result = is_attenuated(
            self._cap([_grant(operations=["get"], handlers=["system/tree"])]),
            self._cap([_grant()]),
            LOCAL,
        )
        assert result.valid, result.error


class TestWhichMatcherEachDimensionUses:
    """Structural rows. The behavioural split above is real on the delegation
    path; at §5.2 the two matchers **agree** on every value these dimensions
    can carry, because the §5.4 transforms all require a leading `/` on the
    *value* and an operation name never has one.

    So a behavioural row at `matches_scope` would pass against the defect, and
    these rows read the source instead — the same reason the SA-PY-29 pin
    asserts an argument's position rather than a status.
    """

    def test_the_dimension_types_are_3_6s(self):
        assert scope_type_for_dimension("handlers") == PATH_SCOPE
        assert scope_type_for_dimension("resources") == PATH_SCOPE
        assert scope_type_for_dimension("operations") == ID_SCOPE
        assert scope_type_for_dimension("peers") == ID_SCOPE

    def test_an_undeclared_dimension_has_no_default_matcher(self):
        """A new dimension silently inheriting one of the two matchers is F40
        arriving from the other direction, and neither default is safe."""
        with pytest.raises(ValueError, match="no scope type declared"):
            scope_type_for_dimension("constraints")

    def test_the_id_dimensions_go_through_the_id_matcher_at_5_2(self):
        from entity_core.capability import checking

        src = inspect.getsource(checking)
        assert "matches_scope(operations_scope" not in src, (
            "an `operations` call site is back on the path matcher"
        )
        assert "matches_scope(peers_scope" not in src, (
            "the `peers` call site is back on the path matcher"
        )
        assert src.count("matches_id_scope(operations_scope, operation)") == 4, (
            "the operations dimension has a new or removed call site — check "
            "it uses the id matcher, then update this count"
        )

    def test_the_id_dimensions_do_not_reach_the_path_helpers_in_grant_subset(self):
        """Walked on the AST, not on the text.

        The first draft of this row read `grant_subset`'s source line by line
        and failed on its own **docstring** — `- Child operations are subset
        of parent operations`. Same shape as the presentation-purity gate
        counting two `entity://` mentions in prose: a gate that cannot tell a
        call from a sentence about a call is not a gate.
        """
        import ast
        import textwrap

        PATH_HELPERS = {
            "scope_includes_subset",
            "scope_exclude_inherited",
            "pattern_covers",
            "canonicalize",
            "matches_pattern",
        }
        tree = ast.parse(textwrap.dedent(inspect.getsource(grant_subset)))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(
                node.func, "attr", None,
            )
            if name not in PATH_HELPERS:
                continue
            mentioned = {
                n.id for n in ast.walk(node) if isinstance(n, ast.Name)
            }
            for dim in ("operations", "peers"):
                if any(dim in m for m in mentioned):
                    offenders.append((name, dim))
        assert not offenders, (
            f"an id dimension is being matched by a path helper: {offenders} "
            "— §5.2 names this a conformance defect, and on this path it "
            "widens authority down a delegation chain"
        )

    def test_the_id_exclude_helper_takes_no_canonicalization_frame(self):
        """The defect was a `local_peer_id` argument that existed and was
        therefore passed. The id-scope helper does not have one to pass.
        """
        from entity_core.capability.delegation import id_scope_exclude_inherited

        params = inspect.signature(id_scope_exclude_inherited).parameters
        assert "local_peer_id" not in params


class TestTheIdScopeMatcherItself:
    @pytest.mark.parametrize(
        "pattern,value,expected",
        [
            ("*", "get", True),
            ("*", "compute/apply", True),
            ("compute/*", "compute/apply", True),
            ("compute/*", "compute/", True),
            ("compute/*", "computed/apply", False),
            ("get", "get", True),
            ("get", "put", False),
            ("/*/*", "get", False),
            ("/*/get", "get", False),
            ("entity://get", "get", False),
        ],
    )
    def test_the_grammar(self, pattern, value, expected):
        scope = {"include": [pattern]}
        assert matches_id_scope(scope, value) is expected

    def test_exclude_uses_the_same_grammar(self):
        scope = {"include": ["*"], "exclude": ["compute/*"]}
        assert matches_id_scope(scope, "get") is True
        assert matches_id_scope(scope, "compute/apply") is False
