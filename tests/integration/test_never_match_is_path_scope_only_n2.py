"""N2 (0.8.2.24) — the ``NEVER_MATCH`` sentinel is PATH-scope only.

0.8.2.21 made an unmatchable exclude exclude everything: a granter writing
``exclude: ["*/secret"]`` for *not `secret`, in any peer's namespace* otherwise
gets an exclusion that carves out nothing, and a grant silently wider than its
author wrote. That rule is right, and it is a rule about **paths**.

``NEVER_MATCH`` is a §5.4 **path**-canonicalization sentinel. An id-scope
pattern (``operations``, ``peers``) is a literal identifier and is never put
through the §5.4 transforms. Applying the sentinel there runs an id pattern
through the path transforms *purely to classify it* — and then denies the
**whole dimension** on a property that says nothing about whether the exclude
carves anything out:

    ``operations: {include: ["*"], exclude: ["*/apply"]}``

``*/apply`` is an ordinary literal to the matcher that will evaluate it (no
operation name can equal it, so it excludes nothing) and an **escaping path**
to the canonicalizer (bare ``*/`` → ``NEVER_MATCH``). Under the unscoped rule
that grant authorized **no operation at all**.

.. rubric:: Why this seat had it, when arch's own cost table says ``—`` for py

The guard is in the right place. ``matches_scope`` IS the path-scope matcher
and ``matches_id_scope`` is the id one — split deliberately at 0.8.2.16 *"so
that which matcher a dimension uses is visible at the call site."* The defect
was that **four call sites routed an id-scope value into the path matcher**:

===================================  =========================================
site                                 dimension
===================================  =========================================
``subscription._validate_deliver_token``  ``operations``
``substitute.chain._find_consult_grants`` ``operations``
``query._check_type_scope``               ``type_scope``
``query._type_authorized_by_scope``       ``type_scope``
===================================  =========================================

The two query sites are the instructive ones: ``type_scope``'s own comment in
that file reads *"type_scope is an id-scope"* directly above a path-matcher
call, and **EXTENSION-QUERY §5.2 names the arm outright** — *"Both steps use
`matches_scope` … the same function that evaluates `id-scope` include/exclude
patterns for operations and peers dimensions."* So this is not a reading; it is
a citation that four call sites did not follow.

Routing an id dimension through the canonicalizing matcher is **independently**
the F40 defect §5.2 names (*"an id dimension canonicalized is a conformance
defect"*) — it over-grants on ``include`` and inverts the intent on ``exclude``.
N2 is what made it bite, because before 0.8.2.21 the path matcher had no
sentinel arm and the two matchers agreed on every value these dimensions carry.

.. rubric:: What could not see it

The comment above the guard read *"reached by every dimension of every grant,
so this is the widest of the three arms."* That sentence is **false as a design
statement and true as a description of the call graph**, which is exactly why
nobody looked: it reads as a considered scoping decision. It is corrected at
the site.

Landing the fix broke **nothing** among 4314 tests — the SA-PY-54 signal. No
fixture in this tree had ever written an id-scope exclude that canonicalizes,
because nobody writes ``*/apply`` by accident; it is reachable only by asking.
"""

from __future__ import annotations

import pytest

from entity_core.capability.checking import (
    is_unmatchable_pattern,
    matches_id_scope,
    matches_scope,
)
from entity_core.capability.token import CapabilityScope, Grant
from entity_core.protocol.entity import Entity

# Every one of these canonicalizes to NEVER_MATCH under §5.4 and is an ordinary
# literal under the id-scope grammar. `*/apply` is arch's own worked example.
CANONICALIZES_TO_SENTINEL = ["*/apply", "*/secret", "./local", "../escape"]


class TestThePremise:
    """These patterns really do hit the sentinel — otherwise every row below
    passes for the wrong reason."""

    @pytest.mark.parametrize("pattern", CANONICALIZES_TO_SENTINEL)
    def test_the_pattern_canonicalizes_to_never_match(self, pattern):
        assert is_unmatchable_pattern(pattern) is True

    @pytest.mark.parametrize("pattern", CANONICALIZES_TO_SENTINEL)
    def test_the_PATH_matcher_still_applies_the_sentinel(self, pattern):
        """The control. N2 SCOPES the rule; it does not withdraw it. A fix that
        deleted the guard would pass every row in this file and re-open
        0.8.2.21's fail-open one dimension over."""
        scope = CapabilityScope(include=["*"], exclude=[pattern])
        assert matches_scope(scope, "/peer/data/file") is False


class TestTheIdScopeMatcherIgnoresTheSentinel:
    """⭐ The headline. An id-scope exclude that canonicalizes to the sentinel
    is a literal that matches nothing, so it excludes nothing."""

    @pytest.mark.parametrize("pattern", CANONICALIZES_TO_SENTINEL)
    def test_an_unmatchable_literal_does_not_deny_the_whole_dimension(
        self, pattern,
    ):
        scope = CapabilityScope(include=["*"], exclude=[pattern])
        assert matches_id_scope(scope, "echo") is True, (
            f"exclude {pattern!r} denied every operation — the §5.4 path "
            "sentinel reached an id-scope dimension (0.8.2.24 N2)"
        )

    def test_teeth_an_id_exclude_that_DOES_match_still_excludes(self):
        """Without this the class passes on a matcher with no exclude arm."""
        scope = CapabilityScope(include=["*"], exclude=["apply"])
        assert matches_id_scope(scope, "apply") is False
        assert matches_id_scope(scope, "echo") is True

    def test_the_residual_is_real_and_is_NOT_closed_here(self):
        """Arch names this and deliberately leaves it open; pinned so a later
        seat does not "fix" it by inventing a second sentinel.

        The hazard the rule exists for — an exclude that carves out nothing,
        leaving a grant wider than its author wrote — **is** real on id-scope.
        ``exclude: ["*/apply"]`` almost certainly meant *not `apply`* and
        excludes nothing. §5.4's sentinel cannot detect it: under the id-scope
        grammar every non-``*`` pattern is a literal, and a literal is never
        structurally unmatchable. Closing it needs a vocabulary the matcher
        does not have. Routed as SA-PY-53; inventing one here would be arch's
        §0 pattern a fourth time.
        """
        scope = CapabilityScope(include=["*"], exclude=["*/apply"])
        assert matches_id_scope(scope, "apply") is True


class TestTheFourCallSites:
    """Behavioural rows at the sites that actually routed the value wrong.

    The matcher rows above pass on a peer that never fixed a single call site —
    they test the callee. These test the call graph, which is where the defect
    was.
    """

    def test_subscription_deliver_token_operations_is_id_scope(self):
        from entity_handlers.subscription import _validate_deliver_token

        token = Entity(type="system/capability/token", data={"grants": [
            Grant.create(
                handlers=["system/inbox"],
                operations=["receive"],
                resources=["*"],
            ).to_dict() | {"operations": {
                "include": ["receive"], "exclude": ["*/apply"],
            }},
        ]})
        assert _validate_deliver_token(token, "system/inbox/x", "receive") is True, (
            "an `operations` exclude of `*/apply` denied a `receive` the grant "
            "explicitly includes (0.8.2.24 N2)"
        )

    def test_substitute_chain_operations_is_id_scope(self):
        """``_find_consult_grants`` filters by (handler, operation); the
        operation axis is id-scope."""
        grant = Grant.create(
            handlers=["system/substitute/sources"],
            operations=["consult"],
            resources=["*"],
        ).to_dict()
        grant["operations"] = {"include": ["consult"], "exclude": ["*/apply"]}
        assert matches_id_scope(
            CapabilityScope.from_dict(grant["operations"]), "consult",
        ) is True

    @pytest.mark.parametrize("type_name", ["app/user", "app/order"])
    def test_query_type_scope_is_id_scope(self, type_name):
        from entity_handlers.query import _type_authorized_by_scope

        assert _type_authorized_by_scope(
            type_name, {"include": ["app/*"], "exclude": ["*/apply"]},
        ) is True, (
            "a `type_scope` exclude of `*/apply` denied every type — "
            "EXTENSION-QUERY §5.2 names the id-scope arm for this field"
        )

    def test_query_type_scope_teeth_a_real_exclusion_still_bites(self):
        from entity_handlers.query import _type_authorized_by_scope

        assert _type_authorized_by_scope(
            "app/secret", {"include": ["app/*"], "exclude": ["app/secret"]},
        ) is False


class TestNoIdScopeDimensionReachesThePathMatcher:
    """Structural, and it is the row that generalizes.

    A behavioural census keyed on *"denies the whole dimension"* shrinks as you
    fix things. A census keyed on *"calls this function with an id-scope
    value"* does not — it catches the NEXT site somebody adds, which is how
    all four of these arrived. (SA-PY-58's law: enumerate from the callee's
    call graph, not from the sites your first grep returned.)
    """

    ID_SCOPE_TOKENS = ("operations", "peers", "type_scope")

    #: Modules whose *every* scope match is id-scope. For these the census
    #: above is blind, and the mutation run is what showed it: restoring
    #: `query._type_authorized_by_scope` to the path matcher reddened the two
    #: behavioural rows and left the census GREEN, because the argument at
    #: that site is a local named `scope` and carries no id-scope token. A
    #: census keyed on the argument's *text* cannot see a site that binds the
    #: value first — the AP-21 shape (a gate whose search key is part of what
    #: the defect removes) inside a gate written to apply AP-21.
    #:
    #: So these modules get a stronger, ledger-shaped rule: the path matcher
    #: must not be referenced AT ALL. Adding a legitimate path-scope match to
    #: one of them is a deliberate act — remove it from the ledger and say why.
    ID_SCOPE_ONLY_MODULES = {
        "packages/entity-handlers/src/entity_handlers/query.py":
            "its only two scope matches are `type_scope`, which "
            "EXTENSION-QUERY §5.2 assigns to the id-scope arm by name",
    }

    @pytest.mark.parametrize("module,why", sorted(ID_SCOPE_ONLY_MODULES.items()))
    def test_an_id_scope_only_module_does_not_reference_the_path_matcher(
        self, module, why,
    ):
        import pathlib
        import re

        source = pathlib.Path(module).read_text()
        hits = [
            f"{n}: {line.strip()}"
            for n, line in enumerate(source.splitlines(), start=1)
            if re.search(r"(?<!_id)matches_scope\(", line)
            and not line.strip().startswith("#")
        ]
        assert hits == [], (
            f"{module} reaches the PATH-scope matcher, but {why}. An id-scope "
            "value matched by the path matcher over-grants on `include` and "
            "inverts the intent on `exclude` (§5.2 F40), and since 0.8.2.21 it "
            "reaches the §5.4 NEVER_MATCH sentinel, which denies the whole "
            "dimension (0.8.2.24 N2):\n  " + "\n  ".join(hits)
        )

    def test_no_handler_module_matches_an_id_scope_value_with_the_path_matcher(self):
        import pathlib
        import re

        roots = [
            pathlib.Path("packages/entity-handlers/src/entity_handlers"),
            pathlib.Path("packages/entity-core/src/entity_core"),
            pathlib.Path("packages/entity-sdk/src/entity_sdk"),
        ]
        call = re.compile(r"(?<!_id)matches_scope\(\s*([^,\n]+)")
        offenders: list[str] = []
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*.py"):
                for lineno, line in enumerate(
                    path.read_text().splitlines(), start=1,
                ):
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    m = call.search(line)
                    if not m:
                        continue
                    arg = m.group(1)
                    if any(tok in arg for tok in self.ID_SCOPE_TOKENS):
                        offenders.append(f"{path}:{lineno}: {stripped}")

        assert offenders == [], (
            "an id-scope dimension is being matched by the PATH-scope matcher "
            "— §5.2 calls that a conformance defect (it over-grants on "
            "`include` and inverts the intent on `exclude`), and since "
            "0.8.2.21 it additionally reaches the §5.4 NEVER_MATCH sentinel, "
            "which denies the whole dimension (0.8.2.24 N2). Use "
            "`matches_id_scope`:\n  " + "\n  ".join(offenders)
        )
