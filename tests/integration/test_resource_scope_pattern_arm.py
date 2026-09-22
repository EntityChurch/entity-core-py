"""§5.2's PATTERN arm of ``check_resource_scope`` — which this peer did not
have at all.

.. rubric:: The defect

§5.2 gives ``check_resource_scope`` **two** arms, and says so in its own
opening comment:

    *"For concrete targets: check grant include coverage + not in grant
    exclude. For pattern targets: check grant include coverage + every
    overlapping grant exclude must be covered by a caller exclude."*

This tree implemented the first and, for the second, fell through to the same
exact-match test — so a grant ``exclude`` was enforced against a **concrete**
target and neutralized by re-spelling the same request as a **pattern**:

===========================================  ==========  ==========
request                                      measured    §5.2
===========================================  ==========  ==========
target ``/{p}/data/secret`` (concrete)       DENY        DENY
target ``/{p}/data/*`` (spans the exclude)   **ALLOW**   DENY
===========================================  ==========  ==========

against a grant of ``include: ["/{p}/*"], exclude: ["/{p}/data/secret"]``.
``matches_pattern(exclude, target)`` compares the concrete exclude against the
pattern **string**, and a concrete path never equals ``/{p}/data/*``, so the
carve-out simply did not apply.

.. rubric:: Why it is the `F68` family and not a missing feature

`F68`'s law is *a gate that caller-controlled input can make vacuous is a
bypass however correct each half is alone.* There the input was the caller's
own ``exclude``; here it is **the spelling of the target**. Neither requires
any authority the caller does not already have — the caller re-writes one
field of its own request and a grant dimension stops binding.

.. rubric:: Why nothing saw it

``patterns_overlap``, ``is_covered_by`` and ``strip_wildcard`` had **zero
occurrences** in this repo, so the arm was not weak — it was absent, and an
absent arm has no call site for a reviewer to find. Landing it broke **no
existing test**, which is the measurement that says the same thing: nothing in
4580 rows had ever sent a pattern target at a grant carrying an exclude.

The handler-level check (§6.3) mitigates this for handlers that expand a
pattern and check each entry — the listing filter does. That is defence in
depth and **not** the reason the dispatch-level rule exists: §5.2 is the gate
for handlers that act on the pattern directly, and 0.8.2.20 withdrew exactly
this "the other layer will catch it" reasoning.

Routed as **SA-PY-54**.
"""

from __future__ import annotations

import pytest

from entity_core.capability.checking import (
    check_resource_scope,
    is_covered_by,
    patterns_overlap,
    strip_wildcard,
)

PEER = "2KTestPatternArmScopePeerJdaaaaaaaaaaaaaaaaaaaa"

GRANT_EXCLUDE = f"/{PEER}/data/secret"


def _cap(include: list[str], exclude: list[str] | None = None) -> dict:
    grant: dict = {
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": include},
    }
    if exclude is not None:
        grant["resources"]["exclude"] = exclude
    return {"grants": [grant]}


def _check(target: str, caller_exclude: list[str] | None = None) -> bool:
    return check_resource_scope(
        _cap([f"/{PEER}/*"], exclude=[GRANT_EXCLUDE]),
        handler_pattern="*", operation="list",
        resource_targets=[target], resource_exclude=caller_exclude,
        local_peer_id=PEER,
    )


class TestTheFixturePeerId:

    def test_the_fixture_peer_id_is_one_a_peer_could_hold(self):
        """`G6` refuses a target whose first segment is not a peer id, so an
        invalid constant makes every row here pass or fail for the wrong
        reason. (A sibling file's first draft spelled ``Exclude`` — the
        lowercase ``l`` is outside Base58.)"""
        from entity_core.utils.identity import is_peer_id

        assert is_peer_id(PEER)


class TestThePatternArm:

    def test_a_pattern_target_MUST_NOT_span_a_grant_exclude(self):
        """⭐ The bypass. The caller changes nothing but the spelling of its
        own target and the grant's carve-out stops applying."""
        assert _check(f"/{PEER}/data/*") is False

    def test_the_concrete_form_of_the_same_request_is_the_CONTROL(self):
        """⭐ The row that makes the one above attributable — and the row that
        shows the defect was a *divergence between two spellings of one
        request*, not a missing exclusion.

        Both of these were the same authorization question; only one was
        answered correctly.
        """
        assert _check(GRANT_EXCLUDE) is False

    def test_a_caller_exclude_covering_it_is_ALLOWED(self):
        """§5.2's actual rule is not "deny pattern targets" — it is *the
        caller must carve out what the grant carves out*. Without this row a
        peer that refused every overlapping pattern would score green."""
        assert _check(f"/{PEER}/data/*", caller_exclude=[GRANT_EXCLUDE]) is True

    def test_a_caller_exclude_covering_a_SUPERSET_is_allowed(self):
        """*"(or a superset)"* — a caller excluding the whole subtree has
        excluded the path within it."""
        assert _check(f"/{PEER}/data/*", caller_exclude=[f"/{PEER}/data/*"]) is True

    def test_teeth_a_pattern_target_that_does_NOT_overlap_is_allowed(self):
        """The overlap test is load-bearing in both directions: a peer that
        denied every pattern target whenever the grant had any exclude would
        pass the headline row and fail this one."""
        assert _check(f"/{PEER}/public/*") is True

    def test_an_unrelated_caller_exclude_does_not_help(self):
        """The caller must cover **the overlapping grant exclude**, not merely
        supply some exclude. A peer testing only *"did the caller send an
        exclude?"* passes the two allow rows above and this one is what fails
        it."""
        assert _check(
            f"/{PEER}/data/*", caller_exclude=[f"/{PEER}/data/other"],
        ) is False


class TestTheHelpers:
    """§5.2 defines these three by name; all were absent from this tree."""

    def test_strip_wildcard(self):
        assert strip_wildcard("/a/b/*") == "/a/b"
        assert strip_wildcard("*") == ""
        assert strip_wildcard("/a/b") == "/a/b"

    def test_patterns_overlap_is_symmetric(self):
        assert patterns_overlap("/a/b/*", "/a/b/c") is True
        assert patterns_overlap("/a/b/c", "/a/b/*") is True
        assert patterns_overlap("/a/b/*", "/a/x/y") is False

    def test_patterns_overlap_handles_the_match_all_prefix(self):
        """``*`` strips to the empty prefix, which every path starts with —
        so a match-all grant exclude overlaps everything, as it must."""
        assert patterns_overlap("*", "/anything/at/all") is True

    def test_is_covered_by(self):
        assert is_covered_by(f"/{PEER}/data/secret", [f"/{PEER}/data/*"], PEER) is True
        assert is_covered_by(f"/{PEER}/data/secret", [f"/{PEER}/other/*"], PEER) is False
        assert is_covered_by(f"/{PEER}/data/secret", [], PEER) is False
