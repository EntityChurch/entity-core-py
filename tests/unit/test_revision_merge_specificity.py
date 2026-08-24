"""`EXTENSION-REVISION` §5.1 `[v3.12]` — `pattern_specificity` is a **total
order**, and §4.4.18 **V7** refuses a pattern the peer cannot evaluate.

Two halves of one surface, and the second is why the first is not enough:

- **The order.** Step 2's pseudocode has called `pattern_specificity` since the
  section was written and the corpus defined it nowhere. It decides *which
  config wins* when several match, and the winning config decides the merged
  bytes — so an implementation collapsing it to a scalar manufactures ties the
  spec does not have and resolves them by whatever the store happened to yield.
  `list_entities` ordering is unspecified, so two peers with identical configs
  and identical content could resolve one conflict differently, with nothing
  failing anywhere.
- **The validator.** SA-PY-12 moved this call site onto `_glob_match` while V6
  still bound `exclude` / `exclude_types` only, so for one day an unevaluable
  pattern was storable and then fell silently to form 4. **A matcher with no
  validator is half a pin.**

`_merge_config_order_key` is deliberately *not* shared with
`EXTENSION-HISTORY`'s `pattern_specificity`, which carries the same name over a
different domain with a different order — see `test_history_config_specificity`.
"""

from __future__ import annotations

import pytest

from entity_handlers.revision import (
    _merge_config_order_key,
    _merge_pattern_rank,
    validate_exclude_pattern,
)


def _most_specific(pairs):
    """The winner under the total order — `min`, since the key sorts ascending
    by specificity."""
    return min(pairs, key=lambda pn: _merge_config_order_key(*pn))


class TestTheFourRanks:
    @pytest.mark.parametrize("pattern,rank", [
        ("docs/a.lock", 3),   # exact
        ("docs/*", 2),        # subtree prefix
        ("*.lock", 1),        # trailing literal
        ("*", 0),             # match-all
    ])
    def test_the_ranks(self, pattern, rank):
        assert _merge_pattern_rank(pattern) == rank

    def test_exact_beats_everything(self):
        assert _most_specific([
            ("*", "a"), ("*.lock", "b"), ("docs/*", "c"), ("docs/a.lock", "d"),
        ]) == ("docs/a.lock", "d")

    def test_anchored_beats_unanchored(self):
        """The one genuinely chosen rung, and the spec records it as a choice:
        for `docs/a.lock` both `docs/*` and `*.lock` match and neither contains
        the other. The prefix names a location the operator laid out; the suffix
        names a file kind that may appear anywhere, so the narrower claim is the
        located one."""
        assert _most_specific([("*.lock", "kind"), ("docs/*", "place")]) == (
            "docs/*", "place")

    def test_match_all_loses_to_everything(self):
        assert _most_specific([("*", "z"), ("*.lock", "a")]) == ("*.lock", "a")


class TestLengthWithinARank:
    def test_a_longer_prefix_wins(self):
        assert _most_specific([
            ("docs/*", "short"), ("docs/deep/nested/*", "long"),
        ]) == ("docs/deep/nested/*", "long")

    def test_a_longer_suffix_wins(self):
        assert _most_specific([("*.lock", "short"), ("*.a.lock", "long")]) == (
            "*.a.lock", "long")

    def test_length_never_outranks_form(self):
        """A very long suffix still loses to a short prefix — rank is the most
        significant key, and a scalar score is exactly what would get this
        backwards."""
        assert _most_specific([
            ("*/a/very/long/suffix.lock", "suffix"), ("d/*", "prefix"),
        ]) == ("d/*", "prefix")


class TestTiesAreImpossible:
    """`[MUST]` — two configs may legitimately carry the same `pattern` under
    different `{name}`s, so rank plus length is not yet total."""

    def test_identical_patterns_are_broken_by_name(self):
        assert _most_specific([("docs/*", "bravo"), ("docs/*", "alpha")]) == (
            "docs/*", "alpha")

    def test_equal_length_patterns_are_broken_lexicographically(self):
        assert _most_specific([("bbb/*", "x"), ("aaa/*", "y")]) == ("aaa/*", "y")

    def test_the_order_is_independent_of_enumeration(self):
        """The defect this rule exists to close. Both orderings select the same
        config; the `specificity > best` comparison this replaced kept whichever
        the store yielded first."""
        configs = [("docs/*", "b"), ("docs/*", "a"), ("*.lock", "c")]
        assert _most_specific(configs) == _most_specific(list(reversed(configs)))

    def test_no_two_distinct_configs_share_a_key(self):
        """Totality, stated as the property rather than as an example."""
        configs = [
            ("*", "z"), ("*.lock", "a"), ("*.lock", "b"), ("docs/*", "a"),
            ("docs/*", "b"), ("docs/deep/*", "a"), ("docs/a.lock", "a"),
        ]
        keys = [_merge_config_order_key(*c) for c in configs]
        assert len(set(keys)) == len(configs)


class TestV7RejectsWhatItCannotEvaluate:
    """§4.4.18 **V7** — the write-time refusal. The handler-level rows live in
    `test_revision_extension`; these pin the predicate V7 calls, which is the
    same one §4.4.17 V6 calls, because one grammar means one validator."""

    @pytest.mark.parametrize("pattern", ["**", "a/**/b", "a*b", "*a*", "a/*/b"])
    def test_the_reject_rows(self, pattern):
        # MERGE-PATTERN-REJECT-1. `**` is the row that matters most: it is not
        # an unsupported token, it is one the corpus reserves nowhere.
        assert validate_exclude_pattern(pattern) is False

    @pytest.mark.parametrize("pattern", ["docs/*", "*.lock", "*", "docs/a.lock"])
    def test_the_acceptance_control(self, pattern):
        # Required by GUIDE-CONFORMANCE §2.4a: a rejection row without one
        # passes trivially against a peer that rejects everything.
        assert validate_exclude_pattern(pattern) is True
