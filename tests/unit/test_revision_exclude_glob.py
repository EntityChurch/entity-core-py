"""`EXTENSION-REVISION` §2.4 `glob_match` — a matcher that is wire contract.

The exclude filter decides which bindings enter a version trie, and the trie
root is the version's identity. So **the glob semantics are part of the hash**:
two peers that disagree about a pattern commit different version hashes for
identical content, and neither is detectably wrong at the call site.

SA-PY-11 reported that §2.4 named `glob_match` and defined it nowhere. It is
now pinned normatively — **four closed forms, tested in order**, plus §4.4.17
**V6**, which rejects anything outside them at config write:

1. `*` — match-all.
2. `<literal>/*` — subtree prefix, `ENTITY-CORE-PROTOCOL` §5.4 verbatim. The
   `*` **crosses `/` at any depth**; the retained `/` stops the sibling-prefix
   false positive.
3. `*<literal>` — trailing literal, a byte suffix over the **whole** subject
   with `/` not special. The only addition to §5.4's vocabulary in the corpus.
4. `<literal>` — exact, not a prefix.

The trap this file exists to pin is that **no stdlib glob is conformant** —
not `fnmatch`, and not a `path.Match` port either. Both fail for the same
simple reason: they *accept patterns this grammar rejects*. The withdrawn
doublestar pin (which this repo's first fix implemented, and which arch
retracted in `ROUTING-2026-08-18-h`) is gone with them. `fnmatch` stays below
as an explicit **control row**, so simplifying to it fails loudly.

Each test names the conformance vector it carries (§2.4's table).
"""

from __future__ import annotations

import fnmatch

import pytest

from entity_handlers.revision import _glob_match, validate_exclude_pattern


class TestForm2SubtreePrefixCrossesSeparators:
    """`REV-GLOB-PREFIX-1/2` — the §6.1 Reentrancy case, with one star."""

    @pytest.mark.parametrize(
        "subject",
        [
            "system/revision/head",
            "system/revision/head/abcd/deep",
            "system/revision/head/abcd/deep/deeper/x",
        ],
    )
    def test_it_reaches_any_depth(self, subject):
        # REV-GLOB-PREFIX-1. This is why no second wildcard token is needed:
        # form 2 IS the protocol's subtree match and always crossed `/`.
        assert _glob_match("system/revision/*", subject) is True

    def test_a_sibling_prefix_is_not_swallowed(self):
        # REV-GLOB-PREFIX-2 — the retained "/" is load-bearing.
        assert _glob_match("system/revision/*", "system/revisionary/x") is False

    def test_the_prefix_itself_without_a_slash_is_not_matched(self):
        assert _glob_match("system/revision/*", "system/revision") is False

    def test_the_required_reentrancy_excludes_reach_their_engine_paths(self):
        for pattern, subject in (
            ("system/revision/*", "system/revision/head/abcd"),
            ("system/tree/root/*", "system/tree/root/abcd"),
            ("system/tree/tracking-config/*", "system/tree/tracking-config/x"),
            ("system/history/*", "system/history/abcd/transition"),
            ("system/clock/*", "system/clock/state"),
        ):
            assert _glob_match(pattern, subject) is True, f"{pattern} vs {subject}"


class TestForm3TrailingLiteralIsAByteSuffix:
    """`REV-GLOB-SUFFIX-1/2` — the one form beyond §5.4, and `/` is NOT special."""

    @pytest.mark.parametrize("subject", ["a/b/foo.cache", ".cache", "x.cache"])
    def test_it_matches_at_any_depth_and_at_the_root(self, subject):
        assert _glob_match("*.cache", subject) is True

    @pytest.mark.parametrize("subject", ["a/cache/b", "foo.cache.tmp", "cache"])
    def test_the_suffix_must_terminate_the_subject(self, subject):
        # `a/cache/b` is the infix case, deliberately unsupported: a pattern
        # matching "anything containing a cache segment" is not expressible.
        assert _glob_match("*.cache", subject) is False


class TestForm4ExactIsNotAPrefix:
    """`REV-GLOB-EXACT-1` — the form a reader most often assumes is a prefix."""

    def test_the_literal_matches_itself(self):
        assert _glob_match("docs", "docs") is True

    @pytest.mark.parametrize("subject", ["docs/x", "docsx", "a/docs"])
    def test_and_nothing_else(self, subject):
        assert _glob_match("docs", subject) is False


class TestForm1MatchAll:
    """`REV-GLOB-ALL-1`."""

    @pytest.mark.parametrize("subject", ["", "a", "a/b/c", "system/revision/x"])
    def test_everything(self, subject):
        assert _glob_match("*", subject) is True


class TestTheSameFourFormsApplyToTypeNames:
    """`REV-GLOB-TYPES-1` — `subject` is the entity type name for
    `exclude_types`, and the grammar does not change with the subject."""

    def test_a_subtree_form_over_a_type_namespace(self):
        assert _glob_match("app/*", "app/note") is True
        assert _glob_match("app/*", "app/deep/note") is True
        assert _glob_match("app/*", "application/note") is False

    def test_a_suffix_form_over_a_type_name(self):
        assert _glob_match("*-draft", "app/note-draft") is True
        assert _glob_match("*-draft", "app/note") is False


class TestV6RejectsEverythingOutsideTheFourForms:
    """`REV-GLOB-REJECT-1/2` — the load-bearing half of the ruling.

    A matcher that merely *omits* `**` and one that *rejects* it are
    indistinguishable until a config carries one. Only write-time rejection
    closes the divergence, because an unrepresentable config cannot be stored.
    """

    @pytest.mark.parametrize(
        "pattern",
        ["**", "a/**/b", "a*b", "*a*", "system/revision/**", "a*", "a/*/b", "a/b*"],
    )
    def test_rejected(self, pattern):
        assert validate_exclude_pattern(pattern) is False

    @pytest.mark.parametrize(
        "pattern",
        ["*", "tmp/*", "system/revision/*", "*.cache", "docs", "", "a/b/c", "*/b"],
    )
    def test_accepted(self, pattern):
        assert validate_exclude_pattern(pattern) is True

    def test_a_leading_star_is_form_3_even_when_the_literal_contains_a_slash(self):
        # `*/b` reads like a segment wildcard and is not one. V6 admits it —
        # one `*`, first character — and form 3 evaluates it as the byte
        # suffix `/b`, because `/` is not special in form 3. So it matches
        # `a/b` and `deep/nested/b`, and NOT the top-level `b`.
        assert validate_exclude_pattern("*/b") is True
        assert _glob_match("*/b", "a/b") is True
        assert _glob_match("*/b", "deep/nested/b") is True
        assert _glob_match("*/b", "b") is False
        # The `a*` control beside it: one `*`, final character, but NOT after
        # a `/` — so V6 refuses it rather than letting form 4 read it as the
        # literal two-character name `a*`.
        assert validate_exclude_pattern("a*") is False

    def test_a_non_string_is_not_a_pattern(self):
        assert validate_exclude_pattern(None) is False  # type: ignore[arg-type]

    def test_every_accepted_pattern_is_evaluable_by_one_of_the_four_branches(self):
        # The grammar and the matcher have to agree on their domain: V6's job
        # is to admit exactly what `_glob_match` can decide. A pattern that
        # validates but falls through to an unintended branch is the failure
        # this pins — it would evaluate silently and wrongly.
        assert _glob_match("*", "anything") is True                  # form 1
        assert _glob_match("tmp/*", "tmp/deep/x") is True            # form 2
        assert _glob_match("*.cache", "a/b.cache") is True           # form 3
        assert _glob_match("docs", "docs") is True                   # form 4


class TestNoStdlibGlobIsConformant:
    """The control rows. These are not assertions about `fnmatch`'s quality —
    they are the difference, pinned, so a later simplification to the obvious
    tool fails here instead of silently forking a version DAG."""

    def test_fnmatch_accepts_the_patterns_the_grammar_rejects(self):
        # This is the actual reason both stdlib defaults are out — not the
        # crossing-`/` question the withdrawn pin argued from.
        for pattern in ("**", "a*b", "*a*"):
            assert validate_exclude_pattern(pattern) is False
            # ...yet fnmatch will happily evaluate every one of them.
            fnmatch.fnmatchcase("a/b", pattern)

    def test_fnmatch_disagrees_on_form_3(self):
        # `*.cache` under fnmatch also matches at depth — same answer here by
        # coincidence, not by rule. The divergence shows on the exact form:
        assert _glob_match("docs", "docs/x") is False
        assert fnmatch.fnmatchcase("docs/x", "docs") is False
        # ...and on character classes, which the grammar has no notion of:
        assert _glob_match("[ab]", "a") is False
        assert fnmatch.fnmatchcase("a", "[ab]") is True
