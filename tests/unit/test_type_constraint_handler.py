"""Tests for the EXTENSION-TYPE v1.1 standard constraint handler.

This is the T2 gate from the Python EXTENSION-TYPE sprint. Covers:

* per-kind table-driven pass/fail across all 11 constraint kinds (§4)
* the §5.2 / §5.3 request / result envelope contract
* unknown constraint dispatch — fail closed per §1.2 + §5.4 default
* the §5.5 normative interop gate — `one_of` ECF byte equality on
  values whose Python-level identity diverges but whose canonical
  ECF encoding is bit-identical (e.g. uint 5 vs int 5)
* fail-closed on unknown format names (§4.5)
* `pattern` rejects PCRE-only constructs (§4.3, RE2 conformance)
* `type_pattern` resolves hash and path references and passes on
  unresolved references (§4.6)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.utils.ecf import ecf_encode
from entity_handlers.type_constraint import (
    TYPE_CONSTRAINT_HANDLER_PATTERN,
    type_constraint_handler,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@dataclass
class Ctx:
    keypair: Keypair
    pathway: EmitPathway
    handler: HandlerContext


def _make_ctx() -> Ctx:
    keypair = Keypair.generate()
    content_store = ContentStore()
    entity_tree = EntityTree(keypair.peer_id)
    pathway = EmitPathway(content_store, entity_tree)
    handler = HandlerContext(
        local_peer_id=keypair.peer_id,
        remote_peer_id=keypair.peer_id,
        handler_grant={},
        caller_capability={},
        emit_pathway=pathway,
        handler_pattern=TYPE_CONSTRAINT_HANDLER_PATTERN,
        keypair=keypair,
    )
    return Ctx(keypair=keypair, pathway=pathway, handler=handler)


def _invoke(
    constraint_type: str,
    value: Any,
    constraint_data: dict[str, Any],
    *,
    ctx: HandlerContext | None = None,
) -> dict[str, Any]:
    """Call the handler the way the dispatcher would and return the result body."""
    if ctx is None:
        ctx = _make_ctx().handler
    params = {
        "data": {
            "value": value,
            "constraint_type": constraint_type,
            "constraint_data": constraint_data,
        }
    }
    response = asyncio.run(
        type_constraint_handler(constraint_type, "validate", params, ctx)
    )
    assert response["status"] == 200
    assert response["result"]["type"] == "system/type/constraint/validate-result"
    return response["result"]["data"]


# ---------------------------------------------------------------------------
# Envelope contract (§5.2 / §5.3)
# ---------------------------------------------------------------------------


class TestEnvelope:
    def test_unsupported_operation_returns_501(self):
        ctx = _make_ctx().handler
        response = asyncio.run(
            type_constraint_handler(
                "system/type/constraint/min", "compare", {"data": {}}, ctx,
            )
        )
        assert response["status"] == 501
        assert response["result"]["data"]["code"] == "unsupported_operation"

    def test_missing_value_returns_400(self):
        ctx = _make_ctx().handler
        params = {
            "data": {
                "constraint_type": "system/type/constraint/min",
                "constraint_data": {"min": 0},
            }
        }
        response = asyncio.run(
            type_constraint_handler(
                "system/type/constraint/min", "validate", params, ctx,
            )
        )
        assert response["status"] == 400
        assert response["result"]["data"]["code"] == "invalid_request"

    def test_missing_constraint_type_returns_400(self):
        ctx = _make_ctx().handler
        params = {"data": {"value": 5, "constraint_data": {"min": 0}}}
        response = asyncio.run(
            type_constraint_handler(
                "system/type/constraint/min", "validate", params, ctx,
            )
        )
        assert response["status"] == 400


# ---------------------------------------------------------------------------
# Numeric bounds (§4.1)
# ---------------------------------------------------------------------------


class TestNumericBounds:
    @pytest.mark.parametrize(
        "value, bound, expect_valid",
        [
            (5, 5, True),       # boundary inclusive
            (5, 4, True),       # above
            (5, 6, False),      # below
            (5.5, 5.0, True),
            (-1, 0, False),
            (0, -1, True),
        ],
    )
    def test_min(self, value, bound, expect_valid):
        r = _invoke("system/type/constraint/min", value, {"min": bound})
        assert r["valid"] is expect_valid

    @pytest.mark.parametrize(
        "value, bound, expect_valid",
        [
            (5, 5, True),
            (5, 6, True),
            (5, 4, False),
        ],
    )
    def test_max(self, value, bound, expect_valid):
        r = _invoke("system/type/constraint/max", value, {"max": bound})
        assert r["valid"] is expect_valid

    def test_min_nan_value_fails(self):
        """Per §4.1: NaN comparisons return false."""
        r = _invoke("system/type/constraint/min", float("nan"), {"min": 0})
        assert r["valid"] is False

    def test_max_nan_value_fails(self):
        r = _invoke("system/type/constraint/max", float("nan"), {"max": 100})
        assert r["valid"] is False

    def test_min_non_numeric_fails(self):
        r = _invoke("system/type/constraint/min", "five", {"min": 0})
        assert r["valid"] is False
        assert "not numeric" in r["reason"]

    def test_min_bool_not_numeric(self):
        """Python's ``bool`` subclasses ``int`` but is not numeric per
        the type system — booleans live on `primitive/bool`."""
        r = _invoke("system/type/constraint/min", True, {"min": 0})
        assert r["valid"] is False


# ---------------------------------------------------------------------------
# Length bounds (§4.2)
# ---------------------------------------------------------------------------


class TestLengthBounds:
    @pytest.mark.parametrize(
        "value, bound, expect_valid",
        [
            ("hello", 5, True),
            ("hi", 5, False),
            ("", 0, True),
            ("café", 4, True),  # codepoints, not bytes
            (b"hello", 5, True),
            (b"hi", 5, False),
        ],
    )
    def test_min_length(self, value, bound, expect_valid):
        r = _invoke("system/type/constraint/min-length", value, {"min_length": bound})
        assert r["valid"] is expect_valid

    @pytest.mark.parametrize(
        "value, bound, expect_valid",
        [
            ("hello", 5, True),
            ("toolong", 5, False),
            ("", 0, True),
        ],
    )
    def test_max_length(self, value, bound, expect_valid):
        r = _invoke("system/type/constraint/max-length", value, {"max_length": bound})
        assert r["valid"] is expect_valid

    def test_length_on_non_string_fails(self):
        r = _invoke("system/type/constraint/min-length", 42, {"min_length": 1})
        assert r["valid"] is False

    def test_codepoint_count_not_utf8_byte_count(self):
        """A 4-char string of multi-byte codepoints has length 4."""
        # 4 codepoints, ~8 UTF-8 bytes
        r = _invoke("system/type/constraint/max-length", "🐍🐍🐍🐍", {"max_length": 4})
        assert r["valid"] is True
        r2 = _invoke("system/type/constraint/max-length", "🐍🐍🐍🐍", {"max_length": 3})
        assert r2["valid"] is False


class TestCountBounds:
    def test_min_count_array(self):
        r = _invoke("system/type/constraint/min-count", [1, 2, 3], {"min_count": 2})
        assert r["valid"] is True
        r = _invoke("system/type/constraint/min-count", [1], {"min_count": 2})
        assert r["valid"] is False

    def test_max_count_map(self):
        r = _invoke("system/type/constraint/max-count", {"a": 1, "b": 2}, {"max_count": 3})
        assert r["valid"] is True
        r = _invoke("system/type/constraint/max-count", {"a": 1, "b": 2, "c": 3}, {"max_count": 2})
        assert r["valid"] is False

    def test_count_on_non_collection_fails(self):
        r = _invoke("system/type/constraint/min-count", "abc", {"min_count": 1})
        assert r["valid"] is False


# ---------------------------------------------------------------------------
# Pattern (§4.3) — RE2 conformance
# ---------------------------------------------------------------------------


class TestPattern:
    def test_full_match_required(self):
        """§4.3: full-match semantics — must match the entire string."""
        r = _invoke("system/type/constraint/pattern", "12345", {"pattern": r"\d+"})
        assert r["valid"] is True
        r = _invoke("system/type/constraint/pattern", "abc123", {"pattern": r"\d+"})
        assert r["valid"] is False  # prefix "abc" prevents full match

    def test_unicode_class(self):
        r = _invoke("system/type/constraint/pattern", "Hello", {"pattern": r"[A-Z][a-z]+"})
        assert r["valid"] is True

    def test_non_string_value_fails(self):
        r = _invoke("system/type/constraint/pattern", 123, {"pattern": r"\d+"})
        assert r["valid"] is False

    def test_pcre_backreference_rejected(self):
        """Per §4.3: backtracking engines / PCRE constructs are not
        conformant. RE2 rejects backreferences at compile time."""
        r = _invoke(
            "system/type/constraint/pattern", "aa", {"pattern": r"(a)\1"}
        )
        assert r["valid"] is False
        assert "invalid RE2 pattern" in r["reason"]


# ---------------------------------------------------------------------------
# one_of / not_one_of (§4.4, §5.5 normative)
# ---------------------------------------------------------------------------


class TestEnumeration:
    def test_one_of_match(self):
        r = _invoke(
            "system/type/constraint/one-of", "red",
            {"values": ["red", "green", "blue"]},
        )
        assert r["valid"] is True

    def test_one_of_miss(self):
        r = _invoke(
            "system/type/constraint/one-of", "yellow",
            {"values": ["red", "green", "blue"]},
        )
        assert r["valid"] is False

    def test_not_one_of_match(self):
        r = _invoke(
            "system/type/constraint/not-one-of", "yellow",
            {"values": ["red", "green", "blue"]},
        )
        assert r["valid"] is True

    def test_not_one_of_miss(self):
        r = _invoke(
            "system/type/constraint/not-one-of", "red",
            {"values": ["red", "green", "blue"]},
        )
        assert r["valid"] is False

    def test_ecf_byte_equality_for_numbers(self):
        """§5.5 normative: equality is canonical-CBOR byte equality. The
        ECF deterministic-CBOR encoder normalizes ``5`` (int) and ``5.0``
        (float) to *different* canonical encodings (the spec preserves
        the numeric kind on the wire), so these should NOT compare equal.
        """
        assert ecf_encode(5) != ecf_encode(5.0)
        r = _invoke(
            "system/type/constraint/one-of", 5.0,
            {"values": [1, 2, 5]},
        )
        # 5.0 encodes as float; the list holds ints. No byte equality.
        assert r["valid"] is False

    def test_ecf_byte_equality_load_bearing_vector(self):
        """Cross-impl interop vector for §5.5.

        Same value encoded identically across impls — agreement on
        valid: true is the cross-impl gate. We pin the byte form here
        so any encoder drift breaks the test loudly.
        """
        value = {"kind": "color", "value": "red"}
        candidates = [
            {"kind": "color", "value": "blue"},
            {"kind": "color", "value": "red"},
            {"kind": "size", "value": "large"},
        ]
        # Pin the canonical encoding of `value` so we'd catch encoder regressions.
        # The canonical-CBOR encoding of {"kind":"color","value":"red"} per
        # RFC 8949 §4.2: map(2) [kind(4)->color(5), value(5)->red(3)].
        expected_ecf = bytes.fromhex(
            "a2"          # map of 2 entries
            "646b696e64"  # text(4) "kind"
            "65636f6c6f72"  # text(5) "color"
            "6576616c7565"  # text(5) "value"
            "63726564"      # text(3) "red"
        )
        assert ecf_encode(value) == expected_ecf

        r = _invoke(
            "system/type/constraint/one-of", value, {"values": candidates}
        )
        assert r["valid"] is True


# ---------------------------------------------------------------------------
# Format (§4.5)
# ---------------------------------------------------------------------------


class TestFormat:
    @pytest.mark.parametrize(
        "fmt, value, expect_valid",
        [
            ("uri", "https://example.com/foo", True),
            ("uri", "not a uri", False),
            ("uri", "mailto:user@example.com", True),
            ("date-time", "2026-05-28T12:34:56Z", True),
            ("date-time", "2026-05-28T12:34:56+02:00", True),
            ("date-time", "2026-05-28", False),  # missing time
            ("date", "2026-05-28", True),
            ("date", "2026-13-01", False),
            ("uuid", "550e8400-e29b-41d4-a716-446655440000", True),
            ("uuid", "not-a-uuid", False),
            ("base58", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", True),
            ("base58", "0OIl", False),  # contains forbidden chars
            ("re2", r"^\d+$", True),
            ("re2", r"(a)\1", False),  # PCRE-only — not RE2
        ],
    )
    def test_well_known_formats(self, fmt, value, expect_valid):
        r = _invoke("system/type/constraint/format", value, {"format": fmt})
        assert r["valid"] is expect_valid, (
            f"format={fmt} value={value!r}: expected valid={expect_valid}, got {r}"
        )

    def test_unknown_format_fails_closed(self):
        """§4.5: unknown format names fail closed — caller maps to
        kind: unknown_constraint."""
        r = _invoke(
            "system/type/constraint/format", "user@example.com",
            {"format": "email"},
        )
        assert r["valid"] is False
        assert r["reason"] == "unknown format: email"


# ---------------------------------------------------------------------------
# type_pattern (§4.6)
# ---------------------------------------------------------------------------


class TestTypePattern:
    def test_path_reference_matching_type(self):
        """Bind an entity at a path; the constraint resolves the path,
        reads the entity's type, and globs against the pattern."""
        ctx = _make_ctx()
        entity = Entity(type="app/sensor/temperature", data={"value": 21.5})
        ctx.pathway.emit("app/sensors/livingroom", entity, EmitContext.bootstrap())

        r = _invoke(
            "system/type/constraint/type-pattern",
            "app/sensors/livingroom",
            {"pattern": "app/sensor/*"},
            ctx=ctx.handler,
        )
        assert r["valid"] is True

    def test_path_reference_non_matching_type(self):
        ctx = _make_ctx()
        entity = Entity(type="app/door/lock", data={"locked": True})
        ctx.pathway.emit("app/doors/front", entity, EmitContext.bootstrap())

        r = _invoke(
            "system/type/constraint/type-pattern",
            "app/doors/front",
            {"pattern": "app/sensor/*"},
            ctx=ctx.handler,
        )
        assert r["valid"] is False

    def test_unresolved_reference_passes_with_warning(self):
        """§4.6: type_pattern validates the type of REACHABLE entities.
        Resolution failure SHOULD pass with a warning."""
        ctx = _make_ctx()
        r = _invoke(
            "system/type/constraint/type-pattern",
            "app/never/bound",
            {"pattern": "app/anything/*"},
            ctx=ctx.handler,
        )
        assert r["valid"] is True
        assert "unresolved" in r["reason"]

    def test_the_subtree_form_crosses_slashes_at_any_depth(self):
        """§4.6 `[ruled 2026-08-18]` — `prefix/*` is core §5.4's **subtree**
        match, so one form reaches every depth.

        This test asserted a `**` before the ruling, and the pair below is why
        that mattered: the old segment-scoped `*` matched `app/widgets/large`
        and **not** `app/widgets/buttons/large`, so an author covering a
        namespace had to reach for a token the corpus reserves nowhere — and
        got two implementations' worth of disagreement about what it meant.
        """
        ctx = _make_ctx()
        for path, type_name in (
            ("app/things/shallow", "app/widgets/large"),
            ("app/things/deep", "app/widgets/buttons/large"),
        ):
            ctx.pathway.emit(path, Entity(type=type_name, data={}),
                             EmitContext.bootstrap())
            r = _invoke(
                "system/type/constraint/type-pattern", path,
                {"pattern": "app/widgets/*"}, ctx=ctx.handler,
            )
            assert r["valid"] is True, f"{type_name} was not matched at depth"

    def test_the_retained_slash_blocks_the_sibling_prefix(self):
        """§5.4 keeps the `/` when it strips the `*`, which is what stops
        `app/widget/*` matching `app/widgetry/x` — a subtree match, not a
        string-prefix one."""
        ctx = _make_ctx()
        ctx.pathway.emit("app/things/sib", Entity(type="app/widgetry/x", data={}),
                         EmitContext.bootstrap())
        r = _invoke(
            "system/type/constraint/type-pattern", "app/things/sib",
            {"pattern": "app/widget/*"}, ctx=ctx.handler,
        )
        assert r["valid"] is False

    def test_double_star_is_not_a_token_and_matches_literally(self):
        """`**` is reserved nowhere in this corpus. §5.4's vocabulary is exact
        / subtree / match-all, so `app/widgets/**` is an *exact* pattern that
        matches the type literally named `app/widgets/**` and nothing else.

        Kept as a control row rather than deleted: the wrong reading is what
        this peer shipped, and a test that fails loudly if it comes back is
        worth more than its absence.
        """
        ctx = _make_ctx()
        ctx.pathway.emit("app/things/foo",
                         Entity(type="app/widgets/buttons/large", data={}),
                         EmitContext.bootstrap())
        r = _invoke(
            "system/type/constraint/type-pattern", "app/things/foo",
            {"pattern": "app/widgets/**"}, ctx=ctx.handler,
        )
        assert r["valid"] is False

    def test_bare_star_matches_any_type(self):
        ctx = _make_ctx()
        ctx.pathway.emit("app/things/any", Entity(type="whatever/at/all", data={}),
                         EmitContext.bootstrap())
        r = _invoke(
            "system/type/constraint/type-pattern", "app/things/any",
            {"pattern": "*"}, ctx=ctx.handler,
        )
        assert r["valid"] is True

    def test_a_bare_literal_is_exact_not_a_prefix(self):
        """`anything else is an exact match` — `app/widgets` does not cover
        `app/widgets/large`. An author wanting the subtree writes the `/*`."""
        ctx = _make_ctx()
        ctx.pathway.emit("app/things/x", Entity(type="app/widgets/large", data={}),
                         EmitContext.bootstrap())
        r = _invoke(
            "system/type/constraint/type-pattern", "app/things/x",
            {"pattern": "app/widgets"}, ctx=ctx.handler,
        )
        assert r["valid"] is False


# ---------------------------------------------------------------------------
# Unknown constraint (§5.4 default branch, §1.2 fail-closed)
# ---------------------------------------------------------------------------


class TestUnknownConstraint:
    def test_unknown_constraint_fails_closed(self):
        r = _invoke("custom/constraint/coverage", "anything", {})
        assert r["valid"] is False
        assert "unknown constraint type" in r["reason"]
