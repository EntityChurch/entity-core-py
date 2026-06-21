"""Narrowing verification tests for EXTENSION-TYPE v1.1 §6.

T4 gate. When a child type extends a parent, each parent constraint
must be present on the child and equal-to-or-more-restrictive per the
§6.2 rules table. We run these tests through the type handler's
validate op (with narrowing wired in `_op_validate` for entities of
type `system/type` that have `extends`) so the end-to-end path is
honest.

Per §5.5, narrowing is a **Conformance** algorithm: two impls MUST
accept/reject the same `extends` relationships, so the test surface
here doubles as the cross-impl conformance vector for Rust + Go.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

@pytest.fixture
def peer():
    kp = Keypair.generate()
    return PeerBuilder().with_keypair(kp).with_all_handlers().build()


def _make_ctx(peer) -> HandlerContext:
    blanket = {
        "grants": [
            {
                "handlers": {"include": ["*"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["*"]},
            }
        ]
    }
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=blanket,
        caller_capability=blanket,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
    )


def _seed_type(peer, type_entity: Entity) -> None:
    peer.emit_pathway.emit(
        f"system/type/{type_entity.data['name']}", type_entity,
        EmitContext.bootstrap(),
    )


async def _validate_type_def(peer, child_def: dict) -> dict:
    """Validate a `system/type` entity through the handler.

    The handler runs Phase 1 (structural against the meta-type),
    Phase 2 (constraint dispatch — meta-type usually has none), and
    Phase 3 (narrowing). For these tests we care about Phase 3.
    """
    handler = peer.handlers.find_handler("system/type")
    ctx = _make_ctx(peer)
    entity = {"type": "system/type", "data": child_def}
    response = await handler(
        "system/type", "validate", {"data": {"entity": entity}}, ctx,
    )
    assert response["status"] == 200, response
    return response["result"]["data"]


def _narrowing_violations(result: dict) -> list[dict]:
    """Pull out just the narrowing violations (everything else is
    likely meta-type structural noise we don't care about here).

    Violations land in flat form per the entity-field-annotation rule
    — `array_of system/type/violation` carries records matching the
    type's fields directly, no `{type, data}` envelope.
    """
    out = []
    for v in result.get("violations", []) or []:
        if "narrowing violation" in v.get("reason", ""):
            out.append(v)
    return out


# ---------------------------------------------------------------------------
# Numeric bounds (§6.2)
# ---------------------------------------------------------------------------


class TestNumericNarrowing:
    @pytest.mark.asyncio
    async def test_min_child_tightens_lower_bound_ok(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/age-adult",
            "fields": {
                "age": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 0}},
                    ],
                },
            },
        }))
        result = await _validate_type_def(peer, {
            "name": "app/age-senior",
            "extends": "app/age-adult",
            "fields": {
                "age": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 65}},
                    ],
                },
            },
        })
        assert _narrowing_violations(result) == []

    @pytest.mark.asyncio
    async def test_min_child_widens_lower_bound_fails(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/strict",
            "fields": {
                "x": {
                    "type_ref": "primitive/int",
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 10}},
                    ],
                },
            },
        }))
        result = await _validate_type_def(peer, {
            "name": "app/loose",
            "extends": "app/strict",
            "fields": {
                "x": {
                    "type_ref": "primitive/int",
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 0}},
                    ],
                },
            },
        })
        violations = _narrowing_violations(result)
        assert len(violations) == 1
        assert violations[0]["constraint"] == "system/type/constraint/min"
        assert "widens lower bound" in violations[0]["reason"]

    @pytest.mark.asyncio
    async def test_max_child_tightens_upper_bound_ok(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/byte",
            "fields": {
                "v": {
                    "type_ref": "primitive/int",
                    "constraints": [
                        {"type": "system/type/constraint/max", "data": {"max": 255}},
                    ],
                },
            },
        }))
        result = await _validate_type_def(peer, {
            "name": "app/nibble",
            "extends": "app/byte",
            "fields": {
                "v": {
                    "type_ref": "primitive/int",
                    "constraints": [
                        {"type": "system/type/constraint/max", "data": {"max": 15}},
                    ],
                },
            },
        })
        assert _narrowing_violations(result) == []

    @pytest.mark.asyncio
    async def test_max_child_widens_upper_bound_fails(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/bounded",
            "fields": {
                "v": {
                    "type_ref": "primitive/int",
                    "constraints": [
                        {"type": "system/type/constraint/max", "data": {"max": 100}},
                    ],
                },
            },
        }))
        result = await _validate_type_def(peer, {
            "name": "app/unbounded",
            "extends": "app/bounded",
            "fields": {
                "v": {
                    "type_ref": "primitive/int",
                    "constraints": [
                        {"type": "system/type/constraint/max", "data": {"max": 1000}},
                    ],
                },
            },
        })
        assert len(_narrowing_violations(result)) == 1


# ---------------------------------------------------------------------------
# Length + count bounds (§6.2) — same rule shape as numeric
# ---------------------------------------------------------------------------


class TestLengthCountNarrowing:
    @pytest.mark.asyncio
    async def test_min_length_must_tighten(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/name",
            "fields": {
                "n": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/min-length",
                         "data": {"min_length": 1}},
                    ],
                },
            },
        }))
        # Child widens — fails.
        bad = await _validate_type_def(peer, {
            "name": "app/maybe-empty-name",
            "extends": "app/name",
            "fields": {
                "n": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/min-length",
                         "data": {"min_length": 0}},
                    ],
                },
            },
        })
        assert len(_narrowing_violations(bad)) == 1

    @pytest.mark.asyncio
    async def test_max_count_must_tighten(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/tag-list",
            "fields": {
                "tags": {
                    "array_of": {"type_ref": "primitive/string"},
                    "constraints": [
                        {"type": "system/type/constraint/max-count",
                         "data": {"max_count": 10}},
                    ],
                },
            },
        }))
        ok = await _validate_type_def(peer, {
            "name": "app/short-tag-list",
            "extends": "app/tag-list",
            "fields": {
                "tags": {
                    "array_of": {"type_ref": "primitive/string"},
                    "constraints": [
                        {"type": "system/type/constraint/max-count",
                         "data": {"max_count": 3}},
                    ],
                },
            },
        })
        assert _narrowing_violations(ok) == []


# ---------------------------------------------------------------------------
# Pattern and format — equal-only (§6.2)
# ---------------------------------------------------------------------------


class TestEqualOnlyNarrowing:
    @pytest.mark.asyncio
    async def test_pattern_byte_equal_narrows(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/digit-string",
            "fields": {
                "s": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/pattern",
                         "data": {"pattern": r"\d+"}},
                    ],
                },
            },
        }))
        ok = await _validate_type_def(peer, {
            "name": "app/digit-string-derived",
            "extends": "app/digit-string",
            "fields": {
                "s": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/pattern",
                         "data": {"pattern": r"\d+"}},
                    ],
                },
            },
        })
        assert _narrowing_violations(ok) == []

    @pytest.mark.asyncio
    async def test_pattern_non_equal_incomparable_fails(self, peer):
        """§6.2: non-equal patterns are incomparable. Even when the
        child pattern intuitively *is* narrower (e.g. r'\\d{4}' under
        r'\\d+'), the v1.1 contract says no speculative regex-subset
        recognition. Reject."""
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/numeric",
            "fields": {
                "s": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/pattern",
                         "data": {"pattern": r"\d+"}},
                    ],
                },
            },
        }))
        bad = await _validate_type_def(peer, {
            "name": "app/four-digit",
            "extends": "app/numeric",
            "fields": {
                "s": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/pattern",
                         "data": {"pattern": r"\d{4}"}},
                    ],
                },
            },
        })
        violations = _narrowing_violations(bad)
        assert len(violations) == 1
        assert "incomparable" in violations[0]["reason"]

    @pytest.mark.asyncio
    async def test_format_equal_narrows(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/id-base",
            "fields": {
                "id": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/format",
                         "data": {"format": "uuid"}},
                    ],
                },
            },
        }))
        ok = await _validate_type_def(peer, {
            "name": "app/id-derived",
            "extends": "app/id-base",
            "fields": {
                "id": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/format",
                         "data": {"format": "uuid"}},
                    ],
                },
            },
        })
        assert _narrowing_violations(ok) == []

    @pytest.mark.asyncio
    async def test_format_non_equal_incomparable_fails(self, peer):
        """§6.2: sub-format relationships incomparable by default."""
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/contact-base",
            "fields": {
                "v": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/format",
                         "data": {"format": "uri"}},
                    ],
                },
            },
        }))
        bad = await _validate_type_def(peer, {
            "name": "app/contact-derived",
            "extends": "app/contact-base",
            "fields": {
                "v": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/format",
                         "data": {"format": "uuid"}},
                    ],
                },
            },
        })
        assert len(_narrowing_violations(bad)) == 1


# ---------------------------------------------------------------------------
# Set kinds — one_of ⊆ / not_one_of ⊇ (ECF byte equality per element)
# ---------------------------------------------------------------------------


class TestSetNarrowing:
    @pytest.mark.asyncio
    async def test_one_of_child_subset_ok(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/color",
            "fields": {
                "c": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/one-of",
                         "data": {"values": ["red", "green", "blue", "yellow"]}},
                    ],
                },
            },
        }))
        ok = await _validate_type_def(peer, {
            "name": "app/color-rgb",
            "extends": "app/color",
            "fields": {
                "c": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/one-of",
                         "data": {"values": ["red", "green", "blue"]}},
                    ],
                },
            },
        })
        assert _narrowing_violations(ok) == []

    @pytest.mark.asyncio
    async def test_one_of_child_superset_widens_fails(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/yes-no",
            "fields": {
                "c": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/one-of",
                         "data": {"values": ["yes", "no"]}},
                    ],
                },
            },
        }))
        bad = await _validate_type_def(peer, {
            "name": "app/yes-no-maybe",
            "extends": "app/yes-no",
            "fields": {
                "c": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/one-of",
                         "data": {"values": ["yes", "no", "maybe"]}},
                    ],
                },
            },
        })
        assert len(_narrowing_violations(bad)) == 1

    @pytest.mark.asyncio
    async def test_not_one_of_child_superset_ok(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/bad-words",
            "fields": {
                "w": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/not-one-of",
                         "data": {"values": ["foo"]}},
                    ],
                },
            },
        }))
        ok = await _validate_type_def(peer, {
            "name": "app/worse-words",
            "extends": "app/bad-words",
            "fields": {
                "w": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/not-one-of",
                         "data": {"values": ["foo", "bar", "baz"]}},
                    ],
                },
            },
        })
        assert _narrowing_violations(ok) == []


# ---------------------------------------------------------------------------
# Removed constraint (§6.3)
# ---------------------------------------------------------------------------


class TestRemovedConstraint:
    @pytest.mark.asyncio
    async def test_child_removes_constraint_fails(self, peer):
        """§6.3: a child MUST NOT remove a constraint present on the parent."""
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/restricted",
            "fields": {
                "n": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 0}},
                        {"type": "system/type/constraint/max", "data": {"max": 100}},
                    ],
                },
            },
        }))
        bad = await _validate_type_def(peer, {
            "name": "app/unrestricted",
            "extends": "app/restricted",
            "fields": {
                "n": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        # min kept; max removed.
                        {"type": "system/type/constraint/min", "data": {"min": 0}},
                    ],
                },
            },
        })
        violations = _narrowing_violations(bad)
        assert len(violations) == 1
        assert violations[0]["constraint"] == "system/type/constraint/max"
        assert "removed parent constraint" in violations[0]["reason"]

    @pytest.mark.asyncio
    async def test_child_adds_constraint_ok(self, peer):
        """Adding a constraint to an unconstrained parent field is fine
        — adding always narrows."""
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/open",
            "fields": {"n": {"type_ref": "primitive/uint"}},
        }))
        ok = await _validate_type_def(peer, {
            "name": "app/closed",
            "extends": "app/open",
            "fields": {
                "n": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/max", "data": {"max": 100}},
                    ],
                },
            },
        })
        assert _narrowing_violations(ok) == []


# ---------------------------------------------------------------------------
# type_pattern — child more specific (§6.2)
# ---------------------------------------------------------------------------


class TestTypePatternNarrowing:
    @pytest.mark.asyncio
    async def test_type_pattern_more_specific_ok(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/ref-base",
            "fields": {
                "ref": {
                    "type_ref": "system/tree/path",
                    "constraints": [
                        {"type": "system/type/constraint/type-pattern",
                         "data": {"pattern": "app/*"}},
                    ],
                },
            },
        }))
        ok = await _validate_type_def(peer, {
            "name": "app/ref-derived",
            "extends": "app/ref-base",
            "fields": {
                "ref": {
                    "type_ref": "system/tree/path",
                    "constraints": [
                        {"type": "system/type/constraint/type-pattern",
                         "data": {"pattern": "app/sensor/*"}},
                    ],
                },
            },
        })
        assert _narrowing_violations(ok) == []

    @pytest.mark.asyncio
    async def test_type_pattern_unrelated_fails(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/ref-narrow",
            "fields": {
                "ref": {
                    "type_ref": "system/tree/path",
                    "constraints": [
                        {"type": "system/type/constraint/type-pattern",
                         "data": {"pattern": "app/sensor/*"}},
                    ],
                },
            },
        }))
        bad = await _validate_type_def(peer, {
            "name": "app/ref-wider",
            "extends": "app/ref-narrow",
            "fields": {
                "ref": {
                    "type_ref": "system/tree/path",
                    "constraints": [
                        # widens — door/* doesn't sit under sensor/* at all.
                        {"type": "system/type/constraint/type-pattern",
                         "data": {"pattern": "app/door/*"}},
                    ],
                },
            },
        })
        assert len(_narrowing_violations(bad)) == 1


# ---------------------------------------------------------------------------
# Multi-link extends chain (§6.3)
# ---------------------------------------------------------------------------


class TestChainNarrowing:
    @pytest.mark.asyncio
    async def test_grandparent_constraint_must_narrow(self, peer):
        """§6.3 says constraint sets only grow through the chain — a
        grandchild can't remove a grandparent's constraint."""
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/gp",
            "fields": {
                "x": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/max", "data": {"max": 100}},
                    ],
                },
            },
        }))
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/p",
            "extends": "app/gp",
            "fields": {
                "x": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/max", "data": {"max": 50}},
                    ],
                },
            },
        }))
        bad = await _validate_type_def(peer, {
            "name": "app/c",
            "extends": "app/p",
            "fields": {
                "x": {
                    "type_ref": "primitive/uint",
                    # Removes max entirely.
                    "constraints": [],
                },
            },
        })
        violations = _narrowing_violations(bad)
        # Both p and gp have `max`; both report "child removed parent
        # constraint" — they're separate violations from each link.
        assert any(v["constraint"] == "system/type/constraint/max" for v in violations)
