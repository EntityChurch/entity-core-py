"""Integration tests for the EXTENSION-TYPE v1.1 type handler.

This is the T3 gate. The type handler at `system/type` implements the
§2.3 two-phase validation flow plus Strategy-1 (`system/type/{name}`)
type resolution plus the §6 effective-fields walk through `extends`.
Phase 2 dispatches each field constraint through ctx.execute() to the
constraint handler — these tests exercise that dispatch via a real
peer so the wiring is honest end-to-end (no mocked dispatcher).

The handlers are wired directly via PeerBuilder.with_handler(...) so
this test doesn't depend on T7's with_type_handler() convenience.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext



# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def peer():
    """Build a peer with all standard handlers + the new type handlers."""
    kp = Keypair.generate()
    # with_all_handlers() now includes with_type_handler() (T7); the
    # constraint pattern outranks system/type's prefix-match at the
    # priorities chosen in the builder method.
    return PeerBuilder().with_keypair(kp).with_all_handlers().build()


def _make_ctx(peer) -> HandlerContext:
    """A test HandlerContext wired to the peer's dispatcher.

    ``_execute_dispatcher`` is the seam ctx.execute() goes through;
    pointing it at the peer's local dispatcher gives Phase 2 honest
    end-to-end routing to the constraint handler.
    """
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
    """Bind a type definition at its conventional `system/type/{name}` path."""
    name = type_entity.data["name"]
    peer.emit_pathway.emit(
        f"system/type/{name}", type_entity, EmitContext.bootstrap(),
    )


async def _validate(peer, entity: dict, type_path: str | None = None) -> dict:
    handler = peer.handlers.find_handler("system/type")
    assert handler is not None, "system/type handler not registered on peer"
    ctx = _make_ctx(peer)
    body = {"entity": entity}
    if type_path is not None:
        body["type_path"] = type_path
    response = await handler("system/type", "validate", {"data": body}, ctx)
    assert response["status"] == 200, response
    assert response["result"]["type"] == "system/type/validate-result"
    return response["result"]["data"]


# ---------------------------------------------------------------------------
# Operation envelope
# ---------------------------------------------------------------------------


class TestEnvelope:
    @pytest.mark.asyncio
    async def test_unsupported_operation_returns_501(self, peer):
        handler = peer.handlers.find_handler("system/type")
        ctx = _make_ctx(peer)
        # `synthesize` isn't a system/type op in v1.1 (and isn't on
        # the §12.3 MAY list either) — should be 501.
        r = await handler("system/type", "synthesize", {"data": {}}, ctx)
        assert r["status"] == 501

    @pytest.mark.asyncio
    async def test_missing_entity_returns_400(self, peer):
        handler = peer.handlers.find_handler("system/type")
        ctx = _make_ctx(peer)
        r = await handler("system/type", "validate", {"data": {}}, ctx)
        assert r["status"] == 400

    @pytest.mark.asyncio
    async def test_missing_type_lookup_target_returns_400(self, peer):
        handler = peer.handlers.find_handler("system/type")
        ctx = _make_ctx(peer)
        # entity has no type and no type_path provided → no resolution target.
        r = await handler(
            "system/type", "validate",
            {"data": {"entity": {"data": {}}}}, ctx,
        )
        assert r["status"] == 400


# ---------------------------------------------------------------------------
# Phase 1 — structural
# ---------------------------------------------------------------------------


class TestStructural:
    @pytest.mark.asyncio
    async def test_required_field_present(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/user",
            "fields": {"name": {"type_ref": "primitive/string"}},
        }))
        r = await _validate(peer, {"type": "app/user", "data": {"name": "alice"}})
        assert r["valid"] is True

    @pytest.mark.asyncio
    async def test_required_field_missing(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/user",
            "fields": {"name": {"type_ref": "primitive/string"}},
        }))
        r = await _validate(peer, {"type": "app/user", "data": {}})
        assert r["valid"] is False
        kinds = {v["kind"] for v in r["violations"]}
        assert kinds == {"structural"}
        assert r["violations"][0]["field"] == "name"

    @pytest.mark.asyncio
    async def test_optional_field_absent_is_clean(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/user",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "nick": {"type_ref": "primitive/string", "optional": True},
            },
        }))
        r = await _validate(peer, {"type": "app/user", "data": {"name": "alice"}})
        assert r["valid"] is True

    @pytest.mark.asyncio
    async def test_primitive_type_mismatch_is_structural(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/user",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "age": {"type_ref": "primitive/uint"},
            },
        }))
        r = await _validate(peer, {
            "type": "app/user", "data": {"name": "alice", "age": "twelve"},
        })
        assert r["valid"] is False
        violation = next(v for v in r["violations"] if v["field"] == "age")
        assert violation["kind"] == "structural"

    @pytest.mark.asyncio
    async def test_array_of_must_be_list(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/group",
            "fields": {
                "members": {"array_of": {"type_ref": "primitive/string"}},
            },
        }))
        r = await _validate(peer, {
            "type": "app/group", "data": {"members": "alice"},
        })
        assert r["valid"] is False
        assert r["violations"][0]["kind"] == "structural"

    @pytest.mark.asyncio
    async def test_unknown_type_path_reports_structural_on_type(self, peer):
        r = await _validate(peer, {"type": "app/never-bound", "data": {}})
        assert r["valid"] is False
        v = r["violations"][0]
        assert v["field"] == "type"
        assert v["kind"] == "structural"
        assert "not found" in v["reason"]

    @pytest.mark.asyncio
    async def test_explicit_type_path_overrides_entity_type(self, peer):
        """§8.3: when type_path is present it wins. Entity.type may
        disagree (e.g. an entity stored under a different type before
        the new type definition existed)."""
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/user",
            "fields": {"name": {"type_ref": "primitive/string"}},
        }))
        r = await _validate(
            peer,
            {"type": "app/different", "data": {"name": "alice"}},
            type_path="app/user",
        )
        assert r["valid"] is True


# ---------------------------------------------------------------------------
# Phase 2 — constraint dispatch via ctx.execute()
# ---------------------------------------------------------------------------


class TestConstraintDispatch:
    @pytest.mark.asyncio
    async def test_min_constraint_pass(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/profile",
            "fields": {
                "age": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 0}},
                        {"type": "system/type/constraint/max", "data": {"max": 150}},
                    ],
                },
            },
        }))
        r = await _validate(peer, {"type": "app/profile", "data": {"age": 42}})
        assert r["valid"] is True

    @pytest.mark.asyncio
    async def test_min_constraint_fail_marks_violation_with_constraint_path(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/profile",
            "fields": {
                "age": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 18}},
                    ],
                },
            },
        }))
        r = await _validate(peer, {"type": "app/profile", "data": {"age": 12}})
        assert r["valid"] is False
        v = r["violations"][0]
        assert v["field"] == "age"
        assert v["kind"] == "constraint"
        assert v["constraint"] == "system/type/constraint/min"

    @pytest.mark.asyncio
    async def test_absent_optional_field_skips_constraints(self, peer):
        """§2.4: absent fields skip constraints."""
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/profile",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "age": {
                    "type_ref": "primitive/uint",
                    "optional": True,
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 18}},
                    ],
                },
            },
        }))
        r = await _validate(peer, {"type": "app/profile", "data": {"name": "alice"}})
        assert r["valid"] is True

    @pytest.mark.asyncio
    async def test_one_of_dispatches_through_constraint_handler(self, peer):
        """End-to-end: type handler → ctx.execute() → constraint handler
        running ECF byte equality. This is the cross-impl-gate path
        exercised under real dispatch."""
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/setting",
            "fields": {
                "color": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/one-of",
                         "data": {"values": ["red", "green", "blue"]}},
                    ],
                },
            },
        }))
        r_ok = await _validate(peer, {
            "type": "app/setting", "data": {"color": "red"},
        })
        assert r_ok["valid"] is True

        r_bad = await _validate(peer, {
            "type": "app/setting", "data": {"color": "yellow"},
        })
        assert r_bad["valid"] is False
        v = r_bad["violations"][0]
        assert v["constraint"] == "system/type/constraint/one-of"

    @pytest.mark.asyncio
    async def test_unknown_constraint_type_reports_unknown_constraint(self, peer):
        """§1.2 / §5.4 default: when the constraint handler returns
        `unknown constraint type: …`, the type handler MUST report
        kind: unknown_constraint, not silent pass."""
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/widget",
            "fields": {
                "size": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/no-such-kind",
                         "data": {}},
                    ],
                },
            },
        }))
        r = await _validate(peer, {"type": "app/widget", "data": {"size": 5}})
        assert r["valid"] is False
        v = r["violations"][0]
        assert v["kind"] == "unknown_constraint"
        assert v["constraint"] == "system/type/constraint/no-such-kind"

    @pytest.mark.asyncio
    async def test_unknown_format_name_propagates_as_unknown_constraint(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/contact",
            "fields": {
                "email": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        {"type": "system/type/constraint/format",
                         "data": {"format": "phone-number"}},
                    ],
                },
            },
        }))
        r = await _validate(peer, {
            "type": "app/contact", "data": {"email": "anything"},
        })
        assert r["valid"] is False
        v = r["violations"][0]
        assert v["kind"] == "unknown_constraint"


# ---------------------------------------------------------------------------
# Effective fields via extends (§6 — narrowing tested separately in T4)
# ---------------------------------------------------------------------------


class TestExtendsChain:
    @pytest.mark.asyncio
    async def test_child_inherits_parent_required_field(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/base",
            "fields": {"id": {"type_ref": "primitive/string"}},
        }))
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/derived",
            "extends": "app/base",
            "fields": {"label": {"type_ref": "primitive/string"}},
        }))
        # Missing the inherited `id` field — structural violation.
        r = await _validate(peer, {
            "type": "app/derived", "data": {"label": "x"},
        })
        assert r["valid"] is False
        fields_failing = {v["field"] for v in r["violations"]}
        assert "id" in fields_failing

    @pytest.mark.asyncio
    async def test_extends_cycle_fails_closed(self, peer):
        """§1.5 invariant 3: cycle detection at the graph level."""
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/a", "extends": "app/b", "fields": {},
        }))
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/b", "extends": "app/a", "fields": {},
        }))
        r = await _validate(peer, {"type": "app/a", "data": {}})
        assert r["valid"] is False
        v = r["violations"][0]
        assert v["field"] == "extends"
        assert "cycle" in v["reason"]

    @pytest.mark.asyncio
    async def test_extends_parent_not_found(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/orphan",
            "extends": "app/missing",
            "fields": {},
        }))
        r = await _validate(peer, {"type": "app/orphan", "data": {}})
        assert r["valid"] is False
        assert "parent not resolvable" in r["violations"][0]["reason"]


# ---------------------------------------------------------------------------
# unevaluated_fields (§8.4 honesty contract)
# ---------------------------------------------------------------------------


class TestUnevaluatedFields:
    @pytest.mark.asyncio
    async def test_unknown_top_level_typedef_field_surfaces(self, peer):
        """The type def carries a future extension field the validator
        doesn't recognize. Per §8.4 it surfaces in unevaluated_fields
        so the caller knows the report is partial."""
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/futured",
            "fields": {"x": {"type_ref": "primitive/string"}},
            "triggers": [{"on": "create"}],  # hypothetical future open-type field
        }))
        r = await _validate(peer, {"type": "app/futured", "data": {"x": "ok"}})
        assert r["valid"] is True
        assert "triggers" in r["unevaluated_fields"]

    @pytest.mark.asyncio
    async def test_unknown_field_spec_extension_surfaces(self, peer):
        _seed_type(peer, Entity(type="system/type", data={
            "name": "app/futured2",
            "fields": {
                "x": {
                    "type_ref": "primitive/string",
                    "triggers": ["custom-extension-hook"],
                },
            },
        }))
        r = await _validate(peer, {"type": "app/futured2", "data": {"x": "ok"}})
        assert r["valid"] is True
        assert "fields.x.triggers" in r["unevaluated_fields"]
