"""Tests for EXTENSION-TYPE v1.1 §7 analysis ops on system/type.

Covers the T5 (SHOULD) + T6 (MAY) gates:

* compare    (§7.2) — structural diff of two type defs.
* compatible (§7.3) — directional + bidirectional compatibility.
* converge   (§7.4) — intersection type across N defs.
* adopt      (§7.5) — rewrite a remote def for local use.
* reconcile  (§7.6) — strategy merge (intersect / union / prefer).

All ops are read-only — the handler returns results inline; the
caller decides whether to ``put`` derived types.
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


def _ctx(peer) -> HandlerContext:
    blanket = {"grants": [
        {"handlers": {"include": ["*"]}, "resources": {"include": ["*"]},
         "operations": {"include": ["*"]}}
    ]}
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=blanket,
        caller_capability=blanket,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
    )


def _seed(peer, type_entity: Entity) -> None:
    peer.emit_pathway.emit(
        f"system/type/{type_entity.data['name']}", type_entity,
        EmitContext.bootstrap(),
    )


async def _invoke(peer, operation: str, data: dict) -> dict:
    """Returns response["result"]["data"] for ops whose result is a
    wrapper entity (compare-result, compatibility-report,
    reconcile-result) — the meaningful payload lives one level down."""
    handler = peer.handlers.find_handler("system/type")
    response = await handler("system/type", operation, {"data": data}, _ctx(peer))
    assert response["status"] == 200, response
    return response["result"]["data"]


async def _invoke_entity(peer, operation: str, data: dict) -> dict:
    """Returns response["result"] for ops whose result IS the entity
    (converge → system/type, adopt → system/type). Per §7.4 / §7.5
    the spec says the result is the entity itself, not a wrapper."""
    handler = peer.handlers.find_handler("system/type")
    response = await handler("system/type", operation, {"data": data}, _ctx(peer))
    assert response["status"] == 200, response
    return response["result"]


# ---------------------------------------------------------------------------
# compare (§7.2)
# ---------------------------------------------------------------------------


class TestCompare:
    @pytest.mark.asyncio
    async def test_identical_types_match(self, peer):
        for name in ("app/a", "app/b"):
            _seed(peer, Entity(type="system/type", data={
                "name": name,
                "fields": {
                    "x": {"type_ref": "primitive/string"},
                    "y": {"type_ref": "primitive/uint"},
                },
            }))
        r = await _invoke(peer, "compare", {
            "type_a": "app/a", "type_b": "app/b",
        })
        assert r["only_a"] == []
        assert r["only_b"] == []
        assert "incompatible" not in r
        for fname in ("x", "y"):
            row = r["shared"][fname]
            assert row["type_match"] is True
            assert row["constraint_match"] is True

    @pytest.mark.asyncio
    async def test_diverging_fields_in_only_lists(self, peer):
        _seed(peer, Entity(type="system/type", data={
            "name": "app/a",
            "fields": {
                "shared": {"type_ref": "primitive/string"},
                "only_in_a": {"type_ref": "primitive/uint"},
            },
        }))
        _seed(peer, Entity(type="system/type", data={
            "name": "app/b",
            "fields": {
                "shared": {"type_ref": "primitive/string"},
                "only_in_b": {"type_ref": "primitive/bool"},
            },
        }))
        r = await _invoke(peer, "compare", {
            "type_a": "app/a", "type_b": "app/b",
        })
        assert r["only_a"] == ["only_in_a"]
        assert r["only_b"] == ["only_in_b"]
        assert "shared" in r["shared"]

    @pytest.mark.asyncio
    async def test_shared_field_with_type_mismatch_lists_incompatibility(self, peer):
        _seed(peer, Entity(type="system/type", data={
            "name": "app/a",
            "fields": {"x": {"type_ref": "primitive/string"}},
        }))
        _seed(peer, Entity(type="system/type", data={
            "name": "app/b",
            "fields": {"x": {"type_ref": "primitive/uint"}},
        }))
        r = await _invoke(peer, "compare", {
            "type_a": "app/a", "type_b": "app/b",
        })
        assert r["shared"]["x"]["type_match"] is False
        assert "incompatible" in r
        incomp = r["incompatible"][0]
        assert incomp["field_name"] == "x"

    @pytest.mark.asyncio
    async def test_constraint_difference_does_not_break_structural(self, peer):
        """§12.2 (NATIVE-TYPE-SYSTEM): constraint diffs are
        independent of structural compatibility."""
        _seed(peer, Entity(type="system/type", data={
            "name": "app/loose",
            "fields": {
                "n": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 0}},
                    ],
                },
            },
        }))
        _seed(peer, Entity(type="system/type", data={
            "name": "app/tight",
            "fields": {
                "n": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 10}},
                    ],
                },
            },
        }))
        r = await _invoke(peer, "compare", {
            "type_a": "app/loose", "type_b": "app/tight",
        })
        row = r["shared"]["n"]
        assert row["type_match"] is True
        assert row["constraint_match"] is False


# ---------------------------------------------------------------------------
# compatible (§7.3)
# ---------------------------------------------------------------------------


class TestCompatible:
    @pytest.mark.asyncio
    async def test_identical_types_fully_compatible(self, peer):
        for name in ("app/a", "app/b"):
            _seed(peer, Entity(type="system/type", data={
                "name": name,
                "fields": {"x": {"type_ref": "primitive/string"}},
            }))
        r = await _invoke(peer, "compatible", {
            "type_a": "app/a", "type_b": "app/b", "direction": "bidirectional",
        })
        assert r["level"] == "fully_compatible"
        assert r["shared_fields"] == ["x"]

    @pytest.mark.asyncio
    async def test_forward_a_satisfies_b_when_b_has_subset_of_required(self, peer):
        """A has {x, y}; B has {x} (required). Forward: A → B passes
        because B's only required is satisfied by A. Backward fails
        because A requires y which B doesn't provide."""
        _seed(peer, Entity(type="system/type", data={
            "name": "app/a",
            "fields": {
                "x": {"type_ref": "primitive/string"},
                "y": {"type_ref": "primitive/uint"},
            },
        }))
        _seed(peer, Entity(type="system/type", data={
            "name": "app/b",
            "fields": {"x": {"type_ref": "primitive/string"}},
        }))
        r = await _invoke(peer, "compatible", {
            "type_a": "app/a", "type_b": "app/b", "direction": "forward",
        })
        assert r["level"] == "forward_only"

    @pytest.mark.asyncio
    async def test_incompatible_when_shared_field_types_diverge(self, peer):
        _seed(peer, Entity(type="system/type", data={
            "name": "app/a",
            "fields": {"x": {"type_ref": "primitive/string"}},
        }))
        _seed(peer, Entity(type="system/type", data={
            "name": "app/b",
            "fields": {"x": {"type_ref": "primitive/uint"}},
        }))
        r = await _invoke(peer, "compatible", {
            "type_a": "app/a", "type_b": "app/b", "direction": "bidirectional",
        })
        # Same name x with divergent types — partial: there's a shared
        # name (x) but it's incompatible.
        assert r["level"] == "partially_compatible"
        assert "incompatible_fields" in r

    @pytest.mark.asyncio
    async def test_disjoint_field_sets_are_incompatible(self, peer):
        _seed(peer, Entity(type="system/type", data={
            "name": "app/a",
            "fields": {"x": {"type_ref": "primitive/string"}},
        }))
        _seed(peer, Entity(type="system/type", data={
            "name": "app/b",
            "fields": {"y": {"type_ref": "primitive/string"}},
        }))
        r = await _invoke(peer, "compatible", {
            "type_a": "app/a", "type_b": "app/b", "direction": "bidirectional",
        })
        assert r["level"] == "incompatible"

    @pytest.mark.asyncio
    async def test_invalid_direction_400(self, peer):
        handler = peer.handlers.find_handler("system/type")
        r = await handler("system/type", "compatible",
            {"data": {"type_a": "a", "type_b": "b", "direction": "sideways"}},
            _ctx(peer))
        assert r["status"] == 400


# ---------------------------------------------------------------------------
# converge (§7.4)
# ---------------------------------------------------------------------------


class TestConverge:
    @pytest.mark.asyncio
    async def test_intersection_keeps_only_common_fields(self, peer):
        _seed(peer, Entity(type="system/type", data={
            "name": "app/a",
            "fields": {
                "shared": {"type_ref": "primitive/string"},
                "only_a": {"type_ref": "primitive/uint"},
            },
        }))
        _seed(peer, Entity(type="system/type", data={
            "name": "app/b",
            "fields": {
                "shared": {"type_ref": "primitive/string"},
                "only_b": {"type_ref": "primitive/bool"},
            },
        }))
        r = await _invoke_entity(peer, "converge", {
            "type_paths": ["app/a", "app/b"],
        })
        assert r["type"] == "system/type"
        assert set(r["data"]["fields"]) == {"shared"}

    @pytest.mark.asyncio
    async def test_converge_picks_most_restrictive_constraint(self, peer):
        _seed(peer, Entity(type="system/type", data={
            "name": "app/a",
            "fields": {
                "n": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 0}},
                    ],
                },
            },
        }))
        _seed(peer, Entity(type="system/type", data={
            "name": "app/b",
            "fields": {
                "n": {
                    "type_ref": "primitive/uint",
                    "constraints": [
                        {"type": "system/type/constraint/min", "data": {"min": 18}},
                    ],
                },
            },
        }))
        r = await _invoke_entity(peer, "converge", {
            "type_paths": ["app/a", "app/b"],
        })
        n_constraints = r["data"]["fields"]["n"]["constraints"]
        assert n_constraints == [
            {"type": "system/type/constraint/min", "data": {"min": 18}},
        ]

    @pytest.mark.asyncio
    async def test_converge_requires_at_least_two_paths(self, peer):
        handler = peer.handlers.find_handler("system/type")
        r = await handler("system/type", "converge",
            {"data": {"type_paths": ["app/a"]}}, _ctx(peer))
        assert r["status"] == 400


# ---------------------------------------------------------------------------
# adopt (§7.5)
# ---------------------------------------------------------------------------


class TestAdopt:
    @pytest.mark.asyncio
    async def test_adopt_returns_rewritten_entity(self, peer):
        _seed(peer, Entity(type="system/type", data={
            "name": "sensor/temperature",
            "fields": {"value": {"type_ref": "primitive/float"}},
        }))
        r = await _invoke_entity(peer, "adopt", {
            "source_path": "/somepeer/system/type/sensor/temperature",
            "local_name": "sensor/temp-local",
        })
        assert r["type"] == "system/type"
        assert r["data"]["name"] == "sensor/temp-local"
        assert "value" in r["data"]["fields"]

    @pytest.mark.asyncio
    async def test_adopt_flags_collision(self, peer):
        _seed(peer, Entity(type="system/type", data={
            "name": "app/existing",
            "fields": {"a": {"type_ref": "primitive/string"}},
        }))
        # source_path resolves locally (since this is a single-peer
        # test) — the adopt op will both rewrite and detect the
        # collision because local_name == existing name.
        r = await _invoke_entity(peer, "adopt", {
            "source_path": "/somepeer/system/type/app/existing",
            "local_name": "app/existing",
        })
        assert "adopt_warnings" in r["data"]
        assert "collision" in r["data"]["adopt_warnings"]

    @pytest.mark.asyncio
    async def test_adopt_404_when_source_missing(self, peer):
        handler = peer.handlers.find_handler("system/type")
        r = await handler("system/type", "adopt",
            {"data": {"source_path": "/p/system/type/never/bound"}}, _ctx(peer))
        assert r["status"] == 404


# ---------------------------------------------------------------------------
# reconcile (§7.6)
# ---------------------------------------------------------------------------


class TestReconcile:
    @pytest.fixture
    def _diverged_types(self, peer):
        """PeerA added `phone`; PeerB added `address`. Both share
        `name`. Classic reconcile-needed scenario per §7.6."""
        _seed(peer, Entity(type="system/type", data={
            "name": "app/contact-a",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "phone": {"type_ref": "primitive/string"},
            },
        }))
        _seed(peer, Entity(type="system/type", data={
            "name": "app/contact-b",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "address": {"type_ref": "primitive/string"},
            },
        }))

    @pytest.mark.asyncio
    async def test_intersect_keeps_only_common(self, peer, _diverged_types):
        r = await _invoke(peer, "reconcile", {
            "type_paths": ["app/contact-a", "app/contact-b"],
            "strategy": "intersect",
        })
        result = r
        merged = result["reconciled_type"]["data"]
        assert set(merged["fields"]) == {"name"}
        assert sorted(result["fields_dropped"]) == ["address", "phone"]

    @pytest.mark.asyncio
    async def test_union_keeps_all_makes_unique_optional(self, peer, _diverged_types):
        r = await _invoke(peer, "reconcile", {
            "type_paths": ["app/contact-a", "app/contact-b"],
            "strategy": "union",
        })
        merged = r["reconciled_type"]["data"]
        assert set(merged["fields"]) == {"name", "phone", "address"}
        # phone and address are not in every source → optional.
        assert merged["fields"]["phone"].get("optional") is True
        assert merged["fields"]["address"].get("optional") is True
        # name is in both → stays required.
        assert merged["fields"]["name"].get("optional") is not True
        assert sorted(r["fields_made_optional"]) == ["address", "phone"]

    @pytest.mark.asyncio
    async def test_prefer_uses_first_def_for_overlap(self, peer):
        """When two sources have the same field with different types,
        prefer uses the first (preferred) source's version and
        records the rest as incompatibilities."""
        _seed(peer, Entity(type="system/type", data={
            "name": "app/p",
            "fields": {"x": {"type_ref": "primitive/string"}},
        }))
        _seed(peer, Entity(type="system/type", data={
            "name": "app/q",
            "fields": {"x": {"type_ref": "primitive/uint"}},
        }))
        r = await _invoke(peer, "reconcile", {
            "type_paths": ["app/p", "app/q"],
            "strategy": "prefer",
        })
        x = r["reconciled_type"]["data"]["fields"]["x"]
        assert x == {"type_ref": "primitive/string"}
        assert "incompatibilities" in r

    @pytest.mark.asyncio
    async def test_invalid_strategy_400(self, peer, _diverged_types):
        handler = peer.handlers.find_handler("system/type")
        r = await handler("system/type", "reconcile",
            {"data": {"type_paths": ["app/contact-a", "app/contact-b"],
                       "strategy": "guess"}},
            _ctx(peer))
        assert r["status"] == 400
