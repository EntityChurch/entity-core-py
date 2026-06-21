"""Unit tests for the V7 §6.2 handlers handler (register/unregister)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.handlers import (
    HANDLERS_HANDLER_PATTERN,
    HANDLERS_TYPE_DEFS,
    handlers_handler,
)


def _ctx(ep, peer_id, keypair=None, *, resource_targets=None):
    """Minimal HandlerContext for handlers_handler tests.

    Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE: register/unregister derive the
    handler pattern from ctx.resource.targets[0]. Tests must pass it.
    """
    ctx = MagicMock()
    ctx.emit_pathway = ep
    ctx.local_peer_id = peer_id
    ctx.handler_pattern = HANDLERS_HANDLER_PATTERN
    ctx.bounds = None
    ctx.keypair = keypair
    ctx.resource_targets = resource_targets
    return ctx


def _setup():
    keypair = Keypair.generate()
    cs = ContentStore()
    et = EntityTree(keypair.peer_id)
    ep = EmitPathway(cs, et)
    return ep, cs, et, keypair


def _manifest(pattern, name, operations, **extra):
    data = {"pattern": pattern, "name": name, "operations": operations, **extra}
    return {"type": "system/handler/manifest", "data": data}


# ============================================================================
# register
# ============================================================================

class TestRegister:

    @pytest.mark.asyncio
    async def test_register_writes_interface_and_handler_at_pattern(self):
        ep, cs, et, kp = _setup()

        manifest = _manifest("local/foo", "foo",
                             {"do": {"output_type": "primitive/any"}})
        params = {"data": {"manifest": manifest}}

        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )
        assert result["status"] == 200
        assert result["result"]["data"]["pattern"] == "local/foo"

        # Handler entity at pattern path
        h = et.get("local/foo")
        assert h is not None
        handler_entity = cs.get(h)
        assert handler_entity.type == "system/handler"
        assert handler_entity.data["interface"] == "system/handler/local/foo"

        # Interface entity at system/handler/{pattern}
        h = et.get("system/handler/local/foo")
        assert h is not None
        interface_entity = cs.get(h)
        assert interface_entity.type == "system/handler/interface"
        assert interface_entity.data["name"] == "foo"
        assert interface_entity.data["pattern"] == "local/foo"
        assert "do" in interface_entity.data["operations"]

    @pytest.mark.asyncio
    async def test_register_creates_grant(self):
        ep, cs, et, kp = _setup()

        manifest = _manifest("local/foo", "foo", {"do": {}})
        params = {"data": {"manifest": manifest}}

        await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )

        h = et.get("system/capability/grants/local/foo")
        assert h is not None
        grant = cs.get(h)
        assert grant.type == "system/capability/token"
        assert isinstance(grant.data["grants"], list)
        assert len(grant.data["grants"]) >= 1

    @pytest.mark.asyncio
    async def test_register_returns_pattern_and_grant(self):
        ep, _, _, kp = _setup()

        manifest = _manifest("local/foo", "foo", {"do": {}})
        params = {"data": {"manifest": manifest}}

        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )
        data = result["result"]["data"]
        assert data["pattern"] == "local/foo"
        # F-CIMP-4: `grant` is the BARE CapabilityToken data
        # (grants / granter / grantee / created_at), NOT an entity wrapper.
        # Pre-fix shape was {"type": "...", "data": {...}, "content_hash": ...}
        # which Go's strict RegisterResultData decoder rejected with
        # "register result grant.grantee is zero". Type def says
        # `{type_ref: "system/capability/token"}` which under the cross-impl
        # wire convention means bare data fields, not entity wrapper. See
        # handlers.py:224 inline note + core-go validate-peer entity_native
        # hardening for the receiver-side decode contract.
        assert "grants" in data["grant"]
        assert "grantee" in data["grant"]
        assert isinstance(data["grant"]["grantee"], bytes)
        assert len(data["grant"]["grantee"]) == 33  # algorithm byte + 32-byte digest
        # Not an entity wrapper — these keys must NOT be present at the top
        # of the `grant` field.
        assert "type" not in data["grant"], (
            "F-CIMP-4 regression: `grant` must be bare CapabilityToken data, "
            "not entity-wrapped. Go's RegisterResultData decoder reads "
            "Grantee at the top level — wrapping under `data` hides it."
        )
        assert "content_hash" not in data["grant"]

    @pytest.mark.asyncio
    async def test_register_rejects_compute_builtin_override(self):
        # EXTENSION-COMPUTE §3.5: the compute builtins MUST NOT be overridden.
        ep, cs, et, kp = _setup()

        manifest = _manifest("system/compute/builtins/map", "evil",
                             {"eval": {"output_type": "primitive/any"}})
        params = {"data": {"manifest": manifest}}

        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/system/compute/builtins/map"]),
        )
        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "builtin_override_prohibited"
        # Nothing should have been written at the builtin pattern path.
        assert et.get("system/compute/builtins/map") is None

    @pytest.mark.asyncio
    async def test_register_uses_requested_scope_over_internal_scope(self):
        ep, cs, et, kp = _setup()

        manifest = _manifest("local/foo", "foo", {"do": {}}, internal_scope=[
            {"handlers": {"include": ["system/tree"]},
             "operations": {"include": ["get"]},
             "resources": {"include": ["local/foo/*"]}},
        ])
        requested_scope = [
            {"handlers": {"include": ["system/tree"]},
             "operations": {"include": ["get", "put"]},
             "resources": {"include": ["local/foo/*"]}},
        ]
        params = {"data": {"manifest": manifest, "requested_scope": requested_scope}}

        await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )

        grant = cs.get(et.get("system/capability/grants/local/foo"))
        ops = grant.data["grants"][0]["operations"]["include"]
        assert "put" in ops  # requested_scope wins, has put

    @pytest.mark.asyncio
    async def test_register_falls_back_to_internal_scope(self):
        ep, cs, et, kp = _setup()

        manifest = _manifest("local/foo", "foo", {"do": {}}, internal_scope=[
            {"handlers": {"include": ["system/tree"]},
             "operations": {"include": ["get"]},
             "resources": {"include": ["local/foo/*"]}},
        ])
        params = {"data": {"manifest": manifest}}

        await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )

        grant = cs.get(et.get("system/capability/grants/local/foo"))
        ops = grant.data["grants"][0]["operations"]["include"]
        assert ops == ["get"]

    @pytest.mark.asyncio
    async def test_register_writes_types(self):
        ep, cs, et, kp = _setup()

        manifest = _manifest("local/foo", "foo", {"do": {}})
        types = {
            "local/foo/widget": {
                "name": "local/foo/widget",
                "fields": {"name": {"type_ref": "primitive/string"}},
            },
        }
        params = {"data": {"manifest": manifest, "types": types}}

        await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )

        h = et.get("system/type/local/foo/widget")
        assert h is not None
        type_entity = cs.get(h)
        assert type_entity.type == "system/type"
        assert type_entity.data["name"] == "local/foo/widget"

    @pytest.mark.asyncio
    async def test_register_propagates_expression_path(self):
        """Entity-native handler manifests carry expression_path through to
        the handler entity so dispatch can find it."""
        ep, cs, et, kp = _setup()

        manifest = _manifest("local/foo", "foo", {"do": {}},
                             expression_path="local/foo/expr")
        params = {"data": {"manifest": manifest}}

        await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )

        handler_entity = cs.get(et.get("local/foo"))
        assert handler_entity.data["expression_path"] == "local/foo/expr"

    @pytest.mark.asyncio
    async def test_register_rejects_missing_manifest(self):
        ep, _, _, kp = _setup()
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", {"data": {}},
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_request"

    @pytest.mark.asyncio
    async def test_register_rejects_malformed_manifest(self):
        ep, _, _, kp = _setup()
        # Missing operations (name+operations are still required)
        params = {"data": {"manifest": {"data": {"name": "foo"}}}}
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )
        assert result["status"] == 400

    @pytest.mark.asyncio
    async def test_register_rejects_missing_resource(self):
        """Per P-V7-1: register requires exactly one resource target."""
        ep, _, _, kp = _setup()
        manifest = _manifest("local/foo", "foo", {"do": {}})
        params = {"data": {"manifest": manifest}}
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp),  # no resource_targets
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "ambiguous_resource"

    @pytest.mark.asyncio
    async def test_register_rejects_manifest_pattern_mismatch(self):
        """Per P-V7-1 manifest.pattern policy: present + disagrees → 400."""
        ep, _, _, kp = _setup()
        # Manifest declares one pattern, resource derives another.
        manifest = _manifest("local/bar", "foo", {"do": {}})
        params = {"data": {"manifest": manifest}}
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "manifest_pattern_mismatch"

    @pytest.mark.asyncio
    async def test_register_derives_pattern_when_manifest_omits_it(self):
        """Per P-V7-1 manifest.pattern policy: absent → derive from resource."""
        ep, cs, et, kp = _setup()
        # Manifest carries no pattern field.
        manifest = {"type": "system/handler/manifest", "data": {
            "name": "foo", "operations": {"do": {}},
        }}
        params = {"data": {"manifest": manifest}}
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register", params,
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )
        assert result["status"] == 200
        assert result["result"]["data"]["pattern"] == "local/foo"
        # Interface entity carries the derived pattern.
        interface = cs.get(et.get("system/handler/local/foo"))
        assert interface.data["pattern"] == "local/foo"


# ============================================================================
# unregister
# ============================================================================

class TestUnregister:

    @pytest.mark.asyncio
    async def test_unregister_removes_all_locations(self):
        ep, cs, et, kp = _setup()

        # First register
        manifest = _manifest("local/foo", "foo", {"do": {}})
        await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register",
            {"data": {"manifest": manifest}},
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )
        # Pre-conditions
        assert et.get("local/foo") is not None
        assert et.get("system/handler/local/foo") is not None
        assert et.get("system/capability/grants/local/foo") is not None

        # Unregister: pattern derived from resource (P-V7-2).
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "unregister",
            {"data": {}},
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/foo"]),
        )
        assert result["status"] == 200

        # All four locations gone
        assert et.get("local/foo") is None
        assert et.get("system/handler/local/foo") is None
        assert et.get("system/capability/grants/local/foo") is None

    @pytest.mark.asyncio
    async def test_unregister_rejects_missing_resource(self):
        """Per P-V7-2: unregister requires exactly one resource target."""
        ep, _, _, kp = _setup()
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "unregister", {"data": {}},
            _ctx(ep, kp.peer_id, kp),
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "ambiguous_resource"

    @pytest.mark.asyncio
    async def test_unregister_rejects_malformed_resource(self):
        """unregister resource must be system/handler/{pattern}."""
        ep, _, _, kp = _setup()
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "unregister", {"data": {}},
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["local/wrong"]),
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "malformed_resource"

    @pytest.mark.asyncio
    async def test_unregister_idempotent_on_unknown(self):
        ep, _, _, kp = _setup()
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "unregister",
            {"data": {}},
            _ctx(ep, kp.peer_id, kp,
                 resource_targets=["system/handler/local/never-registered"]),
        )
        # ep.delete returns 200 even if path didn't exist
        assert result["status"] == 200


# ============================================================================
# unsupported operations
# ============================================================================

class TestUnsupportedOperations:

    @pytest.mark.asyncio
    async def test_unsupported_op_returns_501(self):
        ep, _, _, kp = _setup()
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "list", {}, _ctx(ep, kp.peer_id, kp),
        )
        assert result["status"] == 501
        assert result["result"]["data"]["code"] == "unsupported_operation"


# ============================================================================
# type defs structure
# ============================================================================

class TestTypeDefs:

    def test_handlers_type_defs_present(self):
        # Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE P-V7-2: the
        # unregister-request wrapper is eliminated.
        names = [t["name"] for t in HANDLERS_TYPE_DEFS]
        assert "system/handler/register-request" in names
        assert "system/handler/register-result" in names
        assert "system/handler/unregister-request" not in names
