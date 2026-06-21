"""Tests for handler registration in entity tree.

Per PROPOSAL-HANDLER-NORMALIZATION, manifests are decomposed into
system/handler/interface + system/handler entities during registration.
"""

import pytest

from entity_core.crypto.identity import Keypair
from entity_handlers import (
    ALL_HANDLER_MANIFESTS,
    CONNECT_HANDLER_MANIFEST,
    STORAGE_HANDLER_MANIFEST,
    SYSTEM_HANDLER_MANIFEST,
    build_handler_manifest,
)
from entity_core.peer import PeerBuilder
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.types.registry import (
    get_handler_interface,
    get_handler_manifest,
    list_handler_names,
    register_handlers,
)


class TestHandlerManifestBuilder:
    """Tests for the manifest builder function."""

    def test_build_handler_manifest_basic(self):
        """Build a basic handler manifest."""
        manifest = build_handler_manifest(
            name="test",
            pattern="test/*",
            operations={"read": {"output_type": "primitive/any"}},
        )

        assert manifest.type == "system/handler/manifest"
        assert manifest.data["name"] == "test"
        assert manifest.data["pattern"] == "test/*"
        assert manifest.data["operations"] == {"read": {"output_type": "primitive/any"}}

    def test_build_handler_manifest_multiple_operations(self):
        """Build manifest with multiple operations."""
        manifest = build_handler_manifest(
            name="crud",
            pattern="data/*",
            operations={
                "read": {"output_type": "data/item"},
                "write": {"input_type": "data/item", "output_type": "data/item"},
                "delete": {"output_type": "primitive/boolean"},
            },
        )

        assert len(manifest.data["operations"]) == 3
        assert "read" in manifest.data["operations"]
        assert "write" in manifest.data["operations"]
        assert "delete" in manifest.data["operations"]


class TestBuiltinManifests:
    """Tests for built-in handler manifests."""

    def test_system_handler_manifest(self):
        """System handler manifest has correct structure."""
        assert SYSTEM_HANDLER_MANIFEST.type == "system/handler/manifest"
        assert SYSTEM_HANDLER_MANIFEST.data["name"] == "system"
        assert SYSTEM_HANDLER_MANIFEST.data["pattern"] == "system/*"
        assert "get" in SYSTEM_HANDLER_MANIFEST.data["operations"]

    def test_storage_handler_manifest(self):
        """Storage handler manifest has correct structure."""
        assert STORAGE_HANDLER_MANIFEST.type == "system/handler/manifest"
        assert STORAGE_HANDLER_MANIFEST.data["name"] == "storage"
        assert STORAGE_HANDLER_MANIFEST.data["pattern"] == "*"
        ops = STORAGE_HANDLER_MANIFEST.data["operations"]
        assert "read" in ops
        assert "write" in ops
        assert "list" in ops
        assert "delete" in ops

    def test_connect_handler_manifest(self):
        """Connect handler manifest has correct structure."""
        assert CONNECT_HANDLER_MANIFEST.type == "system/handler/manifest"
        assert CONNECT_HANDLER_MANIFEST.data["name"] == "connect"
        assert CONNECT_HANDLER_MANIFEST.data["pattern"] == "system/protocol/connect"
        ops = CONNECT_HANDLER_MANIFEST.data["operations"]
        assert "hello" in ops
        assert "authenticate" in ops        # Check operation specs
        assert ops["hello"]["input_type"] == "system/protocol/connect/hello"
        assert ops["hello"]["output_type"] == "system/protocol/connect/hello"
        assert ops["authenticate"]["output_type"] == "system/capability/grant"

    def test_all_manifests_count(self):
        """ALL_HANDLER_MANIFESTS contains all built-in manifests."""
        # 23 = prior 22 + capability handler (V7 §6.2 Resolution B; backs
        # the default `system/capability:request` connect grant)
        assert len(ALL_HANDLER_MANIFESTS) == 26  # +system/relay (EXTENSION-RELAY v1.0)
        names = [m.data["name"] for m in ALL_HANDLER_MANIFESTS]
        assert "system" in names
        assert "storage" in names
        assert "connect" in names
        assert "tree" in names
        assert "handlers" in names  # V7 §6.2 system/handler register/unregister
        assert "identity" in names  # EXTENSION-IDENTITY v1.2
        assert "role" in names  # EXTENSION-ROLE v1.5
        assert "continuation" in names
        assert "inbox" in names
        assert "subscriptions" in names
        assert "revision" in names  # EXTENSION-REVISION v2.1
        assert "query" in names  # EXTENSION-QUERY v1.0
        assert "compute" in names  # EXTENSION-COMPUTE v3.5
        assert "type" in names  # EXTENSION-TYPE v1.1
        assert "type-constraints" in names  # EXTENSION-TYPE v1.1 (§5.1)
        assert "content" in names  # EXTENSION-CONTENT v3.5 (§6.1)
        assert "registry" in names  # EXTENSION-REGISTRY v1.0
        assert "discovery" in names  # EXTENSION-DISCOVERY v1.0
        assert "relay" in names  # EXTENSION-RELAY v1.0


class TestHandlerRegistration:
    """Tests for handler registration in entity tree."""

    def test_register_handlers_stores_in_tree(self):
        """Each manifest produces interface + handler entities in the tree."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer-id")
        emit_pathway = EmitPathway(content_store, entity_tree)

        register_handlers(emit_pathway, ALL_HANDLER_MANIFESTS)

        # 12 manifests -> 12 interface + 12 handler entities
        # Some handler entities may share content hashes (identical data),
        # so content store count may be less than 24
        assert len(content_store) >= 12

        # Interface entities at system/handler/{pattern}
        patterns = list_handler_names(entity_tree)
        assert "system" in patterns  # system/* stored as system
        assert "*" in patterns
        assert "system/protocol/connect" in patterns
        assert "system/tree" in patterns
        assert "system/continuation" in patterns
        assert "system/inbox" in patterns
        assert "system/subscription" in patterns

    def test_get_handler_interface(self):
        """Can retrieve handler interface entity by pattern."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer-id")
        emit_pathway = EmitPathway(content_store, entity_tree)
        register_handlers(emit_pathway, ALL_HANDLER_MANIFESTS)

        interface = get_handler_interface("system", content_store, entity_tree)
        assert interface is not None
        assert interface.type == "system/handler/interface"
        assert interface.data["name"] == "system"
        assert interface.data["pattern"] == "system/*"

    def test_handler_entity_at_pattern_path(self):
        """Slim handler entity is stored at the pattern path."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer-id")
        emit_pathway = EmitPathway(content_store, entity_tree)
        register_handlers(emit_pathway, ALL_HANDLER_MANIFESTS)

        uri = entity_tree.normalize_uri("system/tree")
        h = entity_tree.get(uri)
        assert h is not None
        handler = content_store.get(h)
        assert handler is not None
        assert handler.type == "system/handler"
        assert handler.data["interface"] == "system/handler/system/tree"
        assert "pattern" not in handler.data
        assert "name" not in handler.data
        assert "operations" not in handler.data

    def test_get_unknown_handler_returns_none(self):
        """Getting unknown handler returns None."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer-id")
        emit_pathway = EmitPathway(content_store, entity_tree)
        register_handlers(emit_pathway, ALL_HANDLER_MANIFESTS)

        manifest = get_handler_manifest("nonexistent", content_store, entity_tree)
        assert manifest is None

    def test_handler_hashes_are_deterministic(self):
        """Handler manifests produce deterministic hashes."""
        manifest1 = SYSTEM_HANDLER_MANIFEST
        manifest2 = build_handler_manifest(
            name="system",
            pattern="system/*",
            operations={"get": {"output_type": "primitive/any"}},
        )

        assert manifest1.compute_hash() == manifest2.compute_hash()


class TestPeerHandlerRegistration:
    """Tests for handler registration at peer startup."""

    def test_peer_registers_handlers_on_init(self):
        """Peer registers interface entities at system/handler/{pattern}."""
        keypair = Keypair.generate()
        peer = PeerBuilder().with_keypair(keypair).with_default_handlers().build()

        patterns = list_handler_names(peer.entity_tree)
        # 24 patterns: prior 22 + system/capability (V7 §6.2 Resolution B
        # backs the default `system/capability:request` connect grant) +
        # system/registry (EXTENSION-REGISTRY v1.0). All bootstrap-registered
        # from ALL_HANDLER_MANIFESTS regardless of which handlers run.
        assert len(patterns) == 26  # +system/relay (EXTENSION-RELAY v1.0)
        assert "system" in patterns
        assert "*" in patterns
        assert "system/protocol/connect" in patterns
        assert "system/tree" in patterns
        assert "system/continuation" in patterns
        assert "system/inbox" in patterns
        assert "system/revision" in patterns
        assert "system/subscription" in patterns
        assert "system/compute" in patterns
        assert "system/query" in patterns
        assert "system/identity" in patterns
        assert "system/role" in patterns

    def test_peer_handler_interfaces_retrievable(self):
        """Handler interface entities are retrievable by pattern."""
        keypair = Keypair.generate()
        peer = PeerBuilder().with_keypair(keypair).with_default_handlers().build()

        interface = get_handler_interface(
            "system", peer.content_store, peer.entity_tree
        )
        assert interface is not None
        assert interface.type == "system/handler/interface"
        assert interface.data["name"] == "system"

    def test_peer_tree_shows_handlers(self):
        """Interface entities appear at system/handler/ prefix."""
        keypair = Keypair.generate()
        peer = PeerBuilder().with_keypair(keypair).with_default_handlers().build()

        prefix = peer.entity_tree.normalize_uri("system/handler/")
        uris = peer.entity_tree.list_prefix(prefix)

        assert len(uris) == 26  # +system/relay (EXTENSION-RELAY v1.0)
        assert any("system/handler/system" in uri and "system/handler/system/" not in uri for uri in uris)
        assert any("system/handler/*" in uri for uri in uris)
        assert any("system/handler/system/protocol/connect" in uri for uri in uris)
        assert any("system/handler/system/tree" in uri for uri in uris)
        assert any("system/handler/system/continuation" in uri for uri in uris)
        assert any("system/handler/system/inbox" in uri for uri in uris)
        assert any("system/handler/system/revision" in uri for uri in uris)
        assert any("system/handler/system/subscription" in uri for uri in uris)
        assert any("system/handler/system/query" in uri for uri in uris)


class TestHandlerManifestContent:
    """Tests verifying handler manifest content matches spec."""

    def test_manifest_operations_is_dict(self):
        """Handler operations field is a dict (map), not a list."""
        for manifest in ALL_HANDLER_MANIFESTS:
            operations = manifest.data["operations"]
            assert isinstance(operations, dict), (
                f"Handler {manifest.data['name']} operations should be dict"
            )

    def test_operation_specs_have_types(self):
        """Operation specs have input/output type information."""
        # Connect handler has detailed operation specs
        ops = CONNECT_HANDLER_MANIFEST.data["operations"]

        # hello operation
        assert "input_type" in ops["hello"]
        assert "output_type" in ops["hello"]

        # authenticate operation (V7: renamed from identify)
        assert "input_type" in ops["authenticate"]
        assert "output_type" in ops["authenticate"]
