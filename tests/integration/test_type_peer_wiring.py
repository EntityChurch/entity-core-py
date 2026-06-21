"""PeerBuilder wiring tests for EXTENSION-TYPE v1.1.

T7 gate. Verifies that ``with_type_handler()`` registers both
handlers correctly, that ``with_all_handlers()`` includes them, that
the manifests are stored in the entity tree (discoverable by other
peers via ``system/handler/{pattern}`` lookup), and that the
priority ordering routes ``system/type/constraint/*`` paths to the
constraint handler rather than to the more general ``system/type``
handler's prefix match.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder


@pytest.fixture
def peer():
    return (
        PeerBuilder().with_keypair(Keypair.generate())
        .with_all_handlers().build()
    )


class TestRegistration:
    def test_type_handler_registered(self, peer):
        info = peer.handlers.find_handler_info("system/type")
        assert info is not None
        assert info.name == "type"
        assert info.pattern == "system/type"

    def test_constraint_handler_registered(self, peer):
        # Probing with a concrete constraint path; the handler at
        # pattern `system/type/constraint/*` should be the match.
        info = peer.handlers.find_handler_info("system/type/constraint/min")
        assert info is not None
        assert info.name == "type-constraints"
        assert info.pattern == "system/type/constraint/*"

    def test_constraint_pattern_outranks_type_prefix_match(self, peer):
        """The constraint handler's pattern is more specific than
        ``system/type``'s prefix-match coverage of the same paths;
        the dispatcher must route ``system/type/constraint/...``
        paths to the constraint handler, never to the type handler."""
        info = peer.handlers.find_handler_info("system/type/constraint/one-of")
        assert info is not None
        assert info.name == "type-constraints"

    def test_type_handler_does_not_swallow_constraint_paths(self, peer):
        """Symmetric: requesting `system/type` directly hits the type
        handler — not the constraint handler."""
        info = peer.handlers.find_handler_info("system/type")
        assert info is not None
        assert info.name == "type"


class TestManifestsInTree:
    """The type handler manifests are published to the entity tree
    on build so other peers can discover the v1.1 ops."""

    def test_type_handler_interface_in_tree(self, peer):
        uri = peer.entity_tree.normalize_uri("system/handler/system/type")
        h = peer.entity_tree.get(uri)
        assert h is not None
        entity = peer.content_store.get(h)
        assert entity is not None
        assert entity.type == "system/handler/interface"
        assert entity.data["name"] == "type"
        ops = entity.data["operations"]
        # MUST + SHOULD + MAY all expose surface-level ops
        for op in ("validate", "compare", "compatible",
                   "converge", "adopt", "reconcile"):
            assert op in ops, f"missing op {op} in published manifest"
        assert ops["validate"]["input_type"] == "system/type/validate-request"
        assert ops["validate"]["output_type"] == "system/type/validate-result"

    def test_constraint_handler_interface_in_tree(self, peer):
        uri = peer.entity_tree.normalize_uri(
            "system/handler/system/type/constraint"
        )
        h = peer.entity_tree.get(uri)
        assert h is not None
        entity = peer.content_store.get(h)
        assert entity is not None
        assert entity.type == "system/handler/interface"
        assert entity.data["name"] == "type-constraints"
        ops = entity.data["operations"]
        assert "validate" in ops
        assert (
            ops["validate"]["input_type"]
            == "system/type/constraint/validate-request"
        )
