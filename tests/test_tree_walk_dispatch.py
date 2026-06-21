"""Unit tests for V7 §6.6 tree-walk dispatch resolution."""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_handlers import HANDLERS_HANDLER_PATTERN, ComputeExtension


@pytest.fixture
def peer():
    return (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_default_handlers()
        .with_compute_handler()
        .build()
    )


def _write_handler_entity(peer, pattern: str, *, expression_path: str | None = None,
                          interface_path: str | None = None) -> None:
    ep = peer.emit_pathway
    data = {"interface": interface_path or f"system/handler/{pattern}"}
    if expression_path is not None:
        data["expression_path"] = expression_path
    handler_entity = Entity(type="system/handler", data=data)
    ep.emit(pattern, handler_entity, EmitContext.bootstrap())


def _write_interface_entity(peer, pattern: str) -> None:
    """Write a system/handler/interface entity at system/handler/{pattern}.
    These MUST NOT be picked up by dispatch tree walk (V7 §6.6 type filter)."""
    ep = peer.emit_pathway
    interface_entity = Entity(
        type="system/handler/interface",
        data={"pattern": pattern, "name": "iface", "operations": {}},
    )
    ep.emit(f"system/handler/{pattern}", interface_entity, EmitContext.bootstrap())


# ============================================================================
# Basic tree walk
# ============================================================================

class TestTreeWalk:

    def test_finds_handler_at_exact_path(self, peer):
        _write_handler_entity(peer, "app/foo", expression_path="app/foo/expr")

        registered = peer._resolve_handler("app/foo")
        assert registered is not None
        assert registered.pattern == "app/foo"

    def test_finds_handler_at_longest_prefix(self, peer):
        """Dispatch path longer than handler pattern → longest-prefix match."""
        _write_handler_entity(peer, "app/foo", expression_path="app/foo/expr")

        registered = peer._resolve_handler("app/foo/instances/backup")
        assert registered is not None
        assert registered.pattern == "app/foo"

    def test_returns_none_when_no_match_and_no_wildcard(self):
        """A peer without a wildcard catchall returns None for unknown paths."""
        # Use minimal peer (no with_default_handlers, no wildcard).
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_handlers_handler()
            .build()
        )
        registered = peer._resolve_handler("app/never-registered")
        assert registered is None

    def test_falls_back_to_wildcard_when_tree_walk_misses(self, peer):
        """Tree walk fails for app/bar (no entity), but with_default_handlers
        registers a `*` storage catchall — that should win."""
        registered = peer._resolve_handler("app/bar")
        assert registered is not None
        assert registered.pattern == "*"


# ============================================================================
# Type filter — system/handler/interface entries excluded from dispatch
# ============================================================================

class TestInterfaceTypeFilter:

    def test_interface_entity_not_dispatchable(self, peer):
        """V7 §6.6 normative: dispatch walks only system/handler entities.
        system/handler/interface entries at system/handler/{pattern} are
        the discovery index and MUST NOT be dispatch targets."""
        # Manually write an interface entity at a path that could match.
        # No corresponding system/handler entity at the path.
        _write_interface_entity(peer, "app/iface-only")

        # Dispatch path system/handler/app/iface-only would walk:
        #   "system/handler/app/iface-only" → interface entity → SKIP (wrong type)
        #   "system/handler/app" → no entity
        #   "system/handler" → handlers handler (system/handler entity) → MATCH
        # So the handlers handler at system/handler is what wins (not the interface).
        registered = peer._resolve_handler("system/handler/app/iface-only")
        assert registered is not None
        assert registered.pattern == "system/handler"


# ============================================================================
# Compiled vs entity-native binding lookup
# ============================================================================

class TestBindingLookup:

    def test_tree_walked_pattern_matching_compiled_uses_compiled(self, peer):
        """When the tree-walked pattern matches a compiled handler in the
        in-memory registry, the compiled function is used."""
        # system/handler is in the tree (bootstrap manifest) AND in the
        # in-memory registry (handlers_handler from with_handlers_handler).
        registered = peer._resolve_handler("system/handler")
        assert registered.pattern == "system/handler"
        # Compiled binding: name should NOT be the synthetic tree-walked: prefix.
        assert not registered.name.startswith("tree-walked:")
        assert registered.name == "handlers"

    def test_tree_walked_with_expression_path_synthesizes_wrapper(self, peer):
        """Tree entity with expression_path but no compiled binding →
        ComputeExtension synthesizes an entity-native wrapper."""
        _write_handler_entity(peer, "app/native", expression_path="app/native/expr")

        registered = peer._resolve_handler("app/native")
        assert registered is not None
        assert registered.pattern == "app/native"
        # Synthesized handler — name carries tree-walked: prefix.
        assert registered.name.startswith("tree-walked:")

    def test_tree_walked_without_binding_or_expression_falls_through(self, peer):
        """Tree has manifest but no expression_path and no compiled binding.
        Fall-through to in-memory wildcard fallback."""
        # Write a system/handler entity with NO expression_path at app/orphan.
        _write_handler_entity(peer, "app/orphan")

        registered = peer._resolve_handler("app/orphan")
        # Falls through to the storage wildcard catchall.
        assert registered is not None
        assert registered.pattern == "*"


# ============================================================================
# End-to-end: register -> dispatch -> unregister -> dispatch
# ============================================================================

class TestRegisterDispatchUnregister:
    """Sanity-check the full lifecycle through the handlers handler."""

    @pytest.mark.asyncio
    async def test_register_then_resolve(self, peer):
        from entity_handlers.handlers import handlers_handler
        from unittest.mock import MagicMock

        ctx = MagicMock()
        ctx.emit_pathway = peer.emit_pathway
        ctx.local_peer_id = peer.peer_id
        ctx.handler_pattern = HANDLERS_HANDLER_PATTERN
        ctx.bounds = None
        ctx.keypair = peer.keypair
        ctx.resource_targets = ["system/handler/app/native"]

        # Pre-write the expression so the entity-native wrapper has
        # something to evaluate (not strictly needed for resolve).
        manifest = {"type": "system/handler/manifest", "data": {
            "pattern": "app/native",
            "name": "native",
            "operations": {"compute": {"output_type": "primitive/any"}},
            "expression_path": "app/native/expr",
        }}
        await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register",
            {"data": {"manifest": manifest}}, ctx,
        )

        registered = peer._resolve_handler("app/native")
        assert registered is not None
        assert registered.pattern == "app/native"
        assert registered.name.startswith("tree-walked:")

    @pytest.mark.asyncio
    async def test_unregister_then_resolve_falls_through(self, peer):
        from entity_handlers.handlers import handlers_handler
        from unittest.mock import MagicMock

        ctx = MagicMock()
        ctx.emit_pathway = peer.emit_pathway
        ctx.local_peer_id = peer.peer_id
        ctx.handler_pattern = HANDLERS_HANDLER_PATTERN
        ctx.bounds = None
        ctx.keypair = peer.keypair
        ctx.resource_targets = ["system/handler/app/native"]

        manifest = {"type": "system/handler/manifest", "data": {
            "pattern": "app/native",
            "name": "native",
            "operations": {"compute": {}},
            "expression_path": "app/native/expr",
        }}
        await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register",
            {"data": {"manifest": manifest}}, ctx,
        )
        # Sanity check
        assert peer._resolve_handler("app/native").pattern == "app/native"

        await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "unregister",
            {"data": {}}, ctx,
        )

        # After unregister, tree walk finds nothing → falls back to wildcard.
        registered = peer._resolve_handler("app/native")
        assert registered is not None
        assert registered.pattern == "*"
