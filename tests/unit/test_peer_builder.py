"""Tests for PeerBuilder pattern and extension system."""

import warnings
from typing import Any

import pytest

from entity_core.capability.grant import Grant, create_full_access_grant
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.handlers.protocols import ManifestProvider, NamedHandler, TypeProvider
from entity_core.peer import Extension, ExtensionContext, Peer, PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.types.registry import TypeRegistry


@pytest.fixture
def keypair():
    """Generate a test keypair."""
    return Keypair.generate()


class TestPeerBuilder:
    """Tests for PeerBuilder fluent API."""

    def test_build_requires_keypair(self):
        """Build fails without keypair."""
        with pytest.raises(ValueError, match="Keypair is required"):
            PeerBuilder().build()

    def test_minimal_peer_has_storage_but_no_handlers(self, keypair):
        """Minimal peer has storage layers but no handlers."""
        peer = PeerBuilder().with_keypair(keypair).build()

        # Has storage
        assert peer.content_store is not None
        assert peer.entity_tree is not None
        assert peer.emit_pathway is not None

        # No handlers registered
        assert peer.handlers.find_handler("anything") is None
        assert peer.handlers.find_handler("system/status") is None

    def test_with_default_handlers_registers_system_and_storage(self, keypair):
        """with_default_handlers() registers system and storage handlers."""
        peer = PeerBuilder().with_keypair(keypair).with_default_handlers().build()

        # System handler is registered
        system_handler = peer.handlers.find_handler_info("system/status")
        assert system_handler is not None
        assert system_handler.name == "system"
        assert system_handler.priority == 100

        # Storage fallback is registered
        storage_handler = peer.handlers.find_handler_info("anything/else")
        assert storage_handler is not None
        assert storage_handler.name == "storage"
        assert storage_handler.priority == 0

    def test_custom_handler_registration(self, keypair):
        """Custom handlers can be registered."""
        async def my_handler(
            path: str, operation: str, params: dict[str, Any], ctx: HandlerContext
        ) -> dict[str, Any]:
            return {"status": 200, "result": {"custom": True}}

        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_handler("myapp/*", my_handler, priority=50, name="myapp")
            .build()
        )

        handler_info = peer.handlers.find_handler_info("myapp/test")
        assert handler_info is not None
        assert handler_info.name == "myapp"
        assert handler_info.priority == 50

    def test_handler_priority_order(self, keypair):
        """Higher priority handlers are checked first."""
        async def handler1(path, op, params, ctx):
            return {"status": 200, "result": {"handler": 1}}

        async def handler2(path, op, params, ctx):
            return {"status": 200, "result": {"handler": 2}}

        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_handler("data/*", handler1, priority=10, name="low")
            .with_handler("data/*", handler2, priority=100, name="high")
            .build()
        )

        # Higher priority handler should match first
        handler_info = peer.handlers.find_handler_info("data/test")
        assert handler_info is not None
        assert handler_info.name == "high"

    def test_generic_storage_pattern(self, keypair):
        """with_generic_storage registers storage at specific pattern."""
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_generic_storage("data/files/*")
            .build()
        )

        handler_info = peer.handlers.find_handler_info("data/files/test.txt")
        assert handler_info is not None
        assert "storage" in handler_info.name

        # No fallback handler for other paths
        assert peer.handlers.find_handler("other/path") is None

    def test_without_type_registration(self, keypair):
        """without_type_registration skips type registration."""
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .without_type_registration()
            .build()
        )

        # Types are not registered
        type_hash = peer.entity_tree.get(
            f"entity://{peer.peer_id}/system/types/system/protocol/execute"
        )
        assert type_hash is None

    def test_with_type_registration_default(self, keypair):
        """Types are registered by default."""
        peer = PeerBuilder().with_keypair(keypair).build()

        # Types are registered (V7.7 singular namespace)
        type_hash = peer.entity_tree.get(
            f"entity://{peer.peer_id}/system/type/system/protocol/execute"
        )
        assert type_hash is not None

    def test_fluent_api_chaining(self, keypair):
        """All builder methods return self for chaining."""
        admin_ids = {"peer123"}
        grants = [Grant.create(handlers=["*"], resources=["data/*"], operations=["read"])]

        # All methods should chain
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_default_grants(grants)
            .with_admin_peer_ids(admin_ids)
            .debug_mode(True)
            .with_default_handlers()
            .build()
        )

        assert peer.keypair == keypair
        assert peer.admin_peer_ids == admin_ids
        assert peer.debug_mode is True
        assert peer.default_grants == grants

    def test_debug_mode_default_false(self, keypair):
        """debug_mode defaults to False."""
        peer = PeerBuilder().with_keypair(keypair).build()
        assert peer.debug_mode is False

    def test_admin_peer_ids_default_empty(self, keypair):
        """admin_peer_ids defaults to empty set."""
        peer = PeerBuilder().with_keypair(keypair).build()
        assert peer.admin_peer_ids == set()

    def test_default_grants_full_access(self, keypair):
        """default_grants defaults to full access."""
        peer = PeerBuilder().with_keypair(keypair).build()
        full_access = create_full_access_grant()

        # Compare grant contents
        assert len(peer.default_grants) == len(full_access)
        assert peer.default_grants[0].resources == full_access[0].resources

    def test_with_attestation_handler_registers_handler(self, keypair):
        """with_attestation_handler installs the substrate handler."""
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_attestation_handler()
            .build()
        )
        # Handler registry contains system/attestation.
        registered = [h.pattern for h in peer.handlers._handlers]
        assert "system/attestation" in registered

    def test_with_quorum_handler_registers_extension(self, keypair):
        """with_quorum_handler installs handler AND QuorumExtension."""
        from entity_handlers import QuorumExtension

        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_quorum_handler()
            .build()
        )
        registered = [h.pattern for h in peer.handlers._handlers]
        assert "system/quorum" in registered
        # QuorumExtension is initialized; its concrete resolver is registered.
        ext = peer.emit_pathway._quorum_extension  # type: ignore[attr-defined]
        assert isinstance(ext, QuorumExtension)
        assert ext.lookup_resolver("concrete") is not None

    def test_with_identity_handler_pulls_in_substrates(self, keypair):
        """v3.2 identity depends on attestation + quorum substrates;
        with_identity_handler() must auto-install both."""
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_identity_handler()
            .build()
        )
        registered = [h.pattern for h in peer.handlers._handlers]
        assert "system/attestation" in registered
        assert "system/quorum" in registered
        assert "system/identity" in registered


class TestDirectConstruction:
    """Tests that direct Peer() construction is not allowed."""

    def test_direct_peer_raises_type_error(self):
        """Direct Peer() constructor raises TypeError."""
        with pytest.raises(TypeError, match="PeerBuilder"):
            Peer()


class TestExtensions:
    """Tests for extension system."""

    def test_extension_initialize_called(self, keypair):
        """Extension.initialize() is called during build."""
        initialized = []

        class TestExtension(Extension):
            def initialize(self, ctx: ExtensionContext) -> None:
                initialized.append(ctx.peer_id)

        ext = TestExtension()
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_extension(ext)
            .build()
        )

        assert len(initialized) == 1
        assert initialized[0] == peer.peer_id

    def test_extension_shutdown_called(self, keypair):
        """Extension.shutdown() is called during peer.stop()."""
        shutdown_called = []

        class ShutdownExtension(Extension):
            def initialize(self, ctx: ExtensionContext) -> None:
                pass

            def shutdown(self) -> None:
                shutdown_called.append(True)

        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_extension(ShutdownExtension())
            .build()
        )

        import asyncio

        asyncio.run(peer.stop())

        assert len(shutdown_called) == 1

    def test_extension_context_has_keypair(self, keypair):
        """ExtensionContext provides keypair and peer_id."""
        context_info = {}

        class InspectorExtension(Extension):
            def initialize(self, ctx: ExtensionContext) -> None:
                context_info["peer_id"] = ctx.peer_id
                context_info["keypair"] = ctx.keypair

        PeerBuilder().with_keypair(keypair).with_extension(InspectorExtension()).build()

        assert context_info["peer_id"] == keypair.peer_id
        assert context_info["keypair"] is keypair

    def test_multiple_extensions_initialized_in_order(self, keypair):
        """Multiple extensions are initialized in registration order."""
        init_order = []

        class FirstExtension(Extension):
            def initialize(self, ctx: ExtensionContext) -> None:
                init_order.append("first")

        class SecondExtension(Extension):
            def initialize(self, ctx: ExtensionContext) -> None:
                init_order.append("second")

        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_extension(FirstExtension())
            .with_extension(SecondExtension())
            .build()
        )

        assert init_order == ["first", "second"]

    def test_extensions_shutdown_in_reverse_order(self, keypair):
        """Extensions are shut down in reverse registration order."""
        shutdown_order = []

        class FirstExtension(Extension):
            def initialize(self, ctx: ExtensionContext) -> None:
                pass

            def shutdown(self) -> None:
                shutdown_order.append("first")

        class SecondExtension(Extension):
            def initialize(self, ctx: ExtensionContext) -> None:
                pass

            def shutdown(self) -> None:
                shutdown_order.append("second")

        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_extension(FirstExtension())
            .with_extension(SecondExtension())
            .build()
        )

        import asyncio

        asyncio.run(peer.stop())

        assert shutdown_order == ["second", "first"]


class TestHandlerProtocols:
    """Tests for handler protocol detection."""

    def test_named_handler_auto_detected(self, keypair):
        """NamedHandler protocol auto-detects handler name."""

        class MyNamedHandler:
            @property
            def name(self) -> str:
                return "auto-named"

            async def __call__(self, path, op, params, ctx):
                return {"status": 200}

        handler = MyNamedHandler()
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_handler("myapp/*", handler, priority=50)
            .build()
        )

        handler_info = peer.handlers.find_handler_info("myapp/test")
        assert handler_info is not None
        assert handler_info.name == "auto-named"

    def test_explicit_name_overrides_protocol(self, keypair):
        """Explicit name parameter overrides NamedHandler protocol."""

        class MyNamedHandler:
            @property
            def name(self) -> str:
                return "protocol-name"

            async def __call__(self, path, op, params, ctx):
                return {"status": 200}

        handler = MyNamedHandler()
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_handler("myapp/*", handler, priority=50, name="explicit-name")
            .build()
        )

        handler_info = peer.handlers.find_handler_info("myapp/test")
        assert handler_info is not None
        assert handler_info.name == "explicit-name"

    def test_handler_max_scope(self, keypair):
        """Handler max_scope is stored in registered handler."""

        async def handler(path, op, params, ctx):
            return {"status": 200}

        restricted_grants = [
            Grant.create(handlers=["myapp/*"], resources=["data/*"], operations=["read"])
        ]
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_handler("myapp/*", handler, max_scope=restricted_grants)
            .build()
        )

        handler_info = peer.handlers.find_handler_info("myapp/test")
        assert handler_info is not None
        assert handler_info.max_scope == restricted_grants


class TestExecuteResult:
    """Tests for ExecuteResult dataclass."""

    def test_ok_for_success_status(self):
        """ok is True for 2xx status codes."""
        result = ExecuteResult(status=200, result={"data": "value"})
        assert result.ok is True

        result = ExecuteResult(status=201)
        assert result.ok is True

    def test_ok_false_for_error_status(self):
        """ok is False for non-2xx status codes."""
        result = ExecuteResult(status=404, error="Not found")
        assert result.ok is False

        result = ExecuteResult(status=500, error="Server error")
        assert result.ok is False

    def test_raise_for_status_on_error(self):
        """raise_for_status raises on error status."""
        result = ExecuteResult(status=404, error="Not found")
        with pytest.raises(RuntimeError, match="Not found"):
            result.raise_for_status()

    def test_raise_for_status_silent_on_success(self):
        """raise_for_status does nothing on success."""
        result = ExecuteResult(status=200, result={"ok": True})
        result.raise_for_status()  # Should not raise
