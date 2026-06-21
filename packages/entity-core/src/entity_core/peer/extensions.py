"""Extension protocol for peer plugins.

Extensions provide a way to add functionality to peers without modifying
the core Peer class. Extensions are initialized when the peer is built.

Example:
    class MyExtension(Extension):
        def initialize(self, ctx: ExtensionContext) -> None:
            # Register handlers during initialization
            # Subscribe to tree changes via emit_pathway
            if ctx.emit_pathway:
                ctx.emit_pathway.subscribe("*", self)
            pass

        def shutdown(self) -> None:
            pass  # Cleanup if needed

    # Handlers should be registered via PeerBuilder
    peer = (PeerBuilder()
        .with_keypair(keypair)
        .with_handler("myapp/*", my_handler, name="myapp")
        .with_extension(MyExtension())
        .build())
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Awaitable, Callable

if TYPE_CHECKING:
    from entity_core.capability.grant import Grant
    from entity_core.crypto.identity import Keypair
    from entity_core.handlers.context import ExecuteResult
    from entity_core.storage.emit import EmitPathway


@dataclass
class ExtensionContext:
    """Context provided to extensions during initialization.

    Attributes:
        keypair: The peer's cryptographic identity.
        max_scope: Maximum capability scope for this extension.
        execute: Callback for capability-gated handler dispatch.
            Available after peer is fully built.
        emit_pathway: Storage access for subscribing to tree changes.
            Extensions can use this to register async listeners.
    """

    keypair: Keypair
    max_scope: list[Grant] | None = None
    execute: Callable[..., Awaitable[ExecuteResult]] | None = None
    emit_pathway: EmitPathway | None = None

    @property
    def peer_id(self) -> str:
        """The peer's ID."""
        return self.keypair.peer_id


class Extension(ABC):
    """Protocol for peer extensions.

    Extensions are initialized when the peer is built.

    Lifecycle:
    1. initialize() is called during PeerBuilder.build()
    2. Extension is active for peer lifetime
    3. shutdown() is called during Peer.stop()
    """

    @abstractmethod
    def initialize(self, ctx: ExtensionContext) -> None:
        """Initialize the extension with peer context.

        This is called during PeerBuilder.build() after the peer's core
        infrastructure is set up.

        Args:
            ctx: Context providing access to peer infrastructure.
        """
        ...

    def shutdown(self) -> None:
        """Clean up extension resources.

        Called during Peer.stop(). Override to clean up any resources.

        Default implementation does nothing.
        """
        pass
