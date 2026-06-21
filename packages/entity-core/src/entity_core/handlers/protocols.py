"""Handler protocols for type/manifest discovery.

These protocols allow handlers to be self-describing. Handlers that
implement these protocols can:
- TypeProvider: Register custom types with the type registry
- ManifestProvider: Provide a manifest entity for discovery
- NamedHandler: Have an explicit name (used in builder auto-detection)

Usage:
    class MyHandler:
        @property
        def name(self) -> str:
            return "my-handler"

        def manifest(self) -> Entity:
            return Entity(type="system/handler/manifest", data={...})

        def register_types(self, registry: TypeRegistry) -> None:
            registry.register(my_type)

    # PeerBuilder auto-detects protocols
    builder.with_handler("myapp/*", MyHandler())
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from entity_core.protocol.entity import Entity
    from entity_core.types.registry import TypeRegistry


@runtime_checkable
class NamedHandler(Protocol):
    """Handler with an explicit name.

    Handlers implementing this protocol have their name auto-detected
    by PeerBuilder.with_handler() when no name is provided.

    Example:
        class MyHandler:
            @property
            def name(self) -> str:
                return "my-handler"
    """

    @property
    def name(self) -> str:
        """The handler's name."""
        ...


@runtime_checkable
class TypeProvider(Protocol):
    """Handler that registers custom types.

    Handlers implementing this protocol are called during peer
    initialization to register their types with the type registry.

    Example:
        class MyHandler:
            def register_types(self, registry: TypeRegistry) -> None:
                registry.register(my_custom_type)
    """

    def register_types(self, registry: TypeRegistry) -> None:
        """Register custom types with the type registry.

        Args:
            registry: The type registry to register types with.
        """
        ...


@runtime_checkable
class ManifestProvider(Protocol):
    """Handler that provides a manifest for registration.

    Handlers implementing this protocol provide a manifest entity
    that is decomposed into interface + handler entities during
    peer initialization.

    Example:
        class MyHandler:
            def manifest(self) -> Entity:
                return Entity(
                    type="system/handler/manifest",
                    data={
                        "pattern": "myapp/*",
                        "name": "myapp",
                        "operations": {
                            "do-thing": {"description": "Does a thing"},
                        },
                    },
                )
    """

    def manifest(self) -> Entity:
        """Return the handler's manifest entity.

        Returns:
            Entity of type "system/handler/manifest" describing this handler.
        """
        ...
