"""Handler infrastructure for Entity Core Protocol.

This module provides handler registration and execution infrastructure:
- HandlerRegistry: Path-based handler dispatch
- HandlerContext: Context provided to handlers
- ExecuteResult: Result from ctx.execute() calls
- Handler: Type alias for async handler functions
- connect: Connect protocol handler (MUST per spec)

Handler Protocols:
- NamedHandler: Protocol for handlers with explicit names
- TypeProvider: Protocol for handlers that register custom types
- ManifestProvider: Protocol for handlers with discovery manifests

For standard handlers (tree, system, storage), see the entity-handlers package.
"""

from entity_core.handlers.registry import Handler, HandlerRegistry, RegisteredHandler
from entity_core.handlers.context import (
    ExecuteResult,
    HandlerContext,
)
from entity_core.handlers.protocols import ManifestProvider, NamedHandler, TypeProvider

__all__ = [
    "ExecuteResult",
    "Handler",
    "HandlerRegistry",
    "ManifestProvider",
    "NamedHandler",
    "RegisteredHandler",
    "HandlerContext",
    "TypeProvider",
]
