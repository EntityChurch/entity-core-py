"""Type and handler registration at peer startup.

Registers all built-in type entities and handler manifests in the content
store and entity tree.

Types are stored at paths like: system/type/system/protocol/hello
Handlers are stored at paths like: system/handler/system/tree

This enables introspection - clients can fetch type schemas and handler
manifests to understand entity structures and available operations.

V7.7: Uses singular namespace paths (system/type/* not system/types/*).
"""

from __future__ import annotations

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.types.definitions import get_all_type_entities


class TypeRegistry:
    """Registry for type entities.

    Provides a simple interface for handlers to register custom types
    via the TypeProvider protocol.

    Example:
        registry = TypeRegistry(emit_pathway)
        registry.register(my_type_entity)
    """

    def __init__(self, emit_pathway: EmitPathway) -> None:
        """Initialize the registry with an emit pathway.

        Args:
            emit_pathway: The emit pathway for storing type entities.
        """
        self._emit_pathway = emit_pathway
        self._ctx = EmitContext.bootstrap()

    def register(self, type_entity: Entity) -> str:
        """Register a type entity.

        Args:
            type_entity: The type entity to register. Must have a 'name'
                field in its data.

        Returns:
            The hash of the registered type entity.
        """
        type_name = type_entity.data["name"]
        path = f"system/type/{type_name}"
        return self._emit_pathway.emit(path, type_entity, self._ctx)

    def register_all(self, type_entities: list[Entity]) -> list[str]:
        """Register multiple type entities.

        Args:
            type_entities: List of type entities to register.

        Returns:
            List of hashes for the registered type entities.
        """
        return [self.register(entity) for entity in type_entities]


def register_types(emit_pathway: EmitPathway) -> None:
    """Register all built-in type entities at startup.

    Stores each type entity via EmitPathway at system/type/<type_name>.
    Uses bootstrap context to mark these as startup writes.

    Args:
        emit_pathway: EmitPathway for writing entities.
    """
    ctx = EmitContext.bootstrap()
    for type_entity in get_all_type_entities():
        # Map in entity tree at system/type/<type_name>
        type_name = type_entity.data["name"]
        path = f"system/type/{type_name}"
        emit_pathway.emit(path, type_entity, ctx)


def get_type_entity(
    type_name: str,
    content_store: ContentStore,
    entity_tree: EntityTree,
) -> Entity | None:
    """Get a type entity by name.

    Args:
        type_name: The type name (e.g., "system/protocol/hello").
        content_store: Content store to look up the entity.
        entity_tree: Entity tree to look up the URI.

    Returns:
        The type Entity if found, None otherwise.
    """
    path = f"system/type/{type_name}"
    uri = entity_tree.normalize_uri(path)
    hash_str = entity_tree.get(uri)

    if hash_str is None:
        return None

    return content_store.get(hash_str)


def list_type_names(entity_tree: EntityTree) -> list[str]:
    """List all registered type names.

    Args:
        entity_tree: Entity tree to query.

    Returns:
        List of type names (e.g., ["system/protocol/hello", ...]).
    """
    prefix = entity_tree.normalize_uri("system/type/")
    uris = entity_tree.list_prefix(prefix)

    # Extract type name from path: /{peer_id}/system/type/<type_name>
    names = []
    for uri in uris:
        # Path format: /{peer_id}/system/type/<type_name>
        parts = uri.split("/system/type/", 1)
        if len(parts) == 2:
            names.append(parts[1])
    return names


def _normalize_pattern(pattern: str) -> str:
    """Strip trailing /* from a handler pattern for storage paths."""
    return pattern.rstrip("/*") if pattern.endswith("/*") else pattern


def register_handlers(
    emit_pathway: EmitPathway,
    manifests: list[Entity],
) -> None:
    """Register handler manifests by decomposing into interface + handler entities.

    Per PROPOSAL-HANDLER-NORMALIZATION N5, each manifest is decomposed into:
    1. system/handler/interface at system/handler/{pattern} (public contract)
    2. system/handler at {pattern} (dispatch target, references interface)

    Args:
        emit_pathway: EmitPathway for writing entities.
        manifests: List of system/handler/manifest entities.
    """
    ctx = EmitContext.bootstrap()
    for manifest in manifests:
        pattern = manifest.data["pattern"]
        storage_pattern = _normalize_pattern(pattern)
        interface_path = f"system/handler/{storage_pattern}"

        interface_entity = Entity(
            type="system/handler/interface",
            data={
                "pattern": manifest.data["pattern"],
                "name": manifest.data["name"],
                "operations": manifest.data["operations"],
            },
        )

        handler_data: dict = {"interface": interface_path}
        if manifest.data.get("max_scope") is not None:
            handler_data["max_scope"] = manifest.data["max_scope"]
        if manifest.data.get("internal_scope") is not None:
            handler_data["internal_scope"] = manifest.data["internal_scope"]
        if manifest.data.get("expression_path") is not None:
            handler_data["expression_path"] = manifest.data["expression_path"]

        handler_entity = Entity(
            type="system/handler",
            data=handler_data,
        )

        emit_pathway.emit(interface_path, interface_entity, ctx)
        emit_pathway.emit(storage_pattern, handler_entity, ctx)


def get_handler_interface(
    pattern: str,
    content_store: ContentStore,
    entity_tree: EntityTree,
) -> Entity | None:
    """Get a handler interface entity by pattern.

    Args:
        pattern: The handler pattern (e.g., "system/tree", "system").
        content_store: Content store to look up the entity.
        entity_tree: Entity tree to look up the URI.

    Returns:
        The system/handler/interface Entity if found, None otherwise.
    """
    path = f"system/handler/{pattern}"
    uri = entity_tree.normalize_uri(path)
    hash_str = entity_tree.get(uri)

    if hash_str is None:
        return None

    return content_store.get(hash_str)


# Backward compatibility alias
get_handler_manifest = get_handler_interface


def list_handler_patterns(entity_tree: EntityTree) -> list[str]:
    """List all registered handler patterns.

    Args:
        entity_tree: Entity tree to query.

    Returns:
        List of handler patterns (e.g., ["system/tree", "system/capability", ...]).
    """
    prefix = entity_tree.normalize_uri("system/handler/")
    uris = entity_tree.list_prefix(prefix)

    # Extract handler pattern from path: /{peer_id}/system/handler/<pattern>
    patterns = []
    for uri in uris:
        # Path format: /{peer_id}/system/handler/<pattern>
        parts = uri.split("/system/handler/", 1)
        if len(parts) == 2:
            patterns.append(parts[1])
    return patterns


# Backward compatibility alias
list_handler_names = list_handler_patterns
