"""System introspection handler at system/*.

The system handler provides peer introspection:
- system/status: Peer status
- system/peer/info: Peer information
- system/handlers: List of registered handlers
"""

from __future__ import annotations

from typing import Any

from entity_core.handlers.context import HandlerContext
from entity_core.types.registry import list_handler_names, get_handler_manifest


async def system_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle system/* requests.

    Args:
        path: The request path (e.g., "system/status").
        operation: The operation (get).
        params: Operation parameters.
        ctx: Handler context.

    Returns:
        Response dictionary with status and result.
    """
    if path == "system/status" and operation == "get":
        return {
            "status": 200,
            "result": {
                "type": "status",
                "data": {
                    "peer_id": ctx.local_peer_id,
                    "status": "ok",
                },
            },
        }

    if path == "system/peer/info" and operation == "get":
        return {
            "status": 200,
            "result": {
                "type": "peer-info",
                "data": {
                    "peer_id": ctx.local_peer_id,
                    "protocols": ["entity-core/7.0"],
                },
            },
        }

    # Handler listing - queries entity tree
    if path == "system/handlers" and operation == "get":
        entity_tree = ctx.emit_pathway.entity_tree
        content_store = ctx.emit_pathway.content_store
        handler_names = list_handler_names(entity_tree)
        # Filter out grant paths
        handler_names = [n for n in handler_names if "/grant" not in n]
        handlers = []
        for name in handler_names:
            manifest = get_handler_manifest(name, content_store, entity_tree)
            if manifest:
                handlers.append({
                    "pattern": manifest.data.get("pattern"),
                    "name": manifest.data.get("name"),
                    "operations": manifest.data.get("operations", {}),
                })
        return {
            "status": 200,
            "result": {
                "type": "handler-listing",
                "data": {
                    "handlers": handlers,
                },
            },
        }

    # Handle listing requests (paths ending with /)
    if operation == "get" and path.endswith("/"):
        entity_tree = ctx.emit_pathway.entity_tree
        prefix = entity_tree.normalize_uri(path)
        uris = entity_tree.list_prefix(prefix)

        entries: dict[str, dict[str, Any]] = {}
        seen: set[str] = set()
        for uri in uris:
            suffix = uri[len(prefix):]
            if not suffix:
                continue
            parts = suffix.split("/")
            child_name = parts[0]
            if child_name in seen:
                continue
            seen.add(child_name)
            child_uri = prefix + child_name
            content_hash = entity_tree.get(child_uri)
            has_children = len(parts) > 1 or any(u.startswith(child_uri + "/") for u in uris)
            entries[child_name] = {"hash": content_hash, "has_children": has_children}

        return {
            "status": 200,
            "result": {
                "type": "tree/listing",
                "data": {"path": path, "entries": entries, "count": len(entries)},
            },
        }

    # Handle entity read (get without trailing slash)
    if operation == "get":
        entity_tree = ctx.emit_pathway.entity_tree
        content_store = ctx.emit_pathway.content_store
        uri = entity_tree.normalize_uri(path)
        content_hash = entity_tree.get(uri)
        if content_hash:
            entity = content_store.get(content_hash)
            if entity is not None:
                return {"status": 200, "result": entity.to_dict()}

    return {
        "status": 404,
        "result": {
            "type": "system/protocol/error",
            "data": {"code": "not_found", "message": f"Unknown system path: {path}"},
        },
    }
