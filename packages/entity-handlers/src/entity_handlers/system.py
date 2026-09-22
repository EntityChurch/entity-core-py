"""System introspection handler at system/*.

The system handler provides peer introspection:
- system/status: Peer status
- system/peer/info: Peer information
- system/handlers: List of registered handlers
"""

from __future__ import annotations

from typing import Any

from entity_core.handlers.connect import ADVERTISED_PROTOCOLS
from entity_core.handlers.context import HandlerContext
from entity_core.types.registry import list_handler_names, get_handler_manifest
from entity_handlers._common import error_response
from entity_handlers.tree import caller_can_read


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
                    # The same string the hello negotiates (V7 §8.4). This was
                    # a fourth independent literal of it, which is how a peer
                    # ends up advertising one version here and negotiating
                    # another at §4.5 — the two are read by different parties
                    # and never compared.
                    "protocols": ADVERTISED_PROTOCOLS,
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
            # §6.3's listing filter, widened by 0.8.2.22 (J5) from *"when the
            # tree handler returns a listing"* to **any handler returning a
            # multi-entry result whose entries are tree paths**. This branch is
            # a domain listing over the same `EntityTree` the tree handler
            # serves, so an unfiltered entry here is the H1 bulk-read
            # disclosure reached through a second handler pattern: the caller
            # asks `system/*` for `data/` instead of `system/tree`, and the
            # exclude that `caller_can_read` enforces there carves out nothing
            # here. The entry also carries the child's content hash, so it is
            # the entity's address and not merely its name.
            #
            # ONE derivation, not two agreeing ones (F68) — this is the same
            # `caller_can_read` the tree handler's three bulk reads call, and
            # it frames on `system/tree` because the access being authorized is
            # a tree read whichever handler enumerates it (§6.3, 0.8.2.23).
            if not caller_can_read(ctx, path, child_name):
                continue
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

    # Two different failures were collapsed into this one 404 until 0.8.2.7,
    # and the collapse is §3.3's 404/501 boundary drawn in the wrong place.
    #
    # `SYSTEM_HANDLER_MANIFEST` declares exactly ONE operation: `get`. So an
    # operation that is not `get` is *"an operation absent from a registered
    # handler's manifest"* — §3.3's **501** row, verbatim — and answering 404
    # for it asserts that no handler is registered at the path, which is false
    # of a path this handler was dispatched to.
    #
    # Found by `entity-core-go`'s `handler_not_found_on_unregistered_path`,
    # which dispatches a bogus operation at `system/no-such-handler-…`. It
    # reports us FAIL either way — see SA-PY-36 — but the 501 is the answer
    # §3.3 actually names for that input, and the previous 404 was wrong on
    # both halves of the pair rather than on one.
    if operation != "get":
        return error_response(
            501,
            "unsupported_operation",
            f"system handler does not support operation: {operation}",
        )

    # `get` IS implemented and the path carries no entity: an entity-absent
    # 404 raised inside a registered handler, which §3.3's 404 row (0.8.2.7)
    # explicitly excludes from the `handler_not_found` row — *"a domain outcome
    # carrying the domain's own code"*. Stays `not_found`.
    return error_response(404, "not_found", f"Unknown system path: {path}")
