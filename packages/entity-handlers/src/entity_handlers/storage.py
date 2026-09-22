"""Generic storage handler (fallback).

The storage handler provides basic CRUD operations for entities.
It's typically registered at "*" as a fallback handler.

This handler delegates to the tree handler via ctx.execute() for all
storage operations, providing a simpler interface for common CRUD patterns.

Operations:
- read/get: Get entity at path (delegates to system/tree get)
- write/put: Store entity at path (delegates to system/tree put)
- list: List entities under prefix (delegates to system/tree get with /)
- delete: Remove entity at path (delegates to system/tree put with null)
"""

from __future__ import annotations

from typing import Any

from entity_core.handlers.context import HandlerContext
from entity_handlers._common import error_response


async def storage_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Generic storage handler for read/write/list/delete.

    Delegates to system/tree handler via ctx.execute() for capability-gated
    access to the entity tree.

    Args:
        path: The request path.
        operation: The operation (read, write, list, delete).
        params: Operation parameters.
        ctx: Handler context.

    Returns:
        Response dictionary with status and result.

    .. note:: The three ``if not result.ok`` arms below forward an upstream
       status with a bare ``{"error": message}`` body and **no** ``code``.
       They are left as-is deliberately: ``ExecuteResult`` (``handlers/
       context.py``) carries ``status``, ``result`` and ``error`` and **drops
       ``result.data.code``**, so an in-process sub-dispatch cannot forward the
       code the sub-handler emitted. Minting one here would fabricate a claim
       about a refusal this handler did not make — the ``connect_refusal``
       lesson (*a default is a decision; the correct decision is not always the
       correct value*). Filed as SA-PY-34; the fix is to plumb ``code`` through
       ``ExecuteResult``, which is 13 construction sites and a separate change.
    """
    # Per §3.4, params arrives as an entity envelope on the wire. Extract
    # the payload (same shim all handlers use).
    params = params.get("data", params) if isinstance(params, dict) else {}

    if operation == "read" or operation == "get":
        # Delegate to tree handler
        result = await ctx.execute("system/tree", "get", {"path": path})
        if not result.ok:
            return {"status": result.status, "result": {"error": result.error}}
        return {"status": result.status, "result": result.result}

    if operation == "write" or operation == "put":
        entity_data = params.get("entity")
        if not entity_data:
            return error_response(
                400, "invalid_params", "Missing entity in params",
            )

        # Delegate to tree handler
        result = await ctx.execute("system/tree", "put", {"path": path, "entity": entity_data})
        if not result.ok:
            return {"status": result.status, "result": {"error": result.error}}

        # Extract hash and uri from tree handler response
        put_result = result.result or {}
        put_data = put_result.get("data", put_result)
        return {
            "status": 200,
            "result": {
                "hash": put_data.get("hash"),
                "uri": put_data.get("uri"),
            },
        }

    if operation == "list":
        # Ensure trailing slash for listing
        list_path = path if path.endswith("/") else path + "/"
        result = await ctx.execute("system/tree", "get", {"path": list_path})
        if not result.ok:
            return {"status": result.status, "result": {"error": result.error}}

        # Extract URIs from listing entries
        listing = result.result or {}
        listing_data = listing.get("data", listing)
        entries = listing_data.get("entries", {})
        # Reconstruct full URIs from listing
        base_path = listing_data.get("path", list_path)
        uris = [base_path + name for name in entries.keys()]
        return {"status": 200, "result": {"uris": uris}}

    if operation == "delete":
        # First get the entity to return it
        get_result = await ctx.execute("system/tree", "get", {"path": path})
        if not get_result.ok:
            # An entity-absent 404 raised *inside* a registered handler. Per
            # §3.3's 404 row (0.8.2.7) that is a domain outcome and explicitly
            # NOT the `handler_not_found` row, so it keeps this tier's
            # `not_found` spelling rather than taking the row's default.
            return error_response(404, "not_found", f"Not found: {path}")

        removed_entity = get_result.result

        # Delete by putting null
        result = await ctx.execute("system/tree", "put", {"path": path, "entity": None})
        if not result.ok:
            return {"status": result.status, "result": {"error": result.error}}

        return {"status": 200, "result": {"removed": removed_entity}}

    # §3.3's 501 row, §6.2: a handler IS registered at this path — this one,
    # the `*` catch-all — and does not implement the named operation. That is
    # the row's input, so it is `501 unsupported_operation` regardless of how
    # the site is spelled. It read `400` with **no `code` at all** and a
    # `{"error": str}` body that is not a `system/protocol/error`, which is why
    # no census of the 501 slot could see it: a slot is keyed by status, and
    # this site had the status wrong.
    return error_response(
        501,
        "unsupported_operation",
        f"storage handler does not support operation: {operation}",
    )
