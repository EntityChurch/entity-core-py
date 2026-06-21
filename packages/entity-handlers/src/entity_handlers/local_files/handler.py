"""Operation dispatcher for the ``local/files`` handler.

The handler binds at the literal prefix ``local/files`` per the §3.1
manifest spec; the manifest's ``pattern`` field is identical
advertisement. Operations are domain names (``read`` / ``write`` /
``list`` / ``delete`` / ``watch``) — not entity system names — because
the handler translates between filesystem and entity-tree worlds and
its operations belong to the filesystem domain.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from entity_core.handlers.context import HandlerContext

from entity_handlers._common import error_response
from entity_handlers.local_files.operations import (
    handle_delete,
    handle_list,
    handle_read,
    handle_write,
)

if TYPE_CHECKING:
    from entity_handlers.local_files.extension import LocalFilesExtension

logger = logging.getLogger(__name__)


LOCAL_FILES_HANDLER_PATTERN: str = "local/files"
"""Per §4.9 (GUIDE-EXTENSION-DEVELOPMENT) registration discipline: the
handler binds at the literal prefix; the manifest's ``pattern`` field
advertises the spec glob (here identical: ``local/files``). The
dispatcher walks back from the request path to find this prefix.
"""


HandlerFn = Callable[
    [str, str, dict[str, Any], HandlerContext], Awaitable[dict[str, Any]]
]


def build_handler(extension: "LocalFilesExtension") -> HandlerFn:
    """Bind an :class:`LocalFilesExtension` into a dispatch function.

    Returns a coroutine that the peer's handler registry calls per
    EXECUTE. The closure captures ``extension`` so the operations can
    read root mappings and the recent-write tracker without threading
    them through the call signature.
    """

    async def local_files_handler(
        path: str,
        operation: str,
        params: dict[str, Any],
        ctx: HandlerContext,
    ) -> dict[str, Any]:
        params_data: dict[str, Any] = {}
        if isinstance(params, dict):
            inner = params.get("data")
            params_data = inner if isinstance(inner, dict) else params

        if operation == "read":
            return await handle_read(extension, ctx)
        if operation == "write":
            return await handle_write(extension, params_data, ctx)
        if operation == "list":
            return await handle_list(extension, ctx)
        if operation == "delete":
            return await handle_delete(extension, ctx)
        # `watch` is intentionally omitted per v1.3 §10.1 L2: a
        # config-only handler that returns success without monitoring
        # the filesystem is non-conformant. Once the platform-native
        # watcher lands (inotify on Linux, FSEvents on macOS,
        # ReadDirectoryChangesW on Windows) re-route `watch` here.

        return error_response(
            501,
            "unknown_operation",
            f"local/files handler does not support operation: {operation}",
        )

    return local_files_handler


# Convenience: a bare dispatcher with no extension binding. Useful for
# tests that mount the handler manually; the closure builder above is
# what production wiring uses.
async def local_files_handler(  # type: ignore[misc]
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Stub dispatcher used only for module-level imports.

    Production wiring uses :func:`build_handler` to bind an extension;
    this stub returns a 501 if called without the extension, surfacing
    the misconfiguration loudly instead of silently 404-ing.
    """
    return error_response(
        501,
        "extension_not_bound",
        "local/files handler invoked without a LocalFilesExtension; "
        "use LocalFilesExtension.handler() to build a bound dispatcher",
    )


__all__ = [
    "LOCAL_FILES_HANDLER_PATTERN",
    "build_handler",
    "local_files_handler",
]
