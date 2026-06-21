"""Shared runtime helpers for the standard handlers.

These were previously duplicated verbatim across several handler modules
(attestation, role, identity, quorum, query, ...). They live here now so there
is a single implementation. Handlers import them under their existing private
names, e.g.::

    from entity_handlers._common import ok_response as _ok

so call sites are unchanged.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from entity_core.handlers.context import HandlerContext


def error_response(
    status: int, code: str, message: str, **extra: Any
) -> dict[str, Any]:
    """Build a ``system/protocol/error`` response.

    Args:
        status: HTTP-style status code.
        code: Error code string.
        message: Human-readable error message.
        **extra: Additional keys merged into the error data payload.

    Returns:
        Response dict wrapping an error entity.
    """
    data: dict[str, Any] = {"code": code, "message": message}
    data.update(extra)
    return {
        "status": status,
        "result": {"type": "system/protocol/error", "data": data},
    }


def ok_response(result_type: str, data: dict[str, Any]) -> dict[str, Any]:
    """Build a 200 response wrapping ``data`` as ``result_type``."""
    return {"status": 200, "result": {"type": result_type, "data": data}}


def params_data(params: Any) -> dict[str, Any]:
    """Extract the operation's data dict from EXECUTE params.

    Accepts either a bare data dict or a ``{"data": {...}}`` envelope.
    """
    if isinstance(params, dict):
        if "data" in params and isinstance(params["data"], dict):
            return params["data"]
        return params
    return {}


def resource_target(ctx: HandlerContext) -> str | None:
    """First resource-target path from the dispatch context, if any."""
    targets = getattr(ctx, "resource_targets", None) or []
    if targets and isinstance(targets[0], str):
        return targets[0]
    return None


def now_ms() -> int:
    """Current wall-clock time in milliseconds since the epoch."""
    return int(time.time() * 1000)


def normalize_hash(value: Any) -> bytes | None:
    """Coerce a hash-shaped value to its canonical byte form.

    Accepts raw bytes, an ``{algorithm, digest}`` dict, or a hex string.
    Returns None when the value is not a valid hash.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, dict):
        algorithm = value.get("algorithm")
        digest = value.get("digest")
        if isinstance(algorithm, int) and isinstance(digest, bytes):
            return bytes([algorithm]) + digest
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return None
    return None
