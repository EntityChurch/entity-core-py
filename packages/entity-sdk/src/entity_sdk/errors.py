"""The SDK error model — `SDK-OPERATIONS` v0.8 §12.

Two normative constraints shape everything here:

* **§12.3 — the SDK MUST preserve status codes and MUST NOT collapse all errors
  into a single generic type.** So :attr:`EntityError.status` is always the
  response's own status, and the hierarchy branches by the three categories the
  spec asks for: *client* errors the caller can fix (400 / 404 / 409),
  *authorization* errors (403), and *system* errors (500 / 501).
* **§12.2 — `system/protocol/error` is `{code, message?}` and an SDK MUST NOT
  add `status` or `details` to it.** These exceptions *read* an error entity;
  they never construct one. :attr:`EntityError.status` comes from the EXECUTE
  response, one level up, which is where core puts it — the two fields are kept
  apart here for the same reason core keeps them apart on the wire: one fact,
  one source.

**Status 207 is not an error** (§12.4): the primary operation succeeded and an
emit consumer failed. :func:`raise_for_status` lets it through, and callers that
care read :attr:`Response.consumer_errors`. Treating 207 as a failure is called
out by the spec as a bug, so it is called out by a test here.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "EntityError",
    "ClientError",
    "BadRequest",
    "NotFound",
    "Conflict",
    "AuthorizationError",
    "RateLimited",
    "SystemFailure",
    "InternalError",
    "NotSupported",
    "HandlerUndeclared",
    "error_for_status",
    "raise_for_status",
]


class EntityError(Exception):
    """Base for every dispatched-operation failure.

    Never raised directly for a known status — :func:`error_for_status` picks
    the specific subclass. It stays instantiable so an unmapped future status
    surfaces as *something* typed rather than as a bare ``Exception``.
    """

    #: The EXECUTE response status. Per §12.2 this lives on the response, not
    #: on the error entity, and the SDK preserves it verbatim (§12.3).
    status: int
    #: `system/protocol/error.data.code` — the programmatic identifier.
    code: str | None
    #: `system/protocol/error.data.message` — optional human-readable detail.
    message: str | None

    def __init__(
        self,
        status: int,
        code: str | None = None,
        message: str | None = None,
        *,
        path: str | None = None,
        operation: str | None = None,
    ) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.path = path
        self.operation = operation
        where = ""
        if operation is not None or path is not None:
            where = f" ({operation or '?'} {path or '?'})"
        detail = f": {message}" if message else ""
        super().__init__(f"[{status}] {code or 'error'}{where}{detail}")


# --- §12.3 category 1: client errors — the caller can fix these -------------


class ClientError(EntityError):
    """400 / 404 / 409 — malformed or conflicting request."""


class BadRequest(ClientError):
    """400 — invalid params, path, type, or expression."""


class NotFound(ClientError):
    """404 — no binding at path, or no handler matched."""


class Conflict(ClientError):
    """409 — CAS failure or merge conflict."""


# --- §12.3 category 2: authorization ----------------------------------------


class AuthorizationError(EntityError):
    """403 — the capability grant does not authorize this operation.

    Deliberately *not* a :class:`ClientError`: the caller usually cannot fix a
    grant problem by editing the request, and §12.3 asks for the distinction.
    """


# --- §12.3 category 3: system -----------------------------------------------


class SystemFailure(EntityError):
    """500 / 501 — something broke, or the handler does not implement this.

    Named ``SystemFailure`` rather than ``SystemError`` because ``SystemError``
    is a Python builtin, and shadowing it in a package everything imports is
    how a confusing traceback gets made.
    """


class InternalError(SystemFailure):
    """500 — unrecoverable failure."""


class NotSupported(SystemFailure):
    """501 — handler does not implement the requested operation."""


# --- statuses that sit outside the three categories -------------------------


class RateLimited(EntityError):
    """429 — peer or handler capacity exceeded. Retryable as-is."""


class HandlerUndeclared(EntityError):
    """503 — handler in the dispatch index but not declared in the tree.

    Tree-gated dispatch, §11.6. A deployment/registration fault rather than a
    fault in this request, so it is neither a client nor a system error.
    """


_BY_STATUS: dict[int, type[EntityError]] = {
    400: BadRequest,
    403: AuthorizationError,
    404: NotFound,
    409: Conflict,
    429: RateLimited,
    500: InternalError,
    501: NotSupported,
    503: HandlerUndeclared,
}


def _unwrap_error_entity(result: Any) -> tuple[str | None, str | None]:
    """Pull ``(code, message)` out of a `system/protocol/error` result.

    Tolerant by design: a handler that returns a bare string, or a dict without
    the expected shape, still yields a usable message instead of masking the
    real failure behind a decoding error.
    """
    if isinstance(result, dict):
        data = result.get("data")
        if isinstance(data, dict):
            code = data.get("code")
            message = data.get("message")
            return (
                code if isinstance(code, str) else None,
                message if isinstance(message, str) else None,
            )
        # Some paths hand back the error payload unwrapped.
        code = result.get("code")
        message = result.get("message")
        return (
            code if isinstance(code, str) else None,
            message if isinstance(message, str) else None,
        )
    if isinstance(result, str):
        return None, result
    return None, None


def error_for_status(
    status: int,
    result: Any = None,
    *,
    path: str | None = None,
    operation: str | None = None,
) -> EntityError:
    """Build the typed exception for ``status`` without raising it."""
    code, message = _unwrap_error_entity(result)
    cls = _BY_STATUS.get(status, EntityError)
    return cls(status, code, message, path=path, operation=operation)


def raise_for_status(
    status: int,
    result: Any = None,
    *,
    path: str | None = None,
    operation: str | None = None,
) -> None:
    """Raise the typed exception for a non-success ``status``.

    Success is **2xx**, which deliberately includes:

    * **207** (§12.4) — partial success. The primary operation succeeded; an
      emit consumer failed. The spec says application code MUST NOT treat this
      as failure, so neither does the SDK.
    * **202** — accepted; the result arrives later via the inbox.

    3xx is *not* treated as success: a 303 subscription redirect is a control
    signal the caller must handle, and silently returning it as a value would
    hand back a redirect where an entity was expected.
    """
    if 200 <= status < 300:
        return
    raise error_for_status(status, result, path=path, operation=operation)
