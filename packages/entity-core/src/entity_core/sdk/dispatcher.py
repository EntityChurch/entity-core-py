"""Dispatcher Protocol + adapters per SDK-EXTENSION-OPERATIONS v0.8 §11.

The Protocol is the seam SDK affordances (closure-completion, future
extension SDK surfaces) compose against. Two reference adapters — one over
:class:`entity_core.handlers.context.HandlerContext` (handler-internal local
dispatch) and one over :class:`entity_core.peer.connection.Connection`
(outer-caller cross-peer dispatch) — let both surfaces satisfy the contract
without disturbing their existing call shapes.

``ExecuteRequest`` carries:

* URI + operation + params (the EXECUTE basics)
* ``resource_targets`` (V7 §3.2 path-as-resource)
* ``included`` (V7 §3.3 v7.51 envelope-``included`` preservation; needed for
  chain dispatch that bundles an ``include_payload`` entity per
  EXTENSION-SUBSCRIPTION §2.2)
* ``capability`` + ``capability_chain`` (V7 §6.8 propagated-cap-not-a-gate +
  EXTENSION-CONTINUATION §4.2 case 3 dispatch-cap override; needed for
  cross-peer chain dispatch from a handler running on peer B against peer A's
  namespace)

The Python answer for ``ExecuteResponse`` is the existing
:class:`entity_core.handlers.context.ExecuteResult` — same shape (status +
result + envelope_included + error), no parallel type invented.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from entity_core.handlers.context import ExecuteResult, HandlerContext
    from entity_core.peer.connection import Connection


@dataclass
class ExecuteRequest:
    """A fully-specified EXECUTE request for the Dispatcher contract.

    Per SDK-EXTENSION-OPERATIONS v0.8 §11. Lean shape: required positional
    fields up top, optional propagation / envelope fields at the bottom.

    For handler-internal dispatch with the handler's own grant, leave
    ``capability`` and ``capability_chain`` unset — the adapter routes through
    :meth:`HandlerContext.execute` which uses ``ctx.handler_grant``.

    For cross-peer dispatch from a handler under a propagated cap-chain (e.g.,
    workbench's Stage 3 case 1.5 — peer B dispatches against peer A's
    namespace under a B-rooted dispatch_capability), populate both
    ``capability`` and ``capability_chain``; the adapter routes through
    :meth:`HandlerContext.execute_with_capability` or
    :meth:`Connection.execute` with ``capability_override``.
    """

    uri: str
    operation: str
    params: dict[str, Any] | None = None
    # V7 §3.2 path-as-resource — list of paths the dispatcher checks the grant
    # against at handler-scope time.
    resource_targets: list[str] | None = None
    # V7 §3.3 v7.51 envelope-included preservation — entities bundled with the
    # request envelope so downstream handlers (and their continuations)
    # resolve hash references from the map without a substrate read.
    included: dict[bytes, dict[str, Any]] | None = None
    # V7 §6.8 + EXTENSION-CONTINUATION §4.2 case 3 — capability override.
    # When set, dispatch is authorized by this capability instead of the
    # handler's own grant / connection's session cap. The chain bundles into
    # the dispatched envelope's `included` per §4.3.
    capability: dict[str, Any] | None = None
    capability_chain: list[dict[str, Any]] | None = None


@runtime_checkable
class Dispatcher(Protocol):
    """The cap-checked EXECUTE dispatch contract SDK affordances compose against.

    Per SDK-EXTENSION-OPERATIONS v0.8 §11 ``Dispatcher.Execute(ctx,
    ExecuteRequest) → (ExecuteResponse, error)``. Python idiom: an awaitable
    method returning :class:`ExecuteResult`; errors surface as non-2xx status
    on the result, matching :class:`HandlerContext.execute` convention.

    Both :class:`HandlerContextDispatcher` and :class:`ConnectionDispatcher`
    satisfy this Protocol. Tests can mock it directly with a stub.
    """

    async def execute(self, request: ExecuteRequest) -> ExecuteResult: ...


class HandlerContextDispatcher:
    """Dispatcher adapter over :class:`HandlerContext`.

    Routes through ``ctx.execute`` for default (handler-grant) dispatch, or
    ``ctx.execute_with_capability`` when ``request.capability`` is set. URIs
    that target a different peer (``entity://{remote_peer}/...``) are handled
    by the underlying ``_remote_execute`` path inside
    :meth:`Peer._execute_internal` — so this adapter naturally covers
    handler-internal local dispatch AND handler-driven cross-peer dispatch,
    no peer-aimed-rewrite required.

    Per SDK-EXTENSION-OPERATIONS §11 — ``content.AtPeer`` wraps this adapter
    with a URI rewrite so handler authors can stay in "namespace" terms
    without manually constructing ``entity://...`` URIs.
    """

    def __init__(self, ctx: HandlerContext) -> None:
        self._ctx = ctx

    async def execute(self, request: ExecuteRequest) -> ExecuteResult:
        if request.capability is not None:
            return await self._ctx.execute_with_capability(
                request.uri,
                request.operation,
                request.params,
                capability_data=request.capability,
                resource_targets=request.resource_targets,
                dispatch_capability_entity=request.capability,
                dispatch_capability_chain=request.capability_chain,
            )
        return await self._ctx.execute(
            request.uri,
            request.operation,
            request.params,
            resource_targets=request.resource_targets,
            included=request.included,
        )


class ConnectionDispatcher:
    """Dispatcher adapter over :class:`Connection` (outer-caller / cross-peer).

    Adapts :class:`ExecuteRequest` to :meth:`Connection.execute`'s keyword
    shape and normalizes the returned :class:`ExecuteResponse` into an
    :class:`ExecuteResult` so SDK code consumes one type regardless of which
    side originated the dispatch.
    """

    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    async def execute(self, request: ExecuteRequest) -> ExecuteResult:
        from entity_core.handlers.context import ExecuteResult

        resource = (
            {"targets": list(request.resource_targets)}
            if request.resource_targets
            else None
        )
        included_list = (
            list(request.included.values()) if request.included else None
        )
        resp = await self._conn.execute(
            uri=request.uri,
            operation=request.operation,
            params=request.params,
            resource=resource,
            included=included_list,
            capability_override=request.capability,
            capability_chain_override=request.capability_chain,
        )
        # Connection.execute returns ExecuteResponse (wire shape: status +
        # result entity + envelope_included). Map onto ExecuteResult so SDK
        # callers see a single type.
        result_payload: dict[str, Any] | None
        error_msg: str | None
        if 200 <= int(resp.status) < 300:
            result_payload = resp.result
            error_msg = None
        else:
            result_payload = None
            # Pull message out of the error result if shaped that way; fall
            # back to a status-only summary.
            err = resp.result if isinstance(resp.result, dict) else None
            error_msg = (
                (err or {}).get("message")
                if isinstance(err, dict)
                else None
            ) or f"execute failed: status={int(resp.status)}"

        return ExecuteResult(
            status=int(resp.status),
            result=result_payload,
            envelope_included=resp.envelope_included,
            error=error_msg,
        )
