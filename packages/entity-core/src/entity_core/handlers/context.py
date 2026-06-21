"""Handler execution context.

The HandlerContext provides handlers with access to:
- execute() for handler-to-handler dispatch
- deliver_async() for async result delivery (v7.8 inbox)
- Peer information (local and remote peer IDs)
- Handler grant and caller capability for authorization
- Request chain information for tracing
- Tree registry for non-default tree access (EXTENSION-TREE.md)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from entity_core.protocol.bounds import Bounds
from entity_core.storage.emit import EmitPathway

if TYPE_CHECKING:
    from entity_core.crypto.identity import Keypair
    from entity_core.protocol.delivery import DeliverySpec
    from entity_core.protocol.durability import DurabilityPolicy
    from entity_core.storage.tree_registry import TreeRegistry

logger = logging.getLogger(__name__)


@dataclass
class ExecuteResult:
    """Result from ctx.execute() call.

    Attributes:
        status: HTTP-style status code (200=success, 404=not found, etc.)
        result: The result data if successful. Handlers MAY return:
            (1) a single entity dict — for the typed result-entity case
            (V3.6 F4 wire-shape pattern; the snapshot/content-response/
            file-entity shape), or
            (2) a ``system/envelope`` wrapper carrying the bundle in its
            own ``data.included`` (V7 §3.3 surface-equivalence pattern,
            kept for handlers that haven't migrated to envelope_included).
            For shape (1), bundled entities ride in :attr:`envelope_included`.
        envelope_included: Hash → entity-dict map of entities the handler
            wants to deliver as part of the response. Drained into the
            outer wire envelope's ``included`` at send time
            (peer.py::_collect_wire_included); preserved across internal
            dispatch so in-process consumers (compute expressions,
            continuations) can resolve hash references the result body
            points at. None when the handler returned the legacy
            system/envelope wrapper shape or no bundle is needed.
        error: Error message if failed.
    """

    status: int
    result: dict[str, Any] | None = None
    envelope_included: dict[bytes, dict[str, Any]] | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Whether the operation succeeded (status 2xx)."""
        return 200 <= self.status < 300

    def raise_for_status(self) -> None:
        """Raise RuntimeError if status indicates failure."""
        if not self.ok:
            raise RuntimeError(self.error or f"Execute failed with status {self.status}")


# Type for execute dispatcher callback.
# Required positional args: uri, operation, params, dispatch_capability, bounds,
# chain_id, resource_targets.
# Optional keyword args (V7 §6.8 propagation, opt-in): propagated_caller_capability,
# propagated_author_peer_id, propagated_author_identity_hash. When provided, the
# child handler's context will reflect these values instead of defaulting to the
# calling handler's grant/peer identity.
ExecuteDispatcher = Callable[..., Awaitable[ExecuteResult]]


@dataclass
class HandlerContext:
    """Context provided to handlers during execution.

    Attributes:
        local_peer_id: This peer's ID.
        remote_peer_id: The requesting peer's ID.
        handler_grant: The handler's own capability grant (for internal operations).
        caller_capability: The caller's capability (for optional defense-in-depth checks).
        emit_pathway: Storage access for the tree handler.
        bounds: Resource bounds for this request.
        chain_id: Request chain identifier for tracing.
        resource_targets: V7 resource targets from EXECUTE (paths for tree operations).
        handler_pattern: The handler's registered pattern (for path permission checks).
        tree_registry: Registry for non-default trees (EXTENSION-TREE.md §7).
        deliver_to: V7.8 inbox delivery spec (where to send async results).
        deliver_token: V7.8 capability token authorizing inbox delivery.
        _execute_dispatcher: Internal callback for handler-to-handler dispatch.
    """

    local_peer_id: str
    remote_peer_id: str
    handler_grant: dict[str, Any]
    caller_capability: dict[str, Any]
    emit_pathway: EmitPathway
    bounds: Bounds | None = None
    chain_id: str | None = None
    parent_chain_id: str | None = None
    # Per CONTINUATION v1.14 (and the general spec posture): handlers
    # that need to bind observability markers keyed by the original
    # request need access to the EXECUTE's request_id. Mirror Go's
    # `hctx.RequestID`. None for internally-synthesized contexts.
    request_id: str | None = None
    resource_targets: list[str] | None = None
    handler_pattern: str | None = None
    # V7 §3.3 (v7.51) request-side envelope-`included` preservation: the
    # request envelope's `included` map (hash -> entity dict) that arrived
    # with this EXECUTE, preserved across dispatch surfaces and propagated to
    # downstream sub-dispatches so a handler and its continuations can resolve
    # bundled hash-refs from the *map itself* (a pure transform like the
    # `deref_included` continuation op reads this map, not the content store).
    # Empty when the EXECUTE carried no included entities.
    included: dict[bytes, dict[str, Any]] = field(default_factory=dict)
    caller_capability_hash: bytes | None = None
    # V7 §PR-8: the granter frame for the caller capability's *own* resource
    # patterns — the granter's peer_id, resolved once at dispatch. Used by
    # check_caller_permission (and compute path checks) so the handler-level
    # defense-in-depth check canonicalizes a foreign-granter cap's bare
    # wildcard against the granter's namespace, not this verifier's. None
    # (-> falls back to local_peer_id, the self-issued frame) for
    # internally-synthesized contexts.
    caller_capability_granter_peer_id: str | None = None
    remote_identity_hash: bytes | None = None
    # The cryptographically-verified author of THIS EXECUTE
    # (`ctx.execute.data.author`, V7 §5.2 / EXTENSION-CONTINUATION §8.1) —
    # the signer of the request, which for a cross-peer install differs
    # from the connect-time session identity (`remote_identity_hash`).
    # None for internally-synthesized contexts; consumers needing the
    # per-EXECUTE writer (continuation install §3.1a) prefer this and fall
    # back to `remote_identity_hash`.
    author_identity_hash: bytes | None = None
    handler_grant_hash: bytes | None = None
    tree_registry: "TreeRegistry | None" = None
    # V7.8 Inbox Extension fields
    deliver_to: "DeliverySpec | None" = None
    deliver_token: bytes | None = None
    # EXTENSION-DURABILITY: the receiving peer's own durability policy,
    # threaded so handlers that need to reason about durability can read
    # it. The extension is exploratory and optional; this field is None
    # on peers that don't install it. Advertisement (§3) is seeded at
    # bootstrap, not surfaced via the inbox handler.
    durability_policy: "DurabilityPolicy | None" = None
    _execute_dispatcher: ExecuteDispatcher | None = None
    # EXTENSION-RELAY §3.1.1 terminal-hop hookpoint. A coroutine
    # ``(destination_peer_id: str, inner_entity) -> bool`` that delivers the
    # bare inner envelope to the destination, reusing the destination's inbound
    # EXECUTE entrypoint (the relay side only writes the raw frame / pushes the
    # held session — it does NOT re-author or re-sign, §5.1/§9). Returns True on
    # delivery to a live session, False when none exists (→ Mode-S fallback,
    # §6.2.1). None on peers without the relay handler wired.
    relay_send: Callable[..., Awaitable[bool]] | None = None
    # Peer-internal: keypair for handlers that need to sign (e.g.,
    # system/handler:register signs handler grants per spec-gap §S1).
    # Exposed only to compiled handlers; entity-native compute expressions
    # cannot access it.
    keypair: "Keypair | None" = None

    async def execute(
        self,
        uri: str,
        operation: str,
        params: dict[str, Any] | None = None,
        resource_targets: list[str] | None = None,
        included: dict[bytes, dict[str, Any]] | None = None,
    ) -> ExecuteResult:
        """Execute operation using handler's own grant.

        Uses the handler's grant (not the caller's capability) for authorization.
        The dispatch goes through the full capability checking system.

        Args:
            uri: Target URI (e.g., "system/tree", "local/data").
            operation: Operation to perform (e.g., "get", "put").
            params: Operation parameters.
            resource_targets: Resource paths for the target handler
                (passed as ctx.resource_targets to the called handler).
            included: Entities to carry in this sub-dispatch's request
                envelope `included` (V7 §3.3 v7.51), e.g. the subscription
                engine bundling an `include_payload` entity. When None, the
                dispatcher propagates this context's own `included` so a
                downstream continuation still resolves bundled hash-refs.

        Returns:
            ExecuteResult with status, result, and optional error.

        Raises:
            RuntimeError: If execute dispatcher is not configured.
        """
        if self._execute_dispatcher is None:
            raise RuntimeError(
                "execute() not available - handler context was created without dispatcher"
            )

        return await self._execute_dispatcher(
            uri,
            operation,
            params,
            self.handler_grant,
            self.bounds,
            self.chain_id,
            resource_targets,
            included=included,
        )

    async def execute_with_capability(
        self,
        uri: str,
        operation: str,
        params: dict[str, Any] | None = None,
        capability_data: dict[str, Any] | None = None,
        resource_targets: list[str] | None = None,
        *,
        propagated_caller_capability: dict[str, Any] | None = None,
        propagated_author_peer_id: str | None = None,
        propagated_author_identity_hash: bytes | None = None,
        dispatch_capability_entity: dict[str, Any] | None = None,
        dispatch_capability_chain: list[dict[str, Any]] | None = None,
    ) -> ExecuteResult:
        """Execute operation using a specific stored capability.

        Used by continuation handler (W9) to dispatch with the continuation's
        stored dispatch_capability instead of the handler's own grant. Also
        used by the compute extension to dispatch sub-requests under a
        voluntary restriction (compute/apply.capability) or under the
        evaluator's authorizing capability.

        The propagated_* kwargs implement V7 §6.8 context propagation —
        when set, the child handler sees the original external caller's
        capability and identity instead of defaulting to the calling
        handler's grant / local peer.

        Args:
            uri: Target URI.
            operation: Operation to perform.
            params: Operation parameters.
            capability_data: The capability entity data to use for authorization.
            resource_targets: Resource paths for the target handler.
            propagated_caller_capability: Original caller's capability for
                history attribution (V7 §6.8). Defaults to caller's grant
                when None.
            propagated_author_peer_id: Original caller's peer ID. Defaults to
                local peer when None.
            propagated_author_identity_hash: Original caller's identity hash.
                Defaults to local peer's identity hash when None.
            dispatch_capability_entity: EXTENSION-CONTINUATION §4.2 case 3 —
                for a cross-peer continuation dispatch, the scoped B-rooted
                `dispatch_capability` ENTITY (full dict w/ content_hash) that
                authorizes the remote EXECUTE, granted to this host peer.
                Threaded to the wire only for remote targets; ignored for
                local dispatch (which uses `capability_data`).
            dispatch_capability_chain: full authority chain for the above
                (collect_chain_bundle) → dispatched envelope `included`
                (§4.3). Ignored unless the entity is set / target is local.
        """
        if self._execute_dispatcher is None:
            raise RuntimeError(
                "execute_with_capability() not available - no dispatcher"
            )

        cap = capability_data if capability_data is not None else self.handler_grant
        return await self._execute_dispatcher(
            uri,
            operation,
            params,
            cap,
            self.bounds,
            self.chain_id,
            resource_targets,
            propagated_caller_capability=propagated_caller_capability,
            propagated_author_peer_id=propagated_author_peer_id,
            propagated_author_identity_hash=propagated_author_identity_hash,
            dispatch_capability_entity=dispatch_capability_entity,
            dispatch_capability_chain=dispatch_capability_chain,
        )

    async def deliver_async(
        self,
        original_request_id: str,
        status: int,
        result: Any,
        deliver_to: "DeliverySpec | None" = None,
    ) -> ExecuteResult:
        """Deliver async result to an inbox (v7.8 inbox extension).

        Delivers the result to the specified inbox using the inbox handler's
        receive operation. If deliver_to is not specified, uses the deliver_to
        from this context (which came from the original EXECUTE request).

        Per EXTENSION-INBOX v5.0 §3.1:
        - Result is delivered as an InboxDelivery entity
        - Delivery uses fresh bounds (independent of original request)
        - If inbox has a continuation, it will be advanced

        Args:
            original_request_id: The request_id of the original EXECUTE request.
            status: HTTP-style status code (200=success, etc.).
            result: The operation result.
            deliver_to: Optional override for delivery destination.

        Returns:
            ExecuteResult from the inbox delivery.

        Raises:
            RuntimeError: If no deliver_to is configured.
        """
        from entity_core.protocol.delivery import InboxDelivery

        target = deliver_to or self.deliver_to
        if target is None:
            raise RuntimeError(
                "deliver_async() requires deliver_to - either pass it or "
                "ensure the original request had deliver_to"
            )

        if self._execute_dispatcher is None:
            raise RuntimeError(
                "deliver_async() not available - handler context was created without dispatcher"
            )

        # Create delivery entity
        delivery = InboxDelivery(
            original_request_id=original_request_id,
            status=status,
            result=result,
        )

        # Deliver to inbox with fresh bounds (per spec)
        # Use handler's grant for authorization
        logger.debug(
            f"deliver_async: delivering to {target.uri} "
            f"operation={target.operation} request_id={original_request_id}"
        )

        # Wrap as entity per spec — params must be {type, data} (V4 §3.4).
        delivery_params = {
            "type": InboxDelivery.TYPE,
            "data": delivery.to_dict(),
        }

        # Per INBOX §4.1: resource = {targets: [deliver_to.uri]}.
        # URI normalization is the dispatcher's responsibility, not ours.
        return await self._execute_dispatcher(
            target.uri,
            target.operation,
            delivery_params,
            self.handler_grant,
            Bounds(),  # Fresh bounds for async delivery
            None,  # No chain_id for async delivery
            [target.uri],  # Per INBOX §4.1
        )

    def check_caller_permission(
        self,
        operation: str,
        path: str,
    ) -> bool:
        """Check if caller's capability grants permission for operation on path.

        Defense-in-depth check. Handlers can use this to verify the caller
        authorized access to a specific path, beyond the dispatch-level check.

        Args:
            operation: The operation to check (get, put, etc.).
            path: The data path being accessed.

        Returns:
            True if the caller's capability grants access.
        """
        from entity_core.capability.checking import check_path_permission

        return check_path_permission(
            self.caller_capability,
            operation,
            path,
            self.local_peer_id,
            handler_pattern=self.handler_pattern,
            granter_peer_id=self.caller_capability_granter_peer_id,
        )
