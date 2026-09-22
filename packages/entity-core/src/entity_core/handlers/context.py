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


#: Sentinel for :py:meth:`HandlerContext.check_caller_permission`'s
#: ``handler_pattern`` — *"the handler currently dispatching"*, which is the
#: right frame only when the check is about this handler's own operation.
#:
#: It cannot be spelled ``None``: ``None`` is a **meaningful** value at
#: :py:func:`check_path_permission` — it disables grant filtering by handler
#: entirely — so a default of ``None`` would make *"I did not think about the
#: frame"* and *"I want no frame"* the same call, which is the shape that hid
#: the defect this sentinel exists to stop (see
#: ``tests/integration/test_handler_frame_of_the_6_3_check.py``).
_DISPATCHING_HANDLER = "\0dispatching-handler"


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
        caller_capability: The caller's capability. The handler-level path
            check it feeds is NOT optional and NOT secondary — §6.7 (0.8.2.20);
            see :meth:`check_caller_permission`.
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
    # PROPOSAL-CONTINUATION-STANDING-MODEL §3 (arch ruling 2026-07-18, MUST) —
    # the explicit reactive-trigger marker. Set True by a *delivery mechanism*
    # (the inbox route, a subscription poke) on the ONE advance it initiates as
    # a consequence of a delivered event; a bare administrative `advance`
    # EXECUTE (operator/handler directly invoking advance) leaves it False.
    #
    # This is the standing-model O1 signal, pinned as an EXPLICIT per-dispatch
    # declaration — NOT inferred from caller identity, cap shape, or dispatch
    # surface (an inference is what "springs apart at the cross-peer seam").
    # It mirrors entity-core-go's `HandlerContext.ReactiveTrigger` /
    # `WithReactiveTrigger()`. Per-dispatch, NOT inherited: it tags only the
    # advance the delivery mechanism initiated, never the continuation's onward
    # chain dispatches (each sub-dispatch context is built fresh and defaults
    # False). It never serializes — the marker is set locally on B when B's
    # inbox re-dispatches advance, after the inbound `receive` already crossed
    # the wire. Read by the continuation advance to gate the authority split:
    # reactive → own `dispatch_capability`, delivery-reachability the gate;
    # administrative → the caller must hold `advance` on the path.
    reactive_trigger: bool = False
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
    # EXTENSION-NETWORK §6.7.1 — the accept-side transport source of the
    # connection THIS request arrived on. Deliberately the bare fact and not a
    # connection handle: §6.7.1 declines to widen the general handler context
    # and asks for "a narrow, NETWORK-scoped accept-side path from the
    # connection to this operation", and one immutable string is the narrowest
    # shape that carries it. Go's equivalent is `HandlerContext.ConnectionState`
    # (an opaque handle the network handler casts); we hand over only the field
    # that handler would read, so no other handler can reach connection
    # internals through it.
    #
    # Set ONLY on dispatch from an accepted connection. `None` for
    # in-process/self dispatch and for reentry over a dialed connection —
    # neither has an observed transport source, and §6.7's handlers answer 400
    # rather than substitute one.
    #
    # MUST NOT be persisted (§6.7.1 MUST 2). It is read from the live
    # connection and returned; it is not connection-state, not a transport
    # profile, and not a peer attribute.
    observed_source_address: str | None = None
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
        *,
        reactive_trigger: bool = False,
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
            # STANDING-MODEL §3: a delivery mechanism (inbox route, subscription
            # poke) declares the advance it initiates is a reactive trigger, so
            # the continuation advances under its OWN dispatch_capability rather
            # than requiring the delivering caller to hold advance-cap on the
            # continuation's path. Explicit, per-dispatch, never inferred.
            reactive_trigger=reactive_trigger,
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
            # STANDING-MODEL §3: deliver_async IS a delivery mechanism — any
            # continuation advance it drives (an inbox receive that re-advances,
            # or an on_error routed directly to an `advance`) is a REACTIVE
            # trigger, not an administrative invoke, so it runs under the
            # continuation's own dispatch_capability. Per-dispatch and not
            # inherited: it marks only this delivery dispatch's context.
            reactive_trigger=True,
        )

    def check_caller_permission(
        self,
        operation: str,
        path: str,
        handler_pattern: str | None = _DISPATCHING_HANDLER,
    ) -> bool:
        """Check if caller's capability grants permission for operation on path.

        .. rubric:: Not a secondary check `[MUST]` — §6.7 / §6.3 (0.8.2.20)

        This docstring read *"defense-in-depth check. Handlers **can** use
        this… beyond the dispatch-level check"*, which is the characterization
        0.8.2.20 **withdraws** at §6.3, §6.7, §9.1 and the §8 layer table. It
        rested on a premise the spec now states is false:

            *"The dispatch-level ``check_permission`` authorizes the request
            the caller MADE; the handler-level check authorizes the path the
            handler is ABOUT TO TOUCH. These differ whenever any part of the
            subject is derived after dispatch — a caller exclusion
            (``effective_targets``), a path resolved at handler time, a
            listing expanded per entry, a merge resolving snapshot content
            into individual writes. Where the dispatch-level check can be made
            vacuous by caller-controlled input it is not a primary check, and
            the handler-level check is the enforcement."*

        `F68` is the case where the premise is false: a caller supplying an
        ``exclude`` covering its own target reaches ALLOW having had nothing
        checked. And §6.8's *"caller-specified paths"* rule went **act-neutral**
        in the same revision — it was scoped to writes, and the measured harm
        was a ``get``, so *"reads or writes"*: the failure mode is disclosure
        rather than mutation and the cause is identical.

        A handler that derives every subject from ``effective_targets`` is
        conformant with one site; this is what makes the guarantee hold for a
        subject derived any other way, and the corpus does not mandate two.
        **Neither is made redundant by the other**, and "optional" was never
        the word for either of them.

        .. rubric:: The handler frame is an ARGUMENT, and it is not always ours

        §6.3's signature filters the caller's grants by ``handler_pattern``
        *before* their ``resources`` scope is read, so a grant scoped to a
        different handler is discarded without ever being consulted. This
        method defaulted that argument to ``self.handler_pattern`` — **the
        handler currently dispatching** — with no way to say otherwise, and
        four extensions write the argument as a literal at the call site:

        ===================  ==================  =============================
        site                 corpus writes       because
        ===================  ==================  =============================
        SUBSCRIPTION §2.3    ``"system/tree"``   the *read* being authorized is
                                                 a tree read; the ``subscribe``
                                                 grant does not carry it
        HISTORY §4.2         ``"system/tree"``   same — the target path
        COMPUTE §7.2         ``"system/tree"``   same — the impure read
        QUERY §5.2 step 6b   ``"system/query"``  the corpus's one *own-handler*
                                                 spelling of a per-entry filter
        ===================  ==================  =============================

        Supplying the dispatching handler at the first three refuses a caller
        holding exactly the capability the corpus describes — §2.3's own prose
        is *"a caller may legitimately hold `subscribe` without `get`"*, which
        only has content if the two live in separately scoped grants. Measured
        on the wire by ``entity-core-go``'s
        ``include_payload_overlapping_exclude`` arm (py 403/403 where go and
        rust answer 403/200).

        Args:
            operation: The operation to check (get, put, etc.).
            path: The data path being accessed.
            handler_pattern: The handler scope to filter grants by. Defaults to
                the dispatching handler, which is correct **only** when the
                check is about this handler's own operation; pass the literal
                the extension names when it is not.

        Returns:
            True if the caller's capability grants access.
        """
        from entity_core.capability.checking import check_path_permission

        frame = (
            self.handler_pattern
            if handler_pattern == _DISPATCHING_HANDLER
            else handler_pattern
        )
        # §6.3 (0.8.2.23) — REQUIRED and fail-closed. The dispatcher populates
        # `handler_pattern` on every context it builds, so in production this
        # resolves; it is `str | None` on the dataclass, and a context built
        # without it (a fixture, a hand-rolled sub-dispatch) previously reached
        # `check_path_permission(None)` and disabled the handlers filter
        # entirely — the widening direction, at the one check §6.3 promoted to
        # *the* enforcement for any subject derived after dispatch.
        #
        # Refusing here rather than defaulting is the point: "I did not think
        # about the frame" MUST NOT be spelled the same as "any handler".
        if not frame:
            return False
        if not check_path_permission(
            self.caller_capability,
            operation,
            path,
            self.local_peer_id,
            handler_pattern=frame,
            granter_peer_id=self.caller_capability_granter_peer_id,
        ):
            return False

        # §6.8 row 1 — THE CEILING, and *"Both MUST pass [MUST]"* (0.8.2.24 N5).
        #
        #   *"the handler is about to touch a path IN SERVICE OF THE CALLER'S
        #   REQUEST … the authority is the caller's verified capability (§6.7)
        #   — AND the executing handler's own grant as an additional ceiling.
        #   Both MUST pass."*
        #
        # This method IS row 1's site: every caller of it is authorizing a path
        # touched in service of a live caller's request (that is what
        # distinguishes it from row 2, where the handler acts on its own behalf
        # and `handler_grant` is the SOLE authority — `execute_with_capability`).
        #
        # .. rubric:: Why all three ground-up seats concluded it was not owed
        #
        # 0.8.2.22 derived row 1 from `EXTENSION-TREE` §8.1/§8.5's dual-check
        # and generalized `max_scope` to *the executing handler's own grant*.
        # §8.5 carries a REDUCTION — absent `max_scope`, the dual check reduces
        # to the single request-capability check — and three independent
        # readers carried that qualifier across with the rest of the
        # derivation. 0.8.2.24 says what the generalization did to it: the
        # thing it generalized TO cannot be absent. §6.8's dispatch-time grant
        # validation requires the grant entity to exist at
        # `system/capability/grants/{pattern}`, treats a missing or invalid one
        # as `permission_denied`, and forbids falling back to the caller's
        # capability — **a handler with no valid grant does not run**. So the
        # ceiling is present at every dispatch and the conjunction always
        # binds. A view tree is one MECHANISM for enforcing the intersection
        # structurally; it is not the condition under which it applies.
        #
        # .. rubric:: Why nothing here could measure it
        #
        # Every handler this peer registers gets §6.2's default self-grant —
        # `handlers:["*"] operations:["*"] resources:["/*/*"]` — which is
        # wider than any caller capability, so the ceiling is satisfied
        # vacuously at every reachable site. That is keystone's finding
        # ("a core peer has one path-resource handler, so owner and runner
        # coincide") and it is why this rule is *"landed, binding, implemented
        # nowhere, observable by nothing"* across the cohort.
        #
        # ⭐ It is observable HERE: `PeerBuilder.with_handler(max_scope=…)`
        # mints a narrower grant, and this peer already ships one —
        # `system/validate/dispatch-outbound`, narrowed on all three of
        # handlers/operations/resources per GUIDE-CONFORMANCE §7a.1. The
        # fixture the cohort is blocked on for KB-16 exists at two seats.
        #
        # The frame is the SAME on both checks by construction: §6.3's
        # `handler_pattern` describes *the access being authorized* (a tree
        # read is a tree read whoever's grant is being consulted), and giving
        # the two checks different frames would be SA-PY-58's defect with the
        # ceiling as the victim.
        return check_path_permission(
            self.handler_grant,
            operation,
            path,
            self.local_peer_id,
            handler_pattern=frame,
        )
