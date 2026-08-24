"""The **client** half — using a connection node from a peer.

This is the cheap half, and the reason Stage 1 is cheap at all: calling
``system/signaling:offer`` on a gated node is an **ordinary EXECUTE**. This impl
already has cross-peer execute and already conformance-tests it, so **no new
handler is needed to *use* the service** — this module is a typed wrapper over
dispatch, not a new protocol surface.

It does *not* extend to the unwrapped surface (a plain client per language, §5.1,
unwritten) or to the punch (socket-level work, not a dispatch handler at all).
Both are Stage 2.

**The client owns the two convergence obligations the node does not:**
:mod:`~entity_handlers.signaling.key` (which key) and
:mod:`~entity_handlers.signaling.pool` (which node). The node is mode-blind and
single; a peer that gets either wrong meets nobody and sees no error. Together
with the ordinary handshake that is the whole client surface.

Capabilities
------------

The wrapped surface's admission control is the ordinary dispatch-layer capability
check — the *caller's* grant must cover
``system/signaling:{offer,collect,advertise}``. This module adds no authority of
its own. Against Rust's ``entity-signaling-node`` that grant comes from the
operator's admission flag (``--open`` for anyone, ``--grant <peer>`` for named
peers); a node started with neither is **closed** and refuses every call 403.

**Send no resource target.** Every dispatch here leaves
:attr:`~entity_core.sdk.dispatcher.ExecuteRequest.resource_targets` unset, and
that is load-bearing rather than incidental: signaling addresses no tree resource
— the rendezvous key rides in ``params`` and the handler reads and writes nothing
— so the seeded grant's resource scope is **empty**, and V7 dispatch
authorization denies any target an empty include list does not cover. The failure
mode is what makes it worth stating: the refusal is a 403 indistinguishable from
"you were never granted this". Pinned by
``test_no_resource_target_rides_along_on_any_of_the_three_verbs`` and live in
``tests/interop/test_signaling_rust_node.py``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from entity_core.sdk.dispatcher import Dispatcher, ExecuteRequest
from entity_handlers.signaling.constants import (
    OP_ADVERTISE,
    OP_COLLECT,
    OP_OFFER,
    PATTERN,
    SignalingError,
)
from entity_handlers.signaling.coordination import (
    Candidate,
    CollectedMessage,
    ConnectRequest,
    ConnectResponse,
    classify_blob,
    generate_nonce,
    to_blob,
)
from entity_handlers.signaling.data import (
    Advertisement,
    advertisement_from_result,
    collect_messages_from_result,
    collect_params,
    empty_params,
    offer_params,
)

# Statuses this client branches on. 429 is the retry signal for *both* capacity
# refusals (§1.1): on this node rate limits are the whole admission story, and a
# full bucket says the same thing to a peer as a throttle — back off and retry.
_STATUS_OK_MIN, _STATUS_OK_MAX = 200, 299
_STATUS_RATE_LIMITED = 429
_STATUS_NOT_SUPPORTED = 501


class ClientError(SignalingError):
    """What can go wrong calling a node."""


class DispatchFailed(ClientError):
    """The EXECUTE itself did not complete (transport / dispatch failure)."""


class Refused(ClientError):
    """The node refused with a status this client does not special-case."""

    def __init__(self, status: int, message: str | None = None) -> None:
        super().__init__(
            f"node refused with status {status}"
            + (f": {message}" if message else "")
        )
        self.status = status
        self.message = message


class Backoff(ClientError):
    """The node is at capacity or throttling (429).

    **Retry-safe by construction** — every core refusal happens before any state
    change, and §1.1 pins each bucket rule to the choice that makes a retry safe.
    """


class Unsupported(ClientError):
    """The node does not serve this operation on this surface (501).

    **Not what a ``reflect`` call gets.** ``reflect`` is not a core operation at
    all (§1.4), so a wrapped node never answers 501 for it — a "not implemented
    here" would imply this is a surface where it could be. What it *does* answer
    depends on the caller's grant: **403** against a real node, whose enumerated
    grant names only ``offer``/``collect``/``advertise`` so the capability check
    refuses before dispatch, and 400 ``unknown_operation`` only for a
    wildcard-granted caller that reaches the handler. There is deliberately no
    ``reflect`` method here: it belongs to the unwrapped listener, whose protocol
    is §5.1 and unwritten.
    """


class SignalingClient:
    """A typed client for one node, over any
    :class:`~entity_core.sdk.dispatcher.Dispatcher`.

    Taking a ``Dispatcher`` rather than a concrete peer keeps this usable from an
    outer caller (over a :class:`~entity_core.peer.connection.Connection`) and
    from handler-internal dispatch alike, and makes it testable against a stub.
    """

    def __init__(self, dispatcher: Dispatcher, node_peer_id: str) -> None:
        """Target the node running at ``node_peer_id``.

        The peer-id normally comes from the pool member the peer selected —
        :func:`~entity_handlers.signaling.pool.select` — not from a config
        constant, because both peers must land on the same one.
        """
        self._dispatcher = dispatcher
        self._node_peer_id = node_peer_id
        self._node_uri = f"entity://{node_peer_id}/{PATTERN}"

    @property
    def node_uri(self) -> str:
        return self._node_uri

    @property
    def node_peer_id(self) -> str:
        return self._node_peer_id

    # -----------------------------------------------------------------------
    # The three operations (§1)
    # -----------------------------------------------------------------------

    async def offer(self, key: bytes, message: bytes) -> None:
        """Deposit ``message`` at ``key``.

        Safe to call again with the same bytes: §1.1 pin 2 dedups by content
        hash, so a retry after a timeout is idempotent rather than an
        accumulation. Peers MUST be prepared to **re-offer**, since the node's
        TTL is binding and a blob may have been reaped (§1.1 pin 3).
        """
        await self._execute(OP_OFFER, offer_params(key, message))

    async def collect(self, key: bytes) -> list[bytes]:
        """Read what is at ``key``. Removes nothing (§1.1 pin 1), so both peers
        may collect and re-collect the same bucket.

        An empty list means "nothing there **yet**" — not an error and not a
        reason to give up. A peer polling ahead of its counterpart is normal.
        """
        result = await self._execute(OP_COLLECT, collect_params(key))
        return collect_messages_from_result(result)

    async def advertise(self) -> Advertisement:
        """Read the node's endpoint, limits and ``lobby`` constant.

        Worth calling **before deriving a lobby key**: if the node overrides the
        constant and the peer derives from
        :data:`~entity_handlers.signaling.constants.LOBBY_DEFAULT` anyway, it
        lands in a bucket nobody else on that pool uses.
        """
        result = await self._execute(OP_ADVERTISE, empty_params())
        return advertisement_from_result(result)

    # -----------------------------------------------------------------------
    # §4 step 2 — exchange candidate lists over the rendezvous carrier
    # -----------------------------------------------------------------------

    async def offer_message(self, key: bytes, entity: Any) -> None:
        """Deposit a coordination entity (§3) as an opaque blob.

        The blob is the canonical ``{type, data, content_hash}`` encoding, so the
        message type travels with it — the reader has nothing else to dispatch
        on, since a bucket is a mixed set.
        """
        await self.offer(key, to_blob(entity))

    async def collect_messages(self, key: bytes) -> list[CollectedMessage]:
        """Collect a bucket and classify every blob in it.

        Returns
        :class:`~entity_handlers.signaling.coordination.UnknownMessage` entries
        rather than dropping them: a shared ``lobby`` bucket may hold other
        pairs' traffic and message types this build has never seen, and a caller
        that wants to know how much it skipped should be able to count.

        **Includes your own offers.** ``collect`` is non-destructive (§1.1 pin 1),
        so you always re-read what you wrote — which is why
        :func:`~entity_handlers.signaling.coordination.find_response` and
        :func:`~entity_handlers.signaling.coordination.find_request` both filter
        on peer-id.
        """
        return [classify_blob(b) for b in await self.collect(key)]

    async def initiate(
        self, key: bytes, my_peer_id: str, candidates: Iterable[Candidate]
    ) -> bytes:
        """§4 step 2, initiator half: offer a ``connect-request`` and return the
        nonce that identifies this exchange.

        Poll :meth:`collect_messages` and pass the nonce to
        :func:`~entity_handlers.signaling.coordination.find_response` to pick your
        answer out of the bucket. Re-offering the same request while polling is
        safe and expected — the node dedups it, and the TTL is binding so a long
        wait may need one.
        """
        nonce = generate_nonce()
        request = ConnectRequest(
            initiator=my_peer_id, candidates=tuple(candidates), nonce=nonce
        )
        await self.offer_message(key, request.to_entity())
        return nonce

    async def respond(
        self,
        key: bytes,
        my_peer_id: str,
        request: ConnectRequest,
        candidates: Iterable[Candidate],
    ) -> None:
        """§4 step 2, responder half: answer a ``connect-request`` with our own
        candidates, **echoing its nonce**."""
        response = ConnectResponse(
            responder=my_peer_id,
            candidates=tuple(candidates),
            nonce=request.nonce,
        )
        await self.offer_message(key, response.to_entity())

    # -----------------------------------------------------------------------

    async def _execute(self, operation: str, params: dict[str, Any]) -> Any:
        try:
            result = await self._dispatcher.execute(
                ExecuteRequest(
                    uri=self._node_uri, operation=operation, params=params
                )
            )
        except Exception as exc:  # transport / dispatch, not a node refusal
            raise DispatchFailed(f"signaling dispatch failed: {exc}") from exc

        status = int(result.status)
        if _STATUS_OK_MIN <= status <= _STATUS_OK_MAX:
            return result.result
        if status == _STATUS_RATE_LIMITED:
            raise Backoff("node is at capacity or rate-limiting; retry")
        if status == _STATUS_NOT_SUPPORTED:
            raise Unsupported(
                "node does not serve this operation on this surface"
            )
        raise Refused(status, getattr(result, "error", None))
