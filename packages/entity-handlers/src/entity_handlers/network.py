"""system/network handler — EXTENSION-NETWORK §3–§4 (Amendment 12 rung 3).

The `maintain-peer` / `release-peer` / `status` / `close` operations and the
§4.1 reconnect lifecycle continuation graph, composed on the §A3 liveness
floor that entity-core's peer layer already provides (status transition
writes + §5.4 keepalive).

Division of labor (§A4 discipline — the handler double-builds nothing):

- ``entity_core.peer`` owns the imperative substrate: establish writes
  ``connected``, the §A1 dispatch seam writes ``suspect``, the §5.4
  keepalive loop writes ``disconnected`` and starts at every outbound pool
  insert.
- this handler owns the REACTIVE half: it installs the continuation graph
  that watches those writes and dials back.

The §4.1 graph as built here follows the six spec-issue resolutions from
the Go reference build (`entity-core-go docs/validation/spec-issues/
2026-07-15-network-amendment-12-rung-3-observations.md` — deliberate
divergences from the §4.1 pseudocode, reported upstream, converged on
cohort-wide):

- ``system/inbox/network/{peer}/on-disconnect`` — standing continuation,
  advanced by a lifecycle subscription on ``system/peer/status/{hex}``;
  dispatches the internal ``reconnect`` operation (the connect-if-needed
  seam — the pseudocode's ``system/protocol/connect hello`` target is the
  responder side of the handshake and cannot dial; spec-issue 4).
- ``system/network/peers/{peer}/on-reconnect-backoff`` — STANDING
  continuation re-EXECUTing ``maintain-peer``; advanced by the handler
  after the computed §2.2 backoff delay (spec-issue 5). Lives in the §11
  managed namespace, NOT under ``system/inbox/*`` — the marker-proposal §5
  discipline (spec-issue 1). Standing per arch ruling 1: as a one-shot it
  could only re-arm from inside the dispatch it triggered, and the consume
  ran after and deleted the path (see ``_install_backoff_continuation``).
- ``system/inbox/network/{peer}/on-reconnect`` — standing continuation,
  advanced by a second lifecycle subscription on the same status path
  (spec-issue 2 — the pseudocode's single subscription never fires this
  leg); dispatches the internal ``restore-subscriptions`` operation (§7.2
  first half only — the second half needs the outbound-subscription record
  no spec defines yet; spec-issue 6).

Failed reconnect dispatches deliberately carry NO ``on_error``: a forward
non-2xx with no ``on_error`` binds the §3.10 lost-error marker under the
continuation handler's own authority (reason ``connection_failed``, keyed
by the original request id) — the PROPOSAL-CONTINUATION-LOST-ERROR-MARKER-
MUST observability surface this rung is the named test subject for.

State model: the durable half of a maintain session (the continuation
graph, the lifecycle subscriptions) lives in the tree; the in-memory
:class:`_MaintainSession` only carries what the retry loop needs between
requests (per §12.4 session/backoff bookkeeping is implementation-defined).
Because the handler needs both persistent state and the peer's imperative
connect/evict seams, it is built as an :class:`~entity_core.peer.extensions.
Extension` (`NetworkExtension`) that exposes the handler — the standard
pattern for stateful handlers in this repo.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from entity_core.capability.grant import Grant, create_capability_token
from entity_core.crypto.identity import derive_peer_from_peer_id
from entity_core.handlers.context import HandlerContext
from entity_core.peer import liveness
from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.protocol.auth import (
    compute_peer_identity_hash,
    create_identity_entity,
)
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_handlers._common import error_response, ok_response

if TYPE_CHECKING:
    from entity_core.peer.peer import Peer
    from entity_core.storage.emit import EmitPathway

logger = logging.getLogger(__name__)

NETWORK_HANDLER_PATTERN = "system/network"

#: §2.2 backoff defaults (impl-defined exact values per §12.4).
DEFAULT_BACKOFF_MIN_MS = 1000
DEFAULT_BACKOFF_MAX_MS = 60_000
DEFAULT_BACKOFF_STRATEGY = "exponential"


# --- §4.1 graph path scheme --------------------------------------------------
# The two inbox residents are subscription-delivery targets (delivery
# EXECUTEs `receive`, the inbox handler's advance seam); the backoff
# continuation lives in the §11 managed namespace and is advanced directly
# by the handler — never via system/inbox/* (marker-proposal §5 discipline).

def on_disconnect_path(peer_id: str) -> str:
    return f"system/inbox/network/{peer_id}/on-disconnect"


def on_reconnect_path(peer_id: str) -> str:
    return f"system/inbox/network/{peer_id}/on-reconnect"


def backoff_path(peer_id: str) -> str:
    return f"system/network/peers/{peer_id}/on-reconnect-backoff"


def _inbox_prefix(peer_id: str) -> str:
    return f"system/inbox/network/{peer_id}/"


def _managed_prefix(peer_id: str) -> str:
    return f"system/network/peers/{peer_id}/"


def _local_identity_hash(keypair: Any) -> bytes:
    """Hash of the local peer's identity entity — the author/subscriber the
    handler's own self-authored dispatches must present (mirrors
    ``Peer._get_local_identity_hash``)."""
    return create_identity_entity(keypair).compute_hash()


def _upstream_error(result: Any) -> tuple[str, str]:
    """Extract ``(code, message)`` from a failed sub-dispatch result.

    Lets a caller re-raise the upstream failure under its own status
    instead of flattening it to ``internal_error`` — the distinction
    between "this handler broke" and "the sub-dispatch was refused" is
    what makes a cross-impl probe diagnosable.
    """
    payload = result.result
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, dict) and (data.get("code") or data.get("message")):
            return (
                str(data.get("code") or "internal_error"),
                str(data.get("message") or result.error or ""),
            )
    return "internal_error", str(result.error or payload or "")


def _delay_ms(backoff: dict[str, Any] | None, k: int) -> int:
    """§2.2 delay in ms before retry ``k``, ``k`` 1-INDEXED: ``k=1`` is the
    first retry after the failure, ``_delay_ms(_, 0) == 0`` (no retry, no
    wait). Mirrors the Go reference ``BackoffConfigData.DelayMs``.

        constant     min
        linear       min · k
        exponential  min · 2^(k-1)

    all clamped to max (max raised to min when a config inverts them, so the
    delay is never below min). Python ints are unbounded, so no saturation
    dance is needed — the exponential loop still short-circuits at the cap."""
    if k <= 0:
        return 0
    cfg = backoff or {}
    min_ms = int(cfg.get("min_ms", DEFAULT_BACKOFF_MIN_MS))
    max_ms = int(cfg.get("max_ms", DEFAULT_BACKOFF_MAX_MS))
    if max_ms < min_ms:
        max_ms = min_ms
    strategy = cfg.get("strategy", DEFAULT_BACKOFF_STRATEGY)
    if strategy == "constant":
        ms = min_ms
    elif strategy == "linear":
        ms = min_ms * k
    else:  # exponential (default; unknown strategies fall back per spec)
        ms = min_ms
        for _ in range(1, k):
            if ms >= max_ms:
                break
            ms *= 2
    return min(ms, max_ms)


@dataclass(frozen=True)
class RetryState:
    """§2.2 retry pacing for one failure episode, DERIVED from
    ``(failing_since, backoff cfg, now)`` — never stored. Mirrors the Go
    reference ``types.RetryState`` (`ROUTING`/`HANDOFF-2026-07-16` §2)."""

    #: Retries that have already FIRED this episode: 0 in the interval between
    #: the failure and the first retry coming due.
    attempt: int = 0
    #: When the next retry comes due, ms since epoch. 0 when ``exhausted`` —
    #: there is no next attempt.
    next_attempt_at: int = 0
    #: An OPTIONAL §2.2 bound (``max_attempts`` / ``max_elapsed_ms``) has been
    #: reached and the relationship is abandoned. Always False under the
    #: default retry-forever config.
    exhausted: bool = False


def derive_retry_state(
    backoff: dict[str, Any] | None, failing_since_ms: int | None, now_ms: int
) -> RetryState:
    """The whole §2.2 retry state machine as one pure function: the pacing for
    the failure episode that began at ``failing_since_ms``, as of ``now_ms``.

    Nothing counts attempts and nothing is written per attempt (§A4): the
    k-th retry is due at a fixed offset from ``failing_since``, so "which
    retry are we on" is a question about elapsed time, answerable from a stamp
    the tree already holds. Restart-hammering dies (a process restarting beside
    a month-dead peer re-derives a large ``attempt`` + a max-length wait, where
    an in-memory counter would reset to 0 and redial in ``min_ms``), and pacing
    converges (two peers reading the same ``failing_since`` agree on the
    schedule without exchanging retry state).

    Schedule, ``elapsed = now - failing_since`` (INCLUSIVE boundary — at
    exactly ``elapsed_to(k)`` the k-th retry has fired):

        elapsed_to(0) = 0
        elapsed_to(k) = elapsed_to(k-1) + delay_ms(k)
        attempt       = max{ k : elapsed_to(k) <= elapsed }
        next_attempt_at = failing_since + elapsed_to(attempt + 1)

    ``failing_since`` None/0 ⇒ no episode ⇒ zero state. A degenerate config
    whose delay is 0 is always due, never counted (``attempt`` 0,
    ``next_attempt_at == failing_since``) rather than looping forever.
    """
    if not failing_since_ms:
        return RetryState()
    elapsed = now_ms - failing_since_ms if now_ms > failing_since_ms else 0
    attempt, next_at = _derive_pacing(backoff, failing_since_ms, elapsed)

    cfg = backoff or {}
    # OPTIONAL §2.2 give-up bounds. Unset ⇒ retry-forever (the default never
    # takes these branches). Whichever bound trips first wins; an exhausted
    # episode reports no next attempt (a nonzero would have the caller schedule
    # a retry it just decided not to make).
    max_attempts = cfg.get("max_attempts")
    if max_attempts is not None and attempt >= int(max_attempts):
        return RetryState(attempt=attempt, next_attempt_at=0, exhausted=True)
    max_elapsed = cfg.get("max_elapsed_ms")
    if max_elapsed is not None and elapsed >= int(max_elapsed):
        return RetryState(attempt=attempt, next_attempt_at=0, exhausted=True)
    return RetryState(attempt=attempt, next_attempt_at=next_at, exhausted=False)


def _derive_pacing(
    backoff: dict[str, Any] | None, failing_since_ms: int, elapsed: int
) -> tuple[int, int]:
    """Walk the schedule; returns ``(attempt, next_attempt_at)``. The delay
    sequence is non-decreasing and every strategy plateaus, so once two
    consecutive delays match the tail is arithmetic and closes in one step —
    without which a month-dead peer at a 60s cap would cost ~43k iterations."""
    attempt = 0  # retries fired so far
    cum = 0      # elapsed_to(attempt)
    prev_delay = 0
    k = 1
    while True:
        delay = _delay_ms(backoff, k)
        if delay == 0:
            # Degenerate zero-delay config: always due, never counted.
            return attempt, failing_since_ms + cum
        if k > 1 and delay == prev_delay:
            # Plateaued: every remaining retry costs exactly `delay`, and
            # cum <= elapsed still holds (we would have returned otherwise).
            extra = (elapsed - cum) // delay
            attempt += extra
            cum += extra * delay
            return attempt, failing_since_ms + cum + delay
        nxt = cum + delay
        if nxt > elapsed:
            return attempt, failing_since_ms + nxt
        cum = nxt
        attempt = k
        prev_delay = delay
        k += 1


@dataclass
class _MaintainSession:
    """In-memory bookkeeping for one maintained peer relationship (§12.4)."""

    peer_id: str
    remote_hash: bytes
    session_id: str
    chain_id: str
    #: The maintain-request data this session was created with; the backoff
    #: continuation re-EXECUTEs maintain-peer with exactly these.
    params: dict[str, Any]
    #: Lifecycle subscription ids (on-disconnect + on-reconnect deliveries);
    #: release-peer unsubscribes them.
    subscription_ids: list[str] = field(default_factory=list)
    #: §2 retry-state: the failure episode start (ms since epoch), the ONE
    #: input the derived §2.2 pacing reads. The TREE's ``failing_since``
    #: (written by the demotion seam) wins when present — it is durable, so a
    #: restart re-derives the curve instead of resetting a counter. This
    #: in-memory copy is only the FALLBACK for a peer that never connected
    #: (no demotion transition ever stamped the tree). ``None`` = no open
    #: episode; cleared on recovery. Replaces the old per-attempt counter,
    #: which reset to 0 on restart and re-hammered a long-dead peer.
    failing_since: int | None = None
    #: Pending backoff-advance timer task, if any.
    retry_task: asyncio.Task | None = None
    #: The §4.1 continuations + subscriptions exist in the tree, so
    #: re-entries (backoff retries) skip re-creation of the subscriptions
    #: (continuation re-puts are content-idempotent).
    graph_installed: bool = False

    def reconnect_enabled(self) -> bool:
        return self.params.get("reconnect") is not False

    def resubscribe_enabled(self) -> bool:
        return self.params.get("resubscribe") is not False

    def cancel_retry(self) -> None:
        if self.retry_task is not None and not self.retry_task.done():
            self.retry_task.cancel()
        self.retry_task = None


class NetworkExtension(Extension):
    """Owns the system/network handler's state + the peer seams.

    ``initialize`` binds the peer (the imperative connect/evict seam) and
    the extension execute callback (the self-authored dispatch surface the
    backoff timer uses — an advance fires outside any request context).
    """

    def __init__(self) -> None:
        self._peer: Peer | None = None
        self._emit_pathway: EmitPathway | None = None
        self._execute = None
        self._keypair = None
        self._sessions: dict[str, _MaintainSession] = {}

    # -- Extension lifecycle --------------------------------------------------

    def initialize(self, ctx: ExtensionContext) -> None:
        self._keypair = ctx.keypair
        self._emit_pathway = ctx.emit_pathway
        self._execute = ctx.execute
        self._peer = ctx.peer

    def shutdown(self) -> None:
        for sess in self._sessions.values():
            sess.cancel_retry()
        self._sessions.clear()

    # -- session bookkeeping --------------------------------------------------

    def get_session(self, peer_id: str) -> _MaintainSession | None:
        return self._sessions.get(peer_id)

    def _get_or_create_session(
        self, peer_id: str, remote_hash: bytes, params: dict[str, Any]
    ) -> tuple[_MaintainSession, bool]:
        sess = self._sessions.get(peer_id)
        if sess is not None:
            return sess, True
        session_id = secrets.token_hex(8)
        sess = _MaintainSession(
            peer_id=peer_id,
            remote_hash=remote_hash,
            session_id=session_id,
            # §3.11: chain_id MUST be a single path segment — it *is* a segment
            # of the §3.10.6 marker path .../lost/{chain_id}/{step_index}/...,
            # so a multi-segment value forks the marker tree. §4.1's literal
            # "network/maintain/{sid}" is ruled non-conformant. Value is opaque.
            chain_id=f"network-maintain-{session_id}",
            params=params,
        )
        self._sessions[peer_id] = sess
        return sess, False

    def _drop_session(self, peer_id: str) -> _MaintainSession | None:
        sess = self._sessions.pop(peer_id, None)
        if sess is not None:
            sess.cancel_retry()
        return sess

    # -- handler entry ---------------------------------------------------------

    async def handler(
        self,
        path: str,
        operation: str,
        params: dict[str, Any],
        ctx: HandlerContext,
    ) -> dict[str, Any]:
        """The system/network handler (§3.1 ops + §A5 internal ops)."""
        params_data = params.get("data", params) if isinstance(params, dict) else {}
        params_type = params.get("type") if isinstance(params, dict) else None

        if operation == "maintain-peer":
            return await self._handle_maintain_peer(params_data, params_type, ctx)
        elif operation == "release-peer":
            return await self._handle_release_peer(params_data, ctx)
        elif operation == "status":
            return await self._handle_status(ctx)
        elif operation == "close":
            return await self._handle_close(params_data, ctx)
        elif operation == "reconnect":
            return await self._handle_reconnect(params_data, ctx)
        elif operation == "restore-subscriptions":
            return await self._handle_restore_subscriptions(params_data, ctx)
        return error_response(
            501,
            "unsupported_operation",
            f"Network handler does not support operation: {operation}",
        )

    # -- §4.1 maintain-peer ----------------------------------------------------

    async def _handle_maintain_peer(
        self,
        params: dict[str, Any],
        params_type: str | None,
        ctx: HandlerContext,
    ) -> dict[str, Any]:
        """§4.1: connect if needed, install the reconnect lifecycle graph +
        lifecycle subscriptions, return session info.

        Ordering nuance vs the §4.1 pseudocode (connect first, 502 with no
        graph on failure): that holds for the FIRST imperative call. On a
        re-entry for an existing session (the backoff continuation
        re-EXECUTing maintain-peer after a failed reconnect), a connect
        failure must NOT strand the retry loop — the next delayed advance of
        the standing backoff continuation is scheduled before the 502 returns.
        """
        peer = self._peer
        if peer is None:
            return error_response(
                500, "internal_error", "network handler not bound to a peer"
            )
        # The backoff continuation's re-EXECUTE arrives untyped (continuation
        # params assembly); shape validation is the field checks below.
        if params_type is not None and params_type not in (
            "system/network/maintain-request",
            "primitive/any",
        ):
            return error_response(
                400, "invalid_params",
                f"maintain-peer params must be system/network/maintain-request,"
                f" got {params_type}",
            )
        peer_id = params.get("peer_id")
        if not peer_id or not isinstance(peer_id, str):
            return error_response(
                400, "invalid_params", "maintain-request requires peer_id"
            )
        if peer_id == ctx.local_peer_id:
            return error_response(
                400, "invalid_params", "cannot maintain a relationship with self"
            )
        remote_hash = _remote_identity_hash(peer_id)
        if remote_hash is None:
            return error_response(
                400, "invalid_params",
                "cannot derive identity hash for peer_id (status-path key "
                "required; SHA-256-form PeerIDs need the public key "
                "registered out-of-band first)",
            )

        # Publish the dial address as a transport profile so the pool (and
        # every later redial) can resolve it.
        address = params.get("address")
        if address:
            try:
                peer.register_remote(peer_id, address)
            except Exception as e:
                return error_response(
                    400, "invalid_params", f"register address: {e}"
                )

        clean_params = {k: v for k, v in params.items() if v is not None}
        sess, existed = self._get_or_create_session(
            peer_id, remote_hash, clean_params
        )

        # 1. Connect if needed (§4.1 step 1). The pool seam reuses the pooled
        # binding or dials + handshakes; the establish path writes the §3.13
        # connected status and pool insert starts keepalive (§4.1 steps 2 and
        # 5 are ambient in entity-core — the handler adds no second write or
        # loop, §A4).
        try:
            await peer.ensure_connected(peer_id)
        except Exception as e:
            if existed and sess.reconnect_enabled():
                # Re-entry from the backoff continuation: keep the retry
                # loop alive.
                try:
                    self._arm_backoff_retry(ctx, sess)
                except Exception as arm_err:  # noqa: BLE001
                    logger.warning(
                        "maintain-peer %s: re-arm backoff failed: %s",
                        peer_id[:16], arm_err,
                    )
                # Arch ruling 2: 200, not 502 — the contract is MAINTAIN, not
                # connect-now. The retry is armed, so an unreachable peer is
                # this operation succeeding at what it promises. 502 is
                # retained below for reconnect:false, where "connect now" IS
                # the whole contract and no later retry can succeed.
                #
                # Coupled with ruling 3's on_error (see
                # _install_reconnect_continuations): the backoff continuation
                # forward-dispatches maintain-peer, so a 502 here was a
                # no-on_error forward non-2xx and bound a lost marker PER
                # RETRY. Ruling 3 alone only moved that marker from the
                # on-disconnect continuation to this one — the two rulings are
                # one change, and together they empty the marker tree for a
                # peer that is merely away.
                #
                # No `status` field on the result: that would rebuild the
                # connected/disconnected mirror §3.13 already owns.
                logger.debug(
                    "maintain-peer %s: unreachable, retry armed — 200 "
                    "(maintain, not connect-now): %s",
                    peer_id[:16], e,
                )
                return ok_response(
                    "system/network/maintain-result",
                    {
                        "peer_id": peer_id,
                        "session_id": sess.session_id,
                        "subscriptions": list(sess.subscription_ids),
                        "chain_id": sess.chain_id,
                    },
                )
            if not existed:
                # First imperative call failed — no session, no graph (§4.1).
                self._drop_session(peer_id)
            return error_response(
                502, "connection_failed", f"connect to {peer_id}: {e}"
            )

        # Recovery: close the failure episode. The TREE's `failing_since` is
        # cleared by the ambient `connected` write (§3.13, by omission); this
        # clears the in-memory never-connected fallback in lockstep.
        sess.failing_since = None
        sess.params = clean_params

        # 2–4. Install the continuation graph + lifecycle subscriptions.
        # Continuation re-puts are content-idempotent; subscriptions are
        # created once per session.
        if not sess.graph_installed:
            try:
                if sess.reconnect_enabled():
                    self._install_reconnect_continuations(ctx, sess)
                if sess.resubscribe_enabled():
                    self._install_resubscribe_continuation(ctx, sess)
            except Exception as e:  # noqa: BLE001
                return error_response(500, "storage_error", str(e))

            sub_ids: list[str] = []
            if sess.reconnect_enabled():
                resp = await self._subscribe_lifecycle(
                    ctx, sess.remote_hash, on_disconnect_path(peer_id)
                )
                if isinstance(resp, dict):
                    return resp
                sub_ids.append(resp)
            if sess.resubscribe_enabled():
                resp = await self._subscribe_lifecycle(
                    ctx, sess.remote_hash, on_reconnect_path(peer_id)
                )
                if isinstance(resp, dict):
                    return resp
                sub_ids.append(resp)
            sess.subscription_ids = sub_ids
            sess.graph_installed = True

        return ok_response(
            "system/network/maintain-result",
            {
                "peer_id": peer_id,
                "session_id": sess.session_id,
                "subscriptions": list(sess.subscription_ids),
                "chain_id": sess.chain_id,
            },
        )

    def _install_reconnect_continuations(
        self, ctx: HandlerContext, sess: _MaintainSession
    ) -> None:
        """Write the on-disconnect standing continuation (inbox resident —
        the lifecycle subscription's delivery target) and the standing
        backoff continuation (managed-namespace resident — advanced only by
        the handler's delayed self-advance, never via system/inbox/*).

        Writes are direct handler-authorized tree binds per §11: the graph
        lives in the handler's managed namespaces, authorized by its own
        grant, with dispatch_capability = the handler grant (the F2 pattern).
        Standing trigger shape: params set, no result_field, no
        remaining_executions. No on_error — a failed reconnect dispatch
        binds the §3.10 lost-error marker (no-on_error forward non-2xx);
        retry pacing is the handler's job.
        """
        reconnect_params: dict[str, Any] = {"peer_id": sess.peer_id}
        if sess.params.get("address"):
            reconnect_params["address"] = sess.params["address"]
        self._bind_continuation(
            ctx,
            on_disconnect_path(sess.peer_id),
            {
                "target": NETWORK_HANDLER_PATTERN,
                "operation": "reconnect",
                "resource": {"targets": [NETWORK_HANDLER_PATTERN]},
                "params": reconnect_params,
                "dispatch_capability": ctx.handler_grant_hash,
                # Arch ruling 3: a reconnect failing against an offline peer is
                # the EXPECTED path through this graph, not an anomaly. With no
                # on_error it fell through to a §3.10 lost marker PER ATTEMPT
                # (~1,440 nodes/day for a peer merely away), recording the
                # lifecycle working as if it were breaking. Routing it to the
                # retry seam is the graph describing its own recovery, and the
                # marker returns to catching exceptional failure.
                #
                # Ruling 4 permits this: the error is MEANT to drive the next
                # step. The marker-proposal §5 "never system/inbox/*" does not
                # bite either — backoff_path is the §11 managed namespace, not
                # an inbox resident.
                "on_error": {
                    "uri": backoff_path(sess.peer_id),
                    "operation": "advance",
                },
            },
        )
        self._install_backoff_continuation(ctx, sess)

    def _install_backoff_continuation(
        self, ctx: HandlerContext, sess: _MaintainSession
    ) -> None:
        """Install the STANDING §4.1 backoff continuation that re-EXECUTEs
        maintain-peer with the session's original request.

        Standing (``remaining_executions`` absent) per arch ruling 1. This was
        a one-shot that re-installed itself on each maintain-peer re-entry, and
        it could not work — the defect is ORDERING, not timing:

            timer fires -> advance READS the continuation (remaining = 1)
              -> dispatches maintain-peer
                  -> connect fails -> re-installs the one-shot at this path
              -> advance applies the remaining it read (1 -> 0), DELETES the path
            next timer fires -> advance finds nothing -> {advanced: false} / 200

        The re-install lands *inside* the dispatch; the consume runs *after* it
        and deletes the path out from under the next advance. So the loop
        managed exactly 2 dials against a peer that stayed dead, then stopped
        silently — no marker, no error, a 200. Measured identically from inside
        (2 dials / 2.002s) and by Go's black-box probe on our wire (2 dials /
        25.037s).

        A standing continuation is never decremented and never deleted
        (`_advance_forward` gates all of that on ``remaining is not None``), so
        the path survives every advance. Retry pacing is the handler's timer;
        the continuation is only the dispatch vehicle, which is why standing is
        the coherent shape here rather than a bookkeeping counter.
        """
        self._bind_continuation(
            ctx,
            backoff_path(sess.peer_id),
            {
                "target": NETWORK_HANDLER_PATTERN,
                "operation": "maintain-peer",
                "resource": {"targets": [NETWORK_HANDLER_PATTERN]},
                "params": dict(sess.params),
                "dispatch_capability": ctx.handler_grant_hash,
            },
        )

    def _install_resubscribe_continuation(
        self, ctx: HandlerContext, sess: _MaintainSession
    ) -> None:
        """Write the standing on-reconnect continuation dispatching the
        internal restore-subscriptions operation (§4.1 step 3 / §7)."""
        self._bind_continuation(
            ctx,
            on_reconnect_path(sess.peer_id),
            {
                "target": NETWORK_HANDLER_PATTERN,
                "operation": "restore-subscriptions",
                "resource": {"targets": [NETWORK_HANDLER_PATTERN]},
                "params": {"peer_id": sess.peer_id},
                "dispatch_capability": ctx.handler_grant_hash,
            },
        )

    def _bind_continuation(
        self, ctx: HandlerContext, path: str, cont_data: dict[str, Any]
    ) -> None:
        entity = Entity(type="system/continuation", data=cont_data)
        uri = ctx.emit_pathway.entity_tree.normalize_uri(path)
        emit_ctx = EmitContext.from_handler_grant(ctx, "maintain-peer")
        result = ctx.emit_pathway.emit(uri, entity, emit_ctx)
        if result.status != 200:
            raise RuntimeError(
                f"bind continuation at {path}: emit status {result.status}"
            )

    async def _subscribe_lifecycle(
        self, ctx: HandlerContext, remote_hash: bytes, deliver_uri: str
    ) -> str | dict[str, Any]:
        """Create one lifecycle subscription on the remote's status path
        delivering to ``deliver_uri``. Returns the subscription id, or an
        error-response dict.

        The deliver token is self-granted (granter == grantee == the local
        peer — the self-owned-namespace pattern) with **no expiry**: the
        lifecycle subscriptions must survive arbitrarily long disconnects;
        release-peer is the deliberate teardown.
        """
        identity_entity = create_identity_entity(self._keypair)
        token_entity, granter_identity, sig_entity = create_capability_token(
            self._keypair,
            identity_entity,
            [
                Grant.create(
                    # Both the bare handler pattern and its subtree: the
                    # subscribe-time token check matches the handler as
                    # "system/inbox" and the resource as the exact
                    # deliver URI.
                    handlers=["system/inbox", "system/inbox/*"],
                    resources=[deliver_uri, deliver_uri + "/*"],
                    operations=["receive"],
                ),
            ],
            expires_in_ms=None,
        )
        # Persist token + authority chain so subscribe-time validation and
        # async delivery-time re-validation can resolve them by hash.
        for ent in (token_entity, granter_identity, sig_entity):
            ctx.emit_pathway.put_content_only(ent)

        status_path = liveness.peer_status_path(remote_hash)
        # Self-authored dispatch: pin the author to the LOCAL peer.
        #
        # This subscribe is the handler's own bookkeeping — the deliver
        # target is this peer's own inbox and the deliver_token above is
        # self-granted (granter == grantee == local peer), so the subscriber
        # that EXTENSION-SUBSCRIPTION §3.1's SB1 creator-authority check
        # sees MUST be this peer. A plain `ctx.execute` would instead
        # inherit the *inbound caller's* identity (the V7 §6.8 propagation
        # default seeded by the dispatcher), which is absent from the
        # self-granted token's authority chain — so every remote-driven
        # maintain-peer 403s `embedded_cap_unauthorized` here while
        # local-driven ones pass. release-peer already unsubscribes these as
        # the local identity (§4.2), so local-peer authorship is also what
        # keeps subscribe/unsubscribe ownership symmetric.
        result = await ctx.execute_with_capability(
            "system/subscription",
            "subscribe",
            {
                "type": "system/subscription/request",
                "data": {
                    "pattern": status_path,
                    # The floor's demotion/establish writes are same-path
                    # overwrites — every transition surfaces as "updated"
                    # (first-ever write as "created", covered too).
                    "events": ["created", "updated"],
                    "deliver_to": {"uri": deliver_uri, "operation": "receive"},
                    "deliver_token": token_entity.compute_hash(),
                },
            },
            resource_targets=[status_path],
            # Author: the §3.1 SB1 creator-authority check reads
            # ctx.remote_identity_hash.
            propagated_author_peer_id=ctx.local_peer_id,
            propagated_author_identity_hash=_local_identity_hash(self._keypair),
            # Caller cap: §5.3 records subscriber_identity from
            # ctx.caller_capability["grantee"] — a *different* source than
            # the SB1 check above. The handler grant is self-granted
            # (granter == grantee == local identity), so riding it here is
            # what makes these subscriptions genuinely self-owned rather
            # than owned by whichever remote happened to drive maintain-peer
            # (which would then bind release-peer to that same caller).
            propagated_caller_capability=ctx.handler_grant,
        )
        if not result.ok:
            # Surface the upstream status/code rather than collapsing every
            # failure into a 500 — an authorization refusal is a 403, and
            # masking it as internal_error hides the actual cause.
            code, message = _upstream_error(result)
            return error_response(
                result.status, code,
                f"lifecycle subscribe for {deliver_uri} failed: {message}",
            )
        sub_id = None
        if isinstance(result.result, dict):
            data = result.result.get("data")
            if isinstance(data, dict):
                sub_id = data.get("subscription_id")
        if not sub_id:
            return error_response(
                500, "internal_error",
                "lifecycle subscribe result carried no subscription_id",
            )
        return sub_id

    # -- backoff retry loop ------------------------------------------------------

    def _arm_backoff_retry(
        self, ctx: HandlerContext, sess: _MaintainSession
    ) -> None:
        """Schedule the next delayed advance of the standing backoff
        continuation, per the session's §2.2 backoff config.

        No re-install: the continuation is standing (ruling 1), so it survives
        its own advance. The re-install this used to do was the one-shot's
        self-re-arm — the very write that lost the race with the consume.
        """
        failing_since = self._resolve_failing_since(ctx, sess)
        self._schedule_backoff_advance(sess, failing_since)

    def _resolve_failing_since(
        self, ctx: HandlerContext, sess: _MaintainSession
    ) -> int:
        """The §2 episode start driving the derived retry pacing.

        The TREE's ``failing_since`` (stamped by the demotion seam) wins: it is
        durable, so a process restarting beside a long-dead peer re-derives the
        curve. Absent (a peer that has NEVER connected made no demotion
        transition), the in-memory session copy is the fallback — opened now on
        the first failure with no episode on record. Keeps the two in sync so a
        later restart still prefers the tree once one exists.
        """
        tree_fs = liveness.read_peer_status_failing_since(
            ctx.emit_pathway.entity_tree,
            ctx.emit_pathway.content_store,
            sess.remote_hash,
        )
        if tree_fs is not None:
            sess.failing_since = tree_fs
            return tree_fs
        if sess.failing_since is None:
            sess.failing_since = liveness.now_ms()
        return sess.failing_since

    def _schedule_backoff_advance(
        self, sess: _MaintainSession, failing_since: int
    ) -> None:
        """Start (or replace) the session's retry timer: at the DERIVED
        ``next_attempt_at``, self-advance the backoff continuation, which
        one-shot re-EXECUTEs maintain-peer. The advance is a self-authored
        dispatch — there is no request context alive when the timer fires.

        Pacing is derived from ``(failing_since, cfg, now)`` (§2), never a
        stored counter: ``next_attempt_at`` is a fixed offset from the episode
        start, so the wait is a question about elapsed time. An OPTIONAL §2.2
        bound (``max_attempts``/``max_elapsed_ms``) reaching its limit stops the
        loop; the default config is retry-forever and never does."""
        now = liveness.now_ms()
        state = derive_retry_state(sess.params.get("backoff"), failing_since, now)
        peer_id = sess.peer_id
        sess.cancel_retry()
        if state.exhausted:
            # §2.2 give-up bound reached — abandon the retry loop (terminal).
            # Writing the §A2 `reason: retry-exhausted` terminal status is the
            # OPTIONAL Group-B follow-up; the load-bearing behaviour is that we
            # STOP rather than hammer. Unreachable under the retry-forever
            # default (max_attempts/max_elapsed_ms unset).
            logger.debug(
                "reconnect %s: §2.2 retry bound reached after %d attempt(s) "
                "(failing_since=%d) — giving up",
                peer_id[:16], state.attempt, failing_since,
            )
            return
        delay_s = max(0.0, (state.next_attempt_at - now) / 1000.0)
        logger.debug(
            "reconnect %s: %d attempt(s) fired since failing_since=%d, "
            "next retry in %.3fs",
            peer_id[:16], state.attempt, failing_since, delay_s,
        )

        async def _fire() -> None:
            await asyncio.sleep(delay_s)
            # Session may have been released while the timer was pending.
            if self._sessions.get(peer_id) is not sess:
                return
            if self._execute is None:
                return
            try:
                result = await self._execute(
                    "system/continuation",
                    "advance",
                    {"type": "system/continuation/advance-request", "data": {}},
                    resource_targets=[backoff_path(peer_id)],
                    # STANDING-MODEL §3: the retry timer firing is a reactive
                    # owner-poke (a timer delivery advancing the peer's own
                    # backoff continuation), not an administrative operator
                    # invoke — there is no request context alive when the timer
                    # fires. Declared reactive so it advances under the
                    # continuation's own dispatch_capability. (Go left its
                    # `selfExecute` unmarked because it already holds its own
                    # path cap; Python declares it reactive — the consistency
                    # follow-up Go's scope note names — so the owner-poke is not
                    # subject to the administrative caller-cap check.)
                    reactive_trigger=True,
                )
                if not result.ok:
                    logger.debug(
                        "reconnect %s: backoff advance returned %d: %s",
                        peer_id[:16], result.status, result.error,
                    )
            except Exception as e:  # noqa: BLE001
                logger.debug(
                    "reconnect %s: backoff advance dispatch: %s",
                    peer_id[:16], e,
                )

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:  # pragma: no cover - handler always runs in a loop
            return
        sess.retry_task = loop.create_task(_fire())

    # -- internal ops (§A5: advertised because the graph dispatches them) -------

    async def _handle_reconnect(
        self, params: dict[str, Any], ctx: HandlerContext
    ) -> dict[str, Any]:
        """The operation the on-disconnect continuation dispatches. The
        lifecycle subscription fires on EVERY status transition (including
        the establish's own ``connected`` write), so the operation is
        guarded: already-connected is a 200 no-op."""
        peer = self._peer
        if peer is None:
            return error_response(
                500, "internal_error", "network handler not bound to a peer"
            )
        peer_id = params.get("peer_id")
        if not peer_id:
            return error_response(400, "invalid_params", "params require peer_id")
        sess = self._sessions.get(peer_id)
        if sess is None:
            return error_response(
                404, "not_found", f"no maintain session for peer {peer_id}"
            )

        if self._read_peer_status(ctx, sess) == liveness.STATUS_CONNECTED:
            return ok_response("primitive/any", {"outcome": "already-connected"})

        try:
            await peer.ensure_connected(peer_id)
        except Exception as e:
            # Schedule the paced retry, then surface 502 — the advancing
            # continuation has no on_error, so this binds the §3.10
            # lost-error marker (reason connection_failed) as the
            # observability record.
            if sess.reconnect_enabled():
                try:
                    self._arm_backoff_retry(ctx, sess)
                except Exception as arm_err:  # noqa: BLE001
                    logger.warning(
                        "reconnect %s: arm backoff failed: %s",
                        peer_id[:16], arm_err,
                    )
            return error_response(
                502, "connection_failed", f"reconnect to {peer_id}: {e}"
            )
        # Recovery: close the failure episode (see the maintain-peer clear).
        sess.failing_since = None
        return ok_response("primitive/any", {"outcome": "reconnected"})

    async def _handle_restore_subscriptions(
        self, params: dict[str, Any], ctx: HandlerContext
    ) -> dict[str, Any]:
        """The internal §7.2 operation the on-reconnect continuation
        dispatches. Guarded on connected (the subscription also fires on
        demotion transitions).

        Scope (rung 3, cohort-converged): the §7.2 FIRST half — re-validate
        the deliver tokens of tree-resident subscriptions whose delivery
        targets the reconnected peer, dropping dead ones (token missing or
        expired). The notification engine reads subscriptions + tokens from
        the tree/index at delivery time, so surviving entries resume
        delivering with no further re-registration. The §7.2 second half
        (re-subscribing on the REMOTE peer) requires a local record of
        outbound subscriptions that no impl keeps yet — flagged upstream
        (Go spec-issue 6), not papered over.

        Dead subscriptions are dropped by a handler-authorized tree delete
        (the §7.2 pseudocode's ``entity_tree.put(sub_path, null)``) rather
        than the ``unsubscribe`` op: the subscriber of a subscription
        delivering TO the remote peer is the REMOTE identity, and the
        unsubscribe op correctly enforces subscriber-ownership.
        """
        peer_id = params.get("peer_id")
        if not peer_id:
            return error_response(400, "invalid_params", "params require peer_id")
        sess = self._sessions.get(peer_id)
        if sess is None:
            return error_response(
                404, "not_found", f"no maintain session for peer {peer_id}"
            )
        if self._read_peer_status(ctx, sess) != liveness.STATUS_CONNECTED:
            return ok_response(
                "primitive/any",
                {"outcome": "not-connected", "retained": 0, "dropped": 0},
            )

        tree = ctx.emit_pathway.entity_tree
        store = ctx.emit_pathway.content_store
        now_ms = int(time.time() * 1000)
        retained, dropped = 0, 0
        emit_ctx = EmitContext.from_handler_grant(ctx, "restore-subscriptions")
        for uri in tree.list_prefix("system/subscription/"):
            h = tree.get(uri)
            ent = store.get(h) if h is not None else None
            if ent is None or ent.type != "system/subscription":
                continue
            deliver_uri = ent.data.get("deliver_uri", "")
            if not _delivery_targets_peer(deliver_uri, peer_id):
                continue
            token = store.get(ent.data.get("deliver_token"))
            alive = token is not None
            if alive:
                expires_at = token.data.get("expires_at")
                if expires_at is not None and expires_at < now_ms:
                    alive = False
            if alive:
                retained += 1
                continue
            # Token expired or missing during the disconnect — the
            # subscription is dead (§7.2); remove it so the engine stops
            # attempting it.
            ctx.emit_pathway.delete(uri, emit_ctx)
            dropped += 1
        logger.debug(
            "restore-subscriptions %s: %d retained, %d dropped",
            peer_id[:16], retained, dropped,
        )
        return ok_response(
            "primitive/any",
            {"outcome": "restored", "retained": retained, "dropped": dropped},
        )

    # -- §4.2 release-peer -------------------------------------------------------

    async def _handle_release_peer(
        self, params: dict[str, Any], ctx: HandlerContext
    ) -> dict[str, Any]:
        """§4.2: tear down the lifecycle graph and, on reason=shutdown,
        close the connection with a terminal ``disconnected`` write."""
        peer = self._peer
        if peer is None:
            return error_response(
                500, "internal_error", "network handler not bound to a peer"
            )
        peer_id = params.get("peer_id")
        if not peer_id:
            return error_response(
                400, "invalid_params", "release-request requires peer_id"
            )
        reason = params.get("reason") or "shutdown"

        # Stop the retry timer and forget the session first — a timer firing
        # mid-teardown must find no session and bail.
        sess = self._drop_session(peer_id)

        # Remove the lifecycle continuations — the inbox residents and the
        # managed-namespace backoff resident. Real tree deletion (the §4.2
        # pseudocode's `put null`); deletion markers are the tree layer's.
        tree = ctx.emit_pathway.entity_tree
        emit_ctx = EmitContext.from_handler_grant(ctx, "release-peer")
        local_prefix = f"/{ctx.local_peer_id}/"
        cleaned_up: list[str] = []
        for prefix in (_inbox_prefix(peer_id), _managed_prefix(peer_id)):
            for uri in list(tree.list_prefix(prefix)):
                ctx.emit_pathway.delete(uri, emit_ctx)
                bare = uri[len(local_prefix):] if uri.startswith(local_prefix) else uri
                cleaned_up.append(bare)

        # Remove the lifecycle subscriptions (self-owned — the unsubscribe
        # rides the handler grant, whose grantee is the local identity, the
        # same identity that subscribed). The pinning must mirror
        # _subscribe_lifecycle exactly: §3.2 checks the caller cap's grantee
        # against the recorded subscriber_identity, so letting the dispatcher
        # seed the *inbound caller's* cap here would 403 not_subscription_owner
        # whenever release-peer is driven by anyone but the original subscriber.
        if sess is not None:
            for sub_id in sess.subscription_ids:
                result = await ctx.execute_with_capability(
                    "system/subscription",
                    "unsubscribe",
                    {
                        "type": "system/subscription/cancel",
                        "data": {"subscription_id": sub_id},
                    },
                    propagated_author_peer_id=ctx.local_peer_id,
                    propagated_author_identity_hash=_local_identity_hash(self._keypair),
                    propagated_caller_capability=ctx.handler_grant,
                )
                if not result.ok:
                    logger.warning(
                        "release-peer %s: unsubscribe %s returned %d",
                        peer_id[:16], sub_id, result.status,
                    )

        # Close the connection on shutdown; idle/migration leave it (and any
        # subscriptions) for potential resumption (§4.2).
        if reason == "shutdown":
            peer.evict_remote_connection(peer_id)
            remote_hash = (
                sess.remote_hash if sess is not None
                else _remote_identity_hash(peer_id)
            )
            if remote_hash:
                # Terminal §3.13 write: this relationship is deliberately
                # over. Eviction alone would leave the last transition value
                # standing. `local-release` is the §A2 additive OPTIONAL
                # reason (readers MUST-ignore-unknown).
                liveness.write_peer_status(
                    ctx.emit_pathway,
                    local_peer_id=ctx.local_peer_id,
                    remote_peer_id=peer_id,
                    remote_identity_hash=remote_hash,
                    status=liveness.STATUS_DISCONNECTED,
                    reason=liveness.REASON_LOCAL_RELEASE,
                )
                liveness.mark_connection_closed(
                    ctx.emit_pathway,
                    ctx.emit_pathway.content_store,
                    tree,
                    remote_hash,
                )

        return ok_response(
            "system/network/release-result",
            {"peer_id": peer_id, "cleaned_up": cleaned_up},
        )

    # -- §4.3 status ---------------------------------------------------------------

    async def _handle_status(self, ctx: HandlerContext) -> dict[str, Any]:
        """§4.3: a read-model over the §3.13 ``system/peer/status`` entities
        plus session bookkeeping. ``pending_count`` is bare zero throughout —
        no §8 outbox is shipped (Amendment 11; rung 4 stays optional)."""
        tree = ctx.emit_pathway.entity_tree
        store = ctx.emit_pathway.content_store

        # Subscription counts per delivery peer, one scan.
        sub_counts: dict[str, int] = {}
        for uri in tree.list_prefix("system/subscription/"):
            h = tree.get(uri)
            ent = store.get(h) if h is not None else None
            if ent is None or ent.type != "system/subscription":
                continue
            pid = _peer_from_deliver_uri(ent.data.get("deliver_uri", ""))
            if pid:
                sub_counts[pid] = sub_counts.get(pid, 0) + 1

        peers: list[dict[str, Any]] = []
        for uri in tree.list_prefix(liveness.PEER_STATUS_PATH_PREFIX + "/"):
            h = tree.get(uri)
            ent = store.get(h) if h is not None else None
            if ent is None or ent.type != "system/peer/status":
                continue
            pid = ent.data.get("peer_id", "")
            sess = self._sessions.get(pid)
            peers.append(
                {
                    "peer_id": pid,
                    "session_id": sess.session_id if sess is not None else "",
                    "status": ent.data.get("status", ""),
                    "pending_count": 0,
                    "subscriptions": sub_counts.get(pid, 0),
                }
            )

        return ok_response(
            "system/network/status",
            {"maintained_peers": peers, "pending_count": 0},
        )

    # -- §4.4 close ------------------------------------------------------------------

    async def _handle_close(
        self, params: dict[str, Any], ctx: HandlerContext
    ) -> dict[str, Any]:
        """§4.4: best-effort remote close notification, then the local §3.13
        close transition. Subscription disposition follows the reason (§9.1):
        shutdown expects the remote to drop its subscriptions; idle/migration
        preserve them — locally there is nothing to delete on either branch
        (release-peer owns lifecycle teardown)."""
        peer = self._peer
        if peer is None:
            return error_response(
                500, "internal_error", "network handler not bound to a peer"
            )
        peer_id = params.get("peer_id")
        reason = params.get("reason")
        if not peer_id or not reason:
            return error_response(
                400, "invalid_params", "close-request requires peer_id and reason"
            )

        # Best-effort remote close notification (§9.2). The cohort's connect
        # layers predate a `close` operation — an unknown-operation error (or
        # a dead transport) must not block the local close.
        if peer.is_connected(peer_id):
            try:
                await ctx.execute(
                    f"entity://{peer_id}/system/protocol/connect",
                    "close",
                    {
                        "type": "system/network/close-request",
                        "data": {"peer_id": peer_id, "reason": reason},
                    },
                )
            except Exception as e:  # noqa: BLE001
                logger.debug(
                    "close %s: remote notification failed (best-effort): %s",
                    peer_id[:16], e,
                )

        # Local transition: evict the pooled binding (its keepalive loop
        # exits with it) and record the §3.13 close.
        peer.evict_remote_connection(peer_id)
        remote_hash = _remote_identity_hash(peer_id)
        if remote_hash:
            liveness.mark_connection_closed(
                ctx.emit_pathway,
                ctx.emit_pathway.content_store,
                ctx.emit_pathway.entity_tree,
                remote_hash,
            )

        return ok_response("primitive/any", {"closed": True, "reason": reason})

    # -- helpers ---------------------------------------------------------------------

    def _read_peer_status(
        self, ctx: HandlerContext, sess: _MaintainSession
    ) -> str | None:
        """Current §3.13 status value for the session's peer, if written."""
        tree = ctx.emit_pathway.entity_tree
        h = tree.get(tree.normalize_uri(liveness.peer_status_path(sess.remote_hash)))
        if h is None:
            return None
        ent = ctx.emit_pathway.content_store.get(h)
        if ent is None:
            return None
        return ent.data.get("status")


def _remote_identity_hash(peer_id: str) -> bytes | None:
    """The remote's ``system/peer`` content hash — the §3.13 status-path
    key (V7 v7.64 §1.4). Derivable locally for identity-multihash form
    PeerIDs; ``None`` for SHA-256-form (public key needed out-of-band)."""
    derived = derive_peer_from_peer_id(peer_id)
    if derived is None:
        return None
    return compute_peer_identity_hash(peer_id, derived[0])


def _delivery_targets_peer(deliver_uri: str, peer_id: str) -> bool:
    """Whether a subscription's deliver URI routes to the given remote peer
    (§7.2: ``entity://{peer_id}/...``)."""
    return deliver_uri.startswith(f"entity://{peer_id}/") or (
        deliver_uri == f"entity://{peer_id}"
    )


def _peer_from_deliver_uri(uri: str) -> str | None:
    """Extract the peer id from an ``entity://{peer}/...`` URI."""
    scheme = "entity://"
    if not uri.startswith(scheme):
        return None
    rest = uri[len(scheme):]
    slash = rest.find("/")
    if slash > 0:
        return rest[:slash]
    return rest or None
