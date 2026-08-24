"""EXTENSION-NETWORK §6.7 reachability facts (Amendment 13).

§10 dispatches by reachability class, but a peer has no protocol way to learn
its **own** reachability facts — only the router knows what mapping a NAT
allocated, and it reveals it only implicitly, on outbound packets. §6.7 defines
the facts and stops there:

- ``observe-address`` (§6.7.1) — reflect the transport source of the connection
  the request arrived on. That observed source *is* the requester's public NAT
  mapping; R telling A what it saw is the whole mechanism.
- ``check-reachability`` (§6.7.2) — dial the requester's **own** observed source
  back and report whether it arrived.

**Both facts ride from the accepted connection, never from the request body.**
That is not a validation choice, it is the structure: ``ctx.observed_source_address``
is populated only by the accept-side dispatch path (``Peer._handle_connection``
→ ``PeerConnectionState.observed_address``), and these handlers read no address
from ``params`` at all. A handler that cannot reach a body-supplied address
cannot launder one:

- §6.7.1 MUST 1 — a body-supplied address makes the responder a laundering
  service for an attacker's chosen address.
- §6.7.2's load-bearing MUST — a body-supplied dial-back target turns every
  peer offering this into a DDoS reflector. Two conformant readings of "dial
  back the requester" diverge into a security hole *at the peer boundary*, and
  prose review does not catch it; this mirrors the STUN binding rule and
  libp2p AutoNAT's dial-back-to-observed-address-only.

**Never persisted (§6.7.1 MUST 2).** The observed address is read from the live
connection and returned. Nothing here writes it to ``system/connection.address``,
a ``system/peer/transport/*`` profile, or ``system/peer/status`` — those fields
mean *"the endpoint I dial to reach this peer"* and are written dialer-side. An
ephemeral NAT source port written there is a routable-**looking** value that
routes nowhere, and §10 and ``system/peer/status`` both consume that field as
dialable.

**The asymmetry in §6.7.4 is the whole security story.** Reflection is a mirror
— the requester learns only about itself, the response is one small address, so
a broad grant is reasonable. Dial-back **causes the responder to emit traffic at
an address**, so it is capability-restricted, rate-limited, fixed-size and
pinned to the observed source. Both are rate-limited; dial-back the more tightly.

Not built here, deliberately: §6.7.3 candidate *gathering* (the client half —
it belongs with the punch, which binds the gathered mapping to the socket it
punches from) and any exchange of candidates between peers, which is the
punch-coordination protocol and is not in this spec. §6.7.3's ``candidate``
*type* is registered, because a peer offering the section owes its types.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from entity_core.handlers.context import HandlerContext
from entity_handlers._common import error_response, ok_response

logger = logging.getLogger(__name__)

#: §6.7.1 / §6.7.2 operation names.
OP_OBSERVE_ADDRESS = "observe-address"
OP_CHECK_REACHABILITY = "check-reachability"

#: Result types (§6.7.1, §6.7.2).
TYPE_OBSERVE_ADDRESS_RESULT = "system/network/observe-address-result"
TYPE_CHECK_REACHABILITY_RESULT = "system/network/check-reachability-result"

#: §6.7.3 candidate typing. Ordering is `host` → `srflx` → `relay`: cheapest
#: first, and the first pair completing a connectivity check wins.
TYPE_CANDIDATE = "system/network/candidate"
CANDIDATE_HOST = "host"
CANDIDATE_SRFLX = "srflx"
CANDIDATE_RELAY = "relay"
#: Priority order for §6.7.3. Session-scoped: this is the ephemeral-candidate
#: analogue of §10's durable "(priority asc, profile-id lex)" profile order,
#: NOT an entry into `resolve_profiles` (§10 step 3 resolves durable profiles
#: only, and §6.7 changes nothing about the §10 pseudocode).
CANDIDATE_PRIORITY = {CANDIDATE_HOST: 0, CANDIDATE_SRFLX: 1, CANDIDATE_RELAY: 2}

#: §6.7.4 capability names. Named for discovery; the gate itself is the
#: ordinary capability path (denial is a 403, no new error code).
CAP_NETWORK_REFLECT = "system/capability/network-reflect"
CAP_NETWORK_DIALBACK = "system/capability/network-dialback"

#: Per-requester min-intervals (§6.7.4 — both operations are "always
#: rate-limited"; dial-back the more tightly, because it is the one that makes
#: this peer emit traffic). Matches Go's 200ms / 1s.
REFLECT_MIN_INTERVAL_S = 0.2
DIALBACK_MIN_INTERVAL_S = 1.0

#: Bound on one §6.7.2 probe. A bare TCP connect is the minimal zero-payload
#: "did it arrive" test — nothing is sent, so there is no amplification factor.
DIALBACK_TIMEOUT_S = 3.0


class RateLimiter:
    """Per-requester minimum-interval gate (§6.7.4).

    A local operational concern rather than a protocol-deterministic one, so
    it reads the wall clock directly. An empty requester (in-process dispatch)
    is never limited — there is no remote to limit.
    """

    def __init__(self, interval_s: float) -> None:
        self._interval_s = interval_s
        self._last: dict[str, float] = {}

    def allow(self, requester: str | None) -> bool:
        if not requester:
            return True
        now = time.monotonic()
        prev = self._last.get(requester)
        if prev is not None and (now - prev) < self._interval_s:
            return False
        self._last[requester] = now
        return True


def split_host_port(address: str) -> tuple[str, int] | None:
    """Split ``"host:port"`` / ``"[v6]:port"`` into its parts.

    Returns ``None`` for anything that is not a well-formed authority, so a
    caller answers rather than dialing a value it could not parse.
    """
    if not address:
        return None
    if address.startswith("["):
        close = address.rfind("]")
        if close == -1 or not address[close + 1:].startswith(":"):
            return None
        host, port_s = address[1:close], address[close + 2:]
    else:
        host, _, port_s = address.rpartition(":")
        if not host or ":" in host:  # bare/unbracketed v6 is ambiguous
            return None
    try:
        port = int(port_s)
    except ValueError:
        return None
    if not host or not (0 < port < 65536):
        return None
    return host, port


async def dial_back(address: str, timeout_s: float = DIALBACK_TIMEOUT_S) -> bool:
    """§6.7.2 probe: did a connection to ``address`` arrive?

    A bare TCP connect, closed immediately. Nothing is written, so the
    responder emits no more than the handshake itself — the fixed-size,
    no-amplification shape the §6.7.2 MUST requires.
    """
    parts = split_host_port(address)
    if parts is None:
        return False
    host, port = parts
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout_s,
        )
        return True
    except (OSError, TimeoutError):
        return False
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, TimeoutError):  # pragma: no cover
                pass


def requester_of(ctx: HandlerContext) -> str | None:
    """The peer to rate-limit against (§6.7.4, per-requester).

    The session peer holding the connection, falling back to the wire author's
    identity — placement identity first, as Go does.
    """
    remote = getattr(ctx, "remote_peer_id", None)
    if remote:
        return remote
    author = getattr(ctx, "author_identity_hash", None)
    return author.hex() if isinstance(author, bytes) else None


def observed_source_of(ctx: HandlerContext) -> str | None:
    """The accept-side transport source of the connection this request
    arrived on, or ``None`` for a dispatch that has no observable one."""
    return getattr(ctx, "observed_source_address", None) or None


class ReachabilityOps:
    """The two §6.7 operations, holding only their rate-limiter state."""

    def __init__(self) -> None:
        self._reflect_limiter = RateLimiter(REFLECT_MIN_INTERVAL_S)
        self._dialback_limiter = RateLimiter(DIALBACK_MIN_INTERVAL_S)

    async def handle_observe_address(self, ctx: HandlerContext) -> dict[str, Any]:
        """§6.7.1 — reflect the transport source of THIS connection.

        Params are not read at all. That is MUST 1 enforced by construction:
        there is no code path from the request body to the returned address.
        """
        if not self._reflect_limiter.allow(requester_of(ctx)):
            return error_response(
                429, "rate_limited",
                "observe-address is rate-limited per requester (§6.7.4)",
            )
        observed = observed_source_of(ctx)
        if observed is None:
            return error_response(
                400, "no_transport_source",
                "observe-address requires a live accepted connection; an "
                "in-process dispatch has no observable transport source",
            )
        return ok_response(
            TYPE_OBSERVE_ADDRESS_RESULT, {"observed_address": observed},
        )

    async def handle_check_reachability(self, ctx: HandlerContext) -> dict[str, Any]:
        """§6.7.2 — dial the requester's OWN observed source back.

        ``address_tested`` echoes the responder's own observation so the
        requester can confirm *which* address was proved rather than inferring
        it; the value is never one the requester supplied.
        """
        if not self._dialback_limiter.allow(requester_of(ctx)):
            return error_response(
                429, "rate_limited",
                "check-reachability is rate-limited per requester (§6.7.2 MUST)",
            )
        observed = observed_source_of(ctx)
        if observed is None:
            return error_response(
                400, "no_transport_source",
                "check-reachability requires a live accepted connection to dial back",
            )
        reachable = await dial_back(observed)
        return ok_response(
            TYPE_CHECK_REACHABILITY_RESULT,
            {"reachable": reachable, "address_tested": observed},
        )
