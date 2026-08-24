"""EXTENSION-NETWORK §4.1 — does the reconnect retry loop actually survive?

Independent confirmation of Go's cross-impl finding (their ask #1 in
`entity-core-go/docs/validation/reports/2026-07-16-retry-survival-cohort.md`):
against a peer that stays dead, the reconnect loop fires ~2 dials and then
stops — silently, no marker, no error, status 200. A neighbour that comes back
a minute later is never recovered. Go measured 2 dials / 25s on OUR wire (and
Rust's, and their own pre-fix) without reading our source; this reproduces it
from our side, in-process.

Why the rung-3 suite never caught it: ``TestReconnectAnchor`` restarts the
counterpart promptly, so re-establishing needs exactly ONE retry — comfortably
inside the two the loop manages before dying. A test asserting that a peer
recovers cannot see that the loop recovering it has already stopped. The
category was honest; the question was absent. This file asks it.

Method mirrors Go's probe: count DIALS at a socket that has taken over the dead
peer's address. It assumes nothing about the handler's internals — every impl's
retry ends in a dial.

STATUS: FIXED — arch ruling 1 (`ROUTING-2026-07-16-arch-rulings-to-cohort.md`)
ruled the backoff continuation **STANDING** (``remaining_executions: null``),
and the loop now survives an indefinite outage.

The defect was ORDERING, not timing. §4.1's continuation was one-shot
(``remaining_executions: 1``) and the only thing re-installing it was the
maintain-peer the continuation itself dispatched, so the re-install landed
inside the dispatch while the consume ran after it — deleting the path out from
under the next advance. A one-shot cannot re-arm itself. Standing removes the
race rather than timing around it: pacing is the handler's timer, and the
continuation is only the dispatch vehicle.

This file was written BEFORE the ruling and deliberately did not fix what it
measured — ``test_retry_survives_outage`` was xfail(strict=True), holding the
shape the ruling would be implemented against, and it XPASSed the moment the
loop started surviving. That is the signal it was built to emit. The xfail is
now dropped and the vector asserts survival directly; the companion pin that
recorded the 2-dial stall shape is gone with the stall.
"""

from __future__ import annotations

import asyncio
import socket
import time

import pytest

from entity_core.crypto.identity import Keypair

from tests.integration.test_network_lifecycle import (
    _bound_port,
    _build_lifecycle_peer,
    _exec_network,
    _free_port,
)


class _DialCounter:
    """Takes over a dead peer's address and counts inbound connects.

    Accepts and immediately closes: the dial completes at TCP level, the
    handshake does not, so the client's connect attempt fails — exactly the
    shape of a peer that is gone but whose address is reachable. Counting
    inbound connects assumes nothing about the client's internals.
    """

    def __init__(self) -> None:
        self.dials = 0
        self._server: asyncio.AbstractServer | None = None

    async def take_over(self, port: int) -> None:
        async def _on_connect(reader, writer):
            self.dials += 1
            writer.close()

        self._server = await asyncio.start_server(_on_connect, "127.0.0.1", port)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


async def _count_dials_against_dead_peer(watch_s: float) -> tuple[int, float]:
    """maintain toward a counterpart, kill it, take over its address, count.

    Returns (dials, elapsed). Backoff is min_ms=50/max_ms=100 so the probe runs
    in ~`watch_s` rather than Go's 25s — the defect is in the loop's SHAPE, not
    its pacing, so a compressed curve exposes it identically. At this curve a
    surviving loop dials on the order of 20+ times in 2s; the stalled loop
    dials twice regardless of how long we watch.
    """
    server_kp, client_kp = Keypair.generate(), Keypair.generate()
    server = _build_lifecycle_peer(server_kp)
    # Short keepalive so the client notices the death promptly and demotes.
    client = _build_lifecycle_peer(
        client_kp, interval_ms=200, timeout_ms=100, max_missed=2
    )
    await server.start("127.0.0.1", _free_port())
    await client.start("127.0.0.1", _free_port())
    port = _bound_port(server)

    counter = _DialCounter()
    try:
        result = await _exec_network(
            client,
            "maintain-peer",
            {
                "peer_id": server.peer_id,
                "address": f"127.0.0.1:{port}",
                "backoff": {"min_ms": 50, "max_ms": 100, "strategy": "exponential"},
            },
            params_type="system/network/maintain-request",
        )
        assert result.status == 200, result.error

        # Kill the counterpart and take over its address. It never comes back.
        await server.stop()
        await asyncio.sleep(0.05)
        await counter.take_over(port)

        started = time.monotonic()
        await asyncio.sleep(watch_s)
        elapsed = time.monotonic() - started
        return counter.dials, elapsed
    finally:
        await counter.close()
        await client.stop()
        try:
            await server.stop()
        except Exception:
            pass


@pytest.mark.asyncio
async def test_retry_survives_outage() -> None:
    """A peer that stays dead MUST keep being retried — retry-forever is the
    normative default (§2.2 max_attempts / max_elapsed_ms are OPTIONAL and
    default unset), so the dials must not stop while the outage continues."""
    dials, elapsed = await _count_dials_against_dead_peer(watch_s=2.0)

    assert dials >= 4, (
        f"only {dials} reconnect dial(s) in {elapsed:.3f}s against a peer that "
        f"stayed dead; want >=4 at min_ms=50/max_ms=100. The retry loop stopped "
        f"while the outage was ongoing — the peer is never recovered, silently "
        f"(no marker, no error: the advance returns {{advanced: false}} with "
        f"status 200). See EXTENSION-NETWORK §4.1 backoff_continuation."
    )


@pytest.mark.asyncio
async def test_retry_loop_has_no_hidden_ceiling() -> None:
    """Retry-forever is normative (ruling 6): the loop must have NO bound the
    operator did not ask for.

    This replaces the defect-pin that recorded the 2-dial stall. That pin's job
    was to give the ruling a number and to fire when the count rose; both have
    happened, so pinning the old shape now would assert a bug we fixed. The
    property worth keeping is its inverse, and it is the one the stall violated:
    a longer outage must produce a longer retry sequence, with no ceiling.

    Watching ~3x longer must dial materially more. A count that plateaus means
    something is capping the loop — a resurrected self-clobber, an exhausted
    counter, a dead timer — which is exactly the class of silent stop that made
    the original defect survive a green 4/4 reconnect suite.
    """
    short_dials, _ = await _count_dials_against_dead_peer(watch_s=1.0)
    long_dials, elapsed = await _count_dials_against_dead_peer(watch_s=3.0)

    assert short_dials >= 1, (
        f"expected the reconnect lifecycle to fire at all; got {short_dials} "
        f"dials. Zero means the graph never reacted to the demotion — a "
        f"different (worse) defect than the stall this file was written for."
    )
    assert long_dials > short_dials, (
        f"a 3x longer outage produced {long_dials} dials vs {short_dials} over "
        f"1s ({elapsed:.3f}s watched) — the retry count PLATEAUED, so something "
        f"bounds the loop. Retry-forever means the sequence grows with the "
        f"outage; a ceiling here is the silent-stop class of defect."
    )
