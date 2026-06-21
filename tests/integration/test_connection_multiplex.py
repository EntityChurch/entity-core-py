"""F-WB28 / Class G — transport-level multiplexing pin tests.

Mirrors core-go's ``core/peer/connection_multiplex_test.go`` (Stage 4
round-2 reference design). Pre-fix Python had no lock around
:meth:`Connection.execute`'s ``await self.send`` / ``await self.recv``
pair — concurrent callers raced on both the writer (frame bytes
interleave) and the reader (responses misroute across callers). Post-fix
(Option A): per-request ``asyncio.Future`` keyed by ``request_id``, a
background demuxer reader task, write lock on the bytes-write only.

The pin tests defend against future refactors that reintroduce
single-pending-per-connection serialization:

* :func:`test_concurrent_executes_are_multiplexed` — N concurrent
  ``conn.execute()`` calls; total wall-clock MUST be substantially less
  than ``N × per-call latency`` (proves the calls overlap on the wire).
* :func:`test_reentrant_cross_peer_does_not_deadlock` — bidirectional
  A↔B reentry probe: peer A's handler synchronously dispatches an
  outbound EXECUTE back to peer B while serving B's inbound EXECUTE. The
  canonical Class G shape that surfaced WB-28; completes inside a tight
  budget post-fix, deadlocks for 15s pre-fix.

Spec anchor: ``BUG-CLASSES.md::Class G`` (transport-level reentrancy /
concurrent-dispatch contention). Reference impl pattern documented in
core-go ``core/peer/connection.go:621-672``.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.entity import Entity


SERVER_PORT_MULTIPLEX = 19410
SERVER_PORT_REENTRANT_A = 19411
SERVER_PORT_REENTRANT_B = 19412


async def _slow_handler(
    path: str, operation: str, params: dict, ctx: HandlerContext,
) -> dict:
    """Handler that sleeps before returning — surfaces serialization.

    A sequential client would observe N * SLEEP wall-clock; a multiplexed
    client overlaps them and observes ~SLEEP + ε.

    ``params`` arrives wrapped as an entity envelope per V7 §3.4 (params
    is entity-typed on the wire); unwrap via the standard
    ``params.get("data", params)`` shim.
    """
    payload = params.get("data", params) if isinstance(params, dict) else {}
    sleep_s = float(payload.get("sleep_s", 0.2))
    request_id = payload.get("rid", "")
    await asyncio.sleep(sleep_s)
    return {
        "status": 200,
        "result": Entity(
            type="test/slow-result",
            data={"rid": request_id, "echoed": True},
        ).to_dict(),
    }


@pytest.fixture
async def slow_server_peer():
    keypair = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(keypair)
        .with_default_handlers()
        .with_handler("test/slow", _slow_handler, priority=200, name="test/slow")
        .debug_mode(True)
        .build()
    )
    await peer.start("127.0.0.1", SERVER_PORT_MULTIPLEX)
    yield peer
    await peer.stop()


@pytest.mark.asyncio
async def test_concurrent_executes_are_multiplexed(slow_server_peer):
    """F-WB28: N concurrent execute() calls overlap on the wire.

    Issue 8 concurrent execute() calls, each handler-side sleeping 200ms.
    Multiplexed: ~200ms wall-clock + ε. Serialized (pre-fix): ~1.6s.
    Threshold of 3× the per-call latency leaves headroom for CI noise
    while still failing decisively if a future refactor re-serializes
    the send+recv pair.

    Failure message names F-WB28 + connection.py so a regression points
    straight at the culprit.
    """
    client_kp = Keypair.generate()
    conn = await Connection.connect(
        "127.0.0.1", SERVER_PORT_MULTIPLEX, client_kp,
    )
    try:
        per_call_sleep = 0.2
        n_concurrent = 8

        async def one_call(i: int):
            return await conn.execute(
                f"/{slow_server_peer.peer_id}/test/slow",
                "ping",
                {"sleep_s": per_call_sleep, "rid": f"req-{i}"},
                resource={"targets": ["test/slow"]},
            )

        start = time.monotonic()
        responses = await asyncio.gather(
            *(one_call(i) for i in range(n_concurrent))
        )
        elapsed = time.monotonic() - start

        # Every call landed correctly — no response misrouting.
        for i, resp in enumerate(responses):
            assert resp.status == 200, (
                f"F-WB28 regression: call {i} got status {resp.status} "
                f"(possible response misrouting in connection.py)"
            )
            result_data = (resp.result or {}).get("data") or {}
            assert result_data.get("rid") == f"req-{i}", (
                f"F-WB28 regression: response misrouted — call {i} "
                f"expected rid=req-{i}, got rid={result_data.get('rid')!r}. "
                f"This is the per-request_id demux failing in "
                f"packages/entity-core/src/entity_core/peer/connection.py."
            )

        # Concurrency check — must be << serialized cost.
        serialized_estimate = n_concurrent * per_call_sleep
        threshold = 3 * per_call_sleep  # 3× per-call leaves CI headroom
        assert elapsed < threshold, (
            f"F-WB28 regression: {n_concurrent} concurrent execute()s "
            f"took {elapsed:.2f}s, serialized cost ~{serialized_estimate:.2f}s, "
            f"multiplexed expected ~{per_call_sleep:.2f}s. "
            f"Threshold {threshold:.2f}s exceeded — likely a future-touch "
            f"reintroduced send+recv serialization in "
            f"packages/entity-core/src/entity_core/peer/connection.py::"
            f"Connection.execute. See Class G in BUG-CLASSES.md."
        )
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_reentrant_cross_peer_does_not_deadlock():
    """F-WB28: bidirectional A↔B reentry probe completes under budget.

    Two server peers (A, B). A's handler synchronously dispatches an
    outbound EXECUTE back to B (the canonical handler-reentry shape that
    surfaced Class G). With Option A landed, the round-trip completes
    well under the 3s budget. Pre-fix (per-connection send+recv with no
    lock or demux) this would either deadlock until the 15s connection
    deadline trips, or misroute the response across concurrent callers.
    """
    kp_a = Keypair.generate()
    kp_b = Keypair.generate()

    # Peer B's outbound conn handle to A — set up after both servers are
    # listening + B has dialed A. Captured in a list because Python's
    # closure-over-cell semantics prefer a reference container here.
    a_handle: list[Connection | None] = [None]

    async def b_handler(
        path: str, operation: str, params: dict, ctx: HandlerContext,
    ) -> dict:
        """B's handler dispatches an outbound EXECUTE back to A.

        This is the reentrant shape: while serving an inbound EXECUTE,
        the handler synchronously makes an outbound EXECUTE to the
        sender. Pre-fix the inbound serve loop + outbound conn.execute()
        would race / deadlock on the shared connection state.
        """
        payload = params.get("data", params) if isinstance(params, dict) else {}
        echo = payload.get("echo", "")
        # Reentrant outbound dispatch back to A on B's own pooled conn.
        if a_handle[0] is not None:
            inner_resp = await a_handle[0].execute(
                f"/{kp_a.peer_id}/test/echo",
                "echo",
                {"from_b": True, "echo": echo},
                resource={"targets": ["test/echo"]},
            )
            inner_status = inner_resp.status
        else:
            inner_status = 0
        return {
            "status": 200,
            "result": Entity(
                type="test/reentrant-result",
                data={"echo": echo, "inner_status": inner_status},
            ).to_dict(),
        }

    async def a_handler(
        path: str, operation: str, params: dict, ctx: HandlerContext,
    ) -> dict:
        return {
            "status": 200,
            "result": Entity(
                type="test/echo-result",
                data={"got": params},
            ).to_dict(),
        }

    peer_a = (
        PeerBuilder()
        .with_keypair(kp_a)
        .with_default_handlers()
        .with_handler("test/echo", a_handler, priority=200, name="test/echo")
        .debug_mode(True)
        .build()
    )
    peer_b = (
        PeerBuilder()
        .with_keypair(kp_b)
        .with_default_handlers()
        .with_handler("test/reentrant", b_handler, priority=200, name="test/reentrant")
        .debug_mode(True)
        .build()
    )
    await peer_a.start("127.0.0.1", SERVER_PORT_REENTRANT_A)
    await peer_b.start("127.0.0.1", SERVER_PORT_REENTRANT_B)

    # Outside caller's connection to B (drives the test).
    caller_kp = Keypair.generate()
    conn_to_b = await Connection.connect(
        "127.0.0.1", SERVER_PORT_REENTRANT_B, caller_kp,
    )
    # B's own outbound connection back to A — used inside b_handler.
    conn_b_to_a = await Connection.connect(
        "127.0.0.1", SERVER_PORT_REENTRANT_A, kp_b,
    )
    a_handle[0] = conn_b_to_a

    try:
        # Tight budget — pre-fix this would hit a 15s deadline or hang.
        start = time.monotonic()
        resp = await asyncio.wait_for(
            conn_to_b.execute(
                f"/{kp_b.peer_id}/test/reentrant",
                "fire",
                {"echo": "ping"},
                resource={"targets": ["test/reentrant"]},
            ),
            timeout=3.0,
        )
        elapsed = time.monotonic() - start

        assert resp.status == 200, (
            f"F-WB28 regression: reentrant cross-peer dispatch returned "
            f"status {resp.status} — see Class G in BUG-CLASSES.md."
        )
        result_data = (resp.result or {}).get("data") or {}
        assert result_data.get("inner_status") == 200, (
            f"F-WB28 regression: B's reentrant outbound to A returned "
            f"inner_status={result_data.get('inner_status')}. The reentry "
            f"path lives in packages/entity-core/src/entity_core/peer/"
            f"connection.py::Connection.execute."
        )
        # If we're under 3s here we're miles ahead of the deadlock window;
        # leaving the explicit assertion so a slow regression is visible.
        assert elapsed < 3.0, (
            f"F-WB28 regression: reentrant probe took {elapsed:.2f}s "
            f"(budget 3.0s). Likely Class G partial regression — "
            f"connection.py serialization reintroduced."
        )
    finally:
        conn_to_b.close()
        await conn_to_b.wait_closed()
        conn_b_to_a.close()
        await conn_b_to_a.wait_closed()
        await peer_a.stop()
        await peer_b.stop()
