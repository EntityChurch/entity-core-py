"""One side of a §4 step-2 rendezvous, as a process — Python's half of the
cross-process go↔py meet.

``PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH`` §3–§4.

**Why this exists.** Everything in ``test_signaling_rust_node.py`` puts *this*
client on both sides of the exchange, so the two convergence obligations (§2.2
which key, §3.1.1 which node) are satisfied trivially — both peers are the same
code. Go's 2026-07-30 report closed that statically: its client and this one
derive byte-identical keys and select the same pool member for the same inputs
(pinned from this side in ``tests/unit/test_signaling_{key,pool}.py``). What is
still missing, and what its §D names as the last piece, is a **live meet between
two implementations** — and Go's validator spawns both of its peers in-process,
so the other side has to arrive as a separate process.

This is that process. It plays exactly one role of one exchange against one node
and prints a JSON line, so a harness in any language can drive it::

    uv run python tests/interop/signaling_meet.py \\
        --node 127.0.0.1:4050 --role responder --mode tag --input chess-42

    {"ok": true, "role": "responder", "peer_id": "...", "key": "004138…",
     "answered": ["<nonce-hex>"], "candidates": [...]}

The two roles have deliberately different exit contracts. The **initiator** exits
0 only if it was answered — a real meet — and returns as soon as it is. The
**responder** is a server: it answers everything for the whole ``--timeout`` and
exits 0 if it answered at least one request, which is weaker on purpose (see
:func:`run_responder`). A driver proves the meet by pairing the two: the
initiator exited 0 *and* its nonce appears in the responder's ``answered``.

The ``key`` field is deliberately in the output. If two impls fail to meet, the
first question is whether they derived the same 33 bytes, and it should be
answerable by diffing two log lines rather than by instrumenting either side.

Both roles are **rerun-safe** on a stable key inside the TTL: the responder
answers every request in the bucket that is not its own (``find_requests``) and
keeps serving to its deadline, and the initiator correlates strictly by its own
nonce. Neither rule is decoration — see :func:`run_responder` for the two ways a
rerun broke before they were in place.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import Any

from entity_core.crypto.identity import Keypair
from entity_core.peer.connection import Connection
from entity_core.sdk.dispatcher import ConnectionDispatcher
from entity_handlers.signaling import (
    Candidate,
    ConnectRequest,
    SignalingClient,
    find_requests,
    find_response,
    lobby_key,
    pair_key,
    secret_key,
    tag_key,
)

#: Poll interval. The node is a plain store — there is no notification — so both
#: roles poll, which is what §4 step 2 assumes.
POLL_SECONDS = 0.2

INITIATOR_CANDIDATES = [
    Candidate("host", "tcp", "192.168.1.10:9000", 0),
    Candidate("srflx", "tcp", "203.0.113.7:41234", 0),
]
RESPONDER_CANDIDATES = [
    Candidate("host", "tcp", "192.168.1.11:9000", 0),
]


def derive_key(mode: str, value: str) -> bytes:
    """Derive the rendezvous key for ``mode``/``value`` (§2.2).

    ``pair`` takes the two peer-ids separated by a comma — the canonicalization
    sorts them, so either side may pass them in either order.
    """
    if mode == "tag":
        return tag_key(value)
    if mode == "secret":
        return secret_key(value)
    if mode == "lobby":
        return lobby_key(value)
    if mode == "pair":
        peer_a, _, peer_b = value.partition(",")
        if not peer_b:
            raise SystemExit("--input for mode 'pair' must be 'peer-a,peer-b'")
        return pair_key(peer_a, peer_b)
    raise SystemExit(f"unknown --mode {mode!r}")


async def run_initiator(
    client: SignalingClient, key: bytes, peer_id: str, deadline: float
) -> dict[str, Any]:
    """Offer a ``connect-request`` and wait for the response echoing our nonce."""
    nonce = await client.initiate(key, peer_id, INITIATOR_CANDIDATES)
    while time.monotonic() < deadline:
        bucket = await client.collect_messages(key)
        response = find_response(bucket, nonce, peer_id)
        if response is not None:
            return {
                "ok": True,
                "nonce": nonce.hex(),
                "responder": response.responder,
                "candidates": [c.address for c in response.candidates],
            }
        await asyncio.sleep(POLL_SECONDS)
    return {
        "ok": False,
        "nonce": nonce.hex(),
        "error": "no response echoing our nonce before the deadline",
    }


async def run_responder(
    client: SignalingClient, key: bytes, peer_id: str, deadline: float
) -> dict[str, Any]:
    """Answer every request in the bucket that is not ours, **for the whole
    deadline** — the responder is a server, and ``--timeout`` is how long it
    serves.

    Two rules, and both were learned from a failing rerun rather than reasoned
    out in advance:

    - **Answer all, not the first.** On a stable ``pair``/``lobby`` key the
      bucket still holds the previous run's request inside the 60 s TTL, and the
      peer waiting *now* is not necessarily the oldest entry. The extra reply
      costs one ``offer``, and an initiator whose nonce it does not echo simply
      discards it.
    - **Do not exit at the first answer.** Answering the backlog and leaving is
      answer-first wearing a different hat: on a rerun the responder empties the
      stale requests, exits 0 having "answered a request", and the initiator that
      started a moment later is never answered. Reproduced live, twice, before
      this loop was made to run to its deadline.

    So the exit status alone means "I served and answered at least one" — which
    is deliberately *weaker* than "we met". The proof of a meet is the
    initiator's status plus its nonce appearing in ``answered`` here; a driver
    should check that pair, not this status alone.
    """
    answered: list[ConnectRequest] = []
    seen: set[bytes] = set()
    while time.monotonic() < deadline:
        bucket = await client.collect_messages(key)
        for request in find_requests(bucket, peer_id):
            if request.nonce in seen:
                continue
            seen.add(request.nonce)
            await client.respond(key, peer_id, request, RESPONDER_CANDIDATES)
            answered.append(request)
        await asyncio.sleep(POLL_SECONDS)

    if answered:
        return {
            "ok": True,
            "answered": [r.nonce.hex() for r in answered],
            "initiators": [r.initiator for r in answered],
            "candidates": [c.address for r in answered for c in r.candidates],
        }
    return {
        "ok": False,
        "answered": [],
        "initiators": [],
        "error": "no request to answer before the deadline",
    }


async def meet(args: argparse.Namespace) -> dict[str, Any]:
    host, _, port = args.node.partition(":")
    conn = await Connection.connect(
        host, int(port), Keypair.generate(), wait_for_capability=True
    )
    try:
        peer_id = conn.session.local_peer_id
        client = SignalingClient(
            ConnectionDispatcher(conn), conn.session.remote_peer_id
        )
        # `pair` needs both peer-ids, and ours is only known once connected —
        # so a driver passes "…,<our-peer-id>" or substitutes the placeholder.
        value = args.input.replace("SELF", peer_id)
        key = derive_key(args.mode, value)
        deadline = time.monotonic() + args.timeout

        run = run_initiator if args.role == "initiator" else run_responder
        outcome = await run(client, key, peer_id, deadline)
        return {
            "role": args.role,
            "peer_id": peer_id,
            "node_peer_id": conn.session.remote_peer_id,
            "mode": args.mode,
            "input": value,
            "key": key.hex(),
            **outcome,
        }
    finally:
        conn.close()
        await conn.wait_closed()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--node", required=True, help="host:port of the connection node")
    parser.add_argument("--role", required=True, choices=("initiator", "responder"))
    parser.add_argument("--mode", required=True, choices=("tag", "secret", "lobby", "pair"))
    parser.add_argument(
        "--input",
        required=True,
        help="the mode's input; 'pair' takes 'peer-a,peer-b' and the literal "
        "SELF is replaced with this process's peer-id once connected",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args(argv)

    result = asyncio.run(meet(args))
    print(json.dumps(result))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
