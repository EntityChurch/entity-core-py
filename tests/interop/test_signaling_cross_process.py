"""The cross-process meet — two peer *processes* rendezvous through one node.

``PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH`` §4 step 2.

Every other test in this directory runs both sides of the exchange in one
process, sharing this client's code — so the two obligations that fail silently
(§2.2 which key, §3.1.1 which node) are satisfied by construction rather than
demonstrated. Go's 2026-07-30 report closed the static half across impls: its
client and this one derive byte-identical keys and pick the same pool member
(pinned in ``tests/unit/test_signaling_{key,pool}.py``). Its §D names the
remaining piece as a live go↔py meet, which needs the two peers to be separate
processes, because Go's validator spawns both of its own in-process.

**This is that harness, with Python on both sides.** What it proves today is the
half that is ours to prove: :mod:`tests.interop.signaling_meet` is a correct,
rerun-safe, self-describing peer process, and its exit status and JSON line are a
contract another language can drive. Swapping either invocation for Go's
equivalent is then a change of one command, and the meet it produces is the real
cross-impl evidence.

It also covers something the in-process tests structurally cannot: the two peers
here share no objects, no keypair, and no memory — each connects, derives, and
polls on its own — so a convergence bug could actually show up as a failure to
meet rather than being papered over by a shared derivation.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.connection import Connection
from entity_handlers.signaling import tag_key
from tests.interop.signaling_meet import derive_key

NODE_A_PORT = int(os.environ.get("SIGNALING_NODE_A_PORT", "4050"))
MEET = Path(__file__).with_name("signaling_meet.py")

#: Generous enough that a slow machine does not produce a false negative, short
#: enough that a genuine never-meet fails the suite rather than hanging it. Well
#: inside the node's 60 s TTL either way.
TIMEOUT_SECONDS = 15.0

#: How long the responder *serves*. It runs to its deadline by design rather than
#: exiting at its first answer (see :func:`signaling_meet.run_responder`), so this
#: is the wall-clock cost of every meet below — kept short because the initiator
#: lands its request in milliseconds.
SERVE_SECONDS = 3.0


async def _node_admits_strangers(port: int) -> bool:
    """Same check the other interop module makes, kept local so this file can be
    run on its own."""
    try:
        conn = await asyncio.wait_for(
            Connection.connect(
                "127.0.0.1", port, Keypair.generate(), wait_for_capability=True
            ),
            timeout=2.0,
        )
    except (TimeoutError, OSError):
        return False
    try:
        response = await conn.execute(
            uri=f"entity://{conn.session.remote_peer_id}/system/signaling",
            operation="advertise",
            params={"type": "system/signaling/empty", "data": {}},
        )
        return int(response.status) == 200
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.fixture
async def open_node():
    if not await _node_admits_strangers(NODE_A_PORT):
        pytest.skip(
            f"needs an --open Rust signaling node at 127.0.0.1:{NODE_A_PORT} "
            f"(a node started closed refuses every call 403)"
        )


async def _spawn(
    role: str, mode: str, value: str, timeout: float = TIMEOUT_SECONDS
) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        sys.executable,
        str(MEET),
        "--node",
        f"127.0.0.1:{NODE_A_PORT}",
        "--role",
        role,
        "--mode",
        mode,
        "--input",
        value,
        "--timeout",
        str(timeout),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(Path(__file__).resolve().parents[2]),
    )


async def _await_json(proc: asyncio.subprocess.Process) -> tuple[int, dict]:
    stdout, stderr = await asyncio.wait_for(
        proc.communicate(), timeout=TIMEOUT_SECONDS + 20
    )
    assert stdout, f"peer process printed nothing; stderr:\n{stderr.decode()}"
    return proc.returncode, json.loads(stdout.decode().strip().splitlines()[-1])


async def _meet(mode: str, value: str) -> tuple[dict, dict]:
    """Run both roles concurrently and return their JSON results.

    The responder starts first only because it must be polling before the
    request lands to make a tight run; ordering is not load-bearing — ``collect``
    is non-destructive and the request stays in the bucket until the TTL, so
    either arrival order meets.
    """
    responder = await _spawn("responder", mode, value, timeout=SERVE_SECONDS)
    initiator = await _spawn("initiator", mode, value)

    (rc_r, out_r), (rc_i, out_i) = await asyncio.gather(
        _await_json(responder), _await_json(initiator)
    )
    assert rc_r == 0, f"responder did not meet: {out_r}"
    assert rc_i == 0, f"initiator did not meet: {out_i}"
    return out_i, out_r


@pytest.mark.parametrize("mode", ["tag", "secret", "lobby"])
async def test_two_processes_meet_at_every_shared_key_mode(open_node, mode: str):
    """Two peers that share nothing but the mode and the input find each other.

    ``lobby`` is the interesting one: its input is a pool constant, so the key is
    identical on every run and the bucket carries traffic from earlier runs. It
    passes only because the responder answers **all** pending requests and the
    initiator correlates by nonce — which is the rerun-safety property a gate
    needs.
    """
    value = "lobby:default" if mode == "lobby" else f"cross-process-{os.urandom(6).hex()}"
    initiator, responder = await _meet(mode, value)

    # Same 33 bytes, computed independently in two processes.
    assert initiator["key"] == responder["key"] == derive_key(mode, value).hex()
    # Two genuinely different peers, and each got the other's candidates.
    assert initiator["peer_id"] != responder["peer_id"]
    assert initiator["responder"] == responder["peer_id"]
    assert responder["initiators"] == [initiator["peer_id"]] or (
        initiator["peer_id"] in responder["initiators"]
    )
    assert initiator["nonce"] in responder["answered"]
    assert initiator["candidates"], "the initiator learned no address"


async def test_the_pair_mode_meets_with_the_peer_ids_in_either_order(open_node):
    """§2.2's sort-and-separate canonicalization, across two processes.

    Each side is handed the pair in the **opposite** order, so this fails unless
    both canonicalize before hashing — the failure mode being two peers that
    politely wait at two different keys.
    """
    peer_a, peer_b = "peerAAA-cross", "peerBBB-cross"
    responder = await _spawn(
        "responder", "pair", f"{peer_a},{peer_b}", timeout=SERVE_SECONDS
    )
    initiator = await _spawn("initiator", "pair", f"{peer_b},{peer_a}")

    (rc_r, out_r), (rc_i, out_i) = await asyncio.gather(
        _await_json(responder), _await_json(initiator)
    )
    assert rc_r == 0 and rc_i == 0, f"pair meet failed: {out_i} / {out_r}"
    assert out_i["key"] == out_r["key"]
    assert out_i["nonce"] in out_r["answered"]


async def test_a_peer_alone_at_a_key_fails_rather_than_reporting_success(open_node):
    """The harness must be able to *fail*.

    A never-meet is the failure this whole feature exists to prevent and it is
    silent by nature — every offer and collect succeeds, the peers simply are not
    in the same bucket. So a driver that trusts the exit status needs the exit
    status to be trustworthy: one peer at a key nobody else uses must exit
    non-zero, not time out green.
    """
    # A deliberately short deadline: this asserts the timeout *path*, and
    # waiting the full default would only be a test of our patience.
    proc = await _spawn(
        "initiator", "tag", f"nobody-answers-{os.urandom(6).hex()}", timeout=2.0
    )
    returncode, result = await _await_json(proc)
    assert returncode != 0
    assert result["ok"] is False
    assert "no response" in result["error"]


def test_the_harness_derives_keys_through_the_same_module_under_test():
    """Guard against the harness quietly growing its own derivation — which
    would make every meet above a test of itself."""
    assert derive_key("tag", "chess") == tag_key("chess")
