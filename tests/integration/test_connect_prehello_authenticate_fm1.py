"""FM-1 — an `authenticate` arriving before any hello nonce was issued.

§4.7 row 6 pins *"Nonce mismatch / absent / **pre-hello** (§4.6 step 1)"* to
**401 `invalid_nonce`**, and §4.7's closing paragraph says in terms that this
input is **not** the out-of-order row: a captured `authenticate` replayed onto
a fresh connection *is* a pre-hello `authenticate`, so it is an authentication
failure and not a malformed request. §4.6 step 1 and §4.2 (0.8.2.1) agree.

.. rubric:: What this peer did, and why the relayed remedy was not enough

`entity-core-go`'s FM-1 relay read our site correctly — the pre-hello branch is
`handle_connect_authenticate`'s opening phase check, one call frame *above* the
nonce comparison, which is why a search near the nonce logic misses it — and it
corrected the formalization census, which had us down as conformant by
fall-through. Measured here it is `400 bad_request`: the raise passes a message
only, and `ConnectError` defaults `code` to `bad_request`.

**The relayed fix was `code="invalid_nonce"` on that raise, described as
carrying a 401. In this tree it does not.** The wire boundary
(`Peer._handle_connect_execute`'s `except ConnectError`) called
`ExecuteResponse.bad_request(..., code=...)`, and `bad_request` hardcodes
`status=400` — the `code` keyword was only ever a *code* keyword. Applying the
relay as written yields `400 invalid_nonce`, which is in no §4.7 row either: a
non-conformant pair that reads as fixed, on a surface whose whole defect was a
non-conformant pair. So the status is asserted here beside the code, and the
refusal carries its status out of `ConnectError` rather than being re-derived
at the boundary.

Both are pinned because neither alone discriminates: a 401 alone does not
separate this from a post-hello nonce mismatch, and `invalid_nonce` alone is
what the incomplete fix produces.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import recv_envelope, send_envelope
from entity_core.protocol.messages import ExecuteResponse

PORT = 19083


@pytest.fixture
async def server_peer():
    peer = (
        PeerBuilder().with_keypair(Keypair.generate())
        .with_default_handlers().debug_mode(True).build()
    )
    await peer.start("127.0.0.1", PORT)
    yield peer
    await peer.stop()


async def _first_frame_authenticate(nonce: bytes) -> ExecuteResponse:
    """Send a well-formed `authenticate` as the very first frame — no hello."""
    from entity_core.handlers.connect import create_connect_authenticate_execute

    client_keypair = Keypair.generate()
    reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
    try:
        execute, sig_entity, identity_entity = create_connect_authenticate_execute(
            client_keypair, nonce,
        )
        await send_envelope(writer, Envelope(
            root=execute.to_entity(),
            included=[sig_entity.to_dict(), identity_entity.to_dict()],
        ))
        return ExecuteResponse.from_entity((await recv_envelope(reader)).root)
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_pre_hello_authenticate_is_401_invalid_nonce(server_peer: Peer):
    """The headline row. The nonce is a fresh CSPRNG value the peer never
    issued — which is the point: no hello preceded this frame, so there is no
    issued nonce for it to match."""
    response = await _first_frame_authenticate(os.urandom(32))

    assert response.status == 401, (
        f"a pre-hello `authenticate` answered status {int(response.status)}; "
        f"§4.7 row 6 pins it to 401 (it is an authentication failure, not a "
        f"malformed request — §4.7's closing paragraph excludes it from the "
        f"out-of-order row)"
    )
    assert response.result["data"]["code"] == "invalid_nonce", (
        f"code was {response.result['data']['code']!r}; §4.7 row 6 pins "
        f"`invalid_nonce`. A 401 with any other code is the half-fix: status "
        f"alone cannot separate this from a post-hello nonce mismatch"
    )


@pytest.mark.asyncio
async def test_the_code_alone_is_not_the_fix(server_peer: Peer):
    """The discriminator against the relayed remedy.

    `code="invalid_nonce"` on the raise, with the boundary left calling
    `bad_request`, produces `400 invalid_nonce` and passes the code assertion
    above while remaining in no §4.7 row. This row fails on exactly that
    intermediate state, so the two halves of the fix cannot be separated.
    """
    response = await _first_frame_authenticate(os.urandom(32))
    assert (int(response.status), response.result["data"]["code"]) == (
        401, "invalid_nonce",
    ), (
        "the (status, code) pair is the conformance unit here — `400 "
        "invalid_nonce` and `401 bad_request` are both non-conformant"
    )


@pytest.mark.asyncio
async def test_the_ordinary_handshake_still_completes(server_peer: Peer):
    """Teeth control. Without it, a peer that refuses every `authenticate`
    with 401 scores the rows above green."""
    from entity_core.peer.connection import Connection

    conn = await Connection.connect("127.0.0.1", PORT, Keypair.generate())
    try:
        assert conn.session.remote_peer_id == server_peer.peer_id
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_an_unknown_connect_operation_is_still_the_out_of_order_row(
    server_peer: Peer,
):
    """The other discriminator: §4.7's out-of-order row is unmoved.

    FM-1 carves the pre-hello `authenticate` **out** of that row; it does not
    empty it. A fix that maps every pre-complete connect failure to 401 would
    pass both rows above and silently take this one with it.

    Written as `status != 401`, which was all this row could say when the input
    answered `400 bad_request` — a code in no §4.7 row. It now asserts the pair
    (G-28/FM-1g), because a negative assertion is the shape that keeps passing
    while the thing it was watching goes empty: `!= 401` was equally satisfied
    by the non-conformant code it was written over. Status 400 is the table's;
    go emits 409 and routed the discrepancy as spec-issue `2026-09-01-b`. Full
    row family: `test_connect_error_table_4_7.py`.
    """
    from entity_core.protocol.messages import Execute

    reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
    try:
        await send_envelope(writer, Envelope(root=Execute(
            request_id="fm1-unknown-op",
            uri=f"entity://{server_peer.peer_id}/system/protocol/connect",
            operation="not-a-connect-operation",
            params={},
        ).to_entity()))
        response = ExecuteResponse.from_entity((await recv_envelope(reader)).root)
    finally:
        writer.close()
        await writer.wait_closed()

    assert (int(response.status), response.result["data"]["code"]) == (
        400, "connection_sequence_error",
    ), (
        f"an unknown connect operation answered "
        f"{(int(response.status), response.result['data']['code'])} — §4.7's "
        f"out-of-order row is `connection_sequence_error`; FM-1 moved the "
        f"pre-hello `authenticate` out of that row and nothing else"
    )
