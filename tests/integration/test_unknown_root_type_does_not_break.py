"""Gap B (PROPOSAL §8.6) — Python responds cleanly to
unknown root message types and stays on the connection.

Pre-fix: Python's inbound loop silently `break`-d when the root envelope
type wasn't ``Execute`` or ``ExecuteResponse``, which presented to
Rust/Go validators as a broken pipe with no diagnostic. The cohort then
had to guess what Python had rejected. This pin holds Python to:

- respond with an ExecuteResponse 400 carrying the offending type name
- KEEP the connection open (framing was intact; only the root type was
  unknown) so subsequent legitimate frames continue to work

We use a raw socket (no `Connection.connect` demuxer) so we can read
the response directly off the wire — the demuxer would claim the
reader exclusively for request-id-keyed Futures.
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import recv_envelope, send_envelope
from entity_core.protocol.messages import ExecuteResponse


@pytest.fixture
async def server_peer():
    keypair = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(keypair)
        .with_default_handlers()
        .debug_mode(True)
        .build()
    )
    await peer.start("127.0.0.1", 19201)
    yield peer
    await peer.stop()


def _resp_message(resp: ExecuteResponse) -> str:
    """Extract `data.message` from the entity-shaped result."""
    result = resp.result
    if not isinstance(result, dict):
        return ""
    inner = result.get("data", result)
    if isinstance(inner, dict):
        return inner.get("message", "") or ""
    return ""


@pytest.mark.asyncio
async def test_unknown_root_type_pre_connect_gets_400(server_peer):
    """Send a foreign-typed root envelope as the very first frame.
    Python should reply 400 with the offending type name, not EOF."""
    reader, writer = await asyncio.open_connection("127.0.0.1", 19201)
    try:
        weird = Entity(type="some/foreign/probe", data={"request_id": "probe-1"})
        await send_envelope(writer, Envelope(root=weird.to_dict()))

        env = await asyncio.wait_for(recv_envelope(reader), timeout=3.0)
        resp = ExecuteResponse.from_entity(env.root)
        assert resp.status == 400, (
            f"expected 400 for unknown root type; got status={resp.status} "
            f"result={resp.result!r}"
        )
        msg = _resp_message(resp)
        assert "unknown message type" in msg, (
            f"expected diagnostic message naming the type; got msg={msg!r}"
        )
        assert "some/foreign/probe" in msg
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


@pytest.mark.asyncio
async def test_connection_survives_unknown_type_can_still_connect(server_peer):
    """After Python rejects an unknown type, the same connection still
    accepts a legitimate Execute (here: CONNECT/hello — the first
    handshake frame). Pre-fix the socket was closed."""
    from entity_core.handlers.connect import create_connect_hello_execute

    reader, writer = await asyncio.open_connection("127.0.0.1", 19201)
    try:
        weird = Entity(type="some/foreign/probe", data={"request_id": "probe-1"})
        await send_envelope(writer, Envelope(root=weird.to_dict()))
        env = await asyncio.wait_for(recv_envelope(reader), timeout=3.0)
        assert ExecuteResponse.from_entity(env.root).status == 400

        client_kp = Keypair.generate()
        hello_execute, _our_nonce = create_connect_hello_execute(client_kp)
        await send_envelope(writer, Envelope(root=hello_execute.to_entity()))

        env2 = await asyncio.wait_for(recv_envelope(reader), timeout=3.0)
        resp2 = ExecuteResponse.from_entity(env2.root)
        assert resp2.status == 200, (
            f"expected CONNECT/hello to succeed after rejection; got "
            f"status={resp2.status} result={resp2.result!r}"
        )
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
