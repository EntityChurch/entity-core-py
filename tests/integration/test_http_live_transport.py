"""Real-wire integration test for the §6.5.2c live HTTP transport (Chunk D).

Stands up two peers — one binds an HTTP listener via ``start_http``, the
other dials via ``HttpConnection.connect`` — and round-trips a
``system/status:get`` EXECUTE through the V7 connect handshake + an
authenticated request. Exercises:

- HTTP/1.1 POST parsing on the server (`http_server`)
- Length-prefix stripping for the response body
- `X-Entity-Session` header threading server-side state across POSTs
  (hello on POST #1, authenticate on POST #2, execute on POST #3)
- The full V7 nonce-challenge handshake over HTTP
- Identical EXECUTE / EXECUTE-RESPONSE wire envelopes that TCP carries
  (Mechanism A — wrapper, NOT BRIDGE-HTTP)
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.http_client import HttpConnection


@pytest.fixture
async def http_server_peer():
    """Spin up a server peer with both a TCP listener (for sanity) and an
    HTTP listener; admit the future client as an admin so the connect
    grants are full-access."""
    server_kp = Keypair.generate()
    client_kp = Keypair.generate()

    server = (
        PeerBuilder()
        .with_keypair(server_kp)
        .with_admin_peer_ids({client_kp.peer_id})
        .with_all_handlers()
        .build()
    )
    # Bind only the HTTP listener — chunk D's surface. (TCP is exercised by
    # the existing real-wire tests.)
    http_server = await server.start_http("127.0.0.1", 0)
    bind = http_server.bound_socket()
    assert bind is not None
    bind_host, bind_port = bind
    url = f"http://{bind_host}:{bind_port}/entity"

    yield server, server_kp, client_kp, url

    await server.stop()


@pytest.mark.asyncio
async def test_http_connect_handshake_and_status_get(http_server_peer):
    """End-to-end: HTTP connect handshake + system/status:get round-trip."""
    server, server_kp, client_kp, url = http_server_peer

    conn = await HttpConnection.connect(
        url, client_kp, expected_peer_id=server_kp.peer_id
    )
    try:
        assert conn.remote_peer_id == server_kp.peer_id
        assert conn.capability is not None, "client should receive a capability"

        response = await conn.execute(
            "system/status", "get", params={"data": {}},
        )
        assert response.status == 200, f"got status={response.status} result={response.result}"
        result = response.result
        assert isinstance(result, dict)
        data = result.get("data", {})
        assert data.get("peer_id") == server_kp.peer_id
        assert data.get("status") == "ok"
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_http_two_executes_share_one_session_id(http_server_peer):
    """Two sequential EXECUTEs on the same HttpConnection thread the same
    `X-Entity-Session` server-side, so session state is preserved
    across POSTs without re-handshaking."""
    server, server_kp, client_kp, url = http_server_peer

    conn = await HttpConnection.connect(
        url, client_kp, expected_peer_id=server_kp.peer_id
    )
    try:
        conn_id_after_connect = conn._session_id
        assert conn_id_after_connect is not None

        for _ in range(3):
            response = await conn.execute("system/status", "get", params={"data": {}})
            assert response.status == 200

        # Connection id unchanged across executes — server resolved the
        # same session each time.
        assert conn._session_id == conn_id_after_connect
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_unauthenticated_execute_before_connect_rejected(http_server_peer):
    """Sending an EXECUTE before completing the connect handshake yields
    a 403/Forbidden response (mirrors the TCP path's pre-connect reject)."""
    from entity_core.protocol.auth import create_authenticated_request
    from entity_core.protocol.messages import Execute
    from entity_core.peer.http_client import HttpConnection

    server, server_kp, client_kp, url = http_server_peer

    # Construct an unauthenticated EXECUTE on a fresh connection (no
    # prior connect, no capability) — server should reject.
    bootstrap = HttpConnection(
        url=url,
        keypair=client_kp,
        session=None,  # type: ignore[arg-type]
        capability=None,
        capability_chain=None,
    )
    execute = Execute.create(
        "system/status", "get", params={"data": {}},
    )
    # Use the raw _post_envelope so we send a non-CONNECT EXECUTE without
    # having authenticated.
    from entity_core.protocol.envelope import Envelope
    response_env = await bootstrap._post_envelope(
        Envelope(root=execute.to_entity())
    )
    from entity_core.protocol.messages import ExecuteResponse
    response = ExecuteResponse.from_entity(response_env.root)
    assert response.status == 403, (
        f"expected 403 Forbidden pre-connect, got {response.status}"
    )


@pytest.mark.asyncio
async def test_send_raw_frame_dispatches_inner_envelope(http_server_peer):
    """Mode-F raw-frame over HTTP transport (RELAY §3.1.1 / §10.4).

    A frame POSTed via ``HttpConnection.send_raw_frame`` is decoded and
    dispatched by the destination exactly like a direct POST, binding the
    inner EXECUTE's tree path. This is the HTTP analog of TCP's
    ``send_raw_frame`` terminal-hop and closes COHORT-PYTHON-HTTP-RAW-FRAME-GAP
    (the relay terminal hop previously fell through to Mode-S over HTTP because
    ``HttpConnection`` exposed no raw-frame primitive).

    Mirrors Go's ``core/peer/http_raw_frame_test.go``.
    """
    from entity_core.protocol.auth import create_authenticated_request
    from entity_core.protocol.entity import Entity
    from entity_core.protocol.messages import Execute, ResourceTarget
    from entity_core.utils.ecf import ecf_encode

    server, server_kp, client_kp, url = http_server_peer

    conn = await HttpConnection.connect(
        url, client_kp, expected_peer_id=server_kp.peer_id
    )
    try:
        # Build a complete, authenticated EXECUTE envelope — what a relay would
        # forward verbatim as the inner system/envelope's .data. We sign it
        # with the dialer's keypair + session capability exactly as
        # HttpConnection.execute does internally, then ship the raw bytes.
        path = "system/raw-frame-probe"
        marker = Entity(type="test/marker", data={"hello": "raw-frame"})
        execute = Execute.create(
            f"entity://{server_kp.peer_id}/system/tree",
            "put",
            # §3.4 entity-shaped params: a {type, data} dict is preserved by the
            # send-side shim, so the handler reads data={"entity": ...} directly.
            {"type": "system/tree/put-request", "data": {"entity": marker.to_dict()}},
            resource=ResourceTarget.from_dict({"targets": [path]}),
        )
        auth_request = create_authenticated_request(
            client_kp, execute, conn.capability, conn.capability_chain,
            algorithm=conn.active_hash_format,
        )
        frame = ecf_encode(auth_request.to_envelope().to_dict())

        # Fire-and-forget: returns None, no response correlation. The POST
        # still awaits the destination's synchronous dispatch, so by the time
        # this returns the put has been applied server-side.
        result = await conn.send_raw_frame(frame)
        assert result is None

        # The destination bound the inner EXECUTE's tree path — proof the raw
        # frame was decoded + dispatched through the normal authenticated path.
        uri = server.entity_tree.normalize_uri(path)
        bound = server.entity_tree.get(uri)
        assert bound is not None, "raw-frame put did not bind on the destination"
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_send_raw_frame_on_closed_connection_raises(http_server_peer):
    """A raw-frame send on a closed HttpConnection fails fast (caller falls
    back to Mode-S), never silently no-ops."""
    server, server_kp, client_kp, url = http_server_peer

    conn = await HttpConnection.connect(
        url, client_kp, expected_peer_id=server_kp.peer_id
    )
    await conn.close()
    with pytest.raises(ConnectionError):
        await conn.send_raw_frame(b"\x80")
