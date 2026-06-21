"""Tests for V7 EXECUTE-based connect between two Python peers."""

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.connect import ConnectError
from entity_core.peer import Peer, PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import recv_envelope, send_envelope
from entity_core.protocol.messages import Execute, ExecuteResponse


@pytest.fixture
async def server_peer():
    """Create and start a server peer."""
    keypair = Keypair.generate()
    # debug_mode=True grants full capabilities to all connecting peers (for testing)
    peer = PeerBuilder().with_keypair(keypair).with_default_handlers().debug_mode(True).build()
    await peer.start("127.0.0.1", 19000)
    yield peer
    await peer.stop()


@pytest.mark.asyncio
async def test_python_to_python_connect(server_peer: Peer):
    """Two Python peers can complete connect via EXECUTE messages."""
    client_keypair = Keypair.generate()

    conn = await Connection.connect("127.0.0.1", 19000, client_keypair)

    # Verify connection was established
    assert conn.session.local_peer_id == client_keypair.peer_id
    assert conn.session.remote_peer_id == server_peer.peer_id

    conn.close()
    await conn.wait_closed()


@pytest.mark.asyncio
async def test_expected_peer_id_verification(server_peer: Peer):
    """Connection with wrong expected peer ID fails."""
    client_keypair = Keypair.generate()

    with pytest.raises(ConnectError, match="Expected peer"):
        await Connection.connect(
            "127.0.0.1",
            19000,
            client_keypair,
            expected_peer_id="wrong-peer-id",
        )


@pytest.mark.asyncio
async def test_correct_expected_peer_id(server_peer: Peer):
    """Connection with correct expected peer ID succeeds."""
    client_keypair = Keypair.generate()

    conn = await Connection.connect(
        "127.0.0.1",
        19000,
        client_keypair,
        expected_peer_id=server_peer.peer_id,
    )

    assert conn.session.remote_peer_id == server_peer.peer_id

    conn.close()
    await conn.wait_closed()


@pytest.mark.asyncio
async def test_capability_received_via_connect(server_peer: Peer):
    """Client receives capability via connect authenticate response."""
    client_keypair = Keypair.generate()

    conn = await Connection.connect("127.0.0.1", 19000, client_keypair)

    try:
        # Should have received a capability from connect
        assert conn.capability is not None
        assert conn.capability["type"] == "system/capability/token"
        assert "content_hash" in conn.capability

        # Capability should have grants
        grants = conn.capability["data"].get("grants", [])
        assert len(grants) > 0
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_connect_already_complete(server_peer: Peer):
    """Sending connect after completion returns 409 conflict."""
    client_keypair = Keypair.generate()

    conn = await Connection.connect("127.0.0.1", 19000, client_keypair)

    try:
        # Try to send another connect hello - should get 409
        # URI is system/protocol/connect
        execute = Execute.create(
            uri="system/protocol/connect",
            operation="hello",
            params={
                "peer_id": client_keypair.peer_id,
                "nonce": "test-nonce",
                "protocols": ["entity-core/7.0"],
                "timestamp": 12345,
            },
        )
        await conn.send(Envelope(root=execute.to_entity()))

        response_env = await conn.recv()
        response = ExecuteResponse.from_entity(response_env.root)
        assert response.status == 409
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_pre_connect_execute_rejected(server_peer: Peer):
    """EXECUTE before connect is rejected with 403."""
    reader, writer = await asyncio.open_connection("127.0.0.1", 19000)

    try:
        # Send an EXECUTE without connecting first
        execute = Execute.create(
            uri=f"entity://{server_peer.peer_id}/system/status",
            operation="get",
        )
        await send_envelope(writer, Envelope(root=execute.to_entity()))

        response_env = await recv_envelope(reader)
        response = ExecuteResponse.from_entity(response_env.root)
        assert response.status == 403
    finally:
        writer.close()
        await writer.wait_closed()


def _forged_authenticate(victim_peer_id, signing_keypair, presented_pubkey, nonce):
    """Build a forged AUTHENTICATE claiming ``victim_peer_id`` while presenting
    ``presented_pubkey`` and signing with ``signing_keypair``. Returns
    ``(params_dict, envelope)`` ready to feed ``handle_connect_authenticate``."""
    from entity_core.protocol.auth import create_signature_entity
    from entity_core.protocol.entity import Entity
    from entity_core.utils.ecf import normalize_hash

    auth_entity = Entity(
        type="system/protocol/connect/authenticate",
        data={
            "peer_id": victim_peer_id,
            "public_key": presented_pubkey,
            "key_type": "ed25519",
            "nonce": nonce,
        },
    )
    auth_hash = normalize_hash(auth_entity.compute_hash())
    sig_entity = create_signature_entity(signing_keypair, auth_hash)
    envelope = Envelope(root=auth_entity.to_dict(), included=[sig_entity.to_dict()])
    return auth_entity.to_dict(), envelope


@pytest.mark.asyncio
async def test_authenticate_rejects_peer_id_pubkey_spoof():
    """G-A (HANDSHAKE-POP advisory): an attacker who claims a
    victim's peer_id but presents their OWN public_key — echoing the nonce and
    signing with their own key — must be rejected. Without the §1.5 binding
    check (peer_id == derive(public_key)) self-consistency + nonce + signature
    all pass and Python mints a connection authorized as the victim. Go and Rust
    reject here; this pins the Python-only fix. ACCEPTED 200 → ❌ before the fix."""
    from entity_core.handlers.connect import (
        ConnectState,
        handle_connect_authenticate,
    )

    server_keypair = Keypair.generate()
    victim_keypair = Keypair.generate()
    attacker_keypair = Keypair.generate()
    nonce = b"\x11" * 32

    state = ConnectState(
        phase="awaiting_authenticate",
        our_nonce=nonce,
        their_nonce=b"\x22" * 32,
        remote_peer_id=victim_keypair.peer_id,  # attacker claimed victim in hello too
    )

    # Forged: claim victim's peer_id, present attacker's pubkey, sign w/ attacker key.
    params, envelope = _forged_authenticate(
        victim_keypair.peer_id,
        attacker_keypair,
        attacker_keypair.public_key_bytes(),
        nonce,
    )

    with pytest.raises(ConnectError, match="identity_mismatch"):
        handle_connect_authenticate(state, params, envelope, server_keypair, grants=[])


@pytest.mark.asyncio
async def test_authenticate_accepts_bound_peer_id():
    """Positive control: an honest authenticate whose peer_id derives from the
    presented public_key passes the §1.5 binding check (does not raise
    identity_mismatch). Guards against the fix over-rejecting valid handshakes."""
    from entity_core.handlers.connect import (
        ConnectState,
        handle_connect_authenticate,
    )

    server_keypair = Keypair.generate()
    client_keypair = Keypair.generate()
    nonce = b"\x33" * 32

    state = ConnectState(
        phase="awaiting_authenticate",
        our_nonce=nonce,
        their_nonce=b"\x44" * 32,
        remote_peer_id=client_keypair.peer_id,
    )
    params, envelope = _forged_authenticate(
        client_keypair.peer_id,
        client_keypair,
        client_keypair.public_key_bytes(),
        nonce,
    )

    # Honest, properly-bound handshake completes without an identity_mismatch.
    state, _resp, _env, _cap, _fresh = handle_connect_authenticate(
        state, params, envelope, server_keypair, grants=[]
    )
    assert state.is_complete


@pytest.mark.asyncio
async def test_malformed_request_path_rejected_400_not_dropped(server_peer: Peer):
    """V7 §5.4: a reserved/ambiguous request path (`../`, `*/`) is rejected with
    a clean 400 by validate_absolute_path AFTER canonicalize (which is now a
    pure transform, no longer the rejection point). The connection MUST stay
    answerable — this is the request-path half of the fail-closed fix; the
    grant-pattern half is in test_capability.py."""
    client_keypair = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19000, client_keypair)
    try:
        for bad_uri in ("../secret", "*/local/files/x"):
            execute = Execute.create(uri=bad_uri, operation="get")
            await conn.send(Envelope(root=execute.to_entity()))
            response_env = await asyncio.wait_for(conn.recv(), timeout=2.0)
            response = ExecuteResponse.from_entity(response_env.root)
            assert response.status == 400, f"{bad_uri!r} should 400, got {response.status}"
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_invalid_message_type_responds_400_and_keeps_socket(
    server_peer: Peer,
):
    """Gap B (PROPOSAL §8.6): an unknown root message type
    MUST be answered with a clean ExecuteResponse 400 and the connection
    MUST stay open — the pre-fix behaviour (silent close) presented as a
    broken pipe to cross-impl validators and is the gap-B fingerprint."""
    reader, writer = await asyncio.open_connection("127.0.0.1", 19000)

    try:
        from entity_core.protocol.messages import compute_content_hash
        real_hash = compute_content_hash("system/unknown/type", {"foo": "bar"})
        bad_entity = {
            "type": "system/unknown/type",
            "data": {"foo": "bar"},
            "content_hash": real_hash,
            "refs": {},
        }
        await send_envelope(writer, Envelope(root=bad_entity))

        response_env = await asyncio.wait_for(recv_envelope(reader), timeout=2.0)
        response = ExecuteResponse.from_entity(response_env.root)
        assert response.status == 400
    finally:
        writer.close()
        await writer.wait_closed()
