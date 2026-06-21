"""V7 v7.67 Phase 2 — Ed448 peer backend handshake (cross-key matrix M2/M6).

Phase 1 pinned Ed448 primitives (sign/verify/peer_id) in isolation. Phase 2
wires Ed448 end-to-end through the connect handshake so a Python peer can run
as an Ed448 backend and complete a real-wire handshake with peers of either
key type — the precondition for Go's `validate-peer` to exercise different
crypto backends against a Python peer.

The matrix below mirrors MATRIX-M2 (server key_type × client key_type). Each
direction must:
  - bind the presented peer_id to the presented public_key (anti-spoof), and
  - verify the authenticate signature with the algorithm selected by the
    presented key_type (Ed448 for 0x02, Ed25519 for 0x01).
"""

from __future__ import annotations

import pytest

from entity_core.crypto.ed448 import Ed448Keypair
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.connection import Connection


def _make_keypair(kind: str):
    return Ed448Keypair.generate() if kind == "ed448" else Keypair.generate()


def test_identity_file_ed448_loader(tmp_path):
    """§4.1 — load_identity dispatches on the PEM header and reconstructs an
    Ed448 keypair from a Go-format identity file (so Go's peer-manager can
    drop its ensureIdentity skip for Python-Ed448 peers)."""
    import base64
    import json

    from entity_core.crypto.ed448 import Ed448Keypair
    from entity_core.crypto.identity import KEY_TYPE_ED448, decode_peer_id
    from entity_core.crypto.identity_file import PEM_HEADER_ED448, load_identity

    seed = bytes([0x42]) * 57  # cohort Phase 1 fixture seed
    kp = Ed448Keypair.from_seed(seed)
    name = "cohort-ed448"

    # Write the Go SaveIdentityToDir shape: 3-line tagged PEM + .json sidecar.
    (tmp_path / name).write_text(
        f"{PEM_HEADER_ED448}\n"
        f"{base64.b64encode(seed).decode()}\n"
        f"-----END ENTITY ED448 PRIVATE KEY-----\n"
    )
    (tmp_path / f"{name}.json").write_text(
        json.dumps(
            {
                "key_type": "ed448",
                "peer_id": kp.peer_id,
                "public_key": base64.b64encode(kp.public_key_bytes()).decode(),
            }
        )
    )

    loaded = load_identity(name, base_path=tmp_path)
    assert loaded.keypair.key_type == "ed448"
    assert loaded.keypair.public_key_bytes() == kp.public_key_bytes()
    assert loaded.keypair.peer_id == kp.peer_id
    assert decode_peer_id(loaded.peer_id_base58)[0] == KEY_TYPE_ED448
    # Signs under Ed448 (114-byte signature).
    assert len(loaded.keypair.sign(b"x")) == 114


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("server_kind", "client_kind", "port"),
    [
        ("ed25519", "ed25519", 19440),  # baseline
        ("ed448", "ed25519", 19441),    # Ed448 server, Ed25519 client
        ("ed25519", "ed448", 19442),    # Ed25519 server, Ed448 client
        ("ed448", "ed448", 19443),      # both Ed448
    ],
)
async def test_handshake_cross_key_matrix(server_kind, client_kind, port):
    server_kp = _make_keypair(server_kind)
    server = (
        PeerBuilder()
        .with_keypair(server_kp)
        .with_default_handlers()
        .debug_mode(True)
        .build()
    )
    await server.start("127.0.0.1", port)
    try:
        # peer_id carries the right wire key_type byte
        from entity_core.crypto.identity import (
            KEY_TYPE_ED448,
            KEY_TYPE_ED25519,
            decode_peer_id,
        )

        expected_byte = KEY_TYPE_ED448 if server_kind == "ed448" else KEY_TYPE_ED25519
        assert decode_peer_id(server_kp.peer_id)[0] == expected_byte

        client_kp = _make_keypair(client_kind)
        conn = await Connection.connect("127.0.0.1", port, client_kp)
        try:
            # Handshake completed both directions (server verified the client's
            # signature with the client's algorithm; client verified the
            # server's).
            assert conn.session.local_peer_id == client_kp.peer_id
            assert conn.session.remote_peer_id == server.peer_id
            # Capability was minted + its granter signature verified.
            assert conn.capability is not None
            assert conn.capability["type"] == "system/capability/token"
        finally:
            conn.close()
            await conn.wait_closed()
    finally:
        await server.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("server_kind", ["ed25519", "ed448"])
async def test_ed448_server_self_serves_authenticated_execute(server_kind):
    """§4.5 sanity gate — an Ed448 server's handler-grants self-verify and an
    authenticated EXECUTE round-trips. This is the cohort blocker path: a
    grant signed under the server's key must NOT self-reject as
    `unsupported_signature_algorithm`, and the client's authenticate-signed
    request must verify under the client's key (here Ed25519).
    """
    port = 19450 if server_kind == "ed25519" else 19451
    server_kp = _make_keypair(server_kind)
    server = (
        PeerBuilder()
        .with_keypair(server_kp)
        .with_default_handlers()
        .debug_mode(True)
        .build()
    )
    await server.start("127.0.0.1", port)
    try:
        conn = await Connection.connect("127.0.0.1", port, Keypair.generate())
        try:
            write = await conn.execute(
                uri=f"entity://{server.peer_id}/data/ed448-check",
                operation="write",
                params={"entity": {"type": "test-data", "data": {"v": 1}}},
                authenticated=True,
            )
            assert write.status == 200, f"write rejected: {write.error}"

            read = await conn.execute(
                uri=f"entity://{server.peer_id}/data/ed448-check",
                operation="get",
                authenticated=True,
            )
            assert read.status == 200, f"read rejected: {read.error}"
            assert read.result["data"]["v"] == 1
        finally:
            conn.close()
            await conn.wait_closed()
    finally:
        await server.stop()
