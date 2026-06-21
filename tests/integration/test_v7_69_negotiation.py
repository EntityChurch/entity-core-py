"""V7 v7.69 — content_hash_format negotiation conformance + mixed-mode interop.

Covers the cohort handoff's two conformance vectors and the M3 end-to-end
guard:

- ``NEGOTIATE-FORMAT-1`` — ``hash_formats`` is a §4.5 single active value:
  the responder advertises a non-empty preference list including the
  ``ecfv1-sha256`` floor, computes the first-match-in-initiator-order
  intersection, and rejects a disjoint set with ``400 incompatible_hash_format``.

- ``NEGOTIATE-KEYTYPE-1`` — ``key_types`` is a §4.5 accept-set: the responder
  advertises a non-empty verify-set including the ``ed25519`` floor and rejects
  an initiator whose set omits the responder's own key_type with
  ``400 unsupported_key_type`` (mutual-verifiability gate at hello).

- Mixed-format interop (§4.5a): two peers negotiate to a single active format
  and author every connection-bound entity under it, so ``grantee == author``
  holds (§5.2) and an authenticated EXECUTE succeeds. This is the regression
  guard for the M3 ``403 capability_denied`` cross-format mismatch.
"""

from __future__ import annotations

import contextlib

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.connect import (
    ConnectError,
    ConnectState,
    handle_connect_hello,
)
from entity_core.peer import Peer, PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.primitives import Uint
from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    ALG_ECFV1_SHA384,
    default_advertised_hash_formats,
    get_default_hash_algorithm,
    set_default_hash_algorithm,
)


@contextlib.contextmanager
def _default_format(code: int):
    """Temporarily set the process-global default content_hash_format,
    simulating a peer booted under ``--hash-type``. Restored on exit."""
    prev = get_default_hash_algorithm()
    set_default_hash_algorithm(code)
    try:
        yield
    finally:
        set_default_hash_algorithm(prev)


def _hello_params(
    keypair: Keypair,
    *,
    hash_formats: list[str] | None = None,
    key_types: list[str] | None = None,
) -> dict:
    """Build a hello EXECUTE params entity (the initiator's hello) with
    optional advertised-set overrides for the disjoint-reject vectors."""
    data: dict = {
        "peer_id": keypair.peer_id,
        "nonce": b"\x01" * 32,
        "protocols": ["entity-core/7.0"],
        "timestamp": Uint(0),
    }
    if hash_formats is not None:
        data["hash_formats"] = hash_formats
    if key_types is not None:
        data["key_types"] = key_types
    return Entity(type="system/protocol/connect/hello", data=data).to_dict()


# ---------------------------------------------------------------------------
# NEGOTIATE-FORMAT-1 / NEGOTIATE-KEYTYPE-1 (in-process responder hello)
# ---------------------------------------------------------------------------


def test_negotiate_format_advertised():
    """format_advertised: responder hello hash_formats non-empty + includes floor."""
    responder = Keypair.generate()
    initiator = Keypair.generate()
    _state, response = handle_connect_hello(
        ConnectState(), _hello_params(initiator), responder, "req-1"
    )
    advertised = response.result["data"]["hash_formats"]
    assert advertised, "responder MUST advertise hash_formats"
    assert "ecfv1-sha256" in advertised, "ecfv1-sha256 is the §4.5 floor"
    assert advertised == ["ecfv1-sha256"]  # SHA-256 home peer advertises floor only


def test_negotiate_keytype_advertised():
    """keytype_advertised: responder hello key_types non-empty + includes floor."""
    responder = Keypair.generate()
    initiator = Keypair.generate()
    _state, response = handle_connect_hello(
        ConnectState(), _hello_params(initiator), responder, "req-1"
    )
    advertised = response.result["data"]["key_types"]
    assert advertised, "responder MUST advertise key_types"
    assert "ed25519" in advertised, "ed25519 is the §4.5 floor"


def test_negotiate_format_disjoint_reject():
    """format_disjoint_reject: disjoint hash_formats → 400 incompatible_hash_format."""
    responder = Keypair.generate()
    initiator = Keypair.generate()
    params = _hello_params(initiator, hash_formats=["ecfv1-fake-disjoint-format"])
    with pytest.raises(ConnectError) as exc:
        handle_connect_hello(ConnectState(), params, responder, "req-1")
    assert exc.value.code == "incompatible_hash_format"


def test_negotiate_keytype_disjoint_reject():
    """keytype_disjoint_reject: responder's key_type absent from initiator
    verify-set → 400 unsupported_key_type (mutual-verifiability gate)."""
    responder = Keypair.generate()  # ed25519
    initiator = Keypair.generate()
    params = _hello_params(initiator, key_types=["fake-disjoint-key-type"])
    with pytest.raises(ConnectError) as exc:
        handle_connect_hello(ConnectState(), params, responder, "req-1")
    assert exc.value.code == "unsupported_key_type"


def test_negotiate_active_format_first_match_initiator_order():
    """The active format is the first initiator preference the responder also
    advertises. A SHA-256 responder pins SHA-256 even if the initiator prefers
    SHA-384; a SHA-384 responder honors a SHA-384-first initiator."""
    initiator = Keypair.generate()
    # SHA-256 responder, initiator prefers SHA-384 → down to SHA-256.
    responder = Keypair.generate()
    state, _ = handle_connect_hello(
        ConnectState(),
        _hello_params(initiator, hash_formats=["ecfv1-sha384", "ecfv1-sha256"]),
        responder,
        "req-1",
    )
    assert state.active_hash_format == ALG_ECFV1_SHA256

    # SHA-384 responder, same initiator → SHA-384 (first match in initiator order).
    with _default_format(ALG_ECFV1_SHA384):
        assert default_advertised_hash_formats() == ["ecfv1-sha384", "ecfv1-sha256"]
        state2, _ = handle_connect_hello(
            ConnectState(),
            _hello_params(initiator, hash_formats=["ecfv1-sha384", "ecfv1-sha256"]),
            responder,
            "req-2",
        )
        assert state2.active_hash_format == ALG_ECFV1_SHA384


def test_pre_v7_69_initiator_defaults_to_sha256():
    """A pre-v7.69 initiator that advertises no hash_formats/key_types takes
    the §4.5 floor defaults and still negotiates (back-compat)."""
    responder = Keypair.generate()
    initiator = Keypair.generate()
    params = _hello_params(initiator)  # no hash_formats / key_types
    # strip the fields entirely to model a legacy peer
    params["data"].pop("hash_formats", None)
    params["data"].pop("key_types", None)
    state, _ = handle_connect_hello(ConnectState(), params, responder, "req-1")
    assert state.active_hash_format == ALG_ECFV1_SHA256


# ---------------------------------------------------------------------------
# Mixed-format interop (real wire) — the M3 regression guard
# ---------------------------------------------------------------------------


async def _assert_authenticated_execute_ok(peer: Peer, conn: Connection) -> None:
    """An authenticated EXECUTE succeeds only if grantee == author under the
    connection's active format (§5.2). This is the M3 cross-format guard."""
    response = await conn.execute(
        uri=f"entity://{peer.peer_id}/system/status",
        operation="get",
        authenticated=True,
    )
    assert response.status == 200, response.result
    assert response.result["type"] == "status"


@pytest.mark.asyncio
async def test_both_sha384_authors_under_sha384():
    """Both peers SHA-384 → active SHA-384; handshake + authenticated EXECUTE
    succeed with the cap grantee authored under SHA-384 (format byte 0x01)."""
    with _default_format(ALG_ECFV1_SHA384):
        server_kp = Keypair.generate()
        peer = (
            PeerBuilder()
            .with_keypair(server_kp)
            .with_default_handlers()
            .debug_mode(True)
            .build()
        )
        await peer.start("127.0.0.1", 19111)
        try:
            client_kp = Keypair.generate()
            conn = await Connection.connect("127.0.0.1", 19111, client_kp)
            try:
                assert conn.active_hash_format == ALG_ECFV1_SHA384
                assert conn.capability is not None
                # grantee hash authored under the active format (0x01 = SHA-384)
                assert conn.capability["data"]["grantee"][0] == ALG_ECFV1_SHA384
                await _assert_authenticated_execute_ok(peer, conn)
            finally:
                conn.close()
                await conn.wait_closed()
        finally:
            await peer.stop()


def test_sha384_home_responder_authors_downgraded_handshake_under_sha256():
    """§4.5a downgrade authoring: a SHA-384 *home* responder that negotiates
    down to SHA-256 for a SHA-256-only initiator authors its cap/identity/
    signature under SHA-256, not its home format — so ``grantee == author``
    holds on that connection.

    This is the precise per-connection-authoring guarantee, exercised through
    the connect handler directly. (The full cross-format two-peer wire path is
    a two-process / cross-impl scenario — the Go validate-peer `-category
    negotiation` gate — because one Python process holds a single home format
    global: a SHA-384 server's own internal non-connection-bound state is
    authored under and validated under SHA-384, so flipping the one global to
    fake a SHA-256 client in-process would corrupt that internal state.)
    """
    from entity_core.capability.grant import create_full_access_grant
    from entity_core.handlers.connect import (
        create_connect_authenticate_execute,
        handle_connect_authenticate,
    )
    from entity_core.protocol.envelope import Envelope

    with _default_format(ALG_ECFV1_SHA384):
        responder = Keypair.generate()  # home format SHA-384
        client = Keypair.generate()

        # Hello: SHA-256-only initiator → active SHA-256 (downgrade from the
        # responder's SHA-384 home).
        state, _ = handle_connect_hello(
            ConnectState(),
            _hello_params(client, hash_formats=["ecfv1-sha256"]),
            responder,
            "r1",
        )
        assert state.active_hash_format == ALG_ECFV1_SHA256

        # Client authenticates under the negotiated active format (SHA-256).
        auth_exec, sig_ent, id_ent = create_connect_authenticate_execute(
            client, state.our_nonce, algorithm=ALG_ECFV1_SHA256,
        )
        params = auth_exec.params  # the authenticate entity dict (SHA-256)
        env = Envelope(
            root=auth_exec.to_entity(ALG_ECFV1_SHA256),
            included=[sig_ent.to_dict(), id_ent.to_dict()],
        )

        _state2, _resp, _resp_env, (cap, granter_id, cap_sig), minted = (
            handle_connect_authenticate(
                state, params, env, responder, create_full_access_grant(),
            )
        )
        assert minted is True
        # Responder's home is SHA-384, but EVERY authored entity on this
        # connection is SHA-256 (format byte 0x00) — the §4.5a downgrade.
        assert cap.compute_hash()[0] == ALG_ECFV1_SHA256
        assert granter_id.compute_hash()[0] == ALG_ECFV1_SHA256
        assert cap_sig.compute_hash()[0] == ALG_ECFV1_SHA256
        assert cap.data["granter"][0] == ALG_ECFV1_SHA256
        # Grantee is the client's wire-authored identity (SHA-256), used
        # verbatim per §1.8 — never re-hashed under the responder's home format.
        assert cap.data["grantee"] == id_ent.compute_hash()
        assert cap.data["grantee"][0] == ALG_ECFV1_SHA256


@pytest.mark.asyncio
async def test_sha256_baseline_active_is_sha256():
    """Default SHA-256 peers negotiate SHA-256 (explicit baseline assertion)."""
    server_kp = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(server_kp)
        .with_default_handlers()
        .debug_mode(True)
        .build()
    )
    await peer.start("127.0.0.1", 19113)
    try:
        client_kp = Keypair.generate()
        conn = await Connection.connect("127.0.0.1", 19113, client_kp)
        try:
            assert conn.active_hash_format == ALG_ECFV1_SHA256
            assert conn.capability["data"]["grantee"][0] == ALG_ECFV1_SHA256
            await _assert_authenticated_execute_ok(peer, conn)
        finally:
            conn.close()
            await conn.wait_closed()
    finally:
        await peer.stop()
