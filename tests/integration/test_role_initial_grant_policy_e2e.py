"""End-to-end test for EXTENSION-ROLE §4.7 initial-grant-policy
resolver, mirroring the cross-impl validator's TV-RV-2.7 fixture
(`role_stage2_recognize_on_attest_*`).

Drives a real connection through `Connection.connect`, exercising:
- the connect handler reading the peer's installed grant resolver,
- the resolver consulting the policy entity at AUTHENTICATE,
- recognition of an agent-cert chain to the trusted quorum,
- the resulting capability carrying the policy's role grants on
  the wire (NOT the static fallback / connect-scope grants).

Sanity check that --debug doesn't short-circuit a bound policy
(otherwise cross-impl runs that start the peer with --debug for
verbose logging would never hit the resolver).
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

from entity_handlers import PolicyGrantResolver
from entity_handlers.attestation import make_attestation
from entity_handlers.identity import (
    FUNCTION_AGENT,
    FUNCTION_CONTROLLER,
    KIND_IDENTITY_CERT,
    PEER_CONFIG_PATH,
    PEER_CONFIG_TYPE,
)
from entity_handlers.role import (
    INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION,
    INITIAL_GRANT_POLICY_PATH,
    INITIAL_GRANT_POLICY_TYPE,
    role_definition_path,
)


CTX_NAME = "validate/stage2-policy/e2e"
ROLE_NAME = "guest"
GUEST_RESOURCES = [f"shared/{CTX_NAME}/*"]
PORT = 19101


def _emit(peer: Peer, path: str, entity: Entity) -> bytes:
    return peer.emit_pathway.emit(
        path, entity, EmitContext.bootstrap(),
    ).hash


def _bind_peer(peer: Peer, kp: Keypair) -> bytes:
    # v7.65 §2: system/peer data = (public_key, key_type) only
    entity = Entity(
        type="system/peer",
        data={
            "public_key": kp.public_key_bytes(),
            "key_type": "ed25519",
        },
    )
    h = entity.compute_hash()
    _emit(peer, f"system/peer/identity/{kp.peer_id}", entity)
    return h


def _stage_recognize_on_attestation(peer: Peer) -> bytes:
    """Set up trusted-quorum, controller cert, role def, policy. Returns
    the controller's `system/peer` content hash (used as `attesting`
    on the agent-cert minted per-connection)."""
    trusted_quorum = b"\x00" + b"Q" * 32
    _emit(
        peer, PEER_CONFIG_PATH,
        Entity(
            type=PEER_CONFIG_TYPE,
            data={"trusts_quorum": trusted_quorum, "bindings": []},
        ),
    )
    controller_kp = Keypair.from_seed(b"\xc0" * 32)
    controller_hash = _bind_peer(peer, controller_kp)
    ctrl_cert = make_attestation(
        attesting=trusted_quorum,
        attested=controller_hash,
        properties={"kind": KIND_IDENTITY_CERT, "function": FUNCTION_CONTROLLER},
    )
    _emit(
        peer,
        f"test/attestation/{ctrl_cert.compute_hash().hex()}",
        ctrl_cert,
    )

    _emit(
        peer, role_definition_path(CTX_NAME, ROLE_NAME),
        Entity(
            type="system/role",
            data={
                "name": ROLE_NAME,
                "grants": [
                    {
                        "handlers": {"include": ["system/tree"]},
                        "resources": {"include": GUEST_RESOURCES},
                        "operations": {"include": ["get"]},
                    }
                ],
            },
        ),
    )
    _emit(
        peer, INITIAL_GRANT_POLICY_PATH,
        Entity(
            type=INITIAL_GRANT_POLICY_TYPE,
            data={
                "unknown_peer": INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION,
                "default_role": ROLE_NAME,
                "default_context": CTX_NAME,
                "identity_required": True,
            },
        ),
    )
    return controller_hash


def _bind_agent_cert(peer: Peer, controller_hash: bytes, kp: Keypair) -> None:
    """Bind an agent-cert for `kp` under `controller_hash`. The peer-
    entity is also bound so the connecting peer's content hash matches
    the `attested` field on the cert."""
    agent_hash = _bind_peer(peer, kp)
    agent_cert = make_attestation(
        attesting=controller_hash,
        attested=agent_hash,
        properties={"kind": KIND_IDENTITY_CERT, "function": FUNCTION_AGENT},
    )
    _emit(
        peer,
        f"test/attestation/{agent_cert.compute_hash().hex()}",
        agent_cert,
    )


@pytest.fixture
async def policy_peer():
    """Server peer with the policy resolver wired and the
    recognize-on-attestation policy bound. NOT in debug_mode by default
    so the connect-scope fallback fires for unrecognized peers."""
    keypair = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(keypair)
        .with_all_handlers()
        .build()
    )
    controller_hash = _stage_recognize_on_attestation(peer)
    peer.set_grant_resolver(
        PolicyGrantResolver(
            peer.emit_pathway, local_peer_id=keypair.peer_id,
        )
    )
    peer._policy_controller_hash = controller_hash  # ad-hoc test handle
    await peer.start("127.0.0.1", PORT)
    yield peer
    await peer.stop()


def _grants_match_guest(cap_dict: dict) -> bool:
    """Return True iff the capability's grants exactly match the
    `guest` role's grants. Tolerates both dict-of-scope and legacy-list
    grant encodings (the role def stores scope dicts)."""
    grants = cap_dict.get("data", {}).get("grants", [])
    if len(grants) != 1:
        return False
    g = grants[0]
    handlers = g.get("handlers")
    resources = g.get("resources")
    operations = g.get("operations")

    def _include(scope):
        if isinstance(scope, dict):
            return scope.get("include")
        return scope

    return (
        _include(handlers) == ["system/tree"]
        and _include(resources) == GUEST_RESOURCES
        and _include(operations) == ["get"]
    )


@pytest.mark.asyncio
async def test_recognize_on_attest_positive_e2e(policy_peer: Peer):
    """TV-RV-2.7 positive: K's agent-cert chains to the trusted
    controller → connection cap carries `guest` grants."""
    k_kp = Keypair.generate()
    _bind_agent_cert(
        policy_peer, policy_peer._policy_controller_hash, k_kp,
    )

    conn = await Connection.connect("127.0.0.1", PORT, k_kp)
    try:
        assert conn.capability is not None
        assert _grants_match_guest(conn.capability), (
            f"RA-6 VIOLATION: expected guest grants, got "
            f"{conn.capability['data'].get('grants')}"
        )
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_recognize_on_attest_bare_keypair_e2e(policy_peer: Peer):
    """TV-RV-2.7 negative: bare keypair (no agent-cert) →
    identity_required=true falls back to connect-scope, NOT guest."""
    bare_kp = Keypair.generate()

    conn = await Connection.connect("127.0.0.1", PORT, bare_kp)
    try:
        assert conn.capability is not None
        assert not _grants_match_guest(conn.capability), (
            "RA-6 VIOLATION: bare keypair received guest grants"
        )
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_recognize_on_attest_unrelated_controller_e2e(
    policy_peer: Peer,
):
    """TV-RV-2.7 negative: agent-cert under a rogue controller (under
    a different quorum) → not recognized, falls back per identity_required."""
    rogue_controller_kp = Keypair.from_seed(b"\xc2" * 32)
    rogue_controller_hash = _bind_peer(policy_peer, rogue_controller_kp)
    rogue_quorum = b"\x00" + b"R" * 32
    rogue_ctrl_cert = make_attestation(
        attesting=rogue_quorum,
        attested=rogue_controller_hash,
        properties={"kind": KIND_IDENTITY_CERT, "function": FUNCTION_CONTROLLER},
    )
    _emit(
        policy_peer,
        f"test/attestation/{rogue_ctrl_cert.compute_hash().hex()}",
        rogue_ctrl_cert,
    )

    n_kp = Keypair.generate()
    _bind_agent_cert(policy_peer, rogue_controller_hash, n_kp)

    conn = await Connection.connect("127.0.0.1", PORT, n_kp)
    try:
        assert conn.capability is not None
        assert not _grants_match_guest(conn.capability), (
            "RA-6 VIOLATION: rogue-controller agent received guest grants"
        )
    finally:
        conn.close()
        await conn.wait_closed()
