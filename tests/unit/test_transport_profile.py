"""Chunk C — `system/peer/transport/tcp` profile entity tests.

Per EXTENSION-NETWORK §6.5 (v1.4 Amendment 2) + PROPOSAL-EXTENSION-
NETWORK-TRANSPORT-FAMILY §4.1. `Peer.register_remote` writes the §4.1
TCP profile entity (replacing the legacy `{peer_id, address}` flat
shape); `RemoteConnectionPool._resolve_endpoint` reads it and parses the
`tcp://host:port` URL per D-14.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder
from entity_core.peer.remote import (
    RemoteConnectionPool,
    _parse_tcp_endpoint_url,
)
from entity_core.protocol.auth import create_identity_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext


def _hex(kp: Keypair) -> str:
    """V7 v7.64 §1.4 peer_id_hex for a keypair (lowercase hex of the
    peer's `system/peer` content_hash)."""
    return create_identity_entity(kp).compute_hash().hex()


class TestTcpEndpointUrlParser:
    def test_parses_standard_url(self):
        assert _parse_tcp_endpoint_url("tcp://127.0.0.1:9000") == ("127.0.0.1", 9000)

    def test_parses_hostname(self):
        assert _parse_tcp_endpoint_url("tcp://peer.example:443") == (
            "peer.example",
            443,
        )

    def test_rejects_wrong_scheme(self):
        with pytest.raises(ValueError, match="must start with 'tcp://'"):
            _parse_tcp_endpoint_url("https://host:443")

    def test_rejects_missing_port(self):
        with pytest.raises(ValueError, match="missing port"):
            _parse_tcp_endpoint_url("tcp://host")

    def test_rejects_non_integer_port(self):
        with pytest.raises(ValueError, match="non-integer port"):
            _parse_tcp_endpoint_url("tcp://host:abc")


def _put_profile(
    peer,
    remote_kp: Keypair,
    profile_id: str,
    *,
    address: str = "10.0.0.1:8080",
    entity_type: str = "system/peer/transport/tcp",
    transport_type: str | None = "tcp",
    url: str | None = None,
    omit_endpoint: bool = False,
) -> None:
    """Emit a custom transport-profile entity at the §6.5.1 path
    (V7 v7.64 §1.4: hex of the remote's ``system/peer`` content_hash)."""
    data: dict = {
        "peer_id": remote_kp.peer_id,
        "supported_ops": ["EXECUTE"],
        "freshness": "live",
        "nonce_required": True,
        "cap_flow": "both",
        "advertised_at": 1_000_000,
    }
    if transport_type is not None:
        data["transport_type"] = transport_type
    if not omit_endpoint:
        data["endpoint"] = {"url": url if url is not None else f"tcp://{address}"}
    entity = Entity(type=entity_type, data=data)
    peer.emit_pathway.emit(
        f"system/peer/transport/{_hex(remote_kp)}/{profile_id}",
        entity,
        EmitContext.bootstrap(),
    )


class TestRegisterRemoteProfile:
    """`Peer.register_remote` writes the §6.5.1 TCP profile at the
    `system/peer/transport/{peer_id}/{profile_id}` path (D1)."""

    def _make_peer(self):
        kp = Keypair.generate()
        return PeerBuilder().with_keypair(kp).with_all_handlers().build()

    def test_writes_at_profile_id_path(self):
        peer = self._make_peer()
        remote_kp = Keypair.generate()
        peer.register_remote(
            remote_kp.peer_id, "192.168.1.50:9000",
            public_key=remote_kp.public_key_bytes(),
        )

        # V7 v7.64 §1.4: path is `system/peer/transport/{peer_id_hex}/primary`.
        path = f"system/peer/transport/{_hex(remote_kp)}/primary"
        full_uri = peer.entity_tree.normalize_uri(path)
        h = peer.entity_tree.get(full_uri)
        assert h is not None
        entity = peer.content_store.get(h)
        assert entity is not None
        assert entity.type == "system/peer/transport/tcp"

    def test_explicit_profile_id_override(self):
        peer = self._make_peer()
        remote_kp = Keypair.generate()
        peer.register_remote(
            remote_kp.peer_id, "10.0.0.1:8080",
            public_key=remote_kp.public_key_bytes(),
            profile_id="cdn-mirror",
        )
        path = f"system/peer/transport/{_hex(remote_kp)}/cdn-mirror"
        assert peer.entity_tree.get(peer.entity_tree.normalize_uri(path)) is not None

    def test_profile_carries_all_required_fields(self):
        """§6.5: peer_id, transport_type, endpoint, supported_ops,
        freshness, nonce_required, cap_flow, advertised_at all required."""
        peer = self._make_peer()
        remote_kp = Keypair.generate()
        peer.register_remote(
            remote_kp.peer_id, "10.0.0.1:8080",
            public_key=remote_kp.public_key_bytes(),
        )

        path = f"system/peer/transport/{_hex(remote_kp)}/primary"
        full_uri = peer.entity_tree.normalize_uri(path)
        entity = peer.content_store.get(peer.entity_tree.get(full_uri))

        d = entity.data
        assert d["peer_id"] == remote_kp.peer_id
        assert d["transport_type"] == "tcp"
        assert d["endpoint"] == {"url": "tcp://10.0.0.1:8080"}
        assert d["supported_ops"] == ["EXECUTE"]
        assert d["freshness"] == "live"
        assert d["nonce_required"] is True
        assert d["cap_flow"] == "both"
        assert isinstance(d["advertised_at"], int)
        assert d["advertised_at"] > 0


class TestListProfileCandidates:
    """`RemoteConnectionPool._list_profile_candidates` applies the §6.5.1a
    D1 selection rule: `primary` first, then lex by profile-id;
    `advertised_at` is NOT a selection key. Returns
    `(profile_id, transport_type, url)` tuples for both tcp and http."""

    def _make_pool(self):
        kp = Keypair.generate()
        peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
        pool = RemoteConnectionPool(
            kp, peer.content_store, peer.entity_tree
        )
        return peer, pool

    def test_resolves_single_primary_profile(self):
        peer, pool = self._make_pool()
        remote_kp = Keypair.generate()
        peer.register_remote(
            remote_kp.peer_id, "10.0.0.1:8080",
            public_key=remote_kp.public_key_bytes(),
        )
        cands = pool._list_profile_candidates(remote_kp.peer_id)
        assert cands == [("primary", "tcp", "tcp://10.0.0.1:8080")]

    def test_unregistered_peer_returns_empty(self):
        _peer, pool = self._make_pool()
        assert pool._list_profile_candidates("unknown-peer-id") == []

    def test_primary_first_then_lex(self):
        """D1: 'primary' first, then remaining by lex order."""
        peer, pool = self._make_pool()
        remote_kp = Keypair.generate()
        _put_profile(peer, remote_kp, "zzz-backup", address="3.3.3.3:9003")
        _put_profile(peer, remote_kp, "fallback", address="2.2.2.2:9002")
        _put_profile(peer, remote_kp, "cdn-mirror", address="4.4.4.4:9004")
        _put_profile(peer, remote_kp, "primary", address="1.1.1.1:9001")

        cands = pool._list_profile_candidates(remote_kp.peer_id)
        ids = [c[0] for c in cands]
        assert ids == ["primary", "cdn-mirror", "fallback", "zzz-backup"]

    def test_advertised_at_is_not_a_selection_key(self):
        """D3: `advertised_at` is informational, not a tiebreaker. Lex
        order on profile-id wins regardless of who claims to be newer."""
        peer, pool = self._make_pool()
        remote_kp = Keypair.generate()
        from entity_core.protocol.entity import Entity

        def emit(profile_id: str, host: str, port: int, advertised_at: int):
            ent = Entity(
                type="system/peer/transport/tcp",
                data={
                    "peer_id": remote_kp.peer_id,
                    "transport_type": "tcp",
                    "endpoint": {"url": f"tcp://{host}:{port}"},
                    "supported_ops": ["EXECUTE"],
                    "freshness": "live",
                    "nonce_required": True,
                    "cap_flow": "both",
                    "advertised_at": advertised_at,
                },
            )
            peer.emit_pathway.emit(
                f"system/peer/transport/{_hex(remote_kp)}/{profile_id}",
                ent,
                EmitContext.bootstrap(),
            )

        emit("alpha", "1.1.1.1", 9001, advertised_at=1_000)
        emit("beta", "2.2.2.2", 9002, advertised_at=999_999)
        cands = pool._list_profile_candidates(remote_kp.peer_id)
        assert [c[0] for c in cands] == ["alpha", "beta"]

    def test_non_live_profiles_filtered_out(self):
        """`websocket` is not yet a live-dialable profile type in v1; the
        resolver returns only `tcp` and `http`."""
        peer, pool = self._make_pool()
        remote_kp = Keypair.generate()
        peer.register_remote(
            remote_kp.peer_id, "1.1.1.1:9001",
            public_key=remote_kp.public_key_bytes(),
        )
        _put_profile(
            peer,
            remote_kp,
            "websocket-fallback",
            entity_type="system/peer/transport/websocket",
            url="wss://example.com/ws",
            transport_type="websocket",
        )
        cands = pool._list_profile_candidates(remote_kp.peer_id)
        assert [c[0] for c in cands] == ["primary"]

    def test_d5_transport_type_must_match_suffix_raises(self):
        """D5: a `system/peer/transport/tcp` entity declaring
        transport_type != 'tcp' MUST be rejected (fail closed)."""
        peer, pool = self._make_pool()
        remote_kp = Keypair.generate()
        _put_profile(
            peer,
            remote_kp,
            "primary",
            entity_type="system/peer/transport/tcp",
            transport_type="websocket",  # mismatch — D5 violation
        )
        with pytest.raises(ConnectionError, match="D5: MUST match suffix"):
            pool._list_profile_candidates(remote_kp.peer_id)

    def test_malformed_endpoint_raises(self):
        peer, pool = self._make_pool()
        remote_kp = Keypair.generate()
        _put_profile(peer, remote_kp, "primary", omit_endpoint=True)
        with pytest.raises(ConnectionError, match="missing endpoint"):
            pool._list_profile_candidates(remote_kp.peer_id)


class TestSelfPublication:
    """§6.5.1a D1: Peer.start() SHOULD self-publish own primary profile."""

    def test_start_writes_own_profile(self):
        import asyncio

        kp = Keypair.generate()
        peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()

        async def run():
            # Use port 0 to let the OS pick — avoids collision in CI.
            await peer.start("127.0.0.1", 0)
            try:
                self_path = f"system/peer/transport/{peer.peer_id_hex}/primary"
                full_uri = peer.entity_tree.normalize_uri(self_path)
                h = peer.entity_tree.get(full_uri)
                assert h is not None, "expected self-published primary profile"
                ent = peer.content_store.get(h)
                assert ent.type == "system/peer/transport/tcp"
                assert ent.data["peer_id"] == peer.peer_id
                assert ent.data["transport_type"] == "tcp"
            finally:
                await peer.stop()

        asyncio.run(run())

    def test_start_does_not_clobber_existing_primary(self):
        """Operator may set a public address before start() — self-pub
        SHOULD NOT overwrite it."""
        import asyncio

        kp = Keypair.generate()
        peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
        # Operator pre-registers a public address.
        peer.register_remote(
            peer.peer_id, "public.example.com:9000",
            public_key=kp.public_key_bytes(),
        )

        async def run():
            await peer.start("127.0.0.1", 0)
            try:
                self_path = f"system/peer/transport/{peer.peer_id_hex}/primary"
                ent = peer.content_store.get(
                    peer.entity_tree.get(peer.entity_tree.normalize_uri(self_path))
                )
                # Operator's URL preserved; not clobbered by start()'s bind addr.
                assert ent.data["endpoint"]["url"] == "tcp://public.example.com:9000"
            finally:
                await peer.stop()

        asyncio.run(run())
