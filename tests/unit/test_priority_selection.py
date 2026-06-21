"""Q1 (PROPOSAL §8.9) — selection by explicit `priority`.

Sort order is `(priority asc, profile-id lex)`. Defaults:
- explicit `priority` on the entity → use it
- absent AND profile-id == `primary` → 0
- absent for any other id → 100

Back-compat: with no explicit priorities, the old "primary first, then
lex" behaviour is preserved verbatim.
"""

from __future__ import annotations

from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder
from entity_core.peer.remote import RemoteConnectionPool
from entity_core.protocol.auth import create_identity_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext


def _hex(kp: Keypair) -> str:
    return create_identity_entity(kp).compute_hash().hex()


def _make_pool():
    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
    return peer, RemoteConnectionPool(kp, peer.content_store, peer.entity_tree)


def _put_tcp(peer, remote_kp: Keypair, profile_id: str, port: int, *, priority=None):
    data = {
        "peer_id": remote_kp.peer_id,
        "transport_type": "tcp",
        "endpoint": {"url": f"tcp://127.0.0.1:{port}"},
        "supported_ops": ["EXECUTE"],
        "freshness": "live",
        "nonce_required": True,
        "cap_flow": "both",
    }
    if priority is not None:
        data["priority"] = priority
    ent = Entity(type="system/peer/transport/tcp", data=data)
    peer.emit_pathway.emit(
        f"system/peer/transport/{_hex(remote_kp)}/{profile_id}",
        ent,
        EmitContext.bootstrap(),
    )


class TestQ1Selection:

    def test_backcompat_no_priorities_primary_first_then_lex(self):
        """With no explicit priorities, the legacy ordering is preserved
        verbatim (primary→0, others→100; lex tie-break)."""
        peer, pool = _make_pool()
        remote_kp = Keypair.generate()
        _put_tcp(peer, remote_kp, "zebra", 9003)
        _put_tcp(peer, remote_kp, "alpha", 9002)
        _put_tcp(peer, remote_kp, "primary", 9001)
        cands = pool._list_profile_candidates(remote_kp.peer_id)
        assert [p[0] for p in cands] == ["primary", "alpha", "zebra"]

    def test_explicit_priority_beats_primary_default(self):
        """A non-primary profile with priority=0 outranks an unpriotized
        primary (which defaults to 0 — explicit 0 ties + lex picks the
        non-primary because 'a' < 'p')."""
        peer, pool = _make_pool()
        remote_kp = Keypair.generate()
        _put_tcp(peer, remote_kp, "primary", 9001)  # default → 0
        _put_tcp(peer, remote_kp, "alpha", 9002, priority=0)
        cands = pool._list_profile_candidates(remote_kp.peer_id)
        assert [p[0] for p in cands] == ["alpha", "primary"]

    def test_lower_priority_strictly_preferred(self):
        peer, pool = _make_pool()
        remote_kp = Keypair.generate()
        # Without explicit priority, "primary" defaults to 0 which would
        # win — set them all explicitly to expose the priority key.
        _put_tcp(peer, remote_kp, "primary", 9001, priority=50)
        _put_tcp(peer, remote_kp, "cdn-fast", 9002, priority=10)
        _put_tcp(peer, remote_kp, "cdn-slow", 9003, priority=200)
        cands = pool._list_profile_candidates(remote_kp.peer_id)
        assert [p[0] for p in cands] == ["cdn-fast", "primary", "cdn-slow"]

    def test_equal_priority_lex_tiebreak(self):
        peer, pool = _make_pool()
        remote_kp = Keypair.generate()
        _put_tcp(peer, remote_kp, "zeta", 9001, priority=10)
        _put_tcp(peer, remote_kp, "alpha", 9002, priority=10)
        _put_tcp(peer, remote_kp, "mu", 9003, priority=10)
        cands = pool._list_profile_candidates(remote_kp.peer_id)
        assert [p[0] for p in cands] == ["alpha", "mu", "zeta"]

    def test_primary_default_zero_only_when_priority_unset(self):
        """If primary EXPLICITLY sets priority, that value wins (no 0
        fallback). primary=300 should land last."""
        peer, pool = _make_pool()
        remote_kp = Keypair.generate()
        _put_tcp(peer, remote_kp, "primary", 9001, priority=300)
        _put_tcp(peer, remote_kp, "alpha", 9002)  # default → 100
        _put_tcp(peer, remote_kp, "beta", 9003, priority=50)
        cands = pool._list_profile_candidates(remote_kp.peer_id)
        assert [p[0] for p in cands] == ["beta", "alpha", "primary"]

    def test_register_remote_propagates_priority(self):
        """`register_remote(..., priority=N)` writes the field into the
        profile entity."""
        peer, pool = _make_pool()
        remote_kp = Keypair.generate()
        peer.register_remote(
            remote_kp.peer_id, "10.0.0.1:9000",
            public_key=remote_kp.public_key_bytes(),
            priority=42,
        )
        path = f"system/peer/transport/{_hex(remote_kp)}/primary"
        ent = peer.content_store.get(
            peer.entity_tree.get(peer.entity_tree.normalize_uri(path))
        )
        assert ent.data["priority"] == 42

    def test_register_remote_priority_unset_emits_no_field(self):
        """No explicit priority → omitempty (field absent on the wire)."""
        peer, pool = _make_pool()
        remote_kp = Keypair.generate()
        peer.register_remote(
            remote_kp.peer_id, "10.0.0.1:9000",
            public_key=remote_kp.public_key_bytes(),
        )
        path = f"system/peer/transport/{_hex(remote_kp)}/primary"
        ent = peer.content_store.get(
            peer.entity_tree.get(peer.entity_tree.normalize_uri(path))
        )
        assert "priority" not in ent.data
