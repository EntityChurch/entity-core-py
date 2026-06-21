"""Q6 (PROPOSAL §8.2 / §8.9) — `advertised_at` is OPTIONAL.

A live profile entity MUST decode even when `advertised_at` is absent
(`omitempty` honored across impls). D-3 already labelled it advisory
and not a selection key; §6.5.1's MUST-list contradicted that and is
being relaxed in the Round-3 amendment.

Python's resolver doesn't read `advertised_at` at all, so it is
inherently permissive — this file pins that contract so a future
refactor can't reintroduce a required-field check.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder
from entity_core.peer.remote import RemoteConnectionPool
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext


def _make_pool():
    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
    return peer, RemoteConnectionPool(kp, peer.content_store, peer.entity_tree)


def _put_profile_without_advertised_at(peer, remote_peer_id: str) -> None:
    """Emit a §6.5.1 TCP profile entity that OMITS `advertised_at`."""
    from entity_core.protocol.auth import compute_peer_identity_hash
    entity = Entity(
        type="system/peer/transport/tcp",
        data={
            "peer_id": remote_peer_id,
            "transport_type": "tcp",
            "endpoint": {"url": "tcp://10.0.0.1:9000"},
            "supported_ops": ["EXECUTE"],
            "freshness": "live",
            "nonce_required": True,
            "cap_flow": "both",
            # advertised_at deliberately omitted (Q6 — OPTIONAL)
        },
    )
    # V7 v7.64 §1.4: path key is hex of `system/peer` content_hash.
    # Identity-form PeerIDs derive locally per §1.5.
    remote_hex = compute_peer_identity_hash(remote_peer_id).hex()
    peer.emit_pathway.emit(
        f"system/peer/transport/{remote_hex}/primary",
        entity,
        EmitContext.bootstrap(),
    )


class TestAdvertisedAtOptional:

    def test_profile_without_advertised_at_resolves(self):
        peer, pool = _make_pool()
        remote_kp = Keypair.generate()
        _put_profile_without_advertised_at(peer, remote_kp.peer_id)

        cands = pool._list_profile_candidates(remote_kp.peer_id)
        assert cands == [("primary", "tcp", "tcp://10.0.0.1:9000")]

    def test_d3_advertised_at_absent_not_a_selection_key(self):
        """Two profiles, one with advertised_at and one without, must still
        D1-sort by (priority/lex), not by presence-of-advertised_at."""
        peer, pool = _make_pool()
        remote_kp = Keypair.generate()
        _put_profile_without_advertised_at(peer, remote_kp.peer_id)

        # A second profile WITH advertised_at, lex-later id.
        ent = Entity(
            type="system/peer/transport/tcp",
            data={
                "peer_id": remote_kp.peer_id,
                "transport_type": "tcp",
                "endpoint": {"url": "tcp://10.0.0.2:9000"},
                "supported_ops": ["EXECUTE"],
                "freshness": "live",
                "nonce_required": True,
                "cap_flow": "both",
                "advertised_at": 999_999,
            },
        )
        from entity_core.protocol.auth import compute_peer_identity_hash
        remote_hex = compute_peer_identity_hash(remote_kp.peer_id).hex()
        peer.emit_pathway.emit(
            f"system/peer/transport/{remote_hex}/secondary",
            ent,
            EmitContext.bootstrap(),
        )

        cands = pool._list_profile_candidates(remote_kp.peer_id)
        # primary first (reserved id), secondary next (lex).
        assert [p[0] for p in cands] == ["primary", "secondary"]
