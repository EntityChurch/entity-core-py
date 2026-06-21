"""V7 §4.4 v7.62 — authenticate-response initial grant scope is the
SHOULD floor ∪ matched policy-table entry.

Pinned via the responder's grant-resolution path: a policy entry seeded
under ``system/capability/policy/{caller_peer_hex}`` is unioned into the
returned grant set; the floor's tree-discovery + capability-request
grants are always present.
"""

from __future__ import annotations

from entity_core.capability.grant import create_connect_grants
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import create_identity_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext


POLICY_ROOT = "system/capability/policy"


def _seed_policy(peer, peer_pattern: str, grants: list[dict]) -> None:
    entity = Entity(
        type="system/capability/policy-entry",
        data={"peer_pattern": peer_pattern, "grants": grants},
    )
    peer.emit_pathway.emit(
        f"{POLICY_ROOT}/{peer_pattern}", entity, EmitContext.bootstrap(),
    )


def _grant_to_dict(g) -> dict:
    """Flatten a Grant to a comparable dict shape (sorted include lists)."""
    return {
        "handlers": sorted(g.handlers.include),
        "resources": sorted(g.resources.include),
        "operations": sorted(g.operations.include),
    }


def test_no_policy_entry_returns_should_floor_only() -> None:
    peer = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    caller_kp = Keypair.generate()
    caller_id = create_identity_entity(caller_kp).compute_hash()

    grants = peer._get_grants_for_peer(caller_kp.peer_id, caller_id)
    assert grants is not None
    flat = [_grant_to_dict(g) for g in grants]
    floor = [_grant_to_dict(g) for g in create_connect_grants()]
    assert flat == floor


def test_specific_policy_entry_unioned_into_floor() -> None:
    peer = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    caller_kp = Keypair.generate()
    caller_id = create_identity_entity(caller_kp).compute_hash()

    extra = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get", "put"]},
    }]
    _seed_policy(peer, caller_id.hex(), extra)

    grants = peer._get_grants_for_peer(caller_kp.peer_id, caller_id)
    assert grants is not None
    flat = [_grant_to_dict(g) for g in grants]
    floor = [_grant_to_dict(g) for g in create_connect_grants()]
    expected_extra = [{
        "handlers": ["system/tree"],
        "resources": ["app/*"],
        "operations": ["get", "put"],
    }]
    assert flat == floor + expected_extra


def test_default_policy_entry_used_when_no_specific_match() -> None:
    peer = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    caller_kp = Keypair.generate()
    caller_id = create_identity_entity(caller_kp).compute_hash()

    _seed_policy(peer, "default", [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["public/*"]},
        "operations": {"include": ["get"]},
    }])

    grants = peer._get_grants_for_peer(caller_kp.peer_id, caller_id)
    assert grants is not None
    flat = [_grant_to_dict(g) for g in grants]
    floor = [_grant_to_dict(g) for g in create_connect_grants()]
    assert flat == floor + [{
        "handlers": ["system/tree"],
        "resources": ["public/*"],
        "operations": ["get"],
    }]


def test_specific_entry_wins_over_default() -> None:
    """When both exist, the specific entry takes precedence (no double-union).

    V7 §6.2 v7.63 F8: fallback segment renamed from ``*`` to ``default``."""
    peer = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    caller_kp = Keypair.generate()
    caller_id = create_identity_entity(caller_kp).compute_hash()

    _seed_policy(peer, "default", [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["public/*"]},
        "operations": {"include": ["get"]},
    }])
    _seed_policy(peer, caller_id.hex(), [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["put"]},
    }])

    grants = peer._get_grants_for_peer(caller_kp.peer_id, caller_id)
    assert grants is not None
    flat = [_grant_to_dict(g) for g in grants]
    # Specific entry's resources are app/*, NOT public/*.
    extras = [g for g in flat if g["resources"] == ["app/*"]]
    assert len(extras) == 1
    assert not any(g["resources"] == ["public/*"] for g in flat)
