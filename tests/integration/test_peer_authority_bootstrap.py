"""V7 §6.9a peer-authority-bootstrap (F27) — Python pin tests.

The bootstrap materializes, at peer-init (L0):

  1. A principal-level self-owner capability over ``/{peer_id}/*`` written
     as a ``system/capability/policy-entry`` at the v7.64 hex-form path
     ``system/capability/policy/{self_identity_hash_hex}`` (§6.9a.1).
  2. Any operator-declared seed-policy entries (builder ``with_seed_policy`` /
     ``with_seed_policy_from_file``), including a ``default`` entry.

It COEXISTS with the per-handler self-grants (§6.9a.4) and is read back at
§4.6 authenticate via the existing v7.62 §8 / v7.64 dual-form policy path
(``_get_grants_for_peer`` → ``_read_policy_grants_for``).
"""

from __future__ import annotations

import json

import pytest

from entity_core.capability.grant import Grant, create_owner_grant
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import create_identity_entity


def _build(**kw) -> "tuple":
    kp = Keypair.generate()
    builder = PeerBuilder().with_keypair(kp).with_all_handlers()
    for method, arg in kw.items():
        getattr(builder, method)(arg)
    return builder.build(), kp


def _policy_entry(peer, key: str):
    h = peer.entity_tree.get(f"system/capability/policy/{key}")
    if h is None:
        return None
    return peer.content_store.get(h)


# ---------------------------------------------------------------------------
# Owner cap bootstrap (§6.9a + §3.5 floor)
# ---------------------------------------------------------------------------

def test_self_owner_entry_materialized_at_hex_path() -> None:
    """The owner cap is written eagerly at peer-init at the hex-form path
    keyed by the peer's own identity content hash (A1 + A5)."""
    peer, kp = _build()
    self_hex = create_identity_entity(kp).compute_hash().hex()

    entry = _policy_entry(peer, self_hex)
    assert entry is not None, "self-owner seed entry not materialized at L0"
    assert entry.type == "system/capability/policy-entry"
    assert entry.data["peer_pattern"] == self_hex

    # The grant is full authority over the peer's OWN namespace.
    grants = entry.data["grants"]
    assert len(grants) == 1
    g = grants[0]
    assert g["handlers"]["include"] == ["*"]
    assert g["operations"]["include"] == ["*"]
    assert f"/{kp.peer_id}/*" in g["resources"]["include"]


def test_owner_grant_is_namespace_scoped_not_cross_peer() -> None:
    """Owner cap is local-namespace only — no cross-namespace /*/* axis
    (that distinguishes it from create_full_access_grant)."""
    grants = create_owner_grant("PEERID")
    assert len(grants) == 1
    resources = grants[0].resources.include
    assert "/*/*" not in resources
    assert grants[0].peers is None


def test_owner_cap_coexists_with_per_handler_self_grants() -> None:
    """§6.9a.4 coexistence: the principal-level owner entry is ADDED; the
    per-handler self-grants remain in place and still validate."""
    peer, _ = _build()
    # Per-handler self-grant still resolves + validates at dispatch read.
    assert peer._get_handler_grant("system/tree") is not None
    assert peer._get_handler_grant("system/handler") is not None


def test_owner_authenticates_to_full_namespace_authority() -> None:
    """When the key-holder operator connects over the wire (remote identity
    == self), the owner entry is read back and UNION'd into the floor."""
    peer, kp = _build()
    self_hash = create_identity_entity(kp).compute_hash()

    grants = peer._get_grants_for_peer(kp.peer_id, self_hash)
    assert grants is not None
    # The owner grant (all handlers/ops over own namespace) is present on
    # top of the discovery floor.
    owner_present = any(
        g.handlers.include == ["*"]
        and g.operations.include == ["*"]
        and f"/{kp.peer_id}/*" in g.resources.include
        for g in grants
    )
    assert owner_present, "owner cap not derived at authenticate-time"


# ---------------------------------------------------------------------------
# Operator override + seed policy
# ---------------------------------------------------------------------------

def test_operator_override_keys_owner_by_operator_identity() -> None:
    """--operator equivalent: the owner cap is keyed by the declared
    operator identity, not self."""
    operator_kp = Keypair.generate()
    operator_identity = create_identity_entity(operator_kp)
    operator_hex = operator_identity.compute_hash().hex()

    peer, kp = _build(with_owner_identity=operator_identity)
    self_hex = create_identity_entity(kp).compute_hash().hex()

    assert _policy_entry(peer, operator_hex) is not None
    # No self entry when an explicit operator owns the peer.
    assert _policy_entry(peer, self_hex) is None


def test_with_seed_policy_materializes_named_and_default_entries() -> None:
    reader_kp = Keypair.generate()
    reader_hex = create_identity_entity(reader_kp).compute_hash().hex()

    policy = {
        "default": [
            Grant.create(
                handlers=["system/tree"], resources=["docs/*"],
                operations=["get"],
            ),
        ],
        reader_hex: [
            Grant.create(
                handlers=["system/query"], resources=["*"],
                operations=["find"],
            ),
        ],
    }
    peer, _ = _build(with_seed_policy=policy)

    default_entry = _policy_entry(peer, "default")
    assert default_entry is not None
    assert default_entry.data["grants"][0]["resources"]["include"] == ["docs/*"]

    reader_entry = _policy_entry(peer, reader_hex)
    assert reader_entry is not None
    assert reader_entry.data["grants"][0]["handlers"]["include"] == [
        "system/query"
    ]


def test_seed_policy_default_drives_authenticate_for_unknown_peer() -> None:
    """A declared `default` entry is unioned into the floor for any
    un-named authenticated identity (§6.9a default entry)."""
    policy = {
        "default": [
            Grant.create(
                handlers=["system/tree"], resources=["public/*"],
                operations=["get"],
            ),
        ],
    }
    peer, _ = _build(with_seed_policy=policy)

    stranger_kp = Keypair.generate()
    stranger_hash = create_identity_entity(stranger_kp).compute_hash()
    grants = peer._get_grants_for_peer(stranger_kp.peer_id, stranger_hash)
    assert any(
        "public/*" in g.resources.include for g in grants
    ), "default seed-policy entry not applied at authenticate"


# ---------------------------------------------------------------------------
# Seed-policy file format — the keystone-owned cross-peer canonical shape
# (protocol-generator/shared/seed-policy/seed-policy.schema.json). All three
# ground-up impls read this ONE format; these tests lock Python's side.
# ---------------------------------------------------------------------------

# The keystone examples/operator-admin.json pattern: a named operator hex
# granted wide admin, everyone else falling to a declared floor.
_ADMIN_HEX = (
    "0098ddb68a95829a86dd50f328062fadb1926c3667866e4b389b161dfcf3c2a556"
)


def _canonical_seed_policy() -> dict:
    return {
        "version": 1,
        "entries": [
            {"grantee": "self", "grants": []},
            {
                "grantee": _ADMIN_HEX,
                "grants": [{
                    "handlers": {"include": ["*"]},
                    "resources": {"include": ["*", "/*/*"]},
                    "operations": {"include": ["*"]},
                    "peers": {"include": ["self"]},
                }],
            },
            {
                "grantee": "default",
                "grants": [{
                    "handlers": {"include": ["system/tree"]},
                    "resources": {"include": ["shared/*"]},
                    "operations": {"include": ["get"]},
                }],
            },
        ],
    }


def _write(tmp_path, doc: dict):
    f = tmp_path / "seed-policy.json"
    f.write_text(json.dumps(doc))
    return str(f)


def test_seed_policy_from_file_reads_keystone_canonical(tmp_path) -> None:
    """`{version, entries:[{grantee, grants}]}` — the canonical container."""
    peer, _ = _build(
        with_seed_policy_from_file=_write(tmp_path, _canonical_seed_policy()),
    )

    default_entry = _policy_entry(peer, "default")
    assert default_entry is not None
    assert default_entry.data["grants"][0]["resources"]["include"] == [
        "shared/*"
    ]

    # `grantee` keys the entry; the lowercase §3.6 grant fields parse.
    admin_entry = _policy_entry(peer, _ADMIN_HEX)
    assert admin_entry is not None
    admin_grant = admin_entry.data["grants"][0]
    assert admin_grant["handlers"]["include"] == ["*"]
    assert admin_grant["operations"]["include"] == ["*"]
    assert admin_grant["peers"]["include"] == ["self"]


def test_seed_policy_from_file_skips_self_entry(tmp_path) -> None:
    """`self` is materialized from the owner identity, not the file — so the
    file's self entry (empty grants above) must not overwrite the owner cap."""
    peer, kp = _build(
        with_seed_policy_from_file=_write(tmp_path, _canonical_seed_policy()),
    )

    assert _policy_entry(peer, "self") is None
    self_hex = create_identity_entity(kp).compute_hash().hex()
    owner_entry = _policy_entry(peer, self_hex)
    assert owner_entry is not None, "owner cap lost to the file's self entry"
    assert owner_entry.data["grants"], "owner cap emptied by the file"


def test_seed_policy_from_file_carries_constraints_and_allowances(
    tmp_path,
) -> None:
    """The schema types constraints/allowances as JSON objects; Python's grant
    model holds them as dicts, so they survive the file → policy-entry path."""
    doc = {
        "version": 1,
        "entries": [{
            "grantee": "default",
            "grants": [{
                "handlers": {"include": ["system/query"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["find"]},
                "constraints": {"type_scope": "docs/note"},
                "allowances": {"max_results": 10},
            }],
        }],
    }
    peer, _ = _build(with_seed_policy_from_file=_write(tmp_path, doc))

    grant = _policy_entry(peer, "default").data["grants"][0]
    assert grant["constraints"] == {"type_scope": "docs/note"}
    assert grant["allowances"] == {"max_results": 10}


def test_seed_policy_from_file_tolerates_comment_keys(tmp_path) -> None:
    """Both keystone examples ship `_comment` keys — top-level in
    debug-open.json, entry-level in operator-admin.json — which the schema's
    `additionalProperties: false` actually forbids (routed upstream). The
    loader stays lenient so the shipped examples load, matching Go.
    """
    doc = {
        "_comment": "the degenerate default -> * policy",
        "version": 1,
        "entries": [{
            "_comment": "a named operator identity",
            "grantee": "default",
            "grants": [{
                "handlers": {"include": ["*"]},
                "resources": {"include": ["*", "/*/*"]},
                "operations": {"include": ["*"]},
            }],
        }],
    }
    peer, _ = _build(with_seed_policy_from_file=_write(tmp_path, doc))

    entry = _policy_entry(peer, "default")
    assert entry is not None
    assert entry.data["grants"][0]["resources"]["include"] == ["*", "/*/*"]


def test_seed_policy_from_file_rejects_unsupported_version(tmp_path) -> None:
    path = _write(tmp_path, {"version": 2, "entries": []})
    with pytest.raises(ValueError, match="version"):
        PeerBuilder().with_seed_policy_from_file(path)


def test_seed_policy_from_file_rejects_missing_container(tmp_path) -> None:
    """The pre-canonical Python shape (a keyed object of grantee → grants) has
    no `version` — it must fail loudly, not seed an empty policy."""
    path = _write(tmp_path, {
        "default": {"grants": [{
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["get"]},
        }]},
    })
    with pytest.raises(ValueError, match="version"):
        PeerBuilder().with_seed_policy_from_file(path)


def test_seed_policy_from_file_rejects_duplicate_grantee(tmp_path) -> None:
    """Entries are keyed by grantee; a repeat would silently drop grants."""
    grants = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["*"]},
        "operations": {"include": ["get"]},
    }]
    path = _write(tmp_path, {
        "version": 1,
        "entries": [
            {"grantee": "default", "grants": grants},
            {"grantee": "default", "grants": grants},
        ],
    })
    with pytest.raises(ValueError, match="duplicate grantee"):
        PeerBuilder().with_seed_policy_from_file(path)


def test_seed_policy_from_file_rejects_unhonourable_bounds(tmp_path) -> None:
    """`bounds` is schema-optional but policy-entry has no not_before /
    expires_at — seeding it as unbounded would be a silent authority upgrade."""
    path = _write(tmp_path, {
        "version": 1,
        "entries": [{
            "grantee": "default",
            "grants": [{
                "handlers": {"include": ["*"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["get"]},
            }],
            "bounds": {"expires_at": 1_800_000_000_000},
        }],
    })
    with pytest.raises(ValueError, match="bounds"):
        PeerBuilder().with_seed_policy_from_file(path)


def test_seed_policy_from_file_rejects_entry_without_grantee(tmp_path) -> None:
    path = _write(tmp_path, {
        "version": 1,
        "entries": [{"grants": []}],
    })
    with pytest.raises(ValueError, match="grantee"):
        PeerBuilder().with_seed_policy_from_file(path)
