"""Tests for handler grant signing + validation (spec-gap §S1, §S2).

These cover the cross-peer security gap diagnosed in
the python entity-native dispatch handoff:
peer A planting a grant signed by A's identity onto peer B's tree must be
rejected by B at dispatch time.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from entity_core.capability.grant_signing import (
    GrantValidationError,
    build_signed_handler_grant,
    grant_signature_path,
    verify_handler_grant,
)
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import create_identity_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers import HANDLERS_HANDLER_PATTERN
from entity_handlers.handlers import handlers_handler


# ============================================================================
# build_signed_handler_grant + verify_handler_grant unit tests
# ============================================================================

class TestSignAndVerify:

    def test_round_trip_passes(self):
        kp = Keypair.generate()
        identity = create_identity_entity(kp)
        identity_hash = identity.compute_hash()

        grants = [{"handlers": {"include": ["*"]},
                   "operations": {"include": ["*"]},
                   "resources": {"include": ["*"]}}]
        grant, signature, _ = build_signed_handler_grant(kp, grants)

        # Should not raise.
        verify_handler_grant(grant, signature, identity, identity_hash)

    def test_granter_and_grantee_set_to_local_identity(self):
        kp = Keypair.generate()
        identity_hash = create_identity_entity(kp).compute_hash()

        grant, _, _ = build_signed_handler_grant(kp, [])
        assert grant.data["granter"] == identity_hash
        assert grant.data["grantee"] == identity_hash
        assert "created_at" in grant.data

    def test_signature_targets_grant_hash_and_signer_is_granter(self):
        kp = Keypair.generate()
        grant, signature, _ = build_signed_handler_grant(kp, [])
        assert signature.type == "system/signature"
        assert signature.data["target"] == grant.compute_hash()
        assert signature.data["signer"] == grant.data["granter"]
        assert signature.data["algorithm"] == "ed25519"


# ============================================================================
# Validation rejection paths (spec-gap §S2)
# ============================================================================

class TestVerifyRejections:

    def _setup(self):
        kp = Keypair.generate()
        identity = create_identity_entity(kp)
        identity_hash = identity.compute_hash()
        return kp, identity, identity_hash

    def test_rejects_null_granter(self):
        """A grant with null granter must be rejected (the failure mode the
        validation doc describes as the original behavior)."""
        _, identity, identity_hash = self._setup()
        grant = Entity(type="system/capability/token", data={
            "grants": [],
            "granter": None,
            "grantee": None,
            "created_at": int(time.time() * 1000),
        })
        with pytest.raises(GrantValidationError) as exc:
            verify_handler_grant(grant, None, identity, identity_hash)
        assert "granter" in exc.value.message.lower()

    def test_rejects_foreign_granter(self):
        """The cross-peer attack: peer A's grant arrives at peer B. B's
        validator must reject because grant.granter != B's identity hash."""
        kp_a = Keypair.generate()
        identity_a = create_identity_entity(kp_a)

        # Peer A signs their grant.
        grant_a, signature_a, _ = build_signed_handler_grant(kp_a, [])

        # Peer B's identity (the receiver).
        kp_b = Keypair.generate()
        identity_b_hash = create_identity_entity(kp_b).compute_hash()

        with pytest.raises(GrantValidationError) as exc:
            verify_handler_grant(grant_a, signature_a, identity_a, identity_b_hash)
        assert "granter" in exc.value.message.lower()

    def test_rejects_missing_signature(self):
        kp, identity, identity_hash = self._setup()
        grant, _, _ = build_signed_handler_grant(kp, [])
        with pytest.raises(GrantValidationError) as exc:
            verify_handler_grant(grant, None, identity, identity_hash)
        assert "signature" in exc.value.message.lower()

    def test_rejects_signature_targeting_wrong_hash(self):
        kp, identity, identity_hash = self._setup()
        grant, _, _ = build_signed_handler_grant(kp, [])
        # Build a signature over a different hash.
        bogus_signature = Entity(type="system/signature", data={
            "target": b"\x00" * 33,
            "algorithm": "ed25519",
            "signature": b"\x00" * 64,
            "signer": identity_hash,
        })
        with pytest.raises(GrantValidationError) as exc:
            verify_handler_grant(grant, bogus_signature, identity, identity_hash)
        assert "target" in exc.value.message.lower()

    def test_rejects_mismatched_signer(self):
        kp, identity, identity_hash = self._setup()
        grant, signature, _ = build_signed_handler_grant(kp, [])
        # Tamper signer.
        tampered = Entity(type="system/signature", data={
            **signature.data,
            "signer": b"\xff" * 33,
        })
        with pytest.raises(GrantValidationError) as exc:
            verify_handler_grant(grant, tampered, identity, identity_hash)
        assert "signer" in exc.value.message.lower()

    def test_rejects_bad_signature_bytes(self):
        kp, identity, identity_hash = self._setup()
        grant, signature, _ = build_signed_handler_grant(kp, [])
        # Tamper signature bytes.
        tampered = Entity(type="system/signature", data={
            **signature.data,
            "signature": b"\x00" * 64,
        })
        with pytest.raises(GrantValidationError) as exc:
            verify_handler_grant(grant, tampered, identity, identity_hash)
        assert "verification" in exc.value.message.lower()

    def test_rejects_unsupported_algorithm(self):
        kp, identity, identity_hash = self._setup()
        grant, signature, _ = build_signed_handler_grant(kp, [])
        bad_alg = Entity(type="system/signature", data={
            **signature.data,
            "algorithm": "rsa",
        })
        with pytest.raises(GrantValidationError) as exc:
            verify_handler_grant(grant, bad_alg, identity, identity_hash)
        assert "algorithm" in exc.value.message.lower()

    def test_rejects_expired_grant(self):
        kp, identity, identity_hash = self._setup()
        past = int(time.time() * 1000) - 60_000
        grant, signature, _ = build_signed_handler_grant(
            kp, [], expires_at=past,
        )
        with pytest.raises(GrantValidationError) as exc:
            verify_handler_grant(grant, signature, identity, identity_hash)
        assert "expired" in exc.value.message.lower()

    def test_rejects_not_yet_valid(self):
        kp, identity, identity_hash = self._setup()
        future = int(time.time() * 1000) + 60_000
        grant, signature, _ = build_signed_handler_grant(
            kp, [], not_before=future,
        )
        with pytest.raises(GrantValidationError) as exc:
            verify_handler_grant(grant, signature, identity, identity_hash)
        assert "not yet valid" in exc.value.message.lower()

    def test_rejects_no_granter_identity(self):
        kp, _, identity_hash = self._setup()
        grant, signature, _ = build_signed_handler_grant(kp, [])
        with pytest.raises(GrantValidationError) as exc:
            verify_handler_grant(grant, signature, None, identity_hash)
        assert "granter identity" in exc.value.message.lower()


# ============================================================================
# Bootstrap grants are signed (Peer._create_handler_grants)
# ============================================================================

class TestBootstrapGrants:

    def test_bootstrap_emits_signed_grants(self):
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .build()
        )
        ep = peer.emit_pathway
        local_identity_hash = create_identity_entity(peer.keypair).compute_hash()

        # The bootstrap handlers all live at known patterns. Pick the
        # handlers handler itself.
        grant_path = "system/capability/grants/system/handler"
        grant_h = ep.entity_tree.get(grant_path)
        assert grant_h is not None
        grant = ep.content_store.get(grant_h)
        assert grant.data["granter"] == local_identity_hash
        assert grant.data["grantee"] == local_identity_hash

        # v7.74 v0.4 §3.4: signature at the invariant-pointer path keyed
        # by the grant's content hash, not colocated with the grant.
        sig_h = ep.entity_tree.get(grant_signature_path(grant_h))
        assert sig_h is not None
        sig = ep.content_store.get(sig_h)
        assert sig.data["signer"] == local_identity_hash
        assert sig.data["target"] == grant.compute_hash()

    def test_bootstrap_grant_validates_via_get_handler_grant(self):
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .build()
        )
        # _get_handler_grant returns dict on success, None on failure.
        grant_data = peer._get_handler_grant("system/handler")
        assert grant_data is not None
        assert "grants" in grant_data


# ============================================================================
# Foreign-granter rejection at dispatch read (the security regression)
# ============================================================================

class TestForeignGranterRejection:

    def test_planted_foreign_grant_is_rejected(self):
        """Plant peer A's grant onto peer B's tree at the same path. Peer
        B's _get_handler_grant must return None (validation fails).

        This is the cross-peer security attack from
        the python entity-native dispatch handoff."""
        peer_b = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .build()
        )
        # Sanity: B's own bootstrap grant validates.
        assert peer_b._get_handler_grant("system/tree") is not None

        # Now overwrite B's grant for system/tree with one signed by peer A.
        kp_a = Keypair.generate()
        grant_a, sig_a, identity_a = build_signed_handler_grant(kp_a, [
            {"handlers": {"include": ["*"]},
             "operations": {"include": ["*"]},
             "resources": {"include": ["*"]}},
        ])
        ep = peer_b.emit_pathway
        # Persist A's identity in B's content store so granter resolves —
        # this models what a real attack would look like (A submits all
        # supporting entities).
        ep.content_store.put(identity_a)
        ep.emit("system/capability/grants/system/tree", grant_a, EmitContext.bootstrap())
        ep.emit(
            grant_signature_path(grant_a.compute_hash()),
            sig_a,
            EmitContext.bootstrap(),
        )

        # B refuses the planted grant — the granter is not B's identity.
        assert peer_b._get_handler_grant("system/tree") is None


# ============================================================================
# handlers_handler:register emits signed grants
# ============================================================================

class TestRegisterEmitsSignedGrant:

    @pytest.mark.asyncio
    async def test_register_emits_signed_grant_and_signature(self):
        kp = Keypair.generate()
        cs = ContentStore()
        et = EntityTree(kp.peer_id)
        ep = EmitPathway(cs, et)

        ctx = MagicMock()
        ctx.emit_pathway = ep
        ctx.local_peer_id = kp.peer_id
        ctx.handler_pattern = HANDLERS_HANDLER_PATTERN
        ctx.bounds = None
        ctx.keypair = kp
        ctx.resource_targets = ["system/handler/local/foo"]

        manifest = {"type": "system/handler/manifest", "data": {
            "pattern": "local/foo",
            "name": "foo",
            "operations": {"do": {}},
        }}
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register",
            {"data": {"manifest": manifest}}, ctx,
        )
        assert result["status"] == 200

        local_identity_hash = create_identity_entity(kp).compute_hash()

        grant_path = "system/capability/grants/local/foo"
        grant = cs.get(et.get(grant_path))
        assert grant.data["granter"] == local_identity_hash

        sig = cs.get(et.get(grant_signature_path(grant.compute_hash())))
        assert sig.data["signer"] == local_identity_hash
        assert sig.data["target"] == grant.compute_hash()

    @pytest.mark.asyncio
    async def test_register_rejected_when_no_keypair_in_ctx(self):
        cs = ContentStore()
        et = EntityTree("peer1")
        ep = EmitPathway(cs, et)

        ctx = MagicMock()
        ctx.emit_pathway = ep
        ctx.local_peer_id = "peer1"
        ctx.handler_pattern = HANDLERS_HANDLER_PATTERN
        ctx.bounds = None
        ctx.keypair = None
        ctx.resource_targets = ["system/handler/local/foo"]

        manifest = {"type": "system/handler/manifest", "data": {
            "pattern": "local/foo",
            "name": "foo",
            "operations": {"do": {}},
        }}
        result = await handlers_handler(
            HANDLERS_HANDLER_PATTERN, "register",
            {"data": {"manifest": manifest}}, ctx,
        )
        assert result["status"] == 500
        assert "keypair" in result["result"]["data"]["message"].lower()


# ============================================================================
# Dispatch-level: _get_handler_grant returns None on rejection
# ============================================================================

class TestDispatchGrantRejection:
    """Lower-level than the security test above — covers each rejection
    path through _get_handler_grant rather than verify_handler_grant."""

    def _peer(self):
        return (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .build()
        )

    def test_missing_grant_returns_none(self):
        peer = self._peer()
        assert peer._get_handler_grant("never/registered") is None

    def test_grant_without_signature_returns_none(self):
        peer = self._peer()
        ep = peer.emit_pathway
        # Write an unsigned grant at a fresh pattern.
        unsigned = Entity(type="system/capability/token", data={
            "grants": [],
            "granter": peer._get_local_identity_hash(),
            "grantee": peer._get_local_identity_hash(),
            "created_at": int(time.time() * 1000),
        })
        ep.emit("system/capability/grants/local/foo", unsigned, EmitContext.bootstrap())
        # No signature emitted at the sibling path.
        assert peer._get_handler_grant("local/foo") is None
