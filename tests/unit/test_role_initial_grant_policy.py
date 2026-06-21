"""Tests for EXTENSION-ROLE §4.7 initial-grant policy resolver.

Mirrors the Go cross-impl validation profile TV-RV-2.7
(`role_stage2_recognize_on_attest_*`) at the resolver layer:
- positive: agent-cert chain to a controller under the trusted quorum
            → role grants are issued.
- bare keypair: no agent-cert → fall back per `identity_required`.
- unrelated controller: agent-cert under a different quorum → no
  recognition.

See the recognize-on-attestation handoff.
"""

from __future__ import annotations

from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree

from entity_handlers.attestation import make_attestation
from entity_handlers.identity import (
    FUNCTION_AGENT,
    FUNCTION_CONTROLLER,
    KIND_IDENTITY_CERT,
    PEER_CONFIG_PATH,
    PEER_CONFIG_TYPE,
)
from entity_handlers.role import (
    INITIAL_GRANT_MODE_ANONYMOUS_ALLOW,
    INITIAL_GRANT_MODE_ANONYMOUS_DENY,
    INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION,
    INITIAL_GRANT_POLICY_PATH,
    INITIAL_GRANT_POLICY_TYPE,
    role_definition_path,
    role_exclusion_path,
)
from entity_handlers.role_policy import (
    PolicyGrantResolver,
    chain_grant_resolvers,
    read_initial_grant_policy,
    recognize_identity_cert,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


CTX_NAME = "stage2"
ROLE_NAME = "guest"

# A role-def grant shape distinct from the connect-scope fallback so
# tests can tell which one was issued.
GUEST_GRANT_DICT = {
    "handlers": {"include": ["system/tree"]},
    "resources": {"include": [f"shared/{CTX_NAME}/*"]},
    "operations": {"include": ["get"]},
}


def _make_pathway() -> tuple[EmitPathway, str]:
    """Construct a fresh local-peer EmitPathway, return (pathway, peer_id)."""
    keypair = Keypair.generate()
    pathway = EmitPathway(ContentStore(), EntityTree(keypair.peer_id))
    return pathway, keypair.peer_id


def _emit(pathway: EmitPathway, path: str, entity: Entity) -> bytes:
    return pathway.emit(path, entity, EmitContext.bootstrap()).hash


def _bind_peer(pathway: EmitPathway, kp: Keypair) -> bytes:
    """Bind a peer's `system/peer` identity entity and return its hash."""
    entity = Entity(
        type="system/peer",
        data={
            "peer_id": kp.peer_id,
            "public_key": kp.public_key_bytes(),
            "key_type": "ed25519",
        },
    )
    h = entity.compute_hash()
    _emit(pathway, f"system/peer/identity/{kp.peer_id}", entity)
    return h


def _bind_policy(
    pathway: EmitPathway,
    *,
    mode: str,
    default_role: str = ROLE_NAME,
    default_context: str = CTX_NAME,
    identity_required: bool = False,
) -> None:
    data: dict[str, Any] = {"unknown_peer": mode}
    if default_role:
        data["default_role"] = default_role
    if default_context:
        data["default_context"] = default_context
    if identity_required:
        data["identity_required"] = True
    _emit(
        pathway, INITIAL_GRANT_POLICY_PATH,
        Entity(type=INITIAL_GRANT_POLICY_TYPE, data=data),
    )


def _bind_role_def(
    pathway: EmitPathway,
    *,
    context: str = CTX_NAME,
    role_name: str = ROLE_NAME,
    grants: list[dict[str, Any]] | None = None,
) -> None:
    role_grants = grants if grants is not None else [GUEST_GRANT_DICT]
    _emit(
        pathway, role_definition_path(context, role_name),
        Entity(
            type="system/role",
            data={"name": role_name, "grants": role_grants},
        ),
    )


def _bind_peer_config(pathway: EmitPathway, trusts_quorum: bytes) -> None:
    _emit(
        pathway, PEER_CONFIG_PATH,
        Entity(
            type=PEER_CONFIG_TYPE,
            data={"trusts_quorum": trusts_quorum, "bindings": []},
        ),
    )


def _att_path(h: bytes) -> str:
    return f"test/attestation/{h.hex()}"


def _bind_identity_cert(
    pathway: EmitPathway,
    *,
    function: str,
    attesting: bytes,
    attested: bytes,
) -> bytes:
    """Bind an unsigned identity-cert attestation. Resolver doesn't
    verify signatures (verification happens at `:create` time)."""
    att = make_attestation(
        attesting=attesting,
        attested=attested,
        properties={"kind": KIND_IDENTITY_CERT, "function": function},
    )
    h = att.compute_hash()
    _emit(pathway, _att_path(h), att)
    return h


# ---------------------------------------------------------------------------
# Policy entity reader
# ---------------------------------------------------------------------------


class TestReadInitialGrantPolicy:
    def test_unbound_returns_none(self):
        pathway, _ = _make_pathway()
        assert read_initial_grant_policy(pathway) is None

    def test_decodes_full_policy(self):
        pathway, _ = _make_pathway()
        _bind_policy(
            pathway,
            mode=INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION,
            identity_required=True,
        )
        policy = read_initial_grant_policy(pathway)
        assert policy is not None
        assert policy.unknown_peer == INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION
        assert policy.default_role == ROLE_NAME
        assert policy.default_context == CTX_NAME
        assert policy.identity_required is True

    def test_malformed_mode_returns_none(self):
        pathway, _ = _make_pathway()
        _emit(
            pathway, INITIAL_GRANT_POLICY_PATH,
            Entity(
                type=INITIAL_GRANT_POLICY_TYPE,
                data={"default_role": ROLE_NAME},  # missing unknown_peer
            ),
        )
        assert read_initial_grant_policy(pathway) is None


# ---------------------------------------------------------------------------
# Mode dispatch (anonymous-deny / anonymous-allow)
# ---------------------------------------------------------------------------


class TestModeDispatch:
    def test_no_policy_returns_none(self):
        pathway, _ = _make_pathway()
        resolver = PolicyGrantResolver(pathway)
        assert resolver("peer-1", b"\x00" * 33) is None

    def test_anonymous_deny_returns_none(self):
        pathway, _ = _make_pathway()
        _bind_policy(pathway, mode=INITIAL_GRANT_MODE_ANONYMOUS_DENY)
        _bind_role_def(pathway)  # present but should be ignored.
        resolver = PolicyGrantResolver(pathway)
        assert resolver("peer-1", b"\x00" * 33) is None

    def test_anonymous_allow_returns_role_grants(self):
        pathway, _ = _make_pathway()
        _bind_policy(pathway, mode=INITIAL_GRANT_MODE_ANONYMOUS_ALLOW)
        _bind_role_def(pathway)
        resolver = PolicyGrantResolver(pathway)
        grants = resolver("peer-1", b"\x00" * 33)
        assert grants is not None
        assert len(grants) == 1
        assert grants[0].handlers.include == ["system/tree"]
        assert grants[0].resources.include == [f"shared/{CTX_NAME}/*"]
        assert grants[0].operations.include == ["get"]

    def test_anonymous_allow_missing_role_def_fails_closed(self):
        """Spec §4.7: don't issue a phantom cap with empty grants when
        the role definition isn't bound."""
        pathway, _ = _make_pathway()
        _bind_policy(pathway, mode=INITIAL_GRANT_MODE_ANONYMOUS_ALLOW)
        # No role definition bound.
        resolver = PolicyGrantResolver(pathway)
        assert resolver("peer-1", b"\x00" * 33) is None

    def test_unknown_mode_fails_closed(self):
        pathway, _ = _make_pathway()
        _bind_policy(pathway, mode="freeform-impl-defined")
        _bind_role_def(pathway)
        resolver = PolicyGrantResolver(pathway)
        assert resolver("peer-1", b"\x00" * 33) is None


# ---------------------------------------------------------------------------
# Layer-2 exclusion (§6.1)
# ---------------------------------------------------------------------------


class TestLayer2Exclusion:
    def test_excluded_peer_blocked_before_mode_dispatch(self):
        pathway, _ = _make_pathway()
        _bind_policy(pathway, mode=INITIAL_GRANT_MODE_ANONYMOUS_ALLOW)
        _bind_role_def(pathway)
        # Excluded in the policy's default context.
        identity_hash = b"\x00" + b"E" * 32
        _emit(
            pathway, role_exclusion_path(CTX_NAME, identity_hash.hex()),
            Entity(
                type="system/role/exclusion",
                data={
                    "excluded_by": b"\x00" * 33,
                    "excluded_at": 0,
                },
            ),
        )
        resolver = PolicyGrantResolver(pathway)
        assert resolver("peer-1", identity_hash) is None


# ---------------------------------------------------------------------------
# Recognize-on-attestation
# ---------------------------------------------------------------------------


class TestRecognizeOnAttestation:
    """TV-RV-2.7 sub-checks at the resolver layer."""

    def _build_recognized_chain(
        self,
        pathway: EmitPathway,
        connecting_kp: Keypair,
    ) -> tuple[bytes, bytes]:
        """Set up: trusted-quorum-id, controller peer with an
        identity-cert chaining to the trusted quorum, and the
        connecting peer's agent-cert chaining to the controller.

        Returns `(connecting_peer_hash, trusted_quorum_id)`.
        """
        # Trusted quorum hash — opaque, just needs to match peer-config.
        trusted_quorum = b"\x00" + b"Q" * 32
        _bind_peer_config(pathway, trusted_quorum)

        # Controller: bind its peer entity, then identity-cert(controller)
        # whose `attesting` is the trusted quorum.
        controller_kp = Keypair.from_seed(b"\xc0" * 32)
        controller_peer_hash = _bind_peer(pathway, controller_kp)
        _bind_identity_cert(
            pathway,
            function=FUNCTION_CONTROLLER,
            attesting=trusted_quorum,
            attested=controller_peer_hash,
        )

        # Connecting peer (the agent): bind its peer entity, then an
        # agent-cert whose `attesting` is the controller's peer hash.
        connecting_peer_hash = _bind_peer(pathway, connecting_kp)
        _bind_identity_cert(
            pathway,
            function=FUNCTION_AGENT,
            attesting=controller_peer_hash,
            attested=connecting_peer_hash,
        )

        return connecting_peer_hash, trusted_quorum

    def test_positive_recognized_chain_returns_role_grants(self):
        """TV-RV-2.7 positive: agent-cert chain to trusted controller →
        guest grants on the connection cap."""
        pathway, _ = _make_pathway()
        kp = Keypair.from_seed(b"\xa0" * 32)
        connecting_hash, _ = self._build_recognized_chain(pathway, kp)

        _bind_policy(
            pathway,
            mode=INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION,
            identity_required=True,
        )
        _bind_role_def(pathway)

        recognized, root = recognize_identity_cert(pathway, connecting_hash)
        assert recognized is True
        assert root is not None

        resolver = PolicyGrantResolver(pathway)
        grants = resolver(kp.peer_id, connecting_hash)
        assert grants is not None
        assert grants[0].resources.include == [f"shared/{CTX_NAME}/*"]

    def test_bare_keypair_with_identity_required_returns_none(self):
        """TV-RV-2.7 negative: no agent-cert in tree, identity_required=true
        → resolver returns None (fall back to deny)."""
        pathway, _ = _make_pathway()
        # Set up trusted quorum + controller cert but NO agent-cert for M.
        trusted_quorum = b"\x00" + b"Q" * 32
        _bind_peer_config(pathway, trusted_quorum)
        controller_kp = Keypair.from_seed(b"\xc1" * 32)
        controller_peer_hash = _bind_peer(pathway, controller_kp)
        _bind_identity_cert(
            pathway,
            function=FUNCTION_CONTROLLER,
            attesting=trusted_quorum,
            attested=controller_peer_hash,
        )

        bare_kp = Keypair.from_seed(b"\xb0" * 32)
        bare_hash = _bind_peer(pathway, bare_kp)

        _bind_policy(
            pathway,
            mode=INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION,
            identity_required=True,
        )
        _bind_role_def(pathway)

        recognized, _ = recognize_identity_cert(pathway, bare_hash)
        assert recognized is False

        resolver = PolicyGrantResolver(pathway)
        assert resolver(bare_kp.peer_id, bare_hash) is None

    def test_bare_keypair_with_identity_required_false_falls_back_to_role(self):
        """`identity_required=false` → unrecognized peers still get the
        role grants."""
        pathway, _ = _make_pathway()
        trusted_quorum = b"\x00" + b"Q" * 32
        _bind_peer_config(pathway, trusted_quorum)

        bare_kp = Keypair.from_seed(b"\xb1" * 32)
        bare_hash = _bind_peer(pathway, bare_kp)

        _bind_policy(
            pathway,
            mode=INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION,
            identity_required=False,
        )
        _bind_role_def(pathway)

        resolver = PolicyGrantResolver(pathway)
        grants = resolver(bare_kp.peer_id, bare_hash)
        assert grants is not None
        assert grants[0].resources.include == [f"shared/{CTX_NAME}/*"]

    def test_unrelated_controller_blocked(self):
        """TV-RV-2.7 negative: agent-cert under a rogue controller (not
        under the trusted quorum) → not recognized."""
        pathway, _ = _make_pathway()
        trusted_quorum = b"\x00" + b"Q" * 32
        rogue_quorum = b"\x00" + b"R" * 32
        _bind_peer_config(pathway, trusted_quorum)

        # Rogue controller cert under a different quorum.
        rogue_controller_kp = Keypair.from_seed(b"\xc2" * 32)
        rogue_controller_hash = _bind_peer(pathway, rogue_controller_kp)
        _bind_identity_cert(
            pathway,
            function=FUNCTION_CONTROLLER,
            attesting=rogue_quorum,
            attested=rogue_controller_hash,
        )
        # Agent-cert chains to the rogue controller.
        rogue_agent_kp = Keypair.from_seed(b"\xa2" * 32)
        rogue_agent_hash = _bind_peer(pathway, rogue_agent_kp)
        _bind_identity_cert(
            pathway,
            function=FUNCTION_AGENT,
            attesting=rogue_controller_hash,
            attested=rogue_agent_hash,
        )

        _bind_policy(
            pathway,
            mode=INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION,
            identity_required=True,
        )
        _bind_role_def(pathway)

        recognized, _ = recognize_identity_cert(pathway, rogue_agent_hash)
        assert recognized is False

        resolver = PolicyGrantResolver(pathway)
        assert resolver(rogue_agent_kp.peer_id, rogue_agent_hash) is None

    def test_sub_controller_chain_recognized(self):
        """Sub-controller (controller → controller → quorum): the walk
        recurses via the controller cert's `attesting` field."""
        pathway, _ = _make_pathway()
        trusted_quorum = b"\x00" + b"Q" * 32
        _bind_peer_config(pathway, trusted_quorum)

        # Top controller chains directly to the trusted quorum.
        top_kp = Keypair.from_seed(b"\xc3" * 32)
        top_hash = _bind_peer(pathway, top_kp)
        _bind_identity_cert(
            pathway,
            function=FUNCTION_CONTROLLER,
            attesting=trusted_quorum,
            attested=top_hash,
        )
        # Sub-controller chains to top controller's peer-hash.
        sub_kp = Keypair.from_seed(b"\xc4" * 32)
        sub_hash = _bind_peer(pathway, sub_kp)
        _bind_identity_cert(
            pathway,
            function=FUNCTION_CONTROLLER,
            attesting=top_hash,
            attested=sub_hash,
        )
        # Agent under sub-controller.
        agent_kp = Keypair.from_seed(b"\xa3" * 32)
        agent_hash = _bind_peer(pathway, agent_kp)
        _bind_identity_cert(
            pathway,
            function=FUNCTION_AGENT,
            attesting=sub_hash,
            attested=agent_hash,
        )

        recognized, _ = recognize_identity_cert(pathway, agent_hash)
        assert recognized is True

    def test_no_peer_config_blocks_recognition(self):
        """Recognition is impossible without a bound peer-config."""
        pathway, _ = _make_pathway()
        agent_hash = b"\x00" + b"A" * 32
        recognized, root = recognize_identity_cert(pathway, agent_hash)
        assert recognized is False
        assert root is None


# ---------------------------------------------------------------------------
# Resolver chaining
# ---------------------------------------------------------------------------


class TestChainGrantResolvers:
    def test_first_non_none_wins(self):
        from entity_core.capability.token import Grant

        static_grants = [Grant.from_dict(GUEST_GRANT_DICT)]

        def static(_pid, _ih):
            return static_grants

        def policy(_pid, _ih):
            raise AssertionError("should not be reached")

        chained = chain_grant_resolvers(static, policy)
        assert chained("peer-1", None) is static_grants

    def test_falls_through_on_none(self):
        from entity_core.capability.token import Grant

        policy_grants = [Grant.from_dict(GUEST_GRANT_DICT)]

        def static(_pid, _ih):
            return None

        def policy(_pid, _ih):
            return policy_grants

        chained = chain_grant_resolvers(static, policy)
        assert chained("peer-1", None) is policy_grants

    def test_none_resolvers_skipped(self):
        chained = chain_grant_resolvers(None, None, None)
        assert chained("peer-1", None) is None


# ---------------------------------------------------------------------------
# Peer integration
# ---------------------------------------------------------------------------


class TestPeerIntegration:
    """End-to-end check that the peer's `_get_grants_for_peer` consults
    the resolver and returns the role grants when it fires."""

    def test_resolver_grants_win_over_connect_scope_fallback(self):
        from entity_core.peer import PeerBuilder

        keypair = Keypair.generate()
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_all_handlers()
            .build()
        )

        _bind_policy(
            peer.emit_pathway,
            mode=INITIAL_GRANT_MODE_ANONYMOUS_ALLOW,
        )
        _bind_role_def(peer.emit_pathway)

        peer.set_grant_resolver(
            PolicyGrantResolver(
                peer.emit_pathway, local_peer_id=keypair.peer_id,
            )
        )

        # Non-admin, non-debug peer with policy issuing role grants.
        # Identity hash doesn't matter for anonymous-allow.
        grants = peer._get_grants_for_peer("some-other-peer", b"\x00" * 33)
        assert grants is not None
        assert len(grants) == 1
        assert grants[0].handlers.include == ["system/tree"]

    def test_resolver_returns_none_falls_back_to_connect_scope(self):
        from entity_core.peer import PeerBuilder
        from entity_core.capability.grant import create_connect_grants

        keypair = Keypair.generate()
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_all_handlers()
            .build()
        )

        # No policy → resolver returns None → fallback fires.
        peer.set_grant_resolver(
            PolicyGrantResolver(
                peer.emit_pathway, local_peer_id=keypair.peer_id,
            )
        )

        grants = peer._get_grants_for_peer("some-other-peer", b"\x00" * 33)
        assert grants is not None
        # Connect-scope-only fallback (length 2 per create_connect_grants).
        assert len(grants) == len(create_connect_grants())

    def test_admin_short_circuits_resolver(self):
        """Admin peer-ids win over the resolver per the documented
        priority order in `_get_grants_for_peer` ("Static FIRST so
        explicit per-peer overrides win over policy")."""
        from entity_core.peer import PeerBuilder

        keypair = Keypair.generate()
        admin_id = "admin-peer-id"
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_all_handlers()
            .with_admin_peer_ids({admin_id})
            .build()
        )

        # Resolver would deny — admin should still get default grants.
        _bind_policy(
            peer.emit_pathway, mode=INITIAL_GRANT_MODE_ANONYMOUS_DENY,
        )
        peer.set_grant_resolver(
            PolicyGrantResolver(
                peer.emit_pathway, local_peer_id=keypair.peer_id,
            )
        )

        grants = peer._get_grants_for_peer(admin_id, b"\x00" * 33)
        assert grants is peer.default_grants

    def test_policy_fires_under_debug_mode(self):
        """Explicit policy MUST win over debug_mode so cross-impl runs
        that start the peer with --debug still exercise the policy
        (otherwise the validator's TV-RV-2.7 fixture can't hit the
        resolver at all). debug_mode is the un-policied fallback,
        not an override."""
        from entity_core.peer import PeerBuilder

        keypair = Keypair.generate()
        peer = (
            PeerBuilder()
            .with_keypair(keypair)
            .with_all_handlers()
            .debug_mode(True)
            .build()
        )

        _bind_policy(
            peer.emit_pathway, mode=INITIAL_GRANT_MODE_ANONYMOUS_ALLOW,
        )
        _bind_role_def(peer.emit_pathway)
        peer.set_grant_resolver(
            PolicyGrantResolver(
                peer.emit_pathway, local_peer_id=keypair.peer_id,
            )
        )

        # Non-admin peer → resolver fires even though debug_mode is on.
        grants = peer._get_grants_for_peer("some-peer", b"\x00" * 33)
        assert grants is not None
        assert len(grants) == 1
        assert grants[0].handlers.include == ["system/tree"]
        # Sanity: debug_mode still gives full access when policy is
        # absent / says nothing about the peer.
        peer.set_grant_resolver(None)
        unpolicied = peer._get_grants_for_peer("other-peer", b"\x00" * 33)
        assert unpolicied is peer.default_grants
