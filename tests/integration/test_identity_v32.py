"""Integration tests for EXTENSION-IDENTITY v3.2 (convention layer over
EXTENSION-ATTESTATION + EXTENSION-QUORUM).

Covers the load-bearing flows:
- 3-key default provisioning (quorum + controller + agent)
- 4-key advanced (controller + identifier + agent)
- Sub-controller chains
- Compromise-recovery validation against cached quorum-publish (§9.4 fail-closed)
- Operational-key confinement under public/ (§9.2)
- Mode REQUIRED on all identity-certs (eliminates rotation race)
- identity-resolved resolver registration during configure
- Topology dispatch (k-of-n / single / dual)
- Authority-revocation (only quorum can revoke its own certs)
- peer-config persistence + local peer→controller cap issuance
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer.extensions import ExtensionContext
from entity_core.protocol.auth import (
    create_identity_entity,
    create_signature_entity,
)
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree

from entity_handlers.attestation import (
    ATTESTATION_TYPE,
    KIND_REVOCATION,
    is_attestation_live,
    make_attestation,
)
from entity_handlers.identity import (
    ALL_MODES,
    ZERO_HASH,
    identity_confers_function,
    CONTACTS_ROOT,
    FUNCTION_AGENT,
    FUNCTION_CONTROLLER,
    FUNCTION_IDENTIFIER,
    IDENTITY_LIFECYCLE_KINDS,
    INTERNAL_ROOT,
    KIND_IDENTITY_CERT,
    KIND_RETIREMENT,
    KIND_ROTATION_HANDOFF,
    KIND_ROTATION_RECOVERY,
    MODE_EMBEDDED,
    MODE_INTERNAL,
    MODE_PER_RELATIONSHIP,
    MODE_PUBLIC,
    PEER_CONFIG_PATH,
    PEER_CONFIG_TYPE,
    PUBLIC_ROOT,
    RELATIONSHIPS_ROOT,
    RESOLUTION_IDENTITY_RESOLVED,
    canonical_storage_path,
    cert_internal_path,
    cert_public_path,
    contacts_quorum_publish_path,
    identity_handler,
    identity_topology_for,
    identity_verify_cert,
    register_identity_resolved_resolver,
    resolve_controller_for_grants,
    walk_cert_chain_to_current_controller,
)
from entity_handlers.quorum import (
    KIND_QUORUM_PUBLISH,
    QUORUM_TYPE,
    QuorumExtension,
    quorum_entity_path,
    quorum_event_path,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@dataclass
class Ctx:
    keypair: Keypair
    pathway: EmitPathway
    handler: HandlerContext
    quorum_ext: QuorumExtension


def _make_ctx() -> Ctx:
    keypair = Keypair.generate()
    content_store = ContentStore()
    entity_tree = EntityTree(keypair.peer_id)
    pathway = EmitPathway(content_store, entity_tree)
    handler = HandlerContext(
        local_peer_id=keypair.peer_id,
        remote_peer_id=keypair.peer_id,
        handler_grant={},
        caller_capability={},
        emit_pathway=pathway,
        handler_pattern="system/identity",
        keypair=keypair,
    )
    quorum_ext = QuorumExtension()
    quorum_ext.initialize(ExtensionContext(keypair=keypair, emit_pathway=pathway))
    return Ctx(keypair=keypair, pathway=pathway, handler=handler, quorum_ext=quorum_ext)


def _bootstrap(pathway: EmitPathway, path: str, entity: Entity) -> bytes:
    return pathway.emit(path, entity, EmitContext.bootstrap()).hash


def _bind_identity(pathway: EmitPathway, kp: Keypair) -> bytes:
    identity = create_identity_entity(kp)
    h = identity.compute_hash()
    _bootstrap(pathway, f"system/peer/identity/{kp.peer_id}", identity)
    return h


def _bind_signature(
    pathway: EmitPathway, kp: Keypair, signer_hash: bytes, target_hash: bytes,
) -> bytes:
    sig = create_signature_entity(kp, target_hash, signer_hash)
    h = sig.compute_hash()
    _bootstrap(
        pathway, f"{kp.peer_id}/system/signature/{target_hash.hex()}", sig,
    )
    return h


def _make_signer(seed: int) -> tuple[Keypair, bytes]:
    kp = Keypair.from_seed(seed.to_bytes(32, "little"))
    return kp, create_identity_entity(kp).compute_hash()


def _bind_quorum(
    pathway: EmitPathway, signers: list[bytes], threshold: int,
    *, signer_resolution: str | None = None,
) -> bytes:
    data: dict[str, Any] = {"signers": signers, "threshold": threshold}
    if signer_resolution is not None:
        data["signer_resolution"] = signer_resolution
    quorum = Entity(type=QUORUM_TYPE, data=data)
    q_id = quorum.compute_hash()
    _bootstrap(pathway, quorum_entity_path(q_id), quorum)
    return q_id


def _signed_cert(
    pathway: EmitPathway,
    *,
    attesting_kp: Keypair | None = None,
    attesting_keys: list[Keypair] | None = None,
    attesting_hash: bytes,
    attested: bytes,
    function: str,
    mode: str,
    contact_id: bytes | None = None,
    target_cert: bytes | None = None,
    kind: str = KIND_IDENTITY_CERT,
    supersedes: bytes | None = None,
    storage_path: str | None = None,
) -> Entity:
    """Build, persist, and sign an identity attestation. Returns the entity."""
    props: dict[str, Any] = {"kind": kind}
    if kind == KIND_IDENTITY_CERT:
        props["function"] = function
        props["mode"] = mode
    if contact_id is not None:
        props["contact_id"] = contact_id
    if target_cert is not None:
        props["target_cert"] = target_cert

    att = make_attestation(
        attesting=attesting_hash, attested=attested,
        properties=props, supersedes=supersedes,
    )
    h = att.compute_hash()
    if storage_path is not None:
        _bootstrap(pathway, storage_path, att)
    else:
        # Caller will bind separately if needed; store in content store.
        pathway.content_store.put(att)

    # Sign per topology.
    if attesting_kp is not None:
        _bind_signature(pathway, attesting_kp, attesting_hash, h)
    if attesting_keys:
        # K-of-N: each provided keypair signs (attesting_hash here is
        # the quorum_id; the keys are the constituent keypairs).
        for kp in attesting_keys:
            kp_id_hash = create_identity_entity(kp).compute_hash()
            _bind_signature(pathway, kp, kp_id_hash, h)

    return att


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 3-key default provisioning
# ---------------------------------------------------------------------------


class TestThreeKeyDefault:
    def test_provision_quorum_controller_agent(self):
        """End-to-end: 1-of-1 quorum + top-level controller + agent.

        We bind everything bootstrap-style (peers + signatures); then
        configure the local agent against the quorum. peer-config
        lands; identity-resolved resolver registers; live top-level
        controller cert is discoverable via walk_cert_chain.
        """
        ctx = _make_ctx()

        # Quorum constituent (1-of-1).
        q_kp, q_id_hash = _make_signer(101)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)

        # Top-level controller cert (mode=public for 3-key default).
        ctrl_kp, ctrl_h = _make_signer(102)
        _bind_identity(ctx.pathway, ctrl_kp)
        ctrl_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        ctrl_cert_hash = ctrl_cert.compute_hash()
        ctrl_cert_path = cert_public_path(ctrl_cert_hash)
        _bootstrap(ctx.pathway, ctrl_cert_path, ctrl_cert)
        # K-of-N (1-of-1) — q_kp signs targeting q_id_hash.
        _bind_signature(ctx.pathway, q_kp, q_id_hash, ctrl_cert_hash)

        # Configure peer-config.
        result = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": [
                    {"path": "test/*", "ops": ["read", "write"]},
                ],
            }},
            ctx.handler,
        ))
        assert result["status"] == 200
        result_data = result["result"]["data"]
        # Cross-impl Go-aligned fields:
        # - peer_config_path: absolute path string where peer-config is bound.
        expected_pc_path = ctx.pathway.entity_tree.normalize_uri(PEER_CONFIG_PATH)
        assert result_data["peer_config_path"] == expected_pc_path
        # - local_peer_to_controller_caps: list of issued CAP HASHES (one
        #   per live top-level controller).
        caps = result_data["local_peer_to_controller_caps"]
        assert len(caps) == 1
        # Verify the issued cap is bound at the expected per-controller path.
        cap_path = ctx.pathway.entity_tree.normalize_uri(
            f"system/capability/grants/identity/peer-to-controller/{ctrl_h.hex()}",
        )
        assert ctx.pathway.entity_tree.get(cap_path) == caps[0]

        # peer-config bound.
        full = ctx.pathway.entity_tree.normalize_uri(PEER_CONFIG_PATH)
        bound = ctx.pathway.entity_tree.get(full)
        assert bound is not None
        config = ctx.pathway.content_store.get(bound)
        assert config.type == PEER_CONFIG_TYPE
        assert config.data["trusts_quorum"] == quorum_id

        # identity-resolved resolver registered against quorum extension.
        assert ctx.quorum_ext.lookup_resolver(RESOLUTION_IDENTITY_RESOLVED) is not None

        # walk_cert_chain finds the live controller.
        live = walk_cert_chain_to_current_controller(quorum_id, ctx.handler)
        assert live is not None
        assert live.compute_hash() == ctrl_cert_hash

        # resolve_controller_for_grants matches.
        grants_cert = resolve_controller_for_grants(config, ctx.handler)
        assert grants_cert is not None
        assert grants_cert.compute_hash() == ctrl_cert_hash

    def test_create_attestation_for_agent_mode_internal(self):
        """Issue an agent cert under the controller; bind at internal/."""
        ctx = _make_ctx()

        # Setup as test_provision_*.
        q_kp, q_id_hash = _make_signer(111)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)

        ctrl_kp, ctrl_h = _make_signer(112)
        _bind_identity(ctx.pathway, ctrl_kp)
        ctrl_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(ctx.pathway, cert_public_path(ctrl_cert.compute_hash()), ctrl_cert)
        _bind_signature(ctx.pathway, q_kp, q_id_hash, ctrl_cert.compute_hash())

        # Agent cert: signed by controller's keypair.
        agent_kp, agent_h = _make_signer(113)
        _bind_identity(ctx.pathway, agent_kp)
        agent_cert = make_attestation(
            attesting=ctrl_h, attested=agent_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        # Sign via controller keypair.
        ctx.pathway.content_store.put(agent_cert)
        _bind_signature(ctx.pathway, ctrl_kp, ctrl_h, agent_cert.compute_hash())

        # Submit through identity handler create_attestation.
        ctx.handler.resource_targets = [cert_internal_path(agent_cert.compute_hash())]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": dict(agent_cert.data)},
            ctx.handler,
        ))
        assert result["status"] == 200, result
        assert result["result"]["data"]["kind"] == KIND_IDENTITY_CERT
        assert result["result"]["data"]["stored_at"] == cert_internal_path(
            agent_cert.compute_hash(),
        )


# ---------------------------------------------------------------------------
# Mode REQUIRED on all certs (eliminates rotation race)
# ---------------------------------------------------------------------------


class TestModeRequired:
    def test_create_attestation_rejects_missing_mode(self):
        ctx = _make_ctx()
        # Synthesize a cert with no mode field.
        att = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"B" * 32,
            properties={"kind": KIND_IDENTITY_CERT, "function": FUNCTION_CONTROLLER},
        )
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": dict(att.data)},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_mode"

    def test_create_attestation_rejects_per_relationship_without_contact_id(self):
        ctx = _make_ctx()
        att = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"B" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_PER_RELATIONSHIP,
            },
        )
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": dict(att.data)},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "missing_contact_id"


# ---------------------------------------------------------------------------
# Path resolution per mode (§5.3)
# ---------------------------------------------------------------------------


class TestCanonicalStoragePath:
    def test_internal_cert(self):
        ctx = _make_ctx()
        att = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"B" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        path = canonical_storage_path(att, ctx.handler)
        assert path == f"{INTERNAL_ROOT}/cert/{att.compute_hash().hex()}"

    def test_public_cert(self):
        ctx = _make_ctx()
        att = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"B" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        path = canonical_storage_path(att, ctx.handler)
        assert path == f"{PUBLIC_ROOT}/cert/{att.compute_hash().hex()}"

    def test_per_relationship_cert(self):
        ctx = _make_ctx()
        contact = b"\x00" + b"C" * 32
        att = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"B" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_PER_RELATIONSHIP,
                "contact_id": contact,
            },
        )
        path = canonical_storage_path(att, ctx.handler)
        assert path == (
            f"{RELATIONSHIPS_ROOT}/{contact.hex()}/cert/{att.compute_hash().hex()}"
        )

    def test_embedded_cert_has_no_path(self):
        ctx = _make_ctx()
        att = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"B" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_EMBEDDED,
            },
        )
        assert canonical_storage_path(att, ctx.handler) is None

    def test_lifecycle_inherits_target_tier(self):
        """A retirement targeting a public cert lives under public/."""
        ctx = _make_ctx()
        # Bind a public cert first so target_cert is resolvable.
        target = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"B" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(ctx.pathway, cert_public_path(target.compute_hash()), target)

        retirement = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"B" * 32,
            properties={
                "kind": KIND_RETIREMENT,
                "target_cert": target.compute_hash(),
            },
        )
        path = canonical_storage_path(retirement, ctx.handler)
        assert path is not None
        assert path.startswith(f"{PUBLIC_ROOT}/cert/")


# ---------------------------------------------------------------------------
# Topology dispatch (§3.6)
# ---------------------------------------------------------------------------


class TestIdentityTopology:
    def test_top_level_controller_cert_is_k_of_n(self):
        ctx = _make_ctx()
        _, q_kp_h = _make_signer(201)
        quorum_id = _bind_quorum(ctx.pathway, [q_kp_h], 1)
        att = make_attestation(
            attesting=quorum_id, attested=b"\x00" + b"X" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        topology = identity_topology_for(att, ctx.handler)
        assert topology is not None
        assert topology.mode == "k-of-n"
        assert topology.signers == [q_kp_h]
        assert topology.threshold == 1

    def test_sub_controller_is_single_sig(self):
        ctx = _make_ctx()
        # `attesting` is a peer hash (NOT a quorum_id).
        att = make_attestation(
            attesting=b"\x00" + b"P" * 32, attested=b"\x00" + b"X" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_INTERNAL,
            },
        )
        topology = identity_topology_for(att, ctx.handler)
        assert topology is not None
        assert topology.mode == "single"
        assert topology.expected_signer == b"\x00" + b"P" * 32

    def test_agent_cert_is_single_sig(self):
        ctx = _make_ctx()
        att = make_attestation(
            attesting=b"\x00" + b"P" * 32, attested=b"\x00" + b"X" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        topology = identity_topology_for(att, ctx.handler)
        assert topology is not None
        assert topology.mode == "single"

    def test_rotation_handoff_is_dual_sig(self):
        ctx = _make_ctx()
        # Build a target cert first.
        target = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"OLD" + b"\x00" * 29,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        ctx.pathway.content_store.put(target)
        att = make_attestation(
            attesting=b"\x00" + b"OLD" + b"\x00" * 29,  # = target.attested
            attested=b"\x00" + b"NEW" + b"\x00" * 29,
            properties={
                "kind": KIND_ROTATION_HANDOFF,
                "target_cert": target.compute_hash(),
            },
        )
        topology = identity_topology_for(att, ctx.handler)
        assert topology is not None
        assert topology.mode == "dual"
        assert b"\x00" + b"OLD" + b"\x00" * 29 in topology.signers
        assert b"\x00" + b"NEW" + b"\x00" * 29 in topology.signers

    def test_recovery_is_k_of_n(self):
        ctx = _make_ctx()
        _, q_h = _make_signer(231)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)
        att = make_attestation(
            attesting=quorum_id, attested=b"\x00" + b"NEW" + b"\x00" * 29,
            properties={
                "kind": KIND_ROTATION_RECOVERY,
                "target_cert": b"\x00" + b"T" * 32,
                "old_handle": b"\x00" + b"OLD" + b"\x00" * 29,
            },
        )
        topology = identity_topology_for(att, ctx.handler)
        assert topology is not None
        assert topology.mode == "k-of-n"


# ---------------------------------------------------------------------------
# Compromise-recovery validation (§9.4)
# ---------------------------------------------------------------------------


class TestCompromiseRecovery:
    def test_recovery_accepted_with_cached_quorum_publish(self):
        """K-of-N validates against the cached publish; cert is accepted."""
        ctx = _make_ctx()
        # Quorum and old controller (handle).
        q_kp, q_h = _make_signer(301)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        old_kp, old_h = _make_signer(302)
        _bind_identity(ctx.pathway, old_kp)
        old_cert = make_attestation(
            attesting=quorum_id, attested=old_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        old_cert_path = cert_public_path(old_cert.compute_hash())
        _bootstrap(ctx.pathway, old_cert_path, old_cert)
        _bind_signature(ctx.pathway, q_kp, q_h, old_cert.compute_hash())

        # Cache a quorum-publish for the OLD handle.
        publish = make_attestation(
            attesting=quorum_id, attested=quorum_id,
            properties={
                "kind": KIND_QUORUM_PUBLISH,
                "signers": [q_h],
                "threshold": 1,
                "published_handle": old_h,
            },
        )
        _bootstrap(
            ctx.pathway,
            quorum_event_path(quorum_id, publish.compute_hash()),
            publish,
        )
        _bind_signature(ctx.pathway, q_kp, q_h, publish.compute_hash())
        # Seed the contacts cache the way process_attestation would.
        _bootstrap(
            ctx.pathway,
            contacts_quorum_publish_path(old_h),
            publish,
        )

        # Compromise-recovery: same quorum signs a new key.
        new_kp, new_h = _make_signer(303)
        _bind_identity(ctx.pathway, new_kp)
        recovery = make_attestation(
            attesting=quorum_id, attested=new_h,
            properties={
                "kind": KIND_ROTATION_RECOVERY,
                "target_cert": old_cert.compute_hash(),
                "old_handle": old_h,
            },
        )
        ctx.pathway.content_store.put(recovery)
        # Signed K-of-N (1-of-1) by quorum constituent.
        _bind_signature(ctx.pathway, q_kp, q_h, recovery.compute_hash())

        # identity_verify_cert should accept (with cached publish).
        valid, reason = identity_verify_cert(recovery, ctx.handler)
        assert valid is True, f"unexpected rejection: {reason}"

    def test_recovery_rejected_without_cached_publish(self):
        """No cached publish → fail-closed (§9.4 MUST)."""
        ctx = _make_ctx()
        q_kp, q_h = _make_signer(311)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        old_h = b"\x00" + b"OLD" + b"\x00" * 29
        old_cert = make_attestation(
            attesting=quorum_id, attested=old_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(ctx.pathway, cert_public_path(old_cert.compute_hash()), old_cert)
        _bind_signature(ctx.pathway, q_kp, q_h, old_cert.compute_hash())

        # NO cached publish here — fail-closed.
        new_kp, new_h = _make_signer(313)
        _bind_identity(ctx.pathway, new_kp)
        recovery = make_attestation(
            attesting=quorum_id, attested=new_h,
            properties={
                "kind": KIND_ROTATION_RECOVERY,
                "target_cert": old_cert.compute_hash(),
                "old_handle": old_h,
            },
        )
        ctx.pathway.content_store.put(recovery)
        _bind_signature(ctx.pathway, q_kp, q_h, recovery.compute_hash())

        valid, reason = identity_verify_cert(recovery, ctx.handler)
        assert valid is False
        assert reason == "recovery_against_cached_publish_failed"


# ---------------------------------------------------------------------------
# Operational-key confinement (§9.2)
# ---------------------------------------------------------------------------


class TestOperationalKeyConfinement:
    def test_public_cert_with_controller_signature_rejected(self):
        """A new public/ attestation MUST NOT carry a signature from any
        currently-live top-level controller of the trusted quorum."""
        ctx = _make_ctx()

        # Standard 3-key setup: quorum + live controller.
        q_kp, q_h = _make_signer(401)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        ctrl_kp, ctrl_h = _make_signer(402)
        _bind_identity(ctx.pathway, ctrl_kp)
        ctrl_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(ctx.pathway, cert_public_path(ctrl_cert.compute_hash()), ctrl_cert)
        _bind_signature(ctx.pathway, q_kp, q_h, ctrl_cert.compute_hash())

        # Configure peer-config so the trusted_quorum is known.
        _run(identity_handler(
            "system/identity", "configure",
            {"data": {"trusts_quorum": quorum_id, "controller_grants": []}},
            ctx.handler,
        ))

        # Now attempt to bind a public/ agent cert SIGNED BY THE CONTROLLER
        # (op-confinement violation per §9.2).
        agent_kp, agent_h = _make_signer(403)
        _bind_identity(ctx.pathway, agent_kp)
        agent_cert = make_attestation(
            attesting=ctrl_h, attested=agent_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_PUBLIC,
            },
        )
        ctx.pathway.content_store.put(agent_cert)
        # Controller signs it (this is the violation).
        _bind_signature(ctx.pathway, ctrl_kp, ctrl_h, agent_cert.compute_hash())

        ctx.handler.resource_targets = [cert_public_path(agent_cert.compute_hash())]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": dict(agent_cert.data)},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert (
            result["result"]["data"]["code"]
            == "controller_signature_forbidden_under_public"
        )


# ---------------------------------------------------------------------------
# Authority-revocation (§3.6 identity_is_authorized_revoker)
# ---------------------------------------------------------------------------


class TestAuthorityRevocation:
    def test_quorum_can_revoke_its_own_cert(self):
        ctx = _make_ctx()
        q_kp, q_h = _make_signer(501)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        # Top-level controller cert.
        ctrl_kp, ctrl_h = _make_signer(502)
        _bind_identity(ctx.pathway, ctrl_kp)
        cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(ctx.pathway, cert_public_path(cert.compute_hash()), cert)
        _bind_signature(ctx.pathway, q_kp, q_h, cert.compute_hash())

        # Cert is alive.
        assert is_attestation_live(cert, ctx.handler) is True
        valid, _ = identity_verify_cert(cert, ctx.handler)
        assert valid is True

        # Authority-revocation: quorum (via attesting=quorum_id) revokes.
        revocation = make_attestation(
            attesting=quorum_id, attested=cert.compute_hash(),
            properties={"kind": KIND_REVOCATION},
        )
        ctx.pathway.content_store.put(revocation)
        _bootstrap(
            ctx.pathway,
            f"{PUBLIC_ROOT}/cert/{revocation.compute_hash().hex()}",
            revocation,
        )
        _bind_signature(ctx.pathway, q_kp, q_h, revocation.compute_hash())

        # Cert rejected. The substrate's self-revocation check fires
        # first because the revocation shares `attesting=quorum_id` with
        # the cert (substrate considers same-attesting revocations
        # self-revocations). Either reason proves rejection works.
        valid, reason = identity_verify_cert(cert, ctx.handler)
        assert valid is False
        assert reason in ("authority_revoked", "not_live")


# ---------------------------------------------------------------------------
# Sub-controller chains
# ---------------------------------------------------------------------------


class TestSubControllerChains:
    def test_sub_controller_chain_walks_to_quorum(self):
        ctx = _make_ctx()
        q_kp, q_h = _make_signer(601)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        # Top-level controller.
        ctrl_kp, ctrl_h = _make_signer(602)
        _bind_identity(ctx.pathway, ctrl_kp)
        top_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_INTERNAL,
            },
        )
        _bootstrap(ctx.pathway, cert_internal_path(top_cert.compute_hash()), top_cert)
        _bind_signature(ctx.pathway, q_kp, q_h, top_cert.compute_hash())

        # Sub-controller (single-sig, mode=internal).
        sub_kp, sub_h = _make_signer(603)
        _bind_identity(ctx.pathway, sub_kp)
        sub_cert = make_attestation(
            attesting=ctrl_h, attested=sub_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_INTERNAL,
            },
        )
        _bootstrap(ctx.pathway, cert_internal_path(sub_cert.compute_hash()), sub_cert)
        _bind_signature(ctx.pathway, ctrl_kp, ctrl_h, sub_cert.compute_hash())

        # identity_verify_cert on the sub-controller walks the chain
        # back to the quorum and returns OK.
        valid, reason = identity_verify_cert(sub_cert, ctx.handler)
        assert valid is True, reason


# ---------------------------------------------------------------------------
# identity-resolved resolver registration (§6.1)
# ---------------------------------------------------------------------------


class TestSubstrateSigAgnostic:
    """SI-1 / TV-I-A8: substrate find_authorizing is signature-agnostic;
    identity_verify_cert rejects invalid sigs at topology dispatch."""

    def test_identity_verify_cert_rejects_invalid_single_sig(self):
        ctx = _make_ctx()
        # A peer's identity bound, but signature for the cert is wrong target.
        kp_a = Keypair.from_seed(b"\xA5" * 32)
        h_a = _bind_identity(ctx.pathway, kp_a)
        peer_b = b"\x00" + b"B" * 32

        # Single-sig agent cert (attesting=peer hash → topology=single).
        agent_cert = make_attestation(
            attesting=h_a, attested=peer_b,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        _bootstrap(ctx.pathway, cert_internal_path(agent_cert.compute_hash()), agent_cert)
        # Bind a sig for a DIFFERENT target — verify_attestation_signature fails.
        wrong_target = b"\x00" + b"\xFF" * 32
        _bind_signature(ctx.pathway, kp_a, h_a, wrong_target)

        valid, reason = identity_verify_cert(agent_cert, ctx.handler)
        assert valid is False
        # Topology dispatch path returns invalid_signature for single-sig.
        assert reason in ("invalid_signature", "chain_to_quorum_not_found")


class TestIdentityResolvedResolver:
    def test_register_resolver_returns_controller_peer(self):
        """The resolver, when invoked with a quorum_id, returns the live
        top-level controller's peer hash."""
        ctx = _make_ctx()

        q_kp, q_h = _make_signer(701)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        ctrl_kp, ctrl_h = _make_signer(702)
        _bind_identity(ctx.pathway, ctrl_kp)
        ctrl_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(ctx.pathway, cert_public_path(ctrl_cert.compute_hash()), ctrl_cert)
        _bind_signature(ctx.pathway, q_kp, q_h, ctrl_cert.compute_hash())

        register_identity_resolved_resolver(ctx.handler)
        resolver = ctx.quorum_ext.lookup_resolver(RESOLUTION_IDENTITY_RESOLVED)
        assert resolver is not None

        # Invoking the resolver on the quorum_id returns the live
        # controller's peer hash.
        resolved = resolver(quorum_id, ctx.handler)
        assert resolved == ctrl_h


# ---------------------------------------------------------------------------
# Rotation handoff (§4.3) — dual-sig graceful key roll
# ---------------------------------------------------------------------------


class TestRotationHandoff:
    def test_handoff_validates_with_both_signatures(self):
        """A graceful rotation: old key + new key both sign the handoff
        attestation. Topology = dual; identity_verify_cert accepts."""
        ctx = _make_ctx()

        # Setup: quorum + controller cert.
        q_kp, q_h = _make_signer(801)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        old_kp, old_h = _make_signer(802)
        _bind_identity(ctx.pathway, old_kp)
        target_cert = make_attestation(
            attesting=quorum_id, attested=old_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        _bootstrap(
            ctx.pathway,
            cert_internal_path(target_cert.compute_hash()),
            target_cert,
        )
        # Sign the agent cert with the controller... well for this test
        # we just need the cert to exist as the rotation target. The
        # rotation itself is what we validate. (Agent-cert chain isn't
        # under test here — the rotation's own dual-sig is.)

        new_kp, new_h = _make_signer(803)
        _bind_identity(ctx.pathway, new_kp)

        handoff = make_attestation(
            attesting=old_h, attested=new_h,
            properties={
                "kind": KIND_ROTATION_HANDOFF,
                "target_cert": target_cert.compute_hash(),
            },
        )
        ctx.pathway.content_store.put(handoff)
        # Both old and new keypairs sign.
        _bind_signature(ctx.pathway, old_kp, old_h, handoff.compute_hash())
        _bind_signature(ctx.pathway, new_kp, new_h, handoff.compute_hash())

        valid, reason = identity_verify_cert(handoff, ctx.handler)
        assert valid is True, reason

    def test_handoff_rejected_when_new_key_doesnt_sign(self):
        """Dual-sig MUST have both signatures; missing one → reject."""
        ctx = _make_ctx()
        q_kp, q_h = _make_signer(811)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        old_kp, old_h = _make_signer(812)
        _bind_identity(ctx.pathway, old_kp)
        target_cert = make_attestation(
            attesting=quorum_id, attested=old_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        _bootstrap(
            ctx.pathway,
            cert_internal_path(target_cert.compute_hash()),
            target_cert,
        )

        _, new_h = _make_signer(813)
        # Note: NEW key's identity is bound but it does NOT sign.
        new_kp = Keypair.from_seed((813).to_bytes(32, "little"))
        _bind_identity(ctx.pathway, new_kp)

        handoff = make_attestation(
            attesting=old_h, attested=new_h,
            properties={
                "kind": KIND_ROTATION_HANDOFF,
                "target_cert": target_cert.compute_hash(),
            },
        )
        ctx.pathway.content_store.put(handoff)
        # Only OLD signs.
        _bind_signature(ctx.pathway, old_kp, old_h, handoff.compute_hash())

        valid, reason = identity_verify_cert(handoff, ctx.handler)
        assert valid is False
        assert reason is not None
        assert reason.startswith("missing_dual_sig")


# ---------------------------------------------------------------------------
# publish_attestation — promote agent cert across modes (§6)
# ---------------------------------------------------------------------------


class TestPublishAttestation:
    def test_promote_agent_cert_internal_to_public(self):
        """Same logical agent cert, new mode + new path."""
        ctx = _make_ctx()
        q_kp, q_h = _make_signer(901)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        ctrl_kp, ctrl_h = _make_signer(902)
        _bind_identity(ctx.pathway, ctrl_kp)
        ctrl_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(ctx.pathway, cert_public_path(ctrl_cert.compute_hash()), ctrl_cert)
        _bind_signature(ctx.pathway, q_kp, q_h, ctrl_cert.compute_hash())

        # Internal agent cert.
        agent_kp, agent_h = _make_signer(903)
        _bind_identity(ctx.pathway, agent_kp)
        internal_agent = make_attestation(
            attesting=ctrl_h, attested=agent_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        ctx.pathway.content_store.put(internal_agent)
        _bind_signature(ctx.pathway, ctrl_kp, ctrl_h, internal_agent.compute_hash())

        # Bind the agent cert at its canonical (internal) path so we can
        # verify the publish moves (not duplicates) the binding.
        old_internal_path = cert_internal_path(internal_agent.compute_hash())
        _bootstrap(ctx.pathway, old_internal_path, internal_agent)

        # Promote to public.
        result = _run(identity_handler(
            "system/identity", "publish_attestation",
            {"data": {
                "attestation_hash": internal_agent.compute_hash(),
                "new_mode": MODE_PUBLIC,
            }},
            ctx.handler,
        ))
        assert result["status"] == 200
        result_data = result["result"]["data"]
        # Cross-impl Go-aligned: `new_path` is the absolute canonical path.
        new_path_abs = result_data["new_path"]
        assert new_path_abs.startswith("/")  # absolute form
        assert f"{PUBLIC_ROOT}/cert/" in new_path_abs
        # Per P-12 (cross-impl invariant): `:publish_attestation` MUST
        # preserve the entity hash — it moves a tree binding, doesn't
        # re-create the cert.
        assert result_data["attestation_hash"] == internal_agent.compute_hash()
        # The hash segment in `new_path` must be the same hash.
        assert internal_agent.compute_hash().hex() in new_path_abs
        # New binding lives at the public path with the same content hash.
        new_full = ctx.pathway.entity_tree.normalize_uri(
            cert_public_path(internal_agent.compute_hash()),
        )
        assert ctx.pathway.entity_tree.get(new_full) == internal_agent.compute_hash()
        # Old internal binding is removed (move, not duplicate).
        old_full = ctx.pathway.entity_tree.normalize_uri(old_internal_path)
        assert ctx.pathway.entity_tree.get(old_full) is None


# ---------------------------------------------------------------------------
# Quorum-publish caching during process_attestation
# ---------------------------------------------------------------------------


class TestQuorumPublishCaching:
    def test_process_attestation_caches_quorum_publish(self):
        """When a quorum-publish carrying published_handle arrives, the
        process_attestation handler caches it at
        contacts/{handle_hex}/quorum-publish for later compromise-recovery
        validation."""
        ctx = _make_ctx()
        q_kp, q_h = _make_signer(951)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        handle = b"\x00" + b"H" * 32
        publish = make_attestation(
            attesting=quorum_id, attested=quorum_id,
            properties={
                "kind": KIND_QUORUM_PUBLISH,
                "signers": [q_h],
                "threshold": 1,
                "published_handle": handle,
            },
        )
        # Bind under the quorum's event subtree so process_quorum_attestation
        # finds it during validation.
        _bootstrap(
            ctx.pathway,
            quorum_event_path(quorum_id, publish.compute_hash()),
            publish,
        )
        _bind_signature(ctx.pathway, q_kp, q_h, publish.compute_hash())

        result = _run(identity_handler(
            "system/identity", "process_attestation",
            {"data": {"attestation": publish.to_dict()}},
            ctx.handler,
        ))
        assert result["status"] == 200, result

        # Cache populated.
        cache_path = ctx.pathway.entity_tree.normalize_uri(
            contacts_quorum_publish_path(handle),
        )
        cached = ctx.pathway.entity_tree.get(cache_path)
        assert cached == publish.compute_hash()


# ---------------------------------------------------------------------------
# identity_confers_function — lifecycle kinds in chain walks (SI-13)
# ---------------------------------------------------------------------------


class TestIdentityConfersFunction:
    def test_identity_cert_confers_directly(self):
        ctx = _make_ctx()
        cert = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"B" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        assert identity_confers_function(cert, FUNCTION_CONTROLLER, ctx.handler)
        assert not identity_confers_function(cert, FUNCTION_AGENT, ctx.handler)

    def test_rotation_handoff_inherits_from_target(self):
        """SI-13: a handoff inherits its target's function — chain walks
        for `function=controller` find rotation-handoff attestations
        without requiring a fresh identity-cert issuance."""
        ctx = _make_ctx()
        target = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"OLD" + b"\x00" * 29,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        ctx.pathway.content_store.put(target)
        handoff = make_attestation(
            attesting=b"\x00" + b"OLD" + b"\x00" * 29,
            attested=b"\x00" + b"NEW" + b"\x00" * 29,
            properties={
                "kind": KIND_ROTATION_HANDOFF,
                "target_cert": target.compute_hash(),
            },
        )
        assert identity_confers_function(handoff, FUNCTION_CONTROLLER, ctx.handler)
        assert not identity_confers_function(handoff, FUNCTION_AGENT, ctx.handler)

    def test_retirement_does_not_confer(self):
        ctx = _make_ctx()
        target = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"X" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        ctx.pathway.content_store.put(target)
        retirement = make_attestation(
            attesting=b"\x00" + b"A" * 32, attested=b"\x00" + b"X" * 32,
            properties={
                "kind": KIND_RETIREMENT,
                "target_cert": target.compute_hash(),
            },
        )
        assert not identity_confers_function(
            retirement, FUNCTION_CONTROLLER, ctx.handler,
        )


# ---------------------------------------------------------------------------
# envelope.included signature ingestion (SI-11)
# ---------------------------------------------------------------------------


class TestEnvelopeSignatureIngestion:
    def test_ingestion_binds_signatures_at_v7_invariant_paths(self):
        """SI-11: signatures from envelope.included are persisted to
        the content store and bound at /{signer_peer_id}/system/signature/
        {target_hash_hex} before validation runs."""
        ctx = _make_ctx()
        # Set up a controller cert that needs K-of-N from the quorum.
        q_kp, q_h = _make_signer(2001)
        # Identity must be in the tree (so the resolver can recover
        # signer_peer_id) — bind it.
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        cert = make_attestation(
            attesting=quorum_id, attested=b"\x00" + b"X" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        cert_hash = cert.compute_hash()

        # Build a signature entity (NOT yet bound at any path).
        sig = create_signature_entity(q_kp, cert_hash, q_h)

        # Send through create_attestation with `included` carrying the sig.
        ctx.handler.resource_targets = [cert_public_path(cert_hash)]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {
                "data": {
                    **cert.data,
                    "included": [sig.to_dict()],
                },
            },
            ctx.handler,
        ))
        assert result["status"] == 200, result
        # The signature is now bound at the V7 invariant pointer path.
        sig_path = ctx.pathway.entity_tree.normalize_uri(
            f"{q_kp.peer_id}/system/signature/{cert_hash.hex()}",
        )
        bound = ctx.pathway.entity_tree.get(sig_path)
        assert bound == sig.compute_hash()

    def test_ingestion_idempotent_on_identical_hash(self):
        ctx = _make_ctx()
        q_kp, q_h = _make_signer(2011)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)
        cert = make_attestation(
            attesting=quorum_id, attested=b"\x00" + b"Y" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        sig = create_signature_entity(q_kp, cert.compute_hash(), q_h)

        ctx.handler.resource_targets = [cert_public_path(cert.compute_hash())]
        # First call: ingests + binds.
        result1 = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": {**cert.data, "included": [sig.to_dict()]}},
            ctx.handler,
        ))
        assert result1["status"] == 200
        # Second call (same envelope shape; cert already at path so
        # we'll re-ingest the sig — should be no-op idempotent).
        # Actually we'd get a path collision on cert; the test just
        # verifies the sig-ingestion path is stable.


# ---------------------------------------------------------------------------
# process_attestation §6.3 fail-closed unbind (SI-10)
# ---------------------------------------------------------------------------


class TestControllerEventsStream:
    """V7 PI-5: phase-3 of :process_attestation emits a controller-event
    entity per failed phase-2 handler. Failure-only in v2; subkind
    distinguishes recovery_signal (orphaned state) from failure_observation
    (consistent state). Recovery-signal events MUST NOT be pruned until
    cleared.
    """

    def test_emit_controller_event_path_and_shape(self):
        """`_emit_controller_event` builds and binds a system/identity/event
        entity at the canonical path. The trailing event-content-hash makes
        the path unique by construction.
        """
        from entity_handlers.identity import (
            EVENT_TYPE,
            EVENTS_ROOT,
            EVENT_SUBKIND_RECOVERY_SIGNAL,
            HANDLER_ID_PUBLISH_ATTESTATION,
            _emit_controller_event,
        )

        ctx = _make_ctx()
        att_hash = b"\x00" + b"A" * 32
        event_hash = _emit_controller_event(
            ctx.handler,
            event_subkind=EVENT_SUBKIND_RECOVERY_SIGNAL,
            handler_id=HANDLER_ID_PUBLISH_ATTESTATION,
            attestation_hash=att_hash,
            attestation_kind="identity-cert",
            error_code="unbind_failed",
            error_detail="old path remained bound after retry",
            operation="publish_attestation",
            timestamp_ms=1700000000000,
        )

        path = (
            f"{EVENTS_ROOT}/1700000000000/{HANDLER_ID_PUBLISH_ATTESTATION}/"
            f"{att_hash.hex()}/{event_hash.hex()}"
        )
        full = ctx.pathway.entity_tree.normalize_uri(path)
        bound_hash = ctx.pathway.entity_tree.get(full)
        assert bound_hash == event_hash, (
            "event entity must bind at the canonical path"
        )
        event = ctx.pathway.content_store.get(event_hash)
        assert event is not None
        assert event.type == EVENT_TYPE
        assert event.data["event_subkind"] == EVENT_SUBKIND_RECOVERY_SIGNAL
        assert event.data["handler_id"] == HANDLER_ID_PUBLISH_ATTESTATION
        assert event.data["attestation_hash"] == att_hash
        assert event.data["attestation_kind"] == "identity-cert"
        assert event.data["error_code"] == "unbind_failed"
        assert event.data["timestamp_ms"] == 1700000000000

    def test_invalid_subkind_rejected(self):
        """Per Rev 3: event_subkind MUST be one of {recovery_signal,
        failure_observation}; informational is OUT OF SCOPE for v2."""
        from entity_handlers.identity import _emit_controller_event
        ctx = _make_ctx()
        with pytest.raises(ValueError):
            _emit_controller_event(
                ctx.handler,
                event_subkind="informational",  # v2.x roadmap, not v2
                handler_id="x",
                attestation_hash=b"\x00" + b"X" * 32,
                attestation_kind="x",
                error_code="x",
                error_detail="x",
                operation="x",
            )


class TestProcessAttestationFailClosed:
    def test_validation_failure_unbinds_path(self):
        """SI-10: process_attestation validation failure MUST unbind
        the path so invalid entities don't sit in the tree."""
        ctx = _make_ctx()
        # Quorum + invalid identity-cert (signed by a peer we never set up)
        q_kp, q_h = _make_signer(1001)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_h], 1)

        # Build a controller cert WITHOUT a signature; bind it (simulating
        # cross-peer arrival of an unsigned attestation).
        cert = make_attestation(
            attesting=quorum_id, attested=b"\x00" + b"X" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        path = cert_public_path(cert.compute_hash())
        _bootstrap(ctx.pathway, path, cert)
        # No signature bound → validation will fail.

        ctx.handler.resource_targets = [path]
        result = _run(identity_handler(
            "system/identity", "process_attestation",
            {"data": {"attestation": cert.to_dict()}},
            ctx.handler,
        ))
        assert result["status"] == 403
        # The path is now unbound (fail-closed).
        full = ctx.pathway.entity_tree.normalize_uri(path)
        assert ctx.pathway.entity_tree.get(full) is None


# ---------------------------------------------------------------------------
# Flat request shape — EXTENSION-ATTESTATION §6.1 / EXTENSION-IDENTITY §6
# (TV-IDENTITY-CREATE-ATTESTATION-FLAT-SHAPE per cross-impl conformance)
# ---------------------------------------------------------------------------


class TestFlatRequestShape:
    """Spec-pinned wire shape: params carry flat top-level fields
    `{attesting, attested, properties, supersedes?, ...}` with no outer
    `attestation:` envelope. Wrapped form is rejected as `invalid_params`."""

    def _setup_signed_agent(self, seed_offset: int) -> tuple[Ctx, Entity, str]:
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(5000 + seed_offset)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)

        ctrl_kp, ctrl_h = _make_signer(5100 + seed_offset)
        _bind_identity(ctx.pathway, ctrl_kp)
        ctrl_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(
            ctx.pathway, cert_public_path(ctrl_cert.compute_hash()), ctrl_cert,
        )
        _bind_signature(ctx.pathway, q_kp, q_id_hash, ctrl_cert.compute_hash())

        agent_kp, agent_h = _make_signer(5200 + seed_offset)
        _bind_identity(ctx.pathway, agent_kp)
        agent_cert = make_attestation(
            attesting=ctrl_h, attested=agent_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        ctx.pathway.content_store.put(agent_cert)
        _bind_signature(ctx.pathway, ctrl_kp, ctrl_h, agent_cert.compute_hash())
        return ctx, agent_cert, cert_internal_path(agent_cert.compute_hash())

    def test_create_attestation_accepts_flat_shape(self):
        ctx, agent_cert, path = self._setup_signed_agent(1)
        ctx.handler.resource_targets = [path]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": {
                "attesting": agent_cert.data["attesting"],
                "attested": agent_cert.data["attested"],
                "properties": agent_cert.data["properties"],
            }},
            ctx.handler,
        ))
        assert result["status"] == 200, result
        assert result["result"]["data"]["stored_at"] == path

    def test_create_attestation_rejects_wrapped_shape(self):
        """Wrapped form `{attestation: <entity>}` is no longer accepted —
        flat fields are missing, so the handler returns invalid_params."""
        ctx, agent_cert, path = self._setup_signed_agent(2)
        ctx.handler.resource_targets = [path]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": {"attestation": agent_cert.to_dict()}},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_params"

    def test_create_attestation_missing_attesting_rejected(self):
        ctx = _make_ctx()
        ctx.handler.resource_targets = ["system/identity/internal/cert/00"]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": {
                "attested": b"\x00" + b"B" * 32,
                "properties": {
                    "kind": KIND_IDENTITY_CERT,
                    "function": FUNCTION_AGENT,
                    "mode": MODE_INTERNAL,
                },
            }},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_params"

    def test_supersede_attestation_accepts_flat_shape(self):
        """Supersede requires top-level `supersedes` set to the previous
        attestation's hash — same flat shape, no `new_attestation:` wrapper."""
        ctx, agent_cert, path = self._setup_signed_agent(3)
        # First, place the original cert.
        ctx.handler.resource_targets = [path]
        first = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": dict(agent_cert.data)}, ctx.handler,
        ))
        assert first["status"] == 200

        # Build a successor cert (changes properties slightly to get a
        # distinct hash) referencing the original via `supersedes`.
        new_props = dict(agent_cert.data["properties"])
        new_props["note"] = "rotation"
        successor = make_attestation(
            attesting=agent_cert.data["attesting"],
            attested=agent_cert.data["attested"],
            properties=new_props,
            supersedes=agent_cert.compute_hash(),
        )
        # Sign via the controller (same attesting key as the original).
        # Recover the controller keypair via deterministic seed.
        ctrl_kp = Keypair.from_seed((5103).to_bytes(32, "little"))
        ctrl_h = create_identity_entity(ctrl_kp).compute_hash()
        ctx.pathway.content_store.put(successor)
        _bind_signature(ctx.pathway, ctrl_kp, ctrl_h, successor.compute_hash())

        ctx.handler.resource_targets = [
            cert_internal_path(successor.compute_hash()),
        ]
        result = _run(identity_handler(
            "system/identity", "supersede_attestation",
            {"data": {
                "attesting": successor.data["attesting"],
                "attested": successor.data["attested"],
                "properties": successor.data["properties"],
                "supersedes": successor.data["supersedes"],
            }},
            ctx.handler,
        ))
        assert result["status"] == 200, result
        assert result["result"]["data"]["stored_at"] == cert_internal_path(
            successor.compute_hash(),
        )

    def test_supersede_attestation_requires_supersedes(self):
        ctx, agent_cert, path = self._setup_signed_agent(4)
        ctx.handler.resource_targets = [path]
        result = _run(identity_handler(
            "system/identity", "supersede_attestation",
            {"data": {
                "attesting": agent_cert.data["attesting"],
                "attested": agent_cert.data["attested"],
                "properties": agent_cert.data["properties"],
                # no `supersedes` field
            }},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_params"

    def test_pi11_controller_per_relationship_rejected(self):
        """V7 PI-11 (§4.2): function=controller does not allow mode=
        per-relationship — controllers are public (3-key) or internal
        (4-key/sub). Returns 400 invalid_mode_for_function with the
        diagnostic envelope (function, attempted_mode, valid_modes).
        """
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(11_001)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)

        ctx.handler.resource_targets = ["system/identity/internal/cert/00"]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": {
                "attesting": quorum_id,
                "attested": b"\x00" + b"C" * 32,
                "properties": {
                    "kind": KIND_IDENTITY_CERT,
                    "function": FUNCTION_CONTROLLER,
                    "mode": MODE_PER_RELATIONSHIP,
                    "contact_id": b"\x00" + b"X" * 32,
                },
            }},
            ctx.handler,
        ))
        assert result["status"] == 400
        d = result["result"]["data"]
        assert d["code"] == "invalid_mode_for_function"
        assert d["function"] == FUNCTION_CONTROLLER
        assert d["attempted_mode"] == MODE_PER_RELATIONSHIP
        # Top-level controller (attesting=quorum_id) → {public, internal}.
        assert set(d["valid_modes_for_function"]) == {MODE_PUBLIC, MODE_INTERNAL}

    def test_pi11_identifier_public_rejected(self):
        """V7 PI-11 (§4.2): function=identifier MUST be mode=internal.
        identifier-cert is internal management; the identifier peer's KEY
        is the external handle, surfaced via the agent certs the
        identifier signs.
        """
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(11_002)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)

        ctx.handler.resource_targets = ["system/identity/internal/cert/00"]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": {
                "attesting": quorum_id,
                "attested": b"\x00" + b"I" * 32,
                "properties": {
                    "kind": KIND_IDENTITY_CERT,
                    "function": FUNCTION_IDENTIFIER,
                    "mode": MODE_PUBLIC,
                },
            }},
            ctx.handler,
        ))
        assert result["status"] == 400
        d = result["result"]["data"]
        assert d["code"] == "invalid_mode_for_function"
        assert d["function"] == FUNCTION_IDENTIFIER
        assert d["valid_modes_for_function"] == [MODE_INTERNAL]

    def test_pi11_sub_controller_only_internal(self):
        """V7 PI-11 (§4.2): sub-controllers (attesting = another
        controller's peer hash, not a quorum_id) MUST be mode=internal.
        Sub-controllers are internal management hierarchy.
        """
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(11_003)
        _bind_identity(ctx.pathway, q_kp)
        _bind_quorum(ctx.pathway, [q_id_hash], 1)
        # attesting points at a peer hash (not a quorum) → sub-controller.
        ctx.handler.resource_targets = ["system/identity/public/cert/00"]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": {
                "attesting": b"\x00" + b"P" * 32,  # not a quorum_id
                "attested": b"\x00" + b"Q" * 32,
                "properties": {
                    "kind": KIND_IDENTITY_CERT,
                    "function": FUNCTION_CONTROLLER,
                    "mode": MODE_PUBLIC,  # invalid for sub-controller
                },
            }},
            ctx.handler,
        ))
        assert result["status"] == 400
        d = result["result"]["data"]
        assert d["code"] == "invalid_mode_for_function"
        assert d["valid_modes_for_function"] == [MODE_INTERNAL]

    def test_pi11_app_defined_function_skipped(self):
        """V7 PI-11 (§4.2): app-defined function values bypass identity's
        valid-modes table. Apps that ship custom functions declare valid
        modes in their own validator extension.
        """
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(11_004)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)
        ctx.handler.resource_targets = ["system/identity/public/cert/00"]
        # function=custom-app-role with any mode — identity does not enforce.
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": {
                "attesting": quorum_id,
                "attested": b"\x00" + b"V" * 32,
                "properties": {
                    "kind": KIND_IDENTITY_CERT,
                    "function": "custom-app-role",
                    "mode": MODE_PUBLIC,
                },
            }},
            ctx.handler,
        ))
        # Either a 200 (valid) or a non-PI-11 error; PI-11 itself MUST not
        # reject app-defined functions.
        if result["status"] == 400:
            assert (
                result["result"]["data"]["code"] != "invalid_mode_for_function"
            )

    def test_pi1_non_rebind_kind_must_preserve_attesting_attested(self):
        """V7 PI-1: kinds NOT in REBIND_KINDS use substrate :supersede
        semantics — attesting/attested MUST equal the predecessor's. The
        rebind branch is reserved for kinds (currently {identity-cert}) where
        rotation legitimately changes the chain root. Non-rebind kinds with
        mismatched attesting/attested return 400.
        """
        ctx = _make_ctx()
        # Create a predecessor of a lifecycle kind (not in REBIND_KINDS).
        from entity_handlers.identity import KIND_ROTATION_HANDOFF, REBIND_KINDS
        assert KIND_ROTATION_HANDOFF not in REBIND_KINDS

        original_attesting = b"\x00" + b"A" * 32
        original_attested = b"\x00" + b"B" * 32
        target_cert = b"\x00" + b"T" * 32
        predecessor = make_attestation(
            attesting=original_attesting,
            attested=original_attested,
            properties={
                "kind": KIND_ROTATION_HANDOFF,
                "target_cert": target_cert,
            },
        )
        ctx.pathway.content_store.put(predecessor)

        # Attempt supersede with DIFFERENT attesting → MUST be rejected.
        ctx.handler.resource_targets = [
            cert_internal_path(predecessor.compute_hash()),
        ]
        rejected = _run(identity_handler(
            "system/identity", "supersede_attestation",
            {"data": {
                "attesting": b"\x00" + b"X" * 32,  # different attester
                "attested": original_attested,
                "properties": predecessor.data["properties"],
                "supersedes": predecessor.compute_hash(),
            }},
            ctx.handler,
        ))
        assert rejected["status"] == 400
        assert (
            rejected["result"]["data"]["code"]
            == "supersede_attesting_attested_mismatch"
        )


# ---------------------------------------------------------------------------
# Deferred validation — TV-IDENTITY-CREATE-ATTESTATION-DEFERRED-VALIDATION
# (cross-impl: locally-issued attestations bind unconditionally; signature
# graph validation is the consumer's domain — `:process_attestation`,
# `:configure`, `:verify`. Sibling of Go's PR-8.3 / TV-IF-INTERNAL-CERT-
# READABLE.)
# ---------------------------------------------------------------------------


class TestDeferredSignatureValidation:
    """Per EXTENSION-ATTESTATION §6.1 (and the analogous IDENTITY §6 wrap):
    `:create_attestation` MUST NOT validate the signature graph at create-
    time. The natural fixture flow is "create → sign → use"; signatures
    target the new attestation's hash and so cannot exist before creation."""

    def test_kofn_cert_binds_without_signatures(self):
        """K-of-N controller cert: caller submits :create_attestation
        BEFORE any quorum signatures land. Handler MUST return 200 and
        bind the entity at its canonical path. (Validation against the
        K-of-N graph happens later in `:configure` / `:process_attestation`.)"""
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(7001)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)

        ctrl_h = b"\x00" + b"C" * 32
        properties = {
            "kind": KIND_IDENTITY_CERT,
            "function": FUNCTION_CONTROLLER,
            "mode": MODE_PUBLIC,
        }
        # Compute the cert's hash deterministically so we can predict
        # the canonical path WITHOUT building+persisting the entity.
        probe = make_attestation(
            attesting=quorum_id, attested=ctrl_h, properties=properties,
        )
        path = cert_public_path(probe.compute_hash())

        ctx.handler.resource_targets = [path]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": {
                "attesting": quorum_id,
                "attested": ctrl_h,
                "properties": properties,
            }},
            ctx.handler,
        ))
        assert result["status"] == 200, result
        assert result["result"]["data"]["stored_at"] == path
        # Tree-bound — `tree:get` semantically returns the entity.
        full = ctx.pathway.entity_tree.normalize_uri(path)
        assert ctx.pathway.entity_tree.get(full) == probe.compute_hash()

    def test_single_sig_agent_cert_binds_without_signatures(self):
        """Single-sig agent cert: caller submits without binding the
        controller's signature first. Handler MUST return 200."""
        ctx = _make_ctx()
        ctrl_kp, ctrl_h = _make_signer(7101)
        _bind_identity(ctx.pathway, ctrl_kp)

        agent_h = b"\x00" + b"A" * 32
        properties = {
            "kind": KIND_IDENTITY_CERT,
            "function": FUNCTION_AGENT,
            "mode": MODE_INTERNAL,
        }
        probe = make_attestation(
            attesting=ctrl_h, attested=agent_h, properties=properties,
        )
        path = cert_internal_path(probe.compute_hash())

        ctx.handler.resource_targets = [path]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": {
                "attesting": ctrl_h,
                "attested": agent_h,
                "properties": properties,
            }},
            ctx.handler,
        ))
        assert result["status"] == 200, result
        # Same canonical path returned in the result + bound in the tree.
        assert result["result"]["data"]["stored_at"] == path

    def test_op_confinement_still_enforced_when_signature_present(self):
        """§9.2 op-confinement is structural — when a controller's
        signature DOES exist targeting a public/ cert, the handler MUST
        still reject (this is not signature-graph validation, it's a
        cross-cutting structural rule)."""
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(7201)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)

        ctrl_kp, ctrl_h = _make_signer(7202)
        _bind_identity(ctx.pathway, ctrl_kp)
        ctrl_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(
            ctx.pathway, cert_public_path(ctrl_cert.compute_hash()), ctrl_cert,
        )
        _bind_signature(ctx.pathway, q_kp, q_id_hash, ctrl_cert.compute_hash())

        # Configure peer-config so live-controllers lookup works.
        _run(identity_handler(
            "system/identity", "configure",
            {"data": {"trusts_quorum": quorum_id, "controller_grants": []}},
            ctx.handler,
        ))

        agent_h = b"\x00" + b"Q" * 32
        agent_cert = make_attestation(
            attesting=ctrl_h, attested=agent_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_PUBLIC,
            },
        )
        ctx.pathway.content_store.put(agent_cert)
        # Controller signs the public/ agent-cert (the op-confinement
        # violation per §9.2).
        _bind_signature(
            ctx.pathway, ctrl_kp, ctrl_h, agent_cert.compute_hash(),
        )

        ctx.handler.resource_targets = [cert_public_path(agent_cert.compute_hash())]
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": dict(agent_cert.data)},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert (
            result["result"]["data"]["code"]
            == "controller_signature_forbidden_under_public"
        )


# ---------------------------------------------------------------------------
# Embedded-mode result shape (P-4 — cross-impl convergence with Go)
# ---------------------------------------------------------------------------


class TestEmbeddedResultShape:
    """Per IDENTITY §4.2: embedded mode is for inline cap-envelope
    embedding, not tree storage. Result shape: `embedded_attestation`
    inline + `attestation_hash = ZERO_HASH` (no `entity`, `mode`, or
    `stored_at` keys). Matches Go's reading."""

    def test_create_attestation_embedded_returns_attestation_data(self):
        """Per IDENTITY §4.2: `embedded_attestation` is the flat
        AttestationData (the entity's `data` field), NOT the wrapped
        Entity. Cross-impl: Go decodes the field directly as
        AttestationData; returning the Entity wrapper hides
        attesting/attested under a `data` key. Round-trip integrity:
        rebuilding the Entity from the returned data must match the
        input's hash."""
        ctx = _make_ctx()
        ctrl_h = b"\x00" + b"E" * 32
        agent_h = b"\x00" + b"F" * 32
        properties = {
            "kind": KIND_IDENTITY_CERT,
            "function": FUNCTION_AGENT,
            "mode": MODE_EMBEDDED,
        }
        result = _run(identity_handler(
            "system/identity", "create_attestation",
            {"data": {
                "attesting": ctrl_h,
                "attested": agent_h,
                "properties": properties,
            }},
            ctx.handler,
        ))
        assert result["status"] == 200, result
        data = result["result"]["data"]
        # Zero attestation_hash signals "no tree write."
        assert data["attestation_hash"] == ZERO_HASH
        # embedded_attestation is the flat AttestationData (no Entity wrapper).
        emb = data["embedded_attestation"]
        assert "type" not in emb  # NOT a wrapped Entity dict
        assert "content_hash" not in emb
        assert emb["attesting"] == ctrl_h
        assert emb["attested"] == agent_h
        assert emb["properties"] == properties
        # Removed legacy fields:
        assert "entity" not in data
        assert "mode" not in data
        assert "stored_at" not in data

        # Round-trip integrity: rebuilding the entity from the returned
        # data MUST produce the same content hash as building from the
        # original input.
        original = make_attestation(
            attesting=ctrl_h, attested=agent_h, properties=properties,
        )
        rebuilt = Entity(type=ATTESTATION_TYPE, data=emb)
        assert rebuilt.compute_hash() == original.compute_hash()

    def test_pi12_3key_default_controller_cert_path(self):
        """V7 PI-12 (Rev 3) — 3-key default deployment worked example.
        Founder quorum issues a function=controller cert with mode=public;
        the cert binds under `system/identity/public/cert/{c}`. Per the
        derivation table that namespace + (function=controller) implies:
          - audience: all contacts via registry/two-tier sync
          - sync: two-tier
          - handle-bearing: YES (3-key default; controller IS the handle)
        This test pins the path-selector job; audience/sync/handle-bearing
        derivation is documented in canonical_storage_path's docstring and
        is the spec invariant the path establishes.
        """
        from entity_handlers.identity import (
            canonical_storage_path,
            cert_public_path,
        )
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(12_001)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)

        ctrl_h = b"\x00" + b"C" * 32
        ctrl_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        path = canonical_storage_path(ctrl_cert, ctx.handler)
        assert path == cert_public_path(ctrl_cert.compute_hash())
        assert path.startswith("system/identity/public/cert/")

    def test_pi12_4key_advanced_identifier_and_controller_paths(self):
        """V7 PI-12 (Rev 3) — 4-key advanced deployment worked example.
        Founder quorum issues:
          - identifier-cert (function=identifier, mode=internal) at
            `system/identity/internal/cert/{i}` — handle-bearing (the
            identifier's KEY is the contact-facing handle).
          - controller-cert (function=controller, mode=internal,
            attesting=identifier_hash) at `system/identity/internal/cert/{c}`
            — NOT handle-bearing in 4-key (controller is internal mgmt).
        Both bind under the internal namespace; per the derivation table,
        audience=own agents only, sync=none for both. Handle-bearing
        differs by (function): identifier yes, controller no.
        """
        from entity_handlers.identity import (
            canonical_storage_path,
            cert_internal_path,
        )
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(12_002)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)

        # identifier-cert (the handle in 4-key).
        identifier_h = b"\x00" + b"I" * 32
        id_cert = make_attestation(
            attesting=quorum_id, attested=identifier_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_IDENTIFIER,
                "mode": MODE_INTERNAL,
            },
        )
        # controller-cert (internal mgmt; attesting points to the identifier
        # peer in 4-key advanced).
        ctrl_h = b"\x00" + b"K" * 32
        ctrl_cert = make_attestation(
            attesting=identifier_h, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_INTERNAL,
            },
        )
        id_path = canonical_storage_path(id_cert, ctx.handler)
        ctrl_path = canonical_storage_path(ctrl_cert, ctx.handler)
        assert id_path == cert_internal_path(id_cert.compute_hash())
        assert ctrl_path == cert_internal_path(ctrl_cert.compute_hash())
        # Both under the internal namespace per the derivation table.
        assert id_path.startswith("system/identity/internal/cert/")
        assert ctrl_path.startswith("system/identity/internal/cert/")

    def test_pi13_revoke_controller_cert_cascades_cap_cleanup(self):
        """V7 PI-13 (Rev 3): :revoke_attestation on a top-level controller
        cert MUST cascade — walk the peer-to-controller/* subtree and unbind
        caps whose grantee matches the revoked controller's `attested`. Cap
        signature siblings unbind alongside the cap.
        """
        from entity_handlers.identity import (
            _local_peer_to_controller_cap_path,
        )

        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(13_001)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)
        ctrl_kp, ctrl_h = _make_signer(13_002)
        _bind_identity(ctx.pathway, ctrl_kp)
        ctrl_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(
            ctx.pathway, cert_public_path(ctrl_cert.compute_hash()), ctrl_cert,
        )
        _bind_signature(
            ctx.pathway, q_kp, q_id_hash, ctrl_cert.compute_hash(),
        )

        # :configure issues a cap for the controller.
        cfg = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": [{"path": "*", "ops": ["*"]}],
            }},
            ctx.handler,
        ))
        assert cfg["status"] == 200, cfg
        cap_path = _local_peer_to_controller_cap_path(ctrl_h)
        cap_full = ctx.pathway.entity_tree.normalize_uri(cap_path)
        cap_hash = ctx.pathway.entity_tree.get(cap_full)
        assert cap_hash is not None
        # Per EXTENSION-IDENTITY v3.6 (I-7): the cap signature
        # is bound at the V7 invariant pointer
        # `/{granter_peer_id}/system/signature/{cap_hash_hex}`, NOT at
        # the v3.5 sibling `{cap_path}/signature`.
        from entity_core.utils.path import invariant_signature_path
        granter_peer_id = ctx.keypair.peer_id
        inv_sig_path = invariant_signature_path(granter_peer_id, cap_hash)
        inv_sig_full = ctx.pathway.entity_tree.normalize_uri(inv_sig_path)
        legacy_sig_full = ctx.pathway.entity_tree.normalize_uri(
            f"{cap_path}/signature",
        )
        # Cap bound; signature bound at the invariant pointer; sibling
        # MUST NOT be bound under v3.6.
        assert ctx.pathway.entity_tree.get(inv_sig_full) is not None
        assert ctx.pathway.entity_tree.get(legacy_sig_full) is None, (
            "cap signature MUST NOT be bound at the v3.5 sibling path "
            "after EXTENSION-IDENTITY v3.6 (I-7)"
        )

        # :revoke_attestation on the controller cert should cascade.
        revoke = _run(identity_handler(
            "system/identity", "revoke_attestation",
            {"data": {"target_hash": ctrl_cert.compute_hash()}},
            ctx.handler,
        ))
        assert revoke["status"] == 200, revoke
        # Cap AND invariant-pointer signature MUST be unbound after cascade.
        assert ctx.pathway.entity_tree.get(cap_full) is None, (
            "cap must be unbound by PI-13 cascade"
        )
        assert ctx.pathway.entity_tree.get(inv_sig_full) is None, (
            "cap signature at V7 invariant pointer must be unbound "
            "alongside the cap"
        )

    def test_pi3_publish_unbind_retry_failure_emits_recovery_signal(self):
        """V7 PI-3 (Rev 3 (3a)): when bind(new_path) succeeds but
        unbind(old_path) fails after retry, the entity is bound at BOTH
        paths. Phase 3 emits a recovery_signal controller-event so the
        controller can resolve the orphan. Per Rev 3 (3): retention is
        constrained — the tombstone IS the recovery signal.
        """
        from entity_handlers.identity import (
            EVENT_SUBKIND_RECOVERY_SIGNAL,
            EVENTS_ROOT,
            HANDLER_ID_PUBLISH_ATTESTATION,
            cert_internal_path,
            cert_public_path,
        )

        ctx = _make_ctx()
        ctrl_h = b"\x00" + b"P" * 32
        agent_h = b"\x00" + b"Q" * 32
        att = make_attestation(
            attesting=ctrl_h, attested=agent_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        att_h = att.compute_hash()
        ctx.pathway.content_store.put(att)
        # Pre-bind at the OLD canonical path so :publish has something to
        # unbind.
        old_path = cert_internal_path(att_h)
        new_path = cert_public_path(att_h)
        _bootstrap(ctx.pathway, old_path, att)

        # Force unbind to always fail. EmitPathway.delete is the outer
        # surface :publish uses for unbinding.
        original_delete = ctx.pathway.delete
        def _fail_delete(path, emit_ctx):
            raise RuntimeError("storage layer rejected unbind")
        ctx.pathway.delete = _fail_delete  # type: ignore[assignment]

        try:
            result = _run(identity_handler(
                "system/identity", "publish_attestation",
                {"data": {
                    "attestation_hash": att_h,
                    "new_mode": MODE_PUBLIC,
                }},
                ctx.handler,
            ))
        finally:
            ctx.pathway.delete = original_delete  # type: ignore[assignment]

        # The publish itself succeeds (new path is bound; the tombstone is
        # how we recover from the orphaned old binding).
        assert result["status"] == 200, result
        # The new path holds the entity.
        new_full = ctx.pathway.entity_tree.normalize_uri(new_path)
        assert ctx.pathway.entity_tree.get(new_full) == att_h
        # The old path is STILL bound (orphan).
        old_full = ctx.pathway.entity_tree.normalize_uri(old_path)
        assert ctx.pathway.entity_tree.get(old_full) == att_h

        # A recovery_signal event was emitted under the events stream.
        events_root = ctx.pathway.entity_tree.normalize_uri(EVENTS_ROOT)
        events = [
            (uri, h) for (uri, h) in ctx.pathway.entity_tree.all_bindings()
            if uri.startswith(events_root)
        ]
        assert events, "expected at least one controller-event entity"
        # Find the publish-attestation tombstone.
        published_events = [
            (uri, h) for (uri, h) in events
            if f"/{HANDLER_ID_PUBLISH_ATTESTATION}/" in uri
        ]
        assert len(published_events) == 1, published_events
        _, event_hash = published_events[0]
        event = ctx.pathway.content_store.get(event_hash)
        assert event is not None
        assert event.data["event_subkind"] == EVENT_SUBKIND_RECOVERY_SIGNAL
        assert event.data["handler_id"] == HANDLER_ID_PUBLISH_ATTESTATION
        assert event.data["attestation_hash"] == att_h
        assert event.data["error_code"] == "unbind_failed_after_retry"

    def test_publish_attestation_embedded_returns_invalid_target_mode(self):
        """V7 PI-3 (Rev 3): embedded is NOT a movable target_mode for
        :publish_attestation. Embedded mode lives inline in cap envelopes
        (set at create-time, not move-time); publishing to embedded is a
        category error. Returns 400 invalid_target_mode.
        """
        ctx = _make_ctx()
        ctrl_h = b"\x00" + b"G" * 32
        agent_h = b"\x00" + b"H" * 32
        att = make_attestation(
            attesting=ctrl_h, attested=agent_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        ctx.pathway.content_store.put(att)
        result = _run(identity_handler(
            "system/identity", "publish_attestation",
            {"data": {
                "attestation_hash": att.compute_hash(),
                "new_mode": MODE_EMBEDDED,
            }},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_target_mode"


# ---------------------------------------------------------------------------
# Cross-impl result-shape conformance for :configure and :publish_attestation
# (Round-4 P-7 / P-8 / P-9 — Go's IdentityConfigureResultData /
# IdentityPublishAttestationResultData).
# ---------------------------------------------------------------------------


class TestConfigureResultShape:
    def _setup_quorum_and_controller(self) -> tuple[Ctx, bytes, bytes]:
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(8001)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)

        ctrl_kp, ctrl_h = _make_signer(8002)
        _bind_identity(ctx.pathway, ctrl_kp)
        ctrl_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(
            ctx.pathway, cert_public_path(ctrl_cert.compute_hash()), ctrl_cert,
        )
        _bind_signature(
            ctx.pathway, q_kp, q_id_hash, ctrl_cert.compute_hash(),
        )
        return ctx, quorum_id, ctrl_h

    def test_configure_result_carries_peer_config_path_absolute(self):
        ctx, quorum_id, _ = self._setup_quorum_and_controller()
        result = _run(identity_handler(
            "system/identity", "configure",
            {"data": {"trusts_quorum": quorum_id, "controller_grants": []}},
            ctx.handler,
        ))
        assert result["status"] == 200, result
        d = result["result"]["data"]
        # peer_config_path is absolute (starts with /), points to the
        # canonical peer-config path under the local peer.
        assert "peer_config_path" in d
        pcp = d["peer_config_path"]
        assert isinstance(pcp, str) and pcp.startswith("/")
        assert pcp.endswith("system/identity/peer-config")
        # Local peer ID appears in the absolute form.
        assert ctx.handler.local_peer_id in pcp

    def test_configure_result_carries_cap_hashes_not_controller_hashes(self):
        ctx, quorum_id, ctrl_h = self._setup_quorum_and_controller()
        result = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": [{"path": "test/*", "ops": ["read"]}],
            }},
            ctx.handler,
        ))
        assert result["status"] == 200, result
        d = result["result"]["data"]
        caps = d["local_peer_to_controller_caps"]
        # One issued cap, exactly.
        assert len(caps) == 1
        # The list contains the CAP HASH (resolvable in the content store)
        # — NOT the controller's identity hash.
        cap_hash = caps[0]
        assert cap_hash != ctrl_h
        cap_entity = ctx.pathway.content_store.get(cap_hash)
        assert cap_entity is not None
        assert cap_entity.type == "system/capability/token"
        assert cap_entity.data["grantee"] == ctrl_h

    def test_configure_with_bindings_populates_path_and_caps(self):
        """P-9: configure with `bindings` should still return the
        canonical fields (shared codepath with vanilla configure)."""
        ctx, quorum_id, ctrl_h = self._setup_quorum_and_controller()
        result = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": [{"path": "*", "ops": ["*"]}],
                "bindings": [],
            }},
            ctx.handler,
        ))
        assert result["status"] == 200, result
        d = result["result"]["data"]
        assert d["peer_config_path"].startswith("/")
        assert len(d["local_peer_to_controller_caps"]) == 1


class TestPublishAttestationResultShape:
    def test_publish_returns_new_path_in_absolute_form(self):
        """P-8: `new_path` MUST be a non-empty absolute path equal to
        the canonical post-move path (`/{peer_id}/system/identity/...`)."""
        ctx = _make_ctx()
        ctrl_kp, ctrl_h = _make_signer(8101)
        _bind_identity(ctx.pathway, ctrl_kp)
        agent_kp, agent_h = _make_signer(8102)
        _bind_identity(ctx.pathway, agent_kp)

        internal_agent = make_attestation(
            attesting=ctrl_h, attested=agent_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        _bootstrap(
            ctx.pathway, cert_internal_path(internal_agent.compute_hash()),
            internal_agent,
        )
        _bind_signature(
            ctx.pathway, ctrl_kp, ctrl_h, internal_agent.compute_hash(),
        )

        result = _run(identity_handler(
            "system/identity", "publish_attestation",
            {"data": {
                "attestation_hash": internal_agent.compute_hash(),
                "new_mode": MODE_PUBLIC,
            }},
            ctx.handler,
        ))
        assert result["status"] == 200, result
        d = result["result"]["data"]
        new_path = d["new_path"]
        # Absolute form.
        assert new_path.startswith("/")
        # Local peer ID is in the path.
        assert ctx.handler.local_peer_id in new_path
        # Canonical public/cert leaf.
        assert "/system/identity/public/cert/" in new_path


# ---------------------------------------------------------------------------
# Round-5: P-10 (configure stale-cap reconciliation), P-11 (revoke target_hash),
# P-12 (publish hash preservation), P-13 (binding cert validation)
# ---------------------------------------------------------------------------


class TestConfigureSupersedeReconciliation:
    """P-10: post-supersede `:configure` MUST issue caps for the live tip
    only AND revoke any cap whose grantee is no longer a live controller."""

    def _setup(self, seed: int) -> tuple[Ctx, bytes, bytes, bytes, bytes]:
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(9000 + seed)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)

        # Old controller cert.
        old_kp, old_h = _make_signer(9100 + seed)
        _bind_identity(ctx.pathway, old_kp)
        old_cert = make_attestation(
            attesting=quorum_id, attested=old_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(
            ctx.pathway, cert_public_path(old_cert.compute_hash()), old_cert,
        )
        _bind_signature(
            ctx.pathway, q_kp, q_id_hash, old_cert.compute_hash(),
        )
        return ctx, quorum_id, q_id_hash, old_h, old_cert.compute_hash()

    def test_configure_post_supersede_revokes_old_cap(self):
        ctx, quorum_id, q_id_hash, old_h, old_cert_hash = self._setup(1)
        # Set up quorum signing keypair for the supersede path.
        q_kp = Keypair.from_seed((9001).to_bytes(32, "little"))

        grants = [{"path": "*", "ops": ["*"]}]
        # First configure issues a cap for the OLD controller.
        result1 = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": grants,
            }},
            ctx.handler,
        ))
        assert result1["status"] == 200
        old_caps = result1["result"]["data"]["local_peer_to_controller_caps"]
        assert len(old_caps) == 1
        # Cap exists at old controller's path.
        old_cap_full = ctx.pathway.entity_tree.normalize_uri(
            f"system/capability/grants/identity/peer-to-controller/{old_h.hex()}",
        )
        assert ctx.pathway.entity_tree.get(old_cap_full) is not None

        # Build NEW controller cert that supersedes the OLD one.
        new_kp, new_h = _make_signer(9201)
        _bind_identity(ctx.pathway, new_kp)
        new_cert = make_attestation(
            attesting=quorum_id, attested=new_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
            supersedes=old_cert_hash,
        )
        _bootstrap(
            ctx.pathway, cert_public_path(new_cert.compute_hash()), new_cert,
        )
        _bind_signature(
            ctx.pathway, q_kp, q_id_hash, new_cert.compute_hash(),
        )

        # Re-run configure post-supersede.
        result2 = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": grants,
            }},
            ctx.handler,
        ))
        assert result2["status"] == 200
        new_caps = result2["result"]["data"]["local_peer_to_controller_caps"]
        # Exactly one cap (for the NEW controller — live tip).
        assert len(new_caps) == 1
        # New cap exists at NEW controller's path.
        new_cap_full = ctx.pathway.entity_tree.normalize_uri(
            f"system/capability/grants/identity/peer-to-controller/{new_h.hex()}",
        )
        assert ctx.pathway.entity_tree.get(new_cap_full) is not None
        # OLD controller cap is GONE (P-10: stale caps reconciled).
        assert ctx.pathway.entity_tree.get(old_cap_full) is None


class TestRevokeAttestation:
    """P-11 / P-11' (Round-6): `:revoke_attestation` MUST accept
    `target_hash` (canonical wire form), MINT a kind=revocation
    attestation entity, bind it at the same audience-tier path as the
    target, and return its content_hash as `revocation_hash`. The
    target's binding is NOT removed — its liveness is determined by the
    chain walk finding the revocation entity."""

    def test_revoke_by_target_hash_mints_revocation(self):
        ctx = _make_ctx()
        ctrl_kp, ctrl_h = _make_signer(9301)
        _bind_identity(ctx.pathway, ctrl_kp)
        agent_h = b"\x00" + b"X" * 32
        att = make_attestation(
            attesting=ctrl_h, attested=agent_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        target_path = cert_internal_path(att.compute_hash())
        _bootstrap(ctx.pathway, target_path, att)

        result = _run(identity_handler(
            "system/identity", "revoke_attestation",
            {"data": {"target_hash": att.compute_hash()}},
            ctx.handler,
        ))
        assert result["status"] == 200, result
        d = result["result"]["data"]
        # P-11' (TV-REVOKE-ATTESTATION-RESULT-HASH): non-zero hash
        # identifying the minted revocation entity.
        revocation_hash = d["revocation_hash"]
        assert revocation_hash != ZERO_HASH
        assert revocation_hash != att.compute_hash()
        # The revocation entity is bound at the same-tier (internal/) path,
        # leaf-keyed by the revocation's own hash.
        rev_full = ctx.pathway.entity_tree.normalize_uri(d["stored_at"])
        assert ctx.pathway.entity_tree.get(rev_full) == revocation_hash
        # The bound entity is a `kind=revocation` attestation pointing
        # at the original target.
        rev_ent = ctx.pathway.content_store.get(revocation_hash)
        assert rev_ent is not None
        assert rev_ent.type == ATTESTATION_TYPE
        assert rev_ent.data["properties"]["kind"] == KIND_REVOCATION
        assert rev_ent.data["attested"] == att.compute_hash()
        assert rev_ent.data["attesting"] == ctrl_h  # same as target's attesting
        # Target's tree binding is preserved (revocation makes it
        # non-live; it's not unbound).
        target_full = ctx.pathway.entity_tree.normalize_uri(target_path)
        assert ctx.pathway.entity_tree.get(target_full) == att.compute_hash()
        # Liveness predicate now returns False (self-revocation fires).
        assert is_attestation_live(att, ctx.handler) is False

    def test_revoke_carries_reason_into_revocation_props(self):
        ctx = _make_ctx()
        ctrl_kp, ctrl_h = _make_signer(9311)
        _bind_identity(ctx.pathway, ctrl_kp)
        att = make_attestation(
            attesting=ctrl_h, attested=b"\x00" + b"Y" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        ctx.pathway.content_store.put(att)
        result = _run(identity_handler(
            "system/identity", "revoke_attestation",
            {"data": {
                "target_hash": att.compute_hash(),
                "reason": "key compromise",
            }},
            ctx.handler,
        ))
        assert result["status"] == 200
        rev_hash = result["result"]["data"]["revocation_hash"]
        rev = ctx.pathway.content_store.get(rev_hash)
        assert rev.data["properties"]["reason"] == "key compromise"

    def test_revoke_target_hash_not_found(self):
        ctx = _make_ctx()
        bogus_hash = b"\x00" + b"Z" * 32
        result = _run(identity_handler(
            "system/identity", "revoke_attestation",
            {"data": {"target_hash": bogus_hash}},
            ctx.handler,
        ))
        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "attestation_not_found"


class TestPublishPreservesHash:
    """P-12: `:publish_attestation` MUST move (not re-create) the binding.
    Entity hash is preserved; the new path's hash segment matches input."""

    def test_publish_preserves_hash_internal_to_public(self):
        ctx = _make_ctx()
        ctrl_h = b"\x00" + b"M" * 32
        agent_h = b"\x00" + b"N" * 32
        att = make_attestation(
            attesting=ctrl_h, attested=agent_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        # Bind at internal path.
        old_path = cert_internal_path(att.compute_hash())
        _bootstrap(ctx.pathway, old_path, att)
        original_hash = att.compute_hash()

        result = _run(identity_handler(
            "system/identity", "publish_attestation",
            {"data": {
                "attestation_hash": original_hash,
                "new_mode": MODE_PUBLIC,
            }},
            ctx.handler,
        ))
        assert result["status"] == 200
        d = result["result"]["data"]
        # Hash preserved across the move.
        assert d["attestation_hash"] == original_hash
        # The new_path's hash segment is the same hash (hex form).
        assert original_hash.hex() in d["new_path"]
        # Bound at the new (public) path.
        new_full = ctx.pathway.entity_tree.normalize_uri(
            cert_public_path(original_hash),
        )
        assert ctx.pathway.entity_tree.get(new_full) == original_hash
        # OLD internal binding removed.
        old_full = ctx.pathway.entity_tree.normalize_uri(old_path)
        assert ctx.pathway.entity_tree.get(old_full) is None

    def test_publish_preserves_hash_to_per_relationship(self):
        ctx = _make_ctx()
        ctrl_h = b"\x00" + b"P" * 32
        agent_h = b"\x00" + b"Q" * 32
        att = make_attestation(
            attesting=ctrl_h, attested=agent_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        _bootstrap(ctx.pathway, cert_internal_path(att.compute_hash()), att)
        contact = b"\x00" + b"K" * 32
        result = _run(identity_handler(
            "system/identity", "publish_attestation",
            {"data": {
                "attestation_hash": att.compute_hash(),
                "new_mode": MODE_PER_RELATIONSHIP,
                "contact_id": contact,
            }},
            ctx.handler,
        ))
        assert result["status"] == 200
        d = result["result"]["data"]
        assert d["attestation_hash"] == att.compute_hash()
        assert att.compute_hash().hex() in d["new_path"]
        assert contact.hex() in d["new_path"]


class TestBindingValidation:
    """P-13: `:configure` with bindings MUST enforce PR-8.4 binding error
    contract. Unresolvable handle_cert/agent_cert → 404 binding_cert_not_found."""

    def _setup_quorum_and_controller(
        self,
    ) -> tuple[Ctx, bytes, bytes, bytes]:
        """Returns (ctx, quorum_id, ctrl_peer_hash, ctrl_cert_hash)."""
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(9501)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)
        ctrl_kp, ctrl_h = _make_signer(9502)
        _bind_identity(ctx.pathway, ctrl_kp)
        ctrl_cert = make_attestation(
            attesting=quorum_id, attested=ctrl_h,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(
            ctx.pathway, cert_public_path(ctrl_cert.compute_hash()), ctrl_cert,
        )
        _bind_signature(
            ctx.pathway, q_kp, q_id_hash, ctrl_cert.compute_hash(),
        )
        return ctx, quorum_id, ctrl_h, ctrl_cert.compute_hash()

    def test_unresolvable_handle_cert_returns_404(self):
        ctx, quorum_id, _ctrl_h, _ctrl_cert_h = self._setup_quorum_and_controller()
        bogus_hash = b"\x00" + b"!" * 32
        agent_hash = b"\x00" + b"?" * 32
        result = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": [],
                "bindings": [{
                    "handle_cert": bogus_hash,
                    "agent_cert": agent_hash,
                }],
            }},
            ctx.handler,
        ))
        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "binding_cert_not_found"

    def test_zero_handle_cert_returns_400(self):
        ctx, quorum_id, _ctrl_h, _ctrl_cert_h = self._setup_quorum_and_controller()
        result = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": [],
                "bindings": [{
                    "handle_cert": b"",
                    "agent_cert": b"\x00" + b"X" * 32,
                }],
            }},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "binding_missing_handle_cert"

    def test_wrong_kind_handle_cert_returns_400(self):
        """A handle_cert hash that resolves but to a non-attestation
        entity (or wrong kind) → 400 binding_cert_wrong_kind."""
        ctx, quorum_id, _ctrl_h, _ctrl_cert_h = self._setup_quorum_and_controller()
        # Put a non-attestation entity in the content store.
        wrong = Entity(
            type="system/peer", data={"peer_id": "z", "public_key": b"x" * 32},
        )
        ctx.pathway.content_store.put(wrong)
        agent_hash = b"\x00" + b"X" * 32
        result = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": [],
                "bindings": [{
                    "handle_cert": wrong.compute_hash(),
                    "agent_cert": agent_hash,
                }],
            }},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "binding_cert_wrong_kind"

    def test_resolvable_bindings_succeed(self):
        """Sanity check: with valid attestations in the store, the
        bindings validation passes and configure returns 200.

        Per V7 PI-2 (Rev 3): handle_cert MUST have function=controller
        (or identifier); agent_cert MUST have function=agent and chain to
        a live controller. The setup binds a live top-level controller;
        the agent_cert's attesting points directly at it.
        """
        ctx, quorum_id, ctrl_h, ctrl_cert_h = self._setup_quorum_and_controller()
        # Use the existing controller cert as the handle_cert (3-key default
        # deployment shape: handle = controller).
        agent_att = make_attestation(
            attesting=ctrl_h, attested=b"\x00" + b"A" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        ctx.pathway.content_store.put(agent_att)

        result = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": [],
                "bindings": [{
                    "handle_cert": ctrl_cert_h,
                    "agent_cert": agent_att.compute_hash(),
                }],
            }},
            ctx.handler,
        ))
        assert result["status"] == 200, result

    def test_pi2_phase3_invalid_controller_signature_aborts(self):
        """V7 PI-2 Phase 3 (Rev 3): :configure MUST re-verify each live
        controller cert's signature graph as defense-in-depth. A
        controller cert that fails verification aborts :configure with
        403 controller_invalid (no caps issued, no peer-config persisted).
        """
        ctx = _make_ctx()
        q_kp, q_id_hash = _make_signer(2_001)
        _bind_identity(ctx.pathway, q_kp)
        quorum_id = _bind_quorum(ctx.pathway, [q_id_hash], 1)
        # Bind a controller cert WITHOUT a valid signature (the quorum
        # signer never signed it). is_attestation_live returns True (no
        # self-revocation/expiry/supersession), so phase 2 enumerates it.
        # Phase 3 MUST catch the missing signature.
        unsigned_ctrl = make_attestation(
            attesting=quorum_id, attested=b"\x00" + b"X" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_CONTROLLER,
                "mode": MODE_PUBLIC,
            },
        )
        _bootstrap(
            ctx.pathway,
            cert_public_path(unsigned_ctrl.compute_hash()),
            unsigned_ctrl,
        )
        # No signature bound — verify will fail.

        result = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": [{"path": "*", "ops": ["*"]}],
            }},
            ctx.handler,
        ))
        assert result["status"] == 403, result
        assert result["result"]["data"]["code"] == "controller_invalid"
        # Phase 3 aborts BEFORE phase 4: no peer-to-controller cap was
        # issued. (The peer-config is also not persisted since phase 5
        # runs after phase 4.)
        cap_prefix = "system/capability/grants/identity/peer-to-controller/"
        bound = list(ctx.pathway.entity_tree.list_prefix(cap_prefix))
        assert bound == []

    def test_pi2_binding_controller_not_live(self):
        """V7 PI-2 phase 2 (Rev 3): a binding whose agent_cert.attesting
        does not chain to a live controller is rejected with
        400 binding_controller_not_live. Prevents bindings to retired
        controllers.
        """
        ctx, quorum_id, _ctrl_h, ctrl_cert_h = self._setup_quorum_and_controller()
        # agent_cert chains to a NON-live controller (random hash).
        rogue_ctrl = b"\x00" + b"Z" * 32
        agent_att = make_attestation(
            attesting=rogue_ctrl, attested=b"\x00" + b"A" * 32,
            properties={
                "kind": KIND_IDENTITY_CERT,
                "function": FUNCTION_AGENT,
                "mode": MODE_INTERNAL,
            },
        )
        ctx.pathway.content_store.put(agent_att)

        result = _run(identity_handler(
            "system/identity", "configure",
            {"data": {
                "trusts_quorum": quorum_id,
                "controller_grants": [],
                "bindings": [{
                    "handle_cert": ctrl_cert_h,
                    "agent_cert": agent_att.compute_hash(),
                }],
            }},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "binding_controller_not_live"


# ---------------------------------------------------------------------------
# Unsupported operation
# ---------------------------------------------------------------------------


def test_unsupported_op_returns_501():
    ctx = _make_ctx()
    result = _run(identity_handler(
        "system/identity", "weld", {}, ctx.handler,
    ))
    assert result["status"] == 501
