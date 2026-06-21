"""Tests for EXTENSION-QUORUM v1.0 substrate primitive.

Covers:
- TV-Q1..Q5 — pluggable signer resolution + fail-closed cases (§5.3.1)
- TV-Q6..Q9 — is_quorum_id (§4.3)
- TV-QF12..QF15 — cache invalidation contract (§4.2.1)
- Handler operations (§6) — :create, :update, :publish, :verify
- K-of-N validator (§4.1)
- current_signer_set chain walk (§4.2)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

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
from entity_handlers.attestation import make_attestation
from entity_handlers.quorum import (
    IdentityResolverCycle,
    IdentityResolverMaxDepthExceeded,
    KIND_QUORUM_PUBLISH,
    KIND_QUORUM_UPDATE,
    MAX_RESOLVER_DEPTH,
    QUORUM_TYPE,
    QuorumExtension,
    QuorumResolverUnavailable,
    RESOLUTION_CONCRETE,
    ResolverAlreadyRegistered,
    current_signer_set,
    encode_hash_segment,
    is_quorum_id,
    process_quorum_attestation,
    quorum_entity_path,
    quorum_event_path,
    quorum_handler,
    verify_k_of_n_signatures,
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
        handler_pattern="system/quorum",
        keypair=keypair,
    )
    quorum_ext = QuorumExtension()
    quorum_ext.initialize(ExtensionContext(keypair=keypair, emit_pathway=pathway))
    return Ctx(keypair=keypair, pathway=pathway, handler=handler, quorum_ext=quorum_ext)


def _bootstrap_emit(pathway: EmitPathway, path: str, entity: Entity) -> bytes:
    return pathway.emit(path, entity, EmitContext.bootstrap()).hash


def _bind_identity(pathway: EmitPathway, kp: Keypair) -> bytes:
    identity = create_identity_entity(kp)
    h = identity.compute_hash()
    _bootstrap_emit(pathway, f"system/peer/identity/{kp.peer_id}", identity)
    return h


def _bind_signature(
    pathway: EmitPathway, kp: Keypair, signer_hash: bytes, target_hash: bytes,
) -> bytes:
    sig = create_signature_entity(kp, target_hash, signer_hash)
    h = sig.compute_hash()
    path = f"{kp.peer_id}/system/signature/{target_hash.hex()}"
    _bootstrap_emit(pathway, path, sig)
    return h


def _make_signer(seed: int) -> tuple[Keypair, bytes]:
    """Generate a deterministic keypair and its identity content hash."""
    kp = Keypair.from_seed(seed.to_bytes(32, "little"))
    return kp, create_identity_entity(kp).compute_hash()


def _bind_quorum(
    pathway: EmitPathway, signers: list[bytes], threshold: int,
    *, signer_resolution: str | None = None, name: str | None = None,
) -> bytes:
    data = {"signers": signers, "threshold": threshold}
    if signer_resolution is not None:
        data["signer_resolution"] = signer_resolution
    if name is not None:
        data["name"] = name
    quorum = Entity(type=QUORUM_TYPE, data=data)
    quorum_id = quorum.compute_hash()
    _bootstrap_emit(pathway, quorum_entity_path(quorum_id), quorum)
    return quorum_id


# ---------------------------------------------------------------------------
# TV-Q6..Q9 — is_quorum_id (§4.3)
# ---------------------------------------------------------------------------


class TestIsQuorumId:
    def test_tv_q6_quorum_at_canonical_path(self):
        """TV-Q6: quorum stored at canonical path → True."""
        ctx = _make_ctx()
        kp, h = _make_signer(1)
        _bind_identity(ctx.pathway, kp)
        q_id = _bind_quorum(ctx.pathway, [h], 1)
        assert is_quorum_id(q_id, ctx.handler) is True

    def test_tv_q7_no_entity_at_path(self):
        """TV-Q7: no entity bound → False."""
        ctx = _make_ctx()
        bogus = b"\x00" + b"Q" * 32
        assert is_quorum_id(bogus, ctx.handler) is False

    def test_tv_q8_type_mismatch_at_path(self):
        """TV-Q8: an entity of wrong type bound at the canonical path
        → False (type check is part of the algorithm)."""
        ctx = _make_ctx()
        # Bind a peer-config-shaped entity at a path that LOOKS like a
        # quorum path. We synthesize a hash to match the path.
        wrong = Entity(
            type="system/identity/peer-config",
            data={"trusts_quorum": b"\x00" + b"x" * 32},
        )
        wrong_hash = wrong.compute_hash()
        path = quorum_entity_path(wrong_hash)
        _bootstrap_emit(ctx.pathway, path, wrong)
        # Path resolves; type mismatch fails.
        assert is_quorum_id(wrong_hash, ctx.handler) is False

    def test_tv_q9_bootstrap_race_resolves_after_write(self):
        """TV-Q9: stateless re-evaluation across writes."""
        ctx = _make_ctx()
        kp, h = _make_signer(1)
        _bind_identity(ctx.pathway, kp)

        # Synthesize the eventual quorum and check is_quorum_id BEFORE
        # binding it.
        quorum = Entity(
            type=QUORUM_TYPE, data={"signers": [h], "threshold": 1},
        )
        q_id = quorum.compute_hash()
        assert is_quorum_id(q_id, ctx.handler) is False

        # Bind it; second call resolves true (no negative caching).
        _bootstrap_emit(ctx.pathway, quorum_entity_path(q_id), quorum)
        assert is_quorum_id(q_id, ctx.handler) is True

    def test_invalid_input_returns_false(self):
        ctx = _make_ctx()
        assert is_quorum_id(b"", ctx.handler) is False


# ---------------------------------------------------------------------------
# TV-Q1..Q5 — pluggable signer resolution (§5.3.1)
# ---------------------------------------------------------------------------


class TestResolverModes:
    def test_tv_q1_concrete_mode_built_in(self):
        """TV-Q1: concrete mode is built in; K-of-N validation succeeds."""
        ctx = _make_ctx()
        kp1, h1 = _make_signer(11)
        kp2, h2 = _make_signer(12)
        _bind_identity(ctx.pathway, kp1)
        _bind_identity(ctx.pathway, kp2)
        q_id = _bind_quorum(
            ctx.pathway, [h1, h2], 2, signer_resolution=RESOLUTION_CONCRETE,
        )

        # Sign the quorum_id directly as a target for verification.
        target = b"\x00" + b"T" * 32
        _bind_signature(ctx.pathway, kp1, h1, target)
        _bind_signature(ctx.pathway, kp2, h2, target)

        signers, threshold, mode = current_signer_set(q_id, ctx.handler)
        assert mode == RESOLUTION_CONCRETE
        assert verify_k_of_n_signatures(
            target, signers, threshold, ctx.handler,
            resolver=ctx.quorum_ext.lookup_resolver(mode),
        ) is True

    def test_tv_q2_identity_resolved_with_registered_resolver(self):
        """TV-Q2: identity-resolved mode succeeds when a resolver is
        registered (we use a stub here; phase 3 will register the real
        identity-resolved resolver)."""
        ctx = _make_ctx()
        kp_pub, h_pub = _make_signer(21)
        kp_op, h_op = _make_signer(22)
        _bind_identity(ctx.pathway, kp_pub)
        _bind_identity(ctx.pathway, kp_op)

        # Stub resolver: any signer slot → operational peer.
        def resolver(signer: bytes, _c) -> bytes:
            if signer == h_pub:
                return h_op
            return signer

        ctx.quorum_ext.register_resolver("identity-resolved", resolver)
        q_id = _bind_quorum(
            ctx.pathway, [h_pub], 1, signer_resolution="identity-resolved",
        )

        # Target signed by the OPERATIONAL key, not the public-id key.
        target = b"\x00" + b"T" * 32
        _bind_signature(ctx.pathway, kp_op, h_op, target)

        signers, threshold, mode = current_signer_set(q_id, ctx.handler)
        assert mode == "identity-resolved"
        assert verify_k_of_n_signatures(
            target, signers, threshold, ctx.handler,
            resolver=ctx.quorum_ext.lookup_resolver(mode),
        ) is True

    def test_tv_q3_identity_resolved_without_resolver_fails_closed(self):
        """TV-Q3: identity-resolved without the resolver registered →
        QuorumResolverUnavailable; do NOT silently fall back to concrete."""
        ctx = _make_ctx()
        kp, h = _make_signer(31)
        _bind_identity(ctx.pathway, kp)
        q_id = _bind_quorum(
            ctx.pathway, [h], 1, signer_resolution="identity-resolved",
        )
        with pytest.raises(QuorumResolverUnavailable) as exc_info:
            current_signer_set(q_id, ctx.handler)
        assert exc_info.value.mode_name == "identity-resolved"
        assert RESOLUTION_CONCRETE in exc_info.value.available_modes
        assert "identity-resolved" not in exc_info.value.available_modes

    def test_tv_q4_unknown_mode_fails_closed(self):
        """TV-Q4: unknown mode → QuorumResolverUnavailable."""
        ctx = _make_ctx()
        kp, h = _make_signer(41)
        _bind_identity(ctx.pathway, kp)
        q_id = _bind_quorum(
            ctx.pathway, [h], 1, signer_resolution="future-mode-xyz",
        )
        with pytest.raises(QuorumResolverUnavailable):
            current_signer_set(q_id, ctx.handler)

    def test_register_resolver_duplicate_raises(self):
        """V7 PR-6: registering the same `mode_name` twice with a different
        callable MUST raise `resolver_already_registered`. Re-registering
        the same callable is permitted as a no-op (hot-reload).
        """
        ctx = _make_ctx()
        first = lambda s, _c: s
        ctx.quorum_ext.register_resolver("custom-mode", first)
        # Same callable: idempotent no-op.
        ctx.quorum_ext.register_resolver("custom-mode", first)
        # Different callable: error.
        with pytest.raises(ResolverAlreadyRegistered) as exc_info:
            ctx.quorum_ext.register_resolver("custom-mode", lambda s, _c: s)
        assert exc_info.value.mode_name == "custom-mode"
        assert exc_info.value.code == "resolver_already_registered"

    def test_tv_q5_resolver_registers_later(self):
        """TV-Q5: at boot before the resolver is registered, validation
        fails closed; after registration, retry succeeds (no negative
        caching of resolver-missing status)."""
        ctx = _make_ctx()
        kp, h = _make_signer(51)
        _bind_identity(ctx.pathway, kp)
        q_id = _bind_quorum(
            ctx.pathway, [h], 1, signer_resolution="identity-resolved",
        )

        with pytest.raises(QuorumResolverUnavailable):
            current_signer_set(q_id, ctx.handler)

        # Now register the resolver and retry.
        ctx.quorum_ext.register_resolver(
            "identity-resolved", lambda s, _c: s,
        )
        signers, threshold, mode = current_signer_set(q_id, ctx.handler)
        assert mode == "identity-resolved"
        assert signers == [h]
        assert threshold == 1


# ---------------------------------------------------------------------------
# K-of-N validator (§4.1)
# ---------------------------------------------------------------------------


class TestKofNValidator:
    def test_2_of_3_threshold_reached(self):
        ctx = _make_ctx()
        kp1, h1 = _make_signer(101)
        kp2, h2 = _make_signer(102)
        _kp3, h3 = _make_signer(103)  # h3 doesn't sign
        _bind_identity(ctx.pathway, kp1)
        _bind_identity(ctx.pathway, kp2)

        target = b"\x00" + b"T" * 32
        _bind_signature(ctx.pathway, kp1, h1, target)
        _bind_signature(ctx.pathway, kp2, h2, target)

        assert verify_k_of_n_signatures(
            target, [h1, h2, h3], 2, ctx.handler,
        ) is True

    def test_below_threshold_fails(self):
        ctx = _make_ctx()
        kp1, h1 = _make_signer(111)
        _kp2, h2 = _make_signer(112)
        _bind_identity(ctx.pathway, kp1)

        target = b"\x00" + b"T" * 32
        _bind_signature(ctx.pathway, kp1, h1, target)

        # Only 1 valid sig, threshold 2.
        assert verify_k_of_n_signatures(
            target, [h1, h2], 2, ctx.handler,
        ) is False

    def test_duplicate_signer_counted_once(self):
        ctx = _make_ctx()
        kp, h = _make_signer(121)
        _bind_identity(ctx.pathway, kp)
        target = b"\x00" + b"T" * 32
        _bind_signature(ctx.pathway, kp, h, target)

        # Same signer listed twice — must not double-count.
        assert verify_k_of_n_signatures(
            target, [h, h], 2, ctx.handler,
        ) is False

    def test_threshold_zero_returns_true(self):
        ctx = _make_ctx()
        target = b"\x00" + b"T" * 32
        assert verify_k_of_n_signatures(target, [], 0, ctx.handler) is True


# ---------------------------------------------------------------------------
# current_signer_set walk (§4.2)
# ---------------------------------------------------------------------------


class TestCurrentSignerSet:
    def test_uses_quorum_data_when_no_updates(self):
        ctx = _make_ctx()
        _, h1 = _make_signer(201)
        _, h2 = _make_signer(202)
        q_id = _bind_quorum(ctx.pathway, [h1, h2], 2)
        signers, threshold, mode = current_signer_set(q_id, ctx.handler)
        assert signers == [h1, h2]
        assert threshold == 2
        assert mode == RESOLUTION_CONCRETE

    def test_walks_to_live_quorum_update_head(self):
        """A quorum-update attestation overrides the entity's signers."""
        ctx = _make_ctx()
        kp1, h1 = _make_signer(211)
        _bind_identity(ctx.pathway, kp1)
        _, h2 = _make_signer(212)
        q_id = _bind_quorum(ctx.pathway, [h1], 1)

        # Bind a quorum-update at the canonical event path. (We don't
        # validate K-of-N here; current_signer_set walks the live head
        # by structural lookup. K-of-N validation happens at accept
        # time via process_quorum_attestation.)
        update = make_attestation(
            attesting=q_id, attested=q_id,
            properties={
                "kind": KIND_QUORUM_UPDATE,
                "new_signers": [h1, h2],
                "new_threshold": 2,
            },
        )
        _bootstrap_emit(
            ctx.pathway,
            quorum_event_path(q_id, update.compute_hash()),
            update,
        )

        # current_signer_set may have cached; clear before re-querying.
        ctx.quorum_ext.invalidate(q_id)
        signers, threshold, _ = current_signer_set(q_id, ctx.handler)
        assert set(signers) == {h1, h2}
        assert threshold == 2

    def test_quorum_not_found(self):
        ctx = _make_ctx()
        with pytest.raises(LookupError):
            current_signer_set(b"\x00" + b"X" * 32, ctx.handler)


# ---------------------------------------------------------------------------
# TV-QF12..QF15 — cache invalidation (§4.2.1)
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


def _expected_update_path(quorum_id: bytes, new_signers, new_threshold, supersedes=None) -> str:
    """Mirror the handler's canonicalization to pre-compute the path
    callers must pass as resource_targets per SI-7/SI-22."""
    att = make_attestation(
        attesting=quorum_id, attested=quorum_id,
        properties={
            "kind": KIND_QUORUM_UPDATE,
            "new_signers": new_signers,
            "new_threshold": new_threshold,
        },
        supersedes=supersedes,
    )
    return quorum_event_path(quorum_id, att.compute_hash())


def _expected_publish_path(
    quorum_id: bytes, signers, threshold,
    *, published_handle=None, properties=None, supersedes=None,
) -> str:
    props = {
        "kind": KIND_QUORUM_PUBLISH,
        "signers": signers,
        "threshold": threshold,
    }
    if published_handle is not None:
        props["published_handle"] = published_handle
    if isinstance(properties, dict):
        for k, v in properties.items():
            if k not in props:
                props[k] = v
    att = make_attestation(
        attesting=quorum_id, attested=quorum_id,
        properties=props, supersedes=supersedes,
    )
    return quorum_event_path(quorum_id, att.compute_hash())


class TestResolverDepthAndCycle:
    """IDENTITY-2: resolvers that recurse into current_signer_set MUST
    propagate _depth/_visited; the runtime enforces MAX_RESOLVER_DEPTH=8
    and rejects cycles."""

    def test_max_depth_exceeded_raises(self):
        """A resolver that always recurses into a fresh quorum trips
        the depth bound (8 levels deep). Each level binds a distinct
        quorum entity (varied signers) so the visited set never matches
        and only depth gates the recursion."""
        ctx = _make_ctx()
        # Pre-build 10 distinct quorums (each with a unique signer set
        # so their hashes differ).
        quorum_chain: list[bytes] = []
        for i in range(10):
            _, h = _make_signer(3001 + i)
            q = _bind_quorum(
                ctx.pathway, [h], 1,
                signer_resolution="recursive_chain",
                name=f"q{i}",
            )
            quorum_chain.append(q)

        depth_seen: list[int] = []

        def recursive_resolver(signer, c, *, as_of=None, _depth=0, _visited=None):
            depth_seen.append(_depth)
            # Use the depth as an index into the chain, so each call
            # recurses into the NEXT distinct quorum.
            next_idx = _depth + 1
            if next_idx >= len(quorum_chain):
                return signer
            current_signer_set(
                quorum_chain[next_idx], c, as_of=as_of,
                _depth=_depth, _visited=_visited,
            )
            return signer

        ctx.quorum_ext.register_resolver("recursive_chain", recursive_resolver)

        with pytest.raises(IdentityResolverMaxDepthExceeded):
            current_signer_set(quorum_chain[0], ctx.handler)

    def test_cycle_detection_raises(self):
        """A resolver that recurses back into the same quorum_id triggers
        IdentityResolverCycle."""
        ctx = _make_ctx()
        _, h_a = _make_signer(3011)
        q_a = _bind_quorum(
            ctx.pathway, [h_a], 1, signer_resolution="cyclic",
        )

        def cyclic_resolver(signer, c, *, as_of=None, _depth=0, _visited=None):
            # Recurse back into q_a directly — visited set should fire.
            current_signer_set(
                q_a, c, as_of=as_of, _depth=_depth, _visited=_visited,
            )
            return signer

        ctx.quorum_ext.register_resolver("cyclic", cyclic_resolver)

        with pytest.raises(IdentityResolverCycle):
            current_signer_set(q_a, ctx.handler)

    def test_max_depth_constant_is_eight(self):
        """Spec: MAX_RESOLVER_DEPTH = 8."""
        assert MAX_RESOLVER_DEPTH == 8


class TestAsOfResolution:
    """SI-16: current_signer_set takes optional `as_of`; full
    historical-state resolution MUST. Cache only populated for as_of=None."""

    def test_tv_q_v16a_walks_to_state_at_as_of(self):
        """TV-Q-V16a: quorum-update u1 (not_before=t1) and u2
        (not_before=t2 > t1, supersedes u1); current_signer_set at
        t1.5 returns u1's signer set."""
        ctx = _make_ctx()
        kp1, h1 = _make_signer(2001)
        _bind_identity(ctx.pathway, kp1)
        _, h2 = _make_signer(2002)
        _, h3 = _make_signer(2003)
        q_id = _bind_quorum(ctx.pathway, [h1], 1)

        t1 = 1_000_000
        t2 = 2_000_000

        # u1 active at t1: signers = [h1, h2], threshold 2.
        u1 = make_attestation(
            attesting=q_id, attested=q_id,
            properties={
                "kind": KIND_QUORUM_UPDATE,
                "new_signers": [h1, h2],
                "new_threshold": 2,
            },
            not_before=t1,
        )
        _bind_signature(ctx.pathway, kp1, h1, u1.compute_hash())
        _bootstrap_emit(ctx.pathway, quorum_event_path(q_id, u1.compute_hash()), u1)

        # u2 supersedes u1 at t2: signers = [h1, h2, h3], threshold 2.
        u2 = make_attestation(
            attesting=q_id, attested=q_id,
            properties={
                "kind": KIND_QUORUM_UPDATE,
                "new_signers": [h1, h2, h3],
                "new_threshold": 2,
            },
            not_before=t2, supersedes=u1.compute_hash(),
        )
        _bind_signature(ctx.pathway, kp1, h1, u2.compute_hash())
        _bootstrap_emit(ctx.pathway, quorum_event_path(q_id, u2.compute_hash()), u2)

        # at t1.5: u2 not yet effective → u1's signer set.
        signers, threshold, _ = current_signer_set(q_id, ctx.handler, as_of=1_500_000)
        assert set(signers) == {h1, h2}
        assert threshold == 2

    def test_tv_q_v16b_walks_to_state_after_as_of(self):
        """TV-Q-V16b: same setup; as_of past u2's not_before returns
        u2's signer set."""
        ctx = _make_ctx()
        kp1, h1 = _make_signer(2011)
        _bind_identity(ctx.pathway, kp1)
        _, h2 = _make_signer(2012)
        _, h3 = _make_signer(2013)
        q_id = _bind_quorum(ctx.pathway, [h1], 1)
        t1, t2 = 1_000_000, 2_000_000

        u1 = make_attestation(
            attesting=q_id, attested=q_id,
            properties={
                "kind": KIND_QUORUM_UPDATE,
                "new_signers": [h1, h2],
                "new_threshold": 2,
            },
            not_before=t1,
        )
        _bind_signature(ctx.pathway, kp1, h1, u1.compute_hash())
        _bootstrap_emit(ctx.pathway, quorum_event_path(q_id, u1.compute_hash()), u1)

        u2 = make_attestation(
            attesting=q_id, attested=q_id,
            properties={
                "kind": KIND_QUORUM_UPDATE,
                "new_signers": [h1, h2, h3],
                "new_threshold": 2,
            },
            not_before=t2, supersedes=u1.compute_hash(),
        )
        _bind_signature(ctx.pathway, kp1, h1, u2.compute_hash())
        _bootstrap_emit(ctx.pathway, quorum_event_path(q_id, u2.compute_hash()), u2)

        signers, threshold, _ = current_signer_set(q_id, ctx.handler, as_of=t2 + 1)
        assert set(signers) == {h1, h2, h3}
        assert threshold == 2

    def test_as_of_bypasses_cache(self):
        """Per SI-16: as_of queries bypass the cache to avoid polluting
        with time-travel state."""
        ctx = _make_ctx()
        _, h1 = _make_signer(2021)
        q_id = _bind_quorum(ctx.pathway, [h1], 1)
        # Populate cache with current state.
        current_signer_set(q_id, ctx.handler)
        cached = ctx.quorum_ext.cache_lookup(q_id)
        assert cached is not None

        # Historical query at as_of=0 should NOT use the cache (it
        # returns the same answer here trivially because there are no
        # updates, but the spec requires bypass behavior; we verify by
        # confirming the cache contents are unchanged after a historical
        # lookup).
        current_signer_set(q_id, ctx.handler, as_of=0)
        # Cache untouched.
        assert ctx.quorum_ext.cache_lookup(q_id) == cached


class TestCacheInvalidation:
    def test_tv_qf12_local_update_op_invalidates(self):
        """TV-QF12: successful :update on quorum_id invalidates cache."""
        ctx = _make_ctx()
        _, h1 = _make_signer(301)
        _, h2 = _make_signer(302)
        q_id = _bind_quorum(ctx.pathway, [h1], 1)

        # Populate cache.
        current_signer_set(q_id, ctx.handler)
        assert ctx.quorum_ext.cache_lookup(q_id) is not None

        ctx.handler.resource_targets = [_expected_update_path(q_id, [h1, h2], 2)]
        result = _run(quorum_handler(
            "system/quorum", "update",
            {"data": {
                "quorum_id": q_id, "new_signers": [h1, h2], "new_threshold": 2,
            }},
            ctx.handler,
        ))
        assert result["status"] == 200
        # Cache cleared.
        assert ctx.quorum_ext.cache_lookup(q_id) is None

    def test_tv_qf13_validated_attestation_arrival_invalidates(self):
        """TV-QF13: validated quorum-update arrival invalidates cache.

        We simulate "cross-peer arrival" by binding a quorum-update at
        the event path WITHOUT going through the local handler, then
        invoking process_quorum_attestation as the validate-accept gate.
        """
        ctx = _make_ctx()
        kp1, h1 = _make_signer(311)
        _bind_identity(ctx.pathway, kp1)
        kp2, h2 = _make_signer(312)
        _bind_identity(ctx.pathway, kp2)
        q_id = _bind_quorum(ctx.pathway, [h1], 1)

        # Populate cache.
        current_signer_set(q_id, ctx.handler)

        # Bind a quorum-update signed K-of-N by the CURRENT signer set
        # (just kp1 with threshold 1).
        update = make_attestation(
            attesting=q_id, attested=q_id,
            properties={
                "kind": KIND_QUORUM_UPDATE,
                "new_signers": [h1, h2],
                "new_threshold": 2,
            },
        )
        update_hash = update.compute_hash()
        _bootstrap_emit(
            ctx.pathway, quorum_event_path(q_id, update_hash), update,
        )
        _bind_signature(ctx.pathway, kp1, h1, update_hash)

        accepted = process_quorum_attestation(update, ctx.handler)
        assert accepted is True
        assert ctx.quorum_ext.cache_lookup(q_id) is None

    def test_tv_qf14_failed_validation_does_not_invalidate(self):
        """TV-QF14: failed K-of-N validation MUST NOT invalidate cache."""
        ctx = _make_ctx()
        kp1, h1 = _make_signer(321)
        _bind_identity(ctx.pathway, kp1)
        kp2, h2 = _make_signer(322)
        _bind_identity(ctx.pathway, kp2)
        q_id = _bind_quorum(ctx.pathway, [h1, h2], 2)  # threshold 2

        # Populate cache.
        current_signer_set(q_id, ctx.handler)
        cached_before = ctx.quorum_ext.cache_lookup(q_id)
        assert cached_before is not None

        # Bind a quorum-update with INSUFFICIENT signatures (only h1
        # signs; threshold is 2).
        update = make_attestation(
            attesting=q_id, attested=q_id,
            properties={
                "kind": KIND_QUORUM_UPDATE,
                "new_signers": [h1],
                "new_threshold": 1,
            },
        )
        update_hash = update.compute_hash()
        _bootstrap_emit(
            ctx.pathway, quorum_event_path(q_id, update_hash), update,
        )
        _bind_signature(ctx.pathway, kp1, h1, update_hash)
        # Note: kp2 does NOT sign.

        accepted = process_quorum_attestation(update, ctx.handler)
        assert accepted is False
        # Cache untouched.
        assert ctx.quorum_ext.cache_lookup(q_id) == cached_before

    def test_sync_hook_invalidates_on_emit(self):
        """SI-6: cache MUST invalidate on validate-accept of cross-peer
        sync arrivals. The sync hook fires when a quorum-update entity
        is bound at the canonical event path; when validation succeeds
        inline the cache is dropped without going through a handler."""
        ctx = _make_ctx()
        kp1, h1 = _make_signer(341)
        _bind_identity(ctx.pathway, kp1)
        kp2, h2 = _make_signer(342)
        _bind_identity(ctx.pathway, kp2)
        q_id = _bind_quorum(ctx.pathway, [h1], 1)

        # Populate cache.
        current_signer_set(q_id, ctx.handler)
        assert ctx.quorum_ext.cache_lookup(q_id) is not None

        # Sign first, then bind the attestation. The hook fires on bind
        # and validates against the (already-bound) signature.
        update = make_attestation(
            attesting=q_id, attested=q_id,
            properties={
                "kind": KIND_QUORUM_UPDATE,
                "new_signers": [h1, h2],
                "new_threshold": 2,
            },
        )
        update_hash = update.compute_hash()
        _bind_signature(ctx.pathway, kp1, h1, update_hash)
        # Bind the attestation — the sync hook on emit_pathway fires.
        _bootstrap_emit(
            ctx.pathway, quorum_event_path(q_id, update_hash), update,
        )

        # Cache invalidated by the hook (no manual process_quorum_attestation
        # call).
        assert ctx.quorum_ext.cache_lookup(q_id) is None

    def test_sync_hook_does_not_invalidate_on_failed_validation(self):
        """SI-6 NON-trigger: validation failure (e.g., missing
        signatures) must leave cache untouched."""
        ctx = _make_ctx()
        kp1, h1 = _make_signer(351)
        _bind_identity(ctx.pathway, kp1)
        kp2, h2 = _make_signer(352)
        _bind_identity(ctx.pathway, kp2)
        q_id = _bind_quorum(ctx.pathway, [h1, h2], 2)  # threshold 2

        # Populate cache.
        current_signer_set(q_id, ctx.handler)
        cached_before = ctx.quorum_ext.cache_lookup(q_id)
        assert cached_before is not None

        # Build an attestation but DON'T provide enough signatures.
        update = make_attestation(
            attesting=q_id, attested=q_id,
            properties={
                "kind": KIND_QUORUM_UPDATE,
                "new_signers": [h1],
                "new_threshold": 1,
            },
        )
        # Only one sig (insufficient for threshold 2).
        _bind_signature(ctx.pathway, kp1, h1, update.compute_hash())
        # Bind — hook fires, validation fails, cache untouched.
        _bootstrap_emit(
            ctx.pathway, quorum_event_path(q_id, update.compute_hash()), update,
        )

        assert ctx.quorum_ext.cache_lookup(q_id) == cached_before

    def test_tv_qf15_invalidation_scoped_to_specific_quorum(self):
        """TV-QF15: invalidating quorum_A leaves quorum_B's cache intact."""
        ctx = _make_ctx()
        _, h1 = _make_signer(331)
        _, h2 = _make_signer(332)
        q_a = _bind_quorum(ctx.pathway, [h1], 1, name="A")
        q_b = _bind_quorum(ctx.pathway, [h2], 1, name="B")

        current_signer_set(q_a, ctx.handler)
        current_signer_set(q_b, ctx.handler)
        assert ctx.quorum_ext.cache_lookup(q_a) is not None
        assert ctx.quorum_ext.cache_lookup(q_b) is not None

        ctx.quorum_ext.invalidate(q_a)
        assert ctx.quorum_ext.cache_lookup(q_a) is None
        assert ctx.quorum_ext.cache_lookup(q_b) is not None


# ---------------------------------------------------------------------------
# Handler ops (§6)
# ---------------------------------------------------------------------------


class TestCreateHandler:
    def test_create_binds_at_canonical_path(self):
        ctx = _make_ctx()
        _, h1 = _make_signer(401)
        _, h2 = _make_signer(402)
        # Pre-compute the canonical path (mirror the handler's
        # canonicalization) per SI-7/SI-22.
        expected_quorum = Entity(
            type=QUORUM_TYPE,
            data={"signers": [h1, h2], "threshold": 2},
        )
        expected_q_id = expected_quorum.compute_hash()
        ctx.handler.resource_targets = [quorum_entity_path(expected_q_id)]
        result = _run(quorum_handler(
            "system/quorum", "create",
            {"data": {"signers": [h1, h2], "threshold": 2}},
            ctx.handler,
        ))
        assert result["status"] == 200
        q_id = result["result"]["data"]["quorum_id"]
        assert q_id == expected_q_id
        full = ctx.pathway.entity_tree.normalize_uri(quorum_entity_path(q_id))
        assert ctx.pathway.entity_tree.get(full) == q_id

    def test_create_rejects_missing_resource_target(self):
        """Per SI-7/SI-22: substrate ops MUST receive a resource target."""
        ctx = _make_ctx()
        _, h = _make_signer(403)
        result = _run(quorum_handler(
            "system/quorum", "create",
            {"data": {"signers": [h], "threshold": 1}},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "path_required"

    def test_create_rejects_threshold_above_signer_count(self):
        ctx = _make_ctx()
        _, h1 = _make_signer(411)
        result = _run(quorum_handler(
            "system/quorum", "create",
            {"data": {"signers": [h1], "threshold": 2}},
            ctx.handler,
        ))
        assert result["status"] == 400

    def test_create_rejects_zero_threshold(self):
        ctx = _make_ctx()
        _, h1 = _make_signer(412)
        result = _run(quorum_handler(
            "system/quorum", "create",
            {"data": {"signers": [h1], "threshold": 0}},
            ctx.handler,
        ))
        assert result["status"] == 400


class TestUpdateHandler:
    def test_update_creates_attestation_at_event_path(self):
        ctx = _make_ctx()
        _, h1 = _make_signer(421)
        _, h2 = _make_signer(422)
        q_id = _bind_quorum(ctx.pathway, [h1], 1)

        ctx.handler.resource_targets = [_expected_update_path(q_id, [h1, h2], 2)]
        result = _run(quorum_handler(
            "system/quorum", "update",
            {"data": {
                "quorum_id": q_id, "new_signers": [h1, h2], "new_threshold": 2,
            }},
            ctx.handler,
        ))
        assert result["status"] == 200
        update_hash = result["result"]["data"]["update_hash"]
        full = ctx.pathway.entity_tree.normalize_uri(
            quorum_event_path(q_id, update_hash),
        )
        bound = ctx.pathway.entity_tree.get(full)
        assert bound == update_hash
        att = ctx.pathway.content_store.get(bound)
        assert att.data["properties"]["kind"] == KIND_QUORUM_UPDATE
        assert set(att.data["properties"]["new_signers"]) == {h1, h2}

    def test_update_unknown_quorum_returns_404(self):
        ctx = _make_ctx()
        _, h = _make_signer(431)
        result = _run(quorum_handler(
            "system/quorum", "update",
            {"data": {
                "quorum_id": b"\x00" + b"X" * 32,
                "new_signers": [h], "new_threshold": 1,
            }},
            ctx.handler,
        ))
        assert result["status"] == 404


class TestPublishHandler:
    def test_publish_initial_must_match_current_signer_set(self):
        ctx = _make_ctx()
        _, h1 = _make_signer(441)
        q_id = _bind_quorum(ctx.pathway, [h1], 1)

        # Mismatch: try to publish with a different signer.
        _, h2 = _make_signer(442)
        result = _run(quorum_handler(
            "system/quorum", "publish",
            {"data": {
                "quorum_id": q_id, "signers": [h2], "threshold": 1,
            }},
            ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "publish_mismatch"

    def test_publish_initial_ok_when_matches_current(self):
        ctx = _make_ctx()
        _, h1 = _make_signer(451)
        q_id = _bind_quorum(ctx.pathway, [h1], 1)

        ctx.handler.resource_targets = [_expected_publish_path(
            q_id, [h1], 1, published_handle=h1,
        )]
        result = _run(quorum_handler(
            "system/quorum", "publish",
            {"data": {
                "quorum_id": q_id, "signers": [h1], "threshold": 1,
                "published_handle": h1,
            }},
            ctx.handler,
        ))
        assert result["status"] == 200
        h = result["result"]["data"]["publish_hash"]
        att = ctx.pathway.content_store.get(h)
        assert att.data["properties"]["kind"] == KIND_QUORUM_PUBLISH
        assert att.data["properties"]["published_handle"] == h1

    def test_publish_supersede_uses_previous_signers(self):
        """Superseding publish doesn't validate against current state;
        it carries its own signers/threshold to be checked at accept
        time against the previous publish."""
        ctx = _make_ctx()
        _, h1 = _make_signer(461)
        _, h2 = _make_signer(462)
        q_id = _bind_quorum(ctx.pathway, [h1], 1)

        # Initial publish.
        ctx.handler.resource_targets = [_expected_publish_path(q_id, [h1], 1)]
        first = _run(quorum_handler(
            "system/quorum", "publish",
            {"data": {
                "quorum_id": q_id, "signers": [h1], "threshold": 1,
            }},
            ctx.handler,
        ))
        prev_hash = first["result"]["data"]["publish_hash"]

        # Supersede: the new publish carries the new (post-update)
        # signers; the structural rule allows it because there's a
        # supersedes pointer.
        ctx.handler.resource_targets = [_expected_publish_path(
            q_id, [h1, h2], 2, supersedes=prev_hash,
        )]
        second = _run(quorum_handler(
            "system/quorum", "publish",
            {"data": {
                "quorum_id": q_id, "signers": [h1, h2], "threshold": 2,
                "supersedes": prev_hash,
            }},
            ctx.handler,
        ))
        assert second["status"] == 200


class TestVerifyHandler:
    def test_verify_returns_valid_with_signed_by(self):
        ctx = _make_ctx()
        kp1, h1 = _make_signer(471)
        kp2, h2 = _make_signer(472)
        _bind_identity(ctx.pathway, kp1)
        _bind_identity(ctx.pathway, kp2)
        q_id = _bind_quorum(ctx.pathway, [h1, h2], 2)

        target = b"\x00" + b"T" * 32
        _bind_signature(ctx.pathway, kp1, h1, target)
        _bind_signature(ctx.pathway, kp2, h2, target)

        result = _run(quorum_handler(
            "system/quorum", "verify",
            {"data": {"entity_hash": target, "quorum_id": q_id}},
            ctx.handler,
        ))
        assert result["status"] == 200
        assert result["result"]["data"]["valid"] is True
        assert set(result["result"]["data"]["signed_by"]) == {h1, h2}

    def test_verify_unknown_quorum_returns_404(self):
        ctx = _make_ctx()
        result = _run(quorum_handler(
            "system/quorum", "verify",
            {"data": {
                "entity_hash": b"\x00" + b"T" * 32,
                "quorum_id": b"\x00" + b"X" * 32,
            }},
            ctx.handler,
        ))
        assert result["status"] == 404

    def test_verify_resolver_unavailable_propagates(self):
        ctx = _make_ctx()
        _, h = _make_signer(481)
        q_id = _bind_quorum(
            ctx.pathway, [h], 1, signer_resolution="future-mode",
        )
        result = _run(quorum_handler(
            "system/quorum", "verify",
            {"data": {
                "entity_hash": b"\x00" + b"T" * 32, "quorum_id": q_id,
            }},
            ctx.handler,
        ))
        assert result["status"] == 400
        data = result["result"]["data"]
        assert data["code"] == "quorum_resolver_unavailable"
        assert data["mode_name"] == "future-mode"
        assert RESOLUTION_CONCRETE in data["available_modes"]


class TestUnsupportedOperation:
    def test_unsupported_op_returns_501(self):
        ctx = _make_ctx()
        result = _run(quorum_handler(
            "system/quorum", "weld", {}, ctx.handler,
        ))
        assert result["status"] == 501


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


class TestPathHelpers:
    def test_quorum_entity_path_uses_lowercase_hex(self):
        h = bytes(range(33))
        path = quorum_entity_path(h)
        assert path.startswith("system/quorum/")
        assert path == f"system/quorum/{h.hex()}"

    def test_quorum_event_path_segments(self):
        q = bytes(range(33))
        e = bytes(range(1, 34))
        path = quorum_event_path(q, e)
        assert path == f"system/quorum/{q.hex()}/event/{e.hex()}"

    def test_encode_hash_segment_is_lowercase_hex(self):
        h = bytes([0x00] + [0xAB] * 32)
        assert encode_hash_segment(h) == h.hex()
        assert encode_hash_segment(h).islower()
