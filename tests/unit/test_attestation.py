"""Tests for EXTENSION-ATTESTATION v1.0 substrate primitive.

Covers:
- TV-A1..A11 — default_find_authorizing test vectors (§5.1)
- TV-I1..I5 — index/lookup invariants (§5.7)
- Signature validation (§4.1, §4.2)
- Liveness composite check (§4.3)
- Graph walks (§5.1, §5.2, §5.3)
- Handler operations (§6)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
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
    attestation_handler,
    default_find_authorizing,
    find_attestations_by,
    find_attestations_targeting,
    find_attestations_with_kind,
    find_attestations_with_supersedes,
    find_live_head,
    find_revocations_for,
    is_attestation_live,
    make_attestation,
    make_peer_resolver,
    verify_attestation_signature,
    verify_specific_signer,
    walk_attesting_chain,
    walk_supersedes_chain,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@dataclass
class Ctx:
    keypair: Keypair
    pathway: EmitPathway
    handler: HandlerContext


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
        handler_pattern="system/attestation",
        keypair=keypair,
    )
    return Ctx(keypair=keypair, pathway=pathway, handler=handler)


def _bootstrap_emit(pathway: EmitPathway, path: str, entity: Entity) -> bytes:
    return pathway.emit(path, entity, EmitContext.bootstrap()).hash


def _bind_identity(pathway: EmitPathway, kp: Keypair) -> bytes:
    """Bind a peer's `system/identity` entity at a discoverable path so
    the resolver can find it for signature verification."""
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


def _att_path(hash_bytes: bytes) -> str:
    """Test-only storage path; substrate primitive doesn't mandate one."""
    return f"test/attestation/{hash_bytes.hex()}"


def _bind_attestation(
    pathway: EmitPathway, att: Entity, *, path: str | None = None,
) -> bytes:
    h = att.compute_hash()
    if path is None:
        path = _att_path(h)
    _bootstrap_emit(pathway, path, att)
    return h


def _signed_att(
    pathway: EmitPathway,
    signer_kp: Keypair,
    signer_hash: bytes,
    *,
    attested: bytes,
    properties: dict[str, Any] | None = None,
    supersedes: bytes | None = None,
    not_before: int | None = None,
    expires_at: int | None = None,
    bind_path: str | None = None,
) -> Entity:
    """Construct, bind, and sign an attestation."""
    att = make_attestation(
        attesting=signer_hash,
        attested=attested,
        properties=properties or {},
        supersedes=supersedes,
        not_before=not_before,
        expires_at=expires_at,
    )
    _bind_attestation(pathway, att, path=bind_path)
    _bind_signature(pathway, signer_kp, signer_hash, att.compute_hash())
    return att


# ---------------------------------------------------------------------------
# default_find_authorizing — TV-A1..A11
# ---------------------------------------------------------------------------


class TestDefaultFindAuthorizing:
    """Cross-impl test vectors per §5.1."""

    def test_tv_a1_single_live_attestation(self):
        """TV-A1: single live attestation at peer P → return it."""
        ctx = _make_ctx()
        signer_kp = Keypair.generate()
        signer_h = _bind_identity(ctx.pathway, signer_kp)
        peer_h = b"\x00" + b"P" * 32

        att = _signed_att(
            ctx.pathway, signer_kp, signer_h,
            attested=peer_h, properties={"kind": "x"},
        )

        result = default_find_authorizing(peer_h, ctx.handler)
        assert result is not None
        assert result.compute_hash() == att.compute_hash()

    def test_tv_a2_no_attestations(self):
        """TV-A2: no attestations targeting P → null."""
        ctx = _make_ctx()
        peer_h = b"\x00" + b"P" * 32
        assert default_find_authorizing(peer_h, ctx.handler) is None

    def test_tv_a3_three_distinct_chains_tiebreak_by_lowest_hash(self):
        """TV-A3: three live attestations targeting P, distinct chains
        → lowest content_hash wins."""
        ctx = _make_ctx()
        peer_h = b"\x00" + b"P" * 32

        atts: list[Entity] = []
        for i in range(3):
            kp = Keypair.from_seed(bytes([i + 1]) * 32)
            h = _bind_identity(ctx.pathway, kp)
            att = _signed_att(
                ctx.pathway, kp, h,
                attested=peer_h, properties={"kind": "x", "n": i},
            )
            atts.append(att)

        expected = min(atts, key=lambda a: a.compute_hash())
        result = default_find_authorizing(peer_h, ctx.handler)
        assert result is not None
        assert result.compute_hash() == expected.compute_hash()

    def test_tv_a4_supersedes_chain_returns_live_head(self):
        """TV-A4: A→A'→A'' all live, peer=A.attested → A'' (live head)."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x10" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"P" * 32

        a0 = _signed_att(
            ctx.pathway, kp, signer_h, attested=peer_h,
            properties={"kind": "x", "v": 0},
        )
        a1 = _signed_att(
            ctx.pathway, kp, signer_h, attested=peer_h,
            properties={"kind": "x", "v": 1}, supersedes=a0.compute_hash(),
        )
        a2 = _signed_att(
            ctx.pathway, kp, signer_h, attested=peer_h,
            properties={"kind": "x", "v": 2}, supersedes=a1.compute_hash(),
        )

        result = default_find_authorizing(peer_h, ctx.handler)
        assert result is not None
        assert result.compute_hash() == a2.compute_hash()

    def test_tv_a5_two_chains_compare_heads(self):
        """TV-A5: chain {A, A'} (A' supersedes A) and singleton {B}, both
        target P → tie-break by lowest content_hash on heads (A', B)."""
        ctx = _make_ctx()
        kp1 = Keypair.from_seed(b"\x21" * 32)
        kp2 = Keypair.from_seed(b"\x22" * 32)
        h1 = _bind_identity(ctx.pathway, kp1)
        h2 = _bind_identity(ctx.pathway, kp2)
        peer_h = b"\x00" + b"P" * 32

        a0 = _signed_att(
            ctx.pathway, kp1, h1, attested=peer_h,
            properties={"kind": "x", "v": 0},
        )
        a1 = _signed_att(
            ctx.pathway, kp1, h1, attested=peer_h,
            properties={"kind": "x", "v": 1}, supersedes=a0.compute_hash(),
        )
        b = _signed_att(
            ctx.pathway, kp2, h2, attested=peer_h,
            properties={"kind": "x"},
        )

        expected = min([a1, b], key=lambda e: e.compute_hash())
        result = default_find_authorizing(peer_h, ctx.handler)
        assert result is not None
        assert result.compute_hash() == expected.compute_hash()

    def test_tv_a6_expired_attestation_returns_null(self):
        """TV-A6: expired attestation is not live → null."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x30" * 32)
        h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"P" * 32

        _signed_att(
            ctx.pathway, kp, h, attested=peer_h,
            properties={"kind": "x"}, expires_at=1,  # very old
        )

        assert default_find_authorizing(peer_h, ctx.handler) is None

    def test_tv_a7_self_revoked_returns_null(self):
        """TV-A7: A targets P; self-revocation R targets A → null."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x40" * 32)
        h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"P" * 32

        a = _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"kind": "x"},
        )
        # Self-revocation: same `attesting`, attested=A's hash.
        _signed_att(
            ctx.pathway, kp, h,
            attested=a.compute_hash(),
            properties={"kind": KIND_REVOCATION},
        )

        assert default_find_authorizing(peer_h, ctx.handler) is None

    def test_tv_a8_invalid_signature_returned_substrate_is_sig_agnostic(self):
        """TV-A8 (revised v1.1 / SI-1): substrate stays sig-agnostic.

        A targets P; A's signature is invalid (raw tree:put bypassed
        :create validation) → returns A. Consumers layer signature
        validation per topology; identity_verify_cert rejects with
        invalid_signature at the topology-dispatch step (TV-I-A8)."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x50" * 32)
        h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"P" * 32

        # Build attestation but bind WITHOUT a valid signature.
        att = make_attestation(
            attesting=h, attested=peer_h, properties={"kind": "x"},
        )
        _bind_attestation(ctx.pathway, att)
        # Bind an INVALID signature (for a different target).
        wrong_target = bytes([0x00] + [0xFF] * 32)
        _bind_signature(ctx.pathway, kp, h, wrong_target)

        result = default_find_authorizing(peer_h, ctx.handler)
        assert result is not None
        assert result.compute_hash() == att.compute_hash()

    def test_tv_a9_as_of_before_not_before_returns_null(self):
        """TV-A9: as_of is before A's not_before — but default_find_authorizing
        doesn't take as_of; instead, set not_before in the future and verify
        is_attestation_live filters it out."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x60" * 32)
        h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"P" * 32

        future_ms = 10**18  # year ~33658
        _signed_att(
            ctx.pathway, kp, h, attested=peer_h,
            properties={"kind": "x"}, not_before=future_ms,
        )

        assert default_find_authorizing(peer_h, ctx.handler) is None

    def test_tv_a10_kind_agnostic_default(self):
        """TV-A10: A targets P with `properties.kind = "reputation"` —
        default behavior is kind-agnostic; returns A."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x70" * 32)
        h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"P" * 32

        att = _signed_att(
            ctx.pathway, kp, h, attested=peer_h,
            properties={"kind": "reputation"},
        )

        result = default_find_authorizing(peer_h, ctx.handler)
        assert result is not None
        assert result.compute_hash() == att.compute_hash()

    def test_tv_a11_multi_context_custom_find_authorizing(self):
        """TV-A11: peer P is target of two unrelated live attestations
        (different `attesting`, different `kind`). Default tie-break is
        by content_hash; a custom find_authorizing_fn filtering by
        `kind` returns the consumer-intended chain."""
        ctx = _make_ctx()
        kp_a = Keypair.from_seed(b"\xAA" * 32)
        kp_b = Keypair.from_seed(b"\xBB" * 32)
        ha = _bind_identity(ctx.pathway, kp_a)
        hb = _bind_identity(ctx.pathway, kp_b)
        peer_h = b"\x00" + b"P" * 32

        a1 = _signed_att(
            ctx.pathway, kp_a, ha, attested=peer_h,
            properties={"kind": "identity-cert", "function": "controller"},
        )
        b1 = _signed_att(
            ctx.pathway, kp_b, hb, attested=peer_h,
            properties={"kind": "identity-cert", "function": "agent"},
        )

        # Default behavior: deterministic tie-break.
        default = default_find_authorizing(peer_h, ctx.handler)
        assert default is not None
        assert default.compute_hash() in (a1.compute_hash(), b1.compute_hash())
        assert default.compute_hash() == min(
            a1.compute_hash(), b1.compute_hash(),
        )

        # Custom finder filters by `function` to return controller chain.
        def controller_only(attest_target: bytes, c: HandlerContext) -> Entity | None:
            for cand in find_attestations_targeting(
                attest_target, lambda _a, _c: True, c,
            ):
                props = cand.data.get("properties") or {}
                if props.get("function") != "controller":
                    continue
                if not is_attestation_live(cand, c):
                    continue
                if not verify_attestation_signature(cand, c):
                    continue
                return cand
            return None

        result = controller_only(peer_h, ctx.handler)
        assert result is not None
        assert result.compute_hash() == a1.compute_hash()


# ---------------------------------------------------------------------------
# Index invariants — TV-I1..I5
# ---------------------------------------------------------------------------


class TestIndexInvariants:
    """Cross-impl test vectors per §5.7."""

    def test_tv_i1_write_then_read(self):
        """TV-I1: create attestation A; immediately
        find_attestations_targeting(A.attested) returns A."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x01" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)
        target = b"\x00" + b"T" * 32

        att = make_attestation(
            attesting=signer_h, attested=target, properties={"kind": "x"},
        )
        _bind_attestation(ctx.pathway, att)

        results = find_attestations_targeting(
            target, lambda _a, _c: True, ctx.handler,
        )
        assert len(results) == 1
        assert results[0].compute_hash() == att.compute_hash()

    def test_tv_i2_failed_create_no_index_entry(self):
        """TV-I2: :create that fails validation MUST NOT appear in any
        index. Drive via the handler with bad params."""
        ctx = _make_ctx()
        # Missing attested triggers structural rejection.
        params = {"data": {"attesting": b"\x00" + b"A" * 32, "properties": {}}}
        result = asyncio.run(attestation_handler(
            "system/attestation", "create", params, ctx.handler,
        ))
        assert result["status"] == 400

        # No attestations should be visible.
        all_atts = find_attestations_targeting(
            b"\x00" + b"X" * 32, lambda _a, _c: True, ctx.handler,
        )
        assert all_atts == []

    def test_tv_i3_attesting_index(self):
        """TV-I3: two attestations with same attesting, different
        attested → find_attestations_by returns both."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x02" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)

        a = _signed_att(
            ctx.pathway, kp, signer_h,
            attested=b"\x00" + b"A" * 32, properties={"kind": "x"},
        )
        b = _signed_att(
            ctx.pathway, kp, signer_h,
            attested=b"\x00" + b"B" * 32, properties={"kind": "x"},
        )

        results = find_attestations_by(
            signer_h, lambda _a, _c: True, ctx.handler,
        )
        hashes = {r.compute_hash() for r in results}
        assert hashes == {a.compute_hash(), b.compute_hash()}

    def test_tv_i4_revoked_attestation_still_indexed(self):
        """TV-I4: revocation does NOT remove A from the index;
        is_attestation_live(A) returns false."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x03" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)
        target = b"\x00" + b"T" * 32

        a = _signed_att(
            ctx.pathway, kp, signer_h, attested=target, properties={"kind": "x"},
        )
        _signed_att(
            ctx.pathway, kp, signer_h,
            attested=a.compute_hash(),
            properties={"kind": KIND_REVOCATION},
        )

        # A still in the index.
        results = find_attestations_targeting(
            target, lambda _a, _c: True, ctx.handler,
        )
        assert any(r.compute_hash() == a.compute_hash() for r in results)
        # But not live.
        assert is_attestation_live(a, ctx.handler) is False

    def test_tv_i5_kind_index_excludes_missing_kind(self):
        """TV-I5: A,B with kind=foo; C with no kind →
        find_attestations_with_kind('foo') returns A,B not C."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x04" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)

        a = _signed_att(
            ctx.pathway, kp, signer_h,
            attested=b"\x00" + b"1" * 32, properties={"kind": "foo"},
        )
        b = _signed_att(
            ctx.pathway, kp, signer_h,
            attested=b"\x00" + b"2" * 32, properties={"kind": "foo"},
        )
        # C has properties but no `kind` key.
        c = make_attestation(
            attesting=signer_h, attested=b"\x00" + b"3" * 32,
            properties={"other": "value"},
        )
        _bind_attestation(ctx.pathway, c)
        _bind_signature(ctx.pathway, kp, signer_h, c.compute_hash())

        results = find_attestations_with_kind("foo", ctx.handler)
        hashes = {r.compute_hash() for r in results}
        assert hashes == {a.compute_hash(), b.compute_hash()}


# ---------------------------------------------------------------------------
# Signature validation (§4.1, §4.2)
# ---------------------------------------------------------------------------


class TestSignatureValidation:
    def test_verify_attestation_signature_default_signer(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x05" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)
        target = b"\x00" + b"T" * 32

        att = _signed_att(
            ctx.pathway, kp, signer_h, attested=target,
            properties={"kind": "x"},
        )
        assert verify_attestation_signature(att, ctx.handler) is True

    def test_verify_attestation_signature_no_sig(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x06" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)
        target = b"\x00" + b"T" * 32

        att = make_attestation(
            attesting=signer_h, attested=target, properties={"kind": "x"},
        )
        # Don't bind a signature.
        assert verify_attestation_signature(att, ctx.handler) is False

    def test_verify_specific_signer_pass_explicit_signer(self):
        """verify_specific_signer locates a sig from a particular signer
        — useful for dual-sig topologies where consumer composes calls."""
        ctx = _make_ctx()
        kp1 = Keypair.from_seed(b"\x07" * 32)
        kp2 = Keypair.from_seed(b"\x08" * 32)
        h1 = _bind_identity(ctx.pathway, kp1)
        h2 = _bind_identity(ctx.pathway, kp2)
        target = b"\x00" + b"T" * 32

        # Attestation `attesting=h1`, but ALSO carries a sig from h2.
        att = make_attestation(
            attesting=h1, attested=target, properties={"kind": "x"},
        )
        _bind_attestation(ctx.pathway, att)
        att_hash = att.compute_hash()
        _bind_signature(ctx.pathway, kp1, h1, att_hash)
        _bind_signature(ctx.pathway, kp2, h2, att_hash)

        assert verify_specific_signer(att, h1, ctx.handler) is True
        assert verify_specific_signer(att, h2, ctx.handler) is True
        # Unknown signer → false.
        unknown_h = b"\x00" + b"\xFF" * 32
        assert verify_specific_signer(att, unknown_h, ctx.handler) is False


# ---------------------------------------------------------------------------
# Liveness (§4.3)
# ---------------------------------------------------------------------------


class TestLiveness:
    def test_basic_live(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x09" * 32)
        h = _bind_identity(ctx.pathway, kp)
        att = _signed_att(
            ctx.pathway, kp, h, attested=b"\x00" + b"x" * 32,
            properties={"kind": "x"},
        )
        assert is_attestation_live(att, ctx.handler) is True

    def test_expired(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x0A" * 32)
        h = _bind_identity(ctx.pathway, kp)
        att = _signed_att(
            ctx.pathway, kp, h, attested=b"\x00" + b"x" * 32,
            properties={"kind": "x"}, expires_at=1,
        )
        assert is_attestation_live(att, ctx.handler) is False

    def test_not_yet_active(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x0B" * 32)
        h = _bind_identity(ctx.pathway, kp)
        future = 10**18
        att = _signed_att(
            ctx.pathway, kp, h, attested=b"\x00" + b"x" * 32,
            properties={"kind": "x"}, not_before=future,
        )
        assert is_attestation_live(att, ctx.handler) is False

    def test_as_of_time_travel(self):
        """as_of is propagated through the recursive supersession check."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x0C" * 32)
        h = _bind_identity(ctx.pathway, kp)
        # Window: not_before=1000, expires_at=2000.
        att = _signed_att(
            ctx.pathway, kp, h, attested=b"\x00" + b"x" * 32,
            properties={"kind": "x"}, not_before=1000, expires_at=2000,
        )
        assert is_attestation_live(att, ctx.handler, as_of=500) is False
        assert is_attestation_live(att, ctx.handler, as_of=1500) is True
        assert is_attestation_live(att, ctx.handler, as_of=2500) is False

    def test_superseded_by_live_successor(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x0D" * 32)
        h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"x" * 32

        a0 = _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"kind": "x"},
        )
        _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"kind": "x"},
            supersedes=a0.compute_hash(),
        )
        assert is_attestation_live(a0, ctx.handler) is False

    def test_superseded_by_dead_successor_still_live(self):
        """A successor whose own liveness is false (e.g., expired) does
        NOT supersede its predecessor (per recursive liveness)."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x0E" * 32)
        h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"x" * 32

        a0 = _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"kind": "x"},
        )
        # Successor is itself expired.
        _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"kind": "x"},
            supersedes=a0.compute_hash(), expires_at=1,
        )
        assert is_attestation_live(a0, ctx.handler) is True

    def test_self_revocation_only(self):
        """Authority-revocation is consumer-supplied; the primitive
        only respects revocations from the same `attesting`."""
        ctx = _make_ctx()
        kp_a = Keypair.from_seed(b"\x10" * 32)
        kp_b = Keypair.from_seed(b"\x11" * 32)
        ha = _bind_identity(ctx.pathway, kp_a)
        hb = _bind_identity(ctx.pathway, kp_b)
        peer_h = b"\x00" + b"x" * 32

        a = _signed_att(
            ctx.pathway, kp_a, ha, attested=peer_h, properties={"kind": "x"},
        )
        # Foreign revocation by kp_b — primitive ignores it.
        _signed_att(
            ctx.pathway, kp_b, hb, attested=a.compute_hash(),
            properties={"kind": KIND_REVOCATION},
        )
        assert is_attestation_live(a, ctx.handler) is True

        # Self-revocation by kp_a — kills A.
        _signed_att(
            ctx.pathway, kp_a, ha, attested=a.compute_hash(),
            properties={"kind": KIND_REVOCATION},
        )
        assert is_attestation_live(a, ctx.handler) is False


# ---------------------------------------------------------------------------
# Walks (§5.2, §5.3)
# ---------------------------------------------------------------------------


class TestWalks:
    def test_walk_supersedes_chain_back_to_origin(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x20" * 32)
        h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"P" * 32

        a0 = _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"v": 0},
        )
        a1 = _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"v": 1},
            supersedes=a0.compute_hash(),
        )
        a2 = _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"v": 2},
            supersedes=a1.compute_hash(),
        )

        chain = walk_supersedes_chain(a2, ctx.handler)
        assert [c.compute_hash() for c in chain] == [
            a2.compute_hash(), a1.compute_hash(), a0.compute_hash(),
        ]

    def test_find_live_head_walks_forward(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x21" * 32)
        h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"P" * 32

        a0 = _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"v": 0},
        )
        a1 = _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"v": 1},
            supersedes=a0.compute_hash(),
        )
        a2 = _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"v": 2},
            supersedes=a1.compute_hash(),
        )

        head = find_live_head(a0, ctx.handler)
        assert head is not None
        assert head.compute_hash() == a2.compute_hash()

    def test_walk_attesting_chain_with_terminate_predicate(self):
        """The chain link looks up the authorizing attestation for
        `current.attesting`. We seed a 2-level cert chain (root → mid →
        leaf) and walk back from the leaf until we reach the root."""
        ctx = _make_ctx()
        # Three keypairs.
        root_kp = Keypair.from_seed(b"\xC0" * 32)
        mid_kp = Keypair.from_seed(b"\xC1" * 32)
        leaf_kp = Keypair.from_seed(b"\xC2" * 32)
        root_h = _bind_identity(ctx.pathway, root_kp)
        mid_h = _bind_identity(ctx.pathway, mid_kp)
        leaf_h = _bind_identity(ctx.pathway, leaf_kp)

        # root certifies mid.
        cert_mid = _signed_att(
            ctx.pathway, root_kp, root_h, attested=mid_h,
            properties={"kind": "cert", "level": "mid"},
        )
        # mid certifies leaf.
        cert_leaf = _signed_att(
            ctx.pathway, mid_kp, mid_h, attested=leaf_h,
            properties={"kind": "cert", "level": "leaf"},
        )

        # Terminate when we hit a cert whose attesting equals root_h.
        def is_root(att: Entity, _c: HandlerContext) -> bool:
            return att.data.get("attesting") == root_h

        chain = walk_attesting_chain(cert_leaf, is_root, ctx.handler)
        assert chain is not None
        assert [c.compute_hash() for c in chain] == [
            cert_leaf.compute_hash(), cert_mid.compute_hash(),
        ]

    def test_walk_attesting_chain_max_depth_bounds_walk(self):
        ctx = _make_ctx()
        # Build a long chain that never terminates.
        kp = Keypair.from_seed(b"\xC3" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)

        # Each cert authorizes the previous signer (degenerate self-loop
        # avoided by alternating, but for max_depth we rely on the depth
        # bound; build a chain that asymptotically loops via an indirect
        # cycle).
        # Simpler: build a chain that doesn't terminate by always
        # re-authorizing the same signer with no parent.
        att = _signed_att(
            ctx.pathway, kp, signer_h, attested=signer_h,
            properties={"kind": "x"},
        )

        def never_terminate(_a: Entity, _c: HandlerContext) -> bool:
            return False

        # This walks but never terminates — should return None when
        # max_depth is exhausted (or when cycle detected).
        result = walk_attesting_chain(
            att, never_terminate, ctx.handler, max_depth=4,
        )
        assert result is None


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


class TestLookups:
    def test_find_revocations_for_only_revocation_kind(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x30" * 32)
        h = _bind_identity(ctx.pathway, kp)

        a = _signed_att(
            ctx.pathway, kp, h, attested=b"\x00" + b"P" * 32,
            properties={"kind": "x"},
        )
        rev = _signed_att(
            ctx.pathway, kp, h, attested=a.compute_hash(),
            properties={"kind": KIND_REVOCATION},
        )
        # Non-revocation also targeting A should NOT show up.
        _signed_att(
            ctx.pathway, kp, h, attested=a.compute_hash(),
            properties={"kind": "comment"},
        )

        results = find_revocations_for(a.compute_hash(), ctx.handler)
        assert [r.compute_hash() for r in results] == [rev.compute_hash()]

    def test_find_attestations_with_supersedes_inverse_lookup(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x31" * 32)
        h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"P" * 32

        a0 = _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"kind": "x"},
        )
        a1 = _signed_att(
            ctx.pathway, kp, h, attested=peer_h, properties={"kind": "x"},
            supersedes=a0.compute_hash(),
        )

        successors = find_attestations_with_supersedes(
            a0.compute_hash(), ctx.handler,
        )
        assert [s.compute_hash() for s in successors] == [a1.compute_hash()]


# ---------------------------------------------------------------------------
# Handler ops (§6)
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


class TestCreateHandler:
    def test_create_rejects_missing_resource_target(self):
        """Per SI-7/SI-22 (v1.1): :create without resource_targets MUST
        return path_required."""
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x40" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)

        params = {"data": {
            "attesting": signer_h,
            "attested": b"\x00" + b"P" * 32,
            "properties": {"kind": "x"},
        }}
        result = _run(attestation_handler(
            "system/attestation", "create", params, ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "path_required"

    def test_create_with_resource_target_binds_tree(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x41" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)
        path = "test/attestation/x"

        ctx.handler.resource_targets = [path]
        params = {"data": {
            "attesting": signer_h,
            "attested": b"\x00" + b"P" * 32,
            "properties": {"kind": "x"},
        }}
        result = _run(attestation_handler(
            "system/attestation", "create", params, ctx.handler,
        ))
        assert result["status"] == 200
        h = result["result"]["data"]["attestation_hash"]
        full = ctx.pathway.entity_tree.normalize_uri(path)
        assert ctx.pathway.entity_tree.get(full) == h

    def test_create_rejects_missing_attesting(self):
        ctx = _make_ctx()
        ctx.handler.resource_targets = ["test/attestation/x"]
        params = {"data": {
            "attested": b"\x00" + b"P" * 32,
            "properties": {"kind": "x"},
        }}
        result = _run(attestation_handler(
            "system/attestation", "create", params, ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_params"

    def test_create_rejects_non_dict_properties(self):
        ctx = _make_ctx()
        ctx.handler.resource_targets = ["test/attestation/x"]
        params = {"data": {
            "attesting": b"\x00" + b"A" * 32,
            "attested": b"\x00" + b"P" * 32,
            "properties": "not a map",
        }}
        result = _run(attestation_handler(
            "system/attestation", "create", params, ctx.handler,
        ))
        assert result["status"] == 400

    def test_create_supersedes_requires_existing_predecessor(self):
        ctx = _make_ctx()
        ctx.handler.resource_targets = ["test/attestation/x"]
        params = {"data": {
            "attesting": b"\x00" + b"A" * 32,
            "attested": b"\x00" + b"P" * 32,
            "properties": {"kind": "x"},
            "supersedes": b"\x00" + b"\xFF" * 32,  # not present
        }}
        result = _run(attestation_handler(
            "system/attestation", "create", params, ctx.handler,
        ))
        assert result["status"] == 400


class TestSupersedeHandler:
    def test_supersede_copies_attesting_and_attested(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x50" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)
        peer_h = b"\x00" + b"P" * 32
        original = _signed_att(
            ctx.pathway, kp, signer_h, attested=peer_h,
            properties={"kind": "x", "v": 0},
        )

        ctx.handler.resource_targets = ["test/attestation/v1"]
        params = {"data": {
            "previous_hash": original.compute_hash(),
            "properties": {"kind": "x", "v": 1},
        }}
        result = _run(attestation_handler(
            "system/attestation", "supersede", params, ctx.handler,
        ))
        assert result["status"] == 200
        h = result["result"]["data"]["attestation_hash"]
        new_att = ctx.pathway.content_store.get(h)
        assert new_att is not None
        assert new_att.data["attesting"] == signer_h
        assert new_att.data["attested"] == peer_h
        assert new_att.data["supersedes"] == original.compute_hash()
        assert new_att.data["properties"] == {"kind": "x", "v": 1}

    def test_supersede_unknown_previous_returns_404(self):
        ctx = _make_ctx()
        ctx.handler.resource_targets = ["test/attestation/x"]
        params = {"data": {
            "previous_hash": b"\x00" + b"\xFF" * 32,
            "properties": {"kind": "x"},
        }}
        result = _run(attestation_handler(
            "system/attestation", "supersede", params, ctx.handler,
        ))
        assert result["status"] == 404


class TestRevokeHandler:
    def test_revoke_creates_revocation_attestation(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x60" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)
        target = b"\x00" + b"T" * 32

        ctx.handler.resource_targets = ["test/attestation/rev"]
        params = {"data": {
            "attesting": signer_h,
            "target_hash": target,
            "reason": "key_compromise",
        }}
        result = _run(attestation_handler(
            "system/attestation", "revoke", params, ctx.handler,
        ))
        assert result["status"] == 200
        h = result["result"]["data"]["attestation_hash"]
        rev = ctx.pathway.content_store.get(h)
        assert rev is not None
        assert rev.data["properties"]["kind"] == KIND_REVOCATION
        assert rev.data["properties"]["reason"] == "key_compromise"
        assert rev.data["attested"] == target


class TestVerifyHandler:
    def test_verify_signed_and_live(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x70" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)
        att = _signed_att(
            ctx.pathway, kp, signer_h, attested=b"\x00" + b"P" * 32,
            properties={"kind": "x"},
        )
        params = {"data": {"attestation_hash": att.compute_hash()}}
        result = _run(attestation_handler(
            "system/attestation", "verify", params, ctx.handler,
        ))
        assert result["status"] == 200
        assert result["result"]["data"]["valid"] is True

    def test_verify_unsigned_reports_invalid(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x71" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)
        att = make_attestation(
            attesting=signer_h, attested=b"\x00" + b"P" * 32,
            properties={"kind": "x"},
        )
        _bind_attestation(ctx.pathway, att)  # no signature bound

        params = {"data": {"attestation_hash": att.compute_hash()}}
        result = _run(attestation_handler(
            "system/attestation", "verify", params, ctx.handler,
        ))
        assert result["status"] == 200
        assert result["result"]["data"]["valid"] is False
        assert result["result"]["data"]["reason"] == "invalid_signature"

    def test_verify_expired_reports_not_live(self):
        ctx = _make_ctx()
        kp = Keypair.from_seed(b"\x72" * 32)
        signer_h = _bind_identity(ctx.pathway, kp)
        att = _signed_att(
            ctx.pathway, kp, signer_h, attested=b"\x00" + b"P" * 32,
            properties={"kind": "x"}, expires_at=1,
        )
        params = {"data": {"attestation_hash": att.compute_hash()}}
        result = _run(attestation_handler(
            "system/attestation", "verify", params, ctx.handler,
        ))
        assert result["status"] == 200
        assert result["result"]["data"]["valid"] is False
        assert result["result"]["data"]["reason"] == "not_live"

    def test_verify_unknown_attestation_returns_404(self):
        ctx = _make_ctx()
        params = {"data": {"attestation_hash": b"\x00" + b"\xFF" * 32}}
        result = _run(attestation_handler(
            "system/attestation", "verify", params, ctx.handler,
        ))
        assert result["status"] == 404


class TestUnsupportedOperation:
    def test_unsupported_op_returns_501(self):
        ctx = _make_ctx()
        result = _run(attestation_handler(
            "system/attestation", "weld", {}, ctx.handler,
        ))
        assert result["status"] == 501


# ---------------------------------------------------------------------------
# make_peer_resolver smoke
# ---------------------------------------------------------------------------


def test_identity_resolver_finds_bound_identity():
    ctx = _make_ctx()
    kp = Keypair.from_seed(b"\x80" * 32)
    h = _bind_identity(ctx.pathway, kp)
    resolver = make_peer_resolver(ctx.handler)
    data = resolver(h)
    assert data is not None
    # v7.65 §2: system/peer data carries (public_key, key_type) only; the wire
    # peer_id is a presentation handle derived from public_key.
    assert data.get("public_key") == kp.public_key_bytes()
    assert resolver(b"\x00" + b"\xFF" * 32) is None
