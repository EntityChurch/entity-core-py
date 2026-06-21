"""K-of-N multi-signature root capability tests.

Covers PROPOSAL-MULTISIG-CORE-PRIMITIVE.md §12 vectors (1–23) plus the
spec's content-validation, wire-encoding, and attenuation surfaces.

The tests use real Ed25519 keypairs end-to-end so the verifier exercises
the actual cryptographic path — no mocked signature checks. Wire-encoding
tests round-trip through `cbor2` to confirm bstr-vs-map kinded
discrimination and that CBOR tags on data fields are rejected.
"""

from __future__ import annotations

from typing import Any

import cbor2
import pytest

from entity_core.capability.delegation import (
    ChainCollectStatus,
    check_creator_authority,
    find_signature_by_signer as find_sig_by_signer_helper,
    verify_capability_chain,
)
from entity_core.capability.token import (
    CapabilityToken,
    Grant,
    MULTI_GRANTER_N_CEILING,
    MultiGranter,
    get_multi_granter,
    is_multi_granter,
    multi_sig_root_path,
    validate_multi_granter,
)
from entity_core.crypto.identity import Keypair
from entity_core.protocol.auth import (
    create_identity_entity,
    create_signature_entity,
)
from entity_core.utils.ecf import ALG_ECFV1_SHA256, ecf_decode, ecf_encode


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_peer(seed: bytes) -> tuple[Keypair, dict[str, Any], bytes]:
    """Generate a deterministic keypair, identity entity, and identity hash."""
    keypair = Keypair.from_seed(seed)
    identity = create_identity_entity(keypair).to_dict(include_hash=True)
    return keypair, identity, identity["content_hash"]


def _seeded(label: bytes) -> bytes:
    """Pad/truncate a label into a 32-byte seed (for deterministic test peers)."""
    if len(label) >= 32:
        return label[:32]
    return label + b"\x00" * (32 - len(label))


def _multi_sig_root_cap(
    signers: list[bytes],
    threshold: int,
    grantee: bytes,
    *,
    grants: list[Grant] | None = None,
    expires_at: int | None = None,
    created_at: int = 1_700_000_000_000,
) -> dict[str, Any]:
    """Build a multi-sig root cap entity dict (with content_hash)."""
    token = CapabilityToken(
        grants=grants or [Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
        granter=MultiGranter(signers=signers, threshold=threshold),
        grantee=grantee,
        created_at=created_at,
        expires_at=expires_at,
    )
    return _entity_to_wire_dict(token.to_entity())


def _entity_to_wire_dict(entity: dict[str, Any]) -> dict[str, Any]:
    """Compute and attach content_hash to an entity dict (mirrors Entity.to_dict)."""
    from entity_core.utils.ecf import compute_ecf_hash

    cap_hash = compute_ecf_hash({"type": entity["type"], "data": entity["data"]})
    out = dict(entity)
    out["content_hash"] = cap_hash
    return out


def _sign_cap_by(
    cap_hash: bytes,
    signer_keypair: Keypair,
    signer_identity_hash: bytes,
) -> dict[str, Any]:
    """Produce a signature entity (dict) from a keypair signing the cap hash."""
    sig = create_signature_entity(signer_keypair, cap_hash, signer_identity_hash)
    return sig.to_dict(include_hash=True)


def _included_map(
    *entities: dict[str, Any],
) -> dict[bytes, dict[str, Any]]:
    """Index a set of entity dicts by content_hash (envelope `included` shape)."""
    return {e["content_hash"]: e for e in entities}


def _make_finders(included: dict[bytes, dict[str, Any]]):
    """Return (lookup, find_signature, find_signature_by_signer) callbacks."""

    def lookup(h: bytes) -> dict[str, Any] | None:
        return included.get(h)

    def find_signature(target_hash: bytes) -> dict[str, Any] | None:
        for entity in included.values():
            if entity.get("type") != "system/signature":
                continue
            data = entity.get("data", {})
            if data.get("target") == target_hash:
                return entity
        return None

    def find_signature_by_signer(
        target_hash: bytes, signer_hash: bytes,
    ) -> dict[str, Any] | None:
        return find_sig_by_signer_helper(target_hash, signer_hash, included)

    return lookup, find_signature, find_signature_by_signer


# ---------------------------------------------------------------------------
# Vector 1 — single-sig regression
# ---------------------------------------------------------------------------


class TestSingleSigRegression:
    """Vector 1: existing single-sig caps verify identically to today."""

    def test_single_sig_root_still_verifies(self):
        kp_alice, alice_id, alice_hash = _make_peer(_seeded(b"alice"))
        kp_bob, bob_id, bob_hash = _make_peer(_seeded(b"bob"))

        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
            granter=alice_hash,  # single-sig
            grantee=bob_hash,
            created_at=1,
        )
        cap = _entity_to_wire_dict(token.to_entity())
        sig = _sign_cap_by(cap["content_hash"], kp_alice, alice_hash)

        included = _included_map(cap, alice_id, bob_id, sig)
        lookup, find_sig, find_sig_by = _make_finders(included)

        result = verify_capability_chain(
            cap, lookup, find_sig, kp_alice.peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert result.valid, result.error


class TestPR3UnresolvableGrantee:
    """TV-CAP-ZERO-GRANTEE (V7 v7.39 §3.6 PR-3): caps whose `grantee`
    does not resolve to a `system/identity` entity MUST be rejected
    with `unresolvable_grantee`. Closes the bearer-cap surface SEC-18
    surfaced (zero-hash grantee accepted silently)."""

    def test_zero_hash_grantee_rejected(self):
        kp_alice, alice_id, alice_hash = _make_peer(_seeded(b"alice"))
        zero_hash = bytes([0x00]) + b"\x00" * 32  # ECFv1-SHA256 prefix + 32 zero bytes

        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
            granter=alice_hash,
            grantee=zero_hash,  # bearer cap — no real recipient
            created_at=1,
        )
        cap = _entity_to_wire_dict(token.to_entity())
        sig = _sign_cap_by(cap["content_hash"], kp_alice, alice_hash)

        included = _included_map(cap, alice_id, sig)  # no entity at zero_hash
        lookup, find_sig, find_sig_by = _make_finders(included)

        result = verify_capability_chain(
            cap, lookup, find_sig, kp_alice.peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid
        assert result.error_code == "unresolvable_grantee", result

    def test_grantee_present_in_included_passes(self):
        """Symmetric to granter resolution: an identity present only in
        the wire envelope's `included` (not in any local store) is
        sufficient. Cross-impl handoff §4.2 informative note."""
        kp_alice, alice_id, alice_hash = _make_peer(_seeded(b"alice"))
        kp_bob, bob_id, bob_hash = _make_peer(_seeded(b"bob"))

        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
            granter=alice_hash,
            grantee=bob_hash,
            created_at=1,
        )
        cap = _entity_to_wire_dict(token.to_entity())
        sig = _sign_cap_by(cap["content_hash"], kp_alice, alice_hash)

        # bob_id is in `included` — emulates wire envelope only.
        included = _included_map(cap, alice_id, bob_id, sig)
        lookup, find_sig, find_sig_by = _make_finders(included)

        result = verify_capability_chain(
            cap, lookup, find_sig, kp_alice.peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert result.valid, result.error

    def test_self_cap_grantee_resolves_via_granter(self):
        """Self-cap (grantee == granter): resolves naturally because the
        granter's identity is already required to be present per §5.5
        granter resolution."""
        kp_alice, alice_id, alice_hash = _make_peer(_seeded(b"alice"))
        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
            granter=alice_hash,
            grantee=alice_hash,  # self-cap
            created_at=1,
        )
        cap = _entity_to_wire_dict(token.to_entity())
        sig = _sign_cap_by(cap["content_hash"], kp_alice, alice_hash)
        included = _included_map(cap, alice_id, sig)
        lookup, find_sig, find_sig_by = _make_finders(included)
        result = verify_capability_chain(
            cap, lookup, find_sig, kp_alice.peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert result.valid, result.error


# ---------------------------------------------------------------------------
# Vectors 2–4, 13, 14 — Site 1 multi-sig signature counting
# ---------------------------------------------------------------------------


class TestSite1ThresholdCounting:
    """Vectors 2, 3, 4, 13, 14: K-of-N signature acceptance/denial."""

    def _setup_2of3(self, signed_by: list[str], local: str = "alice"):
        peers = {
            name: _make_peer(_seeded(name.encode()))
            for name in ("alice", "bob", "carol", "dave")
        }
        signer_hashes = [peers["alice"][2], peers["bob"][2], peers["carol"][2]]
        cap = _multi_sig_root_cap(
            signers=signer_hashes, threshold=2, grantee=peers["dave"][2],
        )
        sigs = [
            _sign_cap_by(cap["content_hash"], peers[name][0], peers[name][2])
            for name in signed_by
        ]
        included = _included_map(
            cap,
            peers["alice"][1], peers["bob"][1], peers["carol"][1], peers["dave"][1],
            *sigs,
        )
        lookup, find_sig, find_sig_by = _make_finders(included)
        return cap, lookup, find_sig, find_sig_by, peers[local][0].peer_id

    def test_vector2_2of3_local_signed(self):
        """2-of-3 with 2 valid sigs; local peer is one of the signers."""
        cap, lookup, find_sig, find_sig_by, local_pid = self._setup_2of3(
            signed_by=["alice", "bob"]
        )
        result = verify_capability_chain(
            cap, lookup, find_sig, local_pid,
            find_signature_by_signer=find_sig_by,
        )
        assert result.valid, result.error

    def test_vector3_below_threshold_denied(self):
        """2-of-3 with only 1 valid sig → DENY."""
        cap, lookup, find_sig, find_sig_by, local_pid = self._setup_2of3(
            signed_by=["alice"]
        )
        result = verify_capability_chain(
            cap, lookup, find_sig, local_pid,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid
        assert "threshold" in result.error.lower()

    def test_vector4_above_threshold_short_circuits(self):
        """2-of-3 with all 3 sigs → ALLOW; verifier only needs K=2."""
        cap, lookup, find_sig, find_sig_by, local_pid = self._setup_2of3(
            signed_by=["alice", "bob", "carol"]
        )
        result = verify_capability_chain(
            cap, lookup, find_sig, local_pid,
            find_signature_by_signer=find_sig_by,
        )
        assert result.valid

    def test_vector13_local_is_one_of_threshold_signers(self):
        """K=2 signed including local peer → ALLOW (covered by vector 2; explicit reaffirm)."""
        # Local is alice; signed are bob+alice (alice last to confirm order doesn't matter).
        cap, lookup, find_sig, find_sig_by, local_pid = self._setup_2of3(
            signed_by=["bob", "alice"]
        )
        result = verify_capability_chain(
            cap, lookup, find_sig, local_pid,
            find_signature_by_signer=find_sig_by,
        )
        assert result.valid

    def test_vector14_k_equals_n_3of3(self):
        """K=N (3-of-3) all sigs present → ALLOW."""
        peers = {
            name: _make_peer(_seeded(name.encode()))
            for name in ("alice", "bob", "carol", "dave")
        }
        signer_hashes = [peers["alice"][2], peers["bob"][2], peers["carol"][2]]
        cap = _multi_sig_root_cap(
            signers=signer_hashes, threshold=3, grantee=peers["dave"][2],
        )
        sigs = [
            _sign_cap_by(cap["content_hash"], peers[n][0], peers[n][2])
            for n in ("alice", "bob", "carol")
        ]
        included = _included_map(
            cap,
            peers["alice"][1], peers["bob"][1], peers["carol"][1], peers["dave"][1],
            *sigs,
        )
        lookup, find_sig, find_sig_by = _make_finders(included)
        result = verify_capability_chain(
            cap, lookup, find_sig, peers["alice"][0].peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert result.valid


# ---------------------------------------------------------------------------
# Vectors 5–10 — M3 content validation at chain-walk entry
# ---------------------------------------------------------------------------


class TestM3ContentValidation:
    """Vectors 5–10: malformed multi-sig caps fail at chain-walk entry."""

    def test_vector5_parent_non_null_denied(self):
        """Multi-sig with non-null parent → DENY."""
        peers = {n: _make_peer(_seeded(n.encode())) for n in ("a", "b", "c", "d")}
        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
            granter=MultiGranter(
                signers=[peers["a"][2], peers["b"][2], peers["c"][2]], threshold=2,
            ),
            grantee=peers["d"][2],
            created_at=1,
            parent=b"\x00" * 33,  # M3 violation
        )
        cap = _entity_to_wire_dict(token.to_entity())
        # Even with a complete signature set, M3 fires before sig checks.
        sigs = [
            _sign_cap_by(cap["content_hash"], peers[n][0], peers[n][2])
            for n in ("a", "b")
        ]
        included = _included_map(
            cap, peers["a"][1], peers["b"][1], peers["c"][1], peers["d"][1], *sigs,
        )
        # The parent points to nothing — the chain walker will report
        # UNREACHABLE before M3 ever runs. The semantic outcome is the same
        # (DENY); we assert the cap doesn't verify, not the specific error.
        lookup, find_sig, find_sig_by = _make_finders(included)
        result = verify_capability_chain(
            cap, lookup, find_sig, peers["a"][0].peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid

    def test_vector5b_parent_non_null_with_resolvable_parent(self):
        """Multi-sig pointing to a resolvable parent → DENY at M3 (root-only)."""
        peers = {n: _make_peer(_seeded(n.encode())) for n in ("a", "b", "c", "d")}
        # Parent: a normal single-sig cap rooted at peer 'd'.
        parent_token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
            granter=peers["d"][2],
            grantee=peers["a"][2],
            created_at=1,
        )
        parent = _entity_to_wire_dict(parent_token.to_entity())

        # Child: multi-sig but with a non-null parent — illegal.
        child_token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
            granter=MultiGranter(
                signers=[peers["a"][2], peers["b"][2], peers["c"][2]], threshold=2,
            ),
            grantee=peers["d"][2],
            created_at=2,
            parent=parent["content_hash"],
        )
        child = _entity_to_wire_dict(child_token.to_entity())
        included = _included_map(
            child, parent,
            peers["a"][1], peers["b"][1], peers["c"][1], peers["d"][1],
        )
        lookup, find_sig, find_sig_by = _make_finders(included)
        result = verify_capability_chain(
            child, lookup, find_sig, peers["a"][0].peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid
        assert "root" in result.error.lower() or "parent" in result.error.lower()

    def test_vector6_threshold_1_invalid(self):
        """K=1 invalid (use single-sig form)."""
        ok, err = validate_multi_granter(
            MultiGranter(signers=[b"\x00" * 33, b"\x01" * 33], threshold=1),
        )
        assert not ok
        assert "threshold" in err

    def test_vector7_threshold_0_invalid(self):
        ok, err = validate_multi_granter(
            MultiGranter(signers=[b"\x00" * 33, b"\x01" * 33], threshold=0),
        )
        assert not ok

    def test_vector8_threshold_exceeds_n(self):
        ok, err = validate_multi_granter(
            MultiGranter(signers=[b"\x00" * 33, b"\x01" * 33], threshold=3),
        )
        assert not ok
        assert "exceeds" in err.lower() or "threshold" in err.lower()

    def test_vector9_duplicate_signers(self):
        ok, err = validate_multi_granter(
            MultiGranter(
                signers=[b"\x00" * 33, b"\x01" * 33, b"\x00" * 33], threshold=2,
            ),
        )
        assert not ok
        assert "duplicate" in err.lower()

    def test_vector10_n_equals_1(self):
        ok, err = validate_multi_granter(
            MultiGranter(signers=[b"\x00" * 33], threshold=1),
        )
        assert not ok
        assert "n" in err.lower() or ">= 2" in err.lower()

    def test_n_ceiling(self):
        """N > 32 rejected by default (M9)."""
        signers = [bytes([ALG_ECFV1_SHA256, i]) + b"\x00" * 31 for i in range(33)]
        ok, err = validate_multi_granter(MultiGranter(signers=signers, threshold=2))
        assert not ok
        assert "ceiling" in err.lower() or "32" in err
        # MAY accept if ceiling override.
        ok2, _ = validate_multi_granter(
            MultiGranter(signers=signers, threshold=2),
            enforce_n_ceiling=False,
        )
        assert ok2

    def test_n_ceiling_constant_is_32(self):
        assert MULTI_GRANTER_N_CEILING == 32


# ---------------------------------------------------------------------------
# Vectors 11, 12, 22, 23 — M6 root trust (Site 3)
# ---------------------------------------------------------------------------


class TestM6RootTrust:
    """Vectors 11, 12, 22, 23: local peer must be in signers AND have signed."""

    def _build(self, local: str, signers: list[str], signed_by: list[str]):
        peers = {n: _make_peer(_seeded(n.encode())) for n in (*signers, "dave", local, "outside")}
        signer_hashes = [peers[n][2] for n in signers]
        cap = _multi_sig_root_cap(
            signers=signer_hashes, threshold=2, grantee=peers["dave"][2],
        )
        sigs = [
            _sign_cap_by(cap["content_hash"], peers[n][0], peers[n][2])
            for n in signed_by
        ]
        included = _included_map(
            cap,
            *(peers[n][1] for n in (*signers, "dave", local, "outside")),
            *sigs,
        )
        lookup, find_sig, find_sig_by = _make_finders(included)
        return cap, lookup, find_sig, find_sig_by, peers[local][0].peer_id

    def test_vector11_local_not_in_signers(self):
        """Local peer NOT in signer set → DENY at Site 3."""
        cap, lookup, find_sig, find_sig_by, local_pid = self._build(
            local="outside", signers=["alice", "bob", "carol"], signed_by=["alice", "bob"],
        )
        result = verify_capability_chain(
            cap, lookup, find_sig, local_pid,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid
        assert "local" in result.error.lower() or "root" in result.error.lower()

    def test_vector12_local_in_signers_but_didnt_sign(self):
        """Local in signers but didn't sign → DENY at Site 3."""
        # Signers include alice but only bob+carol signed; local is alice.
        cap, lookup, find_sig, find_sig_by, local_pid = self._build(
            local="alice", signers=["alice", "bob", "carol"], signed_by=["bob", "carol"],
        )
        result = verify_capability_chain(
            cap, lookup, find_sig, local_pid,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid

    def test_vector22_connection_time_receiver_signed(self):
        """Connection-time semantics: receiver in signers + signed → ALLOW."""
        # Connection-time delivery is operationally identical to any other
        # multi-sig delivery from the verifier's perspective.
        cap, lookup, find_sig, find_sig_by, local_pid = self._build(
            local="alice", signers=["alice", "bob", "carol"], signed_by=["alice", "bob"],
        )
        result = verify_capability_chain(
            cap, lookup, find_sig, local_pid,
            find_signature_by_signer=find_sig_by,
        )
        assert result.valid

    def test_vector23_connection_time_receiver_not_signed(self):
        """Connection-time: receiver in signers but didn't sign → DENY."""
        cap, lookup, find_sig, find_sig_by, local_pid = self._build(
            local="alice", signers=["alice", "bob", "carol"], signed_by=["bob", "carol"],
        )
        result = verify_capability_chain(
            cap, lookup, find_sig, local_pid,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid


# ---------------------------------------------------------------------------
# Vectors 15–17 — M7 strict-with-signature in check_creator_authority
# ---------------------------------------------------------------------------


class TestM7StrictWithSignature:
    """Vectors 15, 16, 17: writer in single-sig granter / multi-sig signers + signed."""

    def test_vector15_single_sig_writer_match(self):
        kp_alice, alice_id, alice_hash = _make_peer(_seeded(b"alice"))
        kp_bob, bob_id, bob_hash = _make_peer(_seeded(b"bob"))
        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
            granter=alice_hash,
            grantee=bob_hash,
            created_at=1,
        )
        cap = _entity_to_wire_dict(token.to_entity())
        result = check_creator_authority(cap, alice_hash, lambda h: None)
        assert result.found
        assert result.status == ChainCollectStatus.OK

    def test_vector16_multi_sig_writer_in_signers_and_signed(self):
        kp_alice, alice_id, alice_hash = _make_peer(_seeded(b"alice"))
        kp_bob, bob_id, bob_hash = _make_peer(_seeded(b"bob"))
        kp_carol, carol_id, carol_hash = _make_peer(_seeded(b"carol"))
        kp_dave, dave_id, dave_hash = _make_peer(_seeded(b"dave"))

        cap = _multi_sig_root_cap(
            signers=[alice_hash, bob_hash, carol_hash], threshold=2,
            grantee=dave_hash,
        )
        sig_alice = _sign_cap_by(cap["content_hash"], kp_alice, alice_hash)
        sig_bob = _sign_cap_by(cap["content_hash"], kp_bob, bob_hash)
        included = _included_map(cap, alice_id, bob_id, carol_id, dave_id, sig_alice, sig_bob)
        lookup, _find_sig, find_sig_by = _make_finders(included)

        result = check_creator_authority(
            cap, alice_hash, lookup,
            find_signature_by_signer=find_sig_by,
            identity_lookup=lookup,
        )
        assert result.found

    def test_vector17_multi_sig_writer_in_signers_but_didnt_sign(self):
        """Writer is in signers but never signed → not found (strict-with-signature)."""
        kp_alice, alice_id, alice_hash = _make_peer(_seeded(b"alice"))
        kp_bob, bob_id, bob_hash = _make_peer(_seeded(b"bob"))
        kp_carol, carol_id, carol_hash = _make_peer(_seeded(b"carol"))
        kp_dave, dave_id, dave_hash = _make_peer(_seeded(b"dave"))

        cap = _multi_sig_root_cap(
            signers=[alice_hash, bob_hash, carol_hash], threshold=2,
            grantee=dave_hash,
        )
        # carol didn't sign; bob + alice signed.
        sig_alice = _sign_cap_by(cap["content_hash"], kp_alice, alice_hash)
        sig_bob = _sign_cap_by(cap["content_hash"], kp_bob, bob_hash)
        included = _included_map(cap, alice_id, bob_id, carol_id, dave_id, sig_alice, sig_bob)
        lookup, _find_sig, find_sig_by = _make_finders(included)

        result = check_creator_authority(
            cap, carol_hash, lookup,
            find_signature_by_signer=find_sig_by,
            identity_lookup=lookup,
        )
        # carol is in signers but didn't sign → strict-with-signature → not found.
        assert not result.found

    def test_no_finder_skips_multisig_links(self):
        """When no by-signer finder is provided, multi-sig links don't match."""
        kp_alice, alice_id, alice_hash = _make_peer(_seeded(b"alice"))
        kp_bob, bob_id, bob_hash = _make_peer(_seeded(b"bob"))
        cap = _multi_sig_root_cap(
            signers=[alice_hash, bob_hash], threshold=2, grantee=alice_hash,
        )
        result = check_creator_authority(cap, alice_hash, lambda h: None)
        # Without a finder, multi-sig granters are skipped → not found.
        assert not result.found


# ---------------------------------------------------------------------------
# Vector 18 — Wire encoding (CBOR major-type discrimination, no tags)
# ---------------------------------------------------------------------------


class TestM8WireEncoding:
    """Vectors 18a/b/c: bstr → single-sig, map → multi-sig, tag → reject."""

    def test_vector18a_bstr_decoded_as_single_sig(self):
        granter = bytes([ALG_ECFV1_SHA256]) + b"alice_" + b"\x00" * 26
        encoded = ecf_encode({"granter": granter})
        # Major type byte: top 3 bits encode major type. bstr = 2 → top byte
        # in [0x40, 0x57] (or starts a longer header). Since we wrap in a
        # map, peek inside.
        decoded = ecf_decode(encoded)
        assert isinstance(decoded["granter"], bytes)
        assert not is_multi_granter(decoded["granter"])
        assert get_multi_granter(decoded["granter"]) is None

    def test_vector18b_map_decoded_as_multi_sig(self):
        signers = [
            bytes([ALG_ECFV1_SHA256]) + b"a" + b"\x00" * 31,
            bytes([ALG_ECFV1_SHA256]) + b"b" + b"\x00" * 31,
        ]
        encoded = ecf_encode({"granter": {"signers": signers, "threshold": 2}})
        decoded = ecf_decode(encoded)
        assert isinstance(decoded["granter"], dict)
        assert is_multi_granter(decoded["granter"])
        multi = get_multi_granter(decoded["granter"])
        assert multi is not None
        assert multi.threshold == 2
        assert multi.signers == signers

    def test_vector18c_cbor_tag_on_data_field_rejected(self):
        """CBOR tags on data fields are forbidden (ENTITY-CBOR-ENCODING §11).

        We don't emit tags; if a peer sent us one inside a granter we'd
        decode it as a non-bytes / non-dict value, which neither the
        single-sig (`isinstance(_, bytes)`) nor the multi-sig
        (`is_multi_granter`) path accepts.
        """
        # cbor2 represents tags as CBORTag objects after decode; encoding via
        # cbor2.dumps with a CBORTag value produces a tagged value on the wire.
        from cbor2 import CBORTag

        tagged = CBORTag(42, b"\x00" * 33)
        encoded = ecf_encode({"granter": tagged})
        decoded = ecf_decode(encoded)
        # A tag-wrapped granter is neither a hash bytes nor a multi-granter map.
        assert not isinstance(decoded["granter"], bytes)
        assert not is_multi_granter(decoded["granter"])

    def test_round_trip_through_to_entity_from_entity(self):
        """to_entity() + from_entity() preserves polymorphic granter shape."""
        signers = [
            bytes([ALG_ECFV1_SHA256]) + b"a" + b"\x00" * 31,
            bytes([ALG_ECFV1_SHA256]) + b"b" + b"\x00" * 31,
            bytes([ALG_ECFV1_SHA256]) + b"c" + b"\x00" * 31,
        ]
        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
            granter=MultiGranter(signers=signers, threshold=2),
            grantee=bytes([ALG_ECFV1_SHA256]) + b"d" + b"\x00" * 31,
            created_at=1,
        )
        entity = token.to_entity()
        # CBOR encode then decode to simulate wire round-trip.
        encoded = ecf_encode(entity["data"])
        decoded_data = ecf_decode(encoded)
        rebuilt = CapabilityToken.from_entity({"type": entity["type"], "data": decoded_data})
        assert isinstance(rebuilt.granter, MultiGranter)
        assert rebuilt.granter.threshold == 2
        assert rebuilt.granter.signers == signers


# ---------------------------------------------------------------------------
# Vector 19, 19b — M10 attenuation across depth (no threshold inheritance)
# ---------------------------------------------------------------------------


class TestM10AttenuationAcrossDepth:
    """Vectors 19 and 19b: multi-sig root + downstream single-sig links."""

    def test_vector19_root_plus_one_child(self):
        kp_alice, alice_id, alice_hash = _make_peer(_seeded(b"alice"))
        kp_bob, bob_id, bob_hash = _make_peer(_seeded(b"bob"))
        kp_carol, carol_id, carol_hash = _make_peer(_seeded(b"carol"))
        kp_dave, dave_id, dave_hash = _make_peer(_seeded(b"dave"))
        kp_eve, eve_id, eve_hash = _make_peer(_seeded(b"eve"))

        # Root: multi-sig 2-of-3, granted to alice. The grantee of a multi-sig
        # cap MUST be one of the signers (GUIDE-MULTISIG §7.2 / edge case "caps
        # issued to a peer not in the signers"): the cap only roots at a peer in
        # `signers`, so a non-signer grantee holds an unusable cap that cannot
        # delegate. alice is both a signer and the verifying (local) peer, so the
        # authority roots here and downstream §5.5a resource frames line up.
        root = _multi_sig_root_cap(
            signers=[alice_hash, bob_hash, carol_hash], threshold=2,
            grantee=alice_hash,
        )
        sig_a = _sign_cap_by(root["content_hash"], kp_alice, alice_hash)
        sig_b = _sign_cap_by(root["content_hash"], kp_bob, bob_hash)

        # Child: single-sig from alice (the multi-sig grantee) to eve, attenuated
        # to a resource subset — proves the K-of-N threshold does NOT inherit
        # (the child needs only alice's single signature). Bare `data/*`
        # canonicalizes against the granter alice (= local peer) to /alice/data/*,
        # a subset of the root's /alice/* (§5.5a per-granter canonicalization).
        # (Operations stay "*" because op-set uses exact subset, not pattern cover.)
        child_token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["data/*"], operations=["*"])],
            granter=alice_hash,
            grantee=eve_hash,
            created_at=2,
            parent=root["content_hash"],
        )
        child = _entity_to_wire_dict(child_token.to_entity())
        sig_child = _sign_cap_by(child["content_hash"], kp_alice, alice_hash)

        included = _included_map(
            root, child,
            alice_id, bob_id, carol_id, dave_id, eve_id,
            sig_a, sig_b, sig_child,
        )
        lookup, find_sig, find_sig_by = _make_finders(included)

        result = verify_capability_chain(
            child, lookup, find_sig, kp_alice.peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert result.valid, result.error

    def test_vector19b_root_plus_three_link_depth(self):
        peers = {n: _make_peer(_seeded(n.encode())) for n in
                 ("alice", "bob", "carol", "dave", "eve", "frank", "grace")}
        signer_hashes = [peers["alice"][2], peers["bob"][2], peers["carol"][2]]
        # Multi-sig grantee MUST be a signer (GUIDE-MULTISIG §7.2): grant to
        # alice, who is also the verifying (local) peer, so the chain roots here.
        alice_pid = peers["alice"][0].peer_id
        root = _multi_sig_root_cap(
            signers=signer_hashes, threshold=2, grantee=peers["alice"][2],
        )
        sig_a = _sign_cap_by(root["content_hash"], peers["alice"][0], peers["alice"][2])
        sig_b = _sign_cap_by(root["content_hash"], peers["bob"][0], peers["bob"][2])

        # alice → eve. Granter alice IS the local peer, so bare `data/*`
        # canonicalizes to /alice/data/* (§5.5a), a subset of the root's /alice/*.
        link1 = _entity_to_wire_dict(CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["data/*"], operations=["*"])],
            granter=peers["alice"][2], grantee=peers["eve"][2],
            created_at=2, parent=root["content_hash"],
        ).to_entity())
        sig_d = _sign_cap_by(link1["content_hash"], peers["alice"][0], peers["alice"][2])
        # eve → frank. eve is a FOREIGN granter, so a bare `data/*` here would
        # canonicalize to /eve/data/* and fail the subset check against the
        # parent's /alice/data/* (§5.5a / PR-8: cross-peer links must name the
        # namespace explicitly). Use the explicit absolute path, which is
        # frame-invariant and stays within alice's namespace.
        link2 = _entity_to_wire_dict(CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=[f"/{alice_pid}/data/*"], operations=["*"])],
            granter=peers["eve"][2], grantee=peers["frank"][2],
            created_at=3, parent=link1["content_hash"],
        ).to_entity())
        sig_e = _sign_cap_by(link2["content_hash"], peers["eve"][0], peers["eve"][2])
        # frank → grace. frank is also foreign — explicit absolute path again,
        # narrowed one segment deeper (/alice/data/specific/*).
        link3 = _entity_to_wire_dict(CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=[f"/{alice_pid}/data/specific/*"], operations=["*"])],
            granter=peers["frank"][2], grantee=peers["grace"][2],
            created_at=4, parent=link2["content_hash"],
        ).to_entity())
        sig_f = _sign_cap_by(link3["content_hash"], peers["frank"][0], peers["frank"][2])

        included = _included_map(
            root, link1, link2, link3,
            *(peers[n][1] for n in peers),
            sig_a, sig_b, sig_d, sig_e, sig_f,
        )
        lookup, find_sig, find_sig_by = _make_finders(included)
        result = verify_capability_chain(
            link3, lookup, find_sig, alice_pid,
            find_signature_by_signer=find_sig_by,
        )
        assert result.valid, result.error


# ---------------------------------------------------------------------------
# Vectors 20, 21 — M12 storage path
# ---------------------------------------------------------------------------


class TestM12StoragePath:
    """Vectors 20, 21: multi-sig root storage path convention."""

    def test_path_format(self):
        h = bytes([ALG_ECFV1_SHA256]) + b"\xab" * 32
        path = multi_sig_root_path(h)
        assert path.startswith("system/capability/grants/multi-sig-root/")
        # Hex-encoded form of the bytes hash.
        assert path.endswith(h.hex())

    def test_path_is_distinct_from_handler_grant_path(self):
        """multi-sig-root/ != handler self-grant convention."""
        h = bytes([ALG_ECFV1_SHA256]) + b"\xcd" * 32
        path = multi_sig_root_path(h)
        # Handler self-grants live at system/capability/grants/{pattern} per V7 §6.8.
        assert "/multi-sig-root/" in path
        # Hex digest is 33 bytes * 2 = 66 hex chars.
        assert len(path.split("/")[-1]) == 66


# ---------------------------------------------------------------------------
# Vectors 24, 25 — amendment: status normalization + precedence
# ---------------------------------------------------------------------------


class TestM3PrecedenceOverSignatures:
    """Vectors 25a, 25b (PROPOSAL §3.3 amendment).

    Within-cap precedence: when an M3-violating cap also has signature defects,
    M3 must fire first. This is security-critical — the failure category
    surfaced to the caller communicates "capability invalid," not "sig
    failed," so a malformed cap can never look like a forgery attempt.

    The verifier runs Phase 1 (M3 validation across all chain entries) before
    Phase 2 (per-link signature checks), so the precedence is structural in
    `verify_capability_chain`. These tests pin that behavior so a future
    refactor can't accidentally interleave them.
    """

    def _malformed_cap(self, threshold: int):
        """Build a cap where K is invalid AND no sigs are attached."""
        peers = {n: _make_peer(_seeded(n.encode())) for n in ("a", "b", "c", "d")}
        signer_hashes = [peers["a"][2], peers["b"][2], peers["c"][2]]
        cap = _multi_sig_root_cap(
            signers=signer_hashes, threshold=threshold,
            grantee=peers["d"][2],
        )
        # Identity entities only — no signatures.
        included = _included_map(
            cap, peers["a"][1], peers["b"][1], peers["c"][1], peers["d"][1],
        )
        lookup, find_sig, find_sig_by = _make_finders(included)
        return cap, lookup, find_sig, find_sig_by, peers["a"][0].peer_id

    def test_vector25a_m3_beats_missing_sigs(self):
        """K > N AND no signatures attached → M3 surfaces, not sig-failure."""
        cap, lookup, find_sig, find_sig_by, local_pid = self._malformed_cap(threshold=4)
        result = verify_capability_chain(
            cap, lookup, find_sig, local_pid,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid
        # Error must indicate M3 (multi-granter validity), not below-threshold.
        err = result.error.lower()
        assert "multi-granter" in err and "exceeds" in err, (
            f"Expected M3 'exceeds N' error, got: {result.error!r}"
        )
        assert "threshold not met" not in err, (
            "M3 must precede M4: missing-sigs error must NOT surface when M3 fires"
        )

    def test_vector25b_m3_beats_invalid_sigs(self):
        """K > N AND invalid signatures attached → M3 surfaces, not sig-failure.

        Build a cap with K > N, then attach signatures with garbage bytes.
        If precedence is correct, M3 fires before any signature check sees
        the garbage.
        """
        peers = {n: _make_peer(_seeded(n.encode())) for n in ("a", "b", "c", "d")}
        signer_hashes = [peers["a"][2], peers["b"][2], peers["c"][2]]
        cap = _multi_sig_root_cap(
            signers=signer_hashes, threshold=4, grantee=peers["d"][2],  # K > N
        )

        # Forged signature entities — claim to sign cap but bytes are wrong.
        # If M4 ran first, it would try to verify and fail with sig-failure.
        bad_sig = {
            "type": "system/signature",
            "data": {
                "target": cap["content_hash"],
                "signer": peers["a"][2],
                "signature": b"\x00" * 64,  # garbage
                "algorithm": "ed25519",
            },
            "content_hash": bytes([ALG_ECFV1_SHA256]) + b"badsig" + b"\x00" * 26,
        }
        included = _included_map(
            cap, peers["a"][1], peers["b"][1], peers["c"][1], peers["d"][1], bad_sig,
        )
        lookup, find_sig, find_sig_by = _make_finders(included)

        result = verify_capability_chain(
            cap, lookup, find_sig, peers["a"][0].peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid
        err = result.error.lower()
        assert "multi-granter" in err and "exceeds" in err, (
            f"M3 must beat invalid sigs, got: {result.error!r}"
        )
        assert "invalid capability signature" not in err
        assert "threshold not met" not in err

    def test_vector25c_threshold_below_with_structurally_valid_cap(self):
        """Structurally valid cap, sigs missing → DENY (M4 below threshold).

        Confirms that with a valid M3 shape, the signature-failure path is
        the one that surfaces. This is the M4 path; together with 25a/25b
        it proves M3-vs-M4 is correctly distinguishable on the wire.
        """
        peers = {n: _make_peer(_seeded(n.encode())) for n in ("a", "b", "c", "d")}
        signer_hashes = [peers["a"][2], peers["b"][2], peers["c"][2]]
        cap = _multi_sig_root_cap(
            signers=signer_hashes, threshold=2, grantee=peers["d"][2],
        )
        # No signatures attached.
        included = _included_map(
            cap, peers["a"][1], peers["b"][1], peers["c"][1], peers["d"][1],
        )
        lookup, find_sig, find_sig_by = _make_finders(included)

        result = verify_capability_chain(
            cap, lookup, find_sig, peers["a"][0].peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid
        err = result.error.lower()
        # Signature-failure category surfaces when M3 is clean.
        assert "threshold not met" in err
        assert "multi-granter" not in err  # not an M3 error


class TestM3PhaseOrdering:
    """Verifier-internal: M3 runs across the whole chain before any signature
    work. Covers the spec's "before any signature verification on the same
    cap" rule even when the cap is mid-chain (only possible via a malformed
    sender that violates M3 root-only — the verifier still rejects M3 first).
    """

    def test_m3_validation_runs_for_every_chain_entry(self):
        """If any chain entry is a malformed multi-sig, M3 fires regardless of
        position, before any per-link sig check anywhere."""
        peers = {n: _make_peer(_seeded(n.encode())) for n in
                 ("a", "b", "c", "d", "e")}

        # Hand-craft a chain where the *root* is multi-sig but the sender
        # forgot to set parent=None on a hypothetical mid-chain attempt.
        # Actually this is exactly vector 5b — pin it twice from the
        # ordering perspective.
        parent_token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
            granter=peers["d"][2],
            grantee=peers["a"][2],
            created_at=1,
        )
        parent = _entity_to_wire_dict(parent_token.to_entity())

        bad_child = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["*"])],
            granter=MultiGranter(
                signers=[peers["a"][2], peers["b"][2], peers["c"][2]], threshold=2,
            ),
            grantee=peers["e"][2],
            created_at=2,
            parent=parent["content_hash"],  # M3 violation: multi-sig must be root
        )
        child = _entity_to_wire_dict(bad_child.to_entity())

        included = _included_map(
            child, parent,
            peers["a"][1], peers["b"][1], peers["c"][1], peers["d"][1], peers["e"][1],
        )
        lookup, find_sig, find_sig_by = _make_finders(included)
        result = verify_capability_chain(
            child, lookup, find_sig, peers["a"][0].peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid
        # The M3 root-only violation must surface, not "signature missing".
        err = result.error.lower()
        assert "root" in err or "parent=null" in err
        assert "signature" not in err  # no sig check ran on child


class TestM3StatusNormalization:
    """Vector 24 (PROPOSAL §3.3): all M3 violations surface as 403.

    The verifier returns DelegationResult; the dispatcher (peer.py) maps any
    invalid result to ExecuteResponse.forbidden (403). This test fakes the
    boundary mapping — every M3 case must route through the same code path.
    """

    @pytest.mark.parametrize("threshold,signers_n,name", [
        (0, 3, "K=0"),
        (1, 3, "K=1"),
        (4, 3, "K>N"),
        (2, 1, "N=1"),
    ])
    def test_all_m3_violations_route_to_403(self, threshold, signers_n, name):
        """Each M3-class violation is rejected by verify_capability_chain.

        Per PROPOSAL §3.3 / §10.1 the wire-response shaper must surface this
        as 403 capability_denied; the dispatcher unconditionally calls
        ExecuteResponse.forbidden for any invalid VerificationResult, so the
        invariant is structural here. The unit-level guarantee is that the
        verifier rejects each case.
        """
        peers = {f"p{i}": _make_peer(_seeded(f"p{i}".encode())) for i in range(signers_n + 1)}
        signer_hashes = [peers[f"p{i}"][2] for i in range(signers_n)]
        # Bypass MultiGranter type-level constraints by going through the dict
        # form (the wire shape) — that's what a malicious peer would send.
        granter = {"signers": signer_hashes, "threshold": threshold}
        cap_data = {
            "grants": [Grant.create(
                handlers=["*"], resources=["*"], operations=["*"],
            ).to_dict()],
            "granter": granter,
            "grantee": peers[f"p{signers_n}"][2],
            "created_at": 1,
        }
        from entity_core.utils.ecf import compute_ecf_hash
        cap = {
            "type": "system/capability/token",
            "data": cap_data,
            "content_hash": compute_ecf_hash({
                "type": "system/capability/token", "data": cap_data,
            }),
        }
        included = _included_map(
            cap, *(peers[f"p{i}"][1] for i in range(signers_n + 1)),
        )
        lookup, find_sig, find_sig_by = _make_finders(included)
        result = verify_capability_chain(
            cap, lookup, find_sig, peers["p0"][0].peer_id,
            find_signature_by_signer=find_sig_by,
        )
        assert not result.valid, f"M3 case {name} unexpectedly accepted"
        # Whatever the specific error string, the dispatcher returns 403.
        # We confirm it's an M3-class error by looking for the marker.
        err = result.error.lower()
        assert "multi-granter" in err, (
            f"M3 case {name}: expected multi-granter error, got {result.error!r}"
        )


# ---------------------------------------------------------------------------
# Helper-level tests
# ---------------------------------------------------------------------------


class TestHelpers:
    """Shape-discrimination helpers used by the verifier branches."""

    def test_is_multi_granter_on_bytes(self):
        assert not is_multi_granter(b"\x00" * 33)

    def test_is_multi_granter_on_dict(self):
        assert is_multi_granter({"signers": [b"\x00" * 33, b"\x01" * 33], "threshold": 2})

    def test_is_multi_granter_on_instance(self):
        mg = MultiGranter(signers=[b"\x00" * 33, b"\x01" * 33], threshold=2)
        assert is_multi_granter(mg)

    def test_get_multi_granter_returns_none_for_bytes(self):
        assert get_multi_granter(b"\x00" * 33) is None

    def test_get_multi_granter_returns_instance_for_dict(self):
        d = {"signers": [b"\x00" * 33, b"\x01" * 33], "threshold": 2}
        mg = get_multi_granter(d)
        assert isinstance(mg, MultiGranter)
        assert mg.threshold == 2

    def test_find_signature_by_signer_helper(self):
        """Module-level helper finds signature by both target and signer."""
        target = bytes([ALG_ECFV1_SHA256]) + b"target" + b"\x00" * 26
        signer_a = bytes([ALG_ECFV1_SHA256]) + b"siga__" + b"\x00" * 26
        signer_b = bytes([ALG_ECFV1_SHA256]) + b"sigb__" + b"\x00" * 26

        sig_a = {
            "type": "system/signature",
            "data": {"target": target, "signer": signer_a, "signature": b"\x00" * 64,
                     "algorithm": "ed25519"},
            "content_hash": bytes([ALG_ECFV1_SHA256]) + b"sigent" + b"\x00" * 26,
        }
        included = {sig_a["content_hash"]: sig_a}

        # Match.
        assert find_sig_by_signer_helper(target, signer_a, included) is sig_a
        # Different signer for same target → None.
        assert find_sig_by_signer_helper(target, signer_b, included) is None
        # Different target → None.
        other_target = bytes([ALG_ECFV1_SHA256]) + b"other_" + b"\x00" * 26
        assert find_sig_by_signer_helper(other_target, signer_a, included) is None

    def test_validate_multi_granter_accepts_valid(self):
        ok, err = validate_multi_granter(
            MultiGranter(
                signers=[
                    bytes([ALG_ECFV1_SHA256]) + b"a" + b"\x00" * 31,
                    bytes([ALG_ECFV1_SHA256]) + b"b" + b"\x00" * 31,
                    bytes([ALG_ECFV1_SHA256]) + b"c" + b"\x00" * 31,
                ],
                threshold=2,
            ),
        )
        assert ok
        assert err is None

    def test_validate_multi_granter_rejects_non_multi(self):
        ok, err = validate_multi_granter(b"\x00" * 33)
        assert not ok
