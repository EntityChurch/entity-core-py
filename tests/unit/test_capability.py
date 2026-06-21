"""Tests for capability checking and delegation."""

import time

from entity_core.capability.checking import (
    matches_pattern,
    check_handler_scope,
    check_path_permission,
)
from entity_core.capability.token import CapabilityToken, Grant
from entity_core.capability.delegation import (
    is_attenuated,
    grant_covered_by,
    check_caveats,
    validate_delegation,
    pattern_covers,
    collect_authority_chain,
    collect_chain_bundle,
    check_creator_authority,
    verify_capability_chain,
    ChainCollectStatus,
)
from entity_core.utils.ecf import ALG_ECFV1_SHA256

# Test hash values (bytes format for V4)
HASH_CLIENT = bytes([ALG_ECFV1_SHA256]) + b"client" + b"\x00" * 26  # 33 bytes
HASH_OTHER = bytes([ALG_ECFV1_SHA256]) + b"other_" + b"\x00" * 26  # 33 bytes
HASH_ROOT = bytes([ALG_ECFV1_SHA256]) + b"root__" + b"\x00" * 26  # 33 bytes
HASH_ALICE = bytes([ALG_ECFV1_SHA256]) + b"alice_" + b"\x00" * 26  # 33 bytes
HASH_BOB = bytes([ALG_ECFV1_SHA256]) + b"bob___" + b"\x00" * 26  # 33 bytes
HASH_MALLORY = bytes([ALG_ECFV1_SHA256]) + b"mallor" + b"\x00" * 26  # 33 bytes
HASH_GRANTER = bytes([ALG_ECFV1_SHA256]) + b"grante" + b"\x00" * 26  # 33 bytes
HASH_GRANTEE = bytes([ALG_ECFV1_SHA256]) + b"grntee" + b"\x00" * 26  # 33 bytes
HASH_MISSING = bytes([ALG_ECFV1_SHA256]) + b"missin" + b"\x00" * 26  # 33 bytes


class TestPatternMatching:
    """Tests for pattern matching (v7.18 absolute paths)."""

    def test_exact_match(self):
        """Exact pattern matches exact path (both absolute)."""
        assert matches_pattern("/peer/local/files/doc.txt", "/peer/local/files/doc.txt")
        assert not matches_pattern("/peer/local/files/doc.txt", "/peer/local/files/other.txt")

    def test_wildcard_prefix(self):
        """Trailing * matches subtree."""
        assert matches_pattern("/peer/local/files/*", "/peer/local/files/doc.txt")
        assert matches_pattern("/peer/local/files/*", "/peer/local/files/subdir/doc.txt")
        assert not matches_pattern("/peer/local/files/*", "/peer/local/other/doc.txt")

    def test_peer_wildcard(self):
        """/*/ peer wildcard matches any peer."""
        assert matches_pattern("/*/local/files/*", "/peer1/local/files/doc.txt")
        assert matches_pattern("/*/local/files/*", "/peer2/local/files/doc.txt")

    def test_full_wildcard(self):
        """/*/* matches all peers, all paths."""
        assert matches_pattern("/*/*", "/peer1/local/files/doc.txt")
        assert matches_pattern("/*/*", "/peer2/anything/here")

    def test_universal_wildcard(self):
        """Bare * matches everything (recursive base case)."""
        assert matches_pattern("*", "/peer/anything")
        assert matches_pattern("*", "anything")

    def test_peer_wildcard_exact(self):
        """/*/exact matches any peer at exact subpath."""
        assert matches_pattern("/*/system/tree", "/peer1/system/tree")
        assert not matches_pattern("/*/system/tree", "/peer1/system/other")

    def test_pr8_bare_wildcard_canonicalizes_to_granter_namespace(self):
        """V7 PR-8: bare `*` in a cap resource pattern is peer-local (the
        granter's own namespace), NOT a universal cross-peer wildcard.
        `*` canonicalized against granter `alice` becomes `/alice/*`, which
        does NOT match a request path under a different peer's namespace.
        Cross-peer authority MUST be expressed as `/*/...` explicitly.
        """
        from entity_core.capability.checking import canonicalize

        # Bare * → /granter/* — peer-local only
        assert canonicalize("*", "alice") == "/alice/*"

        # Peer-local cap pattern does NOT match a different peer's path
        peer_local = canonicalize("*", "alice")
        assert matches_pattern(peer_local, "/alice/foo/bar")
        assert not matches_pattern(peer_local, "/bob/foo/bar")

        # Cross-peer authority requires explicit /*/...
        assert canonicalize("/*/*", "alice") == "/*/*"
        assert matches_pattern("/*/*", "/alice/foo/bar")
        assert matches_pattern("/*/*", "/bob/foo/bar")

    def test_pr8_open_access_grant_includes_cross_peer(self):
        """V7 PR-8: open-access caps (e.g., dev-mode connection caps) MUST
        include `/*/*` plus `peers: ["*"]` for full cross-peer coverage —
        bare `*` alone is insufficient since it canonicalizes to the
        granter's namespace only.
        """
        from entity_core.capability.grant import create_full_access_grant

        grants = create_full_access_grant()
        for g in grants:
            grant_dict = g.to_dict() if hasattr(g, "to_dict") else g
            resources = grant_dict.get("resources")
            # CapabilityScope dict shape vs include list
            include = (
                resources.get("include") if isinstance(resources, dict) else None
            )
            assert include is not None and "/*/*" in include, (
                f"open-access grant must include /*/* for cross-peer coverage: {include}"
            )
            peers = grant_dict.get("peers")
            peers_include = (
                peers.get("include") if isinstance(peers, dict) else None
            )
            assert peers_include is not None and "*" in peers_include, (
                f"open-access grant must include peers=['*']: {peers_include}"
            )


class TestCapabilityToken:
    """Tests for CapabilityToken with delegation_caveats."""

    def test_token_with_delegation_caveats(self):
        """Token serializes delegation_caveats as flat struct per V4 §3.6."""
        from entity_core.capability.token import DelegationCaveats

        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["read"])],
            granter=HASH_GRANTER,
            grantee=HASH_GRANTEE,
            delegation_caveats=DelegationCaveats(no_delegation=True),
        )
        entity = token.to_entity()
        # V4 §3.6: delegation_caveats is a flat struct, not an array
        assert entity["data"]["delegation_caveats"] == {"no_delegation": True}

    def test_granter_grantee_in_data(self):
        """V4: Granter and grantee are bytes in data only (no refs)."""
        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["read"])],
            granter=HASH_ALICE,
            grantee=HASH_BOB,
        )
        entity = token.to_entity()
        # V4: Only in data (no refs field), as bytes
        assert entity["data"]["granter"] == HASH_ALICE
        assert entity["data"]["grantee"] == HASH_BOB
        assert "refs" not in entity

    def test_different_parties_different_hash(self):
        """Capabilities with different parties have different content_hash."""
        from entity_core.protocol.entity import Entity

        token1 = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["read"])],
            granter=HASH_ALICE,
            grantee=HASH_BOB,
        )
        token2 = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["read"])],
            granter=HASH_ALICE,
            grantee=HASH_MALLORY,  # Different grantee
        )
        entity1 = Entity.from_dict(token1.to_entity())
        entity2 = Entity.from_dict(token2.to_entity())
        # Different parties = different hash (prevents signature substitution)
        assert entity1.compute_hash() != entity2.compute_hash()

    def test_token_from_entity_with_delegation_caveats(self):
        """Token parses delegation_caveats correctly as flat struct."""
        entity = {
            "type": "system/capability/token",
            "data": {
                "grants": [{"resources": {"include": ["*"]}, "operations": {"include": ["read"]}}],
                "granter": HASH_GRANTER,
                "grantee": HASH_GRANTEE,
                "delegation_caveats": {"max_delegation_depth": 2},
            },
        }
        token = CapabilityToken.from_entity(entity)
        assert token.delegation_caveats is not None
        assert token.delegation_caveats.max_delegation_depth == 2

    def test_has_caveat(self):
        """has_caveat helper works with V4 flat struct."""
        from entity_core.capability.token import DelegationCaveats

        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["read"])],
            granter=b"",
            grantee=b"",
            delegation_caveats=DelegationCaveats(no_delegation=True, max_delegation_depth=2),
        )
        assert token.has_caveat("no_delegation")
        assert token.has_caveat("max_delegation_depth")
        assert not token.has_caveat("max_delegation_ttl")

    def test_get_caveat_limit(self):
        """get_caveat_limit helper works with V4 flat struct."""
        from entity_core.capability.token import DelegationCaveats

        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["read"])],
            granter=b"",
            grantee=b"",
            delegation_caveats=DelegationCaveats(max_delegation_depth=3, max_delegation_ttl=1000),
        )
        assert token.get_caveat_limit("max_delegation_depth") == 3
        assert token.get_caveat_limit("max_delegation_ttl") == 1000
        assert token.get_caveat_limit("no_delegation") is None


class TestSec18ZeroGrantee:
    """SEC-18 / V7 v7.39 PR-3: zero/absent grantee rejected at mint time.

    Defense-in-depth: chain-walk already rejects such caps at use time with
    `unresolvable_grantee`; these guard the generic mint chokepoint so a dud
    cap never gets signed/bound (it never resolves to a system/identity).
    """

    def test_grantee_is_zero_helper(self):
        from entity_core.capability.token import grantee_is_zero
        from entity_core.utils.ecf import ALG_ECFV1_SHA256

        # Absent / empty forms
        assert grantee_is_zero(b"")
        assert grantee_is_zero(None)
        # All-zero digest, with and without the algorithm prefix
        assert grantee_is_zero(b"\x00" * 32)
        assert grantee_is_zero(b"\x00" * 33)
        assert grantee_is_zero(bytes([0x00]) + b"\x00" * 32)
        # Real (non-zero) grantee is fine
        real = bytes([ALG_ECFV1_SHA256]) + b"grntee" + b"\x00" * 26
        assert not grantee_is_zero(real)

    def test_validate_structure_rejects_zero_grantee(self):
        import pytest

        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["read"])],
            granter=HASH_GRANTER,
            grantee=b"\x00" * 33,
        )
        with pytest.raises(ValueError, match="SEC-18"):
            token.validate_structure()

    def test_validate_structure_rejects_absent_grantee(self):
        import pytest

        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["read"])],
            granter=HASH_GRANTER,
            grantee=b"",
        )
        with pytest.raises(ValueError, match="grantee MUST be a non-zero hash"):
            token.validate_structure()

    def test_validate_structure_accepts_real_grantee(self):
        token = CapabilityToken(
            grants=[Grant.create(handlers=["*"], resources=["*"], operations=["read"])],
            granter=HASH_GRANTER,
            grantee=HASH_GRANTEE,
        )
        token.validate_structure()  # must not raise

    def test_create_capability_token_rejects_zero_grantee(self):
        """The generic mint chokepoint fails fast on a zero-hash grantee."""
        import pytest

        from entity_core.capability.grant import (
            create_capability_token,
            create_full_access_grant,
        )
        from entity_core.crypto.identity import Keypair

        granter_kp = Keypair.generate()

        # create_capability_token only calls `.compute_hash()` on the grantee
        # identity; a zero-hash identity is unconstructible in practice, so
        # duck-type the dud to exercise the SEC-18 fail-fast guard.
        class _ZeroGranteeIdentity:
            def compute_hash(self) -> bytes:
                return b"\x00" * 33

        with pytest.raises(ValueError, match="SEC-18"):
            create_capability_token(
                granter_kp, _ZeroGranteeIdentity(), create_full_access_grant()
            )


class TestPatternCovers:
    """Tests for pattern_covers function (attenuation)."""

    def test_exact_match(self):
        """Exact patterns cover each other."""
        assert pattern_covers("local/files/doc.txt", "local/files/doc.txt")

    def test_wildcard_covers_specific(self):
        """Wildcard covers specific path."""
        assert pattern_covers("local/files/*", "local/files/doc.txt")
        assert pattern_covers("local/files/*", "local/files/subdir/doc.txt")

    def test_specific_does_not_cover_wildcard(self):
        """Specific path doesn't cover wildcard."""
        assert not pattern_covers("local/files/doc.txt", "local/files/*")

    def test_universal_covers_everything(self):
        """Universal patterns cover everything."""
        assert pattern_covers("*", "local/files/doc.txt")
        assert pattern_covers("/*/*", "/peer/local/files")

    def test_subtree_covers_subtree(self):
        """Parent subtree covers child subtree."""
        assert pattern_covers("local/*", "local/files/*")
        assert pattern_covers("local/files/*", "local/files/subdir/*")
        assert not pattern_covers("local/files/*", "local/*")


class TestGrantCoveredBy:
    """Tests for grant_covered_by function."""

    def test_operations_subset(self):
        """Child operations must be subset of parent."""
        child = {"handlers": {"include": ["*"]}, "resources": {"include": ["local/*"]}, "operations": {"include": ["read"]}}
        parent = [{"handlers": {"include": ["*"]}, "resources": {"include": ["local/*"]}, "operations": {"include": ["read", "write"]}}]
        assert grant_covered_by(child, parent)

    def test_operations_not_subset(self):
        """Child with extra operations is not covered."""
        child = {"handlers": {"include": ["*"]}, "resources": {"include": ["local/*"]}, "operations": {"include": ["read", "write"]}}
        parent = [{"handlers": {"include": ["*"]}, "resources": {"include": ["local/*"]}, "operations": {"include": ["read"]}}]
        assert not grant_covered_by(child, parent)

    def test_resources_subset(self):
        """Child resources must be subset of parent."""
        child = {"handlers": {"include": ["*"]}, "resources": {"include": ["local/files/*"]}, "operations": {"include": ["read"]}}
        parent = [{"handlers": {"include": ["*"]}, "resources": {"include": ["local/*"]}, "operations": {"include": ["read"]}}]
        assert grant_covered_by(child, parent)

    def test_resources_not_subset(self):
        """Child with broader resources is not covered."""
        child = {"handlers": {"include": ["*"]}, "resources": {"include": ["local/*"]}, "operations": {"include": ["read"]}}
        parent = [{"handlers": {"include": ["*"]}, "resources": {"include": ["local/files/*"]}, "operations": {"include": ["read"]}}]
        assert not grant_covered_by(child, parent)

    def test_handlers_subset(self):
        """Child handlers must be subset of parent."""
        child = {"handlers": {"include": ["system/tree"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}
        parent = [{"handlers": {"include": ["system/*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}]
        assert grant_covered_by(child, parent)

    def test_handlers_not_subset(self):
        """Child with broader handlers is not covered."""
        child = {"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}
        parent = [{"handlers": {"include": ["system/*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}]
        assert not grant_covered_by(child, parent)


class TestIsAttenuated:
    """Tests for is_attenuated function."""

    def test_same_capability_is_attenuated(self):
        """Identical capabilities are attenuated."""
        parent = {
            "data": {"grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}]},
        }
        child = {
            "data": {"grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}]},
        }
        result = is_attenuated(child, parent)
        assert result.valid

    def test_narrower_resources_is_attenuated(self):
        """Narrower resources are attenuated."""
        parent = {
            "data": {"grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["local/*"]}, "operations": {"include": ["read"]}}]},
        }
        child = {
            "data": {"grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["local/files/*"]}, "operations": {"include": ["read"]}}]},
        }
        result = is_attenuated(child, parent)
        assert result.valid

    def test_broader_resources_not_attenuated(self):
        """Broader resources are not attenuated."""
        parent = {
            "data": {"grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["local/files/*"]}, "operations": {"include": ["read"]}}]},
        }
        child = {
            "data": {"grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["local/*"]}, "operations": {"include": ["read"]}}]},
        }
        result = is_attenuated(child, parent)
        assert not result.valid

    def test_expiration_must_not_exceed_parent(self):
        """Child expiration must not exceed parent."""
        parent = {
            "data": {
                "grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}],
                "expires_at": 1000,
            },
        }
        child = {
            "data": {
                "grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}],
                "expires_at": 2000,  # After parent
            },
        }
        result = is_attenuated(child, parent)
        assert not result.valid
        assert "expires after parent" in result.error

    def test_child_must_have_parent_exclusions(self):
        """Child must inherit parent exclusions."""
        parent = {
            "data": {
                "grants": [
                    {
                        "handlers": {"include": ["*"]},
                        "resources": {"include": ["local/*"], "exclude": ["local/secrets/*"]},
                        "operations": {"include": ["read"]},
                    }
                ]
            },
        }
        child = {
            "data": {
                "grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["local/*"]}, "operations": {"include": ["read"]}}]  # Missing exclusion
            },
        }
        result = is_attenuated(child, parent)
        assert not result.valid
        # V4: Per-grant exclude checking - child grant isn't covered because it lacks the exclude
        assert "not covered" in result.error.lower()

    def test_narrower_handlers_is_attenuated(self):
        """Narrower handlers are attenuated."""
        parent = {
            "data": {"grants": [{"handlers": {"include": ["system/*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}]},
        }
        child = {
            "data": {"grants": [{"handlers": {"include": ["system/tree"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}]},
        }
        result = is_attenuated(child, parent)
        assert result.valid

    def test_broader_handlers_not_attenuated(self):
        """Broader handlers are not attenuated."""
        parent = {
            "data": {"grants": [{"handlers": {"include": ["system/tree"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}]},
        }
        child = {
            "data": {"grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}]},
        }
        result = is_attenuated(child, parent)
        assert not result.valid


class TestCheckCaveats:
    """Tests for check_caveats function."""

    def test_no_caveats_passes(self):
        """No caveats always passes."""
        parent = {"data": {"grants": []}}
        child = {"data": {"grants": []}}
        result = check_caveats(parent, child, 0, 0)
        assert result.valid

    def test_no_delegation_fails(self):
        """no_delegation caveat prevents delegation."""
        # V4 §3.6: delegation_caveats is a flat struct
        parent = {"data": {"grants": [], "delegation_caveats": {"no_delegation": True}}}
        child = {"data": {"grants": []}}
        result = check_caveats(parent, child, 0, 0)
        assert not result.valid
        assert "no_delegation" in result.error

    def test_max_depth_within_limit(self):
        """max_delegation_depth within limit passes."""
        # V4 §3.6: delegation_caveats is a flat struct
        parent = {
            "data": {"grants": [], "delegation_caveats": {"max_delegation_depth": 3}},
        }
        child = {"data": {"grants": []}}
        result = check_caveats(parent, child, 2, 0)  # depth 2 < limit 3
        assert result.valid

    def test_max_depth_at_limit_fails(self):
        """max_delegation_depth at limit fails."""
        # V4 §3.6: delegation_caveats is a flat struct
        parent = {
            "data": {"grants": [], "delegation_caveats": {"max_delegation_depth": 2}},
        }
        child = {"data": {"grants": []}}
        result = check_caveats(parent, child, 2, 0)  # depth 2 >= limit 2
        assert not result.valid
        assert "depth" in result.error.lower()

    def test_max_ttl_within_limit(self):
        """max_delegation_ttl within limit passes."""
        now = 1000
        # V4 §3.6: delegation_caveats is a flat struct
        parent = {
            "data": {"grants": [], "delegation_caveats": {"max_delegation_ttl": 1000}},
        }
        child = {
            "data": {"grants": [], "created_at": now, "expires_at": now + 500},  # TTL 500 < 1000
        }
        result = check_caveats(parent, child, 0, now)
        assert result.valid

    def test_max_ttl_exceeds_limit_fails(self):
        """max_delegation_ttl exceeding limit fails."""
        now = 1000
        # V4 §3.6: delegation_caveats is a flat struct
        parent = {
            "data": {"grants": [], "delegation_caveats": {"max_delegation_ttl": 500}},
        }
        child = {
            "data": {"grants": [], "created_at": now, "expires_at": now + 1000},  # TTL 1000 > 500
        }
        result = check_caveats(parent, child, 0, now)
        assert not result.valid
        assert "ttl" in result.error.lower()

    def test_max_ttl_infinite_child_fails(self):
        """Infinite TTL child fails when parent limits TTL."""
        now = 1000
        # V4 §5.7: Infinite lifetime exceeds any finite limit
        parent = {
            "data": {"grants": [], "delegation_caveats": {"max_delegation_ttl": 500}},
        }
        child = {
            "data": {"grants": [], "created_at": now},  # No expires_at = infinite
        }
        result = check_caveats(parent, child, 0, now)
        assert not result.valid


class TestValidateDelegation:
    """Tests for validate_delegation function (creation-time check)."""

    def test_valid_delegation(self):
        """Valid delegation passes."""
        parent = {
            "data": {
                "grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["local/*"]}, "operations": {"include": ["read", "write"]}}],
                "grantee": HASH_CLIENT,
            },
        }
        child = {
            "data": {
                "grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["local/files/*"]}, "operations": {"include": ["read"]}}],
                "granter": HASH_CLIENT,
            },
        }
        result = validate_delegation(child, parent)
        assert result.valid

    def test_granter_must_be_parent_grantee(self):
        """Child granter must be parent grantee."""
        parent = {
            "data": {
                "grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}],
                "grantee": HASH_CLIENT,
            },
        }
        child = {
            "data": {
                "grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}],
                "granter": HASH_OTHER,  # Wrong granter
            },
        }
        result = validate_delegation(child, parent)
        assert not result.valid
        assert "granter must be parent grantee" in result.error.lower()

    def test_delegation_with_no_delegation_caveat(self):
        """Cannot delegate capability with no_delegation caveat."""
        # V4 §3.6: delegation_caveats is a flat struct
        parent = {
            "data": {
                "grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}],
                "delegation_caveats": {"no_delegation": True},
                "grantee": HASH_CLIENT,
            },
        }
        child = {
            "data": {
                "grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["read"]}}],
                "granter": HASH_CLIENT,
            },
        }
        result = validate_delegation(child, parent)
        assert not result.valid


class TestHandlerScopeChecking:
    """Tests for check_handler_scope with explicit handlers field."""

    def test_handler_scope_matches_exact_handler(self):
        """Handler scope matches exact handler pattern."""
        cap_data = {
            "grants": [
                {"handlers": {"include": ["system/tree"]}, "resources": {"include": ["*"]}, "operations": {"include": ["get"]}}
            ]
        }
        assert check_handler_scope(cap_data, "system/tree", "get", "peer123")
        assert not check_handler_scope(cap_data, "system/types", "get", "peer123")

    def test_handler_scope_matches_wildcard_handler(self):
        """Handler scope matches wildcard handler pattern."""
        cap_data = {
            "grants": [
                {"handlers": {"include": ["system/*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["get"]}}
            ]
        }
        assert check_handler_scope(cap_data, "system/tree", "get", "peer123")
        assert check_handler_scope(cap_data, "system/types", "get", "peer123")
        assert not check_handler_scope(cap_data, "data/files", "get", "peer123")

    def test_handler_scope_universal_wildcard(self):
        """Universal wildcard matches all handlers."""
        cap_data = {
            "grants": [
                {"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["get"]}}
            ]
        }
        assert check_handler_scope(cap_data, "system/tree", "get", "peer123")
        assert check_handler_scope(cap_data, "data/files", "get", "peer123")

    def test_handler_scope_checks_operations(self):
        """Handler scope requires matching operation."""
        cap_data = {
            "grants": [
                {"handlers": {"include": ["system/tree"]}, "resources": {"include": ["*"]}, "operations": {"include": ["get"]}}
            ]
        }
        assert check_handler_scope(cap_data, "system/tree", "get", "peer123")
        assert not check_handler_scope(cap_data, "system/tree", "put", "peer123")

    def test_handler_scope_multiple_grants(self):
        """Multiple grants with different handlers."""
        cap_data = {
            "grants": [
                {"handlers": {"include": ["system/tree"]}, "resources": {"include": ["*"]}, "operations": {"include": ["get"]}},
                {"handlers": {"include": ["system/capabilities"]}, "resources": {"include": ["*"]}, "operations": {"include": ["execute"]}},
            ]
        }
        assert check_handler_scope(cap_data, "system/tree", "get", "peer123")
        assert check_handler_scope(cap_data, "system/capabilities", "execute", "peer123")
        assert not check_handler_scope(cap_data, "system/tree", "execute", "peer123")


class TestPathPermissionWithHandlerFilter:
    """Tests for check_path_permission with handler filtering."""

    def test_path_permission_without_handler_filter(self):
        """Path permission works without handler filter."""
        cap_data = {
            "grants": [
                {"handlers": {"include": ["system/tree"]}, "resources": {"include": ["system/types/*"]}, "operations": {"include": ["get"]}}
            ]
        }
        # Without handler filter, just checks path
        assert check_path_permission(cap_data, "get", "system/types/foo", "peer123")

    def test_path_permission_with_handler_filter(self):
        """Path permission with handler filter only uses matching grants."""
        cap_data = {
            "grants": [
                {"handlers": {"include": ["system/tree"]}, "resources": {"include": ["system/types/*"]}, "operations": {"include": ["get"]}},
                {"handlers": {"include": ["system/content"]}, "resources": {"include": ["data/*"]}, "operations": {"include": ["get"]}},
            ]
        }
        # With handler filter, only grants matching the handler are considered
        assert check_path_permission(
            cap_data, "get", "system/types/foo", "peer123", handler_pattern="system/tree"
        )
        assert not check_path_permission(
            cap_data, "get", "data/file", "peer123", handler_pattern="system/tree"
        )
        assert check_path_permission(
            cap_data, "get", "data/file", "peer123", handler_pattern="system/content"
        )


class TestOpenAccessCapResources:
    """Per V7 §1.4 / §5.4 strict cap-resource canonicalization (and the
    cross-impl Round-3 P-6 update): bare `*` → `/{granter_peer_id}/*`
    (local namespace only); `/*/*` is required for cross-peer authority.
    The open-access full-access grant MUST cover both — local-namespace
    paths AND cross-peer V7 invariant pointer paths."""

    def test_full_access_grant_covers_local_namespace(self):
        from entity_core.capability.grant import create_full_access_grant
        grants = create_full_access_grant()
        cap_data = {"grants": [g.to_dict() for g in grants]}
        # Local-namespace path under the granter peer.
        assert check_path_permission(
            cap_data, "put", "system/anything/here", "peer123",
            handler_pattern="system/tree",
        )

    def test_full_access_grant_covers_cross_namespace(self):
        """The Round-3 P-6 fix: the open-access cap MUST authorize
        writes to V7 invariant pointer paths under OTHER peers'
        namespaces (e.g., `/ephemeral_peer/system/signature/{hex}`)."""
        from entity_core.capability.grant import create_full_access_grant
        grants = create_full_access_grant()
        cap_data = {"grants": [g.to_dict() for g in grants]}
        # Cross-peer absolute path — outside the local granter's namespace.
        assert check_path_permission(
            cap_data, "put",
            "/ephemeral_peer/system/signature/abcdef0123456789",
            "peer123", handler_pattern="system/tree",
        )

    def test_full_access_grant_includes_peers_wildcard(self):
        """The grant must declare `peers: ["*"]` so cross-peer scope is
        explicit (matches Rust's open-access-cap shape)."""
        from entity_core.capability.grant import create_full_access_grant
        grants = create_full_access_grant()
        # The general (handlers=["*"]) grant should declare peers: ["*"].
        general = [g for g in grants if "*" in g.handlers.include]
        assert general
        for g in general:
            assert g.peers is not None
            assert "*" in g.peers.include

    def test_create_full_access_token_covers_cross_namespace(self):
        """CapabilityToken.create_full_access uses the same shape."""
        token = CapabilityToken.create_full_access(
            granter=HASH_GRANTER, grantee=HASH_GRANTEE,
        )
        # check_path_permission expects the cap's `data` field — i.e.,
        # the entity's `data` payload, not the wrapped {type, data} entity.
        cap_data = token.to_entity()["data"]
        assert check_path_permission(
            cap_data, "put",
            "/some_other_peer/system/signature/deadbeef",
            "local_peer", handler_pattern="system/tree",
        )
        # Sanity: the grant declares peers: ["*"].
        general = [g for g in token.grants if "*" in g.handlers.include]
        assert general
        for g in general:
            assert g.peers is not None and "*" in g.peers.include


def _root_cap(granter: bytes, content_hash: bytes | None = None) -> dict:
    return {
        "type": "system/capability/token",
        "data": {"granter": granter, "parent": None, "grants": []},
        "content_hash": content_hash or (bytes([ALG_ECFV1_SHA256]) + b"root_h" + b"\x00" * 26),
    }


def _delegated_cap(granter: bytes, parent_hash: bytes, content_hash: bytes) -> dict:
    return {
        "type": "system/capability/token",
        "data": {"granter": granter, "parent": parent_hash, "grants": []},
        "content_hash": content_hash,
    }


class TestCollectAuthorityChain:
    """Tests for `collect_authority_chain` per PROPOSAL-UNIFIED-CHAIN-WALK §2.

    The shared chain-walk primitive — walks leaf-to-root, returns chain
    or error (UNREACHABLE / TOO_DEEP). Used by verify_capability_chain,
    check_creator_authority, and (optionally) is_revoked.
    """

    def test_root_only(self):
        """Single-link chain returns OK with just the cap."""
        cap = _root_cap(HASH_ALICE)
        result = collect_authority_chain(cap, lambda h: None)
        assert result.status == ChainCollectStatus.OK
        assert result.ok
        assert len(result.chain) == 1
        assert result.chain[0] is cap

    def test_two_link_chain(self):
        """Walks parent, returns leaf-to-root order."""
        root_hash = bytes([ALG_ECFV1_SHA256]) + b"root_h" + b"\x00" * 26
        root = _root_cap(HASH_ALICE, content_hash=root_hash)
        leaf_hash = bytes([ALG_ECFV1_SHA256]) + b"leaf_h" + b"\x00" * 26
        leaf = _delegated_cap(HASH_BOB, root_hash, leaf_hash)

        result = collect_authority_chain(leaf, lambda h: root if h == root_hash else None)
        assert result.status == ChainCollectStatus.OK
        assert len(result.chain) == 2
        assert result.chain[0] is leaf
        assert result.chain[1] is root

    def test_three_link_chain(self):
        """Three levels: leaf → mid → root."""
        root_hash = bytes([ALG_ECFV1_SHA256]) + b"root_h" + b"\x00" * 26
        mid_hash = bytes([ALG_ECFV1_SHA256]) + b"mid_h_" + b"\x00" * 26
        leaf_hash = bytes([ALG_ECFV1_SHA256]) + b"leaf_h" + b"\x00" * 26
        root = _root_cap(HASH_ALICE, content_hash=root_hash)
        mid = _delegated_cap(HASH_BOB, root_hash, mid_hash)
        leaf = _delegated_cap(HASH_MALLORY, mid_hash, leaf_hash)
        store = {root_hash: root, mid_hash: mid}

        result = collect_authority_chain(leaf, lambda h: store.get(h))
        assert result.status == ChainCollectStatus.OK
        assert [c["content_hash"] for c in result.chain] == [leaf_hash, mid_hash, root_hash]

    def test_unreachable_parent(self):
        """Missing parent → UNREACHABLE, empty chain, parent hash reported."""
        leaf_hash = bytes([ALG_ECFV1_SHA256]) + b"leaf_h" + b"\x00" * 26
        leaf = _delegated_cap(HASH_BOB, HASH_MISSING, leaf_hash)
        result = collect_authority_chain(leaf, lambda h: None)
        assert result.status == ChainCollectStatus.UNREACHABLE
        assert not result.ok
        assert result.chain == []  # rejection paths must not contribute partial chain
        assert result.unreachable_parent == HASH_MISSING

    def test_unreachable_mid_chain(self):
        """Mid-level parent missing → UNREACHABLE even if leaf had a real parent ref."""
        mid_hash = bytes([ALG_ECFV1_SHA256]) + b"mid_h_" + b"\x00" * 26
        leaf_hash = bytes([ALG_ECFV1_SHA256]) + b"leaf_h" + b"\x00" * 26
        # mid points to HASH_MISSING; mid is in the lookup but its parent isn't.
        mid = _delegated_cap(HASH_BOB, HASH_MISSING, mid_hash)
        leaf = _delegated_cap(HASH_MALLORY, mid_hash, leaf_hash)
        store = {mid_hash: mid}

        result = collect_authority_chain(leaf, lambda h: store.get(h))
        assert result.status == ChainCollectStatus.UNREACHABLE
        assert result.unreachable_parent == HASH_MISSING

    def test_too_deep(self):
        """Self-referential cap exceeding max_depth → TOO_DEEP."""
        self_hash = bytes([ALG_ECFV1_SHA256]) + b"self_l" + b"\x00" * 26
        loop = {
            "type": "system/capability/token",
            "data": {"granter": HASH_BOB, "parent": self_hash, "grants": []},
            "content_hash": self_hash,
        }
        result = collect_authority_chain(
            loop, lambda h: loop if h == self_hash else None, max_depth=3,
        )
        assert result.status == ChainCollectStatus.TOO_DEEP
        assert result.chain == []

    def test_too_deep_surfaces_chain_depth_exceeded_code(self):
        """V7 §4.10(b) (v7.75): an over-deep chain yields error_code
        ``chain_depth_exceeded`` so the dispatcher routes it to 400, NOT the
        generic 403 (Keystone V7.75 ruling — a too-deep chain is a
        client-correctable structural excess, not an authz verdict)."""
        self_hash = bytes([ALG_ECFV1_SHA256]) + b"deep_l" + b"\x00" * 26
        loop = {
            "type": "system/capability/token",
            "data": {"granter": HASH_BOB, "parent": self_hash, "grants": []},
            "content_hash": self_hash,
        }
        result = verify_capability_chain(
            loop,
            lambda h: loop if h == self_hash else None,
            lambda target: None,
            "local-peer",
            int(time.time() * 1000),
            find_signature_by_signer=lambda target, signer: None,
        )
        assert result.valid is False
        assert result.error_code == "chain_depth_exceeded"


class TestCheckCreatorAuthority:
    """Tests for `check_creator_authority` per PROPOSAL-UNIFIED-CHAIN-WALK §3.2.

    Replaces the retired `identity_in_authority_chain`. Combines chain
    collection + identity lookup; returns chain alongside the result so
    callers can persist without re-walking. Per §3.2: persistence runs
    only when found=True (caller responsibility, not enforced by helper).
    """

    def test_root_granter_match(self):
        """Writer is the root granter — found, chain = [root]."""
        cap = _root_cap(HASH_ALICE)
        result = check_creator_authority(cap, HASH_ALICE, lambda h: None)
        assert result.status == ChainCollectStatus.OK
        assert result.found
        assert result.chain == [cap]

    def test_root_granter_no_match(self):
        """Writer not in chain — found=False, chain still returned."""
        cap = _root_cap(HASH_ALICE)
        result = check_creator_authority(cap, HASH_BOB, lambda h: None)
        assert result.status == ChainCollectStatus.OK
        assert not result.found
        # Chain returned but caller MUST NOT persist on found=False (§3.2).
        assert result.chain == [cap]

    def test_match_at_leaf_with_full_chain(self):
        """Writer matches leaf granter; chain valid → found, full chain returned."""
        root_hash = bytes([ALG_ECFV1_SHA256]) + b"root_h" + b"\x00" * 26
        leaf_hash = bytes([ALG_ECFV1_SHA256]) + b"leaf_h" + b"\x00" * 26
        root = _root_cap(HASH_ALICE, content_hash=root_hash)
        leaf = _delegated_cap(HASH_BOB, root_hash, leaf_hash)
        result = check_creator_authority(
            leaf, HASH_BOB, lambda h: root if h == root_hash else None,
        )
        assert result.status == ChainCollectStatus.OK
        assert result.found
        assert len(result.chain) == 2

    def test_match_at_root_via_walk(self):
        """Writer matches root granter; walker traversed one parent → found."""
        root_hash = bytes([ALG_ECFV1_SHA256]) + b"root_h" + b"\x00" * 26
        leaf_hash = bytes([ALG_ECFV1_SHA256]) + b"leaf_h" + b"\x00" * 26
        root = _root_cap(HASH_ALICE, content_hash=root_hash)
        leaf = _delegated_cap(HASH_BOB, root_hash, leaf_hash)
        result = check_creator_authority(
            leaf, HASH_ALICE, lambda h: root if h == root_hash else None,
        )
        assert result.found
        assert len(result.chain) == 2

    def test_unreachable_supersedes_leaf_match(self):
        """Vector 4 regression: leaf granter matches writer, parent unreachable.
        Walker errors before identity check runs → status != OK, found=False."""
        leaf_hash = bytes([ALG_ECFV1_SHA256]) + b"leaf_h" + b"\x00" * 26
        leaf = _delegated_cap(HASH_BOB, HASH_MISSING, leaf_hash)
        result = check_creator_authority(leaf, HASH_BOB, lambda h: None)
        assert result.status == ChainCollectStatus.UNREACHABLE
        assert not result.found
        assert result.chain == []  # nothing to persist on rejection
        assert result.unreachable_parent == HASH_MISSING

    def test_writer_not_in_full_valid_chain(self):
        """Writer absent from a fully-walkable chain — found=False, chain returned."""
        root_hash = bytes([ALG_ECFV1_SHA256]) + b"root_h" + b"\x00" * 26
        leaf_hash = bytes([ALG_ECFV1_SHA256]) + b"leaf_h" + b"\x00" * 26
        root = _root_cap(HASH_ALICE, content_hash=root_hash)
        leaf = _delegated_cap(HASH_BOB, root_hash, leaf_hash)
        result = check_creator_authority(
            leaf, HASH_MALLORY, lambda h: root if h == root_hash else None,
        )
        assert result.status == ChainCollectStatus.OK
        assert not result.found
        assert len(result.chain) == 2  # full chain still returned for diagnostics

# --- collect_chain_bundle (EXTENSION-CONTINUATION §4.3 dispatch bundle) ---

from entity_core.crypto.identity import peer_id_from_public_key_bytes as _pid_from_pk

_PEER_B_PUBKEY = b"\x01" * 32
_INSTALLER_PUBKEY = b"\x02" * 32
_PEER_B_ID = _pid_from_pk(_PEER_B_PUBKEY)
_INSTALLER_ID = _pid_from_pk(_INSTALLER_PUBKEY)
_BID_HASH = bytes([ALG_ECFV1_SHA256]) + b"b_idnt" + b"\x00" * 26
_IID_HASH = bytes([ALG_ECFV1_SHA256]) + b"i_idnt" + b"\x00" * 26


def _peer_identity(pubkey: bytes, content_hash: bytes) -> dict:
    # v7.65 §2: system/peer data = (public_key, key_type) only.
    return {
        "type": "system/peer",
        "data": {"public_key": pubkey, "key_type": "ed25519"},
        "content_hash": content_hash,
    }


def _sig(target: bytes, signer: bytes, content_hash: bytes) -> dict:
    return {
        "type": "system/signature",
        "data": {"target": target, "signer": signer, "signature": b"\x00" * 64},
        "content_hash": content_hash,
    }


class TestCollectChainBundle:
    """`collect_chain_bundle` — the §4.3 dispatch chain-walk + bundle helper.

    Gathers leaf→root caps + each link's granter identity + the signature
    bound at the V7 invariant pointer path, for cross-peer transport.
    Python analog of Go `capability.CollectChainBundle`.
    """

    def _setup(self):
        root_h = bytes([ALG_ECFV1_SHA256]) + b"rootc_" + b"\x00" * 26
        leaf_h = bytes([ALG_ECFV1_SHA256]) + b"leafc_" + b"\x00" * 26
        # root granter = peer B (B-rooted); leaf granter = installer.
        root = _root_cap(_BID_HASH, content_hash=root_h)
        leaf = _delegated_cap(_IID_HASH, root_h, leaf_h)
        b_id = _peer_identity(_PEER_B_PUBKEY, _BID_HASH)
        i_id = _peer_identity(_INSTALLER_PUBKEY, _IID_HASH)
        rsig_h = bytes([ALG_ECFV1_SHA256]) + b"rootsg" + b"\x00" * 26
        lsig_h = bytes([ALG_ECFV1_SHA256]) + b"leafsg" + b"\x00" * 26
        root_sig = _sig(root_h, _BID_HASH, rsig_h)
        leaf_sig = _sig(leaf_h, _IID_HASH, lsig_h)
        store = {root_h: root, leaf_h: leaf, _BID_HASH: b_id, _IID_HASH: i_id}
        sigs = {(_PEER_B_ID, root_h): root_sig, (_INSTALLER_ID, leaf_h): leaf_sig}
        return leaf, store, sigs

    def test_full_bundle_caps_identities_signatures(self):
        leaf, store, sigs = self._setup()
        bundle = collect_chain_bundle(
            leaf,
            entity_lookup=lambda h: store.get(h),
            bound_signature_lookup=lambda pid, t: sigs.get((pid, t)),
        )
        types = sorted(e["type"] for e in bundle)
        # 2 caps + 2 granter identities + 2 bound signatures, deduped.
        assert types == [
            "system/capability/token", "system/capability/token",
            "system/peer", "system/peer",
            "system/signature", "system/signature",
        ]

    def test_best_effort_omits_unresolvable_signature(self):
        """A link whose signature isn't locally resolvable is omitted;
        caps + identities still travel (verifier fails closed if needed)."""
        leaf, store, _ = self._setup()
        bundle = collect_chain_bundle(
            leaf,
            entity_lookup=lambda h: store.get(h),
            bound_signature_lookup=lambda pid, t: None,  # no sigs resolvable
        )
        types = sorted(e["type"] for e in bundle)
        assert "system/signature" not in types
        assert types.count("system/capability/token") == 2
        assert types.count("system/peer") == 2

    def test_unreachable_chain_returns_empty(self):
        """Leaf chain unreachable (parent missing) → empty bundle."""
        leaf, _, sigs = self._setup()
        bundle = collect_chain_bundle(
            leaf,
            entity_lookup=lambda h: None,  # parent unresolvable
            bound_signature_lookup=lambda pid, t: sigs.get((pid, t)),
        )
        assert bundle == []

    def test_dedup_by_content_hash(self):
        """Shared parent / repeated identity collapses by content hash."""
        leaf, store, sigs = self._setup()
        bundle = collect_chain_bundle(
            leaf,
            entity_lookup=lambda h: store.get(h),
            bound_signature_lookup=lambda pid, t: sigs.get((pid, t)),
        )
        hashes = [e["content_hash"] for e in bundle]
        assert len(hashes) == len(set(hashes))


class TestMalformedResourcePatternFailClosed:
    """V7 §1.11 fail-closed (F5) — a capability whose GRANT carries a malformed
    resource pattern (reserved `../` / `./`, ambiguous `*/`) must produce a
    deterministic DENY verdict, never an exception that drops the connection.

    This is the `chain_malformed_resource_pattern` cross-impl probe (the one
    that previously hung validate-peer for 60s). Go passes by treating
    canonicalize as a pure transform: the malformed pattern passes through
    unchanged, fails to match any canonical `/{peer_id}/...` target, and the
    grant simply does not cover the target -> clean DENY. Python diverged by
    raising ValueError inside canonicalize mid-check; this pins the fix."""

    PEER = "QmZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"  # >=46-char peer_id

    def _cap(self, resource_include):
        return {
            "grants": [
                {
                    "handlers": {"include": ["*"]},
                    "operations": {"include": ["*"]},
                    "resources": {"include": resource_include},
                }
            ]
        }

    def test_malformed_grant_pattern_denies_not_raises(self):
        from entity_core.capability.checking import check_resource_scope

        target = f"/{self.PEER}/local/files/doc.txt"
        for bad in ("../etc/passwd", "./rel", "*/local/files/*"):
            # Must return a verdict (DENY), not raise / crash.
            granted = check_resource_scope(
                self._cap([bad]),
                handler_pattern="*",
                operation="get",
                resource_targets=[target],
                resource_exclude=None,
                local_peer_id=self.PEER,
            )
            assert granted is False, f"malformed grant pattern {bad!r} must DENY"

    def test_malformed_grant_exclude_denies_not_raises(self):
        """A malformed pattern in the grant's EXCLUDE list must also be a
        verdict, not a crash (same canonicalize call path)."""
        from entity_core.capability.checking import check_resource_scope

        cap = self._cap(["*"])
        cap["grants"][0]["resources"]["exclude"] = ["../escape"]
        target = f"/{self.PEER}/local/files/doc.txt"
        # include "*" covers; malformed exclude passes through, matches nothing,
        # so the target stays covered -> ALLOW (and crucially, no exception).
        granted = check_resource_scope(
            cap, handler_pattern="*", operation="get",
            resource_targets=[target], resource_exclude=None,
            local_peer_id=self.PEER,
        )
        assert granted is True

    def test_valid_grant_pattern_still_grants(self):
        """Positive control: a well-formed grant pattern still covers."""
        from entity_core.capability.checking import check_resource_scope

        target = f"/{self.PEER}/local/files/doc.txt"
        granted = check_resource_scope(
            self._cap(["local/files/*"]),
            handler_pattern="*", operation="get",
            resource_targets=[target], resource_exclude=None,
            local_peer_id=self.PEER,
        )
        assert granted is True
