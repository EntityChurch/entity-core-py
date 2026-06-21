"""V7 v7.64 POL-DF-1..6 conformance vectors — capability policy dual-form.

Per `PROPOSAL-V7-POLICY-DUAL-FORM-PRE-CONFIGURATION.md` §2.7:

- POL-DF-1: hex match
- POL-DF-2: Base58 match (pre-configuration affordance)
- POL-DF-3: hex precedence over Base58 when both exist
- POL-DF-4: SHOULD canonicalize on Base58 match (Python opts in)
- POL-DF-5: no match → default
- POL-DF-6: invalid peer_pattern → 400 invalid_peer_pattern
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer.builder import PeerBuilder
from entity_core.protocol.auth import create_identity_entity
from entity_core.storage.emit import EmitContext
from entity_core.protocol.entity import Entity
from entity_handlers.capability import (
    CAPABILITY_HANDLER_PATTERN,
    capability_handler,
)


@pytest.fixture
def peer():
    kp = Keypair.generate()
    return PeerBuilder().with_keypair(kp).with_all_handlers().build()


def _full_access_cap() -> dict[str, object]:
    return {
        "grants": [{
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*", "/*/*"]},
            "operations": {"include": ["*"]},
            "peers": {"include": ["*"]},
        }]
    }


def _ctx(peer, caller_kp: Keypair) -> HandlerContext:
    caller_identity = create_identity_entity(caller_kp)
    caller_identity_hash = caller_identity.compute_hash()
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=caller_kp.peer_id,
        handler_grant=_full_access_cap(),
        caller_capability=_full_access_cap(),
        emit_pathway=peer.emit_pathway,
        keypair=peer.keypair,
        author_identity_hash=caller_identity_hash,
        remote_identity_hash=caller_identity_hash,
    )


def _put_policy_entry(peer, peer_pattern: str, grants: list[dict]) -> None:
    entry = Entity(
        type="system/capability/policy-entry",
        data={"peer_pattern": peer_pattern, "grants": grants},
    )
    peer.emit_pathway.emit(
        f"system/capability/policy/{peer_pattern}",
        entry,
        EmitContext.bootstrap(),
    )


def _narrow_grants() -> list[dict]:
    return [{
        "handlers": {"include": ["system/tree"]},
        "operations": {"include": ["get"]},
        "resources": {"include": ["app/*"]},
    }]


@pytest.mark.asyncio
async def test_pol_df_1_hex_match(peer) -> None:
    """Hex-form policy entry applies when the caller matches by content_hash."""
    caller_kp = Keypair.generate()
    caller_identity = create_identity_entity(caller_kp)
    caller_hex = caller_identity.compute_hash().hex()

    _put_policy_entry(peer, caller_hex, _narrow_grants())

    ctx = _ctx(peer, caller_kp)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": _narrow_grants()}}, ctx,
    )
    assert result["status"] == 200


@pytest.mark.asyncio
async def test_pol_df_2_base58_match(peer) -> None:
    """Base58-form policy entry applies when the caller connects."""
    caller_kp = Keypair.generate()

    _put_policy_entry(peer, caller_kp.peer_id, _narrow_grants())

    ctx = _ctx(peer, caller_kp)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": _narrow_grants()}}, ctx,
    )
    # Caller matched the Base58-form policy ceiling.
    assert result["status"] == 200


@pytest.mark.asyncio
async def test_pol_df_3_hex_takes_precedence_over_base58(peer) -> None:
    """If BOTH a hex-form AND a Base58-form entry exist for the same
    caller, the hex-form entry wins (§2.2 precedence)."""
    caller_kp = Keypair.generate()
    caller_identity = create_identity_entity(caller_kp)
    caller_hex = caller_identity.compute_hash().hex()

    # Hex form: narrow grants (allowed for the request).
    _put_policy_entry(peer, caller_hex, _narrow_grants())
    # Base58 form: empty grants (would block any request via the ceiling).
    _put_policy_entry(peer, caller_kp.peer_id, [])

    ctx = _ctx(peer, caller_kp)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": _narrow_grants()}}, ctx,
    )
    # Hex took precedence → request inside the ceiling → 200.
    assert result["status"] == 200


@pytest.mark.asyncio
async def test_pol_df_4_canonicalization_on_base58_match(peer) -> None:
    """§2.3 SHOULD: on Base58 match, the handler canonicalizes — writes
    a hex-form entry and deletes the Base58 entry. Python opts in."""
    caller_kp = Keypair.generate()
    caller_identity = create_identity_entity(caller_kp)
    caller_hex = caller_identity.compute_hash().hex()

    _put_policy_entry(peer, caller_kp.peer_id, _narrow_grants())
    base58_path = f"system/capability/policy/{caller_kp.peer_id}"
    hex_path = f"system/capability/policy/{caller_hex}"

    # Pre-state: only Base58 entry exists.
    assert peer.entity_tree.get(base58_path) is not None
    assert peer.entity_tree.get(hex_path) is None

    ctx = _ctx(peer, caller_kp)
    await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": _narrow_grants()}}, ctx,
    )

    # Post-state: hex-form written, Base58 deleted (canonicalized).
    assert peer.entity_tree.get(hex_path) is not None
    assert peer.entity_tree.get(base58_path) is None


@pytest.mark.asyncio
async def test_pol_df_5_no_match_falls_to_default(peer) -> None:
    """No specific entry → ``default`` applies."""
    caller_kp = Keypair.generate()
    _put_policy_entry(peer, "default", _narrow_grants())

    ctx = _ctx(peer, caller_kp)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": _narrow_grants()}}, ctx,
    )
    assert result["status"] == 200


@pytest.mark.asyncio
async def test_pol_df_6_invalid_peer_pattern_rejected(peer) -> None:
    """``configure`` MUST reject patterns that are neither hex nor Base58
    nor ``default`` with 400 ``invalid_peer_pattern``."""
    ctx = _ctx(peer, peer.keypair)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "configure",
        {"data": {"peer_pattern": "not-a-valid-pattern!@#$", "grants": []}},
        ctx,
    )
    assert result["status"] == 400
    assert result["result"]["data"]["code"] == "invalid_peer_pattern"


def test_peer_pattern_hex_width_is_format_relative() -> None:
    """V7 §3.5 / v7.70 §1.2 — the canonical-hex peer_pattern width is
    format-relative: 66 hex for ECFv1-SHA-256 (0x00 + 32B), 98 hex for
    ECFv1-SHA-384 (0x01 + 48B). The prior hardcoded 66 rejected a valid
    SHA-384 home peer's canonical hash (the cross-impl peer_pattern bug)."""
    from entity_handlers.capability import _valid_peer_pattern

    sha256_hex = "00" + "ab" * 32  # 66 hex, format byte 0x00
    sha384_hex = "01" + "cd" * 48  # 98 hex, format byte 0x01
    assert len(sha256_hex) == 66 and _valid_peer_pattern(sha256_hex)
    assert len(sha384_hex) == 98 and _valid_peer_pattern(sha384_hex)
    # Right width, unsupported format byte → rejected (fail closed).
    assert not _valid_peer_pattern("7e" + "00" * 32)
    # Supported format byte, wrong digest width → rejected.
    assert not _valid_peer_pattern("00" + "ab" * 31)  # 64 hex, SHA-256 short
    # Uppercase hex is not the canonical lowercase form.
    assert not _valid_peer_pattern(("01" + "cd" * 48).upper())


@pytest.mark.asyncio
async def test_configure_accepts_98_hex_sha384_pattern(peer) -> None:
    """``configure`` accepts a 98-hex SHA-384 canonical peer_pattern and
    writes the policy entry — the fix for the SHA-384 cross-impl FAIL
    (configure_writes_policy_entry / peer_pattern_1_canonical_match)."""
    ctx = _ctx(peer, peer.keypair)
    sha384_pattern = "01" + "cd" * 48
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "configure",
        {"data": {"peer_pattern": sha384_pattern, "grants": _narrow_grants()}},
        ctx,
    )
    assert result["status"] == 200
    assert result["result"]["data"]["status"] == "configured"
    # Entry is readable back at the format-relative path.
    tree = peer.emit_pathway.entity_tree
    assert tree.get(f"system/capability/policy/{sha384_pattern}") is not None
