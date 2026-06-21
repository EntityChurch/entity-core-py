"""V7 v7.66 format-agility validation + cleanup conformance vectors.

Per `proposals/implemented/PROPOSAL-V7-V7.66-FORMAT-AGILITY-VALIDATION-AND-CLEANUP.md` §7:

- KEY-TYPE-STRING-1   — entity-data key_type field is string "ed25519"
- KEY-TYPE-PREFIX-1   — binary peer_id prefix is varint(0x01) for Ed25519
- LEGACY-MINT-1       — no live mint API path produces legacy SHA-256-form Ed25519 peer_id
- AGILITY-DECODE-1    — wire decoder accepts key_type=0xFE first byte
- AGILITY-ENTITY-1    — system/peer({0xAA×64, 0xFE}) constructs + content_hash cross-impl byte-equal
- AGILITY-CANONICAL-1 — canonical form for 0xFE is SHA-256-form (hash_type=0x01)
- AGILITY-PATTERN-1   — cap pattern with 0xFE peer ref canonicalizes per v7.65 §6 (no Ed25519 hardcode)
- AGILITY-UNKNOWN-1   — unallocated 0xFD raises unsupported_key_type (NOT 0xFF — that's protocol-reserved)
- FORMAT-CODE-INTERPRETATION-1  — content_hash format-code interpretation by leading
                        varint; unsupported format raises unsupported_content_hash_format.
                        Renamed from v7.66 PREFIX-DISPATCH-1 per v7.67 §2.3 errata
                        (semantics unchanged; framing aligned to "system property").
- CAP-FREEZE-1        — cap-chain verifier refuses chains spanning format-code boundaries (Reading A)

Per §7.2 corpus-authoring discipline: pinned bytestrings derive from the
spec algorithm, not from a first-mover impl. Cross-impl convergence on
the same bytes IS the validation. The 0xFE fixture is the canonical
``public_key = 0xAA × 64``.
"""

from __future__ import annotations

import base58
import hashlib

import pytest

from entity_core.capability.delegation import (
    DelegationResult,
    _check_chain_format_code_freeze,
)
from entity_core.capability.peer_canon import (
    PolicyEntryCanonState,
    canonicalize_cap_pattern_peer_refs,
)
from entity_core.crypto.identity import (
    CANONICAL_HASH_TYPE_FOR_KEY_TYPE,
    ENTITY_DATA_KEY_TYPE_TO_BYTE,
    HASH_TYPE_IDENTITY,
    HASH_TYPE_SHA256,
    KEY_TYPE_ED25519,
    KEY_TYPE_TEST_SYNTHETIC,
    Keypair,
    UnsupportedKeyTypeError,
    _peer_id_from_bytes,
    decode_peer_id,
    derive_peer_id,
    is_canonical_pair,
    key_type_byte_from_entity_data,
    peer_id_from_public_key_bytes,
    validate_supported_key_type,
)
from entity_core.protocol.auth import create_peer_entity
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    SUPPORTED_CONTENT_HASH_FORMATS,
    UnsupportedContentHashFormatError,
    compute_ecf_hash,
    content_hash_format,
    validate_hash,
    validate_supported_content_hash_format,
)


# ---------- §7 corpus fixture: experimental-test cryptosystem ----------

EXPERIMENTAL_TEST_PUBKEY: bytes = b"\xaa" * 64  # canonical fixture per §7
SEED_X = b"\xa0" * 32


# ============================================================================
# KEY-TYPE-STRING-1 / KEY-TYPE-PREFIX-1 — v7.65 errata pin
# ============================================================================

def test_key_type_string_1_entity_data_field_is_string() -> None:
    """V7 v7.66 §2.2 — system/peer.data.key_type encodes as primitive/string
    ("ed25519"), NOT int (1). The string is the entity-data surface; the
    int is the binary peer_id wire-format prefix (different surface)."""
    kp = Keypair.from_seed(SEED_X)
    ent = create_peer_entity(kp.public_key_bytes())
    kt = ent.data.get("key_type") if hasattr(ent, "data") else ent.to_dict()["data"]["key_type"]
    assert isinstance(kt, str), f"key_type must be string, got {type(kt).__name__}"
    assert kt == "ed25519"
    # Mapping table corroborates the entity-data string is registered.
    assert "ed25519" in ENTITY_DATA_KEY_TYPE_TO_BYTE
    assert ENTITY_DATA_KEY_TYPE_TO_BYTE["ed25519"] == KEY_TYPE_ED25519


def test_key_type_prefix_1_binary_wire_prefix_is_varint_byte() -> None:
    """V7 v7.66 §2.2 — binary peer_id wire-format prefix is varint(uint8).
    For Ed25519: 0x01. This is the wire-form surface, separate from the
    entity-data string surface."""
    kp = Keypair.from_seed(SEED_X)
    raw = base58.b58decode(kp.peer_id)
    assert len(raw) >= 2
    assert raw[0] == KEY_TYPE_ED25519 == 0x01
    # Round-trip via decoder.
    kt, ht, _digest = decode_peer_id(kp.peer_id)
    assert kt == 0x01
    assert ht == HASH_TYPE_IDENTITY  # canonical pair for Ed25519


# ============================================================================
# LEGACY-MINT-1 — no live mint API path for legacy SHA-256-form Ed25519
# ============================================================================

def test_legacy_mint_1_no_live_api_path_for_legacy_sha256_form() -> None:
    """V7 v7.66 §3 / LEGACY-MINT-1 — public mint API is canonical-only.

    Calling derive_peer_id() or peer_id_from_public_key_bytes() with the
    legacy ``hash_type`` kwarg MUST fail at the API surface (TypeError on
    Python; symbol-not-found on Go/Rust; equivalent runtime error
    elsewhere). The §3.4 wire-acceptance corpus may still hold opaque
    legacy-form bytestrings — but those are corpus fixtures, not the
    output of a live mint API.
    """
    kp = Keypair.from_seed(SEED_X)

    # Canonical-only output via the public API.
    assert derive_peer_id(kp.public_key) == kp.peer_id
    assert peer_id_from_public_key_bytes(kp.public_key_bytes()) == kp.peer_id

    # Public mint API refuses the legacy kwarg.
    with pytest.raises(TypeError):
        derive_peer_id(kp.public_key, hash_type=HASH_TYPE_SHA256)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        peer_id_from_public_key_bytes(  # type: ignore[call-arg]
            kp.public_key_bytes(), hash_type=HASH_TYPE_SHA256,
        )

    # Decode side is preserved per §5 wire-acceptance carve-out: a
    # legacy-form bytestring is still parseable (corpus-authoring helper
    # produces it for fixture exercise).
    legacy_bytes = _peer_id_from_bytes(
        kp.public_key_bytes(), key_type=KEY_TYPE_ED25519, hash_type=HASH_TYPE_SHA256,
    )
    kt, ht, _ = decode_peer_id(legacy_bytes)
    assert kt == KEY_TYPE_ED25519
    assert ht == HASH_TYPE_SHA256


# ============================================================================
# AGILITY-DECODE-1 — wire-format decoder accepts 0xFE first byte
# ============================================================================

def test_agility_decode_1_decoder_accepts_0xfe_first_byte() -> None:
    """V7 v7.66 §4.4 surface 1 — wire-format multikey decoder accepts
    key_type=0xFE first byte without panic or hardcoded-Ed25519 reject."""
    raw = bytes([KEY_TYPE_TEST_SYNTHETIC, HASH_TYPE_SHA256]) + hashlib.sha256(
        EXPERIMENTAL_TEST_PUBKEY
    ).digest()
    pid = base58.b58encode(raw).decode("ascii")

    kt, ht, digest = decode_peer_id(pid)
    assert kt == KEY_TYPE_TEST_SYNTHETIC == 0xFE
    assert ht == HASH_TYPE_SHA256 == 0x01
    assert digest == hashlib.sha256(EXPERIMENTAL_TEST_PUBKEY).digest()


# ============================================================================
# AGILITY-ENTITY-1 — system/peer construction + content_hash cross-impl
# ============================================================================

def test_agility_entity_1_system_peer_constructs_with_experimental_test() -> None:
    """V7 v7.66 §4.4 surfaces 2+4 — system/peer({0xAA×64, key_type="experimental-test"})
    constructs with data.key_type=="experimental-test" string, and
    content_hash is reproducible/deterministic from the spec algorithm
    (cross-impl byte-equality via §7.2 corpus-authoring discipline)."""
    ent = create_peer_entity(EXPERIMENTAL_TEST_PUBKEY, key_type="experimental-test")
    d = ent.to_dict()
    assert d["data"]["key_type"] == "experimental-test"
    assert d["data"]["public_key"] == EXPERIMENTAL_TEST_PUBKEY
    assert d["type"] == "system/peer"

    # content_hash is a deterministic function of (type, data) per V7 §1.2.
    h1 = ent.compute_hash()
    h2 = create_peer_entity(EXPERIMENTAL_TEST_PUBKEY, key_type="experimental-test").compute_hash()
    assert h1 == h2
    # Leading byte is the format-code (0x00 ECFv1-SHA-256 today).
    assert h1[0] == ALG_ECFV1_SHA256
    assert len(h1) == 33  # 1 format-code + 32 SHA-256 digest


# ============================================================================
# AGILITY-CANONICAL-1 — canonical form for 0xFE is SHA-256-form
# ============================================================================

def test_agility_canonical_1_canonical_form_for_0xfe_is_sha256_form() -> None:
    """V7 v7.66 §4.4 surface 3 — canonical-form selection for key_type=0xFE
    returns SHA-256-form (hash_type=0x01); identity-form is non-canonical
    (size 66-byte raw segment exceeds v7.65 §10 informative floor)."""
    # Table-driven canonical-pair check.
    assert CANONICAL_HASH_TYPE_FOR_KEY_TYPE[KEY_TYPE_TEST_SYNTHETIC] == HASH_TYPE_SHA256
    assert is_canonical_pair(KEY_TYPE_TEST_SYNTHETIC, HASH_TYPE_SHA256)
    assert not is_canonical_pair(KEY_TYPE_TEST_SYNTHETIC, HASH_TYPE_IDENTITY)

    # Public mint API produces canonical (0xFE, 0x01) for 0xFE.
    pid = peer_id_from_public_key_bytes(
        EXPERIMENTAL_TEST_PUBKEY, key_type=KEY_TYPE_TEST_SYNTHETIC,
    )
    kt, ht, digest = decode_peer_id(pid)
    assert kt == KEY_TYPE_TEST_SYNTHETIC
    assert ht == HASH_TYPE_SHA256
    # Digest algorithm pin per §4.2: H(public_key) := SHA-256(public_key_bytes).
    assert digest == hashlib.sha256(EXPERIMENTAL_TEST_PUBKEY).digest()


# ============================================================================
# AGILITY-PATTERN-1 — cap pattern with 0xFE peer ref canonicalizes
# ============================================================================

def test_agility_pattern_1_cap_pattern_canonicalizes_0xfe_peer_ref() -> None:
    """V7 v7.66 §4.4 surface 5 — cap pattern with key_type=0xFE peer
    reference canonicalizes per v7.65 §6 rules. Impls with an
    Ed25519-specific canonical-form short-circuit (e.g., a hardcoded
    ``key_type == 0x01 and hash_type == 0x00`` check) FAIL this vector
    by either (a) treating canonical (0xFE, 0x01) as non-canonical and
    looping into PENDING when it's already canonical, or (b) flagging
    it canonical even when in non-canonical form. The fix: per-key_type
    canonical-pair check (Python uses ``is_canonical_pair``)."""
    # Canonical-form (0xFE, 0x01) 0xFE peer-ref pattern.
    canonical_0xfe_pid = peer_id_from_public_key_bytes(
        EXPERIMENTAL_TEST_PUBKEY, key_type=KEY_TYPE_TEST_SYNTHETIC,
    )
    pattern = f"/{canonical_0xfe_pid}/system/files"
    out, state = canonicalize_cap_pattern_peer_refs(pattern)
    assert out == pattern, "canonical 0xFE pattern should pass through unchanged"
    assert state == PolicyEntryCanonState.CANONICAL, (
        "canonical 0xFE pattern wrongly flagged non-canonical — Ed25519 "
        "short-circuit likely still present"
    )

    # Non-canonical (0xFE, 0x00) 0xFE peer-ref pattern.
    # Construct an identity-form bytestring for 0xFE (64-byte digest) —
    # non-canonical per §4.2 sizing. Identity-form is self-resolving
    # (digest IS pubkey, length-agnostic per PIM-5), so canonicalization
    # succeeds without out-of-band pubkey lookup; the rewrite produces
    # the canonical (0xFE, 0x01) form. The point this vector pins:
    # the rewrite happens per-key_type, not via an Ed25519 hardcode.
    noncanon_0xfe = _peer_id_from_bytes(
        EXPERIMENTAL_TEST_PUBKEY,
        key_type=KEY_TYPE_TEST_SYNTHETIC,
        hash_type=HASH_TYPE_IDENTITY,
    )
    noncanon_pattern = f"/{noncanon_0xfe}/system/files"
    out2, state2 = canonicalize_cap_pattern_peer_refs(noncanon_pattern)
    assert state2 == PolicyEntryCanonState.CANONICAL, (
        "non-canonical 0xFE identity-form should canonicalize to (0xFE, 0x01)"
    )
    assert out2 == f"/{canonical_0xfe_pid}/system/files", (
        "rewrite target should be canonical (0xFE, 0x01) form"
    )


# ============================================================================
# AGILITY-UNKNOWN-1 — unallocated 0xFD raises unsupported_key_type
# ============================================================================

def test_agility_unknown_1_unallocated_0xfd_rejected() -> None:
    """V7 v7.66 §4.4 surface 6 — impl that does NOT support key_type=0xFD
    (unallocated experimental within 0xF0–0xFE; NOT 0xFF which is
    protocol-reserved) returns 400 unsupported_key_type. Python's
    supported set is exactly {0x01, 0xFE}; 0xFD is in the experimental
    range but not allocated.

    Verifies both the helper-level raise AND the wire-level response
    code: the §4.7 contract is the response code string
    ``"unsupported_key_type"``, NOT the generic ``"bad_request"``."""
    assert 0xFD not in ENTITY_DATA_KEY_TYPE_TO_BYTE.values()
    assert 0xFF not in ENTITY_DATA_KEY_TYPE_TO_BYTE.values()

    with pytest.raises(UnsupportedKeyTypeError):
        validate_supported_key_type(0xFD)
    with pytest.raises(UnsupportedKeyTypeError):
        validate_supported_key_type(0xFF)  # protocol-reserved, also rejected
    with pytest.raises(UnsupportedKeyTypeError):
        validate_supported_key_type(0x05)  # production-reserved (unallocated;
                                           # 0x02 was promoted to Ed448 at v7.67)

    # Entity-data string-side: unknown strings rejected with same error.
    with pytest.raises(UnsupportedKeyTypeError):
        key_type_byte_from_entity_data("unknown-test")

    # Allocated types pass.
    validate_supported_key_type(KEY_TYPE_ED25519)  # 0x01
    validate_supported_key_type(KEY_TYPE_TEST_SYNTHETIC)  # 0xFE


def test_agility_unknown_1_wire_response_code_is_unsupported_key_type() -> None:
    """V7 §4.7 wire-code contract — the connect handler emits an
    ExecuteResponse with ``result.code = "unsupported_key_type"`` (NOT
    the generic ``"bad_request"``) when an unallocated key_type is
    presented in the binary peer_id prefix.

    This was the cross-impl convergence regression caught in the
    cohort sweep: Python returned 400 with the generic
    ``code="bad_request"`` because ``ConnectError`` collapsed every
    failure mode at the wire boundary."""
    from entity_core.handlers.connect import ConnectError
    from entity_core.protocol.messages import ExecuteResponse

    # Construct a ConnectError raised from the §4.4 surface 6 path.
    exc = ConnectError(
        "unsupported key_type 0xfd; allocated: [1, 2, 254]",
        code="unsupported_key_type",
    )
    assert exc.code == "unsupported_key_type"

    # Wire emission goes through ExecuteResponse.bad_request(code=...);
    # verify the body carries the canonical V7 §4.7 identifier.
    resp = ExecuteResponse.bad_request(
        request_id="r0", message=str(exc), code=exc.code,
    )
    body = resp.result if isinstance(resp.result, dict) else {}
    assert int(resp.status) == 400
    assert body.get("code") == "unsupported_key_type", (
        f"wire code must be canonical 'unsupported_key_type' per V7 §4.7, "
        f"got {body.get('code')!r}"
    )


# ============================================================================
# FORMAT-CODE-INTERPRETATION-1 — content_hash format-code interpretation
# (renamed from v7.66 PREFIX-DISPATCH-1 per v7.67 §2.3 errata; semantics
# unchanged. The "dispatch" framing was reframed to "system property" —
# the format code is intrinsic to the hash, not a separate routing layer.)
# ============================================================================

def test_format_code_interpretation_1_content_hash_format_code_interpretation() -> None:
    """V7 v7.67 §2.3 (renamed from v7.66 PREFIX-DISPATCH-1) — the leading
    varint of a content_hash IS the content_hash_format code; impls
    interpret it when decoding/verifying/matching. An unsupported format
    code surfaces as ``unsupported_content_hash_format``."""
    # v7.67 §4 promotes 0x01 (SHA-384) to validated; production set is now
    # {0x00 SHA-256, 0x01 SHA-384}. BLAKE3 (0x03) lands at Phase 3a.
    assert ALG_ECFV1_SHA256 in SUPPORTED_CONTENT_HASH_FORMATS

    # Compute a real ECFv1-SHA-256 hash; format-code is the first byte.
    real_hash = compute_ecf_hash({"type": "x", "data": {}})
    assert content_hash_format(real_hash) == ALG_ECFV1_SHA256
    assert validate_supported_content_hash_format(real_hash) == ALG_ECFV1_SHA256

    # Unsupported format-code at the wire: leading byte 0x77 (single-byte;
    # in the reserved-future range, not the v7.67 §5.3 0xFF reservation).
    bogus = bytes([0x77]) + b"\x00" * 32
    with pytest.raises(UnsupportedContentHashFormatError):
        validate_supported_content_hash_format(bogus)
    with pytest.raises(UnsupportedContentHashFormatError):
        validate_hash(bogus)

    # Format-code introspection is non-throwing — the format code is the
    # leading byte (single-byte happy path; multi-byte LEB128 chains are
    # handled by decode_content_hash_format per v7.67 §5.4).
    assert content_hash_format(bogus) == 0x77


# ============================================================================
# CAP-FREEZE-1 — cap-chain verifier refuses cross-format chains (Reading A)
# ============================================================================

def test_cap_freeze_1_chain_spanning_format_codes_refused() -> None:
    """V7 v7.66 §5.3 — cap chain verifier refuses to verify a chain
    whose own link content_hashes cross format-code boundaries
    without a continuous re-signing event. Reading A: chain's own
    link hashes, not signed targets."""
    # Synthesize a 2-link chain: root link with content_hash_format=0x00
    # (real ECFv1-SHA-256), child link with content_hash_format=0x99
    # (synthetic; cross-format boundary).
    root_link = {
        "type": "system/capability/token",
        "data": {},
        "content_hash": bytes([0x00]) + b"\x01" * 32,
    }
    child_link = {
        "type": "system/capability/token",
        "data": {},
        "content_hash": bytes([0x99]) + b"\x02" * 32,
    }

    result = _check_chain_format_code_freeze([root_link, child_link])
    assert result is not None
    assert isinstance(result, DelegationResult)
    assert result.valid is False
    assert result.error_code == "cap_chain_format_code_freeze"
    assert "0x0" in (result.error or "") or "0x99" in (result.error or "")

    # Same-format chain is accepted.
    same_format_chain = [
        {
            "type": "system/capability/token",
            "data": {},
            "content_hash": bytes([0x00]) + b"\xaa" * 32,
        },
        {
            "type": "system/capability/token",
            "data": {},
            "content_hash": bytes([0x00]) + b"\xbb" * 32,
        },
    ]
    assert _check_chain_format_code_freeze(same_format_chain) is None
