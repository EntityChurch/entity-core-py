"""V7 v7.67 Phase 1 — Ed448 + SHA-384 baseline conformance vectors.

Per `proposals/implemented/PROPOSAL-V7-V7.67-CRYPTO-AGILITY-SEED-TABLES.md`
§7 (vectors) + the V7.67 impl-team alignment §3 (Phase 1 scope):

- KEY-TYPE-ED448-1   — system/peer({pubkey, key_type="ed448"}) constructs
                        canonical-form (0x02, 0x01) peer_id; sign/verify
                        round-trip from a fixed Ed448 seed; canonical
                        peer_id digest is SHA-256(pubkey) per §3.2.
- HASH-FORMAT-SHA-384-1 — content_hash under format=0x01 (SHA-384) is
                        49 bytes (1-byte varint + 48-byte digest); ECF
                        bytes inherit from canonical v7.66 fixture; the
                        digest is hashlib.sha384(ECF({type, data})).
- VARINT-MULTIBYTE-1 — multi-byte LEB128 decode per §5.4 mandatory.
                        Format-code varint 0x80 0x01 (value 128) decodes
                        cleanly but is unallocated → rejects with
                        unsupported_content_hash_format. Confirms the
                        decoder walks the chain instead of treating 0x80
                        as a malformed single byte.
- VARINT-RESERVED-FF-1 — value 255 is reserved on BOTH axes per §5.3
                        (mirror of v7.66 key_type reservation). Impl
                        rejects construction with key_type=0xFF AND with
                        content_hash_format=0xFF.
- FORMAT-CODE-INTERPRETATION-1 — see test_v7_66_format_agility.py;
                        renamed in place from PREFIX-DISPATCH-1 per §2.3
                        errata. Semantics unchanged; not duplicated here.

Per §7.6 corpus-authoring discipline (carry-over from v7.66 §7.2): pinned
bytestring values derive from the SPEC ALGORITHM, not from whichever impl
writes first. The Ed448 seed below is a placeholder pending arch's
corpus authoring (per IMPL-TEAM-ALIGNMENT §3.4 lock gate: cross-impl
byte-equal sign/verify on the corpus-pinned seed is the Phase 1 gate).
Until that seed lands, the Phase 1 lock gate stays at "Python-side
self-consistency" for KEY-TYPE-ED448-1; cross-impl byte-equality runs
once the corpus fixture is published.
"""

from __future__ import annotations

import hashlib

import pytest

from entity_core.crypto.ed448 import (
    ED448_PUBKEY_LEN,
    ED448_SEED_LEN,
    ED448_SIGNATURE_LEN,
    Ed448Keypair,
    ed448_public_key_from_bytes,
    verify_ed448_signature,
)
from entity_core.crypto.identity import (
    CANONICAL_HASH_TYPE_FOR_KEY_TYPE,
    ENTITY_DATA_KEY_TYPE_TO_BYTE,
    HASH_TYPE_SHA256,
    KEY_TYPE_ED448,
    UnsupportedKeyTypeError,
    decode_peer_id,
    is_canonical_pair,
    key_type_byte_from_entity_data,
    validate_supported_key_type,
)
from entity_core.protocol.auth import create_peer_entity
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    ALG_ECFV1_SHA384,
    DIGEST_SIZES,
    SUPPORTED_CONTENT_HASH_FORMATS,
    UnsupportedContentHashFormatError,
    compute_ecf_hash,
    content_hash_format,
    decode_content_hash_format,
    ecf_encode,
    hash_to_display,
    validate_content_hash_format_code,
    validate_hash,
    validate_supported_content_hash_format,
)
from entity_core.utils.varint import decode_leb128, encode_leb128


# ---------- §7 corpus fixture: Ed448 cohort cross-impl pin ----------
#
# Cohort-agreed Phase 1 fixture (Rust at 2c81a20; Go adopted the pin;
# Python swaps to match). The seed is the all-0x42 57-byte string and the
# message is a fixed ASCII byte string. Cross-impl byte-equal sign/verify
# on THIS seed/message is the Phase 1 lock gate per IMPL-TEAM-ALIGNMENT
# §3.4 — see the V7.67 phase-1 cohort cross-impl pin
# for the three-way byte dump. The pinned hex below is asserted by
# test_key_type_ed448_1_cohort_byte_pin so any drift fails loudly.
ED448_TEST_SEED: bytes = bytes([0x42]) * ED448_SEED_LEN
ED448_COHORT_MESSAGE: bytes = b"v7.67 Phase 1 cohort cross-impl Ed448 fixture"

# Inherits v7.66 canonical fixture for the SHA-384 vector — same ECF bytes,
# re-hashed under format=0x01.
EXPERIMENTAL_TEST_PUBKEY: bytes = b"\xaa" * 64


# ============================================================================
# KEY-TYPE-ED448-1 — Ed448 (key_type=0x02) allocation
# ============================================================================

def test_key_type_ed448_1_seed_table_and_canonical_pair() -> None:
    """V7 v7.67 §3.1/§3.2/§3.3 — Ed448 lands at key_type=0x02 with entity-data
    string "ed448" and canonical pair (0x02, 0x01) SHA-256-form."""
    # §3.3 entity-data string → wire-prefix byte mapping
    assert ENTITY_DATA_KEY_TYPE_TO_BYTE["ed448"] == 0x02
    assert key_type_byte_from_entity_data("ed448") == KEY_TYPE_ED448

    # §3.2 canonical pair selection
    assert CANONICAL_HASH_TYPE_FOR_KEY_TYPE[KEY_TYPE_ED448] == HASH_TYPE_SHA256
    assert is_canonical_pair(KEY_TYPE_ED448, HASH_TYPE_SHA256)
    assert not is_canonical_pair(KEY_TYPE_ED448, 0x00)  # identity-form non-canonical (size-forced)

    # §3.1 promotion from production-reserved to validated: 0x02 is now allocated.
    validate_supported_key_type(KEY_TYPE_ED448)  # does not raise


def test_key_type_ed448_1_peer_id_construction_and_sign_verify() -> None:
    """V7 v7.67 §3.2 + IMPL-TEAM-ALIGNMENT §3.1 — Ed448Keypair.from_seed
    produces a 57-byte pubkey, 114-byte signature, and canonical
    (0x02, 0x01) peer_id whose digest is SHA-256(pubkey)."""
    kp = Ed448Keypair.from_seed(ED448_TEST_SEED)

    # §3.1 size pins
    assert len(kp.public_key_bytes()) == ED448_PUBKEY_LEN == 57
    sig = kp.sign(ED448_COHORT_MESSAGE)
    assert len(sig) == ED448_SIGNATURE_LEN == 114

    # §3.2 canonical-form peer_id: (0x02, 0x01) || SHA-256(pubkey)
    kt, ht, digest = decode_peer_id(kp.peer_id)
    assert kt == KEY_TYPE_ED448 == 0x02
    assert ht == HASH_TYPE_SHA256 == 0x01
    assert digest == hashlib.sha256(kp.public_key_bytes()).digest()
    assert len(digest) == 32

    # Determinism: same seed → same pubkey → same peer_id
    kp2 = Ed448Keypair.from_seed(ED448_TEST_SEED)
    assert kp2.public_key_bytes() == kp.public_key_bytes()
    assert kp2.peer_id == kp.peer_id

    # Sign/verify round-trip
    assert verify_ed448_signature(kp.public_key, ED448_COHORT_MESSAGE, sig)
    # Tamper-rejection (verify fails on altered message)
    assert not verify_ed448_signature(kp.public_key, b"tampered", sig)
    # Pubkey reload from raw bytes
    pk = ed448_public_key_from_bytes(kp.public_key_bytes())
    assert verify_ed448_signature(pk, ED448_COHORT_MESSAGE, sig)


def test_key_type_ed448_1_cohort_byte_pin() -> None:
    """V7 v7.67 §7.6 + IMPL-TEAM-ALIGNMENT §3.4 — byte-equal cross-impl pin.

    These are the exact bytes the cohort compares across Rust/Go/Python on
    the agreed seed (0x42 × 57) and fixed message. A mismatch on any line is
    a Phase 1 lock-gate failure — see the byte dump in
    the V7.67 phase-1 cohort cross-impl pin.
    Ed448 from a fixed seed is fully deterministic (RFC 8032, no per-sig
    nonce), so the signature is pinnable too — unlike ECDSA.
    """
    kp = Ed448Keypair.from_seed(ED448_TEST_SEED)
    pub = kp.public_key_bytes()
    sig = kp.sign(ED448_COHORT_MESSAGE)

    assert pub.hex() == (
        "2601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f24"
        "6b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00"
    )
    assert kp.peer_id == "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4"
    assert sig.hex() == (
        "0aff7a36b2b5e7502f9a133bc9ed39316284f0be738e2485546b33fda60966b1"
        "9ac0e3424ed549072af7ac5caa6d695c3e1e6412207cecaf8085444fbf062cb5"
        "271ea6d127c6c87327e1e20793f2b10341d04bd4bed32e220eca1b2255cc8aa4"
        "d2a0c8304d67e6f20e814b90411049b33400"
    )
    # system/peer content_hash (33 B, default SHA-256 format 0x00)
    ch = create_peer_entity(pub, key_type="ed448").compute_hash()
    assert ch.hex() == (
        "002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c70748"
    )


def test_key_type_ed448_1_system_peer_entity_carries_ed448_string() -> None:
    """V7 v7.67 §3.3 — system/peer({public_key, key_type="ed448"}) entity
    carries the string ``"ed448"`` in ``data.key_type`` (NOT 0x02 — the
    binary prefix lives in the wire peer_id, not the entity data)."""
    kp = Ed448Keypair.from_seed(ED448_TEST_SEED)
    ent = create_peer_entity(kp.public_key_bytes(), key_type="ed448")
    d = ent.to_dict()
    assert d["data"]["key_type"] == "ed448"
    assert d["data"]["public_key"] == kp.public_key_bytes()
    assert d["type"] == "system/peer"

    # Deterministic content_hash from (pubkey, key_type=string) — pure
    # function per v7.65 §2 (peer_id has exited the hashable basis).
    h1 = ent.compute_hash()
    h2 = create_peer_entity(kp.public_key_bytes(), key_type="ed448").compute_hash()
    assert h1 == h2
    # Default format-code remains 0x00 SHA-256 (Phase 1 does not change the
    # peer-entity hash format; SHA-384 is exercised by HASH-FORMAT-SHA-384-1).
    assert h1[0] == ALG_ECFV1_SHA256


# ============================================================================
# HASH-FORMAT-SHA-384-1 — content_hash_format=0x01 SHA-384 allocation
# ============================================================================

def test_hash_format_sha_384_1_supported_set_and_sizes() -> None:
    """V7 v7.67 §4.1/§4.2 — SHA-384 (0x01) promoted from reserved to validated.
    Supported set MUST include both 0x00 and 0x01 at v7.67."""
    assert ALG_ECFV1_SHA256 in SUPPORTED_CONTENT_HASH_FORMATS
    assert ALG_ECFV1_SHA384 in SUPPORTED_CONTENT_HASH_FORMATS
    # Digest size: 48 bytes; total system/hash size: 49 bytes (1-byte varint + 48)
    assert DIGEST_SIZES[ALG_ECFV1_SHA384] == 48


def test_hash_format_sha_384_1_canonical_fixture_re_hash() -> None:
    """V7 v7.67 §7.1 — re-hash the v7.66 canonical 0xAA × 64 fixture under
    SHA-384. The digest is hashlib.sha384(ECF({type, data})); the total
    system/hash is 49 bytes (varint 0x01 || digest). ECF bytes are
    unchanged from v7.66 — the format-code is the only axis that moves."""
    inner = {
        "type": "system/peer",
        "data": {
            "public_key": EXPERIMENTAL_TEST_PUBKEY,
            "key_type": "experimental-test",
        },
    }
    ecf_bytes = ecf_encode(inner)
    expected_digest = hashlib.sha384(ecf_bytes).digest()
    assert len(expected_digest) == 48

    h = compute_ecf_hash(inner, algorithm=ALG_ECFV1_SHA384)
    assert len(h) == 49
    assert h[0] == ALG_ECFV1_SHA384 == 0x01
    assert h[1:] == expected_digest
    # Cross-impl byte pin (cohort SHA-384 fixture, see V7.67-PHASE1 pin doc).
    assert h.hex() == (
        "012e64bbde3c494cf7cd4fb53ae3bf6420ec6d9bfa686348729eaa687e421c01"
        "c059c1ed5775824bcffc50df0f3eef5a69"
    )

    # validate_hash(h) accepts the SHA-384 form (v7.67 promotes from reserved)
    validate_hash(h)
    # And the leading varint interprets cleanly
    code, consumed = decode_content_hash_format(h)
    assert code == 0x01
    assert consumed == 1  # single-byte happy path
    # validate_supported_content_hash_format alias
    assert validate_supported_content_hash_format(h) == 0x01

    # Display format pin: "ecfv1-sha384:" + hex digest
    disp = hash_to_display(h)
    assert disp == f"ecfv1-sha384:{expected_digest.hex()}"


def test_hash_format_sha_384_1_store_retrieve_round_trip() -> None:
    """V7 v7.67 §4 — a SHA-384 content_hash round-trips through validate_hash
    + format-code interpretation. The store/retrieve dispatch is byte-equal
    whether the format is 0x00 or 0x01 — the ContentStore is format-agnostic
    on key (bytes-keyed); only validation cares about the format-code byte."""
    e1 = {"type": "x", "data": {"v": 1}}
    e2 = {"type": "x", "data": {"v": 2}}

    h1_sha256 = compute_ecf_hash(e1, algorithm=ALG_ECFV1_SHA256)
    h1_sha384 = compute_ecf_hash(e1, algorithm=ALG_ECFV1_SHA384)
    h2_sha384 = compute_ecf_hash(e2, algorithm=ALG_ECFV1_SHA384)

    assert h1_sha256 != h1_sha384  # format-code makes the byte streams differ
    assert h1_sha384 != h2_sha384  # different data → different digest
    assert len(h1_sha256) == 33
    assert len(h1_sha384) == 49

    # validate_hash distinguishes "format unknown" from "digest wrong length"
    with pytest.raises(ValueError):
        validate_hash(bytes([ALG_ECFV1_SHA384]) + b"\x00" * 32)  # too short for SHA-384


# ============================================================================
# VARINT-MULTIBYTE-1 — multi-byte LEB128 decode mandatory (v7.67 §5.4)
# ============================================================================

def test_varint_multibyte_1_leb128_codec_round_trip() -> None:
    """V7 v7.67 §5.4 — LEB128 varint codec: single-byte 0x00-0x7F + multi-byte
    chain with continuation bits. Both encode and decode MUST round-trip
    every value, even when no current production allocation exceeds 0x7F."""
    # Single-byte happy path
    for n in (0, 1, 0x7F):
        encoded = encode_leb128(n)
        assert encoded == bytes([n])
        assert decode_leb128(encoded) == (n, 1)

    # Multi-byte: 0x80 is the FIRST two-byte value; encoding = 0x80 0x01
    encoded_128 = encode_leb128(0x80)
    assert encoded_128 == bytes([0x80, 0x01])
    value, consumed = decode_leb128(encoded_128)
    assert (value, consumed) == (0x80, 2)

    # Value 255 (the §5.3 reservation): LEB128 = 0xFF 0x01. Codec decodes
    # the value cleanly; the REJECTION happens at the format-code validator
    # layer (validate_content_hash_format_code / decode_content_hash_format).
    encoded_255 = encode_leb128(255)
    assert encoded_255 == bytes([0xFF, 0x01])
    assert decode_leb128(encoded_255) == (255, 2)

    # Larger multi-byte: 0x3FFF is the last two-byte value; 0x4000 is three.
    assert encode_leb128(0x3FFF) == bytes([0xFF, 0x7F])
    assert decode_leb128(encode_leb128(0x3FFF)) == (0x3FFF, 2)

    # Truncated input raises
    with pytest.raises(ValueError):
        decode_leb128(bytes([0x80]))  # continuation set but no further bytes
    with pytest.raises(ValueError):
        decode_leb128(b"")


def test_varint_multibyte_1_content_hash_decoder_walks_chain() -> None:
    """V7 v7.67 §5.4 — a system/hash whose leading varint is multi-byte
    (e.g. 0x80 0x01 = value 128) MUST be decoded as the multi-byte value,
    not treated as a malformed single byte. Because 0x80 is unallocated
    in the seed table, the decoder rejects with
    ``unsupported_content_hash_format`` — confirming the chain was walked
    (single-byte handling would have produced a different code path)."""
    # value=128, encoded as 0x80 0x01; followed by an arbitrary 32-byte "digest"
    multi_hash = bytes([0x80, 0x01]) + b"\xab" * 32
    # The varint codec sees value 128
    value, consumed = decode_leb128(multi_hash)
    assert (value, consumed) == (0x80, 2)
    # The content-hash decoder walks the chain AND rejects 0x80 as unallocated
    with pytest.raises(UnsupportedContentHashFormatError) as excinfo:
        decode_content_hash_format(multi_hash)
    assert "0x80" in str(excinfo.value) or "128" in str(excinfo.value)


# ============================================================================
# VARINT-RESERVED-FF-1 — value 255 reserved on BOTH axes (v7.67 §5.3)
# ============================================================================

def test_varint_reserved_ff_1_key_type_axis_rejects_255() -> None:
    """V7 v7.67 §5.3 — value 255 SHALL NOT be allocated as a key_type code.
    The reservation already held at v7.66 on the key_type axis; v7.67
    re-pins it and mirrors to the content_hash_format axis."""
    # 0xFF is not in the allocation table
    from entity_core.crypto.identity import KEY_TYPE_BYTE_TO_ENTITY_DATA
    assert 0xFF not in KEY_TYPE_BYTE_TO_ENTITY_DATA

    # Validator rejects with UnsupportedKeyTypeError (subclass of ValueError)
    with pytest.raises(UnsupportedKeyTypeError):
        validate_supported_key_type(0xFF)


def test_varint_reserved_ff_1_content_hash_format_axis_rejects_255() -> None:
    """V7 v7.67 §5.3 — value 255 is newly reserved on the content_hash_format
    axis (mirror of v7.66's key_type 0xFF reservation). Mandatory on both
    axes per §5.4 normative text."""
    # Bare-code validator path
    with pytest.raises(UnsupportedContentHashFormatError) as excinfo:
        validate_content_hash_format_code(0xFF)
    assert "reserved" in str(excinfo.value).lower()

    # Decoded-from-content_hash path (single-byte form 0xFF doesn't have the
    # continuation bit, so it decodes to value 255 in a single byte)
    bogus = bytes([0xFF]) + b"\x00" * 32
    with pytest.raises(UnsupportedContentHashFormatError):
        decode_content_hash_format(bogus)

    # validate_supported_content_hash_format inherits the rejection
    with pytest.raises(UnsupportedContentHashFormatError):
        validate_supported_content_hash_format(bogus)

    # validate_hash also rejects (format-code check is upstream of digest-length)
    with pytest.raises(UnsupportedContentHashFormatError):
        validate_hash(bogus)
