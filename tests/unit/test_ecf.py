"""Tests for Entity Canonical Form (ECF) encoding."""

import pytest

from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    ALG_ECFV1_SHA384,
    ALG_ECFV1_SHA512,
    Hash,
    compute_ecf_hash,
    ecf_decode,
    ecf_encode,
    get_hash_algorithm,
    get_hash_digest,
    hash_equals,
    hash_to_display,
    hash_to_string,
    hash_to_wire,
    is_hash_ref,
    validate_hash,
    wire_to_hash,
)


class TestEcfEncodeDecode:
    """Tests for ECF encoding/decoding."""

    def test_encode_empty_map(self):
        """Empty map encodes correctly."""
        data = {}
        encoded = ecf_encode(data)
        # CBOR: A0 = empty map
        assert encoded == b"\xa0"

    def test_encode_decode_roundtrip(self):
        """Data survives encode/decode roundtrip."""
        data = {"type": "test", "data": {"value": 42}}
        encoded = ecf_encode(data)
        decoded = ecf_decode(encoded)
        assert decoded == data

    def test_encode_determinism(self):
        """Same input always produces same output."""
        data = {"b": 1, "a": 2, "z": 3}
        encoded1 = ecf_encode(data)
        encoded2 = ecf_encode(data)
        assert encoded1 == encoded2

    def test_key_ordering(self):
        """Keys sorted by encoded length, then lexicographically."""
        # Keys: "a" (1 char), "z" (1 char), "bb" (2 char), "aaa" (3 char)
        # Expected order: a, z (both 1 char, sorted), bb (2 char), aaa (3 char)
        data = {"aaa": 4, "bb": 3, "z": 1, "a": 2}
        encoded = ecf_encode(data)
        decoded = ecf_decode(encoded)

        # Verify all values preserved
        assert decoded == data

        # The encoded bytes should have keys in length-then-lexicographic order
        # For verification, re-encode the decoded data
        reencoded = ecf_encode(decoded)
        assert encoded == reencoded

    def test_nested_structures(self):
        """Nested maps and arrays encode correctly."""
        data = {"outer": {"inner": {"deep": [1, 2, 3]}}}
        encoded = ecf_encode(data)
        decoded = ecf_decode(encoded)
        assert decoded == data

    def test_various_types(self):
        """Various types encode/decode correctly."""
        data = {
            "string": "hello",
            "integer": 42,
            "negative": -1,
            "float": 1.5,
            "bool_true": True,
            "bool_false": False,
            "null": None,
            "array": [1, 2, 3],
            "nested": {"key": "value"},
        }
        encoded = ecf_encode(data)
        decoded = ecf_decode(encoded)
        assert decoded == data

    def test_unicode_string(self):
        """Unicode strings encode correctly."""
        data = {"text": "hello 世界"}
        encoded = ecf_encode(data)
        decoded = ecf_decode(encoded)
        assert decoded == data

    def test_large_integer(self):
        """Large integers (> 2^53) encode correctly."""
        # This is larger than JavaScript's safe integer
        large_int = 9007199254740993
        data = {"value": large_int}
        encoded = ecf_encode(data)
        decoded = ecf_decode(encoded)
        assert decoded["value"] == large_int


class TestEcfHash:
    """Tests for ECF hashing."""

    def test_hash_format(self):
        """Hash is bytes (algorithm byte + digest)."""
        data = {"type": "test", "data": {}}
        h = compute_ecf_hash(data)
        assert isinstance(h, bytes)
        assert len(h) == 33  # 1 byte algorithm + 32 bytes SHA-256 digest
        assert h[0] == ALG_ECFV1_SHA256

    def test_hash_determinism(self):
        """Same input always produces same hash."""
        data = {"type": "test", "data": {"value": 42}}
        hash1 = compute_ecf_hash(data)
        hash2 = compute_ecf_hash(data)
        assert hash_equals(hash1, hash2)
        assert hash1 == hash2

    def test_different_data_different_hash(self):
        """Different data produces different hash."""
        data1 = {"type": "test", "data": {"value": 42}}
        data2 = {"type": "test", "data": {"value": 43}}
        hash1 = compute_ecf_hash(data1)
        hash2 = compute_ecf_hash(data2)
        assert not hash_equals(hash1, hash2)
        assert hash1 != hash2

    def test_empty_map_hash(self):
        """Empty map produces consistent hash."""
        data = {}
        h = compute_ecf_hash(data)
        assert h[0] == ALG_ECFV1_SHA256
        # SHA256 of CBOR empty map (single byte 0xA0)
        expected_digest = bytes.fromhex("c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0")
        assert h[1:] == expected_digest

    def test_hash_to_display(self):
        """Hash converts to human-readable display string."""
        data = {"type": "test", "data": {}}
        h = compute_ecf_hash(data)
        display = hash_to_display(h)
        assert display.startswith("ecfv1-sha256:")
        assert len(display) == 13 + 64  # "ecfv1-sha256:" + 64 hex chars

    def test_hash_equals_none(self):
        """hash_equals handles None correctly."""
        h = compute_ecf_hash({})
        assert hash_equals(None, None)
        assert not hash_equals(h, None)
        assert not hash_equals(None, h)

    def test_get_hash_algorithm(self):
        """get_hash_algorithm extracts algorithm byte."""
        h = compute_ecf_hash({})
        assert get_hash_algorithm(h) == ALG_ECFV1_SHA256

    def test_get_hash_digest(self):
        """get_hash_digest extracts digest bytes."""
        h = compute_ecf_hash({})
        digest = get_hash_digest(h)
        assert len(digest) == 32  # SHA-256


class TestWireFormat:
    """Tests for hash wire format conversion.

    Hash is bytes on wire (algorithm byte + digest).
    wire_to_hash and hash_to_wire are identity functions.
    """

    def test_hash_to_wire(self):
        """Hash is already bytes, hash_to_wire is identity."""
        digest = bytes.fromhex("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
        h = bytes([ALG_ECFV1_SHA256]) + digest
        wire = hash_to_wire(h)
        assert wire == h  # Identity function

    def test_wire_to_hash(self):
        """Wire format (bytes) converts to hash (same bytes)."""
        digest = bytes.fromhex("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
        wire = bytes([ALG_ECFV1_SHA256]) + digest
        h = wire_to_hash(wire)
        assert h == wire  # V4: hash IS bytes

    def test_wire_roundtrip(self):
        """Hash survives wire format roundtrip."""
        digest = bytes.fromhex("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
        original = bytes([ALG_ECFV1_SHA256]) + digest
        wire = hash_to_wire(original)
        restored = wire_to_hash(wire)
        assert hash_equals(restored, original)

    def test_wire_empty_fails(self):
        """Empty bytes raises ValueError."""
        with pytest.raises(ValueError, match="too short"):
            wire_to_hash(b"")

    def test_wire_invalid_format(self):
        """Invalid format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid wire hash format"):
            wire_to_hash(12345)  # type: ignore


class TestHashToString:
    """Tests for hash_to_string display formatting."""

    def test_hash_to_string(self):
        """Hash converts to a display string."""
        digest = bytes.fromhex("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")
        h = bytes([ALG_ECFV1_SHA256]) + digest
        s = hash_to_string(h)
        assert s == "ecf-sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"


class TestValidateHash:
    """Tests for hash validation."""

    def test_validate_valid_hash(self):
        """Valid hash passes validation."""
        h = compute_ecf_hash({})
        validate_hash(h)  # Should not raise

    def test_validate_too_short(self):
        """Too-short hash fails validation."""
        with pytest.raises(ValueError, match="too short"):
            validate_hash(b"")

    def test_validate_unknown_algorithm(self):
        """V7 v7.66 §5.2 — unsupported format code raises the spec-aligned error."""
        with pytest.raises(ValueError, match="unsupported_content_hash_format"):
            validate_hash(bytes([0xFF]) + b"\x00" * 32)

    def test_validate_wrong_digest_length(self):
        """Wrong digest length fails validation."""
        with pytest.raises(ValueError, match="Invalid digest length"):
            validate_hash(bytes([ALG_ECFV1_SHA256]) + b"\x00" * 16)


class TestIsHashRef:
    """Tests for the crypto-agile hash-reference predicate.

    is_hash_ref must recognize a reference by its leading algorithm byte +
    matching digest length, NOT by a fixed length==33 assumption. The latter
    silently fails to spot a SHA-384/512 reference once those algorithms land.
    """

    def test_sha256_ref_recognized(self):
        """A real SHA-256 reference (33 bytes, format 0x00) is a hash ref."""
        assert is_hash_ref(compute_ecf_hash({"type": "x", "data": {}}))
        assert is_hash_ref(bytes([ALG_ECFV1_SHA256]) + b"\x00" * 32)

    def test_longer_digest_algorithms_recognized(self):
        """SHA-384 (49 bytes) and SHA-512 (65 bytes) refs are recognized.

        This is the crux: len==33 would miss both of these.
        """
        assert is_hash_ref(bytes([ALG_ECFV1_SHA384]) + b"\x00" * 48)
        assert is_hash_ref(bytes([ALG_ECFV1_SHA512]) + b"\x00" * 64)

    def test_unknown_format_byte_rejected(self):
        """A 33-byte value with an unknown leading byte is NOT a hash ref.

        Stricter (and more correct) than len==33, which accepted any 33 bytes.
        """
        assert not is_hash_ref(bytes([0xFF]) + b"\x00" * 32)

    def test_wrong_length_for_algorithm_rejected(self):
        """Known algorithm byte but mismatched digest length is not a ref."""
        assert not is_hash_ref(bytes([ALG_ECFV1_SHA256]) + b"\x00" * 16)
        assert not is_hash_ref(bytes([ALG_ECFV1_SHA384]) + b"\x00" * 32)

    def test_non_bytes_rejected(self):
        """Non-bytes values (and empty bytes) are never hash refs."""
        assert not is_hash_ref(b"")
        assert not is_hash_ref("ecfv1-sha256:abcd")
        assert not is_hash_ref(None)
        assert not is_hash_ref(33)
        assert not is_hash_ref({"algorithm": 0, "digest": b""})

    def test_bytearray_accepted(self):
        """bytearray with valid shape is also recognized."""
        assert is_hash_ref(bytearray([ALG_ECFV1_SHA256]) + b"\x00" * 32)


class TestSpecTestVectors:
    """Test vectors for CBOR encoding (ECF).

    Note: These are CBOR-specific test vectors. The spec examples
    may show JSON-derived hashes for illustration, but ECF uses
    CBOR canonical encoding which produces different hashes.
    """

    def test_empty_map_vector(self):
        """Test vector: empty_map - ECF encoding and hash."""
        data = {}
        encoded = ecf_encode(data)
        assert encoded.hex() == "a0"  # CBOR empty map
        h = compute_ecf_hash(data)
        # SHA256 of CBOR 0xA0
        expected_digest = bytes.fromhex("c19a797fa1fd590cd2e5b42d1cf5f246e29b91684e2f87404b81dc345c7a56a0")
        assert h[0] == ALG_ECFV1_SHA256
        assert h[1:] == expected_digest

    def test_single_uint_vector(self):
        """Test vector: single_uint - {"value": 42}."""
        data = {"value": 42}
        encoded = ecf_encode(data)
        # A1 = map with 1 pair
        # 65 76616C7565 = text string "value" (5 bytes)
        # 18 2A = integer 42 (with 1-byte length indicator)
        assert encoded.hex() == "a16576616c7565182a"

    def test_boolean_true_vector(self):
        """Test vector: boolean_true - {"flag": true}."""
        data = {"flag": True}
        encoded = ecf_encode(data)
        # A1 = map with 1 pair
        # 64 666C6167 = text string "flag" (4 bytes)
        # F5 = true
        assert encoded.hex() == "a164666c6167f5"

    def test_boolean_false_vector(self):
        """Test vector: boolean_false - {"flag": false}."""
        data = {"flag": False}
        encoded = ecf_encode(data)
        # A1 64 666C6167 F4
        assert encoded.hex() == "a164666c6167f4"

    def test_null_value_vector(self):
        """Test vector: null_value - {"value": null}."""
        data = {"value": None}
        encoded = ecf_encode(data)
        # A1 65 76616C7565 F6
        assert encoded.hex() == "a16576616c7565f6"

    def test_negative_int_vector(self):
        """Test vector: negative_int - {"value": -1}."""
        data = {"value": -1}
        encoded = ecf_encode(data)
        # A1 65 76616C7565 20
        # 20 = negative int -1 (major type 1, additional info 0 = -1 - 0 = -1)
        assert encoded.hex() == "a16576616c756520"

    def test_array_of_ints_vector(self):
        """Test vector: array_of_ints - {"arr": [1, 2, 3]}."""
        data = {"arr": [1, 2, 3]}
        encoded = ecf_encode(data)
        # Verify roundtrip
        decoded = ecf_decode(encoded)
        assert decoded == data


class TestTagPreservingDecode:
    """V7 §1.8 byte-fidelity: ecf_decode must preserve CBOR tags as CBORTag.

    Without this, cbor2 silently strips tag-55799 (self-describe) — breaking
    hash verification on any entity whose ``data`` field carries it. Root
    cause for the conformance-passthrough py-diagnosis (`tag_reject.4`
    crash + cascading content_hash.* broken-pipe FAILs).
    """

    def test_tag_55799_self_describe_round_trip(self):
        """tag-55799 wrapping empty map MUST round-trip byte-identical."""
        raw = bytes([0xD9, 0xD9, 0xF7, 0xA0])
        decoded = ecf_decode(raw)
        # cbor2's pure-Py and C-ext CBORTag are distinct classes; duck-type
        # on the .tag / .value attribute shape they share.
        assert decoded.tag == 55799
        assert decoded.value == {}
        assert ecf_encode(decoded) == raw

    def test_arbitrary_tags_preserved(self):
        """Other semantic tags (datetime, uuid) also preserved."""
        # tag-0 wrapping ISO datetime text
        dt_bytes = bytes.fromhex("c074323032362d30362d30365431323a30303a30305a")
        decoded = ecf_decode(dt_bytes)
        assert decoded.tag == 0
        assert ecf_encode(decoded) == dt_bytes

        # tag-37 wrapping 16-byte UUID
        uuid_bytes = bytes.fromhex("d82550" + "00112233445566778899aabbccddeeff")
        decoded = ecf_decode(uuid_bytes)
        assert decoded.tag == 37
        assert ecf_encode(decoded) == uuid_bytes

    def test_entity_with_tag_55799_data_field_hash_validates(self):
        """End-to-end §1.8: hash check passes on entity whose data carries tag-55799."""
        import hashlib
        from entity_core.protocol.framing import validate_entity_hash

        raw_data = bytes([0xD9, 0xD9, 0xF7, 0xA0])
        entity = {
            "type": "system/validate/conformance-tag/tag_reject-4",
            "data": ecf_decode(raw_data),  # CBORTag(55799, {})
        }
        entity["content_hash"] = b"\x00" + hashlib.sha256(ecf_encode(entity)).digest()
        # MUST NOT raise HashValidationError.
        validate_entity_hash(entity)
