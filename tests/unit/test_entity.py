"""Tests for Entity structure and hashing."""

import pytest

from entity_core.protocol.entity import Entity
from entity_core.protocol.framing import HashValidationError, validate_entity_hash
from entity_core.utils.ecf import ALG_ECFV1_SHA256, get_hash_algorithm, get_hash_digest, hash_equals


def test_entity_creation():
    """Entity can be created with type and data."""
    entity = Entity(type="test", data={"value": 42})
    assert entity.type == "test"
    assert entity.data["value"] == 42


def test_entity_hash():
    """Entity hash is computed from type and data only."""
    entity = Entity(type="test", data={"value": 42})
    hash1 = entity.compute_hash()

    # Same content = same hash
    entity2 = Entity(type="test", data={"value": 42})
    assert hash_equals(entity2.compute_hash(), hash1)

    # Different data = different hash
    entity3 = Entity(type="test", data={"value": 43})
    assert not hash_equals(entity3.compute_hash(), hash1)


def test_entity_hash_consistent():
    """Same entity data produces same hash."""
    entity1 = Entity(type="test", data={"value": 42})
    entity2 = Entity(type="test", data={"value": 42})

    # Same hash for same content
    assert hash_equals(entity1.compute_hash(), entity2.compute_hash())


def test_entity_hash_excludes_uri():
    """Hash does not include URI."""
    entity1 = Entity(type="test", data={"value": 42})
    entity2 = Entity(type="test", data={"value": 42}, uri="entity://peer/path")

    # Same hash despite different URI
    assert hash_equals(entity1.compute_hash(), entity2.compute_hash())


def test_entity_hash_format():
    """Hash is bytes (algorithm byte + digest)."""
    entity = Entity(type="test", data={})
    h = entity.compute_hash()
    assert isinstance(h, bytes)
    assert len(h) == 33  # 1 byte algorithm + 32 bytes SHA-256 digest
    assert get_hash_algorithm(h) == ALG_ECFV1_SHA256
    assert len(get_hash_digest(h)) == 32  # SHA-256 is 32 bytes


def test_entity_to_dict():
    """Entity converts to dict correctly — includes content_hash by default (I2)."""
    entity = Entity(
        type="test",
        data={"value": 42},
        uri="entity://peer/path",
    )
    d = entity.to_dict()

    assert d["type"] == "test"
    assert d["data"]["value"] == 42
    assert d["uri"] == "entity://peer/path"
    assert "content_hash" in d
    assert len(d["content_hash"]) == 33  # algorithm byte + SHA-256


def test_entity_from_dict():
    """Entity can be created from dict (wire format)."""
    d = {
        "type": "test",
        "data": {"value": 42},
        "uri": "entity://peer/path",
    }
    entity = Entity.from_dict(d)

    assert entity.type == "test"
    assert entity.data["value"] == 42
    assert entity.uri == "entity://peer/path"


def test_entity_to_dict_minimal():
    """to_dict with minimal entity — still includes content_hash (I2)."""
    entity = Entity(type="test", data={})
    d = entity.to_dict()

    assert d["type"] == "test"
    assert d["data"] == {}
    assert "content_hash" in d
    # uri is omitted when None
    assert "uri" not in d


class TestHashValidation:
    """Tests for content_hash validation on receive."""

    def test_valid_hash_passes(self):
        """Entity with correct content_hash passes validation."""
        entity = Entity(type="test", data={"value": 42})
        entity_dict = entity.to_dict()

        # Should not raise, returns validated hash (bytes)
        validated = validate_entity_hash(entity_dict)
        assert isinstance(validated, bytes)
        assert get_hash_algorithm(validated) == ALG_ECFV1_SHA256

    def test_missing_hash_fails(self):
        """Entity without content_hash fails validation."""
        entity_dict = {
            "type": "test",
            "data": {"value": 42},
        }

        with pytest.raises(HashValidationError, match="missing content_hash"):
            validate_entity_hash(entity_dict)

    def test_wrong_hash_fails(self):
        """Entity with incorrect content_hash fails validation."""
        # V4: Use bytes format for hash
        entity_dict = {
            "type": "test",
            "data": {"value": 42},
            "content_hash": bytes([ALG_ECFV1_SHA256]) + bytes(32),  # Algorithm + zeros
        }

        with pytest.raises(HashValidationError, match="Hash mismatch"):
            validate_entity_hash(entity_dict)

    def test_tampered_data_fails(self):
        """Tampering with data causes hash mismatch."""
        entity = Entity(type="test", data={"value": 42})
        entity_dict = entity.to_dict()

        # Tamper with data
        entity_dict["data"]["value"] = 999

        with pytest.raises(HashValidationError, match="Hash mismatch"):
            validate_entity_hash(entity_dict)

    def test_unknown_fields_preserved_in_hash(self):
        """Unknown fields in data are included in hash computation."""
        # Create entity with unknown field
        entity = Entity(type="test", data={"value": 42, "future_field": "unknown"})
        entity_dict = entity.to_dict()

        # Should pass - unknown field is included in hash
        validated = validate_entity_hash(entity_dict)
        assert isinstance(validated, bytes)
        assert get_hash_algorithm(validated) == ALG_ECFV1_SHA256

    def test_removing_unknown_field_fails(self):
        """Removing an unknown field from data causes hash mismatch."""
        # Original entity with unknown field
        original_data = {"value": 42, "future_field": "unknown"}
        entity = Entity(type="test", data=original_data)
        original_hash = entity.compute_hash()

        # Simulate receiving entity with hash, then stripping field
        entity_dict = {
            "type": "test",
            "data": {"value": 42},  # future_field removed!
            "content_hash": original_hash,  # V4: bytes directly
        }

        with pytest.raises(HashValidationError, match="Hash mismatch"):
            validate_entity_hash(entity_dict)


class TestEntityFidelity:
    """§1.8 entity fidelity: validate on receipt, then carry the validated
    hash + original fields through store + forward without recompute.

    The receive path goes through ``from_wire_dict`` (the *trust* step that
    pairs with ``framing.validate_entity_hash``); locally-authored entities
    keep computing their hash on demand via ``from_dict`` / the constructor.
    """

    def test_from_wire_dict_carries_the_validated_hash(self):
        """from_wire_dict returns the claimed hash and the entity carries it."""
        wire = Entity(type="test", data={"value": 42}).to_dict()
        entity, claimed = Entity.from_wire_dict(wire)

        assert claimed == wire["content_hash"]
        assert entity.content_hash == claimed
        # compute_hash returns the carried hash verbatim.
        assert entity.compute_hash() == claimed

    def test_carried_hash_is_trusted_not_recomputed(self):
        """A carried hash is returned verbatim — never recomputed.

        We carry a structurally-valid hash that does NOT match {type, data}.
        compute_hash() and to_dict() must return the carried hash, proving we
        trust the validated hash rather than recomputing (§1.8 MUST NOT
        recompute). A real receive path only ever carries a *validated* hash;
        this asserts the trust mechanism directly.
        """
        # Structurally valid (algo byte + 32-byte digest) but not the real hash.
        bogus = bytes([ALG_ECFV1_SHA256]) + bytes(32)
        entity = Entity(type="test", data={"value": 42}, content_hash=bogus)

        # The genuine hash differs from the carried one...
        assert Entity(type="test", data={"value": 42}).compute_hash() != bogus
        # ...yet the carried entity returns the carried hash, not a recompute.
        assert entity.compute_hash() == bogus
        assert entity.to_dict()["content_hash"] == bogus

    def test_unknown_top_level_fields_preserved(self):
        """Unknown top-level fields survive from_wire_dict → to_dict verbatim."""
        base = Entity(type="test", data={"value": 42}).to_dict()
        # A forward-compat top-level field an older impl doesn't model.
        # It is NOT part of the hash (hash covers {type, data} only), so the
        # entity still validates and the field must ride along.
        base["future_top_level"] = {"added_by": "v9"}

        entity, _ = Entity.from_wire_dict(base)
        assert entity.extra == {"future_top_level": {"added_by": "v9"}}

        forwarded = entity.to_dict()
        assert forwarded["future_top_level"] == {"added_by": "v9"}
        # The carried hash is unchanged by the presence of the extra field.
        assert forwarded["content_hash"] == base["content_hash"]

    def test_forward_reproduces_wire_form(self):
        """to_dict on a received entity reproduces the original wire dict."""
        original = Entity(
            type="doc", data={"k": [1, 2, 3], "nested": {"x": True}}
        ).to_dict()
        original["unknown"] = "carry me"

        entity, _ = Entity.from_wire_dict(original)
        assert entity.to_dict() == original

    def test_store_then_forward_preserves_fidelity(self):
        """Receive → ContentStore.put → get → forward keeps hash + unknown fields.

        The store key is the carried (validated) hash, and a re-emitted entity
        carries the same hash and unknown fields — the store/forward path is
        byte-faithful, not a recompute.
        """
        from entity_core.storage.content_store import ContentStore

        wire = Entity(type="cap", data={"scope": "read"}).to_dict()
        wire["ext_field"] = 7  # unknown top-level field

        entity, claimed = Entity.from_wire_dict(wire)
        store = ContentStore()
        key = store.put(entity)

        # Keyed by the carried/validated hash (matches the wire reference).
        assert key == claimed
        got = store.get(claimed)
        assert got is not None
        assert got.to_dict() == wire

    def test_from_dict_does_not_carry_hash(self):
        """Locally-authored entities (from_dict) compute their hash fresh."""
        entity = Entity.from_dict({"type": "test", "data": {"value": 42}})
        assert entity.content_hash is None
        assert entity.extra == {}
        # Recomputed from {type, data}, matches a fresh construction.
        assert entity.compute_hash() == Entity(type="test", data={"value": 42}).compute_hash()

    def test_from_wire_dict_rejects_missing_or_bad_hash(self):
        """from_wire_dict requires a structurally-valid bytes content_hash."""
        with pytest.raises(ValueError, match="must have content_hash"):
            Entity.from_wire_dict({"type": "t", "data": {}})
        with pytest.raises(ValueError, match="Invalid content_hash format"):
            Entity.from_wire_dict({"type": "t", "data": {}, "content_hash": "not-bytes"})
