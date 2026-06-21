"""ECF (Entity Canonical Form) canonical-encoding + round-trip conformance.

ENTITY-CBOR-ENCODING pins RFC 8949 §4.2 deterministic encoding: minimal ints,
sorted map keys, definite lengths, and (Rule 4/4a) shortest-float + canonical
NaN/±Inf/-0.0. These guard the two properties cross-impl interop and §1.8
entity fidelity rely on:

  (1) round-trip idempotency — encode(decode(canonical_bytes)) == canonical_bytes
      (so carrying a validated hash + re-emitting is byte-faithful);
  (2) canonical determinism — the same logical value encodes to the same bytes
      regardless of construction order (so peers agree on content hashes).

The convergent-mirror cross-impl triage (Item B) lives here: the entity types
on that wire — caps (incl. multi-granter), notifications, continuations,
snapshots — are ints/bytes/strings/maps/lists, all canonical + round-trip
exact below. The one documented gap is float16-max minimization (a latent,
floats-only issue, not exercised by those entities).
"""

from __future__ import annotations

import io

import cbor2
import pytest

from entity_core.utils.ecf import ecf_decode, ecf_encode


def _roundtrip_exact(value) -> bool:
    enc = ecf_encode(value)
    return ecf_encode(ecf_decode(enc)) == enc


class TestRoundTripIdempotency:
    @pytest.mark.parametrize("value", [
        0, 1, -1, 23, 24, 255, 256, 65535, 65536, 1_000_000, 2**63 - 1,
        b"", b"\x00", b"\x01" * 33, b"\xff" * 64,
        "", "x", "system/tree", "a" * 300,
        [], [1, 2, 3], [b"\x01", "two", 3],
        {}, {"a": 1, "b": 2}, {"z": 1, "a": 2, "aa": 3},
        None, True, False,
    ])
    def test_scalars_and_containers_round_trip_exact(self, value):
        assert _roundtrip_exact(value)

    def test_nested_entity_shape_round_trips_exact(self):
        entity = {
            "type": "system/capability/token",
            "data": {
                "granter": b"\x01" * 33,
                "grantee": b"\x02" * 33,
                "grants": [{
                    "handlers": {"include": ["system/tree"]},
                    "resources": {"include": ["*"]},
                    "operations": {"include": ["put", "get"]},
                }],
                "expires_at": 1737900000000,
            },
        }
        assert _roundtrip_exact(entity)


class TestCanonicalDeterminism:
    def test_map_key_order_is_normalized(self):
        # Same logical map, different construction order → identical bytes.
        a = ecf_encode({"a": 1, "b": 2, "aa": 3, "z": 4})
        b = ecf_encode({"z": 4, "aa": 3, "b": 2, "a": 1})
        assert a == b

    def test_minimal_integer_encoding(self):
        assert ecf_encode(1) == bytes([0x01])           # 1 byte
        assert ecf_encode(23) == bytes([0x17])
        assert ecf_encode(24) == bytes([0x18, 0x18])    # 1-byte arg form
        assert ecf_encode(256) == bytes([0x19, 0x01, 0x00])

    def test_canonical_floats_small_magnitude(self):
        # Rule 4/4a: shortest float + canonical specials, all float16 here.
        assert ecf_encode(1.0).hex() == "f93c00"
        assert ecf_encode(1.5).hex() == "f93e00"
        assert ecf_encode(float("nan")).hex() == "f97e00"
        assert ecf_encode(float("inf")).hex() == "f97c00"
        assert ecf_encode(float("-inf")).hex() == "f9fc00"
        assert ecf_encode(-0.0).hex() == "f98000"


class TestCapEntityFidelity:
    """The convergent-mirror cap chain decodes + re-encodes faithfully — so a
    multi-sig validation error is cap-chain *semantics*, never a decode/round-
    trip artifact (Item B triage)."""

    def test_multi_granter_cap_round_trips_and_decodes_faithfully(self):
        cap = {
            "type": "system/capability/token",
            "data": {
                "granter": {
                    "signers": [b"\x01" * 33, b"\x02" * 33, b"\x03" * 33],
                    "threshold": 2,
                },
                "grantee": b"\x09" * 33,
            },
        }
        # Byte-identical round-trip.
        assert _roundtrip_exact(cap)
        # The multi-granter decodes with the exact signer count + threshold —
        # so "threshold exceeds N" can only be a genuine cap property, not a
        # Python miscount.
        granter = ecf_decode(ecf_encode(cap))["data"]["granter"]
        assert len(granter["signers"]) == 3
        assert granter["threshold"] == 2


class TestFloatMinimization:
    """RFC 8949 §4.2 Rule 4: shortest float encoding preserving value.

    Confirmed Go (fxamacker CoreDetEncOptions) and Rust (custom
    `try_encode_half` in `core/ecf/src/encoder.rs`) both minimize large-
    magnitude f16-representable values to float16 — so Python MUST too, or
    a future entity carrying such a float silently hash-diverges.

    cbor2's C extension (the default backing of `cbor2.dumps`) does NOT
    minimize these — it emits float32. `ecf_encode` routes around the C
    extension by using cbor2's pure-Python `encode_minimal_float`, which
    implements Rule 4 correctly. These tests lock in the conformance and
    guard against a future cbor2 internal shift dragging us back to the
    buggy path.
    """

    # Small-magnitude — both encoders agree, kept here as a sibling check.
    def test_small_magnitude_specials_are_float16(self):
        assert ecf_encode(1.0).hex() == "f93c00"
        assert ecf_encode(1.5).hex() == "f93e00"
        assert ecf_encode(0.0).hex() == "f90000"
        assert ecf_encode(-0.0).hex() == "f98000"
        assert ecf_encode(float("nan")).hex() == "f97e00"
        assert ecf_encode(float("inf")).hex() == "f97c00"
        assert ecf_encode(float("-inf")).hex() == "f9fc00"

    # Large-magnitude f16-representable — the cbor2 C-extension bug zone.
    # ECF must minimize to float16. Round-trip stays exact in both cases;
    # the assertion that matters is the head byte (0xF9, not 0xFA).
    @pytest.mark.parametrize(
        "value,expected_hex",
        [
            (32768.0, "f97800"),    # 1.0 * 2**15, smallest "large" f16
            (65472.0, "f97bfe"),    # 65504 - 32 (one f16 step below max)
            (65504.0, "f97bff"),    # max representable normal f16
            (-65504.0, "f9fbff"),   # negative max normal f16
        ],
    )
    def test_large_float16_values_minimize_to_float16(self, value, expected_hex):
        enc = ecf_encode(value)
        assert ecf_decode(enc) == value, "round-trip must remain exact"
        assert enc.hex() == expected_hex
        assert enc[0] == 0xF9, f"expected float16 head, got 0x{enc[0]:02x}"

    # Values that are NOT f16-representable still float32-ify correctly.
    @pytest.mark.parametrize("value", [65503.0, 100000.0, 1.1])
    def test_non_f16_values_use_larger_encoding(self, value):
        enc = ecf_encode(value)
        assert ecf_decode(enc) == value
        assert enc[0] in (0xFA, 0xFB), f"expected float32/64, got 0x{enc[0]:02x}"


class TestCExtensionAgreementOnNonFloatShapes:
    """`ecf_encode` uses cbor2's pure-Python encoder (so floats minimize per
    Rule 4 — see TestFloatMinimization). On every non-float shape the
    protocol actually exchanges, the pure-Py encoder must produce bytes
    identical to `cbor2.dumps(..., canonical=True)` — otherwise switching
    encoders would have introduced a cross-impl divergence elsewhere.

    Regression guard: if cbor2 ever changes its C-ext canonical output for
    these shapes (or its pure-Py output drifts), this test catches it
    before a peer-to-peer hash mismatch does.
    """

    @pytest.mark.parametrize("value", [
        # integer-encoding boundaries
        0, 1, 23, 24, 255, 256, 65535, 65536, -1, -24, -25, -256, -257,
        # byte strings of various lengths (incl. hash-shaped 33 bytes)
        b"", b"\x00", b"\x01" * 33, b"\xff" * 64,
        # text strings
        "", "x", "system/tree", "a" * 300,
        # collections
        [], [1, 2, 3], [b"\x01" * 33, "two", 3],
        {}, {"a": 1, "b": 2}, {"z": 1, "a": 2, "aa": 3},
        # 30-entry map (the tree:merge-request size class)
        {f"k{i:02d}": i for i in range(30)},
        # nested entity shape with hash-byte-string values
        {"type": "system/capability/token",
         "data": {"granter": b"\x01" * 33, "grantee": b"\x02" * 33,
                  "expires_at": 1737900000000}},
        # full envelope with hash-keyed `included`
        {"root": {"type": "t", "data": {}, "content_hash": b"\x00" + b"\x01" * 32},
         "included": {b"\x00" + b"\x01" * 32: {"type": "t", "data": {"x": 1}}}},
        # primitives
        None, True, False,
    ])
    def test_pure_py_matches_c_extension_on_non_float_shape(self, value):
        ecf_bytes = ecf_encode(value)
        cext_bytes = cbor2.dumps(value, canonical=True)
        assert ecf_bytes == cext_bytes, (
            f"ECF (pure-Py) diverged from cbor2 C-ext on {value!r:.60s}\n"
            f"  ECF:    {ecf_bytes.hex()}\n"
            f"  C-ext:  {cext_bytes.hex()}"
        )
