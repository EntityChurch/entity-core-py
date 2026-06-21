"""Wire-conformance harness — emit-canonical pin tests.

Pins:
- diag parser handles every shape in the v1 corpus (no errors).
- strict ECF validator rejects every authored tag_reject vector.
- emit-canonical is deterministic across two runs (same input → same bytes).
- Class A spot-checks against RFC 8949 §4.2 canonical encodings.
"""

from __future__ import annotations

import math
from pathlib import Path

import cbor2

from entity_core.conformance import (
    emit_canonical,
    is_canonical_ecf,
    load_corpus,
    parse_diag,
)
from entity_core.conformance.emit import encode_emission

CORPUS_PATH = (
    Path(__file__).resolve().parents[2]
    / "test-vectors"
    / "v1"
    / "conformance-vectors-v1.diag"
)


def test_corpus_loads_with_expected_shape() -> None:
    corpus = load_corpus(str(CORPUS_PATH))
    assert len(corpus) == 69
    kinds = {v["kind"] for v in corpus}
    assert kinds == {"encode_equal", "decode_reject"}
    # Every vector has the expected fields
    for v in corpus:
        assert "id" in v and "description" in v and "kind" in v
        if v["kind"] == "encode_equal":
            assert "input" in v
        else:
            assert "canonical" in v


def test_emit_canonical_no_errors() -> None:
    corpus = load_corpus(str(CORPUS_PATH))
    emission = emit_canonical(corpus, "test")
    assert emission["impl"] == "core-py"
    assert emission["corpus_version"] == "v1"
    assert emission["spec_version"] == "1.5"
    assert len(emission["encode_results"]) == 64
    assert len(emission["decode_results"]) == 5
    assert emission["errors"] == {}


def test_emission_is_deterministic() -> None:
    corpus = load_corpus(str(CORPUS_PATH))
    a = encode_emission(emit_canonical(corpus, "test"))
    b = encode_emission(emit_canonical(corpus, "test"))
    assert a == b


def test_all_decode_rejects_are_caught() -> None:
    corpus = load_corpus(str(CORPUS_PATH))
    emission = emit_canonical(corpus, "test")
    for vid, rejected in emission["decode_results"].items():
        assert rejected is True, f"{vid} was not rejected by strict validator"


def test_class_a_spot_checks() -> None:
    corpus = load_corpus(str(CORPUS_PATH))
    emission = emit_canonical(corpus, "test")
    results = emission["encode_results"]
    # RFC 8949 §4.2 canonical encodings
    assert results["int.1"] == b"\x00"           # uint 0
    assert results["int.2"] == b"\x17"           # uint 23 (last inline)
    assert results["int.3"] == b"\x18\x18"       # uint 24 (first 1-byte)
    assert results["length.2"] == b"\xa0"        # empty map
    assert results["length.1"] == b"\x80"        # empty array
    assert results["length.3"] == b"\x60"        # empty text
    assert results["length.4"] == b"\x40"        # empty bytes
    assert results["primitive.1"] == b"\xf6"     # null
    assert results["primitive.2"] == b"\xf5"     # true
    assert results["primitive.3"] == b"\xf4"     # false
    # Float battery — Rule 4 minimization
    assert results["float.1"] == b"\xf9\x00\x00"        # 0.0 → f16
    assert results["float.3"] == b"\xf9\x3c\x00"        # 1.0 → f16
    assert results["float.5"] == b"\xf9\x7c\x00"        # +inf → f16
    assert results["float.7"] == b"\xf9\x7e\x00"        # NaN → f16 canonical
    assert results["float.10"] == b"\xf9\x7b\xff"       # 65504.0 → f16 (max)
    assert results["float.12"][0] == 0xFA               # 65503.0 → f32
    assert results["float.14"] == b"\xfb\x3f\xf1\x99\x99\x99\x99\x99\x9a"  # 1.1 → f64


def test_strict_validator_accepts_canonical_emission() -> None:
    corpus = load_corpus(str(CORPUS_PATH))
    encoded = encode_emission(emit_canonical(corpus, "test"))
    assert is_canonical_ecf(encoded)


def test_strict_validator_rejects_tags() -> None:
    # Tag 0 wrapping a timestamp string — exact tag_reject.1 wire bytes.
    bad = bytes.fromhex("c074323032362d30362d30365431323a30303a30305a")
    assert not is_canonical_ecf(bad)


def test_strict_validator_rejects_indefinite_length() -> None:
    # 0x9f = indefinite-length array start
    assert not is_canonical_ecf(b"\x9f\x01\xff")


def test_strict_validator_rejects_non_minimal_int() -> None:
    # Uint 0 encoded with explicit 1-byte arg: 0x18 0x00 (should be 0x00)
    assert not is_canonical_ecf(b"\x18\x00")


def test_strict_validator_rejects_unsorted_map_keys() -> None:
    # {"b": 1, "a": 2} — wrong sort order
    bad = b"\xa2\x61\x62\x01\x61\x61\x02"
    assert not is_canonical_ecf(bad)
    # Sorted {"a": 2, "b": 1} should accept
    good = b"\xa2\x61\x61\x02\x61\x62\x01"
    assert is_canonical_ecf(good)


def test_diag_parser_keywords_and_specials() -> None:
    val = parse_diag('{"a": true, "b": false, "c": null, "d": Infinity, "e": -Infinity, "f": NaN}')
    assert val["a"] is True
    assert val["b"] is False
    assert val["c"] is None
    assert val["d"] == math.inf
    assert val["e"] == -math.inf
    assert math.isnan(val["f"])


def test_diag_parser_byte_string_with_whitespace() -> None:
    val = parse_diag("h'01 02 03'")
    assert val == b"\x01\x02\x03"


def test_multicodec_varint_boundaries() -> None:
    """V7 §7.3 — LEB128 multicodec varint, not CBOR-uint argument encoding."""
    from entity_core.conformance.emit import _multicodec_varint
    # Single-byte (no continuation)
    assert _multicodec_varint(0) == b"\x00"
    assert _multicodec_varint(1) == b"\x01"
    assert _multicodec_varint(127) == b"\x7f"
    # 2-byte boundary (continuation bit on first byte)
    assert _multicodec_varint(128) == b"\x80\x01"
    assert _multicodec_varint(255) == b"\xff\x01"
    assert _multicodec_varint(16383) == b"\xff\x7f"
    # 3-byte boundary
    assert _multicodec_varint(16384) == b"\x80\x80\x01"


def test_varint_matches_go_rust_emission() -> None:
    """content_hash.4 and peer_id.3 must byte-match Go/Rust emission.

    Pinned from the conformance v1 3-way diff: Go and Rust agree
    on multicodec LEB128 (`0x80 0x01` for 128). Python's earlier CBOR-uint
    interpretation (`0x18 0x80`) was the divergence.
    """
    corpus = load_corpus(str(CORPUS_PATH))
    e = emit_canonical(corpus, "test")
    # content_hash.4: 0x80 0x01 ‖ <32-byte digest>
    ch4 = e["encode_results"]["content_hash.4"]
    assert ch4[:2] == b"\x80\x01"
    assert len(ch4) == 34
    # peer_id.3 ECF-encoded tstr starts with 0x78 0x30 (tstr length 48);
    # decode the Base58 to verify the inner prefix is 0x80 0x01 0x01.
    import base58
    assert e["encode_results"]["peer_id.3"][:2] == b"\x78\x30"
    pid_str = e["encode_results"]["peer_id.3"][2:].decode("ascii")
    raw = base58.b58decode(pid_str)
    assert raw[:3] == b"\x80\x01\x01"


def test_diag_parser_handles_comments() -> None:
    src = """
    / this is a comment /
    {
      "x": 1
    }
    """
    assert parse_diag(src) == {"x": 1}
