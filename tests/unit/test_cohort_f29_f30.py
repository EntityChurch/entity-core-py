"""Cohort cross-bless probe — F29 + F30 corpus changes.

Drives the Python ECF encoder/validator against the candidate bytes in
`entity-system-architecture/docs/status/HANDOFF-2026-07-12-cohort-F29-F30-corpus.md`
so our verdicts + bytes can be reported back for the Appendix E.4 cross-bless.

No spec/wire change — `ENTITY-CBOR-ENCODING` §6.3 (no tags) and the text-head
rules are unchanged; these are corpus-coverage fixtures.

- F30 (decode_reject, no cross-bless): all five `tag_reject.*` MUST reject
  (`is_canonical_ecf` False → protocol boundary maps to `non_canonical_ecf`),
  and the tag-stripped structures MUST re-encode byte-exact (proving the tag
  is the *sole* rejection trigger, not trailing data).
- F29 (encode_equal, CROSS-BLESS REQUIRED): `nested.5` / `nested.6` MUST
  encode byte-identical to the Go reference bytes for the lock to proceed.

These are NOT in our local `test-vectors/v1/` corpus yet (still the 69-vector
`41d68d2d…`); the vectors are inlined here from the handoff. F29 locks upstream
only after Go × Rust × Python agree.
"""

from __future__ import annotations

from entity_core.conformance import is_canonical_ecf
from entity_core.utils.ecf import ecf_encode

# --- F30: tag_reject decode vectors (decoder MUST reject all five) -----------

TAG_REJECT_CANONICAL = {
    "tag_reject.1": "a26464617461a1627473c074323032362d30362d30365431323a30303a30305a647479706567746573742f7631",
    "tag_reject.2": "a26464617461a1627473c11a661fa680647479706567746573742f7631",
    "tag_reject.3": "a26464617461a1626964d82550112233445566778899aabbccddeeff00647479706567746573742f7631",
    "tag_reject.4": "d9d9f7a0",  # unchanged (real tag 55799)
    "tag_reject.5": (
        "a264726f6f74a26464617461a0647479706567746573742f763168696e636c75646564"
        "a15821000000000000000000000000000000000000000000000000000000000000000001"
        "a26464617461a1627473c074323032362d30362d30365431323a30303a30305a647479706567746573742f7631"
    ),
}


def test_f30_all_tag_reject_vectors_reject() -> None:
    """Every tag_reject vector fails the strict validator (→ non_canonical_ecf)."""
    for vid, hex_bytes in TAG_REJECT_CANONICAL.items():
        assert not is_canonical_ecf(bytes.fromhex(hex_bytes)), (
            f"{vid} was ACCEPTED by strict validator; expected rejection"
        )


# --- F30: tag-stripped structures the encoder MUST reproduce -----------------
# Same logical value, tag removed. Structure is already canonical, so our
# encoder MUST emit exactly these bytes — proving the rejection above was the
# tag (§6.3), not trailing-data / full-consumption.

STRIPPED_REPRODUCE = {
    ".1": (
        {"data": {"ts": "2026-06-06T12:00:00Z"}, "type": "test/v1"},
        "a26464617461a162747374323032362d30362d30365431323a30303a30305a647479706567746573742f7631",
    ),
    ".2": (
        {"data": {"ts": 1713350272}, "type": "test/v1"},
        "a26464617461a16274731a661fa680647479706567746573742f7631",
    ),
    ".3": (
        {"data": {"id": bytes.fromhex("112233445566778899aabbccddeeff00")}, "type": "test/v1"},
        "a26464617461a162696450112233445566778899aabbccddeeff00647479706567746573742f7631",
    ),
    ".5": (
        {
            "root": {"data": {}, "type": "test/v1"},
            "included": {
                bytes.fromhex("00" * 32 + "01"): {
                    "data": {"ts": "2026-06-06T12:00:00Z"},
                    "type": "test/v1",
                }
            },
        },
        (
            "a264726f6f74a26464617461a0647479706567746573742f763168696e636c75646564"
            "a15821000000000000000000000000000000000000000000000000000000000000000001"
            "a26464617461a162747374323032362d30362d30365431323a30303a30305a647479706567746573742f7631"
        ),
    ),
}


def test_f30_stripped_structures_reencode_byte_exact() -> None:
    """Tag-stripped canonical structures round-trip through our encoder byte-exact."""
    for label, (input_val, expected_hex) in STRIPPED_REPRODUCE.items():
        got = ecf_encode(input_val).hex()
        assert got == expected_hex, (
            f"stripped {label} mismatch\n  expected {expected_hex}\n  got      {got}"
        )


# --- F29: encode_equal cross-bless vectors -----------------------------------
# Boundary of the CBOR text head (1-byte → head+length-byte) INSIDE an array
# element. Must byte-match the Go reference for the E.4 lock.

NESTED_5_INPUT = [{"k": "a" * 24}, {"k": "b" * 30}]
NESTED_5_EXPECTED = (
    "82a1616b7818" + "61" * 24 + "a1616b781e" + "62" * 30
)  # inner text heads 0x78 0x18 (24), 0x78 0x1e (30)

NESTED_6_INPUT = [{"k": "c" * 256}]
NESTED_6_EXPECTED = "81a1616b790100" + "63" * 256  # inner text head 0x79 0x0100 (256)


def test_f29_nested_5_matches_go_reference() -> None:
    assert ecf_encode(NESTED_5_INPUT).hex() == NESTED_5_EXPECTED


def test_f29_nested_6_matches_go_reference() -> None:
    assert ecf_encode(NESTED_6_INPUT).hex() == NESTED_6_EXPECTED
