"""Strict Entity Canonical Form (ECF) validator.

Walks raw CBOR bytes and returns True iff the bytes meet the ECF canonical
rules from `ENTITY-CBOR-ENCODING.md` §§3-9 / RFC 8949 §4.2:

1. Definite lengths only — indefinite-length headers 0x5f / 0x7f / 0x9f /
   0xbf are forbidden.
2. Minimal arguments — every length / int argument uses the shortest of
   the inline / 1B / 2B / 4B / 8B forms that fits.
3. No tags (major type 6) — §6.3 forbids them at any depth.
4. No ``undefined`` (0xf7) and no simple values other than false/true/null.
5. Floats minimal per Rule 4 — every float MUST be encoded as the shortest
   of f16 / f32 / f64 that round-trips to the same value (with the canonical
   f16 NaN being 0x7e00).
6. Map keys sorted deterministically — shorter encoded key first, then
   lex-ascending byte-wise.

The function is the canonical-form check used by the `decode_reject`
conformance category. It does not attempt to recover from violations —
the first violation found returns False.
"""

from __future__ import annotations

import struct


def is_canonical_ecf(data: bytes) -> bool:
    """Return True iff ``data`` is a single valid canonical-ECF CBOR item.

    Trailing bytes after the item are a violation (canonical form is a
    single self-delimited item).
    """
    try:
        end = _validate_item(data, 0)
    except _NonCanonical:
        return False
    except (IndexError, struct.error):
        return False
    return end == len(data)


class _NonCanonical(Exception):
    pass


def _validate_item(data: bytes, pos: int) -> int:
    """Validate the CBOR item starting at ``pos``. Returns end offset."""
    if pos >= len(data):
        raise _NonCanonical("unexpected EOF")
    initial = data[pos]
    pos += 1
    major = initial >> 5
    info = initial & 0x1F

    # Major type 6 (tag) — forbidden in ECF.
    if major == 6:
        raise _NonCanonical("tag encountered (major type 6 forbidden in ECF)")

    # Major type 7 — primitives, simple values, floats, break.
    if major == 7:
        return _validate_primitive(data, pos, info)

    # Read argument with minimal-encoding check.
    arg, pos = _read_arg(data, pos, info, major_for_int_min=(major in (0, 1)))

    if major == 0:
        # uint — minimization already enforced by _read_arg
        return pos
    if major == 1:
        # nint — minimization already enforced (value = -1 - arg)
        return pos
    if major == 2:
        # byte string
        end = pos + arg
        if end > len(data):
            raise _NonCanonical("byte string truncated")
        return end
    if major == 3:
        # text string
        end = pos + arg
        if end > len(data):
            raise _NonCanonical("text string truncated")
        return end
    if major == 4:
        # array
        for _ in range(arg):
            pos = _validate_item(data, pos)
        return pos
    if major == 5:
        # map — validate each key/value and check key ordering
        prev_key: bytes | None = None
        for _ in range(arg):
            key_start = pos
            pos = _validate_item(data, pos)
            key_bytes = data[key_start:pos]
            if prev_key is not None and not _key_lt(prev_key, key_bytes):
                raise _NonCanonical("map keys not in canonical order")
            prev_key = key_bytes
            pos = _validate_item(data, pos)
        return pos

    raise _NonCanonical(f"unreachable major type {major}")


def _read_arg(
    data: bytes, pos: int, info: int, *, major_for_int_min: bool
) -> tuple[int, int]:
    """Read the unsigned argument; enforce minimal-length encoding.

    ``major_for_int_min`` is True when the argument IS the integer value
    (major types 0 and 1) — the minimization check is identical to that
    for length arguments (the smallest form that fits is required).
    """
    if info < 24:
        return info, pos
    if info == 24:
        if pos + 1 > len(data):
            raise _NonCanonical("truncated 1-byte arg")
        val = data[pos]
        if val < 24:
            raise _NonCanonical("non-minimal 1-byte arg")
        return val, pos + 1
    if info == 25:
        if pos + 2 > len(data):
            raise _NonCanonical("truncated 2-byte arg")
        val = (data[pos] << 8) | data[pos + 1]
        if val < 256:
            raise _NonCanonical("non-minimal 2-byte arg")
        return val, pos + 2
    if info == 26:
        if pos + 4 > len(data):
            raise _NonCanonical("truncated 4-byte arg")
        val = (
            (data[pos] << 24)
            | (data[pos + 1] << 16)
            | (data[pos + 2] << 8)
            | data[pos + 3]
        )
        if val < 65536:
            raise _NonCanonical("non-minimal 4-byte arg")
        return val, pos + 4
    if info == 27:
        if pos + 8 > len(data):
            raise _NonCanonical("truncated 8-byte arg")
        val = 0
        for i in range(8):
            val = (val << 8) | data[pos + i]
        if val < (1 << 32):
            raise _NonCanonical("non-minimal 8-byte arg")
        return val, pos + 8
    # 28, 29, 30 reserved; 31 = indefinite-length
    if info == 31:
        raise _NonCanonical("indefinite-length encoding forbidden in ECF")
    raise _NonCanonical(f"reserved additional-info value {info}")


def _validate_primitive(data: bytes, pos: int, info: int) -> int:
    """Validate a major-type-7 item starting after the initial byte."""
    if info < 20:
        # simple value 0..19 — not used in ECF
        raise _NonCanonical(f"simple value {info} not allowed in ECF")
    if info == 20:  # false
        return pos
    if info == 21:  # true
        return pos
    if info == 22:  # null
        return pos
    if info == 23:  # undefined — not allowed
        raise _NonCanonical("undefined (0xf7) not allowed in ECF")
    if info == 24:
        # one-byte simple value
        if pos >= len(data):
            raise _NonCanonical("truncated simple value")
        val = data[pos]
        if val < 32:
            raise _NonCanonical("non-minimal simple value encoding")
        # simple values 32..255 reserved / unassigned; reject conservatively
        raise _NonCanonical(f"simple value {val} not allowed in ECF")
    if info == 25:
        # f16
        if pos + 2 > len(data):
            raise _NonCanonical("truncated f16")
        return pos + 2
    if info == 26:
        # f32 — must NOT be representable as a shorter f16
        if pos + 4 > len(data):
            raise _NonCanonical("truncated f32")
        (val,) = struct.unpack(">f", data[pos : pos + 4])
        if _float_fits_f16(val):
            raise _NonCanonical("f32 value MUST be encoded as f16 (minimization)")
        return pos + 4
    if info == 27:
        # f64 — must NOT be representable as a shorter f32 or f16
        if pos + 8 > len(data):
            raise _NonCanonical("truncated f64")
        (val,) = struct.unpack(">d", data[pos : pos + 8])
        if _float_fits_f32(val):
            raise _NonCanonical("f64 value MUST be encoded as f32 or smaller")
        return pos + 8
    if info == 31:
        # break stop code — only valid inside indefinite items; canonical
        # forbids both.
        raise _NonCanonical("break stop code forbidden in ECF")
    # 28, 29, 30 reserved
    raise _NonCanonical(f"reserved additional-info value {info} for major 7")


def _float_fits_f32(val: float) -> bool:
    """True if ``val`` round-trips through f32 exactly (NaN handled)."""
    try:
        packed = struct.pack(">f", val)
    except (OverflowError, struct.error):
        return False
    (back,) = struct.unpack(">f", packed)
    if val != val:  # NaN
        return back != back
    return back == val


def _float_fits_f16(val: float) -> bool:
    """True if ``val`` round-trips through f16 exactly (NaN handled)."""
    try:
        packed = struct.pack(">e", val)
    except (OverflowError, struct.error):
        return False
    (back,) = struct.unpack(">e", packed)
    if val != val:  # NaN
        return back != back
    return back == val


def _key_lt(a: bytes, b: bytes) -> bool:
    """Canonical key-ordering predicate: shorter first, then lex-ascending."""
    if len(a) != len(b):
        return len(a) < len(b)
    return a < b
