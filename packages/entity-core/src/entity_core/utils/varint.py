"""Multicodec-style LEB128 varint codec per V7 §7.3.

V7 v7.67 §5 ties two normative properties to this codec:

1. **Multi-byte decode mandatory** — encodings with leading-byte ``≥ 0x80``
   are normal multi-byte LEB128 sequences and impls MUST decode them
   correctly even when no current production allocation exceeds ``0x7F``.
2. **Value 255 reserved** on both the ``key_type`` axis and the
   ``content_hash_format`` axis — SHALL NOT be allocated as an algorithm
   code. The LEB128 encoding of value 255 happens to be the two-byte
   sequence ``0xFF 0x01`` (``0xFF`` has the continuation bit set; ``0x01``
   carries the high bits); what's forbidden is the integer value 255.

Codes 0–127 encode as a single byte (no continuation bit); codes ≥ 128
chain with the continuation bit (MSB) set on every non-final byte. Not
the same as CBOR's argument encoding — CBOR uses major-type-bits +
fixed-length argument, multicodec chains 7-bit groups.
"""

from __future__ import annotations


def encode_leb128(n: int) -> bytes:
    """Encode a non-negative integer as a multicodec-style LEB128 varint.

    Single-byte happy path for ``n < 0x80``; multi-byte sequences chain
    7-bit groups with the continuation bit (MSB) on every non-final byte.
    """
    if n < 0:
        raise ValueError(f"negative varint not supported: {n}")
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def decode_leb128(data: bytes, *, offset: int = 0, max_bytes: int = 9) -> tuple[int, int]:
    """Decode a multicodec-style LEB128 varint from ``data`` starting at
    ``offset``; return ``(value, bytes_consumed)``.

    ``max_bytes`` caps the chain length at 9 bytes (covers any uint63
    value, which is far beyond any allocation horizon for the protocol-level
    fields that use this codec).

    Raises ``ValueError`` on truncated input (continuation bit set at the
    last byte read) or on a chain longer than ``max_bytes``.
    """
    if offset >= len(data):
        raise ValueError(f"varint truncated: no bytes at offset {offset}")
    value = 0
    shift = 0
    consumed = 0
    while consumed < max_bytes:
        if offset + consumed >= len(data):
            raise ValueError(
                f"varint truncated at byte {consumed}: continuation bit set "
                f"but no further bytes available"
            )
        b = data[offset + consumed]
        value |= (b & 0x7F) << shift
        consumed += 1
        if (b & 0x80) == 0:
            return value, consumed
        shift += 7
    raise ValueError(
        f"varint exceeds maximum {max_bytes} bytes; refusing to decode"
    )
