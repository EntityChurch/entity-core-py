"""Entity Canonical Form (ECF) encoding.

ECF is CBOR deterministic encoding per RFC 8949 Section 4.2.
Used for content-addressable hashing.

Rules per RFC 8949 §4.2:
- Map keys sorted by encoded byte length, then lexicographically
- Minimal integer encoding
- Shortest float encoding preserving value
- Definite lengths only

V4 Hash Format:
- Hash is flat bytes: algorithm (1 byte) + digest (N bytes)
- For SHA-256: 33 bytes total (1 + 32)
- Algorithm identifiers:
  - 0x00 = ECFv1-SHA-256 (32-byte digest)
  - 0x01 = ECFv1-SHA-384 (48-byte digest)
  - 0x02 = ECFv1-SHA-512 (64-byte digest)
"""

from __future__ import annotations

import hashlib
import io
from typing import Any

import threading

import cbor2
import cbor2._decoder as _cbor2_dec
# cbor2's C extension (the default backing of cbor2.dumps) does NOT minimize
# float16-representable values at |x| >= 2**15 (e.g. 32768.0, 65504.0) — it
# emits float32. That violates RFC 8949 §4.2 Rule 4 ("shortest float encoding
# preserving value") / ENTITY-CBOR-ENCODING §3.2 Rule 4, and creates a latent
# hash divergence with Rust/Go (both of which minimize properly: Rust via a
# hand-written `try_encode_half`, Go via fxamacker's CoreDetEncOptions).
#
# The pure-Python encoder shipped in `cbor2._encoder` implements Rule 4
# correctly (its `encode_minimal_float` tries f64→f32→f16 and keeps the
# shortest that round-trips). It is byte-identical to the C extension on
# every non-float shape the protocol exchanges (verified across the
# canonical-encoding test matrix). We use it for ECF emit; decode stays on
# the C extension since canonical-form choices do not apply on decode.
#
# Trade-off: ~8× slower than the C extension. Still ~1000+ envelope encodes
# per second on a realistic 30-entity merge-request shape — not the
# bottleneck. If encode throughput ever matters, the right replacement is a
# hand-rolled encoder mirroring Rust's `core/ecf/src/encoder.rs`, not a
# return to the buggy C path.
from cbor2._encoder import CBOREncoder as _PyCBOREncoder

# The pure-Python encoder only registers its own `cbor2._types.CBORTag` /
# `CBORSimpleValue` / `undefined` classes. The C-extension decoder returns
# instances of the *C-extension's* `_cbor2.CBORTag` / `CBORSimpleValue` /
# `undefined` — distinct classes the pure-Python encoder rejects with
# "cannot serialize type CBORTag". The two share their public shape
# (.tag / .value attributes), so we register adapters mapping the C-ext
# types to the existing pure-Python encode methods. This is what lets a
# decode-then-encode round-trip stay byte-faithful for tagged data on the
# wire.
import _cbor2 as _cext_types  # noqa: E402


def _register_cext_type_adapters(encoder: _PyCBOREncoder) -> None:
    encoder._encoders[_cext_types.CBORTag] = _PyCBOREncoder.encode_semantic
    encoder._encoders[_cext_types.CBORSimpleValue] = _PyCBOREncoder.encode_simple_value
    encoder._encoders[type(_cext_types.undefined)] = _PyCBOREncoder.encode_undefined

# Algorithm identifiers per ENTITY-CBOR-ENCODING §8.2
ALG_ECFV1_SHA256: int = 0x00
ALG_ECFV1_SHA384: int = 0x01
ALG_ECFV1_SHA512: int = 0x02

# Expected digest sizes per algorithm
DIGEST_SIZES: dict[int, int] = {
    ALG_ECFV1_SHA256: 32,
    ALG_ECFV1_SHA384: 48,
    ALG_ECFV1_SHA512: 64,
}

# Human-readable algorithm names (for display/logging only)
ALGORITHM_NAMES: dict[int, str] = {
    ALG_ECFV1_SHA256: "ecfv1-sha256",
    ALG_ECFV1_SHA384: "ecfv1-sha384",
    ALG_ECFV1_SHA512: "ecfv1-sha512",
}

# Type alias: Hash is bytes (algorithm byte + digest)
# For SHA-256: 33 bytes (1 + 32)
Hash = bytes


def ecf_encode(obj: Any) -> bytes:
    """Encode to Entity Canonical Form (deterministic CBOR).

    Args:
        obj: Any CBOR-serializable object.

    Returns:
        Deterministic CBOR bytes.

    Rules per RFC 8949 §4.2:
    - Map keys sorted by encoded byte length, then lexicographically
    - Minimal integer encoding
    - Shortest float encoding preserving value (Rule 4 — see module note
      on why this goes through the pure-Python encoder, not cbor2.dumps)
    - Definite lengths only
    """
    buf = io.BytesIO()
    encoder = _PyCBOREncoder(buf, canonical=True)
    _register_cext_type_adapters(encoder)
    encoder.encode(obj)
    return buf.getvalue()


# Lock guarding the cbor2.semantic_decoders monkey-patch in ecf_decode.
# asyncio is single-threaded so contention is essentially nil, but the lock
# keeps the swap safe if user code ever calls ecf_decode from a thread pool
# (e.g. asyncio.to_thread). Patch is held for ~microseconds per call.
_ECF_DECODE_LOCK = threading.Lock()


def ecf_decode(data: bytes) -> Any:
    """Decode CBOR bytes with byte-fidelity for entity data fields.

    All CBOR semantic tags (tag-55799 self-describe, tag-0/1 datetimes,
    tag-2/3 big-ints, tag-37 UUID, …) are preserved as ``CBORTag`` instances
    rather than transformed/stripped. This lets ``ecf_encode`` round-trip
    the bytes verbatim, which V7 §1.8 byte-fidelity (and downstream hash
    verification) requires.

    Without this, cbor2's default ``loads`` silently strips tag-55799 —
    breaking hash check on any entity whose ``data`` field carries that
    marker (surfaced by ``tag_reject.4`` in the v1 conformance corpus).

    Implementation: cbor2's pure-Python decoder dispatches tags via a
    module-level ``semantic_decoders`` table; the fall-through path already
    wraps as ``CBORTag``. Swap the table to empty for the duration of the
    call so every tag falls through. (Goes through the pure-Py decoder —
    cbor2's C extension has its own hard-coded tag dispatch we can't
    intercept.)
    """
    original = _cbor2_dec.semantic_decoders
    with _ECF_DECODE_LOCK:
        _cbor2_dec.semantic_decoders = {}
        try:
            return _cbor2_dec.loads(data)
        finally:
            _cbor2_dec.semantic_decoders = original


class UnsupportedContentHashFormatError(ValueError):
    """V7 v7.67 §2.3 / FORMAT-CODE-INTERPRETATION-1 (renamed from v7.66
    PREFIX-DISPATCH-1) — content_hash format-code interpretation saw an
    unrecognized leading varint of a ``content_hash``. Subclass of
    ValueError for back-compat with callers that catch ValueError;
    protocol boundary maps to ``400 unsupported_content_hash_format``
    (V7 §4.7, added per v7.66 §7.1)."""


def content_hash_format(content_hash: Hash) -> int:
    """V7 v7.67 §2.3 — interpret the leading varint of a ``content_hash``
    as the ``content_hash_format`` code.

    Today every allocated format code is single-byte (< 0x80) so the
    leading byte IS the code; multi-byte LEB128 decode is mandatory per
    v7.67 §5.4 for forward-compat. Use ``decode_content_hash_format`` for
    the full LEB128-aware decode that also returns the digest offset.

    Raises ``ValueError`` on empty input.
    """
    if not content_hash:
        raise ValueError("content_hash is empty; no format-code byte")
    return content_hash[0]


def decode_content_hash_format(content_hash: Hash) -> tuple[int, int]:
    """V7 v7.67 §5.4 — decode the leading multi-byte LEB128 varint of a
    ``content_hash`` per V7 §7.3 and return ``(format_code, digest_offset)``.

    The single-byte happy path returns ``(content_hash[0], 1)``;
    multi-byte sequences (leading byte ≥ 0x80) walk the LEB128 chain.
    Raises :class:`UnsupportedContentHashFormatError` if the decoded
    value is 255 (v7.67 §5.3 reserved) or not in
    :data:`SUPPORTED_CONTENT_HASH_FORMATS`. Raises ``ValueError`` on
    truncated input.
    """
    from entity_core.utils.varint import decode_leb128

    code, n = decode_leb128(content_hash)
    if code == 0xFF:
        raise UnsupportedContentHashFormatError(
            "content_hash_format value 0xFF is reserved (v7.67 §5.3); "
            "SHALL NOT be allocated as an algorithm code"
        )
    if code not in SUPPORTED_CONTENT_HASH_FORMATS:
        raise UnsupportedContentHashFormatError(
            f"unsupported content_hash_format {code:#x}; "
            f"supported: {sorted(SUPPORTED_CONTENT_HASH_FORMATS)}"
        )
    return code, n


# V7 v7.67 §4.1 — supported format-code set. Production: 0x00 (ECFv1-SHA-256,
# validated since v7.0). VALIDATE at v7.67: 0x01 (ECFv1-SHA-384), 0x03
# (ECFv1-BLAKE3-256, Phase 3a). The 0x01 slot is wired here; the BLAKE3
# allocation lands at Phase 3a (gated on Phase 1 + 2). Update this set
# when promoting a reserved slot to validated.
SUPPORTED_CONTENT_HASH_FORMATS: frozenset[int] = frozenset({
    ALG_ECFV1_SHA256,
    ALG_ECFV1_SHA384,
})


def validate_supported_content_hash_format(content_hash: Hash) -> int:
    """V7 v7.67 §2.3 — validate the leading varint is a supported format code.

    Returns the format code on success; raises
    :class:`UnsupportedContentHashFormatError` otherwise. Used by
    content-store lookup, cap-chain verification, and any other read
    path that needs to interpret the format code (FORMAT-CODE-INTERPRETATION-1,
    renamed from v7.66 PREFIX-DISPATCH-1).
    """
    code, _ = decode_content_hash_format(content_hash)
    return code


def validate_content_hash_format_code(code: int) -> int:
    """V7 v7.67 §5.3 — validate a bare ``content_hash_format`` integer
    value (already decoded from varint or supplied by an entity-data field).

    Rejects the reserved value 255 per §5.3 and any code not in
    :data:`SUPPORTED_CONTENT_HASH_FORMATS`. Raises
    :class:`UnsupportedContentHashFormatError`.
    """
    if code == 0xFF:
        raise UnsupportedContentHashFormatError(
            "content_hash_format value 0xFF is reserved (v7.67 §5.3); "
            "SHALL NOT be allocated as an algorithm code"
        )
    if code not in SUPPORTED_CONTENT_HASH_FORMATS:
        raise UnsupportedContentHashFormatError(
            f"unsupported content_hash_format {code:#x}; "
            f"supported: {sorted(SUPPORTED_CONTENT_HASH_FORMATS)}"
        )
    return code


# ---------------------------------------------------------------------------
# V7 v7.69 §4.5 — content_hash_format negotiation primitives
#
# The negotiated format is the connection's single active value (§4.5a): both
# peers author every transmitted entity under it. These helpers translate
# between the entity-data/hello string surface (``"ecfv1-sha256"``) and the
# wire format-code byte (``0x00``), expose a process-global default for
# non-connection-bound authoring (peer-startup one-shot mints), and compute
# the deterministic first-match-in-initiator-order intersection.
# ---------------------------------------------------------------------------

# Inverse of ALGORITHM_NAMES, restricted to formats this impl can author.
ALGORITHM_CODES: dict[str, int] = {
    ALGORITHM_NAMES[code]: code for code in SUPPORTED_CONTENT_HASH_FORMATS
}

# Process-global default hash algorithm. Used by ``Entity.compute_hash`` and
# ``compute_content_hash`` when no explicit per-entity/per-connection algorithm
# is threaded — i.e. for peer-startup local state and other non-connection-
# bound authoring (the Go analog is ``entity.DefaultHashAlgorithm()``). The
# §4.5a per-connection active format is threaded EXPLICITLY (the ``algorithm``
# parameter on the authoring entry points); it never mutates this global, so
# concurrent connections negotiating different formats don't race.
_DEFAULT_HASH_ALGORITHM: int = ALG_ECFV1_SHA256


def get_default_hash_algorithm() -> int:
    """Return the process-global default content_hash_format code."""
    return _DEFAULT_HASH_ALGORITHM


def set_default_hash_algorithm(code: int) -> None:
    """Set the process-global default content_hash_format (e.g. a peer booted
    with ``--hash-type sha384``). Validated against the supported set.

    This is the non-connection-bound default ONLY. Connection-bound authoring
    (handshake caps/signatures/identities, ongoing authenticated EXECUTEs)
    threads the negotiated active format explicitly and ignores this global.
    """
    global _DEFAULT_HASH_ALGORITHM
    _DEFAULT_HASH_ALGORITHM = validate_content_hash_format_code(code)


def hash_format_name(code: int) -> str:
    """Map a format code to its hello/entity-data string (``0x00`` → ``"ecfv1-sha256"``)."""
    return ALGORITHM_NAMES.get(code, f"unknown-{code}")


def hash_format_code(name: str) -> int | None:
    """Map a hello/entity-data string to its format code, or None if unsupported."""
    return ALGORITHM_CODES.get(name)


# V7 v7.69 §4.2 (handoff) — key_types is an accept-set, identity-bound: each
# peer advertises every key_type it can VERIFY. Matches Go DefaultAdvertisedKeyTypes().
DEFAULT_ADVERTISED_KEY_TYPES: list[str] = ["ed25519", "ed448"]


def default_advertised_hash_formats(default: int | None = None) -> list[str]:
    """Preference-ordered hash_formats this peer advertises in its hello.

    Matches Go ``DefaultAdvertisedHashFormats()`` exactly: the peer's home
    format first, then the SHA-256 floor as a downgrade target (only if the
    home format isn't already SHA-256). SHA-384 peer → ``["ecfv1-sha384",
    "ecfv1-sha256"]``; SHA-256 peer → ``["ecfv1-sha256"]``.

    A home peer advertises only its home format + the universal SHA-256 floor,
    NOT every format it could technically author. This keeps a SHA-256 peer
    purely SHA-256 unless explicitly booted under another format, and makes
    SHA-256 the deterministic common downgrade for cross-impl convergence.
    """
    if default is None:
        default = get_default_hash_algorithm()
    ordered: list[int] = [default]
    if default != ALG_ECFV1_SHA256:
        ordered.append(ALG_ECFV1_SHA256)
    return [hash_format_name(c) for c in ordered]


def negotiate_active_hash_format(
    initiator_formats: list[str], responder_formats: list[str],
) -> int | None:
    """V7 v7.69 §4.5 single-active-value negotiation.

    Returns the format CODE of the first entry in the **initiator's**
    preference order that the responder also advertises and this impl
    supports, or ``None`` if the intersection is empty (caller maps to
    ``400 incompatible_hash_format``). Both peers run this identically
    (initiator over its own list, responder over the received list) and
    converge on the same active value.
    """
    responder_set = set(responder_formats)
    for name in initiator_formats:
        if name in responder_set:
            code = hash_format_code(name)
            if code is not None:
                return code
    return None


def compute_ecf_hash(obj: Any, algorithm: int = ALG_ECFV1_SHA256) -> Hash:
    """Compute ECF hash: algorithm byte + SHA-256 of ECF-encoded bytes.

    Args:
        obj: Object to hash (typically {"type": ..., "data": ...}).
        algorithm: Hash algorithm to use (default: ECFv1-SHA-256).

    Returns:
        Hash as bytes: algorithm (1 byte) + digest (N bytes).

    Raises:
        ValueError: If algorithm is not supported.
    """
    ecf_bytes = ecf_encode(obj)

    if algorithm == ALG_ECFV1_SHA256:
        digest = hashlib.sha256(ecf_bytes).digest()
    elif algorithm == ALG_ECFV1_SHA384:
        digest = hashlib.sha384(ecf_bytes).digest()
    elif algorithm == ALG_ECFV1_SHA512:
        digest = hashlib.sha512(ecf_bytes).digest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return bytes([algorithm]) + digest


def hash_equals(a: Hash | None, b: Hash | None) -> bool:
    """Compare two hashes for equality.

    Args:
        a: First hash (or None).
        b: Second hash (or None).

    Returns:
        True if hashes are equal.
    """
    return a == b


def get_hash_algorithm(h: Hash) -> int:
    """Get the algorithm byte from a hash.

    Args:
        h: Hash bytes.

    Returns:
        Algorithm identifier (first byte).
    """
    if len(h) < 1:
        raise ValueError("Hash too short")
    return h[0]


def get_hash_digest(h: Hash) -> bytes:
    """Get the digest bytes from a hash.

    Args:
        h: Hash bytes.

    Returns:
        Digest bytes (everything after algorithm byte).
    """
    if len(h) < 1:
        raise ValueError("Hash too short")
    return h[1:]


def hash_to_display(h: Hash) -> str:
    """Convert hash to human-readable display string.

    For logging and debugging only - never used on wire.

    Args:
        h: Hash bytes.

    Returns:
        Human-readable string like "ecfv1-sha256:abcd1234...".
    """
    if len(h) < 1:
        return "invalid:empty"
    algorithm = h[0]
    digest = h[1:]
    alg_name = ALGORITHM_NAMES.get(algorithm, f"unknown-{algorithm}")
    return f"{alg_name}:{digest.hex()}"


def hash_to_short(h: Hash, length: int = 8) -> str:
    """Convert hash to short display string.

    For compact logging - shows only first N hex characters.

    Args:
        h: Hash bytes.
        length: Number of hex characters to show.

    Returns:
        Short string like "abcd1234...".
    """
    if len(h) < 2:
        return "..."
    digest = h[1:]
    hex_digest = digest.hex()
    return f"{hex_digest[:length]}..."


def validate_hash(h: Hash) -> None:
    """Validate hash structure and algorithm.

    V7 v7.66 §5.2 — format-code dispatch contract. The leading byte
    selects the format-specific decoder/verifier; unsupported format
    codes raise :class:`UnsupportedContentHashFormatError` (subclass of
    ValueError; protocol boundary maps to
    ``400 unsupported_content_hash_format``).

    Raises:
        ValueError: hash too short or digest-length mismatch.
        UnsupportedContentHashFormatError: leading format-code byte is
            not in :data:`SUPPORTED_CONTENT_HASH_FORMATS`.
    """
    if len(h) < 1:
        raise ValueError("Hash too short")

    algorithm = h[0]
    digest = h[1:]

    if algorithm not in SUPPORTED_CONTENT_HASH_FORMATS:
        raise UnsupportedContentHashFormatError(
            f"unsupported_content_hash_format: format-code {algorithm:#x} "
            f"not in supported set {sorted(SUPPORTED_CONTENT_HASH_FORMATS)}"
        )

    expected_size = DIGEST_SIZES[algorithm]
    if len(digest) != expected_size:
        raise ValueError(
            f"Invalid digest length for algorithm {algorithm}: "
            f"expected {expected_size}, got {len(digest)}"
        )


def is_zero_hash(h: object) -> bool:
    """True for the reserved zero/empty hash sentinel.

    The zero hash is the all-zero (or empty) byte value — never a valid
    content hash (a real hash carries a nonzero structure). It is the V7 §3.9
    CAS-create sentinel (zero ``expected_hash`` ⇒ "expect path unbound"), the
    bearer-cap zero-grantee marker, and the revision "full-closure base"
    signal.

    Note ``None`` (an absent value) is also treated as zero here; callers that
    must distinguish "field omitted" (e.g. unconditional put) from "present and
    zero" (CAS-create) MUST check presence before calling this.
    """
    if h is None:
        return True
    if isinstance(h, (bytes, bytearray)):
        return len(h) == 0 or not any(h)
    return False


def is_hash_ref(val: object) -> bool:
    """True if ``val`` is a flat hash reference (algorithm byte + digest).

    A hash reference is bytes whose leading format byte names a known algorithm
    and whose length matches that algorithm's digest size (e.g. 33 bytes for
    ECFv1-SHA-256, 49 for SHA-384, 65 for SHA-512). This is the crypto-agile
    way to recognize an embedded reference in entity data — prefer it over a
    fixed ``len(val) == 33`` check, which silently fails to spot a reference
    once a digest of a different length is in use.
    """
    if not isinstance(val, (bytes, bytearray)) or len(val) < 1:
        return False
    expected_size = DIGEST_SIZES.get(val[0])
    return expected_size is not None and len(val) == 1 + expected_size


# Wire format functions - simplified since hash IS bytes now

def hash_to_wire(h: Hash) -> bytes:
    """Convert hash to wire format (identity — hash is already bytes)."""
    return h


def wire_to_hash(wire: bytes) -> Hash:
    """Validate a wire-format hash (algorithm byte + digest) and return it.

    Args:
        wire: Raw hash bytes.

    Returns:
        Hash bytes.

    Raises:
        ValueError: If wire format is invalid.
    """
    if not isinstance(wire, bytes):
        raise ValueError(f"Invalid wire hash format: {type(wire)}")
    validate_hash(wire)
    return wire


def hash_to_string(h: Hash) -> str:
    """Convert hash to a human-readable string (for CLI display).

    Args:
        h: Hash bytes.

    Returns:
        String like "ecf-sha256:<hex>".
    """
    if len(h) < 1:
        raise ValueError("Hash too short")
    algorithm = h[0]
    digest = h[1:]

    if algorithm == ALG_ECFV1_SHA256:
        return f"ecf-sha256:{digest.hex()}"
    elif algorithm == ALG_ECFV1_SHA384:
        return f"ecf-sha384:{digest.hex()}"
    elif algorithm == ALG_ECFV1_SHA512:
        return f"ecf-sha512:{digest.hex()}"
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


def normalize_hash(h: Any) -> Hash | None:
    """Return h if it is a bytes hash, else None.

    Args:
        h: A candidate hash value.

    Returns:
        The bytes hash, or None if h is None or not bytes.
    """
    if isinstance(h, bytes):
        return h
    return None
