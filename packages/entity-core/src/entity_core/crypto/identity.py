"""Ed25519 keypair and peer ID derivation.

V7 v7.65 §1.5 / §7.4 — PeerID := Base58(varint(key_type) || varint(hash_type) || digest).

**Two `key_type` surfaces (V7 v7.66 §2 errata — DO NOT CONFLATE):**

This module deals with the *binary peer_id wire-format prefix* surface only:
``key_type`` here is a ``uint8`` varint byte (``0x01`` for Ed25519,
``0xFE`` for the test-synthetic experimental cryptosystem). The
*entity-data field* surface lives on ``system/peer.data.key_type``
and is a ``primitive/string`` (lowercase ASCII: ``"ed25519"``,
``"experimental-test"``); see ``protocol/auth.py:create_peer_entity``.
The two surfaces share a name but encode separately, occupy separate
namespaces, and SHALL NOT be conflated.

**Canonical form per key_type (v7.65 §4 + v7.66 §4.4 MUST):**
- ``key_type = 0x01`` (Ed25519) → canonical ``hash_type = 0x00`` (identity multihash).
- ``key_type = 0xFE`` (experimental-test, 64-byte pubkey) → canonical
  ``hash_type = 0x01`` (SHA-256-form), forced by size (identity-form
  would yield a 66-byte raw segment, above the v7.65 §10 informative floor).
  Peer-ID construction MUST use canonical form per key_type; mint-side
  legacy paths (SHA-256-form for Ed25519) are removed (v7.66 §3).

**Wire-acceptance carve-out (v7.65 §5 MAY decode + MUST canonicalize):**
- ``derive_peer_from_peer_id`` retains SHA-256-form decode for legacy peers.
- ``decode_peer_id`` is length-agnostic (PIM-5) and accepts non-canonical
  ``(key_type, hash_type)`` pairs for wire-decode round-trip.

Per §4: digest forms by hash_type —
- ``hash_type = 0x00`` (identity): ``digest = public_key`` (raw key bytes).
  Self-resolving; ``derive_peer_from_peer_id`` extracts pubkey directly.
- ``hash_type = 0x01`` (SHA-256): ``digest = SHA-256(public_key)``. Not
  self-resolving; pubkey must be obtained out-of-band.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Peer ID algorithm identifiers (V7 v7.67 §3.1 seed table).
# Production / VALIDATE allocations:
KEY_TYPE_ED25519 = 0x01  # PRODUCTION (v7.65 validated)
KEY_TYPE_ED448 = 0x02    # VALIDATE at v7.67 Phase 1 (pubkey 57 B, sig 114 B)
# 0x03 ML-DSA-65 — VALIDATE at v7.67 Phase 3b (conditional)
# 0x04-0x0A — RESERVE (per §3.1 seed table: SLH-DSA, ML-DSA-44/-87, FALCON-512, secp256k1, P-256)
# 0x0B-0xEF reserved (future); 0xF0-0xFD experimental range.
KEY_TYPE_TEST_SYNTHETIC = 0xFE  # V7 v7.66 §4 — test-only experimental cryptosystem.
                                # Wire/path/canonical-form test type; NO sign/verify semantics.
                                # 64-byte synthetic public_key (e.g., 0xAA × 64 fixture per §7).
# V7 v7.67 §5.3 — value 255 (0xFF) reserved on the key_type axis; SHALL
# NOT be allocated as an algorithm code. Defensive: many codebases sentinel
# 0xFF for "invalid"/"uninitialized"; mirror reservation on
# content_hash_format axis (see utils.ecf.validate_content_hash_format_code).

HASH_TYPE_IDENTITY = 0x00  # identity multihash; digest IS the public_key
HASH_TYPE_SHA256 = 0x01    # SHA-256 fingerprint of the public_key

# Per-key-type identity-form digest length (§2.3 length validation).
# Validated by derive_peer_from_peer_id; length mismatch → None.
_IDENTITY_DIGEST_LEN = {
    KEY_TYPE_ED25519: 32,
    KEY_TYPE_ED448: 57,  # v7.67 §3.2 — Ed448 raw pubkey is 57 B (canonical
                        # form is SHA-256-form per the size-cutoff; identity-form
                        # support here is for wire-acceptance decode of any
                        # non-canonical legacy bytestrings, per v7.65 §5).
}

# V7 v7.67 §3.2 — canonical (key_type, hash_type) pair per key_type.
# Used by canonicalize_peer_id() and peer_canon to recognize "already canonical"
# without an Ed25519-specific short-circuit. Update this table when a new
# key_type is allocated, per v7.65 §4 size-cutoff principle.
CANONICAL_HASH_TYPE_FOR_KEY_TYPE: dict[int, int] = {
    KEY_TYPE_ED25519: HASH_TYPE_IDENTITY,       # (0x01, 0x00) — identity multihash (32 B fits floor)
    KEY_TYPE_ED448: HASH_TYPE_SHA256,           # (0x02, 0x01) — SHA-256-form (57 B exceeds floor)
    KEY_TYPE_TEST_SYNTHETIC: HASH_TYPE_SHA256,  # (0xFE, 0x01) — SHA-256-form (size-forced)
}

# V7 v7.67 §3.3 — entity-data `system/peer.data.key_type` field is a
# primitive/string. This table maps the canonical lowercase ASCII name to
# the binary wire-format prefix byte. Allocated entries (per v7.67 §3.3):
#   "ed25519"           ↔ 0x01  (production; V7 §1.5)
#   "ed448"             ↔ 0x02  (v7.67 Phase 1)
#   "experimental-test" ↔ 0xFE  (V7 v7.66 §4 stub)
ENTITY_DATA_KEY_TYPE_TO_BYTE: dict[str, int] = {
    "ed25519": KEY_TYPE_ED25519,
    "ed448": KEY_TYPE_ED448,
    "experimental-test": KEY_TYPE_TEST_SYNTHETIC,
}
KEY_TYPE_BYTE_TO_ENTITY_DATA: dict[int, str] = {
    v: k for k, v in ENTITY_DATA_KEY_TYPE_TO_BYTE.items()
}


def is_canonical_pair(key_type: int, hash_type: int) -> bool:
    """V7 v7.66 §4.4 surface 3 — is this (key_type, hash_type) the canonical pair?

    True iff the pair matches the canonical entry in
    ``CANONICAL_HASH_TYPE_FOR_KEY_TYPE``. Unknown key_types return False
    (caller treats as non-canonical, falling to lazy-canon per v7.65 §6).
    """
    canonical = CANONICAL_HASH_TYPE_FOR_KEY_TYPE.get(key_type)
    return canonical is not None and canonical == hash_type


def key_type_byte_from_entity_data(key_type_str: str) -> int:
    """V7 v7.66 §2 errata — map entity-data string to wire-prefix byte.

    Raises :class:`UnsupportedKeyTypeError` for unknown strings; impls
    surface this as `400 unsupported_key_type` (V7 §4.7) at the
    protocol boundary.
    """
    byte = ENTITY_DATA_KEY_TYPE_TO_BYTE.get(key_type_str)
    if byte is None:
        raise UnsupportedKeyTypeError(
            f"unsupported key_type string {key_type_str!r}; "
            f"allocated: {sorted(ENTITY_DATA_KEY_TYPE_TO_BYTE.keys())}"
        )
    return byte


class UnsupportedKeyTypeError(ValueError):
    """V7 v7.66 §4.4 surface 6 / AGILITY-UNKNOWN-1 — receipt-side reject for
    unknown ``key_type``. Subclass of ValueError for back-compat with
    callers that catch ValueError; protocol boundary maps to
    `400 unsupported_key_type` (V7 §4.7)."""


def validate_supported_key_type(key_type: int) -> None:
    """V7 v7.66 §4.4 surface 6 — reject unallocated/unsupported key_type bytes.

    Supported set is exactly ``ENTITY_DATA_KEY_TYPE_TO_BYTE.values()``
    (currently Ed25519 ``0x01`` + experimental-test ``0xFE``). Anything
    else — including unallocated experimental (e.g. ``0xFD``),
    production-reserved (``0x02-0xEF``), or protocol-reserved (``0xFF``)
    — raises :class:`UnsupportedKeyTypeError`.
    """
    if key_type not in KEY_TYPE_BYTE_TO_ENTITY_DATA:
        raise UnsupportedKeyTypeError(
            f"unsupported key_type {key_type:#x}; "
            f"allocated: {sorted(KEY_TYPE_BYTE_TO_ENTITY_DATA.keys())}"
        )


@dataclass
class Keypair:
    """Ed25519 keypair with derived peer ID.

    Attributes:
        private_key: The Ed25519 private key.
        public_key: The Ed25519 public key.
        peer_id: The derived peer ID (Base58 encoded).
    """

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    peer_id: str

    # Entity-data `key_type` string (v7.66 §2 errata — primitive/string
    # surface, NOT the binary wire byte). Single source of truth for every
    # system/peer / authenticate entity this keypair authors, so handshake
    # and signing code never hardcode "ed25519".
    key_type: str = "ed25519"

    @classmethod
    def generate(cls) -> Keypair:
        """Generate a new random keypair.

        V7 v7.65 §4: Ed25519's canonical wire form is identity-multihash
        (hash_type=0x00). Construction mints canonical form only; the
        SHA-256 form mint path is removed (decoders still accept it per
        §5 wire-acceptance carve-out).
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        peer_id = derive_peer_id(public_key)
        return cls(private_key, public_key, peer_id)

    @classmethod
    def from_seed(cls, seed: bytes) -> Keypair:
        """Generate keypair from 32-byte seed (deterministic).

        V7 v7.65 §4: canonical-only construction (identity-multihash for Ed25519).
        """
        if len(seed) != 32:
            raise ValueError(f"Seed must be 32 bytes, got {len(seed)}")
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        public_key = private_key.public_key()
        peer_id = derive_peer_id(public_key)
        return cls(private_key, public_key, peer_id)

    def public_key_bytes(self) -> bytes:
        """Get raw public key bytes (32 bytes)."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)


def derive_peer_id(
    public_key: Ed25519PublicKey,
    *,
    key_type: int = KEY_TYPE_ED25519,
) -> str:
    """Derive canonical peer ID from public key (V7 v7.66 §3 — canonical-only mint).

    Public mint API mints canonical form only: ``hash_type`` is selected
    from ``CANONICAL_HASH_TYPE_FOR_KEY_TYPE`` and is NOT a caller-tunable
    parameter (the legacy v7.65 ``hash_type`` kwarg was dropped at v7.66).

    For ``key_type = KEY_TYPE_ED25519`` (0x01): canonical
    ``hash_type = HASH_TYPE_IDENTITY`` (0x00). Pubkey-resolving form.
    """
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _peer_id_from_bytes(
        raw_bytes,
        key_type=key_type,
        hash_type=_canonical_hash_type(key_type),
    )


def peer_id_from_public_key_bytes(
    public_key_bytes: bytes,
    *,
    key_type: int = KEY_TYPE_ED25519,
) -> str:
    """Derive canonical peer ID from raw public-key bytes (V7 v7.66 §3 — canonical-only mint).

    Public mint API mints canonical form only. See :func:`derive_peer_id`
    for the contract; this overload accepts raw bytes for callers that
    have decoded a pubkey out-of-band (e.g., from a remote handshake).
    """
    return _peer_id_from_bytes(
        public_key_bytes,
        key_type=key_type,
        hash_type=_canonical_hash_type(key_type),
    )


def _canonical_hash_type(key_type: int) -> int:
    canonical = CANONICAL_HASH_TYPE_FOR_KEY_TYPE.get(key_type)
    if canonical is None:
        raise ValueError(
            f"no canonical hash_type registered for key_type {key_type:#x}; "
            "production allocations need an entry in CANONICAL_HASH_TYPE_FOR_KEY_TYPE"
        )
    return canonical


def _peer_id_from_bytes(
    public_key_bytes: bytes, *, key_type: int, hash_type: int,
) -> str:
    """Internal peer_id assembly helper.

    Used by:
      - canonical mint paths (:func:`derive_peer_id`,
        :func:`peer_id_from_public_key_bytes`) — these compute the
        canonical ``hash_type`` from the key_type table;
      - wire-acceptance binding-verification (v7.65 §5 carve-out;
        ``handlers/connect.py``) — re-derives the presented
        ``(key_type, hash_type)`` pair to verify pubkey binding;
      - conformance-corpus authoring — produces legacy-form opaque
        bytestrings (v7.66 §3.4) for fixtures that exercise the §5
        wire-acceptance decode path.

    NOT a public mint API. Production callers MUST go through
    :func:`derive_peer_id` / :func:`peer_id_from_public_key_bytes`
    (canonical-only per v7.66 §3).
    """
    if hash_type == HASH_TYPE_IDENTITY:
        digest = public_key_bytes
    elif hash_type == HASH_TYPE_SHA256:
        digest = hashlib.sha256(public_key_bytes).digest()
    else:
        raise ValueError(f"unsupported hash_type: {hash_type:#x}")
    data = bytes([key_type, hash_type]) + digest
    return base58.b58encode(data).decode("ascii")


def decode_peer_id(peer_id: str) -> tuple[int, int, bytes]:
    """Decode a Base58 PeerID into ``(key_type, hash_type, digest)`` per §7.4.

    Raises ``ValueError`` on Base58-decode failure or truncated framing.
    Does NOT validate the digest length against the key_type — that is
    `derive_peer_from_peer_id`'s job (length-agnostic decoder per PIM-5).
    """
    data = base58.b58decode(peer_id)
    if len(data) < 2:
        raise ValueError(f"peer_id too short: {len(data)} bytes")
    return data[0], data[1], data[2:]


def peer_id_from_identity_entity(id_ent: dict) -> str:
    """V7 v7.65 §2/§3 + V7 v7.66 §4 — derive canonical wire peer_id from a system/peer entity.

    Under v7.65 the system/peer entity carries only (public_key, key_type);
    the wire peer_id is a presentation handle derived from the public_key
    under the canonical hash_type per key_type (v7.65 §4 / v7.66 §4.4).

    The entity-data ``key_type`` field (a primitive/string per v7.66 §2
    errata) selects the binary wire-format prefix and the canonical
    hash_type. Defaults to ``"ed25519"`` for entities that omit it
    (v7.64-shape pre-errata).

    Returns the canonical peer_id string. Returns ``""`` when the entity's
    ``data.public_key`` is missing/not bytes, or ``data.key_type`` is an
    unknown string — caller decides whether to treat as a malformed entity.
    """
    data = id_ent.get("data", {})
    pkey = data.get("public_key")
    if not isinstance(pkey, (bytes, bytearray)):
        return ""
    kt_str = data.get("key_type", "ed25519")
    try:
        kt_byte = key_type_byte_from_entity_data(kt_str)
    except ValueError:
        return ""
    return peer_id_from_public_key_bytes(bytes(pkey), key_type=kt_byte)


def canonicalize_peer_id(
    peer_id: str,
    *,
    public_key: bytes | None = None,
) -> str | None:
    """V7 v7.65 §5 — canonicalize a wire peer_id to its canonical form per
    its key_type.

    Behavior:
    - Already-canonical input: returned unchanged.
    - Non-canonical input with derivable pubkey (identity-form per §1.5 of
      the original key_type): canonical form recomputed and returned.
    - Non-canonical input without pubkey AND not derivable from peer_id
      (e.g. SHA-256-form, opaque): if ``public_key`` is supplied, canonical
      form recomputed. Otherwise returns ``None`` — the caller MUST handle
      via the §6 lazy-canonicalization path (store as
      ``pending-canonicalization``, rewrite at first handshake when
      pubkey becomes available).

    SHOULD-tier: callers SHOULD debug-log non-canonical acceptance per §5.
    """
    try:
        key_type, hash_type, _digest = decode_peer_id(peer_id)
    except (ValueError, Exception):
        return None
    # V7 v7.66 §4.4 surface 3 — per-key_type canonical check (no Ed25519 short-circuit).
    if is_canonical_pair(key_type, hash_type):
        return peer_id  # already canonical
    # Non-canonical. Try to derive pubkey from peer_id (works only for identity-form).
    if public_key is None:
        derived = derive_peer_from_peer_id(peer_id)
        if derived is None:
            return None  # caller falls to §6 lazy-canon
        public_key, _ = derived
    return peer_id_from_public_key_bytes(public_key, key_type=key_type)


def derive_peer_from_peer_id(
    peer_id: str,
) -> tuple[bytes, int] | None:
    """Extract ``(public_key, key_type)`` from a Base58 PeerID (V7 v7.64 §7.4).

    Returns ``Some((public_key, key_type))`` when the PeerID is
    identity-multihash form (``hash_type == 0x00``) and the digest length
    matches the key type. Returns ``None`` for SHA-256-form PeerIDs (the
    public_key must be obtained out-of-band) and for length-mismatched
    identity-form PeerIDs of known key types.

    For unknown key types in identity form, returns the raw digest as
    public_key (length-agnostic) so PIM-5 round-trips. Callers that need
    strict per-key-type validation should compare key_type against an
    allowlist after the call.
    """
    try:
        key_type, hash_type, digest = decode_peer_id(peer_id)
    except (ValueError, Exception):
        return None
    if hash_type != HASH_TYPE_IDENTITY:
        return None
    expected = _IDENTITY_DIGEST_LEN.get(key_type)
    if expected is not None and len(digest) != expected:
        return None
    return digest, key_type
