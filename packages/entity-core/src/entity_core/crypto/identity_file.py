"""Load identity files from ~/.entity/identities/.

Cross-impl identity files (minted by the Go peer-manager / validate-peer
harness — Python has no identity-creation path of its own) are stored as:
- {name} - Private key seed in PEM-like format
- {name}.json - Metadata with peer_id, public_key
- {name}.pub - Public key in text format

**The wire peer_id is derived from the public key, NOT trusted from the
file.** A file's stored ``peer_id`` is informational only: pre-v7.66 files
carried non-canonical SHA-256-form Ed25519 peer_ids (``hash_type=0x01``),
and trusting them propagates staleness onto the wire (remote re-derives the
canonical identity-form ``hash_type=0x00`` → chain-root mismatch,
"Root capability not granted by local peer"). ``load_identity`` always
re-derives the canonical peer_id per key_type (v7.66 §4.4) and warns (§5
SHOULD debug-log) when the stored value disagrees.
"""

from __future__ import annotations

import base64
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization

from entity_core.crypto.identity import Keypair, derive_peer_id


# PEM header tags (v7.67 §3.6 — cross-impl identity-file format). The
# untagged Ed25519 header is the historical default; the Ed448 tag carries
# the 57-byte seed. Matches Go's SaveIdentityToDir / LoadIdentityFromFile.
PEM_HEADER_ED25519 = "-----BEGIN ENTITY PRIVATE KEY-----"
PEM_HEADER_ED448 = "-----BEGIN ENTITY ED448 PRIVATE KEY-----"

# Base58 alphabet (Bitcoin style)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    """Encode bytes to base58."""
    # Convert bytes to integer
    num = int.from_bytes(data, "big")

    # Encode
    result = ""
    while num > 0:
        num, rem = divmod(num, 58)
        result = BASE58_ALPHABET[rem] + result

    # Handle leading zeros
    for byte in data:
        if byte == 0:
            result = "1" + result
        else:
            break

    return result or "1"


def base58_decode(s: str) -> bytes:
    """Decode base58 to bytes."""
    # Decode to integer
    num = 0
    for char in s:
        num = num * 58 + BASE58_ALPHABET.index(char)

    # Convert to bytes
    # Determine byte length
    byte_length = (num.bit_length() + 7) // 8
    result = num.to_bytes(byte_length, "big") if num > 0 else b""

    # Handle leading ones (zeros in original)
    leading_ones = len(s) - len(s.lstrip("1"))
    return b"\x00" * leading_ones + result


@dataclass
class LoadedIdentity:
    """Identity loaded from file."""

    keypair: Keypair
    peer_id_base58: str  # Canonical wire peer_id (re-derived from public key)
    name: str


def load_identity(name: str, base_path: Path | None = None) -> LoadedIdentity:
    """Load an identity from ~/.entity/identities/.

    Args:
        name: Identity name (e.g., "framework-admin").
        base_path: Override for identity directory (default: ~/.entity/identities).

    Returns:
        LoadedIdentity with keypair and peer IDs.

    Raises:
        FileNotFoundError: If identity files don't exist.
        ValueError: If files are malformed.
    """
    if base_path is None:
        base_path = Path.home() / ".entity" / "identities"

    private_key_path = base_path / name
    json_path = base_path / f"{name}.json"

    # Read JSON metadata
    with open(json_path) as f:
        metadata = json.load(f)

    peer_id_base58 = metadata["peer_id"]
    public_key_b64 = metadata["public_key"]

    # Read private key
    with open(private_key_path) as f:
        content = f.read()

    # Parse PEM-like format. The header line selects the cryptosystem
    # (v7.67 §3.6 / Go SaveIdentityToDir): untagged "ENTITY PRIVATE KEY" is
    # Ed25519 (32-byte seed); "ENTITY ED448 PRIVATE KEY" is Ed448 (57-byte
    # seed). The body is the base64 seed.
    lines = content.strip().split("\n")
    if len(lines) != 3:
        raise ValueError(f"Invalid private key format in {private_key_path}")

    header = lines[0].strip()
    seed = base64.b64decode(lines[1])
    expected_public = base64.b64decode(public_key_b64)

    if header == PEM_HEADER_ED448:
        from entity_core.crypto.ed448 import Ed448Keypair

        ed448_kp = Ed448Keypair.from_seed(seed)
        if ed448_kp.public_key_bytes() != expected_public:
            raise ValueError("Public key mismatch")
        # Ed448 is new at v7.67 — no legacy peer_id form. The seed-derived
        # canonical (0x02, 0x01) peer_id is the wire identity; metadata's
        # peer_id is informational and matches by construction.
        return LoadedIdentity(
            keypair=ed448_kp,  # structurally compatible with Keypair
            peer_id_base58=ed448_kp.peer_id,
            name=name,
        )

    # Ed25519 (untagged header, explicit Ed25519 tag, or any other legacy
    # header — the loader historically ignored the header line, so default
    # to Ed25519 for anything that isn't the Ed448 tag).
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()
    actual_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if expected_public != actual_public:
        raise ValueError("Public key mismatch")

    # Re-derive the canonical wire peer_id from the public key (v7.66 §4.4
    # canonical-only mint: Ed25519 → identity-form hash_type=0x00). The
    # file's stored peer_id is informational and MUST NOT be trusted —
    # pre-v7.66 files carry non-canonical SHA-256-form peer_ids
    # (hash_type=0x01), and propagating them onto the wire causes
    # cross-impl chain-root mismatch (the remote re-derives canonical).
    canonical_peer_id = derive_peer_id(public_key)
    if peer_id_base58 and peer_id_base58 != canonical_peer_id:
        # v7.65 §5 SHOULD: surface non-canonical acceptance. We canonicalize
        # rather than refuse so a stale file still yields a correct peer on
        # the wire; the file SHOULD be regenerated to silence this.
        print(
            f"Warning: identity '{name}' stored peer_id "
            f"{peer_id_base58[:16]}... is non-canonical; using re-derived "
            f"canonical peer_id {canonical_peer_id[:16]}... "
            f"(regenerate the identity file to silence this).",
            file=sys.stderr,
        )

    keypair = Keypair(
        private_key=private_key,
        public_key=public_key,
        peer_id=canonical_peer_id,
    )

    return LoadedIdentity(
        keypair=keypair,
        peer_id_base58=canonical_peer_id,
        name=name,
    )


def list_identities(base_path: Path | None = None) -> list[str]:
    """List available identity names.

    Args:
        base_path: Override for identity directory.

    Returns:
        List of identity names.
    """
    if base_path is None:
        base_path = Path.home() / ".entity" / "identities"

    names = []
    for json_file in base_path.glob("*.json"):
        name = json_file.stem
        # Verify private key exists
        if (base_path / name).exists():
            names.append(name)

    return sorted(names)
