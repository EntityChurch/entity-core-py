"""Tests for cryptographic operations."""

import base64

from entity_core.crypto.identity import Keypair, derive_peer_id, peer_id_from_public_key_bytes
from entity_core.crypto.signing import public_key_from_bytes, verify_signature


def test_keypair_generate():
    """Keypair generation produces valid keypair."""
    keypair = Keypair.generate()
    assert keypair.peer_id
    assert len(keypair.public_key_bytes()) == 32


def test_keypair_deterministic_from_seed():
    """Same seed produces same keypair."""
    seed = b"0" * 32
    kp1 = Keypair.from_seed(seed)
    kp2 = Keypair.from_seed(seed)
    assert kp1.peer_id == kp2.peer_id
    assert kp1.public_key_bytes() == kp2.public_key_bytes()


def test_different_seeds_different_keys():
    """Different seeds produce different keypairs."""
    kp1 = Keypair.from_seed(b"a" * 32)
    kp2 = Keypair.from_seed(b"b" * 32)
    assert kp1.peer_id != kp2.peer_id


def test_sign_and_verify():
    """Signature can be verified."""
    keypair = Keypair.generate()
    message = b"Hello, World!"
    signature = keypair.sign(message)

    public_key = public_key_from_bytes(keypair.public_key_bytes())
    assert verify_signature(public_key, message, signature)


def test_verify_wrong_message():
    """Wrong message fails verification."""
    keypair = Keypair.generate()
    message = b"Hello, World!"
    signature = keypair.sign(message)

    public_key = public_key_from_bytes(keypair.public_key_bytes())
    assert not verify_signature(public_key, b"Wrong message", signature)


def test_peer_id_format():
    """Peer ID is Base58 encoded (key_type || hash_type || SHA256(pubkey))."""
    keypair = Keypair.generate()
    # 34 bytes (1 + 1 + 32) Base58 encoded is ~46 characters
    assert len(keypair.peer_id) >= 44  # Base58 varies slightly
    assert len(keypair.peer_id) <= 48
    # Should start with '2' (Base58 of 0x01 prefix)
    assert keypair.peer_id.startswith("2")


def test_peer_id_from_public_key_bytes():
    """peer_id_from_public_key_bytes matches derive_peer_id."""
    keypair = Keypair.generate()
    peer_id_1 = derive_peer_id(keypair.public_key)
    peer_id_2 = peer_id_from_public_key_bytes(keypair.public_key_bytes())
    assert peer_id_1 == peer_id_2
