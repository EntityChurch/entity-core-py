"""EXTENSION-ENCRYPTION §9.2 — Tier-2 passphrase-wrapped key backup.

Round-trip + negative paths for the cold-backup defense-in-depth tier, with the
flattened backup AAD pinned. Note the deliberate spec asymmetry: the backup AAD
*flattens* the Argon2id params (contrast the self-mode AAD which nests them
under ``kdf_params``).
"""

from __future__ import annotations

import copy

import pytest

from entity_core.protocol.entity import Entity
from entity_handlers.encryption import (
    EncryptionError,
    make_key_backup,
    restore_key_backup,
)
from entity_handlers.encryption.keystore import _backup_aad
from entity_handlers.encryption.modes_self import baseline_kdf_params

PRIV = bytes([0x45]) * 32
PUBREF = bytes([0x00]) + bytes(range(32))
SALT = bytes([0x43]) * 16
WRAP_NONCE = bytes([0x42]) * 24
PASS = b"correct horse battery staple"

# Flattened 6-key backup AAD (§9.2) — params are sibling keys, not nested.
BACKUP_AAD_HEX = (
    "a66974696d655f636f7374036a6f75747075745f6c656e18206a7075626b65795f726566582100"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f6b6d656d6f7279"
    "5f636f73741a000100006b706172616c6c656c69736d016e6172676f6e325f76657273696f6e13"
)


def test_backup_aad_is_flattened():
    assert _backup_aad(PUBREF, baseline_kdf_params()).hex() == BACKUP_AAD_HEX


@pytest.mark.slow
def test_key_backup_roundtrip():
    ent = make_key_backup(
        private_key=PRIV, pubkey_ref=PUBREF, passphrase=PASS,
        kdf_salt=SALT, wrap_nonce=WRAP_NONCE,
    )
    assert ent.type == "system/encryption/key-backup"
    assert len(ent.data["wrapped_key"]) == len(PRIV) + 16  # +Poly1305 tag
    assert restore_key_backup(entity=ent, passphrase=PASS) == PRIV


@pytest.mark.slow
def test_key_backup_wrong_passphrase_rejected():
    ent = make_key_backup(
        private_key=PRIV, pubkey_ref=PUBREF, passphrase=PASS,
        kdf_salt=SALT, wrap_nonce=WRAP_NONCE,
    )
    with pytest.raises(EncryptionError) as ei:
        restore_key_backup(entity=ent, passphrase=b"wrong passphrase")
    assert ei.value.code == "encryption_aead_failed"


@pytest.mark.slow
def test_key_backup_tampered_pubkey_ref_rejected():
    ent = make_key_backup(
        private_key=PRIV, pubkey_ref=PUBREF, passphrase=PASS,
        kdf_salt=SALT, wrap_nonce=WRAP_NONCE,
    )
    # pubkey_ref is bound into both HKDF info and the AAD — tampering fails both.
    bad = Entity(type=ent.type, data=copy.deepcopy(ent.data))
    bad.data["pubkey_ref"] = bytes([0x00]) + bytes([0xFF]) * 32
    with pytest.raises(EncryptionError):
        restore_key_backup(entity=bad, passphrase=PASS)
