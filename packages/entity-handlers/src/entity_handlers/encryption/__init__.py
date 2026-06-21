"""EXTENSION-ENCRYPTION v1.0 — base per-entity stateless encryption.

The base (per-entity stateless) half of the base/session split: ``self``
(at-rest storage, v1 PRIMARY), ``peer`` (single-shot hybrid send, v1 PRIMARY),
``group`` (static key-wrap + key-commitment, v1 best-effort). The stateful
sibling EXTENSION-ENCRYPTED-SESSION (§20) is deferred post-release.

Layering:
- Pure-crypto primitives live in ``entity_core.crypto`` (aead / kdf / ecdh).
- This package owns the protocol logic: AAD construction (§5.2), entity shapes,
  the three mode flows, cipher-suite policy, and (forthcoming) tier-aware
  publishing/rotation/revocation + the ``system/encryption`` handler.
"""

from __future__ import annotations

from .aad import group_outer_aad, group_wrap_aad, peer_aad, self_aad
from .conformance import enc_kat_inner_entity, enc_kat_inner_plaintext
from .entities import (
    ENCRYPTED_TYPE,
    PUBKEY_TYPE,
    encryption_pubkey_entity,
    pubkey_content_hash,
)
from .errors import EncryptionError
from .keystore import KEY_BACKUP_TYPE, make_key_backup, restore_key_backup
from .modes_group import (
    GroupMember,
    group_add_member,
    group_decrypt,
    group_encrypt,
    group_rekey,
)
from .modes_peer import peer_decrypt, peer_encrypt
from .modes_self import baseline_kdf_params, self_decrypt, self_encrypt
from .resolver import (
    is_pubkey_revoked,
    next_in_handoff_chain,
    resolve_current_pubkey,
    resolve_current_recipient,
)
from .separation import birational_ed_to_x25519, validate_key_separation

__all__ = [
    # AAD (§5.2)
    "self_aad",
    "peer_aad",
    "group_outer_aad",
    "group_wrap_aad",
    # entities
    "PUBKEY_TYPE",
    "ENCRYPTED_TYPE",
    "encryption_pubkey_entity",
    "pubkey_content_hash",
    # modes
    "self_encrypt",
    "self_decrypt",
    "baseline_kdf_params",
    "peer_encrypt",
    "peer_decrypt",
    "group_encrypt",
    "group_decrypt",
    "group_add_member",
    "group_rekey",
    "GroupMember",
    # at-rest key storage (§9)
    "KEY_BACKUP_TYPE",
    "make_key_backup",
    "restore_key_backup",
    # R6 key separation
    "validate_key_separation",
    "birational_ed_to_x25519",
    # §10/§11 Tier-A resolution + refusal
    "resolve_current_recipient",
    "resolve_current_pubkey",
    "next_in_handoff_chain",
    "is_pubkey_revoked",
    # §16 ENC-KAT-INNER (R3)
    "enc_kat_inner_entity",
    "enc_kat_inner_plaintext",
    # errors
    "EncryptionError",
]
