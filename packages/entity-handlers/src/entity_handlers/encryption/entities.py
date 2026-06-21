"""EXTENSION-ENCRYPTION entity shapes (§4.1, §5.1, §6.1, §7.2, §8.2).

Builders for the wire entities and the content_hash convention that the whole
key schedule binds to. The single load-bearing function is
``encryption_pubkey_entity`` / ``pubkey_content_hash``: ``recipient_key`` is the
content_hash of the *inner* ``system/encryption-pubkey`` entity, uniform at
every tier (F-GO-1) and over the byte-identical authored entity (F2-3).
"""

from __future__ import annotations

from typing import Any

from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import Hash

PUBKEY_TYPE = "system/encryption-pubkey"
ENCRYPTED_TYPE = "system/encrypted"


def encryption_pubkey_entity(
    *,
    enc_key_type: int,
    public_key: bytes,
    supported_aead_ids: list[int],
    supported_kdf_ids: list[int],
    created: int,
    expires: int | None = None,
) -> Entity:
    """Build a ``system/encryption-pubkey`` entity (§4.1).

    content_hash is a pure function of these six fields; ``expires`` is omitted
    when absent (optional field — absence, not present-empty, per normal entity
    data discipline). The byte-identical authored entity MUST be re-published
    (not re-minted) across tiers (F2-3).
    """
    data: dict[str, Any] = {
        "enc_key_type": enc_key_type,
        "public_key": public_key,
        "supported_aead_ids": list(supported_aead_ids),
        "supported_kdf_ids": list(supported_kdf_ids),
        "created": created,
    }
    if expires is not None:
        data["expires"] = expires
    return Entity(type=PUBKEY_TYPE, data=data)


def pubkey_content_hash(pubkey: Entity) -> Hash:
    """content_hash of the inner pubkey entity — the ``recipient_key`` value."""
    return pubkey.compute_hash()


def encrypted_entity(mode: str, fields: dict[str, Any]) -> Entity:
    """Assemble a ``system/encrypted`` outer entity from common + per-mode fields.

    Common fields (§5.1): ``mode``, ``enc_key_type``, ``aead_id``, ``kdf_id``,
    ``nonce``, ``ciphertext``. ``fields`` carries those plus the per-mode extras
    (§6.1 self / §7.2 peer / §8.2 group). Sender authentication is NOT a field
    here — it lives at the V7 invariant pointer ``system/signature/{hex(hash)}``
    (§5.1 / F-GO-3).
    """
    data = dict(fields)
    data["mode"] = mode
    return Entity(type=ENCRYPTED_TYPE, data=data)
