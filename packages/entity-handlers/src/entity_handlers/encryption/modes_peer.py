"""EXTENSION-ENCRYPTION §7 — mode ``peer`` (relay-encrypted sending), v1 PRIMARY.

Non-interactive single-shot hybrid encryption to one recipient — structurally
age / NaCl ``crypto_box`` with sender authentication. The sender does ECDH with
the recipient's encryption pubkey, derives a per-message key, AEAD-seals the
inner entity, and (handler layer) signs the outer entity at the V7 invariant
pointer. NOT forward-secret against recipient-key compromise (§7.1 honest
framing).

The mode functions here cover §7.3 steps 1–6 (the byte-producing core) and
§7.5 steps 2–6; sender-signature publish/verify (§7.4) and recipient-pubkey
resolution (§4.4) are the handler/tier layer's job — kept out so this stays
KAT-testable and reusable by group mode's per-member wrap.

FLAG F-PY-ENC-2 (cohort byte-pin): §7.3 step 4 binds
``info = utf8("entity-core/peer/") || recipient_pubkey_hash``. We use the FULL
33-byte content_hash (format byte 0x00 + 32-byte SHA-256 digest), matching
``Entity.compute_hash()`` and the refless 33-byte ``system/hash`` convention.
If Go binds the bare 32-byte digest the derived key (hence ciphertext) diverges
— diff this in the §16.5 round alongside F-PY-ENC-1.
"""

from __future__ import annotations

from entity_core.crypto.aead import aead_decrypt, aead_encrypt, aead_key_len
from entity_core.crypto.ecdh import derive_public_key, ecdh, generate_keypair
from entity_core.crypto.kdf import hkdf
from entity_core.protocol.entity import Entity

from .aad import peer_aad
from .entities import encrypted_entity
from .errors import AEAD_FAILED, INVALID_WRAPPER, UNSUPPORTED_SUITE, EncryptionError
from .registries import FLOOR_AEAD_ID, FLOOR_ENC_KEY_TYPE, FLOOR_KDF_ID, aead_allowed_in_mode

# §7.3 — HKDF info prefix.
PEER_INFO_PREFIX = b"entity-core/peer/"


def peer_seal(
    *,
    plaintext: bytes,
    recipient_pubkey: bytes,
    recipient_pubkey_hash: bytes,
    nonce: bytes,
    enc_key_type: int = FLOOR_ENC_KEY_TYPE,
    aead_id: int = FLOOR_AEAD_ID,
    kdf_id: int = FLOOR_KDF_ID,
    ephemeral_seed: bytes | None = None,
    mode: str = "peer",
) -> dict:
    """§7.3 steps 1–6. Returns the per-mode field dict (no signing).

    ``ephemeral_seed`` pins the ephemeral key for KATs; otherwise a fresh
    keypair is generated. ``mode`` lets group mode reuse this for its per-member
    wrap (it passes ``"group-wrap"`` so the AAD is domain-separated, F2-2).
    Returns ``{ephemeral_key, recipient_key, ciphertext, enc_key_type, aead_id,
    kdf_id, nonce}``.
    """
    if not aead_allowed_in_mode(aead_id, mode):
        raise EncryptionError(UNSUPPORTED_SUITE, f"AEAD {aead_id:#04x} forbidden in {mode} mode")

    if ephemeral_seed is not None:
        eph_pub = derive_public_key(enc_key_type, ephemeral_seed)
        shared_secret = ecdh(enc_key_type, ephemeral_seed, recipient_pubkey)
    else:
        eph_priv, eph_pub = generate_keypair(enc_key_type)
        shared_secret = ecdh(enc_key_type, eph_priv, recipient_pubkey)

    aead_key = hkdf(
        kdf_id, ikm=shared_secret, salt=nonce,
        info=PEER_INFO_PREFIX + recipient_pubkey_hash, length=aead_key_len(aead_id),
    )
    aad = _build_aad(
        mode=mode, enc_key_type=enc_key_type, aead_id=aead_id, kdf_id=kdf_id,
        nonce=nonce, recipient_key=recipient_pubkey_hash, ephemeral_key=eph_pub,
    )
    ciphertext = aead_encrypt(aead_id, aead_key, nonce, aad, plaintext)
    return {
        "enc_key_type": enc_key_type,
        "aead_id": aead_id,
        "kdf_id": kdf_id,
        "nonce": nonce,
        "ephemeral_key": eph_pub,
        "recipient_key": recipient_pubkey_hash,
        "ciphertext": ciphertext,
    }


def peer_encrypt(
    *,
    plaintext: bytes,
    recipient_pubkey: bytes,
    recipient_pubkey_hash: bytes,
    nonce: bytes,
    enc_key_type: int = FLOOR_ENC_KEY_TYPE,
    aead_id: int = FLOOR_AEAD_ID,
    kdf_id: int = FLOOR_KDF_ID,
    ephemeral_seed: bytes | None = None,
) -> Entity:
    """Encrypt ``plaintext`` (inner-entity ECF) → peer-mode ``system/encrypted``.

    Sender authentication (§7.4) is applied separately at the handler layer.
    """
    fields = peer_seal(
        plaintext=plaintext, recipient_pubkey=recipient_pubkey,
        recipient_pubkey_hash=recipient_pubkey_hash, nonce=nonce,
        enc_key_type=enc_key_type, aead_id=aead_id, kdf_id=kdf_id,
        ephemeral_seed=ephemeral_seed,
    )
    return encrypted_entity("peer", fields)


def peer_unseal(
    *,
    ciphertext: bytes,
    my_private: bytes,
    ephemeral_key: bytes,
    recipient_key: bytes,
    nonce: bytes,
    enc_key_type: int,
    aead_id: int,
    kdf_id: int,
    mode: str = "peer",
) -> bytes:
    """§7.5 steps 3–6: recompute shared secret, derive key, AEAD-open.

    Recipient lookup + signature verification (§7.5 steps 1–2) are the handler
    layer's job. ``mode`` matches whatever ``peer_seal`` used so the AAD lines up.
    """
    shared_secret = ecdh(enc_key_type, my_private, ephemeral_key)
    aead_key = hkdf(
        kdf_id, ikm=shared_secret, salt=nonce,
        info=PEER_INFO_PREFIX + recipient_key, length=aead_key_len(aead_id),
    )
    aad = _build_aad(
        mode=mode, enc_key_type=enc_key_type, aead_id=aead_id, kdf_id=kdf_id,
        nonce=nonce, recipient_key=recipient_key, ephemeral_key=ephemeral_key,
    )
    try:
        return aead_decrypt(aead_id, aead_key, nonce, aad, ciphertext)
    except Exception as e:
        raise EncryptionError(AEAD_FAILED, str(e)) from None


def peer_decrypt(*, entity: Entity, my_private: bytes) -> bytes:
    """Recover inner-entity ECF from a peer-mode ``system/encrypted``."""
    d = entity.data
    try:
        return peer_unseal(
            ciphertext=d["ciphertext"], my_private=my_private,
            ephemeral_key=d["ephemeral_key"], recipient_key=d["recipient_key"],
            nonce=d["nonce"], enc_key_type=d["enc_key_type"],
            aead_id=d["aead_id"], kdf_id=d["kdf_id"],
        )
    except KeyError as e:
        raise EncryptionError(INVALID_WRAPPER, f"missing peer field {e}") from None


def _build_aad(*, mode: str, **kw) -> bytes:
    if mode == "group-wrap":
        from .aad import group_wrap_aad
        return group_wrap_aad(**kw)
    return peer_aad(**kw)
