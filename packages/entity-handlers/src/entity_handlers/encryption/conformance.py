"""EXTENSION-ENCRYPTION §16 — ENC-KAT-INNER canonical plaintext (R3).

Arch ruling R3 pins the §16 KAT plaintext to a real typed entity,
not a bare string: the ECF of a fixed ``system/note``. This gives the
decrypt-and-reinject path (§13.3) a genuine entity to re-author and makes the
byte-pin vectors exercise the same hashable form ``content_hash`` is computed
over. Shared by production (reinject) and the conformance tests so they cannot
drift.

Plaintext = ECF of the hashable 2-key ``{type, data}`` form (ENTITY-CBOR-ENCODING
§4.2 length-first) — 79 bytes, byte-identical to Go's ``EncKATInnerPlaintext``.
"""

from __future__ import annotations

from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import ecf_encode

ENC_KAT_INNER_TYPE = "system/note"
ENC_KAT_INNER_BODY = "entity-core encryption KAT inner entity"
ENC_KAT_INNER_CREATED = 0


def enc_kat_inner_entity() -> Entity:
    """The canonical ENC-KAT-INNER ``system/note`` entity (R3)."""
    return Entity(
        type=ENC_KAT_INNER_TYPE,
        data={"body": ENC_KAT_INNER_BODY, "created": ENC_KAT_INNER_CREATED},
    )


def enc_kat_inner_plaintext() -> bytes:
    """The §16 KAT plaintext: 79-byte ECF of ENC-KAT-INNER's hashable form."""
    ent = enc_kat_inner_entity()
    return ecf_encode({"type": ent.type, "data": ent.data})
