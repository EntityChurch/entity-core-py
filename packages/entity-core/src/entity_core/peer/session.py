"""Authenticated session state.

Represents the result of a successful connect handshake.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from entity_core.protocol.entity import Entity


@dataclass
class Session:
    """Authenticated session after successful connect handshake.

    Attributes:
        local_peer_id: This peer's ID.
        remote_peer_id: The other peer's ID.
        remote_public_key: The other peer's raw public key bytes.
        remote_identity_hash: Content hash of the remote peer's identity entity.
    """

    local_peer_id: str
    remote_peer_id: str
    remote_public_key: bytes
    remote_identity_hash: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        if not self.remote_identity_hash and self.remote_public_key:
            # V7 v7.65 §2: system/peer data = (public_key, key_type) only.
            # V7 v7.67 Phase 2 — the remote's key_type is decoded from its
            # peer_id so an Ed448 remote's identity hash matches what the
            # remote itself computes (key_type is in the hashable basis).
            from entity_core.crypto.identity import (
                KEY_TYPE_BYTE_TO_ENTITY_DATA,
                decode_peer_id,
            )

            key_type = "ed25519"
            try:
                kt_byte, _ht, _digest = decode_peer_id(self.remote_peer_id)
                key_type = KEY_TYPE_BYTE_TO_ENTITY_DATA.get(kt_byte, "ed25519")
            except Exception:
                pass
            identity_entity = Entity(
                type="system/peer",
                data={
                    "public_key": self.remote_public_key,
                    "key_type": key_type,
                },
            )
            self.remote_identity_hash = identity_entity.compute_hash()
