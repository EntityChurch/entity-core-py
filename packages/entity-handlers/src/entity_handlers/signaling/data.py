"""Entity codecs for the **wrapped** surface (``PROPOSAL-CONNECTION-NODE`` §2).

Everything here is the entity wrapper and nothing else — the translation between
an EXECUTE's params/result entities and the plain values the client deals in.

There is no reflection type: ``reflect`` is the unwrapped listener's verb (§1.4)
and the unwrapped surface carries no entities at all, so the shape it returns
will be pinned by §5.1's plain protocol, not by an entity codec here.

Wire notes that bite cross-impl
-------------------------------

- ``rendezvous_key`` is a **plain CBOR bstr**, always 33 bytes. It is *not* a
  ``system/hash`` field being reused — to the node it is opaque bytes with no
  format byte to interpret — but it is byte-identical to the 33-byte
  ``algorithm ‖ digest`` form the peer derives, so the derived bytes pass
  straight through.
- ``limits`` is a **bare CBOR map**, not an entity wrapper: it is a field typed
  as a specific struct, not as ``core/entity``.
- ``collect`` returns **the blobs themselves**, not hashes (arch ruling 1). An
  earlier §1 draft said hashes; it was residue from a content-addressed sketch
  and is unimplementable — a hash reply needs a fetch surface the node
  structurally does not have.
- **Absent optional fields are absent, never null.**
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from entity_core.utils.ecf import Hash
from entity_handlers.signaling.constants import (
    LOBBY_DEFAULT,
    SignalingDecodeError,
)
from entity_handlers.signaling.key import key_from_wire

# ---------------------------------------------------------------------------
# Entity types (§1 verb surface)
# ---------------------------------------------------------------------------

TYPE_OFFER_REQUEST = "system/signaling/offer-request"
TYPE_OFFER_RESULT = "system/signaling/offer-result"
TYPE_COLLECT_REQUEST = "system/signaling/collect-request"
TYPE_COLLECT_RESULT = "system/signaling/collect-result"
TYPE_ADVERTISEMENT = "system/signaling/advertisement"

#: ``advertise`` takes no arguments, but an EXECUTE still carries a params entity
#: and a node rejects empty ``data`` — so we send an empty CBOR map, the encoding
#: of "no fields".
TYPE_EMPTY_PARAMS = "system/signaling/empty"


def offer_params(rendezvous_key: Hash, message: bytes) -> dict[str, Any]:
    """``offer(rendezvous_key, message)`` params (§1).

    The key is length-checked here so a wrong-width key fails loudly on our side
    rather than as a remote ``invalid_params`` we then have to attribute.
    """
    return {
        "type": TYPE_OFFER_REQUEST,
        "data": {
            "message": bytes(message),
            "rendezvous_key": key_from_wire(rendezvous_key),
        },
    }


def collect_params(rendezvous_key: Hash) -> dict[str, Any]:
    """``collect(rendezvous_key)`` params (§1)."""
    return {
        "type": TYPE_COLLECT_REQUEST,
        "data": {"rendezvous_key": key_from_wire(rendezvous_key)},
    }


def empty_params() -> dict[str, Any]:
    """``advertise`` params — an empty CBOR map (see :data:`TYPE_EMPTY_PARAMS`)."""
    return {"type": TYPE_EMPTY_PARAMS, "data": {}}


def offer_ok(result: Any) -> bool:
    """Read ``offer``'s ``{ ok }`` result (§1).

    A duplicate offer is ``ok: true``, not a distinct wire status: §1.1 pin 2
    makes a retry idempotent, so "your message is at the key" is the only fact
    that matters, and reporting duplicate-vs-stored would invite a client to
    branch on something that carries no meaning for it.
    """
    return _result_data(result).get("ok") is True


def collect_messages_from_result(result: Any) -> list[bytes]:
    """Read ``collect``'s ``{ messages: [<blob>, ...] }`` result (§1).

    An **empty list is a 200**, not a 404: a peer polling ahead of its
    counterpart is the normal case in a rendezvous.
    """
    data = _result_data(result)
    items = data.get("messages")
    if items is None:
        raise SignalingDecodeError("missing array field messages")
    if not isinstance(items, list):
        raise SignalingDecodeError("missing/invalid array field messages")
    blobs: list[bytes] = []
    for item in items:
        if not isinstance(item, (bytes, bytearray)):
            raise SignalingDecodeError("messages entry is not a bstr")
        blobs.append(bytes(item))
    return blobs


# ---------------------------------------------------------------------------
# advertise
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Limits:
    """The node's advisory-to-peers, binding-on-the-node bounds (§1.1).

    A **bare CBOR map** on the wire, not an entity wrapper. The node **refuses,
    never evicts** — eviction would reproduce exactly the silent-never-meet shape,
    with the evicted peer believing it is at the key and waiting.
    """

    bucket_ttl_ms: int
    max_message_bytes: int
    max_messages_per_key: int
    max_keys: int


@dataclass(frozen=True)
class Advertisement:
    """What ``advertise`` answers: the node's endpoint, limits and lobby constant.

    Attributes:
        endpoint: The advertised endpoint string. Weight is computed over these
            bytes **exactly as published** (§3.1.1), so it is never normalized.
        limits: The node's bounds.
        lobby: The node's ``lobby`` override, or ``None`` for "I use the
            default". **Absent, never null** on the wire; a value equal to
            :data:`LOBBY_DEFAULT` normalizes back to ``None`` so a decoded
            advertisement compares equal to one from a node that never set it.
    """

    endpoint: str
    limits: Limits
    lobby: str | None = None

    @property
    def lobby_constant(self) -> str:
        """The input to hand :func:`~entity_handlers.signaling.key.lobby_key` —
        the override if one is set, else :data:`LOBBY_DEFAULT`."""
        return self.lobby if self.lobby is not None else LOBBY_DEFAULT


def advertisement_from_result(result: Any) -> Advertisement:
    """Decode an advertisement (client side / registry pool membership)."""
    data = _result_data(result)
    limits = data.get("limits")
    if not isinstance(limits, dict):
        raise SignalingDecodeError("missing/invalid map field limits")
    lobby = data.get("lobby")
    if lobby is not None and not isinstance(lobby, str):
        raise SignalingDecodeError("invalid text field lobby")
    return Advertisement(
        endpoint=_field_text(data, "endpoint"),
        # Absent → no override; a present-but-default value normalizes away.
        lobby=None if lobby is None or lobby == LOBBY_DEFAULT else lobby,
        limits=Limits(
            bucket_ttl_ms=_field_int(limits, "bucket_ttl_ms"),
            max_message_bytes=_field_int(limits, "max_message_bytes"),
            max_messages_per_key=_field_int(limits, "max_messages_per_key"),
            max_keys=_field_int(limits, "max_keys"),
        ),
    )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _result_data(result: Any) -> dict[str, Any]:
    """Pull ``data`` off a result entity dict.

    Handlers return a single typed result entity (``{type, data, content_hash}``);
    this reads its payload without recomputing or re-serializing anything (§1.8).
    """
    if not isinstance(result, dict):
        raise SignalingDecodeError(
            f"expected a result entity dict, got {type(result).__name__}"
        )
    data = result.get("data")
    if not isinstance(data, dict):
        raise SignalingDecodeError("result entity has no data map")
    return data


def _field_text(m: dict[str, Any], key: str) -> str:
    v = m.get(key)
    if not isinstance(v, str):
        raise SignalingDecodeError(f"missing/invalid text field {key}")
    return v


def _field_int(m: dict[str, Any], key: str) -> int:
    v = m.get(key)
    if isinstance(v, bool) or not isinstance(v, int):
        raise SignalingDecodeError(f"missing/invalid integer field {key}")
    return v
