"""Shared constants and errors for the signaling client.

Mirrors the constant surface of Rust's ``extensions/signaling/src/lib.rs`` and
``core.rs`` (``PATTERN``, ``OP_*``, ``CAP_*``, ``CODE_*``, ``LOBBY_DEFAULT``,
``RENDEZVOUS_KEY_LEN``) so the two impls name the same wire facts identically.

Only the **client** half is built here (``PROPOSAL-CONNECTION-NODE`` §1.2 makes
the server role optional, and nobody runs a Python rendezvous box) — the codes
below are what a client *reads* off a refusal, not what it emits.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# The verb surface (§1) — handler pattern and the exactly-three operations
# ---------------------------------------------------------------------------

#: Handler pattern; a node is addressed as ``entity://{node_peer_id}/{PATTERN}``.
PATTERN = "system/signaling"

#: Deposit an opaque blob at an opaque key.
OP_OFFER = "offer"
#: Read what is at a key, removing nothing.
OP_COLLECT = "collect"
#: Announce this node's endpoint and limits.
OP_ADVERTISE = "advertise"

#: Exactly three (§1). ``reflect`` is deliberately **not** here: it is the
#: unwrapped listener's verb (§1.4), so asking a wrapped node for it is an
#: ordinary ``unknown_operation`` / 400, not a 501.
OPERATIONS: tuple[str, ...] = (OP_OFFER, OP_COLLECT, OP_ADVERTISE)

# ---------------------------------------------------------------------------
# Capability surface (§2) — the wrapped surface's admission control
# ---------------------------------------------------------------------------
#
# The client adds no authority of its own: each dispatch is cap-checked at the
# dispatcher, so the *caller's* grant must cover these.

CAP_SIGNALING_OFFER = "system/capability/signaling-offer"
CAP_SIGNALING_COLLECT = "system/capability/signaling-collect"
CAP_SIGNALING_ADVERTISE = "system/capability/signaling-advertise"

SIGNALING_SEED_CAPS: tuple[str, ...] = (
    CAP_SIGNALING_OFFER,
    CAP_SIGNALING_COLLECT,
    CAP_SIGNALING_ADVERTISE,
)

# ---------------------------------------------------------------------------
# Error codes a node answers with (§1.1). Both capacity refusals are 429.
# ---------------------------------------------------------------------------

#: Params fail to decode, or the key is not 33 bytes — 400.
CODE_INVALID_PARAMS = "invalid_params"
#: Message exceeds ``max_message_bytes`` — 400.
CODE_MESSAGE_TOO_LARGE = "message_too_large"
#: The key already holds ``max_messages_per_key`` live messages — 429.
CODE_BUCKET_FULL = "bucket_full"
#: The node is at ``max_keys`` — 429.
CODE_CAPACITY_EXHAUSTED = "capacity_exhausted"
#: Unknown signaling operation — 400. This is what ``reflect`` gets (§1.4).
CODE_UNKNOWN_OPERATION = "unknown_operation"

# ---------------------------------------------------------------------------
# Key and lobby constants
# ---------------------------------------------------------------------------

#: A rendezvous key is always ``0x00 ‖ SHA-256`` — 33 bytes, the SHA-256 floor
#: regardless of the deriving peer's home hash format (§2.2). See
#: :mod:`entity_handlers.signaling.key` for why that inversion is load-bearing.
RENDEZVOUS_KEY_LEN = 33

#: The named ``lobby`` input (§2.2 Finding B). "Per deployment" without an
#: actual named default is a silent-never-meet bug: two peers on the same open
#: node would each invent a different input. A node MAY override it via
#: ``advertise`` — call ``advertise`` before deriving a lobby key.
LOBBY_DEFAULT = "lobby:default"


class SignalingError(Exception):
    """A codec-level failure — encoding or decoding a signaling entity."""


class SignalingDecodeError(SignalingError):
    """Malformed CBOR, a missing field, or a wrong-width rendezvous key."""


class SignalingEncodeError(SignalingError):
    """A value that cannot be encoded into a signaling entity."""
