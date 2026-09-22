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
#: unwrapped listener's verb (§1.4). Asking a *wrapped* node for it is
#: therefore an operation a registered handler does not implement, which is
#: core §3.3's 501 row — ``501 unsupported_operation``, not a 400. (This read
#: ``ordinary unknown_operation / 400, not a 501`` until 0.8.2.7; the
#: intent-flavoured distinction it drew is one §6.2 says the corpus does not
#: make.)
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
# `CODE_UNKNOWN_OPERATION = "unknown_operation"` lived here until 0.8.2.7,
# documented as *"Unknown signaling operation — 400. This is what `reflect`
# gets (§1.4)."* It is gone rather than renamed. Three separate things were
# wrong with it and only the first is about spelling:
#
#   1. `unknown_operation` is the synonym §3.3's 501 row forbids outright.
#   2. `EXTENSION-SIGNALING` pins no such code — grepped at arch `646b82e`,
#      **zero** occurrences in the extension. So unlike SA-PY-33's
#      `bad_request`, this was not a corpus conflict to file; it was
#      vocabulary this seat minted and then exported in `__all__`.
#   3. It was **never emitted**. The node answered `CODE_INVALID_REQUEST` at
#      that site, so nothing would have caught the constant drifting — a
#      declared-but-dead wire value has no consumer to disagree with it.
#
# The node now answers `501 unsupported_operation` there, which is the core
# code and needs no signaling-local constant.

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
