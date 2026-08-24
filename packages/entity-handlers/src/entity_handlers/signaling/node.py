"""EXTENSION-SIGNALING §4/§5 — the rendezvous **node** (server) role.

A keyed mailbox and nothing more. `offer` deposits an opaque blob at an opaque
33-byte key, `collect` reads what is there, `advertise` publishes the endpoint
and the bounds. The node derives nothing and knows nothing about the four modes
of §3 — it compares keys **byte-wise** and never decodes a blob (§4.3).

Why Python builds this at all
-----------------------------

§2.1 makes the server role OPTIONAL and names the cost of declining it:
*"underspecification stays invisible — one implementation cannot disagree with
itself."* Go and Rust both carry node roles; a third is what turns
cohort-consistency into something a little stronger. It is also the only way
this peer's own §4/§5 surface and the punch carrier get exercised at all — an
unimplemented surface is an untested one.

§5's six pins, which are the whole design
-----------------------------------------

Answered by fiat once, because a lone server implementer has nothing
downstream to surface a wrong answer:

1. **`collect` is non-destructive.** It removes nothing; TTL is the only
   reaper, and an absent key is an **empty list, not an error**. A handshake
   has both peers polling and a `pair` bucket is read by both sides; a draining
   read makes a retry lose the peer's offer — a silent handshake failure
   indistinguishable from absence.
2. **`offer` appends**, deduplicated by content hash. `lobby` and `tag` are
   inherently multi-party, so replace would make the last writer erase
   everyone; dedup makes a retry idempotent rather than an accumulation.
3. **TTL is advisory to peers, binding on the node.**
4. **`collect` returns deposit order, oldest first.** A reader scans a bucket
   for the first message it can act on (§6.4); two nodes scanning in different
   orders answer *different peers* out of one shared `lobby` bucket — a
   cross-peer divergence wearing the costume of a preference.
5. **8 KiB per blob, 32 blobs per bucket — refuse, never truncate or evict.**
   Eviction reproduces exactly the silent-never-meet shape this surface exists
   to avoid, with the evicted peer believing it is at the key and waiting; a
   refusal tells the offerer it failed and it can retry.
6. **60 s default TTL**, published in `advertise`. Bound by the lifetime of
   what the blob *describes*: a `srflx` candidate expires with the NAT binding
   that produced it, so a longer TTL only serves candidates already unpunchable.

State lives in memory, deliberately
-----------------------------------

A bucket is ephemeral, TTL-reaped, and worthless after a restart — the peers
that deposited into it have long since retried or given up. Persisting it to
the tree would make a dumb mailbox durable state with a republish contract, and
`system/signaling/*` entities would then outlive the exchange they describe.
So the node holds buckets in a :class:`SignalingNodeExtension` and the tree
never sees a blob.

Rate limiting (§8.2 MUST) is per source **and** per key, refusing with
`rate_limited` rather than dropping silently. On the wrapped surface the
capability check is the admission story and this is defense in depth; the MUST
is written for the unwrapped surface (§9), where the limiter is the *entire*
admission story. The thresholds are deployment policy and deliberately not
pinned by the spec (§13 item 2); the error code is.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from entity_core.handlers.context import HandlerContext
from entity_core.peer.extensions import Extension, ExtensionContext
from entity_handlers._common import error_response, ok_response
from entity_handlers.signaling.constants import (
    LOBBY_DEFAULT,
    OP_ADVERTISE,
    OP_COLLECT,
    OP_OFFER,
    RENDEZVOUS_KEY_LEN,
)
from entity_handlers.signaling.data import (
    TYPE_ADVERTISE_RESULT,
    TYPE_COLLECT_RESULT,
    TYPE_OFFER_RESULT,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# §5 pins 5 and 6 — the published bounds
# ---------------------------------------------------------------------------

#: §5 pin 5. A handshake is ~1 KB, so this is generous by 8×.
DEFAULT_MAX_BLOB_BYTES = 8192
#: §5 pin 5.
DEFAULT_MAX_BUCKET_BLOBS = 32
#: §5 pin 6, in **seconds** — the committed §4.5 unit. (The pre-v1.0 shape
#: carried `bucket_ttl_ms`; a node emitting that is a 1000× reap race.)
DEFAULT_TTL_SECONDS = 60
#: A node-internal backstop, NOT one of §4.5's published limits — it is not
#: emitted in `advertise` (same call as Rust's).
DEFAULT_MAX_KEYS = 4096

# ---------------------------------------------------------------------------
# §9.2's closed error enum. A node MUST NOT invent codes outside this set.
# ---------------------------------------------------------------------------

#: Malformed input, unknown op, wrong key length, missing field — 400.
CODE_BAD_REQUEST = "bad_request"
#: Blob exceeds `max_blob_bytes` — refused, never truncated.
CODE_MESSAGE_TOO_LARGE = "message_too_large"
#: Bucket at `max_bucket_blobs` — refused, never evicted.
CODE_BUCKET_FULL = "bucket_full"
#: Admission control refused it (§8.2).
CODE_RATE_LIMITED = "rate_limited"

#: §8.2's thresholds are deployment policy; these are this deployment's call —
#: generous enough that a real rendezvous (a handful of offers and a poll loop)
#: never trips them, tight enough to bound a flood.
DEFAULT_RATE_LIMIT_OPS = 120
DEFAULT_RATE_LIMIT_WINDOW_S = 10.0


@dataclass
class _Blob:
    """One deposited message, with what the node needs to reap and dedup it."""

    payload: bytes
    digest: bytes
    deposited_at: float


@dataclass
class _Bucket:
    """The blobs at one rendezvous key, in deposit order (§5 pin 4)."""

    blobs: list[_Blob] = field(default_factory=list)


class RateLimiter:
    """§8.2 — a fixed-window counter, per source **and** per key.

    Per source alone lets one client monopolize a bucket others need; per key
    alone lets one client exhaust every bucket. The MUST names both.
    """

    def __init__(
        self,
        max_ops: int = DEFAULT_RATE_LIMIT_OPS,
        window_s: float = DEFAULT_RATE_LIMIT_WINDOW_S,
    ) -> None:
        self._max_ops = max_ops
        self._window_s = window_s
        self._counters: dict[tuple[str, bytes], tuple[float, int]] = {}

    def allow(self, source: str | None, key: bytes) -> bool:
        if not source:
            return True  # in-process dispatch; no remote to limit
        now = time.monotonic()
        slot = (source, key)
        window_start, count = self._counters.get(slot, (now, 0))
        if now - window_start >= self._window_s:
            window_start, count = now, 0
        if count >= self._max_ops:
            return False
        self._counters[slot] = (window_start, count + 1)
        return True

    def sweep(self, now: float | None = None) -> None:
        """Drop counters whose window has closed, so an idle node's limiter
        does not grow with every source that ever spoke to it."""
        moment = time.monotonic() if now is None else now
        for slot, (window_start, _count) in list(self._counters.items()):
            if moment - window_start >= self._window_s:
                del self._counters[slot]


class SignalingNode:
    """The keyed mailbox itself — buckets, TTL, and the §5 pins.

    Separate from the handler so the semantics are testable without a peer,
    and so the unwrapped §9 listener (not built here) could sit on the same
    core if it is ever wanted: §2.2's "two surfaces, one core".
    """

    def __init__(
        self,
        *,
        endpoint: str = "",
        max_blob_bytes: int = DEFAULT_MAX_BLOB_BYTES,
        max_bucket_blobs: int = DEFAULT_MAX_BUCKET_BLOBS,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_keys: int = DEFAULT_MAX_KEYS,
        lobby_constant: str | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.max_blob_bytes = max_blob_bytes
        self.max_bucket_blobs = max_bucket_blobs
        self.ttl_seconds = ttl_seconds
        self.max_keys = max_keys
        #: ``None`` means "I use the default" — emitted as an ABSENT field,
        #: never a null (§4.5).
        self.lobby_constant = (
            None if lobby_constant in (None, LOBBY_DEFAULT) else lobby_constant
        )
        self._buckets: dict[bytes, _Bucket] = {}

    # -- §5 semantics ------------------------------------------------------

    def _now(self) -> float:
        return time.monotonic()

    def _reap(self, key: bytes) -> _Bucket | None:
        """Drop expired blobs at ``key`` (§5 pin 3 — TTL is the only reaper),
        and the bucket itself once empty."""
        bucket = self._buckets.get(key)
        if bucket is None:
            return None
        cutoff = self._now() - self.ttl_seconds
        bucket.blobs = [b for b in bucket.blobs if b.deposited_at > cutoff]
        if not bucket.blobs:
            del self._buckets[key]
            return None
        return bucket

    def sweep(self) -> None:
        """Reap every bucket. Called opportunistically; correctness does not
        depend on it (reads reap their own key), but an untouched key would
        otherwise hold its blobs forever."""
        for key in list(self._buckets):
            self._reap(key)

    def offer(self, key: bytes, message: bytes) -> tuple[bool, str | None]:
        """§4.3 — deposit ``message`` at ``key``. Returns ``(ok, error_code)``.

        Append + dedup by content hash (§5 pin 2): a duplicate is ``ok``, not a
        distinct status, because "your message is at the key" is the only fact
        that matters to the offerer.
        """
        if len(message) > self.max_blob_bytes:
            # Refused, NEVER truncated (§5 pin 5) — a truncated blob is a
            # message that decodes to garbage at the far peer.
            return False, CODE_MESSAGE_TOO_LARGE
        bucket = self._reap(key)
        if bucket is None:
            if len(self._buckets) >= self.max_keys:
                # The node-internal backstop. It is a capacity refusal, and
                # §9.2's enum is closed, so it answers `rate_limited` rather
                # than inventing a code outside the set.
                return False, CODE_RATE_LIMITED
            bucket = _Bucket()
            self._buckets[key] = bucket
        digest = hashlib.sha256(message).digest()
        for existing in bucket.blobs:
            if existing.digest == digest:
                return True, None  # idempotent retry
        if len(bucket.blobs) >= self.max_bucket_blobs:
            # Refused, NEVER evicted (§5 pin 5).
            return False, CODE_BUCKET_FULL
        bucket.blobs.append(
            _Blob(payload=bytes(message), digest=digest, deposited_at=self._now()),
        )
        return True, None

    def collect(self, key: bytes) -> list[bytes]:
        """§4.4 — the blobs at ``key``, **oldest first**, removing nothing.

        An absent key returns an empty list, not an error: a peer polling
        ahead of its counterpart is the normal case in a rendezvous.
        """
        bucket = self._reap(key)
        return [b.payload for b in bucket.blobs] if bucket is not None else []

    def limits(self) -> dict[str, Any]:
        """`system/signaling/limits` (§4.5) — a **bare map**, not an entity.

        `lobby_constant` is bytes (§4.5 types it `primitive/bytes`: it is a
        derivation input §3.1 hashes verbatim, not a label) and is **absent,
        never null** when the deployment does not override the default.
        `max_keys` is not published — it is an internal backstop.
        """
        limits: dict[str, Any] = {
            "max_blob_bytes": self.max_blob_bytes,
            "max_bucket_blobs": self.max_bucket_blobs,
            "ttl_seconds": self.ttl_seconds,
        }
        if self.lobby_constant is not None:
            limits["lobby_constant"] = self.lobby_constant.encode("utf-8")
        return limits


def _key_from_params(params: dict[str, Any]) -> bytes | None:
    """The 33 opaque bytes, or ``None`` if the field is missing or the wrong
    width. §4.3: "33 opaque bytes compared byte-wise"; §9.2: any other length
    is `bad_request`."""
    raw = params.get("rendezvous_key")
    if not isinstance(raw, (bytes, bytearray)):
        return None
    key = bytes(raw)
    return key if len(key) == RENDEZVOUS_KEY_LEN else None


class SignalingNodeExtension(Extension):
    """Holds the node's buckets and exposes the `system/signaling` handler.

    An Extension because the buckets are per-peer state with a lifetime longer
    than one dispatch — the standard shape in this repo for a stateful handler.
    """

    def __init__(
        self,
        *,
        endpoint: str = "",
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_blob_bytes: int = DEFAULT_MAX_BLOB_BYTES,
        max_bucket_blobs: int = DEFAULT_MAX_BUCKET_BLOBS,
        max_keys: int = DEFAULT_MAX_KEYS,
        lobby_constant: str | None = None,
    ) -> None:
        self.node = SignalingNode(
            endpoint=endpoint,
            ttl_seconds=ttl_seconds,
            max_blob_bytes=max_blob_bytes,
            max_bucket_blobs=max_bucket_blobs,
            max_keys=max_keys,
            lobby_constant=lobby_constant,
        )
        self._limiter = RateLimiter()
        self._peer: Any | None = None

    # -- Extension lifecycle ------------------------------------------------

    def initialize(self, ctx: ExtensionContext) -> None:
        self._peer = ctx.peer

    def shutdown(self) -> None:
        self.node._buckets.clear()

    # -- handler entry ------------------------------------------------------

    async def handler(
        self,
        path: str,
        operation: str,
        params: dict[str, Any],
        ctx: HandlerContext,
    ) -> dict[str, Any]:
        """The `system/signaling` handler — exactly three operations (§4.0)."""
        data = params.get("data", params) if isinstance(params, dict) else {}
        if not isinstance(data, dict):
            data = {}

        if operation == OP_OFFER:
            return self._handle_offer(data, ctx)
        if operation == OP_COLLECT:
            return self._handle_collect(data, ctx)
        if operation == OP_ADVERTISE:
            return self._handle_advertise()
        # `reflect` lands here too: it is the UNWRAPPED listener's verb (§9.3
        # is plain STUN), so asking a wrapped node for it is an ordinary
        # unknown operation, not a 501-shaped "not implemented yet".
        return error_response(
            400, CODE_BAD_REQUEST,
            f"unknown signaling operation: {operation}",
        )

    def _source(self, ctx: HandlerContext) -> str | None:
        return getattr(ctx, "remote_peer_id", None)

    def _handle_offer(self, data: dict[str, Any], ctx: HandlerContext) -> dict[str, Any]:
        key = _key_from_params(data)
        if key is None:
            return error_response(
                400, CODE_BAD_REQUEST,
                f"rendezvous_key must be exactly {RENDEZVOUS_KEY_LEN} bytes",
            )
        message = data.get("message")
        if not isinstance(message, (bytes, bytearray)):
            return error_response(
                400, CODE_BAD_REQUEST, "message must be a byte string",
            )
        if not self._limiter.allow(self._source(ctx), key):
            return error_response(
                429, CODE_RATE_LIMITED,
                "offer refused by admission control (§8.2, per source and key)",
            )
        ok, code = self.node.offer(key, bytes(message))
        if not ok:
            # 400 for the size refusal, 429 for the capacity ones — §5 pin 5's
            # "refuse, don't evict", surfaced so the offerer can retry rather
            # than believe it is at the key.
            status = 400 if code == CODE_MESSAGE_TOO_LARGE else 429
            return error_response(status, code or CODE_BAD_REQUEST, _refusal_text(code))
        return ok_response(TYPE_OFFER_RESULT, {"ok": True})

    def _handle_collect(self, data: dict[str, Any], ctx: HandlerContext) -> dict[str, Any]:
        key = _key_from_params(data)
        if key is None:
            return error_response(
                400, CODE_BAD_REQUEST,
                f"rendezvous_key must be exactly {RENDEZVOUS_KEY_LEN} bytes",
            )
        if not self._limiter.allow(self._source(ctx), key):
            return error_response(
                429, CODE_RATE_LIMITED,
                "collect refused by admission control (§8.2, per source and key)",
            )
        # Non-destructive (§5 pin 1); absent key → empty list, a 200.
        return ok_response(
            TYPE_COLLECT_RESULT, {"messages": self.node.collect(key)},
        )

    def _handle_advertise(self) -> dict[str, Any]:
        # Resolved on first advertise, not at initialize(): extensions are
        # initialized during build(), before the listener exists, so a node
        # asked at build time would publish "". Cached once found — §3.1.1
        # weights are computed over the advertised bytes EXACTLY as published,
        # so an endpoint that changed between advertisements would silently
        # move every peer's pool selection.
        if not self.node.endpoint and self._peer is not None:
            self.node.endpoint = _listen_endpoint(self._peer) or ""
        return ok_response(
            TYPE_ADVERTISE_RESULT,
            {"endpoint": self.node.endpoint, "limits": self.node.limits()},
        )


def _refusal_text(code: str | None) -> str:
    if code == CODE_MESSAGE_TOO_LARGE:
        return "message exceeds max_blob_bytes — refused, never truncated (§5 pin 5)"
    if code == CODE_BUCKET_FULL:
        return "bucket at max_bucket_blobs — refused, never evicted (§5 pin 5)"
    return "node at capacity"


def _listen_endpoint(peer: Any) -> str | None:
    """Where this peer actually listens, as ``host:port``.

    Best-effort: a node built before `start()` has no socket yet, and one
    given an explicit endpoint never asks.
    """
    server = getattr(peer, "_server", None)
    sockets = getattr(server, "sockets", None) if server is not None else None
    if not sockets:
        return None
    try:
        host, port = sockets[0].getsockname()[:2]
    except (OSError, IndexError, ValueError):  # pragma: no cover - defensive
        return None
    return f"[{host}]:{port}" if ":" in str(host) else f"{host}:{port}"
