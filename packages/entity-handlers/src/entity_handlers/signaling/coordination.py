"""The coordination messages — **what actually rides through the node**.

``PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH`` §3, §4.

Everything above this module moves opaque bytes. This is what those bytes *are*:
the DCUtR-analog "we both dial at T" dance, three message types, ordinary V7
entities. **The rendezvous node sees only the 33-byte key and an opaque blob** —
it never decodes any of this, which is why §3 calls them carrier-agnostic::

      A                          node                          B
      │  offer(K, connect-request) ─►│                          │
      │                              │◄─ collect(K) ────────────│
      │                              │── connect-response ─────►│  offer(K, ...)
      │◄─ collect(K) ────────────────│                          │
      │  punch-sync(fire_at) ───────►│─────────────────────────►│
      └──────────── both fire at ≈ the same instant ────────────┘   ← Stage 2

What is here and what is not
----------------------------

The three **wire shapes** and the §4 step-2 exchange (offer/collect the candidate
lists) are here — that is the rendezvous carrier's job and it is Stage 1.
:class:`PunchSync` is carried too, because its shape is part of the same message
family, but **nothing fires it**: §4 steps 3–5 are RTT measurement, a
simultaneous open and a transport upgrade — socket work, Stage 2.

One piece of step 3 *is* here, deliberately: :func:`punch_delay` and
``fire_at``'s clock domain (§4.1). Both are pure computation and both are
cross-peer-observable, so they belong with the wire shapes rather than with the
socket work that consumes them.

The Stage-1 gap, stated: these messages are not signed
------------------------------------------------------

§3.3 pins that a coordination blob is self-contained — the entity plus a detached
signature carrying the signer's ``public_key``. **None of it is implemented, and
that is correct for Stage 1**: Stage 1 does not punch, and Rust built then
reverted it as premature. What bounds the exposure meanwhile is that **the key
introduces, it never authorizes** — a punched connection still runs the full
handshake and capability flow, so the worst case from a forged bucket entry is a
wasted dial.

The MUST that is easy to violate
--------------------------------

**Candidates are session-scoped and ephemeral. They MUST NOT be persisted as
durable ``system/peer/transport/{peer}/{profile-id}`` profiles**
(``PROPOSAL-NETWORK-REACHABILITY-FACTS`` §4.1). A profile is a *stable published
endpoint*; a candidate is one NAT mapping for one connection attempt and goes
stale instantly. Writing one as a profile mis-routes every later dispatch that
reads it — the classic "worked for the issuer, stale for everyone else" failure.
Candidates live **inside** these messages and never as tree state, so nothing in
this module writes anything.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import ecf_decode, ecf_encode
from entity_handlers.signaling.constants import SignalingDecodeError

# ---------------------------------------------------------------------------
# Entity types (§6.1, §12). The namespace open item (`system/nat/*` vs
# `system/signaling/*`) resolved to **`system/signaling/*`** on 2026-08-02
# (§13 item #1; the owner-not-problem-domain rule — `nat` named a problem
# domain that would strand its siblings the moment a second substrate
# arrived). These strings were `system/nat/*` here until the 2026-08-05
# re-diff against the committed corpus.
# ---------------------------------------------------------------------------

TYPE_CONNECT_REQUEST = "system/signaling/connect-request"
TYPE_CONNECT_RESPONSE = "system/signaling/connect-response"
TYPE_PUNCH_SYNC = "system/signaling/punch-sync"

# ---------------------------------------------------------------------------
# Candidates (``PROPOSAL-NETWORK-REACHABILITY-FACTS`` §4)
# ---------------------------------------------------------------------------

#: A local/LAN address — works when the peers share a network. Cheapest, first.
CANDIDATE_HOST = "host"
#: Server-reflexive: the public mapping a reflector observed. **The punch target.**
CANDIDATE_SRFLX = "srflx"
#: A public relay address — the always-works fallback, tried last because it is
#: the metered path.
CANDIDATE_RELAY = "relay"

#: Built and shipping.
SUBSTRATE_TCP = "tcp"
#: Declared but unbuilt in v1 (§5) — gated on building our own QUIC transport.
SUBSTRATE_QUIC = "quic"
#: Declared but unbuilt in v1 (§5).
SUBSTRATE_WEBRTC = "webrtc"

#: The §4 class ordering. An unknown type sorts **last** rather than being
#: dropped — MUST-ignore says a peer that learns a new candidate class from a
#: newer impl should still try what it does understand first, not refuse the
#: whole message.
_CLASS_RANK = {CANDIDATE_HOST: 0, CANDIDATE_SRFLX: 1, CANDIDATE_RELAY: 2}
_CLASS_RANK_UNKNOWN = 3

#: 16 random bytes — enough that two concurrent exchanges in one ``lobby``
#: bucket will not collide.
NONCE_LEN = 16


@dataclass(frozen=True)
class Candidate:
    """One address a peer might be reachable at, typed and ordered ICE-style.

    Attributes:
        candidate_type: ``host`` | ``srflx`` | ``relay``.
        substrate: ``tcp`` | ``quic`` | ``webrtc``.
        address: The address itself. Deliberately an **opaque string** at this
            layer — the entity layer never interprets ``IP:port``, which is the
            load-bearing addressing invariant these facts are careful not to
            break.
        priority: Lower is tried first, matching §10's existing
            ``(priority asc, profile-id lex)`` profile loop.
    """

    candidate_type: str
    substrate: str
    address: str
    priority: int = 0

    def class_rank(self) -> int:
        """The §4 class rank; unknown classes sort last (see :data:`_CLASS_RANK`)."""
        return _CLASS_RANK.get(self.candidate_type, _CLASS_RANK_UNKNOWN)

    def to_data(self) -> dict[str, Any]:
        """The bare CBOR map a candidate is on the wire."""
        return {
            "address": self.address,
            "priority": self.priority,
            "substrate": self.substrate,
            "type": self.candidate_type,
        }

    @classmethod
    def from_data(cls, value: Any) -> Candidate:
        if not isinstance(value, dict):
            raise SignalingDecodeError("candidate is not a map")
        return cls(
            candidate_type=_field_text(value, "type"),
            substrate=_field_text(value, "substrate"),
            address=_field_text(value, "address"),
            priority=_field_uint_or(value, "priority", 0),
        )


def order_for_dialing(candidates: Iterable[Candidate]) -> list[Candidate]:
    """Order a candidate list for dialing: class first (``host`` → ``srflx`` →
    ``relay``), then ``priority`` ascending, then address for a total order.

    "First pair that completes a connectivity check wins" (§4), so this ordering
    *is* the dial plan. It is deterministic to the last tiebreak on purpose — two
    peers that order differently waste attempts crossing at different candidates.
    """
    return sorted(
        candidates, key=lambda c: (c.class_rank(), c.priority, c.address)
    )


def generate_nonce() -> bytes:
    """A fresh :data:`NONCE_LEN`-byte correlator for one exchange (§3).

    Load-bearing in the multi-party modes: a ``lobby`` or ``tag`` bucket holds
    everyone's messages, and ``collect`` is non-destructive, so a peer re-reads
    the whole bucket every poll. Without the nonce echo there is no way to tell
    *your* answer from someone else's, or a fresh answer from one you already
    processed two polls ago. It is a **correlator, not a secret**.
    """
    return secrets.token_bytes(NONCE_LEN)


# ---------------------------------------------------------------------------
# §3 — the three messages
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectRequest:
    """A → B. "Here is who I am, where I might be reached, and the tag that ties
    your answer to this attempt.\""""

    initiator: str
    candidates: tuple[Candidate, ...] = ()
    nonce: bytes = b""

    def to_entity(self) -> Entity:
        return Entity(
            type=TYPE_CONNECT_REQUEST,
            data={
                "candidates": [c.to_data() for c in self.candidates],
                "initiator": self.initiator,
                "nonce": self.nonce,
            },
        )

    @classmethod
    def from_data(cls, data: Any) -> ConnectRequest:
        m = _as_map(data)
        return cls(
            initiator=_field_text(m, "initiator"),
            candidates=_field_candidates(m),
            nonce=_field_bytes(m, "nonce"),
        )


@dataclass(frozen=True)
class ConnectResponse:
    """B → A, echoing A's nonce."""

    responder: str
    candidates: tuple[Candidate, ...] = ()
    nonce: bytes = b""

    def to_entity(self) -> Entity:
        return Entity(
            type=TYPE_CONNECT_RESPONSE,
            data={
                "candidates": [c.to_data() for c in self.candidates],
                "nonce": self.nonce,
                "responder": self.responder,
            },
        )

    @classmethod
    def from_data(cls, data: Any) -> ConnectResponse:
        m = _as_map(data)
        return cls(
            responder=_field_text(m, "responder"),
            candidates=_field_candidates(m),
            nonce=_field_bytes(m, "nonce"),
        )


@dataclass(frozen=True)
class PunchSync:
    """Either direction — aligns the moment both sides fire.

    **``fire_at`` is a delay, not a timestamp** (§4.1, MUST, conformance MUST #5).
    It is **unsigned integer milliseconds measured from the receiving peer's
    moment of receipt** of this entity. V7 assumes no synchronized clocks, and
    two peers' wall clocks can differ by far more than the whole punch window, so
    a wall-clock instant on the wire is a silent never-meet.

    **Why this shape needs a test rather than care.** The failure is invisible to
    every same-host test — both peers read the same clock, so a wall-clock
    encoding passes — the same masking shape §2.2's home-format trap has. It is
    also the *plausible* implementation: "the agreed instant" reads like a
    timestamp, and Rust encoded one (a signed ``i64`` of ms since epoch) until
    §4.1 pinned the clock domain. So the test asserts on the **encoded bytes**
    (CBOR major 0), not through our own decoder.

    Who fires when (§4.1): **A fires ``d`` after *sending*, B fires ``d`` after
    *receiving*.** The sync crosses roughly half the carrier round trip, so the
    two firings meet near the middle. Deriving ``d`` is :func:`punch_delay`;
    measuring the RTT and actually firing are Stage 2.
    """

    nonce: bytes
    #: Milliseconds from **receipt**, never an absolute instant.
    fire_at: int = 0

    def __post_init__(self) -> None:
        # Unrepresentable rather than merely unwise: a negative delay is the
        # wall-clock reading of a field that has no such domain.
        if self.fire_at < 0:
            raise ValueError(
                f"fire_at is a delay in ms from receipt and MUST be unsigned; "
                f"got {self.fire_at}"
            )

    def to_entity(self) -> Entity:
        return Entity(
            type=TYPE_PUNCH_SYNC,
            data={"fire_at": self.fire_at, "nonce": self.nonce},
        )

    @classmethod
    def from_data(cls, data: Any) -> PunchSync:
        m = _as_map(data)
        return cls(
            nonce=_field_bytes(m, "nonce"),
            fire_at=_field_uint(m, "fire_at"),
        )


#: The default ``d`` in §4.1's derivation: ``d = max(rtt, 250 ms)``.
#: Industry-typical, **not** measured here — §4.1 pins the shape and leaves the
#: number to the live gate, so this is a tunable default, not a wire constant.
#: Two peers may hold different floors without failing to meet; they may not
#: differ on the clock domain or the encoding.
PUNCH_DELAY_FLOOR_MS = 250


def punch_delay(rtt_ms: int) -> int:
    """Derive the ``fire_at`` delay from the measured carrier round-trip (§4.1).

    ``rtt_ms`` is the round trip **through the carrier** — A's ``offer`` to the
    ``collect`` that returns B's response. That is the only latency estimate
    either peer has, since by construction neither can yet reach the other
    directly.

    The MUST this enforces: **``d`` ≥ the one-way carrier latency (``rtt/2``)**.
    Below that floor B's fire time has already elapsed when the sync lands and
    the two sides never overlap. ``max(rtt, 250)`` satisfies it with margin —
    ``d ≥ rtt`` implies ``d ≥ rtt/2`` — so the guarantee holds for any floor,
    not just this default.
    """
    if rtt_ms < 0:
        raise ValueError(f"rtt_ms must be non-negative, got {rtt_ms}")
    return max(rtt_ms, PUNCH_DELAY_FLOOR_MS)


# ---------------------------------------------------------------------------
# Reading a bucket — §3.2, where a naive impl breaks. All the filters below are
# MUSTs, ratified from the Rust build rather than authored ahead of it: skip your
# own messages, correlate a response by nonce echo, and skip an undecodable blob
# rather than erroring. Bucket order is deposit order, oldest first (§1.1 pin 4).
# *Which* of several ``lobby`` requests to answer is deliberately peer policy.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UnknownMessage:
    """An undecodable or unrecognized blob.

    A bucket is a *set* the node never interprets, so anything may be in it: your
    own offer (``collect`` is non-destructive, so you always re-read what you
    wrote), other pairs' traffic in ``lobby``/``tag``, and — MUST-ignore —
    message types a newer impl introduced. Classification is therefore lossy on
    purpose: an unknown blob is a **normal outcome, never an error**.

    The raw bytes are kept rather than dropped so a caller can *count* what it
    skipped instead of silently ignoring a bucket full of messages it does not
    understand.
    """

    blob: bytes = field(repr=False, default=b"")


#: What :func:`classify_blob` returns. ``isinstance`` is the dispatch, which
#: keeps :class:`UnknownMessage` countable alongside the three known shapes.
CollectedMessage = ConnectRequest | ConnectResponse | PunchSync | UnknownMessage


def to_blob(entity: Entity) -> bytes:
    """Serialize a coordination entity into the opaque blob the node stores —
    **§3.1, the pinned framing.**

    The blob is the canonical ``{type, data, content_hash}`` encoding, so the
    message's **type travels with it** — a bucket holds a mixed set and the
    reader has nothing else to dispatch on. ``connect-request`` and
    ``connect-response`` differ by a single field *name*, so a reader handed bare
    ``data`` would be reduced to sniffing map keys.

    This shape was chosen by Rust's Stage-1 build and **ratified unchanged** as
    §3.1 — the spec had never said what ``offer``'s ``message`` bytes are, which
    would have meant Go and Rust wrapping differently and every cross-impl
    rendezvous returning blobs nobody could classify.
    """
    return ecf_encode(entity.to_dict(include_hash=True))


def classify_blob(blob: bytes) -> CollectedMessage:
    """Classify one blob collected from a bucket.

    An undecodable blob is an :class:`UnknownMessage`, **not** an error: a shared
    ``lobby`` bucket may legitimately hold anything, including a future message
    type this build has never heard of, and MUST-ignore says we skip it rather
    than fail the poll.
    """
    try:
        wire = ecf_decode(blob)
    except Exception:
        return UnknownMessage(blob)
    if not isinstance(wire, dict):
        return UnknownMessage(blob)
    entity_type = wire.get("type")
    if not isinstance(entity_type, str):
        return UnknownMessage(blob)
    return classify(entity_type, wire.get("data"), blob=blob)


def classify(
    entity_type: str, data: Any, *, blob: bytes = b""
) -> CollectedMessage:
    """Classify from an already-split type and data.

    We match on the **type string** rather than sniffing the map, because two of
    these three have identical field sets apart from ``initiator``/``responder``.
    """
    decoders = {
        TYPE_CONNECT_REQUEST: ConnectRequest.from_data,
        TYPE_CONNECT_RESPONSE: ConnectResponse.from_data,
        TYPE_PUNCH_SYNC: PunchSync.from_data,
    }
    decoder = decoders.get(entity_type)
    if decoder is None:
        return UnknownMessage(blob)
    try:
        return decoder(data)
    except (SignalingDecodeError, ValueError):
        return UnknownMessage(blob)


def find_response(
    messages: Iterable[CollectedMessage], my_nonce: bytes, my_peer_id: str
) -> ConnectResponse | None:
    """Find the response to *my* exchange in a collected bucket.

    Two §3.2 MUSTs, both necessary:

    - **nonce echo** — in ``lobby``/``tag`` the bucket is shared, so someone
      else's response is not mine, and a fresh answer is not one processed two
      polls ago. The nonce is a **correlator, not a secret**: anyone who can
      collect the bucket can read it and echo it, which is what §3.3's signature
      is for.
    - **not my own peer-id** — a peer that answered its own request would
      "succeed" at meeting itself, and that failure is miserable to diagnose
      because every individual step reports success.
    """
    for m in messages:
        if (
            isinstance(m, ConnectResponse)
            and m.nonce == my_nonce
            and m.responder != my_peer_id
        ):
            return m
    return None


def find_requests(
    messages: Iterable[CollectedMessage], my_peer_id: str
) -> list[ConnectRequest]:
    """Every request in the bucket that I could answer — anyone's but my own, in
    deposit order (oldest first).

    The plural is the one a responder usually wants. ``pair`` and ``lobby`` keys
    are **stable by construction** — a pair's key is its two peer-ids, a lobby's
    is a pool constant — so within the 60 s TTL a bucket legitimately holds
    earlier exchanges, including a *previous run's*. A responder that answers
    only the first match can spend every poll answering a stranger whose
    counterpart has long since given up, while the peer waiting right now is
    never answered and every individual step reports success.

    **Answering all of them is the rerun-safe policy** and is what go's
    ``signaling`` validator category adopted (``entity-core-go`` @ ``989366c``);
    responding costs one ``offer`` per request and the initiator discards
    anything whose nonce is not its own. This layer still does not *decide* the
    policy — §3.2 leaves that to the peer — it just stops making answer-first the
    path of least resistance.
    """
    return [
        m
        for m in messages
        if isinstance(m, ConnectRequest) and m.initiator != my_peer_id
    ]


def find_request(
    messages: Iterable[CollectedMessage], my_peer_id: str
) -> ConnectRequest | None:
    """Find a request addressed at this rendezvous that I should answer — anyone's
    but my own.

    Returns the first match in bucket order (deposit order, oldest first). A
    ``lobby`` bucket may hold several, and which one to answer is a **peer
    policy** question (answer all, answer one, prefer a known peer) that this
    layer deliberately does not decide — but see :func:`find_requests` before
    reaching for this one: answering only the first match is exactly the
    stale-request trap on a stable key inside the TTL.
    """
    for m in messages:
        if isinstance(m, ConnectRequest) and m.initiator != my_peer_id:
            return m
    return None


# ---------------------------------------------------------------------------
# Field helpers — decode strictly, so a malformed message classifies as Unknown
# rather than yielding a half-populated one.
# ---------------------------------------------------------------------------


def _as_map(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise SignalingDecodeError("expected a CBOR map")
    return data


def _field_text(m: dict[str, Any], key: str) -> str:
    v = m.get(key)
    if not isinstance(v, str):
        raise SignalingDecodeError(f"missing/invalid text field {key}")
    return v


def _field_bytes(m: dict[str, Any], key: str) -> bytes:
    v = m.get(key)
    if not isinstance(v, (bytes, bytearray)):
        raise SignalingDecodeError(f"missing/invalid bstr field {key}")
    return bytes(v)


def _field_uint(m: dict[str, Any], key: str) -> int:
    """Read an unsigned integer field.

    A negative value **fails here rather than being clamped or widened**:
    ``fire_at`` is a delay (§4.1), so a negative one is not a small mistake to
    tolerate — it is the wall-clock reading of a field that has no such domain,
    and acting on it means firing into a window that has already passed.
    """
    v = m.get(key)
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise SignalingDecodeError(f"missing/invalid unsigned integer field {key}")
    return v


def _field_uint_or(m: dict[str, Any], key: str, default: int) -> int:
    v = m.get(key)
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        return default
    return v


def _field_candidates(m: dict[str, Any]) -> tuple[Candidate, ...]:
    items = m.get("candidates")
    if not isinstance(items, list):
        raise SignalingDecodeError("missing/invalid array field candidates")
    return tuple(Candidate.from_data(i) for i in items)
