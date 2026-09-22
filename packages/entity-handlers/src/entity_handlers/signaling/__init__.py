"""Signaling — the **client** for a rendezvous connection node.

``PROPOSAL-CONNECTION-NODE`` §1–§2, ``PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH``
§2.2 / §3 / §4, ``PROPOSAL-REGISTRY-SERVICE-ADVERTISEMENT`` §3.1.1.

A connection node is a stateless introducer: two peers that cannot reach each
other deposit and read opaque blobs at an opaque 33-byte **rendezvous key** until
they have each other's candidate addresses. This package is the peer-side half —
what a Python peer needs to *use* such a node.

What is built here
------------------

============================================ ==========================================
:mod:`~entity_handlers.signaling.key`        §2.2 key derivation, the four modes
:mod:`~entity_handlers.signaling.pool`       §3.1.1 pool selection (rendezvous-hash)
:mod:`~entity_handlers.signaling.coordination` §3 messages, §3.1 blob framing, §3.2 read rules
:mod:`~entity_handlers.signaling.data`       the three ops' params/result codecs
:mod:`~entity_handlers.signaling.client`     :class:`SignalingClient` over a Dispatcher
============================================ ==========================================

Deliberately **not** built, per the go/py build brief: ``reflect`` and the
unwrapped surface (§5.1 is unwritten), the punch itself (Stage 2, socket work), a
``service-advertisement`` consumer (still DRAFT — take the pool as a list of
``(endpoint, priority)`` and stop there), §3.3 signing (staged with the probe
budget, deferred), and **the server role** (optional per §1.2 — nobody runs a
Python rendezvous box).

The two obligations that fail silently
--------------------------------------

The node is mode-blind: it compares 33 opaque bytes and derives nothing. So the
**client** owns both convergence obligations — *which key* (§2.2) and *which node
of a pool* (§3.1.1) — and a peer that gets either wrong **meets nobody and sees
no error**, with every individual step reporting success. That is why a
wrong-but-self-consistent derivation passes a same-impl suite exactly as a
correct one does, and why the tests beside this package are differential
(§2.2.1) rather than authored expected-key vectors.

Stage 1 does **not** connect two NAT'd peers. It proves mechanism, not
connectivity; the both-NAT'd case is Stage 2.
"""

from __future__ import annotations

from entity_handlers.signaling.client import (
    Backoff,
    ClientError,
    DispatchFailed,
    Refused,
    SignalingClient,
    Unsupported,
)
from entity_handlers.signaling.constants import (
    CAP_SIGNALING_ADVERTISE,
    CAP_SIGNALING_COLLECT,
    CAP_SIGNALING_OFFER,
    CODE_BUCKET_FULL,
    CODE_CAPACITY_EXHAUSTED,
    CODE_INVALID_PARAMS,
    CODE_MESSAGE_TOO_LARGE,
    LOBBY_DEFAULT,
    OP_ADVERTISE,
    OP_COLLECT,
    OP_OFFER,
    OPERATIONS,
    PATTERN,
    RENDEZVOUS_KEY_LEN,
    SIGNALING_SEED_CAPS,
    SignalingDecodeError,
    SignalingEncodeError,
    SignalingError,
)
from entity_handlers.signaling.coordination import (
    CANDIDATE_HOST,
    CANDIDATE_RELAY,
    CANDIDATE_SRFLX,
    PUNCH_DELAY_FLOOR_MS,
    SUBSTRATE_QUIC,
    SUBSTRATE_TCP,
    SUBSTRATE_WEBRTC,
    TYPE_CONNECT_REQUEST,
    TYPE_CONNECT_RESPONSE,
    TYPE_PUNCH_SYNC,
    Candidate,
    CollectedMessage,
    ConnectRequest,
    ConnectResponse,
    PunchSync,
    UnknownMessage,
    classify,
    classify_blob,
    find_request,
    find_requests,
    find_response,
    generate_nonce,
    order_for_dialing,
    punch_delay,
    to_blob,
)
from entity_handlers.signaling.data import (
    TYPE_ADVERTISE_RESULT,
    TYPE_COLLECT_REQUEST,
    TYPE_COLLECT_RESULT,
    TYPE_OFFER_REQUEST,
    TYPE_OFFER_RESULT,
    Advertisement,
    Limits,
)
from entity_handlers.signaling.key import (
    DOMAIN,
    MODE_LOBBY,
    MODE_PAIR,
    MODE_SECRET,
    MODE_TAG,
    RENDEZVOUS_KEY_TYPE,
    SEP,
    derive,
    key_from_wire,
    lobby_key,
    pair_key,
    rendezvous_payload,
    secret_key,
    tag_key,
)
from entity_handlers.signaling.pool import (
    SKEW_FANOUT,
    PoolMember,
    select,
    select_top,
    weight,
)
from entity_handlers.signaling.reflection import (
    SCHEME_STUN,
    SCHEME_STUNS,
    ReflectionEndpointError,
    normalize_reflection_endpoints,
    validate_reflection_endpoint,
)

__all__ = [
    # constants / errors
    "PATTERN",
    "OP_OFFER",
    "OP_COLLECT",
    "OP_ADVERTISE",
    "OPERATIONS",
    "CAP_SIGNALING_OFFER",
    "CAP_SIGNALING_COLLECT",
    "CAP_SIGNALING_ADVERTISE",
    "SIGNALING_SEED_CAPS",
    "CODE_INVALID_PARAMS",
    "CODE_MESSAGE_TOO_LARGE",
    "CODE_BUCKET_FULL",
    "CODE_CAPACITY_EXHAUSTED",
    "RENDEZVOUS_KEY_LEN",
    "LOBBY_DEFAULT",
    "SignalingError",
    "SignalingDecodeError",
    "SignalingEncodeError",
    # key (§2.2)
    "RENDEZVOUS_KEY_TYPE",
    "DOMAIN",
    "SEP",
    "MODE_PAIR",
    "MODE_TAG",
    "MODE_SECRET",
    "MODE_LOBBY",
    "rendezvous_payload",
    "derive",
    "pair_key",
    "tag_key",
    "secret_key",
    "lobby_key",
    "key_from_wire",
    # pool (§3.1.1)
    "PoolMember",
    "weight",
    "select",
    "select_top",
    "SKEW_FANOUT",
    # coordination (§3, §4)
    "TYPE_CONNECT_REQUEST",
    "TYPE_CONNECT_RESPONSE",
    "TYPE_PUNCH_SYNC",
    "CANDIDATE_HOST",
    "CANDIDATE_SRFLX",
    "CANDIDATE_RELAY",
    "SUBSTRATE_TCP",
    "SUBSTRATE_QUIC",
    "SUBSTRATE_WEBRTC",
    "Candidate",
    "order_for_dialing",
    "generate_nonce",
    "ConnectRequest",
    "ConnectResponse",
    "PunchSync",
    "PUNCH_DELAY_FLOOR_MS",
    "punch_delay",
    "CollectedMessage",
    "UnknownMessage",
    "to_blob",
    "classify",
    "classify_blob",
    "find_response",
    "find_request",
    "find_requests",
    # data (§5.1)
    "TYPE_OFFER_REQUEST",
    "TYPE_OFFER_RESULT",
    "TYPE_COLLECT_REQUEST",
    "TYPE_COLLECT_RESULT",
    "TYPE_ADVERTISE_RESULT",
    "Limits",
    "Advertisement",
    # reflection (§4.5.1)
    "SCHEME_STUN",
    "SCHEME_STUNS",
    "ReflectionEndpointError",
    "validate_reflection_endpoint",
    "normalize_reflection_endpoints",
    # client
    "SignalingClient",
    "ClientError",
    "DispatchFailed",
    "Refused",
    "Backoff",
    "Unsupported",
]
