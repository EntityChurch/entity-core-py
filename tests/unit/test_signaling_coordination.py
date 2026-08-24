"""§3 coordination messages, §3.1 blob framing, §3.2 bucket-reading rules.

``PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH`` §3, §4, §4.1.

The §3.2 filters are all MUSTs and every one of them fails *quietly*: the symptom
is "the peers never meet" while each individual step reports success. ``fire_at``
is the other invisible one — a wall-clock encoding round-trips green on any
same-host test, because both peers read the same clock — so it is asserted **on
the encoded bytes**, not through our own decoder.
"""

from __future__ import annotations

import cbor2
import pytest

from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import ecf_decode, ecf_encode
from entity_handlers.signaling import (
    CANDIDATE_HOST,
    CANDIDATE_RELAY,
    CANDIDATE_SRFLX,
    PUNCH_DELAY_FLOOR_MS,
    SUBSTRATE_TCP,
    TYPE_CONNECT_REQUEST,
    TYPE_CONNECT_RESPONSE,
    TYPE_PUNCH_SYNC,
    Candidate,
    ConnectRequest,
    ConnectResponse,
    PunchSync,
    UnknownMessage,
    classify_blob,
    find_request,
    find_requests,
    find_response,
    generate_nonce,
    order_for_dialing,
    punch_delay,
    to_blob,
)

HOST = Candidate(CANDIDATE_HOST, SUBSTRATE_TCP, "192.168.1.10:9000", 0)
SRFLX = Candidate(CANDIDATE_SRFLX, SUBSTRATE_TCP, "203.0.113.7:41234", 0)
RELAY = Candidate(CANDIDATE_RELAY, SUBSTRATE_TCP, "relay.example:443", 0)


# ---------------------------------------------------------------------------
# §3.1 blob framing — the type must travel with the blob
# ---------------------------------------------------------------------------


def test_blob_round_trip_preserves_the_message_type():
    """A bucket is a mixed set and the reader has nothing else to dispatch on.

    ``connect-request`` and ``connect-response`` differ by a single field *name*,
    so a reader handed bare ``data`` would be reduced to sniffing map keys.
    """
    nonce = generate_nonce()
    request = ConnectRequest("peer-a", (HOST, SRFLX), nonce)
    decoded = classify_blob(to_blob(request.to_entity()))
    assert isinstance(decoded, ConnectRequest)
    assert decoded == request

    response = ConnectResponse("peer-b", (HOST,), nonce)
    decoded = classify_blob(to_blob(response.to_entity()))
    assert isinstance(decoded, ConnectResponse)
    assert decoded == response


def test_the_blob_is_the_canonical_type_data_content_hash_encoding():
    """§3.1's pinned framing, asserted at the wire level."""
    entity = ConnectRequest("peer-a", (HOST,), generate_nonce()).to_entity()
    wire = ecf_decode(to_blob(entity))
    assert set(wire) == {"type", "data", "content_hash"}
    assert wire["type"] == TYPE_CONNECT_REQUEST
    assert isinstance(wire["content_hash"], bytes)


def test_request_and_response_are_distinguished_by_type_not_by_field_sniffing():
    """The two shapes are near-identical; only the type separates them."""
    nonce = generate_nonce()
    req = ecf_decode(to_blob(ConnectRequest("p", (HOST,), nonce).to_entity()))
    res = ecf_decode(to_blob(ConnectResponse("p", (HOST,), nonce).to_entity()))
    assert req["type"] == TYPE_CONNECT_REQUEST
    assert res["type"] == TYPE_CONNECT_RESPONSE
    # Same arity, differing by one field *name*.
    assert set(req["data"]) == {"candidates", "initiator", "nonce"}
    assert set(res["data"]) == {"candidates", "nonce", "responder"}


# ---------------------------------------------------------------------------
# §4.1 fire_at — asserted on the bytes
# ---------------------------------------------------------------------------


def test_fire_at_encodes_as_a_cbor_uint():
    """**Assert on the encoded bytes, not through our own decoder.**

    Rust shipped this wrong (a signed ``i64`` holding ms since epoch, test vector
    ``1_700_000_000_500``) and it round-tripped green: a wall-clock encoding is
    invisible to any same-host test because both peers read the same clock. CBOR
    major type 0 is unsigned; major type 1 is negative. Only major 0 is legal
    here.
    """
    entity = PunchSync(nonce=generate_nonce(), fire_at=250).to_entity()
    data_bytes = ecf_encode(entity.data)

    # Locate the encoded `fire_at` key and read the major type of the value byte
    # that immediately follows it — an assertion on the wire, not through our own
    # decoder, which would agree with a wrong encoder.
    key_enc = ecf_encode("fire_at")
    value_at = data_bytes.index(key_enc) + len(key_enc)
    assert data_bytes[value_at] >> 5 == 0, (
        "fire_at MUST encode as CBOR major type 0 (unsigned); major type 1 "
        "would be a negative, i.e. a wall-clock reading of a delay field"
    )
    assert cbor2.loads(data_bytes)["fire_at"] == 250

    # Zero is a legal delay — the domain is "ms from receipt", so guard the
    # domain rather than the magnitude.
    assert PunchSync(nonce=b"n", fire_at=0).fire_at == 0


def test_a_negative_fire_at_is_refused_not_clamped():
    """A negative delay is not a small mistake to tolerate — it is the wall-clock
    reading of a field that has no such domain, and acting on it means firing into
    a window that has already passed."""
    with pytest.raises(ValueError):
        PunchSync(nonce=generate_nonce(), fire_at=-1)


def test_a_negative_fire_at_on_the_wire_classifies_as_unknown():
    """Refused at decode too, rather than widened into something plausible."""
    hostile = Entity(
        type=TYPE_PUNCH_SYNC, data={"fire_at": -250, "nonce": b"0123456789abcdef"}
    )
    assert isinstance(classify_blob(to_blob(hostile)), UnknownMessage)


def test_punch_sync_round_trips():
    sync = PunchSync(nonce=generate_nonce(), fire_at=400)
    decoded = classify_blob(to_blob(sync.to_entity()))
    assert isinstance(decoded, PunchSync)
    assert decoded == sync


def test_punch_delay_never_falls_below_one_way_carrier_latency():
    """§4.1's MUST: ``d`` ≥ the one-way carrier latency (``rtt/2``).

    Below that floor B's fire time has already elapsed when the sync lands and the
    two sides never overlap. ``max(rtt, 250)`` satisfies it with margin, and the
    guarantee holds for any floor because ``d ≥ rtt`` implies ``d ≥ rtt/2``.
    """
    for rtt in (0, 1, 40, 249, 250, 251, 1000, 5000):
        d = punch_delay(rtt)
        assert d >= rtt / 2
        assert d >= PUNCH_DELAY_FLOOR_MS
    assert punch_delay(40) == PUNCH_DELAY_FLOOR_MS
    assert punch_delay(1000) == 1000


# ---------------------------------------------------------------------------
# §4 dial order
# ---------------------------------------------------------------------------


def test_candidates_order_host_then_srflx_then_relay():
    """"First pair that completes a connectivity check wins", so this ordering
    *is* the dial plan — and two peers that order differently waste attempts
    crossing at different candidates."""
    ordered = order_for_dialing([RELAY, SRFLX, HOST])
    assert [c.candidate_type for c in ordered] == [
        CANDIDATE_HOST,
        CANDIDATE_SRFLX,
        CANDIDATE_RELAY,
    ]


def test_unknown_candidate_class_sorts_last_and_survives():
    """MUST-ignore means a peer that learns a new class from a newer impl still
    tries what it *does* understand first — it does not drop the message."""
    future = Candidate("prflx-v2", SUBSTRATE_TCP, "198.51.100.1:1", 0)
    ordered = order_for_dialing([future, RELAY, HOST])
    assert [c.candidate_type for c in ordered] == [
        CANDIDATE_HOST,
        CANDIDATE_RELAY,
        "prflx-v2",
    ]
    assert future in ordered, "an unknown class survives rather than being dropped"


def test_dial_order_is_total_to_the_last_tiebreak():
    """Deterministic on purpose: class, then priority ascending, then address."""
    a = Candidate(CANDIDATE_HOST, SUBSTRATE_TCP, "10.0.0.2:1", 5)
    b = Candidate(CANDIDATE_HOST, SUBSTRATE_TCP, "10.0.0.1:1", 5)
    c = Candidate(CANDIDATE_HOST, SUBSTRATE_TCP, "10.0.0.9:1", 1)
    assert order_for_dialing([a, b, c]) == [c, b, a]
    assert order_for_dialing([b, a, c]) == [c, b, a]


def test_candidates_survive_a_blob_round_trip_in_order():
    candidates = (RELAY, HOST, SRFLX)
    request = ConnectRequest("peer-a", candidates, generate_nonce())
    decoded = classify_blob(to_blob(request.to_entity()))
    assert isinstance(decoded, ConnectRequest)
    assert decoded.candidates == candidates


# ---------------------------------------------------------------------------
# §3.2 bucket-reading rules — all MUST
# ---------------------------------------------------------------------------


def test_unrecognized_blobs_classify_as_unknown_not_an_error():
    """Anyone may write to a shared bucket, and a newer impl's message type is
    MUST-ignore. Classify it as unknown and keep it **countable** rather than
    dropping it silently."""
    # Not CBOR at all.
    assert isinstance(classify_blob(b"\xff\xff not cbor"), UnknownMessage)
    # Valid CBOR, but not an entity.
    assert isinstance(classify_blob(ecf_encode([1, 2, 3])), UnknownMessage)
    # A well-formed entity of a type from some future impl.
    future = Entity(type="system/signaling/teleport-v9", data={"whatever": 1})
    assert isinstance(classify_blob(to_blob(future)), UnknownMessage)
    # A known type with a malformed body.
    broken = Entity(type=TYPE_CONNECT_REQUEST, data={"initiator": 42})
    assert isinstance(classify_blob(to_blob(broken)), UnknownMessage)


def test_unknown_messages_keep_their_bytes_so_a_caller_can_count():
    blob = b"\xff\xff not cbor"
    unknown = classify_blob(blob)
    assert isinstance(unknown, UnknownMessage)
    assert unknown.blob == blob


def test_find_response_ignores_own_offers_and_strangers():
    """A peer that answered its own request would "succeed" at meeting itself —
    miserable to diagnose, because every step reports success."""
    my_nonce = generate_nonce()
    bucket = [
        # My own request, re-read because collect is non-destructive.
        ConnectRequest("me", (HOST,), my_nonce),
        # A response I wrote myself.
        ConnectResponse("me", (HOST,), my_nonce),
        # Someone else's exchange entirely, sharing the lobby bucket.
        ConnectResponse("stranger", (HOST,), generate_nonce()),
        UnknownMessage(b"junk"),
        # The real answer.
        ConnectResponse("peer-b", (SRFLX,), my_nonce),
    ]
    found = find_response(bucket, my_nonce, "me")
    assert found is not None and found.responder == "peer-b"


def test_find_response_requires_the_nonce_echo():
    """In ``lobby``/``tag`` the bucket is shared, so someone else's response is not
    mine — and a fresh answer is not one I processed two polls ago. The nonce is a
    **correlator, not a secret**."""
    my_nonce = generate_nonce()
    stale = [ConnectResponse("peer-b", (HOST,), generate_nonce())]
    assert find_response(stale, my_nonce, "me") is None

    echoed = [ConnectResponse("peer-b", (HOST,), my_nonce)]
    assert find_response(echoed, my_nonce, "me") is not None


def test_find_request_skips_my_own():
    my_own = ConnectRequest("me", (HOST,), generate_nonce())
    theirs = ConnectRequest("peer-b", (HOST,), generate_nonce())
    assert find_request([my_own], "me") is None
    found = find_request([my_own, theirs], "me")
    assert found is not None and found.initiator == "peer-b"


def test_find_requests_returns_every_answerable_one_in_bucket_order():
    """The plural, and why a responder should prefer it.

    ``pair`` and ``lobby`` keys are stable by construction, so inside the 60 s
    TTL a bucket holds earlier exchanges — including a previous run's. A
    responder that answers only ``find_request``'s first hit answers a stale
    stranger and leaves the peer waiting *now* unanswered, while every step
    reports success. Answering all of them is the rerun-safe policy go's
    validator adopted; the initiator discards anything whose nonce is not its
    own.
    """
    stale = ConnectRequest("peer-gone", (HOST,), generate_nonce())
    mine = ConnectRequest("me", (HOST,), generate_nonce())
    live = ConnectRequest("peer-here-now", (HOST,), generate_nonce())

    answerable = find_requests([stale, mine, live], "me")
    assert [r.initiator for r in answerable] == ["peer-gone", "peer-here-now"]
    # And the singular is the head of the plural — same filter, less of it.
    assert find_request([stale, mine, live], "me") == answerable[0]


def test_find_requests_is_empty_rather_than_none_when_only_mine_are_there():
    """An empty bucket-of-mine is the normal early state of every rendezvous, so
    it must be nothing to handle rather than a special case."""
    assert find_requests([ConnectRequest("me", (HOST,), generate_nonce())], "me") == []
    assert find_requests([], "me") == []


def test_bucket_order_is_deposit_order_oldest_first():
    """Two impls scanning in different orders answer *different peers* out of one
    shared ``lobby`` bucket, so the first match in bucket order is the answer."""
    first = ConnectRequest("peer-early", (HOST,), generate_nonce())
    second = ConnectRequest("peer-late", (HOST,), generate_nonce())
    found = find_request([first, second], "me")
    assert found is not None and found.initiator == "peer-early"


def test_a_response_echoing_my_nonce_from_myself_is_still_skipped():
    """Both filters are needed, not either one: the nonce matches here."""
    my_nonce = generate_nonce()
    mine_only = [ConnectResponse("me", (HOST,), my_nonce)]
    assert find_response(mine_only, my_nonce, "me") is None
