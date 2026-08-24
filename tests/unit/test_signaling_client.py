"""The wrapped surface (§5.1) and the client's handling of it (§5.2, §5.3).

``PROPOSAL-CONNECTION-NODE`` §1, §2. Params/result shapes and status handling are
asserted against a stub dispatcher — the live equivalents run against a real Rust
node in ``tests/interop/test_signaling_rust_node.py``.

The stub matters for one thing a live node cannot easily be made to do on demand:
produce each refusal status. §5.3's table has **both capacity refusals at 429**,
and a client that treats ``bucket_full`` as a hard error rather than a back-off
stops retrying a rendezvous that would have succeeded.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from entity_core.handlers.context import ExecuteResult
from entity_core.sdk.dispatcher import ExecuteRequest
from entity_handlers.signaling import (
    LOBBY_DEFAULT,
    OP_ADVERTISE,
    OP_COLLECT,
    OP_OFFER,
    PATTERN,
    TYPE_ADVERTISEMENT,
    TYPE_COLLECT_REQUEST,
    TYPE_OFFER_REQUEST,
    Backoff,
    Candidate,
    ConnectRequest,
    DispatchFailed,
    Refused,
    SignalingClient,
    SignalingDecodeError,
    Unsupported,
    classify_blob,
    find_response,
    tag_key,
)
from entity_handlers.signaling.data import (
    TYPE_COLLECT_RESULT,
    TYPE_OFFER_RESULT,
    advertisement_from_result,
    collect_messages_from_result,
)

KEY = tag_key("chess")
NODE = "12D3KooWnode"

HOST = Candidate("host", "tcp", "192.168.1.10:9000", 0)


@dataclass
class StubDispatcher:
    """Records requests and replays canned results."""

    results: list[ExecuteResult]
    seen: list[ExecuteRequest] = None  # type: ignore[assignment]
    raises: Exception | None = None

    def __post_init__(self) -> None:
        if self.seen is None:
            self.seen = []

    async def execute(self, request: ExecuteRequest) -> ExecuteResult:
        self.seen.append(request)
        if self.raises is not None:
            raise self.raises
        return self.results.pop(0) if self.results else _ok(_offer_result())


def _ok(result: Any) -> ExecuteResult:
    return ExecuteResult(status=200, result=result)


def _offer_result() -> dict[str, Any]:
    return {"type": TYPE_OFFER_RESULT, "data": {"ok": True}}


def _collect_result(blobs: list[bytes]) -> dict[str, Any]:
    return {"type": TYPE_COLLECT_RESULT, "data": {"messages": blobs}}


def _advertisement(lobby: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "endpoint": "node-a:4050",
        "limits": {
            "bucket_ttl_ms": 60_000,
            "max_keys": 4096,
            "max_message_bytes": 8192,
            "max_messages_per_key": 32,
        },
    }
    if lobby is not None:
        data["lobby"] = lobby
    return {"type": TYPE_ADVERTISEMENT, "data": data}


# ---------------------------------------------------------------------------
# §5.1 — the three operations, addressed and shaped
# ---------------------------------------------------------------------------


async def test_the_node_is_addressed_at_the_signaling_pattern():
    stub = StubDispatcher([_ok(_offer_result())])
    client = SignalingClient(stub, NODE)
    assert client.node_uri == f"entity://{NODE}/{PATTERN}"
    await client.offer(KEY, b"blob")
    assert stub.seen[0].uri == f"entity://{NODE}/system/signaling"
    assert stub.seen[0].operation == OP_OFFER


async def test_offer_params_carry_a_33_byte_bstr_key_and_the_blob():
    """``rendezvous_key`` is a **plain CBOR bstr**, not a ``system/hash`` field —
    to the node it is opaque bytes with no format byte to interpret."""
    stub = StubDispatcher([_ok(_offer_result())])
    await SignalingClient(stub, NODE).offer(KEY, b"opaque-blob")
    params = stub.seen[0].params
    assert params["type"] == TYPE_OFFER_REQUEST
    assert params["data"]["rendezvous_key"] == KEY
    assert isinstance(params["data"]["rendezvous_key"], bytes)
    assert len(params["data"]["rendezvous_key"]) == 33
    assert params["data"]["message"] == b"opaque-blob"


async def test_collect_params_carry_only_the_key():
    stub = StubDispatcher([_ok(_collect_result([]))])
    await SignalingClient(stub, NODE).collect(KEY)
    params = stub.seen[0].params
    assert params["type"] == TYPE_COLLECT_REQUEST
    assert params["data"] == {"rendezvous_key": KEY}
    assert stub.seen[0].operation == OP_COLLECT


async def test_advertise_sends_an_empty_map_not_empty_data():
    """``advertise`` takes no arguments, but an EXECUTE still carries a params
    entity and a node rejects empty ``data`` — so we send an empty CBOR map, the
    encoding of "no fields"."""
    stub = StubDispatcher([_ok(_advertisement())])
    await SignalingClient(stub, NODE).advertise()
    params = stub.seen[0].params
    assert params["data"] == {}
    assert stub.seen[0].operation == OP_ADVERTISE


async def test_no_resource_target_rides_along_on_any_of_the_three_verbs():
    """**The resource-target trap** (brief §5.1, added 2026-07-30).

    A signaling EXECUTE must carry no resource target. V7 dispatch authorization
    checks ``grant.resources`` before the handler runs, and the node's seeded
    grant has an **empty** resource scope — deliberately, since signaling
    addresses no tree resource: the rendezvous key travels in ``params`` and the
    handler reads and writes nothing. So a target that looks harmless is refused
    with a 403 **indistinguishable from "not granted"**, which is what cost the
    Go client time before Rust pinned it in
    ``cmd/entity-signaling-node/tests/admission.rs``.

    This client has always left ``resource_targets`` unset; asserted here so a
    later "let's be explicit about what we're addressing" edit fails loudly
    rather than in a live rendezvous. The live half is
    ``test_a_resource_target_is_refused_even_though_the_verb_is_granted``.
    """
    stub = StubDispatcher(
        [_ok(_offer_result()), _ok(_collect_result([])), _ok(_advertisement())]
    )
    client = SignalingClient(stub, NODE)
    await client.offer(KEY, b"blob")
    await client.collect(KEY)
    await client.advertise()

    assert [r.operation for r in stub.seen] == [OP_OFFER, OP_COLLECT, OP_ADVERTISE]
    for request in stub.seen:
        assert request.resource_targets is None, (
            f"{request.operation} must dispatch with no resource target"
        )


async def test_a_wrong_width_key_is_refused_before_it_reaches_the_node():
    """Fails loudly on our side rather than as a remote ``invalid_params`` we then
    have to attribute."""
    stub = StubDispatcher([])
    with pytest.raises(SignalingDecodeError):
        await SignalingClient(stub, NODE).offer(b"\x00" * 49, b"blob")
    assert stub.seen == [], "nothing should have been dispatched"


# ---------------------------------------------------------------------------
# §5.1 — results
# ---------------------------------------------------------------------------


async def test_collect_returns_the_blobs_themselves_not_hashes():
    """Arch ruling 1. An earlier §1 draft said hashes; it was residue from a
    content-addressed sketch and is unimplementable — a hash reply needs a fetch
    surface the node structurally does not have."""
    blobs = [b"blob-one", b"blob-two"]
    stub = StubDispatcher([_ok(_collect_result(blobs))])
    assert await SignalingClient(stub, NODE).collect(KEY) == blobs


async def test_an_unknown_key_is_an_empty_list_and_a_200_never_a_404():
    """A peer polling ahead of its counterpart is the normal case in a
    rendezvous, so "nothing there yet" is not an error and not a reason to give
    up."""
    stub = StubDispatcher([_ok(_collect_result([]))])
    assert await SignalingClient(stub, NODE).collect(KEY) == []


async def test_the_advertisement_decodes_endpoint_limits_and_lobby():
    stub = StubDispatcher([_ok(_advertisement())])
    ad = await SignalingClient(stub, NODE).advertise()
    assert ad.endpoint == "node-a:4050"
    assert ad.limits.bucket_ttl_ms == 60_000
    assert ad.limits.max_message_bytes == 8192
    assert ad.limits.max_messages_per_key == 32
    assert ad.limits.max_keys == 4096
    # Absent → no override, and the client derives from the default constant.
    assert ad.lobby is None
    assert ad.lobby_constant == LOBBY_DEFAULT


async def test_a_lobby_override_is_carried_and_a_default_normalizes_away():
    """**Absent, never null.** A ``lobby`` present but equal to the default
    normalizes back to ``None``, so a decoded advertisement compares equal to one
    from a node that never set it."""
    stub = StubDispatcher([_ok(_advertisement(lobby="lobby:chess-night"))])
    ad = await SignalingClient(stub, NODE).advertise()
    assert ad.lobby == "lobby:chess-night"
    assert ad.lobby_constant == "lobby:chess-night"

    stub = StubDispatcher([_ok(_advertisement(lobby=LOBBY_DEFAULT))])
    ad = await SignalingClient(stub, NODE).advertise()
    assert ad.lobby is None


def test_limits_is_a_bare_map_not_an_entity_wrapper():
    """It is a field typed as a specific struct, not as ``core/entity``."""
    ad = advertisement_from_result(_advertisement())
    assert ad.limits.max_keys == 4096

    wrapped = _advertisement()
    wrapped["data"]["limits"] = {
        "type": "system/signaling/limits",
        "data": wrapped["data"]["limits"],
    }
    with pytest.raises(SignalingDecodeError):
        advertisement_from_result(wrapped)


def test_a_messages_field_of_hashes_is_refused():
    """Guards the ruling-1 shape from quietly regressing into the hash sketch."""
    with pytest.raises(SignalingDecodeError):
        collect_messages_from_result(
            {"type": TYPE_COLLECT_RESULT, "data": {"messages": ["not-a-bstr"]}}
        )


# ---------------------------------------------------------------------------
# §5.3 — errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", ["bucket_full", "capacity_exhausted"])
async def test_both_capacity_refusals_are_429_and_mean_back_off(code: str):
    """A full bucket says the same thing to a peer as a throttle — back off and
    retry. Every refusal happens **before any state change**, so every one is
    retry-safe."""
    stub = StubDispatcher(
        [ExecuteResult(status=429, result=None, error=code)]
    )
    with pytest.raises(Backoff):
        await SignalingClient(stub, NODE).offer(KEY, b"blob")


@pytest.mark.parametrize("status", [400, 403, 404, 500])
async def test_other_refusals_surface_their_status(status: int):
    stub = StubDispatcher([ExecuteResult(status=status, result=None, error="no")])
    with pytest.raises(Refused) as exc:
        await SignalingClient(stub, NODE).collect(KEY)
    assert exc.value.status == status


async def test_a_501_is_unsupported_and_is_not_what_reflect_gets():
    """``reflect`` is not a core operation at all (§1.4), so a wrapped node never
    answers **501** for it — that would say "not implemented *here*", implying
    this is a surface where it could be.

    Which refusal it does get depends on the caller's grant, and the brief's §7.2
    corrected our expectation on 2026-07-30: against a real node it is **403**
    (the enumerated grant names three operations and the capability check runs
    before dispatch), and 400 ``unknown_operation`` only for a wildcard-granted
    caller that reaches the handler. Both live statuses are asserted in
    ``tests/interop``; what this pins is the client side of it — 501 means
    Unsupported, and there is deliberately no ``reflect`` method at all, because
    it belongs to the unwrapped listener whose protocol is §5.1 and unwritten.
    """
    stub = StubDispatcher([ExecuteResult(status=501, result=None, error="nope")])
    with pytest.raises(Unsupported):
        await SignalingClient(stub, NODE).advertise()

    assert not hasattr(SignalingClient, "reflect")


async def test_a_transport_failure_is_distinguished_from_a_node_refusal():
    stub = StubDispatcher([], raises=ConnectionResetError("peer went away"))
    with pytest.raises(DispatchFailed):
        await SignalingClient(stub, NODE).collect(KEY)


# ---------------------------------------------------------------------------
# §4 step 2 — the candidate exchange over the carrier
# ---------------------------------------------------------------------------


async def test_initiate_offers_a_connect_request_and_returns_its_nonce():
    stub = StubDispatcher([_ok(_offer_result())])
    client = SignalingClient(stub, NODE)
    nonce = await client.initiate(KEY, "peer-a", [HOST])

    assert len(nonce) == 16
    blob = stub.seen[0].params["data"]["message"]
    decoded = classify_blob(blob)
    assert isinstance(decoded, ConnectRequest)
    assert decoded.initiator == "peer-a"
    assert decoded.nonce == nonce
    assert decoded.candidates == (HOST,)


async def test_respond_echoes_the_requests_nonce():
    request = ConnectRequest("peer-a", (HOST,), b"0123456789abcdef")
    stub = StubDispatcher([_ok(_offer_result())])
    await SignalingClient(stub, NODE).respond(KEY, "peer-b", request, [HOST])

    decoded = classify_blob(stub.seen[0].params["data"]["message"])
    assert decoded.responder == "peer-b"
    assert decoded.nonce == request.nonce


async def test_collect_messages_classifies_and_keeps_unknowns_countable():
    """A shared bucket may hold other pairs' traffic and message types this build
    has never seen; a caller that wants to know how much it skipped should be able
    to count."""
    from entity_handlers.signaling import (
        ConnectResponse,
        UnknownMessage,
        to_blob,
    )

    nonce = b"0123456789abcdef"
    blobs = [
        to_blob(ConnectRequest("peer-a", (HOST,), nonce).to_entity()),
        b"\xff\xff not cbor",
        to_blob(ConnectResponse("peer-b", (HOST,), nonce).to_entity()),
    ]
    stub = StubDispatcher([_ok(_collect_result(blobs))])
    messages = await SignalingClient(stub, NODE).collect_messages(KEY)

    assert len(messages) == 3
    assert sum(isinstance(m, UnknownMessage) for m in messages) == 1
    # And the §3.2 filters compose on top of the classified bucket.
    found = find_response(messages, nonce, "peer-a")
    assert found is not None and found.responder == "peer-b"
