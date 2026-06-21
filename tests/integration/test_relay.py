"""EXTENSION-RELAY v1.0 — Mode F + Mode S behaviour pins (own-peer).

Python-side behaviour pins for the relay handler: Mode S put/poll roundtrip
with relay-owned cursor, empty-namespace-returns-empty (§4.2), put_by
verification (§3.2), the §4.3 error taxonomy, and Mode F ttl/no_route/terminal-
hop-fallback control flow (§3.1 / §6.2.1).

The three-way cross-impl gate (terminal-hop byte-identical unwrap + put/poll/
cursor convergence) lives in the cohort validate-peer run; the remote live
terminal-hop byte shape is gated on the wire lock (F-PY-RELAY-3).
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer.builder import PeerBuilder
from entity_core.protocol.auth import (
    create_identity_entity,
    create_signature_entity,
)
from entity_core.protocol.entity import Entity

from entity_core.storage.emit import EmitContext

from entity_handlers.relay import (
    FORWARD_REQUEST_TYPE,
    STORE_ENTRY_TYPE,
    make_forward_request,
    make_inbox_relay,
    make_store_entry,
    inbox_relay_storage_path,
)

_BLANKET = {
    "grants": [
        {
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }
    ]
}


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


def _ctx(peer, *, caller=None, included=None, relay_send=None) -> HandlerContext:
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=caller or peer.keypair.peer_id,
        handler_grant=_BLANKET,
        caller_capability=_BLANKET,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
        handler_pattern="system/relay",
        included=included or {},
        relay_send=relay_send,
    )


async def _call(peer, op, data, *, caller=None, included=None, relay_send=None):
    h = peer.handlers.find_handler("system/relay")
    ctx = _ctx(peer, caller=caller, included=included, relay_send=relay_send)
    return await h("system/relay", op, {"data": data}, ctx)


def _inner_entity():
    """A dummy 'inner envelope' opaque entity + (hash, included-map).

    Per §2.3 (R6/R7 fold): the carried inner entity is a full
    ``system/envelope``-typed entity whose data is the {root, included} of the
    destination-bound dispatch (only this shape delivers an independently-
    verifiable message at the terminal hop). Held opaque by the relay (§9).
    """
    ent = Entity(type="system/envelope", data={"root": {"x": 1}, "included": {}})
    h = ent.compute_hash()
    return ent, h, {h: ent.to_dict()}


def _seed_inbox_relay(peer, declaring_keypair, relays, *, expires_at=None, sign=True):
    """Author a destination's *signed* inbox-relay declaration into this relay's
    tree (the relay-as-always-on-holder, §3.5/§3.1).

    The declaration is signed by ``declaring_keypair`` at the V7 §5.2 invariant
    pointer ``system/signature/{hex(decl_hash)}`` — the forged-redirection
    defense (SIG-1) requires it. Pass ``sign=False`` to seed an unsigned decl
    (which the resolver must now reject). Returns the declaring peer_id.
    """
    declaring_peer = declaring_keypair.peer_id
    decl = make_inbox_relay(relays=relays, expires_at=expires_at)
    peer.emit_pathway.emit(
        inbox_relay_storage_path(declaring_peer), decl, EmitContext.bootstrap()
    )
    if sign:
        decl_hash = decl.compute_hash()
        signer_hash = create_identity_entity(declaring_keypair).compute_hash()
        sig = create_signature_entity(
            declaring_keypair,
            target_hash=decl_hash,
            signer_identity_hash=signer_hash,
        )
        peer.emit_pathway.emit(
            f"system/signature/{decl_hash.hex()}", sig, EmitContext.bootstrap()
        )
    return declaring_peer


def _seed_relay_config(peer, *, disable_default_fallback):
    cfg = Entity(
        type="system/relay/config",
        data={"disable_default_fallback": disable_default_fallback},
    )
    peer.emit_pathway.emit("system/relay/config", cfg, EmitContext.bootstrap())


# --- Mode S ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_put_then_poll_roundtrip(peer):
    caller = peer.keypair.peer_id
    inner, inner_hash, included = _inner_entity()

    put = await _call(
        peer,
        "put",
        {"namespace": "alice", "put_by": caller, "envelope_inner": inner_hash},
        caller=caller,
        included=included,
    )
    assert put["status"] == 200
    assert put["result"]["data"]["status"] == "stored"
    entry_hash = put["result"]["data"]["entry_hash"]

    poll = await _call(peer, "poll", {"namespace": "alice"}, caller=caller)
    assert poll["status"] == 200
    entries = poll["result"]["data"]["entries"]
    assert entry_hash in entries
    assert poll["result"]["data"]["has_more"] is False

    # Two-hop pointer discipline (§4.2): fetch the store-entry by hash, read its
    # envelope_inner, then fetch the inner envelope — both content-addressed.
    store_entry = peer.content_store.get(entry_hash)
    assert store_entry.type == STORE_ENTRY_TYPE
    assert peer.content_store.get(store_entry.data["envelope_inner"]) is not None


@pytest.mark.asyncio
async def test_inner_tree_bound_and_fetchable_without_system_content(peer):
    """Per the relay receive-side fetch-surface ruling (§3.2/§4.2): the inner
    envelope is tree-bound at ``system/relay/store/{ns}/inner/{inner_hash_hex}``
    and the receiver fetches it via ``tree:get`` — ``system/content`` is NOT a
    receive-side dependency. Mirrors Go validator od3/od4/od5.
    """
    caller = peer.keypair.peer_id
    inner, inner_hash, included = _inner_entity()

    put = await _call(
        peer,
        "put",
        {"namespace": "alice", "put_by": caller, "envelope_inner": inner_hash},
        caller=caller,
        included=included,
    )
    assert put["status"] == 200

    # The inner is tree-bound under the namespace subtree (path → hash).
    inner_path = f"system/relay/store/alice/inner/{inner_hash.hex()}"
    full = peer.emit_pathway.entity_tree.normalize_uri(inner_path)
    assert peer.emit_pathway.entity_tree.get(full) == inner_hash

    # poll returns ONLY the store-entry hash, never the inner (type filter).
    poll = await _call(peer, "poll", {"namespace": "alice"}, caller=caller)
    assert inner_hash not in poll["result"]["data"]["entries"]
    assert len(poll["result"]["data"]["entries"]) == 1

    # Receive-side fetch is tree:get on the inner path — no system/content.
    tree = peer.handlers.find_handler("system/tree")
    got = await tree(
        "system/tree", "get", {"path": inner_path}, _ctx(peer, caller=caller)
    )
    assert got["status"] == 200
    assert got["result"]["type"] == "system/envelope"


@pytest.mark.asyncio
async def test_empty_namespace_returns_empty_not_404(peer):
    poll = await _call(peer, "poll", {"namespace": "never-written"})
    assert poll["status"] == 200
    assert poll["result"]["data"] == {
        "entries": [],
        "cursor": "",
        "has_more": False,
    }


@pytest.mark.asyncio
async def test_poll_cursor_pagination(peer):
    caller = peer.keypair.peer_id
    for i in range(3):
        inner = Entity(type="system/protocol/execute", data={"i": i})
        h = inner.compute_hash()
        await _call(
            peer,
            "put",
            {"namespace": "n", "put_by": caller, "envelope_inner": h},
            caller=caller,
            included={h: inner.to_dict()},
        )
    first = await _call(peer, "poll", {"namespace": "n", "limit": 2}, caller=caller)
    assert len(first["result"]["data"]["entries"]) == 2
    assert first["result"]["data"]["has_more"] is True
    cursor = first["result"]["data"]["cursor"]
    rest = await _call(
        peer, "poll", {"namespace": "n", "since": cursor}, caller=caller
    )
    assert len(rest["result"]["data"]["entries"]) == 1
    assert rest["result"]["data"]["has_more"] is False


@pytest.mark.asyncio
async def test_put_by_mismatch_rejected(peer):
    _, inner_hash, included = _inner_entity()
    res = await _call(
        peer,
        "put",
        {"namespace": "a", "put_by": "SomeoneElse", "envelope_inner": inner_hash},
        caller=peer.keypair.peer_id,
        included=included,
    )
    assert res["status"] == 400
    assert res["result"]["data"]["code"] == "put_by_mismatch"


@pytest.mark.asyncio
async def test_namespace_invalid_nul(peer):
    _, inner_hash, included = _inner_entity()
    res = await _call(
        peer,
        "put",
        {"namespace": "a\x00b", "put_by": peer.keypair.peer_id, "envelope_inner": inner_hash},
        included=included,
    )
    assert res["status"] == 400
    assert res["result"]["data"]["code"] == "namespace_invalid"


@pytest.mark.asyncio
async def test_expired_on_arrival(peer):
    caller = peer.keypair.peer_id
    _, inner_hash, included = _inner_entity()
    res = await _call(
        peer,
        "put",
        {
            "namespace": "a",
            "put_by": caller,
            "envelope_inner": inner_hash,
            "expires_at": 1,  # epoch ms in the past
        },
        caller=caller,
        included=included,
    )
    assert res["status"] == 400
    assert res["result"]["data"]["code"] == "expired_on_arrival"


@pytest.mark.asyncio
async def test_advertise_publishes_signed_entity(peer):
    res = await _call(
        peer,
        "advertise",
        {"modes": ["S"], "endpoints": [], "caps_required": []},
    )
    assert res["status"] == 200
    path = f"system/relay/advertise/{peer.keypair.peer_id}"
    assert peer.entity_tree.get(path) is not None


# --- Mode F ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_forward_ttl_exhausted(peer):
    fr = make_forward_request(destination="D", envelope_inner=b"\x00" * 33, ttl_hops=0, next_hop="D")
    res = await _call(peer, "forward", fr.data)
    assert res["status"] == 400
    assert res["result"]["data"]["code"] == "ttl_exhausted"


@pytest.mark.asyncio
async def test_forward_no_route_without_next_hop(peer):
    fr = make_forward_request(destination="D", envelope_inner=b"\x00" * 33, ttl_hops=4)
    res = await _call(peer, "forward", fr.data)
    assert res["status"] == 502
    assert res["result"]["data"]["code"] == "no_route"


@pytest.mark.asyncio
async def test_terminal_hop_falls_back_to_mode_s_when_offline(peer):
    # next_hop == destination (terminal) and no relay_send hook / no live
    # session → Mode-S fallback (§6.2.1): queued-fallback + stored at namespace
    # = destination peer_id.
    dest = "DestPeer123"
    inner, inner_hash, included = _inner_entity()
    fr = make_forward_request(
        destination=dest, envelope_inner=inner_hash, ttl_hops=4, next_hop=dest
    )
    res = await _call(peer, "forward", fr.data, included=included)
    assert res["status"] == 200
    assert res["result"]["data"]["status"] == "queued-fallback"
    # §4.2 (Rust R6 catch): forward-result.stored_at = the NAMESPACE (= dest by
    # default convention), not the full path+hash.
    assert res["result"]["data"]["stored_at"] == dest
    # The destination can later poll its own namespace and find the entry.
    poll = await _call(peer, "poll", {"namespace": dest})
    assert len(poll["result"]["data"]["entries"]) == 1


# --- §3.5 inbox-relay (MX-equivalent) fallback resolution ------------------


@pytest.mark.asyncio
async def test_fallback_honors_inbox_relay_declaration_targeting_us(peer):
    # The destination declares THIS relay as its inbox-relay with a custom
    # namespace → fallback stores there (not the default dest convention).
    dest_kp = Keypair.generate()
    me = peer.keypair.peer_id
    dest = _seed_inbox_relay(
        peer, dest_kp, [{"relay": me, "namespace": "bob-mail", "priority": 10}]
    )
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4, next_hop=dest)
    res = await _call(peer, "forward", fr.data, included=included)
    assert res["result"]["data"]["status"] == "queued-fallback"
    assert res["result"]["data"]["stored_at"] == "bob-mail"
    assert len(( await _call(peer, "poll", {"namespace": "bob-mail"}))["result"]["data"]["entries"]) == 1


@pytest.mark.asyncio
async def test_fallback_priority_sort_picks_lowest(peer):
    # Two entries; the lower-priority one targets us → its namespace wins.
    dest_kp = Keypair.generate()
    me = peer.keypair.peer_id
    dest = _seed_inbox_relay(
        peer,
        dest_kp,
        [
            {"relay": "OtherRelay", "namespace": "x", "priority": 50},
            {"relay": me, "namespace": "primary-mail", "priority": 10},
        ],
    )
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4, next_hop=dest)
    res = await _call(peer, "forward", fr.data, included=included)
    assert res["result"]["data"]["stored_at"] == "primary-mail"


@pytest.mark.asyncio
async def test_forged_inbox_relay_decl_rejected_falls_back_to_default(peer):
    # INBOX-RELAY-SIG-1 (mp4): a decl claiming "dest's mail lives at FORGED-NS
    # on this relay" but signed by the WRONG key MUST be rejected by the
    # sig-verify path → fallback uses the §6.2.1 default convention (namespace
    # = destination peer_id), NOT the forged namespace.
    dest_kp = Keypair.generate()
    dest = dest_kp.peer_id
    forged_ns = "FORGED-NAMESPACE-XYZ"
    me = peer.keypair.peer_id

    # Author the decl + a signature by the WRONG keypair (an attacker's), at
    # the destination's invariant pointer in this relay's tree.
    wrong_kp = Keypair.generate()
    decl = make_inbox_relay(relays=[{"relay": me, "namespace": forged_ns, "priority": 10}])
    peer.emit_pathway.emit(
        inbox_relay_storage_path(dest), decl, EmitContext.bootstrap()
    )
    decl_hash = decl.compute_hash()
    forged_sig = create_signature_entity(
        wrong_kp,
        target_hash=decl_hash,
        signer_identity_hash=create_identity_entity(wrong_kp).compute_hash(),
    )
    peer.emit_pathway.emit(
        f"system/signature/{decl_hash.hex()}", forged_sig, EmitContext.bootstrap()
    )

    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4, next_hop=dest)
    res = await _call(peer, "forward", fr.data, included=included)
    assert res["result"]["data"]["status"] == "queued-fallback"
    # THE gate: forged namespace was rejected → default convention used.
    assert res["result"]["data"]["stored_at"] == dest
    assert res["result"]["data"]["stored_at"] != forged_ns
    # Nothing landed at the forged namespace.
    assert (await _call(peer, "poll", {"namespace": forged_ns}))["result"]["data"]["entries"] == []


@pytest.mark.asyncio
async def test_unsigned_inbox_relay_decl_rejected_falls_back_to_default(peer):
    # A decl with no signature at all is rejected fail-closed → default
    # convention (SIG-1 requires a valid invariant-pointer signature).
    dest_kp = Keypair.generate()
    me = peer.keypair.peer_id
    dest = _seed_inbox_relay(
        peer, dest_kp, [{"relay": me, "namespace": "bob-mail", "priority": 10}], sign=False
    )
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4, next_hop=dest)
    res = await _call(peer, "forward", fr.data, included=included)
    assert res["result"]["data"]["status"] == "queued-fallback"
    assert res["result"]["data"]["stored_at"] == dest  # not "bob-mail"


@pytest.mark.asyncio
async def test_no_inbox_relay_when_mx_required_and_undeclared(peer):
    # MX-required posture (disable_default_fallback) + no declaration →
    # no_inbox_relay/502, fail-closed (§9.5).
    _seed_relay_config(peer, disable_default_fallback=True)
    dest = "DestPeer123"
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4, next_hop=dest)
    res = await _call(peer, "forward", fr.data, included=included)
    assert res["status"] == 502
    assert res["result"]["data"]["code"] == "no_inbox_relay"
    # Nothing queued.
    assert (await _call(peer, "poll", {"namespace": dest}))["result"]["data"]["entries"] == []


@pytest.mark.asyncio
async def test_no_inbox_relay_when_mx_required_and_declares_other_relay(peer):
    # MX-required + declares a relay that ISN'T us (cross-relay store deferred)
    # → no_inbox_relay.
    _seed_relay_config(peer, disable_default_fallback=True)
    dest_kp = Keypair.generate()
    dest = _seed_inbox_relay(
        peer, dest_kp, [{"relay": "SomeOtherRelay", "namespace": "x", "priority": 10}]
    )
    _, inner_hash, included = _inner_entity()
    fr = make_forward_request(destination=dest, envelope_inner=inner_hash, ttl_hops=4, next_hop=dest)
    res = await _call(peer, "forward", fr.data, included=included)
    assert res["status"] == 502
    assert res["result"]["data"]["code"] == "no_inbox_relay"


@pytest.mark.asyncio
async def test_terminal_hop_delivers_when_session_live(peer):
    # A live session is modeled by a relay_send hook returning True → forwarded,
    # no fallback store.
    dest = "DestPeer123"
    inner, inner_hash, included = _inner_entity()

    async def _live_send(destination, inner_entity):
        assert destination == dest
        return True

    fr = make_forward_request(
        destination=dest, envelope_inner=inner_hash, ttl_hops=4, next_hop=dest
    )
    res = await _call(peer, "forward", fr.data, included=included, relay_send=_live_send)
    assert res["status"] == 200
    assert res["result"]["data"]["status"] == "forwarded"
    assert res["result"]["data"]["next_hop"] == dest
    # Nothing queued.
    poll = await _call(peer, "poll", {"namespace": dest})
    assert poll["result"]["data"]["entries"] == []


@pytest.mark.asyncio
async def test_relay_deliver_inner_writes_raw_frame_verbatim(peer):
    # mp2 raw-frame carriage (§3.1.1 / §10.4): the terminal hop must write the
    # inner system/envelope's .data (the ECF {root, included}) VERBATIM — not
    # re-wrap it as a new envelope root (the prior double-wrap bug, which made
    # C drop the frame because root.type was "system/envelope").
    from entity_core.utils.ecf import ecf_decode, ecf_encode

    dest = "DestPeerLive"
    inner_payload = {
        "root": {
            "type": "system/protocol/execute",
            "data": {"uri": "entity://X/system/tree", "operation": "put"},
        },
        "included": {},
    }
    inner = Entity(type="system/envelope", data=inner_payload)

    captured: list[bytes] = []

    class _FakeConn:
        async def send_raw_frame(self, payload: bytes) -> None:
            captured.append(payload)

    # Inject a live connection into the pool so get_connection returns it.
    peer._remote_pool._connections[dest] = _FakeConn()

    delivered = await peer._relay_deliver_inner(dest, inner)
    assert delivered is True
    assert len(captured) == 1
    # Verbatim: the frame is exactly ecf_encode(inner.data), no re-wrap.
    assert captured[0] == ecf_encode(inner_payload)
    # And it decodes to the source's {root, included} — the destination sees a
    # real EXECUTE at the root, NOT a system/envelope wrapper.
    decoded = ecf_decode(captured[0])
    assert decoded["root"]["type"] == "system/protocol/execute"


@pytest.mark.asyncio
async def test_relay_deliver_inner_rejects_non_envelope_inner(peer):
    # §3.1: a non-system/envelope inner is malformed for the raw-frame hop →
    # return False (→ Mode-S fallback), never a silent re-wrap.
    bare = Entity(type="system/protocol/execute", data={"operation": "put"})
    delivered = await peer._relay_deliver_inner("DestX", bare)
    assert delivered is False


@pytest.mark.asyncio
async def test_relay_deliver_inner_unreachable_returns_false(peer):
    # No pooled connection and no transport profile to dial → unreachable →
    # False so the caller performs the §6.2.1 Mode-S fallback.
    inner = Entity(type="system/envelope", data={"root": {"x": 1}, "included": {}})
    delivered = await peer._relay_deliver_inner("NeverHeardOfPeer", inner)
    assert delivered is False


@pytest.mark.asyncio
async def test_send_raw_frame_traverses_real_socket_verbatim():
    # Real-socket proof of the §10.4 raw-frame primitive: pre-encoded ECF bytes
    # written via send_raw_frame arrive byte-identical and decode to the
    # original {root, included} on the receiving end (length-prefix framing
    # intact, no decode/re-encode in between). Exercises the actual framing
    # primitive the terminal hop uses over a TCP StreamWriter.
    from entity_core.protocol.framing import recv_envelope, send_raw_frame
    from entity_core.utils.ecf import ecf_encode

    inner_payload = {
        "root": {
            "type": "system/protocol/execute",
            "data": {"uri": "entity://X/system/tree", "operation": "put"},
        },
        "included": {},
    }
    frame = ecf_encode(inner_payload)

    received: list = []
    ready = asyncio.Event()

    async def _handle(reader, writer):
        env = await recv_envelope(reader, validate_hashes=False)
        received.append(env)
        ready.set()
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await send_raw_frame(writer, frame)
        await asyncio.wait_for(ready.wait(), timeout=2.0)
        writer.close()

    assert len(received) == 1
    # The destination reads a real EXECUTE at the root — not a system/envelope
    # wrapper. This is the byte-for-byte property the terminal hop relies on.
    assert received[0].root["type"] == "system/protocol/execute"


@pytest.mark.asyncio
async def test_unsupported_operation(peer):
    res = await _call(peer, "bogus", {})
    assert res["status"] == 501
