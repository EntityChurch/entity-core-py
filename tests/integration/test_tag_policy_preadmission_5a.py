"""§4.11 row (5a) / ``ENTITY-CBOR-ENCODING`` §5.4 — the tag-policy refusal.

0.8.2.26 ``DR-3`` partitions an input §4.11's framing row used to swallow::

    bytes that do NOT decode at all      -> 400 invalid_request   (framing)
    bytes that DO decode, carrying a
    CBOR major-type-6 item in a
    data-field position                  -> 400 non_canonical_ecf (tag policy)

and states that the second is *"a pre-admission refusal under its own row of
§4.11's table"* — so it carries the frame obligation like every other member:
a coded EXECUTE_RESPONSE on the wire, and a silent drop or a bare close is
non-conformant.

.. rubric:: The measured pre-state, and why no row in this repo could see it

`arch`'s `.26` fold scores `DR-3` *"no — a prohibition was withdrawn"*, and
`entity-core-go` relayed that to this seat as **"nothing in either of your
trees moves for .26."** True of go, whose typed decoder errors on a tag.
Measured here **before any edit**, it is false in the most expensive
direction: ``is_canonical_ecf`` — a complete strict ECF validator carrying an
explicit ``major type 6 forbidden`` arm since the initial release — had
**zero call sites on the protocol boundary**. Its only consumer was
``conformance/emit.py``, scoring ``decode_reject`` *vectors*.

So a tagged frame did not merely get the wrong code. ``cbor2`` **preserves**
tags as ``CBORTag`` instances (``utils/ecf.py``), the envelope decoded, the
root was a map, and the request was **admitted** — a peer go and rust refuse,
served. `non_canonical_ecf` had **zero emission sites** in the tree, on a
surface this peer has shipped a validator for the whole time.

That is the standing *validator-with-no-consumer* law (§2.4 ``exclude``, the
``peers`` dimension, the resolver ceiling) in its widest form yet: the field
had a **validator**, a **test suite**, and a **conformance category**, and no
call site on the path the rule is about.
"""

from __future__ import annotations

import asyncio
import struct

import pytest
from cbor2 import CBORTag

from entity_core.conformance import is_canonical_ecf
from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder
from entity_core.protocol.framing import ecf_decode, ecf_encode
from entity_core.utils.ecf import _CBOR_TAG_TYPES, contains_cbor_tag
from entity_core.protocol.messages import Execute


@pytest.fixture
async def listening_peer():
    peer = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    await peer.start("127.0.0.1", 0)
    port = peer._server.sockets[0].getsockname()[1]
    try:
        yield peer, port
    finally:
        await peer.stop()


def _frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


#: Tag 0 (RFC 8949 standard date/time string) in a data-field position. §5.4
#: forbids major type 6 at ANY depth; the tag NUMBER is irrelevant to the
#: rule, so the most innocuous tag in the spec is the honest probe.
_TAG = CBORTag(0, "2026-09-16T00:00:00Z")


def _execute(peer_id: str, request_id: str, *, tagged: bool) -> bytes:
    """A structurally valid EXECUTE, with or without a tag in ``data``.

    ⚠ **The URI names the LOCAL peer, and the first draft did not.**
    It said ``entity://x/system/tree``, and measured `(400,
    invalid_request)` — which looked like the framing-arm defect this file
    exists to close and was the **§1.4 address gate**: *"EXECUTE targets peer
    x, not this peer …, evaluated before authentication."* A second,
    independent refusal, reached before anything could look at the tag. Both
    arms of the probe answered it, so the file would have been green on a
    peer with no tag check at all.

    That is the standing *your fixture is not the discriminating
    configuration* law, and it is why the tagged and untagged frames below
    are built by ONE function differing in ONE field.

    ⚠ **Built through our own encoder, then asserted against our own strict
    validator.** A conformant serializer usually cannot express the attack;
    here it can — ``ecf_encode`` registers an encoder for ``CBORTag`` — but
    *that it can* is what has to be checked rather than assumed, so
    :class:`TestTheProbeIsTheThingItClaimsToBe` drives the payload at
    ``is_canonical_ecf`` directly.
    """
    data = {
        "request_id": request_id,
        "uri": f"entity://{peer_id}/system/tree",
        "operation": "get",
        "when": _TAG if tagged else "2026-09-16T00:00:00Z",
    }
    return _frame(ecf_encode({
        "root": {"type": Execute.TYPE, "data": data},
        "included": {},
    }))


async def _read_frame(reader: asyncio.StreamReader) -> bytes | None:
    try:
        header = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        return None
    length = struct.unpack(">I", header)[0]
    try:
        return await asyncio.wait_for(reader.readexactly(length), timeout=5.0)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        return None


def _error_of(payload: bytes | None) -> tuple[int | None, str | None]:
    assert payload is not None, (
        "the peer put NOTHING on the wire. §4.11: a silent drop and a bare "
        "close are each non-conformant, separately."
    )
    env = ecf_decode(payload)
    data = env["root"].get("data", {})
    result = data.get("result") or {}
    code = result.get("code") or result.get("data", {}).get("code")
    return data.get("status"), code


class TestTheProbeIsTheThingItClaimsToBe:
    """The input is asserted against the parser that owns the rule.

    0.8.2.25's own finding at this seat was a row named
    ``test_undecodable_cbor_still_gets_a_coded_frame`` whose payload
    **decoded**. The remedy ratified then was: *drive the input at the
    decoder directly in one row, and keep the wire row for the behaviour.*
    """

    def test_the_probe_really_does_carry_a_tag(self):
        payload = _execute("p", "probe", tagged=True)[4:]
        assert not is_canonical_ecf(payload), (
            "the probe payload must be a genuine §5.4 tag-policy violation. "
            "If this passes, the encoder normalized the tag away and every "
            "wire row below is measuring a canonical frame."
        )
        # Major type 6 is 0b110xxxxx. Asserted on the bytes so a future
        # `is_canonical_ecf` regression cannot make this row vacuous.
        assert any(0xC0 <= b <= 0xDB for b in payload), (
            "no major-type-6 initial byte in the payload"
        )

    def test_the_untagged_twin_is_canonical(self):
        """The control: same builder, same fields, no tag — so a refusal
        below is attributable to the tag and to nothing else in the frame."""
        assert is_canonical_ecf(_execute("p", "probe", tagged=False)[4:])


class TestTheTwoDerivationsAgree:
    """One rule, two implementations in one process — pinned against each
    other.

    ``is_canonical_ecf`` walks BYTES (conformance emitter);
    ``contains_cbor_tag`` walks the DECODED object (receive path). The
    standing two-representations law says the second one is written for a
    narrower purpose and drifts, so the agreement is asserted rather than
    assumed.
    """

    def test_the_byte_walker_and_the_object_walker_agree_on_the_tag_arm(self):
        tagged = _execute("p", "x", tagged=True)[4:]
        clean = _execute("p", "x", tagged=False)[4:]

        assert contains_cbor_tag(ecf_decode(tagged)) is True
        assert is_canonical_ecf(tagged) is False

        assert contains_cbor_tag(ecf_decode(clean)) is False
        assert is_canonical_ecf(clean) is True

    def test_a_tagged_MAP_KEY_is_also_a_tag(self):
        """The position a value-only walk misses.

        §5.4 is *any major-type-6 item in a data-field position*, and a map
        key is one. Written because the obvious implementation recurses into
        ``dict.values()``.
        """
        assert contains_cbor_tag({CBORTag(0, "k"): "v"}) is True

    def test_the_detector_names_the_class_OUR_DECODER_MINTS(self):
        """⛔ The row that caught the first draft, and the only one that could.

        ``cbor2.CBORTag`` **is** ``_cbor2.CBORTag`` (the C extension), while
        ``ecf_decode`` goes through the **pure-Python** decoder and mints
        ``cbor2._types.CBORTag`` — a distinct class. The first draft of
        ``_CBOR_TAG_TYPES`` read ``(cbor2.CBORTag, _cext_types.CBORTag)``,
        i.e. **one class named twice**, and was blind on exactly the path it
        guards. Every wire row then failed identically to an unfixed peer,
        which is what sent the diagnosis to the check instead of to the type.

        Asserted **structurally**, against the class the decoder really
        returns, rather than by driving a tag — a behavioural row cannot tell
        *"the detector is blind"* from *"the detector is absent"*.
        """
        minted = type(ecf_decode(ecf_encode({"a": _TAG}))["a"])
        assert minted in _CBOR_TAG_TYPES, (
            f"ecf_decode mints {minted!r}, which the receive-path tag "
            "detector does not name. A tagged frame would be ADMITTED."
        )

    def test_the_walker_reaches_a_tag_nested_under_a_list(self):
        assert contains_cbor_tag({"a": [{"b": [CBORTag(2, b"\x01")]}]}) is True


class TestTheTagPolicyArm:
    """§4.11 row (5a) — the refusal, its code, and its stream disposition."""

    @pytest.mark.asyncio
    async def test_a_tagged_frame_is_refused_400_non_canonical_ecf(
        self, listening_peer
    ):
        """The headline row.

        ⛔ **Measured before the fix: `(401, 'authentication_failed')` — and
        the UNTAGGED twin measured the same pair.** The frame was ADMITTED
        and refused at the request layer by CE-1's pre-establishment gate,
        i.e. nothing on the path ever looked at the tag. The two arms being
        *indistinguishable* is the measurement; a peer that later completes a
        handshake serves the tagged frame.
        """
        peer, port = listening_peer
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_execute(peer.peer_id, "tagged-1", tagged=True))
            await writer.drain()
            status, code = _error_of(await _read_frame(reader))
        finally:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=5.0)

        assert (status, code) == (400, "non_canonical_ecf"), (
            "§4.11 row (5a) / §5.4: bytes that DECODE and carry a "
            "major-type-6 item in a data-field position are the tag-policy "
            "refusal, not the framing one. The code selects the caller's "
            f"remedy — 're-encode without the tag' — and got ({status}, {code})."
        )

    @pytest.mark.asyncio
    async def test_the_stream_stays_synchronized_so_the_connection_survives(
        self, listening_peer
    ):
        """Arm (f) binds this member: the frame was consumed WHOLE.

        0.8.2.26 exempts only ``(a2)`` — the truncated half — because a
        desynchronized stream has no boundary for the response to travel in.
        A tag-policy refusal reads a complete frame, so the next frame's
        boundary is known and the connection MUST survive.
        """
        peer, port = listening_peer
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_execute(peer.peer_id, "tagged-2", tagged=True))
            await writer.drain()
            first = _error_of(await _read_frame(reader))
            assert first == (400, "non_canonical_ecf")

            # A second, canonical frame on the SAME connection must be
            # answered — any coded answer proves the stream resynchronized.
            writer.write(_execute(peer.peer_id, "after-the-tag", tagged=False))
            await writer.drain()
            second_payload = await _read_frame(reader)
        finally:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=5.0)

        assert second_payload is not None, (
            "the connection did not survive a SYNCHRONIZED pre-admission "
            "refusal. §4.11 (0.8.2.26): the close is a CHOICE where the frame "
            "was consumed whole, and §9 arm (f) binds every such member."
        )
        env = ecf_decode(second_payload)
        assert env["root"]["data"].get("request_id") == "after-the-tag"


class TestTheCausesDoNotCollapse:
    """§4.11's teeth, extended by one cause.

    The standing row asserts three causes give three distinct ``(status,
    code)`` pairs. ``DR-3``'s whole content is that a FOURTH cause was being
    answered by the framing row, so the peer that fails this is exactly the
    peer that reads *"non-canonical"* out of the pre-`.26` framing row.
    """

    @pytest.mark.asyncio
    async def test_a_tag_and_a_decode_failure_answer_DIFFERENTLY(
        self, listening_peer
    ):
        peer, port = listening_peer

        async def drive(frame: bytes, *, eof: bool = False):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                writer.write(frame)
                await writer.drain()
                if eof:
                    writer.write_eof()
                    await writer.drain()
                return _error_of(await _read_frame(reader))
            finally:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=5.0)

        tagged = await drive(_execute(peer.peer_id, "t", tagged=True))
        # b"\x61" — major type 3 declaring one byte and carrying none, so the
        # decoder hits EOF INSIDE the item. Genuinely un-parseable.
        unparseable = await drive(_frame(b"\x61"))

        assert tagged == (400, "non_canonical_ecf")
        assert unparseable == (400, "invalid_request")
        assert tagged != unparseable, (
            "0.8.2.26 partitions these two inputs and gives them different "
            "codes BECAUSE the remedies differ: 're-encode without the tag' "
            "is not 'your bytes are truncated'. A peer with one code for the "
            "class passes every row that only asserts 'a frame arrived'."
        )
