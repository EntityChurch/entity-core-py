"""§4.11 (0.8.2.25) — a pre-admission refusal is ANSWERED, and the code is the
cause's.

0.8.2.25 gives the class a normative home. Four members had been specified
independently, each as a local answer to a local incident, and reached four
different strengths — §4.6 forbidding the bare close outright, §5.2a
forbidding both failures, §4.10(a) *permitting* the close, and §3.3
*requiring* it with no frame at all. A fifth member, the framing arm, was
specified nowhere and three implementations produced three different
caller-observable answers.

    *"A peer that refuses a frame pre-admission MUST put a coded
    EXECUTE_RESPONSE on the wire ``[MUST]`` … Whether the peer closes the
    connection afterwards is its own choice."*

    *"The frame obligation belongs to the CLASS; the CODE belongs to the
    CAUSE ``[MUST]``. A single code for the class would answer an honest
    caller under the wrong reason and send them to the wrong layer."*

.. rubric:: ⭐ SA-PY-61 was ruled in this seat's shape

py split the decode boundary at 0.8.2.24 and routed the split: N4 said a
decode-boundary refusal *"MUST emit the coded response above"* and the
response above was ``hash_mismatch``, which read literally answers *check
your hashes* to a caller whose bytes were truncated. 0.8.2.25 §5.2a:

    *"⚠ The code above is THIS arm's, not the class's ``[MUST]``. … a frame
    that does not decode into an Envelope at all is ``400 invalid_request``
    (§4.7, §4.11). … Answering ``hash_mismatch`` to a truncated payload is the
    same code-under-the-wrong-reason defect this revision corrected when it
    refused ``non_canonical_ecf``, arriving one boundary earlier inside the
    correction itself."*

So `test_a_framing_failure_is_not_reported_as_a_hash_problem` in the N4 file
was pinning the ruled answer a revision early, and its "if arch rules
otherwise this row flips" caveat is discharged.

.. rubric:: ⛔ What was NOT already right here, and go's packet says otherwise

`ROUTING-2026-09-15-b` reports the framing split closed with *"go was the
bare-close seat (not rust, which silent-drops, and **not py, which already
emits a coded frame**)."* Measured here before any edit, that is true of one
half of arm (a) and false of the other two members:

* **arm (a), truncated payload — BARE CLOSE.** ``recv_envelope`` reads the
  payload with ``readexactly``, so a short payload raises
  ``asyncio.IncompleteReadError`` — which the serve loop caught *first*, one
  arm above the refusal, and logged as ``reason=incomplete_read (peer hung up
  cleanly)`` before ``break``. A truncated frame and an ordinary disconnect
  are the same exception, and the loop had one answer for both: silence. Only
  the *whole-but-undecodable* half ever reached the coded frame.
* **arm (c), oversize — ``400 invalid_request``, where §4.10(a) has always
  said ``413 payload_too_large``.** The oversize check raised a bare
  ``FramingError`` and the refusal emitter's ``else`` gave every
  ``FramingError`` one code. ``payload_too_large`` had **zero** occurrences in
  this tree.
* **arm (f), multiplex survival — FAILED.** py emitted the coded frame and
  then closed, on every cause, with the reason stated in the source:
  *"framing can no longer be trusted, so we still close."*

This is the standing hearsay law on its **remedy** axis: go's measurement of
their own seat is correct, and the parenthetical about ours is a claim about
our code that our code answers differently. A peer that emits a coded frame
for one of three causes is *"a peer that already emits a coded frame"* from
outside.

.. rubric:: ⚠ And arm (f) is not satisfiable on all of arm (a) — SA-PY-62

§9's ``CORE-PREADMISSION-REFUSAL-1`` arm **(f)** requires that arm **(a)** —
*"a truncated / un-parseable CBOR frame"* — run on a multiplexed connection
without costing an admitted in-flight request its response. Those are two
different frames with opposite stream dispositions:

* **un-parseable, payload whole** — a complete length-prefixed frame was
  consumed, so the next read starts on a frame boundary. The connection can
  survive, and arm (f) says it must. Driven below.
* **truncated** — the sender promised ``length`` bytes and sent fewer. There
  is no next boundary to find; a peer that kept reading would parse the
  following frame's head as this frame's tail. The close is **forced**, so
  arm (f) is unsatisfiable on this half at any conformant peer.

Same for arm **(c)**: oversize is detected at the length prefix with
``length`` bytes still in the socket, and draining them to resynchronize is
exactly the unbounded read §4.10(a) exists to refuse.

So §4.11's *"the close is its own choice"* is not a free choice — it is
available precisely when the refusal left the stream synchronized, and that
is a property of the frame rather than a peer preference. Routed as SA-PY-62;
the rows below assert the disposition each frame actually licenses.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder
from entity_core.protocol.messages import Execute
from entity_core.protocol.framing import (
    MAX_MESSAGE_SIZE,
    ecf_decode,
    ecf_encode,
)


@pytest.fixture
async def listening_peer():
    """A real peer on a real socket, on an EPHEMERAL port.

    Port 0, deliberately: the standing fixed-port discipline is six instances
    deep, and its sixth is that a port inside `ip_local_port_range` is
    *unclaimed* rather than *free*.
    """
    peer = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    await peer.start("127.0.0.1", 0)
    port = peer._server.sockets[0].getsockname()[1]
    try:
        yield peer, port
    finally:
        await peer.stop()


def _frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


#: A payload that is a WHOLE frame and genuinely un-parseable CBOR: major
#: type 3 (text string) declaring one byte of content and carrying none, so
#: the decoder hits EOF *inside* the item.
#:
#: ⚠ Not ``b"\xff\xff\xff\xff not cbor"``, which the N4 file uses and which
#: **decodes** — ``\xff`` is the CBOR break marker, so that payload never
#: reaches the decoder's error path at all. It used to surface as a bare
#: ``AttributeError`` from ``data.get("root")`` one line later. A probe whose
#: input is filtered by your own decoder is measuring the filter.
UNPARSEABLE_CBOR = b"\x61"

#: Decodes cleanly and is not a map — ``\xf6`` is CBOR ``null``. §4.11's arm
#: is *"never becomes an Envelope"*, which this satisfies without ever being
#: a decode failure.
DECODES_BUT_NOT_AN_ENVELOPE = b"\xf6"


def _valid_execute(request_id: str) -> bytes:
    """A structurally valid EXECUTE frame.

    ``Execute.TYPE`` is read from the protocol module rather than written as a
    literal: the first draft of this file spelled it ``"system/execute"`` and
    every "valid" frame was silently taking the **wrong-root-type** branch, so
    the arm (f) rows were proving that a connection survives a refusal by
    driving two more refusals. (The N4 file's own teeth row has the same
    literal; its assertion is only ``code != "hash_mismatch"``, which holds on
    either branch, so it never surfaced.)

    It is refused at the REQUEST layer — no handshake, so §4.2/§5.2a answer
    ``401 authentication_failed`` (CE-1). That is the point: any answer
    carrying this ``request_id`` proves the frame was admitted and the
    connection lived.
    """
    return _frame(ecf_encode({
        "root": {
            "type": Execute.TYPE,
            "data": {
                "request_id": request_id,
                "uri": "entity://x/system/tree",
                "operation": "get",
            },
        },
        "included": {},
    }))


async def _read_frame(reader: asyncio.StreamReader) -> bytes | None:
    """The next frame's payload, or ``None`` if the peer sent nothing.

    ``None`` IS the bare-close / silent-drop behaviour §4.11 forbids, so
    distinguishing it from a coded frame is the whole measurement.
    """
    try:
        header = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        return None
    length = struct.unpack(">I", header)[0]
    try:
        return await asyncio.wait_for(reader.readexactly(length), timeout=5.0)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        return None


def _error_of(payload: bytes | None) -> tuple[int, str, str]:
    """``(status, code, request_id)`` from a response frame."""
    assert payload is not None, (
        "the peer put NOTHING on the wire. §4.11: 'Dropping the frame — no "
        "response and no close' and 'closing with no coded frame' are BOTH "
        "non-conformant, and they are distinct failures rather than one. A "
        "bare close is indistinguishable from a network fault (§4.6)."
    )
    env = ecf_decode(payload)
    data = env["root"].get("data", {})
    result = data.get("result") or {}
    code = result.get("code") or result.get("data", {}).get("code")
    return data.get("status"), code, data.get("request_id")


class TestTheTruncatedArm:
    """Arm (a)'s truncated half — the one py answered with a bare close,
    because a short payload and a clean hangup are the same exception."""

    @pytest.mark.asyncio
    async def test_a_truncated_payload_gets_a_coded_frame(self, listening_peer):
        """The sender declares 4096 bytes and sends 5.

        Pre-fix this logged ``reason=incomplete_read (peer hung up cleanly)``
        and closed in silence — the caller cannot tell a defect in its own
        request from a defect in the path, and the two remedies are opposite.
        """
        _peer, port = listening_peer
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(struct.pack(">I", 4096) + b"short")
            await writer.drain()
            writer.write_eof()
            status, code, _rid = _error_of(await _read_frame(reader))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        assert status == 400
        assert code == "invalid_request", (
            "§4.11 tabulates the framing arm as `400 invalid_request`. "
            "`hash_mismatch` is non-conformant here — nothing was hashed — "
            "and so is `non_canonical_ecf`, which §5.4 defines for CBOR "
            "tag-policy violations: 'your bytes are truncated' is not "
            "'re-encode without the tag'."
        )

    @pytest.mark.asyncio
    async def test_a_PARTIAL_length_prefix_is_also_a_frame_that_was_offered(
        self, listening_peer,
    ):
        """Two of the four bytes, then EOF.

        The discriminator is ``IncompleteReadError.partial``: nothing consumed
        at a frame boundary is an ordinary disconnect, but a sender that got
        two bytes into a length prefix **began a frame**. Without this row the
        fix could read the prefix with a bare ``readexactly`` and still
        bare-close on the shape that is hardest to attribute from outside.
        """
        _peer, port = listening_peer
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(b"\x00\x00")
            await writer.drain()
            writer.write_eof()
            status, code, _rid = _error_of(await _read_frame(reader))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        assert (status, code) == (400, "invalid_request")


class TestNeverBecomesAnEnvelopeIsWiderThanDoesNotDecode:
    """§4.7's widened scope (0.8.2.25): *"a frame that never becomes an
    Envelope at all ``[MUST]`` — un-parseable, truncated or non-canonical
    CBOR, or a length prefix that never completes."*

    Found building the arm (f) row, not routed by anyone. A payload can decode
    perfectly and still not be an envelope, and this peer had no check for it:
    the line after the decode is ``data.get("root")``, so CBOR ``null``
    reached it and raised ``AttributeError: 'NoneType' object has no attribute
    'get'`` out of the framing layer.

    It still produced a coded 400 — via the serve loop's catch-all — which is
    why nothing surfaced it. What the fallback could not supply is the
    ``stream_synchronized`` property, so the peer closed a connection whose
    stream was on a frame boundary, failing arm (f) on an input arch's own
    sentence covers.
    """

    @pytest.mark.asyncio
    async def test_a_payload_that_decodes_to_a_non_map_is_refused_AND_survives(
        self, listening_peer,
    ):
        _peer, port = listening_peer
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(
                _frame(DECODES_BUT_NOT_AN_ENVELOPE)
                + _valid_execute("req-after-non-map")
            )
            await writer.drain()
            refusal = _error_of(await _read_frame(reader))
            following = _error_of(await _read_frame(reader))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        assert refusal[0] == 400
        assert refusal[1] == "invalid_request"
        assert following[2] == "req-after-non-map", (
            "a whole frame that merely is not a map left the stream on a "
            "frame boundary, so §9 arm (f) applies: the connection MUST NOT "
            "be closed. Pre-fix this raised an AttributeError, which carries "
            "no stream disposition, so the peer closed."
        )


class TestTheOversizeArm:
    """Arm (c) — §4.10(a)'s code, which this peer did not emit anywhere.

    0.8.2.25 changed this arm's *strength* (``SHOULD`` + ``MAY close`` became
    a ``[MUST]`` governed by §4.11) and not its code: ``413
    payload_too_large`` has been §4.10(a)'s answer throughout. py answered
    ``400 invalid_request`` because the oversize check raised a bare
    ``FramingError`` and one ``else`` gave every ``FramingError`` one code —
    the *"a single code for the class"* defect §4.11 names, at the member
    whose code was never in question.
    """

    @pytest.mark.asyncio
    async def test_an_oversize_declaration_is_413_payload_too_large(
        self, listening_peer,
    ):
        """A length prefix over the maximum, and no payload at all.

        Nothing is sent after the prefix deliberately: the refusal MUST come
        from the declared length, *"before fully buffering or decoding it"*
        (§4.10(a)). A peer that waited for the bytes would hang here, which is
        the allocation this row exists to refuse.
        """
        _peer, port = listening_peer
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(struct.pack(">I", MAX_MESSAGE_SIZE + 1))
            await writer.drain()
            status, code, _rid = _error_of(await _read_frame(reader))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        assert status == 413, (
            "§4.10(a)/§4.11: an inbound envelope over the configured maximum "
            "is `413 payload_too_large`. py answered 400 — a status in the "
            "wrong CLASS, so a caller cannot tell 'your request is malformed' "
            "(fix the request) from 'your request is too big' (split it)."
        )
        assert code == "payload_too_large"


class TestArmFTheConnectionSurvivesASYNCHRONIZEDRefusal:
    """Arm (f) — *"the arm nothing else implies"*.

    A pre-admission refusal on a **multiplexed** connection MUST NOT cost an
    admitted in-flight request its response (§4.9(c)). py emitted the coded
    frame and then closed on every cause, so it passed arms (a)-(e) and failed
    this one — which is exactly why §9 scores it separately.
    """

    @pytest.mark.asyncio
    async def test_a_bad_frame_between_two_valid_ones_costs_neither_a_response(
        self, listening_peer,
    ):
        """``[valid A][undecodable][valid B]`` in one write.

        Both A and B MUST be answered. This is the multiplex property without
        needing a slow handler to hold a request open: the refusal is
        interleaved between two admitted requests on one connection, and a
        peer that closes on the refusal loses B.
        """
        _peer, port = listening_peer
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(
                _valid_execute("req-A")
                + _frame(UNPARSEABLE_CBOR)
                + _valid_execute("req-B")
            )
            await writer.drain()
            seen = []
            for _ in range(3):
                payload = await _read_frame(reader)
                if payload is None:
                    break
                seen.append(_error_of(payload))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        ids = [rid for _s, _c, rid in seen]
        assert "req-A" in ids, "the request BEFORE the bad frame was not answered"
        assert "req-B" in ids, (
            "the request AFTER the bad frame was not answered — the peer "
            "closed the connection to punish one undecodable frame, which "
            "§4.9(c) forbids for every admitted request on it and §4.10 "
            "forbids again ('MUST NOT degrade service to in-flight "
            "requests'). §9 arm (f)."
        )
        assert any(
            code == "invalid_request" and not rid for _s, code, rid in seen
        ), (
            "the refusal itself is still owed: surviving the bad frame MUST "
            "NOT be implemented by ignoring it, which is the silent-drop "
            "failure §4.11 lists as the weaker of the two."
        )


class TestTheWrongRootTypeArm:
    """Arm (b) — and this peer was already right, ahead of the spec.

    §3.3 read *"the connection MUST be closed"* until 0.8.2.25, assigning no
    code and requiring no frame. py refused to close and answered a coded
    frame anyway, with the reason in the source: *"a validator probe should
    see the response, not a broken pipe. Stay on the connection: framing is
    intact; only the root type is unrecognized."* 0.8.2.25 ratified exactly
    that, and §9 records the prior form as *"a requirement that gates the
    defect is worse than an absent one."*

    Pinned rather than assumed: it is the one arm where this seat's behaviour
    was non-conformant to the letter and correct in substance, so a later
    reader "restoring" the close has a row to fail.
    """

    @pytest.mark.asyncio
    async def test_a_third_root_type_is_refused_and_the_connection_lives(
        self, listening_peer,
    ):
        _peer, port = listening_peer
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_frame(ecf_encode({
                "root": {
                    "type": "system/not/a/message/type",
                    "data": {"request_id": "req-third-type"},
                },
                "included": {},
            })) + _valid_execute("req-after"))
            await writer.drain()
            first = _error_of(await _read_frame(reader))
            second = _error_of(await _read_frame(reader))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        assert first[0] == 400
        assert first[1] == "invalid_request", (
            "§3.3/§4.11 tabulate a non-EXECUTE/EXECUTE_RESPONSE root as "
            "`400 invalid_request`."
        )
        assert second[2] == "req-after", (
            "the frame after a wrong-root-type refusal was not answered — "
            "framing is intact here, so there is no reason to close and "
            "§4.9(c) forbids it for anything admitted."
        )


class TestTheTeeth:
    """Without these, the rows above pass on a peer that answers 400 to
    everything, or that has turned every ordinary disconnect into noise."""

    @pytest.mark.asyncio
    async def test_a_clean_EOF_AT_A_FRAME_BOUNDARY_is_still_silent(
        self, listening_peer,
    ):
        """The control the truncated-arm fix could break.

        A peer hanging up *between* frames offered no frame, so there is
        nothing to refuse and §4.11 does not reach it. If this row fails, the
        fix has started answering ordinary disconnects — which would put a
        coded refusal on the wire for every well-behaved client that closes a
        connection, and make the truncated rows above pass for the wrong
        reason.
        """
        _peer, port = listening_peer
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write_eof()
        payload = await _read_frame(reader)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        assert payload is None, (
            "the peer answered a refusal to a connection that simply closed "
            "at a frame boundary. `IncompleteReadError.partial` is the "
            "discriminator: empty means nothing was consumed."
        )

    @pytest.mark.asyncio
    async def test_the_three_causes_do_not_collapse_to_one_answer(
        self, listening_peer,
    ):
        """§4.11's actual MUST is about the TABLE, not any row.

        *"The frame obligation belongs to the class; the CODE belongs to the
        cause."* Three causes, three pairs — a peer with one code for the
        class passes every individual row that only asserts "a frame arrived"
        and fails here.
        """
        _peer, port = listening_peer

        async def drive(writer_bytes: bytes, *, eof: bool) -> tuple[int, str]:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                writer.write(writer_bytes)
                await writer.drain()
                if eof:
                    writer.write_eof()
                status, code, _rid = _error_of(await _read_frame(reader))
                return status, code
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        framing = await drive(_frame(UNPARSEABLE_CBOR), eof=False)
        truncated = await drive(struct.pack(">I", 4096) + b"short", eof=True)
        oversize = await drive(
            struct.pack(">I", MAX_MESSAGE_SIZE + 1), eof=False,
        )

        assert framing == (400, "invalid_request")
        assert truncated == (400, "invalid_request")
        assert oversize == (413, "payload_too_large")
        assert oversize != framing, (
            "oversize and un-parseable answered the same pair — the code no "
            "longer selects the caller's remedy, which is the whole reason "
            "§4.11 splits the class from the cause."
        )
