"""N3 + N4 (0.8.2.24) — a decode-boundary refusal is a REFUSAL, not silence.

§5.2a, and both halves are new normative text:

* **N3** — *"A peer that refuses at the decode boundary … **MUST answer**
  ``400 hash_mismatch`` ``[MUST]`` (mood corrected 0.8.2.24)."* The sentence
  previously stated the code in the indicative and carried no ``[MUST]``, and
  independent implementations read it as *one conformant choice*.
  ``400 non_canonical_ecf`` is explicitly non-conformant there:
  ``ENTITY-CBOR-ENCODING`` §5.4 defines that code for CBOR **tag-policy**
  violations and a mis-keyed ``included`` entry carries no tag — its encoding
  is canonical; what is false is the claim the key makes.
* **N4** — *"A peer that refuses at the decode boundary MUST emit the coded
  response above, correlated by ``request_id`` where the id is available, and
  otherwise MUST make a best-effort coded frame before closing. Dropping the
  frame with no response and no close is non-conformant, **and so is closing
  with no coded frame**."*

§4.9(c)'s deliver-or-signal rule does **not** reach this seam: it is scoped to
*"every request the peer ADMITS"*, and a frame refused at decode was never
admitted. That is the point of refusing there, and it is why N4 had to be
stated rather than inherited.

.. rubric:: ⛔ py owed this, and arch's cost table says otherwise

`0.8.2.24` §5 marks `N4` ``⛔ one edit`` for go and ``—`` for rust and py.
Measured at this seat before any edit: the serve loop caught every
``recv_envelope`` failure, logged it at INFO, and ``break``'d — **a bare
socket close with nothing on the wire**, which §4.6 says is indistinguishable
from a network fault. Exactly go's pre-N4 behaviour, and go's own packet
predicted the right move (*"go will confirm on the cross-impl drive rather
than assume — a bare close at the decode boundary is the tell"*).

.. rubric:: ⭐ And this repo had ALREADY told the cohort otherwise

`test_resolution_integrity_k1.py`'s module docstring reads:

    *"go refuses by a receive-boundary connection close with no status …
    py answers a coded 401 on one arm and a coded 400 on the other, so this
    seat's data point is: the coded response is reachable."*

The **401 arm is true** — that request is admitted and refused by
``verify_request``. The **400 arm was not**. Its row asserts
``pytest.raises(HashValidationError)`` against ``recv_envelope`` called
directly, and the claim *"which the wire boundary renders as that pair"* is
prose in a docstring that nothing drove. The wire boundary rendered it as a
bare close.

That sentence went into a routing packet as a cohort-comparable measurement.
It is the standing law — *a comment that paraphrases behaviour is not a
measurement of it* — arriving at our own seat, in the flattering direction,
about the one number a sibling was going to compare against. **The lesson is
the one this file exists to enforce: if the claim is about what goes on the
wire, the row has to read the wire.** Every row below opens a socket.
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder
from entity_core.protocol.framing import ecf_decode, ecf_encode


@pytest.fixture
async def listening_peer():
    """A real peer on a real socket, on an EPHEMERAL port.

    Port 0, deliberately: the standing fixed-port discipline is six instances
    deep, and its sixth is that a port inside `ip_local_port_range` is
    *unclaimed* rather than *free*. Letting the kernel assign and reading it
    back is the only form with neither hazard.
    """
    peer = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    await peer.start("127.0.0.1", 0)
    port = peer._server.sockets[0].getsockname()[1]
    try:
        yield peer, port
    finally:
        await peer.stop()


async def _send_frame_and_read(port: int, payload: bytes) -> bytes | None:
    """Write one length-prefixed frame; return the next frame's payload, or
    ``None`` if the peer closed without sending anything.

    ``None`` IS the pre-N4 behaviour, and distinguishing it from a coded frame
    is the whole measurement.
    """
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(struct.pack(">I", len(payload)) + payload)
        await writer.drain()
        try:
            header = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None
        length = struct.unpack(">I", header)[0]
        try:
            return await asyncio.wait_for(
                reader.readexactly(length), timeout=5.0,
            )
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _error_of(payload: bytes | None) -> tuple[int, str, str]:
    """``(status, code, request_id)`` from a response frame."""
    assert payload is not None, (
        "the peer closed the connection with NOTHING on the wire. §5.2a "
        "(0.8.2.24 N4): 'Dropping the frame with no response and no close is "
        "non-conformant, AND SO IS CLOSING WITH NO CODED FRAME' — a bare "
        "socket close is indistinguishable from a network fault (§4.6)."
    )
    env = ecf_decode(payload)
    root = env["root"]
    data = root.get("data", {})
    return (
        data.get("status"),
        (data.get("result") or {}).get("data", {}).get("code"),
        data.get("request_id"),
    )


class TestTheHashBindingArm:
    """N3's subject: the §1.8 forgery, where the root is a valid EXECUTE and
    an ``included`` entry's hash binding is false."""

    @pytest.mark.asyncio
    async def test_a_mis_stamped_included_entity_gets_a_coded_frame(
        self, listening_peer,
    ):
        _peer, port = listening_peer
        # A well-formed envelope whose ROOT decodes cleanly and carries a
        # request_id, with one `included` entry whose content_hash is a lie.
        # The root being valid is what makes the id available to correlate by,
        # which is the arm N4 says MUST be correlated.
        payload = ecf_encode({
            "root": {
                "type": "system/execute",
                "data": {
                    "request_id": "req-n4-correlated",
                    "uri": "entity://x/system/tree",
                    "operation": "get",
                },
            },
            "included": {
                b"\x00" + b"\xaa" * 32: {
                    "type": "system/peer",
                    "data": {"public_key": b"\xbb" * 32},
                    "content_hash": b"\x00" + b"\xcc" * 32,
                },
            },
        })
        status, code, request_id = _error_of(
            await _send_frame_and_read(port, payload),
        )
        assert status == 400, f"expected 400, got {status}"
        assert code == "hash_mismatch", (
            "§5.2a pins `400 hash_mismatch` at the decode boundary in the "
            f"imperative (0.8.2.24 N3); got {code!r}"
        )

    @pytest.mark.asyncio
    async def test_the_refusal_is_CORRELATED_by_request_id(
        self, listening_peer,
    ):
        """*"correlated by ``request_id`` where the id is available"*.

        The id is available exactly here — the root decoded and validated, and
        only an included entry is bad. A peer that answers the right code with
        an empty id has satisfied N3 and not N4: on a multiplexed connection
        the caller cannot tell which request was refused.
        """
        _peer, port = listening_peer
        payload = ecf_encode({
            "root": {
                "type": "system/execute",
                "data": {
                    "request_id": "req-n4-correlated",
                    "uri": "entity://x/system/tree",
                    "operation": "get",
                },
            },
            "included": {
                b"\x00" + b"\xaa" * 32: {
                    "type": "system/peer",
                    "data": {"public_key": b"\xbb" * 32},
                    "content_hash": b"\x00" + b"\xcc" * 32,
                },
            },
        })
        _status, _code, request_id = _error_of(
            await _send_frame_and_read(port, payload),
        )
        assert request_id == "req-n4-correlated", (
            f"the refusal was not correlated (got {request_id!r})"
        )

    @pytest.mark.asyncio
    async def test_non_canonical_ecf_is_NOT_the_code(self, listening_peer):
        """0.8.2.24 names this spelling non-conformant at this seam.

        Kept as its own row rather than folded into the code assertion above:
        `non_canonical_ecf` is a REAL code for a real condition (a CBOR
        tag-policy violation), so a peer emitting it here is making a
        plausible-looking mistake rather than minting a synonym — and the
        remedy it selects (*re-encode*) sends an honest caller to the wrong
        layer.
        """
        _peer, port = listening_peer
        payload = ecf_encode({
            "root": {
                "type": "system/execute",
                "data": {"request_id": "r", "uri": "entity://x/y",
                         "operation": "get"},
            },
            "included": {
                b"\x00" + b"\xaa" * 32: {
                    "type": "system/peer",
                    "data": {"public_key": b"\xbb" * 32},
                    "content_hash": b"\x00" + b"\xcc" * 32,
                },
            },
        })
        _status, code, _rid = _error_of(
            await _send_frame_and_read(port, payload),
        )
        assert code != "non_canonical_ecf"


class TestTheFramingArm:
    """⚠ The arm N4's sentence does not separate, and py has to.

    N4 says a decode-boundary refusal MUST emit *"the coded response above"* —
    and the response above is ``hash_mismatch``. py's decode boundary also
    catches genuinely undecodable CBOR, which is **not** a hash-binding
    failure, and answering ``hash_mismatch`` to a caller whose bytes were
    truncated is the same defect arch corrected in this very delta when it
    refused ``non_canonical_ecf``: the code selects the caller's remedy, and
    *check your hashes* is the wrong instruction for *your bytes are
    malformed*.

    go does not face the choice — their edit sits at ``ValidateAll``, the hash
    step alone. So this seat answers §3.3's declared 400 default here and
    routes the question. The row pins today's answer with that filing named,
    rather than settling it.
    """

    @pytest.mark.asyncio
    async def test_undecodable_cbor_still_gets_a_coded_frame(
        self, listening_peer,
    ):
        """The N4 half is not in doubt: whatever the code, a refusal is owed
        and a bare close is not one."""
        _peer, port = listening_peer
        status, code, _rid = _error_of(
            await _send_frame_and_read(port, b"\xff\xff\xff\xff not cbor"),
        )
        assert status == 400
        assert code is not None

    @pytest.mark.asyncio
    async def test_a_framing_failure_is_not_reported_as_a_hash_problem(
        self, listening_peer,
    ):
        """Today's answer, and the one we are routing.

        If arch rules that N4's `hash_mismatch` covers the whole decode
        boundary, this row flips and the reason is a ruling rather than a
        regression.
        """
        _peer, port = listening_peer
        _status, code, _rid = _error_of(
            await _send_frame_and_read(port, b"\xff\xff\xff\xff not cbor"),
        )
        assert code == "invalid_request", (
            "py answers §3.3's declared 400 default for a FRAMING failure and "
            "reserves `hash_mismatch` for a hash-binding one. Routed: N4's "
            "sentence does not separate the two arms, and go's edit sits at "
            "the hash step alone so the question does not arise there."
        )


class TestTheTeeth:
    """Without these, every row above passes on a peer that answers
    ``400 hash_mismatch`` to everything, including valid traffic."""

    @pytest.mark.asyncio
    async def test_a_WELL_FORMED_frame_is_not_refused_at_decode(
        self, listening_peer,
    ):
        """A structurally valid envelope reaches the request layer and is
        refused *there* — a different status, from a different rule.

        The discriminator is that it is NOT ``400 hash_mismatch``: a peer whose
        decode boundary refuses everything would answer that here too, and
        every row above would still be green.
        """
        _peer, port = listening_peer
        payload = ecf_encode({
            "root": {
                "type": "system/execute",
                "data": {
                    "request_id": "req-well-formed",
                    "uri": "entity://x/system/tree",
                    "operation": "get",
                },
            },
            "included": {},
        })
        response = await _send_frame_and_read(port, payload)
        assert response is not None, (
            "a well-formed frame got a bare close — the decode boundary is "
            "refusing traffic it should be admitting"
        )
        env = ecf_decode(response)
        data = env["root"].get("data", {})
        code = (data.get("result") or {}).get("data", {}).get("code")
        assert code != "hash_mismatch", (
            "the peer answered the decode-boundary refusal for a frame whose "
            "hashes are fine — the rows above are measuring a blanket refusal"
        )
