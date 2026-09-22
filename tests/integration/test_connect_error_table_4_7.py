"""§4.7's connect-error rows, driven as `(status, code)` pairs on the wire.

`entity-core-go`'s G-28/FM-1g probe family measured this peer at `bac0244` and
found rows 7 and 8 — an invalid authenticate signature, and a `peer_id` not
derived from its `public_key` — both answering **`400 bad_request`**. Verified
here before acting (a routed report's claims about our repo are hearsay): the
raises in `handle_connect_authenticate` passed a message only, and
`ConnectError` defaults `code` to `bad_request` at the §4.7 400 class. So the
measurement was right, and the same read found **rows go's probes never
drove**, because a probe family is evidence about the rows it seeds:

* **row 6's mismatch arm** — FM-1 fixed the *pre-hello* input of "Nonce
  mismatch / absent / pre-hello"; a post-hello nonce mismatch is the same row
  and was still a generic 400.
* **row 8's second input** — the row names *"`peer_id` not derived from
  `public_key`, **or** `hello`/`authenticate` peer_id mismatch"*. Only the
  first was probed.
* **step 2's absent-signature arm** — §4.6 step 2 pins absent and invalid to
  one pair; go's probe drives the invalid one.
* **row 10** — `connection_sequence_error`, which this peer emitted for
  neither of the row's two named inputs.

.. rubric:: What is asserted, and what is deliberately not

§4.7 is a MUST-emit contract on the **pair** — *"an impl that collapses several
of these to one code, or returns a different status, is non-conformant"* — so
every row here asserts `(status, code)` together. A status-only assertion does
not separate row 6 from row 8, and a code-only assertion is satisfied by the
half-fix FM-1 already documented (`400 invalid_nonce`, a pair in no row).

`TestTheRowsDoNotCollapse` is the row that survives a lazy fix: three inputs
that a peer answering "401 authentication_failed for anything that fails after
hello" would score green on individually.

Row 10's **status** is contested and is asserted at the table's 400 with that
stated: go emits 409 (spec-issue `2026-09-01-b` asks which is authoritative)
and only the status is in question — the code is uncontested and was wrong
here. If arch rules 409, this row moves; nothing else in the file does.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.connect import ADVERTISED_PROTOCOLS
from entity_core.peer import Peer, PeerBuilder
from entity_core.protocol.auth import create_identity_entity, create_signature_entity
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import recv_envelope, send_envelope
from entity_core.protocol.messages import Execute, ExecuteResponse
from entity_core.utils.ecf import (
    DEFAULT_ADVERTISED_KEY_TYPES,
    default_advertised_hash_formats,
)

PORT = 19087
CONNECT_URI_PATH = "system/protocol/connect"


@pytest.fixture
async def server_peer():
    peer = (
        PeerBuilder().with_keypair(Keypair.generate())
        .with_default_handlers().debug_mode(True).build()
    )
    await peer.start("127.0.0.1", PORT)
    yield peer
    await peer.stop()


# --------------------------------------------------------------------------
# Frame construction — built here rather than through
# `create_connect_{hello,authenticate}_execute` because every row below is a
# frame those helpers cannot produce by construction. A probe that can only
# send well-formed frames cannot reach a single row of this table.
# --------------------------------------------------------------------------


def _hello_execute(peer_id: str, nonce: bytes) -> Execute:
    return Execute.create(
        uri=f"entity://{peer_id}/{CONNECT_URI_PATH}",
        operation="hello",
        params=Entity(
            type="system/protocol/connect/hello",
            data={
                "peer_id": peer_id,
                "nonce": nonce,
                "protocols": list(ADVERTISED_PROTOCOLS),
                "hash_formats": default_advertised_hash_formats(),
                "key_types": list(DEFAULT_ADVERTISED_KEY_TYPES),
            },
        ).to_dict(),
    )


def _authenticate_frames(
    keypair: Keypair,
    their_nonce: bytes,
    *,
    claimed_peer_id: str | None = None,
    corrupt_signature: bool = False,
) -> tuple[Execute, list[dict]]:
    """An authenticate EXECUTE plus its `included` set.

    ``claimed_peer_id`` overrides the peer_id the frame claims while the
    `public_key` stays ``keypair``'s — the identity-spoofing shape §4.6 step 3
    exists to refuse. ``corrupt_signature`` flips a byte of the signature so it
    is well-formed and does not verify (step 2's *invalid* arm, distinct from
    its *absent* arm, which is built by dropping the signature from `included`).
    """
    authenticate = Entity(
        type="system/protocol/connect/authenticate",
        data={
            "peer_id": claimed_peer_id or keypair.peer_id,
            "public_key": keypair.public_key_bytes(),
            "key_type": keypair.key_type,
            "nonce": their_nonce,
        },
    )
    auth_hash = authenticate.compute_hash()
    identity = create_identity_entity(keypair)
    signature = create_signature_entity(keypair, auth_hash, identity.compute_hash())

    if corrupt_signature:
        raw = bytearray(signature.data["signature"])
        raw[0] ^= 0xFF
        signature = Entity(
            type=signature.type,
            data={**signature.data, "signature": bytes(raw)},
        )

    execute = Execute.create(
        uri=f"entity://{keypair.peer_id}/{CONNECT_URI_PATH}",
        operation="authenticate",
        params=authenticate.to_dict(),
    )
    return execute, [signature.to_dict(), identity.to_dict()]


async def _drive(hello: Execute | None, *frames) -> ExecuteResponse:
    """Send `hello` (if any), then each `(execute, included)` frame, and return
    the response to the LAST one. The hello response is read and discarded —
    it carries the responder's nonce, which the callers that need it fetch via
    :func:`_hello_and_nonce` instead."""
    reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
    try:
        if hello is not None:
            await send_envelope(writer, Envelope(root=hello.to_entity()))
            await recv_envelope(reader)
        response = None
        for execute, included in frames:
            await send_envelope(
                writer, Envelope(root=execute.to_entity(), included=included)
            )
            response = ExecuteResponse.from_entity((await recv_envelope(reader)).root)
        assert response is not None
        return response
    finally:
        writer.close()
        await writer.wait_closed()


async def _hello_and_nonce(peer_id: str) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bytes]:
    """Complete the hello leg and return the responder's issued nonce — the
    value an `authenticate` must echo (§4.6 step 1)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
    await send_envelope(writer, Envelope(root=_hello_execute(peer_id, os.urandom(32)).to_entity()))
    hello_response = await recv_envelope(reader)
    issued = hello_response.root["data"]["result"]["data"]["nonce"]
    return reader, writer, issued


async def _authenticate_after_hello(
    keypair: Keypair,
    *,
    hello_peer_id: str | None = None,
    claimed_peer_id: str | None = None,
    corrupt_signature: bool = False,
    omit_signature: bool = False,
    nonce_override: bytes | None = None,
) -> ExecuteResponse:
    reader, writer, issued = await _hello_and_nonce(hello_peer_id or keypair.peer_id)
    try:
        execute, included = _authenticate_frames(
            keypair,
            nonce_override if nonce_override is not None else issued,
            claimed_peer_id=claimed_peer_id,
            corrupt_signature=corrupt_signature,
        )
        if omit_signature:
            # Keep the identity entity: dropping both would make this a frame
            # with nothing in `included` at all, and the row is about a missing
            # SIGNATURE specifically.
            included = [e for e in included if e.get("type") != "system/signature"]
        await send_envelope(
            writer, Envelope(root=execute.to_entity(), included=included)
        )
        return ExecuteResponse.from_entity((await recv_envelope(reader)).root)
    finally:
        writer.close()
        await writer.wait_closed()


def _pair(response: ExecuteResponse) -> tuple[int, str]:
    return int(response.status), response.result["data"]["code"]


# --------------------------------------------------------------------------
# Row 7 — §4.6 step 2: absent OR invalid authenticate signature
# --------------------------------------------------------------------------


class TestRow7AuthenticationFailed:
    """`401 authentication_failed`. §4.7 records that `invalid_signature` (the
    pre-v7.61 spelling) is superseded here — this peer has never emitted it on
    this surface and the rows below would fail if it started."""

    @pytest.mark.asyncio
    async def test_an_invalid_signature_is_401_authentication_failed(self, server_peer: Peer):
        """go's `connect_authenticate_bad_signature` probe, in-tree. Measured
        `400 bad_request` at `bac0244`."""
        response = await _authenticate_after_hello(
            Keypair.generate(), corrupt_signature=True
        )
        assert _pair(response) == (401, "authentication_failed"), (
            f"an authenticate whose signature does not verify answered "
            f"{_pair(response)}; §4.7 row 7 / §4.6 step 2 pin "
            f"(401, 'authentication_failed')"
        )

    @pytest.mark.asyncio
    async def test_an_absent_signature_takes_the_same_pair(self, server_peer: Peer):
        """The arm go's probe does not drive. §4.6 step 2 is explicit that an
        **absent** signature and an **invalid** one are one row — a peer that
        codes the invalid arm and leaves the absent arm at 400 passes the
        cross-impl check and is still non-conformant."""
        response = await _authenticate_after_hello(
            Keypair.generate(), omit_signature=True
        )
        assert _pair(response) == (401, "authentication_failed"), (
            f"an authenticate carrying no system/signature answered "
            f"{_pair(response)}; §4.6 step 2 pins the absent arm to the same "
            f"(401, 'authentication_failed') as the invalid arm"
        )


# --------------------------------------------------------------------------
# Row 8 — §4.6 step 3: identity binding, both named inputs
# --------------------------------------------------------------------------


class TestRow8IdentityMismatch:
    """`401 identity_mismatch`, for both inputs §4.7 row 8 names."""

    @pytest.mark.asyncio
    async def test_a_peer_id_not_derived_from_the_public_key(self, server_peer: Peer):
        """go's `connect_authenticate_identity_mismatch` probe, in-tree.

        The hello carries the SAME claimed peer_id, so the hello/authenticate
        equality check passes and the failure is attributable to the derivation
        check — without that, this row would be measuring row 8's other input
        and the derivation check could be deleted with the row still green.
        """
        attacker = Keypair.generate()
        victim = Keypair.generate()
        response = await _authenticate_after_hello(
            attacker,
            hello_peer_id=victim.peer_id,
            claimed_peer_id=victim.peer_id,
        )
        assert _pair(response) == (401, "identity_mismatch"), (
            f"an authenticate claiming a peer_id not derived from its "
            f"public_key answered {_pair(response)}; §4.6 step 3 pins "
            f"(401, 'identity_mismatch') — this is the check that binds the "
            f"step-2 proof to the identity the caller claims"
        )

    @pytest.mark.asyncio
    async def test_a_hello_authenticate_peer_id_mismatch(self, server_peer: Peer):
        """Row 8's second named input. The authenticate is internally
        consistent (its peer_id DOES derive from its public_key) and disagrees
        with the hello, so it reaches the equality check and not the derivation
        check."""
        first = Keypair.generate()
        second = Keypair.generate()
        response = await _authenticate_after_hello(
            second, hello_peer_id=first.peer_id
        )
        assert _pair(response) == (401, "identity_mismatch"), (
            f"an authenticate whose peer_id differs from the hello's answered "
            f"{_pair(response)}; §4.7 row 8 names this input explicitly "
            f"alongside the derivation failure and gives them one pair"
        )


# --------------------------------------------------------------------------
# Row 6 — §4.6 step 1: nonce mismatch (the arm FM-1 did not reach)
# --------------------------------------------------------------------------


class TestRow6InvalidNonce:
    @pytest.mark.asyncio
    async def test_a_post_hello_nonce_mismatch_is_401_invalid_nonce(self, server_peer: Peer):
        """FM-1 pinned the pre-hello input of row 6 and carried the status
        through `ConnectError`; the *mismatch* input is the same row, three
        frames further down the same function, and was left at 400. A captured
        authenticate replayed against a fresh nonce lands here."""
        response = await _authenticate_after_hello(
            Keypair.generate(), nonce_override=os.urandom(32)
        )
        assert _pair(response) == (401, "invalid_nonce"), (
            f"an authenticate echoing a nonce the peer never issued answered "
            f"{_pair(response)}; §4.7 row 6 covers 'Nonce mismatch / absent / "
            f"pre-hello' with one pair"
        )


# --------------------------------------------------------------------------
# Row 10 — out-of-order operation (code settled, status contested)
# --------------------------------------------------------------------------


class TestRow10ConnectionSequenceError:
    """**Row 10 is two failures, not one** — arch's 2026-09-01 ruling (FM-2
    Edit D), implemented here.

    The landed table gives one code and one status to two different inputs, and
    asking *"400 or 409?"* as a single question is what makes either answer
    wrong:

    | input | nature | code | status |
    |---|---|---|---|
    | second `hello` mid-handshake | state conflict | `connection_sequence_error` | **409** |
    | unknown connect operation | invalid request | `invalid_request` | **400** |

    The derivation for 409 is row 9's precedent (`connection_already_established`
    is already 409 for the same class) plus §4.6's Hardening block, which
    presumes 409 is what a state conflict gets. The derivation for
    `invalid_request` is that nothing is out of order when the operation does not
    exist in any state — and §4.7 exists so clients key handling off the code, so
    one that misdirects the remedy fails its own contract.

    **Both are landed ahead of the FM-2 fold**, matching `entity-core-go` and
    `entity-core-rust` so all three seats reach the ruled behaviour before
    ratification rather than after. The rows below are the two halves, and they
    are separate rows because the whole finding is that they are separate
    failures.
    """

    @pytest.mark.asyncio
    async def test_a_second_hello_mid_handshake_is_409(self, server_peer: Peer):
        """The state-conflict half.

        Distinct from row 9 (`409 connection_already_established`), which is a
        second hello *after* the handshake completes and is answered a frame
        earlier at the wire boundary. Both are 409 now, which is the point —
        two adjacent state rows at two different statuses was the inconsistency
        the ruling removed.
        """
        keypair = Keypair.generate()
        hello = _hello_execute(keypair.peer_id, os.urandom(32))
        second = _hello_execute(keypair.peer_id, os.urandom(32))
        response = await _drive(hello, (second, []))
        assert _pair(response) == (409, "connection_sequence_error"), (
            f"a second hello mid-handshake answered {_pair(response)}; the "
            f"ruled pair is (409, 'connection_sequence_error') — a valid "
            f"operation refused for the connection's STATE"
        )

    @pytest.mark.asyncio
    async def test_an_unknown_connect_operation_is_400_invalid_request(
        self, server_peer: Peer
    ):
        """The invalid-request half, and the one that moved.

        It was pinned only by a `!= 401` assertion in the FM-1 file — a negative
        assertion that stayed green while the code was `bad_request`, and would
        have stayed green through this change too. That is why the pair is
        asserted positively here.
        """
        execute = Execute(
            request_id="row10-unknown-op",
            uri=f"entity://{server_peer.peer_id}/{CONNECT_URI_PATH}",
            operation="not-a-connect-operation",
            params={},
        )
        response = await _drive(None, (execute, []))
        assert _pair(response) == (400, "invalid_request"), (
            f"an unknown connect operation answered {_pair(response)}; the "
            f"ruled pair is (400, 'invalid_request') — the operation name "
            f"exists in no state, so nothing is out of ORDER"
        )

    @pytest.mark.asyncio
    async def test_the_two_halves_do_not_answer_the_same_thing(
        self, server_peer: Peer
    ):
        """The row that carries the ruling itself rather than either half.

        Both rows above pass against a peer that answers one pair for both
        inputs — they just have to be *that* pair. This one fails such a peer,
        because the finding is not "row 10 has these values", it is "row 10 was
        one row describing two failures." A future seat that re-merges them
        satisfies half the table and this row.
        """
        keypair = Keypair.generate()
        hello = _hello_execute(keypair.peer_id, os.urandom(32))
        second = _hello_execute(keypair.peer_id, os.urandom(32))
        state_conflict = _pair(await _drive(hello, (second, [])))

        unknown = _pair(
            await _drive(
                None,
                (
                    Execute(
                        request_id="row10-split",
                        uri=f"entity://{server_peer.peer_id}/{CONNECT_URI_PATH}",
                        operation="not-a-connect-operation",
                        params={},
                    ),
                    [],
                ),
            )
        )

        assert state_conflict != unknown, (
            f"both inputs answered {state_conflict}; row 10 names two distinct "
            f"failures and collapsing them is what the ruling undid"
        )


# --------------------------------------------------------------------------
# The discriminators
# --------------------------------------------------------------------------


class TestTheRowsDoNotCollapse:
    """§4.7's MUST is about the table as a whole: *"an impl that collapses
    several of these to one code … is non-conformant."* Each row above passes
    against a peer that answers one blanket 401 for every post-hello failure;
    this one does not.

    **What it does NOT catch, recorded because the prediction was wrong.**
    Mutation-verifying the three arms (invalid signature, identity derivation,
    absent signature) reddened exactly one per-row assertion each and left this
    row GREEN every time — the prediction said it would fall with them. It does
    not: a reverted arm answers `bad_request`, which is *wrong* but still
    *distinct* from `identity_mismatch` and `invalid_nonce`, so three inputs
    still produce three codes. This row discriminates collapse and nothing
    else; the per-row pairs are what catch a wrong code. Deleting one of them
    on the strength of this row would leave its arm unwatched.
    """

    @pytest.mark.asyncio
    async def test_three_inputs_three_codes(self, server_peer: Peer):
        bad_sig = await _authenticate_after_hello(
            Keypair.generate(), corrupt_signature=True
        )
        attacker, victim = Keypair.generate(), Keypair.generate()
        bad_identity = await _authenticate_after_hello(
            attacker, hello_peer_id=victim.peer_id, claimed_peer_id=victim.peer_id
        )
        bad_nonce = await _authenticate_after_hello(
            Keypair.generate(), nonce_override=os.urandom(32)
        )
        codes = [_pair(r)[1] for r in (bad_sig, bad_identity, bad_nonce)]
        assert len(set(codes)) == 3, (
            f"three distinct §4.6 failures produced codes {codes}; clients key "
            f"error handling off result.data.code, so collapsing them is the "
            f"exact non-conformance §4.7's preamble names"
        )

    @pytest.mark.asyncio
    async def test_a_structurally_malformed_authenticate_stays_in_the_400_class(
        self, server_peer: Peer
    ):
        """The boundary the 401 rows must not swallow.

        An authenticate with no `public_key` cannot reach a numbered §4.6 step
        — there is nothing to verify a signature against and nothing to derive
        a peer_id from — so it is not any row of §4.7 and takes the table's 400
        default. A fix that routed every authenticate failure to 401 would hand
        an authentication verdict to a caller who never presented a claim.
        """
        keypair = Keypair.generate()
        reader, writer, issued = await _hello_and_nonce(keypair.peer_id)
        try:
            execute = Execute.create(
                uri=f"entity://{keypair.peer_id}/{CONNECT_URI_PATH}",
                operation="authenticate",
                params=Entity(
                    type="system/protocol/connect/authenticate",
                    data={"peer_id": keypair.peer_id, "nonce": issued},
                ).to_dict(),
            )
            await send_envelope(writer, Envelope(root=execute.to_entity()))
            response = ExecuteResponse.from_entity((await recv_envelope(reader)).root)
        finally:
            writer.close()
            await writer.wait_closed()
        assert int(response.status) == 400, (
            f"a structurally undecodable authenticate answered status "
            f"{int(response.status)}; §4.7 has no row for a frame that cannot "
            f"be read far enough to reach a §4.6 step, and its default class "
            f"is 400"
        )

    @pytest.mark.asyncio
    async def test_the_ordinary_handshake_still_completes(self, server_peer: Peer):
        """Teeth. Without it a peer that refuses every authenticate scores
        every row in this file green."""
        from entity_core.peer.connection import Connection

        conn = await Connection.connect("127.0.0.1", PORT, Keypair.generate())
        try:
            assert conn.session.remote_peer_id == server_peer.peer_id
        finally:
            conn.close()
            await conn.wait_closed()
