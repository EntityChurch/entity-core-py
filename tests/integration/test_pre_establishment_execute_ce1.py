"""CE-1 — a non-connect EXECUTE arriving before the handshake is `401 authentication_failed`.

`entity-core-go` measured this three-way on live peers and routed it as an
**unruled** code. It is not unruled, and that is the finding worth keeping:
`ENTITY-CORE-PROTOCOL` **§4.2**'s third pre-authorization bullet has governed
this input since **0.8.1**, where F32 replaced that bullet's blanket `403` with
the auth/authz discriminator —

    EXECUTE targeting any other path without valid authentication MUST be
    rejected per §5.2a: a missing/unverifiable `author` or signature is
    auth-class **401**; an authenticated request lacking a covering capability
    is authz-class **403**.

— and **§5.2a**'s table gives the code (*"Request-time (§5.2 step 2) · Author
absent · 401 · `authentication_failed`"*). `0.8.2.5` restates it as a note under
§4.7 and names `connection_required` and `handshake_failed`, the two codes seats
were minting in its place, **non-conformant**. So the three-way divergence go
measured was a conformance gap two releases old, at every seat:

===============  ==============================  =========================
impl             observed before the ruling      in a spec code set?
===============  ==============================  =========================
go               ``403 connection_required``     no — minted
rust             ``400 handshake_failed``        no — minted
**py**           ``403 capability_denied``       the code is real; the
                                                 **class** is false of the
                                                 input
===============  ==============================  =========================

.. rubric:: Why no seat found it, and why this peer's version is the sneakiest

All three were reading §4.7, which declares itself the MUST-emit contract for
the connect surface and had no row for this input; §4.2 states the rule in the
vocabulary of *pre-authorization*, which is not reachable from the vocabulary of
*connection state*. Ours then had a second layer of cover: 403 `capability_denied`
is a real code from a real table, so nothing looked minted. It was still a false
statement about the input — 403 asserts the caller authenticated and then lacked
authority, and this caller never authenticated.

And it was not a *chosen* wrong answer. Both call sites read
``ExecuteResponse.forbidden``, which hardcodes **both** halves, so no call site
named a status or a code and no reviewer reading either site could see one. That
is the ``bad_request`` default from one commit ago (*a wire value with no call
site to review it*) arriving in a **helper** instead of a default argument.

.. rubric:: The row that states the defect best

``test_the_two_states_now_agree_on_the_same_frame``. This peer already answered
`401 authentication_failed` for a frame with no author on an **established**
connection — `test_authenticated.py::test_unauthenticated_request_fails` has
pinned that for as long as it has existed. The *identical* frame one state
earlier answered 403. One peer, one input class, two answers, split by a state
that changes nothing about whether a signer was verified.

.. rubric:: What is asserted, and what is deliberately not

Every row asserts the `(status, code)` **pair**. §4.7's contract language — *"an
impl that collapses several of these to one code, or returns a different status,
is non-conformant"* — is about the pair, and this file's own history is why: the
FM-1d relay prescribed a fix that would have produced `400 invalid_nonce`, a
pair in no row, because it moved one half.

Three attribution controls stop a blanket *"pre-establishment ⇒ 401"* from
scoring green here: a pre-hello `ping` is still `409 connection_sequence_error`,
an unknown connect operation is still `400 invalid_request`, and a genuine
authorization denial on an established connection is still `403
capability_denied`. Without the third, this file would be satisfied by a peer
that had simply deleted the authz class.

.. rubric:: The §5.2a walk, since the row-walk rule says to do it

Walking §5.2a's other surfaces rather than only the routed one: the six
request-time **auth** rows are covered at the verifier layer by
`test_authz_error_codes_v7_71.py` and reach 401 `authentication_failed`
correctly; the authz rows reach 403; the §1.4 pre-dispatch row is
`test_peers_dimension_outbound_gap.py` / PD-1h. The pre-establishment boundary
was the one surface in the enumeration with no row anywhere, in either
direction — which is what let two call sites inherit a status nobody picked.

One site was walked and deliberately **not** changed: ``peer.py``'s *"No
capability grant for this peer"* refusal, raised during `authenticate` when
`assemble_inbound_grants` returns None. That peer *has* authenticated — the
proof-of-possession steps all passed — and the responder simply grants it
nothing. That is authz-class by §5.2a's own discriminator, so `403` is correct
there, and it is not §4.2's bullet.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
from pathlib import Path

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.peer.http_client import (
    _body_to_envelope,
    _envelope_to_body,
    http_post,
)
from entity_core.protocol.auth import create_identity_entity
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import recv_envelope, send_envelope
from entity_core.protocol.messages import Execute, ExecuteResponse

PORT = 19091

#: §5.2a's row for this input, as the spec spells it. Written out rather than
#: imported from anything of ours: our constant is what was wrong for two
#: releases, and a row that compares our value to our value cannot fail.
RULED_PAIR = (401, "authentication_failed")


@pytest.fixture
async def server_peer():
    peer = (
        PeerBuilder().with_keypair(Keypair.generate())
        .with_default_handlers().debug_mode(True).build()
    )
    await peer.start("127.0.0.1", PORT)
    yield peer
    await peer.stop()


def _pair(response: ExecuteResponse) -> tuple[int, str]:
    return int(response.status), response.result["data"]["code"]


def _non_connect_execute(peer_id: str) -> Execute:
    """A well-formed EXECUTE at a path that is not `system/protocol/connect`.

    Targets the responder's **own** namespace deliberately. §1.4's inbound
    routing gate (PD-1h) refuses a foreign namespace with `400 invalid_request`,
    so a frame naming any other peer could be refused by that gate instead and
    the measurement would not attribute. This is go's own care on their probe
    and it is why their three-way numbers were usable at all.
    """
    return Execute.create(
        uri=f"entity://{peer_id}/system/status",
        operation="get",
    )


async def _send_before_handshake(execute: Execute) -> ExecuteResponse:
    """Open a socket, send one frame, read one response. No hello, ever."""
    reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
    try:
        await send_envelope(writer, Envelope(root=execute.to_entity()))
        return ExecuteResponse.from_entity((await recv_envelope(reader)).root)
    finally:
        writer.close()
        await writer.wait_closed()


# --------------------------------------------------------------------------
# The ruled row, at both wire boundaries
# --------------------------------------------------------------------------


class TestTheRuledPair:
    @pytest.mark.asyncio
    async def test_a_non_connect_execute_before_the_handshake_is_401(
        self, server_peer: Peer
    ) -> None:
        """CE-1 itself. Measured `403 capability_denied` at `827cbe3`."""
        response = await _send_before_handshake(
            _non_connect_execute(server_peer.peer_id)
        )
        assert _pair(response) == RULED_PAIR, (
            "§4.2 bullet 3 routes a frame with no verified signer to §5.2a's "
            "auth class; §5.2a gives 401 `authentication_failed`. A 403 here "
            "claims the caller authenticated and then lacked authority, which "
            f"is false of an input that never authenticated. Got {_pair(response)}"
        )

    @pytest.mark.asyncio
    async def test_the_status_half_is_the_one_that_moved(
        self, server_peer: Peer
    ) -> None:
        """The halves, asserted separately — because a half-fix passes the pair
        row's sibling and not this one.

        `capability_denied` is a real §5.2a code, so a fix that changed only the
        code (401 `capability_denied`) reads as a smaller, safer edit and is a
        pair in no table. The status is what carries the auth/authz class, and
        the class is the whole of what F32 decided.
        """
        response = await _send_before_handshake(
            _non_connect_execute(server_peer.peer_id)
        )
        assert int(response.status) == 401, "auth-class, per §5.2a's discriminator"
        assert response.result["data"]["code"] == "authentication_failed"
        assert response.result["data"]["code"] != "capability_denied", (
            "an authz code under an auth status is the half-fix"
        )

    @pytest.mark.asyncio
    async def test_the_http_boundary_answers_the_same_pair(
        self, server_peer: Peer
    ) -> None:
        """The boundary no probe in the cohort can reach.

        Every conformance probe dials TCP, so this refusal — the HTTP
        transport's own copy — is unmeasurable from outside and would have
        stayed at 403 through any number of green cross-impl runs. It is the
        second of the two hand-rolled copies §4.7 row 10 taught us to look for,
        found by grepping the *gate* (`is_connected`) rather than the site the
        relay named.
        """
        server = server_peer
        http_server = await server.start_http("127.0.0.1", 0)
        bind = http_server.bound_socket()
        assert bind is not None
        url = f"http://{bind[0]}:{bind[1]}/entity"

        envelope = Envelope(root=_non_connect_execute(server.peer_id).to_entity())
        status, _headers, body = await http_post(
            url, _envelope_to_body(envelope),
            headers={"content-type": "application/cbor"},
        )
        assert status == 200, (
            "the refusal rides in the EXECUTE_RESPONSE body; a non-200 HTTP "
            "status would mean the transport refused before the peer saw it"
        )
        response = ExecuteResponse.from_entity(_body_to_envelope(body).root)
        assert _pair(response) == RULED_PAIR, (
            f"the HTTP boundary must not diverge from the TCP one: {_pair(response)}"
        )


class TestTheTwoStatesAgree:
    @pytest.mark.asyncio
    async def test_the_two_states_now_agree_on_the_same_frame(
        self, server_peer: Peer
    ) -> None:
        """One frame, two connection states, one answer — which is the point.

        The input is identical in both halves: an EXECUTE with no author, no
        capability and no signature, at the responder's own `system/status`.
        Nothing about whether a signer was verified changes between the two
        states, so §5.2a's discriminator gives one class for both. This peer
        answered `401` established and `403` pre-establishment — disagreeing
        with itself about the same frame, which no cross-impl check can see
        because each half is individually plausible.
        """
        before = await _send_before_handshake(
            _non_connect_execute(server_peer.peer_id)
        )

        client = await Connection.connect("127.0.0.1", PORT, Keypair.generate())
        try:
            await client.send(
                Envelope(root=_non_connect_execute(server_peer.peer_id).to_entity())
            )
            after = ExecuteResponse.from_entity((await client.recv()).root)
        finally:
            client.close()
            await client.wait_closed()

        assert _pair(before) == _pair(after) == RULED_PAIR, (
            "the same unauthenticated frame must get the same verdict either "
            f"side of the handshake: before={_pair(before)} after={_pair(after)}"
        )


# --------------------------------------------------------------------------
# Attribution — the change is scoped to non-connect EXECUTEs
# --------------------------------------------------------------------------


class TestTheChangeDidNotSmear:
    """Three rows a peer answering "401 for anything pre-establishment" fails,
    and one it fails by having deleted the authz class instead."""

    @pytest.mark.asyncio
    async def test_a_pre_hello_ping_is_still_409(self, server_peer: Peer) -> None:
        """§4.7 row 10's state-conflict arm, in the same state as CE-1.

        `ping` is a connect operation this peer implements, arriving in a state
        that forbids it — `409 connection_sequence_error`, ruled at 0.8.2.4 and
        landed here at `827cbe3`. It is pre-establishment and it is not 401,
        which is the whole discriminator: §4.2's bullet is about EXECUTEs
        targeting *any other path*, and `system/protocol/connect` is the sole
        pre-authorized one.
        """
        response = await _send_before_handshake(
            Execute.create(
                uri=f"entity://{server_peer.peer_id}/system/protocol/connect",
                operation="ping",
                params=Entity(
                    type="system/network/ping",
                    data={"timestamp": 1, "sequence": 1},
                ).to_dict(),
            )
        )
        assert _pair(response) == (409, "connection_sequence_error")

    @pytest.mark.asyncio
    async def test_an_unknown_connect_operation_is_still_400(
        self, server_peer: Peer
    ) -> None:
        """§4.7 row 10's unknown-operation arm, same state. `400 invalid_request`."""
        response = await _send_before_handshake(
            Execute.create(
                uri=f"entity://{server_peer.peer_id}/system/protocol/connect",
                operation="nonesuch",
            )
        )
        assert _pair(response) == (400, "invalid_request")

    @pytest.mark.asyncio
    async def test_a_real_authorization_denial_is_still_403(
        self, server_peer: Peer
    ) -> None:
        """The control without which this file is satisfied by deleting 403.

        Two clients connect; A authors an EXECUTE but presents **B's**
        capability. A is authenticated — signature verifies, author resolves —
        and the capability's grantee is not the author, which is §5.2a's
        *"Capability grantee ≠ EXECUTE author"* row: **403 `capability_denied`**,
        authz-class. This is the arm CE-1's input only *looked* like.

        B's identity entity rides in `included` on purpose. Without it the
        grantee does not resolve and §5.2a's **PR-3 carve-out** answers `401
        `unresolvable_grantee`` instead — measured on this row's first draft.
        That is a structurally-authz failure the spec surfaces as 401 by
        explicit choice, so it would have made this control assert the very
        collapse it exists to rule out, while looking like a passing 401.
        """
        a_kp, b_kp = Keypair.generate(), Keypair.generate()
        a = await Connection.connect("127.0.0.1", PORT, a_kp)
        b = await Connection.connect("127.0.0.1", PORT, b_kp)
        try:
            assert b.capability is not None
            response = await a.execute(
                uri=f"entity://{server_peer.peer_id}/system/status",
                operation="get",
                capability_override=b.capability,
                capability_chain_override=[],
                included=[create_identity_entity(b_kp).to_dict()],
            )
            assert _pair(response) == (403, "capability_denied"), (
                "an authenticated caller presenting someone else's capability "
                "is authz-class; if this went 401 the auth/authz split is gone "
                f"rather than corrected. Got {_pair(response)}"
            )
        finally:
            for conn in (a, b):
                conn.close()
                await conn.wait_closed()


# --------------------------------------------------------------------------
# Structural — the two boundaries cannot diverge again
# --------------------------------------------------------------------------


class TestBothBoundariesShareOneRefusal:
    def test_every_pre_establishment_gate_calls_the_one_helper(self) -> None:
        """Read the source, not the behaviour, and pin the *shape*.

        The behavioural rows above pass on a peer that hand-rolls the response
        at each site and happens to spell both the same way today — which is
        precisely the state §4.7 row 10 was in for months, until the two
        boundaries were found classifying one predicate two different ways.
        There the fix was a shared set; here it is a shared constructor, and
        this row is what makes "shared" an invariant instead of a coincidence.

        The gate is `not conn_state.is_connected`. Every ``if``/``elif`` whose
        test is that expression must reach ``_pre_establishment_refusal`` and
        must not reach ``ExecuteResponse.forbidden``, which is where the 403
        came from and which still correctly serves the authz sites.
        """
        source = Path(inspect.getsourcefile(Peer)).read_text()
        tree = ast.parse(source)

        gates: list[ast.If] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            test = node.test
            if (
                isinstance(test, ast.UnaryOp)
                and isinstance(test.op, ast.Not)
                and isinstance(test.operand, ast.Attribute)
                and test.operand.attr == "is_connected"
            ):
                gates.append(node)

        assert len(gates) == 2, (
            "two boundaries carry this refusal — the TCP frame loop and the "
            "HTTP transport. A third appearing without a shared refusal is the "
            f"divergence this row exists to catch; found {len(gates)}"
        )

        for gate in gates:
            called = {
                n.func.attr
                for n in ast.walk(gate)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            } | {
                n.func.id
                for n in ast.walk(gate)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            }
            assert "_pre_establishment_refusal" in called, (
                f"the gate at line {gate.lineno} builds its own refusal; both "
                "boundaries must share one so they cannot answer differently"
            )
            assert "forbidden" not in called, (
                f"the gate at line {gate.lineno} still reaches "
                "`ExecuteResponse.forbidden`, which hardcodes 403 "
                "`capability_denied` — the pair CE-1 retired"
            )

    def test_the_helper_emits_the_pair_the_spec_declares(self) -> None:
        """The helper's own pair, against §5.2a's literal rather than a call
        site's expectation."""
        from entity_core.peer.peer import _pre_establishment_refusal

        response = _pre_establishment_refusal("req-1")
        # Read pre-serialization: `result` gains its `data` nesting in
        # `to_entity()`, which the wire rows above go through and this one does
        # not. Asserting here as well as on the wire is deliberate — it is the
        # helper's own contract, independent of either boundary calling it.
        assert (int(response.status), response.result["code"]) == RULED_PAIR
        assert response.request_id == "req-1", (
            "the refusal must correlate: §4.1's every-EXECUTE-gets-a-response "
            "is useless to a caller that cannot match it to its request"
        )

    def test_the_retired_codes_appear_nowhere(self) -> None:
        """`connection_required` and `handshake_failed`, which 0.8.2.5 names
        non-conformant by name.

        Neither was ever ours — go minted the first, rust the second — and that
        is exactly why this row is worth having: a code named non-conformant in
        landed text is a thing a later reader could reach for while
        "harmonising" with a sibling, and the ratchet costs one AST walk.
        """
        root = Path(__file__).resolve().parents[2] / "packages"
        offenders = [
            f"{path.relative_to(root)}:{node.lineno}"
            for path in root.rglob("*.py")
            for node in ast.walk(ast.parse(path.read_text()))
            if isinstance(node, ast.Constant)
            and node.value in ("connection_required", "handshake_failed")
        ]
        assert not offenders, (
            "0.8.2.5: `Implementations MUST NOT emit connection_required or "
            f"handshake_failed` — both are minted codes in no spec set: {offenders}"
        )
