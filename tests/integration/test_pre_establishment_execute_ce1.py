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
from entity_core.handlers.connect import ADVERTISED_PROTOCOLS
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
from entity_core.utils.ecf import (
    DEFAULT_ADVERTISED_KEY_TYPES,
    default_advertised_hash_formats,
)

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


# --------------------------------------------------------------------------
# The two rows arch reported as never driven against this seat
# --------------------------------------------------------------------------


class TestTheTwoRowsNobodyDrove:
    """`ROUTING-2026-09-03-a` §5.2, verbatim: *"Two rows unmeasured at your
    seat, both cheap: a pre-establishment **foreign-namespace** EXECUTE (→ `400
    invalid_request`), and an unauthenticated **post-handshake `ping`** (→ must
    be served). Neither has ever been driven against py."*

    Both claims were correct, and the pair of them is the shape worth naming.
    **They are the two arms adjacent to rows this seat had just fixed**, one on
    each side:

    * CE-1's own row deliberately targets the responder's **own** namespace so
      the measurement attributes (the §1.4 gate would otherwise refuse first).
      That care is what leaves the foreign arm undriven — *the control that
      makes a measurement attributable is also what stops it covering the
      neighbour.*
    * `827cbe3` fixed the **pre-hello** `ping` and this file already asserts it.
      The **post-hello** arm is the far side of a handshake a probe writes as
      setup, which is the standing "a probe family's blind spot is the seat the
      prober sits in" finding — here reaching us as our own blind spot rather
      than a sibling's.
    """

    @pytest.mark.asyncio
    async def test_a_pre_establishment_foreign_namespace_execute_is_400(
        self, server_peer: Peer
    ) -> None:
        """0.8.2.6 Q1: **address is evaluated before authentication.**

        The deciding argument is 0.8.2.4's own: a `401` directs the caller to
        authenticate and retry, and for a foreign address that retry cannot
        succeed at any authentication state — so the `401` names a remedy that
        does not exist. This is therefore NOT CE-1's row even though the
        connection state is identical; the §1.4 canonicalization gate answers
        first, and that ordering is the ruling.
        """
        response = await _send_before_handshake(
            Execute.create(
                uri="entity://someone-elses-peer-id/system/status",
                operation="get",
            )
        )
        assert _pair(response) == (400, "invalid_request"), (
            "§1.4 / §5.2a: a foreign namespace is refused at canonicalization, "
            "ahead of §4.2's pre-authorization bullet — a 401 here would name a "
            f"remedy no authentication state can reach. Got {_pair(response)}"
        )

    @pytest.mark.asyncio
    async def test_the_foreign_arm_and_the_local_arm_do_not_collapse(
        self, server_peer: Peer
    ) -> None:
        """The discriminator, because both rows are pre-establishment refusals.

        A peer that answered `400 invalid_request` to everything before the
        handshake passes the row above and fails this one; a peer that answered
        `401` to everything passes CE-1's row and fails the one above. Only the
        pair of answers shows the two gates are both present and correctly
        ordered.
        """
        foreign = await _send_before_handshake(
            Execute.create(
                uri="entity://someone-elses-peer-id/system/status",
                operation="get",
            )
        )
        local = await _send_before_handshake(
            _non_connect_execute(server_peer.peer_id)
        )
        assert _pair(foreign) != _pair(local), (
            "the §1.4 address gate and §4.2's pre-authorization bullet are two "
            f"gates; one answer for both inputs means one of them is missing: "
            f"foreign={_pair(foreign)} local={_pair(local)}"
        )
        assert _pair(foreign) == (400, "invalid_request")
        assert _pair(local) == RULED_PAIR

    @pytest.mark.asyncio
    async def test_the_http_boundary_answers_the_foreign_arm_too(
        self, server_peer: Peer
    ) -> None:
        """The gap the mutation run found in this file's own coverage.

        Disarming the address gate reds two rows; removing `uri=` from the
        **HTTP** call site reds nothing, because the existing HTTP row uses the
        responder's own namespace and this class's foreign rows are TCP-only.
        That is precisely the two-hand-rolled-copies shape `_pre_establishment_
        refusal`'s docstring exists to prevent, reappearing as a **test-side**
        asymmetry one commit after the code-side one was closed: the refusal is
        shared, and the coverage of it was not.

        No cohort probe dials HTTP, so without this row the HTTP boundary could
        drift back to a 401 through any number of green cross-impl runs.
        """
        http_server = await server_peer.start_http("127.0.0.1", 0)
        bind = http_server.bound_socket()
        assert bind is not None
        url = f"http://{bind[0]}:{bind[1]}/entity"

        envelope = Envelope(
            root=Execute.create(
                uri="entity://someone-elses-peer-id/system/status",
                operation="get",
            ).to_entity()
        )
        status, _headers, body = await http_post(
            url, _envelope_to_body(envelope),
            headers={"content-type": "application/cbor"},
        )
        assert status == 200, "the refusal rides in the EXECUTE_RESPONSE body"
        response = ExecuteResponse.from_entity(_body_to_envelope(body).root)
        assert _pair(response) == (400, "invalid_request"), (
            "the HTTP boundary must order address-before-auth exactly as the "
            f"TCP one does: {_pair(response)}"
        )

    @pytest.mark.asyncio
    async def test_an_unsigned_ping_on_an_established_connection_is_SERVED(
        self, server_peer: Peer
    ) -> None:
        """Arch's Q2, ruled against `entity-core-rust` and in go's favour.

        §3.2 excepts *"requests targeting the connection path (§4)"* from the
        `author`/`capability` MUST **with no state qualifier**, and §5.1 is
        scoped to *"every **authenticated** EXECUTE"* — a class §3.2 defines by
        **excluding** the connection path. rust read §5.1 as the general rule
        with §4.2 as its exception; it is the other way round, so go's
        `pingServedOnceEstablished` is correct as written and was explicitly
        told not to change.

        .. rubric:: Which "unauthenticated" this row means, because the first
           draft got it wrong

        Written first against a socket that completed **`hello` only**. That
        peer answers `409 connection_sequence_error`, and reading the commit
        summaries it looked like a defect. Reading the ruling itself does not
        support that: its security leg is *"by the time the connection is
        established **both peers have authenticated** (§4.6) and the frame
        arrives on that authenticated connection"*, and the objection it
        answers is that per-frame author/capability would re-prove *"at every
        keepalive, an identity the connection already carries."*

        So the ruled subject is a **frame-level** unauthenticated ping on a
        **fully established** connection — not a ping on a half-open handshake,
        which is §4.7 row 10's ordering rule and stays `409`. Two different
        senses of "unauthenticated", and the routed one-line summary
        (*"unauthenticated post-handshake ping → must be served"*) is true under
        both. The standing *"open the ruling, not the packet that tabulates
        it"* rule, reaching a summary arch wrote about its own ruling.
        """
        client = await Connection.connect("127.0.0.1", PORT, Keypair.generate())
        try:
            assert client.remote_peer_id == server_peer.peer_id, (
                "control: `Connection.connect` completes hello AND "
                "authenticate, so a session exists — without it this row is "
                "the half-open 409 case below, not Q2's"
            )
            ping = Execute.create(
                uri=f"entity://{server_peer.peer_id}/system/protocol/connect",
                operation="ping",
                params=Entity(
                    type="system/network/ping",
                    data={"timestamp": 1, "sequence": 1},
                ).to_dict(),
            )
            # Sent as a bare envelope rather than through `client.execute`, so
            # the frame carries **no** `author`, `capability` or signature.
            # That is the whole input: a signed ping would measure nothing,
            # because §5.1 is satisfied and the exception never fires.
            assert "author" not in ping.to_entity()["data"]
            await client.send(Envelope(root=ping.to_entity()))
            response = ExecuteResponse.from_entity((await client.recv()).root)
        finally:
            client.close()
            await client.wait_closed()

        assert int(response.status) == 200, (
            "§3.2 excepts the connection path from author/capability with no "
            "state qualifier, and §5.1 binds only the *authenticated* EXECUTE "
            "class. An unsigned ping on an established connection MUST be "
            f"served; got {int(response.status)} "
            f"{(response.result or {}).get('data', {}).get('code', '')!r}"
        )

    @pytest.mark.asyncio
    async def test_a_post_hello_pre_authenticate_ping_is_still_409(
        self, server_peer: Peer
    ) -> None:
        """The state the ruling does NOT cover, pinned so it stays deliberate.

        Between `hello` and `authenticate` the connection is half-open: §4.7
        row 10's ordering rule applies and `ping` *"requires an established
        connection"*. This peer answers `409 connection_sequence_error`, which
        is the same answer it gives pre-hello and is consistent with the row.

        Recorded because it is the state the routed summary's wording reaches
        and the ruling's argument does not, and because a later reader
        "completing" Q2 could sweep it to 200 on the strength of that summary —
        which would serve a keepalive on a connection whose peer has not proved
        anything. **Routed to arch as the arm 0.8.2.6 leaves unstated.**
        """
        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        try:
            keypair = Keypair.generate()
            hello = Execute.create(
                uri=f"entity://{server_peer.peer_id}/system/protocol/connect",
                operation="hello",
                params=Entity(
                    type="system/protocol/connect/hello",
                    data={
                        "peer_id": keypair.peer_id,
                        "nonce": b"\x11" * 32,
                        "protocols": list(ADVERTISED_PROTOCOLS),
                        "hash_formats": default_advertised_hash_formats(),
                        "key_types": list(DEFAULT_ADVERTISED_KEY_TYPES),
                    },
                ).to_dict(),
            )
            await send_envelope(writer, Envelope(root=hello.to_entity()))
            hello_response = ExecuteResponse.from_entity(
                (await asyncio.wait_for(recv_envelope(reader), timeout=5.0)).root
            )
            assert int(hello_response.status) == 200, (
                "control: the hello must succeed, or this is the pre-hello "
                f"state and the row below measures nothing new ({hello_response.status})"
            )

            ping = Execute.create(
                uri=f"entity://{server_peer.peer_id}/system/protocol/connect",
                operation="ping",
                params=Entity(
                    type="system/network/ping",
                    data={"timestamp": 1, "sequence": 1},
                ).to_dict(),
            )
            await send_envelope(writer, Envelope(root=ping.to_entity()))
            response = ExecuteResponse.from_entity(
                (await asyncio.wait_for(recv_envelope(reader), timeout=5.0)).root
            )
        finally:
            writer.close()
            await writer.wait_closed()

        assert _pair(response) == (409, "connection_sequence_error"), (
            "the half-open state is §4.7 row 10's ordering rule, not Q2's "
            f"pre-authorization rule; got {_pair(response)}"
        )
