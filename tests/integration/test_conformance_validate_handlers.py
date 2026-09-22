"""GUIDE-CONFORMANCE §7a — the two ``system/validate/*`` test handlers.

Real two-peer wire test. The validator (``V``) dials the target peer (``P``)
and has **no listener of its own** — exactly the §7a.2a B-no-listener case.
That makes the dispatch-outbound reentry leg travel back over the same
inbound connection (V7 §6.11(b)), which is the substrate this exercises:

- ``system/validate/echo``: verbatim-echo §7a.1 contract (byte equality
  between ``result.data`` and ``params.data``).
- ``system/validate/dispatch-outbound``: P originates exactly ONE outbound
  EXECUTE back to V's echo over the inbound connection, and V (playing
  B-role on the wire it dialed) serves it.

``V`` is built on a real :class:`Connection` whose demux reader task is
cancelled immediately after the handshake, so the test drives the wire
directly the way the Go validator's background reader does — sending probes
and serving the reentrant echo on the same socket.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from entity_core.capability.grant import Grant, create_capability_token
from entity_core.capability.token import (
    CapabilityScope,
    CapabilityToken,
    MultiGranter,
)
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.auth import (
    create_authenticated_request,
    create_identity_entity,
    create_signature_entity,
)
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import recv_envelope, send_envelope
from entity_core.protocol.messages import Execute, ExecuteResponse
from entity_core.utils.ecf import compute_ecf_hash, ecf_encode
from entity_core.utils.path import extract_handler_path
from entity_handlers.conformance import (
    DISPATCH_OUTBOUND_HANDLER_PATTERN,
    ECHO_HANDLER_PATTERN,
)

#: The operation the F63 discriminator sub-dispatches to prove the
#: narrow-grant refusal. It is deliberately **outside** the
#: `dispatch-outbound` handler's declared grant (which is `echo` only), while
#: the presented credential **does** cover it — so the handler's own grant is
#: the only thing that can refuse. Matches `entity-core-go`'s
#: `reentryOutOfScopeOp` so a shared oracle drives both seats identically.
REENTRY_OUT_OF_SCOPE_OP = "reentry-oos-probe"


class RawValidator:
    """B-role validator on a real Connection with the demux reader disabled.

    The handshake runs through :meth:`Connection.connect` (tested path,
    yields the granted cap + negotiated hash format); the demux reader task
    is then cancelled so this test can read frames itself and serve the
    reentrant echo on the same socket.
    """

    def __init__(self, conn: Connection) -> None:
        self._conn = conn
        self.kp = conn.keypair
        self.cap = conn.capability
        self.chain = conn.capability_chain
        self.active_format = conn.active_hash_format
        self.target_peer_id = conn.session.remote_peer_id
        # The second signer of the E3 K-of-2 root. A distinct identity, so the
        # root is a genuine multi-granter rather than V wearing two hats.
        self._cosigner = Keypair.generate()

    @classmethod
    async def connect(cls, host: str, port: int, keypair: Keypair) -> "RawValidator":
        conn = await Connection.connect(host, port, keypair)
        # Disable the demux reader so we own the read side (the reentry leg
        # delivers an inbound EXECUTE this side must serve — the demux reader
        # would otherwise drop it).
        if conn._reader_task is not None:
            conn._reader_task.cancel()
            try:
                await conn._reader_task
            except (asyncio.CancelledError, Exception):
                pass
            conn._reader_task = None
        return cls(conn)

    @property
    def peer_id(self) -> str:
        return self.kp.peer_id

    async def _send_execute(
        self, uri: str, operation: str, params: dict, *,
        cap: dict | None = None, chain: list | None = None,
    ) -> str:
        execute = Execute.create(uri, operation, params)
        auth = create_authenticated_request(
            self.kp, execute,
            cap if cap is not None else self.cap,
            chain if chain is not None else self.chain,
            algorithm=self.active_format,
        )
        await send_envelope(self._conn.writer, auth.to_envelope())
        return execute.request_id

    async def execute_raw(self, uri: str, operation: str, params) -> ExecuteResponse:
        """One EXECUTE, one EXECUTE_RESPONSE. Used by the rows that drive
        `dispatch-outbound` with a request the reentry helper cannot express
        (no credential at all, or a partial one)."""
        req_id = await self._send_execute(uri, operation, params)
        env = await asyncio.wait_for(recv_envelope(self._conn.reader), timeout=10)
        assert env.root.get("data", {}).get("request_id") == req_id
        return ExecuteResponse.from_entity(env.root)

    async def echo(self, payload, *, operation: str = "echo") -> ExecuteResponse:
        params = Entity(type="primitive/any", data={"value": payload}).to_dict()
        uri = f"entity://{self.target_peer_id}/{ECHO_HANDLER_PATTERN}"
        req_id = await self._send_execute(uri, operation, params)
        env = await asyncio.wait_for(recv_envelope(self._conn.reader), timeout=10)
        assert env.root.get("data", {}).get("request_id") == req_id
        return ExecuteResponse.from_entity(env.root)

    def _mint_reentry_cap(
        self, target_peer_kp: Keypair, operations: list[str] | None = None,
    ):
        """Mint a V-rooted cap granting P the right to call V's echo back.

        granter = V, grantee = P. Scope = system/validate/echo over
        ``operations`` (default ``["echo"]``). A well-formed, properly-rooted
        cap mirroring the validator's ``mintReentryCapForOps`` exactly.

        ``operations`` is a parameter because the F63 discriminator needs ONE
        credential covering **both** the in-scope and the out-of-scope
        operation — that is what makes the handler's narrow grant the only
        variable between the two arms.
        """
        p_identity = create_identity_entity(target_peer_kp)
        grant = Grant(
            handlers=CapabilityScope(include=[ECHO_HANDLER_PATTERN]),
            operations=CapabilityScope(include=operations or ["echo"]),
            resources=CapabilityScope(
                include=[f"/{self.peer_id}/{ECHO_HANDLER_PATTERN}"],
            ),
        )
        return create_capability_token(
            self.kp, p_identity, [grant], expires_in_ms=300_000,
            algorithm=self.active_format,
        )

    def _mint_multisig_reentry_cap(self, target_peer_kp: Keypair):
        """Mint a K-of-2 **multi-signature-rooted** reentry cap (E3).

        Byte-parallel with :meth:`_mint_reentry_cap` — same grants, same
        handler/operation/resource scope, same grantee, same expiry window —
        with **the granter form as the only variable**. That is what makes the
        single-sig arm a true control for the E3 refusal, per §7a.1's second
        ⛔ block and GUIDE-CONFORMANCE §2.4b.

        Signer set is ``[V, cosigner]``, threshold 2 — so the validator (the
        sub-dispatch target) is *among* the signers but is not itself the
        multi-granter. That is precisely the shape 0.8.2.19's §1.4 rule
        refuses: *a root whose signer set merely includes the target does
        not* satisfy the root-granter check.

        Returns ``(cap_dict, [granter_dicts], [signature_dicts])``.
        """
        p_identity = create_identity_entity(target_peer_kp)
        grant = Grant(
            handlers=CapabilityScope(include=[ECHO_HANDLER_PATTERN]),
            operations=CapabilityScope(include=["echo"]),
            resources=CapabilityScope(
                include=[f"/{self.peer_id}/{ECHO_HANDLER_PATTERN}"],
            ),
        )
        v_identity = create_identity_entity(self.kp)
        co_identity = create_identity_entity(self._cosigner)
        signer_hashes = [
            v_identity.compute_hash(), co_identity.compute_hash(),
        ]
        now_ms = int(time.time() * 1000)
        token = CapabilityToken(
            grants=[grant],
            granter=MultiGranter(signers=signer_hashes, threshold=2),
            grantee=p_identity.compute_hash(),
            created_at=now_ms,
            expires_at=now_ms + 300_000,
        )
        cap_dict = token.to_entity()
        cap_hash = compute_ecf_hash(
            {"type": cap_dict["type"], "data": cap_dict["data"]}
        )
        cap_dict = dict(cap_dict)
        cap_dict["content_hash"] = cap_hash
        sigs = [
            create_signature_entity(kp, cap_hash, ih).to_dict(include_hash=True)
            for kp, ih in (
                (self.kp, signer_hashes[0]),
                (self._cosigner, signer_hashes[1]),
            )
        ]
        granters = [
            v_identity.to_dict(include_hash=True),
            co_identity.to_dict(include_hash=True),
        ]
        return cap_dict, granters, sigs

    async def dispatch_outbound(
        self,
        payload,
        target_peer_kp: Keypair,
        *,
        operation: str = "echo",
        cap_operations: list[str] | None = None,
        multisig: bool = False,
    ):
        """Send dispatch-outbound; serve the reentry echo; return (resp, hits).

        ``operation`` is what P is asked to sub-dispatch; ``cap_operations``
        is what the presented credential covers. They are separate parameters
        because F63's whole content is driving them apart.
        """
        if multisig:
            cap_d, granter_ds, sig_ds = self._mint_multisig_reentry_cap(
                target_peer_kp,
            )
        else:
            cap_ent, granter_ent, sig_ent = self._mint_reentry_cap(
                target_peer_kp, cap_operations,
            )
            cap_d = cap_ent.to_dict()
            granter_ds, sig_ds = [granter_ent.to_dict()], [sig_ent.to_dict()]
        data = {
            # P dispatches back to *us* (the validator) over the inbound wire.
            "target": f"entity://{self.peer_id}/{ECHO_HANDLER_PATTERN}",
            "operation": operation,
            "value": payload,
            "reentry_capability": cap_d,
            # §7a.1 plural carriers (0.8.2.19): arrays, single-sig is an
            # array of one.
            "reentry_granters": granter_ds,
            "reentry_cap_signatures": sig_ds,
        }
        params = Entity(type="primitive/any", data=data).to_dict()
        uri = f"entity://{self.target_peer_id}/{DISPATCH_OUTBOUND_HANDLER_PATTERN}"
        req_id = await self._send_execute(uri, "dispatch", params)

        hits = 0
        dispatch_resp: ExecuteResponse | None = None
        # Bounded read loop: expect one inbound reentry EXECUTE then the
        # dispatch-outbound EXECUTE_RESPONSE.
        for _ in range(6):
            env = await asyncio.wait_for(
                recv_envelope(self._conn.reader), timeout=10,
            )
            root = env.root
            mtype = root.get("type", "")
            d = root.get("data", {})
            if mtype == Execute.TYPE:
                # We answer BOTH `echo` and the out-of-scope probe operation
                # verbatim. Answering only `echo` would make a bypassing peer's
                # out-of-scope sub-dispatch fail here, at the validator, rather
                # than at the gate under test — so the F63 row would go green
                # against a peer with no gate at all.
                if (
                    extract_handler_path(d.get("uri", "")) == ECHO_HANDLER_PATTERN
                    and d.get("operation") in ("echo", REENTRY_OUT_OF_SCOPE_OP)
                ):
                    hits += 1
                    # Verbatim echo back over the same connection.
                    resp = ExecuteResponse(
                        request_id=d.get("request_id", ""),
                        status=200,
                        result=d.get("params"),
                    )
                    await send_envelope(
                        self._conn.writer, Envelope(root=resp.to_entity()),
                    )
            elif mtype == ExecuteResponse.TYPE:
                if d.get("request_id") == req_id:
                    dispatch_resp = ExecuteResponse.from_entity(root)
                    break
        assert dispatch_resp is not None, "no dispatch-outbound response received"
        return dispatch_resp, hits

    async def close(self) -> None:
        self._conn.close()
        await self._conn.wait_closed()


@pytest.fixture
async def target_peer():
    """Start P with the §7a handlers + open access on loopback."""
    p_kp = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(p_kp)
        .with_all_handlers()
        .with_conformance_handlers()
        # Open access so the validator's connection cap covers the validate
        # handlers (the authorization concern is orthogonal to §7a).
        .debug_mode(True)
        .build()
    )
    host, port = "127.0.0.1", 19571
    await peer.start(host, port)
    try:
        yield peer, p_kp, host, port
    finally:
        await peer.stop()


async def test_echo_verbatim(target_peer):
    """§7a.1: result.data byte-equals params.data."""
    peer, p_kp, host, port = target_peer
    v = await RawValidator.connect(host, port, Keypair.generate())
    try:
        resp = await v.echo({"hello": "world", "n": 42})
        assert resp.status == 200
        result = resp.result
        assert isinstance(result, dict)
        # The §7a.1 verbatim contract: ECF of result.data equals ECF of the
        # params.data we sent.
        sent = {"value": {"hello": "world", "n": 42}}
        assert ecf_encode(result["data"]) == ecf_encode(sent)
    finally:
        await v.close()


async def test_echo_unsupported_operation(target_peer):
    """A non-echo operation on the echo handler returns 501."""
    peer, p_kp, host, port = target_peer
    v = await RawValidator.connect(host, port, Keypair.generate())
    try:
        resp = await v.echo("x", operation="bogus")
        assert resp.status == 501
        # V7 §3.3: error results are materialized as system/protocol/error;
        # the code lives under .data.
        assert resp.result["type"] == "system/protocol/error"
        assert resp.result["data"]["code"] == "unsupported_operation"
    finally:
        await v.close()


async def test_dispatch_outbound_reentry(target_peer):
    """§7a.2a: P originates exactly one reentry EXECUTE over the inbound wire."""
    peer, p_kp, host, port = target_peer
    v = await RawValidator.connect(host, port, Keypair.generate())
    try:
        resp, hits = await v.dispatch_outbound("reentry-payload", p_kp)
        assert resp.status == 200, f"dispatch-outbound status {resp.status}: {resp.result}"
        # §7a.1: exactly one outbound EXECUTE.
        assert hits == 1, f"expected exactly one reentry, got {hits}"
        # Result is primitive/any wrapping {status, result}; downstream echo
        # must have returned 200.
        inner = resp.result["data"]
        assert inner["status"] == 200
    finally:
        await v.close()


async def test_dispatch_outbound_ambient_at_a_foreign_peer_is_refused(target_peer):
    """0.8.2.17 §9.1's **negative** arm, over the wire — the half of the
    two-arm row that is new and that a peer is red on until it builds it.

    *Drive `system/validate/dispatch-outbound` at a foreign peer presenting no
    capability → MUST refuse.* `test_dispatch_outbound_reentry` above is the
    positive arm and has been green since §7a landed; arch's phrasing is the
    reason both live here: *"a check that only exercises the refusal passes on
    a peer that refuses everything."*

    .. rubric:: Why the handler had to change for this row to mean anything

    Omitting the three §7a.2a in-band authority fields used to be a `400
    invalid_params` — a refusal, at param validation, before any dispatch was
    attempted. A probe cannot tell that apart from Dimension 4 doing its job,
    which is the attribution trap this repo has hit from the other side (a
    control that makes a measurement attributable also stops it covering the
    neighbour). The three fields are now optional as a set, and the refusal
    the probe sees is relayed as `403 capability_denied` rather than wrapped
    in the generic `502`.

    The `403` is therefore asserted as a **pair with its code**, and the
    positive arm's `200` is asserted beside it, because a peer answering the
    same thing to both inputs has one gate, not two.
    """
    peer, p_kp, host, port = target_peer
    v = await RawValidator.connect(host, port, Keypair.generate())
    try:
        data = {
            "target": f"entity://{v.peer_id}/{ECHO_HANDLER_PATTERN}",
            "operation": "echo",
            "value": "ambient-payload",
            # No reentry_capability / reentry_granter / reentry_cap_signature.
        }
        params = Entity(type="primitive/any", data=data).to_dict()
        uri = f"entity://{v.target_peer_id}/{DISPATCH_OUTBOUND_HANDLER_PATTERN}"
        resp = await v.execute_raw(uri, "dispatch", params)

        assert resp.status == 403, (
            f"ambient outbound sub-dispatch at a foreign peer was not refused "
            f"(status={resp.status}, result={resp.result}) — §1.4 PD-2's "
            "negative arm is unarmed on the wire"
        )
        assert resp.result["type"] == "system/protocol/error"
        assert resp.result["data"]["code"] == "capability_denied"
    finally:
        await v.close()


@pytest.mark.parametrize(
    "drop",
    ["reentry_capability", "reentry_granters", "reentry_cap_signatures"],
)
async def test_dispatch_outbound_rejects_a_partial_credential(target_peer, drop):
    """Some of the three carriers and not others is a malformed request.

    The set is optional; the members are not individually optional. Without
    this row, a probe that drops one field by accident silently gets the
    ambient arm and reads its refusal as the negative arm passing.

    **Parametrized over which carrier is missing**, because the check is a
    three-term conjunction and a peer that reads `present` off the capability
    alone passes the `reentry_capability`-dropped row while silently
    discarding a caller's granters. One row per term or the conjunction is
    only tested on one of its arms — which is the arm the fixture author
    happens to type.
    """
    peer, p_kp, host, port = target_peer
    v = await RawValidator.connect(host, port, Keypair.generate())
    try:
        cap_ent, granter_ent, sig_ent = v._mint_reentry_cap(p_kp)
        data = {
            "target": f"entity://{v.peer_id}/{ECHO_HANDLER_PATTERN}",
            "operation": "echo",
            "value": "partial",
            "reentry_capability": cap_ent.to_dict(),
            "reentry_granters": [granter_ent.to_dict()],
            "reentry_cap_signatures": [sig_ent.to_dict()],
        }
        del data[drop]
        params = Entity(type="primitive/any", data=data).to_dict()
        uri = f"entity://{v.target_peer_id}/{DISPATCH_OUTBOUND_HANDLER_PATTERN}"
        resp = await v.execute_raw(uri, "dispatch", params)

        assert resp.status == 400, (
            f"dropping {drop} was not treated as malformed (status "
            f"{resp.status}) — a partial credential is not ambient (§7a.1)"
        )
        assert resp.result["data"]["code"] == "invalid_params"
    finally:
        await v.close()


async def test_dispatch_outbound_accepts_an_empty_array_as_absent(target_peer):
    """An empty plural carrier is the *partial* case, not the ambient one.

    `reentry_capability` present with `reentry_granters: []` is a caller who
    meant to present authority and supplied none. Reading an empty array as
    "omitted" would route it to the ambient arm, where its `403` is
    indistinguishable from Dimension 4 refusing — the attribution trap the
    ambient arm was widened to avoid in the first place.
    """
    peer, p_kp, host, port = target_peer
    v = await RawValidator.connect(host, port, Keypair.generate())
    try:
        cap_ent, _g, sig_ent = v._mint_reentry_cap(p_kp)
        data = {
            "target": f"entity://{v.peer_id}/{ECHO_HANDLER_PATTERN}",
            "operation": "echo",
            "value": "empty-array",
            "reentry_capability": cap_ent.to_dict(),
            "reentry_granters": [],
            "reentry_cap_signatures": [sig_ent.to_dict()],
        }
        params = Entity(type="primitive/any", data=data).to_dict()
        uri = f"entity://{v.target_peer_id}/{DISPATCH_OUTBOUND_HANDLER_PATTERN}"
        resp = await v.execute_raw(uri, "dispatch", params)

        assert resp.status == 400
        assert resp.result["data"]["code"] == "invalid_params"
    finally:
        await v.close()


class TestTheNarrowGrantDiscriminator:
    """F63 — the compose-vs-bypass vector, on the wire.

    §1.4's outbound gate composes two authorities: the executing handler's
    grant (Dimensions 1-3) and a target-minted credential (Dimension 4). The
    two vectors everyone writes — *both agree → allow* and *neither → refuse*
    — are precisely the two that **cannot** tell a compose from a bypass.
    `test_dispatch_outbound_reentry` and
    `test_dispatch_outbound_ambient_at_a_foreign_peer_is_refused` above are
    those two, and they were green through the entire life of the F67 bypass.

    The discriminator is the input that belongs to **both** arms at once: a
    valid credential covering the request, presented to a handler whose own
    grant does not cover it. It is unconstructible against a wide grant, which
    is why §7a.1's ⛔ narrow grant is a scaffold requirement rather than
    hardening — see `dispatch_outbound_narrow_grant`.
    """

    async def test_in_scope_and_out_of_scope_differ_on_one_credential(
        self, target_peer,
    ):
        """Both arms, one credential covering both operations.

        The credential is minted over ``[echo, reentry-oos-probe]``, so it
        authorizes **both** sub-dispatches on its own four dimensions. The
        only thing that differs between the arms is whether the
        *dispatch-outbound handler's own grant* covers the operation.

        The in-scope arm is the antecedent (§2.4b): if it does not return 200
        with exactly one reentry, the credential family is not valid+covering
        at this seat and the refusal below would measure nothing. Asserting
        the refusal alone is the deny-only shape that goes green cohort-wide
        having measured nothing at all.
        """
        peer, p_kp, host, port = target_peer
        v = await RawValidator.connect(host, port, Keypair.generate())
        try:
            both = ["echo", REENTRY_OUT_OF_SCOPE_OP]

            # ANTECEDENT — in-scope: the narrow grant covers `echo`, the
            # credential relaxes Dimension 4, the sub-dispatch lands.
            resp_in, hits_in = await v.dispatch_outbound(
                "f63-in-scope", p_kp, operation="echo", cap_operations=both,
            )
            assert resp_in.status == 200, (
                f"the in-scope control failed (status {resp_in.status}: "
                f"{resp_in.result}) — the credential is not valid+covering "
                "at this seat, so the out-of-scope refusal below is "
                "unattributable and this row measures nothing"
            )
            assert hits_in == 1, (
                f"in-scope control reached the sub-dispatched handler "
                f"{hits_in} times, expected exactly 1"
            )
            assert resp_in.result["data"]["status"] == 200

            # DISCRIMINATOR — out-of-scope: the SAME credential covers this
            # operation, and the handler's own grant does not. MUST refuse,
            # and MUST NOT reach the sub-dispatched handler.
            resp_oos, hits_oos = await v.dispatch_outbound(
                "f63-out-of-scope", p_kp,
                operation=REENTRY_OUT_OF_SCOPE_OP, cap_operations=both,
            )
            assert resp_oos.status != 200, (
                "BYPASS: a target-minted credential authorized an operation "
                "outside the dispatch-outbound handler's own grant. §1.4 "
                "0.8.2.19: the target answers WHERE, the handler's grant "
                "answers WHAT (§6.8) — a credential is not a grant."
            )
            # §7a.1a — and it is refused as an AUTHORIZATION verdict, not as a
            # transport fault. This arm answered `502 reentry_dispatch_failed`
            # until 2026-09-10: the ambient arm forty lines up in the same
            # handler already relayed `403 capability_denied` **and carried
            # the argument for it**, so one function was disagreeing with
            # itself about what one gate decided. A scaffold that wraps every
            # unsuccessful sub-dispatch in one generic failure launders an
            # authorization verdict into a transport fault, and the negative
            # arm becomes unattributable a second time — §2.4b's
            # unattributability one layer over: the property holds perfectly
            # and the wire cannot say so.
            assert resp_oos.status == 403, (
                f"the out-of-scope refusal surfaced status "
                f"{resp_oos.status}, not 403. §3.3 normalizes an "
                "authorization refusal's code regardless of which pipeline "
                "layer detected it, precisely so a caller cannot read a "
                "peer's internal layering off its error codes"
            )
            assert resp_oos.result["data"]["code"] == "capability_denied", (
                f"the out-of-scope refusal surfaced code "
                f"{resp_oos.result['data'].get('code')!r}. A §1.4 outbound "
                "refusal is an authorization DENY whichever dimension raised "
                "it (§7a.1a)"
            )
            assert hits_oos == 0, (
                f"BYPASS: the out-of-scope sub-dispatch REACHED the "
                f"sub-dispatched handler ({hits_oos} hits). A refusal that "
                "arrives after the request landed is not a refusal."
            )
        finally:
            await v.close()

    async def test_the_handler_grant_really_is_narrow(self, target_peer):
        """The enabler, asserted structurally rather than inferred.

        If this peer ever registers `dispatch-outbound` under §6.2's wide
        default self-grant again, the row above goes green **for the wrong
        reason** — a wide grant makes compose and bypass agree on every input,
        so there is nothing left to discriminate. That failure is silent at
        the behavioural rows, so it is pinned here at the grant itself.
        """
        peer, p_kp, host, port = target_peer
        grant = peer._get_handler_grant(DISPATCH_OUTBOUND_HANDLER_PATTERN)
        assert grant is not None, (
            "dispatch-outbound has no handler grant at all; §1.4's "
            "Dimensions 1-3 have nothing to gate on"
        )
        entries = grant["grants"]
        assert entries, "the narrow grant is empty"
        for entry in entries:
            assert entry["operations"]["include"] == ["echo"], (
                f"dispatch-outbound's grant covers {entry['operations']} — "
                "§7a.1's ⛔ requires a fixed, declared operation set. A wide "
                "grant makes the F63 discriminator unconstructible."
            )
            assert entry["handlers"]["include"] == [ECHO_HANDLER_PATTERN]
            # `peers` OMITTED: Dimension 4 for the reentry direction comes
            # from the caller-minted credential, never from this grant.
            assert "peers" not in entry, (
                "the scaffold grant carries a `peers` scope — that re-opens "
                "on Dimension 4 what the narrow handler/operation scope "
                "closes on 1-2"
            )


class TestTheMultiSigRootIsRefusedOnTheWire:
    """E3 — §1.4's multi-signature-root rule, driven over the wire.

    *A K-of-N root satisfies the root-granter check only when the target
    peer's identity is the multi-granter itself; a root whose signer set
    merely includes the target does not.*

    This vector is **the reason the carriers went plural**: a K-of-2 root
    needs two granter identities and two signatures, and a singular carrier
    cannot express the input. Every seat drove this rule in-process only —
    where a mutation proves your own gate and says nothing about the cohort's.

    .. rubric:: ⚠ At THIS seat the row passes fail-closed-by-absence, and the
       wire vector cannot tell that apart from the rule

    Measured: neutering the §1.4 root-granter rule
    (``is_multi_granter(root_granter) and peer_of(root_granter) != target_peer``
    in ``_presented_credential_relaxes_peers``) leaves this class **13/13
    green**. The reason is documented in
    ``test_outbound_sub_dispatch_authorization_pd2.py``'s
    ``TestTheMultiGranterRootIsFailClosed``: the outbound gate calls
    ``verify_capability_chain`` with **no** ``find_signature_by_signer``, so
    the walk refuses *every* multi-signature root one layer earlier —
    including one where the target genuinely IS the multi-granter. The rule is
    correct and currently **unreachable**.

    So the spec property holds here and this row measures it honestly, but the
    **mechanism** is broader than the rule, and a refusal is a refusal on the
    wire. `entity-core-go`'s portable oracle will therefore score this seat
    PASS on ``dispatch_outbound_multisig_root_refused`` **for a reason that is
    not the rule it names** — the standing *"a detector is only
    mutation-verified on the peer you mutated"* law, with go's oracle as the
    detector and us as the seat it reports green. Stated here rather than left
    for the three-way to imply.

    The row that *does* isolate the rule is
    ``test_a_k_of_n_root_whose_signers_include_the_target_relaxes_nothing``
    (chain verification forced to succeed), and the reachability row beside it
    goes red the day a by-signer finder is wired in.
    """

    async def test_multisig_root_does_not_relax_dimension_4(self, target_peer):
        """Deny, **with its single-signature antecedent** (§2.4b).

        A credential invalid for any unrelated reason — a malformed
        multi-granter, a signature over the wrong bytes, a grantee mismatch, a
        resource that does not cover — is refused by every conformant peer for
        that reason, and a deny-only row goes green having measured nothing.
        The single-sig arm below is byte-parallel with the multi-sig one
        except the granter form, so it establishes that the credential family
        is valid and covering at this seat.
        """
        peer, p_kp, host, port = target_peer
        v = await RawValidator.connect(host, port, Keypair.generate())
        try:
            # ANTECEDENT — single-signature, target-minted, covering.
            resp_single, hits_single = await v.dispatch_outbound(
                "e3-single-sig", p_kp, operation="echo",
            )
            assert resp_single.status == 200, (
                f"the single-sig control failed (status "
                f"{resp_single.status}: {resp_single.result}) — the "
                "credential family is not valid+covering at this seat, so "
                "the multi-sig refusal below would measure nothing"
            )
            assert hits_single == 1

            # THE RULE — K-of-2 root over the identical request. The target
            # is among the signers but is not the multi-granter.
            resp_multi, hits_multi = await v.dispatch_outbound(
                "e3-multi-sig", p_kp, operation="echo", multisig=True,
            )
            assert resp_multi.status != 200, (
                "OVER-ACCEPTANCE: a K-of-2 multi-signature-rooted credential "
                "relaxed Dimension 4 and the sub-dispatch SUCCEEDED, while "
                "the single-sig control over the identical request also "
                "succeeded — the granter form is the only variable, so the "
                "multi-sig root wrongly authorized (§1.4, 0.8.2.19)"
            )
            assert hits_multi == 0, (
                f"the multi-sig sub-dispatch REACHED the sub-dispatched "
                f"handler ({hits_multi} hits)"
            )
        finally:
            await v.close()


async def test_presence_probe_paths(target_peer):
    """The validator's tree-get presence probe paths exist when opted in."""
    peer, p_kp, host, port = target_peer
    tree = peer.entity_tree
    for pattern in (ECHO_HANDLER_PATTERN, DISPATCH_OUTBOUND_HANDLER_PATTERN):
        uri = tree.normalize_uri(f"system/handler/{pattern}")
        assert tree.get(uri) is not None, f"missing manifest at system/handler/{pattern}"


def test_handlers_off_by_default():
    """Without the opt-in, the §7a handlers are not registered."""
    peer = (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_all_handlers()
        .build()
    )
    tree = peer.entity_tree
    for pattern in (ECHO_HANDLER_PATTERN, DISPATCH_OUTBOUND_HANDLER_PATTERN):
        uri = tree.normalize_uri(f"system/handler/{pattern}")
        assert tree.get(uri) is None, f"{pattern} present without --validate opt-in"
