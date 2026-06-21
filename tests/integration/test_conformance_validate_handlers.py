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

import pytest

from entity_core.capability.grant import Grant, create_capability_token
from entity_core.capability.token import CapabilityScope
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.auth import (
    create_authenticated_request,
    create_identity_entity,
)
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import recv_envelope, send_envelope
from entity_core.protocol.messages import Execute, ExecuteResponse
from entity_core.utils.ecf import ecf_encode
from entity_core.utils.path import extract_handler_path
from entity_handlers.conformance import (
    DISPATCH_OUTBOUND_HANDLER_PATTERN,
    ECHO_HANDLER_PATTERN,
)


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

    async def echo(self, payload, *, operation: str = "echo") -> ExecuteResponse:
        params = Entity(type="primitive/any", data={"value": payload}).to_dict()
        uri = f"entity://{self.target_peer_id}/{ECHO_HANDLER_PATTERN}"
        req_id = await self._send_execute(uri, operation, params)
        env = await asyncio.wait_for(recv_envelope(self._conn.reader), timeout=10)
        assert env.root.get("data", {}).get("request_id") == req_id
        return ExecuteResponse.from_entity(env.root)

    def _mint_reentry_cap(self, target_peer_kp: Keypair):
        """Mint a V-rooted cap granting P the right to call V's echo back.

        granter = V, grantee = P. Scope = system/validate/echo:echo. The
        substrate does not verify this cap on the reentry leg (V's echo just
        matches URI+op), but a well-formed, properly-rooted cap mirrors the
        validator's MintReentryCapability exactly.
        """
        p_identity = create_identity_entity(target_peer_kp)
        grant = Grant(
            handlers=CapabilityScope(include=[ECHO_HANDLER_PATTERN]),
            operations=CapabilityScope(include=["echo"]),
            resources=CapabilityScope(
                include=[f"/{self.peer_id}/{ECHO_HANDLER_PATTERN}"],
            ),
        )
        return create_capability_token(
            self.kp, p_identity, [grant], expires_in_ms=300_000,
            algorithm=self.active_format,
        )

    async def dispatch_outbound(self, payload, target_peer_kp: Keypair):
        """Send dispatch-outbound; serve the reentry echo; return (resp, hits)."""
        cap_ent, granter_ent, sig_ent = self._mint_reentry_cap(target_peer_kp)
        data = {
            # P dispatches back to *us* (the validator) over the inbound wire.
            "target": f"entity://{self.peer_id}/{ECHO_HANDLER_PATTERN}",
            "operation": "echo",
            "value": payload,
            "reentry_capability": cap_ent.to_dict(),
            "reentry_granter": granter_ent.to_dict(),
            "reentry_cap_signature": sig_ent.to_dict(),
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
                if (
                    extract_handler_path(d.get("uri", "")) == ECHO_HANDLER_PATTERN
                    and d.get("operation") == "echo"
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
