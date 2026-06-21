"""HTTP live transport client — POST EXECUTE / EXECUTE-RESPONSE.

Per EXTENSION-NETWORK §6.5.2c (v1.4 Amendment 2) + Chunk D. Counterpart
to ``http_server.HttpServer``. Performs the V7 connect handshake over
HTTP (one POST per envelope, threaded by the ``X-Entity-Session``
header), then dispatches authenticated EXECUTEs.

Stdlib-only: implements a minimal async HTTP/1.1 client on top of
``asyncio.open_connection``. No new dependency.

Scheme support:
- ``http://`` — cleartext, suitable for localhost / dev / TLS-terminating
  reverse proxy in front of the listener.
- ``https://`` — TLS via stdlib ``ssl.create_default_context()``. For
  self-signed dev certs, pass a custom ``SSLContext`` to ``HttpConnection``.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Any
from urllib.parse import urlparse

from entity_core.crypto.identity import Keypair
from entity_core.handlers.connect import (
    ConnectError,
    create_connect_authenticate_execute,
    create_connect_hello_execute,
    verify_connect_authenticate_response,
)
from entity_core.peer.session import Session
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import (
    FramingError,
    MAX_MESSAGE_SIZE,
    validate_entity_hash,
)
from entity_core.protocol.messages import (
    Execute,
    ExecuteResponse,
    ResourceTarget,
)
from entity_core.protocol.auth import create_authenticated_request
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    default_advertised_hash_formats,
    ecf_decode,
    ecf_encode,
    negotiate_active_hash_format,
)

logger = logging.getLogger(__name__)

SESSION_HEADER = "x-entity-session"
CONTENT_TYPE_CBOR = "application/cbor"
DEFAULT_REQUEST_TIMEOUT_SECONDS = 30.0

_HEADER_READ_LIMIT = 16 * 1024


async def _read_response_head(
    reader: asyncio.StreamReader, limit: int
) -> tuple[bytes, bytes]:
    """Read through the `\\r\\n\\r\\n` HTTP response head terminator.

    Returns ``(head_with_terminator, body_prefix)``. The body prefix is
    whatever bytes overran into the response body and need to be
    consumed before reading the rest per Content-Length.
    """
    out = bytearray()
    while True:
        idx = out.find(b"\r\n\r\n")
        if idx >= 0:
            return bytes(out[: idx + 4]), bytes(out[idx + 4:])
        if len(out) >= limit:
            raise FramingError(
                f"HTTP response head exceeds limit ({limit} bytes)"
            )
        chunk = await reader.read(min(4096, limit - len(out)))
        if not chunk:
            raise FramingError(
                "connection closed before HTTP response head terminator"
            )
        out.extend(chunk)


async def http_post(
    url: str,
    body: bytes,
    *,
    headers: dict[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
    timeout: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, str], bytes]:
    """Minimal async HTTP/1.1 POST.

    Returns:
        (status, response headers (lowercase keys), response body).

    Raises:
        ValueError: unsupported URL scheme.
        FramingError: malformed HTTP response.
        asyncio.TimeoutError: response did not arrive within ``timeout``.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme!r}")

    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    open_kwargs: dict[str, Any] = {}
    if parsed.scheme == "https":
        open_kwargs["ssl"] = ssl_context or ssl.create_default_context()

    async def _do() -> tuple[int, dict[str, str], bytes]:
        reader, writer = await asyncio.open_connection(host, port, **open_kwargs)
        try:
            full_headers = {
                "host": parsed.netloc or host,
                "content-length": str(len(body)),
                "connection": "close",
            }
            if headers:
                for k, v in headers.items():
                    full_headers[k.lower()] = v

            request_head = (
                f"POST {path} HTTP/1.1\r\n"
                + "".join(f"{k}: {v}\r\n" for k, v in full_headers.items())
                + "\r\n"
            ).encode("ascii")
            writer.write(request_head + body)
            await writer.drain()

            head, body_prefix = await _read_response_head(reader, _HEADER_READ_LIMIT)

            lines = head[:-4].decode("ascii", errors="replace").split("\r\n")
            status_line = lines[0].split(" ", 2)
            if len(status_line) < 2:
                raise FramingError(f"malformed HTTP status line: {lines[0]!r}")
            try:
                status = int(status_line[1])
            except ValueError as exc:
                raise FramingError(f"non-integer status code: {status_line!r}") from exc

            resp_headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()

            content_length_raw = resp_headers.get("content-length", "0")
            try:
                content_length = int(content_length_raw)
            except ValueError:
                raise FramingError(
                    f"non-integer Content-Length: {content_length_raw!r}"
                )
            if content_length > MAX_MESSAGE_SIZE:
                raise FramingError(
                    f"response body too large: {content_length} (max {MAX_MESSAGE_SIZE})"
                )
            response_body = bytearray(body_prefix)
            remaining = content_length - len(response_body)
            if remaining > 0:
                response_body.extend(await reader.readexactly(remaining))
            elif remaining < 0:
                # Body overran Content-Length; treat as malformed.
                raise FramingError(
                    f"body overran Content-Length: got {len(response_body)}, declared {content_length}"
                )
            return status, resp_headers, bytes(response_body)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    return await asyncio.wait_for(_do(), timeout=timeout)


def _envelope_to_body(envelope: Envelope) -> bytes:
    """ECF-encode an envelope into a CBOR HTTP body (no length prefix)."""
    payload = ecf_encode(envelope.to_dict())
    if len(payload) > MAX_MESSAGE_SIZE:
        raise FramingError(
            f"envelope too large: {len(payload)} bytes (max {MAX_MESSAGE_SIZE})"
        )
    return payload


def _body_to_envelope(body: bytes) -> Envelope:
    """Decode an HTTP response body into a validated envelope."""
    if not body:
        raise FramingError("empty HTTP response body")
    try:
        data = ecf_decode(body)
    except Exception as exc:
        raise FramingError(f"invalid CBOR payload: {exc}") from exc

    root = data.get("root", {})
    if isinstance(root, dict) and root.get("content_hash"):
        validate_entity_hash(root)
    included = data.get("included", {})
    if isinstance(included, dict):
        for ent in included.values():
            if isinstance(ent, dict) and ent.get("content_hash"):
                validate_entity_hash(ent)
    elif isinstance(included, list):
        for ent in included:
            if isinstance(ent, dict) and ent.get("content_hash"):
                validate_entity_hash(ent)
    return Envelope.from_dict(data)


class HttpConnection:
    """Authenticated HTTP-live connection to a remote peer.

    Mirrors ``Connection`` for the HTTP transport: handles the V7 connect
    handshake on construction, then dispatches authenticated EXECUTEs
    via one POST per envelope. The server tracks per-client state across
    POSTs via the ``X-Entity-Session`` header.

    Each POST is its own TCP connection at the transport layer
    (``Connection: close``), so there is no socket to manage on the
    client side after the handshake completes — ``close()`` is a no-op.
    """

    def __init__(
        self,
        url: str,
        keypair: Keypair,
        session: Session,
        capability: dict[str, Any] | None,
        capability_chain: list[dict[str, Any]] | None,
        *,
        session_id: str | None = None,
        ssl_context: ssl.SSLContext | None = None,
        active_hash_format: int = ALG_ECFV1_SHA256,
    ) -> None:
        self.url = url
        self.keypair = keypair
        self.session = session
        self.capability = capability
        self.capability_chain = capability_chain
        self._session_id = session_id
        self._ssl_context = ssl_context
        # V7 v7.69 §4.5a — negotiated active content_hash_format for this
        # connection; every authenticated request authors under it.
        self.active_hash_format = active_hash_format
        self._closed = False

    @property
    def remote_peer_id(self) -> str:
        return self.session.remote_peer_id

    async def _post_envelope(self, envelope: Envelope) -> Envelope:
        """POST one envelope, return the decoded response envelope."""
        body = _envelope_to_body(envelope)
        headers: dict[str, str] = {"content-type": CONTENT_TYPE_CBOR}
        if self._session_id is not None:
            headers[SESSION_HEADER] = self._session_id
        status, resp_headers, resp_body = await http_post(
            self.url, body, headers=headers, ssl_context=self._ssl_context,
        )
        # Update connection-id if the server assigned a new one.
        assigned = resp_headers.get(SESSION_HEADER)
        if assigned:
            self._session_id = assigned
        if status != 200:
            raise ConnectionError(
                f"HTTP {status} from {self.url}: "
                f"{resp_body[:256].decode('utf-8', errors='replace')}"
            )
        return _body_to_envelope(resp_body)

    @classmethod
    async def connect(
        cls,
        url: str,
        keypair: Keypair,
        expected_peer_id: str | None = None,
        *,
        ssl_context: ssl.SSLContext | None = None,
    ) -> "HttpConnection":
        """Open an HTTP-live connection: hello + authenticate handshake.

        Two POSTs:
          1. CONNECT/hello — server returns hello response with their
             peer_id + nonce and an ``X-Entity-Session`` header.
          2. CONNECT/authenticate — server returns auth response with
             our session capability.

        Subsequent ``execute()`` calls POST authenticated EXECUTEs against
        the same connection-id.
        """
        bootstrap = cls(
            url=url,
            keypair=keypair,
            session=None,  # type: ignore[arg-type] — bootstrap-only
            capability=None,
            capability_chain=None,
            ssl_context=ssl_context,
        )

        # Step 1: hello
        hello_execute, our_nonce = create_connect_hello_execute(keypair)
        hello_response_env = await bootstrap._post_envelope(
            Envelope(root=hello_execute.to_entity())
        )
        hello_root = hello_response_env.root
        if hello_root.get("type") != ExecuteResponse.TYPE:
            raise ConnectError(
                f"expected EXECUTE_RESPONSE hello, got {hello_root.get('type')}"
            )
        hello_data = hello_root.get("data", {})
        hello_result = hello_data.get("result", {})
        hello_result_data = hello_result.get("data", {})
        their_peer_id = hello_result_data.get("peer_id", "")
        their_nonce = hello_result_data.get("nonce", "")
        if not their_peer_id or not their_nonce:
            raise ConnectError("missing peer_id or nonce in hello response")
        if expected_peer_id and their_peer_id != expected_peer_id:
            raise ConnectError(
                f"expected peer {expected_peer_id}, got {their_peer_id}"
            )

        # V7 v7.69 §4.5 — negotiate the active content_hash_format from the
        # responder's advertised hello sets (same intersection both sides run).
        our_hash_formats = default_advertised_hash_formats()
        their_hash_formats = hello_result_data.get("hash_formats") or ["ecfv1-sha256"]
        active_format = negotiate_active_hash_format(
            our_hash_formats, their_hash_formats,
        )
        if active_format is None:
            raise ConnectError(
                f"no common hash format: ours {our_hash_formats}, "
                f"theirs {their_hash_formats}",
                code="incompatible_hash_format",
            )

        # Step 2: authenticate (sign their nonce)
        auth_execute, signature_entity, identity_entity = (
            create_connect_authenticate_execute(
                keypair, their_nonce, algorithm=active_format,
            )
        )
        auth_response_env = await bootstrap._post_envelope(
            Envelope(
                root=auth_execute.to_entity(),
                included=[
                    signature_entity.to_dict(),
                    identity_entity.to_dict(),
                ],
            )
        )
        auth_root = auth_response_env.root
        if auth_root.get("type") != ExecuteResponse.TYPE:
            raise ConnectError(
                f"expected EXECUTE_RESPONSE auth, got {auth_root.get('type')}"
            )
        response = ExecuteResponse.from_entity(auth_root)
        if response.status != 200:
            error_msg = ""
            if isinstance(response.result, dict):
                error_msg = response.result.get(
                    "message", response.result.get("error", "")
                )
            raise ConnectError(
                f"http connect authenticate failed (status {response.status}): {error_msg}"
            )

        remote_peer_id, remote_public_key_bytes, token_hash = (
            verify_connect_authenticate_response(
                response.result,
                auth_response_env,
                our_nonce,
                expected_peer_id,
            )
        )

        capability: dict[str, Any] | None = None
        capability_chain: list[dict[str, Any]] | None = None
        if token_hash:
            cap_dict = auth_response_env.find_included(token_hash)
            if cap_dict:
                capability = cap_dict
                cap_data = cap_dict.get("data", {})
                granter_hash = cap_data.get("granter")
                cap_content_hash = cap_dict.get("content_hash")
                chain_entities = []
                cap_sig = auth_response_env.find_signature_for_target(
                    cap_content_hash
                )
                if cap_sig:
                    chain_entities.append(cap_sig)
                if granter_hash:
                    granter_identity = auth_response_env.find_included(
                        granter_hash
                    )
                    if granter_identity:
                        chain_entities.append(granter_identity)
                if chain_entities:
                    capability_chain = chain_entities

        session = Session(
            local_peer_id=keypair.peer_id,
            remote_peer_id=remote_peer_id,
            remote_public_key=remote_public_key_bytes,
        )
        return cls(
            url=url,
            keypair=keypair,
            session=session,
            capability=capability,
            capability_chain=capability_chain,
            session_id=bootstrap._session_id,
            ssl_context=ssl_context,
            active_hash_format=active_format,
        )

    async def execute(
        self,
        uri: str,
        operation: str,
        params: dict[str, Any] | None = None,
        *,
        resource: dict[str, Any] | None = None,
        deliver_to: dict[str, Any] | None = None,
        deliver_token_entity: dict[str, Any] | None = None,
        deliver_token_chain: list[dict[str, Any]] | None = None,
        capability_override: dict[str, Any] | None = None,
        capability_chain_override: list[dict[str, Any]] | None = None,
        included: list[dict[str, Any]] | None = None,
    ) -> ExecuteResponse:
        """POST an authenticated EXECUTE and return the EXECUTE-RESPONSE.

        Mirrors the call surface of ``Connection.execute`` so the
        outbound pool can dispatch through either transport transparently.
        Subscription / continuation back-direction delivery uses
        ``capability_override`` (the per-delivery scoped cap) and
        ``deliver_token_*`` (EXTENSION-INBOX); both are wire-encoded the
        same way as on TCP (V7 §3.3 + EXTENSION-CONTINUATION §4.2).

        Durability (EXTENSION-DURABILITY §2) is not on the HTTP path —
        it is request/response and offers nothing for it; callers needing
        durability use TCP.
        """
        if self._closed:
            raise ConnectionError("HttpConnection is closed")

        if capability_override is not None:
            wire_capability = capability_override
            wire_capability_chain = capability_chain_override
        else:
            wire_capability = self.capability
            wire_capability_chain = self.capability_chain
        if wire_capability is None:
            raise RuntimeError("no capability available for authenticated request")

        resource_target = ResourceTarget.from_dict(resource) if resource else None

        deliver_to_spec = None
        deliver_token_hash = None
        if deliver_to:
            from entity_core.protocol.delivery import DeliverySpec
            deliver_to_spec = DeliverySpec.from_dict(deliver_to)
            if deliver_token_entity:
                deliver_token_hash = deliver_token_entity.get("content_hash")

        execute = Execute.create(
            uri, operation, params,
            resource=resource_target,
            deliver_to=deliver_to_spec,
            deliver_token=deliver_token_hash,
        )
        auth_request = create_authenticated_request(
            self.keypair, execute, wire_capability, wire_capability_chain,
            algorithm=self.active_hash_format,
        )
        envelope = auth_request.to_envelope()
        if deliver_token_entity:
            envelope.included.append(deliver_token_entity)
        if deliver_token_chain:
            envelope.included.extend(deliver_token_chain)
        if included:
            envelope.included.extend(included)

        response_env = await self._post_envelope(envelope)
        return ExecuteResponse.from_entity(response_env.root)

    async def send_raw_frame(self, payload: bytes) -> None:
        """POST a pre-encoded inner-envelope frame verbatim (RELAY §3.1.1 /
        §10.4 terminal-hop raw-frame delivery over the HTTP-live transport).

        The HTTP analog of TCP :meth:`Connection.send_raw_frame`: ``payload``
        is the source's original ``ECF({root, included})`` bytes, written
        unchanged — no decode, re-encode, or re-sign. The destination's
        HTTP-live endpoint decodes the body and dispatches it through the same
        path a direct POST takes (``HttpServer._handle_live`` →
        ``_http_dispatch_envelope``), so it verifies the source's signature +
        capability chain exactly as on a direct connection (§9) and needs no
        RELAY extension to receive.

        The connection is already authenticated (HELLO + AUTHENTICATE ran
        during :meth:`connect`); session pinning rides the ``X-Entity-Session``
        header so the destination sees the inbound EXECUTE on an authenticated
        connection.

        Fire-and-forget per §3.1.1: any async response flows back via the inner
        envelope's INBOX ``deliver_to`` (§6.2), not through this POST's HTTP
        response — we drain and discard the response body. A non-2xx raises so
        the terminal-hop caller can trigger the §6.2.1 Mode-S fallback.
        """
        if self._closed:
            raise ConnectionError("HttpConnection is closed")
        if len(payload) > MAX_MESSAGE_SIZE:
            raise FramingError(
                f"raw frame too large: {len(payload)} bytes (max {MAX_MESSAGE_SIZE})"
            )
        headers: dict[str, str] = {"content-type": CONTENT_TYPE_CBOR}
        if self._session_id is not None:
            headers[SESSION_HEADER] = self._session_id
        status, resp_headers, _resp_body = await http_post(
            self.url, payload, headers=headers, ssl_context=self._ssl_context,
        )
        # Track a server-assigned session id, mirroring _post_envelope.
        assigned = resp_headers.get(SESSION_HEADER)
        if assigned:
            self._session_id = assigned
        if status != 200:
            raise ConnectionError(
                f"HTTP {status} from {self.url}: raw-frame terminal-hop rejected"
            )

    async def close(self) -> None:
        """No-op for HTTP transport — each POST is its own TCP connection."""
        self._closed = True

    async def aclose(self) -> None:
        """RemoteEndpoint protocol: close + wait. Used by RemoteConnectionPool."""
        await self.close()

    @property
    def is_closed(self) -> bool:
        """RemoteEndpoint protocol: has close() been called."""
        return self._closed
