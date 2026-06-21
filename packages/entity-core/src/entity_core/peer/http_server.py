"""HTTP live transport server — POST EXECUTE / EXECUTE-RESPONSE.

Per EXTENSION-NETWORK §6.5.2c (v1.4 Amendment 2) + Chunk D. Implements
the **live HTTP** profile: POST a CBOR-encoded EXECUTE envelope, get a
CBOR-encoded EXECUTE-RESPONSE envelope back. POST-only — GET/HEAD/PUT/etc.
return HTTP 405. Half-duplex — no server-push v1.

This is a **wrapper, NOT BRIDGE-HTTP**: bytes on the wire ARE entity
envelopes (Mechanism A). BRIDGE-HTTP (Mechanism B) is a structurally-
distinct surface for foreign content (HTML/JSON) and is NOT used here.

V7 nonce-required handshake: each POST carries a single envelope; the
server tracks a per-connection state (`PeerConnectionState`) across
POSTs via an ``X-Entity-Session`` header. First POST creates a
fresh session and returns the assigned id; subsequent POSTs reference
it. Idle sessions are reaped after ``SESSION_IDLE_TIMEOUT_SECONDS``.

Stdlib-only: uses ``asyncio.start_server`` with a minimal HTTP/1.1
request parser (POST + Content-Length + body). No new dependency.
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import (
    MAX_MESSAGE_SIZE,
    FramingError,
    validate_entity_hash,
)
from entity_core.utils.ecf import ecf_decode, ecf_encode, validate_hash

if TYPE_CHECKING:
    from entity_core.peer.peer import Peer, PeerConnectionState
    from entity_core.peer.serving import ScopePredicate

logger = logging.getLogger(__name__)

#: How long a server-side HTTP session stays alive without traffic before
#: being reaped. The default trades memory for resilience to flaky
#: clients; tighten via the constructor if needed.
SESSION_IDLE_TIMEOUT_SECONDS = 300.0

#: Custom header used to thread V7 connect state across POSTs. First POST
#: omits it; server response includes the assigned id; subsequent POSTs
#: echo it back.
SESSION_HEADER = "x-entity-session"

CONTENT_TYPE_CBOR = "application/cbor"

#: Chunk E: content-by-hash responses are always `application/octet-stream`
#: per cohort plan §4 ("always-octet-stream for v1; descriptor honoring is
#: a follow-on"). The receiver knows what hash they asked for.
CONTENT_TYPE_OCTET_STREAM = "application/octet-stream"

#: Default URL path the live HTTP listener serves at (cohort convention,
#: matches Go's `-http-path` default).
DEFAULT_URL_PATH = "/entity"

#: Chunk E: default poll-route prefix when mounting on the live listener
#: (Posture 2). For isolated-port (Posture 1), the prefix is `""` so routes
#: sit at the top level (`/content/{hex(H)}`, `/tree/{path}`).
DEFAULT_POLL_PREFIX = "/poll"

#: Amendment 5: first-segment demux literals. The tree route has NO
#: reserved word — a parseable peer-id first segment IS the tree signal
#: (co-located drops the `tree/` segment per §6.5.6). The reserved set
#: is `{content, manifest, peers}`; an operator's EXECUTE `{http-path}`
#: MUST avoid all three (§6.5.6 G4).
CONTENT_LITERAL = "content"
MANIFEST_LITERAL = "manifest"
PEERS_LITERAL = "peers"

#: EXTENSION-NETWORK §6.5.3 defaults (operator-overridable in the profile;
#: `tree_listing_suffix` MUST differ from `tree_leaf_suffix`).
DEFAULT_TREE_LEAF_SUFFIX = ".bin"
DEFAULT_TREE_LISTING_SUFFIX = ".list"

#: Amendment 5: URL-length cap per RFC 7230 §3.1.1 (parser-DoS guard;
#: tree paths are uncapped per V7 §1.4, so the length bound lives here).
#: Operator-overridable on the listener; `414` is MAY.
DEFAULT_MAX_URL_BYTES = 8 * 1024

#: Maximum bytes we will read for a request line / header block.
_HEADER_READ_LIMIT = 16 * 1024


@dataclass
class _HttpSession:
    """Per-client server-side state — mirrors TCP's `PeerConnectionState`."""

    conn_state: "PeerConnectionState" = field(default=None)  # type: ignore[assignment]
    last_activity: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        if self.conn_state is None:
            # Defer import to avoid circular: peer.py imports http_server lazily.
            from entity_core.peer.peer import PeerConnectionState
            self.conn_state = PeerConnectionState()


class _CollectingWriter:
    """``asyncio.StreamWriter``-compatible bytes collector.

    The dispatcher writes a length-prefixed envelope frame here via
    ``send_envelope``; the HTTP layer strips the 4-byte length prefix
    (HTTP carries the framing via Content-Length) and returns just the
    CBOR payload as the response body.
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def write(self, data: bytes) -> None:
        self._buf.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None

    def take_envelope_bytes(self) -> bytes:
        """Return the response body — the CBOR payload, length-prefix stripped."""
        if len(self._buf) < 4:
            return bytes(self._buf)
        # Trust the dispatcher to have written exactly one frame.
        length = struct.unpack(">I", bytes(self._buf[:4]))[0]
        body = bytes(self._buf[4 : 4 + length])
        return body


async def _read_header_block(
    reader: asyncio.StreamReader, limit: int
) -> tuple[bytes, bytes]:
    """Read up through the `\\r\\n\\r\\n` terminator.

    Reads in chunks until the terminator is found, then splits at the
    terminator and returns ``(header_block_with_terminator, body_prefix)``
    — the latter is whatever bytes overran into the body and need to be
    consumed before reading the rest of the body.

    Raises:
        FramingError: terminator not found within ``limit`` bytes or
            the connection closes before the terminator arrives.
    """
    out = bytearray()
    while True:
        idx = out.find(b"\r\n\r\n")
        if idx >= 0:
            terminator_end = idx + 4
            return bytes(out[:terminator_end]), bytes(out[terminator_end:])
        if len(out) >= limit:
            raise FramingError(
                f"HTTP header block exceeds limit ({limit} bytes)"
            )
        chunk = await reader.read(min(4096, limit - len(out)))
        if not chunk:
            raise FramingError(
                "connection closed before HTTP header terminator"
            )
        out.extend(chunk)


async def _parse_http_request(
    reader: asyncio.StreamReader,
) -> tuple[str, str, dict[str, str], bytes]:
    """Parse a minimal HTTP/1.1 request — method, path, headers, body.

    Supports only the surface we need: the request line, header block,
    Content-Length-delimited body. Chunked transfer-encoding is not
    supported (returned as a FramingError to the dispatcher).

    Returns:
        (method, path, headers dict (lowercase keys), body bytes).
    """
    head, body_prefix = await _read_header_block(reader, _HEADER_READ_LIMIT)

    header_block = head[: -4].decode("ascii", errors="replace")
    lines = header_block.split("\r\n")
    if not lines:
        raise FramingError("empty HTTP request")

    request_line = lines[0].split(" ", 2)
    if len(request_line) != 3:
        raise FramingError(f"malformed HTTP request line: {lines[0]!r}")
    method, path, _http_version = request_line
    method = method.upper()

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()

    if "transfer-encoding" in headers:
        # We don't support chunked encoding in v1.
        raise FramingError("transfer-encoding not supported (use Content-Length)")

    content_length = int(headers.get("content-length", "0"))
    if content_length > MAX_MESSAGE_SIZE:
        raise FramingError(
            f"request body too large: {content_length} (max {MAX_MESSAGE_SIZE})"
        )

    body = bytearray(body_prefix)
    remaining = content_length - len(body)
    if remaining > 0:
        body.extend(await reader.readexactly(remaining))
    elif remaining < 0:
        # Body overflowed Content-Length (extra bytes from a pipelined
        # request would land here — but we set Connection: close and
        # don't support pipelining).
        raise FramingError(
            f"body overran Content-Length: got {len(body)}, declared {content_length}"
        )
    return method, path, headers, bytes(body)


async def _send_http_response(
    writer: asyncio.StreamWriter,
    status: int,
    reason: str,
    headers: dict[str, str],
    body: bytes,
) -> None:
    """Write a minimal HTTP/1.1 response. Always Connection: close."""
    full_headers = dict(headers)
    full_headers.setdefault("content-length", str(len(body)))
    full_headers.setdefault("connection", "close")
    head = [f"HTTP/1.1 {status} {reason}\r\n"]
    for k, v in full_headers.items():
        head.append(f"{k}: {v}\r\n")
    head.append("\r\n")
    writer.write("".join(head).encode("ascii") + body)
    await writer.drain()


def _decode_envelope_body(body: bytes) -> Envelope:
    """Decode a raw CBOR envelope from an HTTP request body.

    Validates hashes the same way ``recv_envelope`` does. Unlike TCP
    framing, there is no 4-byte length prefix — Content-Length carries
    the framing.
    """
    if not body:
        raise FramingError("empty request body")
    try:
        data = ecf_decode(body)
    except Exception as exc:
        raise FramingError(f"invalid CBOR payload: {exc}") from exc

    # Mirror recv_envelope's hash validation (root + included).
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


class HttpServer:
    """Live-HTTP listener attached to a Peer.

    Lifecycle:
      * ``start(host, port)`` binds a TCP listener that speaks HTTP/1.1
        for POST requests and rejects everything else with 405. Also
        self-publishes a ``system/peer/transport/http`` profile entity
        at the §6.5.1 path (D1 SHOULD), unless an operator-provided
        profile already exists.
      * ``stop()`` closes the listener and drops all sessions.

    The server holds a weak link back to its Peer for dispatch.
    """

    def __init__(
        self,
        peer: "Peer",
        *,
        base_url: str | None = None,
        url_path: str | None = DEFAULT_URL_PATH,
        poll_prefix: str | None = None,
        scope_predicate: "ScopePredicate | None" = None,  # noqa: F821
        poll_base_url: str | None = None,
        session_timeout: float = SESSION_IDLE_TIMEOUT_SECONDS,
        tree_leaf_suffix: str = DEFAULT_TREE_LEAF_SUFFIX,
        tree_listing_suffix: str = DEFAULT_TREE_LISTING_SUFFIX,
        max_url_bytes: int = DEFAULT_MAX_URL_BYTES,
    ) -> None:
        """Per cohort convention (Go+Rust): the live HTTP listener serves
        a single configured path; all other paths return 404.

        Chunk E adds optional poll routes. When `poll_prefix` is set, the
        server ALSO answers `GET {poll_prefix}/content/{hex(H)}` (with
        scope predicate gating) and `GET {poll_prefix}/tree/{path}` on
        the same listener — that's Posture 2 (mount on live). For
        Posture 1 (isolated port), create a separate HttpServer with
        `url_path=None` and `poll_prefix=""` so the routes mount at the
        top level (`/content/{hex(H)}`, `/tree/{path}`).

        Args:
            url_path: Live POST path; `None` disables the live route.
            poll_prefix: Poll route prefix; `None` disables poll routes;
                `""` mounts at the top level.
            scope_predicate: Required when poll routes are enabled.
                Decides which hashes the content route answers for. See
                `entity_core.peer.serving` for predicate types.
            poll_base_url: Public URL prefix advertised in the http-poll
                profile entity (Posture 1; the live profile uses
                `base_url`). When None, derived as
                `http://{bind-host}:{bind-port}{poll_prefix}`.
        """
        if poll_prefix is not None and scope_predicate is None:
            raise ValueError(
                "scope_predicate is required when poll_prefix is set "
                "(Amendment 5: serve_scope is the authorization lever; "
                "poll routes are unauthenticated by design — the "
                "published serve_scope.cap IS the effective cap per "
                "§6.5.6)"
            )
        if tree_leaf_suffix == tree_listing_suffix:
            raise ValueError(
                "tree_leaf_suffix and tree_listing_suffix MUST differ "
                "(EXTENSION-NETWORK §6.5.3 Amendment 5); got "
                f"{tree_leaf_suffix!r} for both"
            )
        if not tree_leaf_suffix.startswith(".") or not tree_listing_suffix.startswith("."):
            # Not strictly required by the spec, but the two named-object
            # extensions are the documented convention and a non-dot
            # suffix collides with path components in real publishers.
            raise ValueError(
                "tree_leaf_suffix and tree_listing_suffix SHOULD be "
                "dot-prefixed extensions (e.g. .bin / .list); got "
                f"{tree_leaf_suffix!r} / {tree_listing_suffix!r}"
            )
        self.peer = peer
        self.base_url = base_url
        self.poll_base_url = poll_base_url
        self.url_path = (
            (url_path if url_path.startswith("/") else "/" + url_path)
            if url_path is not None else None
        )
        # Empty prefix is legal (isolated-port routes at top level).
        # Strip trailing slash so concatenation with /content/ etc. is clean.
        if poll_prefix is None:
            self.poll_prefix: str | None = None
        else:
            normalized = poll_prefix if poll_prefix.startswith("/") or poll_prefix == "" else "/" + poll_prefix
            self.poll_prefix = normalized.rstrip("/")
        self.scope_predicate = scope_predicate
        self.tree_leaf_suffix = tree_leaf_suffix
        self.tree_listing_suffix = tree_listing_suffix
        self.max_url_bytes = max_url_bytes
        self._session_timeout = session_timeout
        self._sessions: dict[str, _HttpSession] = {}
        self._server: asyncio.AbstractServer | None = None
        self._reaper_task: asyncio.Task | None = None

    async def start(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        self._server = await asyncio.start_server(self._handle_conn, host, port)
        sockets = self._server.sockets or []
        bound = sockets[0].getsockname() if sockets else (host, port)
        bound_host, bound_port = bound[0], bound[1]

        # SHOULD self-publish per D1, mirroring the TCP path. Each enabled
        # route gets its own profile entity. Chunk E (E.2): live and poll
        # are independent profiles even when they share a listener (Posture
        # 2) — different `supported_ops`, potentially different URLs.
        # V7 v7.64 §1.4: self-publish at `system/peer/transport/{peer_id_hex}/...`.
        local_peer_id_hex = self.peer.peer_id_hex
        local_public_key = self.peer.keypair.public_key_bytes()
        if self.url_path is not None:
            advertised = self.base_url or f"http://{bound_host}:{bound_port}{self.url_path}"
            self_uri = self.peer.entity_tree.normalize_uri(
                f"system/peer/transport/{local_peer_id_hex}/primary-http"
            )
            if self.peer.entity_tree.get(self_uri) is None:
                self.peer._publish_http_profile(
                    self.peer.peer_id, advertised,
                    public_key=local_public_key,
                    profile_id="primary-http",
                )

        if self.poll_prefix is not None:
            poll_advertised = (
                self.poll_base_url
                or f"http://{bound_host}:{bound_port}{self.poll_prefix}"
            )
            poll_uri = self.peer.entity_tree.normalize_uri(
                f"system/peer/transport/{local_peer_id_hex}/primary-http-poll"
            )
            if self.peer.entity_tree.get(poll_uri) is None:
                self.peer._publish_http_poll_profile(
                    self.peer.peer_id,
                    poll_advertised,
                    public_key=local_public_key,
                    profile_id="primary-http-poll",
                    tree_leaf_suffix=self.tree_leaf_suffix,
                )

        self._reaper_task = asyncio.create_task(self._reap_idle_sessions())
        roles = []
        if self.url_path is not None:
            roles.append(f"live POST {self.url_path}")
        if self.poll_prefix is not None:
            roles.append(
                f"poll GET {self.poll_prefix}/content/<hash>, "
                f"{self.poll_prefix}/<peer-id>/<path>{self.tree_leaf_suffix}|"
                f"{self.tree_listing_suffix}, "
                f"{self.poll_prefix}/peers{self.tree_listing_suffix}, "
                f"{self.poll_prefix}/manifest "
                f"(scope={self.scope_predicate.describe()})"
            )
        logger.info(
            f"Peer {self.peer.peer_id[:8]}... HTTP listening on {bound}; "
            f"roles: {' | '.join(roles)}"
        )

    async def stop(self) -> None:
        if self._reaper_task is not None:
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except (asyncio.CancelledError, Exception):
                pass
            self._reaper_task = None
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._sessions.clear()

    def bound_socket(self) -> tuple[str, int] | None:
        if self._server is None:
            return None
        socks = self._server.sockets or []
        if not socks:
            return None
        host, port, *_ = socks[0].getsockname()
        return host, port

    # -- internals -------------------------------------------------------------

    async def _reap_idle_sessions(self) -> None:
        while True:
            await asyncio.sleep(max(30.0, self._session_timeout / 4))
            cutoff = time.monotonic() - self._session_timeout
            for sid in [s for s, sess in self._sessions.items()
                        if sess.last_activity < cutoff]:
                self._sessions.pop(sid, None)
                logger.debug("HTTP session %s reaped (idle timeout)", sid[:8])

    async def _handle_conn(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            try:
                method, path, headers, body = await _parse_http_request(reader)
            except FramingError as exc:
                await _send_http_response(
                    writer, 400, "Bad Request", {"content-type": "text/plain"},
                    str(exc).encode("utf-8"),
                )
                return
            except asyncio.IncompleteReadError:
                return

            # Amendment 5 §6.5.3.1: %2F inside a path component is malformed
            # (path components are `/`-delimited; reject rather than recover
            # as a literal). We check on the raw request line BEFORE
            # stripping query/fragment so the diagnostic stays meaningful.
            raw_path = path.split("?", 1)[0].split("#", 1)[0]
            if "%2f" in raw_path.lower():
                await _send_http_response(
                    writer, 400, "Bad Request",
                    {"content-type": "text/plain"},
                    b"encoded slash (%2F) is not permitted inside a path component\n",
                )
                return

            # §6.5.3.1 Amendment 5: `414` MAY on URL exceeding the operator-
            # configured cap (RFC 7230 §3.1.1; default 8 KB). Tree paths are
            # uncapped per V7 §1.4 — the bound is a parser-DoS guard.
            if len(path) > self.max_url_bytes:
                await _send_http_response(
                    writer, 414, "URI Too Long",
                    {"content-type": "text/plain"},
                    f"URL exceeds configured cap ({self.max_url_bytes} bytes)\n".encode("utf-8"),
                )
                return

            request_path = raw_path

            # Route demux. Order: live POST path match → poll routes → 404.
            # The poll branch handles its own method gating (GET only) so a
            # GET to the live path correctly 405s instead of falling through
            # to poll's 404.
            if self.url_path is not None and request_path == self.url_path:
                await self._handle_live(method, headers, body, writer)
                return

            if self.poll_prefix is not None and self._is_poll_path(request_path):
                await self._handle_poll(method, request_path, writer)
                return

            await _send_http_response(
                writer, 404, "Not Found",
                {"content-type": "text/plain"},
                f"unknown path {request_path!r}\n".encode("utf-8"),
            )
        except Exception:
            logger.exception("HTTP connection handler crashed")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # -- live route (Chunk D — POST EXECUTE) ----------------------------------

    async def _handle_live(
        self,
        method: str,
        headers: dict[str, str],
        body: bytes,
        writer: asyncio.StreamWriter,
    ) -> None:
        if method != "POST":
            await _send_http_response(
                writer, 405, "Method Not Allowed",
                {"content-type": "text/plain", "allow": "POST"},
                b"POST only - live HTTP profile carries EXECUTE envelopes.\n",
            )
            return

        try:
            envelope = _decode_envelope_body(body)
        except Exception as exc:
            await _send_http_response(
                writer, 400, "Bad Request",
                {"content-type": "text/plain"},
                f"invalid envelope: {exc}".encode("utf-8"),
            )
            return

        # Look up or create the connection-state session.
        session_id = headers.get(SESSION_HEADER)
        if session_id and session_id in self._sessions:
            session = self._sessions[session_id]
        else:
            session_id = uuid.uuid4().hex
            session = _HttpSession()
            self._sessions[session_id] = session
        session.last_activity = time.monotonic()

        # Dispatch a single envelope and capture the response.
        collecting_writer = _CollectingWriter()
        try:
            await self.peer._http_dispatch_envelope(
                envelope, session.conn_state, collecting_writer,
            )
        except Exception:
            logger.exception("HTTP dispatch error")
            await _send_http_response(
                writer, 500, "Internal Server Error",
                {"content-type": "text/plain"},
                b"dispatch error",
            )
            return

        response_body = collecting_writer.take_envelope_bytes()
        await _send_http_response(
            writer, 200, "OK",
            {
                "content-type": CONTENT_TYPE_CBOR,
                SESSION_HEADER: session_id,
            },
            response_body,
        )

    # -- poll routes (Amendment 5 — named-object addressing) ------------------

    def _is_poll_path(self, request_path: str) -> bool:
        """True iff request_path falls under the configured poll prefix.

        Just a prefix test — the actual demux (literal-or-peer-id-parse)
        runs in `_handle_poll`. We do not pre-classify by suffix here;
        anything under the prefix that isn't a recognized route 404s
        through `_handle_poll`.
        """
        if self.poll_prefix is None:
            return False
        if self.poll_prefix == "":
            # Posture 1: any path that isn't the live URL is a poll
            # candidate. The live route already matched before this check
            # ran (see `_handle_conn`), so a falling-through path is poll.
            return True
        if request_path == self.poll_prefix:
            # Bare prefix with no trailing slash is the operator's poll
            # base — no recognized route; 404 through `_handle_poll`.
            return True
        return request_path.startswith(self.poll_prefix + "/")

    async def _handle_poll(
        self,
        method: str,
        request_path: str,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Amendment 5 literal-or-peer-id-parse demux (§6.5.6).

        Order (MUST):
          (1) literal `content`     → CONTENT_GET
          (2) literal `manifest`    → MANIFEST_GET
          (3) literal `peers{listing_suffix}` (`peers.list` default)
                                    → all-peers root listing
              · bare `peers` (no listing suffix) → 404
          (4) else parse as peer-id → TREE_GET (entity or listing by suffix)
          (5) else                  → 404

        The reserved literals `{content, manifest, peers}` can't collide
        with a peer-id (a peer-id parse of those short strings fails).
        Tree has NO reserved word — a parseable-peer-id first segment IS
        the tree signal (co-located drops the `tree/` segment).
        """
        if method != "GET":
            await _send_http_response(
                writer, 405, "Method Not Allowed",
                {"content-type": "text/plain", "allow": "GET"},
                b"GET only - poll routes are read-only.\n",
            )
            return

        # Strip the configured prefix; the tail is the routing surface.
        if self.poll_prefix:
            tail = request_path[len(self.poll_prefix):]
        else:
            tail = request_path
        if tail.startswith("/"):
            tail = tail[1:]
        if not tail:
            # The bare poll base. No recognized route.
            await self._send_404(writer, "no route")
            return

        from entity_core.utils.identity import is_peer_id

        # Split into first segment + rest. Every URL is a concrete static
        # object key (no trailing slashes); the *first segment may carry
        # the named-object suffix* in the single-segment forms (peer-root
        # listing `{peer_id}.list`, all-peers listing `peers.list`).
        slash = tail.find("/")
        first = tail if slash < 0 else tail[:slash]
        rest = "" if slash < 0 else tail[slash + 1:]

        if slash < 0:
            # Single-segment requests. The valid shapes are:
            #   - `manifest`                    → MANIFEST_GET
            #   - `peers{listing_suffix}`       → all-peers root listing
            #   - `{peer_id}{listing_suffix}`   → peer-root listing
            # Anything else (bare `peers`, bare `content`,
            # `{peer_id}{leaf_suffix}`, unknown literal, …) → 404.
            if first == MANIFEST_LITERAL:
                await self._handle_manifest_get(writer)
                return
            if first.endswith(self.tree_listing_suffix):
                base = first[: -len(self.tree_listing_suffix)]
                if base == PEERS_LITERAL:
                    await self._handle_peers_listing(writer)
                    return
                if is_peer_id(base):
                    await self._handle_peer_root_listing(base, writer)
                    return
            # Any leaf-suffix single segment (`{peer_id}.bin` etc.) is
            # explicitly 404 — peer-id roots are directories per V7 §1.4
            # (§6.5.3.1 Amendment 5 status table).
            await self._send_404(writer, "no recognized route")
            return

        # slash >= 0: first segment + rest.
        if first == CONTENT_LITERAL:
            # CONTENT_GET — `rest` is the hash form (with optional layout
            # sharding, but Python's `_handle_content_get` accepts the
            # flat `hex(H)` wire form only today; sharding lands when
            # validate-peer surfaces it). Bare `/content` (rest empty) →
            # 400 via `_handle_content_get`'s `validate_hash` gate (empty
            # string decodes to a zero-length hash → too short).
            await self._handle_content_get(rest, writer)
            return

        if first == MANIFEST_LITERAL:
            # `manifest/...` is terminal — `GET {manifest_prefix}/` → 404
            # (§6.5.3.1 Amendment 5: no suffix, no trailing slash).
            await self._send_404(writer, "manifest is terminal (no suffix, no trailing slash)")
            return

        if first == PEERS_LITERAL:
            # Bare `peers` is not a routable first segment; anything under
            # it is 404 (`peers.list` would be a single segment handled
            # above).
            await self._send_404(writer, "bare `peers` is not a route")
            return

        # Else: parse as peer-id. Success → TREE_GET, with `rest` carrying
        # the path-plus-suffix that the named-object addressing requires.
        # Failure → 404 (length-disjointness with the reserved set means
        # short non-reserved first segments land here too).
        if not is_peer_id(first):
            await self._send_404(writer, "unknown route")
            return

        await self._handle_tree_route(
            peer_id=first, rest=rest, writer=writer,
        )

    async def _handle_content_get(
        self,
        hash_hex: str,
        writer: asyncio.StreamWriter,
    ) -> None:
        """GET {poll_prefix}/content/{hex(H)} — content-by-hash.

        Per the arch serving-mode content-scope ruling
        §1 (the §2 follow-up body-shape ruling):
          - Body = full entity ECF (the only bytes that re-hash to H).
            Content-Type: application/cbor.
          - URL hex is the **full wire hash** = `{format byte} ||
            {digest}` (V7 §3.5). Width is format-relative: 66 hex for
            ECFv1-SHA-256 (33 bytes), 98 for ECFv1-SHA-384 (49 bytes).
            The content_store keys on these same bytes verbatim (home
            format), so no re-prefixing is needed before lookup.
          - 200 + ECF bytes + `application/cbor` + `Cache-Control:
            immutable, max-age=...` + `ETag: "{hex(H)}"` on hit
          - 400 on malformed hex, wrong digest width, or an unsupported
            format byte (`validate_hash` fail-closed)
          - 404 (identical body) on out-of-scope OR not-held — §1.3 T4
            mitigation: no presence oracle

        The verify-by-rehash contract: a consumer fetches body, recomputes
        `{format byte} || DIGEST(ECF({type, data}))` under the format the
        URL hash declares, and trusts only if it equals the URL hash.
        That's Mechanism A — the reason hostile-CDN fetch is safe. The
        body MUST re-hash to the URL hash.
        """
        # F-PY-13 ruling: the URL is `hex(H)` where H is the
        # full wire hash per V7 §3.5 = `{format byte} || {digest}` — a
        # bare digest-only URL still 400s (no format byte = ambiguous).
        # But the width is **format-relative** (V7 §3.5 invariant pointer,
        # v7.70 §1.2): 66 hex for ECFv1-SHA-256 (33 bytes), 98 for
        # ECFv1-SHA-384 (49 bytes), etc. A SHA-384 home peer hashes its
        # own content with SHA-384, so a hardcoded 66 would 400 it out of
        # serving its own store. We delegate width+format validation to
        # `validate_hash` (supported format byte + matching digest width) —
        # the same structural gate the v7.70 capability `peer_pattern` fix
        # uses (5c31e28). Non-hex, wrong width, or an unsupported format
        # byte all 400 fail-closed; the bytes we then look up are the full
        # wire hash (the content_store keys on the home format verbatim).
        try:
            h = bytes.fromhex(hash_hex)
        except ValueError:
            await _send_http_response(
                writer, 400, "Bad Request",
                {"content-type": "text/plain"},
                b"malformed hash (expected lowercase hex of the full wire hash)\n",
            )
            return
        try:
            validate_hash(h)
        except ValueError as exc:
            await _send_http_response(
                writer, 400, "Bad Request",
                {"content-type": "text/plain"},
                f"malformed content hash (V7 \xc2\xa73.5 format-relative): {exc}\n".encode("utf-8"),
            )
            return

        from entity_core.peer.serving import resolve_content_bytes
        body = resolve_content_bytes(
            h, self.peer.content_store, self.scope_predicate,
        )
        if body is None:
            await _send_http_response(
                writer, 404, "Not Found",
                {"content-type": "text/plain"},
                b"not found\n",
            )
            return

        await _send_http_response(
            writer, 200, "OK",
            {
                # Body is full entity ECF — application/cbor not
                # octet-stream. The receiver re-hashes {type, data} to
                # verify against the URL hash.
                "content-type": CONTENT_TYPE_CBOR,
                # Content is hash-addressed — immutable by construction.
                "cache-control": "public, max-age=31536000, immutable",
                # ETag mirrors what the URL carried (the 32-byte digest
                # form is canonical; 33-byte form keeps Python-internal
                # tests symmetric).
                "etag": f'"{hash_hex}"',
            },
            body,
        )

    async def _send_404(
        self,
        writer: asyncio.StreamWriter,
        diagnostic: str,
    ) -> None:
        """Identical-bytes 404 (no presence oracle — §6.5.6 T4).

        The body MUST be the same regardless of why we 404'd: not-held vs
        out-of-scope vs unknown-route. The `diagnostic` argument is for
        the server logger only; it never leaves the process.
        """
        logger.debug("poll 404: %s", diagnostic)
        await _send_http_response(
            writer, 404, "Not Found",
            {"content-type": "text/plain"},
            b"not found\n",
        )

    async def _handle_tree_route(
        self,
        peer_id: str,
        rest: str,
        writer: asyncio.StreamWriter,
    ) -> None:
        """`{tree_prefix}/{peer_id}/{path}{suffix}` (Amendment 5).

        Strip-one of the recognized suffix; the suffix identity selects
        entity vs listing. Bare path with no recognized suffix ⇒ 404
        (§6.5.3.1 — every URL is a concrete object key).
        """
        if rest.endswith(self.tree_leaf_suffix):
            inner = rest[: -len(self.tree_leaf_suffix)]
            if not inner:
                # `{peer_id}/{leaf_suffix}` alone — path component empty.
                await self._send_404(writer, "empty path with leaf suffix")
                return
            tree_path = f"/{peer_id}/{inner}"
            await self._handle_tree_entity(tree_path, writer)
            return
        if rest.endswith(self.tree_listing_suffix):
            inner = rest[: -len(self.tree_listing_suffix)]
            # An empty inner here means the request is
            # `{peer_id}/{listing_suffix}` (with a slash before the
            # suffix) — that's NOT the peer-root form (that one has no
            # slash; it lives in the single-segment branch above), so
            # 404 it: the path component is empty.
            if not inner:
                await self._send_404(writer, "empty path with listing suffix")
                return
            tree_path = f"/{peer_id}/{inner}"
            await self._handle_tree_listing(tree_path, writer)
            return
        # No recognized suffix — Amendment 5 §6.5.3.1: bare path ⇒ 404.
        await self._send_404(writer, "no recognized suffix on tree path")

    async def _handle_tree_entity(
        self,
        tree_path: str,
        writer: asyncio.StreamWriter,
    ) -> None:
        """`TREE_GET` leaf body — `system/hash` pointer (Amendment 6).

        Per §6.5.3.1 (post-Amendment-6) the leaf route returns the
        **bound content hash** as a `system/hash` 2-key bare pointer
        — `ECF({type: "system/hash", data: H})` where `H` is the
        33-byte hash — **NOT** the dereferenced wire entity. This is
        exactly `tree:get mode:"hash"` (V7 §1.7) over HTTP. The
        consumer reads `data` and second-hops `CONTENT_GET
        /content/{hex33(H)}` for the entity bytes.

        Why the pointer: returning the entity at every tree URL
        materializes a separate copy of the same bytes at every path
        bound to `H`, defeating V7 §1.7's content-store dedup
        invariant (same content at N paths ⇒ one copy). A static CDN
        has no content-awareness and cannot recover the dedup.

        Why 2-key not 3-key: a path-addressed pointer has no useful
        self-`content_hash`; a 3-key body would carry two hashes (the
        bound `data` AND the pointer's own self-hash) and force the
        consumer to disambiguate. Mirrors `CONTENT_GET`'s 2-key bare
        precedent.

        ETag = the **bound hash** (changes on rebind = correct mutable
        cache key), NOT the pointer entity's own self-hash. No
        `immutable` Cache-Control (tree bindings are mutable).
        """
        h = self.peer.entity_tree.get(tree_path)
        if h is None:
            await self._send_404(writer, f"no binding at {tree_path}")
            return

        # Scope-gate by path (cap-token; one ACL machinery — §6.5.6).
        if not self.scope_predicate.in_scope_path(tree_path):
            await self._send_404(writer, f"out of scope: {tree_path}")
            return

        # Two-hop, normative: build the bare 2-key system/hash pointer.
        # No content_store.get — the path→hash resolution is the route's
        # only job; the consumer second-hops to fetch the bytes.
        body = ecf_encode({"type": "system/hash", "data": bytes(h)})
        await _send_http_response(
            writer, 200, "OK",
            {
                "content-type": CONTENT_TYPE_CBOR,
                # Mutable binding — no `immutable`. ETag mirrors the
                # bound hash; rebinding the path produces a new ETag,
                # which is the correct mutable-resource cache key.
                "etag": f'"{bytes(h).hex()}"',
            },
            body,
        )

    async def _handle_tree_listing(
        self,
        tree_path: str,
        writer: asyncio.StreamWriter,
    ) -> None:
        """`TREE_GET` listing body — `system/tree/listing` in ECF.

        Per §6.5.3.1: scope-gated (filtered count); empty in-scope ⇒ 200
        with `entries={}` `count=0`; out-of-scope or non-existent ⇒
        identical 404 (T4). No `immutable` (mutable view); `ETag`
        derived from the body's own content_hash.
        """
        from entity_core.peer.serving import render_tree_listing
        from entity_core.utils.ecf import compute_ecf_hash
        listing = render_tree_listing(
            tree_path, self.peer.entity_tree, self.scope_predicate,
        )
        if listing is None:
            await self._send_404(writer, f"out of scope or non-existent: {tree_path}")
            return

        # Serialize as a wire entity ECF({type, data, content_hash}). The
        # spec says the listing carries its own content_hash even though
        # it's a mutable view — so a consumer can verify the head bytes
        # they got match the hash they expected.
        hashable = {"type": listing["type"], "data": listing["data"]}
        h = compute_ecf_hash(hashable)
        wire = {
            "type": listing["type"],
            "data": listing["data"],
            "content_hash": h,
        }
        body = ecf_encode(wire)
        etag_hex = h.hex()
        await _send_http_response(
            writer, 200, "OK",
            {
                "content-type": CONTENT_TYPE_CBOR,
                # Mutable view — no `immutable`. ETag from the rendered
                # content_hash so two identical re-renders share an ETag.
                "etag": f'"{etag_hex}"',
            },
            body,
        )

    async def _handle_manifest_get(
        self,
        writer: asyncio.StreamWriter,
    ) -> None:
        """`MANIFEST_GET` body — signed manifest wire entity.

        Per §6.5.3.1 (Amendment 5): `GET {manifest_prefix}` returns the
        publisher's signed manifest as `ECF({type, data, content_hash})`
        (`system/peer/published-root` / static-handshake manifest).
        Singular/terminal: no suffix, no trailing slash; `/manifest/` ⇒
        404 (handled upstream); none published ⇒ 404.

        The manifest is **mutable** (revocation lives here) ⇒ MUST NOT
        be `immutable`-cached.

        v1 looks up `system/peer/{peer_id}/published-root` in the tree;
        if present, returns the entity. Python doesn't yet *produce* a
        signed manifest (PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE not yet
        landed); until then the route serves whatever the operator has
        bound at that path or 404s.
        """
        manifest_path = f"/{self.peer.peer_id}/system/peer/published-root"
        h = self.peer.entity_tree.get(manifest_path)
        if h is None:
            await self._send_404(writer, "no manifest published")
            return
        entity = self.peer.content_store.get(h)
        if entity is None:
            await self._send_404(writer, "manifest bound but not held")
            return
        body = ecf_encode(entity.to_dict())
        await _send_http_response(
            writer, 200, "OK",
            {
                "content-type": CONTENT_TYPE_CBOR,
                # Mutable — NO `immutable`. Revocation lives in the
                # manifest; an immutable cache would defeat it.
                "etag": f'"{bytes(h).hex()}"',
            },
            body,
        )

    async def _handle_peer_root_listing(
        self,
        peer_id: str,
        writer: asyncio.StreamWriter,
    ) -> None:
        """`{tree_prefix}/{peer_id}{listing_suffix}` — peer-root listing."""
        await self._handle_tree_listing(f"/{peer_id}/", writer)

    async def _handle_peers_listing(
        self,
        writer: asyncio.StreamWriter,
    ) -> None:
        """`{tree_prefix}/peers{listing_suffix}` — universal-tree-root listing.

        Amendment 5 §6.5.6: enumerate **every peer-id top-level segment
        for which the local tree holds at least one binding** — the
        normal multi-peer publish case (sync, mirroring, cross-peer
        writes via `tree:put /{other_peer}/…`). Matches Go's
        `serveAllPeersListing` cohort semantics: aggregate by leading
        segment, accept any segment that parses as a peer-id, mark
        `has_children=True` for any peer-id with a descendant binding,
        scope-check only direct hashes bound exactly at the peer-id
        root (vanishingly rare per V7 §1.4 — roots are directories).

        NB: scope-gating applies to entity hashes only, NOT to the
        peer-id navigation handles. A foreign peer-id with any binding
        in the local tree appears here; the follow-the-link to
        `/{foreign_peer}.list` returns whatever scope allows (empty
        listing or 404 if `prefix_in_scope` is False under a narrowly-
        scoped cap). This mirrors Go's behavior (validated three-way).
        """
        from entity_core.utils.identity import is_peer_id
        from entity_core.utils.ecf import compute_ecf_hash

        # Aggregate by leading peer-id segment. Each peer-id collects
        # (a) an in-scope hash if something is bound exactly at the
        # peer-id root, and (b) a has_children flag if any descendant
        # binding exists. The flag is the load-bearing signal — under
        # normal publishing patterns (where roots are directories) it
        # alone is what makes a peer-id show up.
        agg: dict[str, dict[str, Any]] = {}
        for uri, bound in self.peer.entity_tree.all_bindings():
            if not uri.startswith("/"):
                continue
            rel = uri[1:]
            if not rel:
                continue
            slash = rel.find("/")
            first = rel if slash < 0 else rel[:slash]
            # Defensively skip non-peer-id top-level segments — V7 §1.4
            # forbids them at the universal-tree root, but a filter
            # keeps the listing clean if the store contains stray data.
            if not is_peer_id(first):
                continue
            has_more = slash >= 0 and slash + 1 < len(rel)
            entry = agg.setdefault(first, {"hash": None, "has_children": False})
            if has_more:
                entry["has_children"] = True
            else:
                # Direct binding at /{peer_id} root (rare). Scope-check
                # the hash — it's the only entity-visibility decision
                # at this level.
                if self.scope_predicate.in_scope(bound):
                    entry["hash"] = bound

        # Drop peer-ids with neither an in-scope hash nor children — that
        # would be a peer-id with a single out-of-scope direct binding
        # (vanishingly rare), and there's nothing to show.
        entries: dict[str, dict[str, Any]] = {}
        for peer_id in sorted(agg.keys()):
            e = agg[peer_id]
            if e["hash"] is None and not e["has_children"]:
                continue
            row: dict[str, Any] = {"has_children": e["has_children"]}
            if e["hash"] is not None:
                row["hash"] = e["hash"]
            entries[peer_id] = row

        listing_data: dict[str, Any] = {
            "path": "/",
            "entries": entries,
            "count": len(entries),
            "offset": 0,
        }
        hashable = {"type": "system/tree/listing", "data": listing_data}
        h = compute_ecf_hash(hashable)
        wire = {
            "type": "system/tree/listing",
            "data": listing_data,
            "content_hash": h,
        }
        body = ecf_encode(wire)
        etag_hex = h.hex()
        await _send_http_response(
            writer, 200, "OK",
            {
                "content-type": CONTENT_TYPE_CBOR,
                "etag": f'"{etag_hex}"',
            },
            body,
        )
