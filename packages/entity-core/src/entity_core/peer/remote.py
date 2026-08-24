"""Outbound connection pool for remote peer dispatch.

Manages pooled connections to remote peers. Connections are created lazily
on first use and cached by peer_id. Broken connections are evicted so the
next call re-dials.

Address resolution scans ``system/peer/transport/`` profile entities and
matches on the entity's Base58 ``peer_id`` body field (V7 v7.64 §1.4:
the path key is now ``peer_id_hex`` — lowercase hex of the publisher's
``system/peer`` content_hash — and the dialer typically only has the
Base58 form, so we filter by body). Per EXTENSION-NETWORK §6.5.1 +
§6.5.1a D1 (v1.5 path-encoding alignment).

Selection order (Q1, PROPOSAL §8.9): sort candidates by
``(effective_priority asc, profile-id lex)``. ``priority`` is an
optional ``uint`` on the profile entity; lower = preferred (DNS-SRV
semantics). Defaults:

- ``priority`` explicit on the entity → use it
- ``priority`` absent AND profile-id is the reserved ``primary`` → 0
- ``priority`` absent for any other id → 100

So the legacy "primary first, then lex" behaviour is preserved verbatim
when no explicit priority is set. ``advertised_at`` is informational
(D-3); it is NOT a selection key. ``advertised_at`` is OPTIONAL (Q6).
Decoders MUST reject ``transport_type``/entity-type-suffix mismatch
(D5).

R1 (PROPOSAL §7.3, Round-2 LOCKED): the dialer walks both
``tcp`` and ``http`` live profiles and dispatches on ``transport_type``.
A single ``RemoteEndpoint`` protocol abstracts the outbound surface so
subscription / continuation / handler-initiated EXECUTE all ride either
transport transparently.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any, Protocol

from entity_core.protocol.bounds import Bounds
from entity_core.protocol.messages import ExecuteResponse

if TYPE_CHECKING:
    from entity_core.crypto.identity import Keypair
    from entity_core.peer.liveness import KeepaliveConfig
    from entity_core.storage.content_store import ContentStore
    from entity_core.storage.emit import EmitPathway
    from entity_core.storage.entity_tree import EntityTree

logger = logging.getLogger(__name__)

#: §4.1 / D-14: TCP endpoints are advertised as `tcp://host:port` URLs.
TCP_URL_SCHEME = "tcp://"


def _parse_tcp_endpoint_url(url: str) -> tuple[str, int]:
    """Parse a TCP endpoint URL into (host, port).

    Per EXTENSION-NETWORK §4.1 + D-14 the URL form is `tcp://host:port`.
    """
    if not url.startswith(TCP_URL_SCHEME):
        raise ValueError(f"endpoint url must start with 'tcp://': {url}")
    authority = url[len(TCP_URL_SCHEME):]
    if ":" not in authority:
        raise ValueError(f"endpoint url missing port: {url}")
    host, port_str = authority.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"endpoint url has non-integer port: {url}") from None
    return host, port


class RemoteEndpoint(Protocol):
    """Outbound surface common to TCP and HTTP transports.

    Concrete satisfiers: ``Connection`` (tcp), ``HttpConnection`` (http).
    The pool stores these polymorphically and the caller (peer-initiated
    EXECUTE, subscription delivery, continuation dispatch) talks to them
    through this protocol — transport choice is invisible above the pool.
    """

    @property
    def remote_peer_id(self) -> str: ...

    @property
    def is_closed(self) -> bool: ...

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
        bounds: "Bounds | None" = None,
        included: list[dict[str, Any]] | None = None,
    ) -> ExecuteResponse: ...

    async def aclose(self) -> None: ...


class RemoteConnectionPool:
    """Manages outbound connections to remote peers.

    Connections are:
    - Created lazily on first use (connect + handshake)
    - Cached by peer_id for reuse (any transport)
    - Evicted on error so the next call re-dials
    - Closed on peer shutdown

    Address resolution scans ``system/peer/transport/`` and filters by
    the entity's Base58 ``peer_id`` body field (V7 v7.64 §1.4 — the path
    key is ``peer_id_hex``, but the dialer holds only the Base58 form).
    Selects per D1: ``primary`` first, then lex by profile-id. The dialer
    walks BOTH ``tcp`` and ``http`` profiles in D1 order and dials the
    first that connects (R1 — Round-2 LOCKED).
    """

    def __init__(
        self,
        keypair: Keypair,
        content_store: ContentStore,
        entity_tree: EntityTree,
        emit_pathway: "EmitPathway | None" = None,
        keepalive_config: "KeepaliveConfig | None" = None,
    ) -> None:
        from entity_core.peer.liveness import KeepaliveConfig

        self._keypair = keypair
        self._content_store = content_store
        self._entity_tree = entity_tree
        self._emit_pathway = emit_pathway
        self._connections: dict[str, RemoteEndpoint] = {}
        self._lock = asyncio.Lock()
        # §5 keepalive: one loop task per pooled outbound connection
        # (outbound is what liveness tracks). MUST per §12.1 — app-level,
        # never disabled because a transport carries its own ping (§5.1).
        self._keepalive_config = keepalive_config or KeepaliveConfig()
        self._keepalive_tasks: dict[str, asyncio.Task] = {}
        # §5.4 adaptive suppression: monotonic seconds of the last
        # successful exchange per peer; pings are skipped while the
        # connection is actively exchanging messages.
        self._last_activity: dict[str, float] = {}
        # §A4: per-tick freshness is impl-internal — the status entity is
        # transition-written only. Wall-clock ms of the last exchange per
        # peer, snapshotted into a demotion write as its `last_seen`
        # evidence ("when I last heard from this peer as of this
        # transition"). Peer-level fact, deliberately not popped on
        # eviction: the demotion write happens after the binding is gone.
        self._last_heard_ms: dict[str, int] = {}

    async def get_connection(self, peer_id: str) -> RemoteEndpoint:
        """Get or create a connection to a remote peer.

        Walks profile candidates in D1 order (primary first, then lex)
        across both `tcp` and `http` transport types; dials the first
        that connects. Returns a `RemoteEndpoint` (TCP `Connection` or
        `HttpConnection`) — callers do not branch on transport.
        """
        if peer_id in self._connections:
            return self._connections[peer_id]

        async with self._lock:
            if peer_id in self._connections:
                return self._connections[peer_id]

            candidates = self._list_profile_candidates(peer_id)
            if not candidates:
                raise ConnectionError(
                    f"No live transport profile for peer {peer_id}. "
                    f"Register a tcp or http profile under "
                    f"system/peer/transport/<peer_id_hex>/<profile_id> "
                    f"(V7 v7.64 §1.4 — hex of the peer's `system/peer` "
                    f"content_hash)."
                )

            from entity_core.peer.connection import Connection
            from entity_core.peer.http_client import HttpConnection

            failures: list[str] = []
            for profile_id, transport_type, url in candidates:
                logger.debug(
                    "Dialing remote peer %s via %s/%s at %s",
                    peer_id[:16], transport_type, profile_id, url,
                )
                try:
                    if transport_type == "tcp":
                        host, port = _parse_tcp_endpoint_url(url)
                        endpoint: RemoteEndpoint = await Connection.connect(
                            host, port, self._keypair, expected_peer_id=peer_id
                        )
                    elif transport_type == "http":
                        endpoint = await HttpConnection.connect(
                            url, self._keypair, expected_peer_id=peer_id
                        )
                    else:
                        failures.append(
                            f"{profile_id}({transport_type}): unsupported transport"
                        )
                        continue
                except Exception as e:
                    failures.append(f"{profile_id}({transport_type} {url}): {e}")
                    continue

                self._connections[peer_id] = endpoint
                logger.debug(
                    "Connected to remote peer %s via %s/%s",
                    peer_id[:16], transport_type, profile_id,
                )
                self._persist_session(endpoint)
                # Amendment 12 §A3: `connected` on establish (dialer end;
                # the responder end writes its own at authenticate-complete).
                self._write_connected(endpoint, transport_type, url)
                self._start_keepalive(peer_id, endpoint)
                return endpoint

            raise ConnectionError(
                f"Failed to connect to peer {peer_id} on any live profile: "
                + "; ".join(failures)
            )

    def _persist_session(self, endpoint: "RemoteEndpoint") -> None:
        """Write the per-peer session entity locally after a successful dial.

        Per PROPOSAL-TRANSPORT-FAMILY R6 §9.1 R6-a (grantee side): the cap
        the remote granted me is recorded at
        ``system/peer/session/{remote_peer_id}.held_capability``. §10
        dispatch will read this to authenticate outbound without
        re-handshaking.

        No-op when the pool has no ``emit_pathway`` (constructed bare in
        some unit tests), when the endpoint has no capability bound
        (degenerate ``wait_for_capability=False`` call), or when the
        endpoint is for our own peer (no self-session, §9.1 R6-f).
        """
        if self._emit_pathway is None:
            return
        capability = getattr(endpoint, "capability", None)
        if not capability:
            return
        session_obj = getattr(endpoint, "session", None)
        if session_obj is None:
            return
        # §9.1 R6-f — no self-session.
        if session_obj.remote_peer_id == self._keypair.peer_id:
            return

        from entity_core.peer.session_entity import write_session
        from entity_core.protocol.entity import Entity

        cap_entity = (
            capability if isinstance(capability, Entity)
            else Entity.from_dict(capability)
        )
        # §9.1 R6-d: chain is the cap delegation chain ONLY (leaf→root).
        # The connect cap is self-rooted; chain = [leaf] (no parents).
        # Supporting entities (granter identity, cap signature) are not
        # included in chain — they are reachable via cap.data.granter
        # (content store) and via ed25519 redetermination respectively.
        parent_chain: list[Entity] = []
        try:
            write_session(
                self._emit_pathway,
                self._content_store,
                self._entity_tree,
                remote_peer_id=session_obj.remote_peer_id,
                remote_identity_hash=session_obj.remote_identity_hash,
                remote_public_key=session_obj.remote_public_key,
                held_capability=(cap_entity, parent_chain),
            )
        except Exception as e:
            # Persisting the session entity is best-effort — failing here
            # MUST NOT cause an otherwise-successful dial to surface as an
            # error. R6 inspectability/reconnect-reuse is a property added
            # on top of the live connection, not a precondition for it.
            logger.warning(
                "Failed to persist client-side session entity for %s: %s",
                session_obj.remote_peer_id[:16], e,
            )

    def remove_connection(
        self, peer_id: str, expected: "RemoteEndpoint | None" = None
    ) -> bool:
        """Evict a connection from the pool (e.g., on error).

        The connection's close is best-effort; the next get_connection()
        call will re-dial. For TCP the sync close() pre-empts in-flight
        writes; for HTTP each POST is its own socket so eviction is just
        a flag flip — the bg cleanup is scheduled if a running loop is
        available, else dropped (the next dial re-handshakes anyway).

        No-clobber guard (Amendment 12 §A1, behavioral): when ``expected``
        is given, evict only if it is still the currently-bound endpoint
        for this peer — object identity, the ``Arc::ptr_eq`` analog. A
        concurrent re-dial that already replaced the binding (and wrote
        its own ``connected``) is left untouched; a concurrent identical
        failure that already evicted makes this a no-op. Returns whether
        the eviction happened, so the caller can gate the liveness
        demotion on it.

        R6 §9.1 R6-c: the session entity is the durable AUTH record and
        is NOT touched here. Connection-lifecycle marker lives on
        ``system/peer/status``, not on the session entity. The held cap
        survives connection close — that persistence is the whole point
        (cap reuse across reconnect / restart).
        """
        bound = self._connections.get(peer_id)
        if bound is None:
            return False
        if expected is not None and bound is not expected:
            return False
        del self._connections[peer_id]
        self._cancel_keepalive(peer_id)
        self._last_activity.pop(peer_id, None)
        logger.debug("Evicting connection to peer %s", peer_id[:16])
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return True
        loop.create_task(bound.aclose())
        return True

    # --- Amendment 12 liveness slice (rungs 1-2) -------------------------

    def note_activity(self, peer_id: str) -> None:
        """Record a successful exchange for §5.4 adaptive suppression.

        Called by the dispatch seam on every successful remote EXECUTE so
        keepalive pings are suppressed (and the missed counter reset)
        while the connection is actively exchanging messages.
        """
        self._last_activity[peer_id] = time.monotonic()
        self._last_heard_ms[peer_id] = int(time.time() * 1000)

    def demote_on_transport_error(
        self, peer_id: str, failed: "RemoteEndpoint", cause: Exception
    ) -> None:
        """§A1 reactive demotion: a transport failure observed on a
        connection believed active MUST demote peer liveness by writing
        ``system/peer/status = suspect`` (reason ``transport-error``),
        firing the same subscription the keepalive path fires. Also
        evicts the dead connection so the next dispatch re-dials.

        Seam discipline (ruling E, normative): called from the
        direct-dispatch send site only — the caller that both observes
        the send error and holds ``peer_id``. The RELAY terminal-hop
        forward and the dispatch-fallback path MUST NOT demote (they use
        the bare guarded ``remove_connection``).

        No-clobber / idempotency (§A1): the demotion fires only if
        ``failed`` is still the currently-bound endpoint (identity guard
        in ``remove_connection``). A single transport error writes
        ``suspect``, not ``disconnected`` — one failure is not proof of a
        dead peer; §5.4 keepalive escalates.
        """
        if not self.remove_connection(peer_id, expected=failed):
            # `failed` is no longer the bound endpoint — a concurrent
            # re-establishment owns liveness now, or a concurrent failure
            # already demoted. Do not clobber.
            return
        self._write_demotion(
            failed,
            status_reason=("suspect", "transport-error"),
            last_error=str(cause) if cause is not None else None,
        )

    def _write_connected(
        self, endpoint: "RemoteEndpoint", transport: str, address: str
    ) -> None:
        """Write `connected` + the §3.13 connection entity (dialer end).

        Soft-fail: liveness writes are observability-only and never turn
        a successful dial into an error (same contract as
        ``_persist_session``). Skipped for bare pools (no emit pathway),
        endpoints without a session, and self-dials.
        """
        if self._emit_pathway is None:
            return
        session_obj = getattr(endpoint, "session", None)
        if session_obj is None:
            return
        from entity_core.peer import liveness

        ts = liveness.now_ms()
        # Connection entity first (ruling C: write-on-transition, full-
        # conformance surface) so the status entity can carry the path ref.
        write_connection = liveness.write_connection_status(
            self._emit_pathway,
            remote_peer_id=session_obj.remote_peer_id,
            remote_identity_hash=session_obj.remote_identity_hash,
            transport=transport,
            address=address,
            status="active",
            established_at=ts,
        )
        liveness.write_peer_status(
            self._emit_pathway,
            local_peer_id=self._keypair.peer_id,
            remote_peer_id=session_obj.remote_peer_id,
            remote_identity_hash=session_obj.remote_identity_hash,
            status=liveness.STATUS_CONNECTED,
            connected_at=ts,
            connection_ref=(
                liveness.connection_path(session_obj.remote_identity_hash)
                if write_connection is not None else None
            ),
        )

    def _write_demotion(
        self,
        endpoint: "RemoteEndpoint",
        *,
        status_reason: tuple[str, str],
        last_error: str | None = None,
    ) -> None:
        """Write the demotion status + flip ``system/connection`` to closed.

        §A4: the write carries a ``last_seen`` snapshot — the demotion's
        evidence ("when I last heard from this peer as of this
        transition"), taken from the impl-internal freshness map, never
        refreshed at cadence.
        """
        if self._emit_pathway is None:
            return
        session_obj = getattr(endpoint, "session", None)
        if session_obj is None:
            return
        from entity_core.peer import liveness

        status, reason = status_reason
        liveness.write_peer_status(
            self._emit_pathway,
            local_peer_id=self._keypair.peer_id,
            remote_peer_id=session_obj.remote_peer_id,
            remote_identity_hash=session_obj.remote_identity_hash,
            status=status,
            reason=reason,
            last_error=last_error,
            last_seen=self._last_heard_ms.get(session_obj.remote_peer_id),
        )
        liveness.mark_connection_closed(
            self._emit_pathway,
            self._content_store,
            self._entity_tree,
            session_obj.remote_identity_hash,
        )

    def _start_keepalive(self, peer_id: str, endpoint: "RemoteEndpoint") -> None:
        """Start the §5 keepalive loop for a freshly pooled connection."""
        self._cancel_keepalive(peer_id)
        self._last_activity[peer_id] = time.monotonic()
        self._last_heard_ms[peer_id] = int(time.time() * 1000)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:  # pragma: no cover - pool used without a loop
            return
        self._keepalive_tasks[peer_id] = loop.create_task(
            self._keepalive_loop(peer_id, endpoint)
        )

    def _cancel_keepalive(self, peer_id: str) -> None:
        task = self._keepalive_tasks.pop(peer_id, None)
        if task is not None and not task.done():
            task.cancel()

    async def _keepalive_loop(
        self, peer_id: str, endpoint: "RemoteEndpoint"
    ) -> None:
        """§5.4 failure detection for one pooled outbound connection.

        Idle-period app-level ping (EXECUTE ``system/protocol/connect``
        op ``ping``); any successful exchange resets the missed counter
        (adaptive suppression). On ``max_missed`` consecutive misses:
        write ``suspect`` (reason ``keepalive-miss``), grace-wait
        ``timeout_ms``, then — if no reconnection replaced the binding —
        write ``disconnected`` and evict. A dead idle connection that
        never went ``suspect`` via §A1 goes through this same path; both
        orderings are §5.4-conformant.

        The loop exits when its endpoint is no longer the pool binding
        (evicted or replaced) — the no-clobber discipline applied to the
        keepalive writer.
        """
        from entity_core.peer import liveness

        cfg = self._keepalive_config
        interval_s = cfg.interval_ms / 1000.0
        timeout_s = cfg.timeout_ms / 1000.0
        missed = 0
        sequence = 0
        try:
            while True:
                await asyncio.sleep(interval_s)
                if self._connections.get(peer_id) is not endpoint:
                    return
                # §5.4 adaptive suppression: skip the ping during active
                # message exchange; activity also resets the counter.
                last = self._last_activity.get(peer_id, 0.0)
                if time.monotonic() - last < interval_s:
                    missed = 0
                    continue

                sequence += 1
                ok = False
                try:
                    response = await asyncio.wait_for(
                        endpoint.execute(
                            "system/protocol/connect",
                            "ping",
                            {
                                "type": "system/network/ping",
                                "data": {
                                    "timestamp": liveness.now_ms(),
                                    "sequence": sequence,
                                },
                            },
                        ),
                        timeout=timeout_s,
                    )
                    ok = response.status == 200
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.debug(
                        "keepalive ping %d to %s failed: %s",
                        sequence, peer_id[:16], e,
                    )

                if ok:
                    # §A4: pong freshness is impl-internal bookkeeping —
                    # no tree write. The status entity is transition-
                    # written only; `last_seen` is snapshotted into the
                    # demotion write when a transition happens.
                    missed = 0
                    self._last_activity[peer_id] = time.monotonic()
                    self._last_heard_ms[peer_id] = liveness.now_ms()
                    continue

                missed += 1
                if missed < cfg.max_missed:
                    continue

                # Connection failed (§5.4): suspect → grace → disconnected.
                self._write_demotion(
                    endpoint, status_reason=("suspect", "keepalive-miss"),
                )
                await asyncio.sleep(timeout_s)
                if self._connections.get(peer_id) is not endpoint:
                    # Reconnected during the grace period — the new
                    # binding wrote its own `connected`. Do not clobber.
                    return
                # Evict WITHOUT the cancel-self path racing us: drop the
                # binding first, then write. remove_connection cancels
                # this task; from here the loop only returns.
                self._keepalive_tasks.pop(peer_id, None)
                del self._connections[peer_id]
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(endpoint.aclose())
                except RuntimeError:  # pragma: no cover
                    pass
                self._write_demotion(
                    endpoint,
                    status_reason=("disconnected", "keepalive-miss"),
                )
                return
        except asyncio.CancelledError:
            raise

    def _list_profile_candidates(
        self, peer_id: str
    ) -> list[tuple[str, str, str]]:
        """List ordered `(profile_id, transport_type, url)` candidates per D1.

        Per V7 v7.64 §1.4 the profile path is
        ``system/peer/transport/{peer_id_hex}/{profile_id}``. For
        **identity-multihash form** PeerIDs (V7 v7.64 §1.5 ``hash_type
        = 0x00``), the dialer derives ``peer_id_hex`` locally from the
        Base58 PeerID and does an O(1) prefix lookup — no scan needed.
        For SHA-256-form PeerIDs (legacy/privacy choice), the dialer
        falls back to the O(N) scan-and-filter on the Base58 ``peer_id``
        body field (the hex form requires the peer's ``system/peer``
        entity, which may not be locally cached).

        Apply §6.5.1a D5 (transport_type MUST match entity-type suffix),
        and return candidates ordered per Q1 (PROPOSAL §8.9): sort by
        ``(effective_priority asc, profile-id lex)``. ``priority`` is an
        optional ``uint`` on the profile entity (lower = preferred);
        absence defaults to 0 for the reserved ``primary`` profile-id,
        else 100.

        Malformed profiles surface as ConnectionError rather than silently
        filtering out — operators see broken advertisements.
        """
        prefix = "system/peer/transport/"
        full_prefix = self._entity_tree.normalize_uri(prefix)

        # Fast path: identity-form PeerIDs let the dialer compute
        # peer_id_hex locally (V7 v7.64 §1.5 / §2.5 Python audit) — O(1)
        # prefix lookup instead of full-tree scan.
        from entity_core.crypto.identity import derive_peer_from_peer_id
        from entity_core.protocol.auth import compute_peer_identity_hash

        scan_uris: list[str]
        derived = derive_peer_from_peer_id(peer_id)
        if derived is not None:
            peer_hex = compute_peer_identity_hash(peer_id, derived[0]).hex()
            scan_uris = self._entity_tree.list_prefix(
                f"{prefix}{peer_hex}/"
            )
        else:
            # SHA-256-form: legacy scan-and-filter on the Base58 body field.
            scan_uris = self._entity_tree.list_prefix(prefix)

        # (effective_priority, profile_id, transport_type, url)
        profiles: list[tuple[int, str, str, str]] = []
        for uri in scan_uris:
            rest = uri[len(full_prefix):]
            # Expect `{peer_id_hex}/{profile_id}` — exactly one '/' separator.
            if "/" not in rest:
                continue
            peer_id_hex_seg, profile_id = rest.split("/", 1)
            if not peer_id_hex_seg or not profile_id or "/" in profile_id:
                continue
            hash_val = self._entity_tree.get(uri)
            if hash_val is None:
                continue
            entity = self._content_store.get(hash_val)
            if entity is None:
                continue
            entity_type = entity.type
            if entity_type not in (
                "system/peer/transport/tcp",
                "system/peer/transport/http",
            ):
                continue
            # SHA-256-form scan path needs the body-field filter; the
            # identity-form fast path already prefix-restricted, so the
            # check is a no-op there but harmless.
            if entity.data.get("peer_id") != peer_id:
                continue
            expected_suffix = entity_type.rsplit("/", 1)[1]
            declared = entity.data.get("transport_type")
            if declared != expected_suffix:
                raise ConnectionError(
                    f"transport profile at {uri} has type {entity_type} but "
                    f"transport_type={declared!r} (D5: MUST match suffix)"
                )
            endpoint = entity.data.get("endpoint")
            if not isinstance(endpoint, dict):
                raise ConnectionError(
                    f"transport profile at {uri} missing endpoint dict"
                )
            url = endpoint.get("url")
            if not isinstance(url, str) or not url:
                raise ConnectionError(
                    f"transport profile at {uri} missing endpoint.url"
                )

            # Q1 priority resolution: explicit > primary-default-0 > 100.
            raw_priority = entity.data.get("priority")
            if isinstance(raw_priority, int) and raw_priority >= 0:
                effective_priority = raw_priority
            elif profile_id == "primary":
                effective_priority = 0
            else:
                effective_priority = 100

            profiles.append(
                (effective_priority, profile_id, expected_suffix, url)
            )

        profiles.sort(key=lambda p: (p[0], p[1]))
        return [(pid, t, url) for _, pid, t, url in profiles]

    async def close_all(self) -> None:
        """Close all pooled connections. Called during peer shutdown.

        R6 §9.1 R6-c: session entities are NOT modified on close. The
        held cap survives shutdown for the next process's pool to reuse
        (R3a / TV-LT2).
        """
        # Stop keepalive loops first so no ping races the close below.
        tasks = list(self._keepalive_tasks.values())
        self._keepalive_tasks.clear()
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        async with self._lock:
            endpoints = list(self._connections.items())
            self._connections.clear()
        for peer_id, endpoint in endpoints:
            logger.debug("Closing connection to peer %s", peer_id[:16])
            try:
                await endpoint.aclose()
            except Exception:
                pass
