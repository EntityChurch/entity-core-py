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
from typing import TYPE_CHECKING, Any, Protocol

from entity_core.protocol.messages import ExecuteResponse

if TYPE_CHECKING:
    from entity_core.crypto.identity import Keypair
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
    ) -> None:
        self._keypair = keypair
        self._content_store = content_store
        self._entity_tree = entity_tree
        self._emit_pathway = emit_pathway
        self._connections: dict[str, RemoteEndpoint] = {}
        self._lock = asyncio.Lock()

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

    def remove_connection(self, peer_id: str) -> None:
        """Evict a connection from the pool (e.g., on error).

        The connection's close is best-effort; the next get_connection()
        call will re-dial. For TCP the sync close() pre-empts in-flight
        writes; for HTTP each POST is its own socket so eviction is just
        a flag flip — the bg cleanup is scheduled if a running loop is
        available, else dropped (the next dial re-handshakes anyway).

        R6 §9.1 R6-c: the session entity is the durable AUTH record and
        is NOT touched here. Connection-lifecycle marker lives on
        ``system/peer/status``, not on the session entity. The held cap
        survives connection close — that persistence is the whole point
        (cap reuse across reconnect / restart).
        """
        endpoint = self._connections.pop(peer_id, None)
        if endpoint is None:
            return
        logger.debug("Evicting connection to peer %s", peer_id[:16])
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(endpoint.aclose())

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
        async with self._lock:
            endpoints = list(self._connections.items())
            self._connections.clear()
        for peer_id, endpoint in endpoints:
            logger.debug("Closing connection to peer %s", peer_id[:16])
            try:
                await endpoint.aclose()
            except Exception:
                pass
