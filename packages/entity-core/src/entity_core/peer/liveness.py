"""Peer liveness — the §3.13 ``system/peer/status`` write (Amendment 12 §A3).

The **liveness slice**: write ``system/peer/status/{peer}`` on connection
state change — ``connected`` on establish (both ends of the handshake),
``suspect`` on transport error at the direct-dispatch seam (§A1),
``suspect → disconnected`` on keepalive miss (§5.4) — and nothing more.
These are ordinary tree entities, so a write fires any
``system/subscription`` bound to the path: the "no poll" liveness signal
consumers block on. The slice requires none of ``maintain-peer``, the
continuation graph, or the §8 outbox; those compose on top of it.

Shape discipline (rung-1 ruling D): the canonical field set lives at
ENTITY-CORE-PROTOCOL §3.13 only (``peer_id``, ``status`` required;
``connected_at``, ``last_seen``, ``connection`` optional). NETWORK's
put-sites are minimal writes, not exhaustive shapes — a bare
``{peer_id, status}`` write is conformant. ``reason``/``last_error`` are
the Amendment 12 §A2 additive OPTIONAL fields.

Seam discipline (ruling E, normative): the ``suspect`` demotion fires at
the **direct-dispatch send sites only** — never on the RELAY terminal-hop
forward or the dispatch-fallback path (a store-and-forward target is not
"a connection believed active"). The no-clobber guard (§A1) is the
*caller's* job — demote only if the failed connection is still the
currently-bound one; this module only performs the write.

Straight write, not read-modify-write (matches the Go reference
``protocol.WritePeerStatus``): the status entity has no field a writer
must preserve.

Write discipline (§A4, rung-2 ruling 1): the status entity is
**transition-written only** — ``status`` or ``reason`` change. No cadence
writes to the tree; per-tick keepalive freshness is impl-internal
bookkeeping (it drives §5.4 adaptive suppression). ``last_seen`` is a
*snapshot taken at a transition write* — on a demotion, the demotion's
evidence — never a refresh stream. Superseded operational-state entities
are GC-eligible (mechanism impl-defined).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from entity_core.primitives import Uint
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

if TYPE_CHECKING:
    from entity_core.storage.content_store import ContentStore
    from entity_core.storage.emit import EmitPathway
    from entity_core.storage.entity_tree import EntityTree

logger = logging.getLogger(__name__)

PEER_STATUS_PATH_PREFIX = "system/peer/status"
CONNECTION_PATH_PREFIX = "system/connection"

# --- status enum (ENTITY-CORE-PROTOCOL §3.13 — THREE states, ruling D) -------
#: A live connection is established (§6.2).
STATUS_CONNECTED = "connected"
#: A single transport error was observed on a connection believed active
#: (§A1). One failure is not proof of a dead peer — it may be this pooled
#: socket only. The keepalive/grace path (§5.4) escalates suspect →
#: disconnected.
STATUS_SUSPECT = "suspect"
#: The peer is gone: keepalive miss (§5.4), release (§4.2), or graceful
#: close (§4.4).
STATUS_DISCONNECTED = "disconnected"
# NOTE: "reconnecting" is NOT a status-entity value — it belongs to
# system/network/peer-summary (§2.8), the derived status-op output
# (rung-1 ruling D, an arch-authored D-class divergence caught at review).

# --- §A2 transition reasons (OPTIONAL kebab enum) -----------------------------
# Recovery mapping a consumer / the reconnect continuation reads off `reason`:
#   transport-error, keepalive-miss → backoff-reconnect (§4.1)
#   auth-rejected                   → re-handshake (§6.3); do NOT reuse held cap
#   peer-shutdown, local-release    → terminal; session ended deliberately
#   peer-idle, peer-migration       → preserve subscriptions; expect resume
# A reader treats an unrecognized value as generic (MUST-ignore-unknowns)
# and falls back to backoff.
REASON_TRANSPORT_ERROR = "transport-error"
REASON_KEEPALIVE_MISS = "keepalive-miss"
REASON_AUTH_REJECTED = "auth-rejected"
REASON_PEER_SHUTDOWN = "peer-shutdown"
REASON_PEER_IDLE = "peer-idle"
REASON_PEER_MIGRATION = "peer-migration"
REASON_LOCAL_RELEASE = "local-release"


@dataclass(frozen=True)
class KeepaliveConfig:
    """§2.3 keepalive parameters (defaults per spec; impl-defined §12.4).

    The §A3 floor's consumer latency contract: an idle-dead connection is
    demoted within ``interval_ms × max_missed + timeout_ms`` (defaults
    ≈ 100 s). A consumer needing tighter latency configures keepalive,
    not polls.
    """

    interval_ms: int = 30_000
    timeout_ms: int = 10_000
    max_missed: int = 3


def peer_status_path(remote_identity_hash: bytes) -> str:
    """Tree path for a remote peer's status entity.

    Per V7 v7.64 §1.4 the segment is lowercase hex of the remote's
    ``system/peer`` content_hash (same convention as the session entity).
    """
    return f"{PEER_STATUS_PATH_PREFIX}/{remote_identity_hash.hex()}"


def connection_path(remote_identity_hash: bytes) -> str:
    """Tree path for a remote peer's ``system/connection`` entity (§3.13)."""
    return f"{CONNECTION_PATH_PREFIX}/{remote_identity_hash.hex()}"


def now_ms() -> int:
    return int(time.time() * 1000)


def write_peer_status(
    emit_pathway: "EmitPathway",
    *,
    local_peer_id: str,
    remote_peer_id: str,
    remote_identity_hash: bytes,
    status: str,
    reason: str | None = None,
    last_error: str | None = None,
    connected_at: int | None = None,
    last_seen: int | None = None,
    connection_ref: str | None = None,
    ctx: EmitContext | None = None,
) -> bytes | None:
    """Write ``system/peer/status/{remote_hex}`` through the emit pathway.

    Returns the entity hash, or ``None`` when the write is skipped:

    - no self-status (§9.1 R6-f analog): a peer never writes a liveness
      entity keyed by its own peer_id — local dispatch has no connection
      to observe;
    - empty ``remote_identity_hash``: the path key requires the remote's
      canonical identity hash (a SHA-256-form remote without a
      public_key threaded through can't be keyed) — graceful skip, same
      contract as the session write.

    The write is observability-only and soft-fails: it must never mask
    the transport error the caller is about to surface.
    """
    if remote_peer_id == local_peer_id:
        return None
    if not remote_identity_hash:
        logger.debug(
            "peer-status %s skipped for %s: no identity hash (path key required)",
            status, remote_peer_id[:16],
        )
        return None

    data: dict = {
        "peer_id": remote_peer_id,
        "status": status,
    }
    if reason is not None:
        data["reason"] = reason
    if last_error is not None:
        data["last_error"] = last_error
    if connected_at is not None:
        data["connected_at"] = Uint(int(connected_at))
    if last_seen is not None:
        data["last_seen"] = Uint(int(last_seen))
    if connection_ref is not None:
        data["connection"] = connection_ref

    entity = Entity(type="system/peer/status", data=data)
    if ctx is None:
        ctx = EmitContext.bootstrap()
    try:
        result = emit_pathway.emit(peer_status_path(remote_identity_hash), entity, ctx)
    except Exception as e:
        logger.warning(
            "peer-status %s write for %s failed: %s", status, remote_peer_id[:16], e,
        )
        return None
    return result.hash if result.hash is not None else entity.compute_hash()


def write_connection_status(
    emit_pathway: "EmitPathway",
    *,
    remote_peer_id: str,
    remote_identity_hash: bytes,
    transport: str,
    address: str,
    status: str,
    established_at: int,
    ctx: EmitContext | None = None,
) -> bytes | None:
    """Write ``system/connection/{remote_hex}`` — write-on-transition only
    (§3.13: establish → ``active``, close/failure → ``closed``).

    MUST at full NETWORK conformance (§12.1), NOT part of the §A3 floor
    (rung-1 ruling C) — a floor-only consumer MUST NOT assume this entity.
    Soft-fails like the status write.
    """
    if not remote_identity_hash:
        return None
    entity = Entity(
        type="system/connection",
        data={
            "peer_id": remote_peer_id,
            "transport": transport,
            "address": address,
            "status": status,
            "established_at": Uint(int(established_at)),
        },
    )
    if ctx is None:
        ctx = EmitContext.bootstrap()
    try:
        result = emit_pathway.emit(connection_path(remote_identity_hash), entity, ctx)
    except Exception as e:
        logger.warning(
            "system/connection %s write for %s failed: %s",
            status, remote_peer_id[:16], e,
        )
        return None
    return result.hash if result.hash is not None else entity.compute_hash()


def mark_connection_closed(
    emit_pathway: "EmitPathway",
    content_store: "ContentStore",
    entity_tree: "EntityTree",
    remote_identity_hash: bytes,
    ctx: EmitContext | None = None,
    expected_hash: bytes | None = None,
) -> None:
    """Flip an existing ``system/connection/{remote_hex}`` to ``closed``.

    Read-modify-write of the transition field only, preserving the
    establish-time ``transport``/``address``/``established_at`` (§3.13:
    "updated on close or failure"). No-op when no connection entity was
    ever written (floor-only operation — ruling C).

    ``expected_hash`` is the §A1 no-clobber guard in CAS form: when given,
    the flip happens only if the currently-bound entity is still the one
    this closer wrote at establish. A re-established connection (which
    wrote its own fresh ``active``) is left untouched by a stale closer's
    teardown.
    """
    if not remote_identity_hash:
        return
    try:
        uri = entity_tree.normalize_uri(connection_path(remote_identity_hash))
        h = entity_tree.get(uri)
        if h is None:
            return
        if expected_hash is not None and h != expected_hash:
            return
        existing = content_store.get(h)
        if existing is None or existing.data.get("status") == "closed":
            return
        data = dict(existing.data)
        data["status"] = "closed"
        entity = Entity(type="system/connection", data=data)
        if ctx is None:
            ctx = EmitContext.bootstrap()
        emit_pathway.emit(connection_path(remote_identity_hash), entity, ctx)
    except Exception as e:
        logger.warning("system/connection close transition failed: %s", e)
