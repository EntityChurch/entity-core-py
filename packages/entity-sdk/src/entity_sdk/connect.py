"""Connection — `SDK-OPERATIONS` v0.8 §7.

One function's worth of surface, and the reason it earns a module is that the
thing it returns is an :class:`~entity_sdk.EntityClient` rather than a
``Connection``. §7.1's own return type is a ``Connection``, but a bare
connection is not usable without re-deriving the two facts every caller needs
next — *whose* namespace peer-relative paths mean, and how to turn an operation
into a cap-checked EXECUTE. The CLI re-derived both at seventeen call sites.

**What this deliberately does not do.** §7.1's `Connection` shape, §7.2 `listen`
and §7.3 `connected_peers` are not wrapped here:

* The connection object already exists (``entity_core.peer.connection.Connection``)
  and carries the negotiated protocols and the session's grants. Re-modelling it
  in the SDK would create a second source for facts that live on the wire
  object.
* §7.2 `listen` belongs to peer lifecycle — you get it from ``PeerBuilder`` and
  ``Peer.start``, not from a client.
* §7.3 `connected_peers` carries an explicit warning in the spec: *"This is a
  pool snapshot, not liveness … a mid-session drop leaves a stale entry that
  still says connected until something reaps it,"* and notes that **two**
  implementations already shipped the snapshot-as-status shape, one of them
  reporting `Connected` straight through a drop. Adding a third
  ``connected_peers()`` that reads the pool would be building the known-bad
  shape on purpose. When this lands it should be a read-model over
  ``system/peer/status`` (`EXTENSION-NETWORK` §5.4.1), which is
  transition-written — and that is a real piece of work, not a wrapper.

**The concurrency floor is not ours to satisfy and is not skipped.** §7's
normative MUST — inbound frame processing concurrent with outbound dispatch on
the same connection, without which bidirectional P2P deadlocks — is a property
of the transport layer in ``entity-core``, which already runs a task per inbound
frame. The SDK cannot weaken it and does not need to re-implement it.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from typing import Any

from entity_core.sdk import ConnectionDispatcher

from entity_sdk.client import EntityClient

__all__ = ["client_for_connection", "connect"]


def client_for_connection(
    connection: Any, *, local_peer_id: str | None = None
) -> EntityClient:
    """Wrap an established ``Connection`` in an :class:`EntityClient`.

    Args:
        connection: An established ``entity_core.peer.connection.Connection``.
        local_peer_id: Whose namespace peer-relative paths resolve to. **Defaults
            to the remote peer**, which is the right default for a client whose
            whole purpose is to operate on the peer it just dialed — ``ls docs/``
            against a remote peer means *their* ``docs/``, not ours. Pass this
            explicitly when the caller is a peer in its own right and means its
            own namespace.

    The returned client has **no Level 0 surface** — there is no honest direct
    store access across a wire (§2.7). ``client.store`` raises accordingly.
    """
    resolved = local_peer_id or connection.session.remote_peer_id
    return EntityClient(ConnectionDispatcher(connection), resolved)


@asynccontextmanager
async def connect(
    host: str,
    port: int,
    keypair: Any,
    *,
    expected_peer_id: str | None = None,
    local_peer_id: str | None = None,
) -> AsyncIterator[EntityClient]:
    """Dial ``host:port``, complete the handshake, yield a ready client (§7.1).

    The full §7.1 sequence runs inside ``Connection.connect``: transport dial,
    HELLO exchange with protocol negotiation, AUTHENTICATE exchange with signed
    nonces, and the capability-grant exchange in both directions. What comes
    back here is the far side of all that, already addressable.

    A context manager because a connection is a resource and §7 gives no
    close semantics — leaving that to the caller is how sockets leak in a CLI
    that exits down an error path.

    Args:
        expected_peer_id: Pin the remote identity. When supplied, a handshake
            with a peer whose id differs fails rather than proceeding — worth
            passing whenever the caller knows who it expects to reach.

    Errors surface as ``entity_core`` transport/handshake exceptions rather
    than §12 status exceptions: §12 is the *dispatched-operation* error model,
    and a failed dial never reached the point of having a status.
    """
    from entity_core.peer.connection import Connection

    connection = await Connection.connect(
        host, port, keypair, expected_peer_id=expected_peer_id
    )
    try:
        yield client_for_connection(connection, local_peer_id=local_peer_id)
    finally:
        connection.close()
        await connection.wait_closed()
