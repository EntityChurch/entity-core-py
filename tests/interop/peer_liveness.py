"""One liveness probe for the interop suite: *is a peer there*, not *is a socket*.

**A liveness probe that tests for a socket rather than for a peer converts a
foreign process into a false failure in your own diff.** That is a ratified
lesson in `AGENTS.md` (2026-08-19, third fixed-port instance) — an unrelated
container publishing 9000 makes a socket probe see a listener, so the suite does
**not** skip and dies mid-handshake with an error that reads exactly like a
protocol regression in whatever you just changed.

Measured again 2026-08-22, and the observed failure was worse than the recorded
one: with a Selenium container on 9000 the run did not error, it **hung** — an
ESTABLISHED connection to a server that will never speak this protocol, blocked
in `ep_poll` with no timeout, indefinitely. A suite that hangs is worse than one
that fails: there is no output to read, no attributable row, and CI reports a
timeout against the whole run rather than against the probe.

Five modules had each hand-rolled the same socket-only probe. That is the
two-representations law with the **probe** as the subject, so the fix is this
module and not five patches: a concept with N implementations in one process
diverges at the copy nobody re-reads.

The rule this encodes: **a probe must complete a handshake and read the remote
peer id before declaring a peer available, and every step must be bounded by a
timeout.** Anything less is a claim about TCP, not about a peer.
"""

from __future__ import annotations

import asyncio

from entity_core.crypto.identity import Keypair
from entity_core.peer.connection import Connection

#: Bound on the whole connect+handshake. Generous for a local peer, and short
#: enough that a foreign listener costs seconds rather than the whole run.
HANDSHAKE_TIMEOUT_S = 5.0


async def open_peer(
    host: str,
    port: int,
    keypair: Keypair | None = None,
    *,
    timeout: float = HANDSHAKE_TIMEOUT_S,
    wait_for_capability: bool = True,
) -> Connection | None:
    """Connect and complete the handshake, or ``None``.

    ``None`` means "no entity peer here" for every reason a caller should treat
    alike: nothing listening, something listening that is not a peer, a peer too
    slow to handshake, or a handshake that produced no remote peer id.

    Never raises — a liveness probe that can throw pushes its own failure modes
    into the caller's assertions, which is how a foreign process ends up
    reported as a defect in the code under test.
    """
    if keypair is None:
        keypair = Keypair.generate()
    try:
        conn = await asyncio.wait_for(
            Connection.connect(
                host, int(port), keypair,
                wait_for_capability=wait_for_capability,
            ),
            timeout=timeout,
        )
    except Exception:
        # Broad on purpose, and the breadth IS the fix: whatever is on this
        # port may not speak the protocol, so the handshake's decode path can
        # raise anything at all — `IncompleteReadError`, a CBOR decode error, a
        # struct error. Enumerating the exceptions we happened to see is how
        # the next foreign process gets reported as a defect in our code.
        return None

    # A handshake that produced no peer id is not a peer, however well the
    # bytes flowed.
    if conn.session.remote_peer_id is None:
        await close_quietly(conn)
        return None
    return conn


async def close_quietly(conn: Connection | None) -> None:
    """Close a probe connection without letting teardown fail a test."""
    if conn is None:
        return
    try:
        conn.close()
        await asyncio.wait_for(conn.wait_closed(), timeout=HANDSHAKE_TIMEOUT_S)
    except Exception:
        pass


async def peer_available(
    host: str,
    port: int,
    keypair: Keypair | None = None,
    *,
    timeout: float = HANDSHAKE_TIMEOUT_S,
) -> bool:
    """``True`` only if a real entity peer answered a handshake at host:port."""
    conn = await open_peer(host, port, keypair, timeout=timeout)
    if conn is None:
        return False
    await close_quietly(conn)
    return True


def skip_reason(host: str, port: int) -> str:
    """The message a skip should carry.

    It names the handshake explicitly, because "no peer at 127.0.0.1:9000" gets
    read as "nothing is listening" — and the case that costs a day is the one
    where something *is* listening and it is not ours.
    """
    return (
        f"no entity peer completed a handshake at {host}:{port} "
        "(nothing listening, or something listening that is not an entity "
        "peer — check `ss -ltnp` and `podman ps` before treating this as a "
        "missing peer)"
    )
