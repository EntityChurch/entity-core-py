"""Level 0 — direct, local, unchecked observation. `SDK-OPERATIONS` §2.7, §6.5.

**This module exists to be a separate name.** §6.5: *"The SDK MUST expose L0
observation through the Level 0 API surface (the `store()` accessor or
equivalent) and L1 observation through the Level 1 API surface. **The naming
MUST carry the boundary.**"* And §2.7 names the anti-pattern outright: *"Mixing
dispatched and direct operations under the same names (both called `get`) is the
anti-pattern — it hides the security boundary."*

So the boundary is a separate object reached through a separate accessor, and
:class:`entity_sdk.EntityClient` has no L0 method of its own. A reader looking
at ``client.store.watch(...)`` can see the level from the call site, which is
the entire requirement.

**L0 is local-only, and that is enforced by construction rather than by a
check.** A :class:`LocalStore` needs an ``EmitPathway``, which is an object only
the peer's own process has. A client built over a ``Connection`` to a remote
peer cannot produce one, so ``client.store`` raises rather than silently
degrading — matching §2.7's *"Level 0 is for the peer owner's code, the code
that built and configured the peer."*

What L0 does **not** skip is the emit pathway: per §2.7, every L0 tree mutation
still fires it, so history, subscription and query all observe the write. The
only thing bypassed is handler dispatch and its capability check.
"""

from __future__ import annotations

from typing import Any

from entity_sdk.events import (
    ChangeStream,
    TreeChangeEvent,
    TreeChangeStream,
    validate_watch_pattern,
)

__all__ = ["LocalStore"]


class LocalStore:
    """Direct observation of the local peer's tree (§6.5 Level 0).

    Always available — no extension required, no capability check. §6.5:
    *"A minimal peer (no extensions) still has pattern-filtered local
    observation via `store().watch()`."*
    """

    def __init__(self, emit_pathway: Any, local_peer_id: str) -> None:
        self._emit = emit_pathway
        self._local_peer_id = local_peer_id

    # -- §6.5 L0 filtered observation ---------------------------------------

    def watch(self, pattern: str) -> TreeChangeStream:
        """Pattern-filtered local event stream. No capability check.

        Same §6.1 grammar as the dispatched surface — exact or ``prefix/*`` —
        because a caller moving between the two levels should not have to learn
        a second pattern language. See
        :func:`entity_sdk.events.validate_watch_pattern` for why the check
        happens here rather than being left to the peer.

        Yields the wider §6.3 :class:`TreeChangeEvent` (with ``previous_hash``):
        at L0 the caller *is* the peer owner, and withholding a field the raw
        pathway already carries would be ceremony rather than a boundary.
        """
        return self.open_change_stream(pattern, wide=True)  # type: ignore[return-value]

    def open_change_stream(
        self, pattern: str, *, wide: bool
    ) -> ChangeStream:
        """Subscribe a new stream to ``pattern`` on the local emit pathway.

        The shared seam under both this class's :meth:`watch` and
        :meth:`entity_sdk.EntityClient.watch`. It exists so the L1 client can
        build a narrow §6.1 stream on the local backend **without reaching into
        this object's privates** — the access-level boundary §6.5 asks for is
        not worth much if the layer above it is coupled to the internals.

        Args:
            wide: ``True`` for the §6.3 four-field ``TreeChangeEvent``,
                ``False`` for the narrow §6.1 ``ChangeEvent``.
        """
        validate_watch_pattern(pattern)
        stream: ChangeStream = (
            TreeChangeStream(on_cancel=self._cancel)
            if wide
            else ChangeStream(on_cancel=self._cancel)
        )
        self._emit.subscribe(pattern, stream)
        return stream

    # -- §6.3 the raw, unfiltered stream ------------------------------------

    def subscribe_events(self) -> TreeChangeStream:
        """Every tree mutation, unfiltered (§6.3).

        This is the designated primitive for "everything", which is why
        :func:`validate_watch_pattern` refuses a bare ``*`` and sends callers
        here instead.
        """
        stream: TreeChangeStream = TreeChangeStream(on_cancel=self._cancel)
        self._emit.subscribe("*", stream)
        return stream

    def _cancel(self, stream: TreeChangeStream) -> None:
        self._emit.unsubscribe(stream)

    # -- L0 reads ------------------------------------------------------------

    @property
    def content_store(self) -> Any:
        """The raw content store. Reads bypass dispatch entirely (§2.7 L0)."""
        return self._emit.content_store

    @property
    def entity_tree(self) -> Any:
        """The raw location index. Reads bypass dispatch entirely (§2.7 L0)."""
        return self._emit.entity_tree

    def __repr__(self) -> str:
        return f"LocalStore(peer={self._local_peer_id!r})"


# Re-exported so callers annotating an L0 stream do not have to reach into
# `entity_sdk.events` for the element type.
_ = TreeChangeEvent
