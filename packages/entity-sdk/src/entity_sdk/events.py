"""Change notification — `SDK-OPERATIONS` v0.8 §6.

§6's conformance note is unusually explicit about what is and is not binding:
*"the semantic pieces (pull-style change notification, pattern-filtered,
exact-or-prefix-glob) are conformance-bearing. The exact factory name and
return-type construction are platform-idiomatic … Python uses async
iterators."* So :class:`ChangeStream` is an async iterator, and what is held to
the spec is the pattern grammar, the event shape, and the delivery guarantees.

**Two event shapes, deliberately not merged.** §6.1's ``ChangeEvent`` has three
fields; §6.3's ``TreeChangeEvent`` adds ``previous_hash``. Collapsing them into
one type with an optional field would be tidier Python and wrong: the narrow
shape is what §6.1 promises a `watch()` caller, and widening it silently makes
the extra field part of the contract on the day someone reads it off a stream
and depends on it.

**Three representations of one change, so read the projection carefully.** The
peer's internal ``entity_core.storage.emit.ChangeEvent`` carries
``(kind, uri, hash, entity, previous_hash, context, cascade_depth)``; the two
SDK shapes above carry three and four fields. ``kind`` is an enum of *three*
values (created / updated / deleted) and ``event_type`` is a string of *two*
("put" / "remove") — created **and** updated both mean "put". A projection that
mapped the enum name straight through would emit an ``event_type`` no consumer
in any other implementation recognises.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from entity_sdk.errors import BadRequest

__all__ = [
    "ChangeEvent",
    "TreeChangeEvent",
    "ChangeStream",
    "validate_watch_pattern",
    "project_change_event",
    "project_tree_change_event",
]


@dataclass(frozen=True, slots=True)
class ChangeEvent:
    """§6.1 — what a ``watch()`` stream yields."""

    #: "put" | "remove". Note "put" covers both create and update; the wire
    #: vocabulary has two values, not three.
    event_type: str
    path: str
    #: New content hash. ``None`` on remove.
    new_hash: bytes | None


@dataclass(frozen=True, slots=True)
class TreeChangeEvent:
    """§6.3 — the raw stream's shape. Adds ``previous_hash``."""

    event_type: str
    path: str
    new_hash: bytes | None
    previous_hash: bytes | None


_T = TypeVar("_T", ChangeEvent, TreeChangeEvent)


class _EndOfStream:
    """Queue sentinel marking a cancelled stream.

    Cancellation has to be something the queue *carries*, not just a flag on
    the object: a consumer parked inside ``queue.get()`` is woken by an item
    arriving and by nothing else. A flag checked at the top of the loop is only
    read after an item arrives, which on a quiet stream is never — so a flag
    alone deadlocks the ordinary "one task iterates, another cancels" shape.

    Pushing it through the same FIFO also gets the drain semantics for free:
    events queued before the cancel are still delivered, because they are
    already ahead of the sentinel.
    """

    __slots__ = ()


_END = _EndOfStream()


def validate_watch_pattern(pattern: str) -> None:
    """Enforce §6.1's *"two forms only"* grammar.

    Valid::

        knowledge/articles/intro      exact path match
        knowledge/articles/*          prefix match

    Everything else raises :class:`BadRequest` (400, the status §6.1 assigns to
    invalid pattern syntax).

    **This check is load-bearing, not defensive.** The peer's emit-pathway
    matcher (`entity_core.storage.emit._pattern_matches`) handles ``*``,
    ``prefix/*`` and exact, and falls through to an **exact string compare** for
    anything else. So ``knowledge/*/intro`` — a form §6.1 explicitly reserves —
    does not error there: it registers happily and then never matches anything,
    for the life of the process. Silently subscribing a caller to nothing is a
    worse failure than refusing them, because there is no moment at which it
    looks wrong. Converting it to a 400 at the SDK boundary is the whole reason
    this function exists.

    A bare ``*`` is rejected too. It is neither of §6.1's two forms, and the
    spec already designates a primitive for "everything":
    ``store().subscribe_events()`` (§6.3). Pointing the caller there keeps
    ``watch()`` to exactly the specified grammar instead of quietly growing a
    third form.
    """
    if pattern == "*":
        raise BadRequest(
            400,
            "invalid_pattern",
            "'*' is not one of §6.1's two pattern forms (exact, or prefix/*). "
            "For an unfiltered stream use store().subscribe_events() (§6.3).",
        )
    if not pattern:
        raise BadRequest(400, "invalid_pattern", "pattern must not be empty")

    star_count = pattern.count("*")
    if star_count == 0:
        return  # exact match
    if star_count == 1 and pattern.endswith("/*"):
        return  # prefix match
    raise BadRequest(
        400,
        "invalid_pattern",
        f"{pattern!r} is not one of §6.1's two pattern forms. Only an exact "
        f"path or a trailing '/*' prefix is specified; interior wildcards "
        f"(e.g. 'a/*/b') are reserved for future specification. Note the peer "
        f"would accept this pattern and never match it, which is why the SDK "
        f"refuses it here.",
    )


def _event_type(kind: Any) -> str:
    """Project the peer's three-valued ``ChangeKind`` onto §6's two values."""
    value = getattr(kind, "value", kind)
    return "remove" if value == "deleted" else "put"


def project_change_event(event: Any) -> ChangeEvent:
    """Project an internal ``emit.ChangeEvent`` onto the §6.1 shape."""
    return ChangeEvent(
        event_type=_event_type(event.kind),
        path=event.uri,
        new_hash=event.hash,
    )


def project_tree_change_event(event: Any) -> TreeChangeEvent:
    """Project an internal ``emit.ChangeEvent`` onto the §6.3 shape."""
    return TreeChangeEvent(
        event_type=_event_type(event.kind),
        path=event.uri,
        new_hash=event.hash,
        previous_hash=event.previous_hash,
    )


class ChangeStream(Generic[_T]):
    """An async iterator of change events, with an explicit cancel.

    Python's §6.1 ``ChangeStream``. Usable three ways::

        async for change in stream: ...          # iterate
        async with client.watch("docs/*") as s:  # scoped
            ...
        stream.unwatch()                         # §6.2 explicit cancel

    **The queue is unbounded on purpose.** §6.1: implementations *"MAY coalesce
    rapid changes to the same path but **MUST NOT** silently drop changes unless
    the underlying subscription has ``rate_limit`` configured."* A bounded queue
    with any drop-on-full policy would violate that, and it would do so exactly
    under load — when the dropped event matters most and the test suite is least
    likely to be watching. Memory growth under a slow consumer is the honest
    failure and the one the caller can see.

    Delivery is Phase-2 async (SYSTEM-COMPOSITION §1.3), and per-path ordering
    is preserved because the peer emits per path in order and this queue is
    FIFO. Cross-path ordering is implementation-defined, as §6 allows.
    """

    def __init__(self, on_cancel: Any = None) -> None:
        self._queue: asyncio.Queue[Any] = asyncio.Queue()
        self._on_cancel = on_cancel
        self._closed = False

    # -- the emit-pathway listener contract ---------------------------------

    async def on_change(self, event: Any) -> None:
        """Satisfies ``entity_core.storage.emit.AsyncChangeListener``."""
        if self._closed:
            return
        await self._queue.put(self._project(event))

    def _project(self, event: Any) -> Any:  # overridden per stream flavour
        return project_change_event(event)

    # -- iteration -----------------------------------------------------------

    def __aiter__(self) -> AsyncIterator[_T]:
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[_T]:
        while True:
            getter = asyncio.ensure_future(self._queue.get())
            try:
                item = await getter
            except GeneratorExit:
                getter.cancel()
                raise
            if isinstance(item, _EndOfStream):
                # Put it back so a second iteration over a closed stream also
                # terminates instead of parking on an empty queue forever.
                self._queue.put_nowait(_END)
                return
            yield item

    async def next_event(self, timeout: float | None = None) -> _T:
        """Await one event. Convenience for tests and simple consumers.

        Raises:
            StopAsyncIteration: if the stream is cancelled and drained. An
                exception rather than ``None`` because ``None`` would be
                indistinguishable from a legitimately-absent value at every
                call site.
        """
        item = (
            await self._queue.get()
            if timeout is None
            else await asyncio.wait_for(self._queue.get(), timeout)
        )
        if isinstance(item, _EndOfStream):
            self._queue.put_nowait(_END)
            raise StopAsyncIteration("stream cancelled")
        return item  # type: ignore[no-any-return]

    def pending(self) -> int:
        """Events queued but not yet consumed.

        Excludes the end-of-stream sentinel — it is bookkeeping, not an event,
        and counting it would make a cancelled empty stream report 1 pending.
        """
        size = self._queue.qsize()
        if self._closed and size:
            # The sentinel is always last, so at most one is in flight.
            return size - 1
        return size

    # -- §6.2 cancellation ---------------------------------------------------

    def unwatch(self) -> None:
        """Cancel the subscription (§6.2). Idempotent.

        Detaches from the backend *and* pushes the end-of-stream sentinel, so a
        consumer already parked in ``async for`` wakes and exits. Detaching
        alone leaves that consumer hanging forever — see :class:`_EndOfStream`.
        """
        if self._closed:
            return
        self._closed = True
        if self._on_cancel is not None:
            self._on_cancel(self)
            self._on_cancel = None
        try:
            self._queue.put_nowait(_END)
        except RuntimeError:
            # No running loop — reachable from `__del__` during interpreter
            # teardown. The subscription is already detached, which is the part
            # that matters; there is no consumer left to wake.
            pass

    @property
    def closed(self) -> bool:
        return self._closed

    async def aclose(self) -> None:
        self.unwatch()

    async def __aenter__(self) -> ChangeStream[_T]:
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.unwatch()

    def __del__(self) -> None:
        """§6.2 SHOULD: auto-cancel on handle drop.

        Best-effort — ``__del__`` runs at an arbitrary point during teardown,
        where the interpreter may already be tearing down the objects the
        cancel callback touches. An exception raised here is printed and
        swallowed by Python, so it would be noise, not a signal; the explicit
        :meth:`unwatch` is the reliable path and §6.2 requires it be available
        for exactly this reason.
        """
        try:
            self.unwatch()
        except Exception:  # noqa: BLE001 - see docstring
            pass


class TreeChangeStream(ChangeStream[TreeChangeEvent]):
    """A :class:`ChangeStream` yielding the wider §6.3 shape."""

    def _project(self, event: Any) -> TreeChangeEvent:
        return project_tree_change_event(event)
