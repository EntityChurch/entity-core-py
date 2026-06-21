"""Lightweight observation primitives for debugging cross-impl + perf probes.

Sibling to wb-go's ``perfreview/inspect.go`` — same idea, smaller surface.
The single highest-leverage primitive is the **dispatch tap**: wrap any
handler, capture every response, query the histogram. One call gives you
"19 × revision/fetch-diff/base_not_a_version" instead of reading source
and theorizing.

Companion: the **content tap** wraps a ContentStore and records every
put, indexed by entity type. Useful when the question is "what content
actually got persisted in this run".

Both primitives are zero-cost when not installed and add no behavior —
pure observation. Designed for use from tests, the CLI, or ad-hoc REPL
inspection during a debugging session.

Usage::

    from entity_core.diagnostic import DispatchTap, ContentTap

    tap = DispatchTap()
    wrapped = tap.wrap(revision_handler)
    # ...run a probe that calls `wrapped`...
    print(tap.histogram())
    # → [('system/revision', 'fetch-diff', 400, 'base_not_a_version', 19),
    #    ('system/revision', 'fetch-diff', 200, None, 1), ...]

    cs_tap = ContentTap(content_store)
    # ...run a probe that puts entities...
    print(cs_tap.histogram())
    # → [('system/revision/entry', 20), ('system/tree/snapshot/node', 12), ...]
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import (
    ContentStore,
    ContentStoreEvent,
    NotifyingContentStore,
)
from entity_core.storage.emit import ChangeEvent, EmitPathway

__all__ = [
    "DispatchTap",
    "DispatchRecord",
    "ContentTap",
    "ContentRecord",
    "BindingTap",
    "BindingRecord",
    "chain_trace",
    "ChainTraceResult",
]


HandlerFn = Callable[
    [str, str, dict[str, Any], Any], Awaitable[dict[str, Any]]
]


@dataclass
class DispatchRecord:
    """One observed handler dispatch.

    The shape mirrors wb-go's perfreview tap record so the two telemetry
    streams diff cleanly. `error_code` and `error_message` are pulled from
    the standard `result.data.{code,message}` shape used by
    ``_error_response``; if a handler returns a non-standard error shape
    both stay None and the raw result_type tells you why.
    """

    timestamp: float
    handler_pattern: str
    operation: str
    status: int
    error_code: str | None
    error_message: str | None
    result_type: str | None


class DispatchTap:
    """Capture every response from one or more wrapped handlers.

    Thread-affine — built for single-event-loop use, the same world as
    pytest-asyncio and the dispatcher. No locks. If you need cross-thread
    capture, wrap calls to ``record`` yourself.
    """

    def __init__(self) -> None:
        self.records: list[DispatchRecord] = []

    def wrap(self, handler: HandlerFn) -> HandlerFn:
        """Return a wrapper that records every dispatch through `handler`.

        Pass-through on the result — no behavior change. Exceptions are
        recorded with status=500 then re-raised so test failures surface
        normally.
        """

        async def wrapped(
            path: str,
            operation: str,
            params: dict[str, Any],
            ctx: Any,
        ) -> dict[str, Any]:
            try:
                result = await handler(path, operation, params, ctx)
            except Exception:
                self._record(
                    handler_pattern=path,
                    operation=operation,
                    status=500,
                    result=None,
                )
                raise
            self._record(
                handler_pattern=path,
                operation=operation,
                status=result.get("status", 200),
                result=result.get("result"),
            )
            return result

        return wrapped

    def _record(
        self,
        handler_pattern: str,
        operation: str,
        status: int,
        result: Any,
    ) -> None:
        error_code: str | None = None
        error_message: str | None = None
        result_type: str | None = None
        if isinstance(result, dict):
            result_type = result.get("type")
            data = result.get("data")
            if isinstance(data, dict):
                error_code = data.get("code")
                error_message = data.get("message")
        self.records.append(
            DispatchRecord(
                timestamp=time.monotonic(),
                handler_pattern=handler_pattern,
                operation=operation,
                status=status,
                error_code=error_code,
                error_message=error_message,
                result_type=result_type,
            )
        )

    def histogram(self) -> list[tuple[str, str, int, str | None, int]]:
        """Return ``[(pattern, operation, status, error_code, count), ...]``
        sorted by count descending.

        Identical-status records with distinct ``error_code`` are kept
        separate — the whole point is naming the exact failure mode.
        """
        counter: Counter[tuple[str, str, int, str | None]] = Counter()
        for r in self.records:
            counter[(r.handler_pattern, r.operation, r.status, r.error_code)] += 1
        return [
            (pattern, op, status, code, count)
            for (pattern, op, status, code), count in counter.most_common()
        ]

    def failures(self) -> list[DispatchRecord]:
        """All non-2xx records, oldest first."""
        return [r for r in self.records if r.status >= 300]

    def clear(self) -> None:
        self.records.clear()

    def summary(self) -> str:
        """One-line-per-bucket histogram, formatted for log/REPL eyeballing.

        Example output::

            19  system/revision/fetch-diff  status=400  code=base_not_a_version
             1  system/revision/fetch-diff  status=200  code=-
        """
        rows = self.histogram()
        if not rows:
            return "(no dispatches recorded)"
        return "\n".join(
            f"{count:>4}  {pattern}/{op}  status={status}  code={code or '-'}"
            for (pattern, op, status, code, count) in rows
        )


@dataclass
class ContentRecord:
    """One observed entity put."""

    timestamp: float
    entity_hash: bytes
    entity_type: str


class ContentTap:
    """Record every entity put against a ContentStore.

    Uses the substrate's existing hook surface when available
    (``NotifyingContentStore.add_content_hook``) — the proper citizenship
    path. Falls back to monkey-patching ``put`` on a bare ``ContentStore``
    (the bare class doesn't expose hooks; tests use it directly).

    Detach via ``tap.detach()``.
    """

    def __init__(self, content_store: ContentStore) -> None:
        self._cs = content_store
        self.records: list[ContentRecord] = []
        self._hook_attached: bool = False
        self._original_put = content_store.put

        if isinstance(content_store, NotifyingContentStore):
            content_store.add_content_hook(self, name="diagnostic.ContentTap")
            self._hook_attached = True
        else:
            # Bare ContentStore: monkey-patch put. Same behavior, slightly
            # less polite; the substrate doesn't expose hooks here.
            content_store.put = self._wrapped_put  # type: ignore[method-assign]

    def on_content_stored(self, event: ContentStoreEvent) -> None:
        """ContentStoreHook protocol — called by NotifyingContentStore."""
        self.records.append(
            ContentRecord(
                timestamp=time.monotonic(),
                entity_hash=event.hash,
                entity_type=event.entity.type,
            )
        )

    def _wrapped_put(self, entity: Entity) -> bytes:
        h = self._original_put(entity)
        # Mirror NotifyingContentStore: only record on genuine new put.
        # Skip if the hash was already there (ContentStore.put is idempotent).
        if any(r.entity_hash == h for r in reversed(self.records[-32:])):
            return h
        self.records.append(
            ContentRecord(
                timestamp=time.monotonic(),
                entity_hash=h,
                entity_type=entity.type,
            )
        )
        return h

    def detach(self) -> None:
        """Restore original put / uninstall hook — observation off."""
        if self._hook_attached and isinstance(self._cs, NotifyingContentStore):
            self._cs.remove_content_hook(self)
            self._hook_attached = False
        else:
            self._cs.put = self._original_put  # type: ignore[method-assign]

    def histogram(self) -> list[tuple[str, int]]:
        """``[(entity_type, count), ...]`` sorted by count descending."""
        counter: Counter[str] = Counter(r.entity_type for r in self.records)
        return counter.most_common()

    def summary(self) -> str:
        rows = self.histogram()
        if not rows:
            return "(no puts recorded)"
        return "\n".join(f"{count:>4}  {etype}" for etype, count in rows)

    def clear(self) -> None:
        self.records.clear()


# ---------------------------------------------------------------------------
# Binding tap (§2.1 #2) — observes path bindings via EmitPathway hooks
# ---------------------------------------------------------------------------


@dataclass
class BindingRecord:
    """One observed binding mutation.

    Mirrors `ChangeEvent` shape but strips it to the fact-tuple the guide
    names: `(path, hash, prior_hash, timestamp)` plus the change kind.
    """

    timestamp: float
    kind: str  # ChangeKind value: created/updated/deleted
    uri: str
    new_hash: bytes | None
    prior_hash: bytes | None
    entity_type: str | None
    cascade_depth: int


class BindingTap:
    """Record every path binding mutation observed by an EmitPathway.

    Uses the substrate's existing public hook surface
    (`EmitPathway.subscribe(pattern, listener)`) — no monkey-patching.
    Default pattern is ``*`` (everything); pass a narrower pattern to
    focus on one subtree::

        tap = BindingTap(emit_pathway, pattern="system/revision/**")
        # ...run probe...
        print(tap.summary())

    Detach via ``tap.detach()``.
    """

    def __init__(self, emit: EmitPathway, pattern: str = "*") -> None:
        self._emit = emit
        self._pattern = pattern
        self.records: list[BindingRecord] = []
        emit.subscribe(pattern, self)

    async def on_change(self, event: ChangeEvent) -> None:
        """AsyncChangeListener protocol — called by EmitPathway."""
        self.records.append(
            BindingRecord(
                timestamp=time.monotonic(),
                kind=str(event.kind),
                uri=event.uri,
                new_hash=event.hash,
                prior_hash=event.previous_hash,
                entity_type=event.entity.type if event.entity else None,
                cascade_depth=event.cascade_depth,
            )
        )

    def detach(self) -> None:
        self._emit.unsubscribe(self)

    def histogram(self) -> list[tuple[str, str, int]]:
        """``[(kind, uri, count), ...]`` sorted by count descending."""
        counter: Counter[tuple[str, str]] = Counter(
            (r.kind, r.uri) for r in self.records
        )
        return [(k, u, c) for (k, u), c in counter.most_common()]

    def summary(self) -> str:
        rows = self.histogram()
        if not rows:
            return "(no bindings recorded)"
        return "\n".join(
            f"{count:>4}  {kind:>7}  {uri}" for (kind, uri, count) in rows
        )

    def clear(self) -> None:
        self.records.clear()


# ---------------------------------------------------------------------------
# Composed: chain_trace (§2.3) — walk a chain_id's substrate footprint
# ---------------------------------------------------------------------------


@dataclass
class ChainTraceResult:
    """Result of walking a chain_id through the content store + entity tree.

    All facts are derived from substrate-observable state; no new hooks
    needed at trace time (the chain's life is already entity-native).
    """

    chain_id: str
    continuation_entries: list[dict]            # raw entity.data dicts
    error_markers: list[tuple[str, dict]]       # (uri, entity.data) pairs
    related_uris: list[str]

    def summary(self) -> str:
        lines = [f"chain_trace({self.chain_id!r}):"]
        lines.append(f"  continuation entries: {len(self.continuation_entries)}")
        lines.append(f"  error markers: {len(self.error_markers)}")
        for uri, data in self.error_markers:
            code = data.get("code") if isinstance(data, dict) else "?"
            lines.append(f"    {code}: {uri}")
        return "\n".join(lines)


def chain_trace(
    chain_id: str,
    *,
    content_store: ContentStore,
    entity_tree: Any,
) -> ChainTraceResult:
    """Walk a chain_id's substrate footprint; report what's there.

    The chain framework persists continuation state at
    ``system/continuation/<chain_id>/...`` and chain-error markers at
    ``system/runtime/chain-errors/lost/<chain_id>/<step>/...``. This is
    the §2.3 "Chain trace" composed capability: a single function that
    collects the substrate-observable artifacts for one chain.

    Read-only. Best-effort snapshot — if the chain advances mid-walk
    the result is what was visible at scan time.
    """
    cont_prefix = f"system/continuation/{chain_id}"
    err_prefix = f"system/runtime/chain-errors/lost/{chain_id}"

    related_uris: list[str] = []
    continuation_entries: list[dict] = []
    error_markers: list[tuple[str, dict]] = []

    cont_full = entity_tree.normalize_uri(cont_prefix)
    for uri in entity_tree.list_prefix(cont_full):
        related_uris.append(uri)
        h = entity_tree.get(uri)
        if h is None:
            continue
        ent = content_store.get(h)
        if ent is not None:
            continuation_entries.append(ent.data)

    err_full = entity_tree.normalize_uri(err_prefix)
    for uri in entity_tree.list_prefix(err_full):
        related_uris.append(uri)
        h = entity_tree.get(uri)
        if h is None:
            continue
        ent = content_store.get(h)
        if ent is not None:
            error_markers.append((uri, ent.data))

    return ChainTraceResult(
        chain_id=chain_id,
        continuation_entries=continuation_entries,
        error_markers=error_markers,
        related_uris=related_uris,
    )
