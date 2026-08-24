"""Revision operations — `SDK-EXTENSION-OPERATIONS` v0.9 §4 / `EXTENSION-REVISION` v3.4.

Structural version control over an entity subtree: content-addressed snapshots,
a version DAG, three-way merge, and cross-peer transfer. Everything is scoped to
a **prefix**, so the surface is a handle bound to one::

    rev = client.revision("project/")
    result = await rev.commit()
    page = await rev.log(limit=20)
    merged = await rev.merge(theirs)
    if merged.has_conflicts:
        ...

.. rubric:: §4 has drifted from the extension it summarizes — filed as SA-PY-5/-6

The ratified procedure (`AGENTS.md`) is to open `EXTENSION-REVISION`'s normative
schema sections **alongside** `SDK-EXTENSION-OPERATIONS` §4 and, where they
differ, implement the extension. On this surface they differ in seventeen
places — thirteen params/result rows (SA-PY-5) and four rows about which layer
an operation even belongs to (SA-PY-6) — which is why this module's names are
the extension's throughout.

The rows that matter most are the ones that fail **silently** — an SDK built
from §4 gets an answer, and the answer is wrong:

======================  ============================  ==============================
concern                 §4 (the SDK doc)              `EXTENSION-REVISION` (normative)
======================  ============================  ==============================
``log`` paging          ``count`` / ``cursor``        ``limit`` / ``since``
``config`` excludes     ``exclude_patterns``          ``exclude`` (§2.4)
``merge`` result        ``status: uint`` 200/409      ``status: string``, nine values
``status`` result       ``{head}`` alone              ``+ conflicts, pending, remotes``
branch / tag storage    ``system/revision/branches/`` ``system/revision/{H}/branches/``
======================  ============================  ==============================

``count=20`` reaches a handler that reads ``limit`` and returns the **entire**
DAG; ``exclude_patterns`` reaches one that reads ``exclude`` and versions the
paths you asked it to skip; ``status == 409`` is never true, so a merge that
conflicted reads as clean; and a branch written at §4's unhashed path is a
branch the handler never finds. None of those raise.

**This module speaks the extension's vocabulary.** Where §4's spelling is a
straight rename it is absorbed at this boundary (``count=`` → ``limit=``,
``theirs=`` → ``remote_version=``, ``exclude_patterns=`` → ``exclude=``) so a
caller working from either document gets the same behaviour — that is what an
absorption is for while an SA is open. Where §4's spelling names something that
does not exist here (``merge_strategy`` in a prefix config: merge strategy lives
in the separate merge-config namespace, written by a separate operation) it
raises rather than guesses, because absorbing it would mean writing a field no
handler reads.

Every absorption is a **debt to the ruling** and gets retired when upstream
rules — see the `put`/`remove` and `neq` retirements at `30f55ff`.

.. rubric:: Two absorptions that are ours, not the document's

*The zero-hash head.* ``status`` encodes "no versions yet" as the canonical
33-byte zero hash rather than by omitting ``head`` — deliberately, to match the
Go and Rust peers' encoding. The extension's type says the field is absent in
that case. :attr:`RevisionStatus.head` is ``None``, and
:attr:`RevisionStatus.has_versions` is the predicate; a caller never sees the
sentinel, because a hash that means "no hash" is the CAP-6 class of bug.

*The envelope.* ``log``, ``fetch``, ``fetch-entities`` and ``fetch-diff`` answer
a ``system/envelope`` whose ``data.root`` is the result and whose
``data.included`` carries the version entries / trie nodes / entities. That is a
transport convenience, not something a caller should branch on, so this module
unwraps it and hangs the map off ``.entities``.

.. rubric:: `since` means two different things and we implement both — SA-PY-7

`EXTENSION-REVISION` §4.4.2 describes ``log``'s ``since`` as *"start after this
version"* (a paging cursor) while §4.4.6 describes ``fetch``'s as *"latest known
version hash — DAG walk stops here"* (a stop marker). They are opposite ends of
the same walk. Our handler implements the paging reading for ``log`` (inclusive
of ``since``) and the stop-marker reading for ``fetch``; `entity-core-go`
implements the **stop-marker** reading for both. So ``log(since=X)`` returns
different sets from a py peer and a go peer, and neither is provably wrong
against the text. Filed as SA-PY-7 and routed; this module documents it at
:meth:`RevisionClient.log` rather than picking a winner behind the caller's
back — a wrapper that silently normalized would hide a live cross-impl
divergence, which is the one thing this implementation exists to surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field as _dc_field
from typing import Any, Iterator

from entity_sdk.errors import BadRequest

__all__ = [
    "REVISION_PATTERN",
    "MERGE_STATUSES",
    "CLEAN_MERGE_STATUSES",
    "CONFLICT_MERGE_STATUSES",
    "BranchListing",
    "CheckoutResult",
    "CherryPickResult",
    "CommitResult",
    "FetchEntitiesResult",
    "FetchResult",
    "LogPage",
    "MergeResult",
    "PushResult",
    "ResolveResult",
    "RevertResult",
    "RevisionClient",
    "RevisionStatus",
    "TagListing",
    "VersionDiff",
    "find_ancestor",
    "revision",
]

#: The handler's dispatch pattern.
REVISION_PATTERN = "system/revision"

_COMMIT_PARAMS = "system/revision/commit-params"
_LOG_PARAMS = "system/revision/log-params"
_STATUS_PARAMS = "system/revision/status-params"
_MERGE_PARAMS = "system/revision/merge-params"
_RESOLVE_PARAMS = "system/revision/resolve-params"
_FETCH_PARAMS = "system/revision/fetch-params"
_FETCH_ENTITIES_PARAMS = "system/revision/fetch-entities-params"
_FETCH_DIFF_PARAMS = "system/revision/fetch-diff-params"
_PUSH_PARAMS = "system/revision/push-params"
_ANCESTOR_PARAMS = "system/revision/ancestor-params"
_BRANCH_PARAMS = "system/revision/branch-params"
_CHECKOUT_PARAMS = "system/revision/checkout-params"
_TAG_PARAMS = "system/revision/tag-params"
_DIFF_PARAMS = "system/revision/diff-params"
_CHERRY_PICK_PARAMS = "system/revision/cherry-pick-params"
_REVERT_PARAMS = "system/revision/revert-params"
_CONFIG_PARAMS = "system/revision/config-params"
_MERGE_CONFIG_PARAMS = "system/revision/merge-config-params"

_CONFIG_TYPE = "system/revision/config"
_MERGE_CONFIG_TYPE = "system/revision/merge-config"

#: §4.5 `merge-result.status` — the nine values the field can take. A string,
#: never the 200/409 uint `SDK-EXTENSION-OPERATIONS` §4 shows (SA-PY-5).
MERGE_STATUSES = (
    "already_in_sync",
    "fast_forward",
    "already_ahead",
    "merged",
    "merged_with_conflicts",
    "would_merge",
    "would_conflict",
    "converged_identical",
    "oscillation_detected",
)

#: Statuses that mean "the merge completed and left nothing to resolve."
CLEAN_MERGE_STATUSES = frozenset(
    {
        "already_in_sync",
        "already_ahead",
        "fast_forward",
        "merged",
        "would_merge",
        "converged_identical",
    }
)

#: Statuses that mean "conflicts exist" — `conflicts` names the paths.
CONFLICT_MERGE_STATUSES = frozenset({"merged_with_conflicts", "would_conflict"})

#: Spellings §4 carries that this boundary absorbs, per parameter. Named so the
#: absorption is greppable when the ruling lands and it has to be retired.
_ABSORBED_LOG_PARAMS = {"count": "limit", "cursor": "since"}
_ABSORBED_MERGE_PARAMS = {"theirs": "remote_version"}
_ABSORBED_CONFIG_FIELDS = {"exclude_patterns": "exclude"}


# =============================================================================
# Result types — `EXTENSION-REVISION` §4.5
# =============================================================================


@dataclass(frozen=True, slots=True)
class CommitResult:
    """§4.5 `commit-result` — the new version and the trie it snapshotted.

    A commit that changes nothing returns the **current** head rather than
    minting a redundant entry (§6.2 dedup), so ``version`` may equal the head
    the caller already had.
    """

    version: bytes
    root: bytes


@dataclass(frozen=True, slots=True)
class LogPage:
    """§4.5 `log-result` — one page of the version DAG, newest first.

    ``versions`` are hashes; ``entities`` is the envelope's `included` map, so
    ``page.entity(h)["data"]["parents"]`` reaches the DAG structure without a
    second round trip.
    """

    prefix: str
    versions: list[bytes] = _dc_field(default_factory=list)
    has_more: bool = False
    entities: dict[bytes, dict[str, Any]] = _dc_field(default_factory=dict)

    def __iter__(self) -> Iterator[bytes]:
        return iter(self.versions)

    def __len__(self) -> int:
        return len(self.versions)

    def entity(self, version: bytes) -> dict[str, Any] | None:
        """The version entry entity for ``version``, if the peer bundled it."""
        return self.entities.get(version)

    def parents_of(self, version: bytes) -> list[bytes]:
        """Parent hashes of ``version`` — empty for the root or when unbundled."""
        entry = self.entities.get(version) or {}
        data = entry.get("data") or {}
        parents = data.get("parents") or []
        return [p for p in parents if isinstance(p, (bytes, bytearray))]


@dataclass(frozen=True, slots=True)
class RevisionStatus:
    """§2.5 `system/revision/status`.

    ``head`` is ``None`` when the prefix has no versions — the peer's zero-hash
    sentinel is absorbed here (module docstring). ``conflicts`` and ``pending``
    are the two fields `SDK-EXTENSION-OPERATIONS` §4 omits entirely, and the
    reason it omits them is why a caller reading that document cannot tell a
    conflicted prefix from a clean one.
    """

    prefix: str
    head: bytes | None = None
    remotes: dict[str, bytes] = _dc_field(default_factory=dict)
    conflicts: int = 0
    pending: int = 0
    keep_both_paths: list[str] = _dc_field(default_factory=list)

    @property
    def has_versions(self) -> bool:
        return self.head is not None

    @property
    def is_clean(self) -> bool:
        """No unresolved conflicts and nothing uncommitted."""
        return self.conflicts == 0 and self.pending == 0


@dataclass(frozen=True, slots=True)
class MergeResult:
    """§4.5 `merge-result`.

    ``status`` is one of :data:`MERGE_STATUSES` — a **string**. §4's
    ``200``/``409`` uint reading is SA-PY-5's most dangerous row precisely
    because comparing against it raises nothing: a conflicted merge simply
    reads as not-409. :attr:`has_conflicts` is the predicate to branch on.
    """

    status: str
    version: bytes | None = None
    conflicts: list[str] = _dc_field(default_factory=list)
    dry_run: bool = False
    merged_count: int | None = None
    deleted_count: int | None = None
    cascade_warnings: list[dict[str, Any]] = _dc_field(default_factory=list)

    @property
    def has_conflicts(self) -> bool:
        return bool(self.conflicts) or self.status in CONFLICT_MERGE_STATUSES

    @property
    def is_clean(self) -> bool:
        return not self.has_conflicts and self.status in CLEAN_MERGE_STATUSES

    @property
    def applied(self) -> bool:
        """Whether the tree actually moved — false for a dry run or a no-op."""
        return (
            not self.dry_run
            and self.version is not None
            and self.status not in ("already_in_sync", "already_ahead")
        )


@dataclass(frozen=True, slots=True)
class ResolveResult:
    """§4.5 `resolve-result`. ``resolved`` is ``None`` for resolve-by-deletion."""

    path: str
    resolved: bytes | None = None
    remaining_conflicts: int = 0

    @property
    def all_resolved(self) -> bool:
        """Zero conflicts left — §4.4.5's cue that a commit is now worth making."""
        return self.remaining_conflicts == 0


@dataclass(frozen=True, slots=True)
class FetchResult:
    """§4.5 `fetch-result` — DAG metadata only; entity content needs `fetch-entities`."""

    head: bytes | None = None
    versions: list[bytes] = _dc_field(default_factory=list)
    has_more: bool = False
    entities: dict[bytes, dict[str, Any]] = _dc_field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.versions)


@dataclass(frozen=True, slots=True)
class FetchEntitiesResult:
    """§4.5 `fetch-entities-result`.

    ``missing`` is not an error — it is the peer saying a hash is not in its
    content store (GC'd, or never held), which a trie walk has to handle rather
    than retry.
    """

    found: list[bytes] = _dc_field(default_factory=list)
    missing: list[bytes] = _dc_field(default_factory=list)
    entities: dict[bytes, dict[str, Any]] = _dc_field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CheckoutResult:
    """§4.5 `checkout-result`.

    ``target_version`` is what was asked for; ``head`` is where the prefix
    actually ended up. Under ``auto_version: false`` they are equal. Under
    ``auto_version: true`` checkout is state *restoration*, so applying the
    bindings mints versions and ``head`` is a **new descendant** of
    ``target_version`` with a matching root (§4.4.12). Display ``head``; record
    ``target_version``.
    """

    status: str
    target_version: bytes | None = None
    head: bytes | None = None
    branch: str | None = None
    cascade_warnings: list[dict[str, Any]] = _dc_field(default_factory=list)

    @property
    def created_intermediates(self) -> bool:
        """True when auto-version turned the checkout into forward edits."""
        return (
            self.head is not None
            and self.target_version is not None
            and self.head != self.target_version
        )


@dataclass(frozen=True, slots=True)
class CherryPickResult:
    """§4.5 `cherry-pick-result`."""

    status: str
    version: bytes | None = None
    source: bytes | None = None
    conflicts: list[str] = _dc_field(default_factory=list)
    applied: int = 0
    cascade_warnings: list[dict[str, Any]] = _dc_field(default_factory=list)

    @property
    def has_conflicts(self) -> bool:
        return bool(self.conflicts) or self.status.endswith("with_conflicts")


@dataclass(frozen=True, slots=True)
class RevertResult:
    """§4.5 `revert-result`."""

    status: str
    version: bytes | None = None
    reverted: bytes | None = None
    conflicts: list[str] = _dc_field(default_factory=list)
    applied: int = 0
    cascade_warnings: list[dict[str, Any]] = _dc_field(default_factory=list)

    @property
    def has_conflicts(self) -> bool:
        return bool(self.conflicts) or self.status.endswith("with_conflicts")


@dataclass(frozen=True, slots=True)
class PushResult:
    """§4.5 `push-result`."""

    status: str
    pushed: int = 0
    head: bytes | None = None
    message: str | None = None


@dataclass(frozen=True, slots=True)
class BranchListing:
    """The list action of §4.4.11 — names to version hashes, plus the active one."""

    branches: dict[str, bytes] = _dc_field(default_factory=dict)
    active: str | None = None

    def __contains__(self, name: object) -> bool:
        return name in self.branches

    def __len__(self) -> int:
        return len(self.branches)


@dataclass(frozen=True, slots=True)
class TagListing:
    """The list action of §4.4.13."""

    tags: dict[str, bytes] = _dc_field(default_factory=dict)

    def __contains__(self, name: object) -> bool:
        return name in self.tags

    def __len__(self) -> int:
        return len(self.tags)


@dataclass(frozen=True, slots=True)
class VersionDiff:
    """`system/tree/diff` between two versions' tries (§4.4.14).

    Paths are **trie-relative** — relative to the prefix, not absolute tree
    paths (§4's result-path convention), so two peers versioning the same
    content under different prefixes report the same diff.

    Deletion markers never appear here: §4.4.14 translates a marker binding
    back to logical deletion, so a path deleted between the two versions shows
    up in ``removed`` rather than as a marker hash in ``changed``.
    """

    base: bytes | None = None
    target: bytes | None = None
    added: dict[str, bytes] = _dc_field(default_factory=dict)
    removed: dict[str, bytes] = _dc_field(default_factory=dict)
    changed: dict[str, dict[str, bytes]] = _dc_field(default_factory=dict)
    unchanged: int = 0

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed)

    def __len__(self) -> int:
        return len(self.added) + len(self.removed) + len(self.changed)


# =============================================================================
# Wire helpers
# =============================================================================


def _unwrap(result: Any) -> tuple[dict[str, Any], dict[bytes, dict[str, Any]]]:
    """Split a response into (result data, included entities).

    Handles both shapes: the bare typed result, and the `system/envelope` the
    DAG-transfer operations wrap it in.
    """
    if not isinstance(result, dict):
        return {}, {}
    if result.get("type") == "system/envelope":
        data = result.get("data") or {}
        root = data.get("root") or {}
        included = data.get("included") or {}
        root_data = root.get("data") if isinstance(root, dict) else None
        return (
            root_data if isinstance(root_data, dict) else {},
            {
                bytes(h): e
                for h, e in (included if isinstance(included, dict) else {}).items()
                if isinstance(h, (bytes, bytearray)) and isinstance(e, dict)
            },
        )
    inner = result.get("data")
    return (inner if isinstance(inner, dict) else result), {}


def _hash(value: Any) -> bytes | None:
    """A hash field, with the zero-hash sentinel read as absent.

    The peer encodes "no head" as 33 zero bytes to match Go/Rust rather than by
    omitting the field. A caller who compares that against a real hash gets
    `False` and moves on; a caller who forwards it as a version hash gets a
    404 from somewhere else entirely. Absorbed once, here.
    """
    if not isinstance(value, (bytes, bytearray)):
        return None
    raw = bytes(value)
    if not raw or not any(raw):
        return None
    return raw


def _hashes(value: Any) -> list[bytes]:
    if not isinstance(value, (list, tuple)):
        return []
    return [bytes(h) for h in value if isinstance(h, (bytes, bytearray))]


def _paths(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [p for p in value if isinstance(p, str)]


def _warnings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [w for w in value if isinstance(w, dict)]


def _int_or_none(value: Any) -> int | None:
    return int(value) if isinstance(value, int) and not isinstance(value, bool) else None


def _absorb(
    kwargs: dict[str, Any],
    mapping: dict[str, str],
    *,
    operation: str,
) -> dict[str, Any]:
    """Translate the §4 spellings this boundary absorbs into the extension's.

    Raises:
        BadRequest: 400 ``invalid_params`` when both spellings are passed —
            one of them was going to be dropped, and dropping the caller's
            paging argument silently is the failure this whole module is about.
    """
    out = dict(kwargs)
    for old, new in mapping.items():
        if old not in out:
            continue
        value = out.pop(old)
        if value is None:
            continue
        if out.get(new) is not None:
            raise BadRequest(
                400,
                "invalid_params",
                f"{operation}: pass either {old!r} (SDK-EXTENSION-OPERATIONS §4) "
                f"or {new!r} (EXTENSION-REVISION), not both — they are the same "
                f"argument under two names (SA-PY-5).",
            )
        out[new] = value
    return out


# =============================================================================
# The prefix-bound surface
# =============================================================================


class RevisionClient:
    """Revision operations bound to one prefix.

    Built by :func:`revision` / ``client.revision(prefix)``. Every operation
    dispatches ``system/revision`` at the client's peer, except where a ``peer``
    argument redirects it — ``fetch`` and ``fetch_entities`` are *served by the
    peer that holds the DAG*, so fetching from a remote means dispatching at the
    remote, not passing its id as a parameter (`SDK-EXTENSION-OPERATIONS` §4's
    ``fetch(peer, prefix)`` signature has no counterpart in the extension's
    params type — SA-PY-5).

    ``pull`` and ``push`` are different: the extension makes them **handler**
    operations that run the multi-round transfer inside the peer (§4.2's
    convenience tier), so they take ``remote`` as a parameter and this wrapper
    is one dispatch, not an orchestration. §4 classifies both as SDK-level
    workflows the SDK must compose — SA-PY-6. Composing them client-side would
    re-implement a round trip the peer already does, badly.
    """

    __slots__ = ("_client", "_prefix")

    def __init__(self, client: Any, prefix: str) -> None:
        if not isinstance(prefix, str):
            raise BadRequest(400, "invalid_prefix", f"prefix must be a string, got {prefix!r}")
        if prefix and not prefix.endswith("/"):
            # The handler answers `400 invalid_prefix` for this; saying so here
            # costs nothing and names the fix.
            raise BadRequest(
                400,
                "invalid_prefix",
                f"a non-empty prefix must end with '/' — got {prefix!r}, "
                f"did you mean {prefix + '/'!r}?",
            )
        self._client = client
        self._prefix = prefix

    @property
    def prefix(self) -> str:
        return self._prefix

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"RevisionClient({self._prefix!r})"

    async def _execute(
        self,
        operation: str,
        params_type: str,
        data: dict[str, Any],
        *,
        peer: str | None = None,
    ) -> Any:
        return await self._client.execute(
            REVISION_PATTERN,
            operation,
            {"type": params_type, "data": data},
            resource_targets=[REVISION_PATTERN],
            peer_id=peer,
        )

    # -- §4.4.1 commit -------------------------------------------------------

    async def commit(self, message: str | None = None) -> CommitResult:
        """Snapshot the current tree state under the prefix as a version.

        ``message`` is accepted by the params type but is **not** stored in the
        version entry — §1.2's version entries are structural
        (``{root, parents}``) and carry no author, time, or message. A caller
        who needs those stores them as a separate entity at a convention path.
        """
        data: dict[str, Any] = {"prefix": self._prefix}
        if message is not None:
            data["message"] = message
        body, _ = _unwrap(await self._execute("commit", _COMMIT_PARAMS, data))
        version = _hash(body.get("version"))
        root = _hash(body.get("root"))
        if version is None or root is None:
            raise BadRequest(
                400, "invalid_result", f"commit-result missing version/root: {body!r}"
            )
        return CommitResult(version=version, root=root)

    # -- §4.4.2 log ----------------------------------------------------------

    async def log(
        self,
        limit: int | None = None,
        since: bytes | None = None,
        **absorbed: Any,
    ) -> LogPage:
        """Walk the version DAG from HEAD, newest first.

        Args:
            limit: Page size. §4 calls this ``count``; that spelling is
                absorbed here, and passing it to a peer directly returns the
                **whole DAG** rather than raising (SA-PY-5).
            since: Where the walk relates to. **Read SA-PY-7 before paging on
                this**: §4.4.2 documents it as "start after this version" while
                §4.4.6 documents ``fetch``'s identically-named field as a stop
                marker, and the two implementations split the same way — this
                peer starts the walk *at* ``since`` (so it reappears as the
                page's first element), `entity-core-go` walks from HEAD and
                skips it. Use ``has_more`` plus the last hash you saw, and
                expect to drop a duplicate.
        """
        kwargs = _absorb(
            {"limit": limit, "since": since, **absorbed}, _ABSORBED_LOG_PARAMS, operation="log"
        )
        unknown = set(kwargs) - {"limit", "since"}
        if unknown:
            raise BadRequest(
                400, "invalid_params", f"log() got unexpected arguments: {sorted(unknown)}"
            )
        data: dict[str, Any] = {"prefix": self._prefix}
        if kwargs.get("limit") is not None:
            data["limit"] = kwargs["limit"]
        if kwargs.get("since") is not None:
            data["since"] = kwargs["since"]
        body, included = _unwrap(await self._execute("log", _LOG_PARAMS, data))
        return LogPage(
            prefix=body.get("prefix", self._prefix),
            versions=_hashes(body.get("versions")),
            has_more=bool(body.get("has_more", False)),
            entities=included,
        )

    async def head(self) -> bytes | None:
        """The current HEAD version, or ``None`` if the prefix has none."""
        return (await self.status()).head

    # -- §4.4.3 status -------------------------------------------------------

    async def status(self) -> RevisionStatus:
        """Current HEAD, known remote heads, conflict count, pending changes."""
        body, _ = _unwrap(await self._execute("status", _STATUS_PARAMS, {"prefix": self._prefix}))
        raw_remotes = body.get("remotes")
        remotes = {
            k: bytes(v)
            for k, v in (raw_remotes or {}).items()
            if isinstance(k, str) and isinstance(v, (bytes, bytearray))
        } if isinstance(raw_remotes, dict) else {}
        return RevisionStatus(
            prefix=body.get("prefix", self._prefix),
            head=_hash(body.get("head")),
            remotes=remotes,
            conflicts=int(body.get("conflicts") or 0),
            pending=int(body.get("pending") or 0),
            keep_both_paths=_paths(body.get("keep_both_paths")),
        )

    # -- §4.4.4 merge --------------------------------------------------------

    async def merge(
        self,
        remote_version: bytes | None = None,
        *,
        strategy: str | None = None,
        dry_run: bool = False,
        **absorbed: Any,
    ) -> MergeResult:
        """Three-way merge ``remote_version`` into the prefix's tree state.

        Args:
            remote_version: The version to merge. §4 calls this ``theirs``;
                that spelling is absorbed (SA-PY-5).
            dry_run: Preview only — returns ``would_merge`` / ``would_conflict``
                and writes nothing.

        The result's ``status`` is a **string**, never 200/409; branch on
        :attr:`MergeResult.has_conflicts`.
        """
        kwargs = _absorb(
            {"remote_version": remote_version, **absorbed},
            _ABSORBED_MERGE_PARAMS,
            operation="merge",
        )
        unknown = set(kwargs) - {"remote_version"}
        if unknown:
            raise BadRequest(
                400, "invalid_params", f"merge() got unexpected arguments: {sorted(unknown)}"
            )
        target = kwargs.get("remote_version")
        if not isinstance(target, (bytes, bytearray)):
            raise BadRequest(
                400, "invalid_params", "merge() requires remote_version as a content hash"
            )
        data: dict[str, Any] = {"prefix": self._prefix, "remote_version": bytes(target)}
        if strategy is not None:
            data["strategy"] = strategy
        if dry_run:
            data["dry_run"] = True
        body, _ = _unwrap(await self._execute("merge", _MERGE_PARAMS, data))
        return _merge_result_from(body)

    # -- §4.4.5 resolve ------------------------------------------------------

    async def resolve(self, path: str, resolved: bytes | None = None) -> ResolveResult:
        """Resolve the conflict at trie-relative ``path``.

        Args:
            resolved: Content hash of the entity to bind at the path — it must
                already be in the peer's content store, which is why this takes
                a hash rather than the ``Entity`` `SDK-EXTENSION-OPERATIONS` §4
                shows (SA-PY-5; an entity the peer has never seen cannot be
                resolved to). ``None`` resolves **by deletion**: neither side's
                entity wins and the path is unbound.

        Resolving does not commit — §4.4.5 leaves that to the caller, and
        :attr:`ResolveResult.all_resolved` is the cue.
        """
        if not isinstance(path, str) or not path:
            raise BadRequest(400, "invalid_params", "resolve() requires a path")
        if resolved is not None and not isinstance(resolved, (bytes, bytearray)):
            raise BadRequest(
                400,
                "invalid_params",
                "resolve() takes the content hash of an entity already in the "
                "peer's content store, not the entity itself — put it first, "
                "then resolve to its hash (EXTENSION-REVISION §4.4.5).",
            )
        data: dict[str, Any] = {"prefix": self._prefix, "path": path}
        if resolved is not None:
            data["resolved"] = bytes(resolved)
        body, _ = _unwrap(await self._execute("resolve", _RESOLVE_PARAMS, data))
        return ResolveResult(
            path=body.get("path", path),
            resolved=_hash(body.get("resolved")),
            remaining_conflicts=int(body.get("remaining_conflicts") or 0),
        )

    # -- §4.4.6 fetch --------------------------------------------------------

    async def fetch(
        self,
        *,
        peer: str | None = None,
        remote_prefix: str | None = None,
        since: bytes | None = None,
        depth: int | None = None,
    ) -> FetchResult:
        """Get version-DAG metadata (entries + root trie nodes), no content.

        Args:
            peer: Whose DAG to read. ``fetch`` is served by the peer that holds
                the versions, so this redirects the dispatch rather than riding
                as a parameter. Omit for the local peer.
            since: Latest version already held — the walk **stops** there
                (§4.4.6, and unlike ``log``'s field of the same name: SA-PY-7).
            depth: Cap on versions returned; the oldest becomes a shallow
                boundary whose parents may not be locally resolvable.
        """
        data: dict[str, Any] = {"prefix": remote_prefix or self._prefix}
        if since is not None:
            data["since"] = bytes(since)
        if depth is not None:
            data["depth"] = depth
        body, included = _unwrap(await self._execute("fetch", _FETCH_PARAMS, data, peer=peer))
        return FetchResult(
            head=_hash(body.get("head")),
            versions=_hashes(body.get("versions")),
            has_more=bool(body.get("has_more", False)),
            entities=included,
        )

    # -- §4.4.7 fetch-entities ----------------------------------------------

    async def fetch_entities(
        self,
        snapshot: bytes,
        hashes: list[bytes],
        *,
        peer: str | None = None,
        remote_prefix: str | None = None,
    ) -> FetchEntitiesResult:
        """Retrieve entities by hash, scoped to one trie root.

        ``snapshot`` is a version's ``root`` — required, and the reason
        `fetch-entities` is not an open proxy onto the content store: the peer
        validates every requested hash appears somewhere in that trie
        (§4.4.7). §4's ``fetch_entities(peer, hashes)`` signature omits it, and
        omitting it is a ``400 invalid_params`` (SA-PY-5).
        """
        if not isinstance(snapshot, (bytes, bytearray)):
            raise BadRequest(
                400,
                "invalid_params",
                "fetch_entities() requires the trie root (a version's `root`) "
                "as `snapshot` — the peer scopes hash validation to it "
                "(EXTENSION-REVISION §4.4.7).",
            )
        wanted = _hashes(hashes)
        if not wanted:
            raise BadRequest(400, "invalid_params", "fetch_entities() requires hashes")
        data = {
            "prefix": remote_prefix or self._prefix,
            "snapshot": bytes(snapshot),
            "hashes": wanted,
        }
        body, included = _unwrap(
            await self._execute("fetch-entities", _FETCH_ENTITIES_PARAMS, data, peer=peer)
        )
        return FetchEntitiesResult(
            found=_hashes(body.get("found")),
            missing=_hashes(body.get("missing")),
            entities=included,
        )

    # -- §4.4.19 fetch-diff --------------------------------------------------

    async def fetch_diff(
        self,
        base: bytes | None = None,
        *,
        peer: str | None = None,
        remote_prefix: str | None = None,
    ) -> dict[bytes, dict[str, Any]]:
        """The changed closure between ``base`` and the serving peer's head.

        Returns the bundled entities keyed by hash — the V-1 closure feature,
        one round trip at any tree size. ``base=None`` (the zero hash on the
        wire) asks for the **full** closure, which is the bootstrap case.

        The target version is implicit — the serving peer's current head — which
        is what keeps the op single-dynamic-field and so expressible as a
        standing continuation chain (``subscribe head → fetch-diff → tree:merge``).
        """
        data: dict[str, Any] = {"prefix": remote_prefix or self._prefix}
        if base is not None:
            data["base"] = bytes(base)
        _, included = _unwrap(
            await self._execute("fetch-diff", _FETCH_DIFF_PARAMS, data, peer=peer)
        )
        return included

    # -- §4.4.8 pull / §4.4.9 push ------------------------------------------

    async def pull(
        self,
        remote: str,
        *,
        remote_prefix: str | None = None,
        since: bytes | None = None,
        depth: int | None = None,
    ) -> MergeResult:
        """Fetch from ``remote`` and merge its head — one handler dispatch.

        The peer runs fetch → incremental fetch-entities → merge internally
        (§4.4.8), so this is not the client-side orchestration §4 describes
        (SA-PY-6). The result is a merge result, including its conflict list.
        """
        data: dict[str, Any] = {"prefix": self._prefix, "remote": remote}
        if remote_prefix is not None:
            data["remote_prefix"] = remote_prefix
        if since is not None:
            data["since"] = bytes(since)
        if depth is not None:
            data["depth"] = depth
        body, _ = _unwrap(await self._execute("pull", _FETCH_PARAMS, data))
        return _merge_result_from(body)

    async def push(
        self,
        remote: str,
        *,
        remote_prefix: str | None = None,
        force: bool = False,
    ) -> PushResult:
        """Send local versions to ``remote`` — one handler dispatch (§4.4.9).

        Push is explicitly **not** a version-transcription site (§4.4.4, v3.3
        P1): it moves version entries, trie nodes and entities and updates the
        remote's head pointer. The remote's live tree changes only when the
        remote later merges or checks out.
        """
        data: dict[str, Any] = {"prefix": self._prefix, "remote": remote}
        if remote_prefix is not None:
            data["remote_prefix"] = remote_prefix
        if force:
            data["force"] = True
        body, _ = _unwrap(await self._execute("push", _PUSH_PARAMS, data))
        return PushResult(
            status=str(body.get("status") or ""),
            pushed=int(body.get("pushed") or 0),
            head=_hash(body.get("head")),
            message=body.get("message"),
        )

    # -- §4.4.11 branch ------------------------------------------------------

    async def branches(self) -> BranchListing:
        """List branches and the active one."""
        body, _ = _unwrap(
            await self._execute("branch", _BRANCH_PARAMS, {"prefix": self._prefix, "action": "list"})
        )
        raw = body.get("branches")
        return BranchListing(
            branches={
                k: bytes(v)
                for k, v in (raw or {}).items()
                if isinstance(k, str) and isinstance(v, (bytes, bytearray))
            } if isinstance(raw, dict) else {},
            active=body.get("active"),
        )

    async def create_branch(self, name: str, *, start: bytes | str | None = None) -> bytes | None:
        """Create branch ``name`` at ``start`` (default: current HEAD).

        ``start`` may be a version hash or another branch/tag name. Returns the
        version the branch points at.

        Branches are handler state at ``system/revision/{H}/branches/{name}``,
        where ``{H}`` is the prefix hash — **not** the unhashed
        ``system/revision/branches/{name}`` `SDK-EXTENSION-OPERATIONS` §4 shows
        as a plain tree write (SA-PY-6). A branch written at §4's path is a
        branch this handler never reads, and §4.3 says external callers should
        not hold `put` on the handler-owned namespace at all.
        """
        data: dict[str, Any] = {"prefix": self._prefix, "action": "create", "name": name}
        if start is not None:
            data["from"] = start
        body, _ = _unwrap(await self._execute("branch", _BRANCH_PARAMS, data))
        return _hash(body.get("version"))

    async def delete_branch(self, name: str) -> None:
        """Delete branch ``name``. The active branch cannot be deleted (400)."""
        await self._execute(
            "branch", _BRANCH_PARAMS, {"prefix": self._prefix, "action": "delete", "name": name}
        )

    # -- §4.4.12 checkout ----------------------------------------------------

    async def checkout(
        self,
        *,
        branch: str | None = None,
        version: bytes | None = None,
    ) -> CheckoutResult:
        """Switch the tree under the prefix to ``branch`` or ``version``.

        Exactly one of the two is required. This is a **handler** operation, not
        the client-side "read trie, batch-write bindings" §4 describes
        (SA-PY-6) — and the difference is not stylistic: §4.4.4's
        version-transcription invariants require the diff baseline to be the
        committed head's trie rather than the live tree, and require deletion
        markers to translate to unbinds. A client-side batch write honours
        neither, so it reanimates deleted paths and drops in-flight writes.

        Destructive: uncommitted changes under the prefix are overwritten
        (§4.4.12) — commit first if they matter. Under ``auto_version: true``
        the operation mints intermediate versions; see
        :attr:`CheckoutResult.created_intermediates`.
        """
        if (branch is None) == (version is None):
            raise BadRequest(
                400, "invalid_params", "checkout() takes exactly one of branch= or version="
            )
        data: dict[str, Any] = {"prefix": self._prefix}
        if branch is not None:
            data["branch"] = branch
        else:
            data["version"] = bytes(version)  # type: ignore[arg-type]
        body, _ = _unwrap(await self._execute("checkout", _CHECKOUT_PARAMS, data))
        return CheckoutResult(
            status=str(body.get("status") or ""),
            target_version=_hash(body.get("target_version")),
            head=_hash(body.get("head")),
            branch=body.get("branch"),
            cascade_warnings=_warnings(body.get("cascade_warnings")),
        )

    # -- §4.4.13 tag ---------------------------------------------------------

    async def tags(self) -> TagListing:
        """List tags."""
        body, _ = _unwrap(
            await self._execute("tag", _TAG_PARAMS, {"prefix": self._prefix, "action": "list"})
        )
        raw = body.get("tags")
        return TagListing(
            tags={
                k: bytes(v)
                for k, v in (raw or {}).items()
                if isinstance(k, str) and isinstance(v, (bytes, bytearray))
            } if isinstance(raw, dict) else {}
        )

    async def create_tag(self, name: str, *, version: bytes | None = None) -> bytes | None:
        """Tag ``version`` (default: current HEAD) as ``name``."""
        data: dict[str, Any] = {"prefix": self._prefix, "action": "create", "name": name}
        if version is not None:
            data["version"] = bytes(version)
        body, _ = _unwrap(await self._execute("tag", _TAG_PARAMS, data))
        return _hash(body.get("version"))

    async def delete_tag(self, name: str) -> None:
        """Delete tag ``name``."""
        await self._execute(
            "tag", _TAG_PARAMS, {"prefix": self._prefix, "action": "delete", "name": name}
        )

    # -- §4.4.14 diff --------------------------------------------------------

    async def diff(self, base: bytes | str, target: bytes | str) -> VersionDiff:
        """Compare two versions' tries. Either side may be a branch/tag name."""
        body, _ = _unwrap(
            await self._execute(
                "diff",
                _DIFF_PARAMS,
                {"prefix": self._prefix, "base": base, "target": target},
            )
        )
        changed = {
            k: {ck: bytes(cv) for ck, cv in v.items() if isinstance(cv, (bytes, bytearray))}
            for k, v in (body.get("changed") or {}).items()
            if isinstance(k, str) and isinstance(v, dict)
        }
        return VersionDiff(
            base=_hash(body.get("base")),
            target=_hash(body.get("target")),
            added=_binding_map(body.get("added")),
            removed=_binding_map(body.get("removed")),
            changed=changed,
            unchanged=int(body.get("unchanged") or 0),
        )

    # -- §4.4.15 cherry-pick / §4.4.16 revert -------------------------------

    async def cherry_pick(
        self, version: bytes | str, *, parent: bytes | None = None
    ) -> CherryPickResult:
        """Apply what ``version`` changed relative to its parent (§4.4.15)."""
        data: dict[str, Any] = {"prefix": self._prefix, "version": version}
        if parent is not None:
            data["parent"] = bytes(parent)
        body, _ = _unwrap(await self._execute("cherry-pick", _CHERRY_PICK_PARAMS, data))
        return CherryPickResult(
            status=str(body.get("status") or ""),
            version=_hash(body.get("version")),
            source=_hash(body.get("source")),
            conflicts=_paths(body.get("conflicts")),
            applied=int(body.get("applied") or 0),
            cascade_warnings=_warnings(body.get("cascade_warnings")),
        )

    async def revert(self, version: bytes | str, *, parent: bytes | None = None) -> RevertResult:
        """Apply the inverse of ``version``'s changes as a new version (§4.4.16)."""
        data: dict[str, Any] = {"prefix": self._prefix, "version": version}
        if parent is not None:
            data["parent"] = bytes(parent)
        body, _ = _unwrap(await self._execute("revert", _REVERT_PARAMS, data))
        return RevertResult(
            status=str(body.get("status") or ""),
            version=_hash(body.get("version")),
            reverted=_hash(body.get("reverted")),
            conflicts=_paths(body.get("conflicts")),
            applied=int(body.get("applied") or 0),
            cascade_warnings=_warnings(body.get("cascade_warnings")),
        )

    # -- §4.4.17 config ------------------------------------------------------

    async def set_config(
        self,
        name: str,
        *,
        exclude: list[str] | None = None,
        exclude_types: list[str] | None = None,
        auto_version: bool | None = None,
        merge_order: str | None = None,
        oscillation_depth: int | None = None,
        expected_hash: bytes | None = None,
        **absorbed: Any,
    ) -> dict[str, Any]:
        """Write the prefix's revision config (§4.4.17).

        ``name`` is the config's human-readable identifier and is **required** —
        `SDK-EXTENSION-OPERATIONS` §4's ``config(prefix, settings)`` signature
        has neither ``name`` nor ``action``, so a call built from it is a
        ``400 config/missing-name`` (SA-PY-5, and one of the loud rows).

        Config writes go through this operation rather than a tree put: the
        handler validates the excludes before writing (V1-V5) and coordinates
        the paired tracking-config write, which a direct put would skip while
        leaving auto-version half-enabled.

        Note there is no ``merge_strategy`` here. Merge strategy is per-path or
        per-type and lives in a different namespace with a different operation
        (:meth:`set_merge_config`) — §4 lists it as a prefix-config field, which
        is a field no handler reads.
        """
        settings = _absorb(
            {"exclude": exclude, **absorbed}, _ABSORBED_CONFIG_FIELDS, operation="set_config"
        )
        if "merge_strategy" in settings:
            raise BadRequest(
                400,
                "invalid_params",
                "merge_strategy is not a prefix-config field — merge strategy is "
                "per-path/per-type and is written by set_merge_config() into "
                "system/revision/config/merge/** (EXTENSION-REVISION §2.3/§4.4.18). "
                "SDK-EXTENSION-OPERATIONS §4 lists it under RevisionConfig; that "
                "is SA-PY-5, and writing it here would land a field nothing reads.",
            )
        unknown = set(settings) - {"exclude"}
        if unknown:
            raise BadRequest(
                400, "invalid_params", f"set_config() got unexpected arguments: {sorted(unknown)}"
            )

        config: dict[str, Any] = {"prefix": self._prefix}
        if settings.get("exclude") is not None:
            config["exclude"] = list(settings["exclude"])
        if exclude_types is not None:
            config["exclude_types"] = list(exclude_types)
        if auto_version is not None:
            config["auto_version"] = auto_version
        if merge_order is not None:
            config["merge_order"] = merge_order
        if oscillation_depth is not None:
            config["oscillation_depth"] = oscillation_depth

        data: dict[str, Any] = {
            "name": name,
            "action": "set",
            "config": {"type": _CONFIG_TYPE, "data": config},
        }
        if expected_hash is not None:
            data["expected_hash"] = bytes(expected_hash)
        body, _ = _unwrap(await self._execute("config", _CONFIG_PARAMS, data))
        return body

    async def delete_config(
        self, name: str, *, expected_hash: bytes | None = None
    ) -> dict[str, Any]:
        """Delete the prefix's revision config, cleaning up tracking-config."""
        data: dict[str, Any] = {"name": name, "action": "delete", "prefix": self._prefix}
        if expected_hash is not None:
            data["expected_hash"] = bytes(expected_hash)
        body, _ = _unwrap(await self._execute("config", _CONFIG_PARAMS, data))
        return body

    # -- §4.4.18 merge-config ------------------------------------------------

    async def set_merge_config(
        self,
        *,
        path: str | None = None,
        type: str | None = None,  # noqa: A002 - the spec's name
        strategy: str | None = None,
        deletion_resolution: str | None = None,
        expected_hash: bytes | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        """Write a per-path or per-type merge config (§4.4.18).

        Exactly one of ``path`` / ``type``. This is the **canonical** write
        path: a ``system/tree:put`` onto
        ``system/revision/config/merge/{path,type}/*`` bypasses the §2.3
        strategy-rejection contract, which is why ``lww`` and ``keep-both``
        surface as ``400 invalid_strategy`` here and as nothing at all there.

        Merge configs are global, not prefix-scoped — their pattern matches
        trie-relative paths under any prefix (§3.1.1/§5.1) — so this method is
        on the prefix handle only for discoverability.
        """
        if (path is None) == (type is None):
            raise BadRequest(
                400, "invalid_scope", "set_merge_config() takes exactly one of path= or type="
            )
        config: dict[str, Any] = dict(extra)
        if strategy is not None:
            config["strategy"] = strategy
        if deletion_resolution is not None:
            config["deletion_resolution"] = deletion_resolution
        if path is not None:
            # A path-scoped config is addressed by its glob *and* matched by a
            # `pattern` field holding the same glob — the write path names it,
            # §5.1's read-time cascade reads it. Making the caller pass one
            # string twice is how the two end up different, and a config whose
            # pattern disagrees with its address matches nothing while looking
            # installed. Overridable via `extra` for the case where they really
            # do differ.
            config.setdefault("pattern", path)
        data: dict[str, Any] = {
            "scope": "path" if path is not None else "type",
            "name": path if path is not None else type,
            "action": "set",
            "config": {"type": _MERGE_CONFIG_TYPE, "data": config},
        }
        if expected_hash is not None:
            data["expected_hash"] = bytes(expected_hash)
        body, _ = _unwrap(await self._execute("merge-config", _MERGE_CONFIG_PARAMS, data))
        return body

    async def delete_merge_config(
        self,
        *,
        path: str | None = None,
        type: str | None = None,  # noqa: A002 - the spec's name
        expected_hash: bytes | None = None,
    ) -> dict[str, Any]:
        """Delete a per-path or per-type merge config. Idempotent (``no_change``)."""
        if (path is None) == (type is None):
            raise BadRequest(
                400, "invalid_scope", "delete_merge_config() takes exactly one of path= or type="
            )
        data: dict[str, Any] = {
            "scope": "path" if path is not None else "type",
            "name": path if path is not None else type,
            "action": "delete",
        }
        if expected_hash is not None:
            data["expected_hash"] = bytes(expected_hash)
        body, _ = _unwrap(await self._execute("merge-config", _MERGE_CONFIG_PARAMS, data))
        return body


# =============================================================================
# Prefix-independent operations
# =============================================================================


async def find_ancestor(client: Any, version_a: bytes, version_b: bytes) -> bytes | None:
    """Common ancestor of two versions, or ``None`` if they share no history.

    Prefix-independent — the DAG walk is over version entries, which are
    content-addressed and carry no prefix (§4.4.10). Classified convenience
    because *exposing* it is optional; every implementation that supports
    `merge` already has the algorithm.
    """
    result = await client.execute(
        REVISION_PATTERN,
        "find-ancestor",
        {
            "type": _ANCESTOR_PARAMS,
            "data": {"version_a": bytes(version_a), "version_b": bytes(version_b)},
        },
        resource_targets=[REVISION_PATTERN],
    )
    body, _ = _unwrap(result)
    return _hash(body.get("ancestor"))


def revision(client: Any, prefix: str) -> RevisionClient:
    """Bind revision operations to ``prefix`` on ``client``."""
    return RevisionClient(client, prefix)


# =============================================================================
# Shared decoding
# =============================================================================


def _binding_map(value: Any) -> dict[str, bytes]:
    if not isinstance(value, dict):
        return {}
    return {
        k: bytes(v)
        for k, v in value.items()
        if isinstance(k, str) and isinstance(v, (bytes, bytearray))
    }


def _merge_result_from(body: dict[str, Any]) -> MergeResult:
    """Decode a `merge-result`, shared by `merge` and `pull` (§4.4.8 returns one)."""
    return MergeResult(
        status=str(body.get("status") or ""),
        version=_hash(body.get("version")),
        conflicts=_paths(body.get("conflicts")),
        dry_run=bool(body.get("dry_run", False)),
        merged_count=_int_or_none(body.get("merged_count")),
        deleted_count=_int_or_none(body.get("deleted_count")),
        cascade_warnings=_warnings(body.get("cascade_warnings")),
    )
