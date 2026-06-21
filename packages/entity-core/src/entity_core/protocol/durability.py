"""Durability contract types and reconciliation (EXTENSION-DURABILITY).

Per EXTENSION-DURABILITY v0.1 (extracted from EXTENSION-INBOX
§10; ``proposals/PROPOSAL-DELIVERY-AND-DURABILITY.md`` is **RETRACTED**).
EXTENSION-DURABILITY is **EXPLORATORY · OPTIONAL · NOT ACTIVELY
DEVELOPED**; no deployment is required to install it and V7 v7.46 does
not depend on it. The 412 status and the durability use of 202 are
reintroduced *within this extension's surface only* — V7 v7.46 does
not reserve them at the core level. Depends V7 v7.46+.

This module is the shared, pure core of the durability contract:

- :class:`DurabilityRequest` — the optional request-side marker
  (``system/durability-request``) carried on EXECUTE.
- :class:`DurabilityResult` — the pinned response field
  (``system/durability-result``) carried on EXECUTE_RESPONSE.
- :class:`DurabilityPolicy` — the receiver's own configured policy,
  decided at acceptance from its own configuration (§4); a *mistrust*
  model — both sides are observable, neither blindly trusts the other.
- :func:`reconcile` — the §5 verdict table, one distinct meaning per
  status number, with the invariant that ``applied`` is *durability
  physically in place at response time* and never names a promise.

The strength *vocabulary* here (``none`` < ``stored`` < ``replicated``)
is **illustrative, not a ratified enum** (§7). The field *shape* is
pinned for cross-impl determinism; the level vocabulary is
receiver-defined and one peer's may not match another's — unknown levels
are handled per the §5 fail-closed rule. ``stored`` is self-determinable
at acceptance; ``replicated`` is replication-class — a second peer
holding the data cannot be proven synchronously, so a *required*
replication strength is inherently "202-then-observe" (§5 invariant),
never a synchronous guarantee.

Reason-code spellings for spec-enumerated cases are **pinned** by §7:
``no_durable_store``, ``durability_required_unmet``, ``unknown_level``,
``duplicate_request_id``. Other diagnostic codes remain
implementation-defined.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Status codes (EXTENSION-DURABILITY §5; EXTENSION-INBOX §7.1 for 202).
# 202 is the *existing* "accepted; completion asynchronous, observed
# elsewhere" meaning EXTENSION-INBOX §7.1 already uses — reused within
# this extension's surface, not a new sense. 412 is reserved for a
# required-durability precondition that could not be met: the operation
# was NOT performed (refused at acceptance), safe to retry — no
# double-execution hazard. 409 is for duplicate (author, request_id) —
# already in V7's reserved set for ``duplicate_request_id``.
STATUS_ACCEPTED = 202
STATUS_PRECONDITION_FAILED = 412
STATUS_CONFLICT = 409

# Illustrative strength vocabulary (§7 — NOT a frozen enum). Ordered
# weakest -> strongest. Unknown levels are handled per the §5 fail-closed
# rule (``must_have`` → 412 ``unknown_level``; otherwise → 200 best-effort
# with ``applied: none``).
LEVEL_NONE = "none"
LEVEL_STORED = "stored"
LEVEL_REPLICATED = "replicated"

_LEVEL_ORDER = [LEVEL_NONE, LEVEL_STORED, LEVEL_REPLICATED]
_KNOWN_LEVELS = frozenset(_LEVEL_ORDER)

# Replication-class strengths are NOT self-certifiable at acceptance
# (§5 invariant): no receiver can synchronously prove a second peer
# holds the data.
_REPLICATION_CLASS = frozenset({LEVEL_REPLICATED})

# Reason code spellings for spec-enumerated cases are PINNED by §7
# (a §8 MUST). Other diagnostic ``reason`` strings remain
# implementation-defined.
REASON_NO_DURABLE_STORE = "no_durable_store"
REASON_REQUIRED_UNMET = "durability_required_unmet"
REASON_UNKNOWN_LEVEL = "unknown_level"
REASON_DUPLICATE_REQUEST_ID = "duplicate_request_id"
# Implementation-defined diagnostic; not in §7's pinned set. Used by
# this peer when ``deliver_to`` is requested but no inbox handler can
# honor the delivery.
REASON_NO_INBOX_HANDLER = "no_inbox_handler"


def level_rank(level: str) -> int:
    """Total order over recognized strength levels.

    For unknown levels, returns ``len(_LEVEL_ORDER)`` (strictly above
    every recognized level) so any policy comparison naturally falls
    to "cannot meet" — but the spec contract for unknown levels is the
    §5 fail-closed rule, not the rank. Use :func:`is_known_level` for
    the §5 unknown-level branch.
    """
    try:
        return _LEVEL_ORDER.index(level)
    except ValueError:
        return len(_LEVEL_ORDER)


def is_known_level(level: str) -> bool:
    """Whether ``level`` is in this receiver's recognized vocabulary
    (§7). The §5 fail-closed rule turns on this: an unrecognized
    must_have level is 412 ``unknown_level``; otherwise it is 200
    best-effort with ``applied: none, reason: unknown_level``."""
    return level in _KNOWN_LEVELS


def is_replication_class(level: str) -> bool:
    """Whether ``level`` is replication-class (not self-certifiable at
    acceptance — inherently 202-then-observe per §5)."""
    return level in _REPLICATION_CLASS


@dataclass
class DurabilityRequest:
    """``system/durability-request`` — optional request-side marker.

    Extends ``system/protocol/execute``; independent of
    ``deliver_to``/``deliver_token`` (§2). Setting none of the three
    orthogonal knobs yields prior behavior unchanged (§1).

    Attributes:
        level: requested durability level; vocabulary illustrative (§7).
        must_have: default False. False = best-effort (take less,
            observably). True = required (refuse with 412 if unmet, §5).
    """

    TYPE = "system/durability-request"

    level: str
    must_have: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to wire format. ``must_have`` omitted when False
        (its default) to keep the wire shape minimal for the common case."""
        out: dict[str, Any] = {"level": self.level}
        if self.must_have:
            out["must_have"] = True
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DurabilityRequest:
        """Parse from wire format."""
        return cls(
            level=data["level"],
            must_have=bool(data.get("must_have", False)),
        )


@dataclass
class DurabilityResult:
    """``system/durability-result`` — the pinned response field (§5).

    Carried on EXECUTE_RESPONSE as the ``durability`` field. The shape is
    pinned for cross-impl determinism:

    - ``applied`` is durability PHYSICALLY IN PLACE at the moment of the
      response (or ``"none"``). ONE meaning in every row; never a promise.
    - ``committed`` is a strength committed to an ASYNCHRONOUS pathway —
      present ONLY with status 202.
    - ``max_available`` is the best the receiver could offer — present
      ONLY with status 412.
    - ``handle`` is the absolute tree path where the durable entry can be
      read — the sender's lookup address (§6). Present when
      ``applied != none`` (200 with achieved strength) and on 202
      (naming where the committed entry will land); absent otherwise.
      The RECEIVER chooses the path; the spec does NOT prescribe layout.
    - ``reason`` is an optional code string. Spec-enumerated cases use
      PINNED spellings (§7); other diagnostic codes remain
      implementation-defined.
    """

    TYPE = "system/durability-result"

    requested: str
    applied: str
    committed: str | None = None
    max_available: str | None = None
    handle: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to wire format. Optional fields are omitted when
        absent so a durability-unaware consumer sees a minimal map and
        the §5/§8 invariants (``committed`` only on 202; ``max_available``
        only on 412; ``handle`` only when ``applied != none`` or on 202)
        are structurally visible."""
        out: dict[str, Any] = {
            "requested": self.requested,
            "applied": self.applied,
        }
        if self.committed is not None:
            out["committed"] = self.committed
        if self.max_available is not None:
            out["max_available"] = self.max_available
        if self.handle is not None:
            out["handle"] = self.handle
        if self.reason is not None:
            out["reason"] = self.reason
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DurabilityResult:
        """Parse from wire format."""
        return cls(
            requested=data["requested"],
            applied=data["applied"],
            committed=data.get("committed"),
            max_available=data.get("max_available"),
            handle=data.get("handle"),
            reason=data.get("reason"),
        )


@dataclass(frozen=True)
class DurabilityPolicy:
    """The receiver's own configured durability policy (§4, §8).

    Implementation-defined. Decided at acceptance from this peer's own
    configuration — NOT a prediction of another peer's future state.

    Attributes:
        self_levels: self-determinable strengths this peer can place
            physically in effect at acceptance time (e.g. ``{"stored"}``
            for a peer with a durable store). Empty = no durable store —
            a peer with this policy that ships the extension still
            answers a durability request observably per §8, never
            silently dropped.
        replication_levels: replication-class strengths this peer is
            *configured for* (a topology role). A required replication
            strength is still 202-then-observe; configuration only
            decides 202 (accepted) vs 412 (not configured for it).
    """

    self_levels: frozenset[str] = frozenset()
    replication_levels: frozenset[str] = frozenset()

    def max_self(self) -> str:
        """Strongest self-determinable level this peer can apply now, or
        ``"none"`` when it has no durable store."""
        best = LEVEL_NONE
        for lvl in self.self_levels:
            if level_rank(lvl) > level_rank(best):
                best = lvl
        return best


# The core default: no durable store. A peer with this policy still
# answers a durability request observably (§8 — never silently dropped);
# it just reports ``applied: none``.
DEFAULT_DURABILITY_POLICY = DurabilityPolicy()


@dataclass
class DurabilityVerdict:
    """Outcome of :func:`reconcile`: the §5 status + the pinned field.

    Status meaning is fixed and is the only branch a consumer needs:

    - ``refuse`` (412 or 409): the operation MUST NOT be performed.
      412 = required precondition unmet (safe to retry — no
      double-execution). 409 = duplicate ``(author, request_id)`` (the
      prior entry stands).
    - ``accepted_async`` (202): accepted; ``result.committed`` completes
      asynchronously and is observable via ``result.handle`` (§6).
    - neither: status is 200-class; the durability outcome is final.
      The handler runs normally; the ``durability`` field is attached.
    """

    result: DurabilityResult
    status: int
    refuse: bool = False
    accepted_async: bool = False


def reconcile(
    request: DurabilityRequest, policy: DurabilityPolicy
) -> DurabilityVerdict:
    """Reconcile a durability request against the receiver's own policy.

    Implements the §5 verdict table exactly (rows 1–7; row 8 — the
    ``duplicate_request_id`` 409 — is enforced at the dispatch site
    against the preserved-entry index, not from policy alone). The
    ``min(requested, policy-supported)`` rule applies to self-determinable
    strengths, decided at acceptance from the receiver's own
    configuration (§4).

    Invariants (§5/§8 MUSTs):

    - ``applied`` is durability physically in place at the moment of
      this response — one meaning in every row, never a promise.
    - A promise lives only in ``committed``, gated to status 202.
    - ``max_available`` appears only with 412.
    - Unknown level + ``must_have`` → 412 ``unknown_level``
      (fail-closed); unknown level best-effort → 200 ``unknown_level``
      with ``applied: none``. Never silently downgrade an unrecognized
      must-have level (§5 rows 6/7).
    """
    requested = request.level
    must = request.must_have
    self_max = policy.max_self()

    # §5 rows 6/7: unknown level. Fail-closed for must_have, best-effort
    # fallback otherwise. Checked BEFORE the replication / self-determinable
    # branches because an unknown level cannot be classified as either.
    if not is_known_level(requested):
        if must:
            return DurabilityVerdict(
                result=DurabilityResult(
                    requested=requested,
                    applied=LEVEL_NONE,
                    max_available=self_max,  # strongest recognized; may be "none"
                    reason=REASON_UNKNOWN_LEVEL,
                ),
                status=STATUS_PRECONDITION_FAILED,
                refuse=True,
            )
        return DurabilityVerdict(
            result=DurabilityResult(
                requested=requested,
                applied=LEVEL_NONE,
                reason=REASON_UNKNOWN_LEVEL,
            ),
            status=200,
        )

    if is_replication_class(requested):
        # Replication-class: not self-certifiable at acceptance. The
        # receiver knows its own configuration, so "configured for it"
        # decides 202 (accepted, completes later) vs 412 (not configured).
        if requested in policy.replication_levels:
            # Row 5: accepted; the committed strength completes
            # asynchronously. ``applied`` still reports only what is
            # physically in place now (a weaker self-determined level
            # or none) — never the promised replication.
            return DurabilityVerdict(
                result=DurabilityResult(
                    requested=requested,
                    applied=self_max,
                    committed=requested,
                ),
                status=STATUS_ACCEPTED,
                accepted_async=True,
            )
        if must:
            # Row 4: required, not configured for the topology.
            return DurabilityVerdict(
                result=DurabilityResult(
                    requested=requested,
                    applied=LEVEL_NONE,
                    max_available=self_max,
                    reason=REASON_REQUIRED_UNMET,
                ),
                status=STATUS_PRECONDITION_FAILED,
                refuse=True,
            )
        # Best-effort: fall back to the strongest self-determined level.
        result = DurabilityResult(requested=requested, applied=self_max)
        if self_max == LEVEL_NONE:
            result.reason = REASON_NO_DURABLE_STORE
        return DurabilityVerdict(result=result, status=200)

    # Self-determinable requested strength.
    achieved = requested if level_rank(self_max) >= level_rank(requested) else self_max

    if level_rank(achieved) >= level_rank(requested):
        # Row 1: receiver can do >= X. Report exactly X.
        return DurabilityVerdict(
            result=DurabilityResult(requested=requested, applied=requested),
            status=200,
        )
    if not must:
        # Row 2 (weaker Y, best-effort) / Row 3 (no durable store).
        result = DurabilityResult(requested=requested, applied=achieved)
        if achieved == LEVEL_NONE:
            result.reason = REASON_NO_DURABLE_STORE
        return DurabilityVerdict(result=result, status=200)
    # Row 4: must-have, cannot meet.
    return DurabilityVerdict(
        result=DurabilityResult(
            requested=requested,
            applied=LEVEL_NONE,
            max_available=achieved,
            reason=REASON_REQUIRED_UNMET,
        ),
        status=STATUS_PRECONDITION_FAILED,
        refuse=True,
    )


def reconcile_for_dispatch(
    request: DurabilityRequest | None,
    policy: DurabilityPolicy,
    *,
    async_completion: bool,
    deliverable: bool = True,
) -> DurabilityVerdict | None:
    """Dispatch-time reconciliation (the §8 no-silent-discard surface).

    Wraps :func:`reconcile` (the pure §5 table) with the two
    dispatch-only facts the table itself does not encode:

    - ``async_completion``: the operation (and any store) completes
      *after* this response is emitted (the ``deliver_to`` async path,
      EXTENSION-INBOX §7.1 — used here independently of the durability
      extension's own 202). The §5 invariant forbids reporting a
      not-yet-achieved strength in ``applied`` — so a strength the peer
      *is* configured for is reported as ``committed`` with status 202
      (observable via ``handle``, §6), never ``applied``. A *required*
      strength the peer is configured for is therefore 202-then-observe,
      not 412 (§5 invariant).
    - ``deliverable``: a ``deliver_to`` was requested but no inbox
      handler exists to honor it. The result/durability cannot be
      delivered, so report it observably (``no_inbox_handler`` —
      implementation-defined diagnostic, not in §7's pinned set); a
      ``must_have`` ask that cannot be honored is refused at acceptance
      (412), never run-then-lost.

    Returns ``None`` when there is nothing to reconcile (no durability
    marker and the ``deliver_to``, if any, is honorable) — the caller
    proceeds exactly as before, no ``durability`` field on the wire, so
    durability-unaware callers are unaffected.
    """
    if request is None:
        if deliverable:
            return None
        # deliver_to requested but undeliverable; no durability marker,
        # so no must_have — degrade to an observable report, never the
        # 202-then-silent-loss class.
        return DurabilityVerdict(
            result=DurabilityResult(
                requested=LEVEL_NONE,
                applied=LEVEL_NONE,
                reason=REASON_NO_INBOX_HANDLER,
            ),
            status=200,
        )

    if not deliverable:
        if request.must_have:
            return DurabilityVerdict(
                result=DurabilityResult(
                    requested=request.level,
                    applied=LEVEL_NONE,
                    max_available=LEVEL_NONE,
                    reason=REASON_REQUIRED_UNMET,
                ),
                status=STATUS_PRECONDITION_FAILED,
                refuse=True,
            )
        return DurabilityVerdict(
            result=DurabilityResult(
                requested=request.level,
                applied=LEVEL_NONE,
                reason=REASON_NO_INBOX_HANDLER,
            ),
            status=200,
        )

    base = reconcile(request, policy)
    if not async_completion:
        return base
    if base.refuse:
        # A required strength the peer is not configured for at all is
        # still refused at acceptance (no double-execution) — unchanged.
        return base

    # Async completion: nothing the handler does is physically in place
    # at response time. If the peer is configured for the requested
    # strength (the sync table met it, or it was already replication
    # 202), the strength is committed to the async pathway.
    met = (
        base.accepted_async
        or (
            level_rank(base.result.applied) >= level_rank(request.level)
            and base.result.reason is None
        )
    )
    if met:
        return DurabilityVerdict(
            result=DurabilityResult(
                requested=request.level,
                applied=LEVEL_NONE,
                committed=request.level,
            ),
            status=STATUS_ACCEPTED,
            accepted_async=True,
        )
    # Best-effort: peer not configured for the requested strength (and
    # not must_have — that already refused above via base.refuse). The
    # deliver_to still completes asynchronously (existing 202 ack).
    result = DurabilityResult(requested=request.level, applied=LEVEL_NONE)
    if base.result.applied == LEVEL_NONE:
        result.reason = REASON_NO_DURABLE_STORE
    return DurabilityVerdict(
        result=result, status=STATUS_ACCEPTED, accepted_async=True
    )


# Tree path for the §3 advertisement entity. Discovery is **MAY** in
# EXTENSION-DURABILITY v0.1 (loosened from §10.3's SHOULD on extraction):
# probe-via-request (the §5 contract itself) is the canonical fallback
# when advertisement is absent. Path is implementation-chosen; this
# implementation seeds at ``system/durability`` to match the Go reference.
ADVERTISEMENT_PATH = "system/durability"
ADVERTISEMENT_TYPE = "system/durability-advertisement"


def advertise(policy: DurabilityPolicy) -> dict[str, Any]:
    """Discovery payload for a receiver's supported durability (§3).

    Shape aligned with the Go reference for tree-level discovery:

    - ``levels``: union of self-determinable and replication-class
      strengths the peer supports, weakest → strongest.
    - ``max_self_determinable``: the strongest level guaranteed
      synchronously at acceptance (``"none"`` when no durable store).

    **MAY** be exposed (§3, loosened from SHOULD on extraction) so a
    sender can choose ``level``/``must_have`` informedly. Absence of
    advertisement does not change the response contract (§5) — it only
    removes the sender's ability to choose in advance; probe-via-request
    is the canonical fallback.
    """
    all_levels = sorted(
        policy.self_levels | policy.replication_levels, key=level_rank
    )
    return {
        "levels": all_levels,
        "max_self_determinable": policy.max_self(),
    }
