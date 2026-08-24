"""Subscription operations — `SDK-EXTENSION-OPERATIONS` v0.8 §3.

The **cross-peer** half of change notification. `SDK-OPERATIONS` §6's
`watch`/`unwatch` (`client.watch`) is the L1 ergonomic wrapper and is powered
here by the local emit pathway, which needs no extension and observes only the
local tree. This module is the other backend §6 names: a real subscription on a
peer, with a deliver token, server-tightened limits, and rate limiting. The L1
docstring points here by name.

.. rubric:: Two SDK-spec defects we found here, both since ruled

`SDK-EXTENSION-OPERATIONS` §3 is *the document an SDK author reads*, and on two
fields it disagreed with `EXTENSION-SUBSCRIPTION`, the normative contract the
handlers implement. Both were filed (**SA-PY-2**, **SA-PY-3**), routed, and
**ruled at `SDK-EXTENSION-OPERATIONS` 0.8.1 as SA-2 and SA-3** — §3 now carries
the extension's vocabulary and unit, with the old text recorded inline as what
it wrongly said.

1. **The event vocabulary (SA-2).** §3 read *"Event types to filter (`"put"`,
   `"remove"`)"* against the extension's `created` / `updated` / `deleted`, and
   the engine filters with `event.kind.value not in subscription.events`. A
   caller following the SDK spec literally matched **nothing, silently, for the
   life of the subscription**. §3 is now correct, and
   :func:`normalize_events` accepts only the ruled vocabulary — see there for
   why the old spelling is now rejected rather than aliased.

2. **The rate-limit unit (SA-3).** §3 said *"Max events per second"* against the
   extension's *"per minute"* and the engine's 60-second window
   (`check_rate_limit`) — 60× apart, with nothing in the result to tell them
   apart. §3 now says per minute. The parameter here stays named
   **`rate_limit_per_minute`**: the ruling fixed the document, and naming the
   unit keeps the mistake unspellable regardless of which revision a caller
   read.

.. rubric:: What is *not* absorbed

Server-tightened limits are returned as the peer merged them, not as requested
(§3: *"server may tighten client limits"*). :attr:`SubscriptionInfo.limits`
is the effective set; comparing it against what you asked for is how you learn
the peer tightened something, and that is a fact the caller is entitled to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from entity_sdk.errors import BadRequest

__all__ = [
    "SUBSCRIPTION_PATTERN",
    "SUBSCRIBE_REQUEST_TYPE",
    "UNSUBSCRIBE_REQUEST_TYPE",
    "WIRE_EVENTS",
    "SubscriptionLimits",
    "SubscriptionInfo",
    "normalize_events",
    "subscribe",
    "unsubscribe",
]

#: The handler's dispatch pattern. A pattern string, not an import.
SUBSCRIPTION_PATTERN = "system/subscription"

SUBSCRIBE_REQUEST_TYPE = "system/subscription/request"
UNSUBSCRIBE_REQUEST_TYPE = "system/subscription/cancel"

#: `EXTENSION-SUBSCRIPTION` §2.1 — the vocabulary the engine actually filters on.
WIRE_EVENTS = ("created", "updated", "deleted")

#: `SDK-OPERATIONS` §6.1's `ChangeEvent.event_type` values. **Not** valid as a
#: subscribe filter — see :func:`normalize_events`. Kept only to make the error
#: message able to name what the caller probably has in hand.
_L1_CHANGE_EVENT_TYPES: dict[str, tuple[str, ...]] = {
    "put": ("created", "updated"),
    "remove": ("deleted",),
}


def normalize_events(events: Iterable[str] | None) -> list[str] | None:
    """Validate subscribe's ``events`` filter against §3's vocabulary.

    Returns wire values in a stable order, deduplicated, or ``None`` for "all
    events" — the absent-parameter shape the handler expects, which is not the
    same as an empty list.

    .. rubric:: `put` / `remove` are rejected here, deliberately

    They were accepted while SA-PY-2 was open, because §3 documented them as
    *the* filter vocabulary. **Arch ruled SA-2 at 0.8.1** and §3 now reads
    `("created", "updated", "deleted")`, recording `("put", "remove")` only as
    what the line wrongly used to say. So for *this parameter* the two-value
    spelling names a vocabulary no document defines, and an SDK that keeps
    accepting it is manufacturing a local divergence — precisely the class of
    defect this implementation exists to find in other people's stacks.

    **The confusion is real and the error message answers it.** `put`/`remove`
    *are* still normative — as `ChangeEvent.event_type` in `SDK-OPERATIONS`
    §6.1, the L1 `watch()` surface. A caller who reads an event off
    :meth:`EntityClient.watch` and reaches for the same word here is making a
    reasonable mistake between two real vocabularies, so they get told the
    mapping rather than just "invalid".

    Raises:
        BadRequest: 400 ``invalid_events`` for anything outside §3's three.
            Loud by design: the handler compares event names by equality, so an
            unrecognized one never matches and a typo'd subscription is a
            subscription to nothing that looks perfectly healthy.
    """
    if events is None:
        return None

    out: list[str] = []
    for raw in events:
        if not isinstance(raw, str):
            raise BadRequest(400, "invalid_events", f"event name must be a string, got {raw!r}")
        name = raw.strip()
        if name in WIRE_EVENTS:
            if name not in out:
                out.append(name)
            continue
        if name in _L1_CHANGE_EVENT_TYPES:
            equivalent = " + ".join(_L1_CHANGE_EVENT_TYPES[name])
            raise BadRequest(
                400, "invalid_events",
                f"{raw!r} is a ChangeEvent.event_type (SDK-OPERATIONS §6.1, the "
                f"L1 watch() surface), not a subscribe filter. §3 filters on "
                f"{'/'.join(WIRE_EVENTS)} — pass {equivalent} instead.",
            )
        raise BadRequest(
            400, "invalid_events",
            f"unknown event {raw!r} — use {'/'.join(WIRE_EVENTS)}. "
            "An unrecognized name would match nothing rather than error.",
        )

    if not out:
        raise BadRequest(
            400, "invalid_events",
            "events must be None (all events) or a non-empty list — an empty "
            "list is a subscription that can never fire",
        )
    # Stable, vocabulary order rather than caller order: two callers asking for
    # the same set should produce the same stored subscription.
    return [e for e in WIRE_EVENTS if e in out]


@dataclass(frozen=True, slots=True)
class SubscriptionLimits:
    """§3 / `EXTENSION-SUBSCRIPTION` §2.4 — per-subscription resource bounds.

    ``rate_limit_per_minute`` is named for its unit (SA-PY-3): the SDK spec
    calls it per-second, the normative extension and the engine's 60s window
    make it per-minute, and the two differ by 60× with nothing in the result to
    tell them apart.

    ``max_events`` and ``max_duration_ms`` *terminate* the subscription;
    exceeding the rate limit only **drops** individual notifications.
    """

    max_events: int | None = None
    max_duration_ms: int | None = None
    rate_limit_per_minute: int | None = None
    notification_budget: int | None = None

    def to_data(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.max_events is not None:
            out["max_events"] = self.max_events
        if self.max_duration_ms is not None:
            out["max_duration_ms"] = self.max_duration_ms
        if self.rate_limit_per_minute is not None:
            out["rate_limit"] = self.rate_limit_per_minute
        if self.notification_budget is not None:
            out["notification_budget"] = self.notification_budget
        return out

    @classmethod
    def from_data(cls, data: Any) -> SubscriptionLimits:
        d = data if isinstance(data, dict) else {}
        return cls(
            max_events=d.get("max_events"),
            max_duration_ms=d.get("max_duration_ms"),
            rate_limit_per_minute=d.get("rate_limit"),
            notification_budget=d.get("notification_budget"),
        )


@dataclass(frozen=True, slots=True)
class SubscriptionInfo:
    """§3 `SubscriptionInfo` — the subscription as the peer stored it.

    :attr:`limits` is the **effective** set after the server merged its own in;
    the server may tighten and never loosen. Compare against what you requested
    to learn what it tightened.
    """

    subscription_id: str
    pattern: str
    events: list[str]
    limits: SubscriptionLimits


def _data_of(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {}
    inner = result.get("data")
    return inner if isinstance(inner, dict) else result


async def subscribe(
    client: Any,
    pattern: str,
    *,
    deliver_to: str,
    deliver_token: bytes,
    deliver_operation: str = "receive",
    events: Iterable[str] | None = None,
    include_payload: bool = False,
    limits: SubscriptionLimits | None = None,
) -> SubscriptionInfo:
    """Register for change notifications on ``pattern`` (§3).

    Args:
        pattern: Path pattern — an exact path or a trailing ``/*`` prefix.
        deliver_to: URI notifications are delivered to, usually an inbox
            (``entity://{peer}/system/inbox/{name}``).
        deliver_token: Content hash of the capability token authorizing
            delivery to ``deliver_to``. The token must already be resolvable by
            the peer — it is validated against the content store, its expiry,
            and (SB1) the subscriber's presence in its authority chain.
        events: Which changes to notify on, in **either** vocabulary. ``None``
            means all. See :func:`normalize_events` and SA-PY-2.
        include_payload: Bundle the changed entity into the notification's
            ``included`` (v3.14). **Requires ``tree:get`` on the subscribed
            resource** — a caller holding `subscribe` but not `get` is refused
            with ``403 payload_unauthorized`` rather than silently downgraded,
            because the option is a capability bypass otherwise (§2.3 v3.13).
            Omit it and the same caller still receives lean hashes-only events.

    Raises:
        BadRequest: 400 for an unknown event name, a missing deliver token, or
            an absent pattern.
        AuthorizationError: 403 — token expired, token insufficient for the
            deliver URI, SB1 chain check failed, or `payload_unauthorized`.
    """
    if not pattern:
        raise BadRequest(400, "missing_pattern", "pattern is required")

    data: dict[str, Any] = {
        "pattern": pattern,
        "deliver_to": {"uri": deliver_to, "operation": deliver_operation},
        "deliver_token": deliver_token,
    }
    normalized = normalize_events(events)
    if normalized is not None:
        data["events"] = normalized
    if include_payload:
        data["include_payload"] = True
    if limits is not None:
        limit_data = limits.to_data()
        if limit_data:
            data["limits"] = limit_data

    result = await client.execute(
        SUBSCRIPTION_PATTERN,
        "subscribe",
        {"type": SUBSCRIBE_REQUEST_TYPE, "data": data},
    )
    body = _data_of(result)
    return SubscriptionInfo(
        subscription_id=body.get("subscription_id", ""),
        pattern=body.get("pattern", pattern),
        events=list(body.get("events") or []),
        limits=SubscriptionLimits.from_data(body.get("limits")),
    )


async def unsubscribe(client: Any, subscription_id: str) -> None:
    """Cancel a subscription (§3).

    Returns nothing: the operation's result is a status, and there is no field
    on it a caller can act on that the absence of an exception does not already
    say. A failure arrives as a typed §12 exception like any other.
    """
    if not subscription_id:
        raise BadRequest(400, "invalid_params", "subscription_id is required")
    await client.execute(
        SUBSCRIPTION_PATTERN,
        "unsubscribe",
        {"type": UNSUBSCRIBE_REQUEST_TYPE, "data": {"subscription_id": subscription_id}},
    )
