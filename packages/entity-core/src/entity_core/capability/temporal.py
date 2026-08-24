"""Temporal validity of a capability token — representability, then bounds.

One predicate, because there were five copies of the bounds check and none of
them checked representability (`checking.py` ×4, `delegation.py` ×2 counting the
chain walk). `GUIDE-CAPABILITIES` §6.2 splits the question in two, and the order
matters:

1. **Representable?** `expires_at`, `not_before` and `created_at` are `uint64`
   milliseconds. A value that does not fit — a bignum above 2^64, a negative, a
   non-integer — makes the token **malformed**. CAP-6a (ingest) requires refusal
   via the §5.2 `capability_denied` disposition: not "treat the field as
   absent", and not a decode-layer silent drop.
2. **In bounds?** Only then does `expires_at < now` / `not_before > now` mean
   anything.

.. rubric:: Why this is a Python-shaped bug

In Go and Rust the CBOR decode into a `u64` fails and a hostile token never
reaches step 2. `cbor2` hands back an arbitrary-precision `int`, so
``2**64 + 1000 < now`` is a perfectly well-formed comparison that evaluates to
``False`` — the token is not rejected and not truncated, it is compared,
correctly, and found to expire after the heat death of the universe. Four of the
six field×shape variants `entity-core-go`'s CAP-6a probe sends were honored
here; the other two (`expires_at=-1`, `not_before=2**64+1000`) were refused by
**accident**, as ordinary expiry verdicts, which is why a narrower probe would
have called this clean.

.. rubric:: The mint side is not this

`capability/grant.py` and `entity_handlers/capability.py::_mint_token` already
refuse to *emit* an unrepresentable expiry (CAP-6, fixed at `70493c9`): there,
an unrepresentable `now + ttl` is **absent**, per §5.6, because a token we mint
with no expiry is a token we chose to make non-expiring. On **ingest** absence
is not available as an answer — the sender chose the value, and "absent" would
hand a hostile token exactly the never-expiring reading it was reaching for.
Same three fields, opposite dispositions, and the asymmetry is the point.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "UINT64_MAX",
    "TEMPORAL_FIELDS",
    "is_representable_timestamp",
    "unrepresentable_temporal_field",
    "temporal_validity",
]

#: The largest value a `uint64` millisecond timestamp can carry.
UINT64_MAX = 2**64 - 1

#: The three fields §6.2 names. `created_at` is included even though nothing in
#: this implementation compares it: a token carrying a value no conformant peer
#: could have encoded is malformed whether or not *our* logic depends on it, and
#: two peers disagreeing about whether a token is well-formed is worse than
#: either verdict alone.
TEMPORAL_FIELDS = ("expires_at", "not_before", "created_at")


def is_representable_timestamp(value: Any) -> bool:
    """Whether ``value`` is a `uint64` millisecond timestamp.

    ``bool`` is excluded deliberately: it is an `int` subclass in Python, so
    ``True`` would otherwise read as the timestamp 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return 0 <= value <= UINT64_MAX


def unrepresentable_temporal_field(capability_data: dict[str, Any]) -> str | None:
    """The first §6.2 temporal field that is present and not `uint64`, if any.

    Fields are checked in :data:`TEMPORAL_FIELDS` order so the reported field is
    the same on every peer that adopts this order — a caller debugging a
    rejection should not get a different field name depending on dict ordering.
    """
    if not isinstance(capability_data, dict):
        return None
    for field in TEMPORAL_FIELDS:
        value = capability_data.get(field)
        if value is None:
            continue
        if not is_representable_timestamp(value):
            return field
    return None


def temporal_validity(
    capability_data: dict[str, Any],
    now: int,
) -> tuple[bool, str | None]:
    """Check representability then bounds.

    Returns ``(ok, reason)`` where ``reason`` is ``None`` when ok, and otherwise
    one of ``"malformed:<field>"``, ``"expired"``, ``"not_yet_valid"``. Callers
    that only need a verdict ignore the reason; the chain walk uses it to say
    which of the three happened, because "malformed" and "expired" are different
    things to tell a caller — one is a bug in their token, the other is time
    passing.
    """
    bad_field = unrepresentable_temporal_field(capability_data)
    if bad_field is not None:
        return False, f"malformed:{bad_field}"

    if not isinstance(capability_data, dict):
        return True, None

    expires_at = capability_data.get("expires_at")
    if expires_at is not None and expires_at < now:
        return False, "expired"

    not_before = capability_data.get("not_before")
    if not_before is not None and not_before > now:
        return False, "not_yet_valid"

    return True, None
