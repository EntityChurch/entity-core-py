"""§2.2 derived retry pacing — the pure-function vector table.

`failing_since` is ONE transition-written field; `attempt` / `next_attempt_at`
are DERIVED from `(failing_since, backoff cfg, now)`, never stored
(`HANDOFF-2026-07-16-network-lifecycle-build.md` §2/§3, arch retry-state
ruling). This is the highest-leverage test in the batch: it converts the
most divergence-prone surface into a table, and it is the artifact the cohort
converges against.

The vectors are the canonical table from the Go reference
(`core/types/network_backoff_test.go`, `TestDeriveRetryState` /
`…Exhaustion` / `…MatchesNaiveSchedule`), re-expressed against Python's
`derive_retry_state`. `fsBase` and the default curve (exponential, min 1s,
max 60s) are identical to Go's so the two tables are line-for-line comparable.
Go's uint64-saturation vectors are omitted — Python ints are unbounded, so
there is no wraparound to defend against.
"""

from __future__ import annotations

import pytest

from entity_handlers.network import (
    RetryState,
    _delay_ms,
    derive_retry_state,
)

# Identical to Go's fsBase — an arbitrary but realistic failing_since (ms).
FS = 1_700_000_000_000

DEFAULT = None  # a None/empty cfg is the §2.2 default: exponential 1s..60s.


# --- delay_ms(k), k 1-indexed -------------------------------------------------

@pytest.mark.parametrize(
    "cfg, k, want",
    [
        (DEFAULT, 0, 0),          # k=0 is no wait
        (DEFAULT, 1, 1000),       # min
        (DEFAULT, 2, 2000),       # doubles
        (DEFAULT, 3, 4000),
        (DEFAULT, 6, 32000),
        (DEFAULT, 7, 60000),      # clamps at max
        (DEFAULT, 8, 60000),
        (DEFAULT, 100, 60000),
        ({"strategy": "constant", "min_ms": 5000}, 1, 5000),
        ({"strategy": "constant", "min_ms": 5000}, 9, 5000),
        ({"strategy": "linear", "min_ms": 1000}, 1, 1000),
        ({"strategy": "linear", "min_ms": 1000}, 3, 3000),
        ({"strategy": "linear", "min_ms": 1000}, 100, 60000),  # clamps
        ({"min_ms": 5000, "max_ms": 1000}, 1, 5000),  # inverted → min
        ({"min_ms": 5000, "max_ms": 1000}, 5, 5000),
        ({"min_ms": 0, "max_ms": 0}, 3, 0),           # degenerate zero
    ],
)
def test_delay_ms(cfg, k, want):
    assert _delay_ms(cfg, k) == want


# --- derive_retry_state: (attempt, next_attempt_at) ---------------------------

@pytest.mark.parametrize(
    "cfg, failing_since, now, want_attempt, want_next",
    [
        # default curve; elapsed_to = 1s, 3s, 7s, 15s, 31s, 63s, 123s
        (DEFAULT, FS, FS, 0, FS + 1000),                     # at the failure
        (DEFAULT, FS, FS + 999, 0, FS + 1000),               # 1ms before first
        (DEFAULT, FS, FS + 1000, 1, FS + 3000),              # at first (inclusive)
        (DEFAULT, FS, FS + 2999, 1, FS + 3000),              # between 1st and 2nd
        (DEFAULT, FS, FS + 3000, 2, FS + 7000),              # at second
        (DEFAULT, FS, FS + 5000, 2, FS + 7000),              # worked example: 5s
        (DEFAULT, FS, FS + 7000, 3, FS + 15000),             # at third
        (DEFAULT, FS, FS + 63000, 6, FS + 123000),           # at sixth
        (DEFAULT, FS, FS + 123000, 7, FS + 183000),          # seventh, on plateau
        (DEFAULT, FS, FS + 150000, 7, FS + 183000),          # mid-plateau
        ({"strategy": "constant", "min_ms": 5000}, FS, FS + 4999, 0, FS + 5000),
        ({"strategy": "constant", "min_ms": 5000}, FS, FS + 12000, 2, FS + 15000),
        ({"strategy": "linear", "min_ms": 1000}, FS, FS + 9999, 3, FS + 10000),
        ({"strategy": "linear", "min_ms": 1000}, FS, FS + 10000, 4, FS + 15000),
        # THE restart-hammering vector: a peer dead 30 days resumes the curve
        # one max-length (60s) interval out, NOT min_ms.
        (DEFAULT, FS, FS + 2592000000, 43204, FS + 2592003000),
        # OPTIONAL bounds, still within them → pacing unaffected.
        ({"max_attempts": 3}, FS, FS + 3000, 2, FS + 7000),
        ({"max_elapsed_ms": 10000}, FS, FS + 3000, 2, FS + 7000),
        # edges
        (DEFAULT, 0, FS + 5000, 0, 0),                       # no episode (0)
        (DEFAULT, None, FS + 5000, 0, 0),                    # no episode (None)
        (DEFAULT, FS, FS - 10000, 0, FS + 1000),             # clock skew
        ({"min_ms": 0, "max_ms": 0}, FS, FS + 100000, 0, FS),  # zero delay always due
    ],
)
def test_derive_retry_state(cfg, failing_since, now, want_attempt, want_next):
    got = derive_retry_state(cfg, failing_since, now)
    assert got.attempt == want_attempt, got
    assert got.next_attempt_at == want_next, (
        f"next offset {got.next_attempt_at - (failing_since or 0)}, "
        f"want {want_next - (failing_since or 0)}"
    )
    assert got.exhausted is False


# --- the OPTIONAL §2.2 give-up bounds -----------------------------------------

YEAR = 365 * 24 * 60 * 60 * 1000


@pytest.mark.parametrize(
    "cfg, now, want_exhausted, want_attempt",
    [
        # the headline: default config NEVER exhausts — retry-forever is normative.
        (DEFAULT, FS + YEAR, False, 525604),
        ({"max_attempts": 3}, FS + 3000, False, 2),
        ({"max_attempts": 3}, FS + 7000, True, 3),
        ({"max_attempts": 3}, FS + 60000, True, 5),
        ({"max_attempts": 0}, FS, True, 0),               # gives up immediately
        ({"max_elapsed_ms": 10000}, FS + 9999, False, 3),
        ({"max_elapsed_ms": 10000}, FS + 10000, True, 3),  # inclusive
        ({"max_elapsed_ms": 10000}, FS + 11000, True, 3),
        # whichever bound trips first wins
        ({"max_attempts": 2, "max_elapsed_ms": 600000}, FS + 3000, True, 2),
        ({"max_attempts": 99, "max_elapsed_ms": 5000}, FS + 5000, True, 2),
    ],
)
def test_derive_retry_state_exhaustion(cfg, now, want_exhausted, want_attempt):
    got = derive_retry_state(cfg, FS, now)
    assert got.exhausted is want_exhausted, got
    assert got.attempt == want_attempt, got
    # An exhausted episode has no next attempt; a live one always has one.
    if got.exhausted:
        assert got.next_attempt_at == 0, got
    else:
        assert got.next_attempt_at != 0, got


# --- the plateau shortcut must agree exactly with the naive walk --------------

def _naive_schedule(cfg, elapsed: int) -> tuple[int, int]:
    """The definition, walked one retry at a time: largest k with
    elapsed_to(k) <= elapsed, and the offset of retry attempt+1."""
    attempt = 0
    cum = 0
    k = 1
    while True:
        delay = _delay_ms(cfg, k)
        if delay == 0:
            return attempt, cum
        nxt = cum + delay
        if nxt > elapsed:
            return attempt, nxt
        cum = nxt
        attempt = k
        k += 1


@pytest.mark.parametrize(
    "cfg",
    [
        DEFAULT,
        {"strategy": "constant", "min_ms": 5000},
        {"strategy": "linear", "min_ms": 1000},
        {"min_ms": 1000, "max_ms": 1500},  # tight cap, plateau hits fast
    ],
)
def test_derive_matches_naive_schedule(cfg):
    for elapsed in range(0, 400_001, 250):
        want_attempt, want_next = _naive_schedule(cfg, elapsed)
        got = derive_retry_state(cfg, FS, FS + elapsed)
        assert (got.attempt, got.next_attempt_at) == (want_attempt, FS + want_next), (
            f"elapsed {elapsed}: got ({got.attempt}, +{got.next_attempt_at - FS}), "
            f"naive ({want_attempt}, +{want_next})"
        )


def test_retry_state_defaults():
    """A defaulted RetryState is the no-episode zero value."""
    assert RetryState() == RetryState(attempt=0, next_attempt_at=0, exhausted=False)
