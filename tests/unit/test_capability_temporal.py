"""The shared temporal predicate — `entity_core.capability.temporal`.

The integration counterpart (`test_capability_ingest_temporal_cap6a.py`) proves
the ingest path refuses a hostile token. This file pins the predicate itself,
because it is now the single definition behind seven call sites and the way a
shared predicate fails is by being subtly wrong in a case only one caller hits.
"""

from __future__ import annotations

import pytest

from entity_core.capability.temporal import (
    TEMPORAL_FIELDS,
    UINT64_MAX,
    is_representable_timestamp,
    temporal_validity,
    unrepresentable_temporal_field,
)

NOW = 1_700_000_000_000


class TestRepresentability:
    @pytest.mark.parametrize("value", [0, 1, NOW, UINT64_MAX])
    def test_uint64_range_is_representable(self, value):
        assert is_representable_timestamp(value) is True

    @pytest.mark.parametrize("value", [-1, -NOW, UINT64_MAX + 1, 2**128])
    def test_out_of_range_is_not(self, value):
        assert is_representable_timestamp(value) is False

    @pytest.mark.parametrize("value", ["0", 1.5, float(NOW), b"\x00", None, [], {}])
    def test_non_integers_are_not(self, value):
        assert is_representable_timestamp(value) is False

    def test_bool_is_not_a_timestamp(self):
        """`bool` is an `int` subclass — without the explicit exclusion,
        ``True`` would read as the epoch millisecond 1 and ``False`` as 0,
        which is a token that expired in 1970 rather than a malformed one."""
        assert is_representable_timestamp(True) is False
        assert is_representable_timestamp(False) is False


class TestFieldDetection:
    def test_all_three_fields_are_checked(self):
        for field in TEMPORAL_FIELDS:
            assert unrepresentable_temporal_field({field: -1}) == field

    def test_absent_and_none_are_fine(self):
        assert unrepresentable_temporal_field({}) is None
        assert unrepresentable_temporal_field({"expires_at": None}) is None

    def test_the_reported_field_does_not_depend_on_dict_order(self):
        """Two peers reporting different field names for the same token would
        make a rejection un-reproducible from the message alone."""
        forward = {"expires_at": -1, "not_before": -1, "created_at": -1}
        reverse = dict(reversed(list(forward.items())))
        assert unrepresentable_temporal_field(forward) == TEMPORAL_FIELDS[0]
        assert unrepresentable_temporal_field(reverse) == TEMPORAL_FIELDS[0]


class TestValidity:
    def test_a_normal_token_is_valid(self):
        assert temporal_validity(
            {"not_before": NOW - 1000, "expires_at": NOW + 1000}, NOW
        ) == (True, None)

    def test_no_bounds_at_all_is_valid(self):
        assert temporal_validity({}, NOW) == (True, None)

    def test_expired_and_not_yet_valid_are_distinguished(self):
        assert temporal_validity({"expires_at": NOW - 1}, NOW) == (False, "expired")
        assert temporal_validity({"not_before": NOW + 1}, NOW) == (False, "not_yet_valid")

    def test_malformed_wins_over_bounds(self):
        """Order matters: a token with a bignum `expires_at` and a stale
        `not_before` is malformed, not expired. The two get different
        dispositions and different messages — one says the sender built a bad
        token, the other says time passed."""
        ok, reason = temporal_validity(
            {"expires_at": UINT64_MAX + 1, "not_before": NOW - 1}, NOW
        )
        assert (ok, reason) == (False, "malformed:expires_at")

    def test_the_boundary_value_is_a_bound_not_a_malformation(self):
        assert temporal_validity({"expires_at": UINT64_MAX}, NOW) == (True, None)
        assert temporal_validity({"not_before": UINT64_MAX}, NOW) == (
            False, "not_yet_valid",
        )

    def test_created_at_is_checked_but_never_compared(self):
        """It has no bound semantics — only representability (§6.2)."""
        assert temporal_validity({"created_at": NOW + 10**6}, NOW) == (True, None)
        assert temporal_validity({"created_at": -1}, NOW) == (
            False, "malformed:created_at",
        )
