from datetime import datetime, timezone

import pytest

from pydentity.shared_kernel.guards import (
    guard_all_positive,
    guard_all_within_max,
    guard_before,
    guard_min_not_greater_than_max,
    guard_no_duplicates,
    guard_not_blank,
    guard_not_empty,
    guard_not_empty_collection,
    guard_not_negative,
    guard_positive,
    guard_within_max,
    guard_within_max_length,
    guard_within_max_size,
    guard_within_min,
    guard_within_range,
)


# ── String guards ──


class TestGuardNotEmpty:
    def test_accepts_non_empty(self):
        guard_not_empty("hello")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            guard_not_empty("")


class TestGuardNotBlank:
    def test_accepts_non_blank(self):
        guard_not_blank("hello")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be blank"):
            guard_not_blank("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(ValueError, match="must not be blank"):
            guard_not_blank("   ")


class TestGuardWithinMaxLength:
    def test_accepts_within_limit(self):
        guard_within_max_length("abc", 5)

    def test_accepts_at_limit(self):
        guard_within_max_length("abcde", 5)

    def test_rejects_over_limit(self):
        with pytest.raises(ValueError, match="must not exceed 5 characters"):
            guard_within_max_length("abcdef", 5)


# ── Numeric guards ──


class TestGuardNotNegative:
    def test_accepts_zero(self):
        guard_not_negative(0)

    def test_accepts_positive(self):
        guard_not_negative(5)

    def test_rejects_negative(self):
        with pytest.raises(ValueError, match="cannot be negative"):
            guard_not_negative(-1)


class TestGuardPositive:
    def test_accepts_positive(self):
        guard_positive(1)

    def test_rejects_zero(self):
        with pytest.raises(ValueError, match="must be positive"):
            guard_positive(0)

    def test_rejects_negative(self):
        with pytest.raises(ValueError, match="must be positive"):
            guard_positive(-1)


class TestGuardWithinMax:
    def test_accepts_under_max(self):
        guard_within_max(5, 10)

    def test_accepts_at_max(self):
        guard_within_max(10, 10)

    def test_rejects_over_max(self):
        with pytest.raises(ValueError, match="cannot exceed 10"):
            guard_within_max(11, 10)


class TestGuardWithinMin:
    def test_accepts_above_min(self):
        guard_within_min(5, 1)

    def test_accepts_at_min(self):
        guard_within_min(1, 1)

    def test_rejects_under_min(self):
        with pytest.raises(ValueError, match="cannot be less than 5"):
            guard_within_min(3, 5)


class TestGuardWithinRange:
    def test_accepts_within(self):
        guard_within_range(5, 1, 10)

    def test_accepts_at_boundaries(self):
        guard_within_range(1, 1, 10)
        guard_within_range(10, 1, 10)

    def test_rejects_below(self):
        with pytest.raises(ValueError, match="must be between 1 and 10"):
            guard_within_range(0, 1, 10)

    def test_rejects_above(self):
        with pytest.raises(ValueError, match="must be between 1 and 10"):
            guard_within_range(11, 1, 10)


# ── Collection guards ──


class TestGuardNotEmptyCollection:
    def test_accepts_non_empty(self):
        guard_not_empty_collection([1, 2])

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            guard_not_empty_collection([])


class TestGuardWithinMaxSize:
    def test_accepts_within(self):
        guard_within_max_size([1, 2], 3)

    def test_accepts_at_limit(self):
        guard_within_max_size([1, 2, 3], 3)

    def test_rejects_over(self):
        with pytest.raises(ValueError, match="cannot exceed 3"):
            guard_within_max_size([1, 2, 3, 4], 3)


class TestGuardNoDuplicates:
    def test_accepts_unique(self):
        guard_no_duplicates([1, 2, 3])

    def test_rejects_duplicates(self):
        with pytest.raises(ValueError, match="must not contain duplicates"):
            guard_no_duplicates([1, 2, 2])


class TestGuardAllPositive:
    def test_accepts_all_positive(self):
        guard_all_positive([1, 2, 3])

    def test_rejects_zero(self):
        with pytest.raises(ValueError, match="must be positive"):
            guard_all_positive([1, 0, 3])

    def test_rejects_negative(self):
        with pytest.raises(ValueError, match="must be positive"):
            guard_all_positive([1, -1, 3])


class TestGuardAllWithinMax:
    def test_accepts_all_within(self):
        guard_all_within_max([1, 5, 10], 10)

    def test_rejects_over(self):
        with pytest.raises(ValueError, match="cannot exceed 10"):
            guard_all_within_max([1, 11, 5], 10)


# ── Temporal guards ──


class TestGuardBefore:
    def test_accepts_start_before_end(self):
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        guard_before(start, end)

    def test_rejects_equal(self):
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(ValueError, match="must be before"):
            guard_before(now, now)

    def test_rejects_start_after_end(self):
        start = datetime(2024, 1, 2, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with pytest.raises(ValueError, match="must be before"):
            guard_before(start, end)


# ── Comparison guards ──


class TestGuardMinNotGreaterThanMax:
    def test_accepts_min_less_than_max(self):
        guard_min_not_greater_than_max(1, 10)

    def test_accepts_equal(self):
        guard_min_not_greater_than_max(5, 5)

    def test_rejects_min_greater(self):
        with pytest.raises(ValueError, match="cannot exceed maximum"):
            guard_min_not_greater_than_max(10, 1)
