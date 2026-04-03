from datetime import UTC, datetime

import pytest

from pydentity.shared_kernel import (
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

# --- String guards ---


class TestGuardNotEmpty:
    def test_passes_with_value(self):
        guard_not_empty("hello")

    def test_raises_on_empty_string(self):
        with pytest.raises(ValueError):
            guard_not_empty("")


class TestGuardNotBlank:
    def test_passes_with_content(self):
        guard_not_blank("hello")

    def test_raises_on_whitespace_only(self):
        with pytest.raises(ValueError):
            guard_not_blank("   ")

    def test_raises_on_empty_string(self):
        with pytest.raises(ValueError):
            guard_not_blank("")


class TestGuardWithinMaxLength:
    def test_passes_at_boundary(self):
        guard_within_max_length("abc", 3)

    def test_raises_over_boundary(self):
        with pytest.raises(ValueError):
            guard_within_max_length("abcd", 3)


# --- Numeric guards ---


class TestGuardNotNegative:
    def test_passes_on_zero(self):
        guard_not_negative(0)

    def test_raises_on_negative(self):
        with pytest.raises(ValueError):
            guard_not_negative(-1)


class TestGuardPositive:
    def test_passes_on_one(self):
        guard_positive(1)

    def test_raises_on_zero(self):
        with pytest.raises(ValueError):
            guard_positive(0)

    def test_raises_on_negative(self):
        with pytest.raises(ValueError):
            guard_positive(-1)


class TestGuardWithinMax:
    def test_passes_at_boundary(self):
        guard_within_max(10, 10)

    def test_raises_over_boundary(self):
        with pytest.raises(ValueError):
            guard_within_max(11, 10)


class TestGuardWithinMin:
    def test_passes_at_boundary(self):
        guard_within_min(5, 5)

    def test_raises_under_boundary(self):
        with pytest.raises(ValueError):
            guard_within_min(4, 5)


class TestGuardWithinRange:
    def test_passes_at_lower_boundary(self):
        guard_within_range(1, 1, 10)

    def test_passes_at_upper_boundary(self):
        guard_within_range(10, 1, 10)

    def test_raises_below_lower(self):
        with pytest.raises(ValueError):
            guard_within_range(0, 1, 10)

    def test_raises_above_upper(self):
        with pytest.raises(ValueError):
            guard_within_range(11, 1, 10)


# --- Collection guards ---


class TestGuardNotEmptyCollection:
    def test_passes_with_elements(self):
        guard_not_empty_collection([1, 2])

    def test_raises_on_empty(self):
        with pytest.raises(ValueError):
            guard_not_empty_collection([])


class TestGuardWithinMaxSize:
    def test_passes_at_boundary(self):
        guard_within_max_size([1, 2, 3], 3)

    def test_raises_over_boundary(self):
        with pytest.raises(ValueError):
            guard_within_max_size([1, 2, 3, 4], 3)


class TestGuardNoDuplicates:
    def test_passes_without_duplicates(self):
        guard_no_duplicates([1, 2, 3])

    def test_raises_with_duplicates(self):
        with pytest.raises(ValueError):
            guard_no_duplicates([1, 2, 2])


class TestGuardAllPositive:
    def test_passes_with_positive_values(self):
        guard_all_positive([1, 2, 3])

    def test_raises_with_zero(self):
        with pytest.raises(ValueError):
            guard_all_positive([1, 0, 3])

    def test_raises_with_negative(self):
        with pytest.raises(ValueError):
            guard_all_positive([1, -1, 3])


class TestGuardAllWithinMax:
    def test_passes_at_boundary(self):
        guard_all_within_max([5, 10], 10)

    def test_raises_over_boundary(self):
        with pytest.raises(ValueError):
            guard_all_within_max([5, 11], 10)


# --- Temporal guards ---


class TestGuardBefore:
    def test_passes_when_start_before_end(self):
        start = datetime(2026, 1, 1, tzinfo=UTC)
        end = datetime(2026, 1, 2, tzinfo=UTC)
        guard_before(start, end)

    def test_raises_when_start_equals_end(self):
        same = datetime(2026, 1, 1, tzinfo=UTC)
        with pytest.raises(ValueError):
            guard_before(same, same)

    def test_raises_when_start_after_end(self):
        start = datetime(2026, 1, 2, tzinfo=UTC)
        end = datetime(2026, 1, 1, tzinfo=UTC)
        with pytest.raises(ValueError):
            guard_before(start, end)


# --- Comparison guards ---


class TestGuardMinNotGreaterThanMax:
    def test_passes_when_equal(self):
        guard_min_not_greater_than_max(5, 5)

    def test_passes_when_min_less_than_max(self):
        guard_min_not_greater_than_max(3, 5)

    def test_raises_when_min_exceeds_max(self):
        with pytest.raises(ValueError):
            guard_min_not_greater_than_max(6, 5)
