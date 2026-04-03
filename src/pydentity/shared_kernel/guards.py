from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime


# --- String guards ---


def guard_not_empty(value: str) -> None:
    if not value:
        raise ValueError("Value must not be empty.")


def guard_not_blank(value: str) -> None:
    if not value or not value.strip():
        raise ValueError("Value must not be blank.")


def guard_within_max_length(value: str, max_length: int) -> None:
    if len(value) > max_length:
        raise ValueError(f"Value must not exceed {max_length} characters.")


# --- Numeric guards ---


def guard_not_negative(value: int) -> None:
    if value < 0:
        raise ValueError("Value cannot be negative.")


def guard_positive(value: int) -> None:
    if value <= 0:
        raise ValueError("Value must be positive.")


def guard_within_max(value: int, max_value: int) -> None:
    if value > max_value:
        raise ValueError(f"Value cannot exceed {max_value}.")


def guard_within_min(value: int, min_value: int) -> None:
    if value < min_value:
        raise ValueError(f"Value cannot be less than {min_value}.")


def guard_within_range(value: int, min_value: int, max_value: int) -> None:
    if value < min_value or value > max_value:
        raise ValueError(f"Value must be between {min_value} and {max_value}.")


# --- Collection guards ---


def guard_not_empty_collection[T](value: Sequence[T]) -> None:
    if not value:
        raise ValueError("Collection must not be empty.")


def guard_within_max_size[T](value: Sequence[T], max_size: int) -> None:
    if len(value) > max_size:
        raise ValueError(f"Collection cannot exceed {max_size} entries.")


def guard_no_duplicates[T](value: Sequence[T]) -> None:
    if len(value) != len(set(value)):
        raise ValueError("Collection must not contain duplicates.")


def guard_all_positive(value: Sequence[int]) -> None:
    for element in value:
        if element <= 0:
            raise ValueError("Each element must be positive.")


def guard_all_within_max(value: Sequence[int], max_value: int) -> None:
    for element in value:
        if element > max_value:
            raise ValueError(f"Each element cannot exceed {max_value}.")


# --- Temporal guards ---


def guard_before(start: datetime, end: datetime) -> None:
    if start >= end:
        raise ValueError("Start must be before end.")


# --- Comparison guards ---


def guard_min_not_greater_than_max(min_value: int, max_value: int) -> None:
    if min_value > max_value:
        raise ValueError("Minimum cannot exceed maximum.")
