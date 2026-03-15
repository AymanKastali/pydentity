from __future__ import annotations

import types
from typing import TYPE_CHECKING, Any, get_args, get_origin

if TYPE_CHECKING:
    from collections.abc import Iterable

from pydentity.domain.exceptions import EmptyValueError, InvalidTypeError


def verify_params(**fields: tuple[Any, type | types.UnionType]) -> None:
    """Verify type and presence of each parameter at runtime.

    - Type: checks isinstance against expected type
    - Presence: str values are stripped then checked non-empty;
      bytes values are checked non-empty
    """
    for field_name, (value, expected) in fields.items():
        if not _check(value, expected):
            _raise(field_name, expected, value)
        _check_presence(field_name, value)


def _check_presence(field_name: str, value: Any) -> None:
    if isinstance(value, str):
        if not value.strip():
            raise EmptyValueError(field_name=field_name)
    elif isinstance(value, bytes) and not value:
        raise EmptyValueError(field_name=field_name)


def _check(value: Any, expected: type | types.UnionType) -> bool:
    if isinstance(expected, types.UnionType):
        return _check_union(value, expected)

    origin = get_origin(expected)

    if origin in (set, frozenset, list):
        return _check_collection(value, expected, origin)

    if origin is tuple:
        return _check_tuple(value, expected)

    return isinstance(value, expected)


def _check_union(value: Any, expected: types.UnionType) -> bool:
    return any(_check(value, arg) for arg in get_args(expected))


def _check_collection(
    value: Any,
    expected: type,
    origin: type[Iterable[Any]],
) -> bool:
    if not isinstance(value, origin):
        return False
    args = get_args(expected)
    if args:
        return all(_check(elem, args[0]) for elem in value)
    return True


def _check_tuple(value: Any, expected: type) -> bool:
    if not isinstance(value, tuple):
        return False
    args = get_args(expected)
    if not args:
        return True
    if len(args) == 2 and args[1] is Ellipsis:
        return all(_check(elem, args[0]) for elem in value)
    if len(value) != len(args):
        return False
    return all(_check(v, t) for v, t in zip(value, args, strict=True))


def _raise(field_name: str, expected: type | types.UnionType, value: Any) -> None:
    raise InvalidTypeError(
        field_name=field_name,
        expected=_type_name(expected),
        actual=type(value).__qualname__,
    )


def _type_name(t: type | types.UnionType) -> str:
    if isinstance(t, types.UnionType):
        return " | ".join(_type_name(arg) for arg in get_args(t))
    origin = get_origin(t)
    if origin is not None:
        args = get_args(t)
        args_str = ", ".join(_type_name(a) for a in args)
        return f"{origin.__qualname__}[{args_str}]"
    return t.__qualname__
