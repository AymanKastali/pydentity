from __future__ import annotations

import types
from typing import Any, Union, get_args, get_origin

from pydentity.domain.exceptions import InvalidTypeError


def verify_types(**fields: tuple[Any, type | types.UnionType]) -> None:
    """Verify that each value matches its expected type at runtime.

    Usage::

        verify_types(
            user_id=(user_id, UserId),
            email=(email, EmailAddress),
            token=(token, EmailVerificationToken | None),
        )
    """
    for field_name, (value, expected) in fields.items():
        if not _check(value, expected):
            _raise(field_name, expected, value)


def _check(value: Any, expected: type | types.UnionType) -> bool:
    # X | Y  (PEP 604 union at runtime)
    if isinstance(expected, types.UnionType):
        return any(_check(value, arg) for arg in get_args(expected))

    origin = get_origin(expected)

    # typing.Union (fallback)
    if origin is Union:
        return any(_check(value, arg) for arg in get_args(expected))

    # set[X], frozenset[X], list[X]
    if origin in (set, frozenset, list):
        if not isinstance(value, origin):
            return False
        args = get_args(expected)
        if args:
            return all(_check(elem, args[0]) for elem in value)
        return True

    # tuple[X, ...] or tuple[X, Y]
    if origin is tuple:
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

    # Plain type
    return isinstance(value, expected)


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
