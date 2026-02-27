"""Generic utility helpers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeVar

T = TypeVar("T")


def first_or_none(values: Iterable[T]) -> T | None:
    for item in values:
        return item
    return None


def chunked(values: list[T], size: int) -> list[list[T]]:
    if size <= 0:
        raise ValueError("size must be > 0")
    return [values[i : i + size] for i in range(0, len(values), size)]


def ensure_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")
