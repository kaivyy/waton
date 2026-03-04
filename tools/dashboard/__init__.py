from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flask import Flask

__all__ = ["create_app"]


def create_app(*args: Any, **kwargs: Any) -> Flask:
    from .server import create_app as _create_app

    return _create_app(*args, **kwargs)
