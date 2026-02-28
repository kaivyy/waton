from __future__ import annotations

__all__ = ["create_app"]


def create_app(*args, **kwargs):
    from .server import create_app as _create_app

    return _create_app(*args, **kwargs)
