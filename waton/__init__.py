"""Python WhatsApp Web Multi-Device library."""

from typing import TYPE_CHECKING

from .core.errors import ConnectionError as ConnectionError  # noqa: A004

__version__ = "0.1.0"


__all__ = [
    "App",
    "Context",
    "filters",
    "Message",
    "Chat",
    "Contact",
    "GroupMetadata",
    "WatonError",
    "ConnectionError",
    "DisconnectReason",
    "Jid",
    "jid_decode",
    "jid_encode",
    "simple",
    "SimpleClient",
    "SimpleIncomingMessage",
]

if TYPE_CHECKING:
    from .app import filters
    from .app.app import App, Context
    from .core.entities import Chat, Contact, GroupMetadata, Message
    from .core.errors import DisconnectReason, WatonError
    from .core.jid import Jid, jid_decode, jid_encode
    from .simple_api import SimpleClient, SimpleIncomingMessage, simple


def __getattr__(name: str) -> object:
    """Lazy exports to avoid importing optional heavy dependencies at package import time."""
    if name in {"App", "Context"}:
        from .app.app import App, Context

        return {"App": App, "Context": Context}[name]

    if name == "filters":
        from .app import filters

        return filters

    if name in {"Message", "Chat", "Contact", "GroupMetadata"}:
        from .core.entities import Chat, Contact, GroupMetadata, Message

        return {
            "Message": Message,
            "Chat": Chat,
            "Contact": Contact,
            "GroupMetadata": GroupMetadata,
        }[name]

    if name in {"WatonError", "ConnectionError", "DisconnectReason"}:
        from .core.errors import ConnectionError as _ConnectionError
        from .core.errors import DisconnectReason, WatonError

        mapping = {
            "WatonError": WatonError,
            "ConnectionError": _ConnectionError,
            "DisconnectReason": DisconnectReason,
        }
        return mapping[name]

    if name in {"Jid", "jid_decode", "jid_encode"}:
        from .core.jid import Jid, jid_decode, jid_encode

        return {
            "Jid": Jid,
            "jid_decode": jid_decode,
            "jid_encode": jid_encode,
        }[name]

    if name in {"simple", "SimpleClient", "SimpleIncomingMessage"}:
        from .simple_api import SimpleClient, SimpleIncomingMessage, simple

        return {
            "simple": simple,
            "SimpleClient": SimpleClient,
            "SimpleIncomingMessage": SimpleIncomingMessage,
        }[name]

    raise AttributeError(f"module 'waton' has no attribute {name!r}")
