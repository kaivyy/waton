"""Python WhatsApp Web Multi-Device library."""

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
        from .core.errors import ConnectionError, DisconnectReason, WatonError

        return {
            "WatonError": WatonError,
            "ConnectionError": ConnectionError,
            "DisconnectReason": DisconnectReason,
        }[name]

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
