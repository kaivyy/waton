from dataclasses import dataclass
from typing import Optional

S_WHATSAPP_NET = "s.whatsapp.net"
S_WHATSAPP_NET_LID = "lid"
S_WHATSAPP_NET_GROUP = "g.us"
S_WHATSAPP_NET_BROADCAST = "broadcast"


@dataclass
class Jid:
    user: str
    server: str
    device: Optional[int] = None

    def __str__(self) -> str:
        return jid_encode(self.user, self.server, self.device)


def jid_decode(jid_str: str | None) -> Optional[Jid]:
    """Decodes a JID string into its parts."""
    if not jid_str:
        return None

    parts = jid_str.split("@", 1)
    if len(parts) == 1:
        return Jid(user="", server=parts[0])

    user_device = parts[0].split(":", 1)
    user = user_device[0]
    device = int(user_device[1]) if len(user_device) > 1 and user_device[1].isdigit() else None
    
    return Jid(user=user, server=parts[1], device=device)


def jid_encode(user: str, server: str, device: Optional[int] = None) -> str:
    """Encodes a JID from its parts."""
    base = f"{user}@{server}" if user else server
    if device is not None:
        base = f"{user}:{device}@{server}"
    return base


def jid_normalized_user(jid_str: str) -> str:
    """Gets the normalized user ID (without device info)."""
    decoded = jid_decode(jid_str)
    if not decoded:
        return ""
    return jid_encode(decoded.user, decoded.server)


def is_jid_user(jid_str: str) -> bool:
    """Checks if a JID is a standard user."""
    return jid_str.endswith(f"@{S_WHATSAPP_NET}")


def is_lid_user(jid_str: str) -> bool:
    """Checks if a JID is a LID (Linked Identity Device) user."""
    return jid_str.endswith(f"@{S_WHATSAPP_NET_LID}")


def is_jid_group(jid_str: str) -> bool:
    """Checks if a JID is a group."""
    return jid_str.endswith(f"@{S_WHATSAPP_NET_GROUP}")


def is_jid_broadcast(jid_str: str) -> bool:
    """Checks if a JID is a status broadcast or newsletter."""
    return jid_str.endswith(f"@{S_WHATSAPP_NET_BROADCAST}")
