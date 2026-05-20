from dataclasses import dataclass

S_WHATSAPP_NET = "s.whatsapp.net"
S_WHATSAPP_NET_LID = "lid"
S_WHATSAPP_NET_GROUP = "g.us"
S_WHATSAPP_NET_BROADCAST = "broadcast"
S_WHATSAPP_NET_HOSTED = "hosted"
S_WHATSAPP_NET_HOSTED_LID = "hosted.lid"
S_WHATSAPP_NET_NEWSLETTER = "newsletter"
S_WHATSAPP_NET_BOT = "bot"
C_US = "c.us"
STORIES_JID = "status@broadcast"
META_AI_JID = "13135550002@bot"


@dataclass
class Jid:
    user: str
    server: str
    device: int | None = None
    agent: int | None = None

    def __str__(self) -> str:
        return jid_encode(self.user, self.server, self.device, self.agent)


def jid_decode(jid_str: str | None) -> Jid | None:
    """Decodes a JID string into its parts."""
    if not jid_str:
        return None

    parts = jid_str.split("@", 1)
    if len(parts) == 1:
        return Jid(user="", server=parts[0])

    user_device = parts[0].split(":", 1)
    user_agent = user_device[0]
    user_agent_parts = user_agent.rsplit("_", 1)
    if len(user_agent_parts) > 1 and user_agent_parts[1].isdigit():
        user = user_agent_parts[0]
        agent = int(user_agent_parts[1])
    else:
        user = user_agent
        agent = None
    device = int(user_device[1]) if len(user_device) > 1 and user_device[1].isdigit() else None

    return Jid(user=user, server=parts[1], device=device, agent=agent)


def jid_encode(user: str, server: str, device: int | None = None, agent: int | None = None) -> str:
    """Encodes a JID from its parts."""
    user_part = f"{user}_{agent}" if user and agent is not None else user
    base = f"{user_part}@{server}" if user_part else server
    if device is not None:
        base = f"{user_part}:{device}@{server}"
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


def is_hosted_pn_user(jid_str: str) -> bool:
    """Checks if a JID is a hosted phone-number user."""
    return jid_str.endswith(f"@{S_WHATSAPP_NET_HOSTED}")


def is_hosted_lid_user(jid_str: str) -> bool:
    """Checks if a JID is a hosted LID user."""
    return jid_str.endswith(f"@{S_WHATSAPP_NET_HOSTED_LID}")


def is_jid_group(jid_str: str) -> bool:
    """Checks if a JID is a group."""
    return jid_str.endswith(f"@{S_WHATSAPP_NET_GROUP}")


def is_jid_broadcast(jid_str: str) -> bool:
    """Checks if a JID is a status broadcast or newsletter."""
    return jid_str.endswith(f"@{S_WHATSAPP_NET_BROADCAST}")


def is_jid_status_broadcast(jid_str: str) -> bool:
    """Checks if a JID is the status broadcast."""
    return jid_str == STORIES_JID


def is_jid_newsletter(jid_str: str) -> bool:
    """Checks if a JID is a newsletter/channel."""
    return jid_str.endswith(f"@{S_WHATSAPP_NET_NEWSLETTER}")


def is_jid_meta_ai(jid_str: str) -> bool:
    """Checks if a JID uses the Meta AI bot server."""
    return jid_str.endswith(f"@{S_WHATSAPP_NET_BOT}")


def is_jid_bot(jid_str: str) -> bool:
    """Checks for Baileys-compatible PN bot JID patterns."""
    decoded = jid_decode(jid_str)
    if not decoded or decoded.server != C_US:
        return False
    user = decoded.user
    return (
        len(user) == 11
        and user.startswith("1313555")
        and user.isdigit()
    ) or (
        len(user) == 11
        and user.startswith("131655500")
        and user.isdigit()
    )
