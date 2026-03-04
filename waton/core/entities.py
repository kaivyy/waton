from dataclasses import dataclass, field
from typing import Any


def _empty_str_list() -> list[str]:
    return []


def _empty_content() -> dict[str, Any]:
    return {}


def _empty_participants() -> list[dict[str, Any]]:
    return []


@dataclass
class Message:
    id: str
    from_jid: str
    participant: str | None = None
    push_name: str | None = None
    timestamp: int = 0
    message_type: str = ""
    text: str | None = None
    media_url: str | None = None
    reaction: str | None = None
    reaction_target_id: str | None = None
    destination_jid: str | None = None
    protocol_type: str | None = None
    protocol_code: int | None = None
    target_message_id: str | None = None
    edited_text: str | None = None
    ephemeral_expiration: int | None = None
    history_sync_type: int | None = None
    app_state_key_ids: list[str] = field(default_factory=_empty_str_list)
    encrypted_reaction: dict[str, Any] | None = None
    poll_update: dict[str, Any] | None = None
    event_response: dict[str, Any] | None = None
    content_type: str | None = None
    content: dict[str, Any] = field(default_factory=_empty_content)
    message_secret_b64: str | None = None
    raw_node: Any = None

@dataclass
class Chat:
    jid: str
    name: str | None = None
    unread_count: int = 0
    is_group: bool = False

@dataclass
class Contact:
    jid: str
    name: str | None = None
    short_name: str | None = None
    is_business: bool = False

@dataclass
class GroupMetadata:
    jid: str
    subject: str
    owner: str
    creation: int
    desc: str | None = None
    participants: list[dict[str, Any]] = field(default_factory=_empty_participants)
