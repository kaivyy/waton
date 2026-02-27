from dataclasses import dataclass, field
from typing import Any, Optional

@dataclass
class Message:
    id: str
    from_jid: str
    participant: Optional[str] = None
    push_name: Optional[str] = None
    timestamp: int = 0
    message_type: str = ""
    text: Optional[str] = None
    media_url: Optional[str] = None
    reaction: Optional[str] = None
    reaction_target_id: Optional[str] = None
    destination_jid: Optional[str] = None
    protocol_type: Optional[str] = None
    protocol_code: Optional[int] = None
    target_message_id: Optional[str] = None
    edited_text: Optional[str] = None
    ephemeral_expiration: Optional[int] = None
    history_sync_type: Optional[int] = None
    app_state_key_ids: list[str] = field(default_factory=list)
    encrypted_reaction: Optional[dict[str, Any]] = None
    poll_update: Optional[dict[str, Any]] = None
    event_response: Optional[dict[str, Any]] = None
    content_type: Optional[str] = None
    content: dict[str, Any] = field(default_factory=dict)
    message_secret_b64: Optional[str] = None
    raw_node: Any = None

@dataclass
class Chat:
    jid: str
    name: Optional[str] = None
    unread_count: int = 0
    is_group: bool = False

@dataclass
class Contact:
    jid: str
    name: Optional[str] = None
    short_name: Optional[str] = None
    is_business: bool = False

@dataclass
class GroupMetadata:
    jid: str
    subject: str
    owner: str
    creation: int
    desc: Optional[str] = None
    participants: list[dict[str, Any]] = None
