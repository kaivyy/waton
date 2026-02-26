from dataclasses import dataclass
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
