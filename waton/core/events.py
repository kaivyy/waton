from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import dataclasses

from waton.core.entities import Chat, Contact, Message, GroupMetadata


@dataclass
class ConnectionEvent:
    status: str  # "connecting", "open", "close"
    qr: str | None = None
    reason: Any | None = None


@dataclass
class CredsUpdateEvent:
    update: dict[str, Any]


@dataclass
class MessagingHistorySetEvent:
    chats: list[Chat]
    contacts: list[Contact]
    messages: list[Message]
    lidPnMappings: list[dict[str, Any]] | None = None
    isLatest: bool | None = None
    progress: int | float | None = None
    syncType: int | None = None
    pastParticipants: list[Any] | None = None
    chunkOrder: int | None = None
    peerDataRequestSessionId: str | None = None


@dataclass
class MessagingHistoryStatusEvent:
    syncType: int
    status: str  # 'complete' | 'paused'
    explicit: bool


@dataclass
class ChatsUpsertEvent:
    chats: list[Chat]


@dataclass
class ChatsUpdateEvent:
    updates: list[dict[str, Any]]


@dataclass
class ChatsDeleteEvent:
    jids: list[str]


@dataclass
class ChatsLockEvent:
    id: str
    locked: bool


@dataclass
class LidMappingUpdateEvent:
    mapping: dict[str, Any]


@dataclass
class PresenceUpdateEvent:
    id: str
    presences: dict[str, Any]


@dataclass
class ContactsUpsertEvent:
    contacts: list[Contact]


@dataclass
class ContactsUpdateEvent:
    updates: list[dict[str, Any]]


@dataclass
class MessagesUpsertEvent:
    messages: list[Message]
    type: str  # "append" | "notify"
    requestId: str | None = None


@dataclass
class MessageUpdateEvent:
    updates: list[dict[str, Any]]


@dataclass
class MessagesDeleteEvent:
    keys: list[dict[str, Any]] | None = None
    jid: str | None = None
    all: bool | None = None


@dataclass
class MessagesMediaUpdateEvent:
    updates: list[dict[str, Any]]


@dataclass
class MessagesReactionEvent:
    reactions: list[dict[str, Any]]


@dataclass
class MessageReceiptUpdateEvent:
    receipts: list[dict[str, Any]]


@dataclass
class GroupsUpsertEvent:
    groups: list[GroupMetadata]


@dataclass
class GroupsUpdateEvent:
    updates: list[dict[str, Any]]


@dataclass
class GroupParticipantsUpdateEvent:
    id: str
    author: str
    participants: list[dict[str, Any]]
    action: str
    authorPn: str | None = None
    authorUsername: str | None = None


@dataclass
class GroupJoinRequestEvent:
    id: str
    author: str
    participant: str
    action: str
    method: str
    authorPn: str | None = None
    authorUsername: str | None = None
    participantPn: str | None = None


@dataclass
class BlocklistSetEvent:
    blocklist: list[str]


@dataclass
class BlocklistUpdateEvent:
    blocklist: list[str]
    type: str  # 'add' | 'remove'


@dataclass
class CallEvent:
    events: list[dict[str, Any]]


@dataclass
class LabelsEditEvent:
    label: dict[str, Any]


@dataclass
class LabelsAssociationEvent:
    association: dict[str, Any]
    type: str  # 'add' | 'remove'


@dataclass
class SettingsUpdateEvent:
    setting: str
    value: Any


@dataclass
class NewsletterReactionEvent:
    id: str
    server_id: str
    reaction: dict[str, Any]


@dataclass
class MessageCappingUpdateEvent:
    capping_info: dict[str, Any]


EVENT_NAMES: dict[str, type] = {
    "connection.update": ConnectionEvent,
    "creds.update": CredsUpdateEvent,
    "messaging-history.set": MessagingHistorySetEvent,
    "messaging-history.status": MessagingHistoryStatusEvent,
    "chats.upsert": ChatsUpsertEvent,
    "chats.update": ChatsUpdateEvent,
    "chats.delete": ChatsDeleteEvent,
    "chats.lock": ChatsLockEvent,
    "lid-mapping.update": LidMappingUpdateEvent,
    "presence.update": PresenceUpdateEvent,
    "contacts.upsert": ContactsUpsertEvent,
    "contacts.update": ContactsUpdateEvent,
    "messages.upsert": MessagesUpsertEvent,
    "messages.update": MessageUpdateEvent,
    "messages.delete": MessagesDeleteEvent,
    "messages.media-update": MessagesMediaUpdateEvent,
    "messages.reaction": MessagesReactionEvent,
    "message-receipt.update": MessageReceiptUpdateEvent,
    "groups.upsert": GroupsUpsertEvent,
    "groups.update": GroupsUpdateEvent,
    "group-participants.update": GroupParticipantsUpdateEvent,
    "group.join-request": GroupJoinRequestEvent,
    "blocklist.set": BlocklistSetEvent,
    "blocklist.update": BlocklistUpdateEvent,
    "call": CallEvent,
    "labels.edit": LabelsEditEvent,
    "labels.association": LabelsAssociationEvent,
    "settings.update": SettingsUpdateEvent,
    "newsletter.reaction": NewsletterReactionEvent,
    "message-capping.update": MessageCappingUpdateEvent,
}


def make_event(name: str, data: Any) -> object:
    event_cls = EVENT_NAMES.get(name)
    if not event_cls:
        return None
    
    if isinstance(data, dict):
        # Filter keys to only those defined in the dataclass
        field_names = {f.name for f in dataclasses.fields(event_cls)}
        filtered_data = {k: v for k, v in data.items() if k in field_names}
        return event_cls(**filtered_data)
    elif isinstance(data, list):
        fields = dataclasses.fields(event_cls)
        if len(fields) >= 1:
            return event_cls(**{fields[0].name: data})
    
    return event_cls(data)
