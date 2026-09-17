"""Small in-memory event buffer with replay support."""

from __future__ import annotations

import contextlib
from collections import deque
from dataclasses import dataclass, field
from time import time
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass
class BufferedEvent:
    event: str
    payload: Any
    timestamp: float


class IncomingNodeBuffer:
    def __init__(self, max_events: int = 1000) -> None:
        self._events: deque[BufferedEvent] = deque(maxlen=max_events)

    def push(self, event: str, payload: Any) -> None:
        self._events.append(BufferedEvent(event=event, payload=payload, timestamp=time()))

    def recent(self, event: str | None = None) -> list[BufferedEvent]:
        if event is None:
            return list(self._events)
        return [e for e in self._events if e.event == event]

    def __iter__(self) -> Iterator[BufferedEvent]:
        return iter(self._events)


BUFFERABLE_EVENTS = {
    "messaging-history.set",
    "chats.upsert",
    "chats.update",
    "chats.delete",
    "contacts.upsert",
    "contacts.update",
    "messages.upsert",
    "messages.update",
    "messages.delete",
    "messages.reaction",
    "messages.revoke",
    "messages.edit",
    "message-receipt.update",
    "groups.update",
}



@dataclass
class BufferedEventData:
    history_sets: dict[str, Any] = field(default_factory=lambda: {
        "chats": {}, "messages": {}, "contacts": {},
        "is_latest": False, "empty": True
    })
    chat_upserts: dict[str, Any] = field(default_factory=dict)
    chat_updates: dict[str, Any] = field(default_factory=dict)
    chat_deletes: set[str] = field(default_factory=set)
    contact_upserts: dict[str, Any] = field(default_factory=dict)
    contact_updates: dict[str, Any] = field(default_factory=dict)
    message_upserts: dict[str, Any] = field(default_factory=dict)
    message_updates: dict[str, Any] = field(default_factory=dict)
    message_reactions: dict[str, Any] = field(default_factory=dict)
    message_deletes: dict[str, Any] = field(default_factory=dict)
    message_receipts: dict[str, Any] = field(default_factory=dict)
    group_updates: dict[str, Any] = field(default_factory=dict)


def stringify_message_key(key: dict[str, Any] | Any) -> str:
    if not key:
        return ""
    if isinstance(key, dict):
        remote_jid = key.get("remoteJid", key.get("remote_jid", "")) or ""
        id_ = key.get("id", "") or ""
        from_me = "1" if key.get("fromMe", key.get("from_me", False)) else "0"
        return f"{remote_jid},{id_},{from_me}"
    else:
        remote_jid = getattr(key, "remoteJid", getattr(key, "remote_jid", "")) or ""
        id_ = getattr(key, "id", "") or ""
        from_me = "1" if getattr(key, "fromMe", getattr(key, "from_me", False)) else "0"
        return f"{remote_jid},{id_},{from_me}"



class EventBuffer:
    def __init__(self, emit_callback: Callable[[str, Any], None] | None = None) -> None:
        self.emit_callback = emit_callback or (lambda *args: None)
        self._is_buffering = False
        self._buffer_count = 0
        self._data = BufferedEventData()
        self._history_cache: set[str] = set()

    @property
    def is_buffering(self) -> bool:
        return self._is_buffering

    @contextlib.contextmanager
    def buffer(self) -> Iterator[None]:
        was_buffering = self._is_buffering
        self._is_buffering = True
        self._buffer_count += 1
        try:
            yield
        finally:
            self._buffer_count -= 1
            if self._buffer_count == 0 and not was_buffering:
                self.flush()

    def process(self, event_name: str, data: Any) -> bool:
        if event_name == "messages.upsert":
            # If type mismatch, flush existing buffered upserts
            upserts = list(self._data.message_upserts.values())
            if upserts:
                buffered_type = upserts[0].get("type")
                incoming_type = data.get("type") if isinstance(data, dict) else getattr(data, "type", None)
                if buffered_type != incoming_type:
                    self.emit_callback("messages.upsert", {
                        "messages": [m["message"] for m in upserts],
                        "type": buffered_type
                    })
                    self._data.message_upserts.clear()

        if self._is_buffering and event_name in BUFFERABLE_EVENTS:
            self._append(event_name, data)
            return True

        self.emit_callback(event_name, data)
        return False

    def flush(self) -> bool:
        if not self._is_buffering:
            return False

        self._is_buffering = False
        self._buffer_count = 0

        new_data = BufferedEventData()
        chat_updates = list(self._data.chat_updates.values())
        
        for update in chat_updates:
            cond = update.get("conditional") if isinstance(update, dict) else getattr(update, "conditional", None)
            if cond is not None:
                chat_id = update.get("id") if isinstance(update, dict) else update.id
                if isinstance(new_data.chat_updates, dict):
                    new_data.chat_updates[chat_id] = update
                if isinstance(update, dict):
                    self._data.chat_updates.pop(chat_id, None)
                else:
                    self._data.chat_updates.pop(chat_id, None)

        consolidated = self._consolidate_events()
        for event_name, event_data in consolidated.items():
            self.emit_callback(event_name, event_data)

        self._data = new_data
        return True

    def _append(self, event_name: str, data: Any) -> None:
        if event_name == "messaging-history.set":
            pass # TODO history
        elif event_name == "chats.upsert":
            chats = data if isinstance(data, list) else [data]
            for chat in chats:
                chat_id = chat.get("id", "") if isinstance(chat, dict) else chat.id
                upsert = self._data.chat_upserts.get(chat_id)
                if chat_id and not upsert:
                    upsert = self._data.history_sets["chats"].get(chat_id)
                
                if upsert:
                    self._concat_chats(upsert, chat)
                else:
                    upsert = chat
                    self._data.chat_upserts[chat_id] = upsert
                
                self._absorbing_chat_update(upsert)
                if chat_id in self._data.chat_deletes:
                    self._data.chat_deletes.remove(chat_id)

        elif event_name == "chats.update":
            updates = data if isinstance(data, list) else [data]
            for update in updates:
                chat_id = update.get("id") if isinstance(update, dict) else update.id
                cond = update.get("conditional") if isinstance(update, dict) else getattr(update, "conditional", None)
                matches = cond(self._data) if callable(cond) else True
                
                if matches:
                    if isinstance(update, dict) and "conditional" in update:
                        del update["conditional"]
                    elif hasattr(update, "conditional"):
                        delattr(update, "conditional")
                    
                    upsert = self._data.history_sets["chats"].get(chat_id) or self._data.chat_upserts.get(chat_id)
                    if upsert:
                        self._concat_chats(upsert, update)
                    else:
                        existing_update = self._data.chat_updates.get(chat_id, {})
                        self._data.chat_updates[chat_id] = self._concat_chats(existing_update, update)
                elif matches is None:
                    self._data.chat_updates[chat_id] = update
                
                if chat_id in self._data.chat_deletes:
                    self._data.chat_deletes.remove(chat_id)

        elif event_name == "chats.delete":
            chat_ids = data if isinstance(data, list) else [data]
            for chat_id in chat_ids:
                self._data.chat_deletes.add(chat_id)
                self._data.chat_updates.pop(chat_id, None)
                self._data.chat_upserts.pop(chat_id, None)
                self._data.history_sets["chats"].pop(chat_id, None)

        elif event_name == "messages.upsert":
            if isinstance(data, dict):
                if "messages" in data:
                    messages = data["messages"]
                elif "message" in data:
                    messages = [data["message"]]
                else:
                    messages = []
            else:
                messages = getattr(data, "messages", [getattr(data, "message", data)])
            msg_type = data.get("type") if isinstance(data, dict) else getattr(data, "type", None)
            
            for message in messages:
                key = message.get("key") if isinstance(message, dict) else getattr(message, "key", None)
                if not key and isinstance(message, dict) and message.get("id"):
                    key = {"remoteJid": message.get("from"), "id": message.get("id"), "fromMe": False}
                key_str = stringify_message_key(key)

                existing = self._data.message_upserts.get(key_str, {}).get("message")
                
                if not existing:
                    existing = self._data.history_sets["messages"].get(key_str)
                
                if existing:
                    # sync timestamp
                    ts = existing.get("messageTimestamp") if isinstance(existing, dict) else getattr(existing, "messageTimestamp", None)
                    if isinstance(message, dict):
                        message["messageTimestamp"] = ts
                    else:
                        setattr(message, "messageTimestamp", ts)
                
                if key_str in self._data.message_updates:
                    upd = self._data.message_updates.pop(key_str).get("update", {})
                    if isinstance(message, dict) and isinstance(upd, dict):
                        message.update(upd)
                    elif hasattr(message, "__dict__") and isinstance(upd, dict):
                        message.__dict__.update(upd)
                
                if key_str in self._data.history_sets["messages"]:
                    self._data.history_sets["messages"][key_str] = message
                else:
                    curr_type = self._data.message_upserts.get(key_str, {}).get("type")
                    self._data.message_upserts[key_str] = {
                        "message": message,
                        "type": "notify" if msg_type == "notify" or curr_type == "notify" else msg_type
                    }

        elif event_name == "messages.update":
            msg_updates = data if isinstance(data, list) else getattr(data, "updates", data)
            for item in msg_updates:
                key = item.get("key") if isinstance(item, dict) else getattr(item, "key")
                update = item.get("update") if isinstance(item, dict) else getattr(item, "update")
                key_str = stringify_message_key(key)
                
                existing = self._data.history_sets["messages"].get(key_str) or self._data.message_upserts.get(key_str, {}).get("message")
                if existing:
                    if isinstance(existing, dict) and isinstance(update, dict):
                        existing.update(update)
                    elif hasattr(existing, "__dict__") and isinstance(update, dict):
                        existing.__dict__.update(update)
                    
                    status = update.get("status") if isinstance(update, dict) else getattr(update, "status", None)
                    from_me = key.get("fromMe") if isinstance(key, dict) else getattr(key, "fromMe", getattr(key, "from_me", False))
                    
                    if status == "READ" and not from_me:
                        self._decrement_chat_read_counter(existing)
                else:
                    msg_update = self._data.message_updates.setdefault(key_str, {"key": key, "update": {}})
                    if isinstance(msg_update["update"], dict) and isinstance(update, dict):
                        msg_update["update"].update(update)

        elif event_name == "messages.delete":
            if isinstance(data, dict) and "keys" in data:
                keys = data["keys"]
                for key in keys:
                    key_str = stringify_message_key(key)
                    if key_str not in self._data.message_deletes:
                        self._data.message_deletes[key_str] = key
                    self._data.message_upserts.pop(key_str, None)
                    self._data.message_updates.pop(key_str, None)
            elif hasattr(data, "keys"):
                for key in getattr(data, "keys"):
                    key_str = stringify_message_key(key)
                    if key_str not in self._data.message_deletes:
                        self._data.message_deletes[key_str] = key
                    self._data.message_upserts.pop(key_str, None)
                    self._data.message_updates.pop(key_str, None)

        elif event_name == "messages.reaction":
            reactions = data if isinstance(data, list) else [data]
            for item in reactions:
                key = item.get("key") if isinstance(item, dict) else getattr(item, "key")
                reaction = item.get("reaction") if isinstance(item, dict) else getattr(item, "reaction")
                key_str = stringify_message_key(key)
                
                existing = self._data.message_upserts.get(key_str)
                if existing:
                    self._update_message_with_reaction(existing["message"], reaction)
                else:
                    if key_str not in self._data.message_reactions:
                        self._data.message_reactions[key_str] = {"key": key, "reactions": []}
                    self._update_message_with_reaction(self._data.message_reactions[key_str], reaction)
                    
        elif event_name == "message-receipt.update":
            receipts = data if isinstance(data, list) else [data]
            for item in receipts:
                key = item.get("key") if isinstance(item, dict) else getattr(item, "key")
                receipt = item.get("receipt") if isinstance(item, dict) else getattr(item, "receipt")
                key_str = stringify_message_key(key)
                
                existing = self._data.message_upserts.get(key_str)
                if existing:
                    self._update_message_with_receipt(existing["message"], receipt)
                else:
                    if key_str not in self._data.message_receipts:
                        self._data.message_receipts[key_str] = {"key": key, "userReceipt": []}
                    self._update_message_with_receipt(self._data.message_receipts[key_str], receipt)

        elif event_name == "contacts.upsert":
            contacts = data if isinstance(data, list) else [data]
            for contact in contacts:
                c_id = contact.get("id") if isinstance(contact, dict) else contact.id
                upsert = self._data.contact_upserts.get(c_id)
                if not upsert:
                    upsert = self._data.history_sets["contacts"].get(c_id)
                
                if upsert:
                    if isinstance(upsert, dict) and isinstance(contact, dict):
                        upsert.update({k: v for k, v in contact.items() if v is not None})
                    elif hasattr(upsert, "__dict__") and hasattr(contact, "__dict__"):
                        for k, v in contact.__dict__.items():
                            if v is not None:
                                setattr(upsert, k, v)
                else:
                    upsert = contact
                    self._data.contact_upserts[c_id] = upsert
                
                if c_id in self._data.contact_updates:
                    upd = self._data.contact_updates.pop(c_id)
                    if isinstance(upsert, dict) and isinstance(upd, dict):
                        upsert.update({k: v for k, v in upd.items() if v is not None})
                    elif hasattr(upsert, "__dict__") and hasattr(upd, "__dict__"):
                        for k, v in upd.__dict__.items():
                            if v is not None:
                                setattr(upsert, k, v)

        elif event_name == "contacts.update":
            updates = data if isinstance(data, list) else [data]
            for update in updates:
                c_id = update.get("id") if isinstance(update, dict) else update.id
                upsert = self._data.history_sets["contacts"].get(c_id) or self._data.contact_upserts.get(c_id)
                if upsert:
                    if isinstance(upsert, dict) and isinstance(update, dict):
                        upsert.update(update)
                    elif hasattr(upsert, "__dict__") and isinstance(update, dict):
                        upsert.__dict__.update(update)
                else:
                    existing = self._data.contact_updates.setdefault(c_id, {})
                    if isinstance(existing, dict) and isinstance(update, dict):
                        existing.update(update)

        elif event_name == "groups.update":
            updates = data if isinstance(data, list) else [data]
            for update in updates:
                g_id = update.get("id") if isinstance(update, dict) else update.id
                existing = self._data.group_updates.setdefault(g_id, {})
                if isinstance(existing, dict) and isinstance(update, dict):
                    existing.update(update)

    def _update_message_with_reaction(self, msg: Any, reaction: Any) -> None:
        if isinstance(msg, dict):
            reactions = msg.setdefault("reactions", [])
            reactions.append(reaction)
        else:
            if not hasattr(msg, "reactions"):
                setattr(msg, "reactions", [])
            msg.reactions.append(reaction)
            
    def _update_message_with_receipt(self, msg: Any, receipt: Any) -> None:
        if isinstance(msg, dict):
            receipts = msg.setdefault("userReceipt", [])
            receipts.append(receipt)
        else:
            if not hasattr(msg, "userReceipt"):
                setattr(msg, "userReceipt", [])
            msg.userReceipt.append(receipt)

    def _decrement_chat_read_counter(self, message: Any) -> None:
        key = message.get("key") if isinstance(message, dict) else getattr(message, "key")
        chat_id = key.get("remoteJid") if isinstance(key, dict) else getattr(key, "remoteJid", getattr(key, "remote_jid", ""))
        chat = self._data.chat_updates.get(chat_id) or self._data.chat_upserts.get(chat_id)
        if chat:
            unread = chat.get("unreadCount") if isinstance(chat, dict) else getattr(chat, "unreadCount", getattr(chat, "unread_count", None))
            if isinstance(unread, int) and unread > 0:
                if isinstance(chat, dict):
                    chat["unreadCount"] -= 1
                    if chat["unreadCount"] == 0:
                        chat.pop("unreadCount")
                else:
                    if hasattr(chat, "unreadCount"):
                        chat.unreadCount -= 1
                        if chat.unreadCount == 0:
                            delattr(chat, "unreadCount")
                    elif hasattr(chat, "unread_count"):
                        chat.unread_count -= 1
                        if chat.unread_count == 0:
                            delattr(chat, "unread_count")

    def _concat_chats(self, a: Any, b: Any) -> Any:
        a_unread = a.get("unreadCount") if isinstance(a, dict) else getattr(a, "unreadCount", getattr(a, "unread_count", None))
        b_unread = b.get("unreadCount") if isinstance(b, dict) else getattr(b, "unreadCount", getattr(b, "unread_count", None))
        
        if b_unread is None and isinstance(a_unread, int) and a_unread < 0:
            if isinstance(a, dict):
                a.pop("unreadCount", None)
            else:
                if hasattr(a, "unreadCount"): delattr(a, "unreadCount")
                if hasattr(a, "unread_count"): delattr(a, "unread_count")
        
        if isinstance(a_unread, int) and isinstance(b_unread, int):
            if b_unread >= 0:
                new_unread = max(b_unread, 0) + max(a_unread, 0)
                if isinstance(b, dict):
                    b["unreadCount"] = new_unread
                else:
                    if hasattr(b, "unreadCount"): b.unreadCount = new_unread
                    elif hasattr(b, "unread_count"): b.unread_count = new_unread

        if isinstance(a, dict) and isinstance(b, dict):
            a.update(b)
            return a
        elif hasattr(a, "__dict__") and hasattr(b, "__dict__"):
            for k, v in b.__dict__.items():
                setattr(a, k, v)
            return a
        elif hasattr(a, "__dict__") and isinstance(b, dict):
            for k, v in b.items():
                setattr(a, k, v)
            return a
        return a

    def _absorbing_chat_update(self, existing: Any) -> None:
        chat_id = existing.get("id", "") if isinstance(existing, dict) else existing.id
        update = self._data.chat_updates.get(chat_id)
        if update:
            cond = update.get("conditional") if isinstance(update, dict) else getattr(update, "conditional", None)
            matches = cond(self._data) if callable(cond) else True
            
            if matches:
                if isinstance(update, dict) and "conditional" in update:
                    del update["conditional"]
                elif hasattr(update, "conditional"):
                    delattr(update, "conditional")
                
                self._concat_chats(existing, update)
                self._data.chat_updates.pop(chat_id, None)
            elif matches is False:
                self._data.chat_updates.pop(chat_id, None)

    def _consolidate_events(self) -> dict[str, Any]:
        map_out: dict[str, Any] = {}
        
        if not self._data.history_sets["empty"]:
            map_out["messaging-history.set"] = {
                "chats": list(self._data.history_sets["chats"].values()),
                "messages": list(self._data.history_sets["messages"].values()),
                "contacts": list(self._data.history_sets["contacts"].values()),
            }
        
        if self._data.chat_upserts:
            map_out["chats.upsert"] = list(self._data.chat_upserts.values())
            
        if self._data.chat_updates:
            map_out["chats.update"] = list(self._data.chat_updates.values())
            
        if self._data.chat_deletes:
            map_out["chats.delete"] = list(self._data.chat_deletes)
            
        if self._data.message_upserts:
            upserts = list(self._data.message_upserts.values())
            msg_type = upserts[0].get("type")
            map_out["messages.upsert"] = {
                "messages": [m["message"] for m in upserts],
                "type": msg_type
            }
            
        if self._data.message_updates:
            map_out["messages.update"] = list(self._data.message_updates.values())
            
        if self._data.message_deletes:
            map_out["messages.delete"] = {"keys": list(self._data.message_deletes.values())}
            
        if self._data.message_reactions:
            reactions = []
            for d in self._data.message_reactions.values():
                key = d["key"]
                for r in d["reactions"]:
                    reactions.append({"key": key, "reaction": r})
            if reactions:
                map_out["messages.reaction"] = reactions
                
        if self._data.message_receipts:
            receipts = []
            for d in self._data.message_receipts.values():
                key = d["key"]
                for r in d["userReceipt"]:
                    receipts.append({"key": key, "receipt": r})
            if receipts:
                map_out["message-receipt.update"] = receipts
                
        if self._data.contact_upserts:
            map_out["contacts.upsert"] = list(self._data.contact_upserts.values())
            
        if self._data.contact_updates:
            map_out["contacts.update"] = list(self._data.contact_updates.values())
            
        if self._data.group_updates:
            map_out["groups.update"] = list(self._data.group_updates.values())
            
        return map_out
