from __future__ import annotations

import zlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from waton.protocol.protobuf.wire import iter_fields


class HistorySyncState(Enum):
    AWAITING_INITIAL_SYNC = "AWAITING_INITIAL_SYNC"
    SYNCING = "SYNCING"
    ONLINE = "ONLINE"


@dataclass
class HistorySyncResult:
    chats: list[dict[str, Any]]
    contacts: list[dict[str, Any]]
    messages: list[dict[str, Any]]
    lid_pn_mappings: list[dict[str, str]]
    sync_type: int
    progress: float | None
    chunk_order: int | None


class HistorySyncProcessor:
    def __init__(self, state: HistorySyncState = HistorySyncState.AWAITING_INITIAL_SYNC) -> None:
        self.state = state

    @staticmethod
    async def download_history(notification: dict[str, Any], download_fn: Callable[..., Any]) -> bytes:
        if notification.get("initialHistBootstrapInlinePayload"):
            data = notification["initialHistBootstrapInlinePayload"]
            if isinstance(data, str):
                import base64
                data = base64.b64decode(data)
        else:
            url = notification.get("directPath") or ""
            media_key = notification.get("mediaKey")
            data = await download_fn(url, media_key, "md-msg-hist")
        
        return zlib.decompress(data)

    @staticmethod
    def process_history_message(history_sync_data: bytes) -> HistorySyncResult:
        chats = []
        contacts = []
        messages = []
        lid_pn_mappings = []
        sync_type = 0
        progress = None
        chunk_order = None

        for field_no, wire_type, value in iter_fields(history_sync_data):
            if field_no == 1 and wire_type == 0:
                sync_type = int(value)
            elif field_no == 5 and wire_type == 0:
                chunk_order = int(value)
            elif field_no == 6 and wire_type == 0:
                progress = int(value)
            elif field_no == 15 and wire_type == 2:
                # PhoneNumberToLIDMapping
                pn_jid = None
                lid_jid = None
                for m_field_no, m_wire_type, m_value in iter_fields(bytes(value)):
                    if m_field_no == 1 and m_wire_type == 2:
                        pn_jid = bytes(m_value).decode("utf-8", "ignore")
                    elif m_field_no == 2 and m_wire_type == 2:
                        lid_jid = bytes(m_value).decode("utf-8", "ignore")
                if pn_jid and lid_jid:
                    lid_pn_mappings.append({"lid": lid_jid, "pn": pn_jid})
            elif field_no == 7 and wire_type == 2:
                # Pushname
                c_id = None
                notify = None
                for c_field_no, c_wire_type, c_value in iter_fields(bytes(value)):
                    if c_field_no == 1 and c_wire_type == 2:
                        c_id = bytes(c_value).decode("utf-8", "ignore")
                    elif c_field_no == 2 and c_wire_type == 2:
                        notify = bytes(c_value).decode("utf-8", "ignore")
                if c_id:
                    contacts.append({"id": c_id, "notify": notify})
            elif field_no == 2 and wire_type == 2:
                # Conversation
                chat_id = None
                name = None
                username = None
                pn_jid = None
                lid_jid = None
                account_lid = None
                chat_messages = []
                
                for chat_field_no, chat_wire_type, chat_value in iter_fields(bytes(value)):
                    if chat_field_no == 1 and chat_wire_type == 2:
                        chat_id = bytes(chat_value).decode("utf-8", "ignore")
                    elif chat_field_no == 13 and chat_wire_type == 2:
                        name = bytes(chat_value).decode("utf-8", "ignore")
                    elif chat_field_no == 38 and chat_wire_type == 2:
                        if not name:
                            name = bytes(chat_value).decode("utf-8", "ignore")
                    elif chat_field_no == 39 and chat_wire_type == 2:
                        pn_jid = bytes(chat_value).decode("utf-8", "ignore")
                    elif chat_field_no == 42 and chat_wire_type == 2:
                        lid_jid = bytes(chat_value).decode("utf-8", "ignore")
                    elif chat_field_no == 43 and chat_wire_type == 2:
                        username = bytes(chat_value).decode("utf-8", "ignore")
                    elif chat_field_no == 49 and chat_wire_type == 2:
                        account_lid = bytes(chat_value).decode("utf-8", "ignore")
                    elif chat_field_no == 2 and chat_wire_type == 2:
                        # HistorySyncMsg
                        for msg_field_no, msg_wire_type, msg_value in iter_fields(bytes(chat_value)):
                            if msg_field_no == 1 and msg_wire_type == 2:
                                # WebMessageInfo
                                chat_messages.append(bytes(msg_value))
                
                if chat_id:
                    chat_lid = lid_jid or account_lid
                    contacts.append({
                        "id": chat_id,
                        "name": name,
                        "username": username,
                        "lid": chat_lid,
                        "phoneNumber": pn_jid
                    })
                    
                    is_lid = chat_id.endswith("@lid") or chat_id.endswith("@hosted.lid")
                    is_pn = chat_id.endswith("@s.whatsapp.net") or chat_id.endswith("@hosted")
                    if is_lid and pn_jid:
                        lid_pn_mappings.append({"lid": chat_id, "pn": pn_jid})
                    elif is_pn and lid_jid:
                        lid_pn_mappings.append({"lid": lid_jid, "pn": chat_id})
                    
                    chats.append({
                        "id": chat_id,
                        "messages": chat_messages
                    })
                    messages.extend(chat_messages)

        return HistorySyncResult(
            chats=chats,
            contacts=contacts,
            messages=messages,
            lid_pn_mappings=lid_pn_mappings,
            sync_type=sync_type,
            progress=progress,
            chunk_order=chunk_order
        )

    @staticmethod
    async def download_and_process(notification: dict[str, Any], download_fn: Callable[..., Any]) -> HistorySyncResult:
        data = await HistorySyncProcessor.download_history(notification, download_fn)
        return HistorySyncProcessor.process_history_message(data)

