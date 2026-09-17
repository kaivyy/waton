"""Unit tests verifying Phase 1 Protocol Survival parity features."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waton.client.chats import ChatsAPI
from waton.client.client import WAClient
from waton.client.prekey_manager import PreKeyManager
from waton.core.events import (
    EVENT_NAMES,
    CallEvent,
    ChatsUpsertEvent,
    ConnectionEvent,
    LabelsEditEvent,
    MessagingHistorySetEvent,
    make_event,
)
from waton.protocol.app_state import chat_modification_to_app_patch
from waton.protocol.binary_node import BinaryNode
from waton.protocol.lid_mapping import LIDMappingStore
from waton.utils.auth import AuthCreds, init_auth_creds
from waton.utils.event_buffer import EventBuffer
from waton.utils.generics import (
    bytes_to_crockford,
    generate_message_id_v2,
    generate_participant_hash_v2,
)
from waton.utils.history_sync import HistorySyncProcessor, HistorySyncState


class DummyStorage:
    def __init__(self) -> None:
        self.prekeys: dict[int, bytes] = {}
        self.creds: AuthCreds | None = None
        self.metadata: dict[str, Any] = {}

    async def get_prekey(self, key_id: int) -> bytes | None:
        return self.prekeys.get(key_id)

    async def save_prekey(self, key_id: int, data: bytes) -> None:
        self.prekeys[key_id] = data

    async def get_creds(self) -> AuthCreds | None:
        return self.creds

    async def save_creds(self, creds: AuthCreds) -> None:
        self.creds = creds

    async def get_metadata(self, key: str) -> Any | None:
        return self.metadata.get(key)

    async def save_metadata(self, key: str, value: Any) -> None:
        self.metadata[key] = value


@pytest.fixture
def dummy_creds() -> AuthCreds:
    creds = init_auth_creds()
    creds.me = {"id": "1234567890:1@s.whatsapp.net"}
    return creds


@pytest.fixture
def mock_client(dummy_creds: AuthCreds) -> MagicMock:
    client = MagicMock(spec=WAClient)
    client.creds = dummy_creds
    client.storage = DummyStorage()
    client.storage.creds = dummy_creds
    client.generate_message_tag.return_value = "tag-123"
    client.query = AsyncMock()
    client.send_node = AsyncMock()
    client.is_connected = True
    return client


# --- 1. Generics Tests ---
def test_participant_hash_v2() -> None:
    participants = ["1234567890:1@s.whatsapp.net", "9876543210:0@s.whatsapp.net"]
    phash = generate_participant_hash_v2(participants)
    assert phash.startswith("2:")
    assert len(phash) == 8  # '2:' + 6 base64 chars


def test_message_id_v2() -> None:
    msg_id = generate_message_id_v2("1234567890@s.whatsapp.net")
    assert msg_id.startswith("3EB0")
    assert len(msg_id) >= 22


def test_bytes_to_crockford() -> None:
    data = b"Hello"
    res = bytes_to_crockford(data)
    assert isinstance(res, str)
    assert len(res) > 0


# --- 2. Event Types Tests ---
def test_expanded_events_and_factory() -> None:
    assert len(EVENT_NAMES) >= 25
    assert "messaging-history.set" in EVENT_NAMES
    assert "labels.edit" in EVENT_NAMES
    assert "call" in EVENT_NAMES

    evt = make_event("messaging-history.set", {"chats": [], "contacts": [], "messages": []})
    assert isinstance(evt, MessagingHistorySetEvent)

    call_evt = make_event("call", {"events": [{"id": "call-1", "chatId": "123@s.whatsapp.net"}]})
    assert isinstance(call_evt, CallEvent)

    label_evt = make_event("labels.edit", {"label": {"id": "lbl-1", "name": "VIP", "color": 1}})
    assert isinstance(label_evt, LabelsEditEvent)


# --- 3. Event Buffer Tests ---
def test_event_buffer_coalescing() -> None:
    emitted: list[tuple[str, Any]] = []

    def emit_fn(name: str, data: Any) -> None:
        emitted.append((name, data))

    buf = EventBuffer(emit_callback=emit_fn)

    with buf.buffer():
        assert buf.is_buffering
        buf.process("chats.upsert", [{"id": "chat1", "name": "First"}])
        buf.process("chats.update", [{"id": "chat1", "name": "Updated"}])

    assert not buf.is_buffering
    assert len(emitted) == 1
    name, data = emitted[0]
    assert name == "chats.upsert"
    assert data[0]["name"] == "Updated"


# --- 4. LID Mapping Store Tests ---
@pytest.mark.asyncio
async def test_lid_mapping_store() -> None:
    storage = DummyStorage()
    storage.creds = init_auth_creds()
    store = LIDMappingStore(storage=storage)

    store.store_lid_pn_mapping("10002847291029", "62812345678")
    assert await store.get_lid_for_pn("62812345678@s.whatsapp.net") == "10002847291029@lid"
    assert await store.get_pn_for_lid("10002847291029@lid") == "62812345678@s.whatsapp.net"

    # Test persistence
    await store.save_to_storage()
    store.clear_cache()
    await store.load_from_storage()
    assert await store.get_lid_for_pn("62812345678@s.whatsapp.net") == "10002847291029@lid"


# --- 5. PreKeyManager Tests ---
@pytest.mark.asyncio
async def test_prekey_manager_get_count(mock_client: MagicMock) -> None:
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[BinaryNode(tag="count", attrs={"value": "42"})],
    )
    pkm = PreKeyManager(client=mock_client)
    count = await pkm.get_available_prekeys_on_server()
    assert count == 42


@pytest.mark.asyncio
async def test_prekey_manager_upload(mock_client: MagicMock) -> None:
    pkm = PreKeyManager(client=mock_client)
    await pkm.upload_prekeys(count=5)
    assert mock_client.query.called
    iq_sent = mock_client.query.call_args[0][0]
    assert iq_sent.tag == "iq"
    assert iq_sent.attrs.get("xmlns") == "encrypt"
    assert iq_sent.attrs.get("type") == "set"


@pytest.mark.asyncio
async def test_prekey_manager_rotate_signed_prekey(mock_client: MagicMock) -> None:
    pkm = PreKeyManager(client=mock_client)
    old_id = mock_client.creds.signed_pre_key["keyId"]
    await pkm.rotate_signed_prekey()
    assert mock_client.query.called
    assert mock_client.creds.signed_pre_key["keyId"] == old_id + 1


# --- 6. History Sync Tests ---
@pytest.mark.asyncio
async def test_history_sync_processor() -> None:
    processor = HistorySyncProcessor()
    assert processor.state == HistorySyncState.AWAITING_INITIAL_SYNC

    # Process wire bytes for syncType = 0 (INITIAL_BOOTSTRAP)
    result = processor.process_history_message(b"\x08\x00")
    assert result.sync_type == 0
    assert len(result.chats) == 0


# --- 7. ChatsAPI & Syncd Patch Tests ---
@pytest.mark.asyncio
async def test_chats_api_features(mock_client: MagicMock) -> None:
    chats = ChatsAPI(mock_client)

    # Test create call link
    mock_client.query.return_value = BinaryNode(
        tag="call",
        attrs={},
        content=[BinaryNode(tag="link_create", attrs={"token": "call_token_xyz"})],
    )
    token = await chats.create_call_link(call_type="video")
    assert token == "call_token_xyz"

    # Test star
    await chats.star("target@s.whatsapp.net", "msg-1", from_me=True, star=True)
    assert mock_client.send_node.called

    # Test label
    await chats.add_label(name="Important", color=2)
    assert mock_client.send_node.called

    # Test privacy updates
    await chats.update_messages_privacy("contacts")
    assert mock_client.query.called
    await chats.update_call_privacy("known")
    assert mock_client.query.called
