from __future__ import annotations

import asyncio
import atexit
import base64
import contextlib
import logging
import threading
import time
from typing import Any

import qrcode

from waton.client.client import WAClient
from waton.client.messages import MessagesAPI
from waton.core.events import ConnectionEvent
from waton.core.jid import S_WHATSAPP_NET, jid_decode, jid_encode, jid_normalized_user
from waton.infra.storage_sqlite import SQLiteStorage
from waton.protocol.binary_node import BinaryNode
from waton.protocol.signal_repo import SignalRepository
from waton.utils.process_message import process_incoming_message

from .state import DashboardEvent, DashboardState

logger = logging.getLogger(__name__)


def _qr_svg_data_url(qr_text: str) -> str:
    qr = qrcode.QRCode(border=1)
    qr.add_data(qr_text)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    size = len(matrix)
    cells: list[str] = []
    for y, row in enumerate(matrix):
        for x, is_dark in enumerate(row):
            if is_dark:
                cells.append(f"<rect x='{x}' y='{y}' width='1' height='1'/>")
    svg = (
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {size} {size}' shape-rendering='crispEdges'>"
        "<rect width='100%' height='100%' fill='white'/>"
        "<g fill='black'>"
        + "".join(cells)
        + "</g></svg>"
    )
    encoded = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def normalize_jid_for_chat(jid: str) -> str:
    if not jid:
        return ""
    normalized = jid_normalized_user(jid)
    parsed = jid_decode(normalized)
    if not parsed or not parsed.user:
        return normalized or jid
    server = parsed.server.lower()
    if server in {"s.whatsapp.net", "hosted"}:
        return jid_encode(parsed.user, S_WHATSAPP_NET)
    if server in {"hosted.lid", "lid"}:
        return jid_encode(parsed.user, "lid")
    return jid_encode(parsed.user, parsed.server)


def extract_alt_pn_from_attrs(attrs: dict[str, Any]) -> str | None:
    for key in ("participant_pn", "sender_pn", "peer_recipient_pn", "recipient_pn"):
        raw = attrs.get(key)
        if isinstance(raw, str) and raw:
            normalized = normalize_jid_for_chat(raw)
            if normalized.endswith(f"@{S_WHATSAPP_NET}"):
                return normalized
    return None


def extract_peer_jid_from_attrs(attrs: dict[str, Any], me_jids: set[str]) -> str | None:
    pn_keys = ("participant_pn", "sender_pn", "peer_recipient_pn", "recipient_pn")
    generic_keys = ("participant", "sender", "recipient", "peer_recipient", "to", "from")
    lid_keys = ("participant_lid", "sender_lid", "peer_recipient_lid", "recipient_lid")

    pn_candidates: list[str] = []
    other_candidates: list[str] = []

    for key in (*pn_keys, *generic_keys, *lid_keys):
        raw = attrs.get(key)
        if not isinstance(raw, str) or not raw:
            continue
        normalized = normalize_jid_for_chat(raw)
        if not normalized or normalized in me_jids:
            continue
        if normalized.endswith(f"@{S_WHATSAPP_NET}"):
            pn_candidates.append(normalized)
        else:
            other_candidates.append(normalized)

    if pn_candidates:
        return pn_candidates[0]
    if other_candidates:
        return other_candidates[0]
    return None


def compute_route_keys(
    *,
    from_jid: str,
    participant_jid: str,
    destination_jid: str,
    me_jids: set[str],
) -> tuple[str, str, bool]:
    from_norm = normalize_jid_for_chat(from_jid)
    participant_norm = normalize_jid_for_chat(participant_jid) if participant_jid else ""
    destination_norm = normalize_jid_for_chat(destination_jid) if destination_jid else ""

    is_group = from_norm.endswith("@g.us")
    if is_group:
        sender = participant_norm or from_norm
        return from_norm, sender, sender in me_jids

    if participant_norm and participant_norm not in me_jids:
        return participant_norm, participant_norm, False

    if from_norm in me_jids:
        chat = destination_norm or participant_norm or from_norm
        return chat, from_norm, True

    sender = from_norm or participant_norm
    return sender, sender, False


def choose_lid_chat_fallback(
    *,
    incoming_chat_jid: str,
    from_me: bool,
    active_chat_jid: str | None,
    known_pn_chats: list[str],
    existing_hint: str | None,
) -> str | None:
    if from_me or not incoming_chat_jid.endswith("@lid"):
        return None
    if existing_hint:
        return existing_hint
    if not isinstance(active_chat_jid, str) or not active_chat_jid.endswith(f"@{S_WHATSAPP_NET}"):
        return None
    if known_pn_chats and active_chat_jid not in known_pn_chats:
        return None
    if len(known_pn_chats) > 1:
        return None
    return active_chat_jid


class DashboardRuntime:
    """Real WhatsApp runtime used by the browser dashboard."""

    def __init__(self, auth_db_path: str = "waton_dashboard.db", max_events: int = 400) -> None:
        self.auth_db_path = auth_db_path
        self._events = DashboardState(max_events=max_events)
        self._state_lock = threading.Lock()
        self._chat_lock = threading.Lock()
        self._chats: dict[str, dict[str, Any]] = {}
        self._messages_by_chat: dict[str, list[dict[str, Any]]] = {}
        self._lid_chat_hints: dict[str, str] = {}
        self._active_chat_jid: str | None = None
        self._max_messages_per_chat = 400
        self._state: dict[str, Any] = {
            "state": "disconnected",
            "status": "disconnected",
            "qr": None,
            "qr_image_data_url": None,
            "reason": None,
            "me": None,
        }
        self._loop = asyncio.new_event_loop()
        self._started = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, name="waton-dashboard-loop", daemon=True)
        self._thread.start()
        self._started.wait(timeout=2.0)

        self._client: WAClient | None = None
        self._messages: MessagesAPI | None = None
        self._storage: SQLiteStorage | None = None
        self._connect_guard = asyncio.Lock()

        atexit.register(self.close)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._started.set()
        self._loop.run_forever()

    def _run_coro_sync(self, coro: Any) -> Any:
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=30.0)

    def _set_state(self, **updates: Any) -> None:
        with self._state_lock:
            self._state.update(updates)

    def connection_state(self) -> dict[str, Any]:
        with self._state_lock:
            return dict(self._state)

    def list_events(self) -> list[dict[str, Any]]:
        return self._events.list_events()

    def list_chats(self) -> list[dict[str, Any]]:
        with self._chat_lock:
            chats = [dict(item) for item in self._chats.values()]
        chats.sort(key=lambda item: int(item.get("last_timestamp", 0)), reverse=True)
        return chats

    def list_messages(self, chat_jid: str) -> list[dict[str, Any]]:
        with self._chat_lock:
            chat_keys = {chat_jid}
            mapped = self._lid_chat_hints.get(chat_jid)
            if mapped:
                chat_keys.add(mapped)
            for lid_jid, pn_jid in self._lid_chat_hints.items():
                if pn_jid == chat_jid:
                    chat_keys.add(lid_jid)

            messages: list[dict[str, Any]] = []
            for key in chat_keys:
                for item in self._messages_by_chat.get(key, []):
                    msg = dict(item)
                    msg["chat_jid"] = chat_jid
                    messages.append(msg)
        messages.sort(key=lambda item: int(item.get("timestamp", 0)))
        return messages

    def mark_chat_read(self, chat_jid: str) -> None:
        with self._chat_lock:
            chat = self._chats.get(chat_jid)
            if chat:
                chat["unread_count"] = 0
            self._active_chat_jid = chat_jid

    def ensure_connected(self) -> dict[str, Any]:
        return self._run_coro_sync(self._ensure_connected_async())

    def disconnect(self) -> dict[str, Any]:
        return self._run_coro_sync(self._disconnect_async())

    def send_text(self, to_jid: str, text: str) -> str:
        return self._run_coro_sync(self._send_text_async(to_jid, text))

    async def _ensure_connected_async(self) -> dict[str, Any]:
        async with self._connect_guard:
            if self._client and self._client.is_transport_connected:
                return self.connection_state()

            await self._teardown_client_async()

            storage = SQLiteStorage(self.auth_db_path)
            client = WAClient(storage)
            messages = MessagesAPI(client)

            client.on_connection_update = self._on_connection_update
            client.on_message = self._on_message
            client.on_event = self._on_event
            client.on_disconnected = self._on_disconnected

            self._storage = storage
            self._client = client
            self._messages = messages

            self._set_state(state="connecting", status="connecting", reason=None)
            self._events.add_event(
                DashboardEvent(
                    kind="system",
                    source="dashboard",
                    payload={"event": "connect_requested", "auth_db": self.auth_db_path},
                )
            )
            try:
                await client.connect()
            except Exception as exc:
                self._events.add_event(
                    DashboardEvent(
                        kind="system",
                        source="dashboard",
                        payload={"event": "connect_failed", "error": str(exc)},
                    )
                )
                self._set_state(state="disconnected", status="disconnected", reason=str(exc))
                await self._teardown_client_async()
                raise

            return self.connection_state()

    async def _send_text_async(self, to_jid: str, text: str) -> str:
        if not self._client or not self._messages or not self._client.is_authenticated:
            raise RuntimeError("WhatsApp is not connected yet.")

        msg_id = await self._messages.send_text(to_jid, text)
        sender_jid = None
        if self._client.creds and self._client.creds.me:
            sender_jid = self._client.creds.me.get("id")
        self._append_chat_message(
            chat_jid=to_jid,
            sender_jid=sender_jid or "me",
            text=text,
            from_me=True,
            status="sent",
            message_id=msg_id,
        )
        with self._chat_lock:
            self._active_chat_jid = to_jid
        self._events.add_event(
            DashboardEvent(
                kind="outgoing",
                source="dashboard",
                payload={"to": to_jid, "text": text, "message_id": msg_id},
            )
        )
        return msg_id

    async def _disconnect_async(self) -> dict[str, Any]:
        await self._teardown_client_async()
        self._set_state(
            state="disconnected",
            status="disconnected",
            qr=None,
            qr_image_data_url=None,
            reason=None,
            me=None,
        )
        self._events.add_event(
            DashboardEvent(kind="system", source="dashboard", payload={"event": "disconnect_requested"})
        )
        return self.connection_state()

    async def _teardown_client_async(self) -> None:
        if self._client:
            with contextlib.suppress(Exception):
                await self._client.disconnect()
        if self._storage:
            with contextlib.suppress(Exception):
                await self._storage.close()
        self._client = None
        self._messages = None
        self._storage = None

    async def _on_connection_update(self, event: ConnectionEvent) -> None:
        status = getattr(event, "status", None) or "unknown"
        qr = getattr(event, "qr", None)
        reason_obj = getattr(event, "reason", None)
        reason = str(reason_obj) if reason_obj else None
        mapped_state = "disconnected"
        if status in {"connecting", "pairing-success", "pairing-signed"}:
            mapped_state = "connecting"
        elif status == "open":
            mapped_state = "connected"

        me = None
        if self._client and self._client.creds and self._client.creds.me:
            me = dict(self._client.creds.me)

        updates: dict[str, Any] = {
            "state": mapped_state,
            "status": mapped_state,
            "reason": reason,
            "me": me,
        }
        if qr:
            updates["qr"] = qr
            updates["qr_image_data_url"] = _qr_svg_data_url(qr)
        elif status == "open":
            updates["qr"] = None
            updates["qr_image_data_url"] = None

        self._set_state(**updates)
        self._events.add_event(
            DashboardEvent(
                kind="connection",
                source="wa-client",
                payload={"status": status, "state": mapped_state, "reason": reason, "has_qr": bool(qr)},
            )
        )

    async def _on_message(self, node: BinaryNode) -> None:
        try:
            payload: dict[str, Any] = {
                "tag": node.tag,
                "attrs": dict(node.attrs),
            }
            if node.tag == "message" and self._client is not None:
                attrs = dict(node.attrs)
                raw_from = str(attrs.get("from") or "")
                raw_participant = str(attrs.get("participant") or attrs.get("sender") or "")
                raw_destination = str(attrs.get("to") or attrs.get("recipient") or attrs.get("peer_recipient") or "")
                me_jids = self._known_me_jids()
                inferred_peer = extract_peer_jid_from_attrs(attrs, me_jids)
                if (
                    not raw_participant
                    and not raw_destination
                    and normalize_jid_for_chat(raw_from) in me_jids
                    and inferred_peer
                ):
                    # Some MD sync envelopes use from=self for peer messages.
                    raw_participant = inferred_peer
                try:
                    msg = await process_incoming_message(node, self._client)
                except Exception as exc:  # pragma: no cover - decrypt can fail by session state
                    payload["decrypt_error"] = str(exc)
                    chat_key, sender_key, from_me = compute_route_keys(
                        from_jid=raw_from,
                        participant_jid=raw_participant,
                        destination_jid=raw_destination,
                        me_jids=me_jids,
                    )
                    chat_jid = chat_key
                    if chat_jid:
                        chat_jid = await self._resolve_chat_jid(chat_jid)
                        sender_jid = await self._resolve_chat_jid(sender_key or chat_key)
                        alt_pn = extract_alt_pn_from_attrs(attrs)
                        original_chat_jid = chat_jid
                        if alt_pn and chat_jid.endswith("@lid"):
                            self._set_lid_chat_hint(chat_jid, alt_pn)
                            chat_jid = alt_pn
                        if alt_pn and sender_jid.endswith("@lid"):
                            self._set_lid_chat_hint(sender_jid, alt_pn)
                            sender_jid = alt_pn
                        if inferred_peer and chat_jid in me_jids:
                            chat_jid = inferred_peer
                            sender_jid = inferred_peer
                            from_me = False
                        chat_jid = self._apply_lid_chat_fallback(chat_jid, from_me=from_me)
                        if original_chat_jid.endswith("@lid") and chat_jid.endswith(f"@{S_WHATSAPP_NET}"):
                            self._set_lid_chat_hint(original_chat_jid, chat_jid)
                            if sender_jid.endswith("@lid"):
                                self._set_lid_chat_hint(sender_jid, chat_jid)
                                sender_jid = chat_jid
                        payload["routing"] = {
                            "chat_jid": chat_jid,
                            "sender_jid": sender_jid,
                            "from_me": from_me,
                            "decrypt_error": str(exc),
                        }
                        self._append_chat_message(
                            chat_jid=chat_jid,
                            sender_jid=sender_jid,
                            text="[undecrypted message]",
                            from_me=from_me,
                            status="undecrypted",
                            message_id=node.attrs.get("id"),
                            timestamp_s=self._parse_node_timestamp(node),
                        )
                else:
                    from_jid = msg.from_jid or raw_from
                    participant = msg.participant if isinstance(msg.participant, str) else raw_participant
                    destination_jid = (
                        msg.destination_jid
                        if isinstance(msg.destination_jid, str)
                        else str(attrs.get("to") or attrs.get("recipient") or attrs.get("peer_recipient") or "")
                    )
                    if (
                        not participant
                        and not destination_jid
                        and normalize_jid_for_chat(from_jid) in me_jids
                        and inferred_peer
                    ):
                        participant = inferred_peer
                    chat_key, sender_key, from_me = compute_route_keys(
                        from_jid=from_jid,
                        participant_jid=participant,
                        destination_jid=destination_jid,
                        me_jids=me_jids,
                    )

                    chat_jid = await self._resolve_chat_jid(chat_key)
                    sender_jid = await self._resolve_chat_jid(sender_key)
                    alt_pn = extract_alt_pn_from_attrs(attrs)
                    original_chat_jid = chat_jid
                    if alt_pn and chat_jid.endswith("@lid"):
                        self._set_lid_chat_hint(chat_jid, alt_pn)
                        chat_jid = alt_pn
                    if alt_pn and sender_jid.endswith("@lid"):
                        self._set_lid_chat_hint(sender_jid, alt_pn)
                        sender_jid = alt_pn
                    if inferred_peer and chat_jid in me_jids:
                        chat_jid = inferred_peer
                        sender_jid = inferred_peer
                        from_me = False
                    chat_jid = self._apply_lid_chat_fallback(chat_jid, from_me=from_me)
                    if original_chat_jid.endswith("@lid") and chat_jid.endswith(f"@{S_WHATSAPP_NET}"):
                        self._set_lid_chat_hint(original_chat_jid, chat_jid)
                        if sender_jid.endswith("@lid"):
                            self._set_lid_chat_hint(sender_jid, chat_jid)
                            sender_jid = chat_jid

                    has_enc_child = bool(
                        isinstance(node.content, list)
                        and any(isinstance(child, BinaryNode) and child.tag == "enc" for child in node.content)
                    )
                    inferred_undecrypted = bool(
                        has_enc_child
                        and not msg.text
                        and msg.message_type in {"unknown", "text"}
                    )
                    display_text = msg.text or ("[undecrypted message]" if inferred_undecrypted else "[non-text message]")
                    display_status = "undecrypted" if inferred_undecrypted else ("received" if not from_me else "sent")

                    payload["message"] = {
                        "id": msg.id,
                        "from": msg.from_jid,
                        "to": chat_jid,
                        "text": msg.text,
                        "from_me": from_me,
                    }
                    payload["routing"] = {
                        "chat_jid": chat_jid,
                        "sender_jid": sender_jid,
                        "from_me": from_me,
                    }
                    self._append_chat_message(
                        chat_jid=chat_jid,
                        sender_jid=sender_jid,
                        text=display_text,
                        from_me=from_me,
                        status=display_status,
                        message_id=msg.id,
                        timestamp_s=msg.timestamp if msg.timestamp else None,
                    )
            self._events.add_event(DashboardEvent(kind="node", source="wa-client", payload=payload))
        except Exception as exc:  # pragma: no cover - defensive guard for background tasks
            logger.exception("dashboard on_message handler failed: %s", exc)
            self._events.add_event(
                DashboardEvent(
                    kind="system",
                    source="dashboard",
                    payload={"event": "on_message_handler_error", "error": str(exc)},
                )
            )

    async def _on_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("type")
        payload: dict[str, Any] = {"type": event_type}
        if event_type == "messages.ack":
            ack = event.get("ack")
            payload["ack"] = ack
            if isinstance(ack, dict):
                message_id = ack.get("id")
                if isinstance(message_id, str) and message_id:
                    if ack.get("error"):
                        self._update_message_status(message_id, "error")
                    else:
                        self._update_message_status(message_id, "delivered")
        elif event_type == "messages.bad_ack":
            bad_ack = event.get("bad_ack")
            payload["bad_ack"] = bad_ack
            if isinstance(bad_ack, dict):
                message_id = bad_ack.get("message_id")
                if isinstance(message_id, str) and message_id:
                    self._update_message_status(message_id, "error")
        elif event_type == "messages.receipt":
            payload["receipt"] = event.get("receipt")
        self._events.add_event(DashboardEvent(kind="event", source="wa-client", payload=payload))

    async def _on_disconnected(self, exc: Exception) -> None:
        reason = str(exc)
        self._set_state(
            state="disconnected",
            status="disconnected",
            reason=reason,
            qr=None,
            qr_image_data_url=None,
        )
        self._events.add_event(
            DashboardEvent(
                kind="connection",
                source="wa-client",
                payload={"status": "close", "state": "disconnected", "reason": reason},
            )
        )

    def close(self) -> None:
        if not self._loop.is_running():
            return
        with contextlib.suppress(Exception):
            self._run_coro_sync(self._teardown_client_async())
        self._loop.call_soon_threadsafe(self._loop.stop)

    async def _resolve_chat_jid(self, raw_jid: str) -> str:
        normalized = normalize_jid_for_chat(raw_jid)
        parsed = jid_decode(normalized)
        if not parsed or parsed.server != "lid" or self._client is None or self._storage is None or self._client.creds is None:
            return normalized
        try:
            repo = SignalRepository(self._client.creds, self._storage)
            mapped = await repo.get_pn_for_lid(normalized)
        except Exception:
            return normalized
        if isinstance(mapped, str) and mapped:
            return normalize_jid_for_chat(mapped)
        return normalized

    def _known_me_jids(self) -> set[str]:
        if self._client is None or self._client.creds is None or not self._client.creds.me:
            return set()
        me = self._client.creds.me
        out: set[str] = set()
        for key in ("id", "lid"):
            raw = me.get(key)
            if isinstance(raw, str) and raw:
                out.add(normalize_jid_for_chat(raw))
        return out

    def _set_lid_chat_hint(self, lid_jid: str, pn_jid: str) -> None:
        if not lid_jid.endswith("@lid"):
            return
        if not pn_jid.endswith(f"@{S_WHATSAPP_NET}"):
            return
        with self._chat_lock:
            self._lid_chat_hints[lid_jid] = pn_jid

    def _apply_lid_chat_fallback(self, chat_jid: str, *, from_me: bool) -> str:
        with self._chat_lock:
            known_pn_chats = [jid for jid in self._chats if jid.endswith(f"@{S_WHATSAPP_NET}")]
            active_chat_jid = self._active_chat_jid
            existing_hint = self._lid_chat_hints.get(chat_jid)
        fallback = choose_lid_chat_fallback(
            incoming_chat_jid=chat_jid,
            from_me=from_me,
            active_chat_jid=active_chat_jid,
            known_pn_chats=known_pn_chats,
            existing_hint=existing_hint,
        )
        if fallback and chat_jid.endswith("@lid"):
            self._set_lid_chat_hint(chat_jid, fallback)
        return fallback or chat_jid

    def _append_chat_message(
        self,
        *,
        chat_jid: str,
        sender_jid: str,
        text: str,
        from_me: bool,
        status: str,
        message_id: str | None = None,
        timestamp_s: int | None = None,
    ) -> None:
        if not chat_jid:
            return
        now_ms = int(time.time() * 1000)
        timestamp_ms = now_ms
        if isinstance(timestamp_s, int) and timestamp_s > 0:
            timestamp_ms = timestamp_s * 1000 if timestamp_s < 10**12 else timestamp_s

        normalized_text = (text or "").strip() or "[empty]"
        msg = {
            "id": message_id or f"local-{now_ms}",
            "chat_jid": chat_jid,
            "from_me": bool(from_me),
            "sender_jid": sender_jid,
            "text": normalized_text,
            "timestamp": timestamp_ms,
            "status": status,
        }
        with self._chat_lock:
            chat_messages = self._messages_by_chat.setdefault(chat_jid, [])
            chat_messages.append(msg)
            overflow = len(chat_messages) - self._max_messages_per_chat
            if overflow > 0:
                del chat_messages[:overflow]

            title = chat_jid.split("@", 1)[0]
            existing = self._chats.get(chat_jid) or {
                "jid": chat_jid,
                "title": title,
                "last_text": "",
                "last_timestamp": 0,
                "unread_count": 0,
            }
            existing["last_text"] = normalized_text
            existing["last_timestamp"] = timestamp_ms
            if not from_me:
                existing["unread_count"] = int(existing.get("unread_count", 0)) + 1
            self._chats[chat_jid] = existing

    def _update_message_status(self, message_id: str, status: str) -> None:
        with self._chat_lock:
            for chat_jid, messages in self._messages_by_chat.items():
                for item in reversed(messages):
                    if item.get("id") == message_id:
                        item["status"] = status
                        chat = self._chats.get(chat_jid)
                        if chat and chat.get("last_timestamp") == item.get("timestamp"):
                            chat["last_text"] = item.get("text", "")
                        return

    @staticmethod
    def _parse_node_timestamp(node: BinaryNode) -> int | None:
        raw = node.attrs.get("t")
        if raw is None:
            return None
        try:
            return int(str(raw))
        except ValueError:
            return None
