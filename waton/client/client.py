"""Low-level WhatsApp socket client."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import logging
import time
from typing import TYPE_CHECKING, Any

from waton.client.messages_recv import (
    build_call_reject_node,
    build_message_ack,
    build_placeholder_resend_request,
    build_retry_receipt_node,
    classify_incoming_node,
    drain_nodes_with_buffer,
    normalize_incoming_node,
)
from waton.client.retry_manager import RetryManager
from waton.core.errors import ConnectionError as WatonConnectionError
from waton.core.errors import DisconnectReason
from waton.core.events import ConnectionEvent
from waton.core.jid import S_WHATSAPP_NET, jid_decode
from waton.defaults.config import (
    DEFAULT_CONNECTION_CONFIG,
    KEY_BUNDLE_TYPE,
    WA_ADV_ACCOUNT_SIG_PREFIX,
    WA_ADV_DEVICE_SIG_PREFIX,
    WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX,
    WA_NOISE_HEADER,
)
from waton.infra.websocket import WebSocketTransport
from waton.protocol.binary_codec import encode_binary_node
from waton.protocol.binary_node import BinaryNode
from waton.protocol.noise_handler import NoiseHandler
from waton.protocol.protobuf.wire import (
    ADVDeviceIdentity,
    ADVSignedDeviceIdentity,
    ADVSignedDeviceIdentityHMAC,
    AppVersion,
    ClientPayload,
    DevicePairingRegistrationData,
    DeviceProps,
    DevicePropsAppVersion,
    HandshakeClientFinish,
    HandshakeClientHello,
    HandshakeMessage,
    HistorySyncConfig,
    UserAgent,
    WebInfo,
)
from waton.protocol.signal_repo import SignalRepository
from waton.utils.auth import AuthCreds, StoragePort, init_auth_creds
from waton.utils.crypto import generate_keypair, hmac_sha256, sign, verify

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)


def _encode_big_endian(value: int, width: int = 4) -> bytes:
    return int(value).to_bytes(width, byteorder="big", signed=False)


def _platform_type_from_browser(platform: str) -> int:
    upper = platform.upper()
    if upper in ("DESKTOP", "WINDOWS", "MAC OS", "MACOS"):
        return DeviceProps.PlatformType.DESKTOP
    return DeviceProps.PlatformType.CHROME


class WAClient:
    """Socket-level WhatsApp Web client with native Python+Rust transport."""

    def __init__(self, storage: StoragePort, ws_url: str | None = None, **config_overrides: Any) -> None:
        self.storage = storage

        self.config: dict[str, Any] = {**DEFAULT_CONNECTION_CONFIG, **config_overrides}
        if ws_url is not None:
            self.config["ws_url"] = ws_url

        self.ws = WebSocketTransport(override_url=self.config["ws_url"])
        self.creds: AuthCreds | None = None
        self.noise: NoiseHandler | None = None

        self.is_transport_connected = False
        self.is_connected = False
        self.is_authenticated = False

        self.on_message: Callable[[BinaryNode], Awaitable[None]] = self._default_message_handler
        self.on_event: Callable[[dict[str, Any]], Awaitable[None]] = self._default_event_handler
        self.on_disconnected: Callable[[Exception], Awaitable[None]] = self._default_disconnect_handler
        self.on_connection_update: Callable[[ConnectionEvent], Awaitable[None]] = self._default_connection_handler
        retry_limit = int(self.config.get("max_retry_receipts", 3))
        recent_cache_limit = int(self.config.get("max_recent_sent_messages", 200))
        self.retry_manager = RetryManager(max_attempts=retry_limit, max_recent_messages=recent_cache_limit)
        decrypt_retry_limit = int(self.config.get("max_decrypt_retry_requests", 2))
        self.decrypt_retry_manager = RetryManager(max_attempts=decrypt_retry_limit)
        self._recent_sent_messages: dict[str, BinaryNode] = {}

        self.ws.on_message = self._handle_raw_ws_message
        self.ws.on_disconnect = self._handle_ws_disconnect

        self._raw_frame_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._pending_queries: dict[str, asyncio.Future[BinaryNode]] = {}
        self._epoch = 1
        self._qr_task: asyncio.Task[None] | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._pending_disconnect_reason: WatonConnectionError | None = None
        self._restart_attempts = 0
        self._explicit_disconnect = False
        self._server_time_offset_ms = 0
        self._requested_offline_batch = False

    async def connect(self) -> None:
        self._explicit_disconnect = False
        self._requested_offline_batch = False
        self.creds = await self.storage.get_creds()
        if not self.creds:
            self.creds = init_auth_creds()
            await self.storage.save_creds(self.creds)
        else:
            await self._refresh_unregistered_creds()

        await self.on_connection_update(ConnectionEvent(status="connecting"))

        ephemeral_keypair = generate_keypair()
        self.noise = NoiseHandler(
            keypair=ephemeral_keypair,
            noise_header=WA_NOISE_HEADER,
            routing_info=self.creds.routing_info,
        )

        await self.ws.connect()
        self.is_transport_connected = True

        hello = HandshakeMessage(client_hello=HandshakeClientHello(ephemeral=ephemeral_keypair["public"]))
        await self.ws.send(self.noise.encode_frame(hello.SerializeToString()))

        connect_timeout = float(self.config["connect_timeout"])
        handshake_raw = await asyncio.wait_for(self._raw_frame_queue.get(), timeout=connect_timeout)
        handshake = HandshakeMessage.ParseFromString(handshake_raw)
        if handshake.server_hello is None:
            raise ValueError("invalid handshake: server hello missing")

        key_enc = self.noise.process_handshake(handshake.server_hello, self.creds.noise_key)

        if self.creds.me and "id" in self.creds.me:
            payload = self._generate_login_payload(self.creds.me["id"]).SerializeToString()
        else:
            payload = self._generate_registration_payload().SerializeToString()

        payload_enc = self.noise.encrypt(payload)
        finish = HandshakeMessage(
            client_finish=HandshakeClientFinish(
                static=key_enc,
                payload=payload_enc,
            )
        )
        await self.ws.send(self.noise.encode_frame(finish.SerializeToString()))
        self.noise.finish_init()
        self.is_connected = True

    async def disconnect(self) -> None:
        self._explicit_disconnect = True
        self._restart_attempts = 0
        if self._qr_task:
            self._qr_task.cancel()
            self._qr_task = None
        if self._keepalive_task:
            self._keepalive_task.cancel()
            self._keepalive_task = None
        await self.ws.disconnect()

    async def send_node(self, node: BinaryNode) -> None:
        if not self.is_connected or not self.noise:
            raise WatonConnectionError("Cannot send node: not connected")
        self._remember_sent_message(node)
        payload = encode_binary_node(node)
        frame = self.noise.encode_frame(payload)
        await self.ws.send(frame)

    async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
        timeout_s = timeout if timeout is not None else float(self.config["frame_timeout"])
        msg_id = node.attrs.get("id")
        if not msg_id:
            msg_id = self._generate_message_tag()
            node.attrs["id"] = msg_id

        loop = asyncio.get_running_loop()
        fut: asyncio.Future[BinaryNode] = loop.create_future()
        self._pending_queries[msg_id] = fut
        try:
            await self.send_node(node)
            return await asyncio.wait_for(fut, timeout=timeout_s)
        finally:
            self._pending_queries.pop(msg_id, None)

    async def send_ping(self) -> BinaryNode:
        return await self.query(
            BinaryNode(
                tag="iq",
                attrs={
                    "to": S_WHATSAPP_NET,
                    "type": "get",
                    "xmlns": "w:p",
                },
                content=[BinaryNode(tag="ping", attrs={})],
            ),
            timeout=float(self.config["frame_timeout"]),
        )

    async def _handle_raw_ws_message(self, data: bytes) -> None:
        if self.noise is None:
            return
        try:
            frames = self.noise.decode_frame(data)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.error("failed to decode frame: %s", exc, exc_info=True)
            return

        buffer_enabled = bool(self.config.get("enable_offline_node_buffer", True))
        buffered_nodes: list[BinaryNode] = []

        for frame in frames:
            if isinstance(frame, bytes):
                await self._raw_frame_queue.put(frame)
            else:
                if buffer_enabled and classify_incoming_node(frame) in {"message", "receipt", "notification", "call", "ack", "ib"}:
                    buffered_nodes.append(frame)
                else:
                    await self._handle_binary_node(frame)

        if buffered_nodes:
            await drain_nodes_with_buffer(
                buffered_nodes,
                self._handle_binary_node,
                max_queue_size=int(self.config.get("incoming_node_buffer_size", 1024)),
                yield_every=int(self.config.get("incoming_node_yield_every", 20)),
            )

    async def _handle_binary_node(self, node: BinaryNode) -> None:
        self._update_server_time_offset(node)
        msg_id = node.attrs.get("id")
        if msg_id:
            waiter = self._pending_queries.get(msg_id)
            if waiter and not waiter.done():
                waiter.set_result(node)

        if (
            node.tag == "iq"
            and node.attrs.get("type") == "get"
            and node.attrs.get("xmlns") == "urn:xmpp:ping"
        ):
            reply_attrs = {
                "to": node.attrs.get("from", S_WHATSAPP_NET),
                "type": "result",
            }
            if node.attrs.get("id"):
                reply_attrs["id"] = node.attrs["id"]
            await self.send_node(BinaryNode(tag="iq", attrs=reply_attrs))
            return

        if node.tag == "success":
            await self._handle_success(node)
            return

        if node.tag == "stream:error":
            self._pending_disconnect_reason = self._stream_error_to_exception(node)
            await self.on_message(node)
            return

        if node.tag == "failure":
            self._pending_disconnect_reason = self._failure_to_exception(node)
            await self.on_message(node)
            return

        if node.tag == "iq":
            if self._get_child(node, "pair-device") and node.attrs.get("type") == "set":
                await self._handle_pair_device(node)
                return
            if self._get_child(node, "pair-success"):
                await self._handle_pair_success(node)
                return

        incoming_kind = classify_incoming_node(node)
        if incoming_kind == "ib":
            await self._handle_ib_node(node)

        if incoming_kind in {"message", "receipt", "notification", "call", "ack", "ib"}:
            await self._handle_incoming_node(node, incoming_kind)

        await self.on_message(node)

    async def _handle_incoming_node(self, node: BinaryNode, incoming_kind: str) -> None:
        if incoming_kind in {"message", "receipt", "notification", "call"} and self.config.get("auto_ack_incoming", True):
            await self._maybe_send_ack(node)

        signal_repo: SignalRepository | None = None
        if self.creds:
            signal_repo = SignalRepository(self.creds, self.storage)
        try:
            event = await normalize_incoming_node(node, signal_repo)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.debug("failed to normalize incoming node %s: %s", node.tag, exc)
            await self._handle_incoming_error(node, incoming_kind, exc)
            return
        if event is not None:
            if event.get("type") == "messages.retry_request":
                self._annotate_retry_request_event(event)
                await self._attempt_retry_resend(event)
            if event.get("type") == "messages.ack":
                self._apply_ack_side_effects(event)
            if event.get("type") == "messages.call":
                await self._maybe_reject_call(event, node)
            await self._apply_protocol_event_side_effects(event)
            await self._apply_message_secret_side_effects(event)
            await self.on_event(event)

    async def _maybe_reject_call(self, event: dict[str, Any], node: BinaryNode) -> None:
        if not self.config.get("auto_reject_calls", False):
            return

        call = event.get("call")
        if not isinstance(call, dict):
            return

        status = str(call.get("status") or "").lower()
        if status not in {"offer", "offer_video", "offer_audio"}:
            return

        call_id = call.get("id")
        call_from = call.get("from")
        if not isinstance(call_id, str) or not call_id:
            return
        if not isinstance(call_from, str) or not call_from:
            return

        call_to = node.attrs.get("from") if isinstance(node.attrs.get("from"), str) else None
        reject_node = build_call_reject_node(
            call_id=call_id,
            call_from=call_from,
            call_to=call_to,
        )
        try:
            await self.send_node(reject_node)
        except Exception as exc:  # pragma: no cover - network dependent
            event["call_reject_sent"] = False
            event["call_reject_error"] = str(exc)
        else:
            event["call_reject_sent"] = True

    def _apply_ack_side_effects(self, event: dict[str, Any]) -> None:
        ack = event.get("ack")
        if not isinstance(ack, dict):
            return
        if ack.get("class") != "receipt":
            return
        message_id = ack.get("id")
        if isinstance(message_id, str) and message_id:
            self.retry_manager.mark_retry_acked(message_id)

    async def _apply_protocol_event_side_effects(self, event: dict[str, Any]) -> None:
        if self.creds is None:
            return

        event_type = event.get("type")
        protocol = event.get("protocol")
        if not isinstance(protocol, dict):
            return

        creds_changed = False
        additional_data = dict(self.creds.additional_data or {})

        if event_type == "messages.app_state_sync_key_share":
            share = protocol.get("app_state_sync_key_share")
            keys_payload = share.get("keys") if isinstance(share, dict) else None
            stored_keys = dict(additional_data.get("app_state_sync_keys") or {})
            if isinstance(keys_payload, list):
                for key_item in keys_payload:
                    if not isinstance(key_item, dict):
                        continue
                    key_id = key_item.get("key_id_b64")
                    if not isinstance(key_id, str) or not key_id:
                        continue
                    normalized = {
                        "key_id_b64": key_id,
                        "key_data_size": int(key_item.get("key_data_size", 0)),
                    }
                    if stored_keys.get(key_id) != normalized:
                        stored_keys[key_id] = normalized
                        creds_changed = True
            if stored_keys:
                additional_data["app_state_sync_keys"] = stored_keys
                if creds_changed:
                    event["app_state_sync_keys_saved"] = len(stored_keys)

        if event_type == "messages.history_sync":
            processed = list(self.creds.processed_history_messages or [])
            message = event.get("message")
            history = protocol.get("history_sync")
            message_id = message.get("id") if isinstance(message, dict) else None
            sync_type = history.get("sync_type") if isinstance(history, dict) else None
            chunk_order = history.get("chunk_order") if isinstance(history, dict) else None

            if isinstance(message_id, str) and message_id:
                record = {
                    "id": message_id,
                    "sync_type": sync_type,
                    "chunk_order": chunk_order,
                    "timestamp": message.get("timestamp") if isinstance(message, dict) else None,
                }
                already_recorded = any(
                    isinstance(entry, dict)
                    and entry.get("id") == message_id
                    and entry.get("sync_type") == sync_type
                    and entry.get("chunk_order") == chunk_order
                    for entry in processed
                )
                if not already_recorded:
                    processed.append(record)
                    self.creds.processed_history_messages = processed
                    event["history_processed_count"] = len(processed)
                    creds_changed = True

        if creds_changed:
            self.creds.additional_data = additional_data
            await self.storage.save_creds(self.creds)

    async def _apply_message_secret_side_effects(self, event: dict[str, Any]) -> None:
        if self.creds is None:
            return

        message = event.get("message")
        if not isinstance(message, dict):
            return

        content_type = message.get("content_type")
        if content_type not in {"poll_creation", "event"}:
            return

        message_id = message.get("id")
        message_secret_b64 = message.get("message_secret_b64")
        if not isinstance(message_id, str) or not message_id:
            return
        if not isinstance(message_secret_b64, str) or not message_secret_b64:
            return

        additional_data = dict(self.creds.additional_data or {})
        message_secrets = dict(additional_data.get("message_secrets") or {})

        if message_secrets.get(message_id) == message_secret_b64:
            return

        message_secrets[message_id] = message_secret_b64
        max_entries = int(self.config.get("max_message_secrets_cache", 512))
        if max_entries > 0 and len(message_secrets) > max_entries:
            for stale_id in list(message_secrets.keys())[:-max_entries]:
                message_secrets.pop(stale_id, None)

        additional_data["message_secrets"] = message_secrets
        self.creds.additional_data = additional_data
        await self.storage.save_creds(self.creds)
        event["message_secret_saved"] = message_id

    async def _handle_incoming_error(self, node: BinaryNode, incoming_kind: str, exc: Exception) -> None:
        if incoming_kind != "message" or not self.config.get("auto_retry_on_decrypt_fail", True):
            return

        message_id = node.attrs.get("id", "")
        from_jid = node.attrs.get("from", "")
        participant = node.attrs.get("participant") if isinstance(node.attrs.get("participant"), str) else None
        retry_key = f"{from_jid}:{message_id}"
        attempt = self.decrypt_retry_manager.register_retry(retry_key)
        should_send = self.decrypt_retry_manager.should_retry(retry_key)

        sent = False
        if should_send and message_id and from_jid:
            retry_node = build_retry_receipt_node(node, retry_count=attempt)
            try:
                await self.send_node(retry_node)
                sent = True
            except Exception as send_exc:  # pragma: no cover - network dependent
                logger.debug("failed to send retry receipt for %s: %s", message_id, send_exc)

        placeholder_sent = False
        placeholder_error: str | None = None
        if (
            should_send
            and message_id
            and from_jid
            and self.config.get("enable_placeholder_resend", True)
        ):
            placeholder_node = build_placeholder_resend_request(
                message_id=message_id,
                remote_jid=from_jid,
                participant=participant,
            )
            try:
                await self.send_node(placeholder_node)
                placeholder_sent = True
            except Exception as send_exc:  # pragma: no cover - network dependent
                placeholder_error = str(send_exc)
                logger.debug("failed to send placeholder resend for %s: %s", message_id, send_exc)

        await self.on_event(
            {
                "type": "messages.retry_request_sent",
                "retry_request": {
                    "id": message_id,
                    "to": from_jid,
                    "count": attempt,
                    "sent": sent,
                    "placeholder_sent": placeholder_sent,
                    "placeholder_error": placeholder_error,
                    "error": str(exc),
                },
            }
        )

    def _annotate_retry_request_event(self, event: dict[str, Any]) -> None:
        receipt = event.get("receipt")
        if not isinstance(receipt, dict):
            return

        from_jid = receipt.get("participant") or receipt.get("from") or ""
        message_ids = receipt.get("message_ids")
        if not isinstance(message_ids, list):
            message_ids = []

        retry_decisions: dict[str, bool] = {}
        retry_attempts: dict[str, int] = {}
        for message_id in message_ids:
            if not isinstance(message_id, str) or not message_id:
                continue
            key = f"{from_jid}:{message_id}"
            attempt = self.retry_manager.register_retry(key)
            retry_attempts[message_id] = attempt
            retry_decisions[message_id] = self.retry_manager.should_retry(key)

        event["retry_decisions"] = retry_decisions
        event["retry_attempts"] = retry_attempts
        event["retry_allowed"] = any(retry_decisions.values()) if retry_decisions else False

    async def _attempt_retry_resend(self, event: dict[str, Any]) -> None:
        receipt = event.get("receipt")
        if not isinstance(receipt, dict):
            return

        message_ids = receipt.get("message_ids")
        if not isinstance(message_ids, list):
            message_ids = []

        retry_decisions = event.get("retry_decisions")
        if not isinstance(retry_decisions, dict):
            retry_decisions = {}

        from_jid = receipt.get("from") if isinstance(receipt.get("from"), str) else ""
        participant = receipt.get("participant") if isinstance(receipt.get("participant"), str) else None
        placeholder_on_retry = bool(
            self.config.get("placeholder_resend_on_retry", self.config.get("enable_placeholder_resend", True))
        )

        outcome: dict[str, list[str]] = {
            "attempted_ids": [],
            "sent_ids": [],
            "missing_ids": [],
            "failed_ids": [],
            "skipped_ids": [],
            "placeholder_attempted_ids": [],
            "placeholder_sent_ids": [],
            "placeholder_failed_ids": [],
        }
        for raw_message_id in message_ids:
            if not isinstance(raw_message_id, str) or not raw_message_id:
                continue
            if not bool(retry_decisions.get(raw_message_id)):
                outcome["skipped_ids"].append(raw_message_id)
                continue

            outcome["attempted_ids"].append(raw_message_id)
            if placeholder_on_retry and from_jid:
                outcome["placeholder_attempted_ids"].append(raw_message_id)
                placeholder_node = build_placeholder_resend_request(
                    message_id=raw_message_id,
                    remote_jid=from_jid,
                    participant=participant,
                )
                try:
                    await self.send_node(placeholder_node)
                except Exception:  # pragma: no cover - network dependent
                    outcome["placeholder_failed_ids"].append(raw_message_id)
                else:
                    outcome["placeholder_sent_ids"].append(raw_message_id)

            cached_node = self._recent_sent_messages.get(raw_message_id)
            if cached_node is None:
                retry_cached = self.retry_manager.get_recent_message_by_id(raw_message_id)
                if isinstance(retry_cached, dict):
                    cached_candidate = retry_cached.get("message")
                    if isinstance(cached_candidate, BinaryNode):
                        cached_node = copy.deepcopy(cached_candidate)
            if cached_node is None:
                outcome["missing_ids"].append(raw_message_id)
                continue

            try:
                await self.send_node(copy.deepcopy(cached_node))
            except Exception:  # pragma: no cover - network dependent
                outcome["failed_ids"].append(raw_message_id)
            else:
                outcome["sent_ids"].append(raw_message_id)

        event["retry_resend"] = outcome

    async def _maybe_send_ack(self, node: BinaryNode) -> None:
        if not self.is_connected or not self.noise:
            return
        try:
            await self.send_node(build_message_ack(node))
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.debug("failed to send ack for %s: %s", node.tag, exc)

    def _remember_sent_message(self, node: BinaryNode) -> None:
        if node.tag != "message":
            return

        message_id = node.attrs.get("id")
        if not message_id:
            return

        cached = copy.deepcopy(node)
        self._recent_sent_messages[message_id] = cached
        self.retry_manager.add_recent_message(node.attrs.get("to", ""), message_id, cached)
        max_recent = int(self.config.get("max_recent_sent_messages", 200))
        while len(self._recent_sent_messages) > max_recent:
            oldest = next(iter(self._recent_sent_messages))
            self._recent_sent_messages.pop(oldest, None)

    async def _handle_pair_device(self, stanza: BinaryNode) -> None:
        await self.send_node(
            BinaryNode(
                tag="iq",
                attrs={
                    "to": S_WHATSAPP_NET,
                    "type": "result",
                    "id": stanza.attrs.get("id", ""),
                },
            )
        )

        pair_device_node = self._get_child(stanza, "pair-device")
        if not pair_device_node or not self.creds:
            return
        refs: list[str] = []
        for ref_node in self._get_children(pair_device_node, "ref"):
            if isinstance(ref_node.content, (bytes, bytearray)):
                refs.append(bytes(ref_node.content).decode("utf-8", errors="ignore"))
            elif isinstance(ref_node.content, str):
                refs.append(ref_node.content)

        if not refs:
            return

        if self._qr_task:
            self._qr_task.cancel()
        self._qr_task = asyncio.create_task(self._emit_qr_loop(refs))

    async def _handle_pair_success(self, stanza: BinaryNode) -> None:
        if not self.creds:
            return
        await self.on_connection_update(ConnectionEvent(status="pairing-success"))
        pair_success_node = self._get_child(stanza, "pair-success")
        if pair_success_node is None:
            return

        device_identity_node = self._get_child(pair_success_node, "device-identity")
        device_node = self._get_child(pair_success_node, "device")
        platform_node = self._get_child(pair_success_node, "platform")
        business_node = self._get_child(pair_success_node, "biz")
        if not device_identity_node or not device_node:
            return
        if not isinstance(device_identity_node.content, (bytes, bytearray)):
            return

        signed_hmac = ADVSignedDeviceIdentityHMAC.ParseFromString(bytes(device_identity_node.content))
        details = signed_hmac.details or b""
        sig_hmac = signed_hmac.hmac or b""

        prefix = (
            WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
            if signed_hmac.account_type == ADVSignedDeviceIdentityHMAC.ADVEncryptionType.HOSTED
            else b""
        )
        adv_secret = base64.b64decode(self.creds.adv_secret_key.encode("utf-8"))
        expected_hmac = hmac_sha256(adv_secret, prefix + details)
        if sig_hmac and expected_hmac != sig_hmac:
            logger.warning("pair-success hmac validation failed; continuing for compatibility")

        account = ADVSignedDeviceIdentity.ParseFromString(details)
        if not account.details or not account.account_signature_key:
            return

        device_identity = ADVDeviceIdentity.ParseFromString(account.details)
        account_prefix = (
            WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
            if device_identity.device_type == ADVDeviceIdentity.ADVEncryptionType.HOSTED
            else WA_ADV_ACCOUNT_SIG_PREFIX
        )
        account_msg = account_prefix + account.details + self.creds.signed_identity_key["public"]
        if account.account_signature and not verify(
            account.account_signature_key, account_msg, account.account_signature
        ):
            logger.warning("account signature verification failed; continuing for compatibility")

        device_msg = (
            WA_ADV_DEVICE_SIG_PREFIX
            + account.details
            + self.creds.signed_identity_key["public"]
            + account.account_signature_key
        )
        account.device_signature = sign(self.creds.signed_identity_key["private"], device_msg)
        account_encoded = account.SerializeToString(include_signature_key=False)

        await self.send_node(
            BinaryNode(
                tag="iq",
                attrs={
                    "to": S_WHATSAPP_NET,
                    "type": "result",
                    "id": stanza.attrs.get("id", ""),
                },
                content=[
                    BinaryNode(
                        tag="pair-device-sign",
                        attrs={},
                        content=[
                            BinaryNode(
                                tag="device-identity",
                                attrs={"key-index": str(device_identity.key_index or 0)},
                                content=account_encoded,
                            )
                        ],
                    )
                ],
            )
        )

        jid = device_node.attrs.get("jid")
        lid = device_node.attrs.get("lid")
        biz_name = business_node.attrs.get("name") if business_node else None
        self.creds.account = {
            "details": base64.b64encode(account.details).decode("utf-8"),
            "account_signature_key": base64.b64encode(account.account_signature_key).decode("utf-8"),
            "account_signature": base64.b64encode(account.account_signature or b"").decode("utf-8"),
            "device_signature": base64.b64encode(account.device_signature or b"").decode("utf-8"),
        }
        if jid:
            self.creds.me = {"id": jid, "name": biz_name, "lid": lid}
        if platform_node:
            self.creds.platform = platform_node.attrs.get("name")
        self.creds.registered = True
        await self.storage.save_creds(self.creds)
        await self.on_connection_update(ConnectionEvent(status="pairing-signed"))

    async def _handle_success(self, node: BinaryNode) -> None:
        self.is_authenticated = True
        self._restart_attempts = 0
        self._update_server_time_offset(node)
        if self._qr_task:
            self._qr_task.cancel()
            self._qr_task = None

        if self.creds:
            lid = node.attrs.get("lid")
            if lid and self.creds.me:
                self.creds.me["lid"] = lid
            self.creds.registered = True
            await self.storage.save_creds(self.creds)

        await self._send_passive_iq("active")
        await self.on_connection_update(ConnectionEvent(status="open", qr=None))
        await self._send_unified_session()
        self._start_keepalive()

    async def _emit_qr_loop(self, refs: list[str]) -> None:
        if not self.creds:
            return
        noise_key_b64 = base64.b64encode(self.creds.noise_key["public"]).decode("utf-8")
        identity_key_b64 = base64.b64encode(self.creds.signed_identity_key["public"]).decode("utf-8")
        adv_b64 = self.creds.adv_secret_key

        initial_timeout = float(self.config["qr_timeout"])
        next_timeout = 20.0
        for idx, ref in enumerate(refs):
            qr = ",".join((ref, noise_key_b64, identity_key_b64, adv_b64))
            await self.on_connection_update(ConnectionEvent(status="connecting", qr=qr))
            if idx >= len(refs) - 1:
                return
            try:
                await asyncio.sleep(initial_timeout if idx == 0 else next_timeout)
            except asyncio.CancelledError:
                return

    async def _handle_ib_node(self, node: BinaryNode) -> None:
        if self._requested_offline_batch:
            return
        if node.attrs.get("from") != S_WHATSAPP_NET:
            return
        if self._get_child(node, "offline_preview") is not None:
            await self._send_offline_batch_request()

    async def _send_passive_iq(self, mode: str) -> None:
        if not self.is_connected or not self.noise:
            return
        try:
            await self.send_node(
                BinaryNode(
                    tag="iq",
                    attrs={"to": S_WHATSAPP_NET, "xmlns": "passive", "type": "set"},
                    content=[BinaryNode(tag=mode, attrs={})],
                )
            )
        except Exception as exc:  # pragma: no cover - network dependent
            logger.debug("failed to send passive iq %s: %s", mode, exc)

    def _get_unified_session_id(self) -> str:
        offset_ms = 3 * 24 * 60 * 60 * 1000
        now_ms = int(time.time() * 1000) + self._server_time_offset_ms
        week_ms = 7 * 24 * 60 * 60 * 1000
        return str((now_ms + offset_ms) % week_ms)

    async def _send_unified_session(self) -> None:
        if not self.is_connected or not self.noise:
            return
        try:
            await self.send_node(
                BinaryNode(
                    tag="ib",
                    attrs={},
                    content=[BinaryNode(tag="unified_session", attrs={"id": self._get_unified_session_id()})],
                )
            )
        except Exception as exc:  # pragma: no cover - network dependent
            logger.debug("failed to send unified_session telemetry: %s", exc)

    async def _send_offline_batch_request(self) -> None:
        if not self.is_connected or not self.noise or self._requested_offline_batch:
            return
        try:
            await self.send_node(
                BinaryNode(
                    tag="ib",
                    attrs={},
                    content=[BinaryNode(tag="offline_batch", attrs={"count": "100"})],
                )
            )
            self._requested_offline_batch = True
        except Exception as exc:  # pragma: no cover - network dependent
            logger.debug("failed to send offline_batch request: %s", exc)

    def _update_server_time_offset(self, node: BinaryNode) -> None:
        t_value = node.attrs.get("t")
        if t_value is None:
            return
        try:
            parsed = int(str(t_value))
        except ValueError:
            return
        if parsed <= 0:
            return
        local_ms = int(time.time() * 1000)
        self._server_time_offset_ms = parsed * 1000 - local_ms

    def _start_keepalive(self) -> None:
        if self._keepalive_task:
            return

        async def _loop() -> None:
            interval = float(self.config["keepalive_interval"])
            while self.is_connected and self.is_transport_connected:
                await asyncio.sleep(interval)
                if not self.is_authenticated:
                    continue
                try:
                    await self.send_ping()
                except Exception as exc:  # pragma: no cover - network dependent
                    logger.warning("keepalive ping failed: %s", exc)
                    return

        self._keepalive_task = asyncio.create_task(_loop())

    def _generate_login_payload(self, user_jid: str) -> ClientPayload:
        jid = jid_decode(user_jid)
        if not jid:
            raise ValueError(f"invalid jid for login payload: {user_jid}")
        return ClientPayload(
            username=int(jid.user),
            passive=False,
            pull=True,
            lid_db_migrated=False,
            device=jid.device,
            connect_type=ClientPayload.ConnectType.WIFI_UNKNOWN,
            connect_reason=ClientPayload.ConnectReason.USER_ACTIVATED,
            user_agent=self._build_user_agent(),
            web_info=self._build_web_info(),
        )

    def _generate_registration_payload(self) -> ClientPayload:
        assert self.creds is not None
        build_hash = hashlib.md5(".".join(str(v) for v in self.config["version"]).encode("utf-8")).digest()
        device_props = DeviceProps(
            os=self.config["browser"][0],
            platform_type=_platform_type_from_browser(self.config["browser"][1]),
            require_full_sync=True,
            history_sync_config=HistorySyncConfig(
                storage_quota_mb=10240,
                inline_initial_payload_in_e2ee_msg=True,
                support_call_log_history=False,
                support_bot_user_agent_chat_history=True,
                support_cag_reactions_and_polls=True,
                support_biz_hosted_msg=True,
                support_recent_sync_chunk_message_count_tuning=True,
                support_hosted_group_msg=True,
                support_fbid_bot_chat_history=True,
                support_message_association=True,
                support_group_history=False,
            ),
            version=DevicePropsAppVersion(primary=10, secondary=15, tertiary=7),
        ).SerializeToString()

        pairing_data = DevicePairingRegistrationData(
            e_regid=_encode_big_endian(self.creds.registration_id),
            e_keytype=KEY_BUNDLE_TYPE,
            e_ident=self.creds.signed_identity_key["public"],
            e_skey_id=_encode_big_endian(self.creds.signed_pre_key["keyId"], 3),
            e_skey_val=self.creds.signed_pre_key["keyPair"]["public"],
            e_skey_sig=self.creds.signed_pre_key["signature"],
            build_hash=build_hash,
            device_props=device_props,
        )
        return ClientPayload(
            passive=False,
            pull=False,
            connect_type=ClientPayload.ConnectType.WIFI_UNKNOWN,
            connect_reason=ClientPayload.ConnectReason.USER_ACTIVATED,
            user_agent=self._build_user_agent(),
            web_info=self._build_web_info(),
            device_pairing_data=pairing_data,
        )

    def _build_user_agent(self) -> UserAgent:
        version = self.config["version"]
        return UserAgent(
            platform=UserAgent.Platform.WEB,
            app_version=AppVersion(
                primary=int(version[0]),
                secondary=int(version[1]),
                tertiary=int(version[2]),
            ),
            os_version="0.1",
            device="Desktop",
            os_build_number="0.1",
            release_channel=UserAgent.ReleaseChannel.RELEASE,
            locale_language_iso6391="en",
            locale_country_iso31661_alpha2=str(self.config["country_code"]),
            mcc="000",
            mnc="000",
        )

    def _build_web_info(self) -> WebInfo:
        os_name = self.config["browser"][0]
        sub_platform = WebInfo.WebSubPlatform.WEB_BROWSER
        if os_name == "Mac OS":
            sub_platform = WebInfo.WebSubPlatform.DARWIN
        elif os_name == "Windows":
            sub_platform = WebInfo.WebSubPlatform.WIN32
        return WebInfo(web_sub_platform=sub_platform)

    def _generate_message_tag(self) -> str:
        tag = f"{self._epoch}"
        self._epoch += 1
        return tag

    async def _handle_ws_disconnect(self, exc: Exception) -> None:
        reason = self._pending_disconnect_reason or exc
        self._pending_disconnect_reason = None
        self.is_transport_connected = False
        self.is_connected = False
        self.is_authenticated = False
        if self._qr_task:
            self._qr_task.cancel()
            self._qr_task = None
        if self._keepalive_task:
            self._keepalive_task.cancel()
            self._keepalive_task = None
        await self.on_connection_update(ConnectionEvent(status="close", reason=reason))
        if self._should_auto_restart(reason):
            self._restart_attempts += 1
            logger.info(
                "stream restart required; reconnecting (%s/%s)",
                self._restart_attempts,
                int(self.config["max_restart_attempts"]),
            )
            try:
                await self.connect()
                return
            except Exception as reconnect_exc:
                reason = reconnect_exc
        self._explicit_disconnect = False
        await self.on_disconnected(reason)

    async def _refresh_unregistered_creds(self) -> None:
        """Refresh pre-key signatures for non-registered sessions.

        Older waton builds generated signatures with a non-Baileys-compatible
        routine. Re-signing here avoids forcing users to delete DB files.
        """
        if not self.creds or self.creds.registered:
            return

        key_pair = self.creds.signed_pre_key.get("keyPair", {})
        prekey_public = key_pair.get("public")
        identity_private = self.creds.signed_identity_key.get("private")
        if isinstance(prekey_public, bytes) and isinstance(identity_private, bytes):
            self.creds.signed_pre_key["signature"] = sign(identity_private, b"\x05" + prekey_public)
            await self.storage.save_creds(self.creds)

    @staticmethod
    def _children(node: BinaryNode) -> list[BinaryNode]:
        if isinstance(node.content, list):
            return node.content
        return []

    @classmethod
    def _get_child(cls, node: BinaryNode, tag: str) -> BinaryNode | None:
        for child in cls._children(node):
            if child.tag == tag:
                return child
        return None

    @classmethod
    def _get_children(cls, node: BinaryNode, tag: str) -> list[BinaryNode]:
        return [child for child in cls._children(node) if child.tag == tag]

    @classmethod
    def _stream_error_to_exception(cls, node: BinaryNode) -> WatonConnectionError:
        reason_node = cls._children(node)[0] if cls._children(node) else None
        reason = reason_node.tag if reason_node else "unknown"
        code = node.attrs.get("code")
        if code is not None and str(code).isdigit():
            status_code = int(str(code))
        else:
            status_code = int(
                DisconnectReason.CONNECTION_REPLACED if reason == "conflict" else DisconnectReason.BAD_SESSION
            )
        if status_code == int(DisconnectReason.RESTART_REQUIRED):
            reason = "restart required"
        return WatonConnectionError(f"Stream Errored ({reason})", status_code=status_code)

    def _should_auto_restart(self, reason: Exception) -> bool:
        if self._explicit_disconnect:
            return False
        if not self.config.get("auto_restart_on_515", True):
            return False
        if not isinstance(reason, WatonConnectionError):
            return False
        if reason.status_code != int(DisconnectReason.RESTART_REQUIRED):
            return False
        return self._restart_attempts < int(self.config["max_restart_attempts"])

    @staticmethod
    def _failure_to_exception(node: BinaryNode) -> WatonConnectionError:
        reason = node.attrs.get("reason")
        if reason is not None and str(reason).isdigit():
            status_code = int(str(reason))
        else:
            status_code = int(DisconnectReason.BAD_SESSION)
        return WatonConnectionError("Connection Failure", status_code=status_code)

    async def _default_message_handler(self, node: BinaryNode) -> None:
        logger.debug("received node: %s", node.tag)

    async def _default_event_handler(self, event: dict[str, Any]) -> None:
        logger.debug("received event: %s", event.get("type"))

    async def _default_disconnect_handler(self, exc: Exception) -> None:
        logger.debug("disconnected: %s", exc)

    async def _default_connection_handler(self, event: ConnectionEvent) -> None:
        logger.info("connection update: %s", event)

    async def send_message(self, jid: str, message: dict) -> str:
        msg_id = message.get("id", "generated-id")
        if hasattr(self, "pipeline"):
            await self.pipeline.process({"type": "message.send", "id": msg_id, "jid": jid})
        return msg_id
