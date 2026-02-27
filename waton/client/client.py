"""Low-level WhatsApp socket client."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from waton.core.errors import ConnectionError, DisconnectReason
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
from waton.client.messages_recv import classify_incoming_node
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
from waton.utils.auth import AuthCreds, StoragePort, init_auth_creds
from waton.utils.crypto import generate_keypair, hmac_sha256, sign, verify

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

    def __init__(self, storage: StoragePort, ws_url: str | None = None, **config_overrides: Any):
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
        self.on_disconnected: Callable[[Exception], Awaitable[None]] = self._default_disconnect_handler
        self.on_connection_update: Callable[[ConnectionEvent], Awaitable[None]] = self._default_connection_handler

        self.ws.on_message = self._handle_raw_ws_message
        self.ws.on_disconnect = self._handle_ws_disconnect

        self._raw_frame_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._pending_queries: dict[str, asyncio.Future[BinaryNode]] = {}
        self._epoch = 1
        self._qr_task: asyncio.Task[None] | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._pending_disconnect_reason: ConnectionError | None = None
        self._restart_attempts = 0
        self._explicit_disconnect = False

    async def connect(self) -> None:
        self._explicit_disconnect = False
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
            raise ConnectionError("Cannot send node: not connected")
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

        for frame in frames:
            if isinstance(frame, bytes):
                await self._raw_frame_queue.put(frame)
            else:
                await self._handle_binary_node(frame)

    async def _handle_binary_node(self, node: BinaryNode) -> None:
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

        await self.on_message(node)

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
        if account.account_signature and not verify(account.account_signature_key, account_msg, account.account_signature):
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
        if self._qr_task:
            self._qr_task.cancel()
            self._qr_task = None

        if self.creds:
            lid = node.attrs.get("lid")
            if lid and self.creds.me:
                self.creds.me["lid"] = lid
            self.creds.registered = True
            await self.storage.save_creds(self.creds)

        await self.on_connection_update(ConnectionEvent(status="open", qr=None))
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
            passive=True,
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
    def _stream_error_to_exception(cls, node: BinaryNode) -> ConnectionError:
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
        return ConnectionError(f"Stream Errored ({reason})", status_code=status_code)

    def _should_auto_restart(self, reason: Exception) -> bool:
        if self._explicit_disconnect:
            return False
        if not self.config.get("auto_restart_on_515", True):
            return False
        if not isinstance(reason, ConnectionError):
            return False
        if reason.status_code != int(DisconnectReason.RESTART_REQUIRED):
            return False
        return self._restart_attempts < int(self.config["max_restart_attempts"])

    @staticmethod
    def _failure_to_exception(node: BinaryNode) -> ConnectionError:
        reason = node.attrs.get("reason")
        if reason is not None and str(reason).isdigit():
            status_code = int(str(reason))
        else:
            status_code = int(DisconnectReason.BAD_SESSION)
        return ConnectionError("Connection Failure", status_code=status_code)

    async def _default_message_handler(self, node: BinaryNode) -> None:
        logger.debug("received node: %s", node.tag)

    async def _default_disconnect_handler(self, exc: Exception) -> None:
        logger.debug("disconnected: %s", exc)

    async def _default_connection_handler(self, event: ConnectionEvent) -> None:
        logger.info("connection update: %s", event)
