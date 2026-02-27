from __future__ import annotations

from base64 import b64decode
import struct
from typing import TYPE_CHECKING
import os
import time

from waton.core.jid import S_WHATSAPP_NET, jid_normalized_user, jid_decode, jid_encode
from waton.protocol.binary_node import BinaryNode
from waton.protocol.protobuf import wa_pb2
from waton.protocol.protobuf.wire import (
    ADVSignedDeviceIdentity,
    _encode_bool,
    _encode_len_delimited,
    _encode_string,
    _encode_varint,
    _encode_varint_field,
)
from waton.protocol.signal_repo import SignalRepository
from waton.client.usync import USyncQuery
from waton.utils.message_utils import build_receipt_node, generate_message_id
from waton.utils.crypto import aes_encrypt, hmac_sha256

if TYPE_CHECKING:
    from waton.client.client import WAClient


def _write_random_pad_max16(msg: bytes) -> bytes:
    """Pads the message with 1-16 random bytes (PKCS#7 format)."""
    pad_len = (os.urandom(1)[0] & 0x0F) + 1
    pad_bytes = bytes([pad_len] * pad_len)
    return msg + pad_bytes

def _unpad_random_max16(msg: bytes) -> bytes:
    """Removes PKCS#7 padding from the end of a message."""
    if not msg:
        return msg
    pad_len = msg[-1]
    if pad_len == 0 or pad_len > len(msg):
        # invalid padding, but we shouldn't crash, just return msg
        return msg
    # optionally verify all padding bytes are the same
    for i in range(1, pad_len + 1):
        if msg[-i] != pad_len:
            # invalid padding
            return msg
    return msg[:-pad_len]


def _encode_fixed64_field(field_number: int, value: float | None) -> bytes:
    if value is None:
        return b""
    key = _encode_varint((field_number << 3) | 1)
    return key + struct.pack("<d", float(value))


def _encode_message_key(
    *,
    remote_jid: str,
    message_id: str,
    from_me: bool = False,
    participant: str | None = None,
) -> bytes:
    encoded = b"".join(
        (
            _encode_string(1, remote_jid),
            _encode_varint_field(2, 1 if from_me else 0),
            _encode_string(3, message_id),
        )
    )
    if participant:
        encoded += _encode_string(4, participant)
    return encoded


def _derive_message_addon_key(
    *,
    addon_label: str,
    message_id: str,
    creator_jid: str,
    actor_jid: str,
    message_secret: bytes,
) -> bytes:
    sign = b"".join(
        (
            message_id.encode("utf-8"),
            creator_jid.encode("utf-8"),
            actor_jid.encode("utf-8"),
            addon_label.encode("utf-8"),
            b"\x01",
        )
    )
    key0 = hmac_sha256(message_secret, bytes(32))
    return hmac_sha256(sign, key0)


def _encode_poll_vote_plaintext(selected_options: list[bytes]) -> bytes:
    chunks = []
    for option in selected_options:
        if not option:
            continue
        chunks.append(_encode_len_delimited(1, option))
    return b"".join(chunks)


def _encode_event_response_plaintext(
    *,
    response_type: int,
    timestamp_ms: int,
    extra_guest_count: int | None = None,
) -> bytes:
    payload = b"".join(
        (
            _encode_varint_field(1, max(0, response_type)),
            _encode_varint_field(2, max(0, timestamp_ms)),
        )
    )
    if extra_guest_count is not None:
        payload += _encode_varint_field(3, max(0, extra_guest_count))
    return payload


class MessagesAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def send_text(self, to_jid: str, text: str) -> str:
        """Sends a simple text message to all devices of recipient."""
        msg = wa_pb2.Message()
        msg.conversation = text
        return await self._send_payload(to_jid, msg.SerializeToString(), message_type="text")

    async def send_image(self, to_jid: str, image_bytes: bytes, caption: str = "") -> str:
        """Uploads and sends an image message to all devices of recipient."""
        from waton.client.media import MediaManager
        media = MediaManager()
        media_info = await media.encrypt_and_upload("image", image_bytes)

        msg = wa_pb2.Message()
        msg.imageMessage.url = str(media_info["url"])
        msg.imageMessage.mimetype = "image/jpeg"
        msg.imageMessage.caption = caption
        msg.imageMessage.fileSha256 = bytes(media_info["fileSha256"])
        msg.imageMessage.fileEncSha256 = bytes(media_info["fileEncSha256"])
        msg.imageMessage.mediaKey = bytes(media_info["mediaKey"])
        msg.imageMessage.fileLength = len(image_bytes)
        return await self._send_payload(to_jid, msg.SerializeToString(), message_type="media")

    async def send_document(
        self,
        to_jid: str,
        document_bytes: bytes,
        *,
        file_name: str = "file",
        mimetype: str = "application/octet-stream",
        caption: str = "",
    ) -> str:
        """Uploads and sends a document message to all devices of recipient."""
        from waton.client.media import MediaManager

        media = MediaManager()
        media_info = await media.encrypt_and_upload("document", document_bytes)
        payload = self._build_document_payload(
            media_info=media_info,
            file_name=file_name,
            mimetype=mimetype,
            caption=caption,
        )
        return await self._send_payload(to_jid, payload, message_type="document")

    async def send_location(
        self,
        to_jid: str,
        *,
        latitude: float,
        longitude: float,
        name: str = "",
        address: str = "",
        url: str = "",
        comment: str = "",
    ) -> str:
        """Sends a location message to all recipient devices."""
        payload = self._build_location_payload(
            latitude=latitude,
            longitude=longitude,
            name=name,
            address=address,
            url=url,
            comment=comment,
        )
        return await self._send_payload(to_jid, payload, message_type="location")

    async def send_audio(
        self,
        to_jid: str,
        audio_bytes: bytes,
        *,
        mimetype: str = "audio/ogg; codecs=opus",
        seconds: int = 0,
        ptt: bool = False,
    ) -> str:
        """Uploads and sends an audio message to all devices of recipient."""
        from waton.client.media import MediaManager

        media = MediaManager()
        media_info = await media.encrypt_and_upload("audio", audio_bytes)
        payload = self._build_audio_payload(
            media_info=media_info,
            mimetype=mimetype,
            seconds=seconds,
            ptt=ptt,
        )
        return await self._send_payload(to_jid, payload, message_type="audio")

    async def send_video(
        self,
        to_jid: str,
        video_bytes: bytes,
        *,
        mimetype: str = "video/mp4",
        caption: str = "",
        seconds: int = 0,
        height: int = 0,
        width: int = 0,
        gif_playback: bool = False,
    ) -> str:
        """Uploads and sends a video message to all devices of recipient."""
        from waton.client.media import MediaManager

        media = MediaManager()
        media_info = await media.encrypt_and_upload("video", video_bytes)
        payload = self._build_video_payload(
            media_info=media_info,
            mimetype=mimetype,
            caption=caption,
            seconds=seconds,
            height=height,
            width=width,
            gif_playback=gif_playback,
        )
        return await self._send_payload(to_jid, payload, message_type="video")

    async def send_sticker(
        self,
        to_jid: str,
        sticker_bytes: bytes,
        *,
        mimetype: str = "image/webp",
        height: int = 0,
        width: int = 0,
        is_animated: bool = False,
    ) -> str:
        """Uploads and sends a sticker message to all devices of recipient."""
        from waton.client.media import MediaManager

        media = MediaManager()
        media_info = await media.encrypt_and_upload("sticker", sticker_bytes)
        payload = self._build_sticker_payload(
            media_info=media_info,
            mimetype=mimetype,
            height=height,
            width=width,
            is_animated=is_animated,
        )
        return await self._send_payload(to_jid, payload, message_type="sticker")

    async def send_contact(self, to_jid: str, *, display_name: str, vcard: str) -> str:
        """Sends a contact message to all devices of recipient."""
        payload = self._build_contact_payload(display_name=display_name, vcard=vcard)
        return await self._send_payload(to_jid, payload, message_type="contact")

    async def send_poll_creation(
        self,
        to_jid: str,
        *,
        name: str,
        options: list[str],
        selectable_options_count: int = 1,
        enc_key: bytes | None = None,
        message_secret: bytes | None = None,
    ) -> str:
        """Sends a poll creation message to all devices of recipient."""
        payload = self._build_poll_creation_payload(
            name=name,
            options=options,
            selectable_options_count=selectable_options_count,
            enc_key=enc_key or os.urandom(32),
            message_secret=message_secret or os.urandom(32),
        )
        return await self._send_payload(to_jid, payload, message_type="poll")

    async def send_delete(
        self,
        to_jid: str,
        target_message_id: str,
        *,
        participant: str | None = None,
        from_me: bool = False,
    ) -> str:
        """Send protocol revoke for a target message."""
        payload = self._build_protocol_revoke_payload(
            remote_jid=to_jid,
            target_message_id=target_message_id,
            participant=participant,
            from_me=from_me,
        )
        return await self._send_payload(to_jid, payload, message_type="protocol")

    async def send_edit(
        self,
        to_jid: str,
        target_message_id: str,
        text: str,
        *,
        participant: str | None = None,
        from_me: bool = False,
        edited_at_ms: int | None = None,
    ) -> str:
        """Send protocol message edit for a previously sent/received message."""
        payload = self._build_protocol_edit_payload(
            remote_jid=to_jid,
            target_message_id=target_message_id,
            text=text,
            participant=participant,
            from_me=from_me,
            edited_at_ms=edited_at_ms,
        )
        return await self._send_payload(to_jid, payload, message_type="protocol")

    async def send_ephemeral_setting(
        self,
        to_jid: str,
        *,
        expiration_seconds: int,
        setting_timestamp: int | None = None,
    ) -> str:
        """Send protocol ephemeral setting update."""
        payload = self._build_protocol_ephemeral_setting_payload(
            remote_jid=to_jid,
            expiration_seconds=expiration_seconds,
            setting_timestamp=setting_timestamp,
        )
        return await self._send_payload(to_jid, payload, message_type="protocol")

    async def send_poll_vote(
        self,
        to_jid: str,
        *,
        poll_creation_message_id: str,
        poll_creator_jid: str,
        selected_options: list[bytes],
        message_secret: bytes,
        voter_jid: str | None = None,
        sender_timestamp_ms: int | None = None,
    ) -> str:
        """Send encrypted poll vote update message."""
        actor_jid = voter_jid or (self.client.creds.me["id"] if self.client.creds and self.client.creds.me else "")
        if not actor_jid:
            raise ValueError("missing voter identity")
        payload = self._build_poll_vote_update_payload(
            remote_jid=to_jid,
            poll_creation_message_id=poll_creation_message_id,
            poll_creator_jid=poll_creator_jid,
            voter_jid=actor_jid,
            selected_options=selected_options,
            message_secret=message_secret,
            sender_timestamp_ms=sender_timestamp_ms,
        )
        return await self._send_payload(to_jid, payload, message_type="poll_update")

    async def send_event_response(
        self,
        to_jid: str,
        *,
        event_creation_message_id: str,
        event_creator_jid: str,
        response_type: int,
        message_secret: bytes,
        responder_jid: str | None = None,
        timestamp_ms: int | None = None,
        extra_guest_count: int | None = None,
    ) -> str:
        """Send encrypted event response message."""
        actor_jid = (
            responder_jid or (self.client.creds.me["id"] if self.client.creds and self.client.creds.me else "")
        )
        if not actor_jid:
            raise ValueError("missing responder identity")
        payload = self._build_event_response_update_payload(
            remote_jid=to_jid,
            event_creation_message_id=event_creation_message_id,
            event_creator_jid=event_creator_jid,
            responder_jid=actor_jid,
            response_type=response_type,
            message_secret=message_secret,
            timestamp_ms=timestamp_ms,
            extra_guest_count=extra_guest_count,
        )
        return await self._send_payload(to_jid, payload, message_type="event_response")

    async def send_reaction(self, to_jid: str, message_id: str, reaction: str) -> str:
        """Reacts to a message with an emoji."""
        msg = wa_pb2.Message()
        msg.reactionMessage.key.id = message_id
        msg.reactionMessage.key.remoteJid = to_jid
        msg.reactionMessage.text = reaction

        msg_id = generate_message_id("reaction_")

        node = BinaryNode(
            tag="message",
            attrs={"to": to_jid, "id": msg_id, "type": "reaction"},
            content=msg.SerializeToString()
        )
        await self.client.send_node(node)
        return msg_id

    async def send_receipt(
        self,
        jid: str,
        participant: str | None,
        message_ids: list[str],
        receipt_type: str = "read",
    ) -> None:
        """Sends delivery or read receipts for messages."""
        node = build_receipt_node(jid, message_ids, participant=participant, receipt_type=receipt_type)
        await self.client.send_node(node)

    async def send_receipts_batch(
        self,
        keys: list[dict[str, str | None]],
        *,
        receipt_type: str = "read",
    ) -> None:
        """Aggregate message keys into receipts by chat/participant."""
        grouped: dict[tuple[str, str | None], list[str]] = {}
        for key in keys:
            remote_jid = key.get("remote_jid")
            message_id = key.get("id")
            participant = key.get("participant")
            if not isinstance(remote_jid, str) or not remote_jid:
                continue
            if not isinstance(message_id, str) or not message_id:
                continue
            group_key = (remote_jid, participant if isinstance(participant, str) and participant else None)
            grouped.setdefault(group_key, []).append(message_id)

        for (remote_jid, participant), message_ids in grouped.items():
            await self.send_receipt(
                jid=remote_jid,
                participant=participant,
                message_ids=message_ids,
                receipt_type=receipt_type,
            )

    async def read_messages(self, keys: list[dict[str, str | None]], *, read_self: bool = False) -> None:
        """Send read/read-self receipts for message keys."""
        await self.send_receipts_batch(keys, receipt_type="read-self" if read_self else "read")

    async def _send_payload(self, to_jid: str, payload: bytes, *, message_type: str) -> str:
        if not self.client.creds or not self.client.creds.me:
            raise ValueError("client is not authenticated")

        signal_repo = SignalRepository(self.client.creds, self.client.storage)
        usync = USyncQuery(self.client)

        target_jid = jid_normalized_user(to_jid)
        me_jid = jid_normalized_user(self.client.creds.me["id"])
        all_device_jids = await self._collect_target_devices(signal_repo, usync, target_jid, me_jid)
        await self._assert_sessions(signal_repo, all_device_jids)

        device_sent_payload = self._build_device_sent_payload(target_jid, payload)

        participants: list[BinaryNode] = []
        include_device_identity = False

        for device_jid in all_device_jids:
            decoded = jid_decode(device_jid)
            if not decoded:
                continue

            is_own_device = jid_normalized_user(device_jid) == me_jid
            plain_payload = device_sent_payload if (is_own_device and me_jid != target_jid) else payload
            padded_payload = _write_random_pad_max16(plain_payload)

            msg_type, ciphertext = await signal_repo.encrypt_message(device_jid, padded_payload)
            if msg_type == "pkmsg":
                include_device_identity = True

            participants.append(
                BinaryNode(
                    tag="to",
                    attrs={"jid": device_jid},
                    content=[
                        BinaryNode(
                            tag="enc",
                            attrs={"v": "2", "type": msg_type},
                            content=ciphertext,
                        )
                    ],
                )
            )

        msg_id = generate_message_id()
        content: list[BinaryNode] = [BinaryNode(tag="participants", attrs={}, content=participants)]
        if include_device_identity:
            content.append(BinaryNode(tag="device-identity", attrs={}, content=self._encode_device_identity()))

        node = BinaryNode(
            tag="message",
            attrs={"to": target_jid, "id": msg_id, "type": message_type},
            content=content,
        )
        await self.client.send_node(node)
        return msg_id

    async def _collect_target_devices(
        self,
        signal_repo: SignalRepository,
        usync: USyncQuery,
        target_jid: str,
        me_jid: str,
    ) -> list[str]:
        jids_to_query = [target_jid]
        if me_jid != target_jid:
            jids_to_query.append(me_jid)

        devices_map = await usync.get_devices(jids_to_query)
        all_device_jids: list[str] = []
        for user_jid in jids_to_query:
            decoded = jid_decode(user_jid)
            if not decoded:
                continue
            device_jids = devices_map.get(user_jid, [jid_encode(decoded.user, decoded.server, 0)])
            all_device_jids.extend(device_jids)

        me_device_jid = self.client.creds.me["id"] if self.client.creds and self.client.creds.me else ""
        me_session_key = signal_repo._session_key(me_device_jid)
        return [jid for jid in all_device_jids if signal_repo._session_key(jid) != me_session_key]

    @staticmethod
    def _build_device_sent_payload(destination_jid: str, inner_payload: bytes) -> bytes:
        device_sent_payload = _encode_string(1, destination_jid) + _encode_len_delimited(2, inner_payload)
        return _encode_len_delimited(31, device_sent_payload)

    @staticmethod
    def _build_document_payload(
        *,
        media_info: dict[str, str | bytes | int],
        file_name: str,
        mimetype: str,
        caption: str,
    ) -> bytes:
        url = str(media_info.get("url", ""))
        media_key = bytes(media_info.get("mediaKey", b""))
        file_sha256 = bytes(media_info.get("fileSha256", b""))
        file_enc_sha256 = bytes(media_info.get("fileEncSha256", b""))
        direct_path = str(media_info.get("directPath", ""))
        file_length = int(media_info.get("fileLength", 0))

        document_payload = b"".join(
            (
                _encode_string(1, url),
                _encode_string(2, mimetype),
                _encode_len_delimited(4, file_sha256),
                _encode_varint_field(5, file_length),
                _encode_len_delimited(7, media_key),
                _encode_string(8, file_name),
                _encode_len_delimited(9, file_enc_sha256),
                _encode_string(10, direct_path),
                _encode_string(20, caption),
            )
        )
        return _encode_len_delimited(7, document_payload)

    @staticmethod
    def _build_location_payload(
        *,
        latitude: float,
        longitude: float,
        name: str,
        address: str,
        url: str,
        comment: str,
    ) -> bytes:
        location_payload = b"".join(
            (
                _encode_fixed64_field(1, latitude),
                _encode_fixed64_field(2, longitude),
                _encode_string(3, name),
                _encode_string(4, address),
                _encode_string(5, url),
                _encode_string(11, comment),
            )
        )
        return _encode_len_delimited(5, location_payload)

    @staticmethod
    def _build_audio_payload(
        *,
        media_info: dict[str, str | bytes | int],
        mimetype: str,
        seconds: int,
        ptt: bool,
    ) -> bytes:
        url = str(media_info.get("url", ""))
        media_key = bytes(media_info.get("mediaKey", b""))
        file_sha256 = bytes(media_info.get("fileSha256", b""))
        file_enc_sha256 = bytes(media_info.get("fileEncSha256", b""))
        direct_path = str(media_info.get("directPath", ""))
        file_length = int(media_info.get("fileLength", 0))

        audio_payload = b"".join(
            (
                _encode_string(1, url),
                _encode_string(2, mimetype),
                _encode_len_delimited(3, file_sha256),
                _encode_varint_field(4, file_length),
                _encode_varint_field(5, max(0, seconds)),
                _encode_bool(6, ptt),
                _encode_len_delimited(7, media_key),
                _encode_len_delimited(8, file_enc_sha256),
                _encode_string(9, direct_path),
            )
        )
        return _encode_len_delimited(8, audio_payload)

    @staticmethod
    def _build_video_payload(
        *,
        media_info: dict[str, str | bytes | int],
        mimetype: str,
        caption: str,
        seconds: int,
        height: int,
        width: int,
        gif_playback: bool,
    ) -> bytes:
        url = str(media_info.get("url", ""))
        media_key = bytes(media_info.get("mediaKey", b""))
        file_sha256 = bytes(media_info.get("fileSha256", b""))
        file_enc_sha256 = bytes(media_info.get("fileEncSha256", b""))
        direct_path = str(media_info.get("directPath", ""))
        file_length = int(media_info.get("fileLength", 0))

        video_payload = b"".join(
            (
                _encode_string(1, url),
                _encode_string(2, mimetype),
                _encode_len_delimited(3, file_sha256),
                _encode_varint_field(4, file_length),
                _encode_varint_field(5, max(0, seconds)),
                _encode_len_delimited(6, media_key),
                _encode_string(7, caption),
                _encode_bool(8, gif_playback),
                _encode_varint_field(9, max(0, height)),
                _encode_varint_field(10, max(0, width)),
                _encode_len_delimited(11, file_enc_sha256),
                _encode_string(13, direct_path),
            )
        )
        return _encode_len_delimited(9, video_payload)

    @staticmethod
    def _build_sticker_payload(
        *,
        media_info: dict[str, str | bytes | int],
        mimetype: str,
        height: int,
        width: int,
        is_animated: bool,
    ) -> bytes:
        url = str(media_info.get("url", ""))
        media_key = bytes(media_info.get("mediaKey", b""))
        file_sha256 = bytes(media_info.get("fileSha256", b""))
        file_enc_sha256 = bytes(media_info.get("fileEncSha256", b""))
        direct_path = str(media_info.get("directPath", ""))
        file_length = int(media_info.get("fileLength", 0))

        sticker_payload = b"".join(
            (
                _encode_string(1, url),
                _encode_len_delimited(2, file_sha256),
                _encode_len_delimited(3, file_enc_sha256),
                _encode_len_delimited(4, media_key),
                _encode_string(5, mimetype),
                _encode_varint_field(6, max(0, height)),
                _encode_varint_field(7, max(0, width)),
                _encode_string(8, direct_path),
                _encode_varint_field(9, file_length),
                _encode_bool(13, is_animated),
            )
        )
        return _encode_len_delimited(26, sticker_payload)

    @staticmethod
    def _build_contact_payload(*, display_name: str, vcard: str) -> bytes:
        contact_payload = b"".join(
            (
                _encode_string(1, display_name),
                _encode_string(16, vcard),
            )
        )
        return _encode_len_delimited(4, contact_payload)

    @staticmethod
    def _build_poll_creation_payload(
        *,
        name: str,
        options: list[str],
        selectable_options_count: int,
        enc_key: bytes,
        message_secret: bytes,
    ) -> bytes:
        option_payloads = b"".join(_encode_len_delimited(3, _encode_string(1, option)) for option in options)
        context_info_payload = _encode_len_delimited(3, message_secret)
        poll_payload = b"".join(
            (
                _encode_len_delimited(1, enc_key),
                _encode_string(2, name),
                option_payloads,
                _encode_varint_field(4, max(0, selectable_options_count)),
                _encode_len_delimited(5, context_info_payload),
            )
        )
        return _encode_len_delimited(49, poll_payload)

    @staticmethod
    def _resolve_timestamp_ms(value: int | None) -> int:
        if value is None:
            return int(time.time() * 1000)
        return max(0, int(value))

    @staticmethod
    def _build_protocol_revoke_payload(
        *,
        remote_jid: str,
        target_message_id: str,
        participant: str | None,
        from_me: bool,
    ) -> bytes:
        key_payload = _encode_message_key(
            remote_jid=remote_jid,
            message_id=target_message_id,
            participant=participant,
            from_me=from_me,
        )
        protocol_payload = b"".join(
            (
                _encode_len_delimited(1, key_payload),
                _encode_varint_field(2, 0),
            )
        )
        return _encode_len_delimited(12, protocol_payload)

    @classmethod
    def _build_protocol_edit_payload(
        cls,
        *,
        remote_jid: str,
        target_message_id: str,
        text: str,
        participant: str | None,
        from_me: bool,
        edited_at_ms: int | None,
    ) -> bytes:
        key_payload = _encode_message_key(
            remote_jid=remote_jid,
            message_id=target_message_id,
            participant=participant,
            from_me=from_me,
        )
        edited_message = wa_pb2.Message()
        edited_message.conversation = text
        protocol_payload = b"".join(
            (
                _encode_len_delimited(1, key_payload),
                _encode_varint_field(2, 14),
                _encode_len_delimited(14, edited_message.SerializeToString()),
                _encode_varint_field(15, cls._resolve_timestamp_ms(edited_at_ms)),
            )
        )
        return _encode_len_delimited(12, protocol_payload)

    @classmethod
    def _build_protocol_ephemeral_setting_payload(
        cls,
        *,
        remote_jid: str,
        expiration_seconds: int,
        setting_timestamp: int | None,
    ) -> bytes:
        key_payload = _encode_message_key(
            remote_jid=remote_jid,
            message_id="",
            from_me=False,
        )
        protocol_payload = b"".join(
            (
                _encode_len_delimited(1, key_payload),
                _encode_varint_field(2, 3),
                _encode_varint_field(4, max(0, expiration_seconds)),
                _encode_varint_field(5, cls._resolve_timestamp_ms(setting_timestamp)),
            )
        )
        return _encode_len_delimited(12, protocol_payload)

    @classmethod
    def _build_poll_vote_update_payload(
        cls,
        *,
        remote_jid: str,
        poll_creation_message_id: str,
        poll_creator_jid: str,
        voter_jid: str,
        selected_options: list[bytes],
        message_secret: bytes,
        sender_timestamp_ms: int | None,
    ) -> bytes:
        vote_plain = _encode_poll_vote_plaintext(selected_options)
        vote_iv = os.urandom(12)
        vote_key = _derive_message_addon_key(
            addon_label="Poll Vote",
            message_id=poll_creation_message_id,
            creator_jid=poll_creator_jid,
            actor_jid=voter_jid,
            message_secret=message_secret,
        )
        aad = f"{poll_creation_message_id}\x00{voter_jid}".encode("utf-8")
        vote_cipher = aes_encrypt(vote_plain, vote_key, vote_iv, aad)

        key_payload = _encode_message_key(
            remote_jid=remote_jid,
            message_id=poll_creation_message_id,
            participant=None,
            from_me=False,
        )
        enc_vote_payload = b"".join(
            (
                _encode_len_delimited(1, vote_cipher),
                _encode_len_delimited(2, vote_iv),
            )
        )
        poll_update_payload = b"".join(
            (
                _encode_len_delimited(1, key_payload),
                _encode_len_delimited(2, enc_vote_payload),
                _encode_varint_field(4, cls._resolve_timestamp_ms(sender_timestamp_ms)),
            )
        )
        return _encode_len_delimited(50, poll_update_payload)

    @classmethod
    def _build_event_response_update_payload(
        cls,
        *,
        remote_jid: str,
        event_creation_message_id: str,
        event_creator_jid: str,
        responder_jid: str,
        response_type: int,
        message_secret: bytes,
        timestamp_ms: int | None,
        extra_guest_count: int | None,
    ) -> bytes:
        response_timestamp = cls._resolve_timestamp_ms(timestamp_ms)
        response_plain = _encode_event_response_plaintext(
            response_type=response_type,
            timestamp_ms=response_timestamp,
            extra_guest_count=extra_guest_count,
        )
        response_iv = os.urandom(12)
        response_key = _derive_message_addon_key(
            addon_label="Event Response",
            message_id=event_creation_message_id,
            creator_jid=event_creator_jid,
            actor_jid=responder_jid,
            message_secret=message_secret,
        )
        aad = f"{event_creation_message_id}\x00{responder_jid}".encode("utf-8")
        response_cipher = aes_encrypt(response_plain, response_key, response_iv, aad)

        key_payload = _encode_message_key(
            remote_jid=remote_jid,
            message_id=event_creation_message_id,
            participant=None,
            from_me=False,
        )
        event_payload = b"".join(
            (
                _encode_len_delimited(1, key_payload),
                _encode_len_delimited(2, response_cipher),
                _encode_len_delimited(3, response_iv),
            )
        )
        return _encode_len_delimited(76, event_payload)

    async def _assert_sessions(self, signal_repo: SignalRepository, jids: list[str]) -> None:
        missing: list[str] = []
        for jid in dict.fromkeys(jids):
            if not await signal_repo.get_session(jid):
                missing.append(jid)

        if not missing:
            return

        query = BinaryNode(
            tag="iq",
            attrs={"xmlns": "encrypt", "type": "get", "to": S_WHATSAPP_NET},
            content=[
                BinaryNode(
                    tag="key",
                    attrs={},
                    content=[BinaryNode(tag="user", attrs={"jid": jid}) for jid in missing],
                )
            ],
        )
        result = await self.client.query(query)
        await self._parse_and_inject_sessions(signal_repo, result, missing)

    async def _parse_and_inject_sessions(
        self, signal_repo: SignalRepository, node: BinaryNode, requested_jids: list[str] | None = None
    ) -> None:
        list_node = self._get_child(node, "list")
        if not list_node:
            raise ValueError("encrypt query response missing list node")

        users = self._get_children(list_node, "user")
        if not users:
            raise ValueError("encrypt query response has no user nodes")

        # Build mapping from base user (without device) to requested device JIDs
        requested_map: dict[str, list[str]] = {}
        if requested_jids:
            for jid in requested_jids:
                decoded = jid_decode(jid)
                if decoded:
                    base_jid = jid_encode(decoded.user, decoded.server)
                    requested_map.setdefault(base_jid, []).append(jid)

        for user_node in users:
            response_jid = user_node.attrs.get("jid")
            if not response_jid:
                continue

            registration = self._child_int(user_node, "registration")
            identity_key = self._child_bytes(user_node, "identity")

            skey = self._get_child(user_node, "skey")
            if skey is None:
                raise ValueError(f"skey missing in encrypt response for {response_jid}")
            signed_prekey_id = self._child_int(skey, "id")
            signed_prekey_public = self._child_bytes(skey, "value")
            signed_prekey_signature = self._child_bytes(skey, "signature")

            prekey_node = self._get_child(user_node, "key")
            prekey_id = self._child_int(prekey_node, "id") if prekey_node else None
            prekey_public = self._child_bytes(prekey_node, "value") if prekey_node else None

            # Determine which JIDs to save session for
            # If server returned base JID but we requested device-specific JIDs,
            # save session for all requested device JIDs of that user
            decoded_response = jid_decode(response_jid)
            if decoded_response:
                base_response_jid = jid_encode(decoded_response.user, decoded_response.server)
                jids_to_save = requested_map.get(base_response_jid, [response_jid])
            else:
                jids_to_save = [response_jid]

            for jid_to_save in jids_to_save:
                await signal_repo.inject_session_from_prekey_bundle(
                    jid_to_save,
                    registration_id=registration,
                    identity_key=identity_key,
                    signed_prekey_id=signed_prekey_id,
                    signed_prekey_public=signed_prekey_public,
                    signed_prekey_signature=signed_prekey_signature,
                    prekey_id=prekey_id,
                    prekey_public=prekey_public,
                )

    @staticmethod
    def _get_child(node: BinaryNode | None, tag: str) -> BinaryNode | None:
        if node is None or not isinstance(node.content, list):
            return None
        for child in node.content:
            if child.tag == tag:
                return child
        return None

    @classmethod
    def _get_children(cls, node: BinaryNode | None, tag: str) -> list[BinaryNode]:
        if node is None or not isinstance(node.content, list):
            return []
        return [child for child in node.content if child.tag == tag]

    @classmethod
    def _child_bytes(cls, node: BinaryNode | None, tag: str) -> bytes:
        child = cls._get_child(node, tag)
        if child is None:
            raise ValueError(f"{tag} node missing")
        if isinstance(child.content, (bytes, bytearray)):
            return bytes(child.content)
        if isinstance(child.content, str):
            return child.content.encode("utf-8")
        raise ValueError(f"{tag} node has invalid content type: {type(child.content).__name__}")

    @classmethod
    def _child_int(cls, node: BinaryNode | None, tag: str) -> int:
        return int.from_bytes(cls._child_bytes(node, tag), byteorder="big", signed=False)

    def _encode_device_identity(self) -> bytes:
        if not self.client.creds or not self.client.creds.account:
            raise ValueError("missing account identity for device-identity stanza")

        account = self.client.creds.account
        details = account.get("details")
        account_signature_key = account.get("account_signature_key")
        account_signature = account.get("account_signature")
        device_signature = account.get("device_signature")

        def _decode(value: object) -> bytes | None:
            if value is None:
                return None
            if isinstance(value, bytes):
                return value
            if isinstance(value, str) and value:
                return b64decode(value.encode("utf-8"))
            return None

        payload = ADVSignedDeviceIdentity(
            details=_decode(details),
            account_signature_key=_decode(account_signature_key),
            account_signature=_decode(account_signature),
            device_signature=_decode(device_signature),
        )
        return payload.SerializeToString(include_signature_key=True)
