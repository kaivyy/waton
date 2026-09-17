from __future__ import annotations

import os
import struct
import time
from base64 import b64decode
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast  # noqa: TC006

from waton.client.usync import USyncQuery
from waton.core.jid import S_WHATSAPP_NET, jid_decode, jid_encode, jid_normalized_user
from waton.protocol.binary_node import BinaryNode
from waton.protocol.protobuf import wa_pb2
from waton.protocol.protobuf.wire import (
    ADVSignedDeviceIdentity,
    encode_bool,
    encode_len_delimited,
    encode_string,
    encode_varint,
    encode_varint_field,
)
from waton.protocol.signal_repo import SignalRepository
from waton.utils.crypto import aes_encrypt, hmac_sha256
from waton.utils.generics import generate_participant_hash_v2
from waton.utils.message_utils import build_receipt_node, generate_message_id

if TYPE_CHECKING:
    from waton.client.client import WAClient
    from waton.core.entities import Message


def _write_random_pad_max16(msg: bytes) -> bytes:
    """Pads the message with 1-16 random bytes (PKCS#7 format)."""
    pad_len = (os.urandom(1)[0] & 0x0F) + 1
    pad_bytes = bytes([pad_len] * pad_len)
    return msg + pad_bytes

def _unpad_random_max16(msg: bytes) -> bytes:
    """Removes random padding up to 16 bytes from the end of a message."""
    if not msg:
        return msg
    pad_len = msg[-1]
    if pad_len < 1 or pad_len > 16 or len(msg) < pad_len:
        return msg
    if msg[-pad_len:] != bytes([pad_len] * pad_len):
        return msg
    return msg[:-pad_len]



# Public alias for call sites outside this module (e.g. inbound processing).
unpad_random_max16 = _unpad_random_max16


def _encode_fixed64_field(field_number: int, value: float | None) -> bytes:
    if value is None:
        return b""
    key = encode_varint((field_number << 3) | 1)
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
            encode_string(1, remote_jid),
            encode_varint_field(2, 1 if from_me else 0),
            encode_string(3, message_id),
        )
    )
    if participant:
        encoded += encode_string(4, participant)
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
    key0 = hmac_sha256(bytes(32), message_secret)
    return hmac_sha256(key0, sign)


MediaInfo = Mapping[str, object]


def _bytes_or_default(value: object, default: bytes = b"") -> bytes:
    return value if isinstance(value, bytes) else default


def _int_or_default(value: object, default: int = 0) -> int:
    return value if isinstance(value, int) else default


def _session_key(repo: SignalRepository, jid: str) -> str:
    signal_name, signal_device = repo.jid_to_signal_address(jid)
    return f"{signal_name}.{signal_device}"


def _encode_poll_vote_plaintext(selected_options: list[bytes]) -> bytes:
    chunks: list[bytes] = []
    for option in selected_options:
        if not option:
            continue
        chunks.append(encode_len_delimited(1, option))
    return b"".join(chunks)


def _encode_event_response_plaintext(
    *,
    response_type: int,
    timestamp_ms: int,
    extra_guest_count: int | None = None,
) -> bytes:
    payload = b"".join(
        (
            encode_varint_field(1, max(0, response_type)),
            encode_varint_field(2, max(0, timestamp_ms)),
        )
    )
    if extra_guest_count is not None:
        payload += encode_varint_field(3, max(0, extra_guest_count))
    return payload


class MessagesAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def send_text(
        self,
        to_jid: str,
        text: str,
        *,
        recipients: list[str] | None = None,
        quoted: dict[str, Any] | Message | None = None,
        mentions: list[str] | None = None,
    ) -> str:
        """Sends a text message to all devices of recipient, optionally replying to another message or mentioning users."""
        if quoted or mentions:
            context_info = self._build_context_info(quoted=quoted, mentions=mentions)
            ext_text = encode_string(1, text) + encode_len_delimited(17, context_info)
            payload = encode_len_delimited(6, ext_text)
        else:
            msg = wa_pb2.Message()
            msg.conversation = text
            payload = msg.SerializeToString()
        return await self._send_payload(to_jid, payload, message_type="text", recipients=recipients)

    async def send_image(
        self,
        to_jid: str,
        image_bytes: bytes,
        caption: str = "",
        *,
        recipients: list[str] | None = None,
        quoted: dict[str, Any] | Message | None = None,
        mentions: list[str] | None = None,
    ) -> str:
        """Uploads and sends an image message to all devices of recipient."""
        from waton.client.media import MediaManager

        media = MediaManager()
        media_info = cast("MediaInfo", await media.encrypt_and_upload("image", image_bytes))
        context_info = self._build_context_info(quoted=quoted, mentions=mentions) if (quoted or mentions) else b""
        payload = self._build_image_payload(
            media_info=media_info,
            caption=caption,
            context_info=context_info,
        )
        return await self._send_payload(to_jid, payload, message_type="media", recipients=recipients)

    async def send_status_update(
        self,
        *,
        text: str | None = None,
        image_bytes: bytes | None = None,
        caption: str = "",
        recipients: list[str] | None = None,
    ) -> str:
        """Sends a WhatsApp status story to status@broadcast for the specified recipients."""
        from waton.core.jid import STORIES_JID
        if image_bytes:
            return await self.send_image(STORIES_JID, image_bytes, caption=caption, recipients=recipients)
        if text:
            return await self.send_text(STORIES_JID, text, recipients=recipients)
        raise ValueError("Either text or image_bytes must be provided for a status update")

    async def send_document(
        self,
        to_jid: str,
        document_bytes: bytes,
        *,
        file_name: str = "file",
        mimetype: str = "application/octet-stream",
        caption: str = "",
        recipients: list[str] | None = None,
        quoted: dict[str, Any] | Message | None = None,
        mentions: list[str] | None = None,
    ) -> str:
        """Uploads and sends a document message to all devices of recipient."""
        from waton.client.media import MediaManager

        media = MediaManager()
        media_info = cast("MediaInfo", await media.encrypt_and_upload("document", document_bytes))
        context_info = self._build_context_info(quoted=quoted, mentions=mentions) if (quoted or mentions) else b""
        payload = self._build_document_payload(
            media_info=media_info,
            file_name=file_name,
            mimetype=mimetype,
            caption=caption,
            context_info=context_info,
        )
        return await self._send_payload(to_jid, payload, message_type="document", recipients=recipients)

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
        recipients: list[str] | None = None,
        quoted: dict[str, Any] | Message | None = None,
        mentions: list[str] | None = None,
    ) -> str:
        """Sends a location message to all recipient devices."""
        context_info = self._build_context_info(quoted=quoted, mentions=mentions) if (quoted or mentions) else b""
        payload = self._build_location_payload(
            latitude=latitude,
            longitude=longitude,
            name=name,
            address=address,
            url=url,
            comment=comment,
            context_info=context_info,
        )
        return await self._send_payload(to_jid, payload, message_type="location", recipients=recipients)

    async def send_audio(
        self,
        to_jid: str,
        audio_bytes: bytes,
        *,
        mimetype: str = "audio/ogg; codecs=opus",
        seconds: int = 0,
        ptt: bool = False,
        recipients: list[str] | None = None,
        quoted: dict[str, Any] | Message | None = None,
        mentions: list[str] | None = None,
    ) -> str:
        """Uploads and sends an audio message to all devices of recipient."""
        from waton.client.media import MediaManager

        media = MediaManager()
        media_info = cast("MediaInfo", await media.encrypt_and_upload("audio", audio_bytes))
        context_info = self._build_context_info(quoted=quoted, mentions=mentions) if (quoted or mentions) else b""
        payload = self._build_audio_payload(
            media_info=media_info,
            mimetype=mimetype,
            seconds=seconds,
            ptt=ptt,
            context_info=context_info,
        )
        return await self._send_payload(to_jid, payload, message_type="audio", recipients=recipients)

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
        ptv: bool = False,
        recipients: list[str] | None = None,
        quoted: dict[str, Any] | Message | None = None,
        mentions: list[str] | None = None,
    ) -> str:
        """Uploads and sends a video message to all devices of recipient."""
        from waton.client.media import MediaManager

        media = MediaManager()
        media_info = cast("MediaInfo", await media.encrypt_and_upload("video", video_bytes))
        context_info = self._build_context_info(quoted=quoted, mentions=mentions) if (quoted or mentions) else b""
        payload = self._build_video_payload(
            media_info=media_info,
            mimetype=mimetype,
            caption=caption,
            seconds=seconds,
            height=height,
            width=width,
            gif_playback=gif_playback,
            ptv=ptv,
            context_info=context_info,
        )
        return await self._send_payload(to_jid, payload, message_type="video", recipients=recipients)

    async def send_ptv(
        self,
        to_jid: str,
        video_bytes: bytes,
        *,
        mimetype: str = "video/mp4",
        caption: str = "",
        seconds: int = 0,
        height: int = 0,
        width: int = 0,
        recipients: list[str] | None = None,
        quoted: dict[str, Any] | Message | None = None,
        mentions: list[str] | None = None,
    ) -> str:
        """Uploads and sends a circular push-to-talk video note (PTV) message."""
        kwargs: dict[str, Any] = {
            "to_jid": to_jid,
            "video_bytes": video_bytes,
            "mimetype": mimetype,
            "caption": caption,
            "seconds": seconds,
            "height": height,
            "width": width,
            "ptv": True,
        }
        if recipients is not None:
            kwargs["recipients"] = recipients
        if quoted is not None:
            kwargs["quoted"] = quoted
        if mentions is not None:
            kwargs["mentions"] = mentions
        return await self.send_video(**kwargs)

    async def send_sticker(
        self,
        to_jid: str,
        sticker_bytes: bytes,
        *,
        mimetype: str = "image/webp",
        height: int = 0,
        width: int = 0,
        is_animated: bool = False,
        recipients: list[str] | None = None,
        quoted: dict[str, Any] | Message | None = None,
        mentions: list[str] | None = None,
    ) -> str:
        """Uploads and sends a sticker message to all devices of recipient."""
        from waton.client.media import MediaManager

        media = MediaManager()
        media_info = cast("MediaInfo", await media.encrypt_and_upload("sticker", sticker_bytes))
        context_info = self._build_context_info(quoted=quoted, mentions=mentions) if (quoted or mentions) else b""
        payload = self._build_sticker_payload(
            media_info=media_info,
            mimetype=mimetype,
            height=height,
            width=width,
            is_animated=is_animated,
            context_info=context_info,
        )
        return await self._send_payload(to_jid, payload, message_type="sticker", recipients=recipients)

    async def send_contact(self, to_jid: str, *, display_name: str, vcard: str) -> str:
        """Sends a contact message to all devices of recipient."""
        payload = self._build_contact_payload(display_name=display_name, vcard=vcard)
        return await self._send_payload(to_jid, payload, message_type="contact")

    async def send_group_invite(
        self,
        to_jid: str,
        *,
        group_jid: str,
        invite_code: str,
        group_name: str,
        caption: str | None = None,
        invite_expiration: int | None = None,
        jpeg_thumbnail: bytes | None = None,
    ) -> str:
        """Sends an in-chat group invite link message."""
        payload = self._build_group_invite_payload(
            group_jid=group_jid,
            invite_code=invite_code,
            group_name=group_name,
            caption=caption,
            invite_expiration=invite_expiration,
            jpeg_thumbnail=jpeg_thumbnail,
        )
        return await self._send_payload(to_jid, payload, message_type="group_invite")

    async def send_payment_invite(
        self,
        to_jid: str,
        *,
        service_type: int = 3,
        expiry_timestamp: int | None = None,
    ) -> str:
        """Sends a payment invite message."""
        payload = self._build_payment_invite_payload(
            service_type=service_type,
            expiry_timestamp=expiry_timestamp,
        )
        return await self._send_payload(to_jid, payload, message_type="payment_invite")

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
        chosen_enc_key = enc_key or os.urandom(32)
        chosen_secret = message_secret or os.urandom(32)
        payload = self._build_poll_creation_payload(
            name=name,
            options=options,
            selectable_options_count=selectable_options_count,
            enc_key=chosen_enc_key,
            message_secret=chosen_secret,
        )
        msg_id = await self._send_payload(
            to_jid,
            payload,
            message_type="poll",
            message_secret=chosen_secret,
            extra_nodes=[BinaryNode(tag="meta", attrs={"polltype": "creation"})],
        )
        if hasattr(self.client, "set_message_secret"):
            self.client.set_message_secret(msg_id, chosen_enc_key)
        return msg_id

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
        is_group = to_jid.endswith("@g.us")
        edit_attr = "8" if (is_group and not from_me) else "7"
        return await self._send_payload(
            to_jid,
            payload,
            message_type="protocol",
            extra_attrs={"edit": edit_attr},
        )

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
        return await self._send_payload(
            to_jid,
            payload,
            message_type="protocol",
            extra_attrs={"edit": "1"},
        )

    async def pin_message(
        self,
        to_jid: str,
        target_message_id: str,
        *,
        from_me: bool = False,
        participant: str | None = None,
        pin_type: int = 1,
        duration_seconds: int = 86400,
    ) -> str:
        """Pins or unpins a specific message in a chat (duration: 86400 for 24h, 604800 for 7d, 2592000 for 30d)."""
        payload = self._build_pin_message_payload(
            remote_jid=to_jid,
            target_message_id=target_message_id,
            from_me=from_me,
            participant=participant,
            pin_type=pin_type,
            duration_seconds=duration_seconds,
        )
        return await self._send_payload(
            to_jid,
            payload,
            message_type="protocol",
            extra_attrs={"edit": "2"},
        )

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
        return await self._send_payload(to_jid, payload, message_type="poll_update", message_secret=message_secret)

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
        return await self._send_payload(to_jid, payload, message_type="event_response", message_secret=message_secret)

    async def send_reaction(
        self,
        to_jid: str,
        message_id: str,
        reaction: str | None = None,
        *,
        participant: str | None = None,
        from_me: bool = False,
        message_secret: bytes | None = None,
        sender_timestamp_ms: int | None = None,
    ) -> str:
        """Reacts to a message with an emoji, or removes reaction if empty/None."""
        target_jid = jid_normalized_user(to_jid)
        payload = self._build_reaction_payload(
            remote_jid=target_jid,
            target_message_id=message_id,
            reaction=reaction,
            participant=participant,
            from_me=from_me,
            sender_timestamp_ms=sender_timestamp_ms,
            message_secret=message_secret,
        )
        msg_id = generate_message_id("reaction_")
        try:
            return await self._send_payload(
                target_jid,
                payload,
                message_type="reaction",
                message_secret=message_secret,
                message_id=msg_id,
                extra_attrs={"decrypt-fail": "hide"},
            )
        except Exception:
            # Fallback for offline/test environments without active crypto sessions
            node = BinaryNode(
                tag="message",
                attrs={"to": target_jid, "id": msg_id, "type": "reaction", "decrypt-fail": "hide"},
                content=payload,
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

    async def play_messages(self, keys: list[dict[str, str | None]], *, play_self: bool = False) -> None:
        """Send played/played-self receipts for voice and video notes."""
        await self.send_receipts_batch(keys, receipt_type="played-self" if play_self else "played")


    async def _send_payload(
        self,
        to_jid: str,
        payload: bytes,
        *,
        message_type: str,
        recipients: list[str] | None = None,
        message_secret: bytes | None = None,
        extra_attrs: dict[str, str] | None = None,
        extra_nodes: list[BinaryNode] | None = None,
        message_id: str | None = None,
    ) -> str:
        if not self.client.creds or not self.client.creds.me:
            raise ValueError("client is not authenticated")

        signal_repo = SignalRepository(self.client.creds, self.client.storage)
        usync = USyncQuery(self.client)

        target_jid = jid_normalized_user(to_jid)
        me_jid = jid_normalized_user(self.client.creds.me["id"])

        msg_id = message_id or generate_message_id()
        
        from waton.utils.reporting_token import should_include_reporting_token, get_message_reporting_token
        msg_type_to_key = {
            "reaction": "reactionMessage",
            "poll_update": "pollUpdateMessage",
            "event_response": "encEventResponseMessage",
        }
        test_key = msg_type_to_key.get(message_type, "")
        test_dict = {test_key: True} if test_key else {}
        
        reporting_node = None
        if should_include_reporting_token(test_dict):
            if not message_secret:
                message_secret = os.urandom(32)
                context_info = encode_len_delimited(3, message_secret)
                payload += encode_len_delimited(35, context_info)
            reporting_node = get_message_reporting_token(message_secret, payload, me_jid, target_jid, msg_id)

        if target_jid.endswith("@g.us"):
            padded_payload = _write_random_pad_max16(payload)
            ciphertext, _skdm = await signal_repo.encrypt_group_message(target_jid, me_jid, padded_payload)
            enc_attrs = {"v": "2", "type": "skmsg"}
            if message_type in {"image", "video", "audio", "document", "sticker"}:
                enc_attrs["mediatype"] = message_type
            content = [
                BinaryNode(
                    tag="enc",
                    attrs=enc_attrs,
                    content=ciphertext,
                )
            ]
            if reporting_node:
                content.append(reporting_node)
            if extra_nodes:
                content.extend(extra_nodes)
            attrs = {"to": target_jid, "id": msg_id, "type": message_type}
            if extra_attrs:
                attrs.update(extra_attrs)
            node = BinaryNode(
                tag="message",
                attrs=attrs,
                content=content,
            )
            await self.client.send_node(node)
            return msg_id

        all_device_jids = await self._collect_target_devices(
            signal_repo, usync, target_jid, me_jid, recipients=recipients
        )
        await self._assert_sessions(signal_repo, all_device_jids)

        phash = generate_participant_hash_v2(all_device_jids)
        device_sent_payload = self._build_device_sent_payload(target_jid, payload, phash=phash)

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

            p2p_enc_attrs = {"v": "2", "type": msg_type}
            if message_type in {"image", "video", "audio", "document", "sticker"}:
                p2p_enc_attrs["mediatype"] = message_type

            participants.append(
                BinaryNode(
                    tag="to",
                    attrs={"jid": device_jid},
                    content=[
                        BinaryNode(
                            tag="enc",
                            attrs=p2p_enc_attrs,
                            content=ciphertext,
                        )
                    ],
                )
            )

        content = [BinaryNode(tag="participants", attrs={}, content=participants)]
        if include_device_identity:
            content.append(BinaryNode(tag="device-identity", attrs={}, content=self._encode_device_identity()))

        tc_mgr = getattr(self.client, "tc_token_manager", None)
        if tc_mgr is not None:
            token_data = tc_mgr.get_token(target_jid)
            if token_data:
                from waton.utils.tc_token import build_tc_token_node
                content.append(build_tc_token_node(token_data["token"], token_data["timestamp"]))

        cs_mgr = getattr(self.client, "cs_token_manager", None)
        if cs_mgr is not None:
            cs_token = cs_mgr.generate_cs_token(target_jid)
            if cs_token:
                from waton.utils.cs_token import CSTokenManager
                content.append(CSTokenManager.build_cs_token_node(cs_token))

        if reporting_node:
            content.append(reporting_node)
        if extra_nodes:
            content.extend(extra_nodes)

        attrs = {"to": target_jid, "id": msg_id, "type": message_type}
        if extra_attrs:
            attrs.update(extra_attrs)
        node = BinaryNode(
            tag="message",
            attrs=attrs,
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
        recipients: list[str] | None = None,
    ) -> list[str]:
        if target_jid == "status@broadcast" and recipients:
            jids_to_query = [jid_normalized_user(r) for r in recipients]
        else:
            jids_to_query = [target_jid]
        if me_jid != target_jid and me_jid not in jids_to_query:
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
        me_session_key = _session_key(signal_repo, me_device_jid)
        return [jid for jid in all_device_jids if _session_key(signal_repo, jid) != me_session_key]

    @staticmethod
    def _build_device_sent_payload(destination_jid: str, inner_payload: bytes, phash: str | None = None) -> bytes:
        parts = [
            encode_string(1, destination_jid),
            encode_len_delimited(2, inner_payload),
        ]
        if phash:
            parts.append(encode_string(3, phash))
        device_sent_payload = b"".join(parts)
        return encode_len_delimited(31, device_sent_payload)

    @staticmethod
    def _build_image_payload(
        *,
        media_info: MediaInfo,
        caption: str = "",
        mimetype: str = "image/jpeg",
        context_info: bytes = b"",
    ) -> bytes:
        url = str(media_info.get("url", ""))
        media_key = _bytes_or_default(media_info.get("mediaKey"))
        file_sha256 = _bytes_or_default(media_info.get("fileSha256"))
        file_enc_sha256 = _bytes_or_default(media_info.get("fileEncSha256"))
        direct_path = str(media_info.get("directPath", ""))
        file_length = _int_or_default(media_info.get("fileLength"))

        parts = [
            encode_string(1, url),
            encode_string(2, mimetype),
            encode_string(3, caption),
            encode_len_delimited(4, file_sha256),
            encode_varint_field(5, file_length),
            encode_len_delimited(8, media_key),
            encode_len_delimited(9, file_enc_sha256),
            encode_string(10, direct_path),
        ]
        if context_info:
            parts.append(encode_len_delimited(17, context_info))
        return encode_len_delimited(4, b"".join(parts))

    def _build_context_info(
        self,
        *,
        quoted: dict[str, Any] | Message | None = None,
        mentions: list[str] | None = None,
    ) -> bytes:
        stanza_id: str | None = None
        participant: str | None = None
        quoted_msg_bytes: bytes = b""
        remote_jid: str | None = None

        if quoted is not None:
            if hasattr(quoted, "id"):
                stanza_id = getattr(quoted, "id", None)
                participant = getattr(quoted, "participant", None) or getattr(quoted, "from_jid", None)
                quoted_text = getattr(quoted, "text", None)
                if quoted_text:
                    quoted_msg_bytes = encode_string(1, quoted_text)
            elif isinstance(quoted, dict):
                key = quoted.get("key")
                if isinstance(key, dict):
                    stanza_id = key.get("id")
                    participant = key.get("participant") or key.get("remoteJid")
                    remote_jid = key.get("remoteJid")
                else:
                    stanza_id = quoted.get("id") or quoted.get("stanza_id")
                    participant = quoted.get("participant") or quoted.get("from_jid")
                    remote_jid = quoted.get("remote_jid")

                q_msg = quoted.get("message") or quoted.get("quoted_message") or quoted.get("text")
                if isinstance(q_msg, str):
                    quoted_msg_bytes = encode_string(1, q_msg)
                elif isinstance(q_msg, (bytes, bytearray)):
                    quoted_msg_bytes = bytes(q_msg)
                elif hasattr(q_msg, "SerializeToString"):
                    quoted_msg_bytes = q_msg.SerializeToString()
                elif isinstance(q_msg, dict):
                    if "conversation" in q_msg:
                        quoted_msg_bytes = encode_string(1, str(q_msg["conversation"]))
                    elif "text" in q_msg:
                        quoted_msg_bytes = encode_string(1, str(q_msg["text"]))

        parts: list[bytes] = []
        if stanza_id:
            parts.append(encode_string(1, stanza_id))
        if participant:
            parts.append(encode_string(2, participant))
        if quoted_msg_bytes:
            parts.append(encode_len_delimited(3, quoted_msg_bytes))
        if remote_jid:
            parts.append(encode_string(4, remote_jid))
        if mentions:
            for mention in mentions:
                if mention:
                    parts.append(encode_string(15, mention))

        return b"".join(parts)

    def _build_reaction_payload(
        self,
        *,
        remote_jid: str,
        target_message_id: str,
        reaction: str | None,
        participant: str | None = None,
        from_me: bool = False,
        sender_timestamp_ms: int | None = None,
        message_secret: bytes | None = None,
    ) -> bytes:
        if sender_timestamp_ms is None:
            sender_timestamp_ms = int(time.time() * 1000)
        target_key = _encode_message_key(
            remote_jid=remote_jid,
            message_id=target_message_id,
            from_me=from_me,
            participant=participant,
        )
        reaction_text = reaction if reaction is not None else ""
        reaction_body = b"".join(
            (
                encode_len_delimited(1, target_key),
                encode_string(2, reaction_text),
                encode_varint_field(4, sender_timestamp_ms),
            )
        )
        if message_secret is not None:
            from waton.utils.msg_secret import encrypt_reaction

            me_jid = (
                jid_normalized_user(self.client.creds.me["id"])
                if self.client.creds and self.client.creds.me
                else ""
            )
            target_sender = participant or remote_jid
            enc_dict = encrypt_reaction(
                reaction_payload=reaction_body,
                target_message_id=target_message_id,
                target_sender_jid=target_sender,
                target_chat_jid=remote_jid,
                own_jid=me_jid,
                message_secret=message_secret,
            )
            return encode_len_delimited(56, enc_dict["enc_reaction_bytes"])

        return encode_len_delimited(46, reaction_body)

    @staticmethod
    def _build_document_payload(
        *,
        media_info: MediaInfo,
        file_name: str,
        mimetype: str,
        caption: str,
        context_info: bytes = b"",
    ) -> bytes:
        url = str(media_info.get("url", ""))
        media_key = _bytes_or_default(media_info.get("mediaKey"))
        file_sha256 = _bytes_or_default(media_info.get("fileSha256"))
        file_enc_sha256 = _bytes_or_default(media_info.get("fileEncSha256"))
        direct_path = str(media_info.get("directPath", ""))
        file_length = _int_or_default(media_info.get("fileLength"))

        parts = [
            encode_string(1, url),
            encode_string(2, mimetype),
            encode_len_delimited(4, file_sha256),
            encode_varint_field(5, file_length),
            encode_len_delimited(7, media_key),
            encode_string(8, file_name),
            encode_len_delimited(9, file_enc_sha256),
            encode_string(10, direct_path),
        ]
        if context_info:
            parts.append(encode_len_delimited(17, context_info))
        if caption:
            parts.append(encode_string(20, caption))
        return encode_len_delimited(7, b"".join(parts))

    @staticmethod
    def _build_location_payload(
        *,
        latitude: float,
        longitude: float,
        name: str,
        address: str,
        url: str,
        comment: str,
        context_info: bytes = b"",
    ) -> bytes:
        parts = [
            _encode_fixed64_field(1, latitude),
            _encode_fixed64_field(2, longitude),
            encode_string(3, name),
            encode_string(4, address),
            encode_string(5, url),
            encode_string(11, comment),
        ]
        if context_info:
            parts.append(encode_len_delimited(17, context_info))
        return encode_len_delimited(5, b"".join(parts))

    @staticmethod
    def _build_audio_payload(
        *,
        media_info: MediaInfo,
        mimetype: str,
        seconds: int,
        ptt: bool,
        context_info: bytes = b"",
    ) -> bytes:
        url = str(media_info.get("url", ""))
        media_key = _bytes_or_default(media_info.get("mediaKey"))
        file_sha256 = _bytes_or_default(media_info.get("fileSha256"))
        file_enc_sha256 = _bytes_or_default(media_info.get("fileEncSha256"))
        direct_path = str(media_info.get("directPath", ""))
        file_length = _int_or_default(media_info.get("fileLength"))

        parts = [
            encode_string(1, url),
            encode_string(2, mimetype),
            encode_len_delimited(3, file_sha256),
            encode_varint_field(4, file_length),
            encode_varint_field(5, max(0, seconds)),
            encode_bool(6, ptt),
            encode_len_delimited(7, media_key),
            encode_len_delimited(8, file_enc_sha256),
            encode_string(9, direct_path),
        ]
        if context_info:
            parts.append(encode_len_delimited(17, context_info))
        return encode_len_delimited(8, b"".join(parts))

    @staticmethod
    def _build_video_payload(
        *,
        media_info: MediaInfo,
        mimetype: str,
        caption: str,
        seconds: int,
        height: int,
        width: int,
        gif_playback: bool,
        ptv: bool = False,
        context_info: bytes = b"",
    ) -> bytes:
        url = str(media_info.get("url", ""))
        media_key = _bytes_or_default(media_info.get("mediaKey"))
        file_sha256 = _bytes_or_default(media_info.get("fileSha256"))
        file_enc_sha256 = _bytes_or_default(media_info.get("fileEncSha256"))
        direct_path = str(media_info.get("directPath", ""))
        file_length = _int_or_default(media_info.get("fileLength"))

        parts = [
            encode_string(1, url),
            encode_string(2, mimetype),
            encode_len_delimited(3, file_sha256),
            encode_varint_field(4, file_length),
            encode_varint_field(5, max(0, seconds)),
            encode_len_delimited(6, media_key),
            encode_string(7, caption),
            encode_bool(8, gif_playback),
            encode_varint_field(9, max(0, height)),
            encode_varint_field(10, max(0, width)),
            encode_len_delimited(11, file_enc_sha256),
            encode_string(13, direct_path),
        ]
        if ptv:
            parts.append(encode_bool(16, True))
        if context_info:
            parts.append(encode_len_delimited(17, context_info))
        video_payload = b"".join(parts)
        if ptv:
            return encode_len_delimited(66, video_payload)
        return encode_len_delimited(9, video_payload)

    @classmethod
    def _build_pin_message_payload(
        cls,
        *,
        remote_jid: str,
        target_message_id: str,
        from_me: bool,
        participant: str | None,
        pin_type: int = 1,
        duration_seconds: int = 86400,
    ) -> bytes:
        key_payload = _encode_message_key(
            remote_jid=remote_jid,
            message_id=target_message_id,
            participant=participant,
            from_me=from_me,
        )
        sender_ts_ms = int(time.time() * 1000)
        pin_payload = b"".join(
            (
                encode_len_delimited(1, key_payload),
                encode_varint_field(2, pin_type),
                encode_varint_field(3, sender_ts_ms),
            )
        )
        msg_bytes = encode_len_delimited(63, pin_payload)
        duration = duration_seconds if pin_type == 1 else 0
        context_info = encode_varint_field(1, duration)
        msg_bytes += encode_len_delimited(35, context_info)
        return msg_bytes

    @staticmethod
    def _build_sticker_payload(
        *,
        media_info: MediaInfo,
        mimetype: str,
        height: int,
        width: int,
        is_animated: bool,
        context_info: bytes = b"",
    ) -> bytes:
        url = str(media_info.get("url", ""))
        media_key = _bytes_or_default(media_info.get("mediaKey"))
        file_sha256 = _bytes_or_default(media_info.get("fileSha256"))
        file_enc_sha256 = _bytes_or_default(media_info.get("fileEncSha256"))
        direct_path = str(media_info.get("directPath", ""))
        file_length = _int_or_default(media_info.get("fileLength"))

        parts = [
            encode_string(1, url),
            encode_len_delimited(2, file_sha256),
            encode_len_delimited(3, file_enc_sha256),
            encode_len_delimited(4, media_key),
            encode_string(5, mimetype),
            encode_varint_field(6, max(0, height)),
            encode_varint_field(7, max(0, width)),
            encode_string(8, direct_path),
            encode_varint_field(9, file_length),
            encode_bool(13, is_animated),
        ]
        if context_info:
            parts.append(encode_len_delimited(17, context_info))
        return encode_len_delimited(26, b"".join(parts))

    @staticmethod
    def _build_contact_payload(*, display_name: str, vcard: str) -> bytes:
        contact_payload = b"".join(
            (
                encode_string(1, display_name),
                encode_string(16, vcard),
            )
        )
        return encode_len_delimited(4, contact_payload)

    @staticmethod
    def _build_group_invite_payload(
        *,
        group_jid: str,
        invite_code: str,
        group_name: str,
        caption: str | None = None,
        invite_expiration: int | None = None,
        jpeg_thumbnail: bytes | None = None,
    ) -> bytes:
        if invite_expiration is None:
            invite_expiration = int(time.time()) + (3 * 86400)
        fields = [
            encode_string(1, group_jid),
            encode_string(2, invite_code),
            encode_varint_field(3, invite_expiration),
            encode_string(4, group_name),
        ]
        if jpeg_thumbnail:
            fields.append(encode_len_delimited(5, jpeg_thumbnail))
        if caption:
            fields.append(encode_string(6, caption))
        return encode_len_delimited(28, b"".join(fields))

    @staticmethod
    def _build_payment_invite_payload(
        *,
        service_type: int = 3,
        expiry_timestamp: int | None = None,
    ) -> bytes:
        if expiry_timestamp is None:
            expiry_timestamp = int(time.time()) + 86400
        return encode_len_delimited(
            44,
            b"".join(
                (
                    encode_varint_field(1, service_type),
                    encode_varint_field(2, expiry_timestamp),
                )
            ),
        )

    @staticmethod
    def _build_poll_creation_payload(

        *,
        name: str,
        options: list[str],
        selectable_options_count: int,
        enc_key: bytes,
        message_secret: bytes,
    ) -> bytes:
        option_payloads = b"".join(encode_len_delimited(3, encode_string(1, option)) for option in options)
        context_info_payload = encode_len_delimited(3, message_secret)
        poll_payload = b"".join(
            (
                encode_len_delimited(1, enc_key),
                encode_string(2, name),
                option_payloads,
                encode_varint_field(4, max(0, selectable_options_count)),
                encode_len_delimited(5, context_info_payload),
            )
        )
        return encode_len_delimited(49, poll_payload)

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
                encode_len_delimited(1, key_payload),
                encode_varint_field(2, 0),
            )
        )
        return encode_len_delimited(12, protocol_payload)

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
                encode_len_delimited(1, key_payload),
                encode_varint_field(2, 14),
                encode_len_delimited(14, edited_message.SerializeToString()),
                encode_varint_field(15, cls._resolve_timestamp_ms(edited_at_ms)),
            )
        )
        return encode_len_delimited(12, protocol_payload)

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
                encode_len_delimited(1, key_payload),
                encode_varint_field(2, 3),
                encode_varint_field(4, max(0, expiration_seconds)),
                encode_varint_field(5, cls._resolve_timestamp_ms(setting_timestamp)),
            )
        )
        return encode_len_delimited(12, protocol_payload)

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
        aad = f"{poll_creation_message_id}\x00{voter_jid}".encode()
        vote_cipher = aes_encrypt(vote_plain, vote_key, vote_iv, aad)

        key_payload = _encode_message_key(
            remote_jid=remote_jid,
            message_id=poll_creation_message_id,
            participant=None,
            from_me=False,
        )
        enc_vote_payload = b"".join(
            (
                encode_len_delimited(1, vote_cipher),
                encode_len_delimited(2, vote_iv),
            )
        )
        poll_update_payload = b"".join(
            (
                encode_len_delimited(1, key_payload),
                encode_len_delimited(2, enc_vote_payload),
                encode_varint_field(4, cls._resolve_timestamp_ms(sender_timestamp_ms)),
            )
        )
        return encode_len_delimited(50, poll_update_payload)

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
        aad = f"{event_creation_message_id}\x00{responder_jid}".encode()
        response_cipher = aes_encrypt(response_plain, response_key, response_iv, aad)

        key_payload = _encode_message_key(
            remote_jid=remote_jid,
            message_id=event_creation_message_id,
            participant=None,
            from_me=False,
        )
        event_payload = b"".join(
            (
                encode_len_delimited(1, key_payload),
                encode_len_delimited(2, response_cipher),
                encode_len_delimited(3, response_iv),
            )
        )
        return encode_len_delimited(76, event_payload)

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
                logger.warning("skey missing in encrypt response for %s, skipping device", response_jid)
                continue
            signed_prekey_id = self._child_int(skey, "id")
            signed_prekey_public = self._child_bytes(skey, "value")
            signed_prekey_signature = self._child_bytes(skey, "signature")

            prekey_node = self._get_child(user_node, "key")
            prekey_id = self._child_int(prekey_node, "id") if prekey_node else None
            prekey_public = self._child_bytes(prekey_node, "value") if prekey_node else None

            decoded_response = jid_decode(response_jid)
            if decoded_response and decoded_response.device is not None:
                jids_to_save = [response_jid]
            elif decoded_response:
                jids_to_save = [jid_encode(decoded_response.user, decoded_response.server)]
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
