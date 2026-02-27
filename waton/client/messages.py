from __future__ import annotations

from base64 import b64decode
from typing import TYPE_CHECKING
import os

from waton.core.jid import S_WHATSAPP_NET, jid_normalized_user, jid_decode, jid_encode
from waton.protocol.binary_node import BinaryNode
from waton.protocol.protobuf import wa_pb2
from waton.protocol.protobuf.wire import ADVSignedDeviceIdentity
from waton.protocol.signal_repo import SignalRepository
from waton.client.usync import USyncQuery
from waton.utils.message_utils import build_receipt_node, generate_message_id

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

class MessagesAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def send_text(self, to_jid: str, text: str) -> str:
        """Sends a simple text message to all devices of recipient."""
        if not self.client.creds or not self.client.creds.me:
            raise ValueError("client is not authenticated")

        signal_repo = SignalRepository(self.client.creds, self.client.storage)
        usync = USyncQuery(self.client)

        target_jid = jid_normalized_user(to_jid)
        me_jid = jid_normalized_user(self.client.creds.me["id"])

        # Query devices for target and self
        jids_to_query = [target_jid]
        if me_jid != target_jid:
            jids_to_query.append(me_jid)

        devices_map = await usync.get_devices(jids_to_query)

        # Collect all device JIDs
        all_device_jids: list[str] = []
        for user_jid in jids_to_query:
            decoded = jid_decode(user_jid)
            if not decoded:
                continue
            # Get devices from usync, fallback to device 0
            device_jids = devices_map.get(user_jid, [jid_encode(decoded.user, decoded.server, 0)])
            all_device_jids.extend(device_jids)

        # Filter out our exact sending device
        me_device_jid = self.client.creds.me["id"]
        me_session_key = signal_repo._session_key(me_device_jid)
        all_device_jids = [
            jid for jid in all_device_jids
            if signal_repo._session_key(jid) != me_session_key
        ]

        # Ensure sessions exist for all devices
        await self._assert_sessions(signal_repo, all_device_jids)

        # Build message payloads
        msg = wa_pb2.Message()
        msg.conversation = text

        me_msg = wa_pb2.Message()
        me_msg.deviceSentMessage.destinationJid = target_jid
        me_msg.deviceSentMessage.message.conversation = text

        # Encrypt for each device
        participants: list[BinaryNode] = []
        include_device_identity = False

        for device_jid in all_device_jids:
            decoded = jid_decode(device_jid)
            if not decoded:
                continue

            # Use deviceSentMessage for own devices, regular message for others
            is_own_device = jid_normalized_user(device_jid) == me_jid
            if is_own_device and me_jid != target_jid:
                payload = _write_random_pad_max16(me_msg.SerializeToString())
            else:
                payload = _write_random_pad_max16(msg.SerializeToString())

            msg_type, ciphertext = await signal_repo.encrypt_message(device_jid, payload)
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
            attrs={"to": target_jid, "id": msg_id, "type": "text"},
            content=content,
        )
        await self.client.send_node(node)
        return msg_id

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
