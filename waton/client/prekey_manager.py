"""Pre-key manager for E2EE keys lifecycle, rotation, and server replenishment."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from waton.core.jid import S_WHATSAPP_NET
from waton.defaults.config import KEY_BUNDLE_TYPE
from waton.protocol.binary_node import BinaryNode
from waton.protocol.signal_repo import SignalRepository
from waton.utils.crypto import generate_keypair, sign

if TYPE_CHECKING:
    from waton.client.client import WAClient

logger = logging.getLogger(__name__)


def _encode_big_endian(value: int, width: int = 4) -> bytes:
    return int(value).to_bytes(width, byteorder="big", signed=False)


class PreKeyManager:
    """Manages pre-key count queries, server uploading, key bundle digest verification,
    and signed pre-key rotation to prevent OTK exhaustion."""

    INITIAL_PREKEY_COUNT = 30
    MIN_PREKEY_COUNT = 5
    PREKEY_BATCH_SIZE = 30
    UPLOAD_TIMEOUT = 15.0

    def __init__(self, client: WAClient) -> None:
        self.client = client
        self._upload_lock = asyncio.Lock()
        self._upload_task: asyncio.Task[None] | None = None

    async def get_available_prekeys_on_server(self) -> int:
        """Fetch the number of available one-time pre-keys on WhatsApp server."""
        iq = BinaryNode(
            tag="iq",
            attrs={
                "id": self.client.generate_message_tag(),
                "xmlns": "encrypt",
                "type": "get",
                "to": S_WHATSAPP_NET,
            },
            content=[BinaryNode(tag="count", attrs={})],
        )
        res = await self.client.query(iq)
        if isinstance(res.content, list):
            for child in res.content:
                if isinstance(child, BinaryNode) and child.tag == "count":
                    val = child.attrs.get("value")
                    if val is not None:
                        return int(val)
        return 0

    async def verify_current_prekey_exists(self) -> dict[str, Any]:
        """Check if the current prekey exists in local storage."""
        if not self.client.creds:
            return {"exists": False, "current_prekey_id": 0}
        current_id = self.client.creds.next_pre_key_id - 1
        if current_id <= 0:
            return {"exists": False, "current_prekey_id": 0}

        prekey = await self.client.storage.get_prekey(current_id)
        return {"exists": prekey is not None, "current_prekey_id": current_id}

    async def upload_prekeys(self, count: int = PREKEY_BATCH_SIZE) -> None:
        """Generate and upload a fresh batch of pre-keys to the server."""
        async with self._upload_lock:
            if not self.client.creds or not self.client.storage:
                logger.warning("cannot upload pre-keys: missing credentials or storage")
                return

            logger.info("generating and uploading %d pre-keys to server", count)
            signal_repo = SignalRepository(self.client.creds, self.client.storage)
            new_keys = await signal_repo.generate_prekeys(count)

            key_nodes = [
                BinaryNode(
                    tag="key",
                    attrs={},
                    content=[
                        BinaryNode(tag="id", attrs={}, content=_encode_big_endian(((k["keyId"] - 1) % 0xFFFFFF) + 1, 3)),
                        BinaryNode(tag="value", attrs={}, content=k["keyPair"]["public"]),
                    ],
                )
                for k in new_keys
            ]

            signed_pre_key = self.client.creds.signed_pre_key
            skey_id = ((signed_pre_key["keyId"] - 1) % 0xFFFFFF) + 1
            skey_node = BinaryNode(
                tag="skey",
                attrs={},
                content=[
                    BinaryNode(tag="id", attrs={}, content=_encode_big_endian(skey_id, 3)),
                    BinaryNode(tag="value", attrs={}, content=signed_pre_key["keyPair"]["public"]),
                    BinaryNode(tag="signature", attrs={}, content=signed_pre_key["signature"]),
                ],
            )


            iq = BinaryNode(
                tag="iq",
                attrs={
                    "id": self.client.generate_message_tag(),
                    "xmlns": "encrypt",
                    "type": "set",
                    "to": S_WHATSAPP_NET,
                },
                content=[
                    BinaryNode(
                        tag="registration",
                        attrs={},
                        content=_encode_big_endian(self.client.creds.registration_id, 4),
                    ),
                    BinaryNode(tag="type", attrs={}, content=KEY_BUNDLE_TYPE),
                    BinaryNode(tag="identity", attrs={}, content=self.client.creds.signed_identity_key["public"]),
                    BinaryNode(tag="list", attrs={}, content=key_nodes),
                    skey_node,
                ],
            )

            await self.client.query(iq)
            logger.info("successfully uploaded %d pre-keys to server", count)

    async def upload_prekeys_if_required(self) -> None:
        """Check server pre-key count and replenish if depleted or current key missing."""
        try:
            prekey_count = await self.get_available_prekeys_on_server()
            check = await self.verify_current_prekey_exists()
            current_exists = check["exists"]
            current_id = check["current_prekey_id"]

            logger.debug(
                "server pre-keys: %d, local prekey id %d exists: %s",
                prekey_count,
                current_id,
                current_exists,
            )

            low_count = prekey_count <= self.MIN_PREKEY_COUNT
            missing_current = (not current_exists) and (current_id > 0)

            if low_count or missing_current:
                reasons: list[str] = []
                if low_count:
                    reasons.append(f"server count low ({prekey_count})")
                if missing_current:
                    reasons.append(f"current prekey {current_id} missing from storage")
                logger.info("uploading pre-keys due to: %s", ", ".join(reasons))

                target_count = self.INITIAL_PREKEY_COUNT if prekey_count == 0 else self.PREKEY_BATCH_SIZE
                await self.upload_prekeys(target_count)
        except Exception as exc:
            logger.warning("pre-key verification/upload encountered an error: %s", exc)

    async def rotate_signed_prekey(self) -> None:
        """Generate a new signed pre-key, sign it with identity private key, and upload to server."""
        if not self.client.creds or not self.client.storage:
            logger.warning("cannot rotate signed pre-key: missing creds or storage")
            return

        current_skey = self.client.creds.signed_pre_key or {}
        new_id = int(current_skey.get("keyId", 0)) + 1
        new_kp = generate_keypair()
        new_sig = sign(
            self.client.creds.signed_identity_key["private"],
            KEY_BUNDLE_TYPE + new_kp["public"],
        )

        new_skey = {
            "keyId": new_id,
            "keyPair": new_kp,
            "signature": new_sig,
        }

        skey_node = BinaryNode(
            tag="skey",
            attrs={},
            content=[
                BinaryNode(tag="id", attrs={}, content=_encode_big_endian(new_id, 3)),
                BinaryNode(tag="value", attrs={}, content=new_kp["public"]),
                BinaryNode(tag="signature", attrs={}, content=new_sig),
            ],
        )

        rotate_iq = BinaryNode(
            tag="iq",
            attrs={
                "id": self.client.generate_message_tag(),
                "xmlns": "encrypt",
                "type": "set",
                "to": S_WHATSAPP_NET,
            },
            content=[BinaryNode(tag="rotate", attrs={}, content=[skey_node])],
        )

        await self.client.query(rotate_iq)
        self.client.creds.signed_pre_key = new_skey
        await self.client.storage.save_creds(self.client.creds)
        logger.info("successfully rotated signed pre-key to id %d", new_id)

    async def digest_key_bundle(self) -> bool:
        """Validate current key bundle on server. Triggers pre-key upload on mismatch."""
        try:
            iq = BinaryNode(
                tag="iq",
                attrs={
                    "id": self.client.generate_message_tag(),
                    "xmlns": "encrypt",
                    "type": "get",
                    "to": S_WHATSAPP_NET,
                },
                content=[BinaryNode(tag="digest", attrs={})],
            )
            res = await self.client.query(iq)
            if isinstance(res.content, list):
                for child in res.content:
                    if isinstance(child, BinaryNode) and child.tag == "digest":
                        return True
            logger.warning("digest query returned no digest node, uploading pre-keys")
            await self.upload_prekeys()
            return False
        except Exception as exc:
            logger.warning("key bundle digest verification failed: %s", exc)
            await self.upload_prekeys()
            return False

    def handle_prekey_count_notification(self, count: int) -> None:
        """Handle incoming `<notification type="encrypt"><count value="N"/></notification>`."""
        logger.info("received prekey count notification from server: %d", count)
        if count <= self.MIN_PREKEY_COUNT:
            logger.info("server pre-key count is low (%d <= %d), scheduling refill", count, self.MIN_PREKEY_COUNT)
            self._upload_task = asyncio.create_task(self.upload_prekeys(self.PREKEY_BATCH_SIZE))

