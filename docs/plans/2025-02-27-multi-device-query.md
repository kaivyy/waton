# Multi-Device Query Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement USync device query so messages are encrypted and sent to ALL devices of a recipient, not just device 0.

**Architecture:** Add USyncQuery class to query WhatsApp server for recipient's device list, then encrypt message for each device separately before sending.

**Tech Stack:** Python async, Protocol Buffers, existing Signal encryption

---

## Task 1: Create USyncQuery Module

**Files:**
- Create: `pywa/client/usync.py`

**Step 1: Write the USyncQuery class**

```python
"""USync query for fetching device lists from WhatsApp server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pywa.core.jid import S_WHATSAPP_NET, jid_decode, jid_encode
from pywa.protocol.binary_node import BinaryNode

if TYPE_CHECKING:
    from pywa.client.client import WAClient


class USyncQuery:
    """Query WhatsApp server for user device information."""

    def __init__(self, client: WAClient):
        self.client = client

    async def get_devices(self, jids: list[str]) -> dict[str, list[str]]:
        """
        Query device list for given JIDs.

        Returns dict mapping user JID -> list of device JIDs.
        Example: {"628xxx@s.whatsapp.net": ["628xxx:0@s.whatsapp.net", "628xxx:1@s.whatsapp.net"]}
        """
        if not jids:
            return {}

        # Build usync query node
        user_nodes = []
        for jid in jids:
            decoded = jid_decode(jid)
            if not decoded:
                continue
            # Normalize to user JID without device
            user_jid = jid_encode(decoded.user, decoded.server)
            user_nodes.append(
                BinaryNode(
                    tag="user",
                    attrs={"jid": user_jid},
                )
            )

        if not user_nodes:
            return {}

        query_node = BinaryNode(
            tag="iq",
            attrs={
                "to": S_WHATSAPP_NET,
                "type": "get",
                "xmlns": "usync",
            },
            content=[
                BinaryNode(
                    tag="usync",
                    attrs={
                        "sid": self.client._generate_message_tag(),
                        "mode": "query",
                        "last": "true",
                        "index": "0",
                        "context": "message",
                    },
                    content=[
                        BinaryNode(
                            tag="query",
                            attrs={},
                            content=[
                                BinaryNode(
                                    tag="devices",
                                    attrs={"version": "2"},
                                )
                            ],
                        ),
                        BinaryNode(
                            tag="list",
                            attrs={},
                            content=user_nodes,
                        ),
                    ],
                )
            ],
        )

        result = await self.client.query(query_node)
        return self._parse_device_result(result)

    def _parse_device_result(self, node: BinaryNode) -> dict[str, list[str]]:
        """Parse usync result to extract device JIDs."""
        devices_map: dict[str, list[str]] = {}

        usync_node = self._get_child(node, "usync")
        if not usync_node:
            return devices_map

        list_node = self._get_child(usync_node, "list")
        if not list_node or not isinstance(list_node.content, list):
            return devices_map

        for user_node in list_node.content:
            if user_node.tag != "user":
                continue

            user_jid = user_node.attrs.get("jid")
            if not user_jid:
                continue

            decoded = jid_decode(user_jid)
            if not decoded:
                continue

            device_list: list[str] = []

            devices_node = self._get_child(user_node, "devices")
            if not devices_node:
                # No devices info, assume device 0 only
                device_list.append(jid_encode(decoded.user, decoded.server, 0))
                devices_map[user_jid] = device_list
                continue

            device_list_node = self._get_child(devices_node, "device-list")
            if device_list_node and isinstance(device_list_node.content, list):
                for device_node in device_list_node.content:
                    if device_node.tag != "device":
                        continue
                    device_id = device_node.attrs.get("id")
                    if device_id is not None:
                        device_jid = jid_encode(decoded.user, decoded.server, int(device_id))
                        device_list.append(device_jid)

            # If no devices found, assume device 0
            if not device_list:
                device_list.append(jid_encode(decoded.user, decoded.server, 0))

            devices_map[user_jid] = device_list

        return devices_map

    @staticmethod
    def _get_child(node: BinaryNode, tag: str) -> BinaryNode | None:
        if not isinstance(node.content, list):
            return None
        for child in node.content:
            if child.tag == tag:
                return child
        return None
```

---

## Task 2: Update MessagesAPI to Use Multi-Device

**Files:**
- Modify: `pywa/client/messages.py`

**Step 1: Import USyncQuery and update send_text**

Update `send_text` method to:
1. Query devices for recipient
2. Encrypt message for each device
3. Send with multiple `<to>` nodes

```python
# Add import at top
from pywa.client.usync import USyncQuery

# Replace send_text method with:
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
        device_jids = devices_map.get(user_jid, [jid_encode(jid_decode(user_jid).user, jid_decode(user_jid).server, 0)])
        all_device_jids.extend(device_jids)

    # Filter out our own sending device
    me_device_jid = self.client.creds.me["id"]
    all_device_jids = [jid for jid in all_device_jids if jid != me_device_jid]

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
            payload = me_msg.SerializeToString()
        else:
            payload = msg.SerializeToString()

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
```

---

## Task 3: Update SignalRepository for Device-Specific Sessions

**Files:**
- Modify: `pywa/protocol/signal_repo.py`

**Step 1: Update jid_to_signal_address to handle device IDs**

The current implementation already handles device IDs correctly via `jid_decode`. No changes needed.

---

## Task 4: Add jid_encode Import to messages.py

**Files:**
- Modify: `pywa/client/messages.py`

**Step 1: Add missing import**

```python
from pywa.core.jid import S_WHATSAPP_NET, jid_normalized_user, jid_decode, jid_encode
```

---

## Task 5: Test Multi-Device Query

**Test manually:**

```bash
$env:PYWA_AUTH_DB='pywa_live.db'
$env:PYWA_TEST_JID='628980145555@s.whatsapp.net'
$env:PYWA_TEST_TEXT='test multi-device from pywa'
python -u examples/live_connect.py
```

Expected: Message should be received on recipient's phone.

---

## Summary

| Task | Description |
|------|-------------|
| 1 | Create `pywa/client/usync.py` with USyncQuery class |
| 2 | Update `messages.py` send_text to use multi-device |
| 3 | Verify signal_repo handles device JIDs (no change needed) |
| 4 | Add missing imports to messages.py |
| 5 | Manual test |
