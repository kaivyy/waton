"""USync query for fetching device lists from WhatsApp server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from waton.core.jid import S_WHATSAPP_NET, jid_decode, jid_encode
from waton.protocol.binary_node import BinaryNode

if TYPE_CHECKING:
    from waton.client.client import WAClient


class USyncQuery:
    """Query WhatsApp server for user device information and selected profile protocols."""

    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def get_devices(self, jids: list[str]) -> dict[str, list[str]]:
        """
        Query device list for given JIDs.

        Returns dict mapping user JID -> list of device JIDs.
        Example: {"628xxx@s.whatsapp.net": ["628xxx:0@s.whatsapp.net", "628xxx:1@s.whatsapp.net"]}
        """
        if not jids:
            return {}

        query_node = self._build_usync_query(jids=jids, protocols=["devices"], context="message")
        result = await self.client.query(query_node)
        return self._parse_device_result(result)

    async def get_contact_status_lid_and_disappearing_mode(
        self,
        jids: list[str],
    ) -> dict[str, dict[str, dict[str, str]]]:
        if not jids:
            return {}

        query_node = self._build_usync_query(
            jids=jids,
            protocols=["contact", "status", "lid", "disappearing_mode"],
            context="interactive",
        )
        result = await self.client.query(query_node)
        return self._parse_multi_protocol_result(result, ["contact", "status", "lid", "disappearing_mode"])

    async def get_picture_business_and_verified_name(self, jids: list[str]) -> dict[str, dict[str, dict[str, str]]]:
        if not jids:
            return {}

        protocols = ["picture", "business", "verified_name"]
        query_node = self._build_usync_query(
            jids=jids,
            protocols=protocols,
            context="interactive",
        )
        result = await self.client.query(query_node)
        return self._parse_multi_protocol_result(result, protocols)

    async def get_device_and_bot_profile(self, jids: list[str]) -> dict[str, dict[str, dict[str, str]]]:
        if not jids:
            return {}

        protocols = ["device", "bot_profile", "sidelist"]
        query_node = self._build_usync_query(
            jids=jids,
            protocols=protocols,
            context="interactive",
        )
        result = await self.client.query(query_node)
        return self._parse_multi_protocol_result(result, protocols)

    async def on_whatsapp(self, *phone_numbers: str) -> list[dict[str, Any]]:
        """Check if phone numbers exist on WhatsApp."""
        if not phone_numbers:
            return []

        formatted_numbers = []
        for phone in phone_numbers:
            clean = phone.replace("+", "").replace("@s.whatsapp.net", "")
            clean = "".join(c for c in clean if c.isdigit())
            formatted_numbers.append(clean)

        user_nodes: list[BinaryNode] = []
        for clean_phone in formatted_numbers:
            user_nodes.append(
                BinaryNode(
                    tag="user",
                    attrs={},
                    content=[
                        BinaryNode(tag="contact", attrs={}, content=f"+{clean_phone}")
                    ],
                )
            )

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
                        "sid": self.client.generate_message_tag(),
                        "mode": "query",
                        "last": "true",
                        "index": "0",
                        "context": "interactive",
                    },
                    content=[
                        BinaryNode(
                            tag="query",
                            attrs={},
                            content=[BinaryNode(tag="contact", attrs={})],
                        ),
                        BinaryNode(tag="list", attrs={}, content=user_nodes),
                    ],
                )
            ],
        )

        result = await self.client.query(query_node)
        out = []
        
        usync_node = self._get_child(result, "usync")
        if not usync_node:
            return out

        list_node = self._get_child(usync_node, "list")
        if not list_node or not isinstance(list_node.content, list):
            return out

        for user_node in list_node.content:
            if user_node.tag != "user":
                continue
            jid = user_node.attrs.get("jid")
            if not jid:
                continue

            contact_node = self._get_child(user_node, "contact")
            exists = False
            if contact_node and contact_node.attrs.get("type") == "in":
                exists = True

            phone = f"+{jid.split('@')[0]}"
            out.append({"jid": jid, "exists": exists, "phone": phone})

        return out

    def _build_usync_query(self, *, jids: list[str], protocols: list[str], context: str) -> BinaryNode:
        user_nodes: list[BinaryNode] = []
        for jid in jids:
            decoded = jid_decode(jid)
            if not decoded:
                continue
            user_jid = jid_encode(decoded.user, decoded.server)
            user_nodes.append(BinaryNode(tag="user", attrs={"jid": user_jid}))

        protocol_nodes: list[BinaryNode] = []
        for protocol in protocols:
            if protocol == "devices":
                protocol_nodes.append(BinaryNode(tag="devices", attrs={"version": "2"}))
            elif protocol == "bot":
                protocol_nodes.append(
                    BinaryNode(tag="bot", attrs={}, content=[BinaryNode(tag="profile", attrs={"v": "1"})])
                )
            else:
                protocol_nodes.append(BinaryNode(tag=protocol, attrs={}))

        return BinaryNode(
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
                        "sid": self.client.generate_message_tag(),
                        "mode": "query",
                        "last": "true",
                        "index": "0",
                        "context": context,
                    },
                    content=[
                        BinaryNode(tag="query", attrs={}, content=protocol_nodes),
                        BinaryNode(tag="list", attrs={}, content=user_nodes),
                    ],
                )
            ],
        )

    def _parse_multi_protocol_result(
        self,
        node: BinaryNode,
        protocols: list[str],
    ) -> dict[str, dict[str, dict[str, str]]]:
        if node.attrs.get("type") == "error":
            err_node = self._get_child(node, "error")
            code = err_node.attrs.get("code", "unknown") if err_node else "unknown"
            text = err_node.attrs.get("text", "") if err_node else ""
            raise ValueError(f"USync IQ error {code}: {text}")

        result: dict[str, dict[str, dict[str, str]]] = {}

        usync_node = self._get_child(node, "usync")
        if not usync_node:
            return result

        list_node = self._get_child(usync_node, "list")
        if not list_node or not isinstance(list_node.content, list):
            return result

        for user_node in list_node.content:
            if user_node.tag != "user":
                continue
            user_jid = user_node.attrs.get("jid")
            if not user_jid:
                continue

            row: dict[str, dict[str, str]] = {}
            for protocol in protocols:
                protocol_node = self._get_child(user_node, protocol)
                if protocol_node:
                    data = {k: str(v) for k, v in protocol_node.attrs.items()}
                    if protocol_node.content:
                        if isinstance(protocol_node.content, (bytes, bytearray)):
                            content_str = bytes(protocol_node.content).decode("utf-8", errors="ignore")
                            data.setdefault("text", content_str)
                            data.setdefault("status", content_str)
                        elif isinstance(protocol_node.content, str):
                            data.setdefault("text", protocol_node.content)
                            data.setdefault("status", protocol_node.content)
                        elif isinstance(protocol_node.content, list):
                            profile_child = self._get_child(protocol_node, "profile")
                            if profile_child:
                                data.update({f"profile_{k}": str(v) for k, v in profile_child.attrs.items()})
                    row[protocol] = data
                else:
                    row[protocol] = {}
            result[user_jid] = row

        return result

    def _parse_device_result(self, node: BinaryNode) -> dict[str, list[str]]:
        """Parse usync result to extract device JIDs."""
        if node.attrs.get("type") == "error":
            err_node = self._get_child(node, "error")
            code = err_node.attrs.get("code", "unknown") if err_node else "unknown"
            text = err_node.attrs.get("text", "") if err_node else ""
            raise ValueError(f"USync device query error {code}: {text}")

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

            device_list_node = self._get_child(devices_node, "device-list") or self._get_child(devices_node, "key-index-list")
            if device_list_node and isinstance(device_list_node.content, list):
                for device_node in device_list_node.content:
                    if device_node.tag != "device":
                        continue
                    device_id = device_node.attrs.get("id")
                    if device_id is not None:
                        device_jid = jid_encode(decoded.user, decoded.server, int(device_id))
                        if device_jid not in device_list:
                            device_list.append(device_jid)

            if isinstance(devices_node.content, list):
                for child in devices_node.content:
                    if child.tag == "device":
                        device_id = child.attrs.get("id")
                        if device_id is not None:
                            device_jid = jid_encode(decoded.user, decoded.server, int(device_id))
                            if device_jid not in device_list:
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
