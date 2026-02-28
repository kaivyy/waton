"""USync query for fetching device lists from WhatsApp server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from waton.core.jid import S_WHATSAPP_NET, jid_decode, jid_encode
from waton.protocol.binary_node import BinaryNode

if TYPE_CHECKING:
    from waton.client.client import WAClient


class USyncQuery:
    """Query WhatsApp server for user device information and selected profile protocols."""

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

        query_node = self._build_usync_query(jids=jids, protocols=["devices"], context="message")
        result = await self.client.query(query_node)
        return self._parse_device_result(result)

    async def get_contact_status_lid_and_disappearing_mode(self, jids: list[str]) -> dict[str, dict[str, dict[str, str]]]:
        if not jids:
            return {}

        query_node = self._build_usync_query(
            jids=jids,
            protocols=["contact", "status", "lid", "disappearing_mode"],
            context="interactive",
        )
        result = await self.client.query(query_node)
        return self._parse_multi_protocol_result(result, ["contact", "status", "lid", "disappearing_mode"])

    def _build_usync_query(self, *, jids: list[str], protocols: list[str], context: str) -> BinaryNode:
        user_nodes = []
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
                        "sid": self.client._generate_message_tag(),
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

    def _parse_multi_protocol_result(self, node: BinaryNode, protocols: list[str]) -> dict[str, dict[str, dict[str, str]]]:
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
                    row[protocol] = {k: str(v) for k, v in protocol_node.attrs.items()}
                else:
                    row[protocol] = {}
            result[user_jid] = row

        return result

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
