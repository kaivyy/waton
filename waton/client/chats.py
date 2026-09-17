
from __future__ import annotations

import time
from typing import Any

from waton.client.client import WAClient
from waton.core.jid import S_WHATSAPP_NET, jid_normalized_user
from waton.protocol.app_state import chat_modification_to_app_patch
from waton.protocol.binary_node import BinaryNode

_CHAT_MODIFY_ACTIONS: dict[str, tuple[str, dict[str, str]]] = {
    "archive": ("archive", {"value": "true"}),
    "unarchive": ("archive", {"value": "false"}),
    "pin": ("pin", {"value": "true"}),
    "unpin": ("pin", {"value": "false"}),
    "mute": ("mute", {"value": "true"}),
    "unmute": ("mute", {"value": "false"}),
    "read": ("mark", {"type": "read"}),
    "unread": ("mark", {"type": "unread"}),
}


class ChatsAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def send_presence_update(self, jid: str, presence: str) -> None:
        """
        Sends presence updates (e.g. typing, available) to a specific chat.
        presence: 'composing', 'paused', 'available', 'unavailable'
        """
        node = BinaryNode(
            tag="presence",
            attrs={"to": jid, "type": presence}
        )
        await self.client.send_node(node)

    async def send_chat_presence(self, jid: str, state: str = "composing", media: str | None = None) -> None:
        """Sends chatstate typing/recording status to a conversation."""
        child_attrs = {"media": media} if media else {}
        node = BinaryNode(
            tag="chatstate",
            attrs={"to": jid},
            content=[BinaryNode(tag=state, attrs=child_attrs)],
        )
        await self.client.send_node(node)

    async def presence_subscribe(self, jid: str) -> None:
        content = None
        tc_mgr = getattr(self.client, "tc_token_manager", None)
        if tc_mgr is not None:
            token_data = tc_mgr.get_token(jid)
            if token_data:
                from waton.utils.tc_token import build_tc_token_node
                content = [build_tc_token_node(token_data["token"], token_data["timestamp"])]
        node = BinaryNode(tag="presence", attrs={"to": jid, "type": "subscribe"}, content=content)
        await self.client.send_node(node)

    async def get_profile_picture(self, jid: str, picture_type: str = "preview") -> str | None:
        """Requests the profile picture URL for a JID."""
        norm_jid = jid_normalized_user(jid)

        tc_token_content = None
        tc_mgr = getattr(self.client, "tc_token_manager", None)
        me = getattr(self.client, "creds", None) and getattr(self.client.creds, "me", None)
        is_self = me and (
            norm_jid == jid_normalized_user(me.get("id", ""))
            or (me.get("lid") and norm_jid == jid_normalized_user(me.get("lid", "")))
        )
        if tc_mgr is not None and not is_self:
            token_data = tc_mgr.get_token(norm_jid)
            if token_data:
                from waton.utils.tc_token import build_tc_token_node

                tc_token_content = [build_tc_token_node(token_data["token"], token_data["timestamp"])]

        query_node = BinaryNode(
            tag="iq",
            attrs={"target": norm_jid, "to": S_WHATSAPP_NET, "type": "get", "xmlns": "w:profile:picture"},
            content=[
                BinaryNode(
                    tag="picture",
                    attrs={"type": picture_type, "query": "url"},
                    content=tc_token_content,
                )
            ],
        )
        res = await self.client.query(query_node)
        picture = self._find_child(res, "picture")
        return picture.attrs.get("url") if picture else None

    async def update_profile_picture(self, jid: str, picture_bytes: bytes) -> None:
        """Updates the profile picture for the account or a group."""
        attrs: dict[str, str] = {"to": "s.whatsapp.net", "type": "set", "xmlns": "w:profile:picture"}
        if jid:
            attrs["target"] = jid
        node = BinaryNode(
            tag="iq",
            attrs=attrs,
            content=[BinaryNode(tag="picture", attrs={"type": "image"}, content=picture_bytes)],
        )
        await self.client.query(node)

    async def remove_profile_picture(self, jid: str) -> None:
        """Removes the profile picture for the account or a group."""
        attrs: dict[str, str] = {"to": "s.whatsapp.net", "type": "set", "xmlns": "w:profile:picture"}
        if jid:
            attrs["target"] = jid
        node = BinaryNode(
            tag="iq",
            attrs=attrs,
            content=[BinaryNode(tag="picture", attrs={"type": "image", "delete": "true"})],
        )
        await self.client.query(node)

    async def fetch_blocklist(self) -> list[str]:
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "get", "xmlns": "blocklist"},
            content=None,
        )
        result = await self.client.query(node)
        list_node = self._find_child(result, "list")
        if not list_node:
            return []
        return [
            item.attrs["jid"]
            for item in self._find_children(list_node, "item")
            if "jid" in item.attrs
        ]

    async def update_block_status(self, jid: str, action: str = "block") -> None:
        """Blocks or unblocks a JID ('block' or 'unblock')."""
        if action not in {"block", "unblock"}:
            raise ValueError(f"Invalid block action: {action}, must be 'block' or 'unblock'")

        normalized_jid = jid_normalized_user(jid)
        target_lid = normalized_jid
        pn_jid: str | None = None

        lid_map = getattr(self.client, "lid_mapping", None)
        if lid_map is not None:
            if "@lid" in normalized_jid:
                pn_jid = await lid_map.get_pn_for_lid(normalized_jid)
            else:
                mapped_lid = await lid_map.get_lid_for_pn(normalized_jid)
                if mapped_lid:
                    target_lid = mapped_lid
                    pn_jid = normalized_jid
        elif "@s.whatsapp.net" in normalized_jid:
            pn_jid = normalized_jid

        item_attrs: dict[str, str] = {"action": action, "jid": target_lid}
        if action == "block" and pn_jid:
            item_attrs["pn_jid"] = pn_jid

        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "set", "xmlns": "blocklist"},
            content=[BinaryNode(tag="item", attrs=item_attrs)],
        )
        await self.client.query(node)

    async def fetch_privacy_settings(self) -> dict[str, str]:
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "get", "xmlns": "privacy"},
            content=[BinaryNode(tag="privacy", attrs={})],
        )
        result = await self.client.query(node)
        privacy = self._find_child(result, "privacy")
        if privacy is None:
            return {}

        settings: dict[str, str] = {}
        for category in self._find_children(privacy, "category"):
            name = category.attrs.get("name")
            value = category.attrs.get("value")
            if name and value:
                settings[name] = value
        return settings

    async def update_last_seen_privacy(self, value: str) -> None:
        await self._privacy_update("last", value)

    async def update_online_privacy(self, value: str) -> None:
        await self._privacy_update("online", value)

    async def update_profile_picture_privacy(self, value: str) -> None:
        await self._privacy_update("profile", value)

    async def update_status_privacy(self, value: str) -> None:
        await self._privacy_update("status", value)

    async def update_groups_privacy(self, value: str) -> None:
        await self._privacy_update("groupadd", value)

    async def update_read_receipts_privacy(self, value: str) -> None:
        await self._privacy_update("readreceipts", value)

    async def update_messages_privacy(self, value: str) -> None:
        """Update messages privacy category ('all' or 'contacts')."""
        await self._privacy_update("messages", value)

    async def update_call_privacy(self, value: str) -> None:
        """Update call privacy category ('all' or 'known')."""
        await self._privacy_update("calladd", value)

    async def set_default_disappearing_mode(self, duration: int) -> None:
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "set", "xmlns": "disappearing_mode"},
            content=[BinaryNode(tag="disappearing_mode", attrs={"duration": str(duration)})],
        )
        await self.client.query(node)


    async def _privacy_update(self, name: str, value: str) -> None:
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "set", "xmlns": "privacy"},
            content=[
                BinaryNode(
                    tag="privacy",
                    attrs={},
                    content=[BinaryNode(tag="category", attrs={"name": name, "value": value})],
                )
            ],
        )
        await self.client.query(node)

    async def issue_privacy_tokens(self, jids: list[str], timestamp: int | None = None) -> BinaryNode:
        """Issues trusted contact privacy tokens to a list of JIDs."""
        import time
        from waton.core.jid import jid_decode, jid_encode

        t = str(timestamp if timestamp is not None else int(time.time()))
        tokens: list[BinaryNode] = []
        for jid in jids:
            decoded = jid_decode(jid)
            normalized = jid_encode(decoded.user, decoded.server) if decoded else jid
            tokens.append(
                BinaryNode(
                    tag="token",
                    attrs={"jid": normalized, "t": t, "type": "trusted_contact"},
                )
            )
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "set", "xmlns": "privacy"},
            content=[BinaryNode(tag="tokens", attrs={}, content=tokens)],
        )
        return await self.client.query(node)

    async def update_profile_status(self, status: str) -> None:
        """Updates the current user's about/status text."""
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "set", "xmlns": "status"},
            content=[BinaryNode(tag="status", attrs={}, content=status)]
        )
        await self.client.send_node(node)

    async def update_profile_name(self, name: str) -> None:
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "set", "xmlns": "profile"},
            content=[BinaryNode(tag="profile", attrs={"name": name})],
        )
        await self.client.send_node(node)

    async def chat_modify(
        self,
        jid: str,
        action: str | dict[str, Any],
        *,
        use_syncd: bool = False,
    ) -> None:
        """Modifies chat archive/mute/pin/read status via `w:chat` query or syncd patch."""
        if isinstance(action, dict):
            patch = chat_modification_to_app_patch(action, jid)
            await self.app_patch(patch)
            return

        normalized_action = action.strip().lower()
        if use_syncd:
            mod_dict = {
                "archive": {"archive": True},
                "unarchive": {"archive": False},
                "pin": {"pin": True},
                "unpin": {"pin": False},
                "mute": {"mute": True},
                "unmute": {"mute": False},
                "read": {"mark_read": True},
                "unread": {"mark_read": False},
            }.get(normalized_action)
            if mod_dict:
                patch = chat_modification_to_app_patch(mod_dict, jid)
                await self.app_patch(patch)
                return

        action_spec = _CHAT_MODIFY_ACTIONS.get(normalized_action)
        if action_spec is None:
            raise ValueError(f"Unsupported chat modify action: {action}")

        op_tag, op_attrs = action_spec
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "set", "xmlns": "w:chat"},
            content=[
                BinaryNode(
                    tag="chat",
                    attrs={"jid": jid},
                    content=[BinaryNode(tag=op_tag, attrs=dict(op_attrs))],
                )
            ],
        )
        await self.client.query(node)

    async def app_patch(self, patch_create: dict[str, Any]) -> BinaryNode:
        """Sends a Syncd mutation patch to WhatsApp server."""
        from waton.utils.chat_utils import encode_syncd_patch
        from waton.utils.lt_hash import new_lt_hash_state

        patch_type = str(patch_create.get("type", "regular_low"))
        patch_bytes: bytes | None = None
        current_version = 0
        new_state = None

        key_id = getattr(self.client.creds, "my_app_state_key_id", None) if self.client.creds else None
        key_data = getattr(self.client.creds, "app_state_sync_key", None) if self.client.creds else None

        if key_id and key_data:
            state = getattr(self.client, "_app_state_sync_versions", {}).get(patch_type) or new_lt_hash_state()
            result = encode_syncd_patch(patch_create, key_id, state, key_data)
            patch_bytes = result["patch"]
            current_version = state.get("version", 0)
            new_state = result["state"]

        collection_content: list[BinaryNode] | None = None
        if patch_bytes:
            collection_content = [BinaryNode(tag="patch", attrs={}, content=patch_bytes)]

        iq = BinaryNode(
            tag="iq",
            attrs={
                "to": S_WHATSAPP_NET,
                "type": "set",
                "xmlns": "w:sync:app:state",
                "id": self.client.generate_message_tag(),
            },
            content=[
                BinaryNode(
                    tag="sync",
                    attrs={},
                    content=[
                        BinaryNode(
                            tag="collection",
                            attrs={
                                "name": patch_type,
                                "version": str(current_version),
                                "return_snapshot": "false",
                            },
                            content=collection_content,
                        )
                    ],
                )
            ],
        )
        await self.client.send_node(iq)
        if new_state is not None:
            if not hasattr(self.client, "_app_state_sync_versions"):
                self.client._app_state_sync_versions = {}
            self.client._app_state_sync_versions[patch_type] = new_state

    async def star(
        self,
        jid: str,
        message_id: str,
        from_me: bool = False,
        star: bool = True,
    ) -> None:
        """Star or unstar a message via syncd app patch."""
        patch = chat_modification_to_app_patch(
            {"star": {"starred": star, "message_id": message_id, "from_me": from_me}},
            jid,
        )
        await self.app_patch(patch)

    async def add_label(
        self,
        name: str,
        color: int = 0,
        label_id: str | None = None,
        deleted: bool = False,
    ) -> None:
        """Create or edit a business label via syncd app patch."""
        lid = label_id or str(int(time.time() * 1000))
        patch = chat_modification_to_app_patch(
            {"add_label": {"name": name, "color": color, "id": lid, "deleted": deleted}},
            "",
        )
        await self.app_patch(patch)

    async def add_chat_label(self, jid: str, label_id: str) -> None:
        """Associate a label with a conversation."""
        patch = chat_modification_to_app_patch({"add_chat_label": {"label_id": label_id}}, jid)
        await self.app_patch(patch)

    async def remove_chat_label(self, jid: str, label_id: str) -> None:
        """Remove a label association from a conversation."""
        patch = chat_modification_to_app_patch({"remove_chat_label": {"label_id": label_id}}, jid)
        await self.app_patch(patch)

    async def add_message_label(self, jid: str, message_id: str, label_id: str) -> None:
        """Label a specific message."""
        patch = chat_modification_to_app_patch(
            {"add_message_label": {"label_id": label_id, "message_id": message_id}},
            jid,
        )
        await self.app_patch(patch)

    async def remove_message_label(self, jid: str, message_id: str, label_id: str) -> None:
        """Remove a label from a specific message."""
        patch = chat_modification_to_app_patch(
            {"remove_message_label": {"label_id": label_id, "message_id": message_id}},
            jid,
        )
        await self.app_patch(patch)

    async def create_call_link(
        self,
        call_type: str = "audio",
        start_time: int | None = None,
    ) -> str | None:
        """Generates WhatsApp call link ('audio' or 'video')."""
        content: list[BinaryNode] = []
        if start_time is not None:
            content.append(BinaryNode(tag="event", attrs={"start_time": str(start_time)}))

        node = BinaryNode(
            tag="call",
            attrs={
                "id": self.client.generate_message_tag(),
                "to": "@call",
            },
            content=[
                BinaryNode(
                    tag="link_create",
                    attrs={"media": call_type},
                    content=content if content else None,
                )
            ],
        )
        res = await self.client.query(node)
        link_node = self._find_child(res, "link_create")
        if link_node:
            return link_node.attrs.get("token")
        return None

    async def fetch_status(self, jid: str) -> str | None:
        """Fetches the about/status text for a user JID."""
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "get", "xmlns": "status"},
            content=[BinaryNode(tag="status", attrs={"jid": jid})],
        )
        res = await self.client.query(node)
        status_node = self._find_child(res, "status")
        if status_node and status_node.content is not None:
            return self._content_to_str(status_node.content)
        return None

    async def get_business_profile(self, jid: str) -> dict[str, Any] | None:
        """Fetches business profile details (address, description, email, website, etc.)."""
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "get", "xmlns": "w:biz"},
            content=[
                BinaryNode(
                    tag="business_profile",
                    attrs={"v": "244"},
                    content=[BinaryNode(tag="profile", attrs={"jid": jid})],
                )
            ],
        )
        res = await self.client.query(node)
        biz_node = self._find_child(res, "business_profile")
        profile_node = self._find_child(biz_node, "profile") if biz_node else None
        if not profile_node:
            return None
        profile_data: dict[str, Any] = {"jid": profile_node.attrs.get("jid", jid)}
        if isinstance(profile_node.content, list):
            for item in profile_node.content:
                if isinstance(item, BinaryNode):
                    profile_data[item.tag] = self._content_to_str(item.content)
        return profile_data

    async def resolve_contact_qr_link(self, code: str) -> dict[str, Any] | None:
        """Resolves wa.me/qr/<code> contact share QR code."""
        clean_code = code.split("/")[-1]
        iq = BinaryNode(
            tag="iq",
            attrs={
                "id": self.client.generate_message_tag(),
                "xmlns": "w:qr",
                "type": "get",
                "to": S_WHATSAPP_NET,
            },
            content=[BinaryNode(tag="qr", attrs={"code": clean_code})],
        )
        res = await self.client.query(iq)
        qr_node = self._find_child(res, "qr")
        if not qr_node:
            return None
        return {
            "jid": qr_node.attrs.get("jid"),
            "notify": qr_node.attrs.get("notify"),
            "type": qr_node.attrs.get("type"),
        }

    async def get_contact_qr_link(self, revoke: bool = False) -> str | None:
        """Gets own personal contact share QR link code."""
        iq = BinaryNode(
            tag="iq",
            attrs={
                "id": self.client.generate_message_tag(),
                "xmlns": "w:qr",
                "type": "set",
                "to": S_WHATSAPP_NET,
            },
            content=[BinaryNode(tag="qr", attrs={"type": "contact", "action": "revoke" if revoke else "get"})],
        )
        res = await self.client.query(iq)
        qr_node = self._find_child(res, "qr")
        return qr_node.attrs.get("code") if qr_node else None

    async def resolve_business_message_link(self, code: str) -> dict[str, Any] | None:
        """Resolves wa.me/message/<code> business message link."""
        clean_code = code.split("/")[-1]
        iq = BinaryNode(
            tag="iq",
            attrs={
                "id": self.client.generate_message_tag(),
                "xmlns": "w:qr",
                "type": "get",
                "to": S_WHATSAPP_NET,
            },
            content=[BinaryNode(tag="qr", attrs={"code": clean_code})],
        )
        res = await self.client.query(iq)
        qr_node = self._find_child(res, "qr")
        if not qr_node:
            return None
        msg_child = self._find_child(qr_node, "message")
        biz_child = self._find_child(qr_node, "business")
        return {
            "jid": qr_node.attrs.get("jid"),
            "notify": qr_node.attrs.get("notify"),
            "message": self._content_to_str(msg_child.content) if msg_child else "",
            "verified_name": biz_child.attrs.get("verified_name") if biz_child else None,
        }

    async def add_or_edit_contact(self, jid: str, contact_data: dict[str, Any]) -> None:
        """Adds or edits a contact in the phonebook via Syncd mutation."""
        patch = chat_modification_to_app_patch({"contact": contact_data}, jid)
        await self.app_patch(patch)

    async def remove_contact(self, jid: str) -> None:
        """Removes a contact from the phonebook via Syncd mutation."""
        patch = chat_modification_to_app_patch({"contact": {}, "remove": True}, jid)
        await self.app_patch(patch)

    async def add_or_edit_quick_reply(self, quick_reply: dict[str, Any]) -> None:
        """Adds or edits a business quick reply via Syncd mutation."""
        patch = chat_modification_to_app_patch({"quick_reply": quick_reply}, "")
        await self.app_patch(patch)

    async def remove_quick_reply(self, timestamp: int | str) -> None:
        """Removes a business quick reply via Syncd mutation."""
        patch = chat_modification_to_app_patch(
            {"quick_reply": {"timestamp": timestamp, "deleted": True}}, ""
        )
        await self.app_patch(patch)

    async def clean_dirty_bits(
        self,
        dirty_type: str = "account_sync",
        from_timestamp: int | None = None,
    ) -> None:
        """Cleans dirty sync bits on WhatsApp server ('account_sync' or 'groups')."""
        attrs = {"type": dirty_type}
        if from_timestamp is not None:
            attrs["timestamp"] = str(from_timestamp)
        node = BinaryNode(
            tag="iq",
            attrs={
                "to": S_WHATSAPP_NET,
                "type": "set",
                "xmlns": "urn:xmpp:whatsapp:dirty",
                "id": self.client.generate_message_tag(),
            },
            content=[BinaryNode(tag="clean", attrs=attrs)],
        )
        await self.client.send_node(node)

    async def fetch_props(self) -> dict[str, str]:
        """Fetches AB testing and server feature flags via 'abt' IQ."""
        node = BinaryNode(
            tag="iq",
            attrs={
                "to": S_WHATSAPP_NET,
                "type": "get",
                "xmlns": "abt",
                "id": self.client.generate_message_tag(),
            },
            content=[BinaryNode(tag="props", attrs={"protocol": "1"})],
        )
        res = await self.client.query(node)
        props_node = self._find_child(res, "props")
        props: dict[str, str] = {}
        if props_node and isinstance(props_node.content, list):
            for child in props_node.content:
                if isinstance(child, BinaryNode) and child.tag == "prop":
                    code = child.attrs.get("config_code", "")
                    val = child.attrs.get("config_value", "")
                    if code:
                        props[code] = val
        return props

    async def get_bot_list_v2(self) -> list[dict[str, Any]]:
        """Fetches list of official Meta AI bots via 'bot' IQ."""
        node = BinaryNode(
            tag="iq",
            attrs={
                "to": S_WHATSAPP_NET,
                "type": "get",
                "xmlns": "bot",
                "id": self.client.generate_message_tag(),
            },
            content=[BinaryNode(tag="bot", attrs={"v": "2"})],
        )
        res = await self.client.query(node)
        bot_node = self._find_child(res, "bot")
        bots: list[dict[str, Any]] = []
        if bot_node and isinstance(bot_node.content, list):
            for item in bot_node.content:
                if isinstance(item, BinaryNode):
                    bots.append(dict(item.attrs))
        return bots

    async def fetch_disappearing_duration(self, *jids: str) -> dict[str, int]:
        """Fetches disappearing mode duration for JIDs using USync."""
        from waton.client.usync import USyncQuery

        usync = USyncQuery(self.client)
        res = await usync.get_contact_status_lid_and_disappearing_mode(list(jids))
        durations: dict[str, int] = {}
        for jid, data in res.items():
            if isinstance(data, dict):
                dm = data.get("disappearing_mode")
                if isinstance(dm, dict):
                    try:
                        durations[jid] = int(dm.get("duration", 0) or 0)
                    except (ValueError, TypeError):
                        durations[jid] = 0
                elif dm is not None:
                    try:
                        durations[jid] = int(dm)
                    except (ValueError, TypeError):
                        durations[jid] = 0
                else:
                    durations[jid] = 0
        return durations

    @staticmethod
    def _content_to_str(content: object) -> str:
        if isinstance(content, (bytes, bytearray)):
            return bytes(content).decode("utf-8", errors="ignore")
        if isinstance(content, str):
            return content
        return ""

    @staticmethod
    def _children(node: BinaryNode | None) -> list[BinaryNode]:
        if node is None or not isinstance(node.content, list):
            return []
        return list(node.content)

    @classmethod
    def _find_child(cls, node: BinaryNode | None, tag: str) -> BinaryNode | None:
        for child in cls._children(node):
            if child.tag == tag:
                return child
        return None

    @classmethod
    def _find_children(cls, node: BinaryNode | None, tag: str) -> list[BinaryNode]:
        return [child for child in cls._children(node) if child.tag == tag]
