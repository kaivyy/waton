"""Business profile API surface for WA business metadata operations."""

from __future__ import annotations

import os
from typing import Any

from waton.client.client import WAClient
from waton.protocol.binary_node import BinaryNode


class BusinessAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def business_profile(self, jid: str) -> dict[str, str]:
        normalized_jid = self._normalize_jid(jid)
        result = await self.client.query(
            BinaryNode(
                tag="iq",
                attrs={
                    "to": normalized_jid,
                    "type": "get",
                    "xmlns": "w:biz",
                    "id": self._generate_id(),
                },
                content=[BinaryNode(tag="business_profile", attrs={"jid": normalized_jid})],
            )
        )
        profile = self._find_child(result, "business_profile")
        if profile is None:
            raise ValueError("business profile response missing business_profile node")
        return {
            "jid": str(profile.attrs.get("jid") or normalized_jid),
            "name": str(profile.attrs.get("name") or ""),
            "description": str(profile.attrs.get("description") or ""),
            "email": str(profile.attrs.get("email") or ""),
            "category": str(profile.attrs.get("category") or ""),
        }

    async def update_business_profile(
        self,
        jid: str,
        *,
        name: str | None = None,
        description: str | None = None,
        email: str | None = None,
        category: str | None = None,
    ) -> None:
        normalized_jid = self._normalize_jid(jid)
        attrs: dict[str, str] = {"jid": normalized_jid}
        if name is not None:
            attrs["name"] = name
        if description is not None:
            attrs["description"] = description
        if email is not None:
            attrs["email"] = email
        if category is not None:
            attrs["category"] = category

        await self.client.query(
            BinaryNode(
                tag="iq",
                attrs={
                    "to": normalized_jid,
                    "type": "set",
                    "xmlns": "w:biz",
                    "id": self._generate_id(),
                },
                content=[BinaryNode(tag="business_profile", attrs=attrs)],
            )
        )

    @staticmethod
    def _normalize_jid(jid: str) -> str:
        if not isinstance(jid, str) or not jid.strip():
            raise ValueError("jid must be a non-empty string")
        return jid.strip()

    @staticmethod
    def _generate_id() -> str:
        return os.urandom(6).hex()

    @staticmethod
    def _find_child(node: BinaryNode | None, tag: str) -> BinaryNode | None:
        if node is None or not isinstance(node.content, list):
            return None
        for child in node.content:
            if isinstance(child, BinaryNode) and child.tag == tag:
                return child
        return None
