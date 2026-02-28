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
            "address": str(profile.attrs.get("address") or ""),
            "website": str(profile.attrs.get("website") or ""),
            "hours": str(profile.attrs.get("hours") or ""),
        }

    async def update_business_profile(
        self,
        jid: str,
        *,
        name: str | None = None,
        description: str | None = None,
        email: str | None = None,
        category: str | None = None,
        address: str | None = None,
        website: str | None = None,
        hours: str | None = None,
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
        if address is not None:
            attrs["address"] = address
        if website is not None:
            attrs["website"] = website
        if hours is not None:
            attrs["hours"] = hours

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

    async def business_catalog(self, jid: str) -> dict[str, str]:
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
                content=[BinaryNode(tag="catalog", attrs={"jid": normalized_jid})],
            )
        )
        catalog = self._find_child(result, "catalog")
        if catalog is None:
            raise ValueError("business catalog response missing catalog node")
        return {
            "jid": str(catalog.attrs.get("jid") or normalized_jid),
            "status": str(catalog.attrs.get("status") or ""),
        }

    async def update_order_status(self, jid: str, *, order_id: str, status: str) -> None:
        normalized_jid = self._normalize_jid(jid)
        if not isinstance(order_id, str) or not order_id.strip():
            raise ValueError("order_id must be a non-empty string")
        if not isinstance(status, str) or not status.strip():
            raise ValueError("status must be a non-empty string")

        await self.client.query(
            BinaryNode(
                tag="iq",
                attrs={
                    "to": normalized_jid,
                    "type": "set",
                    "xmlns": "w:biz",
                    "id": self._generate_id(),
                },
                content=[
                    BinaryNode(
                        tag="order",
                        attrs={
                            "id": order_id.strip(),
                            "status": status.strip(),
                        },
                    )
                ],
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
