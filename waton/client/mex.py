"""Minimal MEX query wrapper."""

from __future__ import annotations

import os
from typing import Any

from waton.client.client import WAClient
from waton.protocol.binary_node import BinaryNode


class MexAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def query(self, operation: str, params: dict[str, str] | None = None) -> dict[str, str]:
        if not isinstance(operation, str) or not operation.strip():
            raise ValueError("operation must be a non-empty string")

        attrs: dict[str, str] = {"op": operation.strip()}
        for key, value in (params or {}).items():
            attrs[str(key)] = str(value)

        result = await self.client.query(
            BinaryNode(
                tag="iq",
                attrs={
                    "to": "s.whatsapp.net",
                    "type": "get",
                    "xmlns": "w:mex",
                    "id": os.urandom(6).hex(),
                },
                content=[BinaryNode(tag="mex", attrs=attrs)],
            )
        )

        mex_node = self._find_child(result, "mex")
        if mex_node is None:
            raise ValueError("mex response missing mex node")
        return {k: str(v) for k, v in mex_node.attrs.items()}

    @staticmethod
    def _find_child(node: BinaryNode | None, tag: str) -> BinaryNode | None:
        if node is None or not isinstance(node.content, list):
            return None
        for child in node.content:
            if isinstance(child, BinaryNode) and child.tag == tag:
                return child
        return None
