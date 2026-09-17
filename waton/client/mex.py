"""WhatsApp MEX GraphQL client."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from waton.core.errors import WatonError
from waton.core.jid import S_WHATSAPP_NET
from waton.protocol.binary_node import BinaryNode

if TYPE_CHECKING:
    from waton.client.client import WAClient


class MexError(WatonError):
    """Exception raised for MEX GraphQL errors."""
    def __init__(self, message: str, errors: list[dict[str, Any]] | None = None, status_code: int = 400) -> None:
        super().__init__(message)
        self.errors = errors or []
        self.status_code = status_code


class QueryIds:
    CREATE = "8823471724422422"
    UPDATE_METADATA = "24250201037901610"
    METADATA = "6563316087068696"
    SUBSCRIBERS = "9783111038412085"
    FOLLOW = "24404358912487870"
    UNFOLLOW = "9767147403369991"
    MUTE = "29766401636284406"
    UNMUTE = "9864994326891137"
    ADMIN_COUNT = "7130823597031706"
    CHANGE_OWNER = "7341777602580933"
    DEMOTE = "6551828931592903"
    DELETE = "30062808666639665"
    REACHOUT_TIMELOCK = "23983697327930364"
    MESSAGE_CAPPING_INFO = "24503548349331633"


class MexClient:
    """Client for querying WhatsApp server via MEX GraphQL."""

    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def execute_wmex_query(
        self,
        query_id: str,
        variables: dict[str, Any],
        data_path: str | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """
        Execute a WhatsApp MEX (GraphQL) query.

        Args:
            query_id: The GraphQL query ID (e.g. from QueryIds).
            variables: Query variables dictionary.
            data_path: Optional path to extract from the `data` response object (e.g., 'xwa2_newsletter').

        Returns:
            The parsed result (either the full data object or the specific data_path).

        Raises:
            MexError: If there are GraphQL errors or the response is invalid.
        """
        query_node = BinaryNode(
            tag="iq",
            attrs={
                "id": self.client.generate_message_tag(),
                "type": "get",
                "to": S_WHATSAPP_NET,
                "xmlns": "w:mex",
            },
            content=[
                BinaryNode(
                    tag="query",
                    attrs={"query_id": query_id},
                    content=json.dumps({"variables": variables}).encode("utf-8"),
                )
            ],
        )

        result_node = await self.client.query(query_node)

        child = None
        if isinstance(result_node.content, list):
            for n in result_node.content:
                if isinstance(n, BinaryNode) and n.tag == "result":
                    child = n
                    break

        if child is not None and isinstance(child.content, (bytes, bytearray)):
            try:
                data = json.loads(child.content.decode("utf-8"))
            except json.JSONDecodeError:
                raise MexError("Failed to parse MEX JSON response", status_code=500)

            errors = data.get("errors", [])
            if errors:
                error_messages = ", ".join([str(err.get("message", "Unknown error")) for err in errors])
                first_error = errors[0] if errors else {}
                error_code = 400
                extensions = first_error.get("extensions")
                if isinstance(extensions, dict) and "error_code" in extensions:
                    error_code = extensions["error_code"]
                raise MexError(f"GraphQL server error: {error_messages}", errors=errors, status_code=error_code)

            resp_data = data.get("data")
            if resp_data is not None:
                if data_path:
                    if data_path in resp_data:
                        return resp_data[data_path]
                else:
                    return resp_data

        action = "request"
        if data_path:
            action = data_path.replace("xwa2_", "").replace("_", " ")

        raise MexError(f"Failed to {action}, unexpected response structure.", status_code=400)
