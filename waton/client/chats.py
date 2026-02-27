from waton.protocol.binary_node import BinaryNode
from waton.client.client import WAClient
from typing import Optional

class ChatsAPI:
    def __init__(self, client: WAClient):
        self.client = client

    async def send_presence_update(self, jid: str, presence: str):
        """
        Sends presence updates (e.g. typing, available) to a specific chat.
        presence: 'composing', 'paused', 'available', 'unavailable'
        """
        node = BinaryNode(
            tag="presence",
            attrs={"to": jid, "type": presence}
        )
        await self.client.send_node(node)

    async def get_profile_picture(self, jid: str) -> Optional[str]:
        """Requests the profile picture URL for a JID."""
        query_node = BinaryNode(
            tag="iq",
            attrs={"to": "@s.whatsapp.net", "type": "get", "xmlns": "w:profile:picture"},
            content=[BinaryNode(tag="picture", attrs={"target": jid})]
        )
        # Assuming our client has a query method that waits for an IQ response
        # res = await self.client.query(query_node)
        # return res.content[0].attrs.get("url")
        return "https://fake_url/image.jpg"

    async def update_profile_status(self, status: str):
        """Updates the current user's about/status text."""
        node = BinaryNode(
            tag="iq",
            attrs={"to": "@s.whatsapp.net", "type": "set", "xmlns": "status"},
            content=[BinaryNode(tag="status", attrs={}, content=status)]
        )
        await self.client.send_node(node)
        
    async def chat_modify(self, jid: str, action: str):
        """Modifies chat archive/mute/pin status."""
        # Will sync with AppState later
        pass
