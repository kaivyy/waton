from pywa.protocol.binary_node import BinaryNode
from pywa.client.client import WAClient
import os

class NewsletterAPI:
    def __init__(self, client: WAClient):
        self.client = client

    async def create_newsletter(self, name: str, description: str = "", picture_bytes: bytes | None = None) -> str:
        """Creates a WhatsApp Channel (Newsletter)."""
        create_id = os.urandom(6).hex()
        
        # Newsletters use a completely different IQ hierarchy
        # Using xmlns: newsletter
        metadata = [
            BinaryNode(tag="name", attrs={}, content=name),
            BinaryNode(tag="description", attrs={}, content=description)
        ]
        if picture_bytes:
            metadata.append(BinaryNode(tag="picture", attrs={"direct_path": "stub"}))

        node = BinaryNode(
            tag="iq",
            attrs={"to": "@newsletter", "type": "set", "xmlns": "newsletter", "id": create_id},
            content=[
                BinaryNode(tag="create", attrs={}, content=metadata)
            ]
        )
        await self.client.send_node(node)
        return "stub_newsletter_jid@newsletter"

    async def follow_newsletter(self, jid: str):
        """Follows a WhatsApp Channel."""
        node = BinaryNode(
            tag="iq",
            attrs={"to": jid, "type": "set", "xmlns": "newsletter"},
            content=[BinaryNode(tag="follow", attrs={})]
        )
        await self.client.send_node(node)

    async def mute_newsletter(self, jid: str, mute: bool = True):
        """Mutes or unmutes a Channel."""
        action = "mute" if mute else "unmute"
        node = BinaryNode(
            tag="iq",
            attrs={"to": jid, "type": "set", "xmlns": "newsletter"},
            content=[BinaryNode(tag=action, attrs={})]
        )
        await self.client.send_node(node)
