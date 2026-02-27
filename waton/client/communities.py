from waton.protocol.binary_node import BinaryNode
from waton.client.client import WAClient
import os

class CommunitiesAPI:
    def __init__(self, client: WAClient):
        self.client = client

    async def create_community(self, name: str, description: str = "") -> str:
        """Creates a new WhatsApp Community."""
        create_id = os.urandom(6).hex()
        
        create_node = BinaryNode(
            tag="create",
            attrs={"subject": name},
            content=[
                BinaryNode(tag="description", attrs={}, content=description)
            ]
        )
        
        node = BinaryNode(
            tag="iq",
            attrs={"to": "@g.us", "type": "set", "xmlns": "w:g2", "id": create_id},
            content=[create_node]
        )
        await self.client.send_node(node)
        return "stub_community_jid@g.us"

    async def link_groups(self, community_jid: str, group_jids: list[str]):
        """Links existing WhatsApp groups to a parent Community."""
        links = [BinaryNode(tag="group", attrs={"jid": jid}) for jid in group_jids]
        
        node = BinaryNode(
            tag="iq",
            attrs={"to": community_jid, "type": "set", "xmlns": "w:g2"},
            content=[BinaryNode(tag="links", attrs={}, content=links)]
        )
        await self.client.send_node(node)

    async def deactivate_community(self, community_jid: str):
        """Deactivates a WhatsApp Community."""
        node = BinaryNode(
            tag="iq",
            attrs={"to": community_jid, "type": "set", "xmlns": "w:g2"},
            content=[BinaryNode(tag="deactivate", attrs={})]
        )
        await self.client.send_node(node)
