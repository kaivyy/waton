import asyncio
import io
import pytest

from waton.client.chats import ChatsAPI
from waton.client.messages import MessagesAPI
from waton.client.newsletter import NewsletterAPI
from waton.protocol.binary_codec import (
    Tags,
    _is_hex,
    _read_ad_jid,
    _write_string,
    decode_binary_node,
    encode_binary_node,
)
from waton.protocol.binary_node import BinaryNode


class _MockClient:
    def __init__(self) -> None:
        self.sent: list[BinaryNode] = []
        self.queried: list[BinaryNode] = []
        self.creds = None
        self.storage = None

    async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
        self.queried.append(node)
        if node.attrs.get("xmlns") == "blocklist":
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="list",
                        attrs={},
                        content=[BinaryNode(tag="item", attrs={"jid": "111@s.whatsapp.net"})],
                    )
                ],
            )
        if node.attrs.get("xmlns") == "newsletter":
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="newsletter",
                        attrs={"jid": "chan@newsletter", "creation_time": "1700000000"},
                        content=[
                            BinaryNode(tag="name", attrs={}, content="Chan Name"),
                            BinaryNode(tag="description", attrs={}, content="Chan Desc"),
                            BinaryNode(tag="subscribers", attrs={}, content="1500"),
                            BinaryNode(tag="verification", attrs={"state": "verified"}),
                            BinaryNode(tag="picture", attrs={"direct_path": "/p/pic.jpg"}),
                            BinaryNode(tag="invite", attrs={}, content="INV123"),
                            BinaryNode(tag="mute", attrs={"state": "on"}),
                        ],
                    )
                ],
            )
        return BinaryNode(tag="iq", attrs={"type": "result"}, content=[])

    async def send_node(self, node: BinaryNode) -> None:
        self.sent.append(node)


def test_hex_casing_preserved_roundtrip() -> None:
    # Uppercase hex is recognized as hex and packed with HEX_8
    assert _is_hex("1A2B3C") is True
    buf_upper = bytearray()
    _write_string("1A2B3C", buf_upper)
    assert buf_upper[0] == Tags.HEX_8

    # Lowercase hex is NOT recognized as hex, bypassing HEX_8 packing to preserve casing
    assert _is_hex("1a2b3c") is False
    buf_lower = bytearray()
    _write_string("1a2b3c", buf_lower)
    assert buf_lower[0] != Tags.HEX_8
    # Deserializing round-trip preserves lowercase exactly
    node = BinaryNode(tag="test", attrs={"hash": "1a2b3c"})
    encoded = encode_binary_node(node)
    decoded = decode_binary_node(encoded)
    assert decoded.attrs["hash"] == "1a2b3c"


def test_ad_jid_agent_encoding_and_decoding() -> None:
    buf = bytearray()
    _write_string("user123_4:2@s.whatsapp.net", buf)
    assert buf[0] == Tags.AD_JID
    assert buf[1] == 4  # domain_type carries agent 4
    assert buf[2] == 2  # device 2

    # Unpack from stream
    stream = io.BytesIO(buf[1:])
    decoded = _read_ad_jid(stream)
    assert decoded == "user123_4:2@s.whatsapp.net"


@pytest.mark.asyncio
async def test_fetch_blocklist_sends_empty_content() -> None:
    client = _MockClient()
    chats = ChatsAPI(client)  # type: ignore[arg-type]
    blocked = await chats.fetch_blocklist()
    assert blocked == ["111@s.whatsapp.net"]
    assert len(client.queried) == 1
    query_node = client.queried[0]
    assert query_node.attrs["xmlns"] == "blocklist"
    assert query_node.attrs["type"] == "get"
    # WhatsApp standard: content must be None for get query
    assert query_node.content is None


@pytest.mark.asyncio
async def test_update_block_status_includes_pn_jid() -> None:
    client = _MockClient()
    chats = ChatsAPI(client)  # type: ignore[arg-type]

    # Block a PN JID without active lid_mapping
    await chats.update_block_status("628123456@s.whatsapp.net", action="block")
    assert len(client.queried) == 1
    item_node = client.queried[0].content[0]
    assert item_node.attrs["action"] == "block"
    assert item_node.attrs["pn_jid"] == "628123456@s.whatsapp.net"

    # Unblock does not require pn_jid
    await chats.update_block_status("628123456@s.whatsapp.net", action="unblock")
    item_unblock = client.queried[1].content[0]
    assert item_unblock.attrs["action"] == "unblock"
    assert "pn_jid" not in item_unblock.attrs


@pytest.mark.asyncio
async def test_create_newsletter_picture_bytes_assigned() -> None:
    client = _MockClient()
    api = NewsletterAPI(client)  # type: ignore[arg-type]
    pic_bytes = b"fake_png_data_12345"

    try:
        await api.create_newsletter("My Channel", "Channel Desc", picture_bytes=pic_bytes)
    except ValueError:
        pass  # expected because mock response doesn't contain jid attribute

    assert len(client.queried) == 1
    create_node = client.queried[0].content[0]
    metadata_nodes = create_node.content
    pic_node = next(n for n in metadata_nodes if n.tag == "picture")
    assert pic_node.attrs["source"] == "inline"
    assert pic_node.content == pic_bytes


@pytest.mark.asyncio
async def test_newsletter_metadata_complete_fields() -> None:
    client = _MockClient()
    api = NewsletterAPI(client)  # type: ignore[arg-type]
    meta = await api.newsletter_metadata("chan@newsletter")
    assert meta["jid"] == "chan@newsletter"
    assert meta["name"] == "Chan Name"
    assert meta["description"] == "Chan Desc"
    assert meta["creation_time"] == "1700000000"
    assert meta["subscribers"] == "1500"
    assert meta["verification"] == "verified"
    assert meta["picture"] == "/p/pic.jpg"
    assert meta["invite"] == "INV123"
    assert meta["mute"] == "on"


@pytest.mark.asyncio
async def test_send_reaction_decrypt_fail_hide_attribute() -> None:
    client = _MockClient()
    msg_api = MessagesAPI(client)  # type: ignore[arg-type]

    # Offline fallback triggers send_node
    await msg_api.send_reaction("target@s.whatsapp.net", "msg-id-123", "👍")
    assert len(client.sent) == 1
    sent_node = client.sent[0]
    assert sent_node.tag == "message"
    assert sent_node.attrs["type"] == "reaction"
    assert sent_node.attrs["decrypt-fail"] == "hide"
