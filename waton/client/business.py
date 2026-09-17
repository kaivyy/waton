"""WhatsApp Business API module."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from waton.core.jid import S_WHATSAPP_NET
from waton.protocol.binary_node import BinaryNode

if TYPE_CHECKING:
    from waton.client.client import WAClient


class BusinessAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def get_catalog(self, jid: str, limit: int = 10, cursor: str | None = None) -> dict[str, Any]:
        content: list[BinaryNode] = [
            BinaryNode(tag="limit", attrs={}, content=str(limit).encode("utf-8")),
            BinaryNode(tag="width", attrs={}, content=b"100"),
            BinaryNode(tag="height", attrs={}, content=b"100"),
        ]
        if cursor:
            content.append(BinaryNode(tag="after", attrs={}, content=cursor.encode("utf-8") if isinstance(cursor, str) else cursor))
            
        iq = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "get", "xmlns": "w:biz:catalog"},
            content=[
                BinaryNode(
                    tag="product_catalog",
                    attrs={"jid": jid, "allow_shop_source": "true"},
                    content=content,
                )
            ]
        )
        res = await self.client.query(iq)
        return {"node": res}

    async def get_collections(self, jid: str, limit: int = 10) -> dict[str, Any]:
        iq = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "get", "xmlns": "w:biz:catalog", "smax_id": "35"},
            content=[
                BinaryNode(
                    tag="collections",
                    attrs={"biz_jid": jid},
                    content=[
                        BinaryNode(tag="collection_limit", attrs={}, content=str(limit).encode("utf-8")),
                        BinaryNode(tag="item_limit", attrs={}, content=str(limit).encode("utf-8")),
                        BinaryNode(tag="width", attrs={}, content=b"100"),
                        BinaryNode(tag="height", attrs={}, content=b"100"),
                    ]
                )
            ]
        )
        res = await self.client.query(iq)
        return {"node": res}

    async def get_order_details(self, order_id: str, order_token: str) -> dict[str, Any]:
        iq = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "get", "xmlns": "fb:thrift_iq", "smax_id": "5"},
            content=[
                BinaryNode(
                    tag="order",
                    attrs={"op": "get", "id": order_id},
                    content=[
                        BinaryNode(
                            tag="image_dimensions",
                            attrs={},
                            content=[
                                BinaryNode(tag="width", attrs={}, content=b"100"),
                                BinaryNode(tag="height", attrs={}, content=b"100"),
                            ]
                        ),
                        BinaryNode(tag="token", attrs={}, content=order_token.encode("utf-8")),
                    ]
                )
            ]
        )
        res = await self.client.query(iq)
        return {"node": res}

def _to_product_node(product_id: str | None, data: dict[str, Any]) -> BinaryNode:
    content: list[BinaryNode] = []
    if product_id:
        content.append(BinaryNode(tag="id", attrs={}, content=product_id.encode("utf-8")))
    for field in ["name", "description", "currency", "url", "retailer_id"]:
        if field in data and data[field] is not None:
            content.append(BinaryNode(tag=field, attrs={}, content=str(data[field]).encode("utf-8")))
    if "price" in data and data["price"] is not None:
        price_val = str(int(data["price"]))
        content.append(BinaryNode(tag="price", attrs={}, content=price_val.encode("utf-8")))
    if "is_hidden" in data:
        content.append(BinaryNode(tag="is_hidden", attrs={}, content=b"true" if data["is_hidden"] else b"false"))
    if "images" in data and isinstance(data["images"], list):
        for img_id in data["images"]:
            content.append(
                BinaryNode(
                    tag="image",
                    attrs={},
                    content=[BinaryNode(tag="media_id", attrs={}, content=str(img_id).encode("utf-8"))],
                )
            )
    return BinaryNode(tag="product", attrs={"id": product_id} if product_id else {}, content=content)


    async def product_create(self, product_data: dict[str, Any]) -> dict[str, Any]:
        iq = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "set", "xmlns": "w:biz:catalog"},
            content=[
                BinaryNode(
                    tag="product_catalog_add",
                    attrs={"v": "1"},
                    content=[
                        _to_product_node(None, product_data),
                        BinaryNode(tag="width", attrs={}, content=b"100"),
                        BinaryNode(tag="height", attrs={}, content=b"100"),
                    ]
                )
            ]
        )
        res = await self.client.query(iq)
        return {"node": res}

    async def product_update(self, product_id: str, update_data: dict[str, Any]) -> dict[str, Any]:
        iq = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "set", "xmlns": "w:biz:catalog"},
            content=[
                BinaryNode(
                    tag="product_catalog_edit",
                    attrs={"v": "1"},
                    content=[
                        _to_product_node(product_id, update_data),
                        BinaryNode(tag="width", attrs={}, content=b"100"),
                        BinaryNode(tag="height", attrs={}, content=b"100"),
                    ]
                )
            ]
        )
        res = await self.client.query(iq)
        return {"node": res}


    async def product_delete(self, product_ids: list[str]) -> bool:
        products = [
            BinaryNode(
                tag="product",
                attrs={},
                content=[BinaryNode(tag="id", attrs={}, content=pid.encode("utf-8"))]
            ) for pid in product_ids
        ]
        iq = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "set", "xmlns": "w:biz:catalog"},
            content=[
                BinaryNode(
                    tag="product_catalog_delete",
                    attrs={"v": "1"},
                    content=products
                )
            ]
        )
        await self.client.query(iq)
        return True

    async def update_business_profile(self, profile_data: dict[str, Any]) -> None:
        nodes = []
        for key in ["address", "email", "description"]:
            if key in profile_data:
                nodes.append(BinaryNode(tag=key, attrs={}, content=str(profile_data[key])))
        if "websites" in profile_data:
            for website in profile_data["websites"]:
                nodes.append(BinaryNode(tag="website", attrs={}, content=str(website)))

        iq = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "set", "xmlns": "w:biz"},
            content=[
                BinaryNode(
                    tag="business_profile",
                    attrs={"v": "3", "mutation_type": "delta"},
                    content=nodes
                )
            ]
        )
        await self.client.query(iq)

    async def update_cover_photo(self, photo_bytes: bytes) -> None:
        iq = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "set", "xmlns": "w:biz"},
            content=[
                BinaryNode(
                    tag="business_profile",
                    attrs={"v": "3", "mutation_type": "delta"},
                    content=[
                        BinaryNode(
                            tag="cover_photo",
                            attrs={"op": "update", "id": "123", "token": "dummy", "ts": "123"}
                        )
                    ]
                )
            ]
        )
        await self.client.query(iq)

    async def remove_cover_photo(self) -> None:
        iq = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "set", "xmlns": "w:biz"},
            content=[
                BinaryNode(
                    tag="business_profile",
                    attrs={"v": "3", "mutation_type": "delta"},
                    content=[
                        BinaryNode(
                            tag="cover_photo",
                            attrs={"op": "delete", "id": "1"}
                        )
                    ]
                )
            ]
        )
        await self.client.query(iq)
