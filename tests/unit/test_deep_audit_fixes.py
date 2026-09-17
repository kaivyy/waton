import asyncio
import pytest

from waton.client.communities import CommunitiesAPI
from waton.client.groups import GroupsAPI
from waton.client.messages_recv import decode_call_node
from waton.client.usync import USyncQuery
from waton.protocol.app_state import apply_patch
from waton.protocol.binary_codec import _is_hex
from waton.protocol.binary_node import BinaryNode
from waton.protocol.lid_mapping import LIDMappingStore
from waton.protocol.noise_handler import TransportState, validate_noise_cert_chain
from waton.utils.message_content import _POLL_CREATION_FIELDS
from waton.utils.message_utils import build_receipt_node


def test_transport_counter_exhaustion() -> None:
    state = TransportState(enc_key=bytes(32), dec_key=bytes(32))
    state.write_counter = 0xFFFFFFFF
    with pytest.raises(ConnectionResetError):
        state.encrypt(b"test")

    state.read_counter = 0xFFFFFFFF
    with pytest.raises(ConnectionResetError):
        state.decrypt(b"test")


def test_noise_cert_validation_empty_or_malformed() -> None:
    # Empty payload passes without error
    validate_noise_cert_chain(b"")
    # Non-empty payload without valid certificates raises or returns safely
    validate_noise_cert_chain(b"\x00\x00")


def test_app_state_syncd_mutations_lt_hash() -> None:
    state = {"version": 1, "hash": bytes(128), "index_value_map": {}}
    patch = {
        "op": "set",
        "key": "test_key",
        "value": "test_val",
        "index_mac": b"test_index_mac_16bytes!!",
        "value_mac": b"test_value_mac_16bytes!!",
    }
    out = apply_patch(state, patch)
    assert out["version"] == 2
    assert out["hash"] != state["hash"]
    assert "index_value_map" in out


def test_community_announce_default_sub_group_tag() -> None:
    node = BinaryNode(
        tag="community",
        attrs={"jid": "123@g.us"},
        content=[
            BinaryNode(tag="default_sub_group", attrs={}),
        ],
    )
    parsed = CommunitiesAPI._parse_community_node(node)
    assert parsed["is_community_announce"] is True


def test_binary_codec_is_hex_uppercase_only_preserves_casing() -> None:
    assert _is_hex("0123456789ABCDEF") is True
    assert _is_hex("0123456789abcdef") is False
    assert _is_hex("0123456789abcdefg") is False


def test_ad_jid_agent_roundtrip() -> None:
    import io
    from waton.protocol.binary_codec import _read_ad_jid, _write_string
    buf = bytearray()
    _write_string("user123_2:5@s.whatsapp.net", buf)
    stream = io.BytesIO(buf[1:])
    decoded = _read_ad_jid(stream)
    assert decoded == "user123_2:5@s.whatsapp.net"


def test_lid_mapping_invalidate_mapping() -> None:
    class _DummyStorage:
        async def get_creds(self):
            return None

    store = LIDMappingStore(_DummyStorage())  # type: ignore[arg-type]
    store._cache["628111"] = "lid_999"
    store._reverse_cache["lid_999"] = "628111"

    store.invalidate_mapping("628111@s.whatsapp.net")
    assert "628111" not in store._cache
    assert "lid_999" not in store._reverse_cache


def test_group_metadata_fields_parsed() -> None:
    node = BinaryNode(
        tag="group",
        attrs={"id": "123@g.us", "subject": "Test Group"},
        content=[
            BinaryNode(
                tag="description",
                attrs={
                    "participant": "creator@s.whatsapp.net",
                    "participant_pn": "628111@s.whatsapp.net",
                    "participant_username": "creator_user",
                },
            ),
            BinaryNode(
                tag="participant",
                attrs={
                    "jid": "user@s.whatsapp.net",
                    "type": "admin",
                    "username": "admin_user",
                },
            ),
        ],
    )
    meta = GroupsAPI._parse_group_node(node)
    assert meta["desc_owner_pn"] == "628111@s.whatsapp.net"
    assert meta["desc_owner_username"] == "creator_user"
    assert meta["participants"][0]["username"] == "admin_user"


def test_build_receipt_node_1on1_sender_routing() -> None:
    receipt = build_receipt_node(
        jid="partner@s.whatsapp.net",
        message_ids=["msg-123"],
        participant="me:1@s.whatsapp.net",
        receipt_type="sender",
    )
    assert receipt.attrs["recipient"] == "partner@s.whatsapp.net"
    assert receipt.attrs["to"] == "me:1@s.whatsapp.net"
    assert "participant" not in receipt.attrs


def test_poll_creation_fields_includes_93() -> None:
    assert 93 in _POLL_CREATION_FIELDS


def test_decode_call_node_stub_type() -> None:
    node_timeout = BinaryNode(
        tag="call",
        attrs={"from": "caller@s.whatsapp.net"},
        content=[BinaryNode(tag="timeout", attrs={"call-id": "c1"})],
    )
    parsed = decode_call_node(node_timeout)
    assert parsed["call"]["stub_type"] == "CALL_MISSED_VOICE"

    node_video_timeout = BinaryNode(
        tag="call",
        attrs={"from": "caller@s.whatsapp.net"},
        content=[
            BinaryNode(
                tag="timeout",
                attrs={"call-id": "c2"},
                content=[BinaryNode(tag="video", attrs={})],
            )
        ],
    )
    parsed_video = decode_call_node(node_video_timeout)
    assert parsed_video["call"]["stub_type"] == "CALL_MISSED_VIDEO"


def test_usync_error_detection() -> None:
    class _DummyClient:
        pass

    usync = USyncQuery(_DummyClient())  # type: ignore[arg-type]
    err_node = BinaryNode(
        tag="iq",
        attrs={"type": "error"},
        content=[BinaryNode(tag="error", attrs={"code": "401", "text": "unauthorized"})],
    )
    with pytest.raises(ValueError, match="USync IQ error 401"):
        usync._parse_multi_protocol_result(err_node, ["contact"])

    with pytest.raises(ValueError, match="USync device query error 401"):
        usync._parse_device_result(err_node)


def test_usync_key_index_list_devices() -> None:
    class _DummyClient:
        pass

    usync = USyncQuery(_DummyClient())  # type: ignore[arg-type]
    node = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="usync",
                attrs={},
                content=[
                    BinaryNode(
                        tag="list",
                        attrs={},
                        content=[
                            BinaryNode(
                                tag="user",
                                attrs={"jid": "6281234567@s.whatsapp.net"},
                                content=[
                                    BinaryNode(
                                        tag="devices",
                                        attrs={},
                                        content=[
                                            BinaryNode(
                                                tag="key-index-list",
                                                attrs={},
                                                content=[
                                                    BinaryNode(tag="device", attrs={"id": "0"}),
                                                    BinaryNode(tag="device", attrs={"id": "2"}),
                                                ],
                                            )
                                        ],
                                    )
                                ],
                            )
                        ],
                    )
                ],
            )
        ],
    )
    res = usync._parse_device_result(node)
    devices = res["6281234567@s.whatsapp.net"]
    assert "6281234567:0@s.whatsapp.net" in devices
    assert "6281234567:2@s.whatsapp.net" in devices
