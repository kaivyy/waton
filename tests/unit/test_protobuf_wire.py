from waton.protocol.protobuf.wire import (
    AppVersion,
    ClientPayload,
    DevicePairingRegistrationData,
    HandshakeClientFinish,
    HandshakeClientHello,
    HandshakeMessage,
    UserAgent,
    WebInfo,
)


def test_handshake_message_roundtrip_server_hello() -> None:
    encoded = HandshakeMessage(
        client_hello=HandshakeClientHello(ephemeral=b"a" * 32),
        client_finish=HandshakeClientFinish(static=b"b" * 48, payload=b"c" * 16),
    ).SerializeToString()
    decoded = HandshakeMessage.ParseFromString(encoded)
    assert decoded.client_hello is not None
    assert decoded.client_hello.ephemeral == b"a" * 32
    assert decoded.client_finish is not None
    assert decoded.client_finish.static == b"b" * 48


def test_client_payload_serialization_non_empty() -> None:
    payload = ClientPayload(
        passive=True,
        pull=True,
        connect_type=ClientPayload.ConnectType.WIFI_UNKNOWN,
        connect_reason=ClientPayload.ConnectReason.USER_ACTIVATED,
        user_agent=UserAgent(
            platform=UserAgent.Platform.WEB,
            app_version=AppVersion(primary=2, secondary=3000, tertiary=1033846690),
            mcc="000",
            mnc="000",
            os_version="0.1",
            device="Desktop",
            os_build_number="0.1",
            release_channel=UserAgent.ReleaseChannel.RELEASE,
            locale_language_iso6391="en",
            locale_country_iso31661_alpha2="US",
        ),
        web_info=WebInfo(web_sub_platform=WebInfo.WebSubPlatform.DARWIN),
        device_pairing_data=DevicePairingRegistrationData(
            e_regid=b"\x00\x00\x00\x01",
            e_keytype=b"\x05",
            e_ident=b"x" * 32,
            e_skey_id=b"\x00\x00\x01",
            e_skey_val=b"y" * 32,
            e_skey_sig=b"z" * 64,
            build_hash=b"h" * 16,
            device_props=b"props",
        ),
    )
    assert payload.SerializeToString()

