"""Default protocol and connection constants."""

NOISE_MODE = b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
WA_NOISE_HEADER = b"WA\x06\x03"

WA_CERT_DETAILS = {
    "serial": 0,
    "issuer": "WhatsAppLongTerm1",
    "public_key": bytes.fromhex("142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b"),
}

WA_ADV_ACCOUNT_SIG_PREFIX = b"\x06\x00"
WA_ADV_DEVICE_SIG_PREFIX = b"\x06\x01"
WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX = b"\x06\x05"
WA_ADV_HOSTED_DEVICE_SIG_PREFIX = b"\x06\x06"
KEY_BUNDLE_TYPE = b"\x05"

DEFAULT_CONNECTION_CONFIG = {
    "ws_url": "wss://web.whatsapp.com/ws/chat",
    "origin": "https://web.whatsapp.com",
    "version": (2, 3000, 1033846690),
    "browser": ("Mac OS", "Desktop"),
    "country_code": "US",
    "connect_timeout": 20.0,
    "frame_timeout": 60.0,
    "keepalive_interval": 30.0,
    "qr_timeout": 60.0,
    "auto_restart_on_515": True,
    "max_restart_attempts": 1,
}
