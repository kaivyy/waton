# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Multi-device query support**: Messages are now encrypted and sent to ALL devices
  of the recipient (phone, WhatsApp Web, linked devices) via USync device query,
  fixing the issue where messages were ACKed by server but never received
- New `pywa/client/usync.py` module with `USyncQuery` class for querying device lists
- Real Rust-backed Signal helper integration (`wa-rs-libsignal`) for session bootstrap
  and session encryption
- `send_text` E2E relay flow: device key fetch (`iq encrypt`), session injection, per-device
  encrypted participant fanout, and `device-identity` inclusion for `pkmsg`
- Minimal WA protobuf wire serializer used for outgoing message payloads
- Runtime guidance for wheel-first installation (end users do not need Rust toolchain)

### Changed
- Architecture remains standalone `pywa` (Python API), with Rust used only as internal
  performance/crypto helper
- No runtime dependency on Node.js/Baileys wrapper layers

### Fixed
- **PKCS#7 Payload Padding**: Protobuf message payloads are now padded with 1-16 random bytes
  prior to encryption, fixing Server Error 479 (`Invalid Format`).
- **Exact Sender Device Filtering**: `send_text` now strictly filters out the exact sending device
  using normalized session keys to avoid Error 479 (`Invalid Receiver`) when the server
  detects a client sending an enc payload to itself.
- **AD_JID encoding for multi-device**: Device-specific JIDs (`user:device@server`) are
  now correctly encoded as AD_JID (tag 247) in the binary codec, instead of mangled JID_PAIR.
  This was preventing multi-device messages from reaching the server correctly.
- Server reject/disconnect on message send (`ack error 479`) by replacing stub relay path
  with encrypted Signal relay
- Invalid JSON-based WAProto shim replaced with binary protobuf wire implementation

### Docs
- Added installation guidance differentiating end-user install (wheel, no Rust) vs source
  contributor setup (requires Rust + maturin)
