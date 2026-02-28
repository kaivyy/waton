# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New targeted `BusinessAPI` surface (`app.business`) for business profile fetch/update operations.
- New `MexAPI` minimal wrapper for `w:mex` query envelopes and normalized attrs response.
- New practical `waton.protocol.wam.encode_wam_event(...)` subset for deterministic telemetry framing.
- Expanded `USyncQuery` protocol coverage with `contact/status/lid/disappearing_mode` query support.
- New unit coverage for business/usync/mex/wam in `tests/unit/test_business.py`, `tests/unit/test_usync.py`, `tests/unit/test_mex.py`, and `tests/unit/test_wam.py`.
- New simple callback API surface for drop-in usage: `from waton import simple` with `SimpleClient` and `SimpleIncomingMessage` wrappers for minimal `on_message`/`on_ready` flows.
- New unit coverage for simple API behavior in `tests/unit/test_simple_api.py`.
- New isolated browser dashboard devtool at `tools/dashboard/` with Flask API + HTML UI for real WhatsApp browser testing (`/api/connect`, `/api/disconnect`, `/api/connection`, `/api/qr`, `/api/events`, `/api/send`) without touching `waton/*` runtime code.
- New unit coverage for dashboard state and API validation in `tests/unit/test_dashboard.py`.
- Read the Docs foundation for Waton:
  - `.readthedocs.yaml`
  - Sphinx config at `docs/source/conf.py`
  - initial docs pages under `docs/source/content/` (`getting-started`, `testing`, `browser-dashboard`, `readthedocs`).
- Windows troubleshooting guidance for editable install file-lock failure (`os error 32` on `waton/_crypto.pyd`) in README and docs testing guide.
- WhatsApp Web-style dashboard layout with chat list pane (left) and active message thread pane (right), backed by real runtime chat APIs (`/api/chats`, `/api/chats/<jid>/messages`, `/api/chats/<jid>/read`).

### Changed
- README and Read the Docs pages now include `waton.simple` onboarding path (`getting-started`, `quickstart-app`, `app-framework-reference`, and migration/readthedocs operational notes), plus simple API guardrails (async handler requirement and non-empty `to_jid`).
- Read the Docs references now include BusinessAPI, MexAPI, expanded USync protocol usage, and WAM practical subset notes.
- README and Read the Docs pages now include `waton.simple` onboarding path (`getting-started`, `quickstart-app`, `app-framework-reference`, and migration/readthedocs operational notes).
- Incoming E2EE decryption path in `waton/utils/process_message.py` now applies
  PNâ†”LID candidate fallback (Baileys-style) instead of single-JID decrypt attempt.
- `SignalRepository` now supports lightweight PNâ†”LID mapping helpers and
  session migration primitives used during incoming decrypt recovery.
- Browser dashboard composer now uses a WhatsApp-Web-style footer layout with
  action icons, autosize input box, and cleaner send ergonomics for browser tests.
- Dashboard thread rendering now keeps manual scroll position unless new
  messages arrive, so long chat history remains readable while polling.
- `waton/client/client.py` now performs post-login bootstrap actions aligned with
  Baileys flow: sending passive-active IQ and `ib/unified_session` telemetry after
  login success.
- `waton/client/client.py` now handles `ib/offline_preview` by requesting
  `ib/offline_batch` once per connection, with source guard for
  `from=s.whatsapp.net`.
- Unified-session ID generation now uses tracked server-time offset from stanza
  timestamps for deterministic session telemetry IDs.


### Fixed
- CLI receive flow no longer silently drops inbound messages when parse/decrypt
  edges occur; undecryptable text stanzas are surfaced explicitly and fallback
  routing remains active.
- Reduced false-positive noise by downgrading known stale-counter decrypt
  failures (`old counter`) to debug-level logging.
- Incoming decrypt path now accepts encrypted message stanzas where `enc.v`
  is omitted (treated same as legacy v2 path), preventing false
  `[undecrypted message]` results on valid incoming text envelopes.
- Dashboard incoming chat stream now correctly normalizes PN/LID/device JIDs and
  no longer drops updates due background handler attribute mismatches, so new
  messages appear in left chat list and right thread view.
- Dashboard incoming routing now handles MD envelopes where `from` is self JID
  by inferring peer JID from alternate stanza attrs (`participant_*`, `sender_*`,
  `recipient`), preventing inbound messages from being mis-threaded into self-chat.
- Added dashboard troubleshooting endpoint `GET /api/debug/summary` for quick
  visibility into connection state, cached chats, and recent node/event tails.
- Added unit coverage in `tests/unit/test_client.py` for post-login bootstrap
  parity behavior (`active` passive IQ + unified session), offline-preview
  handling guard/deduplication, and deterministic server-time offset usage.
- Refreshed `docs/parity/baileys-parity-baseline.json` from current code via
  `tools/parity/scan_baileys_parity.py`; all tracked domains remain `done`
  including `connection-core`, `messages-recv`, and `process-message`.

## [0.1.1] - 2026-02-27

### Added
- One-command release preflight CLI at `scripts/preflight_check.py` that runs
  tests, optional lint/typecheck, parity scan, and optional live check in a
  consistent gate flow.
- Shared preflight helper module `waton/utils/preflight.py` with command plan
  builder and parity report validation utilities.
- One-command live reliability CLI at `scripts/live_check.py` with args/env
  support to validate connect/ping/send-ack/reconnect without running pytest
  manually.
- Shared live reliability orchestration module at
  `waton/utils/live_check.py` (`LiveCheckConfig`, `run_live_check`,
  `LiveCheckReport`) used by both integration tests and CLI workflow.
- New live reliability utilities at `waton/utils/live_probe.py` with async
  wait helpers for connection open/close and per-message ACK observation from
  both raw `ack` nodes and normalized `messages.bad_ack` events.
- Real live reliability integration test scenario at
  `tests/integration/test_reliability_live.py` replacing placeholder-only gate:
  connect -> ping -> optional send+ack -> disconnect -> reconnect -> ping.
- Optional inbound call auto-reject in `waton/client/client.py` controlled by
  `auto_reject_calls` config. Incoming `messages.call` events now include
  `call_reject_sent` (and optional `call_reject_error`) when this behavior is
  enabled.
- Runtime offline receive buffering in `waton/client/client.py` now uses
  `drain_nodes_with_buffer` for incoming stanzas (`message`/`receipt`/
  `notification`/`call`/`ack`/`ib`) with priority processing order similar to
  Baileys offline node pipeline semantics.
- New connection config knobs in `waton/defaults/config.py`:
  `enable_offline_node_buffer`, `incoming_node_buffer_size`,
  `incoming_node_yield_every`.
- Advanced outgoing protocol APIs in `waton/client/messages.py`:
  `send_delete`, `send_edit`, `send_ephemeral_setting`, `send_poll_vote`,
  `send_event_response`, `send_receipts_batch`, and `read_messages` to mirror
  Baileys message-send behaviors for revoke/edit/ephemeral and encrypted addon
  updates.
- New receive-pipeline buffering helpers in `waton/client/messages_recv.py`:
  `OfflineNodeProcessor` and `drain_nodes_with_buffer` with priority lane
  ordering (`receipt` -> `notification` -> `call` -> `ack` -> `ib` ->
  `message`) for deterministic offline node draining.
- New unit test coverage for parity-critical flows:
  `tests/unit/test_messages_send_protocol.py` and
  `tests/unit/test_messages_recv_parity_extra.py`.
- Real parity scanner implementation at `tools/parity/scan_baileys_parity.py` with
  domain metrics (line ratio, status) for `messages-recv`, `app-state-sync`,
  `retry-manager`, and `group-signal`.
- Live reliability test gate placeholder at
  `tests/integration/test_reliability_live.py` (env-gated by
  `WATON_RUN_LIVE_RELIABILITY`).
- Release runbook checklist at `docs/runbooks/parity-release-checklist.md`.

### Changed
- `waton/client/chats.py` `chat_modify()` no longer a stub: it now emits
  concrete `w:chat` IQ action nodes for `archive`, `unarchive`, `pin`,
  `unpin`, `mute`, `unmute`, `read`, and `unread`, with explicit
  `ValueError` for unsupported actions.
- `waton/client/client.py` now optionally sends `placeholder` resend IQs in
  two retry paths:
  decrypt-failure retry receipts and incoming retry-receipt handling.
  Behavior is gated by new config flags in `waton/defaults/config.py`:
  `enable_placeholder_resend` and `placeholder_resend_on_retry`
  (both default `False` for backward-compatible runtime behavior).
- Source distribution packaging now excludes non-runtime project folders via
  `Cargo.toml` package `exclude` patterns (`docs/`, `examples/`, `tests/`,
  `tools/`, and other development-only paths), keeping published artifacts
  focused on install/runtime content.
- `README.md` and `docs/runbooks/parity-release-checklist.md` now document the
  new one-command preflight flow.
- `README.md` and `docs/runbooks/parity-release-checklist.md` now include
  explicit wheel/sdist verification steps for package footprint checks.
- `tests/integration/test_reliability_live.py` now delegates to
  `run_live_check` to keep test logic aligned with the CLI reliability flow.
- `README.md` now documents one-command live check usage in How To Use section.
- `examples/live_connect.py` now waits for sent-message ACK (`WATON_ACK_TIMEOUT`)
  and prints explicit send result status (`ok` / `error` / timeout).
- `docs/runbooks/parity-release-checklist.md` now documents concrete env setup
  and ACK verification expectations for live reliability execution.
- Expanded `tests/unit/test_client.py` coverage for raw frame pipeline behavior,
  including buffer-priority ordering and explicit non-buffered FIFO mode.
- `waton/client/messages_recv.py` now decodes additional system notification
  namespaces into structured fields: `encrypt_event`, `link_code_event`,
  `privacy_token_event`, `media_retry_event`, `history_sync_event`,
  `server_sync_event`, and `account_sync_event`.
- `docs/parity/baileys-parity-baseline.json` updated to current scan where all
  tracked domains are `done`, including `messages-recv` and `messages-send`.
- Refreshed `docs/parity/baileys-parity-baseline.json` using current scanner output
  instead of static hardcoded statuses.
- `waton/client/groups.py`, `waton/client/communities.py`, and
  `waton/client/newsletter.py` now parse created JIDs from IQ query responses
  instead of returning hardcoded placeholders.
- `waton/client/messages_recv.py` now uses real PKCS#7 max16 unpadding logic.
- `waton/client/messages_recv.py` now includes structured receive decoding for
  `message`, `receipt`, `notification`, and `ack` stanzas plus ACK-node builder
  and incoming normalizer routing.
- `waton/client/messages_recv.py` now decodes retry receipts (`type=retry`),
  bad message ACKs (`ack` with `error`), and protocol metadata for notification
  stanzas, with dedicated normalized event payloads.
- `waton/client/messages.py` now uses a shared send relay path for
  multi-device fanout (`_send_payload`) to reduce duplication across message
  types and keep send-path behavior consistent.
- `waton/client/messages.py` now adds outgoing `send_document` and
  `send_location` APIs with encrypted multi-device relay, aligned with Baileys'
  broader message-send surface.
- `waton/client/messages.py` now adds outgoing `send_audio`, `send_video`,
  `send_sticker`, `send_contact`, and `send_poll_creation` APIs, all routed
  through the same encrypted multi-device relay path.
- `waton/client/groups.py` now includes Baileys-style participant approval and
  participant mutation helpers (`group_request_participants_list`,
  `group_request_participants_update`, `group_participants_update`,
  `group_revoke_invite_v4`) plus richer metadata parsing fields
  (`notify`, `owner`, `desc_*`, `linked_parent`, `restrict`, `announce`,
  `is_community`, `join_approval_mode`, `member_add_mode`,
  `ephemeral_duration`).
- `waton/client/communities.py` now includes subgroup/participant management
  parity methods (`community_create_group`, `community_link_group`,
  `community_unlink_group`, `community_fetch_linked_groups`,
  `community_request_participants_list`,
  `community_request_participants_update`,
  `community_participants_update`) and richer metadata parsing aligned with
  Baileys community metadata shape.
- `waton/client/newsletter.py` now includes live newsletter message utilities
  (`newsletter_react_message`, `newsletter_fetch_messages`,
  `subscribe_newsletter_updates`) and normalizes extracted newsletter JIDs.
- `waton/app/app.py` now exposes high-level `app.communities` and
  `app.newsletter` clients alongside existing message/chat/group clients.
- `waton/client/messages_recv.py` now emits protocol-specific normalized message
  events (`messages.revoke`, `messages.edit`, `messages.history_sync`,
  `messages.app_state_sync_key_share`, `messages.group_member_label_change`)
  using shared protocol payload decoding from `waton/utils/protocol_message.py`.
- `waton/utils/process_message.py` now extracts protocol metadata into
  Python-friendly fields (`protocol_type`, `protocol_code`,
  `target_message_id`, `edited_text`, `history_sync_type`,
  `app_state_key_ids`) to better match Baileys `process-message` behavior.
- `waton/client/messages_recv.py` now decodes encrypted addon branches from
  top-level message payload (`encReactionMessage`, `pollUpdateMessage`,
  `encEventResponseMessage`) and emits normalized events:
  `messages.reaction_encrypted`, `messages.poll_update_encrypted`,
  `messages.event_response_encrypted`.
- `waton/client/messages_recv.py` now decodes newsletter notification branches
  (`reaction`/`view`) into structured `notification.newsletter_event` payloads.
- `waton/client/messages_recv.py` now decodes additional newsletter
  notification branches (`participant`, `update/settings`) and normalizes them
  into structured `notification.newsletter_event` payloads.
- `waton/client/messages_recv.py` now includes call-node normalization
  (`decode_call_node`) and `classify_incoming_node` support for `call` stanzas.
- `waton/client/client.py` now routes incoming `call` stanzas through the same
  normalized incoming pipeline (including auto-ACK when enabled).
- `waton/client/messages_recv.py` now derives normalized receipt status fields
  (`status`, `is_read`, `is_played`, `is_delivery`) from receipt types such as
  `read-self`/`played-self` for more Baileys-like receipt semantics.
- `waton/client/messages_recv.py` now normalizes more `w:gp2` notification
  branches (`announcement`/`not_announcement`, `locked`/`unlocked`,
  `membership_approval_mode`, and `create`) into structured `group_event`
  payloads.
- `waton/client/messages_recv.py` now normalizes additional `w:gp2` branches:
  `member_add_mode`, `created_membership_requests`,
  `revoked_membership_requests` (revoked vs rejected), and `not_ephemeral`.
- Added shared wire-level content parser at `waton/utils/message_content.py` and
  wired it into both `waton/client/messages_recv.py` and
  `waton/utils/process_message.py` to normalize richer message types:
  `document`, `audio`, `video`, `sticker`, `contact`, `location`,
  `live_location`, `list`, `buttons`, `template`, `poll_creation`, `event`,
  and newsletter invite variants.
- Incoming payload parsing now unwraps nested `FutureProofMessage` containers and
  extracts `messageContextInfo.messageSecret` for poll/event creation messages.
- `waton/client/client.py` now persists poll/event message secrets into auth
  creds (`additional_data.message_secrets`) with bounded cache size
  (`max_message_secrets_cache`) so encrypted poll/event follow-up payloads can
  be decrypted in later events.
- `waton/utils/process_message.py` now classifies encrypted addon branches into
  Python message types (`reaction_encrypted`, `poll_update_encrypted`,
  `event_response_encrypted`) with structured payload metadata.
- `waton/utils/protocol_message.py` now includes dedicated extractors for
  encrypted reaction/event/poll addon payloads so parser behavior is shared.
- `waton/client/client.py` now applies protocol side effects for
  `messages.app_state_sync_key_share` and `messages.history_sync`, persisting
  app-state key metadata and processed history markers into auth creds.
- `waton/client/retry_manager.py` now tracks richer retry state (attempts,
  timestamps, last error, ack state, stale cleanup, snapshots) while preserving
  existing duplicate-send guards.
- `waton/client/retry_manager.py` now includes Baileys-style retry utilities:
  retry reason enum parsing, MAC-error detection, session recreation heuristics,
  recent-message cache/index, retry statistics, and delayed phone-request hooks.
- `waton/client/client.py` now applies receipt-ack side effects to mark retry
  entries acknowledged when `messages.ack` for `class=receipt` arrives.
- `waton/core/entities.py` `Message` model now carries protocol-level metadata
  while preserving existing text/media/reaction fields.
- `examples/live_connect.py` now prints protocol-message events to simplify live
  parity debugging during QR/session tests.
- `waton/utils/lt_hash.py` now provides deterministic non-placeholder lattice
  hash updates (`update_lt_hash`), app-state sync key decoding
  (`decode_app_state_sync_key`), and stable digest generation (`compute_lt_hash`).
- `waton/protocol/group_cipher.py` now implements deterministic sender-key
  bootstrap/rotation/distribution processing (no placeholder payload values),
  including normalized import/export helpers for diagnostics/tests.
- `waton/client/client.py` now wires incoming stanza classification to a
  normalized event callback (`on_event`) and supports configurable auto-ACK via
  `auto_ack_incoming` (default `True`).
- `waton/client/client.py` now annotates retry-request events with retry attempt
  counters/allowance via `RetryManager`, controlled by `max_retry_receipts`.
- `waton/client/retry_manager.py` now tracks retry counts (`register_retry`,
  `should_retry`) in addition to duplicate-send gating.
- `examples/live_connect.py` now prints `messages.retry_request`,
  `messages.bad_ack`, and protocol-notification events for live parity debugging.
- `waton/client/client.py` now maintains a bounded recent outgoing message cache
  and attempts resend on incoming retry receipts (`messages.retry_request`) using
  parsed retry decisions.
- `waton/client/client.py` now emits and sends outgoing retry receipts
  (`messages.retry_request_sent`) when inbound encrypted message decryption fails,
  with configurable retry limit via `max_decrypt_retry_requests`.
- Expanded API surface in:
  - `waton/client/groups.py` (metadata, fetch participating, subject/description/
    setting updates, invite helpers, ephemeral/member mode toggles, and invite
    accept/info helpers)
  - `waton/client/communities.py` (metadata, fetch participating,
    subject/description/setting updates, invite helpers, ephemeral/member mode
    toggles, and invite accept/info helpers)
  - `waton/client/newsletter.py` (metadata, unfollow, update-name,
    update-description helpers)
- `tools/parity/scan_baileys_parity.py` now tracks additional domains:
  `messages-send`, `process-message`, `groups-api`, `communities-api`,
  `newsletter-api`, and `connection-core`.
- Added Baileys large-file parity inventory at
  `docs/parity/baileys-large-files-inventory.md`.
- `waton/client/media.py` and `waton/utils/media_utils.py` now use deterministic
  upload/checksum helpers instead of hardcoded media host strings.

### Fixed
- `waton/protocol/signal_repo.py` PKMSG parsing now accepts signed-prekey field tag
  `2` (and `6` fallback), fixing incorrect `signed_prekey_id` extraction on decrypt.
- `waton/client/messages_recv.py` call decoding now parses `offline="false"`
  correctly instead of treating any non-empty string as `True`.

### Tests
- Added `tests/unit/test_chats.py` coverage for supported `chat_modify`
  action-node emission and unknown action validation.
- Expanded `tests/unit/test_client.py` with placeholder resend coverage for:
  decrypt-failure retry flow (enabled/disabled) and retry-receipt
  placeholder request behavior.
- Expanded parity scanner unit tests in `tests/unit/test_parity_scan.py` to verify
  both domain presence and metric fields.
- Added new unit coverage for community/newsletter create response parsing:
  `tests/unit/test_communities.py`, `tests/unit/test_newsletter.py`.
- Expanded `tests/unit/test_groups.py`, `tests/unit/test_communities.py`, and
  `tests/unit/test_newsletter.py` for new parity helpers (participant request
  workflows, participant updates, subgroup linking/fetching, newsletter
  reaction and live update queries).
- Added `tests/unit/test_app.py::test_app_exposes_community_and_newsletter_clients`
  to verify high-level app surface wiring.
- Updated `tests/unit/test_groups.py` and `tests/unit/test_messages_recv.py` to
  assert non-stub behavior and real unpadding paths.
- Expanded `tests/unit/test_messages_recv.py` to cover receipt/notification
  decoding, ACK-building, and normalized dispatch behavior.
- Expanded `tests/unit/test_messages_recv.py` with call-stanza normalization and
  newsletter participant/settings notification coverage.
- Expanded `tests/unit/test_messages_recv.py` with receipt status derivation
  coverage and richer `w:gp2` notification normalization
  (announce/restrict/join-approval/create branches).
- Expanded `tests/unit/test_messages_recv.py` with `w:gp2` coverage for
  member-add mode, membership request lifecycle branches, and not-ephemeral
  normalization.
- Added `WAClient` receive wiring tests in `tests/unit/test_client.py` for
  auto-ACK and normalized event emission.
- Added `tests/unit/test_client.py` coverage ensuring incoming `call` stanzas
  emit normalized events and send `ack` with `class=call`.
- Added retry/bad-ack/protocol receive coverage in
  `tests/unit/test_messages_recv.py` and `tests/unit/test_client.py`.
- Added protocol-message coverage for revoke/edit/app-state key-share paths in
  `tests/unit/test_messages_recv.py` and `tests/unit/test_messages.py`.
- Added encrypted addon coverage in
  `tests/unit/test_messages_recv.py` and `tests/unit/test_messages.py` for
  reaction/event-response/poll-update branches.
- Added receive/process coverage for richer message-content parsing and
  message-secret extraction (document + poll creation secret paths) in
  `tests/unit/test_messages_recv.py` and `tests/unit/test_messages.py`.
- Added send-path coverage in `tests/unit/test_messages.py` for new
  `send_document` and `send_location` multi-device fanout behavior.
- Expanded send-path coverage in `tests/unit/test_messages.py` for
  `send_audio`, `send_video`, `send_sticker`, `send_contact`, and
  `send_poll_creation`.
- Added client-side effect coverage to verify `message_secret` persistence from
  normalized message events in `tests/unit/test_client.py`.
- Added newsletter notification coverage in `tests/unit/test_messages_recv.py`
  for reaction/view update branches.
- Added protocol side-effect coverage in `tests/unit/test_client.py` for app
  state key-share persistence and history sync processed markers.
- Expanded retry manager coverage for ack gating, force-send behavior, snapshot,
  stale cleanup, and explicit clear in `tests/unit/test_retry_manager.py`.
- Expanded `tests/unit/test_retry_manager.py` with retry reason parsing,
  MAC-error checks, session recreate decision logic, statistics, and
  recent-message lifecycle coverage.
- Expanded `tests/unit/test_lt_hash.py` with deterministic vectors plus
  add/remove lattice roundtrip and key decode coverage.
- Expanded `tests/unit/test_group_signal.py` with sender-key distribution
  bootstrap/validation plus import/export distribution roundtrip coverage.
- Expanded `tests/unit/test_retry_manager.py` with retry-attempt limit checks.
- Added unit coverage for expanded groups/communities/newsletter APIs in:
  `tests/unit/test_groups.py`, `tests/unit/test_communities.py`,
  `tests/unit/test_newsletter.py`.

## [0.1.0] - 2026-02-27

### Added
- **Baileys Parity Implementation**: Replaced structural stubs and mocked paths with real implementation boundaries to achieve deeper Baileys parity. New capabilities include a persist-before-emit event pipeline, an App-State patch engine mapped to LT Hash, an idempotent Retry Manager, an Identity-Change session handler, robust media round-tripping with upload retries and checksum verification, and `waton` wrapper paths for Group Cipher encryption (`group_encrypt` algorithm integration).
- **Multi-device query support**: Messages are now encrypted and sent to ALL devices
  of the recipient (phone, WhatsApp Web, linked devices) via USync device query,
  fixing the issue where messages were ACKed by server but never received
- **Incoming Message Decryption**: The app now successfully decrypts incoming `pkmsg` and `msg` E2E E2E (End-to-End) encrypted nodes inside the Signal Protocol.
- **Interactive CLI Chat (`cli_chat.py`)**: Added an interactive terminal application `examples/cli_chat.py` to test receiving and sending messages directly from the terminal.
- **High-Level App Parser Integration**: The `@app.message()` router now seamlessly unwraps `<enc>` message nodes and yields decrypted `Message` objects.
- New `waton/client/usync.py` module with `USyncQuery` class for querying device lists
- Real Rust-backed Signal helper integration (`wa-rs-libsignal`) for session bootstrap
  and session encryption
- `send_text` E2E relay flow: device key fetch (`iq encrypt`), session injection, per-device
  encrypted participant fanout, and `device-identity` inclusion for `pkmsg`
- Minimal WA protobuf wire serializer used for outgoing message payloads
- Runtime guidance for wheel-first installation (end users do not need Rust toolchain)

### Changed
- Architecture remains standalone `waton` (Python API), with Rust used only as internal
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
