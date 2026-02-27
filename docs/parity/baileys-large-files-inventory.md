# Baileys Large-File Inventory (Read Pass)

Date: 2026-02-27

This inventory records the latest full re-read pass over Baileys source files
with high line counts, and maps them to current WATON modules.

## High-Impact Baileys Files

| Baileys File | Lines | WATON Counterpart | Current Notes |
| --- | ---: | --- | --- |
| `Socket/messages-recv.ts` | 1668 | `waton/client/messages_recv.py`, `waton/client/client.py`, `waton/utils/message_content.py` | Receive parsing now includes message/receipt/notification/ack/ib, retry receipt decode, bad ack decode, protocol-message extraction (revoke/edit/history/app-state key-share/member-label), encrypted addon extraction (`encReactionMessage`, `pollUpdateMessage`, `encEventResponseMessage`), newsletter notification reaction/view extraction, shared wire-level content parsing (`document/audio/video/sticker/contact/location/list/buttons/template/poll/event/newsletter`), FutureProof unwrap handling, protocol side-effect persistence (app-state key-share/history markers), message-secret cache persistence for poll/event decrypt, auto-ack, retry decision annotations, cached resend path, and outgoing decrypt-failure retry receipt emission. |
| `Socket/messages-send.ts` | 1296 | `waton/client/messages.py` | Multi-device send and encrypt fanout exist with shared relay pipeline (`_send_payload`) for text/image/document/location/audio/video/sticker/contact/poll-creation payload classes and reusable device-sent wrapping; still missing deeper retry/session recreation and advanced relay options. |
| `Socket/chats.ts` | 1272 | `waton/client/chats.py`, `waton/client/client.py` | Basic scaffolding exists; missing broader privacy/profile/presence/app-state routines. |
| `Utils/process-message.ts` | 670 | `waton/utils/process_message.py`, `waton/utils/message_content.py` | Core text/media extraction plus protocol metadata extraction now exist (revoke/edit/history/app-state key-share/member-label), protocol side effects persist app-state key-share/history markers in `WAClient`, encrypted addon branches (`encReactionMessage`, `pollUpdateMessage`, `encEventResponseMessage`) are normalized, poll/event response decrypt paths are wired, and message-context secrets are extracted from poll/event creation payloads and cached for later decrypt. Group-stub/messageStub parity remains open. |
| `Socket/groups.ts` | 361 | `waton/client/groups.py` | Added metadata/fetch-participating/subject/description/setting/invite helpers, plus ephemeral/membership mode operations and invite accept/info parsing. |
| `Socket/communities.ts` | 477 | `waton/client/communities.py` | Added metadata/fetch-participating/subject/description/setting/invite helpers, plus ephemeral/membership mode operations and invite accept/info parsing. |
| `Socket/newsletter.ts` | 229 | `waton/client/newsletter.py` | Added metadata/update-name/update-description/unfollow helpers; still missing WMex Graph ops parity depth. |
| `Socket/socket.ts` | 1141 | `waton/client/client.py` | Connection + pairing + ping + incoming routing are present; still missing several socket orchestration edge flows. |

## Key Baileys Branches Re-Checked

- `messages-recv.ts`:
  - `handleReceipt`
  - `handleNotification`
  - `handleMessage`
  - `handleBadAck`
  - `sendRetryRequest`
  - `sendMessagesAgain`
  - `processNotification`
- `groups.ts`:
  - `groupMetadata`
  - `groupFetchAllParticipating`
  - `groupUpdateSubject`
  - `groupUpdateDescription`
  - `groupSettingUpdate`
  - `groupInviteCode` / `groupRevokeInvite`
- `communities.ts`:
  - `communityMetadata`
  - `communityFetchAllParticipating`
  - `communityUpdateSubject`
  - `communityUpdateDescription`
  - `communitySettingUpdate`
  - `communityInviteCode` / `communityRevokeInvite`
- `newsletter.ts`:
  - metadata/follow/unfollow/mute/unmute/update operations

## Immediate Remaining Depth Gaps

- Full `sendRetryRequest` branch parity
  (RetryManager now includes retry reason parsing, MAC-error detection, session-recreate timing heuristics, recent-message cache/index, phone-request scheduling hooks, and retry stats, but resend/session rebuild policy orchestration in socket flow is still thinner than Baileys).
- Extended `process-message` branches (deeper app-state chat mutations, deeper group-stub mapping, broader message association updates).
- Chats/privacy/presence/app-state utilities from `Socket/chats.ts`.
- WMex-heavy newsletter operations beyond core metadata/update/follow-state routines.
