# Baileys V7 Delta Matrix

This matrix tracks the Baileys v7/rc11 capability surface that Waton should follow without changing existing runtime behavior by default.

Policy: new capability lands as additive metadata, storage support, diagnostics, or feature-flagged behavior first. A feature can become default only after replay fixtures, differential evidence, and rollback documentation are available.

| Domain | Status | Risk | Waton Surface | Baileys Reference | Activation Gate |
| --- | --- | --- | --- | --- | --- |
| LID mapping | Partial | High | `waton/core/jid.py`, `waton/protocol/signal_repo.py` | `src/Signal/lid-mapping.ts`, `src/Utils/sync-action-utils.ts` | Storage-first shadow mode |
| Tctoken | Planned | High | `waton/client/retry_manager.py` | `src/Utils/tc-token-utils.ts` | Feature flag and replay evidence |
| Retry/resend | Partial | High | `waton/client/retry_manager.py`, `waton/client/messages_recv.py` | `src/Utils/message-retry-manager.ts`, `src/Socket/messages-recv.ts` | Feature flag and differential fixtures |
| App-state resilience | Partial | Medium | `waton/protocol/app_state.py`, `waton/utils/chat_utils.py` | `src/Utils/chat-utils.ts`, `src/Utils/process-message.ts` | Shadow-mode error classification |
| Offline node batching | Partial | Medium | `waton/client/event_pipeline.py`, `waton/client/client.py` | `src/Utils/offline-node-processor.ts` | Batching benchmarks and event-order fixtures |
| Send/media robustness | Partial | Medium | `waton/client/messages.py`, `waton/client/media.py` | `src/Socket/messages-send.ts`, `src/Utils/messages-media.ts` | Per-recipient diagnostics feature flag |
| Notification surface | Partial | Medium | `waton/client/messages_recv.py`, `waton/core/events.py` | `src/Socket/messages-recv.ts`, `src/Types/Events.ts` | Optional event fields only |
| WA version drift | Planned | Low | `waton/defaults/config.py` | `src/Defaults/baileys-version.json` | Preflight report only |

## Release Target

`0.1.4rc3` extends the tracking and compatibility scaffolding:

- disabled-by-default Baileys v7 power flags in default config;
- machine-readable v7 matrix in parity scan output;
- WA Web version drift tracker for comparing Waton and a local Baileys checkout;
- Baileys-compatible JID classification helpers for PN, LID, hosted, newsletter, bot, and status JIDs;
- additive metadata namespaces in JSON and SQLite storage for future LID, device-list, tctoken, retry, and identity-change state;
- roadmap and status artifacts for future implementation phases.

## Default Behavior Contract

The following behavior remains unchanged in `0.1.4rc3`:

- current ACK policy;
- current retry/resend behavior;
- current message send and receive dispatch semantics;
- current Signal session selection;
- current app-state and offline node processing defaults;
- current public imports and callback API.
