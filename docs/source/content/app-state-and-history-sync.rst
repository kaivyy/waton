App State and History Sync
==========================

This page describes current app-state and history-sync behavior implemented in Waton.

Protocol side effects
---------------------

When low-level normalized events are processed, ``WAClient`` applies persistence
side effects for specific protocol event types.

Implemented flows:

- ``messages.app_state_sync_key_share``: app-state sync key metadata is stored in
  ``creds.additional_data["app_state_sync_keys"]``.

- ``messages.history_sync``: processed history entries are appended to
  ``creds.processed_history_messages`` with dedupe checks.

Message secret persistence
--------------------------

When message content indicates poll/event creation with ``message_secret_b64``,
Waton stores the secret under:

- ``creds.additional_data["message_secrets"][message_id]``

This enables later decryption attempts for:

- encrypted poll vote updates
- encrypted event response updates

Cache size is controlled by:

- ``max_message_secrets_cache``

Related normalized event types
------------------------------

You will commonly see these during app-state/history flows:

- ``messages.history_sync``
- ``messages.app_state_sync_key_share``
- ``messages.notification`` (history/server/account sync metadata can appear here)

Support status
--------------

Partial support:

- Persistence and event-side handling are implemented.
- A full high-level app-state command API is not yet exposed as user-facing wrappers.

Practical guidance
------------------

- Keep credentials storage healthy and durable (for example SQLite in stable path).
- Avoid deleting auth DB between runs if you rely on incremental app-state/history behavior.

Next steps
----------

- Full event categories: :doc:`event-model`
- Troubleshooting sync/retry behavior: :doc:`faq-troubleshooting`
