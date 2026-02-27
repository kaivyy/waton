Event Model
===========

Waton exposes two inbound streams at low level:

1. ``client.on_message(node)`` for raw protocol nodes.
2. ``client.on_event(event_dict)`` for normalized events.

If you need stable event categories for app logic, prefer ``on_event``.

Normalized event categories
---------------------------

The normalizer classifies incoming node tags and emits event dictionaries.
Common event ``type`` values include:

Message and content:

- ``messages.upsert``
- ``messages.reaction``
- ``messages.reaction_encrypted``
- ``messages.poll_update_encrypted``
- ``messages.event_response_encrypted``

Protocol-derived message events:

- ``messages.revoke``
- ``messages.edit``
- ``messages.ephemeral_setting``
- ``messages.history_sync``
- ``messages.app_state_sync_key_share``
- ``messages.group_member_label_change``
- ``messages.protocol`` (fallback)

Receipts and retry:

- ``messages.receipt``
- ``messages.retry_request``
- ``messages.retry_request_sent``

Notifications, calls, and ack lane:

- ``messages.notification``
- ``messages.call``
- ``messages.ack``
- ``messages.bad_ack``
- ``messages.protocol_notification``

Payload shape (high-level)
--------------------------

Event payloads are dictionaries and vary by type. Typical keys:

- message events: ``{"type": ..., "message": {...}}``
- receipt events: ``{"type": ..., "receipt": {...}}``
- notification events: ``{"type": ..., "notification": {...}}``
- ack events: ``{"type": ..., "ack"|"bad_ack": {...}}``
- call events: ``{"type": "messages.call", "call": {...}}``

Ordering and buffering
----------------------

Waton can prioritize incoming lanes when buffering is enabled:

1. receipt
2. notification
3. call
4. ack
5. ib
6. message
7. other

This behavior is controlled by:

- ``enable_offline_node_buffer``
- ``incoming_node_buffer_size``
- ``incoming_node_yield_every``

Tip: if your business logic depends on strict ordering, document and test with
this buffering behavior in mind.

High-level App note
-------------------

``App`` only routes ``message`` nodes to handler decorators.
For full normalized event coverage, attach listeners directly to ``WAClient``.

Next steps
----------

- Message content and parsing details: :doc:`message-model`
- App message handlers and filters: :doc:`handling-messages`
