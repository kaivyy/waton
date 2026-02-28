Core Concepts
=============

This page explains the core building blocks of Waton before you dive into APIs.

Architecture at a glance
------------------------

Waton has two main layers:

1. **High-level App API**
   - ``App`` gives decorator-based handlers (``@app.message(...)``) and context helpers (``ctx.reply(...)``).
   - Best for bot development and application logic.

2. **Low-level WAClient API**
   - ``WAClient`` handles transport, authentication, protocol nodes, and normalized events.
   - Best for advanced control, custom pipelines, and protocol-level debugging.

Supporting APIs (available from ``App``):

- ``MessagesAPI`` for sending messages
- ``GroupsAPI`` for group operations
- ``ChatsAPI`` for profile/privacy/chat modifications
- ``NewsletterAPI`` for channel/newsletter features
- ``BusinessAPI`` for business profile read/update
- ``PresenceAPI`` for presence updates

Message model
-------------

Incoming messages are parsed into a rich ``Message`` entity with fields such as:

- identity: ``id``, ``from_jid``, ``participant``
- text/media: ``text``, ``media_url``
- protocol updates: ``protocol_type``, ``target_message_id``, ``edited_text``
- advanced encrypted add-ons: ``poll_update``, ``event_response``, ``encrypted_reaction``
- content metadata: ``content_type``, ``content``, ``message_secret_b64``

This model is what ``Context.message`` exposes in ``App`` handlers.

App vs WAClient: when to use which
----------------------------------

Use ``App`` when:

- You want fast bot development with decorators and filters.
- You mostly care about message handling and replies.

Use ``WAClient`` when:

- You need normalized events from receipts/notifications/calls/acks.
- You need detailed lifecycle control and protocol-level visibility.

Important limitation in high-level mode
---------------------------------------

``App`` dispatches only nodes tagged ``message`` into router handlers. Non-message
node types (for example receipt/notification/call/ack/ib) are not routed via
``@app.message`` handlers. For those, use low-level ``client.on_event``.

Next steps
----------

- Connection and QR/auth lifecycle: :doc:`connection-lifecycle`
- Event names and payload categories: :doc:`event-model`
- Message categories and parsing behavior: :doc:`message-model`
