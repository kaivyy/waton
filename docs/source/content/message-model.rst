Message Model
=============

Waton parses WhatsApp message payloads into a normalized shape for easier app logic.

Parsed ``Message`` fields
-------------------------

When using ``App``, incoming message nodes are parsed into ``Message`` objects with fields such as:

- core: ``id``, ``from_jid``, ``participant``, ``timestamp``
- text/media: ``text``, ``media_url``
- reactions: ``reaction``, ``reaction_target_id``
- protocol: ``protocol_type``, ``protocol_code``, ``target_message_id``, ``edited_text``
- ephemeral/history/app-state: ``ephemeral_expiration``, ``history_sync_type``, ``app_state_key_ids``
- encrypted add-ons: ``encrypted_reaction``, ``poll_update``, ``event_response``
- content map: ``content_type``, ``content``, ``message_secret_b64``

This rich model allows one handler pipeline to support simple text bots and advanced message types.

Content type extraction
-----------------------

The parser detects and maps multiple message formats. Common ``content_type`` values include:

- ``text``
- ``image``
- ``document``
- ``audio``
- ``video``
- ``sticker``
- ``contact``
- ``location``
- ``live_location``
- ``list``
- ``buttons``
- ``template``
- ``poll_creation``
- ``event``
- ``newsletter_admin_invite``
- ``newsletter_follower_invite``

Encrypted add-ons and message secrets
-------------------------------------

For poll/event flows, Waton stores ``message_secret_b64`` and later uses it to decrypt:

- encrypted poll vote updates
- encrypted event responses

If decryption data is unavailable, the parser still keeps raw encrypted structures so your app can handle fallback behavior.

LID/PN handling notes
---------------------

Incoming processing supports LID/PN mapping logic and fallback decrypt attempts.
If one addressing form fails decryption, Waton can retry alternate mapping paths based on available session/mapping data.

Practical recommendation
------------------------

In handlers, prefer a safe pattern:

1. check ``message.content_type`` first,
2. use ``message.text`` for plain text logic,
3. inspect ``message.content`` for type-specific metadata,
4. use protocol fields for edit/revoke/history/app-state behavior.

Next steps
----------

- Build handlers with filters and context helpers: :doc:`handling-messages`
- Sending compatible message types: :doc:`sending-messages`
