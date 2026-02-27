Sending Messages
================

Waton exposes outbound messaging through ``MessagesAPI``.

Quick start
-----------

From high-level ``App`` handlers, use context helpers:

- ``await ctx.reply("...")``
- ``await ctx.react("🚀")``

For full control, use ``app.messages`` (``MessagesAPI``).

Core send methods
-----------------

Implemented methods include:

- ``send_text(to_jid, text)``
- ``send_image(to_jid, image_bytes, caption="")``
- ``send_document(to_jid, document_bytes, file_name=..., mimetype=..., caption="")``
- ``send_location(to_jid, latitude=..., longitude=..., name=..., address=..., url=..., comment=...)``
- ``send_audio(to_jid, audio_bytes, mimetype=..., seconds=..., ptt=...)``
- ``send_video(to_jid, video_bytes, mimetype=..., caption=..., seconds=..., height=..., width=..., gif_playback=...)``
- ``send_sticker(to_jid, sticker_bytes, mimetype=..., height=..., width=..., is_animated=...)``
- ``send_contact(to_jid, display_name=..., vcard=...)``

Advanced methods
----------------

- ``send_reaction(to_jid, message_id, reaction)``
- ``send_delete(to_jid, target_message_id, participant=None, from_me=False)``
- ``send_edit(to_jid, target_message_id, text, participant=None, from_me=False, edited_at_ms=None)``
- ``send_ephemeral_setting(to_jid, expiration_seconds=..., setting_timestamp=None)``
- ``send_poll_creation(...)``
- ``send_poll_vote(...)``
- ``send_event_response(...)``

Read/receipt utilities
----------------------

- ``send_receipt(jid, participant, message_ids, receipt_type="read")``
- ``send_receipts_batch(keys, receipt_type="read")``
- ``read_messages(keys, read_self=False)``

Minimal example
---------------

.. code-block:: python

    msg_id = await app.messages.send_text("628123456789@s.whatsapp.net", "hello")
    await app.messages.send_reaction("628123456789@s.whatsapp.net", msg_id, "✅")

Reliability notes
-----------------

``MessagesAPI`` sends through multi-device fanout and per-device Signal encryption.
If not authenticated, send methods raise errors (for example when session is not open).

For dashboard HTTP send flow, see :doc:`dashboard-api-reference`.

Next steps
----------

- Parsing and handling incoming content: :doc:`handling-messages`
- Group operations: :doc:`groups`
