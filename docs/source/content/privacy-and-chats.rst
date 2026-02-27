Privacy and Chats
=================

Chat and privacy-related methods are exposed through ``ChatsAPI``.

Chat operations
---------------

Presence and profile:

- ``send_presence_update(jid, presence)``
- ``presence_subscribe(jid)``
- ``get_profile_picture(jid)``
- ``update_profile_status(status)``
- ``update_profile_name(name)``

Chat modifications:

- ``chat_modify(jid, action)``

Supported ``chat_modify`` actions:

- ``archive`` / ``unarchive``
- ``pin`` / ``unpin``
- ``mute`` / ``unmute``
- ``read`` / ``unread``

Privacy operations
------------------

Implemented privacy methods:

- ``fetch_blocklist()``
- ``fetch_privacy_settings()``
- ``update_last_seen_privacy(value)``
- ``update_read_receipts_privacy(value)``

Current support status
----------------------

Partial support:

- Privacy updates currently wrap selected categories (``last`` and ``readreceipts``).
- Broader WhatsApp privacy categories are not yet wrapped as dedicated helper methods.

Example
-------

.. code-block:: python

    settings = await app.chats.fetch_privacy_settings()
    print(settings)

    await app.chats.update_last_seen_privacy("contacts")
    await app.chats.update_read_receipts_privacy("all")

    await app.chats.chat_modify("628123456789@s.whatsapp.net", "archive")

Presence helper API
-------------------

Waton also exposes ``PresenceAPI`` directly as ``app.presence``:

- ``send_presence(jid, presence)``
- ``send_available(jid)``
- ``send_unavailable(jid)``
- ``send_composing(jid)``
- ``send_paused(jid)``

Next steps
----------

- App-state and history sync behavior: :doc:`app-state-and-history-sync`
- Dashboard behavior for chat read/send workflows: :doc:`dashboard-api-reference`
