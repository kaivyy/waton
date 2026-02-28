Client API Reference
====================

This page summarizes core low-level client APIs available in Waton.

WAClient
--------

Constructor:

.. code-block:: python

    WAClient(storage, ws_url=None, **config_overrides)

Core methods:

- ``connect()``
- ``disconnect()``
- ``send_node(node)``
- ``query(node, timeout=None)``
- ``send_ping()``

Callbacks (settable async callables):

- ``on_connection_update(event)``
- ``on_message(node)``
- ``on_event(event_dict)``
- ``on_disconnected(exc)``

MessagesAPI
-----------

Common outbound methods:

- ``send_text`` / ``send_image`` / ``send_document`` / ``send_location``
- ``send_audio`` / ``send_video`` / ``send_sticker`` / ``send_contact``
- ``send_reaction`` / ``send_delete`` / ``send_edit``
- ``send_poll_creation`` / ``send_poll_vote`` / ``send_event_response``
- ``send_ephemeral_setting``
- ``send_receipt`` / ``send_receipts_batch`` / ``read_messages``

GroupsAPI
---------

- metadata/fetch helpers
- group create/update operations
- participants and approval request operations
- invite code and join helpers
- leave group

ChatsAPI
--------

- profile and presence helpers
- blocklist/privacy read + selected privacy updates
- chat modify actions (archive/pin/mute/read variations)

PresenceAPI
-----------

- ``send_presence``
- ``send_available``
- ``send_unavailable``
- ``send_composing``
- ``send_paused``

NewsletterAPI
-------------

- create, metadata, follow/unfollow, mute
- update name/description
- react, fetch messages, subscribe live updates

BusinessAPI
-----------

- ``business_profile(jid)``
- ``update_business_profile(jid, *, name=None, description=None, email=None, category=None)``

MexAPI
------

- ``query(operation, params=None)`` for minimal ``w:mex`` request/response wrapper.

Support status guidance
-----------------------

- APIs listed here are implemented in current codebase.
- Some areas are intentionally low-level and may require careful error handling.
- Use focused tests when integrating advanced features.

Next steps
----------

- Event payload categories: :doc:`event-model`
- Config tuning: :doc:`config-reference`
