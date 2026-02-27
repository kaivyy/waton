Group Management
================

Waton group features are available through ``GroupsAPI``.

Implemented capabilities
------------------------

Metadata and discovery:

- ``group_metadata(jid)``
- ``group_fetch_all_participating()``

Create and basic updates:

- ``create_group(subject, participants)``
- ``group_update_subject(jid, subject)``
- ``group_update_description(jid, description)``

Settings and modes:

- ``group_setting_update(jid, setting)``
- ``group_toggle_ephemeral(jid, ephemeral_expiration)``
- ``group_member_add_mode(jid, mode)``
- ``group_join_approval_mode(jid, mode)``

Participant operations:

- ``group_participants_update(jid, participants, action)``
- ``group_request_participants_list(jid)``
- ``group_request_participants_update(jid, participants, action)``
- ``add_participants(group_jid, participants)``

Invite operations:

- ``group_invite_code(jid)``
- ``group_revoke_invite(jid)``
- ``group_revoke_invite_v4(group_jid, invited_jid)``
- ``group_accept_invite(code)``
- ``group_get_invite_info(code)``

Leave:

- ``leave_group(group_jid)``

Example
-------

.. code-block:: python

    group_jid = await app.groups.create_group(
        subject="Waton Test Group",
        participants=["628123456789@s.whatsapp.net"],
    )
    await app.groups.group_update_subject(group_jid, "Waton Group Updated")

Important notes
---------------

- Some group methods accept generic ``action``/``setting`` tags. Use known server-compatible values.
- Participant/admin/approval semantics depend on current group policy and WhatsApp-side permissions.

Receiving group updates
-----------------------

At low level, group-related changes can appear via ``messages.notification``
(normalized events), including metadata and participant changes.

Next steps
----------

- Privacy and chat-level controls: :doc:`privacy-and-chats`
- Event stream details: :doc:`event-model`
