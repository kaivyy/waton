Business and Newsletters
========================

This page summarizes current business/newsletter support in Waton.

Business-related behavior
-------------------------

Current implementation includes business-aware metadata handling during pairing
and device registration payload preparation.

Support status: **partial**

- Connection/auth paths include business-compatible fields.
- A dedicated high-level Business profile API is not yet exposed as a separate module.

Newsletter API
--------------

Waton currently provides ``NewsletterAPI`` methods, available as ``app.newsletter``:

- ``create_newsletter(name, description="", picture_bytes=None)``
- ``newsletter_metadata(jid)``
- ``follow_newsletter(jid)``
- ``unfollow_newsletter(jid)``
- ``mute_newsletter(jid, mute=True)``
- ``newsletter_update_name(jid, name)``
- ``newsletter_update_description(jid, description)``
- ``newsletter_react_message(jid, server_id, reaction=None)``
- ``newsletter_fetch_messages(jid, count, since=None, after=None)``
- ``subscribe_newsletter_updates(jid)``

Newsletter events
-----------------

Low-level notification parsing can expose newsletter-related structures through
``messages.notification`` payloads (for example reaction/view/participant/settings updates).

Support status notes
--------------------

- Newsletter operations are implemented with low-level query/send-node patterns.
- Server capability and account permissions still determine runtime success.
- Keep error handling in your application for permission or unsupported-operation cases.

Example
-------

.. code-block:: python

    channel_jid = await app.newsletter.create_newsletter("My Channel", "Example channel")
    await app.newsletter.follow_newsletter(channel_jid)
    metadata = await app.newsletter.newsletter_metadata(channel_jid)
    print(metadata)

Next steps
----------

- Group management flows: :doc:`groups`
- Full low-level event map: :doc:`event-model`
