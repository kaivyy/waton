App Framework Reference
=======================

The high-level ``App`` framework is designed for bot/application workflows.

App class
---------

Create app:

.. code-block:: python

    from waton import App
    app = App(storage_path="waton.db")

Attached APIs:

- ``app.messages`` (``MessagesAPI``)
- ``app.chats`` (``ChatsAPI``)
- ``app.groups`` (``GroupsAPI``)
- ``app.communities`` (``CommunitiesAPI``)
- ``app.newsletter`` (``NewsletterAPI``)
- ``app.media`` (``MediaManager``)
- ``app.presence`` (``PresenceAPI``)

Decorators and hooks
--------------------

- ``@app.on_ready``
- ``@app.message(custom_filter=None)``
- ``@app.command(prefix)``

Middleware
----------

Register middleware:

.. code-block:: python

    async def middleware(ctx, next_step):
        await next_step()

    app.use(middleware)

Middleware signature:

- ``(ctx, next_step) -> awaitable``

Router behavior
---------------

- Routes are evaluated in registration order.
- Handlers run when filter passes.
- App dispatch currently processes incoming nodes with tag ``message``.

Context reference
-----------------

Properties:

- ``ctx.text``
- ``ctx.from_jid``
- ``ctx.sender``
- ``ctx.message``

Methods:

- ``await ctx.reply(text)``
- ``await ctx.react(emoji)``
- ``await ctx.forward(to_jid)``
- ``await ctx.delete()``

Lifecycle
---------

``app.run()`` will:

1. connect client,
2. wait until authenticated/open,
3. run ready callback,
4. keep process alive,
5. disconnect and close storage on exit.

Notes
-----

- ``App`` is the easiest way to build handlers quickly.
- For an even simpler callback surface, use ``from waton import simple``.
- For full protocol/event control, attach to ``WAClient`` directly.

Next steps
----------

- Handler patterns: :doc:`handling-messages`
- Low-level client details: :doc:`client-api-reference`
