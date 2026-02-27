Handling Messages
=================

This guide shows how to handle incoming messages with the high-level ``App`` API.

Basic handler flow
------------------

``App`` routes incoming ``message`` nodes into your registered handlers.

.. code-block:: python

    from waton import App
    from waton.app import filters

    app = App(storage_path="my_session.db")

    @app.message(filters.text & filters.private)
    async def on_private_text(ctx):
        if ctx.text:
            await ctx.reply(f"You said: {ctx.text}")

    @app.command("/help")
    async def on_help(ctx):
        await ctx.reply("Available commands: /help, ping")

Filters
-------

Available built-in filters:

- ``filters.text``
- ``filters.private``
- ``filters.group``
- ``filters.regex(pattern)``
- ``filters.command(prefix)``

Filters can be combined:

- ``filters.text & filters.private``
- ``filters.group | filters.private``

Context helpers
---------------

Inside a handler, ``ctx`` provides:

- ``ctx.text``
- ``ctx.from_jid``
- ``ctx.sender``
- ``await ctx.reply(text)``
- ``await ctx.react(emoji)``

Advanced helpers also exist:

- ``await ctx.forward(to_jid)``
- ``await ctx.delete()``

For production-critical revoke/edits, prefer explicit ``MessagesAPI`` methods
such as ``send_delete(...)`` and ``send_edit(...)``.

Middleware
----------

You can add middleware to run logic before/after handlers:

.. code-block:: python

    async def log_middleware(ctx, next_step):
        print(f"incoming from={ctx.from_jid} text={ctx.text!r}")
        await next_step()

    app.use(log_middleware)

Message content model
---------------------

``ctx.message`` contains parsed metadata beyond plain text, including:

- ``content_type`` and ``content``
- protocol fields (edit/revoke/history/app-state)
- encrypted add-on fields (poll update, event response, encrypted reaction)

If you need these details, inspect ``ctx.message`` directly.

Important scope note
--------------------

``App`` handlers process only ``message`` nodes. If you need normalized non-message
events (receipts, notifications, calls, acks), attach handlers to low-level
``WAClient.on_event``.

Next steps
----------

- Outgoing message APIs: :doc:`sending-messages`
- Event categories and payloads: :doc:`event-model`
