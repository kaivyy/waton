Quickstart: App (Recommended)
=============================

This is the fastest way to build a WhatsApp bot with Waton.

Prerequisites
-------------

- Python 3.11+
- WhatsApp account on phone
- Internet connection

Install
-------

.. code-block:: bash

    pip install waton

For local development from repository root:

.. code-block:: bash

    pip install -e .[dev]
    maturin develop

Create a minimal bot
--------------------

Create a file ``my_bot.py``:

.. code-block:: python

    from waton import App
    from waton.app import filters

    app = App(storage_path="my_session.db")

    @app.on_ready
    async def on_ready(ctx):
        print("Connected and ready.")

    @app.message(filters.text & filters.private)
    async def on_private_text(ctx):
        if ctx.text and ctx.text.lower() == "ping":
            await ctx.reply("pong from waton")

    @app.command("/help")
    async def help_command(ctx):
        await ctx.reply("Commands: /help, ping")

    if __name__ == "__main__":
        app.run()

Run
---

.. code-block:: bash

    python my_bot.py

Expected flow
-------------

1. Terminal prints a QR code.
2. Scan from WhatsApp Linked Devices.
3. Connection status reaches ``open``.
4. ``Connected and ready.`` appears.
5. Send ``ping`` from another account; bot replies.

Useful notes
------------

- ``App`` is the high-level API and wraps ``WAClient``.
- ``ctx.reply(...)`` sends to the current chat.
- If your account is active in another linked session, you might see disconnect conflict code ``440``.

Next steps
----------

- For low-level socket/event control, see :doc:`quickstart-low-level`.
- To understand connection states and reconnect behavior, see :doc:`connection-lifecycle`.
- To learn message handlers and filters in detail, see :doc:`handling-messages`.
