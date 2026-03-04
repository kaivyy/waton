AI Agent Quickstart
===================

This page is optimized for AI agents and automation workflows.
It gives a short, deterministic path to install, initialize, and use Waton.

Install
-------

For reproducible agent runs, pin exact version:

.. code-block:: bash

    pip install waton==0.1.2

If you always want newest release:

.. code-block:: bash

    pip install -U waton

Quickest Runtime API (recommended)
----------------------------------

Use the simple callback API for lowest setup friction:

.. code-block:: python

    from waton import simple

    client = simple(storage_path="waton_session.db")

    @client.on_ready
    async def on_ready(bot):
        print("ready")

    @client.on_message
    async def on_message(msg):
        if msg.text:
            await msg.reply(f"echo: {msg.text}")

    if __name__ == "__main__":
        client.run()

Minimal Agent Rules
-------------------

- Use ``from waton import simple`` for first integration.
- Keep one active linked WhatsApp session during test to avoid disconnect conflict ``440``.
- Prefer pinned version in production agents.
- For custom socket/event control, use ``WAClient`` via :doc:`quickstart-low-level`.

Operational Checklist for Agents
--------------------------------

1. Install package (prefer pinned version).
2. Start process and pair via QR on first run.
3. Wait until connection state is open/ready.
4. Send/receive a small text message as smoke test.
5. Persist auth DB volume/path for restart continuity.

Troubleshooting
---------------

**Import/runtime mismatch**

- Run:

  .. code-block:: bash

      python -m pip show waton

- Ensure expected version is installed in active environment.

**Agent environment is Linux and install feels slow**

- If wheel for platform is unavailable, pip may build from source (slower).
- Project release workflow publishes multi-platform wheels to reduce this.

**No incoming message appears**

- Check that pairing succeeded and no other conflicting linked session is taking over.
- Validate target chat/JID format and connectivity before retrying.
