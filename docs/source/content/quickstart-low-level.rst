Quickstart: Low-Level WAClient
==============================

Use this guide if you want direct control over socket lifecycle and events.

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

Minimal client example
----------------------

.. code-block:: python

    import asyncio

    from waton.client.client import WAClient
    from waton.infra.storage_sqlite import SQLiteStorage


    async def main() -> None:
        storage = SQLiteStorage("waton_low_level.db")
        client = WAClient(storage)

        async def on_connection_update(event):
            print(f"[connection] status={event.status}")
            if event.qr:
                print("[connection] qr received")

        async def on_message(node):
            print(f"[node] tag={node.tag} attrs={node.attrs}")

        async def on_event(event):
            print(f"[event] type={event.get('type')}")

        client.on_connection_update = on_connection_update
        client.on_message = on_message
        client.on_event = on_event

        await client.connect()
        print("Connected. Running ping...")
        pong = await client.send_ping()
        print(f"Ping OK: {pong.attrs}")

        await asyncio.sleep(10)
        await client.disconnect()
        await storage.close()


    if __name__ == "__main__":
        asyncio.run(main())

Run
---

.. code-block:: bash

    python my_low_level.py

Expected output
---------------

- ``[connection] status=connecting``
- QR event appears and can be scanned
- ``[connection] status=open``
- ``Ping OK: ...``

When to use WAClient directly
-----------------------------

- You need normalized event stream handling (``client.on_event``).
- You need custom lifecycle/reconnect behavior.
- You are building your own abstraction layer.

Next steps
----------

- Connection state details: :doc:`connection-lifecycle`
- Event catalog and payload shape: :doc:`event-model`
- Full client/reference pages: :doc:`client-api-reference`
