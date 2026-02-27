Connection Lifecycle
====================

This page explains how Waton connects, authenticates, and disconnects.

Connection states
-----------------

``WAClient`` emits connection updates via ``client.on_connection_update``.
Current status values emitted by the implementation include:

- ``connecting``
- ``pairing-success``
- ``pairing-signed``
- ``open``
- ``close``

The event object is ``ConnectionEvent`` with:

- ``status``
- ``qr`` (optional)
- ``reason`` (optional)

Typical flow
------------

1. ``connect()`` is called.
2. Status becomes ``connecting``.
3. If credentials are not ready, QR values are emitted (still ``connecting``).
4. After successful auth and stream success, status becomes ``open``.
5. On disconnect/error, status becomes ``close`` with reason.

Minimal callback example
------------------------

.. code-block:: python

    async def on_connection_update(event):
        print(f"status={event.status}")
        if event.qr:
            print("QR received")
        if event.reason:
            print(f"reason={event.reason}")

Reconnect behavior
------------------

Reconnect-related behavior is controlled through configuration values in
``DEFAULT_CONNECTION_CONFIG``:

- ``auto_restart_on_515``
- ``max_restart_attempts``

These are used to decide whether restart-required disconnects should trigger
automatic reconnect attempts.

Keepalive and timeouts
----------------------

Important connection-related config keys:

- ``connect_timeout``
- ``frame_timeout``
- ``keepalive_interval``
- ``qr_timeout``

If you tune these values, keep conservative defaults for production stability.

High-level ``App`` behavior
---------------------------

``App.run()`` wraps this lifecycle:

1. Calls ``client.connect()``
2. Waits until connection status is ``open``
3. Runs optional ``@app.on_ready`` callback
4. Keeps loop alive until shutdown

If QR rendering package is installed, ``App`` prints terminal QR automatically.

Next steps
----------

- Event stream details: :doc:`event-model`
- Message parsing and content types: :doc:`message-model`
- Sending and receiving patterns: :doc:`handling-messages`
