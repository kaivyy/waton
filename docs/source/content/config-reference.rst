Configuration Reference
=======================

Waton low-level connection behavior is driven by ``DEFAULT_CONNECTION_CONFIG``.

Source of truth
---------------

Configuration defaults are defined in:

- ``waton/defaults/config.py``

The runtime merges defaults with overrides passed to:

- ``WAClient(storage, ws_url=None, **config_overrides)``

Connection and protocol defaults
--------------------------------

- ``ws_url``: WhatsApp Web websocket endpoint.
- ``origin``: default origin string.
- ``version``: tuple used in client version payload.
- ``browser``: browser/platform tuple.
- ``country_code``: locale hint in payload.

Timeouts and intervals
----------------------

- ``connect_timeout``
- ``frame_timeout``
- ``keepalive_interval``
- ``qr_timeout``

Reconnect behavior
------------------

- ``auto_restart_on_515``
- ``max_restart_attempts``

Incoming handling/reliability
-----------------------------

- ``auto_ack_incoming``
- ``max_retry_receipts``
- ``max_recent_sent_messages``
- ``auto_retry_on_decrypt_fail``
- ``max_decrypt_retry_requests``
- ``enable_placeholder_resend``
- ``placeholder_resend_on_retry``

App-state/message-secret cache
------------------------------

- ``max_message_secrets_cache``

Incoming node buffering
-----------------------

- ``enable_offline_node_buffer``
- ``incoming_node_buffer_size``
- ``incoming_node_yield_every``

Call behavior
-------------

- ``auto_reject_calls``

Minimal override example
------------------------

.. code-block:: python

    from waton.client.client import WAClient
    from waton.infra.storage_sqlite import SQLiteStorage

    storage = SQLiteStorage("waton.db")
    client = WAClient(
        storage,
        connect_timeout=30.0,
        keepalive_interval=20.0,
        auto_restart_on_515=True,
        max_restart_attempts=2,
    )

Recommendations
---------------

- Keep defaults unless you have specific operational requirements.
- Tune timeouts gradually and observe reconnect/error behavior.
- For production, pair config changes with focused tests.

Next steps
----------

- Connection lifecycle behavior: :doc:`connection-lifecycle`
- Client API surface: :doc:`client-api-reference`
