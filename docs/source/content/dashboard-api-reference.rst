Dashboard API Reference
=======================

The browser dashboard exposes HTTP endpoints for manual testing and inspection.

Base URL
--------

Default local URL:

.. code-block:: text

    http://127.0.0.1:8080

Core endpoints
--------------

Health and connection:

- ``GET /api/health``
  - Returns service status and current connection snapshot.
- ``GET /api/connection``
  - Returns current dashboard connection state.
- ``GET /api/qr``
  - Returns current QR string + SVG data URL when available.

Events and observability:

- ``GET /api/events``
  - Returns buffered dashboard events.
- ``GET /api/debug/summary``
  - Returns high-level debug summary including ``chat_count``, ``chats`` and ``events_tail``.

Chat views:

- ``GET /api/chats``
  - Returns chat list for sidebar UI.
- ``GET /api/chats/<chat_jid>/messages``
  - Returns message list for selected chat.
- ``POST /api/chats/<chat_jid>/read``
  - Resets unread count for selected chat.

Session actions:

- ``POST /api/connect``
  - Starts WhatsApp connect/pair flow.
- ``POST /api/disconnect``
  - Disconnects active session.
- ``POST /api/send``
  - Queues outbound text message through connected session.

``/api/send`` request
---------------------

Request JSON:

.. code-block:: json

    {
      "to": "6281234567890",
      "text": "hello"
    }

``to`` accepts:

- digits only
- optional leading ``+``
- optional ``@s.whatsapp.net`` suffix

Response behavior:

- ``200``: queued successfully
- ``400``: invalid/missing ``to`` or ``text``
- ``409``: WhatsApp is not connected yet
- ``500``: internal send/connect/disconnect errors

Minimal curl smoke tests
------------------------

.. code-block:: bash

    curl -s http://127.0.0.1:8080/api/health
    curl -s -X POST http://127.0.0.1:8080/api/connect
    curl -s http://127.0.0.1:8080/api/qr
    curl -s -X POST http://127.0.0.1:8080/api/send \
      -H "Content-Type: application/json" \
      -d '{"to":"6281234567890","text":"hello"}'

Notes
-----

- Dashboard runs against real WhatsApp session state.
- Keep a dedicated auth DB for dashboard (``WATON_DASHBOARD_AUTH_DB``) when needed.
- For endpoint behavior verification, see unit tests in ``tests/unit/test_dashboard.py``.

Next steps
----------

- Operational usage guide: :doc:`browser-dashboard`
- General troubleshooting: :doc:`faq-troubleshooting`
