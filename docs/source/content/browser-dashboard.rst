Browser Dashboard (Devtool)
===========================

The browser dashboard provides quick manual testing in a web UI without touching
core ``waton`` runtime modules.

- Source location: ``tools/dashboard/``
- Runtime mode: **real WhatsApp Web connection**
- Purpose: connect via QR, check connection state, and test send/receive flow

Install dependency
------------------

.. code-block:: bash

    pip install -e .[dashboard]

Run dashboard
-------------

.. code-block:: bash

    python -m tools.dashboard.server --host 127.0.0.1 --port 8080

Open in browser:

.. code-block:: text

    http://127.0.0.1:8080

Security note
-------------

Keep the dashboard bound to ``127.0.0.1`` for local use. If you bind to
non-local interfaces, place it behind a trusted reverse proxy/auth layer
before exposing it.

API endpoints
-------------

- ``GET /api/health``: API health + current connection state.
- ``GET /api/connection``: current connection state (``connected``, ``connecting``, ``disconnected``).
- ``GET /api/qr``: latest QR string + QR image data URL.
- ``POST /api/connect``: start WhatsApp socket handshake and pairing.
- ``POST /api/disconnect``: disconnect current session.
- ``GET /api/events``: dashboard event stream (connection/message/ack events).
- ``GET /api/debug/summary``: debug snapshot (connection + chats + latest events).
- ``GET /api/chats``: chat list for sidebar layout.
- ``GET /api/chats/<jid>/messages``: messages for selected chat thread.
- ``POST /api/chats/<jid>/read``: reset unread counter for selected chat.
- ``POST /api/send``: send real text message through connected session.

Validation behavior
-------------------

- Accepts WA number as digits, optional leading ``+``.
- Accepts ``@s.whatsapp.net`` suffix and normalizes it.
- Rejects invalid number formats and empty text fields.
- ``POST /api/send`` returns:
  - ``200`` for queued send,
  - ``400`` for invalid/missing payload,
  - ``409`` when WhatsApp is not connected,
  - ``500`` for runtime/internal failures.

Useful for
----------

- real pairing and status monitoring from browser,
- quick message send tests without leaving UI,
- observing live connection and incoming node events.

Expected connection flow
------------------------

1. Click **Connect WhatsApp**.
2. Status changes to ``connecting`` and QR appears.
3. Scan QR from WhatsApp Linked Devices.
4. Status becomes ``connected``.
5. Send form becomes active and message tests can run.

WhatsApp Web style layout
-------------------------

- Left side shows chat list (number/title, preview, unread count, last time).
- Right side shows active chat thread with incoming/outgoing bubbles.
- New messages from other numbers automatically create/update entries on the left.
