FAQ and Troubleshooting
=======================

This page collects the most common runtime issues and quick fixes.

I cannot send via dashboard
---------------------------

Symptom:

- ``POST /api/send`` returns ``409``.

Cause:

- WhatsApp session is not connected yet.

Fix:

1. Call ``POST /api/connect``.
2. Open ``GET /api/qr`` and scan QR from Linked Devices.
3. Confirm ``GET /api/connection`` reports ``connected``.

I get invalid WA ID errors
--------------------------

Symptom:

- ``POST /api/send`` returns ``400`` with invalid ID message.

Cause:

- ``to`` is not a valid WhatsApp number format.

Fix:

- Use digits only, optional leading ``+``.
- Optional ``@s.whatsapp.net`` suffix is accepted.
- Avoid dashes/spaces/letters.

QR is not shown
---------------

Checklist:

- Ensure runtime state is ``connecting`` after ``/api/connect``.
- Check ``GET /api/qr`` output.
- Use ``GET /api/debug/summary`` to inspect events and state transitions.

Disconnect conflict code 440
----------------------------

Symptom:

- Session disconnects with conflict behavior (often code ``440``).

Cause:

- Another active linked session is competing.

Fix:

- Keep only one active linked session for testing.
- Reconnect and scan QR again if required.

Ack timeout on live send test
-----------------------------

Symptom:

- ``examples/live_connect.py`` reports send-ack timeout.

Fix:

- Verify destination JID is correct.
- Increase timeout (``WATON_ACK_TIMEOUT``).
- Check incoming event logs and network stability.

Editable install fails on Windows (os error 32)
------------------------------------------------

Symptom:

- ``failed to copy ... waton\_crypto.pyd``
- ``os error 32``

Cause:

- Another running Python process is locking ``_crypto.pyd``.

Fix:

- Stop running Waton scripts and retry installation.
- See the README Windows troubleshooting section for PowerShell command.

Docs build fails
----------------

Use strict local build to catch issues:

.. code-block:: bash

    python -m pip install .[docs]
    python -m sphinx -W --keep-going -b html docs/source docs/build/html

If page is missing in nav
-------------------------

- Ensure page is listed in ``docs/source/index.rst`` toctree.

Useful verification commands
----------------------------

.. code-block:: bash

    python -m pytest tests/unit/test_dashboard.py -q
    python -m pytest tests/unit/test_messages.py -q
    python -m pytest tests/unit/test_client.py -q
    python -m pytest tests/unit/test_app.py -q
