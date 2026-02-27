Getting Started
===============

Requirements
------------

- Python 3.11+
- A WhatsApp account on a phone
- Internet connectivity

Install
-------

.. code-block:: bash

    pip install waton

For local development:

.. code-block:: bash

    pip install -e .[dev]
    maturin develop

First connection test
---------------------

Run the live connectivity example:

.. code-block:: bash

    python -u examples/live_connect.py

Expected flow:

1. QR is printed in terminal.
2. Scan from WhatsApp Linked Devices.
3. After pairing and reconnect, status becomes ``open``.
4. Ping IQ receives ``type=result``.

Optional message send test
--------------------------

PowerShell:

.. code-block:: powershell

    $env:WATON_AUTH_DB='waton_live.db'
    $env:WATON_TEST_JID='628123456789@s.whatsapp.net'
    $env:WATON_TEST_TEXT='test from waton'
    python -u examples/live_connect.py

Bash:

.. code-block:: bash

    export WATON_AUTH_DB='waton_live.db'
    export WATON_TEST_JID='628123456789@s.whatsapp.net'
    export WATON_TEST_TEXT='test from waton'
    python -u examples/live_connect.py

If your account is already connected elsewhere, WhatsApp can return conflict
disconnect code ``440``. This usually means another active linked session is
competing. Keep only one active linked session during testing.
