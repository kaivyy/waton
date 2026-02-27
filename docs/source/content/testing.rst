Testing Waton
=============

Unit tests
----------

Run complete unit suite:

.. code-block:: bash

    python -m pytest tests/unit -q

Run a focused area:

.. code-block:: bash

    python -m pytest tests/unit/test_messages.py -q
    python -m pytest tests/unit/test_client.py -q
    python -m pytest tests/unit/test_dashboard.py -q
    python -m pytest tests/unit/test_app.py -q

Live reliability check
----------------------

Run the integrated reliability probe:

.. code-block:: bash

    python scripts/live_check.py --auth-db waton_live.db --test-jid 628123456789@s.whatsapp.net --test-text "hello from waton"

This validates:

1. connect + auth,
2. ping/iq response,
3. optional send + ack,
4. close + reconnect.

Release preflight
-----------------

.. code-block:: bash

    python scripts/preflight_check.py

Faster local gate:

.. code-block:: bash

    python scripts/preflight_check.py --skip-lint --skip-typecheck

Docs verification
-----------------

Run strict docs build (fails on warnings):

.. code-block:: bash

    python -m pip install .[docs]
    python -m sphinx -W --keep-going -b html docs/source docs/build/html

Windows editable install lock issue
-----------------------------------

If editable install fails with:

- ``failed to copy ... waton\_crypto.pyd``
- ``os error 32`` (file being used by another process)

close running Waton Python sessions first:

.. code-block:: powershell

    Get-CimInstance Win32_Process -Filter "name='python.exe'" `
      | Where-Object { $_.CommandLine -match 'examples/cli_chat.py|examples/live_connect.py' } `
      | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

Then rerun:

.. code-block:: powershell

    python -m pip install -e .[dashboard]
