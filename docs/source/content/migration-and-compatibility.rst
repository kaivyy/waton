Migration and Compatibility
===========================

This page documents compatibility expectations and migration checkpoints for Waton users.

Runtime compatibility
---------------------

Current baseline:

- Python ``3.11+``

Always align deployment/runtime with package metadata in ``pyproject.toml``.

Configuration compatibility
---------------------------

When updating Waton versions:

1. Keep your auth storage file/database persistent.
2. Re-check custom ``WAClient`` config overrides against current
   ``DEFAULT_CONNECTION_CONFIG`` keys.
3. Re-validate reconnect and timeout behavior in staging.

Message/event compatibility
---------------------------

Waton supports a broad message/event model, including encrypted add-ons for
poll/event responses. These features rely on internal message-secret persistence.

Migration checklist for apps
----------------------------

- Re-run unit tests for your integration points.
- Re-run docs strict build if you maintain custom docs.
- Re-validate live connect and optional send-ack probe.
- Re-check dashboard behavior if you expose internal tooling.

Suggested validation commands
-----------------------------

.. code-block:: bash

    python -m pytest tests/unit -q
    python scripts/live_check.py --auth-db waton_live.db

For docs maintainers:

.. code-block:: bash

    python -m sphinx -W --keep-going -b html docs/source docs/build/html

Release notes and changes
-------------------------

Use these project artifacts as your change reference:

- ``CHANGELOG.md``
- recent commits on your tracked branch

If behavior changes are detected in your app, prefer pinning and upgrading with
incremental validation rather than big jumps.
