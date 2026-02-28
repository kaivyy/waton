Read the Docs Setup
===================

This repository is ready for Read the Docs via ``.readthedocs.yaml``.

Project import steps
--------------------

1. Open `Read the Docs Dashboard <https://app.readthedocs.org/dashboard/>`_.
2. Click **Import a Project**.
3. Select ``kaivyy/waton`` repository.
4. Confirm default branch (usually ``main``).

Build configuration used
------------------------

- Config file: ``.readthedocs.yaml``
- Builder: Sphinx
- Sphinx config: ``docs/source/conf.py``
- Install command: ``pip install .[docs]``

Local verification before pushing
---------------------------------

.. code-block:: bash

    python -m pip install .[docs]
    python -m sphinx -W --keep-going -b html docs/source docs/build/html

Generated site will be available at:

.. code-block:: text

    docs/build/html/index.html

Operational checklist
---------------------

Before release/tag:

1. Update ``CHANGELOG.md``.
2. Ensure docs pages are linked from ``docs/source/index.rst``.
3. Build docs locally and confirm success.
4. Push branch/tag and verify RTD build result.
5. Open published docs and smoke-test key pages:
   - Getting Started (including ``waton.simple`` snippet)
   - Quickstart App
   - Event Model
   - Browser Dashboard

Troubleshooting
---------------

**Build fails with import errors**

- Make sure ``pyproject.toml`` includes ``docs`` optional dependencies.

**Page exists but not visible in docs nav**

- Add it in ``docs/source/index.rst`` toctree.

**No automatic builds after push**

- Check GitHub webhook/integration status in RTD project settings.
