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
- Release documentation target: ``waton==0.1.3``

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

1. Bump package version in ``pyproject.toml``, ``Cargo.toml``, and ``waton/__init__.py`` (current release: ``0.1.3``).
2. Update ``CHANGELOG.md``.
3. Ensure docs pages are linked from ``docs/source/index.rst``.
4. Build docs locally and confirm success.
5. Push branch/tag and verify RTD build result.
6. Run security dependency gate locally before release:

   .. code-block:: bash

      python -m pip install pip-audit
      pip-audit --strict

7. Open published docs and smoke-test key pages:
   - Getting Started (including ``waton.simple`` snippet)
   - AI Agent Quickstart
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
