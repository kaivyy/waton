# Docs Modern Rebrand Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a bold, dark, modern docs experience with GitHub icon/link polish and less rigid visual presentation while keeping the existing Sphinx stack stable on Read the Docs.

**Architecture:** Keep `sphinx_book_theme` as the base to minimize migration risk, then layer a custom visual system via `html_css_files` and optional icon assets. Restructure homepage content in `index.rst` into a modern hero + quick navigation blocks while preserving current toctree information architecture. Use only additive, low-risk config updates in `conf.py`.

**Tech Stack:** Sphinx 8/9, sphinx-book-theme, MyST parser, custom CSS, Font Awesome CDN (for GitHub/social icons)

---

### Task 1: Configure theme for modern nav and icon support

**Files:**
- Modify: `docs/source/conf.py`
- Test: `python -m sphinx -T -b html -d docs/_build/doctrees docs/source docs/_build/html`

**Step 1: Write the failing test**

Use a build-as-test check that should fail if new config keys are invalid.

Run:
```bash
python -m sphinx -T -b html -d docs/_build/doctrees docs/source docs/_build/html
```

Expected (before edits): PASS currently, used as baseline only.

**Step 2: Run test to verify current baseline**

Run same command and confirm build works before changes.

**Step 3: Write minimal implementation**

In `docs/source/conf.py`, add:
- `html_logo` and `html_favicon` only if existing asset files are present; otherwise skip to avoid broken refs.
- `html_css_files = ["custom.css"]`
- `html_theme_options` enhancements:
  - `icon_links` with GitHub repo icon
  - keep `repository_url` and `use_repository_button`
  - keep/adjust `show_toc_level`
- `html_context` entries only if needed by theme templates.

Example target snippet:
```python
html_css_files = ["custom.css"]

html_theme_options = {
    "repository_url": "https://github.com/kaivyy/waton",
    "use_repository_button": True,
    "show_toc_level": 2,
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/kaivyy/waton",
            "icon": "fa-brands fa-github",
            "type": "fontawesome",
        }
    ],
}
```

**Step 4: Run test to verify it passes**

Run:
```bash
python -m sphinx -T -b html -d docs/_build/doctrees docs/source docs/_build/html
```

Expected: PASS, no theme option errors.

**Step 5: Commit**

```bash
git add docs/source/conf.py
git commit -m "docs: add modern theme config and GitHub icon link"
```

---

### Task 2: Rebuild homepage structure into modern developer portal layout

**Files:**
- Modify: `docs/source/index.rst`
- Test: `python -m sphinx -T -b html -d docs/_build/doctrees docs/source docs/_build/html`

**Step 1: Write the failing test**

Make a small intentional structural change draft in `index.rst` and build; use Sphinx warnings/errors as feedback loop.

Run:
```bash
python -m sphinx -T -b html -d docs/_build/doctrees docs/source docs/_build/html
```

Expected: likely WARN/FAIL if directives malformed.

**Step 2: Run test to verify it fails**

If it does not fail, continue and use strict mode after edits:
```bash
python -m sphinx -W -T -b html -d docs/_build/doctrees docs/source docs/_build/html
```

**Step 3: Write minimal implementation**

Replace `index.rst` top section with:
- Strong title + tagline
- Intro paragraph with value proposition
- Quick links section using `.. grid::`/cards only if extension supports it; if not, use clean `.. list-table::` or bullet groups to avoid adding new extensions.
- Preserve existing toctree groups and page order (Start Here, Core Concepts, How-to Guides, Reference, Support & Operations).

Keep toctree directives valid and avoid changing doc file paths.

**Step 4: Run test to verify it passes**

Run:
```bash
python -m sphinx -W -T -b html -d docs/_build/doctrees docs/source docs/_build/html
```

Expected: PASS with zero warnings.

**Step 5: Commit**

```bash
git add docs/source/index.rst
git commit -m "docs: redesign homepage content for modern developer UX"
```

---

### Task 3: Add bold dark visual system CSS (non-breaking, theme-compatible)

**Files:**
- Create: `docs/source/_static/custom.css`
- Test: `python -m sphinx -T -b html -d docs/_build/doctrees docs/source docs/_build/html`

**Step 1: Write the failing test**

Create empty CSS file reference (from Task 1 already configured) and build.

Run:
```bash
python -m sphinx -T -b html -d docs/_build/doctrees docs/source docs/_build/html
```

Expected: PASS baseline.

**Step 2: Run test to verify baseline**

Confirm docs build succeeds before large style additions.

**Step 3: Write minimal implementation**

Add CSS focusing on:
- Dark background layers and readable typography
- Enhanced code blocks (`pre`, `code`, copy buttons if present)
- Hero/title styling on landing page
- Card-like styling for section blocks
- Link, nav, and hover states with one accent color
- Keep selectors scoped to avoid breaking theme internals.

Starter structure:
```css
:root {
  --waton-bg: #0b1020;
  --waton-bg-elev: #121a2f;
  --waton-text: #e6ebff;
  --waton-muted: #9aa7c7;
  --waton-accent: #4da3ff;
}

html[data-theme="light"] {
  --waton-bg: #0b1020;
  --waton-bg-elev: #121a2f;
  --waton-text: #e6ebff;
}

html, body {
  background: var(--waton-bg);
  color: var(--waton-text);
}

.bd-main .bd-content .bd-article-container {
  max-width: 78rem;
}

a {
  color: var(--waton-accent);
}

pre, .highlight pre {
  border-radius: 12px;
  border: 1px solid #253252;
  background: #0f162b;
}
```

**Step 4: Run test to verify it passes**

Run:
```bash
python -m sphinx -W -T -b html -d docs/_build/doctrees docs/source docs/_build/html
```

Expected: PASS and generated HTML references `_static/custom.css`.

**Step 5: Commit**

```bash
git add docs/source/_static/custom.css
git commit -m "docs: apply bold dark custom stylesheet"
```

---

### Task 4: Verification and regression checks (RTD-safe)

**Files:**
- Verify: `docs/source/conf.py`, `docs/source/index.rst`, `docs/source/_static/custom.css`
- Verify config context: `.readthedocs.yaml`

**Step 1: Write the failing test**

Use strict docs build to catch warnings as failures.

Run:
```bash
python -m sphinx -W -T -b html -d docs/_build/doctrees docs/source docs/_build/html
```

Expected: PASS required; any warning means task fails.

**Step 2: Run test to verify output quality**

Run:
```bash
python -m sphinx -b dirhtml -d docs/_build/doctrees-dirhtml docs/source docs/_build/dirhtml
```

Expected: PASS and no missing static assets.

**Step 3: Run docs dependency install check**

Run:
```bash
python -m pip install ".[docs]"
python -c "import myst_parser, sphinx, sphinx_book_theme; print('ok')"
```

Expected: PASS, no missing module errors.

**Step 4: Commit final polish**

```bash
git add docs/source/conf.py docs/source/index.rst docs/source/_static/custom.css
git commit -m "docs: finalize modern dark rebrand and validate RTD compatibility"
```

---

### Task 5: Final review checklist

**Files:**
- Review: rendered docs in `docs/_build/html/index.html`

**Step 1: Verify requirements mapping**
- GitHub icon visible in header/nav
- Dark modern look applied globally
- Homepage no longer rigid/plain
- Existing docs navigation still complete

**Step 2: Verify no scope creep**
- No runtime Python package behavior changed
- No protocol/client code changed

**Step 3: Final command**

```bash
git status
```

Expected: clean working tree (or only unrelated pre-existing changes intentionally left out).
