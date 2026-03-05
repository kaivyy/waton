# Security Hardening (No-CVE Gate) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enforce strict security defaults across dashboard/runtime/network paths and add CI vulnerability gates so releases fail on known vulnerabilities and high-risk unsafe behavior.

**Architecture:** Apply defense-in-depth at the boundary where untrusted input enters the system: dashboard HTTP API, media URL fetch, and media cache persistence. Keep runtime parity behavior while introducing explicit secure defaults (API token + local-only), strict path/url validation, and CI dependency vulnerability scanning to prevent known CVEs from shipping.

**Tech Stack:** Flask, Python stdlib (`ipaddress`, `urllib.parse`, `pathlib`, `re`), httpx, pytest, GitHub Actions, pip-audit.

---

### Task 1: Enforce dashboard API auth + local-only policy

**Files:**
- Modify: `tools/dashboard/server.py`
- Test: `tests/unit/test_dashboard.py`

**Step 1: Write failing tests for auth/local policy**

Add tests for:
- Missing/invalid API token returns `401` for `/api/*`.
- Loopback request with valid token returns existing behavior.
- Non-loopback request returns `403` unless explicit remote override env is enabled.

```python
def test_dashboard_api_requires_bearer_token(dashboard_client):
    res = dashboard_client.get("/api/health")
    assert res.status_code == 401


def test_dashboard_api_allows_with_valid_token(dashboard_client):
    res = dashboard_client.get("/api/health", headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 200
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_dashboard.py::test_dashboard_api_requires_bearer_token -v`
Expected: FAIL (current implementation has no auth).

**Step 3: Implement minimal policy middleware**

In `create_app()`:
- Read env:
  - `WATON_DASHBOARD_API_TOKEN` (required by default)
  - `WATON_DASHBOARD_ALLOW_REMOTE` (default `0`)
- Add `@app.before_request` guard for `/api/`:
  - Validate bearer token.
  - Validate remote address loopback unless override is enabled.

**Step 4: Run tests to verify pass**

Run: `pytest tests/unit/test_dashboard.py -v`
Expected: PASS for new + existing endpoint tests (with updated test client headers fixture).

**Step 5: Commit**

```bash
git add tools/dashboard/server.py tests/unit/test_dashboard.py
git commit -m "fix(security): require dashboard token and local-only API access"
```

---

### Task 2: Prevent media cache path traversal

**Files:**
- Modify: `tools/dashboard/runtime.py`
- Test: `tests/unit/test_dashboard.py`

**Step 1: Write failing tests for media path safety**

Add tests for:
- `_persist_media_blob()` rejects traversal-like `message_id` (`../x`, `a/b`, `..\\x`).
- Valid `message_id` writes only under configured cache dir.

```python
def test_persist_media_blob_rejects_path_traversal(tmp_path):
    # construct runtime with tmp cache dir
    with pytest.raises(ValueError):
        runtime._persist_media_blob("../evil", b"x", mimetype="image/png", file_name="a.png")
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_dashboard.py::test_persist_media_blob_rejects_path_traversal -v`
Expected: FAIL (currently accepts unsanitized message_id).

**Step 3: Implement safe filename strategy**

In `runtime.py`:
- Add helper to sanitize/validate `message_id` allowlist: `[A-Za-z0-9._-]{1,128}`.
- Build path and enforce containment with `resolve()` check:
  - `resolved_target.is_relative_to(resolved_cache_dir)` equivalent logic.
- Raise `ValueError` on invalid input.

**Step 4: Run tests to verify pass**

Run: `pytest tests/unit/test_dashboard.py -v`
Expected: PASS for new traversal tests and existing dashboard tests.

**Step 5: Commit**

```bash
git add tools/dashboard/runtime.py tests/unit/test_dashboard.py
git commit -m "fix(security): block media cache path traversal in dashboard runtime"
```

---

### Task 3: Add SSRF guard for media download URL

**Files:**
- Modify: `waton/client/media.py`
- Test: `tests/unit/test_media_reliability.py`

**Step 1: Write failing tests for URL guard**

Add tests for:
- Reject non-https URL schemes by default.
- Reject loopback/private/link-local hosts.
- Accept normal public https host.

```python
import pytest


def test_media_url_guard_rejects_localhost():
    manager = MediaManager()
    with pytest.raises(ValueError):
        manager._validate_media_url("https://127.0.0.1/file")
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_media_reliability.py::test_media_url_guard_rejects_localhost -v`
Expected: FAIL (no guard exists now).

**Step 3: Implement URL validation**

In `media.py`:
- Add `_validate_media_url(url: str) -> None`:
  - Parse URL via `urllib.parse.urlparse`.
  - Require `https` scheme (optionally configurable).
  - Resolve host and block private/loopback/link-local/reserved via `ipaddress`.
- Call validator before `httpx.get` in `download_and_decrypt`.

**Step 4: Run tests to verify pass**

Run: `pytest tests/unit/test_media_reliability.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add waton/client/media.py tests/unit/test_media_reliability.py
git commit -m "fix(security): add SSRF-safe media URL validation"
```

---

### Task 4: Add CVE dependency gate in CI

**Files:**
- Create: `.github/workflows/security-audit.yml`
- Modify: `pyproject.toml` (if needed for audit tooling compatibility)

**Step 1: Write failing policy test (workflow-level smoke)**

Add/extend CI policy by creating a workflow that:
- installs project deps and `pip-audit`
- runs `pip-audit --strict`
- fails on known vulnerabilities

(No pytest test needed; CI job itself is the gate.)

**Step 2: Run local command to verify current status**

Run: `python -m pip install pip-audit && python -m pip_audit`
Expected: command executes and reports vulnerabilities (or clean) with non-zero on issues using strict mode.

**Step 3: Implement workflow**

Create `security-audit.yml` with:
- trigger: PR + push to `main`
- python `3.11`
- install `.[dev]`
- run `pip-audit --strict`

**Step 4: Validate workflow syntax**

Run: `gh workflow list` and (optionally) `gh workflow view security-audit.yml`
Expected: workflow recognized.

**Step 5: Commit**

```bash
git add .github/workflows/security-audit.yml pyproject.toml
git commit -m "ci(security): add strict dependency CVE audit gate"
```

---

### Task 5: Security docs + operational policy

**Files:**
- Modify: `README.md`
- Modify: `docs/source/content/ai-agent-quickstart.rst`
- Modify: `docs/source/content/readthedocs.rst`
- Modify: `CHANGELOG.md`

**Step 1: Write failing docs assertion (if docs tests exist) or direct update task**

Add explicit security section requiring:
- dashboard token env setup
- localhost-only default
- explicit remote override warning
- CVE gate expectations

**Step 2: Build docs to verify no regressions**

Run: `python -m sphinx -W --keep-going -b html docs/source docs/build/html`
Expected: PASS.

**Step 3: Update docs**

Add concise “Secure deployment baseline” snippets and explicit warnings.

**Step 4: Re-run docs build**

Run same Sphinx command.
Expected: PASS.

**Step 5: Commit**

```bash
git add README.md docs/source/content/ai-agent-quickstart.rst docs/source/content/readthedocs.rst CHANGELOG.md
git commit -m "docs(security): document strict dashboard and CVE gate policy"
```

---

### Task 6: Full verification gate before merge/release

**Files:**
- Modify if needed from prior tasks
- Test: existing suite + targeted new tests

**Step 1: Run targeted security tests**

Run:
- `pytest tests/unit/test_dashboard.py -q`
- `pytest tests/unit/test_media_reliability.py -q`

Expected: PASS.

**Step 2: Run full project tests**

Run: `pytest tests -q`
Expected: PASS (all unit tests + existing skips).

**Step 3: Run lint/type gates**

Run:
- `ruff check waton tests tools`
- `python -m pyright`

Expected: no errors.

**Step 4: Build docs + package smoke**

Run:
- `python -m sphinx -W --keep-going -b html docs/source docs/build/html`
- `python -m build`
- `python -m twine check dist/*`

Expected: PASS.

**Step 5: Final commit (if verification-only changes)**

```bash
git add <any verification-related updates>
git commit -m "chore(security): finalize strict hardening verification"
```
