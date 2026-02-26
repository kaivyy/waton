# pywa

`pywa` is a standalone Python WhatsApp Web Multi-Device library.

Design goal:
- Python-first API for users
- Rust only as internal crypto/performance helper
- Not a Baileys wrapper and no Node.js runtime dependency

## Installation

For normal users (recommended):

```bash
pip install pywa
```

When installed from a prebuilt wheel, users do **not** need to install Rust.

For contributors building from source:

```bash
pip install -e .[dev]
maturin develop
```

Source builds require Rust toolchain because the internal `_crypto` extension is compiled locally.

## Quick Live Connect

```bash
python -u examples/live_connect.py
```

With test message:

```bash
set PYWA_AUTH_DB=pywa_live.db
set PYWA_TEST_JID=628xxxxxxxxx@s.whatsapp.net
set PYWA_TEST_TEXT=test from pywa
python -u examples/live_connect.py
```

## Number Requirement

- 1 WhatsApp number is enough for pairing/login
- 2 numbers are recommended to validate send/receive messaging end-to-end

## PyWA vs Baileys Comparison

| Aspect | PyWA (Python) | Baileys (Node.js) |
|--------|---------------|-------------------|
| **Runtime** | Python (~30-50MB) | Node.js (~50-100MB) |
| **Package Size** | ~500KB + deps | ~2MB + node_modules |
| **Crypto Engine** | Rust native (pyo3) | JS/WASM |
| **Memory Usage** | ~30-60MB | ~80-150MB |
| **Startup Time** | Faster | Slower (JIT) |
| **Encryption Speed** | Faster (native) | Slower (WASM) |
| **Maturity** | New | Mature |
| **Community** | Growing | Large |

### When to use PyWA

- Resource-constrained environments (VPS, Raspberry Pi)
- Python-based projects
- Performance-critical applications
- Minimal dependency footprint

### When to use Baileys

- Existing Node.js ecosystem
- Need battle-tested stability
- Require extensive community support

