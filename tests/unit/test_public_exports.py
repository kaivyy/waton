from pathlib import Path

import waton


def test_public_exports_exist() -> None:
    for name in waton.__all__:
        assert hasattr(waton, name), name


def test_stable_release_version_metadata_is_aligned() -> None:
    root = Path(__file__).resolve().parents[2]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    cargo = (root / "Cargo.toml").read_text(encoding="utf-8")

    assert waton.__version__ == "0.1.4"
    assert 'version = "0.1.4"' in pyproject
    assert 'version = "0.1.4"' in cargo
