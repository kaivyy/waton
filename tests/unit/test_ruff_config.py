from pathlib import Path


def test_ruff_config_does_not_ignore_removed_ann_rules() -> None:
    text = Path("ruff.toml").read_text(encoding="utf-8")
    assert "ANN101" not in text
    assert "ANN102" not in text


def test_ruff_config_has_test_per_file_ann_suppression() -> None:
    text = Path("ruff.toml").read_text(encoding="utf-8")
    assert '"tests/**/*.py"' in text
    assert '"tests/**/*.py" = ["ANN"]' in text


def test_ruff_config_global_ignore_is_limited() -> None:
    text = Path("ruff.toml").read_text(encoding="utf-8")
    assert 'ignore = ["ANN401"]' in text
    assert 'ignore = ["ANN"]' not in text
    assert 'ignore = ["*"]' not in text
