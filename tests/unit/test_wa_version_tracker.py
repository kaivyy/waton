from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.parity.wa_version_tracker import build_version_report, read_baileys_version

if TYPE_CHECKING:
    from pathlib import Path


def test_read_baileys_version_accepts_repo_root(tmp_path: Path) -> None:
    defaults = tmp_path / "src" / "Defaults"
    defaults.mkdir(parents=True)
    (defaults / "baileys-version.json").write_text(
        json.dumps({"version": [2, 3000, 1035194821]}),
        encoding="utf-8",
    )

    assert read_baileys_version(tmp_path) == (2, 3000, 1035194821)


def test_build_version_report_marks_drift(tmp_path: Path) -> None:
    defaults = tmp_path / "Defaults"
    defaults.mkdir()
    (defaults / "baileys-version.json").write_text(
        json.dumps({"version": [2, 3000, 1035194821]}),
        encoding="utf-8",
    )

    report = build_version_report(
        waton_version=(2, 3000, 1033846690),
        baileys_path=tmp_path,
    )

    assert report["status"] == "drift"
    assert report["waton_version"] == [2, 3000, 1033846690]
    assert report["baileys_version"] == [2, 3000, 1035194821]
    assert report["components"]["tertiary"]["matches"] is False
