from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING

from waton.defaults import DEFAULT_CONNECTION_CONFIG

if TYPE_CHECKING:
    from collections.abc import Sequence


VersionTuple = tuple[int, int, int]


def _coerce_version(value: object, *, field_name: str) -> VersionTuple:
    if not isinstance(value, (list, tuple)) or len(value) != 3:
        raise ValueError(f"{field_name} must contain exactly three version components")

    components: list[int] = []
    for component in value:
        if isinstance(component, bool) or not isinstance(component, int):
            raise ValueError(f"{field_name} components must be integers")
        components.append(component)
    return (components[0], components[1], components[2])


def _find_baileys_version_file(baileys_path: Path) -> Path:
    candidates = [
        baileys_path / "Defaults" / "baileys-version.json",
        baileys_path / "src" / "Defaults" / "baileys-version.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "Could not find Baileys version file. Expected Defaults/baileys-version.json "
        "under either a Baileys src directory or repository root."
    )


def read_baileys_version(baileys_path: str | Path) -> VersionTuple:
    version_path = _find_baileys_version_file(Path(baileys_path))
    payload = json.loads(version_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Baileys version file must contain a JSON object")
    return _coerce_version(payload.get("version"), field_name="Baileys version")


def build_version_report(
    *,
    baileys_path: str | Path,
    waton_version: Sequence[int] | None = None,
) -> dict[str, object]:
    waton_tuple = _coerce_version(
        tuple(DEFAULT_CONNECTION_CONFIG["version"])
        if waton_version is None
        else tuple(waton_version),
        field_name="Waton version",
    )
    baileys_tuple = read_baileys_version(baileys_path)

    labels = ("primary", "secondary", "tertiary")
    components = {
        label: {
            "waton": waton_tuple[index],
            "baileys": baileys_tuple[index],
            "matches": waton_tuple[index] == baileys_tuple[index],
        }
        for index, label in enumerate(labels)
    }

    return {
        "status": "match" if waton_tuple == baileys_tuple else "drift",
        "waton_version": list(waton_tuple),
        "baileys_version": list(baileys_tuple),
        "components": components,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Report WhatsApp Web version drift between Waton and Baileys.")
    parser.add_argument("--baileys", required=True, help="Path to Baileys repo root or src directory")
    parser.add_argument("--out", help="Optional output JSON path")
    args = parser.parse_args()

    report = build_version_report(baileys_path=args.baileys)
    payload = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)


if __name__ == "__main__":
    main()
