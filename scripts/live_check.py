"""One-command live reliability check runner.

Usage examples (PowerShell):
  python scripts/live_check.py --auth-db waton_live.db
  python scripts/live_check.py --auth-db waton_live.db --test-jid 62812xxxx@s.whatsapp.net --test-text "hello"

Environment fallbacks:
  WATON_AUTH_DB
  WATON_TEST_JID
  WATON_TEST_TEXT
  WATON_LIVE_TIMEOUT
  WATON_LIVE_CLOSE_TIMEOUT
  WATON_ACK_TIMEOUT
  WATON_LIVE_RECONNECT_DELAY
  WATON_LIVE_RECONNECT
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from waton.utils.live_check import LiveCheckConfig, LiveCheckError, config_from_env, format_report, run_live_check


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Waton live reliability check.")
    parser.add_argument("--auth-db", help="SQLite auth DB path")
    parser.add_argument("--test-jid", help="Optional target JID for send+ack verification")
    parser.add_argument("--test-text", help="Message text used for send+ack verification")
    parser.add_argument("--timeout", type=float, help="Open/reconnect timeout seconds")
    parser.add_argument("--close-timeout", type=float, help="Close timeout seconds")
    parser.add_argument("--ack-timeout", type=float, help="Ack timeout seconds")
    parser.add_argument("--reconnect-delay", type=float, help="Delay before reconnect (seconds)")
    parser.add_argument("--no-reconnect", action="store_true", help="Skip reconnect phase")
    return parser


def _merge_config(defaults: LiveCheckConfig, args: argparse.Namespace) -> LiveCheckConfig:
    return LiveCheckConfig(
        auth_db=args.auth_db or defaults.auth_db,
        test_jid=args.test_jid if args.test_jid is not None else defaults.test_jid,
        test_text=args.test_text or defaults.test_text,
        timeout_s=float(args.timeout) if args.timeout is not None else defaults.timeout_s,
        close_timeout_s=float(args.close_timeout) if args.close_timeout is not None else defaults.close_timeout_s,
        ack_timeout_s=float(args.ack_timeout) if args.ack_timeout is not None else defaults.ack_timeout_s,
        reconnect_delay_s=float(args.reconnect_delay)
        if args.reconnect_delay is not None
        else defaults.reconnect_delay_s,
        require_reconnect=False if args.no_reconnect else defaults.require_reconnect,
    )


async def _main_async() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    defaults = config_from_env()
    config = _merge_config(defaults, args)

    print("[live-check] starting")
    print(
        f"[live-check] auth_db={config.auth_db} "
        f"test_jid={config.test_jid} reconnect={config.require_reconnect}"
    )

    try:
        report = await run_live_check(config)
    except LiveCheckError as exc:
        print(f"[live-check] FAILED: {exc}")
        return 1
    except Exception as exc:
        print(f"[live-check] ERROR: {exc}")
        return 1

    print("[live-check] PASSED")
    print(format_report(report))
    return 0


def main() -> int:
    with contextlib.suppress(KeyboardInterrupt):
        return asyncio.run(_main_async())
    return 130


if __name__ == "__main__":
    raise SystemExit(main())
