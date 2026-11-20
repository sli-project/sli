#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.sli.reporting.html_audit import DEFAULT_BASE_URL, run_html_audit  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory and safely measure all registered HTML surfaces.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--timeout-seconds", type=int, default=20)
    parser.add_argument("--browser", choices=["off", "auto", "required"], default="auto")
    parser.add_argument("--allow-non-loopback", action="store_true")
    parser.add_argument("--capture-html-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_html_audit(
        base_url=args.base_url,
        timeout_seconds=max(1, args.timeout_seconds),
        browser_mode=args.browser,
        allow_non_loopback=args.allow_non_loopback,
        capture_html_dir=args.capture_html_dir,
    )
    text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    if args.json or not args.output:
        print(text)
    return 1 if result.get("status") == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
