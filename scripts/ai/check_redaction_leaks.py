from __future__ import annotations

import argparse
import json
from pathlib import Path

from server.sli.access.redaction_leak_check import load_and_check


def main() -> int:
    parser = argparse.ArgumentParser(description="Check AI payload/prompt artifacts for possible sensitive data leaks.")
    parser.add_argument("path", type=Path)
    parser.add_argument("--redaction-level", default="strict", choices=["strict", "balanced", "off"])
    args = parser.parse_args()
    result = load_and_check(args.path, redaction_level=args.redaction_level)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if result.get("blocked") else 0


if __name__ == "__main__":
    raise SystemExit(main())
