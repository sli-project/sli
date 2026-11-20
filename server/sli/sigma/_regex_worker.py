"""Private one-shot regex evaluator. Output contains no input or diagnostics."""
from __future__ import annotations

import json
import re
import resource
import sys


def main():
    try:
        # Parent enforces wall time and kills/reaps the child. Bound allocation
        # during both compilation and search; no third-party engine dependency.
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        pattern, text = json.loads(sys.stdin.read(8 * 1024 * 1024))
        result = re.search(pattern, text) is not None
    except Exception:
        return 1
    sys.stdout.write("1" if result else "0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
