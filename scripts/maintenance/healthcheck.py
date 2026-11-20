from __future__ import annotations

import argparse
import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops.system_health import get_system_health


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local project healthcheck.")
    parser.parse_args()
    result = get_system_health()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("status") in {"ok", "warn"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
