from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.events.event_catalog_quality import validate_catalog_data


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate event catalog without reading event payloads.")
    parser.add_argument("--catalog", type=Path, default=ROOT / "config" / "event_catalog.json")
    args = parser.parse_args()
    data = json.loads(args.catalog.read_text(encoding="utf-8"))
    result = validate_catalog_data(data)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
