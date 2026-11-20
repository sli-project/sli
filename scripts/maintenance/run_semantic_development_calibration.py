#!/usr/bin/env python3
"""Generate deterministic, payload-free development calibration evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.semantic.semantic_development_calibration import (  # noqa: E402
    assert_development_only,
    evaluate_development_fixture,
)


FIXTURE_VERDICTS = (
    "confirmed_security", "confirmed_security", "confirmed_security",
    "confirmed_security", "confirmed_security", "confirmed_security",
    "confirmed_security", "confirmed_security", "false_positive",
    "false_positive", "benign_expected", "insufficient_evidence",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the isolated development calibration fixture.")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "semantic_development_calibration.json")
    args = parser.parse_args()
    calibration = evaluate_development_fixture(FIXTURE_VERDICTS)
    assert_development_only(calibration)
    payload = {
        "package_type": "SEMANTIC_DEVELOPMENT_CALIBRATION",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "accepted" if calibration["development_contract_ready"] else "failed",
        "scope": "offline_payload_free_development_fixture",
        "runtime_rows_written": 0,
        "surveyed_servers_contacted": 0,
        "calibration": calibration,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["status"] == "accepted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
