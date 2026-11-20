"""Evaluate one explicitly configured NPS scope using the semantic worker login.

Run periodically with --rule-file (metadata only). Policies and source bindings
must already be approved through the normal maintenance lifecycle. No automatic
activation, source access, channel configuration or secret input is performed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.semantic.nps_threshold import ThresholdRule  # noqa: E402
from server.sli.semantic.nps_threshold_runtime import run_once  # noqa: E402
from server.sli.semantic.semantic_worker_connection import connect_semantic_worker  # noqa: E402
from server.sli.storage.evidence_ref import EvidenceScope  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule-file", required=True)
    args = parser.parse_args()
    try:
        path = Path(args.rule_file)
        if path.stat().st_size > 8192:
            raise ValueError("nps_threshold_rule_invalid")
        document = json.loads(path.read_text(encoding="utf-8"))
        rule = ThresholdRule(**(document | {"scope": EvidenceScope(**document["scope"])}))
        with connect_semantic_worker() as conn, conn.cursor() as cur:
            result = run_once(cur, rule=rule, now=datetime.now(timezone.utc))
            conn.commit()
    except Exception:
        # Never print database diagnostics, rule-file contents or identities.
        print(json.dumps({"state": "failed", "code": "nps_threshold_unavailable"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
