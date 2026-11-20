"""Evaluate one explicitly bound server file scope; never activate it or send messages."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.semantic.file_decoy import FileDecoyRule  # noqa: E402
from server.sli.semantic.file_decoy_runtime import run_once  # noqa: E402
from server.sli.semantic.semantic_worker_connection import connect_semantic_worker  # noqa: E402
from server.sli.storage.evidence_ref import EvidenceScope  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule-file", required=True)
    parser.add_argument("--processing-mode", choices=("live", "historical_replay", "history_import"),
                        help="Explicit provenance; historical replay/import records suppression without dispatch.")
    args = parser.parse_args()
    try:
        path = Path(args.rule_file)
        if path.stat().st_size > 131072:
            raise ValueError("file_decoy_rule_invalid")
        document = json.loads(path.read_text(encoding="utf-8"))
        if args.processing_mode:
            document["processing_mode"] = args.processing_mode
        rule = FileDecoyRule(**(document | {"scope": EvidenceScope(**document["scope"])}))
        with connect_semantic_worker() as conn, conn.cursor() as cur:
            result = run_once(cur, rule=rule, now=datetime.now(timezone.utc))
            conn.commit()
    except Exception:
        print(json.dumps({"state": "failed", "code": "file_decoy_unavailable"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
