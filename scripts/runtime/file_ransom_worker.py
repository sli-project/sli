"""Evaluate one approved file scope; run periodically with a metadata-only rule file.

The source policy, native evidence binding and semantic policy admission must
already exist. This command never activates sources or configures transports.

The local administrator may add at most 100 exclusions to the rule file. Each
requires subject_sid, the rule's collection_scope_id, reason, approved_by and
UTC active_from/active_to (at most 31 days). Only fully covered event windows
are suppressed; retained file evidence and the replay checkpoint are unchanged.
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

from server.sli.semantic.file_ransom import RansomExclusion, RansomRule  # noqa: E402
from server.sli.semantic.file_ransom_runtime import run_once  # noqa: E402
from server.sli.semantic.semantic_worker_connection import connect_semantic_worker  # noqa: E402
from server.sli.storage.evidence_ref import EvidenceScope  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule-file", required=True)
    args = parser.parse_args()
    try:
        path = Path(args.rule_file)
        if path.stat().st_size > 131072:
            raise ValueError("file_ransom_rule_invalid")
        document = json.loads(path.read_text(encoding="utf-8"))
        rule = RansomRule(**(document | {"scope": EvidenceScope(**document["scope"]),
            "exclusions": tuple(RansomExclusion(**item) for item in document.get("exclusions", []))}))
        with connect_semantic_worker() as conn, conn.cursor() as cur:
            result = run_once(cur, rule=rule, now=datetime.now(timezone.utc))
            conn.commit()
    except Exception:
        print(json.dumps({"state": "failed", "code": "file_ransom_unavailable"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
