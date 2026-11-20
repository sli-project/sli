"""Read-only resolution of immutable quarantine records for Operations."""

from typing import Any

from server.sli.semantic.semantic_investigation_backfill import (
    classify_security_history_v2_repair_row,
    read_security_history_v2_repair_rows,
)
from server.sli.semantic.semantic_processing import SEMANTIC_CONTRACT_VERSION
from server.sli.semantic.semantic_processing_repository import PROCESSOR_ID, PROCESSOR_VERSION


def repaired_quarantine_counts(cur: Any) -> tuple[int, int]:
    # Bound the extra work per Operations request. Any excess remains visible
    # as quarantine; this path never admits processing or mutates job history.
    cur.execute(
        """
        select distinct source_event_id,
               source_identity_json->>'normalized_hash' as source_hash
        from semantic_processing_outbox
        where status='quarantined' and job_kind='normalize_event'
          and semantic_contract_version=%s and processor_id=%s and processor_version=%s
          and source_identity_json->>'normalized_hash' ~ '^[0-9a-f]{64}$'
        order by source_event_id,source_hash limit 1024
        """,
        (SEMANTIC_CONTRACT_VERSION, PROCESSOR_ID, PROCESSOR_VERSION),
    )
    pairs = [(int(row["source_event_id"]), str(row["source_hash"])) for row in cur.fetchall()]
    expected = dict(pairs)
    if len(expected) != len(pairs):
        return 0, 0
    rows = read_security_history_v2_repair_rows(cur, pairs)
    if len(rows) != len(pairs) or {row["source_event_id"] for row in rows} != set(expected):
        return 0, 0
    depth = retries = 0
    for row in rows:
        history_digest = str(row.get("repair_history_plan_digest") or "")
        if len(history_digest) != 64 or any(c not in "0123456789abcdef" for c in history_digest):
            continue
        try:
            state = classify_security_history_v2_repair_row(
                row, source_hash=expected[row["source_event_id"]],
                history_plan_digest=history_digest,
            )
        except (TypeError, ValueError):
            continue  # Malformed lineage must remain an unresolved quarantine.
        if state == "completed" and row.get("source_hash") == expected[row["source_event_id"]]:
            depth += 1
            retries += max(0, int(row["original_attempt_count"]) - 1)
    return depth, retries
