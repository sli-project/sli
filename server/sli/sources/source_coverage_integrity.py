"""Bounded source-coverage integrity from local collector metadata only.

The reader never contacts a domain controller and never scans event payloads.
It distinguishes observed collection health from what cannot be proven from
cursor/run metadata alone; in particular, zero detected rollback is not stated
as proof that the remote log contains no gap.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from server.sli.core.database import is_postgres_runtime_db, query_rows_bounded
from server.sli.reporting.reporting_common import parse_utc

_utc = parse_utc


def classify_channel_integrity(
    row: dict[str, Any], *, now: datetime,
    attention_minutes: int = 30, unavailable_minutes: int = 120,
) -> dict[str, Any]:
    """Classify one persisted channel state without inferring remote safety."""
    successful = _utc(row.get("last_successful_collection_utc"))
    age_minutes = None
    if successful is not None:
        age_minutes = max(0, int((now.astimezone(timezone.utc) - successful).total_seconds() // 60))
    last_status = str(row.get("last_status") or "not_observed")
    if successful is None or age_minutes is None or age_minutes >= unavailable_minutes:
        status, reason = "unavailable", "successful_collection_not_recent"
    elif not bool(row.get("backfill_completed")):
        status, reason = "partial", "backfill_not_completed"
    elif last_status in {"failed", "error", "timeout", "partial_timeout"}:
        status, reason = "partial", f"latest_run_{last_status}"
    elif age_minutes >= attention_minutes:
        status, reason = "partial", "successful_collection_outside_attention_budget"
    else:
        status, reason = "complete", "successful_collection_inside_attention_budget"
    return {
        "server": str(row.get("server_hostname") or ""),
        "channel": str(row.get("channel") or ""),
        "status": status,
        "reason": reason,
        "last_status": last_status,
        "collection_age_minutes": age_minutes,
        "backfill_completed": bool(row.get("backfill_completed")),
    }


def get_source_coverage_integrity(
    *, window_hours: int = 24, now: datetime | None = None,
) -> dict[str, Any]:
    """Return a bounded integrity summary over local state/run/audit tables."""
    if not is_postgres_runtime_db():
        raise RuntimeError("source_coverage_integrity_requires_postgres")
    clean_window = max(1, min(int(window_hours or 24), 168))
    generated = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    state_rows = query_rows_bounded(
        """
        with latest as (
            select distinct on (server,channel) server,channel,status
            from collector_channel_runs
            order by server,channel,created_at desc,id desc
        )
        select c.server_hostname,c.channel,c.last_successful_collection_utc,
               c.backfill_completed,l.status as last_status
        from collection_channel_state c
        left join latest l on l.server=c.server_hostname and l.channel=c.channel
        order by c.server_hostname,c.channel
        limit 100
        """,
        statement_timeout_ms=3000,
    )
    run_rows = query_rows_bounded(
        """
        select count(*) as runs,
               count(*) filter (where status in ('failed','error','timeout','partial_timeout')) as noncomplete_runs,
               coalesce(sum(inserted),0) as inserted,
               coalesce(sum(skipped),0) as skipped
        from collector_channel_runs
        where created_at >= now() - (? * interval '1 hour')
        """,
        (clean_window,), statement_timeout_ms=3000,
    )
    audit_rows = query_rows_bounded(
        """
        select count(*) as audits,
               count(*) filter (where decision='rejected' and reason='record_id_rollback_detected') as rejected_rollbacks,
               count(*) filter (
                   where decision='rejected' and reason='record_id_rollback_detected'
                     and collection_status='completed'
                     and import_inserted=0 and import_skipped=0
                     and new_record_id=old_record_id
               ) as stale_empty_proposals,
               count(*) filter (
                   where decision='rejected' and reason='record_id_rollback_detected'
                     and not (
                         collection_status='completed'
                         and import_inserted=0 and import_skipped=0
                         and new_record_id=old_record_id
                     )
               ) as actionable_rollbacks,
               count(*) filter (where decision='no_change') as no_change,
               count(*) filter (where decision='committed') as committed
        from collector_cursor_audit
        where created_at >= now() - (? * interval '1 hour')
        """,
        (clean_window,), statement_timeout_ms=3000,
    )
    items = [classify_channel_integrity(dict(row), now=generated) for row in state_rows]
    by_status: dict[str, int] = {}
    for item in items:
        by_status[item["status"]] = by_status.get(item["status"], 0) + 1
    runs = dict(run_rows[0]) if run_rows else {}
    audits = dict(audit_rows[0]) if audit_rows else {}
    inserted = int(runs.get("inserted") or 0)
    skipped = int(runs.get("skipped") or 0)
    rollback_count = int(audits.get("rejected_rollbacks") or 0)
    stale_empty = int(audits.get("stale_empty_proposals") or 0)
    actionable_rollbacks = int(audits.get("actionable_rollbacks") or 0)
    return {
        "state": "attention_required" if by_status.get("unavailable") or actionable_rollbacks else
                 "partial" if by_status.get("partial") else "observed_complete",
        "window_hours": clean_window,
        "channels": {"total": len(items), "by_status": by_status, "items": items},
        "cursor_integrity": {
            "audits": int(audits.get("audits") or 0),
            "committed": int(audits.get("committed") or 0),
            "no_change": int(audits.get("no_change") or 0),
            "rejected_rollbacks": rollback_count,
            "stale_empty_proposals": stale_empty,
            "actionable_rollbacks": actionable_rollbacks,
            "reset_or_rollover_classification": "unclassified" if actionable_rollbacks else "not_observed",
        },
        "run_integrity": {
            "runs": int(runs.get("runs") or 0),
            "noncomplete_runs": int(runs.get("noncomplete_runs") or 0),
            "inserted": inserted,
            "replay_skipped": skipped,
            "replay_skip_percent": round(100.0 * skipped / max(1, inserted + skipped), 4),
        },
        "gap_detection": {
            "state": "uncertain" if actionable_rollbacks else "bounded_metadata_only",
            "remote_sequence_scan_performed": False,
            "reason": "actionable cursor rollback requires reset/rollover investigation" if actionable_rollbacks else
                      "local metadata shows no actionable rollback but cannot prove remote record continuity",
        },
        "surveyed_servers_contacted": False,
        "payload_read": False,
    }
