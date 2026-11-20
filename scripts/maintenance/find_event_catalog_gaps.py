from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.events.event_catalog import all_event_catalog_entries, catalog_has_rule
from server.sli.events.event_catalog_quality import coverage_summary
from server.sli.core.database import is_postgres_runtime_db, query_rows_bounded


def main() -> int:
    parser = argparse.ArgumentParser(description="Find channel/Event ID/provider tuples missing from config/event_catalog.json.")
    parser.add_argument("--min-count", type=int, default=1, help="Only show gaps with at least this number of events.")
    parser.add_argument("--limit", type=int, default=500, help="Maximum aggregate tuples to inspect (1..2000).")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format.")
    parser.add_argument("--output", type=Path, help="Optional file for the output.")
    args = parser.parse_args()

    requested_limit = max(1, min(int(args.limit), 2000))
    loaded_rows = _load_event_groups(args.min_count, requested_limit + 1)
    truncated = len(loaded_rows) > requested_limit
    rows = loaded_rows[:requested_limit]
    gaps = [
        row
        for row in rows
        if not catalog_has_rule(row["event_id"], row.get("channel"), row.get("provider_name"))
    ]
    coverage = coverage_summary(rows, catalog_entries=all_event_catalog_entries())

    if args.format == "json":
        output = json.dumps({
            "source": "postgres_storage_v2",
            "contains_event_payload": False,
            "groups_inspected": len(rows),
            "truncated": truncated,
            "coverage_complete": not truncated,
            "gap_count": len(gaps),
            "gaps": gaps,
            "coverage": coverage,
        }, ensure_ascii=False, indent=2)
    else:
        output = _format_text(gaps, truncated=truncated)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 2 if gaps else 0


def _load_event_groups(min_count: int, limit: int = 500) -> list[dict]:
    """Read bounded Storage V2 aggregate identities; never export event payload."""
    if not is_postgres_runtime_db():
        raise RuntimeError("event catalog gap report requires the configured PostgreSQL runtime")
    clean_limit = max(1, min(int(limit), 2001))
    rows = query_rows_bounded(
        """
            select
                channel.value as channel,
                e.event_id,
                coalesce(provider.value, '') as provider_name,
                count(*) as count,
                min(e.time_created_utc) as first_seen,
                max(e.time_created_utc) as last_seen
            from events_v2_core e
            join storage_v2_channel channel on channel.id = e.channel_id
            left join storage_v2_provider provider on provider.id = e.provider_id
            group by channel.value, e.event_id, provider.value
            having count(*) >= ?
            order by count(*) desc, channel.value, e.event_id, provider_name
            limit ?
        """,
        (max(1, int(min_count)), clean_limit),
        statement_timeout_ms=8000,
        wall_timeout_ms=9500,
    )
    return [_normalize_aggregate_row(row) for row in rows]


def _normalize_aggregate_row(row: dict) -> dict:
    normalized = dict(row)
    for field in ("first_seen", "last_seen"):
        value = normalized.get(field)
        if isinstance(value, (datetime, date)):
            normalized[field] = value.isoformat()
    return normalized


def _format_text(gaps: list[dict], *, truncated: bool = False) -> str:
    if not gaps:
        suffix = " Выборка усечена: полное покрытие не доказано." if truncated else ""
        return "OK: в проверенном bounded-наборе пробелов каталога не найдено." + suffix
    lines = [f"Найдено пропущенных правил: {len(gaps)}", "count | channel | event_id | provider | first_seen | last_seen"]
    for row in gaps:
        lines.append(
            f"{row['count']} | {row['channel']} | {row['event_id']} | {row['provider_name']} | {row['first_seen']} | {row['last_seen']}"
        )
    if truncated:
        lines.append("ВНИМАНИЕ: выборка усечена; результат не доказывает полное покрытие.")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
