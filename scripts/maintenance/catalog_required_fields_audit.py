#!/usr/bin/env python3
"""Read-only audit of catalogue required_fields against the real Storage V2 corpus."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from psycopg import sql

from scripts.maintenance.stage7_control_benchmark import _connect
from server.sli.events.event_catalog import all_event_catalog_entries
from server.sli.storage.storage_v2_repository import (
    EVENT_FACTS_V2_WRITE_COLUMNS,
    EVENT_V2_WRITE_COLUMNS,
)


def audit_catalog_required_fields() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "begin transaction isolation level repeatable read read only"
            )
            cur.execute(
                "select current_setting('transaction_read_only')::boolean "
                "as read_only"
            )
            session = cur.fetchone()
            if session["read_only"] is not True:
                raise RuntimeError("catalog_required_fields_audit_not_read_only")

            for entry in all_event_catalog_entries():
                fields = tuple(str(field) for field in entry["required_fields"])
                if any(
                    field not in EVENT_V2_WRITE_COLUMNS
                    and field not in EVENT_FACTS_V2_WRITE_COLUMNS
                    for field in fields
                ):
                    raise RuntimeError("catalog_required_field_not_in_storage_v2")
                cur.execute(
                    _aggregate_query(fields),
                    (entry["stream"], int(entry["event_id"])),
                )
                aggregate = dict(cur.fetchone())
                total = int(aggregate.pop("total"))
                rows.append(
                    {
                        "stream": entry["stream"],
                        "event_key": entry["event_key"],
                        "total": total,
                        "missing": {
                            field: int(count)
                            for field, count in aggregate.items()
                            if int(count) > 0
                        },
                    }
                )
            conn.rollback()

    observed = [row for row in rows if row["total"] > 0]
    gaps = [row for row in observed if row["missing"]]
    return {
        "status": "gaps_found" if gaps else "ok",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "transaction_read_only": True,
        "catalog_entries": len(rows),
        "observed_entries": len(observed),
        "unobserved_entries": len(rows) - len(observed),
        "entries_with_missing_required_values": len(gaps),
        "rows": rows,
        "production_postgresql_mutated": False,
    }


def _aggregate_query(fields: tuple[str, ...]) -> sql.Composed:
    return sql.SQL(
        """
        select count(*) as total, {missing}
        from events_v2_core e
        join storage_v2_channel c on c.id=e.channel_id
        left join event_facts_v2 f on f.event_id=e.id
        where c.value=%s and e.event_id=%s
        """
    ).format(
        missing=sql.SQL(", ").join(
            _missing_expression(field)
            + sql.SQL(" as ")
            + sql.Identifier(field)
            for field in fields
        )
    )


def _missing_expression(field: str) -> sql.Composed:
    alias = "e" if field in EVENT_V2_WRITE_COLUMNS else "f"
    return sql.SQL(
        "count(*) filter (where nullif(btrim({alias}.{field}::text),'') is null)"
    ).format(alias=sql.Identifier(alias), field=sql.Identifier(field))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()

    result = audit_catalog_required_fields()
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.result:
        result_path = args.result.resolve()
        if ROOT not in result_path.parents:
            raise SystemExit("result_path_must_be_inside_project")
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(rendered, encoding="utf-8")
    if args.json:
        print(rendered, end="")
    else:
        print(
            "catalog required-fields audit: "
            f"{result['status']}; observed={result['observed_entries']}; "
            f"unobserved={result['unobserved_entries']}; "
            f"gaps={result['entries_with_missing_required_values']}"
        )
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
