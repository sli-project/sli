#!/usr/bin/env python3
"""Create a read-only PostgreSQL size breakdown without exposing credentials."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.app_config import load_config


def collect(limit: int, cutoff_utc: datetime | None) -> dict[str, object]:
    import psycopg
    from psycopg.rows import dict_row

    cfg = load_config()
    if not cfg.postgres_dsn:
        raise RuntimeError("postgres_dsn_not_configured")

    with psycopg.connect(
        cfg.postgres_dsn,
        row_factory=dict_row,
        connect_timeout=max(1, int(cfg.postgres_connect_timeout_seconds)),
        application_name="sli_postgres_size_breakdown",
        options="-c default_transaction_read_only=on -c statement_timeout=180000",
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select current_database() as database_name,
                       pg_database_size(current_database())::bigint as database_bytes,
                       now() as checked_at
                """
            )
            database = dict(cur.fetchone() or {})
            cur.execute(
                """
                select schemaname,
                       relname,
                       greatest(n_live_tup, 0)::bigint as estimated_rows,
                       pg_relation_size(relid)::bigint as heap_bytes,
                       pg_indexes_size(relid)::bigint as index_bytes,
                       greatest(
                           pg_total_relation_size(relid)
                           - pg_relation_size(relid)
                           - pg_indexes_size(relid),
                           0
                       )::bigint as toast_and_aux_bytes,
                       pg_total_relation_size(relid)::bigint as total_bytes
                from pg_stat_user_tables
                order by pg_total_relation_size(relid) desc, schemaname, relname
                limit %s
                """,
                (max(1, min(limit, 200)),),
            )
            relations = [dict(row) for row in cur.fetchall()]
            entity_retention: dict[str, object] | None = None
            if cutoff_utc is not None:
                cur.execute(
                    """
                    with keep_entity_ids as materialized (
                        select entity_id from event_entity_link_blocks_v2
                        union
                        select entity_id from entity_states
                        union
                        select entity_id from entity_state_current
                        union
                        select entity_id from finding_entities
                        union
                        select entity_id from ad_context_entity_aliases
                        union
                        select entity_id from ad_context_entity_versions
                        union
                        select source_entity_id from ad_context_relation_versions
                        union
                        select target_entity_id from ad_context_relation_versions
                    )
                    select
                        (select count(*) from keep_entity_ids)::bigint
                            as protected_distinct_entity_ids,
                        (select count(*) from entities_v2)::bigint
                            as v2_total,
                        (select count(*) from entities_v2
                         where last_seen_utc::timestamptz < %s)::bigint
                            as v2_last_seen_before_cutoff,
                        (select count(*) from entities_v2 entity
                         where not exists (
                             select 1 from keep_entity_ids kept
                             where kept.entity_id=entity.id
                         ))::bigint as v2_unreferenced,
                        (select count(*) from entity_details_v2 detail
                         where not exists (
                             select 1 from keep_entity_ids kept
                             where kept.entity_id=detail.entity_id
                         ))::bigint as v2_unreferenced_details
                    """,
                    (cutoff_utc,),
                )
                entity_retention = dict(cur.fetchone() or {})

    top_total = sum(int(row["total_bytes"]) for row in relations)
    return {
        "status": "ok",
        "mode": "read_only",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "database": database,
        "top_relations_total_bytes": top_total,
        "top_relations_share_of_database": (
            top_total / int(database["database_bytes"])
            if int(database.get("database_bytes") or 0)
            else None
        ),
        "relations": relations,
        "entity_retention": entity_retention,
        "credential_values_exposed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--cutoff-utc")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    cutoff_utc = (
        datetime.fromisoformat(args.cutoff_utc.replace("Z", "+00:00"))
        if args.cutoff_utc
        else None
    )
    result = collect(args.limit, cutoff_utc)
    output = (ROOT / args.output).resolve()
    output.relative_to(ROOT.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
