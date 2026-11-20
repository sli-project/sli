#!/usr/bin/env python3
"""Plan or apply the least-privilege semantic findings report reader migration 079."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment  # noqa: E402


CONFIRMATION = "APPLY-SECURITY-PROBLEMS-REPORT-READER-79"
MIGRATION = ROOT / "config/postgres_migrations/079_semantic_finding_report_reader.sql"
OUTPUT = ROOT / "artifacts/stage8/evidence/security-problems-report-reader79-production.json"


class SecurityProblemsReportControlError(RuntimeError):
    pass


def _load_environment() -> None:
    required = ("ADLOG_PG_DSN", "ADLOG_PG_ADMIN_USER", "ADLOG_PG_ADMIN_PASSWORD")
    if not all(os.getenv(name, "").strip() for name in required):
        load_supervisor_environment()


def _admin_dsn() -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    source = os.getenv("ADLOG_PG_DSN", "").strip()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not source or not user or not password:
        raise SecurityProblemsReportControlError("protected_postgres_credentials_required")
    values = conninfo_to_dict(source)
    values.update(user=user, password=password)
    return make_conninfo(**values)


def _connect(*, autocommit: bool = False):
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(
        _admin_dsn(),
        autocommit=autocommit,
        row_factory=dict_row,
        connect_timeout=5,
        application_name="sli_security_problems_report_reader79",
        options="-c statement_timeout=30000 -c lock_timeout=5000",
    )


def _snapshot() -> dict[str, Any]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("begin read only")
        cur.execute(
            """
            select current_database() as database_name,
                   session_user,
                   current_setting('server_version_num')::integer as server_version_num,
                   pg_has_role(session_user,'adlog_storage_owner','MEMBER')
                       as storage_owner_member,
                   exists(select 1 from schema_migrations
                          where version=55 and name='semantic_finding_publication')
                       as prerequisite_55,
                   exists(select 1 from schema_migrations
                          where version=78 and name='plugin_runtime_guard_read_boundary')
                       as prerequisite_78,
                   exists(select 1 from schema_migrations
                          where version=79 and name='semantic_finding_report_reader')
                       as marker_79,
                   to_regprocedure(
                     'public.is_semantic_finding_published_v1(bigint)'
                   ) is not null as reader_exists,
                   case when to_regprocedure(
                     'public.is_semantic_finding_published_v1(bigint)'
                   ) is not null then has_function_privilege(
                       'adlog_user',
                       'is_semantic_finding_published_v1(bigint)',
                       'EXECUTE'
                   ) else false end as runtime_execute,
                   has_table_privilege(
                     'adlog_user','semantic_finding_publications','SELECT'
                   ) as runtime_direct_select,
                   (select count(*)::bigint from semantic_finding_publications)
                       as publication_count,
                   (select count(*)::bigint from findings)
                       as finding_count
            """
        )
        row = dict(cur.fetchone() or {})
        cur.execute("rollback")
    return row


def _state(snapshot: dict[str, Any]) -> str:
    marker = snapshot.get("marker_79") is True
    reader = snapshot.get("reader_exists") is True
    exact_acl = (
        snapshot.get("runtime_execute") is True
        and snapshot.get("runtime_direct_select") is False
    )
    if marker and reader and exact_acl:
        return "applied"
    if not marker and not reader:
        return "ready"
    return "partial_or_drifted"


def plan() -> dict[str, Any]:
    snapshot = _snapshot()
    state = _state(snapshot)
    blockers: list[str] = []
    if int(snapshot.get("server_version_num") or 0) // 10000 != 18:
        blockers.append("postgres_18_required")
    if snapshot.get("storage_owner_member") is not True:
        blockers.append("storage_owner_membership_required")
    if snapshot.get("prerequisite_55") is not True:
        blockers.append("migration_55_required")
    if snapshot.get("prerequisite_78") is not True:
        blockers.append("migration_78_required")
    if state == "partial_or_drifted":
        blockers.append("migration_79_partial_or_drifted")
    return {
        "status": "ready" if not blockers else "blocked",
        "action": "plan",
        "migration": {
            "version": 79,
            "name": "semantic_finding_report_reader",
            "state": state,
            "sha256": sha256(MIGRATION.read_bytes()).hexdigest(),
        },
        "snapshot": snapshot,
        "blockers": blockers,
        "required_confirmation": CONFIRMATION,
        "production_database_changed": False,
    }


def _runtime_readback() -> dict[str, int]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("begin read only")
        cur.execute("set local role adlog_user")
        cur.execute(
            """
            select count(*)::bigint as published_findings
            from findings_active findings
            where is_semantic_finding_published_v1(findings.id)
            """
        )
        row = dict(cur.fetchone() or {})
        cur.execute("rollback")
    return {"published_findings": int(row.get("published_findings") or 0)}


def apply(*, confirmation: str) -> dict[str, Any]:
    planned = plan()
    if planned["status"] != "ready":
        raise SecurityProblemsReportControlError(
            f"production_plan_blocked:{planned['blockers']}"
        )
    if planned["migration"]["state"] != "ready":
        raise SecurityProblemsReportControlError("migration_79_not_ready")
    if confirmation != CONFIRMATION:
        raise PermissionError("exact migration confirmation is required")
    if OUTPUT.exists():
        raise SecurityProblemsReportControlError("production_evidence_already_exists")

    before = dict(planned["snapshot"])
    with _connect(autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(MIGRATION.read_text(encoding="utf-8"))
    after = _snapshot()
    if _state(after) != "applied":
        raise SecurityProblemsReportControlError("migration_79_postcondition_failed")
    for key in ("publication_count", "finding_count"):
        if int(after.get(key) or 0) != int(before.get(key) or 0):
            raise SecurityProblemsReportControlError(
                f"migration_79_changed_product_rows:{key}"
            )
    readback = _runtime_readback()
    if readback["published_findings"] != int(after.get("publication_count") or 0):
        raise SecurityProblemsReportControlError("runtime_publication_readback_mismatch")

    result = {
        "status": "applied",
        "action": "apply",
        "applied_at_utc": datetime.now(timezone.utc).isoformat(),
        "migration": planned["migration"],
        "before": before,
        "after": after,
        "runtime_readback": readback,
        "production_database_changed": True,
        "product_rows_changed": False,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply"))
    parser.add_argument("--confirmation", default="")
    args = parser.parse_args()
    _load_environment()
    try:
        result = plan() if args.action == "plan" else apply(confirmation=args.confirmation)
        print(json.dumps(result, ensure_ascii=False, default=str))
        return 0 if result.get("status") in {"ready", "applied"} else 1
    except Exception as exc:
        print(json.dumps({"status": "blocked", "error_type": type(exc).__name__, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
