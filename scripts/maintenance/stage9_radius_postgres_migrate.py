#!/usr/bin/env python3
from __future__ import annotations

"""Controlled production apply/rollback for exact migration 058 only."""

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

from server.sli.ops.worker_supervisor_secrets import (  # noqa: E402
    load_supervisor_environment,
)
from scripts.maintenance.stage9_radius_postgres_production_preflight import (  # noqa: E402
    FOUNDATION_TABLES,
    inspect as inspect_production,
)


APPLY_CONFIRM = "APPLY-STAGE9-RADIUS-POSTGRES-58"
ROLLBACK_CONFIRM = "ROLLBACK-STAGE9-RADIUS-POSTGRES-58"
FORWARD = (
    ROOT
    / "config/postgres_migrations/"
    "058_radius_accounting_transaction_foundation.sql"
)
ROLLBACK = (
    ROOT
    / "config/postgres_migrations/"
    "058_radius_accounting_transaction_foundation.rollback.sql"
)
DEFAULT_PREFLIGHT = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-accounting-postgres58-production-preflight.json"
)
DEFAULT_APPLY_RESULT = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-accounting-postgres58-production-apply.json"
)
DEFAULT_ATTESTATION_RESULT = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-accounting-postgres58-production-attestation.json"
)
DISPOSABLE_EVIDENCE = (
    ROOT / "artifacts/stage9/evidence/radius-accounting-postgres58-disposable.json"
)
DEFAULT_ROLLBACK_RESULT = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-accounting-postgres58-production-rollback.json"
)


def _load_environment() -> None:
    if not (
        os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
        and os.getenv("ADLOG_PG_DSN", "").strip()
    ):
        load_supervisor_environment()


def _admin_dsn() -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    source = os.getenv("ADLOG_PG_DSN", "").strip()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not source or not user or not password:
        raise RuntimeError(
            "protected PostgreSQL migration credentials are required"
        )
    values = conninfo_to_dict(source)
    values.update(user=user, password=password)
    return make_conninfo(**values)


def _connect():
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(
        _admin_dsn(),
        autocommit=True,
        row_factory=dict_row,
        connect_timeout=5,
        application_name="sli_stage9_radius58_migrate",
        options="-c statement_timeout=120000 -c lock_timeout=5000",
    )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid evidence file: {path.name}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"evidence must be an object: {path.name}")
    return value


def _hashes() -> dict[str, str]:
    return {
        "forward_sha256": sha256(FORWARD.read_bytes()).hexdigest(),
        "rollback_sha256": sha256(ROLLBACK.read_bytes()).hexdigest(),
    }


def _validate_preflight(
    evidence: dict[str, Any],
    live: dict[str, Any],
) -> None:
    if evidence.get("status") != "ready":
        raise RuntimeError("preflight is not ready")
    if evidence.get("blockers") != []:
        raise RuntimeError("preflight contains blockers")
    migration = dict(evidence.get("migration") or {})
    if migration.get("version") != 58:
        raise RuntimeError("preflight migration version mismatch")
    if migration.get("execution_contract") != "single_file_058_only":
        raise RuntimeError("preflight execution contract mismatch")
    if migration.get("excluded_from_automatic_sequence") != [56, 57]:
        raise RuntimeError("preflight does not exclude migrations 056/057")
    hashes = _hashes()
    if any(migration.get(key) != value for key, value in hashes.items()):
        raise RuntimeError("migration files changed after preflight")
    if live.get("status") != "ready" or live.get("blockers") != []:
        raise RuntimeError("live preflight is no longer ready")
    if dict(live.get("identity") or {}) != dict(
        evidence.get("identity") or {}
    ):
        raise RuntimeError("database identity changed after preflight")
    if dict(live.get("schema") or {}) != dict(
        evidence.get("schema") or {}
    ):
        raise RuntimeError("database schema changed after preflight")
    if dict(live.get("privileges") or {}) != dict(
        evidence.get("privileges") or {}
    ):
        raise RuntimeError("database privileges changed after preflight")


def _post_apply() -> dict[str, Any]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("begin read only")
        cur.execute(
            """
            select exists(
                     select 1 from schema_migrations
                     where version=58
                       and name='radius_accounting_transaction_foundation'
                   ) as marker,
                   to_regrole('adlog_radius_accounting_worker') is not null
                     as worker_role,
                   has_table_privilege(
                     'adlog_radius_accounting_worker',
                     'core_evidence_manifests','INSERT'
                   ) as evidence_insert,
                   has_table_privilege(
                     'adlog_radius_accounting_worker',
                     'core_evidence_manifests','DELETE'
                   ) as evidence_delete,
                   has_table_privilege(
                     'adlog_radius_accounting_worker',
                     'acquisition_stream_cursors','UPDATE'
                   ) as cursor_update
            """
        )
        values = dict(cur.fetchone())
        cur.execute(
            """
            select relname from pg_class
            where relnamespace=current_schema()::regnamespace
              and relname=any(%s)
            order by relname
            """,
            (list(FOUNDATION_TABLES),),
        )
        tables = [str(row["relname"]) for row in cur.fetchall()]
        cur.execute("rollback")
    values["tables"] = tables
    return values


def _accepted_disposable() -> dict[str, Any]:
    value = _read_json(DISPOSABLE_EVIDENCE)
    evidence = dict(value.get("evidence") or {})
    migration = dict(evidence.get("migration") or {})
    registration = dict(evidence.get("registration") or {})
    evidence_first = dict(evidence.get("evidence_first") or {})
    injected_failures = evidence.get("injected_failures")
    commit = dict(evidence.get("commit") or {})
    clean_rollback = dict(evidence.get("clean_rollback") or {})
    if not (
        value.get("status") == "passed"
        and value.get("production_database_changed") is False
        and value.get("radius_source_contacted") is False
        and value.get("runtime_enabled") is False
        and value.get("disposable_schema_cleaned") is True
        and migration == {
            "marker": True,
            "worker_role": True,
            "evidence_insert": True,
            "evidence_delete": False,
            "cursor_update": True,
        }
        and registration.get("registered_disabled_first") is True
        and registration.get("disposable_manual_enable_only") is True
        and all(
            isinstance(registration.get(identifier), str)
            and bool(registration[identifier].strip())
            for identifier in (
                "source_instance_id",
                "subscription_id",
                "stream_id",
                "transport_binding",
            )
        )
        and evidence_first.get("published_objects", 0) > 0
        and evidence_first.get("database_manifest_rows_before_commit") == 0
        and evidence_first.get("orphan_retry_is_idempotent") is True
        and evidence_first.get("payload_in_result") is False
        and isinstance(injected_failures, list)
        and len(injected_failures) == 3
        and {
            (item.get("phase"), item.get("rolled_back"))
            for item in injected_failures
            if isinstance(item, dict)
        } == {("evidence", True), ("outbox", True), ("cache", True)}
        and commit == {
            "evidence_rows": 2,
            "observation_rows": 1,
            "outbox_rows": 1,
            "class_cache_rows": 1,
            "cursor_revision": 1,
            "cursor_byte_offset": 200,
        }
        and evidence.get("stale_replay_rejected") is True
        and evidence.get("persisted_state_rollback_guarded") is True
        and clean_rollback == {
            "marker": False,
            "foundation_table": False,
            "worker_role": False,
        }
    ):
        raise RuntimeError("disposable_058_evidence_invalid")
    return value


def finalize_applied(*, output: Path) -> dict[str, Any]:
    """Attest the already-applied 058 state through read-only SQL only."""
    _accepted_disposable()
    output = _output_path(str(output))
    postcondition = _post_apply()
    expected = {
        "marker": True,
        "worker_role": True,
        "evidence_insert": True,
        "evidence_delete": False,
        "cursor_update": True,
        "tables": sorted(FOUNDATION_TABLES),
    }
    if postcondition != expected:
        raise RuntimeError("migration_058_current_state_attestation_failed")
    return {
        "status": "passed",
        "action": "finalize_applied_readback",
        "evidence_kind": "production_current_state_attestation",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "migration": {"version": 58, **_hashes()},
        "postcondition": postcondition,
        "production_migration_applied": True,
        "production_database_changed": False,
        "source_instance_created": False,
        "runtime_enabled": False,
        "radius_source_contacted": False,
    }


def apply(preflight_path: Path) -> dict[str, Any]:
    preflight = _read_json(preflight_path)
    live = inspect_production()
    _validate_preflight(preflight, live)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(FORWARD.read_text(encoding="utf-8"))
    post = _post_apply()
    expected = {
        "marker": True,
        "worker_role": True,
        "evidence_insert": True,
        "evidence_delete": False,
        "cursor_update": True,
        "tables": sorted(FOUNDATION_TABLES),
    }
    if post != expected:
        raise RuntimeError(f"migration 058 postcondition failed: {post}")
    return {
        "status": "passed",
        "action": "apply",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "migration": {"version": 58, **_hashes()},
        "preflight": preflight_path.name,
        "postcondition": post,
        "production_database_changed": True,
        "radius_source_contacted": False,
        "source_instance_created": False,
        "runtime_enabled": False,
    }


def _pre_rollback() -> dict[str, Any]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select exists(
                     select 1 from schema_migrations
                     where version=58
                       and name='radius_accounting_transaction_foundation'
                   ) as marker
            """
        )
        marker = bool(cur.fetchone()["marker"])
        counts = {}
        for table in FOUNDATION_TABLES:
            cur.execute(f"select count(*) as count from {table}")
            counts[table] = int(cur.fetchone()["count"])
    return {"marker": marker, "row_counts": counts}


def rollback(apply_evidence_path: Path) -> dict[str, Any]:
    apply_evidence = _read_json(apply_evidence_path)
    if (
        apply_evidence.get("status") != "passed"
        or apply_evidence.get("action") != "apply"
        or dict(apply_evidence.get("migration") or {}).get("version") != 58
    ):
        raise RuntimeError("accepted migration 058 apply evidence required")
    if any(
        dict(apply_evidence.get("migration") or {}).get(key) != value
        for key, value in _hashes().items()
    ):
        raise RuntimeError("migration files changed after apply")
    before = _pre_rollback()
    if not before["marker"]:
        raise RuntimeError("migration 058 is not applied")
    if any(before["row_counts"].values()):
        raise RuntimeError("rollback refuses persisted acquisition state")
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(ROLLBACK.read_text(encoding="utf-8"))
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select exists(
                     select 1 from schema_migrations where version=58
                   ) as marker,
                   to_regrole('adlog_radius_accounting_worker') is not null
                     as worker_role,
                   to_regclass('acquisition_source_instances') is not null
                     as foundation_table
            """
        )
        post = dict(cur.fetchone())
    if post != {
        "marker": False,
        "worker_role": False,
        "foundation_table": False,
    }:
        raise RuntimeError(f"migration 058 rollback failed: {post}")
    return {
        "status": "passed",
        "action": "rollback",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "migration": {"version": 58, **_hashes()},
        "apply_evidence": apply_evidence_path.name,
        "precondition": before,
        "postcondition": post,
        "production_database_changed": True,
        "radius_source_contacted": False,
        "runtime_enabled": False,
    }


def _output_path(value: str) -> Path:
    path = Path(value).resolve()
    if not path.is_relative_to(ROOT):
        raise RuntimeError("output must stay inside the project")
    if path.exists():
        raise RuntimeError("migration evidence already exists")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--action",
        choices=("plan", "apply", "rollback", "finalize-applied"),
        default="plan",
    )
    parser.add_argument("--confirmation", default="")
    parser.add_argument(
        "--preflight-evidence",
        default=str(DEFAULT_PREFLIGHT),
    )
    parser.add_argument(
        "--apply-evidence",
        default=str(DEFAULT_APPLY_RESULT),
    )
    parser.add_argument("--output", default="")
    parser.add_argument(
        "--load-supervisor-environment",
        action="store_true",
    )
    args = parser.parse_args()
    try:
        if args.load_supervisor_environment:
            _load_environment()
        if args.action == "plan":
            result = inspect_production()
            result["action"] = "plan"
            result["required_confirmation"] = APPLY_CONFIRM
        elif args.action == "apply":
            if args.confirmation != APPLY_CONFIRM:
                raise RuntimeError(
                    f"apply requires --confirmation {APPLY_CONFIRM}"
                )
            output = _output_path(
                args.output or str(DEFAULT_APPLY_RESULT)
            )
            result = apply(Path(args.preflight_evidence).resolve())
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(result, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        elif args.action == "finalize-applied":
            output = _output_path(
                args.output or str(DEFAULT_ATTESTATION_RESULT)
            )
            result = finalize_applied(output=output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(result, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        else:
            if args.confirmation != ROLLBACK_CONFIRM:
                raise RuntimeError(
                    f"rollback requires --confirmation {ROLLBACK_CONFIRM}"
                )
            output = _output_path(
                args.output or str(DEFAULT_ROLLBACK_RESULT)
            )
            result = rollback(Path(args.apply_evidence).resolve())
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(result, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
    except Exception as exc:  # noqa: BLE001
        result = {
            "status": "failed",
            "action": args.action,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "production_database_changed": (
                False if args.action == "plan" else None
            ),
            "radius_source_contacted": False,
            "runtime_enabled": False,
        }
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("status") in {"ready", "passed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
