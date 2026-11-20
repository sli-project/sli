#!/usr/bin/env python3
"""Plan or apply exact Stage 9 migration 060 in production."""
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

from server.sli.ops.worker_supervisor_secrets import (  # noqa: E402
    load_supervisor_environment,
)


CONFIRMATION = "APPLY-STAGE9-RADIUS-IDENTITY-OWNER-60"
FORWARD = (
    ROOT
    / "config/postgres_migrations/"
    "060_radius_identity_resolver_owner.sql"
)
ROLLBACK = (
    ROOT
    / "config/postgres_migrations/"
    "060_radius_identity_resolver_owner.rollback.sql"
)
IDENTITY_59_FORWARD = (
    ROOT / "config/postgres_migrations/059_radius_identity_spine_resolver.sql"
)
IDENTITY_59_ROLLBACK = (
    ROOT / "config/postgres_migrations/059_radius_identity_spine_resolver.rollback.sql"
)
DISPOSABLE = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-identity-owner60-disposable-pg18.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-identity-owner60-production-apply.json"
)
DEFAULT_ATTESTATION_OUTPUT = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-identity-owner60-production-attestation.json"
)


class RadiusIdentityOwnerMigrationError(RuntimeError):
    pass


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
        raise RadiusIdentityOwnerMigrationError(
            "protected_postgres_credentials_required"
        )
    values = conninfo_to_dict(source)
    values.update(user=user, password=password)
    return make_conninfo(**values)


def _connect():
    import psycopg

    return psycopg.connect(
        _admin_dsn(),
        autocommit=True,
        connect_timeout=5,
        application_name="sli_stage9_radius_identity_owner60",
        options="-c statement_timeout=30000 -c lock_timeout=5000",
    )


def _read_disposable() -> dict[str, Any]:
    try:
        value = json.loads(DISPOSABLE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusIdentityOwnerMigrationError(
            "disposable_evidence_invalid"
        ) from exc
    acceptance = dict(value.get("acceptance") or {})
    rollback = dict(value.get("rollback") or {})
    if not (
        value.get("status") == "passed"
        and value.get("production_database_changed") is False
        and value.get("radius_source_contacted") is False
        and acceptance.get("migration_059_call_failed_before_fix") is True
        and acceptance.get("marker_60") is True
        and acceptance.get("resolver_owner")
        == "adlog_radius_identity_resolver"
        and acceptance.get("worker_exact_resolver_result") == "entity:101"
        and acceptance.get("worker_identity_select") is False
        and rollback.get("marker_60") is False
        and rollback.get("resolver_owner_role") is False
        and rollback.get("function_owner") == "adlog_storage_owner"
    ):
        raise RadiusIdentityOwnerMigrationError(
            "disposable_evidence_not_accepted"
        )
    return value


def _migration_identity() -> dict[str, Any]:
    return {
        "version": 60,
        "forward_sha256": sha256(FORWARD.read_bytes()).hexdigest(),
        "rollback_sha256": sha256(ROLLBACK.read_bytes()).hexdigest(),
    }


def _attestation_migrations() -> dict[str, dict[str, Any]]:
    return {
        "59": {
            "version": 59,
            "forward_sha256": sha256(IDENTITY_59_FORWARD.read_bytes()).hexdigest(),
            "rollback_sha256": sha256(IDENTITY_59_ROLLBACK.read_bytes()).hexdigest(),
        },
        "60": _migration_identity(),
    }


def _snapshot() -> dict[str, Any]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("begin read only")
        cur.execute(
            """
            select
              current_database(),current_user,
              current_setting('server_version_num')::integer,
              (
                select rolsuper from pg_roles where rolname=current_user
              ),
              exists(
                select 1 from schema_migrations
                where version=59 and name='radius_identity_spine_resolver'
              ),
              exists(
                select 1 from schema_migrations
                where version=60
                  and name='radius_identity_resolver_owner'
              ),
              to_regrole('adlog_radius_identity_resolver') is not null,
              (
                select pg_get_userbyid(proowner)
                from pg_proc
                where oid=
                  'sli_radius_resolve_principal_key(text,text)'::regprocedure
              ),
              (
                select pg_get_userbyid(relowner)
                from pg_class
                where oid='domains'::regclass
              ),
              (
                select pg_get_userbyid(relowner)
                from pg_class
                where oid='ad_context_entity_aliases'::regclass
              ),
              (
                select count(*) from acquisition_source_instances
                where source_instance_id='radius.radius01.example.invalid'
                  and desired_activation='disabled'
              ),
              (
                select count(*) from acquisition_consumer_subscriptions
                where subscription_id=
                  'vpn-radius-session-observations-v1'
                  and desired_activation='disabled'
              ),
              (
                select revision from acquisition_stream_cursors
                where source_instance_id='radius.radius01.example.invalid'
                  and stream_id='radius-accounting'
                  and transport_binding=
                    'windows-rpc-smb-readonly-tail-v1'
              ),
              (
                select
                  (select count(*) from core_evidence_manifests)
                + (select count(*)
                   from radius_accounting_session_observations)
                + (select count(*) from acquisition_delivery_outbox)
                + (select count(*) from radius_accounting_class_cache)
              ),
              exists(
                select 1 from pg_roles
                where rolname like 'adlog_radius_manual_%'
              )
            """
        )
        row = cur.fetchone()
        cur.execute("rollback")
    return {
        "database": str(row[0]),
        "current_user": str(row[1]),
        "server_version_num": int(row[2]),
        "current_user_superuser": bool(row[3]),
        "marker_59": bool(row[4]),
        "marker_60": bool(row[5]),
        "resolver_owner_role_exists": bool(row[6]),
        "function_owner": str(row[7]),
        "domains_owner": str(row[8]),
        "aliases_owner": str(row[9]),
        "disabled_source_rows": int(row[10]),
        "disabled_subscription_rows": int(row[11]),
        "cursor_revision": int(row[12]),
        "runtime_state_rows": int(row[13]),
        "ephemeral_login_exists": bool(row[14]),
    }


def plan() -> dict[str, Any]:
    _read_disposable()
    before = _snapshot()
    blockers = []
    if before["server_version_num"] // 10000 != 18:
        blockers.append("postgres_18_required")
    if not before["current_user_superuser"]:
        blockers.append("superuser_migration_admin_required")
    if not before["marker_59"]:
        blockers.append("migration_59_required")
    if before["marker_60"] or before["resolver_owner_role_exists"]:
        blockers.append("migration_60_conflict")
    if before["function_owner"] != "adlog_storage_owner":
        blockers.append("resolver_owner_before_apply_unexpected")
    if before["domains_owner"] != "adlog_user":
        blockers.append("domains_owner_unexpected")
    if before["aliases_owner"] != "adlog_user":
        blockers.append("aliases_owner_unexpected")
    if before["disabled_source_rows"] != 1:
        blockers.append("disabled_source_required")
    if before["disabled_subscription_rows"] != 1:
        blockers.append("disabled_subscription_required")
    if before["cursor_revision"] != 0:
        blockers.append("cursor_revision_zero_required")
    if before["runtime_state_rows"] != 0:
        blockers.append("runtime_state_must_be_empty")
    if before["ephemeral_login_exists"]:
        blockers.append("ephemeral_login_must_be_absent")
    return {
        "status": "ready" if not blockers else "blocked",
        "action": "plan",
        "migration": _migration_identity(),
        "before": before,
        "blockers": blockers,
        "source_contacted": False,
        "production_database_changed": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
        "required_confirmation": CONFIRMATION,
    }


def _postcondition() -> dict[str, Any]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("begin read only")
        cur.execute(
            """
            select
              exists(
                select 1 from schema_migrations
                where version=60
                  and name='radius_identity_resolver_owner'
              ),
              (
                select pg_get_userbyid(proowner)
                from pg_proc
                where oid=
                  'sli_radius_resolve_principal_key(text,text)'::regprocedure
              ),
              (
                select not rolcanlogin and not rolsuper and not rolinherit
                from pg_roles
                where rolname='adlog_radius_identity_resolver'
              ),
              has_column_privilege(
                'adlog_radius_identity_resolver','domains','id','SELECT'
              ) and has_column_privilege(
                'adlog_radius_identity_resolver','domains','fqdn','SELECT'
              ),
              has_column_privilege(
                'adlog_radius_identity_resolver',
                'ad_context_entity_aliases','entity_id','SELECT'
              ) and has_column_privilege(
                'adlog_radius_identity_resolver',
                'ad_context_entity_aliases','domain_id','SELECT'
              ) and has_column_privilege(
                'adlog_radius_identity_resolver',
                'ad_context_entity_aliases','alias_type','SELECT'
              ) and has_column_privilege(
                'adlog_radius_identity_resolver',
                'ad_context_entity_aliases','normalized_value','SELECT'
              ),
              has_schema_privilege(
                'adlog_radius_identity_resolver','public','CREATE'
              ),
              has_table_privilege(
                'adlog_radius_accounting_worker',
                'ad_context_entity_aliases','SELECT'
              ),
              has_function_privilege(
                'public',
                'sli_radius_resolve_principal_key(text,text)','EXECUTE'
              )
            """
        )
        (
            marker,
            owner,
            restricted,
            domains_columns,
            aliases_columns,
            schema_create,
            worker_select,
            public_execute,
        ) = cur.fetchone()
        cur.execute("set role adlog_radius_accounting_worker")
        cur.execute(
            """
            select sli_radius_resolve_principal_key(
              'example.invalid','cn=definitely-missing,dc=example,dc=test'
            )
            """
        )
        missing_value = cur.fetchone()[0]
        cur.execute("reset role")
        cur.execute("rollback")
    result = {
        "marker": bool(marker),
        "resolver_owner": str(owner),
        "resolver_owner_restricted_nologin": bool(restricted),
        "domains_column_select": bool(domains_columns),
        "aliases_column_select": bool(aliases_columns),
        "resolver_owner_schema_create": bool(schema_create),
        "worker_identity_select": bool(worker_select),
        "public_execute": bool(public_execute),
        "missing_identity_result": missing_value,
    }
    expected = {
        "marker": True,
        "resolver_owner": "adlog_radius_identity_resolver",
        "resolver_owner_restricted_nologin": True,
        "domains_column_select": True,
        "aliases_column_select": True,
        "resolver_owner_schema_create": False,
        "worker_identity_select": False,
        "public_execute": False,
        "missing_identity_result": None,
    }
    if result != expected:
        raise RadiusIdentityOwnerMigrationError(
            f"migration_60_postcondition_failed:{result}"
        )
    return result


def _attestation_markers() -> dict[str, bool]:
    """Read only final-state markers; registration rows are irrelevant here."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("begin read only")
        cur.execute(
            """
            select
              exists(select 1 from schema_migrations
                     where version=59 and name='radius_identity_spine_resolver'),
              exists(select 1 from schema_migrations
                     where version=60 and name='radius_identity_resolver_owner')
            """
        )
        marker_59, marker_60 = cur.fetchone()
        cur.execute("rollback")
    return {"marker_59": bool(marker_59), "marker_60": bool(marker_60)}


def finalize_applied(*, output: Path) -> dict[str, Any]:
    """Attest the final 059/060 identity boundary without mutation."""
    _read_disposable()
    output = output.resolve()
    if (ROOT / "artifacts").resolve() not in output.parents:
        raise ValueError("output must stay under artifacts")
    if output.exists():
        raise FileExistsError("identity owner attestation already exists")
    markers = _attestation_markers()
    if not markers["marker_59"] or not markers["marker_60"]:
        raise RadiusIdentityOwnerMigrationError("identity_migration_marker_missing")
    postcondition = _postcondition()
    return {
        "status": "passed",
        "action": "finalize_applied_readback",
        "evidence_kind": "production_current_state_attestation",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "covers_migrations": [59, 60],
        "migrations": _attestation_migrations(),
        "markers": markers,
        "postcondition": postcondition,
        "production_migration_applied": True,
        "production_database_changed": False,
        "radius_source_contacted": False,
        "runtime_enabled": False,
        "registration_changed": False,
        "autostart_enabled": False,
    }


def apply() -> dict[str, Any]:
    planned = plan()
    if planned["status"] != "ready":
        raise RadiusIdentityOwnerMigrationError(
            "migration_60_plan_not_ready"
        )
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(FORWARD.read_text(encoding="utf-8"))
    after = _snapshot()
    post = _postcondition()
    if (
        after["disabled_source_rows"] != 1
        or after["disabled_subscription_rows"] != 1
        or after["cursor_revision"] != 0
        or after["runtime_state_rows"] != 0
        or after["ephemeral_login_exists"]
    ):
        raise RadiusIdentityOwnerMigrationError(
            "registration_changed_by_migration_60"
        )
    return {
        "status": "passed",
        "action": "apply",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "migration": _migration_identity(),
        "postcondition": post,
        "production_database_changed": True,
        "radius_source_contacted": False,
        "registration_changed": False,
        "cursor_revision": 0,
        "runtime_enabled": False,
        "autostart_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--action", choices=("plan", "apply", "finalize-applied"), default="plan"
    )
    parser.add_argument("--confirmation", default="")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--load-supervisor-environment", action="store_true")
    args = parser.parse_args()
    if args.load_supervisor_environment:
        _load_environment()
    if args.action == "plan":
        result = plan()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "ready" else 2
    if args.action == "finalize-applied":
        output = args.output.resolve()
        if args.output == DEFAULT_OUTPUT:
            output = DEFAULT_ATTESTATION_OUTPUT.resolve()
        result = finalize_applied(output=output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"status": result["status"], "output": str(output)}))
        return 0
    if args.confirmation != CONFIRMATION:
        raise PermissionError(
            f"apply requires --confirmation {CONFIRMATION}"
        )
    output = args.output.resolve()
    if (ROOT / "artifacts").resolve() not in output.parents:
        raise ValueError("output must stay under artifacts")
    if output.exists():
        raise FileExistsError("production apply evidence already exists")
    result = apply()
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": result["status"], "output": str(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
