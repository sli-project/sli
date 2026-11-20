"""Plan/apply/verify the first event-store admission for the local SLI installation.

Uses the existing administrator DPAPI secret, never elevates runtime roles or
contacts surveyed systems. This is not a V1 migration or backup/restore claim.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.ad_snapshot_manifest_foundation_migrate import _connect, _dsn
from server.sli.storage.storage_v2_config import load_storage_v2_settings
from server.sli.storage.storage_v2_runtime_authorization import (
    FRESH_BOOTSTRAP_AUTHORITY, bootstrap_fresh_runtime_authorization,
    inspect_fresh_storage, load_runtime_authorization,
)

APPLY_TOKEN = "INITIALIZE-EMPTY-LOCAL-STORAGE-V2"


def validate_target(dsn: str) -> None:
    from psycopg.conninfo import conninfo_to_dict
    parts = conninfo_to_dict(dsn)
    loopback = {"127.0.0.1", "::1", "localhost"}
    if (parts.get("host") not in loopback
            or parts.get("hostaddr", "127.0.0.1") not in {"127.0.0.1", "::1"}
            or parts.get("port") != "55433" or parts.get("dbname") != "sli_local"
            or parts.get("service")):
        raise RuntimeError("local_storage_target_mismatch")


def verify_runtime_grants(cur) -> None:
    # Independently check each privilege: comma-separated PostgreSQL checks mean ANY.
    for table, privileges in {
        "storage_v2_runtime_authorizations": ("SELECT",),
        "raw_log_files": ("SELECT", "INSERT", "UPDATE"),
        "storage_v2_event_identity_allocations": ("SELECT", "INSERT"),
        "storage_v2_entity_identity_allocations": ("SELECT", "INSERT"),
        "events_v2_core": ("SELECT", "INSERT", "UPDATE"),
        "event_facts_v2": ("SELECT", "INSERT", "UPDATE"),
        "entities_v2": ("SELECT", "INSERT", "UPDATE"),
    }.items():
        role = "adlog_user" if table == "storage_v2_runtime_authorizations" else "adlog_storage_worker"
        for privilege in privileges:
            cur.execute("SELECT has_table_privilege(%s,%s,%s) AS allowed", (role, "public." + table, privilege))
            if not cur.fetchone()["allowed"]:
                raise RuntimeError("storage_worker_grant_missing:" + table + ":" + privilege)
    for role in ("adlog_user", "adlog_storage_worker"):
        cur.execute("SELECT rolsuper,rolcreatedb,rolbypassrls FROM pg_roles WHERE rolname=%s", (role,))
        row = cur.fetchone()
        if row is None or any(row.values()):
            raise RuntimeError("storage_runtime_role_elevated")
        for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            cur.execute("SELECT has_table_privilege(%s,'public.storage_v2_runtime_authorizations',%s) AS allowed", (role, privilege))
            if cur.fetchone()["allowed"]:
                raise RuntimeError("storage_runtime_can_modify_admission")


def run(*, action: str = "plan", confirmation: str | None = None) -> dict:
    if action not in {"plan", "apply", "verify"}:
        raise RuntimeError("action_invalid")
    if (action == "apply" and confirmation != APPLY_TOKEN
            or action != "apply" and confirmation is not None):
        raise RuntimeError("confirmation_invalid")
    settings = load_storage_v2_settings(strict=True)
    archive_root = ROOT / "data" / "storage-v2-archive"
    if settings.read_mode != "v2" or settings.write_mode != "v2":
        raise RuntimeError("local_storage_configuration_mismatch")
    owner = None
    if action == "apply":
        from server.sli.sources.windows_runtime_identity import verify_collection_identity
        identity_check = verify_collection_identity()
        if identity_check["status"] != "ok":
            raise RuntimeError("local_storage_windows_owner_mismatch")
        owner = identity_check["current_principal"] + ":" + identity_check["current_sid"]
    dsn = _dsn(admin=True)
    validate_target(dsn)
    with _connect(dsn) as conn, conn.cursor() as cur:
        if action != "apply":
            cur.execute("SET TRANSACTION READ ONLY")
        cur.execute("SET LOCAL statement_timeout='10s'")
        cur.execute("SET LOCAL lock_timeout='3s'")
        cur.execute("SET LOCAL search_path=public,pg_catalog")
        cur.execute("SELECT host(inet_server_addr()) AS address,inet_server_port() AS port,current_database() AS database")
        identity = cur.fetchone()
        if (identity["address"] not in {"127.0.0.1", "::1"}
                or identity["port"] != 55433 or identity["database"] != "sli_local"):
            raise RuntimeError("connected_storage_target_mismatch")
        verify_runtime_grants(cur)
        if action == "plan":
            result = inspect_fresh_storage(cur, archive_root=archive_root)
        else:
            if action == "apply":
                issued = datetime.now(timezone.utc)
                bootstrap_fresh_runtime_authorization(
                    cur, archive_root=archive_root, authorized_by=owner,
                    issued_at=issued, expires_at=issued + timedelta(days=365),
                )
            admission = load_runtime_authorization(cur)
            if (admission is None or admission.authority != FRESH_BOOTSTRAP_AUTHORITY
                    or admission.route != "v2"):
                raise RuntimeError("fresh_storage_admission_missing_or_mismatched")
            result = {"authority": admission.authority, "route": admission.route,
                      "authorization_digest": admission.authorization_digest,
                      "expires_at": admission.expires_at.isoformat()}
    return {"status": "ok", "action": action, "surveyed_source_contacted": False, **result}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("plan", "apply", "verify"), default="plan")
    parser.add_argument("--confirm")
    parser.add_argument("--load-supervisor-environment", action="store_true")
    args = parser.parse_args()
    if args.load_supervisor_environment:
        from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment
        load_supervisor_environment(override_existing=True)
    try:
        result = run(action=args.action, confirmation=args.confirm)
    except Exception as exc:
        # Never print database-driver diagnostics, DSNs or secret material.
        code = str(exc) if type(exc) in {RuntimeError, ValueError} else type(exc).__name__
        print(json.dumps({"status": "error", "code": code}))
        return 1
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
