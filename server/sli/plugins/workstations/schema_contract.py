"""Read-only WR02 acceptance report, run after the normal installed update.

Usage: python -m server.sli.plugins.workstations.schema_contract
Only catalog metadata is returned; no station/evidence rows or credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from deploy.linux.installed_state import migration_checksum_variants

VERSION = 252
NAME = "workstation_overview_projections"
SCHEMA = "sli_plugin_workstations"
MIGRATION = Path(__file__).resolve().parents[4] / f"config/postgres_migrations/{VERSION}_{NAME}.sql"
TABLE_COLUMNS = {
    "station_inventory": {"station_id", "entity_id", "ad_computer_id", "agent_key", "domain_id", "ou_entity_id",
                          "station_type", "association_status", "metadata", "metadata_observed_at", "quality",
                          "revision", "updated_at"},
    "station_summary": {"station_id", "last_interactive_login", "health", "protection", "counters", "quality",
                        "revision", "as_of_utc", "updated_at"},
    "check_findings": {"id", "station_id", "check_id", "rule_version", "subject_id", "subject_ref", "episode_id",
                       "revision", "condition_sha256", "status", "severity", "fact_at", "first_detected_at",
                       "last_observed_at", "materially_changed_at", "resolved_at", "reason_code", "reason_params",
                       "quality", "evidence_refs"},
    "station_changes": {"id", "station_id", "change_kind", "event_at", "detected_at", "actor_ref", "subject_ref",
                        "reason_code", "reason_params", "quality", "evidence_refs"},
    "projection_checkpoints": {"projector_key", "partition_key", "projection_version", "committed_position",
                               "revision", "updated_at"},
}
TABLE_INDEXES = {
    "station_inventory": {"station_inventory_pkey", "station_inventory_entity_id_key",
                          "station_inventory_ad_computer_id_key", "station_inventory_agent_key_key",
                          "workstation_inventory_scope"},
    "station_summary": {"station_summary_pkey"},
    "check_findings": {"check_findings_pkey", "workstation_finding_episode",
                       "workstation_findings_check", "workstation_findings_station", "workstation_findings_detected"},
    "station_changes": {"station_changes_pkey", "workstation_changes_station", "workstation_changes_time"},
    "projection_checkpoints": {"projection_checkpoints_pkey"},
}
PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN")


def inspect_schema(cur, migration_bytes: bytes) -> dict:
    """Inspect the applied marker, owned relations, columns, indexes and ACLs."""
    cur.execute("""select name,to_jsonb(m)->>'sha256' as sha256
                   from public.schema_migrations m where version=%s""", (VERSION,))
    marker = cur.fetchone() or {}
    marker_ok = marker.get("name") == NAME
    checksum_ok = marker.get("sha256") in migration_checksum_variants(migration_bytes)
    cur.execute("""select has_schema_privilege('adlog_user',%s,'USAGE') as usage,
                          has_schema_privilege('adlog_user',%s,'CREATE') as create_allowed""", (SCHEMA, SCHEMA))
    schema_rights = cur.fetchone() or {}
    cur.execute("""select c.relname as table_name,pg_get_userbyid(c.relowner) as owner,
                          pg_has_role('adlog_user',c.relowner,'MEMBER') as runtime_is_owner,
                          exists(select 1 from aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
                                 where a.grantee=0) as public_access,
                          array(select a.attname::text from pg_attribute a where a.attrelid=c.oid
                                and a.attnum>0 and not a.attisdropped) as columns
                   from pg_class c join pg_namespace n on n.oid=c.relnamespace
                   where n.nspname=%s and c.relkind='r' and c.relname=any(%s)""", (SCHEMA, list(TABLE_COLUMNS)))
    tables = {row["table_name"]: row for row in cur.fetchall()}
    cur.execute("""select t.relname as table_name,i.relname as index_name,x.indisvalid,x.indisready
                   from pg_index x join pg_class i on i.oid=x.indexrelid
                   join pg_class t on t.oid=x.indrelid join pg_namespace n on n.oid=t.relnamespace
                   where n.nspname=%s and t.relname=any(%s)""", (SCHEMA, list(TABLE_COLUMNS)))
    indexes = {(row["table_name"], row["index_name"]): row["indisvalid"] and row["indisready"]
               for row in cur.fetchall()}
    cur.execute("""select c.relname as table_name,p.privilege,
                          has_table_privilege('adlog_user',c.oid,p.privilege) as allowed
                   from pg_class c join pg_namespace n on n.oid=c.relnamespace
                   cross join unnest(%s::text[]) as p(privilege)
                   where n.nspname=%s and c.relkind='r' and c.relname=any(%s)""",
                (list(PRIVILEGES), SCHEMA, list(TABLE_COLUMNS)))
    grants = {(row["table_name"], row["privilege"]): row["allowed"] for row in cur.fetchall()}
    objects = []
    for table, columns in TABLE_COLUMNS.items():
        row = tables.get(table, {})
        allowed = {"SELECT", "INSERT"} if table == "station_changes" else {"SELECT", "INSERT", "UPDATE"}
        rights_ok = all(grants.get((table, privilege)) is (privilege in allowed) for privilege in PRIVILEGES)
        missing_columns = sorted(columns - set(row.get("columns", ())))
        missing_indexes = sorted(name for name in TABLE_INDEXES[table] if not indexes.get((table, name)))
        owner_ok = row.get("owner") == "adlog_storage_owner" and row.get("runtime_is_owner") is False
        public_denied = row.get("public_access") is False
        objects.append({
            "table": f"{SCHEMA}.{table}", "present": bool(row), "owner_ok": owner_ok,
            "missing_columns": missing_columns, "missing_indexes": missing_indexes,
            "runtime_rights": {privilege: grants.get((table, privilege)) for privilege in PRIVILEGES},
            "public_denied": public_denied,
            "verified": bool(row) and owner_ok and public_denied and rights_ok and not missing_columns and not missing_indexes,
        })
    verified = (marker_ok and checksum_ok and schema_rights.get("usage") is True
                and schema_rights.get("create_allowed") is False and all(row["verified"] for row in objects))
    return {"contract_id": "sli.workstations.schema.wr02.v1", "status": "verified" if verified else "failed",
            "migration_version": VERSION, "migration_name": NAME,
            "source_sha256": hashlib.sha256(migration_bytes).hexdigest(),
            "marker_ok": marker_ok, "checksum_ok": checksum_ok, "schema_rights": schema_rights, "objects": objects}


def run(*, connect_factory=None) -> dict:
    if connect_factory is None:
        from server.sli.core.postgres_runtime_pipeline import connect
        connect_factory = connect
    with connect_factory() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute("set local statement_timeout='5s'")
        cur.execute("set local lock_timeout='1s'")
        return inspect_schema(cur, MIGRATION.read_bytes())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        report = run()
    except Exception:
        # Connection errors may contain private connection details.
        report = {"status": "failed", "code": "workstation_schema_contract_unavailable"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
