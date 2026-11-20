"""Static migration contracts; execution on PostgreSQL belongs to final gate."""
import hashlib
import json
from pathlib import Path
import re

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.plugins.file_audit.contracts import CAPABILITIES, REPORT_KEYS

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/183_file_audit_contracts.sql"
SQL = PATH.read_text("utf-8")


def test_transaction_owner_prerequisite_and_unique_next_version():
    assert SQL.strip().startswith("-- Stage 1:") and SQL.strip().endswith("commit;")
    assert "begin;" in SQL and "pg_advisory_xact_lock" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "pg_advisory_xact_lock(hashtext('sli_file_audit_contracts_v183'))" in SQL
    assert "version=182 and name='bundled_ad_gpo_defaults'" in SQL
    assert "where version>=183" in SQL
    assert "migration 183 requires exact migration 182 bundled_ad_gpo_defaults and unused version 183" in SQL
    assert "values(183,'file_audit_contracts')" in SQL
    pairs = [(item.version, item.name) for item in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    position = pairs.index((183, "file_audit_contracts"))
    assert position > 0
    assert pairs[position - 1] == (182, "bundled_ad_gpo_defaults")
    assert sum(version == 183 for version, _ in pairs) == 1


def test_manifest_pins_new_sql_and_its_prerequisite_without_old_checksum_changes():
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.file-audit.json").read_text("utf-8"))
    assert manifest["data"]["migrations"][:1] == [{"version": 183, "name": "file_audit_contracts",
        "path": PATH.relative_to(ROOT).as_posix(), "core_prerequisites": [182],
        "sha256": hashlib.sha256(PATH.read_bytes().replace(b"\r\n", b"\n")).hexdigest()}]


def test_narrow_role_grants_and_immutable_evidence():
    assert "create schema sli_plugin_file_audit authorization adlog_file_audit_owner" in SQL
    assert SQL.count("nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication") == 2
    assert "revoke all on all tables in schema sli_plugin_file_audit from public,adlog_user" in SQL
    grants = re.findall(r"grant\s+.*?;", SQL, re.IGNORECASE | re.DOTALL)
    assert len(grants) == 3
    assert all("to adlog_user" not in grant.lower() and "to public" not in grant.lower() for grant in grants)
    assert not re.search(r"grant\s+.*?\b(update|delete|truncate|all)\b.*?;", SQL, re.IGNORECASE)
    assert "grant adlog_file_audit_owner,adlog_file_audit_runtime to adlog_storage_owner" in SQL
    assert "source_xml" not in SQL and "on delete cascade" not in SQL.lower()


def test_evidence_identity_indexes_and_partial_snapshot_contracts():
    for table in ("settings", "policy_revisions", "observations", "actions", "action_evidence",
                  "access_snapshots", "coverage", "audit_commands", "audit_receipts"):
        assert f"create table sli_plugin_file_audit.{table}" in SQL
    assert "unique(agent_id,source_instance_id,channel,generation,record_id)" in SQL
    assert "core_evidence_ref text not null" in SQL
    assert "evidence_key text references sli_plugin_file_audit.observations" in SQL
    assert "primary key(action_id,core_evidence_ref)" in SQL
    assert "foreign key(command_id,agent_id,source_instance_id,policy_revision,action)" in SQL
    assert "check((client_ip is null)=(client_ip_source is null))" in SQL
    assert "check(completeness<>'complete' or unread_objects=0)" in SQL
    assert "correlation_state text not null default 'not_attempted'" in SQL
    assert "outcome text not null default 'unknown'" in SQL
    assert "check(state<>'verified' or (observed_at is not null and result_sha256 is not null))" in SQL
    for name in ("file_audit_action_subject", "file_audit_action_path", "file_audit_observation_window", "file_audit_coverage_window"):
        assert f"create index {name}" in SQL


def test_owner_defaults_cleanup_block_and_core_owned_findings():
    for text in ("source_payload_days integer not null default 7", "acl_history_days integer not null default 365",
                 "facts_retention text not null default 'permanent'", "check(not file_event_cleanup_enabled)",
                 "mass_operation_files integer not null default 100", "mass_operation_seconds integer not null default 300",
                 "working_time_source text not null default 'sli.settings'", "enabled boolean not null default false"):
        assert text in SQL
    assert "create table sli_plugin_file_audit.findings" not in SQL
    assert "delete from" not in SQL.lower()


def test_report_passports_are_draft_and_no_access_or_agent_assignments_exist():
    for key in REPORT_KEYS:
        assert f"('{key}')" in SQL
    for capability in CAPABILITIES.values():
        assert f"'{capability}'" in SQL
    assert "'restricted','draft'" in SQL and "'published'" not in SQL
    for table in ("access_package_reports", "access_report_assignments", "access_capability_assignments",
                  "access_package_capabilities", "sli_agents", "sli_agent_module_bindings"):
        assert f"insert into public.{table}" not in SQL
        assert f"update public.{table}" not in SQL
