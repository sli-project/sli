"""Additive migration/privilege contracts; no applied checksum is replaced."""
import hashlib
import json
from pathlib import Path
import re

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/185_file_audit_management.sql"
SQL = PATH.read_text("utf-8")
PLUGIN_TABLE_GRANT = re.compile(
    r"grant\s+(?:select|insert|update|delete|all)\b[^;]*?\bon\s+(?:table\s+)?sli_plugin_file_audit\.",
    re.I | re.S,
)


def test_exact_predecessor_transaction_and_free_version():
    assert "begin;" in SQL and SQL.strip().endswith("commit;")
    assert "pg_advisory_xact_lock(hashtext('sli_file_audit_management_v185'))" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "version=184 and name='agent_update_waves'" in SQL and "where version>=185" in SQL
    assert "migration 185 requires exact migration 184 agent_update_waves and unused version 185" in SQL
    assert "values(185,'file_audit_management')" in SQL
    assert [p.name for p in PATH.parent.glob("185_*.sql")] == [PATH.name]
    pairs = [(item.version, item.name) for item in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    position = pairs.index((185, "file_audit_management"))
    assert position > 0
    assert pairs[position - 1] == (184, "agent_update_waves")
    assert sum(version == 185 for version, _ in pairs) == 1


def test_manifest_adds_new_checksum_and_preserves_existing_migration_identity():
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.file-audit.json").read_text("utf-8"))
    assert manifest["data"]["migrations"][1:2] == [{"version": 185, "name": "file_audit_management",
        "path": PATH.relative_to(ROOT).as_posix(), "core_prerequisites": [184],
        "sha256": hashlib.sha256(PATH.read_bytes().replace(b"\r\n", b"\n")).hexdigest()}]
    original = manifest["data"]["migrations"][0]
    assert original["version"] == 183 and original["core_prerequisites"] == [182]
    assert original["sha256"] == hashlib.sha256((ROOT / original["path"]).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_core_unknown_state_is_bounded_with_column_update_only():
    assert "add column file_audit jsonb not null default '{}'::jsonb" in SQL
    assert "octet_length(file_audit::text)<=131072" in SQL
    assert "grant update(file_audit) on public.sli_agents to adlog_user" in SQL
    assert "grant select(id,host_id,policy_revision,status,file_audit)" in SQL
    assert "grant adlog_file_audit" not in SQL


def test_definer_boundary_has_pinned_search_path_and_no_public_execute():
    assert SQL.count("security definer set search_path=pg_catalog,pg_temp") == 3
    assert "set local role adlog_file_audit_owner" in SQL
    assert "revoke all on function sli_plugin_file_audit.enqueue_audit" in SQL
    assert "revoke all on function sli_plugin_file_audit.store_audit_result" in SQL
    assert "grant execute on function sli_plugin_file_audit.enqueue_audit" in SQL
    assert "grant execute on function sli_plugin_file_audit.store_audit_result" in SQL
    assert not PLUGIN_TABLE_GRANT.search(SQL)


@pytest.mark.parametrize("sql,forbidden", [
    ("grant update(file_audit) on public.sli_agents to adlog_user;\n"
     "grant usage on schema sli_plugin_file_audit to adlog_user;\n"
     "grant execute on function sli_plugin_file_audit.audit_request(uuid,text) to adlog_user;", False),
    ("grant select(id) on public.sli_agents to adlog_file_audit_owner;\n"
     "revoke all on function sli_plugin_file_audit.audit_request(uuid,text) from public;", False),
    ("grant select on sli_plugin_file_audit.audit_commands to adlog_user;", True),
    ("GRANT INSERT, UPDATE\nON TABLE sli_plugin_file_audit.audit_commands TO adlog_user;", True),
    ("grant update(action) on sli_plugin_file_audit.audit_commands to adlog_user;", True),
    ("grant all privileges on table sli_plugin_file_audit.audit_commands to public;", True),
    ("grant delete on sli_plugin_file_audit.audit_commands to adlog_user;", True),
])
def test_plugin_table_grant_check_stays_within_one_statement(sql, forbidden):
    assert bool(PLUGIN_TABLE_GRANT.search(sql)) is forbidden


def test_commands_are_revision_bound_and_receipts_snapshots_append_only():
    assert "policy_revision+1=v_revision" in SQL and "host_id::text=p_source" in SQL
    assert "c.agent_id=p_agent and a.status='active'" in SQL
    assert "where c.agent_id=p_agent and c.command_id=p_command" in SQL
    assert SQL.count("=any(v_command.collection_scope_ids)") == 2
    assert "on conflict(snapshot_id) do nothing" in SQL
    assert "on conflict(receipt_id) do nothing" in SQL
    assert "update sli_plugin_file_audit" not in SQL.lower()
    assert "delete from" not in SQL.lower() and "on delete cascade" not in SQL.lower()
