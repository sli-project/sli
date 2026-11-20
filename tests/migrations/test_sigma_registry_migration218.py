"""Forward schema and least-privilege contracts; no live PostgreSQL."""
from pathlib import Path
import re

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/218_sigma_registry.sql"
SQL = PATH.read_text("utf-8")
TABLES = ("sigma_rule_revisions", "sigma_source_requirements", "sigma_rule_overlays")


def test_new_migration_is_transactional_and_requires_exact_predecessor():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((218, "sigma_registry")) - 1] == (217, "agent_inbox_quota_payload_bytes")
    assert list(PATH.parent.glob("218_*.sql")) == [PATH]
    assert len(pairs) == len({number for number, _ in pairs})
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "version=217 and name='agent_inbox_quota_payload_bytes'" in SQL
    assert "where version>=218" in SQL
    assert "pg_advisory_xact_lock(hashtext('sli_sigma_registry_v218'))" in SQL
    assert "values(218,'sigma_registry')" in SQL and SQL.strip().endswith("commit;")


def test_roles_have_no_login_or_elevated_privileges_and_no_runtime_memberships():
    for role in ("owner", "reader", "writer"):
        assert f"create role adlog_sigma_{role} nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication;" in SQL
        assert f"to_regrole('adlog_sigma_{role}') is not null" in SQL
    memberships = re.findall(r"^grant adlog_sigma_[^;]+;", SQL, re.M)
    assert memberships == ["grant adlog_sigma_owner to adlog_storage_owner;"]
    assert "revoke all on schema sli_sigma from public,adlog_user;" in SQL
    assert "grant usage on schema sli_sigma to adlog_sigma_reader,adlog_sigma_writer;" in SQL
    assert not re.search(r"grant[^;]+to (?:public|adlog_user)\b", SQL, re.I)
    assert "set local role adlog_sigma_owner;" in SQL


def test_scope_acl_cannot_be_spoofed_with_a_role_switch_or_request_setting():
    guard = SQL.split("create function sli_sigma.scope_allowed", 1)[1].split("$$;", 1)[0]
    assert "security definer set search_path=pg_catalog,pg_temp" in guard
    assert "r.oid=a.principal_oid and r.rolname=a.principal_name" in guard
    assert "r.rolname=session_user" in guard
    for comparison in ("a.installation_id=p_installation", "a.plugin_id=p_plugin", "a.source_instance_id=p_source"):
        assert comparison in guard
    assert "and (not p_write or a.can_write)" in guard
    assert "current_user" not in guard and "current_setting" not in SQL
    assert "revoke all on sli_sigma.scope_access from public,adlog_user,adlog_sigma_reader,adlog_sigma_writer;" in SQL
    assert "revoke all on function sli_sigma.scope_allowed(uuid,text,text,boolean) from public;" in SQL


@pytest.mark.parametrize("table", TABLES)
def test_every_registry_table_has_scope_rls_and_immutable_triggers(table):
    assert f"create table sli_sigma.{table}" in SQL
    assert f"'{table}'" in SQL.split("foreach t in array array[", 1)[1].split("] loop", 1)[0]
    assert "alter table sli_sigma.%I enable row level security" in SQL
    assert "for select to adlog_sigma_reader,adlog_sigma_writer" in SQL
    assert "using (sli_sigma.scope_allowed(installation_id,plugin_id,source_instance_id,false))" in SQL
    assert "for insert to adlog_sigma_writer" in SQL
    assert "with check (sli_sigma.scope_allowed(installation_id,plugin_id,source_instance_id,true))" in SQL
    assert "before update or delete on sli_sigma.%I" in SQL and "before truncate on sli_sigma.%I" in SQL
    assert "sigma_registry_immutable' using errcode='42501'" in SQL
    assert not re.search(r"grant\s+(?:update|delete|truncate|all)\b", SQL, re.I)


def test_foreign_keys_cannot_reference_another_installation_plugin_or_source():
    assert "foreign key(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256)" in SQL
    assert "references sli_sigma.sigma_rule_revisions(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256)" in SQL
    assert "foreign key(installation_id,plugin_id,source_instance_id,rule_id,base_raw_sha256,base_canonical_sha256)" in SQL
    assert "references sli_sigma.sigma_rule_revisions(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256,canonical_sha256)" in SQL
    assert "primary key(installation_id,plugin_id,source_instance_id,overlay_id,version)" in SQL
    assert "on delete cascade" not in SQL and "delete from" not in SQL


def test_hashes_provenance_attribution_requirements_and_overlay_expiry_are_retained():
    for field in ("raw_sha256", "canonical_sha256", "requirements_sha256", "overlay_sha256"):
        assert f"new.{field} := encode(sha256(convert_to(" in SQL
    assert "before insert on sli_sigma.%I" in SQL
    assert "new.created_by := session_user;" in SQL and "new.created_at := clock_timestamp();" in SQL
    assert "canonical_rule->>'id' is not distinct from rule_id::text" in SQL
    for field in ("author", "license", "source_uri", "status", "level", "tags", "requirements", "reason", "mapping_version"):
        assert f"{field} " in SQL
    assert "isfinite(expires_at) and expires_at>created_at" in SQL
    assert "new.expires_at at time zone 'UTC'" in SQL
    # Importers cannot supply hashes, timestamps or recorded authorship.
    inserts = re.findall(r"grant insert\((.*?)\)\s+on sli_sigma\.(\w+) to adlog_sigma_writer;", SQL, re.S)
    assert {table for _, table in inserts} == set(TABLES)
    for columns, _ in inserts:
        assert "created_by" not in columns and "created_at" not in columns
        assert "overlay_sha256" not in columns and "canonical_sha256," not in columns.replace("base_canonical_sha256,", "")


def test_overlay_dialect_is_bounded_structured_and_cannot_execute_supplied_text():
    validator = SQL.split("create function sli_sigma.valid_overlay", 1)[1].split("end $$;", 1)[0]
    assert "p->>'version' is distinct from 'sli.sigma.overlay.v1'" in validator
    assert "p - 'version' - 'all_of' <> '{}'::jsonb" in validator
    assert "v - 'field' - 'equals' <> '{}'::jsonb" in validator
    assert "not between 1 and 32" in validator and "octet_length(p::text)>65536" in validator
    assert "octet_length(v::text)>8192" in validator
    assert "not in ('string','number','boolean','null')" in validator
    assert "execute" not in validator and "check(sli_sigma.valid_overlay(predicate))" in SQL
    assert "public.findings" not in SQL and "grant select on public." not in SQL
