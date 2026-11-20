"""Migration 167 predecessor and least privilege contract, without a real DB."""
from pathlib import Path
import re

SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/167_agent_updates.sql").read_text("utf-8")


def test_exact_predecessor_and_additive_schema():
    header, _ = SQL.split("set local role adlog_storage_owner;", 1)
    assert "sli_agent_updates_v167" in header
    assert "version=167" in header
    assert "version=166 and name='registered_plugin_activation'" in header
    assert "migration 167 already recorded" in header
    assert "or exists(select 1 from public.schema_migrations where version>166)" in header
    assert "migration 167 requires exact migration 166 registered_plugin_activation" in header
    assert "requires membership in adlog_storage_owner" in header
    assert "values(167,'agent_updates')" in SQL
    for table in ("sli_agent_update_packages", "sli_agent_update_policy", "sli_agent_update_results"):
        assert f"create table public.{table}" in SQL
    assert "octet_length(archive) between 1 and 268435456" in SQL
    assert "primary key(agent_id,package_sha256,status,reason_key)" in SQL
    assert "reason_key text generated always as (coalesce(reason,'')) stored" in SQL
    assert "check((status='updated')=(reason is null))" in SQL


def test_runtime_cannot_modify_packages_or_delete_update_evidence():
    grants = re.findall(r"grant[^;]+;", SQL)
    assert grants == [
        "grant select,insert on public.sli_agent_update_packages, public.sli_agent_update_policy, public.sli_agent_update_results to adlog_user;",
        "grant update(package_sha256) on public.sli_agent_update_policy to adlog_user;",
    ]
    assert "revoke all on public.sli_agent_update_packages" in SQL
    assert "delete from" not in SQL.lower()
    for action in ("update_upload", "update_list", "update_assign", "update_result", "module_assign",
                   "policy_ack", "probe_request", "probe_report"):
        assert f"'{action}'" in SQL
