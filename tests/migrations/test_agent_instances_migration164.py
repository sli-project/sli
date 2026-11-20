"""Static migration contract; no database, inventory or checksum edits."""
from pathlib import Path

SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/164_agent_instances.sql").read_text(encoding="utf-8")


def test_exact_predecessor_and_replay_guards_before_ddl():
    header = SQL.split("set local role adlog_storage_owner;")[0]
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in header
    assert "pg_advisory_xact_lock(hashtext('sli_agent_instances_v164'))" in header
    assert "migration 164 requires membership in adlog_storage_owner" in header
    assert "where version=164" in header and "migration 164 already recorded" in header
    assert "version=163 and name='agent_policy_revisions'" in header
    assert "or exists(select 1 from public.schema_migrations where version>163)" in header
    assert "migration 164 requires exact migration 163 agent_policy_revisions" in header
    assert "values(164,'agent_instances')" in SQL
    assert not (Path(__file__).resolve().parents[2] / "config/postgres_migrations/163_agent_instances.sql").exists()
    assert SQL.strip().endswith("commit;")


def test_nullable_names_and_partial_uniqueness_preserve_legacy_rows():
    assert SQL.count("add column instance_name text check(instance_name ~ '^[a-z0-9][a-z0-9_-]{0,47}$')") == 2
    assert "alter table public.sli_agents drop constraint sli_agents_host_id_key" in SQL
    assert "unique index sli_agents_unnamed_host on public.sli_agents(host_id) where instance_name is null" in SQL
    assert "unique index sli_agents_named_host on public.sli_agents(host_id,instance_name) where instance_name is not null" in SQL
    assert "not null" not in SQL.split("add column")[1].split(";")[0]
    assert "delete from" not in SQL and "update public." not in SQL
    assert "grant " not in SQL and "drop table" not in SQL
