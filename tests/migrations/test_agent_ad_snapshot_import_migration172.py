"""Migration 172 state and privilege boundary; no DB or applied SQL changes."""
from pathlib import Path
import re

SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/172_agent_ad_snapshot_import.sql").read_text("utf-8")


def test_exact_predecessor_and_separate_atomic_publication_state():
    assert "version=171 and name='agent_windows_audit'" in SQL
    assert "version>=172" in SQL
    assert "values(172,'agent_ad_snapshot_import')" in SQL
    assert "publication_state text not null default 'pending'" in SQL
    assert "manifest_id uuid references public.ad_snapshot_manifests(manifest_id)" in SQL
    assert "module_id='sli.ad-snapshot' and transport_state='complete'" in SQL


def test_import_privileges_only_on_existing_trusted_worker_and_no_activation():
    assert "to adlog_context_worker" in SQL
    assert "grant update(id) on public.sli_agents" in SQL
    assert not re.search(r"grant .*?to (?:public|adlog_user)\s*;", SQL, re.I | re.S)
    assert not re.search(r"grant (?:delete|truncate|all)|grant adlog_context_worker", SQL, re.I)
    assert not re.search(r"update (?:public\.)?sli_agent_snapshot_bindings|insert into (?:public\.)?sli_agents", SQL)


def test_manifest_reference_and_agent_provenance_are_admitted_without_removing_legacy():
    assert SQL.index("grant references(manifest_id)") < SQL.index("set local role adlog_storage_owner")
    assert SQL.index("reset role") < SQL.index("alter table public.computers_v6_source_snapshots")
    assert "collector_version='sli-agent/ad-snapshot/1'" in SQL
    assert "collector_sha256=sha256(convert_to('sli-agent/ad-snapshot/1','UTF8'))" in SQL
    assert "collector_sha256=decode('caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5','hex')" in SQL
