"""Forward migration and least-privilege contracts; no real PostgreSQL."""
from pathlib import Path
import re

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/222_sigma_attack_coverage.sql"
SQL = PATH.read_text("utf-8")


def test_forward_migration_requires_exact_predecessor_and_is_transactional():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((222, "sigma_attack_coverage")) - 1] == (221, "sigma_chain_plugins")
    assert list(PATH.parent.glob("222_*.sql")) == [PATH]
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "version=221 and name='sigma_chain_plugins'" in SQL
    assert "where version>=222" in SQL
    assert "values(222,'sigma_attack_coverage')" in SQL and SQL.strip().endswith("commit;")


def test_scoped_immutable_reporting_retains_generation_root_revision_and_hash():
    assert "array['attack_source_scopes','attack_history_coverage']" in SQL
    assert "alter table sli_sigma.%I enable row level security" in SQL
    assert "using (sli_sigma.scope_allowed(installation_id,plugin_id,source_instance_id,false))" in SQL
    assert "with check (sli_sigma.scope_allowed(installation_id,plugin_id,source_instance_id,true))" in SQL
    assert "array['attack_catalogs','attack_source_scopes','attack_history_coverage']" in SQL
    assert "before update or delete" in SQL and "before truncate" in SQL
    assert "foreign key(installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id)" in SQL
    assert "references sli_sigma.sigma_rule_revisions(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256)" in SQL
    assert "new.coverage_sha256 := encode(sha256(convert_to(new.document_json::text,'UTF8')),'hex');" in SQL
    assert "new.created_at := clock_timestamp();" in SQL
    assert not re.search(r"grant\s+(?:update|delete|truncate|all)\b", SQL, re.I)
    assert not re.search(r"grant adlog_sigma_\w+ to adlog_user", SQL)


def test_runtime_reads_metadata_without_yaml_overlays_or_native_evidence():
    columns = SQL.split("grant select(installation_id,plugin_id,source_instance_id,rule_id,raw_sha256,canonical_sha256,", 1)[1].split(";", 1)[0]
    assert "upstream_commit,status,tags) on sli_sigma.sigma_rule_revisions to adlog_user" in columns
    assert "raw_yaml" not in columns and "canonical_rule" not in columns
    assert "semantic_detection_matches to adlog_user" not in SQL
    assert "finding_evidence_refs" not in SQL and "public.findings" not in SQL


def test_live_reader_exposes_aggregate_columns_only_and_preserves_scope_rls():
    function = SQL.split("create function sli_sigma.read_attack_live_matches", 1)[1].split("$$;", 1)[0]
    assert "security definer set search_path=pg_catalog,pg_temp" in function
    assert "sli_sigma.scope_allowed(p_installation,p_plugin,p_source,false)" in function
    assert "'source_generation',p_generation,'collection_scope_id',p_collection" in function
    assert "d.occurred_at_utc>=p_since and d.occurred_at_utc<p_until" in function
    assert "p_until<=p_since+interval '31 days'" in function
    assert "group by 1,2,3,4,5,6,7" in function and "limit 5001" in function
    assert "native_id" not in function and "entity_key" not in function
    assert "select d.document_json" not in function
    assert "for select to adlog_sigma_owner" in SQL
    assert "grant select(rule_id,occurred_at_utc,document_json) on public.semantic_detection_matches to adlog_sigma_owner;" in SQL
    assert "revoke all on function sli_sigma.read_attack_live_matches(uuid,text,text,text,text,timestamptz,timestamptz) from public;" in SQL
