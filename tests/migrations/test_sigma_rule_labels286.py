"""Narrow label reader source contract; no production database."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_exact_predecessor_and_only_bounded_label_execute_grant():
    sql = (ROOT / "config/postgres_migrations/286_sigma_rule_labels.sql").read_text("utf-8")
    assert "version=285 and name='report_producer'" in sql
    assert "version>=286" in sql and "values(286,'sigma_rule_labels')" in sql
    assert "security definer set search_path=pg_catalog,pg_temp" in sql
    assert "sli_sigma.scope_allowed(p_installation,p_plugin,p_source,false)" in sql
    assert "r.rule_id=p_rule and r.raw_sha256=p_raw_sha256" in sql
    assert "512" in sql and "4000" in sql and "limit 1" in sql
    assert "to adlog_user" in sql and "from public" in sql
    assert "grant select" not in sql.lower() and "raw_yaml" not in sql


def test_rollback_removes_only_the_new_function_and_exact_marker():
    sql = (ROOT / "config/postgres_migrations/286_sigma_rule_labels.rollback.sql").read_text("utf-8")
    assert "drop function sli_sigma.read_rule_labels(uuid,text,text,uuid,text)" in sql
    assert "version=286 and name='sigma_rule_labels'" in sql
