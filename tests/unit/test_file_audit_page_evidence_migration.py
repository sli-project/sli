"""Read-contract checks for the bounded evidence migration; no database access."""
from pathlib import Path


def test_evidence_enrichment_happens_after_page_selection_without_changing_scope_or_totals():
    sql = (Path(__file__).resolve().parents[2] /
           "config/postgres_migrations/212_file_audit_page_evidence.sql").read_text(encoding="utf-8")
    actions = sql.split("), candidates as materialized (", 1)[1].split("union all", 1)[0]
    assert "from scoped_actions a" in actions
    assert "action_evidence" not in actions and "observations" not in actions
    final = sql.split("select jsonb_build_object('items'", 1)[1]
    assert "where e.action_id=q.id" in final
    assert "from (select * from page order by observed_at desc,id desc limit p_limit) q" in final
    assert "p_tab in ('actions','access-denials','permission-changes')" in final
    for field in ("reference", "event_id", "record_id", "generation", "role", "payload_sha256"):
        assert f"'{field}'" in final
    assert "'filtered_count',(select count(*) from filtered)" in final
    assert "'has_more',(select count(*)>p_limit from page)" in final
    assert "join roots r\n          using(agent_id,source_instance_id,collection_scope_id)" in sql
    assert "(observed_at,id)<((p_after->>'at')::timestamptz,p_after->>'id')" in sql


def test_replacement_keeps_definer_and_existing_execution_boundary():
    sql = (Path(__file__).resolve().parents[2] /
           "config/postgres_migrations/212_file_audit_page_evidence.sql").read_text(encoding="utf-8")
    assert "set local role adlog_file_audit_owner;" in sql
    assert "create or replace function sli_plugin_file_audit.report_rows(" in sql
    assert "stable security definer set search_path=pg_catalog,pg_temp" in sql
    assert "revoke all on function sli_plugin_file_audit.report_rows(" in sql
    assert "to adlog_user;" in sql
    assert "version=211 and name='core_job_deadline_recovery'" in sql
    assert "version>=212" in sql
