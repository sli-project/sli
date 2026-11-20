"""Forward-only evidence contracts; no database or source access."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/236_file_audit_evidence.sql").read_text("utf-8")


def test_migration_is_forward_only_and_preserves_definer_boundary():
    versions = [(m.version, m.name) for m in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    position = versions.index((236, "file_audit_evidence"))
    assert versions[position - 1] == (235, "semantic_claim_order_index")
    assert len(versions) == len({version for version, _ in versions})
    assert "version=235 and name='semantic_claim_order_index'" in SQL
    assert "where version>=236" in SQL and SQL.strip().endswith("commit;")
    assert "set local role adlog_file_audit_owner;" in SQL
    assert "check(operation in ('access_check','read','write','delete_right','delete','rename'," in SQL
    assert SQL.count("security definer set search_path=pg_catalog,pg_temp") == 2
    assert "grant select(sequence,received_at) on public.sli_agent_receipts to adlog_file_audit_owner" in SQL
    assert "grant select" not in SQL.split("to adlog_file_audit_owner;", 1)[1]
    assert "to adlog_user;" in SQL and "from public;" in SQL
    assert "update sli_plugin_file_audit.actions" not in SQL.lower()


def test_action_fast_path_filters_typed_rows_and_enriches_only_the_page():
    fast = SQL.split("if p_tab in ('actions','access-denials','permission-changes') then", 1)[1].split("    end if;", 1)[0]
    filtered = fast.split("filtered as materialized (", 1)[1].split("), page as materialized", 1)[0]
    assert "to_jsonb" not in filtered and "action_evidence" not in filtered
    assert "using(agent_id,source_instance_id,collection_scope_id)" in filtered
    for condition in ("a.observed_at>=p_start and a.observed_at<p_end", "a.subject_sid=p_employee",
                      "a.operation=p_operation", "a.outcome='failure'", "p_nested"):
        assert condition in filtered
    assert "(observed_at,action_id)<((p_after->>'at')::timestamptz,p_after->>'id')" in fast
    assert "'filtered_count',(select count(*) from filtered)" in fast
    assert "'has_more',(select count(*)>p_limit from page)" in fast
    assert "where e.action_id=q.action_id" in fast
    assert "from (select * from page order by observed_at desc,action_id desc limit p_limit) q" in fast
    assert "'path',o.normalized->>'path'" in fast
    assert "return v_result;" in fast


def test_audit_masks_are_append_only_and_delivery_is_source_bound():
    assert "add column required_masks jsonb" in SQL and "add column actual_masks jsonb" in SQL
    assert "v_item->'required_masks',v_item->'actual_masks'" in SQL
    assert "on conflict(receipt_id) do nothing" in SQL
    assert "update sli_plugin_file_audit.audit_receipts" not in SQL.lower()
    for field in ("delivery_received_at", "delivery_imported_at", "delivery_record_id"):
        assert f"'{field}'" in SQL
    assert "receipt.agent_id=r.agent_id and receipt.module_id='sli.file-audit'" in SQL
    assert "receipt.envelope->>'source_instance_id'=r.source_instance_id" in SQL
    assert "order by receipt.sequence desc limit 1" in SQL
    assert "d on p_tab='audit-state'" in SQL
