"""Forward-only rule schema/privilege contracts; no live PostgreSQL."""
import hashlib
import json
from pathlib import Path
import re

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/187_file_audit_rules.sql"


def test_rules_migration_is_next_transactional_and_manifest_pinned():
    sql = PATH.read_text("utf-8")
    assert sql.startswith("-- Stage 4:") and sql.strip().endswith("commit;")
    assert "pg_advisory_xact_lock(hashtext('sli_file_audit_rules_v187'))" in sql
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
    assert "version=186 and name='file_audit_collection'" in sql
    assert "where version>=187" in sql and "values(187,'file_audit_rules')" in sql
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    position = pairs.index((187, "file_audit_rules"))
    assert position > 0
    assert pairs[position - 1] == (186, "file_audit_collection")
    assert len(pairs) == len({version for version, _ in pairs})
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.file-audit.json").read_text("utf-8"))
    assert manifest["data"]["migrations"][3] == {"version": 187, "name": "file_audit_rules",
        "core_prerequisites": [186], "path": PATH.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(PATH.read_bytes().replace(b"\r\n", b"\n")).hexdigest()}


def test_rules_use_core_findings_with_immutable_scope_bound_evidence():
    sql = PATH.read_text("utf-8")
    assert "insert into public.findings" in sql
    assert "create table sli_plugin_file_audit.findings" not in sql
    for table in ("rule_results", "rule_actions", "rule_snapshots"):
        assert f"create table sli_plugin_file_audit.{table}" in sql
    assert "references public.findings(id)" in sql
    assert "references sli_plugin_file_audit.actions(action_id)" in sql
    assert "references sli_plugin_file_audit.access_snapshots(snapshot_id)" in sql
    assert "file_audit_rule_replay_conflict" in sql
    assert "file_audit_rule_evidence_invalid" in sql
    assert "a.collection_scope_id=v_item->>'collection_scope_id'" in sql
    assert "s.collection_scope_id=v_item->>'collection_scope_id'" in sql
    assert "(p_packet is null)=(p_command is null)" in sql
    assert "i.imported_at is null" in sql and "r.module_id='sli.file-audit'" in sql
    assert "source_xml" not in sql and "delete from" not in sql.lower()
    assert "file_event_cleanup_enabled" not in sql


def test_context_is_bounded_and_only_admitted_functions_are_granted():
    sql = PATH.read_text("utf-8")
    assert sql.count("security definer set search_path=pg_catalog,pg_temp") == 2
    assert "limit 4097" in sql and "limit 101" in sql
    assert "jsonb_array_length(v_actions)<=4096" in sql
    assert "interval '2 days'" in sql
    assert "s.observed_at between p_start-interval '1 day' and p_end" in sql
    grants = re.findall(r"grant\s+[^;]+;", sql, re.I)
    application_grants = [grant for grant in grants if "to adlog_user" in grant]
    assert len(application_grants) == 2
    assert all(grant.startswith("grant execute on function") for grant in application_grants)
    assert all("update" not in grant.lower() and "delete" not in grant.lower() for grant in grants)
    for function in ("rule_context(uuid,uuid,timestamptz,timestamptz)", "publish_rules(uuid,uuid,text,jsonb)"):
        assert f"revoke all on function sli_plugin_file_audit.{function} from public" in sql
