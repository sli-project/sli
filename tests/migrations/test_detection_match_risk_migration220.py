"""Additive detection-input schema/ACL contracts without a live database."""
from pathlib import Path
import re

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/220_detection_match_risk.sql"
SQL = PATH.read_text("utf-8")


def test_migration_order_transaction_and_default_dormancy():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((220, "detection_match_risk")) - 1] == (219, "finding_evidence_refs")
    assert list(PATH.parent.glob("220_*.sql")) == [PATH]
    assert len(pairs) == len({version for version, _ in pairs})
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    for fragment in ("pg_advisory_xact_lock", "pg_has_role(session_user,'adlog_storage_owner','MEMBER')",
                     "version=219 and name='finding_evidence_refs'", "where version>=220",
                     "set local role adlog_storage_owner", "values(220,'detection_match_risk')"):
        assert fragment in SQL
    assert not re.search(r"insert into (?:public\.)?(?:semantic_risk_policies|semantic_policy_admission|findings)\b", SQL)


def test_detection_is_distinct_from_native_actions_and_has_restrictive_lineage():
    for table in ("semantic_risk_policies", "semantic_risk_policy_subscriptions", "semantic_risk_evaluation_jobs",
                  "semantic_scenario_steps", "semantic_risk_contributions"):
        section = SQL.split(f"alter table public.{table}\n", 1)[1].split(";", 1)[0]
        assert "'canonical_action','correlation_candidate','control_health','detection_match'" in section
        if table not in ("semantic_risk_policies", "semantic_risk_policy_subscriptions"):
            assert "detection_match_id text references public.semantic_detection_matches(match_id) on delete restrict" in section
            native, detection = section.rsplit("or (source_kind='detection_match'", 1)
            assert native.count("detection_match_id is null") == 3
            assert "canonical_action_id is null" in detection and "correlation_candidate_id is null" in detection
            assert "control_health_id is null" in detection if table.endswith("jobs") else "control_reference is null" in detection
    assert not re.search(r"(?:alter table|insert into) (?:public\.)?(?:canonical_actions|events_v2_core|normalized_events)\b", SQL)


def test_input_is_bounded_immutable_and_scoped_to_login_bound_native_evidence():
    for fragment in ("match_id ~ '^[a-f0-9]{64}$'", "evidence_key ~ '^[a-f0-9]{64}$'",
                     "octet_length(document_json::text)<=16384", "'observed'", "'good'", "'false'::jsonb",
                     "before update or delete", "before truncate", "enable row level security",
                     "using (public.finding_evidence_scope_allowed(", "with check (public.resolve_finding_evidence_ref("):
        assert fragment in SQL
    for key in ("installation_id", "plugin_id", "source_instance_id", "source_generation", "collection_scope_id",
                "storage_kind", "native_id", "sha256"):
        assert key in SQL
    assert "grant select,insert on public.semantic_detection_matches to adlog_semantic_worker" in SQL
    assert not re.search(r"grant\s+(?:update|delete|truncate|all)[^;]+semantic_detection_matches", SQL, re.I)
    assert "create policy detection_match_scope on public.semantic_detection_matches to adlog_semantic_worker" in SQL
    assert not re.search(r"grant[^;]+to (?:public|adlog_user)\b", SQL, re.I)
