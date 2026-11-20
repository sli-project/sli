from pathlib import Path

import pytest

from server.sli.entities.entity_identity_merge import (
    confirmation_token,
    record_scenario_identity_supersessions,
)


ROOT = Path(__file__).resolve().parents[2]
FORWARD = (ROOT / "config/postgres_migrations/068_entity_identity_merge_r7.sql").read_text(encoding="utf-8").lower()
ROLLBACK = (ROOT / "config/postgres_migrations/068_entity_identity_merge_r7.rollback.sql").read_text(encoding="utf-8").lower()
REPAIR = (ROOT / "config/postgres_migrations/069_entity_identity_runtime_repair.sql").read_text(encoding="utf-8").lower()
REPAIR_ROLLBACK = (ROOT / "config/postgres_migrations/069_entity_identity_runtime_repair.rollback.sql").read_text(encoding="utf-8").lower()
BOUNDED_LOOKUP = (ROOT / "config/postgres_migrations/070_entity_identity_bounded_lookup.sql").read_text(encoding="utf-8").lower()
BOUNDED_LOOKUP_ROLLBACK = (ROOT / "config/postgres_migrations/070_entity_identity_bounded_lookup.rollback.sql").read_text(encoding="utf-8").lower()
REPORTING = (ROOT / "server/sli/reporting/reporting_v4.py").read_text(encoding="utf-8").lower()
WORKSPACE = (ROOT / "server/sli/semantic/semantic_workspace.py").read_text(encoding="utf-8").lower()


def test_migration_68_is_append_only_and_blocks_source_resurrection() -> None:
    assert "entity_identity_merges_v2" in FORWARD
    assert "entity_identity_merge_events_v2" in FORWARD
    assert "entity_identity_semantic_replays_v2" in FORWARD
    assert "before update or delete" in FORWARD
    assert "reject_merged_entity_link_block" in FORWARD
    assert "resolve_entity_identity_v2" in FORWARD
    assert "entities_v2_active" in FORWARD
    assert "entity_identity_finding_supersessions_v2" in FORWARD
    assert "findings_active" in FORWARD
    assert "merged_observation.first_seen_utc" in FORWARD
    assert "merged_observation.last_seen_utc" in FORWARD
    assert "rollback blocked by immutable r7 evidence" in ROLLBACK


def test_runtime_gate_uses_exact_migration_marker_not_max_version() -> None:
    assert "version=68 and name='entity_identity_merge_r7'" in WORKSPACE
    assert "runtime_marker >= 68" not in WORKSPACE


def test_migration_69_repairs_the_view_without_exposing_merge_evidence() -> None:
    assert "security definer" in REPAIR
    assert "set search_path=pg_catalog,public" in REPAIR
    assert "public.entity_identity_merges_v2" in REPAIR
    assert "grant select on entity_identity_merges_v2 to adlog_storage_worker" not in REPAIR
    assert "left join lateral" not in REPAIR
    assert "group by merged.target_entity_id" in REPAIR
    assert "values(69,'entity_identity_runtime_repair')" in REPAIR
    assert "rollback 069 is forbidden" in REPAIR_ROLLBACK
    assert "security definer" in REPAIR
    assert "reject_merged_entity_link_block" in REPAIR
    assert "grant select on entity_identity_merges_v2 to adlog_storage_worker" not in REPAIR




def test_migration_70_exposes_only_a_bounded_active_decision() -> None:
    assert "security definer" in BOUNDED_LOOKUP
    assert "set search_path=pg_catalog,public" in BOUNDED_LOOKUP
    assert "returns boolean" in BOUNDED_LOOKUP
    assert "grant execute on function entity_v2_is_active(bigint) to adlog_user" in BOUNDED_LOOKUP
    assert "grant select on entity_identity_merges_v2 to adlog_user" not in BOUNDED_LOOKUP
    assert "values(70,'entity_identity_bounded_lookup')" in BOUNDED_LOOKUP
    assert "rollback 070 is forbidden" in BOUNDED_LOOKUP_ROLLBACK




def test_bounded_ad_reports_do_not_expand_the_security_barrier_view() -> None:
    privileged = REPORTING.split("elif dataset_key == \"ad.accounts.privileged\":", 1)[1].split("elif dataset_key == \"ad.accounts.vpn\":", 1)[0]
    assert "join entities_v2 source_entity" in privileged
    assert "join entities_v2 target_entity" in privileged
    assert "_active_entity_predicate('source_entity', 'target_entity')" in privileged
    assert "entities_v2_active" not in privileged


def test_merge_executor_is_storage_v2_only() -> None:
    source = (ROOT / "server/sli/entities/entity_identity_merge.py").read_text(encoding="utf-8").lower()
    assert "observed_entities" not in source
    assert "event_entity_links " not in source
    assert "from entities_v2 entity" in source
    assert "entity_details_v2" in source
    assert "storage_v2_entity_type" in source
    assert "normalized.source_event_id=any(%s::bigint[])" in source
    assert "normalized.source_event_id=any(%s::integer[])" not in source


def test_merge_requires_exact_source_target_confirmation() -> None:
    assert confirmation_token(10, 20) == "MERGE-PROVISIONAL-R7-10-INTO-20"
    assert "source_event_sha256" in (
        ROOT / "server/sli/entities/entity_identity_merge.py"
    ).read_text(encoding="utf-8")


def test_confirmation_token_rejects_non_integer_ids() -> None:
    with pytest.raises(ValueError):
        confirmation_token("source", 20)  # type: ignore[arg-type]


def test_scenario_supersession_types_uuid_parameters_in_insert_select() -> None:
    class Cursor:
        rowcount = 0

        def __init__(self) -> None:
            self.calls = []
            self._available = False

        def execute(self, sql, params=()) -> None:
            self.calls.append((str(sql), params))
            self._available = "to_regclass" in str(sql)

        def fetchone(self):
            return {"available": True} if self._available else None

    cur = Cursor()
    scenario_id = "00000000-0000-4000-8000-000000000123"

    record_scenario_identity_supersessions(cur, new_scenario_id=scenario_id)

    statement, params = cur.calls[-1]
    assert statement.count("%s::uuid") == 4
    assert params == (scenario_id, scenario_id, scenario_id, scenario_id)
