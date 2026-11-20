from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "config/postgres_migrations"


def test_predecessor_and_migration_number_are_exact_and_unique():
    files = list(MIGRATIONS.glob("176_*.sql"))
    assert [path.name for path in files] == ["176_workstation_history.sql"]
    sql = files[0].read_text(encoding="utf-8")
    assert "version=174 and name='agent_gpo_snapshot_import'" in sql
    assert "version>=176" in sql
    assert "values(176,'workstation_history')" in sql
    assert (MIGRATIONS / "174_agent_gpo_snapshot_import.sql").is_file()


def test_holds_restrict_deletion_and_no_schedule_or_membership_is_enabled():
    sql = (MIGRATIONS / "176_workstation_history.sql").read_text(encoding="utf-8")
    assert "references sli_plugin_workstations.observations(id) on delete restrict" in sql
    assert "primary key (observation_id,reason)" in sql
    assert "('legal_hold','evidence_reference')" in sql
    assert "grant select on sli_plugin_workstations.observation_holds to adlog_workstations_retention" in sql
    assert "grant select(source_xml) on sli_plugin_workstations.observations to adlog_user" in sql
    assert "grant adlog_workstations_retention" not in sql
    assert "insert into public.core_job" not in sql


def test_history_schema_is_permanent_and_idempotent_by_immutable_id():
    sql = (ROOT / "config/clickhouse/005_workstation_history.sql").read_text(encoding="utf-8")
    assert "ENGINE = ReplacingMergeTree" in sql and "ORDER BY id" in sql
    assert "TTL" not in sql and "PARTITION BY" not in sql
    assert "payload_json String" in sql and "payload_sha256 FixedString(64)" in sql
    assert "fsync_after_insert = 1" in sql and "fsync_part_directory = 1" in sql
