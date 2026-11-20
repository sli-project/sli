"""WR10 storage/privilege contract; no database or source connection."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/258_workstation_device_seen.sql"


def test_device_projection_migration_is_guarded_and_attested():
    sql = PATH.read_text("utf-8")
    assert "version=255 and name='workstation_protection_predecessor'" in sql
    assert "version=254 and name='workstation_projection_queue'" in sql
    assert "version=257 and name='semantic_legacy_admission'" in sql
    assert "version>=258" in sql
    assert "sli_workstation_device_seen_v258" in sql
    assert "migration 258 prerequisites failed" in sql
    assert "values(258,'workstation_device_seen')" in sql
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
    assert "pg_advisory_xact_lock" in sql and "set local lock_timeout='5s'" in sql
    assert "set local role adlog_storage_owner;" in sql
    assert "primary key(station_id,device_key)" in sql
    assert "primary key(station_id,device_key,observed_at)" in sql
    assert "on sli_plugin_workstations.device_seen_occurrences(station_id,observed_at,device_key)" in sql
    assert "identity_quality='station_instance'" in sql
    assert "storage_evidence boolean not null check(storage_evidence)" in sql
    assert "last_seen_at>=first_seen_at" in sql
    assert "references sli_plugin_workstations.observations" not in sql
    assert sql.count("execute function sli_plugin_workstations.guard_projection_publication()") == 2
    assert "from public,adlog_user;" in sql
    assert "grant select,insert,update on sli_plugin_workstations.device_seen to sli_job_publisher_light;" in sql
    assert "grant select,insert on sli_plugin_workstations.device_seen_occurrences to sli_job_publisher_light;" in sql
    assert "grant select on sli_plugin_workstations.device_seen,sli_plugin_workstations.device_seen_occurrences to adlog_user;" in sql
    assert "grant all" not in sql and "grant delete" not in sql and "cascade" not in sql
    assert "alter table" not in sql and "drop " not in sql
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.workstations.json").read_text("utf-8"))
    entry = next(row for row in manifest["data"]["migrations"] if row["version"] == 258)
    assert entry == {"version": 258, "name": "workstation_device_seen",
        "path": PATH.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(PATH.read_bytes()).hexdigest(),
        "core_prerequisites": [257]}
