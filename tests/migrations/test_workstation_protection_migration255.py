"""WR06 migration contract: immutable predecessors and bounded history index."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/255_workstation_protection_predecessor.sql"


def test_protection_history_index_is_guarded_and_attested():
    sql = PATH.read_text("utf-8")
    assert "version=254 and name='workstation_projection_queue'" in sql
    assert "version>=255" in sql
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
    assert "pg_advisory_xact_lock" in sql and "set local lock_timeout='5s'" in sql
    assert "on sli_plugin_workstations.projection_work(agent_key,work_id desc)" in sql
    assert "where kind='protection_state'" in sql
    assert "grant select(station_id,protection) on sli_plugin_workstations.station_summary to sli_job_executor_light;" in sql
    assert sql.lower().count("grant ") == 1 and "drop " not in sql.lower()
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.workstations.json").read_text("utf-8"))
    entry = next(row for row in manifest["data"]["migrations"] if row["version"] == 255)
    assert entry == {"version": 255, "name": "workstation_protection_predecessor",
        "path": PATH.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(PATH.read_bytes()).hexdigest(),
        "core_prerequisites": [254]}
