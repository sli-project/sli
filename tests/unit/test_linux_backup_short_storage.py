from __future__ import annotations

from deploy.linux import backup


def test_backup_captures_short_storage_counts_without_retired_event_tables():
    counts = {
        "schema_migrations": 1,
        "event_hot": 2,
        "event_cold_facts": 3,
        "event_cold_daily": 1,
        "storage_v2_event_identity_allocations": 5,
        "ad_snapshot_change_history": 4,
        "finding_event_copies337": 1,
        "entities_v2": 6,
    }

    class Database:
        def execute(self, query):
            name = query.as_string().split('public."', 1)[1].split('"', 1)[0]
            return self.Result(counts[name])

        class Result:
            def __init__(self, count):
                self.count = count

            def fetchone(self):
                return (self.count,)

    captured = backup.row_counts(Database())
    assert captured == counts


def test_native_backups_do_not_request_clickhouse(monkeypatch):
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    monkeypatch.delenv("SLI_BACKUP_FILES_ROOT", raising=False)
    assert backup.default_components() == ("postgres",)
    assert backup.clickhouse_targets() == ()
    monkeypatch.setenv("SLI_BACKUP_FILES_ROOT", "/srv/sli/files")
    assert backup.default_components() == ("postgres", "files")
