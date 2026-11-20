from pathlib import Path


FORWARD = Path(
    "config/postgres_migrations/077_storage_lifecycle_runtime_maintenance.sql"
)
ROLLBACK = Path(
    "config/postgres_migrations/077_storage_lifecycle_runtime_maintenance.rollback.sql"
)


def test_migration_77_registers_lifecycle_and_tunes_only_ordinary_autovacuum() -> None:
    forward = FORWARD.read_text(encoding="utf-8").casefold()
    rollback = ROLLBACK.read_text(encoding="utf-8").casefold()

    assert "storage_lifecycle" in forward
    assert "autovacuum_vacuum_scale_factor = 0.01" in forward
    assert "autovacuum_vacuum_threshold = 50000" in forward
    assert "autovacuum_analyze_scale_factor = 0.02" in forward
    assert "autovacuum_analyze_threshold = 50000" in forward
    assert "delete from events_v2_core" not in forward
    assert "vacuum full" not in forward
    assert "repack" not in forward
    assert "where worker_name='storage_lifecycle'" in rollback
    assert "reset (" in rollback




def test_storage_lifecycle_snapshot_selects_v2_after_physical_v1_drop() -> None:
    from server.sli.storage import storage_lifecycle

    class Cursor:
        def execute(self, _sql, _params=()):
            return None

        def fetchone(self):
            return {"v1_available": False, "v2_available": True}

    assert storage_lifecycle._physical_event_relation(Cursor()) == "events_v2_core"
