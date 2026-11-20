from scripts.maintenance import worker_supervisor


def test_supervisor_does_not_manage_retired_storage_v2_outbox() -> None:
    assert "storage_v2_outbox" not in worker_supervisor.MANAGED
    assert "storage_v2_outbox" not in worker_supervisor.START_ORDER


def test_supervisor_starts_storage_lifecycle_for_either_exact_lane_admission() -> None:
    admitted = getattr(worker_supervisor, "storage_lifecycle_admitted", lambda _env: False)
    assert admitted({
        "ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED": "1",
        "ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION": (
            "DELETE_EXPLICIT_NO_ARCHIVE_ROWS_AFTER_SEMANTIC_COMPLETION"
        ),
    })
    assert admitted({
        "ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED": "1",
        "ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION": "APPLY-STAGE7-HOT-RETENTION-DELETE",
    })
    assert admitted({
        "ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED": "1",
        "ADLOG_STORAGE_LIFECYCLE_WARM_COPY_ADMISSION": "START-STAGE7-WARM-INCREMENTAL-COPY",
        "ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION": "0",
        "ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION": "0",
        "ADLOG_STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED": "0",
    })
    assert not admitted({"ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED": "1"})
