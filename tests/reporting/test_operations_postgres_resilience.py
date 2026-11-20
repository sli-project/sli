from __future__ import annotations

from typing import Any

import pytest


class LockNotAvailable(RuntimeError):
    pass


class _Cursor:
    def __init__(self, *, fail_table_metrics: bool = False) -> None:
        self.fail_table_metrics = fail_table_metrics
        self.query = ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, query: str, params: tuple[Any, ...] | None = None) -> None:
        del params
        self.query = " ".join(query.lower().split())
        if self.fail_table_metrics and "from pg_stat_user_tables" in self.query:
            raise LockNotAvailable("relation lock is busy: private detail")

    def fetchone(self):
        if "pg_database_size" in self.query:
            return {
                "database_name": "adlog",
                "database_bytes": 1_048_576,
                "checked_at": "2026-07-22T00:00:00Z",
            }
        return None

    def fetchall(self):
        return []


class _Connection:
    def __init__(self, *, fail_table_metrics: bool = False) -> None:
        self.fail_table_metrics = fail_table_metrics

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return _Cursor(fail_table_metrics=self.fail_table_metrics)


def test_optional_postgres_metric_failure_keeps_database_ready(monkeypatch):
    from server.sli.ops import postgres_operations
    from server.sli.core import postgres_runtime_pipeline

    monkeypatch.setattr(postgres_operations, "active_backend", lambda: "postgres")
    monkeypatch.setattr(
        postgres_runtime_pipeline,
        "connect",
        lambda: _Connection(fail_table_metrics=True),
    )

    result = postgres_operations.get_postgres_operations_status()

    assert result["status"] == "warn"
    assert result["available"] is True
    assert result["connectivity_status"] == "ready"
    assert result["metrics_status"] == "partial"
    assert result["database"]["database_human"] == "1.0 MB"
    assert result["tables"] == []
    assert result["limitations"] == [
        {"metric": "table_statistics", "error_type": "LockNotAvailable"}
    ]
    assert "error" not in result


def test_operations_overview_reuses_postgres_snapshot(monkeypatch):
    from server.sli.reporting import ui_operations

    postgres = {
        "status": "ok",
        "available": True,
        "connectivity_status": "ready",
        "database": {"database_bytes": 1_048_576, "database_human": "1.0 MB"},
    }
    calls = {"postgres": 0, "storage": 0}

    def read_postgres(*, table_limit: int):
        assert table_limit == 10
        calls["postgres"] += 1
        return postgres

    def read_storage(snapshot):
        assert snapshot is postgres
        calls["storage"] += 1
        return {"status": "ok", "project_overview": {"database_human": "1.0 MB"}}

    monkeypatch.setattr(ui_operations, "get_collection_runtime_status", lambda: {"collection_enabled": True})
    monkeypatch.setattr(ui_operations, "get_runtime_workers_overview", lambda: {"status": "ok", "items": []})
    monkeypatch.setattr(ui_operations, "get_collector_health", lambda: {"status": "ok"})
    monkeypatch.setattr(ui_operations, "get_postgres_operations_status", read_postgres)
    monkeypatch.setattr(ui_operations, "get_operations_storage_summary", read_storage)
    monkeypatch.setattr(
        ui_operations,
        "get_radius_vpn_operations",
        lambda: {"status": "ok", "items": []},
    )

    result = ui_operations.get_operations_overview()

    assert calls == {"postgres": 1, "storage": 1}
    assert result["postgres"] is postgres
    assert result["storage"]["project_overview"]["database_human"] == "1.0 MB"


def test_operations_overview_exposes_payload_free_catalog_completeness(monkeypatch):
    from server.sli.reporting import ui_operations

    entries = [
        {
            "base_risk": "low",
            "purpose_tier": "technical",
            "noise_class": "signal",
            "category": "other",
            "lifecycle": {},
            "correlation": None,
            "required_fields": ["event_id"],
        },
        {},
    ]
    monkeypatch.setattr(ui_operations, "all_event_catalog_entries", lambda: entries)
    monkeypatch.setattr(ui_operations, "get_collection_runtime_status", lambda: {})
    monkeypatch.setattr(ui_operations, "get_runtime_workers_overview", lambda: {"items": []})
    monkeypatch.setattr(ui_operations, "get_collector_health", lambda: {})
    monkeypatch.setattr(ui_operations, "get_postgres_operations_status", lambda *, table_limit: {})
    monkeypatch.setattr(ui_operations, "get_operations_storage_summary", lambda snapshot: {})
    monkeypatch.setattr(
        ui_operations,
        "get_radius_vpn_operations",
        lambda: {"status": "ok", "items": []},
    )

    result = ui_operations.get_operations_overview()["catalog_completeness"]

    assert result == {
        "status": "ok",
        "basis": "distinct_catalog_entries",
        "contains_event_payload": False,
        "entry_count": 2,
        "fully_classified": 1,
        "classification_ratio": 0.5,
        "schema_v2_ready": 1,
        "declared_per_field": {
            "base_risk": 1,
            "purpose_tier": 1,
            "noise_class": 1,
            "category": 1,
            "lifecycle": 0,
            "correlation": 0,
            "required_fields": 1,
        },
    }


def test_operations_overview_keeps_other_health_when_catalog_is_unavailable(monkeypatch):
    from server.sli.reporting import ui_operations

    monkeypatch.setattr(
        ui_operations,
        "all_event_catalog_entries",
        lambda: (_ for _ in ()).throw(ValueError("private catalogue detail")),
    )
    monkeypatch.setattr(ui_operations, "get_collection_runtime_status", lambda: {})
    monkeypatch.setattr(ui_operations, "get_runtime_workers_overview", lambda: {"items": []})
    monkeypatch.setattr(ui_operations, "get_collector_health", lambda: {"status": "ok", "items": []})
    monkeypatch.setattr(
        ui_operations,
        "get_postgres_operations_status",
        lambda *, table_limit: {"status": "ok"},
    )
    monkeypatch.setattr(
        ui_operations,
        "get_operations_storage_summary",
        lambda snapshot: {"status": "ok"},
    )
    monkeypatch.setattr(
        ui_operations,
        "get_radius_vpn_operations",
        lambda: {"status": "ok", "items": []},
    )

    result = ui_operations.get_operations_overview()

    assert result["collector_health"] == {"status": "ok", "items": []}
    assert result["postgres"] == {"status": "ok"}
    assert result["catalog_completeness"] == {
        "status": "unavailable",
        "basis": "distinct_catalog_entries",
        "contains_event_payload": False,
        "error_type": "ValueError",
    }
    assert "private catalogue detail" not in str(result)


def test_operations_overview_keeps_other_health_when_radius_pilot_is_unavailable(
    monkeypatch,
):
    from server.sli.reporting import ui_operations

    monkeypatch.setattr(ui_operations, "get_collection_runtime_status", lambda: {})
    monkeypatch.setattr(
        ui_operations,
        "get_runtime_workers_overview",
        lambda: {"items": []},
    )
    monkeypatch.setattr(
        ui_operations,
        "get_collector_health",
        lambda: {"status": "ok", "items": []},
    )
    monkeypatch.setattr(
        ui_operations,
        "get_postgres_operations_status",
        lambda *, table_limit: {"status": "ok"},
    )
    monkeypatch.setattr(
        ui_operations,
        "get_operations_storage_summary",
        lambda snapshot: {"status": "ok"},
    )
    monkeypatch.setattr(
        ui_operations,
        "get_radius_vpn_operations",
        lambda: (_ for _ in ()).throw(
            RuntimeError("private database detail")
        ),
    )

    result = ui_operations.get_operations_overview()

    assert result["collector_health"] == {"status": "ok", "items": []}
    assert result["plugin_pilots"]["vpn_radius"] == {
        "contract_id": "sli.radius-vpn-operations.v1",
        "status": "unavailable",
        "items": [],
        "contains_identity_or_event_payload": False,
        "error_type": "RuntimeError",
    }
    assert "private database detail" not in str(result)


def test_operations_overview_does_not_report_http_copy_guard_as_external_worker_outage(monkeypatch):
    from server.sli.reporting import ui_operations

    monkeypatch.setattr(ui_operations, "get_collector_health", lambda: {"status": "ok"})
    monkeypatch.setattr(ui_operations, "get_postgres_operations_status", lambda *, table_limit: {"status": "ok"})
    monkeypatch.setattr(ui_operations, "get_operations_storage_summary", lambda snapshot: {"status": "ok"})
    monkeypatch.setattr(
        ui_operations,
        "get_radius_vpn_operations",
        lambda: {"status": "ok", "items": []},
    )
    monkeypatch.setattr(
        ui_operations,
        "get_collection_runtime_status",
        lambda: {
            "collection_enabled": False,
            "collection_block_reason": "collection_disabled_by_ADLOG_DISABLE_COLLECTION",
            "disable_collection_env": True,
        },
    )
    monkeypatch.setattr(
        ui_operations,
        "get_runtime_workers_overview",
        lambda: {
            "status": "ok",
            "items": [{"worker_name": "collection", "state": "active"}],
        },
    )

    collection = ui_operations.get_operations_overview()["collection"]

    assert collection["collection_enabled"] is False
    assert collection["operational_collection_enabled"] is True
    assert collection["operational_collection_block_reason"] is None
    assert collection["collection_execution_owner"] == "external_worker"
    assert collection["local_runtime_guard_only"] is True


def test_operations_overview_keeps_durable_block_when_worker_heartbeat_exists():
    from server.sli.reporting.ui_operations import _collection_execution_view

    result = _collection_execution_view(
        {
            "collection_enabled": False,
            "collection_block_reason": "windows_security_context_invalid",
        },
        {"items": [{"worker_name": "collection", "state": "active"}]},
    )

    assert result["operational_collection_enabled"] is False
    assert result["operational_collection_block_reason"] == "windows_security_context_invalid"
    assert result["local_runtime_guard_only"] is False


def test_operations_overview_treats_fresh_warning_worker_as_external_owner():
    from server.sli.reporting.ui_operations import _collection_execution_view

    result = _collection_execution_view(
        {
            "collection_enabled": False,
            "collection_block_reason": "collection_disabled_by_ADLOG_DISABLE_COLLECTION",
        },
        {
            "items": [{
                "worker_name": "collection",
                "state": "warning",
                "status": "failed",
                "feature_enabled": True,
            }],
        },
    )

    assert result["operational_collection_enabled"] is True
    assert result["operational_collection_block_reason"] is None
    assert result["collection_execution_owner"] == "external_worker"
    assert result["local_runtime_guard_only"] is True


def test_operations_overview_reports_live_bounded_collection_progress(monkeypatch):
    from server.sli.reporting import ui_operations

    channels = [
        {
            "server": server,
            "channel": channel,
            "recovery_mode": channel in {"Security", "DNS Server"},
            "adaptive_limit": 50_000 if channel == "Security" else 35_200,
            "adaptive_action": (
                "keep:completed_fast_recovery"
                if channel in {"Security", "DNS Server"}
                else "exit_recovery:source_boundary_reached"
            ),
            "last_event_record_id": index,
            "last_event_time_utc": "2026-08-26T01:00:00Z",
        }
        for index, (server, channel) in enumerate(
            (
                (server, channel)
                for server in ("DC1", "DC2")
                for channel in (
                    "Security",
                    "System",
                    "Directory Service",
                    "Microsoft-Windows-PowerShell/Operational",
                    "Microsoft-Windows-TaskScheduler/Operational",
                    "DNS Server",
                )
            ),
            start=1,
        )
    ]
    worker = {
        "worker_name": "collection",
        "worker_id": "collection-example-39124",
        "status": "running",
        "state": "active",
        "phase": "collection",
        "heartbeat_at": "2026-08-26T08:37:26+07:00",
        "details": {"active_job": {"job_id": 2, "status": "running", "phase": "collection"}},
    }
    monkeypatch.setattr(ui_operations, "get_collector_health", lambda: {"items": channels})
    monkeypatch.setattr(ui_operations, "get_runtime_workers_overview", lambda: {"status": "ok", "items": [worker]})
    monkeypatch.setattr(ui_operations, "get_collection_runtime_status", lambda: {"collection_enabled": True})
    monkeypatch.setattr(ui_operations, "get_postgres_operations_status", lambda *, table_limit: {"status": "ok"})
    monkeypatch.setattr(ui_operations, "get_operations_storage_summary", lambda snapshot: {"status": "ok"})
    monkeypatch.setattr(ui_operations, "get_radius_vpn_operations", lambda: {"status": "ok", "items": []})

    progress = ui_operations.get_operations_overview()["collection_progress"]

    assert progress["status"] == "running"
    assert progress["channels_total"] == 12
    assert progress["boundaries_reached"] == 8
    assert progress["channels_in_recovery"] == 4
    assert progress["worker_id"] == "collection-example-39124"
    assert progress["job_id"] == 2
    assert {(item["server"], item["channel"]) for item in progress["recovery_items"]} == {
        ("DC1", "Security"),
        ("DC1", "DNS Server"),
        ("DC2", "Security"),
        ("DC2", "DNS Server"),
    }
    assert all(item["boundary_reached"] for item in progress["items"] if not item["recovery_mode"])


def test_source_detail_uses_real_inventory_and_keeps_uncollected_fields_honest(monkeypatch):
    from server.sli.reporting import ui_operations

    monkeypatch.setattr(
        ui_operations,
        "get_sources",
        lambda: [{
            "hostname": "DC2",
            "fqdn": "dc2.host12.example.invalid",
            "role": "domain_controller",
            "is_active": True,
            "domain_fqdn": "host12.example.invalid",
            "site_name": "Main",
            "os_name": "Windows Server",
            "os_version": "2022",
            "ip_addresses": ["192.0.2.10"],
        }],
    )
    monkeypatch.setattr(
        ui_operations,
        "get_collector_health",
        lambda: {
            "items": [{
                "server": "dc2",
                "channel": "Security",
                "last_successful_collection_utc": "2026-07-23T03:58:00Z",
                "last_event_time_utc": "2026-07-23T03:57:00Z",
                "last_status": "completed",
            }]
        },
    )
    monkeypatch.setattr(
        ui_operations,
        "summarize_collection_freshness",
        lambda channels, *, selected_source: {
            "selected_source": selected_source,
            "channels_total": len(channels),
        },
    )

    result = ui_operations.get_source_detail("dc2")

    assert result["source"] == {
        "hostname": "DC2",
        "fqdn": "dc2.host12.example.invalid",
        "role": "domain_controller",
        "active": True,
        "domain_fqdn": "host12.example.invalid",
        "site": "Main",
            "os_name": "Windows Server",
            "os_version": "2022",
            "ip_addresses": ["192.0.2.10"],
            "inventory_observed_at_utc": None,
            "inventory_source": None,
            "disk_state": "not_collected",
            "disks": [],
        }
    assert result["collection_freshness"] == {
        "selected_source": "DC2",
        "channels_total": 1,
    }
    assert result["channels"][0]["server"] == "dc2"
    assert result["read_only"] is True


def test_source_detail_rejects_invalid_or_unknown_source(monkeypatch):
    from server.sli.reporting import ui_operations

    monkeypatch.setattr(ui_operations, "get_sources", lambda: [])
    monkeypatch.setattr(ui_operations, "get_collector_health", lambda: {"items": []})

    with pytest.raises(ValueError, match="invalid_source_hostname"):
        ui_operations.get_source_detail("")
    with pytest.raises(ValueError, match="source_not_found"):
        ui_operations.get_source_detail("UNKNOWN")


def test_fast_storage_summary_uses_existing_database_size(monkeypatch):
    from server.sli.storage import storage_policy

    monkeypatch.setattr(storage_policy, "load_storage_policy", lambda: {})
    monkeypatch.setattr(
        storage_policy,
        "disk_pressure_status",
        lambda root, policy: {"status": "ok", "collection_allowed": True},
    )
    monkeypatch.setattr(
        storage_policy,
        "load_operations_storage_snapshot",
        lambda: {"status": "unavailable", "warnings": [], "totals": {}, "components": []},
    )

    result = storage_policy.get_operations_storage_summary(
        {
            "available": True,
            "database": {"database_bytes": 1_048_576, "database_human": "1.0 MB"},
        }
    )

    assert result["status"] == "ok"
    assert result["project_overview"] == {
        "database_bytes": 1_048_576,
        "database_human": "1.0 MB",
        "total_bytes": None,
        "total_human": None,
        "scope": "deduplicated_known_project_footprint",
        "complete": False,
    }
    assert result["read_only"] is True


def test_fast_storage_summary_exposes_complete_footprint_without_rescanning(monkeypatch):
    from server.sli.storage import storage_policy

    monkeypatch.setattr(storage_policy, "load_storage_policy", lambda: {})
    monkeypatch.setattr(
        storage_policy,
        "disk_pressure_status",
        lambda root, policy: {"status": "ok", "collection_allowed": True},
    )
    footprint = {
        "status": "partial",
        "warnings": ["RAW spool scan is incomplete."],
        "totals": {"accounted_bytes": 1234, "accounted_human": "1.2 КБ"},
        "components": [{"key": "project_root", "bytes": 1234}],
        "raw_spool": {
            "status": "partial", "bytes": 10, "batch_count": 2,
            "oldest_batch_at_utc": "2026-08-30T10:00:00+00:00",
            "oldest_batch_age_seconds": 172800,
            "scan": {"complete": False, "errors": 1},
            "thresholds": {"bytes_warning": 524288000, "bytes_critical": 1073741824,
                           "batch_count_warning": 1000, "oldest_age_warning_seconds": 172800},
        },
    }
    monkeypatch.setattr(storage_policy, "load_operations_storage_snapshot", lambda: footprint)

    result = storage_policy.get_operations_storage_summary(
        {"available": True, "database": {"database_bytes": 512, "database_human": "512 Б"}}
    )

    assert result["status"] == "warn"
    assert result["footprint"] == footprint
    assert result["footprint"]["raw_spool"]["scan"]["errors"] == 1
    assert result["project_overview"]["total_bytes"] == 1234
    assert result["project_overview"]["complete"] is False
