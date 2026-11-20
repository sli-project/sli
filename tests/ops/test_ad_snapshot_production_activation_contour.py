from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_registry_activates_only_canonical_coordinator_and_retires_legacy_ad_workers() -> None:
    from server.sli.ops.runtime_component_registry import get
    from server.sli.ops.runtime_workers import WORKER_SPECS
    from scripts.maintenance import worker_supervisor

    coordinator = get("ad_snapshot_manifest_coordinator")
    assert coordinator.script == "ad_snapshot_manifest_coordinator_worker.py"
    assert coordinator.expected_interval_seconds == 43200
    assert coordinator.feature_enabled and coordinator.supervised

    legacy_workers = {
        "ad_context_snapshot",
        "ad_snapshot_projection",
        "computers_v5_snapshot",
        "computers_v6_source",
        "computers_v6_snapshot",
        "users_v2_snapshot",
    }
    for name in legacy_workers:
        component = get(name)
        assert not component.feature_enabled and not component.supervised
        assert "rollback" in component.label.casefold()

    assert "ad_snapshot_manifest_coordinator" in worker_supervisor.START_ORDER
    assert not legacy_workers & set(worker_supervisor.MANAGED)
    assert not legacy_workers & set(worker_supervisor.START_ORDER)
    operations_workers = {name for name, _label in WORKER_SPECS}
    for name in {"computers_v6_snapshot", "users_v2_snapshot"}:
        assert not get(name).visible_in_operations
        assert name not in operations_workers
    assert worker_supervisor.MANAGED["ad_snapshot_manifest_coordinator"] == (
        "ad_snapshot_manifest_coordinator_worker.py",
        ["--no-initial-delay"],
    )


def test_migration_121_controller_is_bounded_and_reads_exact_foundation() -> None:
    source = (ROOT / "scripts/maintenance/ad_snapshot_manifest_foundation_migrate.py").read_text(encoding="utf-8")
    assert "APPLY-AD-SNAPSHOT-MANIFEST-FOUNDATION-121" in source
    assert "ROLLBACK-AD-SNAPSHOT-MANIFEST-FOUNDATION-121" in source
    assert "--load-supervisor-environment" in source
    assert "set transaction read only" in source
    for name in ("ad_snapshot_manifests", "ad_snapshot_manifest_sources", "ad_snapshot_projection_receipts"):
        assert name in source
    assert "ad_snapshot_manifest_reject_mutation" in source
    assert "idx_ad_snapshot_manifests_slot" in source
    assert "idx_ad_snapshot_projection_receipts_claim" in source
    assert "information_schema.role_table_grants" in source


class _MigrationCursor:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, _params=None):
        self.events.append("ddl" if "create table" in str(sql).casefold() else "query")


class _MigrationConnection:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def __enter__(self):
        self.events.append("transaction_enter")
        return self

    def __exit__(self, exc_type, *_args):
        self.events.append("rollback" if exc_type else "commit")
        return False

    def cursor(self):
        return _MigrationCursor(self.events)


def test_migration_121_controller_commits_only_after_exact_readback(monkeypatch) -> None:
    from scripts.maintenance import ad_snapshot_manifest_foundation_migrate as migration

    events: list[str] = []
    monkeypatch.setattr(migration, "_dsn", lambda **_kwargs: "postgresql://redacted")
    monkeypatch.setattr(migration, "_connect", lambda _dsn: _MigrationConnection(events))
    monkeypatch.setattr(migration, "_status", lambda _cursor: events.append("readback") or {"marker": True})
    monkeypatch.setattr(migration, "_verify_applied", lambda _result: events.append("verified"))

    migration.run(action="apply", confirmation=migration.APPLY_TOKEN)

    assert events.index("ddl") < events.index("readback") < events.index("verified") < events.index("commit")


def test_migration_121_readback_failure_rolls_back_all_ddl(monkeypatch) -> None:
    from scripts.maintenance import ad_snapshot_manifest_foundation_migrate as migration

    events: list[str] = []
    monkeypatch.setattr(migration, "_dsn", lambda **_kwargs: "postgresql://redacted")
    monkeypatch.setattr(migration, "_connect", lambda _dsn: _MigrationConnection(events))
    monkeypatch.setattr(migration, "_status", lambda _cursor: events.append("readback") or {"marker": False})

    with pytest.raises(RuntimeError, match="readback"):
        migration.run(action="apply", confirmation=migration.APPLY_TOKEN)

    assert "ddl" in events and events[-1] == "rollback" and "commit" not in events


def test_migration_121_sql_leaves_transaction_ownership_to_controller() -> None:
    for name in ("121_ad_snapshot_manifest_foundation.sql", "121_ad_snapshot_manifest_foundation.rollback.sql"):
        statements = (ROOT / "config/postgres_migrations" / name).read_text(encoding="utf-8").casefold().splitlines()
        assert not any(line.strip() in {"begin;", "commit;"} for line in statements)


def test_coordinator_rejects_wrong_requested_domain_before_database_or_acquisition(monkeypatch) -> None:
    from datetime import datetime, timezone
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator

    contacts: list[str] = []
    monkeypatch.setenv("ADLOG_AD_CONTEXT_DOMAIN", "approved.example")
    monkeypatch.setattr(coordinator, "connect", lambda: contacts.append("database") or (_ for _ in ()).throw(AssertionError()))
    monkeypatch.setattr(coordinator, "_collect", lambda _family: contacts.append("source") or {})

    with pytest.raises(RuntimeError, match="requested_domain_does_not_match_configured_domain"):
        coordinator._default_cycle(datetime(2026, 8, 31, 12, tzinfo=timezone.utc), domain_dns="wrong.example")

    assert contacts == []


def test_canary_passes_approved_domain_into_coordinator(monkeypatch) -> None:
    from datetime import datetime, timezone
    from scripts.maintenance import ad_snapshot_manifest_canary as canary

    now = datetime(2026, 8, 31, 11, 10, tzinfo=timezone.utc)
    slot_start_utc = "2026-08-31T11:00:00Z"

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now.astimezone(tz)

    monkeypatch.setattr(canary, "datetime", Clock)
    received: list[str] = []

    def cycle(observed_at, *, domain_dns, scheduled_slot):
        assert observed_at == now
        assert scheduled_slot == canary.scheduled_slot_from_utc(datetime(2026, 8, 31, 11, tzinfo=timezone.utc))
        received.append(domain_dns)
        return {"slot_start_utc": slot_start_utc, "domain_dns": domain_dns}

    monkeypatch.setattr(canary, "_default_cycle", cycle)
    canary._coordinator(slot_start_utc=slot_start_utc, domain_dns="approved.example")
    assert received == ["approved.example"]


def test_collector_timeout_terminates_process_tree_and_preserves_output_tail(monkeypatch) -> None:
    import subprocess
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator

    events: list[object] = []

    class HungProcess:
        pid = 4321
        returncode = None

        def communicate(self, timeout):
            events.append(("communicate", timeout))
            if len([event for event in events if isinstance(event, tuple) and event[0] == "communicate"]) == 1:
                raise subprocess.TimeoutExpired(["collector"], timeout, output="stdout-before-timeout", stderr="stderr-before-timeout")
            self.returncode = 137
            return "stdout-after-timeout", "stderr-after-timeout"

        def kill(self):
            events.append("kill")

    monkeypatch.setattr(coordinator.subprocess, "Popen", lambda *args, **kwargs: events.append((args, kwargs)) or HungProcess())
    monkeypatch.setattr(coordinator, "_terminate_process_tree", lambda process: events.append(("tree", process.pid)))

    with pytest.raises(RuntimeError, match="collector_timeout.*stdout-after-timeout.*stderr-after-timeout"):
        coordinator._run_collector_process(["collector"], timeout_seconds=1)

    assert ("tree", 4321) in events


def test_coordinator_records_initial_delay_heartbeat_before_sleep(monkeypatch) -> None:
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator

    monkeypatch.setattr(coordinator, "acquisition_disabled", lambda: False)
    heartbeats: list[dict[str, object]] = []
    monkeypatch.setattr(coordinator, "record_worker_heartbeat", lambda **kwargs: heartbeats.append(kwargs))

    def stop_at_sleep(seconds: int) -> None:
        assert seconds == coordinator.INITIAL_DELAY_SECONDS
        assert len(heartbeats) == 1
        raise RuntimeError("stop_after_initial_heartbeat")

    monkeypatch.setattr(coordinator.time, "sleep", stop_at_sleep)
    with pytest.raises(RuntimeError, match="stop_after_initial_heartbeat"):
        coordinator.main([])

    assert heartbeats[0]["status"] == "idle"
    assert heartbeats[0]["phase"] == "initial_delay"
    assert heartbeats[0]["expected_interval_seconds"] == 43200
