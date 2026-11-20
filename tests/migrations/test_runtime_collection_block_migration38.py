from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]


def test_migration_38_defines_singleton_fail_closed_block() -> None:
    sql = (ROOT / "config/postgres_migrations/038_runtime_collection_blocks.sql").read_text(encoding="utf-8")

    assert "runtime_collection_blocks" in sql
    assert "singleton_id = 1" in sql
    assert "operator_recovery_required" not in sql  # runtime policy, not mutable seed data
    assert "observed_count" in sql
    assert "last_probe_result" in sql
    assert "values (38,'runtime_collection_blocks')" in sql
    assert "version=37 and name='platform_owner_access'" in sql
    assert "version=38 and name<>'runtime_collection_blocks'" in sql
    assert "on conflict(version) do nothing" in sql

    rollback = (ROOT / "config/postgres_migrations/038_runtime_collection_blocks.rollback.sql").read_text(encoding="utf-8")
    assert "rollback 038 refused" in rollback
    assert "exists(select 1 from runtime_collection_blocks)" in rollback


def test_recovery_tool_has_no_unconditional_clear_path() -> None:
    source = (ROOT / "scripts/maintenance/collection_block_control.py").read_text(encoding="utf-8")

    assert "--clear" not in source
    assert "SLI-RECHECK-WINDOWS-CONTEXT" in source
    assert "record_probe_and_clear" in source
    assert "subprocess.TimeoutExpired" in source


def test_internal_probe_uses_handle_close_not_missing_module_evtclose(monkeypatch, capsys) -> None:
    from scripts.collect import collect_windows_events
    from scripts.maintenance import collection_block_control
    from server.sli.sources import dc_discovery

    closed: list[bool] = []
    handle = SimpleNamespace(Close=lambda: closed.append(True))
    monkeypatch.setattr(collect_windows_events, "open_remote_session", lambda server: handle)
    monkeypatch.setattr(
        dc_discovery,
        "resolve_domain_controller_connect_address",
        lambda server: server,
    )
    monkeypatch.setattr(
        collect_windows_events,
        "probe_latest_record_id",
        lambda *args, **kwargs: 1,
    )

    assert collection_block_control._internal_probe("DC-TEST") == 0
    assert closed == [True]
    assert '"status": "ok"' in capsys.readouterr().out


def test_evt_handle_without_close_is_safe_for_short_lived_probe() -> None:
    from scripts.maintenance import collection_block_control

    collection_block_control._close_evt_handle(object())


def test_probe_server_parameter_has_explicit_postgres_type() -> None:
    source = (ROOT / "server/sli/sources/collection_runtime_block.py").read_text(encoding="utf-8")

    assert "jsonb_build_object('successful_probe_server', %s::text)" in source


def test_successful_probe_is_idempotent_when_worker_clears_block_first(
    monkeypatch,
) -> None:
    from server.sli.sources import collection_runtime_block as module
    from server.sli.core import postgres_runtime_pipeline

    class Cursor:
        def __init__(self) -> None:
            self.rows = [
                None,
                {
                    "singleton_id": 1,
                    "active": False,
                    "last_probe_result": "success",
                },
            ]

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def execute(self, query, params=None) -> None:
            return None

        def fetchone(self):
            return self.rows.pop(0)

    class Connection:
        def cursor(self) -> Cursor:
            return Cursor()

    @contextmanager
    def connect():
        yield Connection()

    monkeypatch.setattr(module, "_ensure_schema", lambda: None)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", connect)

    result = module.record_probe_and_clear(
        probe_server="DC2",
        cleared_by="operator",
    )

    assert result["active"] is False
    assert result["clear_outcome"] == "already_clear"
