from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from server.sli.core import database, postgres_runtime_pipeline
from server.sli.core.app_config import AdLogConfig, load_config
from server.sli.ai import ai_reports
from server.sli.events import event_details, event_search
from server.sli.entities import entity_details
from server.sli.semantic import findings, investigation
from server.sli.ops import system_health
from server.sli.reporting import dashboard_fast, dashboard_snapshot
from server.sli.sources import collector_health


def test_config_constructs_without_database_file_and_rejects_removed_argument(tmp_path):
    config = AdLogConfig(reports_dir="reports", log_dir="logs")
    assert config.db_backend == "postgres"
    assert "db_path" not in config.to_dict()
    path = tmp_path / "obsolete.db"
    with pytest.raises(TypeError, match="db_path"):
        AdLogConfig(reports_dir="reports", log_dir="logs", db_path=str(path))
    assert not path.exists()


def test_config_ignores_obsolete_storage_path_and_environment(monkeypatch, tmp_path):
    path = tmp_path / "obsolete.db"
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        f"storage:\n  db_path: {path}\n  reports_dir: reports\n  log_dir: logs\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ADLOG_DB_PATH", str(path))
    config = load_config(config_file)
    assert config.reports_dir == "reports"
    assert config.log_dir == "logs"
    assert "db_path" not in config.to_dict()
    assert not hasattr(config, "db_path")
    assert not path.exists()


@pytest.mark.parametrize(
    "reader,args",
    [
        (database.query_rows, ("select 1", ())),
        (database.query_rows_bounded, ("select 1", ())),
        (findings.get_findings_data, ()),
        (findings.get_findings_dashboard_data, ()),
        (findings.get_security_problems_data, ()),
        (findings.refresh_findings_from_events, ()),
        (findings.get_finding_status_history, (1,)),
        (event_search.get_event_search_data, ()),
        (event_search.get_event_deep_search_data, ()),
        (event_search.get_account_timeline_data, ()),
        (event_search.get_event_category_counts, ()),
        (event_details.get_event_detail_report_data, ()),
        (entity_details.get_entity_detail_report_data, ()),
        (ai_reports.record_ai_run, ({}, {}, {})),
        (ai_reports.list_ai_runs, ()),
        (ai_reports.get_ai_run, ()),
        (system_health.get_system_health, ()),
        (collector_health.get_collector_health, ()),
        (dashboard_fast.get_dashboard_event_summary, ()),
        (dashboard_fast.get_dashboard_entity_summary, ()),
        (dashboard_snapshot.build_dashboard_snapshot, ()),
    ],
)
@pytest.mark.parametrize("argument_style", ["keyword", "positional"])
def test_obsolete_file_argument_cannot_open_runtime_connection(monkeypatch, tmp_path, reader, args, argument_style):
    monkeypatch.setattr(
        postgres_runtime_pipeline,
        "connect",
        lambda: pytest.fail("An obsolete file argument must fail before connecting"),
    )
    path = tmp_path / "obsolete.db"
    with pytest.raises(TypeError):
        if argument_style == "keyword":
            reader(*args, db_path=path)
        else:
            reader(*args, path)
    assert not (tmp_path / "obsolete.db").exists()


@pytest.mark.parametrize("reader", [database.query_rows, database.query_rows_bounded])
def test_read_uses_postgres_without_database_file(monkeypatch, tmp_path, reader):
    statements = []
    closed = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            closed.append("cursor")

        def execute(self, sql, params=()):
            statements.append((sql, params))

        def fetchall(self):
            return [{"value": 7}]

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            closed.append("connection")

        def cursor(self):
            return Cursor()

    monkeypatch.setenv("ADLOG_DB_PATH", str(tmp_path / "unused.db"))
    monkeypatch.setattr(database, "load_config", lambda: SimpleNamespace(db_backend="postgres"))
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", Connection)
    assert reader("select ? as value", (7,)) == [{"value": 7}]
    assert statements[-1] == ("select %s as value", (7,))
    assert closed == ["cursor", "connection"]
    assert not (tmp_path / "unused.db").exists()


@pytest.mark.parametrize("reader", [database.query_rows, database.query_rows_bounded])
def test_unsupported_backend_fails_before_connect(monkeypatch, reader):
    monkeypatch.setattr(database, "load_config", lambda: SimpleNamespace(db_backend="sqlite"))
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: pytest.fail("No fallback may connect"))
    with pytest.raises(RuntimeError, match="PostgreSQL is the only runtime"):
        reader("select 1")


def test_investigation_keeps_reads_and_authorization_without_refresh(monkeypatch):
    calls = {}
    authorization = object()

    def search(**kwargs):
        calls["search"] = kwargs
        return {"items": [], "total": 0}

    def finding_rows(**kwargs):
        calls["findings"] = kwargs
        return {"items": [], "summary": [], "backend": "postgres"}

    monkeypatch.setattr(investigation, "get_event_search_data", search)
    monkeypatch.setattr(investigation, "get_findings_data", finding_rows)
    result = investigation.get_investigation_workspace_data(q="subject", authorization=authorization)
    assert result["findings"]["backend"] == "postgres"
    assert calls["findings"]["refresh"] is False
    for kwargs in calls.values():
        assert kwargs["authorization"] is authorization
        assert "db_path" not in kwargs


@pytest.mark.parametrize("module_name", [
    "scripts.ai.build_ai_prompt",
    "scripts.ai.prepare_ai_preview",
    "scripts.ai.run_openai_analysis",
    "scripts.maintenance.healthcheck",
])
def test_cli_rejects_obsolete_db_option(monkeypatch, tmp_path, module_name):
    module = importlib.import_module(module_name)
    path = tmp_path / "obsolete.db"
    monkeypatch.setattr("sys.argv", [module_name, "--db", str(path)])
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2
    assert not path.exists()
