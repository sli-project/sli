from contextlib import contextmanager
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import scripts.run_dc_log_pilot as pilot


def test_postgres_importer_exists_and_uses_postgres_conflicts():
    text = Path("scripts/import/import_event_jsonl_to_postgres.py").read_text(encoding="utf-8")
    assert "psycopg.connect" in text
    # Storage V2 is the only store (plan 6.5): no V1 event or link writes remain.
    assert "insert into events(" not in text
    assert "insert into event_entity_links" not in text
    assert "storage_v2_admission_required" in text
    assert "total_inserted=" in text


def test_run_import_for_backend_passes_explicit_postgres_source_identity(tmp_path, monkeypatch):
    commands = []

    @contextmanager
    def fake_queue(**_kwargs):
        yield SimpleNamespace(wait_ms=0)

    def fake_run(command, *, timeout_seconds=None):
        commands.append((command, timeout_seconds))
        return subprocess.CompletedProcess(command, 0, "total_inserted=1", "")

    monkeypatch.setattr("server.sli.sources.postgres_import_queue.postgres_import_queue", fake_queue)
    monkeypatch.setattr(pilot, "run_command", fake_run)

    result, _, _, backend = pilot.run_import_for_backend(
        target_backend="postgres",
        output_dir=tmp_path,
        server="DC1",
        trace_id="trace-1",
        job_id=None,
        collector_backend="python",
        domain_fqdn="corp.example",
        forest_name="forest.example",
    )

    command = commands[0][0]
    assert result.returncode == 0
    assert backend == "postgres"
    assert command[command.index("--domain") + 1] == "corp.example"
    assert command[command.index("--forest") + 1] == "forest.example"


def test_postgres_source_identity_derives_domain_and_single_domain_forest():
    assert pilot.resolve_postgres_source_identity(
        connect_address="DC1.Corp.Example.",
        domain_override=None,
        forest_override=None,
    ) == ("corp.example", "corp.example")


@pytest.mark.parametrize(
    ("domain_override", "forest_override"),
    [("EXAMPLE", None), ("example.invalid", None), ("corp.example", "example.invalid")],
)
def test_postgres_source_identity_rejects_importer_placeholders(domain_override, forest_override):
    with pytest.raises(ValueError, match="placeholder_forbidden"):
        pilot.resolve_postgres_source_identity(
            connect_address="DC1.corp.example",
            domain_override=domain_override,
            forest_override=forest_override,
        )


def test_postgres_source_identity_requires_fqdn_when_deriving():
    with pytest.raises(ValueError, match="must_be_fqdn"):
        pilot.resolve_postgres_source_identity(
            connect_address="DC1",
            domain_override=None,
            forest_override=None,
        )


def test_run_dc_pipeline_routes_postgres_through_bounded_import_queue():
    text = Path("scripts/run_dc_log_pilot.py").read_text(encoding="utf-8")
    assert "POSTGRES_IMPORT_SCRIPT" in text
    assert "def run_import_for_backend" in text
    assert "target_backend == \"postgres\"" in text
    assert "run_import_under_sqlite_writer_lock" not in text
    assert "record_collector_channel_runs_pg" in text
    assert "update_collection_state_from_summary_pg" in text


def test_runtime_status_exposes_postgres_pipeline_state():
    text = Path("server/jobs/collector.py").read_text(encoding="utf-8")
    assert "get_runtime_pipeline_status" in text
    assert "postgres_importer_available" in text


