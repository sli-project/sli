import json
from pathlib import Path
from subprocess import CompletedProcess

from scripts.maintenance import pg_archive_worker

ROOT = Path(__file__).resolve().parents[2]


def test_archive_worker_runs_postgres_collection_without_starting_scheduler(monkeypatch, tmp_path, capsys):
    status_path = tmp_path / "status.json"
    monkeypatch.setattr(pg_archive_worker, "STATUS_PATH", status_path)
    monkeypatch.setattr(pg_archive_worker, "parse_targets", lambda _: {"DC1": "dc1.example.test"})
    calls = []

    def run(command, *, env, **kwargs):
        calls.append((command, env))
        return CompletedProcess(command, 0, "import_event_jsonl_to_postgres.py\n", "")

    monkeypatch.setattr(pg_archive_worker.subprocess, "run", run)

    assert pg_archive_worker.main([]) == 0
    (command, env), = calls
    assert "--archive" in command
    assert env["ADLOG_DB_BACKEND"] == "postgres"
    assert env["ADLOG_DISABLE_SCHEDULER"] == "1"
    assert env["ADLOG_ENABLE_POSTGRES_COLLECTION"] == "1"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status["summary"]["servers_ok"] == ["DC1"]
    assert status["summary"]["postgres_importer_used"] is True
    capsys.readouterr()
    assert pg_archive_worker.main(["--status"]) == 0
    assert json.loads(capsys.readouterr().out) == status


def test_archive_worker_is_internal_and_not_exposed_while_collection_is_stopped():
    text = (ROOT / 'tools' / 'adlog-tool.ps1').read_text(encoding='utf-8')
    assert 'pg-archive-worker-dc1' not in text
    assert 'pg-archive-worker-dc2' not in text
    assert 'pg-archive-worker-all' not in text
