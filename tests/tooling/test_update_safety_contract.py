from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("extra", [[], ["--skip-tests"], ["--dry-run"], ["--restart", "never"]])
def test_untrusted_update_cli_exits_nonzero_before_execution(tmp_path, extra):
    sentinel = tmp_path / "executed.txt"
    archive = tmp_path / "untrusted.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("scripts/maintenance/release_check.py", f"open({str(sentinel)!r}, 'w').write('bad')")
    run = subprocess.run([
        sys.executable, str(ROOT / "scripts/maintenance/apply_update.py"),
        "--package", str(archive), "--json", *extra,
    ], cwd=tmp_path, capture_output=True, text=True, timeout=30, check=False)
    assert run.returncode == 1, run.stderr
    assert json.loads(run.stdout)["reason_code"] == "external_trust_required"
    assert not sentinel.exists()


def test_direct_zip_mutation_requires_signed_lifecycle(monkeypatch, tmp_path):
    from scripts import apply_project_zip

    archive = tmp_path / "update.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("package.json", "{}")
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.delenv("SLI_INTERNAL_UPDATE_ORCHESTRATOR", raising=False)
    monkeypatch.setattr("sys.argv", ["apply_project_zip.py", str(archive), "--project-root", str(project)])
    assert apply_project_zip.main() == 3
    assert list(project.iterdir()) == []


def test_legacy_backup_is_not_a_journal_recovery_source(tmp_path):
    from scripts.maintenance import rollback_update

    project = tmp_path / "project"
    project.mkdir()
    backup = tmp_path / "backup.zip"
    with zipfile.ZipFile(backup, "w") as z:
        z.writestr("_update_backup_manifest.json", "{}")
        z.writestr("package.json", '{"restored": true}')
    result = rollback_update.rollback(backup, dry_run=True)
    assert result["status"] == "blocked"
    assert result["reason_code"] == "journal_recovery_required"
    assert list(project.iterdir()) == []
    assert rollback_update.rollback(backup)["status"] == "blocked"
    assert list(project.iterdir()) == []


def test_legacy_rollback_cli_reports_failure_without_mutation(tmp_path):
    run = subprocess.run([
        sys.executable, str(ROOT / "scripts/maintenance/rollback_update.py"),
        "--backup", str(tmp_path / "anything.zip"), "--json",
    ], cwd=tmp_path, capture_output=True, text=True, timeout=30, check=False)
    assert run.returncode == 1
    assert json.loads(run.stdout)["status"] == "blocked"
