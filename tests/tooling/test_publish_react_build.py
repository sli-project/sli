import json
import shutil
import sys
from pathlib import Path

import pytest

from scripts.maintenance import publish_react_build as publisher
from scripts.maintenance.publish_react_build import (
    file_manifest,
    publish_build,
    validate_build,
)


def _build(root: Path, marker: str) -> None:
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(
        f'<script src="/app/assets/{marker}.js"></script>',
        encoding="utf-8",
    )
    (root / "assets" / f"{marker}.js").write_text(marker, encoding="utf-8")


def test_publish_creates_exact_backup_and_exact_live_readback(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    backup = tmp_path / "backup"
    _build(source, "new")
    _build(target, "old")
    old_manifest = file_manifest(target)
    new_manifest = file_manifest(source)

    result = publish_build(
        source=source,
        target=target,
        backup=backup,
        operation_id="test",
    )

    assert result["status"] == "ok"
    assert "warnings" not in result
    assert file_manifest(backup) == old_manifest
    assert file_manifest(target) == new_manifest
    assert result["backup_file_count"] == 2
    assert not (tmp_path / ".target.publish-test").exists()
    assert not (tmp_path / ".target.rollback-test").exists()


def test_empty_or_incomplete_build_is_rejected_before_target_change(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(RuntimeError, match="empty"):
        validate_build(file_manifest(source))

    (source / "index.html").write_text("ok", encoding="utf-8")
    with pytest.raises(RuntimeError, match="assets"):
        validate_build(file_manifest(source))


def test_incomplete_source_cannot_change_last_good_target(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    backup = tmp_path / "backup"
    source.mkdir()
    (source / "index.html").write_text("incomplete", encoding="utf-8")
    _build(target, "last-good")
    old_manifest = file_manifest(target)

    with pytest.raises(RuntimeError, match="assets"):
        publish_build(
            source=source,
            target=target,
            backup=backup,
            operation_id="incomplete",
        )

    assert file_manifest(target) == old_manifest
    assert not backup.exists()


def test_partial_cleanup_preserves_verified_live_and_backup(tmp_path, monkeypatch):
    source, target, backup = (tmp_path / name for name in ("source", "target", "backup"))
    _build(source, "new")
    _build(target, "old")
    old_manifest, new_manifest = file_manifest(target), file_manifest(source)
    rollback = tmp_path / ".target.rollback-partial"
    remove_tree = shutil.rmtree

    def partial_remove(path, *args, **kwargs):
        if path == rollback:
            (path / "index.html").unlink()
            raise PermissionError("synthetic locked asset")
        return remove_tree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", partial_remove)
    result = publish_build(source=source, target=target, backup=backup, operation_id="partial")

    assert result["status"] == "ok"
    assert file_manifest(target) == new_manifest
    assert file_manifest(backup) == old_manifest
    assert file_manifest(rollback) != old_manifest
    assert result["warnings"] == [{
        "code": "rollback_cleanup_failed",
        "path": str(rollback),
        "error_type": "PermissionError",
    }]
    assert not (tmp_path / ".target.failed-partial").exists()
    assert not (tmp_path / ".target.publish-partial").exists()


def test_live_readback_failure_still_restores_intact_old_build(tmp_path, monkeypatch):
    source, target, backup = (tmp_path / name for name in ("source", "target", "backup"))
    _build(source, "new")
    _build(target, "old")
    old_manifest, new_manifest = file_manifest(target), file_manifest(source)

    def corrupt_readback(path):
        manifest = file_manifest(path)
        if path == target and manifest == new_manifest:
            return {"synthetic-mismatch": {"size": 0, "sha256": "invalid"}}
        return manifest

    monkeypatch.setattr(publisher, "file_manifest", corrupt_readback)
    with pytest.raises(RuntimeError, match="live hash readback"):
        publish_build(source=source, target=target, backup=backup, operation_id="readback")
    assert file_manifest(target) == old_manifest
    assert file_manifest(backup) == old_manifest
    assert not (tmp_path / ".target.rollback-readback").exists()
    assert not (tmp_path / ".target.failed-readback").exists()


def test_install_rename_failure_still_restores_old_build(tmp_path, monkeypatch):
    source, target, backup = (tmp_path / name for name in ("source", "target", "backup"))
    _build(source, "new")
    _build(target, "old")
    old_manifest = file_manifest(target)
    replace = publisher.os.replace

    def fail_install(src, dst):
        if src == tmp_path / ".target.publish-rename":
            raise OSError("synthetic install failure")
        return replace(src, dst)

    monkeypatch.setattr(publisher.os, "replace", fail_install)
    with pytest.raises(OSError, match="synthetic install failure"):
        publish_build(source=source, target=target, backup=backup, operation_id="rename")
    assert file_manifest(target) == old_manifest
    assert file_manifest(backup) == old_manifest
    assert not (tmp_path / ".target.publish-rename").exists()


def _cli_fixture(tmp_path, monkeypatch):
    source, target = tmp_path / "source", tmp_path / "target"
    _build(source, "new")
    _build(target, "old")
    monkeypatch.setattr(publisher, "ROOT", tmp_path)
    monkeypatch.setattr(publisher, "TARGET", target)
    monkeypatch.setattr(publisher, "ARTIFACTS", tmp_path / "artifacts")
    monkeypatch.setattr(publisher, "EVIDENCE_ROOT", tmp_path / "artifacts" / "runtime")
    return source, target


def test_cli_reports_cleanup_warning_in_stdout_and_receipt(tmp_path, monkeypatch, capsys):
    source, target = _cli_fixture(tmp_path, monkeypatch)
    remove_tree = shutil.rmtree

    def partial_remove(path, *args, **kwargs):
        if path.parent == target.parent and path.name.startswith(".target.rollback-"):
            (path / "index.html").unlink()
            raise PermissionError("synthetic locked asset")
        return remove_tree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", partial_remove)
    monkeypatch.setattr(sys, "argv", ["publish", "--source", str(source), "--apply",
                                      "--confirm", publisher.CONFIRMATION])
    assert publisher.main() == 0
    summary = json.loads(capsys.readouterr().out)
    receipt = json.loads(Path(summary["evidence"]).read_text(encoding="utf-8"))
    assert summary["status"] == receipt["status"] == "ok"
    assert summary["warnings"] == receipt["warnings"]
    assert summary["warnings"][0]["code"] == "rollback_cleanup_failed"
    assert file_manifest(target) == file_manifest(source)


@pytest.mark.parametrize("apply", [False, True])
def test_cli_plan_and_missing_confirmation_do_not_publish(tmp_path, monkeypatch, apply):
    source, target = _cli_fixture(tmp_path, monkeypatch)
    before = file_manifest(target)
    monkeypatch.setattr(sys, "argv", ["publish", "--source", str(source)]
                        + (["--apply"] if apply else []))
    if apply:
        with pytest.raises(SystemExit) as exc:
            publisher.main()
        assert exc.value.code == 2
    else:
        assert publisher.main() == 0
    assert file_manifest(target) == before
    assert not (tmp_path / "artifacts").exists()
