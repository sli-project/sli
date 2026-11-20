"""Native LAB generator uses only newly created synthetic files, never a source."""
import pytest

from tools.lab import file_ransom as lab


@pytest.mark.parametrize("operation,count,files", [
    ("write", 99, 99), ("write", 100, 100), ("boundary", 100, 100), ("delete", 100, 0),
    ("read", 100, 100), ("repeat", 100, 1), ("burst", 110, 110),
])
def test_one_shot_native_operations_and_honest_unverified_delivery(tmp_path, operation, count, files):
    (tmp_path / "file-ransom-owned").touch()
    original = tmp_path / "existing.txt"
    original.write_text("preserve")
    pauses = []
    result = lab.generate(tmp_path, operation=operation, count=count, pause=pauses.append)
    assert result["state"] == "native_operations_completed"
    assert result["operations"] == count
    assert len(list((tmp_path / ("ransom-" + result["run_id"])).glob("*.txt"))) == files
    assert original.read_text() == "preserve"
    assert all(result[key] == "not_proven" for key in ("native_evidence", "sli_queue", "replay", "smtp", "telegram"))
    if operation == "burst":
        assert len(pauses) == 109 and sum(pauses) < 300
        assert result["expected_default_burst"] == "high_or_explicit_temporary_exclusion"
    elif operation == "boundary":
        assert pauses == [10] and result["first_phase_files"] == 99
    elif operation in {"read", "delete"}:
        assert pauses == [301]
        assert result["setup_may_trigger_write"] and result["setup_writes"] == count
    else:
        assert not pauses


def test_requires_owned_root_and_bounds_work_before_creating_files(tmp_path):
    with pytest.raises(ValueError, match="file_ransom_lab_not_owned"):
        lab.generate(tmp_path, operation="write")
    (tmp_path / "file-ransom-owned").touch()
    for count in (0, 1001, True):
        with pytest.raises(ValueError, match="file_ransom_lab_arguments_invalid"):
            lab.generate(tmp_path, operation="write", count=count)
    assert not list(tmp_path.glob("ransom-*"))


def test_two_roots_and_repeated_runs_have_independent_files(tmp_path):
    ids = set()
    for name in ("root-one", "root-two"):
        root = tmp_path / name
        root.mkdir()
        (root / "file-ransom-owned").touch()
        for _ in range(2):
            ids.add(lab.generate(root, operation="write", count=1)["run_id"])
    assert len(ids) == 4


def test_cli_never_prints_private_paths_or_exception_details(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["file_ransom", "--root", "synthetic-private-missing", "--operation", "write"])
    assert lab.main() == 1
    assert capsys.readouterr().out == '{"code": "file_ransom_lab_unavailable", "state": "not_proven"}\n'


@pytest.mark.parametrize("operation,count", [("boundary", 100), ("burst", 110)])
def test_cli_defaults_match_boundary_and_normal_burst_scenarios(tmp_path, monkeypatch, capsys, operation, count):
    from pathlib import Path
    from types import SimpleNamespace
    (tmp_path / "file-ransom-owned").touch()
    captured = []
    monkeypatch.setattr(lab, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(lab, "Path", lambda value: tmp_path if value == "C:/SLI-Lab" else Path(value))
    monkeypatch.setattr(lab, "generate", lambda root, **kwargs: captured.append((root, kwargs)) or {
        "state": "native_operations_completed"})
    monkeypatch.setattr("sys.argv", ["file_ransom", "--root", str(tmp_path), "--operation", operation])
    assert lab.main() == 0
    assert captured == [(tmp_path, {"operation": operation, "count": count, "window_seconds": 300})]
    assert capsys.readouterr().out == '{"state": "native_operations_completed"}\n'
