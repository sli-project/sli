"""Synthetic, one-shot file probes; no source or permission changes."""
from pathlib import Path

import pytest

from tools.lab import file_decoy as lab


@pytest.mark.parametrize("operation", ["read", "neighbor", "denied"])
def test_one_shot_probe_preserves_files_and_does_not_claim_collection_or_delivery(tmp_path, monkeypatch, operation):
    (tmp_path / "file-decoy-owned").touch()
    for name in ("decoy-bait.txt", "decoy-neighbor.txt"):
        (tmp_path / name).write_bytes(b"synthetic-content")
    original_open = Path.open
    if operation == "denied":
        def denied(path, *args, **kwargs):
            if path.name == "decoy-bait.txt":
                raise PermissionError("synthetic-private-detail")
            return original_open(path, *args, **kwargs)
        monkeypatch.setattr(Path, "open", denied)
    result = lab.generate(tmp_path, operation=operation)
    assert result["state"] == "native_operation_completed"
    assert result["expected_detection"] == ("no_match" if operation == "neighbor" else "high")
    assert all(result[key] == "not_proven" for key in ("native_evidence", "sli_queue", "replay", "audit_loss", "smtp", "telegram"))
    monkeypatch.undo()
    assert (tmp_path / "decoy-bait.txt").read_bytes() == b"synthetic-content"
    assert (tmp_path / "decoy-neighbor.txt").read_bytes() == b"synthetic-content"


def test_missing_ownership_and_unexpected_success_are_honest(tmp_path):
    with pytest.raises(ValueError, match="file_decoy_lab_not_owned"):
        lab.generate(tmp_path, operation="read")
    (tmp_path / "file-decoy-owned").touch()
    (tmp_path / "decoy-bait.txt").write_bytes(b"synthetic")
    assert lab.generate(tmp_path, operation="denied")["state"] == "unexpected_outcome"
    assert len(list(tmp_path.iterdir())) == 2


def test_cli_errors_do_not_print_paths_or_native_exceptions(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["file_decoy", "--root", "synthetic-private-missing", "--operation", "read"])
    assert lab.main() == 1
    assert capsys.readouterr().out == '{"code": "file_decoy_lab_unavailable", "state": "not_proven"}\n'
