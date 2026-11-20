from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from server.sli.storage import storage_lifecycle_bounded_io as bounded_io


def test_read_bytes_rejects_same_size_in_place_mutation(monkeypatch, tmp_path: Path) -> None:
    payload = tmp_path / "payload.json"
    payload.write_bytes(b'{"safe":true}')
    actual_fstat = bounded_io.os.fstat
    expected = payload.stat()
    target_calls = 0

    def changed_mtime(descriptor: int):
        nonlocal target_calls
        current = actual_fstat(descriptor)
        is_target = (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino)
        if is_target:
            target_calls += 1
        return SimpleNamespace(
            st_dev=current.st_dev,
            st_ino=current.st_ino,
            st_size=current.st_size,
            st_mtime_ns=current.st_mtime_ns + (1 if is_target and target_calls > 1 else 0),
            st_ctime_ns=current.st_ctime_ns,
        )

    monkeypatch.setattr(bounded_io.os, "fstat", changed_mtime)

    with pytest.raises(RuntimeError, match="bounded_file_changed_during_read"):
        bounded_io.read_bytes(payload, max_bytes=1024, too_large="too_large")
