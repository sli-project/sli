"""Synthetic-only regression coverage: no live reports or repository scans."""
import json
import os
import subprocess
import sys
import urllib.error
from zipfile import ZipFile

import pytest

from scripts.maintenance import bundle_common as bundle
from scripts.maintenance import export_report_snapshots as exporter
from scripts.maintenance import github_sanitary_check as sanitary


@pytest.mark.parametrize("failure", [False, True])
def test_capture_closes_allocated_descriptors(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(bundle, "TMP_DIR", tmp_path)
    allocated = []
    original = bundle.tempfile.mkstemp

    def tracked(*args, **kwargs):
        fd, name = original(*args, **kwargs)
        allocated.append(fd)
        return fd, name

    monkeypatch.setattr(bundle.tempfile, "mkstemp", tracked)
    command = [str(tmp_path / "missing-executable")] if failure else [sys.executable, "-c", "print('synthetic')"]
    result = bundle.run_command(command, cwd=tmp_path)
    assert result["exit_code"] == (-1 if failure else 0)
    leaked = []
    for fd in allocated:
        try:
            os.fstat(fd)
        except OSError:
            continue
        leaked.append(fd)
        os.close(fd)  # Do not leak in the baseline reproduction itself.
    assert not leaked
    assert list(tmp_path.iterdir()) == []


def test_partial_capture_allocation_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "TMP_DIR", tmp_path)
    original = bundle.tempfile.mkstemp
    calls = []

    def fail_second(*args, **kwargs):
        if calls:
            raise OSError("synthetic allocation failure")
        fd, name = original(*args, **kwargs)
        calls.append(fd)
        return fd, name

    monkeypatch.setattr(bundle.tempfile, "mkstemp", fail_second)
    try:
        result = bundle.run_command(["unused"], cwd=tmp_path)
        assert result["exit_code"] == -1
        assert not list(tmp_path.iterdir())
    finally:
        for fd in calls:
            try:
                os.close(fd)
            except OSError:
                pass


@pytest.mark.parametrize("tracked", [False, True])
def test_git_enumeration_scans_real_unusual_names(tmp_path, tracked):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    names = ['кириллица.txt', 'line\nbreak.txt', 'quote"name.txt', ' space .txt']
    for name in names:
        (tmp_path / name).write_text("-----BEGIN " + "PRIVATE KEY-----", encoding="utf-8")
    if tracked:
        subprocess.run(["git", "-C", str(tmp_path), "add", "--all"], check=True)
    assert {p.name for p in sanitary._candidate_files(tmp_path)} == set(names)
    report = sanitary.scan(tmp_path)
    assert {f["path"] for f in report["findings"] if f["type"] == "private_key"} == set(names)


@pytest.mark.parametrize("failed", [False, True])
def test_redacted_bundle_metadata_names_and_error_pages(tmp_path, monkeypatch, failed):
    query = "SYNTHETIC\\alice"
    requests = []

    class Response:
        status = 200
        headers = {"Content-Type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self):
            if "/api/" not in requests[-1]:
                return f"<p>{query} 192.0.2.25</p>".encode()
            return json.dumps({"account": query, "ip": "192.0.2.25"}).encode()

    def response(req, **kwargs):
        requests.append(req.full_url)
        if failed:
            raise urllib.error.URLError(req.full_url + " " + query)
        return Response()

    monkeypatch.setattr(exporter.urllib.request, "urlopen", response)
    out = tmp_path / "snapshot"
    args = ["--base-url", "http://192.0.2.25:8080", "--output-dir", str(out), "--q", query, "--redact"]
    assert exporter.main(args) == (2 if failed else 0)
    assert any("SYNTHETIC%5Calice" in url for url in requests)
    with ZipFile(out.with_suffix(".zip")) as archive:
        for name in archive.namelist():
            text = name + archive.read(name).decode()
            assert "synthetic" not in text.lower()
            assert "alice" not in text.lower()
            assert "192.0.2.25" not in text
    manifest = json.loads((out / "snapshot_manifest.json").read_text())
    assert manifest["args"]["redact"] is True


def test_timeout_capture_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "TMP_DIR", tmp_path)
    result = bundle.run_command([sys.executable, "-c", "import time; time.sleep(2)"], cwd=tmp_path, timeout=0)
    assert result["timed_out"] is True
    assert result["exit_code"] == -2
    assert not list(tmp_path.iterdir())


def test_reopening_capture_failure_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "TMP_DIR", tmp_path)
    from pathlib import Path
    original = Path.open

    def fail_open(path, *args, **kwargs):
        if path.name.startswith("adlog-cmd-stderr-"):
            raise OSError("synthetic open failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_open)
    result = bundle.run_command(["unused"], cwd=tmp_path)
    assert result["exit_code"] == -1
    assert not list(tmp_path.iterdir())


def test_nonredacted_capture_retains_contract(tmp_path, monkeypatch):
    def fail(req, **kwargs):
        raise urllib.error.URLError("synthetic reason")

    monkeypatch.setattr(exporter.urllib.request, "urlopen", fail)
    target = exporter.Target("query_alice", "/?q=alice")
    result = exporter._save_response(target, "http://localhost", tmp_path, 1)
    assert result.name == target.name
    assert result.output_file == "query_alice.html"
    assert result.source_url == "http://localhost/?q=alice"
    assert "synthetic reason" in result.error
    assert "alice" in (tmp_path / result.output_file).read_text()


@pytest.mark.skipif(os.name == "nt", reason="POSIX byte filenames")
def test_git_enumeration_preserves_non_utf8_and_backslash_names(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for name in [b"invalid-\xff.txt", b"back\\slash.txt"]:
        fd = os.open(os.fsencode(tmp_path) + b"/" + name, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write("-----BEGIN " + "PRIVATE KEY-----")
    assert len(sanitary.scan(tmp_path)["findings"]) == 2


def test_redacted_export_refuses_existing_unreviewed_files(tmp_path, monkeypatch):
    (tmp_path / "old.txt").write_text("synthetic old capture")
    monkeypatch.setattr(exporter.urllib.request, "urlopen", lambda *_a, **_k: pytest.fail("must not fetch"))
    with pytest.raises(ValueError, match="empty"):
        exporter.main(["--output-dir", str(tmp_path), "--redact"])
    assert (tmp_path / "old.txt").read_text() == "synthetic old capture"


def test_redacted_archive_does_not_embed_operator_directory_name(tmp_path):
    out = tmp_path / "synthetic_alice"
    out.mkdir()
    (out / "index.html").write_text("synthetic body")
    with ZipFile(exporter.make_zip(out, redact=True)) as archive:
        assert archive.namelist() == ["snapshot/index.html"]


@pytest.mark.parametrize("redact", [False, True])
def test_existing_sibling_archive_is_preserved_before_fetch(tmp_path, monkeypatch, redact):
    out = tmp_path / "snapshot"
    archive = out.with_suffix(".zip")
    archive.write_bytes(b"unrelated synthetic archive")
    monkeypatch.setattr(exporter.urllib.request, "urlopen", lambda *_a, **_k: pytest.fail("must not fetch"))
    with pytest.raises(FileExistsError, match="ZIP"):
        exporter.main(["--output-dir", str(out)] + (["--redact"] if redact else []))
    assert archive.read_bytes() == b"unrelated synthetic archive"
    assert not out.exists()


def test_archive_creation_race_preserves_winner(tmp_path, monkeypatch):
    from pathlib import Path
    out = tmp_path / "snapshot"
    out.mkdir()
    (out / "index.html").write_text("synthetic")
    archive = out.with_suffix(".zip")
    original = Path.open

    def competing_open(path, *args, **kwargs):
        if path == archive and args and args[0] == "xb":
            with original(path, "wb") as stream:
                stream.write(b"other invocation won")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", competing_open)
    with pytest.raises(FileExistsError):
        exporter.make_zip(out)
    assert archive.read_bytes() == b"other invocation won"


def test_failed_archive_write_retains_partial_and_requires_fresh_destination(tmp_path, monkeypatch):
    out = tmp_path / "snapshot"
    out.mkdir()
    (out / "index.html").write_text("synthetic")

    def fail_write(*_args, **_kwargs):
        raise OSError("synthetic write failure")

    monkeypatch.setattr(exporter.zipfile.ZipFile, "write", fail_write)
    with pytest.raises(OSError, match="synthetic write failure"):
        exporter.make_zip(out)
    assert out.with_suffix(".zip").exists()
    with pytest.raises(FileExistsError):
        exporter.make_zip(out)
    assert (out / "index.html").read_text() == "synthetic"


@pytest.mark.skipif(os.name == "nt", reason="POSIX replacement of an open archive")
def test_failed_archive_does_not_remove_replacement(tmp_path, monkeypatch):
    out = tmp_path / "snapshot"
    out.mkdir()
    (out / "index.html").write_text("synthetic")
    archive = out.with_suffix(".zip")

    def replace_then_fail(*_args, **_kwargs):
        archive.unlink()
        archive.write_bytes(b"foreign replacement")
        raise OSError("synthetic replacement race")

    monkeypatch.setattr(exporter.zipfile.ZipFile, "write", replace_then_fail)
    with pytest.raises(OSError, match="replacement race"):
        exporter.make_zip(out)
    assert archive.read_bytes() == b"foreign replacement"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink fixture")
def test_dangling_archive_symlink_is_a_preflight_collision(tmp_path, monkeypatch):
    out = tmp_path / "snapshot"
    archive = out.with_suffix(".zip")
    archive.symlink_to(tmp_path / "missing-foreign-target")
    monkeypatch.setattr(exporter.urllib.request, "urlopen", lambda *_a, **_k: pytest.fail("must not fetch"))
    with pytest.raises(FileExistsError, match="ZIP"):
        exporter.main(["--output-dir", str(out), "--redact"])
    assert archive.is_symlink()
    assert not archive.exists()
    assert not out.exists()


def test_failed_archive_never_unlinks_after_ownership_stat(tmp_path, monkeypatch):
    from pathlib import Path
    out = tmp_path / "snapshot"
    out.mkdir()
    (out / "index.html").write_text("synthetic")
    archive = out.with_suffix(".zip")
    original_stat = Path.stat
    replaced = []

    def replace_after_stat(path, *args, **kwargs):
        identity = original_stat(path, *args, **kwargs)
        if path == archive and kwargs.get("follow_symlinks") is False:
            archive.unlink()
            archive.write_bytes(b"foreign replacement after ownership stat")
            replaced.append(True)
        return identity

    def fail_write(*_args, **_kwargs):
        raise OSError("synthetic write failure")

    monkeypatch.setattr(Path, "stat", replace_after_stat)
    monkeypatch.setattr(exporter.zipfile.ZipFile, "write", fail_write)
    with pytest.raises(OSError, match="synthetic write failure") as error:
        exporter.make_zip(out)
    # With no cleanup probe there is no replacement; the owned partial remains.
    # If an ownership probe is reintroduced, replacement after it must survive.
    assert archive.exists()
    if replaced:
        assert archive.read_bytes() == b"foreign replacement after ownership stat"
    assert any("partial archive" in note for note in error.value.__notes__)
