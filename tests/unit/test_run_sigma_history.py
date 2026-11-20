from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from scripts.dev import run_sigma_history as runner
from server.sli.sigma.compiler import CompiledRule, IRExpression, IRValue


def xml(event_id=1102, record_id=1):
    provider = ("Microsoft-Windows-Eventlog" if event_id == 1102
                else "Microsoft-Windows-Security-Auditing")
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{provider}"/><EventID>{event_id}</EventID><Version>0</Version>'
        f'<EventRecordID>{record_id}</EventRecordID><Channel>Security</Channel>'
        '<Computer>fixture.example.invalid</Computer>'
        '<TimeCreated SystemTime="2026-01-01T01:00:00Z"/></System>'
        '<EventData><Data Name="SubjectUserName">fixture-private-value</Data></EventData></Event>'
    )


def row(number, payload):
    return {"native_id": str(number), "source_xml": payload,
            "sha256": hashlib.sha256(payload.encode()).hexdigest() if payload is not None else "f" * 64,
            "occurred_at": "2026-01-01T01:00:00Z"}


@pytest.fixture
def copy_document():
    rows = [row(1, xml()), row(2, xml(4625)), row(3, xml(9999)), row(4, None)]
    return {"version": runner.COPY_VERSION, "exported_at": "2026-01-02T00:00:00Z",
            "partitions": [{"scope": {"installation_id": "fixture-installation",
                                      "source_instance_id": "fixture-source", "source_generation": "fixture-generation"},
                            "storage_kind": "core_event", "start": "2026-01-01T00:00:00Z",
                            "end": "2026-01-02T00:00:00Z", "high_watermark": len(rows), "records": rows}]}


def save_copy(tmp_path, document):
    raw = json.dumps(document).encode()
    path = tmp_path / "private-copy.json"
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


def profile():
    rules = tuple(CompiledRule(f"00000000-0000-0000-0000-{number:012d}", "a" * 64, "security",
                               IRExpression("compare", field="EventID", value=IRValue("number", 1102)),
                               ("EventID",), "Fixture Team", "DRL-1.1", "", "b" * 40)
                  for number in range(1, 26))
    return SimpleNamespace(compiled=rules, unsupported=())


def test_sequential_copy_has_all_25_rules_and_quality_counts(tmp_path, copy_document):
    reader = runner.LabCopyReader(*save_copy(tmp_path, copy_document))
    result = runner.evaluate_copy(reader, profile())
    assert (result.status, result.reason, result.mode) == ("completed", "snapshot_exhausted", "test")
    assert result.checkpoint.rows_read == 4
    assert len(result.checkpoint.counts) == 25
    assert all((r.scanned, r.evaluable, r.matched, r.unknown) == (4, 2, 1, 2)
               for r in result.checkpoint.counts)
    assert len(result.checkpoint.samples) == 10
    assert all(sample.ref.native_id == "1" for sample in result.checkpoint.samples)
    exported = json.dumps(result.manifest())
    assert "fixture-private-value" not in exported
    assert "fixture.example.invalid" not in exported
    assert "source_xml" not in exported
    assert all(r.suppressed == 0 for r in result.checkpoint.counts)


def test_copy_resumes_bounded_slices(tmp_path, copy_document):
    block = copy_document["partitions"][0]
    block["records"] = [row(n, xml(record_id=n)) for n in range(1, 102)]
    block["high_watermark"] = 101
    reader = runner.LabCopyReader(*save_copy(tmp_path, copy_document))
    partial = runner.evaluate_copy(reader, profile(), max_slices=1)
    assert partial.status == "partial"
    assert partial.checkpoint.rows_read == 100
    completed = runner.evaluate_copy(reader, profile())
    assert completed.status == "completed"
    assert completed.checkpoint.rows_read == 101
    assert all(r.scanned == 101 for r in completed.checkpoint.counts)


def test_native_submicrosecond_time_is_preserved(tmp_path, copy_document):
    first = copy_document["partitions"][0]["records"][0]
    first["source_xml"] = first["source_xml"].replace("01:00:00Z", "01:00:00.0000007Z")
    first["sha256"] = hashlib.sha256(first["source_xml"].encode()).hexdigest()
    first["occurred_at"] = "2026-01-01T01:00:00.0000007Z"
    reader = runner.LabCopyReader(*save_copy(tmp_path, copy_document))
    assert runner.evaluate_copy(reader, profile()).status == "completed"


def test_cancel_and_incomplete_profile_never_claim_completed(tmp_path, copy_document):
    reader = runner.LabCopyReader(*save_copy(tmp_path, copy_document))
    result = runner.evaluate_copy(reader, profile(), cancelled=lambda: True)
    assert result.status == "cancelled"
    assert result.checkpoint.rows_read == 0
    incomplete = profile()
    incomplete.compiled = incomplete.compiled[:-1]
    with pytest.raises(runner.LabCopyError, match="sigma_lab_profile_incomplete"):
        runner.evaluate_copy(reader, incomplete)
    incomplete = profile()
    incomplete.unsupported = ("fixture-unsupported",)
    with pytest.raises(runner.LabCopyError, match="sigma_lab_profile_incomplete"):
        runner.evaluate_copy(reader, incomplete)


@pytest.mark.parametrize("mutation", ["checksum", "payload", "truncated", "time", "scope", "store", "empty", "native_id"])
def test_copy_fails_closed_before_evaluation(tmp_path, copy_document, mutation):
    block = copy_document["partitions"][0]
    if mutation == "payload":
        block["records"][0]["source_xml"] += "changed"
    elif mutation == "truncated":
        block["records"].pop()
    elif mutation == "time":
        block["records"][0]["occurred_at"] = "2026-01-01T02:00:00Z"
    elif mutation == "scope":
        block["scope"]["source_generation"] = ""
    elif mutation == "store":
        block["storage_kind"] = "workstation_observation"
    elif mutation == "empty":
        block["records"] = []
        block["high_watermark"] = 0
    elif mutation == "native_id":
        block["records"][0]["native_id"] = "fixture-private-value"
    path, digest = save_copy(tmp_path, copy_document)
    with pytest.raises(runner.LabCopyError, match="^sigma_lab_copy_invalid$"):
        runner.LabCopyReader(path, "0" * 64 if mutation == "checksum" else digest)


def test_copy_size_and_row_bounds(tmp_path, copy_document, monkeypatch):
    path, digest = save_copy(tmp_path, copy_document)
    monkeypatch.setattr(runner, "MAX_COPY_BYTES", 10)
    with pytest.raises(runner.LabCopyError):
        runner.LabCopyReader(path, digest)
    monkeypatch.setattr(runner, "MAX_COPY_BYTES", 32 * 1024 * 1024)
    monkeypatch.setattr(runner, "MAX_ROWS", 3)
    with pytest.raises(runner.LabCopyError):
        runner.LabCopyReader(path, digest)


def test_cli_writes_terminal_manifest_and_refuses_overwrite(tmp_path, copy_document, monkeypatch, capsys):
    path, digest = save_copy(tmp_path, copy_document)
    monkeypatch.setattr(runner, "compile_profile", lambda archive: profile())
    output = tmp_path / "result"
    args = ["--archive", "fixture.zip", "--copy", str(path), "--copy-sha256", digest, "--output", str(output)]
    assert runner.main(args) == 0
    manifest = json.loads((output / "result.json").read_text())
    assert manifest["status"] == "completed"
    assert len(manifest["rules"]) == 25
    assert manifest["input_copy"]["sha256"] == digest
    assert len(manifest["input_copy"]["scan_samples"]) == 4
    original = (output / "result.json").read_bytes()
    assert runner.main(args) == 1
    assert (output / "result.json").read_bytes() == original
    assert "fixture-private-value" not in capsys.readouterr().out


def test_scan_samples_on_zero_matches_are_distinct_from_positive_refs(tmp_path, copy_document):
    block = copy_document["partitions"][0]
    block["records"] = [row(2, xml(4625))]
    block["high_watermark"] = 1
    reader = runner.LabCopyReader(*save_copy(tmp_path, copy_document))
    result = runner.evaluate_copy(reader, profile())
    output = tmp_path / "zero-matches"
    runner.write_copy_result(result, reader, output)
    manifest = json.loads((output / "result.json").read_text())
    assert manifest["checkpoint"]["samples"] == []
    assert all(r["matched"] == 0 for r in manifest["checkpoint"]["counts"])
    assert manifest["input_copy"]["scan_samples"][0]["ref"]["native_id"] == "2"
    assert "fixture-private-value" not in json.dumps(manifest)


def test_cancelled_copy_exports_no_unscanned_refs(tmp_path, copy_document):
    reader = runner.LabCopyReader(*save_copy(tmp_path, copy_document))
    result = runner.evaluate_copy(reader, profile(), cancelled=lambda: True)
    output = tmp_path / "cancelled"
    runner.write_copy_result(result, reader, output)
    assert json.loads((output / "result.json").read_text())["input_copy"]["scan_samples"] == []


@pytest.mark.parametrize("slices", [0, 21, True])
def test_invalid_slice_budget(tmp_path, copy_document, slices):
    reader = runner.LabCopyReader(*save_copy(tmp_path, copy_document))
    with pytest.raises(runner.LabCopyError, match="sigma_lab_slice_budget_invalid"):
        runner.evaluate_copy(reader, profile(), max_slices=slices)
