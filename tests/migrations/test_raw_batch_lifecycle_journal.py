from __future__ import annotations

from pathlib import Path


import scripts.run_dc_log_pilot as pilot
from server.sli.core import postgres_runtime_pipeline as pg_pipeline


def _batch(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "raw"
    output = root / "DC1" / "batch-1"
    output.mkdir(parents=True)
    (output / "Security.jsonl").write_text('{"record_id":1}\n', encoding="utf-8")
    return root, output


def test_raw_cleanup_requires_archive_and_durable_same_manifest_authorization(tmp_path, monkeypatch):
    root, output = _batch(tmp_path)
    monkeypatch.setenv("ADLOG_DELETE_IMPORTED_RAW", "1")
    manifest = pilot.raw_batch_manifest(output_dir=output, raw_root=root, server="DC1")
    identity = str(manifest["batch_identity"])
    expected_hash = str(manifest["manifest_hash"])
    calls: list[tuple[str, str]] = []

    def authorize(*, batch_identity: str, manifest_hash: str) -> bool:
        calls.append((batch_identity, manifest_hash))
        return batch_identity == identity and manifest_hash == expected_hash

    assert pilot.cleanup_confirmed_raw_output(
        output_dir=output, raw_root=root, server="DC1", archive=False,
        batch_identity=identity, manifest_hash=expected_hash,
        authorize_cleanup=authorize,
    ) is False
    assert output.exists()
    assert calls == []

    assert pilot.cleanup_confirmed_raw_output(
        output_dir=output, raw_root=root, server="DC1", archive=True,
        batch_identity=identity, manifest_hash="0" * 64,
        authorize_cleanup=authorize,
    ) is False
    assert output.exists()
    assert calls == []

    assert pilot.cleanup_confirmed_raw_output(
        output_dir=output, raw_root=root, server="DC1", archive=True,
        batch_identity=identity, manifest_hash=expected_hash,
        authorize_cleanup=authorize,
    ) is True
    assert calls == [(identity, expected_hash)]
    assert not output.exists()


def test_manifest_is_stable_and_detects_raw_content_changes(tmp_path):
    root, output = _batch(tmp_path)
    first = pilot.raw_batch_manifest(output_dir=output, raw_root=root, server="DC1")
    second = pilot.raw_batch_manifest(output_dir=output, raw_root=root, server="DC1")
    assert first == second
    assert len(str(first["batch_identity"])) == 64
    assert len(str(first["manifest_hash"])) == 64

    (output / "Security.jsonl").write_text('{"record_id":2}\n', encoding="utf-8")
    changed = pilot.raw_batch_manifest(output_dir=output, raw_root=root, server="DC1")
    assert changed["batch_identity"] == first["batch_identity"]
    assert changed["manifest_hash"] != first["manifest_hash"]


def test_cleanup_recomputes_manifest_and_retains_changed_raw(tmp_path, monkeypatch):
    root, output = _batch(tmp_path)
    monkeypatch.setenv("ADLOG_DELETE_IMPORTED_RAW", "1")
    manifest = pilot.raw_batch_manifest(output_dir=output, raw_root=root, server="DC1")
    (output / "Security.jsonl").write_text('{"record_id":99}\n', encoding="utf-8")
    called = False

    def authorize(**_kwargs):
        nonlocal called
        called = True
        return True

    assert pilot.cleanup_confirmed_raw_output(
        output_dir=output, raw_root=root, server="DC1", archive=True,
        batch_identity=str(manifest["batch_identity"]),
        manifest_hash=str(manifest["manifest_hash"]),
        authorize_cleanup=authorize,
    ) is False
    assert output.exists()
    assert called is False


def test_cursor_outcome_is_fail_closed_for_partial_unknown_or_missing_channels():
    summary = {"channels": [
        {"channel": "Security", "status": "completed"},
        {"channel": "System", "status": "completed"},
    ]}
    committed = [
        {"channel": "Security", "decision": "committed"},
        {"channel": "System", "decision": "no_change"},
    ]
    assert pg_pipeline.raw_batch_cursor_outcome(summary=summary, audit_rows=committed) == ("committed", 2)
    assert pg_pipeline.raw_batch_cursor_outcome(summary=summary, audit_rows=committed[:1]) == ("not_committed", 1)
    assert pg_pipeline.raw_batch_cursor_outcome(
        summary={"channels": [{"channel": "Security", "status": "partial_timeout"}]},
        audit_rows=[{"channel": "Security", "decision": "committed"}],
    ) == ("not_committed", 0)
    assert pg_pipeline.raw_batch_cursor_outcome(
        summary={"channels": [{"channel": "Security"}]},
        audit_rows=[{"channel": "Security", "decision": "committed"}],
    ) == ("not_committed", 0)




def test_migration_127_grants_only_required_runtime_privileges_and_denies_public():
    sql = " ".join(
        Path("config/postgres_migrations/127_raw_batch_lifecycle.sql")
        .read_text(encoding="utf-8")
        .casefold()
        .split()
    )

    assert "revoke all on table raw_batch_lifecycle from public;" in sql
    assert "revoke all on table raw_batch_lifecycle from adlog_user;" in sql
    assert "grant select, insert, update on table raw_batch_lifecycle to adlog_user;" in sql
    for privilege in ("delete", "truncate", "references", "trigger"):
        assert f"grant {privilege}" not in sql


