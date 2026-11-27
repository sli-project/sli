from __future__ import annotations

from pathlib import Path




def _batch(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "raw"
    output = root / "DC1" / "batch-1"
    output.mkdir(parents=True)
    (output / "Security.jsonl").write_text('{"record_id":1}\n', encoding="utf-8")
    return root, output


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
