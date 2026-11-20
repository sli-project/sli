"""The bundled AD catalog must be admitted before core publication."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.events.event_catalog import event_noise_classification


ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/215_directory_change_catalog_revision.sql"
SQL = PATH.read_text("utf-8")


def test_exact_bundled_catalog_revision_is_registered_without_rewriting_history():
    for event_id in (4624, 4625, 4728, 5136):
        _, version = event_noise_classification(event_id, "Security", "Microsoft-Windows-Security-Auditing")
        assert f"insert into public.event_catalog_revisions(version) values('{version}')" in SQL
    assert "on conflict(version) do nothing" in SQL
    assert "update public.event_catalog_revisions" not in SQL
    assert "delete from" not in SQL and "drop trigger" not in SQL
    assert "create or replace function" not in SQL


def test_forward_migration_requires_exact_predecessor_and_storage_owner():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((215, "directory_change_catalog_revision")) - 1] == (214, "file_audit_scoped_context")
    assert list(PATH.parent.glob("215_*.sql")) == [PATH]
    assert "version=214 and name='file_audit_scoped_context'" in SQL
    assert "where version>=215" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "set local role adlog_storage_owner;" in SQL
    assert SQL.strip().endswith("commit;")
