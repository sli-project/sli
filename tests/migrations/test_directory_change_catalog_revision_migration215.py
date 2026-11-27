"""The bundled AD catalog must be admitted before core publication."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory


ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/215_directory_change_catalog_revision.sql"
SQL = PATH.read_text("utf-8")


def test_forward_migration_requires_exact_predecessor_and_storage_owner():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((215, "directory_change_catalog_revision")) - 1] == (214, "file_audit_scoped_context")
    assert list(PATH.parent.glob("215_*.sql")) == [PATH]
    assert "version=214 and name='file_audit_scoped_context'" in SQL
    assert "where version>=215" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "set local role adlog_storage_owner;" in SQL
    assert SQL.strip().endswith("commit;")
