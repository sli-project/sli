from pathlib import Path
import sys



ROOT = Path(__file__).resolve().parents[2]


def test_migration_055_is_additive_idempotent_and_rollback_guarded() -> None:
    forward = (
        ROOT
        / "config/postgres_migrations/055_semantic_finding_publication.sql"
    ).read_text(encoding="utf-8").casefold()
    rollback = (
        ROOT
        / "config/postgres_migrations/055_semantic_finding_publication.rollback.sql"
    ).read_text(encoding="utf-8").casefold()

    assert "create table if not exists semantic_finding_publications" in forward
    assert "before update or delete on semantic_finding_publications" in forward
    assert "grant select,insert,update on table findings" in forward
    assert "grant usage,select on sequence" in forward
    assert "values (55,'semantic_finding_publication')" in forward
    assert "publication evidence exists" in rollback
    assert "revoke select,insert,update on table findings" in rollback
