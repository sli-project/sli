from pathlib import Path
from datetime import datetime, timedelta, timezone



ROOT = Path(__file__).resolve().parents[2]


def test_migration_79_exposes_only_publication_membership_to_web_role() -> None:
    forward = (
        ROOT
        / "config/postgres_migrations/079_semantic_finding_report_reader.sql"
    ).read_text(encoding="utf-8").casefold()
    rollback = (
        ROOT
        / "config/postgres_migrations/079_semantic_finding_report_reader.rollback.sql"
    ).read_text(encoding="utf-8").casefold()

    assert "is_semantic_finding_published_v1(bigint)" in forward
    assert "security definer" in forward
    assert "set search_path = pg_catalog, public" in forward
    assert "grant execute on function is_semantic_finding_published_v1(bigint)" in forward
    assert "grant select on" not in forward
    assert "semantic_finding_publications" in forward
    assert "revoke all on function is_semantic_finding_published_v1(bigint)" in rollback
    assert "drop function if exists is_semantic_finding_published_v1(bigint)" in rollback
