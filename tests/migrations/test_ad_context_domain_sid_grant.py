"""Migration 145: AD Context import may record the domain SID once."""

from __future__ import annotations

from inspect import getsource
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FORWARD = ROOT / "config/postgres_migrations/145_ad_context_domain_sid_grant.sql"
ROLLBACK = ROOT / "config/postgres_migrations/145_ad_context_domain_sid_grant.rollback.sql"


def _statements(path: Path) -> str:
    return " ".join(line for line in path.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("--"))


def test_grant_is_column_level_on_domain_sid_only() -> None:
    sql = _statements(FORWARD)
    assert "grant update (domain_sid) on public.domains to adlog_context_worker;" in sql
    assert sql.count("grant ") == 1
    assert "requires exact migration 144 ad_context_evidence_record_key_index" in sql
    assert "values (145, 'ad_context_domain_sid_grant')" in sql


def test_rollback_revokes_only_that_grant() -> None:
    sql = _statements(ROLLBACK)
    assert "revoke update (domain_sid) on public.domains from adlog_context_worker;" in sql
    assert "delete from schema_migrations where version = 145;" in sql


def test_import_path_needs_exactly_this_update() -> None:
    from server.ad_context.repository import _resolve_domain

    assert "update domains set domain_sid=%s where id=%s and domain_sid is null" in getsource(_resolve_domain)
