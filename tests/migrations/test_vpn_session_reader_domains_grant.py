"""Migration 148: VPN session reader role reads domains(id, fqdn) on clean installs."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FORWARD = ROOT / "config/postgres_migrations/148_vpn_session_reader_domains_grant.sql"
ROLLBACK = ROOT / "config/postgres_migrations/148_vpn_session_reader_domains_grant.rollback.sql"


def _statements(path: Path) -> str:
    return " ".join(line for line in path.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("--"))


def test_grant_is_exactly_id_and_fqdn_for_the_reader_role() -> None:
    sql = _statements(FORWARD)
    grants = re.findall(r"grant\s+[^;]+;", sql)
    assert grants == ["grant select (id, fqdn) on public.domains to adlog_vpn_session_reader_owner;"]
    assert "requires exact migration 147 domain_controller_targets" in sql
    assert "pg_advisory_xact_lock" in sql
    assert "values (148, 'vpn_session_reader_domains_grant')" in sql


def test_rollback_revokes_only_that_grant_and_only_when_latest() -> None:
    sql = _statements(ROLLBACK)
    assert re.findall(r"revoke\s+[^;]+;", sql) == [
        "revoke select (id, fqdn) on public.domains from adlog_vpn_session_reader_owner;"
    ]
    assert "version > 148" in sql
    assert "delete from schema_migrations where version = 148;" in sql
