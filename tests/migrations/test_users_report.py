from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest



OBSERVED = datetime(2026, 8, 27, 0, 0, tzinfo=timezone.utc)


def test_users_report_migration_is_additive_registered_and_auditable() -> None:
    migration = Path("config/postgres_migrations/099_users_report_v1.sql").read_text(encoding="utf-8")
    rollback = Path("config/postgres_migrations/099_users_report_v1.rollback.sql").read_text(encoding="utf-8")
    assert "'ad.accounts.users'" in migration
    assert "'ad.users'" in migration
    assert "'/users-report'" in migration
    assert "account_risk_acceptances" in migration
    assert "account_risk_acceptance_audit" in migration
    assert "account_risk_investigation_links" in migration
    assert "account_risks.accept" in migration
    assert "valid_until > valid_from" in migration
    assert "drop table if exists account_risk_acceptance_audit" not in rollback
    assert "drop table if exists account_risk_acceptances" not in rollback
    assert "drop table if exists account_risk_investigation_links" not in rollback
    assert "delete from report_registry_v4 where report_key='ad.users'" in rollback


def test_legacy_users_report_scope_guard_and_update_use_the_same_domain() -> None:
    migration = Path("config/postgres_migrations/100_users_report_domain_scope.sql").read_text(encoding="utf-8")
    compact = "".join(migration.split())
    # Applied SQL stays immutable; the clean-install baseline substitutes its domain.
    domain_filters = compact.split("lower(domain.fqdn)='")[1:]
    assert len(domain_filters) == 2
    assert domain_filters[0].split("'", 1)[0] == domain_filters[1].split("'", 1)[0]
    assert "jsonb_build_object('kind','domain','ids'" in compact
    assert "netbios" not in migration.casefold()
