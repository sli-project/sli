from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest


OBSERVED = datetime.now(timezone.utc).replace(microsecond=0)
ROOT = Path(__file__).resolve().parents[2]


def test_active_directory_migration_republishes_existing_report_without_account_or_computer_fields():
    migration = (ROOT / "config/postgres_migrations/102_active_directory_report_v1.sql").read_text(encoding="utf-8")
    rollback = (ROOT / "config/postgres_migrations/102_active_directory_report_v1_rollback.sql").read_text(encoding="utf-8")
    folded = migration.casefold()

    assert "'ad.state'" in migration
    assert "'Active Directory'" in migration
    assert "'/ad-report'" in migration
    assert "'view','export'" in migration.replace(" ", "")
    assert "domain_controller" in migration
    assert "replication_link" in migration
    assert "domain_trust" in migration
    assert "ad_user" not in folded
    assert "ad_computer" not in folded
    assert "gpo" not in folded
    assert "insert into schema_migrations(version,name) values(102" in folded
    assert "Состояние и риски Active Directory" in rollback
