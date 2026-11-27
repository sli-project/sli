from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest



ROOT = Path(__file__).resolve().parents[2]
FORWARD = (ROOT / "config/postgres_migrations/066_administrative_activity_journal.sql").read_text(encoding="utf-8").lower()
ROLLBACK = (ROOT / "config/postgres_migrations/066_administrative_activity_journal.rollback.sql").read_text(encoding="utf-8").lower()


def test_migration_is_execute_only_hash_chained_and_append_only():
    assert "create table administrative_activity_v1" in FORWARD
    assert "security definer" in FORWARD
    assert "sha256(convert_to(v_content::text,'utf8'))" in FORWARD
    assert "sha256(v_previous_hash || v_content_hash)" in FORWARD
    assert "administrative activity idempotency conflict" in FORWARD
    assert "before update or delete" in FORWARD
    assert "before truncate" in FORWARD
    assert "grant execute on function append_administrative_activity_v1" in FORWARD
    assert "grant usage,create on schema public" in FORWARD
    assert "revoke create on schema public" in FORWARD
    assert "version=63 and name='radius_vpn_operations_read_boundary'" in FORWARD
    assert "version=65" not in FORWARD
    assert "set local role adlog_storage_owner" not in FORWARD.lower()
    assert "set local role adlog_storage_owner" not in ROLLBACK.lower()
    assert "rollback 066 requires migration superuser session" in ROLLBACK.lower()
    assert "radius_session_reconciliation_overlay" not in FORWARD
    assert "grant insert" not in FORWARD
    assert "grant update" not in FORWARD
    assert "grant delete" not in FORWARD
    assert "rollback 066 forbidden after administrative activity" in ROLLBACK
    assert "revoke usage on schema public" in ROLLBACK
