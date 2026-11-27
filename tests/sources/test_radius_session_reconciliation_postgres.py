from pathlib import Path

import pytest



ROOT = Path(__file__).resolve().parents[2]
FORWARD = (
    ROOT
    / "config/postgres_migrations/"
    "065_radius_session_reconciliation_overlay.sql"
).read_text(encoding="utf-8").lower()
ROLLBACK = (
    ROOT
    / "config/postgres_migrations/"
    "065_radius_session_reconciliation_overlay.rollback.sql"
).read_text(encoding="utf-8").lower()
OBSERVATION = "11111111-1111-1111-1111-111111111111"
EVIDENCE = "22222222-2222-2222-2222-222222222222"


def test_migration_is_append_only_and_least_privilege() -> None:
    assert "values (65,'radius_session_reconciliation_overlay')" in FORWARD
    assert "create role adlog_radius_session_reconciliation_writer" in FORWARD
    assert "nologin nosuperuser" in FORWARD
    assert "create table radius_session_reconciliation_attempts" in FORWARD
    assert "create table radius_session_identity_overlays" in FORWARD
    assert "grant insert(" in FORWARD
    assert "grant update" not in FORWARD
    assert "grant delete" not in FORWARD
    assert "rollback 065 forbidden after reconciliation evidence" in ROLLBACK
