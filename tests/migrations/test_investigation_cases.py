from __future__ import annotations

import os
from uuid import UUID, uuid4

import pytest


def test_investigation_case_migration_has_durable_evidence_and_notes_tables() -> None:
    from pathlib import Path

    migration = (Path(__file__).resolve().parents[2] / "config" / "postgres_migrations" / "015_investigation_cases.sql").read_text(encoding="utf-8")

    assert "create table if not exists investigations" in migration
    assert "create table if not exists investigation_events" in migration
    assert "create table if not exists investigation_notes" in migration
    assert "event_db_id bigint not null references events(id) on delete restrict" in migration

    v2_migration = (Path(__file__).resolve().parents[2] / "config" / "postgres_migrations" / "016_investigation_evidence_v2.sql").read_text(encoding="utf-8")
    assert "drop constraint if exists investigation_events_event_db_id_fkey" in v2_migration
    assert "investigation_evidence_v2" in v2_migration


def test_public_uuid_migration_is_additive_and_reversible() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    forward = (root / "config/postgres_migrations/018_investigation_public_identity.sql").read_text(encoding="utf-8")
    rollback = (root / "config/postgres_migrations/018_investigation_public_identity.rollback.sql").read_text(encoding="utf-8")
    assert "add column if not exists public_id uuid" in forward
    assert "investigations_public_id_uidx" in forward
    assert "values (18, 'investigation_public_identity')" in forward
    assert "drop column if exists public_id" in rollback
