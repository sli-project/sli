from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import inspect
import json
from pathlib import Path
from uuid import UUID

import pytest



MIGRATION = Path(
    "config/postgres_migrations/"
    "058_radius_accounting_transaction_foundation.sql"
)
ROLLBACK = Path(
    "config/postgres_migrations/"
    "058_radius_accounting_transaction_foundation.rollback.sql"
)




def test_migration_058_is_atomic_least_privilege_foundation() -> None:
    sql = MIGRATION.read_text(encoding="utf-8").lower()
    assert "requires schema migration 055" in sql
    assert "create role adlog_radius_accounting_worker" in sql
    assert "nologin nosuperuser nocreatedb nocreaterole" in sql
    assert "acquisition_source_instances" in sql
    assert "acquisition_consumer_subscriptions" in sql
    assert "core_evidence_manifests" in sql
    assert "radius_accounting_session_observations" in sql
    assert "acquisition_delivery_outbox" in sql
    assert "radius_accounting_class_cache" in sql
    assert "cursor_start_byte_offset" in sql
    assert "batch_record_ordinal" in sql
    assert "raw_record" not in sql
    assert "account_session_id" not in sql
    assert "nas_identity" not in sql
    assert "values (58,'radius_accounting_transaction_foundation')" in sql


def test_migration_058_rollback_refuses_any_persisted_state() -> None:
    sql = ROLLBACK.read_text(encoding="utf-8").lower()
    guard = sql.index(
        "migration 058 rollback refuses persisted acquisition evidence/state"
    )
    first_drop = sql.index("drop table")
    assert guard < first_drop
    assert "drop role adlog_radius_accounting_worker" in sql
    assert "delete from schema_migrations" in sql
