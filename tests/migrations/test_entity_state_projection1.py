from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def _observation(*, event_id: int = 10, at: str = "2026-07-18T10:00:00Z", status: str = "enabled") -> dict:
    return {
        "entity_id": 7, "state_type": "account.access", "severity": "medium",
        "status": status, "observed_at_utc": at, "summary": "evidence",
        "source_event_db_id": event_id, "rule_id": "account-enabled-4722",
        "rule_version": "entity-state-1.0", "projection_status": "normal", "details": {},
    }


class ClaimCursor:
    def __init__(self):
        self.sql = ""
        self.params = ()

    def execute(self, sql, params=()):
        self.sql = sql
        self.params = params

    def fetchall(self):
        return []


def test_migration_has_forward_rollback_and_fail_closed_active_work_guard() -> None:
    forward = Path("config/postgres_migrations/019_entity_state_projection.sql").read_text(encoding="utf-8")
    rollback = Path("config/postgres_migrations/019_entity_state_projection.rollback.sql").read_text(encoding="utf-8")
    assert "candidate_states jsonb" in forward
    assert "lease_token uuid" in forward and "max_attempts" in forward
    assert "entity_state_current" in forward
    assert "rollback forbidden while projection data exists" in rollback
    assert "grant insert on entity_states to adlog_storage_worker" in forward
    assert "grant usage on sequence entity_states_id_seq to adlog_storage_worker" in forward
    role_switch = forward.index("set local role adlog_storage_owner")
    assert forward.index("grant insert on entity_states to adlog_storage_worker") < role_switch
    assert forward.index("grant usage on sequence entity_states_id_seq to adlog_storage_worker") < role_switch
    assert forward.index("grant usage, create on schema public to adlog_storage_owner") < role_switch
    assert forward.index("grant references on entities_v2, events_v2_core to adlog_storage_owner") < role_switch
    assert forward.index("grant select, insert, update on schema_migrations to adlog_storage_owner") < role_switch
    assert forward.index("grant usage, select on sequence schema_migrations_id_seq to adlog_storage_owner") < role_switch
    assert "migration 019 requires schema migration 018" in forward




def test_conflict_key_privilege_is_column_scoped_and_rollback_guarded() -> None:
    forward = Path("config/postgres_migrations/031_entity_state_conflict_key_privilege.sql").read_text(encoding="utf-8")
    rollback = Path("config/postgres_migrations/031_entity_state_conflict_key_privilege.rollback.sql").read_text(encoding="utf-8")
    columns = "select(entity_id,state_type,evidence_event_id)"
    assert f"grant {columns}" in forward
    assert "grant select on entity_states" not in forward
    assert "migration 031 requires schema migration 030" in forward
    assert f"revoke {columns}" in rollback
    assert "rollback 031 refused: entity-state projection output exists" in rollback




class FailureCursor:
    def __init__(self, updated):
        self.updated = updated
        self.sql = ""
        self.params = ()

    def execute(self, sql, params=()):
        self.sql = sql
        self.params = params

    def fetchone(self):
        return self.updated
