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


def test_newest_wins_and_older_observation_cannot_roll_back() -> None:
    from server.sli.entities.entity_state_model import resolve_current

    current = _observation(event_id=20, at="2026-07-18T12:00:00Z", status="locked")
    action, result = resolve_current(current, _observation(event_id=10, at="2026-07-18T10:00:00Z"))
    assert action == "older"
    assert result["status"] == "locked"

    action, result = resolve_current(current, _observation(event_id=21, at="2026-07-18T12:01:00Z"))
    assert action == "replace"
    assert result["status"] == "enabled"


def test_equal_identity_with_different_status_is_explicit_conflict() -> None:
    from server.sli.entities.entity_state_model import resolve_current

    current = _observation(status="locked")
    action, result = resolve_current(current, _observation(status="enabled"))
    assert action == "conflict"
    assert result["status"] == "unknown"
    assert result["projection_status"] == "conflict"
    assert result["conflict_statuses"] == ["enabled", "locked"]


def test_tie_break_uses_event_identity_then_rule_version() -> None:
    from server.sli.entities.entity_state_model import observation_order

    lower = _observation(event_id=10)
    higher = _observation(event_id=11)
    assert observation_order(higher) > observation_order(lower)


def test_projection_is_catalogued_target_only_and_partial_absence_has_no_transition() -> None:
    from server.sli.entities.entity_state_model import state_for_entity_link

    event = {
        "event_id": 4720, "provider_name": "Microsoft-Windows-Security-Auditing",
        "channel": "Security", "time_created_utc": "2026-07-18T10:00:00+03:00",
    }
    assert state_for_entity_link(event, {"TargetUserName": "fixture"}, {"link_role": "actor"}) is None
    state = state_for_entity_link(event, {"TargetUserName": "fixture"}, {"link_role": "target"})
    assert state is not None
    assert state["status"] == "created"
    assert state["observed_at_utc"] == "2026-07-18T07:00:00Z"
    # There is intentionally no snapshot-absence API: unknown input cannot close state.
    assert state_for_entity_link({**event, "event_id": 999999}, {}, {"link_role": "target"}) is None


class ClaimCursor:
    def __init__(self):
        self.sql = ""
        self.params = ()

    def execute(self, sql, params=()):
        self.sql = sql
        self.params = params

    def fetchall(self):
        return []


def test_claim_is_bounded_leased_v2_gated_and_skips_legacy_jobs() -> None:
    from server.sli.entities.entity_state_projector import claim_projection_jobs

    cur = ClaimCursor()
    assert claim_projection_jobs(cur, worker_id="fixture", limit=999, lease_seconds=1) == []
    normalized = " ".join(cur.sql.split()).lower()
    assert "job.job_schema_version=%s" in normalized
    assert "events_v2_core" in normalized and "entities_v2" in normalized
    assert "for update skip locked" in normalized
    assert cur.params[1] == 16
    assert cur.params[3] == 60


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


def test_evidence_identity_hotfix_supplies_projector_conflict_target() -> None:
    projector = Path("server/sli/entities/entity_state_projector.py").read_text(encoding="utf-8")
    forward = Path("config/postgres_migrations/030_entity_state_evidence_identity.sql").read_text(encoding="utf-8")
    rollback = Path("config/postgres_migrations/030_entity_state_evidence_identity.rollback.sql").read_text(encoding="utf-8")
    identity = "entity_id,state_type,evidence_event_id"
    assert f"on conflict({identity}) do nothing" in projector
    assert f"on entity_states({identity})" in forward
    assert "duplicate entity-state evidence identities exist" in forward
    assert "migration 030 requires schema migration 029" in forward
    assert "rollback 030 refused: entity-state projection output exists" in rollback
    assert "drop index if exists uq_entity_states_evidence_identity" in rollback


def test_conflict_key_privilege_is_column_scoped_and_rollback_guarded() -> None:
    forward = Path("config/postgres_migrations/031_entity_state_conflict_key_privilege.sql").read_text(encoding="utf-8")
    rollback = Path("config/postgres_migrations/031_entity_state_conflict_key_privilege.rollback.sql").read_text(encoding="utf-8")
    columns = "select(entity_id,state_type,evidence_event_id)"
    assert f"grant {columns}" in forward
    assert "grant select on entity_states" not in forward
    assert "migration 031 requires schema migration 030" in forward
    assert f"revoke {columns}" in rollback
    assert "rollback 031 refused: entity-state projection output exists" in rollback


def test_worker_validate_only_does_not_connect(monkeypatch, capsys) -> None:
    from scripts.maintenance import run_entity_state_projection_once as worker

    monkeypatch.setattr(worker, "_connect", lambda: (_ for _ in ()).throw(AssertionError("connected")))
    monkeypatch.setattr("sys.argv", ["worker"])
    assert worker.main() == 0
    assert '"connections": 0' in capsys.readouterr().out


def test_worker_commits_role_setup_and_claims_each_job_just_in_time() -> None:
    source = Path("server/sli/entities/entity_state_runtime.py").read_text(encoding="utf-8")
    assert 'cur.execute("set role adlog_storage_worker")' in source
    assert "conn.commit()" in source
    assert "claim_projection_jobs(cur, worker_id=worker_id, limit=1)" in source
    assert "connect_timeout=connect_timeout" in source
    assert 'application_name="adlog_entity_state_projector"' in source
    assert "statement_timeout={statement_timeout}" in source
    assert "lock_timeout={lock_timeout}" in source


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


def test_failure_transition_requires_current_lease_and_updated_row() -> None:
    import pytest

    from server.sli.entities.entity_state_projector import fail_projection_job

    job = {"job_id": "fixture-job", "lease_token": "fixture-token", "attempt_count": 1, "max_attempts": 5}
    cur = FailureCursor({"status": "failed"})
    assert fail_projection_job(cur, job, RuntimeError("fixture")) == "failed"
    assert "returning status" in " ".join(cur.sql.split()).lower()
    assert cur.params[-2:] == ("fixture-job", "fixture-token")

    with pytest.raises(RuntimeError, match="lease was lost"):
        fail_projection_job(FailureCursor(None), job, RuntimeError("fixture"))
