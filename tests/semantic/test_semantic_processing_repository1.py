from datetime import datetime, timezone
import json
import uuid

import pytest

from server.sli.semantic.semantic_processing import (
    CanonicalAction,
    NORMALIZER_ID,
    NORMALIZER_VERSION,
    SEMANTIC_CONTRACT_VERSION,
    StoredEvent,
    assemble_canonical_actions,
    normalize_windows_event,
)

from server.sli.semantic.semantic_processing_repository import (
    PROCESSOR_ID,
    PROCESSOR_VERSION,
    SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND,
    _identity,
    claim_semantic_jobs,
    complete_semantic_job,
    defer_semantic_job,
    enqueue_semantic_job,
    fail_semantic_job,
    heartbeat_semantic_job,
    load_semantic_source_event,
    normalized_event_id,
    persist_canonical_actions,
    persist_normalized_event,
    semantic_source_identity,
)
from server.sli.entities.identity_resolution import IDENTITY_RESOLUTION_VERSION


class Cursor:
    def __init__(self, row=None):
        self.row, self.sql, self.params, self.history = row, "", (), []
    def execute(self, sql, params=()):
        self.sql, self.params = sql, params
        self.history.append((sql, params))
    def fetchone(self): return self.row
    def fetchall(self): return []


def source_identity(occurred=None) -> dict:
    timestamp = occurred or datetime(2026, 7, 19, 1, tzinfo=timezone.utc)
    return {
        "id": 7,
        "server_id": 1,
        "domain_id": 2,
        "log_source_id": 3,
        "event_id": 4624,
        "time_created_utc": timestamp,
        "normalized_hash": b"n" * 32,
        "correlation_id": None,
        "migrated_at": timestamp,
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DC1",
    }


def test_enqueue_is_identity_only_idempotent_and_rejects_payload_conflict() -> None:
    cur = Cursor({
        "job_id": "fixture",
        "payload_json": {},
        "source_identity_json": source_identity(),
    })
    assert enqueue_semantic_job(cur, source_event_id=7) == "fixture"
    normalized = " ".join(cur.history[0][0].split()).lower()
    assert "idempotency_key" in normalized
    assert "partition_key" in normalized and "occurred_at_utc" in normalized
    assert "raw_xml" not in normalized and "event_data" not in normalized


def test_source_identity_is_bounded_and_strips_payload_fields() -> None:
    value = {**source_identity(), "event_data_json": {"secret": "value"}}
    result = semantic_source_identity(value)
    assert set(result) == {
        "id", "server_id", "domain_id", "log_source_id", "event_id",
        "time_created_utc", "normalized_hash", "correlation_id",
        "migrated_at", "provider_name", "channel", "computer",
    }
    assert result["normalized_hash"] == (b"n" * 32).hex()
    assert "event_data_json" not in result


def test_queue_identity_includes_identity_rule_version() -> None:
    common = {
        "source_event_id": 7,
        "job_kind": "normalize_event",
        "processor_id": "semantic-shadow",
        "processor_version": PROCESSOR_VERSION,
    }
    assert PROCESSOR_VERSION.endswith(
        f"identity-{IDENTITY_RESOLUTION_VERSION}"
    )
    assert _identity(
        **common,
        identity_resolution_version="identity-v1",
    ) != _identity(
        **common,
        identity_resolution_version="identity-v2",
    )


def test_normalizer_release_creates_a_distinct_normal_processing_job_identity() -> None:
    common = {
        "source_event_id": 7,
        "job_kind": "normalize_event",
        "processor_id": "semantic-shadow",
    }
    historical = _identity(
        **common,
        processor_version=f"1.1+identity-{IDENTITY_RESOLUTION_VERSION}",
    )
    current = _identity(**common, processor_version=PROCESSOR_VERSION)

    assert current != historical
    assert PROCESSOR_VERSION == NORMALIZER_VERSION


def test_claim_rejects_base_version_replays_and_requires_current_processor_contract() -> None:
    cur = Cursor()

    assert claim_semantic_jobs(cur, limit=999, lease_seconds=1) == []

    query = " ".join(cur.sql.split()).casefold()
    assert "processor_id=%s" in query
    assert "job_kind='semantic_replay' and processor_version like %s" in query
    assert "job_kind<>'semantic_replay' and processor_version=%s" in query
    assert cur.params[:4] == (
        SEMANTIC_CONTRACT_VERSION,
        PROCESSOR_ID,
        f"{PROCESSOR_VERSION}+r7-%",
        PROCESSOR_VERSION,
    )


def test_normalized_event_identity_and_persistence_are_versioned() -> None:
    event = normalize_windows_event(
        StoredEvent(
            7, 4625, "Security", "DC1", datetime(2026, 7, 19, 1, tzinfo=timezone.utc),
            {"TargetUserSid": "S-1-5-21-7", "TargetLogonId": "0x7"},
            source_host_id=1,
        )
    )
    old_version = "1.1+identity-1.0"
    new_version = "1.3+identity-1.0"
    old_id = normalized_event_id(
        event,
        semantic_contract_version=SEMANTIC_CONTRACT_VERSION,
        normalizer_id=NORMALIZER_ID,
        normalizer_version=old_version,
    )
    new_id = normalized_event_id(
        event,
        semantic_contract_version=SEMANTIC_CONTRACT_VERSION,
        normalizer_id=NORMALIZER_ID,
        normalizer_version=new_version,
    )
    assert old_id != new_id

    class VersionedCursor(Cursor):
        def fetchone(self):
            if "select normalized_event_id" in self.sql.lower():
                version = self.params[3]
                return {
                    "normalized_event_id": normalized_event_id(
                        event,
                        semantic_contract_version=SEMANTIC_CONTRACT_VERSION,
                        normalizer_id=NORMALIZER_ID,
                        normalizer_version=version,
                    ),
                    "semantic_sha256": bytes.fromhex(event.semantic_sha256),
                    "semantic_type": event.semantic_type,
                    "occurred_at_utc": event.occurred_at_utc,
                    "roles_json": dict(event.roles),
                    "facts_json": dict(event.facts),
                    "quality_json": dict(event.quality),
                }
            return None

    assert persist_normalized_event(
        VersionedCursor(), event=event, normalizer_version=new_version
    ) == new_id


def test_enqueue_rejects_missing_v2_source_event() -> None:
    with pytest.raises(LookupError, match="events_v2_core"):
        enqueue_semantic_job(Cursor(None), source_event_id=404)


def test_claim_is_bounded_leased_and_skip_locked() -> None:
    cur = Cursor()
    assert claim_semantic_jobs(cur, limit=999, lease_seconds=1) == []
    normalized = " ".join(cur.sql.split()).lower()
    assert "for update skip locked" in normalized and "status='leased'" in normalized
    assert "processor_id=%s" in normalized and "processor_version=%s" in normalized
    assert "job_kind='semantic_replay'" in normalized and "like %s" in normalized
    assert cur.params[5] == 16 and cur.params[7] == 60


def test_claim_can_be_bounded_to_exact_source_event_ids() -> None:
    cur = Cursor()

    assert claim_semantic_jobs(
        cur,
        limit=999,
        lease_seconds=1,
        source_event_ids=[9, 7, 9],
    ) == []

    normalized = " ".join(cur.sql.split()).lower()
    assert "source_event_id=any(%s)" in normalized
    assert cur.params[4] == [7, 9]
    assert cur.params[6] == 16
    assert cur.params[8] == 60


def test_ordinary_claim_excludes_v2_quarantine_repair_jobs() -> None:
    cur = Cursor()

    assert claim_semantic_jobs(cur, limit=1) == []

    query = " ".join(cur.sql.split()).casefold()
    assert "job_kind<>%s" in query
    assert SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND in cur.params


def test_recovery_claim_requires_exact_v2_kind_and_repair_plan_digest() -> None:
    cur = Cursor()
    digest = "a" * 64

    assert claim_semantic_jobs(cur, limit=1, repair_plan_digest=digest) == []

    query = " ".join(cur.sql.split()).casefold()
    assert "job_kind=%s" in query
    assert "payload_json->>'repair_plan_digest'=%s" in query
    assert SEMANTIC_V2_QUARANTINE_REPAIR_JOB_KIND in cur.params
    assert digest in cur.params


def test_lease_transitions_require_owner_and_quarantine_terminal_failure() -> None:
    current = Cursor({"job_id": "fixture"})
    assert heartbeat_semantic_job(current, job_id="job", lease_token="token", lease_seconds=1)
    assert current.params[0] == 60
    complete_semantic_job(current, job_id="job", lease_token="token")
    assert "status='completed'" in " ".join(current.sql.split()).lower()
    assert fail_semantic_job(current, job_id="job", lease_token="token", attempt_count=5, max_attempts=5, error_code="x", error_detail="y") == "quarantined"
    with pytest.raises(RuntimeError, match="lease was lost"):
        complete_semantic_job(Cursor(None), job_id="job", lease_token="token")


def test_successful_context_expansion_defers_without_spending_retry_budget() -> None:
    current = Cursor({"job_id": "fixture"})

    defer_semantic_job(current, job_id="job", lease_token="token")

    normalized = " ".join(current.sql.split()).lower()
    assert "status='queued'" in normalized
    assert "attempt_count=greatest(attempt_count-1,0)" in normalized
    assert current.params == (1, "job", "token")


def test_shadow_worker_is_disabled_without_execute_or_feature(monkeypatch, capsys) -> None:
    from scripts.maintenance import run_semantic_shadow_once as worker
    monkeypatch.setattr(worker, "_connect", lambda: (_ for _ in ()).throw(AssertionError("connected")))
    monkeypatch.setattr("sys.argv", ["worker"])
    assert worker.main() == 0
    assert '"connections": 0' in capsys.readouterr().out


def test_shadow_worker_commits_migration_gate_before_job_transactions() -> None:
    from pathlib import Path
    source = Path("scripts/maintenance/run_semantic_shadow_once.py").read_text(encoding="utf-8")
    assert "version=25 and name='semantic_persistence_contract'" in source
    assert "version=71 and name='semantic_source_retention_decoupling'" in source
    assert 'raise RuntimeError("migrations 025 and 071 are required")' in source
    assert "PostgresArchiveManifestStore" in source
    assert "join events legacy" not in source.lower()
    assert "conn.commit()" in source


def test_source_event_is_hydrated_from_verified_v2_archive_without_legacy_join() -> None:
    occurred = datetime(2026, 7, 19, 1, tzinfo=timezone.utc)
    summary = {
        "id": 7,
        "server_id": 1,
        "domain_id": 2,
        "log_source_id": 3,
        "event_id": 4624,
        "time_created_utc": occurred,
        "normalized_hash": b"n" * 32,
        "correlation_id": "correlation",
        "migrated_at": occurred,
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "computer": "DC1",
    }
    payload = {
        "id": 7,
        "server_id": 1,
        "domain_id": 2,
        "log_source_id": 3,
        "event_id": 4624,
        "time_created_utc": occurred,
        "event_data_json": {"TargetLogonId": "0x1"},
    }

    class Archive:
        def read_event(self, *, archive_kind: str, event_id: int):
            assert archive_kind == "event" and event_id == 7
            return payload

    cur = Cursor(summary)
    result = load_semantic_source_event(cur, source_event_id=7, archive=Archive())
    assert result is not None
    assert result["event_data_json"] == {"TargetLogonId": "0x1"}
    assert result["source_host_id"] == 1
    sql = " ".join(cur.history[0][0].split()).lower()
    assert "from events_v2_core" in sql
    assert "join events legacy" not in sql


def test_source_event_hydrates_from_retained_identity_without_core_query() -> None:
    identity = source_identity()
    payload = {
        key: identity[key]
        for key in (
            "id", "server_id", "domain_id", "log_source_id", "event_id",
            "time_created_utc",
        )
    }
    payload["event_data_json"] = {"TargetLogonId": "0x1"}

    class Archive:
        def read_event(self, *, archive_kind: str, event_id: int):
            assert archive_kind == "event" and event_id == 7
            return payload

    cur = Cursor(None)
    result = load_semantic_source_event(
        cur,
        source_event_id=7,
        archive=Archive(),
        source_identity=identity,
    )
    assert result is not None
    assert result["source_event_sha256"] == b"n" * 32
    assert cur.history == []


def test_normalized_persistence_keeps_roles_type_and_time() -> None:
    occurred = datetime(2026, 7, 19, 1, tzinfo=timezone.utc)
    normalized = normalize_windows_event(
        StoredEvent(
            7,
            4624,
            "Security",
            "DC1",
            occurred,
            {"TargetUserSid": "S-1", "TargetLogonId": "0x1"},
            source_host_id=1,
        )
    )

    class PersistCursor(Cursor):
        def fetchone(self):
            if "select normalized_event_id" in self.sql.lower():
                return {
                    "normalized_event_id": normalized_event_id(normalized),
                    "semantic_sha256": bytes.fromhex(normalized.semantic_sha256),
                    "semantic_type": normalized.semantic_type,
                    "occurred_at_utc": normalized.occurred_at_utc,
                    "roles_json": dict(normalized.roles),
                    "facts_json": dict(normalized.facts),
                    "quality_json": dict(normalized.quality),
                }
            return None

    cur = PersistCursor()
    assert persist_normalized_event(cur, event=normalized) == normalized_event_id(normalized)
    insert = " ".join(cur.history[0][0].split()).lower()
    assert "semantic_type" in insert
    assert "roles_json" in insert
    assert "occurred_at_utc" in insert


def test_normalized_persistence_uses_retained_identity_without_core_join() -> None:
    occurred = datetime(2026, 7, 19, 1, tzinfo=timezone.utc)
    normalized = normalize_windows_event(
        StoredEvent(
            7,
            4624,
            "Security",
            "DC1",
            occurred,
            {"TargetUserSid": "S-1", "TargetLogonId": "0x1"},
            source_host_id=1,
        )
    )

    class PersistCursor(Cursor):
        def fetchone(self):
            if "select normalized_event_id" in self.sql.lower():
                return {
                    "normalized_event_id": normalized_event_id(normalized),
                    "semantic_sha256": bytes.fromhex(normalized.semantic_sha256),
                    "semantic_type": normalized.semantic_type,
                    "occurred_at_utc": normalized.occurred_at_utc,
                    "roles_json": dict(normalized.roles),
                    "facts_json": dict(normalized.facts),
                    "quality_json": dict(normalized.quality),
                }
            return None

    cur = PersistCursor()
    persist_normalized_event(
        cur,
        event=normalized,
        source_identity=source_identity(occurred),
    )
    insert = " ".join(cur.history[0][0].split()).lower()
    assert "values(" in insert
    assert "source_identity_json" in insert
    assert "from events_v2_core" not in insert


def test_canonical_writer_persists_stable_action_and_normalized_evidence() -> None:
    occurred = datetime(2026, 7, 19, 1, tzinfo=timezone.utc)
    normalized = normalize_windows_event(
        StoredEvent(
            8,
            4719,
            "Security",
            "DC1",
            occurred,
            {
                "SubjectUserSid": "S-1-5-21-1000",
                "SubjectUserName": "auditor",
                "SubjectDomainName": "EXAMPLE",
                "SubjectLogonId": "0x123",
                "CategoryId": "%%8272",
                "SubcategoryId": "%%12801",
                "SubcategoryGuid": "{00000000-0000-4000-8000-000000000004}",
                "AuditPolicyChanges": "%%8448",
            },
            provider="Microsoft-Windows-Security-Auditing",
            source_host_id=1,
        )
    )
    action = assemble_canonical_actions((normalized,))[0]

    class CanonicalCursor(Cursor):
        def __init__(self):
            super().__init__()
            self.current = ""

        def execute(self, sql, params=()):
            super().execute(sql, params)
            self.current = " ".join(sql.split()).lower()

        def fetchone(self):
            if "from canonical_actions" in self.current and "for update" in self.current:
                return None
            if "from canonical_action_evidence" in self.current and "max(" not in self.current:
                return None
            if "max(evidence_order)" in self.current:
                return {"last_order": -1}
            return None

        def fetchall(self):
            if "from normalized_events" in self.current:
                return [
                    {
                        "normalized_event_id": normalized_event_id(normalized),
                        "source_event_id": normalized.source_event_id,
                    }
                ]
            return []

    cur = CanonicalCursor()
    persisted = persist_canonical_actions(cur, actions=(action,))
    assert len(persisted) == 1
    combined = "\n".join(sql.lower() for sql, _ in cur.history)
    assert "canonical_deduplication_key" in combined
    assert "pg_advisory_xact_lock" in combined
    assert "multi_source_confirmed" in combined
    assert "count(distinct normalized.source_event_id)" in combined
    assert "insert into canonical_action_evidence" in combined


def test_canonical_writer_reuses_stable_action_across_assembler_versions() -> None:
    action = CanonicalAction(
        action_kind="audit.policy.changed",
        status="observed",
        occurred_at_utc=datetime(2026, 7, 19, 1, tzinfo=timezone.utc),
        contribution_key="ab" * 32,
        source_event_ids=(),
        attributes={"material_identity": {"source_host": "DC1"}},
    )
    stable_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:canonical:{action.canonical_deduplication_key}"))
    row = {
        "canonical_action_id": stable_id,
        "action_kind": action.action_kind,
        "action_status": action.status,
        "semantic_contract_version": 1,
        "assembler_id": "semantic-action-assembler",
        "assembler_version": "1.0",
        "canonical_deduplication_key": bytes.fromhex(action.canonical_deduplication_key),
        "action_sha256": b"\x11" * 32,
        "attributes_json": dict(action.attributes),
    }

    class ReplayCursor(Cursor):
        def fetchone(self):
            if "from canonical_actions" in self.sql:
                return row
            return None

    cur = ReplayCursor()
    assert persist_canonical_actions(cur, actions=(action,)) == (stable_id,)
    statements = "\n".join(sql.lower() for sql, _ in cur.history)
    assert "pg_advisory_xact_lock" in statements
    assert "update canonical_actions" in statements
    assert "insert into canonical_actions" not in statements


@pytest.mark.parametrize(
    "changed_field,changed_value",
    (
        ("canonical_deduplication_key", b"z" * 32),
        ("assembler_id", "another-assembler"),
    ),
)
def test_canonical_writer_rejects_conflicting_stable_identity(changed_field, changed_value) -> None:
    action = CanonicalAction(
        action_kind="audit.policy.changed",
        status="observed",
        occurred_at_utc=datetime(2026, 7, 19, 1, tzinfo=timezone.utc),
        contribution_key="ab" * 32,
        source_event_ids=(),
        attributes={"material_identity": {"source_host": "DC1"}},
    )
    row = {
        "canonical_action_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:canonical:{action.canonical_deduplication_key}")),
        "action_kind": action.action_kind,
        "action_status": action.status,
        "semantic_contract_version": 1,
        "assembler_id": "semantic-action-assembler",
        "assembler_version": "1.0",
        "canonical_deduplication_key": bytes.fromhex(action.canonical_deduplication_key),
        "attributes_json": dict(action.attributes),
    }
    row[changed_field] = changed_value

    class ReplayCursor(Cursor):
        def fetchone(self):
            if "from canonical_actions" in self.sql:
                return row
            return None

    cur = ReplayCursor()
    with pytest.raises(RuntimeError, match="canonical action identity replay conflict"):
        persist_canonical_actions(cur, actions=(action,))
    assert not any("update canonical_actions" in sql.lower() for sql, _ in cur.history)


def test_canonical_writer_rejects_same_dedup_key_with_different_action_id() -> None:
    action = CanonicalAction(
        action_kind="audit.policy.changed",
        status="observed",
        occurred_at_utc=datetime(2026, 7, 19, 1, tzinfo=timezone.utc),
        contribution_key="ab" * 32,
        source_event_ids=(),
        attributes={"material_identity": {"source_host": "DC1"}},
    )
    row = {
        "canonical_action_id": str(uuid.uuid4()),
        "action_kind": action.action_kind,
        "action_status": action.status,
        "semantic_contract_version": 1,
        "assembler_id": "semantic-action-assembler",
        "assembler_version": "1.1",
        "canonical_deduplication_key": bytes.fromhex(action.canonical_deduplication_key),
        "attributes_json": dict(action.attributes),
    }

    class ReplayCursor(Cursor):
        def fetchone(self):
            if "where canonical_action_id=%s" in self.sql:
                return None
            if "from canonical_actions" in self.sql:
                return row
            return None

    cur = ReplayCursor()
    with pytest.raises(RuntimeError, match="canonical action identity replay conflict"):
        persist_canonical_actions(cur, actions=(action,))
    assert not any("update canonical_actions" in sql.lower() for sql, _ in cur.history)


def test_canonical_writer_replaces_reinterpreted_source_without_duplicate_evidence() -> None:
    action = CanonicalAction(
        action_kind="authentication.succeeded",
        status="observed",
        occurred_at_utc=datetime(2026, 7, 19, 1, tzinfo=timezone.utc),
        contribution_key="ab" * 32,
        source_event_ids=(42,),
        attributes={
            "material_identity": {"source_host": "DC1", "source_event_id": 42},
            "source_evidence": [{"source_event_id": 42, "semantic_sha256": "new-hash"}],
            "observed_facts": [{"logon_type": "network"}],
            "observed_roles": [{"source_host": "DC1"}],
        },
    )
    stable_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:canonical:{action.canonical_deduplication_key}"))
    old_normalized_id = str(uuid.uuid4())
    new_normalized_id = str(uuid.uuid4())
    row = {
        "canonical_action_id": stable_id,
        "action_kind": action.action_kind,
        "action_status": action.status,
        "semantic_contract_version": 1,
        "assembler_id": "semantic-action-assembler",
        "assembler_version": "1.0",
        "canonical_deduplication_key": bytes.fromhex(action.canonical_deduplication_key),
        "action_sha256": b"\x11" * 32,
        "attributes_json": {
            "material_identity": {"source_host": "DC1", "source_event_id": 42},
            "source_evidence": [{"source_event_id": 42, "semantic_sha256": "old-hash"}],
            "observed_facts": [{"logon_type": "network"}],
            "observed_roles": [{"source_host": "DC1"}],
        },
    }

    class ReplayCursor(Cursor):
        def fetchone(self):
            if "from canonical_actions" in self.sql:
                return row
            return None

        def fetchall(self):
            if "from normalized_events" in self.sql:
                return [{"source_event_id": 42, "normalized_event_id": new_normalized_id}]
            if "from canonical_action_evidence" in self.sql and "join normalized_events" in self.sql:
                return [{
                    "source_event_id": 42,
                    "normalized_event_id": old_normalized_id,
                    "evidence_role": "primary",
                    "entity_role": None,
                    "evidence_order": 0,
                    "relation_confidence": "1.000",
                }]
            return []

    cur = ReplayCursor()
    assert persist_canonical_actions(cur, actions=(action,)) == (stable_id,)
    statements = [(" ".join(sql.lower().split()), params) for sql, params in cur.history]
    assert not any("insert into canonical_action_evidence" in sql for sql, _ in statements)
    assert any("update canonical_action_evidence" in sql and new_normalized_id in params for sql, params in statements)
    update_sql, update_params = next((sql, params) for sql, params in statements if "update canonical_actions" in sql)
    assert "assembler_version=" in update_sql
    assert "1.1" in update_params
    updated_attributes = json.loads(update_params[0])
    assert updated_attributes["source_evidence"] == [
        {"source_event_id": 42, "semantic_sha256": "new-hash"}
    ]
    assert updated_attributes["prior_interpretations"] == [{
        "assembler_id": "semantic-action-assembler",
        "assembler_version": "1.0",
        "action_sha256": "11" * 32,
        "evidence": [{
            "source_event_id": 42,
            "normalized_event_id": old_normalized_id,
            "evidence_role": "primary",
            "entity_role": None,
            "evidence_order": 0,
            "relation_confidence": "1.000",
        }],
        "attributes": row["attributes_json"],
    }]


def test_canonical_writer_archives_all_existing_links_on_version_change() -> None:
    action = CanonicalAction(
        action_kind="directory.attribute.changed",
        status="observed",
        occurred_at_utc=datetime(2026, 7, 19, 1, tzinfo=timezone.utc),
        contribution_key="ab" * 32,
        source_event_ids=(42,),
        attributes={"material_identity": {"source_host": "DC1"}},
    )
    stable_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:canonical:{action.canonical_deduplication_key}"))
    links = [
        {"source_event_id": 42, "normalized_event_id": str(uuid.uuid4()), "evidence_role": "primary", "entity_role": None, "evidence_order": 0, "relation_confidence": "1.000"},
        {"source_event_id": 43, "normalized_event_id": str(uuid.uuid4()), "evidence_role": "supporting", "entity_role": None, "evidence_order": 1, "relation_confidence": "1.000"},
    ]
    row = {
        "canonical_action_id": stable_id,
        "action_kind": action.action_kind,
        "action_status": action.status,
        "semantic_contract_version": 1,
        "assembler_id": "semantic-action-assembler",
        "assembler_version": "1.0",
        "canonical_deduplication_key": bytes.fromhex(action.canonical_deduplication_key),
        "action_sha256": b"\x11" * 32,
        "attributes_json": dict(action.attributes),
    }

    class ReplayCursor(Cursor):
        def fetchone(self):
            if "from canonical_actions" in self.sql:
                return row
            return None

        def fetchall(self):
            if "from normalized_events" in self.sql:
                return [{"source_event_id": 42, "normalized_event_id": links[0]["normalized_event_id"]}]
            if "from canonical_action_evidence" in self.sql and "join normalized_events" in self.sql:
                return links if len(self.params) == 1 else links[:1]
            return []

    cur = ReplayCursor()
    assert persist_canonical_actions(cur, actions=(action,)) == (stable_id,)
    update_params = next(params for sql, params in cur.history if "update canonical_actions" in sql)
    previous = json.loads(update_params[0])["prior_interpretations"][0]
    assert previous["evidence"] == links


def test_canonical_writer_version_bump_keeps_other_incremental_source_active() -> None:
    """A one-source replay must not discard another source already in the action."""
    action = CanonicalAction(
        action_kind="directory.attribute.changed",
        status="observed",
        occurred_at_utc=datetime(2026, 7, 19, 1, tzinfo=timezone.utc),
        contribution_key="ab" * 32,
        source_event_ids=(42,),
        attributes={"material_identity": {"source_host": "DC1"}},
    )
    stable_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:canonical:{action.canonical_deduplication_key}"))
    old_normalized_id = str(uuid.uuid4())
    new_normalized_id = str(uuid.uuid4())
    other_normalized_id = str(uuid.uuid4())
    links = [
        {"source_event_id": 42, "normalized_event_id": old_normalized_id, "evidence_role": "primary", "entity_role": None, "evidence_order": 0, "relation_confidence": "1.000"},
        {"source_event_id": 43, "normalized_event_id": other_normalized_id, "evidence_role": "supporting", "entity_role": None, "evidence_order": 1, "relation_confidence": "1.000"},
    ]
    row = {
        "canonical_action_id": stable_id,
        "action_kind": action.action_kind,
        "action_status": action.status,
        "semantic_contract_version": 1,
        "assembler_id": "semantic-action-assembler",
        "assembler_version": "1.0",
        "canonical_deduplication_key": bytes.fromhex(action.canonical_deduplication_key),
        "action_sha256": b"\x11" * 32,
        "attributes_json": dict(action.attributes),
    }

    class ReplayCursor(Cursor):
        def execute(self, sql, params=()):
            super().execute(sql, params)
            if "update canonical_action_evidence set normalized_event_id" in sql.lower():
                for link in links:
                    if link["normalized_event_id"] == params[2]:
                        link["normalized_event_id"] = params[0]

        def fetchone(self):
            if "from canonical_actions" in self.sql:
                return row
            return None

        def fetchall(self):
            if "from normalized_events" in self.sql:
                return [{"source_event_id": 42, "normalized_event_id": new_normalized_id}]
            if "from canonical_action_evidence" in self.sql and "join normalized_events" in self.sql:
                return links
            return []

    cur = ReplayCursor()
    assert persist_canonical_actions(cur, actions=(action,)) == (stable_id,)
    assert [(link["source_event_id"], link["normalized_event_id"]) for link in links] == [
        (42, new_normalized_id), (43, other_normalized_id)
    ]
    statements = [(" ".join(sql.lower().split()), params) for sql, params in cur.history]
    assert not any("delete from canonical_action_evidence" in sql for sql, _ in statements)
    assert not any("insert into canonical_action_evidence" in sql for sql, _ in statements)
    update_params = next(params for sql, params in statements if "update canonical_action_evidence" in sql)
    assert update_params == (new_normalized_id, stable_id, old_normalized_id)
    action_update_params = next(params for sql, params in statements if "set action_status='multi_source_confirmed'" in sql)
    assert action_update_params == (stable_id, stable_id)
    previous = json.loads(next(params for sql, params in cur.history if "update canonical_actions" in sql)[0])
    assert previous["prior_interpretations"][0]["evidence"] == [
        {**links[0], "normalized_event_id": old_normalized_id}, links[1]
    ]


def test_canonical_writer_rejects_reinterpretation_without_old_evidence() -> None:
    action = CanonicalAction(
        action_kind="authentication.succeeded",
        status="observed",
        occurred_at_utc=datetime(2026, 7, 19, 1, tzinfo=timezone.utc),
        contribution_key="ab" * 32,
        source_event_ids=(42,),
        attributes={
            "material_identity": {"source_host": "DC1", "source_event_id": 42},
            "source_evidence": [{"source_event_id": 42, "semantic_sha256": "new-hash"}],
            "observed_facts": [{}],
            "observed_roles": [{}],
        },
    )
    row = {
        "canonical_action_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:canonical:{action.canonical_deduplication_key}")),
        "action_kind": action.action_kind,
        "action_status": action.status,
        "semantic_contract_version": 1,
        "assembler_id": "semantic-action-assembler",
        "assembler_version": "1.0",
        "canonical_deduplication_key": bytes.fromhex(action.canonical_deduplication_key),
        "action_sha256": b"\x11" * 32,
        "attributes_json": {
            **action.attributes,
            "source_evidence": [{"source_event_id": 42, "semantic_sha256": "old-hash"}],
        },
    }

    class ReplayCursor(Cursor):
        def fetchone(self):
            if "from canonical_actions" in self.sql:
                return row
            if "max(evidence_order)" in self.sql:
                return {"last_order": -1}
            return None

        def fetchall(self):
            if "from normalized_events" in self.sql:
                return [{"source_event_id": 42, "normalized_event_id": str(uuid.uuid4())}]
            return []

    cur = ReplayCursor()
    with pytest.raises(RuntimeError, match="canonical action interpretation evidence missing"):
        persist_canonical_actions(cur, actions=(action,))
    assert not any("insert into canonical_action_evidence" in sql.lower() for sql, _ in cur.history)
