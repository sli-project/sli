"""Current admission, replay and preservation of terminal pre-cutover work.

The Python history-repair controller is retired. Exercise the receipt gate and
the shipped .NET worker on the fully migrated disposable schema instead.
"""
from copy import deepcopy
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest

from tests.migrations.short_detection_fixture import run_semantic_worker
from tests.migrations.test_account_watch_pipeline_postgres import (
    _register, _source, watch_db as watch_db,
)

pytestmark = pytest.mark.postgres_integration


@pytest.fixture
def accepted_event(watch_db):
    item = _source(watch_db)
    with watch_db() as conn:
        event = conn.execute("select * from event_hot where event_id=%s", (item["event"],)).fetchone()
        packet, = conn.execute("select packet_id from sli_agent_packet_inbox").fetchall()
    payload = {key: event[key] for key in (
        "event_id", "event_kind", "domain_id", "actor", "target", "source", "computer", "method", "outcome", "fields")}
    payload["time_created_utc"] = event["time_created_utc"].isoformat()
    payload["method"] = payload["method"] | {"$packet_id": str(packet["packet_id"]), "$packet_ordinal": 0}
    payload["layer"] = "summary"
    return item, payload


@pytest.mark.parametrize("change", [
    None, "unimported", "pending_receipt", "envelope", "binding", "disabled_agent",
    "unassigned_module", "inactive_server", "provider", "event_kind", "time", "ordinal", "forged_origin",
])
def test_short_admission_requires_exact_committed_source(watch_db, accepted_event, change):
    """Bad provenance cannot become a detector-authorized short event."""
    from psycopg.errors import CheckViolation, ObjectNotInPrerequisiteState
    from psycopg.types.json import Jsonb

    item, original = accepted_event
    payload = deepcopy(original)
    mutations = {
        "unimported": "update sli_agent_packet_inbox set imported_at=null",
        "pending_receipt": "update sli_agent_receipts set receipt='{\"status\":\"pending\"}'",
        "envelope": "update sli_agent_packet_inbox set envelope=envelope||'{\"generation\":\"forged\"}'",
        "binding": "update sli_agent_module_bindings set source_instance_id='forged'",
        "disabled_agent": "update sli_agents set status='disabled'",
        "unassigned_module": "update sli_agents set assigned_modules='[]'",
        "inactive_server": "update servers set is_active=false",
    }
    if change == "provider":
        payload["method"]["$provider"] = "forged"
    elif change == "event_kind":
        payload["event_kind"] = 4625
    elif change == "time":
        payload["time_created_utc"] = (datetime.fromisoformat(payload["time_created_utc"])+timedelta(seconds=1)).isoformat()
    elif change == "ordinal":
        payload["method"]["$packet_ordinal"] = 1
    elif change == "forged_origin":
        payload["method"].pop("$packet_id")
        payload["method"]["$origin"] = {"plugin_id": "sli.windows.ad-dc", "agent_id": str(uuid4())}
    with watch_db() as conn:
        if change in ("pending_receipt", "unassigned_module"):
            table = "sli_agent_receipts" if change == "pending_receipt" else "sli_agents"
            before = conn.execute(f"select to_jsonb(t) as value from {table} t").fetchall()
            error, message = ((CheckViolation, "sli_agent_receipts_receipt_check") if change == "pending_receipt"
                              else (ObjectNotInPrerequisiteState, "agent_ad_issuer_identity"))
            with pytest.raises(error, match=message), conn.transaction():
                conn.execute(mutations[change])
            assert conn.execute(f"select to_jsonb(t) as value from {table} t").fetchall() == before
            assert conn.execute("select source_sha256 from event_hot").fetchone()["source_sha256"].hex() == item["digest"]
            return
        # Retain durable identity and representation, then re-admit through the
        # real writer. No trigger, grant or verifier is replaced.
        conn.execute("delete from event_hot")
        conn.execute("delete from event_cold_daily")
        if change in mutations:
            conn.execute(mutations[change])
        conn.execute("set local role adlog_storage_worker")
        assert conn.execute("select * from write_short_events349(%s)", (Jsonb([payload]),)).fetchone() == {
            "groups": 1, "summaries": 1, "attested": int(change is None)}
        conn.execute("reset role")
        stored, = conn.execute("select source_sha256,event_record_id,method from event_hot").fetchall()
        if change is None:
            assert stored["source_sha256"].hex() == item["digest"] and stored["event_record_id"] == 1
            assert stored["method"]["$origin"]["plugin_id"] == "sli.windows.ad-dc"
        else:
            assert stored["source_sha256"] is None and stored["event_record_id"] is None
            assert "$origin" not in stored["method"]
        assert conn.execute("select count(*) as n from findings").fetchone()["n"] == 0


def test_short_replay_preserves_receipts_identity_and_summary(watch_db, accepted_event):
    from psycopg.types.json import Jsonb

    _, payload = accepted_event
    tables = ("event_hot", "event_cold_daily", "storage_v2_event_identity_allocations",
              "event_source_representations_v2", "sli_agent_receipts", "sli_agent_packet_inbox")
    with watch_db() as conn:
        before = {table: conn.execute(f"select to_jsonb(t) as value from {table} t order by to_jsonb(t)::text").fetchall()
                  for table in tables}
        conn.execute("set local role adlog_storage_worker")
        assert conn.execute("select * from write_short_events349(%s)", (Jsonb([payload]),)).fetchone() == {
            "groups": 0, "summaries": 0, "attested": 1}
        conn.execute("reset role")
        for table in tables:
            assert conn.execute(f"select to_jsonb(t) as value from {table} t order by to_jsonb(t)::text").fetchall() == before[table]


@pytest.mark.parametrize("statement", [
    "select * from event_hot", "select * from sli_agent_packet_inbox",
    "select * from write_short_events349('[]')",
])
def test_semantic_login_cannot_read_or_forge_ingest_sources(postgres_semantic_worker_dsn, statement):
    import psycopg

    with psycopg.connect(postgres_semantic_worker_dsn) as worker:
        worker.execute("set role adlog_semantic_worker")
        with pytest.raises(psycopg.errors.InsufficientPrivilege), worker.transaction():
            worker.execute(statement)


def test_short_worker_preserves_quarantined_originals_without_repairing_them(
    watch_db, accepted_event, postgres_semantic_worker_dsn, tmp_path,
):
    """Current processing and replay leave terminal legacy lineage intact."""
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb
    from server.sli.semantic import account_watch, default_detections as defaults
    from server.sli.semantic.semantic_processing_repository import (
        PROCESSOR_ID, PROCESSOR_VERSION, SEMANTIC_CONTRACT_VERSION,
    )
    from server.sli.storage.evidence_ref import EvidenceScope

    item, payload = accepted_event
    _register(watch_db, item, "active")
    with watch_db() as conn:
        for identity in (9_720_000, 9_720_001):
            source = {"id": identity, "server_id": payload["method"]["$server_id"],
                "domain_id": item["domain"], "log_source_id": payload["method"]["$origin"]["log_source_id"],
                "event_id": 4624, "time_created_utc": payload["time_created_utc"],
                "normalized_hash": item["digest"], "migrated_at": payload["time_created_utc"], "channel": "Security"}
            conn.execute("""insert into semantic_processing_outbox(
                job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,
                idempotency_key,status,attempt_count,max_attempts,last_error_code,
                source_id,domain_id,partition_key,occurred_at_utc,source_identity_json)
                values(%s,%s,'normalize_event',%s,%s,%s,%s,'quarantined',5,5,'synthetic-error',
                    %s,%s,'synthetic-legacy',%s,%s)""", (uuid4(), identity, SEMANTIC_CONTRACT_VERSION,
                    PROCESSOR_ID, PROCESSOR_VERSION, sha256(str(identity).encode()).digest(),
                    source["server_id"], item["domain"], payload["time_created_utc"], Jsonb(source)))
        before = conn.execute("select to_jsonb(q) as value from semantic_processing_outbox q order by source_event_id").fetchall()
    with psycopg.connect(postgres_semantic_worker_dsn, row_factory=dict_row) as worker:
        worker.execute("set role adlog_semantic_worker")
        source, = worker.execute("select source from default_detection_sources()").fetchall()
        rule = account_watch.WatchRule(scope=EvidenceScope(**source["source"]["scope"]), evaluation_mode="enabled")
        assert defaults._admit(worker.cursor(), account_watch.risk_policy(rule, policy_id=defaults.policy_id(rule.execution)))
    for _ in range(2):
        run_semantic_worker(postgres_semantic_worker_dsn, tmp_path)
        with watch_db() as conn:
            assert conn.execute("select to_jsonb(q) as value from semantic_processing_outbox q order by source_event_id").fetchall() == before
            assert conn.execute("select native_id from finding_evidence_refs").fetchall() == [{"native_id": str(item["event"])}]
