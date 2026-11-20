"""Collector/agent projection equivalence using the real importer and fake sinks."""
import importlib
import json
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents import consumer
from server.sli.sources.ad_dc_agent_import import (
    import_ad_dc_packet,
    run_agent_import_once,
)
from server.sli.sources.collection_packet_import import (
    consume_agent_packets,
    event_rows_from_packet,
)
from sli_agent.ad_dc import ADDCModule, event_identities
from sli_agent.envelope import digest, make_packet
from sli_collect.eventlog import parse_event_xml

importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)
HOST = str(uuid4())
CONFIG = {"source_name": "fixture-dc", "connect_address": "fixture-endpoint"}


def event_xml(channel, provider, event_id, record_id):
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="{provider}"/><EventID>{event_id}</EventID>'
            f'<EventRecordID>{record_id}</EventRecordID><Channel>{channel}</Channel>'
            '<Computer>fixture-dc</Computer><TimeCreated SystemTime="2026-10-07T00:00:00Z"/>'
            '</System><EventData><Data Name="TargetUserName">fixture-account</Data>'
            '<Data Name="TargetUserSid">S-1-5-21-100-200-300-1001</Data>'
            '<Data Name="LogonType">3</Data></EventData></Event>')


class Cursor:
    def __init__(self, envelope=None):
        self.envelope = envelope
        self.agent = {"status": "active", "assigned_modules": [
            {"module_id": "sli.windows.ad-dc", "enabled": True}]}
        self.plugin = {"installed": True, "enabled": True}
        self.receipt = {"envelope": deepcopy(envelope), "envelope_sha256": digest(envelope)} if envelope else None

    def execute(self, sql, params=()):
        self.sql = sql

    def fetchone(self):
        if "from sli_agents" in self.sql:
            return self.agent
        if "from sli_agent_receipts" in self.sql:
            return self.receipt
        if "from read_plugin_states_v1" in self.sql:
            return self.plugin
        if "from servers" in self.sql:
            return {"server_id": 3, "domain_id": 2, "site_id": 1}
        if "from log_sources" in self.sql:
            return {"id": 4}
        if "from sli_agent_module_bindings" in self.sql:
            return {"source_instance_id": HOST, "source_name": "fixture-dc", "channel": "ad-dc",
                    "module_version": "1.0.0", "policy_revision": "1"}
        if "to_regprocedure" in self.sql:
            return {"available": False}
        raise AssertionError("unexpected fixture query")

    def fetchall(self):
        return [self.fetchone()]


def envelope_for(sample):
    return make_packet(ec.generate_private_key(ec.SECP256R1()), agent_id=str(uuid4()),
                       sequence=1, sample=sample, now=NOW)["envelope"]


def test_unpublished_legacy_reservation_keeps_its_original_hash_when_published():
    from server.sli.storage.event_source_identity import legacy_event_hash

    row = parse_event_xml(event_xml("Security", "fixture-provider", 4624, 7),
                          source_name="fixture-dc", connect_address="localhost", channel="Security")
    retained_hash = bytes.fromhex(legacy_event_hash(row))
    repository = SimpleNamespace(reserve_event_identities=lambda rows: [
        {"ordinal": 0, "id": 42, "published": False, "normalized_hash": retained_hash, "source_row": row}])
    results = importer.resolve_direct_event_ids(repository=repository, server_id=3, channel_ids={"Security": 4},
        items=[(row, importer.parse_event_data(row["xml"]))])
    event_id, inserted, preferred, data = results[0]
    built = importer.build_direct_event_source_row(event_db_id=event_id, raw_log_file_id=7,
        server_id=3, domain_id=2, site_id=1, log_source_id=4, normalized_at=NOW.isoformat(),
        row=preferred, event_data=data)
    assert inserted and built["normalized_hash"] == retained_hash.hex()
    assert importer.event_normalized_hash(row) != retained_hash.hex()


@pytest.fixture
def sinks(monkeypatch):
    published, projected = [], []
    class Repository:
        def reserve_raw_log_file(self, **_):
            return {"id": 7, "imported_at": NOW.isoformat()}
        def dictionary_id(self, *_):
            return 4
        def supports_process_activity_facts(self, **_):
            return False
        def reserve_event_identities(self, rows):
            return [{"ordinal": i, "id": 100 + i, "published": False} for i in range(len(rows))]
    runtime = SimpleNamespace(repository=Repository(), publisher=object(),
                              connect_factory=lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(Cursor()))))
    def assign(_cur, *, states, **_):
        for i, state in enumerate(states):
            state.entity_id = state.effective_entity_id = 200 + i
    monkeypatch.setattr(importer, "is_authorized_direct_runtime", lambda _: True)
    monkeypatch.setattr(importer, "require_entity_state_projection_schema", lambda _: None)
    monkeypatch.setattr(importer, "assign_direct_entity_ids", assign)
    monkeypatch.setattr(importer, "publish_direct_batch", lambda **kwargs: published.append(kwargs["batch"]))
    monkeypatch.setattr(importer, "enqueue_projection_job", lambda _, **kw: projected.append(kw))
    monkeypatch.setattr(importer, "get_log_source", lambda *_: 4)
    monkeypatch.setattr(importer, "finalize_raw_log_file", lambda *_args, **_kw: 7)
    monkeypatch.setattr(importer, "_persist_source_capture_continuity", lambda *_args, **_kw: 0)
    return runtime, published, projected


@pytest.mark.parametrize("channel", ["Security", "System", "Directory Service"])
def test_same_events_produce_identical_source_facts_entities_links_and_state_jobs(tmp_path, sinks, channel):
    runtime, published, projected = sinks
    identities = sorted(identity for identity in event_identities() if identity[0] == channel)
    # Include authentication/account state as well as the other native channels.
    if channel == "Security":
        identities = [identity for identity in identities if identity[2] in (4624, 4725, 4740)]
    raws = [event_xml(ch, provider, event_id, i + 1) for i, (ch, provider, event_id) in enumerate(identities[:3])]
    assert raws
    collector_rows = [parse_event_xml(raw, source_name=CONFIG["source_name"],
                                     connect_address=CONFIG["connect_address"], channel=channel) for raw in raws]
    path = tmp_path / f"{channel}.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in collector_rows), encoding="utf-8")
    importer.import_file(Cursor(), path, 1, 3, 2, 1, direct_runtime=runtime, commit_direct_metadata=lambda: None)
    expected_batches, expected_jobs = list(published), list(projected)
    published.clear()
    projected.clear()
    dc = ADDCModule(HOST, CONFIG, reader=lambda ch, *_: [(raw, f"bookmark-{i + 1}")
                    for i, raw in enumerate(raws)] if ch == channel else [])
    captured = None
    for _ in range(3):
        sample = dc.collect(captured, now=NOW)
        captured = {"generation": sample.generation, "cursor_after": sample.cursor_after}
        if sample.payload["header"]["channel"] == channel:
            break
    envelope = envelope_for(sample)
    conn = SimpleNamespace(cursor=lambda: nullcontext(Cursor(envelope)))
    import_ad_dc_packet(conn, event_rows_from_packet(sample.payload), packet=sample.payload,
                        envelope=envelope, direct_runtime=runtime)
    assert published == expected_batches and projected == expected_jobs
    from server.sli.storage.storage_v2_backfill import transform_batch_with_facts
    assert [transform_batch_with_facts(runtime.repository, batch) for batch in published] == [
        transform_batch_with_facts(runtime.repository, batch) for batch in expected_batches]


@pytest.mark.parametrize("event_id,caller,semantic_type", [
    (4740, "fixture-client", "authentication.account.locked"),
    (4740, None, "authentication.account.locked"),
    (4767, None, "authentication.account.unlocked"),
])
def test_agent_lockout_events_keep_target_and_source_through_import(sinks, event_id, caller, semantic_type):
    from server.sli.plugins.ad.windows_ad_dc.semantics import (
        semantic_projection_for_event,
    )

    runtime, published, _ = sinks
    raw = event_xml("Security", "Microsoft-Windows-Security-Auditing", event_id, 1)
    if caller:
        raw = raw.replace("</EventData>", f'<Data Name="CallerComputerName">{caller}</Data></EventData>')
    module = ADDCModule(HOST, CONFIG, reader=lambda channel, *_:
                        [(raw, "fixture-bookmark")] if channel == "Security" else [])
    sample = module.collect(now=NOW, channel="Security")
    rows = event_rows_from_packet(sample.payload)
    assert len(rows) == 1 and rows[0]["event_id"] == event_id
    data = importer.parse_event_data(rows[0]["xml"])
    assert data["TargetUserSid"] == "S-1-5-21-100-200-300-1001"
    assert data.get("CallerComputerName") == caller
    envelope = envelope_for(sample)
    conn = SimpleNamespace(cursor=lambda: nullcontext(Cursor(envelope)))
    import_ad_dc_packet(conn, rows, packet=sample.payload, envelope=envelope, direct_runtime=runtime)
    batch, = published
    event, = batch.events
    retained = json.loads(event["event_data_json"])
    assert retained["TargetUserSid"] == data["TargetUserSid"]
    assert retained.get("CallerComputerName") == caller
    projection = semantic_projection_for_event(event_id=event_id, channel="Security",
        provider="Microsoft-Windows-Security-Auditing", event_data=retained,
        correlation_id=None, source_host="fixture-dc")
    assert projection["semantic_type"] == semantic_type
    if event_id == 4740:
        assert projection["facts"].get("caller_computer") == caller


@pytest.mark.parametrize("source_name", [None, "fixture-unbound-dc"])
def test_import_rejects_unbound_source_before_any_publication(sinks, source_name):
    from server.sli.agents.import_authorization import PacketPending

    runtime, published, _ = sinks
    class Unbound(Cursor):
        def fetchone(self):
            row = super().fetchone()
            if "from sli_agent_module_bindings" in self.sql:
                return {**row, "source_name": source_name} if source_name else None
            return row
    sample = ADDCModule(HOST, CONFIG, reader=lambda *_: []).collect(now=NOW)
    envelope = envelope_for(sample)
    conn = SimpleNamespace(cursor=lambda: nullcontext(Unbound(envelope)))
    with pytest.raises(PacketPending, match="agent_ad_dc_source_not_bound"):
        import_ad_dc_packet(conn, [], packet=sample.payload,
                            envelope=envelope,
                            direct_runtime=runtime)
    assert not published


def test_missing_ad_validator_leaves_receipted_packet_pending(monkeypatch, sinks):
    from server.sli.agents.import_authorization import PacketPending
    from server.sli.plugins.ad import event_import

    runtime, published, projected = sinks
    monkeypatch.setattr(event_import, "plugin_hook", lambda *_: None)
    sample = ADDCModule(HOST, CONFIG, reader=lambda *_: []).collect(now=NOW)
    envelope = envelope_for(sample)
    with pytest.raises(PacketPending, match="agent_packet_attestation_invalid"):
        import_ad_dc_packet(SimpleNamespace(cursor=lambda: nullcontext(Cursor(envelope))), [],
                           packet=sample.payload, envelope=envelope, direct_runtime=runtime)
    assert not published and not projected


def test_legacy_importer_alias_preserves_bounded_scan_state():
    from server.sli.plugins.ad import event_import
    from server.sli.sources import ad_dc_agent_import

    assert ad_dc_agent_import is event_import
    assert run_agent_import_once is event_import.run_agent_import_once


def test_acknowledged_packet_is_imported_after_policy_revision_changes(sinks):
    runtime, _, _ = sinks
    sample = ADDCModule(HOST, CONFIG, reader=lambda *_: []).collect(now=NOW)
    sample.payload["context"]["ad_dc"]["policy_revision"] = "fixture-old-policy"
    envelope = envelope_for(replace(sample, policy_revision="fixture-old-policy"))
    assert import_ad_dc_packet(SimpleNamespace(cursor=lambda: nullcontext(Cursor(envelope))), [],
        packet=sample.payload, envelope=envelope, direct_runtime=runtime) == {"inserted": 0, "skipped": 0}


def test_history_dispatch_uses_ad_authority_and_existing_event_projection(monkeypatch, sinks):
    from sli_agent.ad_dc import HISTORY_ID, DCHistoryModule
    runtime, published, _ = sinks
    raw = event_xml("Security", "Microsoft-Windows-Security-Auditing", 4624, 1)
    module = DCHistoryModule(HOST, {**CONFIG, "history_before_utc": "2026-10-08T00:00:00Z"},
                             reader=lambda *_: [(raw, "fixture-bookmark")])
    sample = module.collect(now=NOW)
    envelope = envelope_for(sample)
    cursor = Cursor(envelope)
    cursor.agent["assigned_modules"].append({"module_id": HISTORY_ID, "enabled": True})
    monkeypatch.setattr(importer, "load_authorized_direct_runtime", lambda *a, **k: runtime)
    conn = SimpleNamespace(cursor=lambda: nullcontext(cursor))
    consumer.dispatch_packet(conn, event_rows_from_packet(sample.payload), packet=sample.payload, envelope=envelope)
    assert len(published) == 1
    assert int(published[0].events[0]["event_id"]) == 4624


def test_malformed_signed_native_attestation_has_specific_pending_reason(sinks):
    from server.sli.agents.import_authorization import PacketPending

    runtime, published, projected = sinks
    raw = event_xml("Security", "Microsoft-Windows-Security-Auditing", 4624, 1)
    sample = ADDCModule(HOST, CONFIG, reader=lambda *_: [(raw, "fixture-bookmark")]).collect(now=NOW)
    sample.payload["context"]["ad_dc"]["channel_reset"] = True
    envelope = envelope_for(sample)
    cur = Cursor(envelope)
    runtime.repository.reserve_raw_log_file = lambda **kw: pytest.fail("invalid attestation must not reserve storage")
    with pytest.raises(PacketPending, match="^agent_packet_attestation_invalid$"):
        import_ad_dc_packet(SimpleNamespace(cursor=lambda: nullcontext(cur)), event_rows_from_packet(sample.payload),
                            packet=sample.payload, envelope=envelope, direct_runtime=runtime)
    assert not published and not projected


def test_unrelated_validator_value_error_remains_projection_failure(monkeypatch, sinks):
    from server.sli.agents.import_authorization import PacketPending
    from server.sli.sources import ad_dc_agent_import

    runtime, published, projected = sinks
    sample = ADDCModule(HOST, CONFIG, reader=lambda *_: []).collect(now=NOW)
    envelope = envelope_for(sample)
    cur = Cursor(envelope)
    error = ValueError("fixture-private-diagnostic")

    def validator(*args):
        raise error

    monkeypatch.setattr(ad_dc_agent_import, "plugin_hook", lambda *args: validator)
    with pytest.raises(ValueError) as caught:
        import_ad_dc_packet(SimpleNamespace(cursor=lambda: nullcontext(cur)), [],
                            packet=sample.payload, envelope=envelope, direct_runtime=runtime)
    assert caught.value is error and not isinstance(caught.value, PacketPending)
    assert not published and not projected


@pytest.mark.parametrize("change,reason", [("disabled", "agent_disabled"),
    ("unassigned", "agent_module_not_assigned"), ("module_disabled", "agent_module_not_assigned"),
    ("plugin", "agent_plugin_disabled"), ("receipt", "agent_packet_attestation_invalid"),
    ("payload", "agent_packet_attestation_invalid")])
def test_import_rechecks_authority_before_reserving_or_publishing(sinks, change, reason):
    runtime, published, projected = sinks
    raw = event_xml("Security", "Microsoft-Windows-Security-Auditing", 4624, 1)
    sample = ADDCModule(HOST, CONFIG, reader=lambda *_: [(raw, "fixture-bookmark")]).collect(now=NOW)
    envelope = envelope_for(sample)
    cur = Cursor(envelope)
    if change == "disabled": cur.agent["status"] = "disabled"
    elif change == "unassigned": cur.agent["assigned_modules"] = []
    elif change == "module_disabled": cur.agent["assigned_modules"][0]["enabled"] = False
    elif change == "plugin": cur.plugin["enabled"] = False
    elif change == "receipt": cur.receipt["envelope_sha256"] = "0" * 64
    else: sample.payload["records"][0]["payload"]["level"] = 999
    def reserve(**_):
        pytest.fail("blocked packet must not reserve storage")
    runtime.repository.reserve_raw_log_file = reserve
    with pytest.raises(ValueError, match=reason):
        import_ad_dc_packet(SimpleNamespace(cursor=lambda: nullcontext(cur)), event_rows_from_packet(sample.payload),
                            packet=sample.payload, envelope=envelope, direct_runtime=runtime)
    assert not published and not projected


@pytest.mark.parametrize("change,reason", [(None, None), ("disabled", "agent_disabled"),
    ("plugin", "agent_plugin_disabled"), ("receipt", "agent_packet_attestation_invalid"),
    ("unassigned", "agent_module_not_assigned"), ("storage", "agent_storage_unavailable")])
def test_core_dispatch_imports_dc_packet_or_retains_evidence(monkeypatch, sinks, change, reason):
    runtime, published, projected = sinks
    raw = event_xml("Security", "Microsoft-Windows-Security-Auditing", 4624, 1)
    sample = ADDCModule(HOST, CONFIG, reader=lambda *_: [(raw, "fixture-bookmark")]).collect(now=NOW)
    envelope = envelope_for(sample)
    cur = Cursor(envelope)
    if change == "disabled": cur.agent["status"] = "disabled"
    elif change == "plugin": cur.plugin["enabled"] = False
    elif change == "receipt": cur.receipt["envelope_sha256"] = "0" * 64
    elif change == "unassigned": cur.agent["assigned_modules"] = []
    inbox = [{"packet_id": envelope["packet_id"], "envelope": envelope, "packet": sample.payload,
              "event_rows": event_rows_from_packet(sample.payload), "received_at": NOW}]
    imported = []

    class InboxCursor(Cursor):
        def execute(self, sql, params=()):
            super().execute(sql, params)
            self.params = params
            if sql.startswith("update sli_agent_packet_inbox"):
                imported.append(params[0])

        def fetchall(self):
            if "from sli_agent_packet_inbox" in self.sql:
                if imported or len(self.params) == 3 and (NOW, envelope["packet_id"]) <= self.params[:2]:
                    return []
                return inbox
            if "from sli_agent_snapshot_cycles" in self.sql:
                return []
            return super().fetchall()

    conn = SimpleNamespace(cursor=lambda: nullcontext(inbox_cur), transaction=lambda: nullcontext(), commit=lambda: None)
    inbox_cur = InboxCursor(envelope)
    inbox_cur.agent, inbox_cur.plugin, inbox_cur.receipt = cur.agent, cur.plugin, cur.receipt
    monkeypatch.setattr(consumer, "connect", lambda: nullcontext(conn))

    def load_runtime(_cur, *, connect_factory, publish_archive):
        assert publish_archive is False
        return None if change == "storage" else runtime

    monkeypatch.setattr(importer, "load_authorized_direct_runtime", load_runtime)
    result = consumer.AgentPacketConsumer().run_once()
    assert result["pending_reasons"] == ({reason: 1} if reason else {})
    assert result["imported"] == (0 if reason else 1)
    assert imported == ([] if reason else [envelope["packet_id"]])
    assert len(published) == (0 if reason else 1)
    if reason:
        assert not projected
    else:
        event, = published[0].events
        assert event["server_id"] == 3 and event["domain_id"] == 2
        assert int(event["event_id"]) == 4624
        assert consumer.AgentPacketConsumer().run_once()["imported"] == 0
        assert len(published) == 1


def test_core_dispatch_missing_ad_package_keeps_packet_pending(monkeypatch):
    from server.sli.agents.import_authorization import PacketPending

    monkeypatch.setattr(consumer, "plugin_hook", lambda *_: None)
    with pytest.raises(PacketPending, match="agent_plugin_not_installed"):
        consumer.dispatch_packet(None, [], packet={}, envelope={"module_id": "sli.windows.ad-dc"})


@pytest.mark.parametrize("limit", [1, 16])
def test_dc_failure_does_not_hide_next_packet_and_records_only_safe_reason(monkeypatch, limit):
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.ops import logging_config
    from server.sli.sources import ad_dc_agent_import as adapter
    updates, scans, logs = [], [], []
    effects = []
    pending = [{"packet_id": str(uuid4()), "received_at": NOW.replace(second=n), "envelope": {},
                "packet": {}, "event_rows": [n]} for n in range(2)]
    for row in pending:
        row["envelope"]["packet_id"] = row["packet_id"]
    class Pending:
        def execute(self, sql, params=()):
            if sql.startswith("update"):
                updates.append(params[0])
            elif "from sli_agent_packet_inbox" in sql:
                scans.append(params)
                after = params[1:3] if len(params) == 4 else None
                self.rows = [row for row in pending if row["packet_id"] not in updates and
                    (after is None or (row["received_at"], row["packet_id"]) > after)][:params[-1]]
        def fetchall(self):
            return self.rows
    @contextmanager
    def transaction():
        saved = list(effects)
        try:
            yield
        except Exception:
            effects[:] = saved
            raise
    conn = SimpleNamespace(transaction=transaction, cursor=lambda: nullcontext(Pending()), commit=lambda: None)
    monkeypatch.setenv("SLI_AD_DC_AGENT_IMPORT_ENABLED", "1")
    monkeypatch.setattr(adapter, "_after", None)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: nullcontext(conn))
    monkeypatch.setattr(importer, "load_authorized_direct_runtime", lambda *_args, **_kw: object())
    monkeypatch.setattr(logging_config, "log_event", lambda *_args, **kw: logs.append(kw))
    def project(_conn, rows, **_):
        effects.extend(rows)
        if rows == [0]:
            raise ValueError("fixture-private-diagnostic")
    monkeypatch.setattr(adapter, "import_ad_dc_packet", project)
    if limit == 1:
        assert adapter.run_agent_import_once(limit=limit) == 0
    assert adapter.run_agent_import_once(limit=limit) == 1
    assert updates == [pending[1]["packet_id"]]
    assert effects == [1]
    assert adapter._after == (pending[1]["received_at"], pending[1]["packet_id"])
    assert logs == [{"pending_reasons": {"agent_ad_dc_projection_failed": 1},
                    "pending_packets": [{"packet_id": pending[0]["packet_id"], "reason": "agent_ad_dc_projection_failed"}]}]
    assert "private" not in repr(logs)
    assert adapter.run_agent_import_once(limit=limit) == 0
    assert adapter._after is None


def test_inbox_selects_only_dc_packets_and_progress_follows_sink():
    calls = []
    class Pending(Cursor):
        def execute(self, sql, params=()):
            calls.append((sql, params))
        def fetchall(self):
            return [{"packet_id": "fixture-packet", "event_rows": [], "packet": {}, "envelope": {}}]
    conn = SimpleNamespace(transaction=lambda: nullcontext(), cursor=lambda: nullcontext(Pending()))
    def sink(*_args, **_kwargs):
        calls.append(("sink", ()))
    assert consume_agent_packets(conn, import_rows=sink, module_id="sli.windows.ad-dc") == 1
    assert "envelope->>'module_id'" in calls[0][0]
    assert calls[0][1] == ("sli.windows.ad-dc", 16)
    assert calls[1][0] == "sink" and calls[2][0].startswith("update")


def test_runtime_import_is_opt_in(monkeypatch):
    monkeypatch.delenv("SLI_AD_DC_AGENT_IMPORT_ENABLED", raising=False)
    assert run_agent_import_once() == 0
    monkeypatch.setenv("SLI_AD_DC_AGENT_IMPORT_ENABLED", "invalid")
    with pytest.raises(ValueError, match="agent_ad_dc_import_config_invalid"):
        run_agent_import_once()


def test_agent_import_ownership_blocks_pull_and_keeps_rollback(monkeypatch):
    from server.jobs import collector
    monkeypatch.setenv("SLI_AD_DC_AGENT_IMPORT_ENABLED", "1")
    assert collector._collection_block_reason() == "ad_dc_agent_collection_owner"
    monkeypatch.setenv("SLI_AD_DC_AGENT_IMPORT_ENABLED", "0")
    monkeypatch.setattr(collector, "_runtime_db_backend", lambda: "postgres")
    monkeypatch.setattr(collector, "_postgres_collection_enabled", lambda: True)
    from server.sli.sources import collection_runtime_block
    monkeypatch.setattr(collection_runtime_block, "get_active_collection_block", lambda: None)
    monkeypatch.delenv("ADLOG_DISABLE_COLLECTION", raising=False)
    assert collector._collection_block_reason() is None


def test_post_collection_worker_runs_bounded_agent_import(monkeypatch):
    from scripts.runtime import post_collection_worker as worker
    from server.sli.sources import ad_dc_agent_import
    calls = []
    monkeypatch.setattr(worker, "resolve_storage_route", lambda **_: None)
    monkeypatch.setattr(worker, "_worker_id", lambda: "fixture-worker")
    monkeypatch.setattr(worker, "log_event", lambda *_args, **_kw: None)
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **_: None)
    monkeypatch.setattr(worker, "run_persisted_post_collection_worker_once", lambda **_: {"failed": 0})
    monkeypatch.setattr(ad_dc_agent_import, "run_agent_import_once", lambda **kw: calls.append(kw) or 1)
    assert worker._run_locked(once=True, poll_seconds=1, limit=2) == 0
    assert calls == [{"limit": 2}]


def test_storage_published_retry_still_queues_state_jobs_without_republishing(sinks):
    runtime, published, projected = sinks
    # Use a catalogued state rule; 4725 has no entity-state projection rule.
    raw = event_xml("Security", "Microsoft-Windows-Security-Auditing", 4722, 1)
    row = parse_event_xml(raw, source_name=CONFIG["source_name"],
                          connect_address=CONFIG["connect_address"], channel="Security")
    runtime.repository.reserve_event_identities = lambda rows: [
        {"ordinal": i, "id": 100 + i, "published": True} for i in range(len(rows))]
    profile = importer.ImportProfile(file="fixture", rows=1)
    assert importer.import_direct_event_batch(Cursor(), [(row, importer.parse_event_data(raw))],
        direct_runtime=runtime, server_id=3, domain_id=2, site_id=1, log_source_id=4,
        raw_log_file_id=7, normalized_at=NOW.isoformat(), batch_identity=lambda *_: "fixture",
        entity_cache={}, profile=profile, relink_existing_events=True) == (0, 1)
    assert not published
    assert profile.entity_state_projection_jobs_queued == 1
    job, = projected
    assert job["source_event_db_id"] == 100
    candidate, = job["candidates"]
    assert candidate["source_event_db_id"] == 100
    assert candidate["state_type"] == "account.access" and candidate["status"] == "enabled"
    assert candidate["rule_id"] == "account-enabled-4722"
    assert candidate["observed_at_utc"] == NOW.isoformat().replace("+00:00", "Z")


def test_overlap_publishes_only_new_event_links(sinks):
    runtime, published, _ = sinks
    runtime.repository.reserve_event_identities = lambda rows: [
        {"ordinal": i, "id": 100 + i, "published": i == 0} for i in range(len(rows))]
    rows = [parse_event_xml(event_xml("Security", "Microsoft-Windows-Security-Auditing", 4725, n),
        source_name=CONFIG["source_name"], connect_address=CONFIG["connect_address"], channel="Security")
        for n in (1, 2)]
    importer.import_direct_event_batch(Cursor(), [(row, importer.parse_event_data(row["xml"])) for row in rows],
        direct_runtime=runtime, server_id=3, domain_id=2, site_id=1, log_source_id=4,
        raw_log_file_id=7, normalized_at=NOW.isoformat(), batch_identity=lambda *_: "fixture",
        entity_cache={}, profile=importer.ImportProfile(file="fixture", rows=2), relink_existing_events=True)
    batch, = published
    assert [event["id"] for event in batch.events] == [101]
    assert batch.links and all(link["event_id"] == 101 for link in batch.links)


def test_dc_batch_commits_packet_before_claiming_next(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.sources import ad_dc_agent_import as adapter

    pending = [{"packet_id": str(uuid4()), "received_at": NOW.replace(second=n),
                "envelope": {"ordinal": n}, "packet": {}, "event_rows": [n]} for n in range(2)]
    durable, staged, scans, observed = [], [], [], []

    class Cursor:
        def execute(self, sql, params=()):
            if sql.startswith("update sli_agent_packet_inbox"):
                staged.append(params[0])
            elif "from sli_agent_packet_inbox" in sql:
                scans.append(params)
                after = params[1:3] if len(params) == 4 else None
                self.rows = [row for row in pending if row["packet_id"] not in durable + staged
                    and (after is None or (row["received_at"], row["packet_id"]) > after)][:params[-1]]
        def fetchall(self):
            return self.rows

    def commit():
        durable.extend(staged)
        staged.clear()

    conn = SimpleNamespace(transaction=lambda: nullcontext(), cursor=lambda: nullcontext(Cursor()), commit=commit)
    monkeypatch.setenv("SLI_AD_DC_AGENT_IMPORT_ENABLED", "1")
    monkeypatch.setattr(adapter, "_after", None)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: nullcontext(conn))
    monkeypatch.setattr(importer, "load_authorized_direct_runtime", lambda *_args, **_kw: object())
    def project(_conn, rows, **_):
        observed.append(list(durable))
    monkeypatch.setattr(adapter, "import_ad_dc_packet", project)
    assert adapter.run_agent_import_once(limit=2) == 2
    assert observed == [[], [pending[0]["packet_id"]]], "previous packet remains uncommitted"
    assert durable == [row["packet_id"] for row in pending]
    assert staged == []
    assert [params[-1] for params in scans] == [1, 1]
    assert adapter._after == (pending[-1]["received_at"], pending[-1]["packet_id"])


@pytest.mark.parametrize("limit", [0, 129, True, 1.5, "2"])
def test_dc_batch_rejects_invalid_limit_before_connecting(monkeypatch, limit):
    from server.sli.core import postgres_runtime_pipeline
    monkeypatch.setenv("SLI_AD_DC_AGENT_IMPORT_ENABLED", "1")
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: pytest.fail("invalid limit connected"))
    with pytest.raises(RuntimeError, match="^agent_ad_dc_import_failed$"):
        run_agent_import_once(limit=limit)


def test_dc_batch_commit_failure_does_not_advance_scan_position(monkeypatch):
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.sources import ad_dc_agent_import as adapter
    position = (NOW, str(uuid4()))
    monkeypatch.setenv("SLI_AD_DC_AGENT_IMPORT_ENABLED", "1")
    monkeypatch.setattr(adapter, "_after", position)
    def consume(_conn, *, on_scan, **_):
        on_scan((NOW, str(uuid4())))
        return 1
    def fail_commit():
        raise OSError("synthetic-private-diagnostic")
    conn = SimpleNamespace(cursor=lambda: nullcontext(object()), commit=fail_commit)
    monkeypatch.setattr(adapter, "consume_agent_packets", consume)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: nullcontext(conn))
    monkeypatch.setattr(importer, "load_authorized_direct_runtime", lambda *_args, **_kw: object())
    with pytest.raises(RuntimeError, match="^agent_ad_dc_import_failed$"):
        adapter.run_agent_import_once(limit=2)
    assert adapter._after == position
