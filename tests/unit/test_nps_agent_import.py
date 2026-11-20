"""Legacy/agent equivalence at the real VPN sinks, using transactional fakes."""
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import asdict
from datetime import timedelta
import importlib
import json
from types import SimpleNamespace

import pytest

from server.sli.agents import consumer
from server.sli.sources import nps_agent_import, radius_plugin_runtime as radius
from server.sli.sources.collection_packet_import import event_rows_from_packet, store_agent_packet
from sli_agent.nps import AccountingModule, NPSModule, ACCOUNTING_MODULE, NPS_MODULE
from sli_collect.eventlog import parse_event_xml
from sli_collect.radius import collect_radius_packet
from sli_collect.radius_contract import RadiusFileCursor
from sli_collect.radius_tail import RadiusTailBatch, derive_file_generation
from tests.unit.test_ad_dc_agent_import import sinks  # noqa: F401 - real importer fake publication fixture
from tests.unit.test_sli_agent_nps import (
    NOW, HOST, AGENT, CONFIG, event, accounting_line, accounting_config, signed, receive,
)

importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")


class Cursor:
    def __init__(self, context, *, plugin=True):
        _, self.identity, _, self.value = context
        self.identity = {**self.identity, "status": "active"}
        self.plugin = plugin
        self.calls = []

    def execute(self, sql, params=()):
        self.sql = sql
        self.calls.append((sql, params))

    def fetchone(self):
        if "public.lock_nps_import_agent_v304(" in self.sql:
            return self.identity
        if "from sli_agent_receipts" in self.sql:
            from sli_agent.envelope import digest
            return {"envelope": self.value["envelope"], "envelope_sha256": digest(self.value["envelope"])}
        if "read_plugin_states_v1" in self.sql:
            return {"installed": True, "enabled": self.plugin}
        if "from servers" in self.sql:
            return {"server_id": 3, "domain_id": 2, "site_id": 1}
        if "from log_sources" in self.sql:
            return {"id": 4}
        if "to_regprocedure" in self.sql:
            return {"available": False}
        if "current_user" in self.sql:
            return {"role_name": "adlog_nps_agent_import_worker"}
        raise AssertionError("unexpected fixture query")

    def fetchall(self):
        return [self.fetchone()]


def connection(cur):
    return SimpleNamespace(cursor=lambda **_kw: nullcontext(cur), transaction=lambda: nullcontext())


def test_nps_legacy_jsonl_and_signed_agent_publish_identical_facts_and_policy_rows(tmp_path, sinks, monkeypatch):
    runtime, published, projected = sinks
    raws = [event(6272, 1), event(6273, 2)]
    legacy_rows = [parse_event_xml(raw, source_name=CONFIG["source_name"],
        connect_address=CONFIG["connect_address"], channel="Security") for raw in raws]
    sample = NPSModule(HOST, CONFIG, reader=lambda *_: [(raw, f"bookmark-{i}")
        for i, raw in enumerate(raws, 1)]).collect(now=NOW)
    context = signed(sample, CONFIG)
    assert receive(context)["status"] == "committed"
    cur = Cursor(context)
    path = tmp_path / "fixture-nps.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in legacy_rows), encoding="utf-8")
    importer.import_file(cur, path, 1, 3, 2, 1, direct_runtime=runtime, commit_direct_metadata=lambda: None)
    expected_batches = deepcopy(published)
    expected_jobs = deepcopy(projected)
    published.clear()
    projected.clear()
    monkeypatch.setattr(importer, "load_authorized_direct_runtime", lambda *_a, **_kw: runtime)
    monkeypatch.setenv("SLI_NPS_AGENT_IMPORT_ENABLED", "1")
    consumer.dispatch_packet(connection(cur), event_rows_from_packet(sample.payload),
                             packet=sample.payload, envelope=context[3]["envelope"])
    assert published == expected_batches and projected == expected_jobs

    from server.sli.semantic.semantic_processing import StoredEvent, normalize_windows_event
    from server.sli.reports.nps_policy_denials_reporting import compose_policy_denials
    def report(rows):
        facts = []
        for row in rows:
            normalized = normalize_windows_event(StoredEvent(row["record_id"], row["event_id"], "Security",
                CONFIG["source_name"], NOW, importer.parse_event_data(row["xml"]), provider=row["provider_name"]))
            facts.append({"source_event_id": normalized.source_event_id,
                "normalized_event_id": f"fixture-normalized-{normalized.source_event_id}",
                "semantic_type": normalized.semantic_type,
                "occurred_at_utc": NOW, "roles_json": normalized.roles, "facts_json": normalized.facts,
                "quality_json": normalized.quality})
        return compose_policy_denials(facts, [], start=NOW, end=NOW + timedelta(days=1))
    expected_report = report(legacy_rows)
    assert expected_report == report(event_rows_from_packet(sample.payload))
    assert expected_report["metrics"]["allowed"] == expected_report["metrics"]["denied"] == 1
    assert [row["normalized_event_id"] for row in expected_report["events"]] == [
        "fixture-normalized-1", "fixture-normalized-2"]


def test_same_accounting_file_produces_identical_vpn_connection_rows(tmp_path, monkeypatch):
    path = tmp_path / "IN-fixture.log"
    path.write_text("\n".join([accounting_line(packet_type="2"), accounting_line(),
                              accounting_line("2", minute="05")]) + "\n", encoding="utf-8")
    generation = derive_file_generation(source_instance_id=CONFIG["source_instance_id"],
        file_name=path.name, file_creation_time_ns=path.stat().st_ctime_ns)
    config = accounting_config(tmp_path, generation=generation)
    cursor = RadiusFileCursor(**config["initial_cursor"])
    legacy = collect_radius_packet(tmp_path, cursor=cursor, source_timezone_id="UTC",
                                  source_utc_offset_minutes=0, observed_at=NOW)
    sample = AccountingModule(HOST, config).collect(now=NOW)
    assert sample.payload == legacy
    context = signed(sample, config)
    assert receive(context)["status"] == "committed"
    state = SimpleNamespace(cursor=cursor, revision=1, cursor_epoch="fixture-epoch", class_cache={})
    plans = []
    def commit(_conn, **kwargs):
        plans.append(kwargs["plan"])
        assert kwargs["subscription_id"] == config["subscription_id"]
        return SimpleNamespace(cursor_revision=2, evidence_rows=3, observation_rows=2, outbox_rows=2, class_cache_rows=1)
    monkeypatch.setattr(radius, "publish_radius_batch_evidence", lambda *_a, **_kw: ())
    monkeypatch.setattr(radius, "AcquisitionEvidenceStore", lambda *_a: object())
    monkeypatch.setattr(radius, "commit_radius_batch", commit)
    monkeypatch.setattr(radius, "load_runtime_state", lambda *_a, **_kw: state)
    monkeypatch.setattr(radius, "_resolve_acquisition_identity", lambda *_a: "entity:fixture-account")
    monkeypatch.setattr(radius, "acquisition_subscription_id", lambda: config["subscription_id"])
    cur = Cursor(context)
    radius.import_acquisition_packet(connection(cur), legacy, state=state)
    nps_agent_import.import_nps_agent_packet(connection(cur), [], packet=sample.payload, envelope=context[3]["envelope"])
    assert plans[0] == plans[1]
    assert cur.calls[-1] == ("select set_config('role',%s,true)", ("adlog_nps_agent_import_worker",))

    from server.source_packs.radius.session_read_model import RadiusLifecycleInput, fold_radius_sessions
    from server.sli.reports.vpn_connections_reporting import compose_vpn_connections_report
    def report(plan):
        folded = fold_radius_sessions([RadiusLifecycleInput(str(i), o.lifecycle_event, "exact", "ready",
            o.session_identity_key, o.exact_principal_key, o.observed_at_utc, o.canonical_record_sha256)
            for i, o in enumerate(plan.session_observations)])
        rows = [{**asdict(row), "entity_id": 101, "domain_id": 2} for row in folded.sessions]
        return compose_vpn_connections_report(source_domain_id=2, period_start=NOW,
            period_end=NOW + timedelta(days=1), office_timezone="UTC", coverage={"projected_session_count": 1,
                "total_delivery_count": 2}, session_rows=rows, identities={101: {"display_name": "fixture-account"}},
            entitlement_rows=[], failed_events=[], failed_collection_state="not_collected", generated_at=NOW)
    expected = report(plans[0])
    assert expected == report(plans[1])
    assert expected["analytics"]["closed_session_count"] == 1
    assert expected["analytics"]["open_session_count"] == 0
    assert expected["analytics"]["confirmed_seconds"] == 300
    assert len(expected["employees"]) == 1
    assert expected["employees"][0]["sessions"][0]["duration_seconds"] == 300
    assert plans[0].session_observations[1].lifecycle_event == "stop"


@pytest.mark.parametrize("mode,reason", [
    ("plugin", "agent_plugin_disabled"),
    ("attestation", "agent_packet_attestation_invalid"),
    ("source", "agent_source_binding_changed"),
    ("binding", "agent_source_binding_changed"),
    ("cursor", "agent_radius_cursor_conflict"),
    ("valid", None),
])
def test_accounting_fails_closed_before_publication(tmp_path, monkeypatch, mode, reason):
    config = accounting_config(tmp_path)
    line = accounting_line()
    tail = RadiusTailBatch("fixture-generation", 0, len(line) + 1, False, (line,), 1, len(line) + 1, 0)
    sample = AccountingModule(HOST, config, reader=lambda *_a, **_kw: tail).collect(now=NOW)
    context = signed(sample, config)
    assert receive(context)["status"] == "committed"
    # Keep the receipt and packet otherwise consistent. Changing the assignment
    # source here would introduce a second, masking runtime-binding rejection.
    if mode == "source":
        context[3]["envelope"]["source_instance_id"] = "fixture-other"
    cur = Cursor(context, plugin=mode != "plugin")
    if mode == "binding":
        cur.identity["assigned_modules"][0]["config"]["initial_cursor"]["transport_binding"] = "fixture-other"
    packet = deepcopy(sample.payload)
    if mode == "attestation":
        packet["records"][0]["payload"] += "fixture"
    state = SimpleNamespace(cursor=RadiusFileCursor(**{
        **sample.payload["header"]["cursor"]["before"], "byte_offset": 1 if mode == "cursor" else 0,
    }))
    published = []

    def publish(conn, actual, **kwargs):
        if reason is not None:
            pytest.fail("rejected Accounting packet reached publication")
        assert isinstance(conn, nps_agent_import.AccountingConnection)
        assert actual == packet
        assert kwargs["state"] is state
        assert kwargs["subscription_id"] == config["subscription_id"]
        published.append(actual)

    monkeypatch.setattr(radius, "load_runtime_state", lambda *_a, **_kw: state)
    monkeypatch.setattr(radius, "import_acquisition_packet", publish)
    if reason is None:
        nps_agent_import.import_nps_agent_packet(connection(cur), [], packet=packet, envelope=context[3]["envelope"])
        assert published == [packet]
        assert cur.calls[0][0] == "select status,assigned_modules from public.lock_nps_import_agent_v304(%s)"
    else:
        with pytest.raises(consumer.PacketPending, match=f"^{reason}$"):
            nps_agent_import.import_nps_agent_packet(connection(cur), [], packet=packet, envelope=context[3]["envelope"])
        assert published == []


def test_durable_accounting_inbox_stores_no_event_rows(tmp_path):
    sample = AccountingModule(HOST, accounting_config(tmp_path), reader=lambda *_a, **_kw:
        RadiusTailBatch(
            "fixture-generation", 0, 0, False, (), 1, 0, 0)).collect(now=NOW)
    context = signed(sample, accounting_config(tmp_path))
    cur = Cursor(context)
    store_agent_packet(cur, packet_id=context[3]["envelope"]["packet_id"], envelope=context[3]["envelope"],
                       packet=sample.payload, event_rows=[])
    assert cur.calls[0][0].startswith("insert into sli_agent_packet_inbox")
    assert json.loads(cur.calls[0][1][-1]) == []


def test_import_default_disabled_and_errors_are_safe(monkeypatch):
    monkeypatch.delenv("SLI_NPS_AGENT_IMPORT_ENABLED", raising=False)
    assert nps_agent_import.run_accounting_import_once() == 0
    monkeypatch.setenv("SLI_NPS_AGENT_IMPORT_ENABLED", "invalid")
    with pytest.raises(ValueError, match="agent_nps_import_config_invalid"):
        nps_agent_import.run_accounting_import_once()
    monkeypatch.setenv("SLI_NPS_AGENT_IMPORT_ENABLED", "1")
    def fail():
        raise RuntimeError("fixture-private-password")
    monkeypatch.setattr(nps_agent_import, "connect_agent_import_worker", fail)
    with pytest.raises(RuntimeError, match="^agent_radius_import_failed$"):
        nps_agent_import.run_accounting_import_once()


def test_registered_nps_importer_stays_disabled_before_publication(monkeypatch):
    monkeypatch.delenv("SLI_NPS_AGENT_IMPORT_ENABLED", raising=False)
    monkeypatch.setattr(nps_agent_import, "import_nps_agent_packet",
                        lambda *_a, **_kw: pytest.fail("must not publish"))
    with pytest.raises(consumer.PacketPending, match="^agent_nps_import_disabled$"):
        consumer.dispatch_packet(None, [], packet={}, envelope={"module_id": NPS_MODULE})


def test_legacy_accounting_cursor_uses_tuple_rows_on_the_inbox_connection():
    from psycopg.rows import tuple_row
    calls = []
    conn = SimpleNamespace(cursor=lambda **kwargs: calls.append(kwargs) or "fixture-cursor",
                           transaction=lambda: "fixture-savepoint")
    adapter = nps_agent_import.AccountingConnection(conn)
    assert adapter.cursor() == "fixture-cursor" and adapter.transaction() == "fixture-savepoint"
    assert calls == [{"row_factory": tuple_row}]
