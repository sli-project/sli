"""Local acquisition packets preserve the existing server import inputs."""
from __future__ import annotations

import ast
import importlib
import json
import os
from contextlib import nullcontext
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from server.source_packs.radius.accounting import DATABASE_COMPATIBLE_COLUMNS
from server.source_packs.radius.accounting_runtime_contract import (
    initial_cursor,
    plan_batch,
)
from server.source_packs.radius.accounting_tail import RadiusTailBatch


def _wire(packet):
    return json.loads(json.dumps(packet, ensure_ascii=False))


def _radius_fixture():
    cursor = initial_cursor(source_instance_id="fixture-radius", transport_binding="fixture-tail",
                            file_generation="fixture-generation")
    row = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
    for name, value in {"ComputerName": "fixture-nps", "ServiceName": "IAS",
                        "Record-Date": "10/05/2026", "Record-Time": "12:00:00",
                        "Packet-Type": "4", "Acct-Status-Type": "1",
                        "NAS-Identifier": "fixture-gateway", "Acct-Session-Id": "fixture-session"}.items():
        row[DATABASE_COMPATIBLE_COLUMNS.index(name)] = value
    lines = (",".join(row),)
    tail = RadiusTailBatch(cursor.file_generation, 0, 256, False, lines, 1, 256, 0)
    return cursor, tail


@pytest.mark.parametrize("rotated", [False, True])
def test_radius_round_trip_uses_the_same_plan_evidence_and_commit(monkeypatch, tmp_path, rotated):
    from dataclasses import replace

    from server.sli.sources import radius_plugin_runtime as runtime
    from sli_collect.radius import collect_radius_packet

    cursor, tail = _radius_fixture()
    if rotated:
        tail = replace(tail, file_generation="fixture-next-generation", previous_generation_eof=True)
    state = SimpleNamespace(cursor=cursor, revision=7, cursor_epoch="fixture-epoch", class_cache={})
    observed = datetime(2026, 10, 5, 12, tzinfo=timezone.utc)
    packet = collect_radius_packet(tmp_path, cursor=cursor, source_timezone_id="UTC",
                                  source_utc_offset_minutes=0, observed_at=observed,
                                  read_tail=lambda *a, **kw: tail)
    legacy = plan_batch(cursor=cursor, class_cache={}, file_generation=tail.file_generation,
                        start_offset=tail.start_offset, end_offset=tail.end_offset, lines=tail.records,
                        identity_resolver=lambda dn: None, batch_observed_at_utc=observed,
                        source_timezone_id="UTC", source_utc_offset_minutes=0,
                        previous_generation_eof=rotated)
    captured = {}
    class Cursor:
        def execute(self, sql):
            assert sql == "set local role adlog_radius_accounting_worker"
    connection = SimpleNamespace(transaction=lambda: nullcontext(), cursor=lambda: nullcontext(Cursor()))
    def evidence(store, **kwargs):
        captured["evidence"] = kwargs
        return ("fixture-evidence",)
    def commit(conn, **kwargs):
        captured["commit"] = kwargs
        return SimpleNamespace(cursor_revision=8, evidence_rows=1, observation_rows=0,
                               outbox_rows=0, class_cache_rows=0)
    monkeypatch.setattr(runtime, "publish_radius_batch_evidence", evidence)
    monkeypatch.setattr(runtime, "AcquisitionEvidenceStore", lambda root: object())
    monkeypatch.setattr(runtime, "commit_radius_batch", commit)
    monkeypatch.setattr(runtime, "acquisition_subscription_id", lambda: "fixture-subscription")
    result = runtime.import_acquisition_packet(connection, _wire(packet), state=state)
    assert asdict(captured["commit"]["plan"]) == asdict(legacy)
    assert captured["evidence"]["canonical_records"] == tail.records
    assert captured["commit"]["expected_revision"] == 7
    assert captured["commit"]["cursor_epoch"] == state.cursor_epoch
    assert result["cursor_revision_after"] == 8


def test_event_packet_and_legacy_jsonl_produce_identical_import_rows(tmp_path):
    from sli_collect.eventlog import event_packet
    importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")

    row = {"computer_name": "fixture-dc", "connect_address": "fixture-endpoint",
           "channel": "Security", "record_id": 42, "event_id": 4624,
           "xml": "<Event />", "message": None, "properties": []}
    packet = event_packet(row, generation="fixture-generation", after_record_id=41)
    path = tmp_path / "Security.jsonl"
    path.write_text(json.dumps(packet) + "\n" + json.dumps(row) + "\n", encoding="utf-8")
    assert list(importer.iter_jsonl(path)) == [row, row]


def test_snapshot_file_round_trip_preserves_validated_bundle(monkeypatch, tmp_path):
    from hashlib import sha256

    from server.sli.sources import collection_packet_import as importer
    from sli_collect.snapshots import collect_snapshot_packet

    bundle = {"run_id": "fixture-run", "domain": {"sid": "fixture-domain"},
              "sections": [{"name": "directory_accounts", "status": "partial"}],
              "records": [], "gpo_v2_snapshot": {"fixture": True}}
    raw = json.dumps(bundle).encode("utf-8")
    output = tmp_path / "bundle.json"
    output.write_bytes(raw)
    output.with_name(output.name + ".sha256").write_text(sha256(raw).hexdigest(), encoding="ascii")
    packet = collect_snapshot_packet(output, source="fixture-domain", channel="ad_context_base")
    captured = []
    from server.ad_context import contracts, repository
    monkeypatch.setattr(contracts, "validate_bundle", lambda value: value)
    monkeypatch.setattr(repository, "import_bundle", lambda conn, value: captured.append(value) or {"replayed": 0})
    assert importer.import_snapshot_packet(object(), _wire(packet)) == {"replayed": 0}
    assert captured == [bundle]
    assert packet["continuity"]["status"] == "not_proven"


def test_collection_modules_have_no_database_imports_or_dsn():
    root = Path(__file__).resolve().parents[2]
    assert (root / "sli_collect").is_dir()
    pending = list((root / "sli_collect").glob("*.py"))
    checked = set()
    while pending:
        path = pending.pop()
        if path in checked:
            continue
        checked.add(path)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = [node.module or ""] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names]
                assert all(not (m.startswith("psycopg") or "repository" in m or
                                "postgres" in m or m == "server.sli.core.app_config")
                           for m in modules), path
                for module in modules:
                    if module.startswith(("sli_collect", "server")):
                        relative = Path(*module.split("."))
                        for candidate in (root / relative.with_suffix(".py"), root / relative / "__init__.py"):
                            if candidate.is_file():
                                pending.append(candidate)
                        # Python executes parent packages before the imported leaf.
                        for parent in relative.parents:
                            candidate = root / parent / "__init__.py"
                            if candidate.is_file():
                                pending.append(candidate)
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert "ADLOG_PG_DSN" not in node.value and "SLI_PLUGIN_PG_DSN" not in node.value


def test_invalid_packet_fails_before_server_import(monkeypatch):
    from server.sli.sources.collection_packet_import import event_rows_from_packet
    from sli_collect.eventlog import event_packet

    packet = event_packet({"computer_name": "fixture-dc", "channel": "Security",
                           "record_id": 42, "xml": "<Event />"}, generation=None,
                          after_record_id=None)
    packet["header"]["record_id_range"]["last"] = 41
    with pytest.raises(ValueError, match="collection_packet"):
        event_rows_from_packet(packet)


def test_local_eventlog_read_round_trip_to_server_parameters(monkeypatch, tmp_path):
    from server.sli.sources.collection_packet_import import event_rows_from_packet
    from sli_collect.eventlog import (
        event_packet,
        parse_event_xml,
        query_event_source,
        render_event_source,
    )

    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
           '<System><EventID>6272</EventID><EventRecordID>52</EventRecordID>'
           '<TimeCreated SystemTime="2026-10-05T12:00:00Z" /></System><EventData /></Event>')
    calls = []
    backend = SimpleNamespace(EvtQueryChannelPath=1, EvtQueryForwardDirection=2,
                              EvtRenderEventXml=1,
                              EvtQuery=lambda *args: calls.append(args) or "fixture-query",
                              EvtRender=lambda event, flags: xml)
    assert query_event_source(backend, None, "Security", "*") == "fixture-query"
    row = parse_event_xml(render_event_source(backend, "fixture-event"), source_name="fixture-nps",
                          connect_address="fixture-endpoint", channel="Security")
    packet = event_packet(row, generation="fixture-generation", after_record_id=51)
    restored = event_rows_from_packet(_wire(packet))[0]
    importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
    def parameters(value):
        return importer._event_params(raw_log_file_id=1, server_id=2, domain_id=3,
                                      site_id=4, log_source_id=5, row=value,
                                      event_data=importer.parse_event_data(value["xml"]))
    assert parameters(restored) == parameters(row)
    assert restored["xml"] == xml
    assert calls == [("Security", 3, "*", None)]

    # Exercise the live collector seam as well as the reusable local reader.
    from scripts.collect import collect_windows_events as collector
    monkeypatch.setattr(collector, "win32evtlog", backend)
    monkeypatch.setattr(collector, "open_remote_session", lambda *a, **k: None)
    monkeypatch.setattr(collector, "probe_channel_state", lambda *a: {
        "latest_record_id": 52, "oldest_record_id": 1, "generation_identity": "fixture-generation"})
    batches = iter([["fixture-event"], []])
    monkeypatch.setattr(collector, "next_event_batch", lambda *a: next(batches))
    monkeypatch.setattr(collector, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(collector, "log_performance_stage", lambda *a, **k: None)
    path = tmp_path / "Security.jsonl"
    summary = collector.collect_channel(
        computer_name="fixture-endpoint", source_name="fixture-nps", channel="Security",
        out_file=path, start_time_utc="2026-10-05T11:00:00Z", event_ids=(6272,),
        after_record_id=51, saved_channel_generation_identity="fixture-generation",
        max_events=10, timeout_seconds=60, collect_message=False, progress_every=0,
    )
    assert summary["status"] == "completed" and summary["count"] == 1
    assert summary["collection_packet"]["continuity"] == summary["continuity"]
    assert summary["continuity"]["status"] == "complete"
    assert [parameters(value) for value in importer.iter_jsonl(path)] == [parameters(row)]


def test_empty_accounting_packet_never_advances_cursor_or_opens_transaction(tmp_path):
    from dataclasses import replace

    from server.sli.sources.radius_plugin_runtime import import_acquisition_packet
    from sli_collect.radius import collect_radius_packet

    cursor, tail = _radius_fixture()
    tail = replace(tail, records=(), end_offset=0, bytes_read=0)
    packet = collect_radius_packet(tmp_path, cursor=cursor, source_timezone_id="UTC",
                                  source_utc_offset_minutes=0, read_tail=lambda *a, **k: tail)
    result = import_acquisition_packet(object(), _wire(packet),
                                      state=SimpleNamespace(cursor=cursor, revision=7))
    assert result["status"] == "no_new_complete_records"
    assert result["cursor_revision_before"] == result["cursor_revision_after"] == 7


def test_real_accounting_tail_retains_partial_line_and_bounds(tmp_path):
    from dataclasses import replace

    from server.source_packs.radius.accounting_tail import derive_file_generation
    from sli_collect.radius import collect_radius_packet

    cursor, tail = _radius_fixture()
    raw = (tail.records[0] + "\r\npartial").encode("utf-8")
    path = tmp_path / "IN-fixture.log"
    path.write_bytes(raw)
    with path.open("rb") as stream:
        created_at = os.fstat(stream.fileno()).st_ctime_ns
    generation = derive_file_generation(source_instance_id=cursor.source_instance_id,
                                        file_name=path.name, file_creation_time_ns=created_at)
    cursor = replace(cursor, file_generation=generation)
    packet = collect_radius_packet(tmp_path, cursor=cursor, source_timezone_id="UTC",
                                  source_utc_offset_minutes=0)
    assert [record["payload"] for record in packet["records"]] == list(tail.records)
    assert packet["header"]["cursor"]["end_offset"] == len(raw) - len(b"partial")
    assert packet["context"]["partial_trailing_bytes"] == len(b"partial")
    assert packet["header"]["record_id_range"] == {"first": None, "last": None}


def test_snapshot_digest_mismatch_cannot_reach_import(tmp_path):
    from sli_collect.snapshots import collect_snapshot_packet

    path = tmp_path / "bundle.json"
    path.write_text('{}', encoding="utf-8")
    path.with_name(path.name + ".sha256").write_text("0" * 64, encoding="ascii")
    with pytest.raises(ValueError, match="snapshot_packet_digest_mismatch"):
        collect_snapshot_packet(path, channel="ad_context_base")


def test_schema_envelope_and_record_formats_match_producers():
    from sli_collect.eventlog import event_packet
    from sli_collect.packets import CONTRACT, FORMATS

    schema = json.loads((Path(__file__).resolve().parents[2] /
                         "config/collection_packet_v1.schema.json").read_text(encoding="utf-8"))
    packet = event_packet({"computer_name": "fixture-dc", "channel": "Security",
                           "record_id": 42, "xml": "<Event />"}, generation=None, after_record_id=None)
    assert schema["properties"]["contract"]["const"] == CONTRACT
    assert set(schema["required"]) == set(packet)
    assert set(schema["properties"]["header"]["required"]) == set(packet["header"])
    schema_formats = set(schema["properties"]["records"]["items"]["properties"]["format"]["enum"])
    # Folded file actions are native to the .NET producer and checked by its
    # schema parity test. The legacy Python producer still emits three formats.
    assert FORMATS <= schema_formats
    assert schema_formats - FORMATS == {"file_action"}


@pytest.mark.parametrize("status", ["complete", "partial"])
def test_snapshot_round_trip_runs_the_same_repository_sql_on_fakes(monkeypatch, tmp_path, status):
    from hashlib import sha256

    from server.ad_context import contracts, repository
    from server.sli.sources.collection_packet_import import import_snapshot_packet
    from sli_collect.snapshots import collect_snapshot_packet

    bundle = {"schema_version": contracts.SCHEMA_VERSION, "source_pack_id": contracts.PACK_ID,
              "source_pack_version": "0.8.0", "run_id": "00000000-0000-4000-8000-000000000001",
              "mode": "full", "domain": {"sid": "S-1-5-21-100-200-300", "dns_name": "example.invalid"},
              "scope": {"search_base": "fixture-base"}, "observed_at_utc": "2026-10-05T12:00:00Z",
              "sections": [{"name": "directory_accounts", "status": status, "record_count": 0,
                            "duration_ms": 0, "error_code": None}], "records": []}
    raw = json.dumps(bundle).encode("utf-8")
    path = tmp_path / "bundle.json"
    path.write_bytes(raw)
    path.with_name(path.name + ".sha256").write_text(sha256(raw).hexdigest(), encoding="ascii")
    monkeypatch.setattr(repository, "_resolve_domain", lambda cur, domain: 1)
    monkeypatch.setattr(repository, "_start_run", lambda cur, domain_id, value: False)
    monkeypatch.setattr(repository, "_preload_existing_entity_ids", lambda *a: {})
    class Cursor:
        rowcount = 0
        def __init__(self):
            self.calls = []
        def execute(self, sql, params):
            self.calls.append((sql, params))
    legacy_cursor, packet_cursor = Cursor(), Cursor()
    def connection(cursor):
        return SimpleNamespace(cursor=lambda: nullcontext(cursor))
    old = repository.import_bundle(connection(legacy_cursor), contracts.load_bundle(path))
    packet = collect_snapshot_packet(path, channel="ad_context_base")
    new = import_snapshot_packet(connection(packet_cursor), _wire(packet))
    assert new == old
    assert packet_cursor.calls == legacy_cursor.calls
    assert packet["continuity"]["status"] == ("complete" if status == "complete" else "not_proven")


def test_legacy_snapshot_worker_imports_through_packet(monkeypatch):
    from scripts.runtime import ad_context_snapshot_worker as worker

    bundle = {"run_id": "fixture-run", "domain": {"sid": "fixture-domain"},
              "sections": [{"name": "directory_accounts", "status": "complete"}], "records": []}
    captured = []
    connection = object()
    monkeypatch.setattr(worker, "_import_connect", lambda: nullcontext(connection))
    def consume(conn, packet):
        assert conn is connection
        captured.append(packet["records"][0]["payload"])
        return {"replayed": 0}
    monkeypatch.setattr(worker, "import_snapshot_packet", consume)
    assert worker._import_cycle([bundle]) == [{"replayed": 0}]
    assert captured == [bundle]
