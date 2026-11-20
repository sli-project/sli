"""GPO plugin publication, signed transport and legacy-equivalent storage."""
from __future__ import annotations

import json
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.ad_context.repository import _store_gpo_v2_snapshot
from server.ad_context.contracts import validate_bundle
from server.sli.agents import snapshot_consumer
from server.sli.agents.import_authorization import PacketPending
from server.sli.plugins.gpo import snapshot_import as importer
from server.sli.plugins.gpo import effective_access as access
from server.sli.reports.gpo_v2_reporting import build_gpo_v2_payload
from server.sli.sources.gpo_v2_source import canonical_snapshot, redact_gpo_snapshot
from sli_agent.gpo_snapshot import normalize_capture
from sli_agent.snapshot_stream import SnapshotStream
from test_agent_gpo_snapshot import SID, capture, config
from test_agent_snapshot_stream import Ledger, NOW, packets
from test_gpo_effective_access import graph


class Connection:
    def __init__(self, cycle=None, rows=(), state=None):
        self.cycle, self.rows = cycle, list(rows)
        self.state = state or {"transport_state": "pending", "publication_state": "pending"}
        self.effects, self.sql = [], []

    def cursor(self):
        return nullcontext(Cursor(self))

    @contextmanager
    def transaction(self):
        previous = deepcopy(self.effects)
        try:
            yield
        except Exception:
            self.effects = previous
            raise


class Cursor:
    def __init__(self, conn):
        self.conn, self.rows = conn, []

    def execute(self, sql, params=()):
        self.conn.sql.append((sql, params))
        if "from sli_agent_snapshot_chunks" in sql:
            self.rows = self.conn.rows
        elif "select transport_state" in sql:
            self.rows = [self.conn.state]
        elif "from sli_agent_snapshot_cycles" in sql:
            self.rows = [self.conn.cycle] if self.conn.cycle else []
        elif "from domains" in sql:
            self.rows = [{"id": 7}]
        elif "from gpo_report_v2_source_snapshots" in sql:
            self.rows = [{"source_run_id": self.conn.run_id, "payload_sha256": self.conn.sha}]
        elif sql.lstrip().startswith("update sli_agent_snapshot_cycles"):
            self.conn.effects.append(("publication" if "publication_state" in sql else "transport", params))
            self.rows = []
        elif "pg_advisory_xact_lock" in sql:
            self.rows = []
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


def signed(tmp_path, cfg, families):
    stream = SnapshotStream(tmp_path, "sli.gpo-snapshot")
    stream.freeze(stream.begin(cfg, now=NOW), families)
    key = ec.generate_private_key(ec.SECP256R1())
    ledger = Ledger(cfg, module="sli.gpo-snapshot")
    for packet in packets(stream, key):
        assert ledger.receive(packet, key)["status"] == "committed"
    cycle = next(iter(ledger.cycles.values()))
    cycle["domain_sid"] = SID
    return cycle, ledger.rows, ledger.identity


def fake_import(monkeypatch, conn, *, fail=False):
    def imported(connection, bundle):
        assert connection is conn
        assert validate_bundle(bundle) == bundle
        conn.run_id = bundle["run_id"]
        conn.sha = canonical_snapshot(redact_gpo_snapshot(bundle["gpo_v2_snapshot"]))[1]
        conn.effects.append(("import", deepcopy(bundle)))
        if fail:
            raise ValueError("synthetic-private-diagnostic")
    monkeypatch.setattr(importer, "import_bundle", imported)


@pytest.mark.parametrize("postgres_slot", [None, timezone.utc, timezone(timedelta(hours=7))])
@pytest.mark.parametrize("schedule", [None, {"timezone": "UTC", "hours": list(range(24))},
    {"timezone": "Asia/Kathmandu", "hours": [0, 8, 23]}])
def test_complete_signed_cycle_imports_governance_and_gpo_on_trusted_connection(tmp_path, monkeypatch, postgres_slot, schedule):
    cfg = config(max_objects=1, **({"schedule": schedule} if schedule else {}))
    families = normalize_capture(capture(), cfg)
    cycle, rows, identity = signed(tmp_path, cfg, families)
    if postgres_slot is not None:
        cycle["slot_start_utc"] = datetime.fromisoformat(cycle["slot_start_utc"]).astimezone(postgres_slot)
    conn, publication = Connection(cycle, rows), Connection(cycle, rows)
    fake_import(monkeypatch, publication)
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    plugins = []
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda cur, plugin: plugins.append(plugin))
    result = snapshot_consumer.consume_snapshot_cycles(conn, publication_connection_factory=lambda: nullcontext(publication))
    assert result == {"completed": 1, "scanned": 1, "pending_reasons": {}}
    assert plugins == ["sli.gpo"] and not conn.effects
    assert [kind for kind, _ in publication.effects] == ["transport", "import", "publication"]
    bundle = publication.effects[1][1]
    assert bundle["gpo_v2_snapshot"]["acl"] == families["gpo_v2"][0]["acl"]
    assert "gpo_source_run_id=%s" in publication.sql[-1][0]
    assert not any("latest" in sql.lower() for sql, _ in publication.sql)


@pytest.mark.parametrize("failure", ["plugin", "agent", "chunk", "overflow", "import"])
def test_pending_or_failed_cycle_retains_previous_publication(tmp_path, monkeypatch, failure):
    cfg, raw = config(), capture()
    if failure == "overflow":
        raw["overflow"] = True
    families = normalize_capture(raw, cfg)
    cycle, rows, identity = signed(tmp_path, cfg, families)
    conn = Connection(cycle, rows[:-1] if failure == "chunk" else rows)
    conn.effects = [("previous", "retained")]
    fake_import(monkeypatch, conn, fail=failure == "import")
    def authorize(*args, **kwargs):
        if failure == "agent":
            raise PacketPending("agent_disabled")
        return identity
    def plugin(*args):
        if failure == "plugin":
            raise PacketPending("agent_plugin_disabled")
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", authorize)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", plugin)
    result = snapshot_consumer.consume_snapshot_cycles(conn)
    assert not any(kind in {"import", "publication"} for kind, _ in conn.effects)
    assert conn.effects[0] == ("previous", "retained")
    assert result["completed"] == int(failure in {"overflow", "import"})
    if failure != "chunk":
        assert result["pending_reasons"]
    assert "synthetic-private-diagnostic" not in json.dumps(result)


def test_complete_transport_source_failures_keep_sectional_states(tmp_path, monkeypatch):
    cfg, raw = config(), capture()
    raw["snapshot"]["collection_status"] = "partial"
    raw["snapshot"]["source_states"]["sysvol_gpt"]["status"] = "access_denied"
    families = normalize_capture(raw, cfg)
    cycle, rows, identity = signed(tmp_path, cfg, families)
    conn = Connection(cycle, rows)
    fake_import(monkeypatch, conn)
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda *a: None)
    assert snapshot_consumer.consume_snapshot_cycles(conn)["pending_reasons"] == {}
    bundle = next(value for kind, value in conn.effects if kind == "import")
    assert bundle["mode"] == "targeted"
    assert bundle["gpo_v2_snapshot"]["source_states"]["sysvol_gpt"]["status"] == "access_denied"


@pytest.mark.parametrize("change", ["domain", "population", "time", "rights", "families", "bytes"])
def test_prepare_validates_whole_cycle_before_import(change):
    cfg = config()
    families = {name: data for name, (data, _) in normalize_capture(capture(), cfg).items()}
    cycle = {"domain_sid": SID, "policy": cfg}
    if change == "domain":
        families["gpo_v2"]["domain"]["dns_name"] = "other.invalid"
    elif change == "population":
        families["ad_gpo_governance"]["records"][0]["attributes"]["display_name"] = "Other policy"
    elif change == "time":
        families["gpo_v2"]["observed_at"] = "2026-10-01T00:00:00Z"
    elif change == "rights":
        families["ad_gpo_governance"]["records"][0]["attributes"]["gpo_security_filtering_effective_evaluated"] = True
    elif change == "families":
        families.pop("gpo_v2")
    else:
        cfg["max_bytes"] = 1
    conn = Connection()
    with pytest.raises(ValueError):
        importer.import_gpo_cycle(conn, cycle, families)
    assert conn.effects == [] and conn.sql == []


def equivalence_rows(legacy, agent):
    """PR 4 can extend exact report comparison to isolated DB schemas/exports."""
    def report(snapshot):
        return build_gpo_v2_payload({"current": snapshot, "previous": None})
    assert report(legacy) == report(agent)
    for mode in ("filtering", "delegation"):
        assert access.analyze_access(legacy, graph(), mode=mode) == access.analyze_access(agent, graph(), mode=mode)


def test_synthetic_agent_uses_same_legacy_storage_and_report_projector(monkeypatch):
    cfg, raw = config(), capture()
    raw["snapshot"]["acl"][0].update(trustee_sid=SID + "-2102", access_mask=0x20010 | 0x100 | 0x20,
        object_type=access.EMPTY_GUID)
    families = {name: data for name, (data, _) in normalize_capture(raw, cfg).items()}
    bundle = importer.prepare_gpo_cycle({"domain_sid": SID, "policy": cfg}, families)
    class Storage:
        def execute(self, sql, params):
            assert "insert into gpo_report_v2_source_snapshots" in sql
            self.payload, self.sha = json.loads(params[-2]), params[-1]
    legacy, agent = Storage(), Storage()
    # IDs/time are held fixed; collection provenance and masking receipts vary.
    old = deepcopy(raw["snapshot"])
    old["privacy"] = families["gpo_v2"]["privacy"]
    _store_gpo_v2_snapshot(legacy, domain_id=7, run_id=bundle["run_id"], snapshot=old)
    _store_gpo_v2_snapshot(agent, domain_id=7, run_id=bundle["run_id"], snapshot=bundle["gpo_v2_snapshot"])
    assert legacy.payload == agent.payload and legacy.sha == agent.sha
    equivalence_rows(legacy.payload, agent.payload)
    filtering = access.analyze_access(agent.payload, graph(), mode="filtering")
    assert any(row["outcome"] == "allowed" and len(row["path_keys"]) == 3 for row in filtering["items"])


def test_publication_failure_retries_after_transport_completed_without_reimporting_ad(tmp_path, monkeypatch):
    cfg = config()
    families = normalize_capture(capture(), cfg)
    cycle, rows, identity = signed(tmp_path, cfg, families)
    conn = Connection(cycle, rows, {"transport_state": "complete", "publication_state": "pending"})
    fake_import(monkeypatch, conn)
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda *a: None)
    monkeypatch.setattr(snapshot_consumer, "import_ad_cycle", lambda *a: pytest.fail("GPO cannot import AD"))
    result = snapshot_consumer.consume_snapshot_cycles(conn)
    assert result == {"completed": 0, "scanned": 1, "pending_reasons": {}}
    assert [kind for kind, _ in conn.effects] == ["import", "publication"]
    assert "publication_state='pending'" in conn.sql[0][0]


def test_dotnet_timestamp_precision_is_compatible_with_existing_bundle_contract():
    cfg, raw = config(), capture()
    stamp = "2026-10-08T12:00:00.1234567Z"
    raw["snapshot"]["observed_at"] = stamp
    raw["records"][0]["observed_at_utc"] = stamp
    families = {name: data for name, (data, _) in normalize_capture(raw, cfg).items()}
    bundle = importer.prepare_gpo_cycle({"domain_sid": SID, "policy": cfg}, families)
    assert bundle["observed_at_utc"] == "2026-10-08T12:00:00.123456Z"
    assert bundle["gpo_v2_snapshot"]["observed_at"] == stamp


def test_stale_gpo_cycle_keeps_current_publication_and_safe_reason(tmp_path, monkeypatch):
    from server.ad_context.repository import AdContextOutOfOrderError, _start_run

    cfg = config()
    cycle, rows, identity = signed(tmp_path, cfg, normalize_capture(capture(), cfg))
    conn = Connection(cycle, rows, {"transport_state": "complete", "publication_state": "pending"})
    conn.effects = [("previous", "retained")]

    class WatermarkCursor:
        def execute(self, sql, params):
            assert "insert" not in sql

        def fetchone(self):
            return None

        def fetchall(self):
            return [{"section_name": "gpo_governance", "latest": NOW + timedelta(days=1)}]

    def imported(connection, bundle):
        connection.effects.append(("partial_import", "rolled_back"))
        with pytest.raises(AdContextOutOfOrderError) as caught:
            _start_run(WatermarkCursor(), 7, bundle)
        raise caught.value

    monkeypatch.setattr(importer, "import_bundle", imported)
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda *a: None)
    result = snapshot_consumer.consume_snapshot_cycles(conn)
    assert result == {"completed": 0, "scanned": 1, "pending_reasons": {}}
    assert conn.effects[0] == ("previous", "retained")
    assert [kind for kind, _ in conn.effects] == ["previous", "publication"]
    sql, params = conn.sql[-1]
    assert "publication_state='superseded'" in sql
    assert params == ("agent_gpo_snapshot_superseded", cycle["cycle_id"])
    assert "out-of-order" not in json.dumps(result)


def test_superseded_gpo_cycle_is_not_imported_again(tmp_path, monkeypatch):
    cfg = config()
    cycle, rows, identity = signed(tmp_path, cfg, normalize_capture(capture(), cfg))
    conn = Connection(cycle, rows, {"transport_state": "complete", "publication_state": "superseded"})
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda *a: None)
    monkeypatch.setattr(importer, "import_bundle", lambda *a: pytest.fail("terminal cycle must not import"))
    assert snapshot_consumer.consume_snapshot_cycles(conn) == {"completed": 0, "scanned": 1, "pending_reasons": {}}
    assert conn.effects == []


@pytest.mark.parametrize("family,other_family", [
    ("gpo_v2", "ad_gpo_governance"),
    ("ad_gpo_governance", "gpo_v2"),
])
@pytest.mark.parametrize("max_objects,max_bytes,expected", [
    (10000, 2000, False),
    (9999, 2000, True),
    (10000, 1999, True),
])
def test_ingress_counts_two_gpo_representations_once_but_keeps_combined_byte_limit(
    family, other_family, max_objects, max_bytes, expected,
):
    from server.sli.agents.snapshot_ingest import conflict
    cfg = config(max_objects=max_objects, max_bytes=max_bytes)
    payload = {"cycle_id": "00000000-0000-4000-8000-000000000099", "family": family,
               "slot_start_utc": NOW.isoformat(), "chunk_index": 0,
               "total_objects": 10000, "total_bytes": 1000}
    class Cursor:
        def execute(self, sql, params=()):
            self.rows = [{"family": other_family, "objects": 10000, "bytes": 1000}] if "select distinct" in sql else []
        def fetchone(self):
            return self.rows[0] if self.rows else None
        def fetchall(self):
            return self.rows
    assert conflict(Cursor(), {"module_id": "sli.gpo-snapshot"}, payload, cfg) is expected
