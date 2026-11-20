"""PG -> immutable history -> report/detail, with synthetic stores only."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from server.sli.plugins.workstations import importer, reports, retention
from server.sli.reporting.v2.definition import QueryContext
from server.sli.storage import purge_audit
from server.sli.storage import workstation_history as history

NOW = datetime(2026, 10, 9, tzinfo=timezone.utc)


def observation(index=1, *, age=91, family="processes", agent="fixture-agent"):
    xml = "<Event><fixture/></Event>"
    stamp = NOW - timedelta(days=age)
    body = {"family": family, "semantic_type": "fixture.observed", "facts": {
        "process_image": "fixture.exe", "storage_evidence": family == "usb"},
        "quality": {}, "source_sha256": hashlib.sha256(xml.encode()).hexdigest()}
    return {"id": f"{index:064x}", "agent_key": agent, "entity_id": 17,
            "ad_computer_id": None, "family": family, "event_id": 4688,
            "observed_at": stamp, "observation": body,
            "observation_sha256": importer.digest(body), "source_xml": xml}


class PG:
    def __init__(self, rows, days=None, holds=()):
        self.rows = copy.deepcopy(rows)
        self.days, self.holds = days, set(holds)
        self.calls = []
        self.selected = []
        self.one = None
        self.rowcount = 0

    def cursor(self):
        return nullcontext(self)

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        self.calls.append((sql, params))
        if "enrolled.host_name as enrolled_name" in sql:
            self.selected = []
        elif sql.startswith("select wanted.agent_key, recent.source_xml"):
            assert "order by o.observed_at desc,o.id desc limit 1" in sql
            self.selected = []
        elif sql.startswith("select value"):
            self.one = {"value": str(self.days)} if self.days is not None else None
        elif sql.startswith("select observation.*"):
            self.selected = [{**row, "purge_row_bytes": 256} for row in self.rows
                             if row["observed_at"] < params[0] and row["family"] in {"processes", "usb"}
                             and row["id"] not in self.holds][:params[1]]
            assert "not exists" in sql and "observation_holds" in sql
        elif sql.startswith("delete"):
            assert params[0] not in self.holds
            before = len(self.rows)
            self.rows = [row for row in self.rows if row["id"] != params[0]]
            self.rowcount = before - len(self.rows)
        elif "workstation_delete_readback" in sql:
            self.one = next((row for row in self.rows if row["id"] == params[0]), None)
        elif "from sli_plugin_workstations.observations" in sql:
            keys, family, start, end, cursor = params[:5]
            limit = params[-1]
            exact_id = params[5] if len(params) > 6 else None
            rows = [row for row in self.rows if row["agent_key"] in keys and row["family"] == family
                    and start <= row["observed_at"] < end and row["id"] > cursor
                    and (family != "usb" or row["observation"]["facts"].get("storage_evidence") is True)
                    and (exact_id is None or row["id"] == exact_id)]
            self.selected = [history.report_row(row, evidence=exact_id is not None)
                             for row in sorted(rows, key=lambda row: row["id"])[:limit]]

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.selected


class CH:
    def __init__(self):
        self.rows = {}
        self.calls = []
        self.inserts = 0
        self.corrupt = False
        self.unavailable = False
        self.durable = True
        self.lost_ack = False

    def insert(self, port, table, rows, **kwargs):
        if self.unavailable:
            raise OSError("fixture unavailable")
        self.inserts += len(rows)
        for row in rows:
            self.rows.setdefault(row["id"], copy.deepcopy(row))
        return len(rows), True

    def read(self, port, sql, *, query_params=None):
        if self.unavailable:
            raise OSError("fixture unavailable")
        self.calls.append((sql, query_params))
        if "FROM system.tables" in sql:
            return [{"engine": "ReplacingMergeTree", "sorting_key": "id", "partition_key": "",
                     "create_table_query": "SETTINGS fsync_after_insert = 1, fsync_part_directory = 1" if self.durable else ""}]
        rows = list(self.rows.values())
        p = query_params
        if "keys" in p:
            rows = [row for row in rows if row["agent_key"] in json.loads(base64.b64decode(p["keys"]))
                    and row["family"] == p["family"] and p["start"] <= row["observed_at"] < p["end"]
                    and row["id"] > p["cursor"]
                    and (p["family"] != "usb" or json.loads(row["payload_json"])["observation"]["facts"].get("storage_evidence") is True)]
        if "id" in p:
            rows = [row for row in rows if row["id"] == p["id"]]
        rows = copy.deepcopy(sorted(rows, key=lambda row: row["id"])[:int(p.get("limit", "2"))])
        if self.corrupt and rows:
            rows[0]["payload_json"] = rows[0]["payload_json"].replace("fixture.exe", "changed.exe")
        return rows

    def query(self, port, sql, *, params=None, **kwargs):
        assert params == {"async_insert": "0", "wait_for_async_insert": "1"}
        result = self.insert(port, history.TABLE, [json.loads(sql.split("\n", 1)[1])])
        if self.lost_ack:
            self.lost_ack = False
            raise OSError("fixture acknowledgement lost")
        return result


@pytest.fixture
def stores(monkeypatch, tmp_path):
    monkeypatch.setattr(purge_audit, "AUDIT_DIR", tmp_path / "purge")
    monkeypatch.delenv("SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS", raising=False)
    monkeypatch.setattr(history.ch, "configured_read_port", lambda: None)
    ch = CH()
    monkeypatch.setattr(history.ch, "_rows", ch.read)
    monkeypatch.setattr(history.ch, "_http_query", ch.query)
    return ch, history.ClickHouseHistoryAdapter(8123)


def context(adapter, family="processes", **changes):
    key = reports.REPORTS[family][0]
    grant = {"report_key": key, "allowed": True, "allowed_actions": ["view"], "grants": [{
        "allowed_actions": ["view"], "field_categories": list(reports.FIELDS), "scope": {"kind": "all"}}]}
    ctx = QueryContext(access={"reports": [grant]}, action="view", domain_ids=None, cursor=None,
        limit=2, timezone="UTC", params={"period": {"from_utc": (NOW - timedelta(days=365)).isoformat(),
        "to_utc": NOW.isoformat()}}, runtime={"workstation_history_adapter": adapter,
        "workstation_scope_adapter": SimpleNamespace(agent_keys=lambda *args: ("fixture-agent",))})
    return replace(ctx, **changes)


@pytest.mark.parametrize("family", ["processes", "usb"])
@pytest.mark.parametrize("days,moved", [(None, 1), (180, 0), (30, 3)])
def test_boundary_setting_history_and_exact_detail(stores, monkeypatch, family, days, moved):
    ch, adapter = stores
    pg = PG([observation(i, age=age, family=family) for i, age in enumerate((91, 90, 89), 1)], days=days)
    monkeypatch.setattr(reports, "connect", lambda: nullcontext(pg))
    outcome = retention.retain_batch(pg, history=adapter, now=NOW)
    assert outcome["moved"] == moved and len(pg.rows) == 3 - moved
    assert ch.inserts == moved
    receipt = purge_audit.last_purge_runs()["runs"][0]
    assert receipt["status"] == "success" and receipt["tables"]["sli_plugin_workstations.observations"]["deleted_count"] == moved
    assert receipt["retention_days"] == (days or 90)
    assert receipt["cutoff_utc"] == (NOW - timedelta(days=days or 90)).isoformat()
    definition = reports.make_report(family)
    page = definition.query(context(adapter, family))
    assert [row["id"] for row in page["items"]] == [f"{i:064x}" for i in (1, 2)]
    assert page["has_more"] and page["coverage"]["history"] == "loaded"
    assert definition.query(context(adapter, family, cursor=page["next_cursor"]))["items"][0]["id"] == f"{3:064x}"
    detail = definition.detail.query(context(adapter, family), f"{1:064x}")
    assert detail["items"][0]["source_xml"] == observation()["source_xml"]
    assert detail["items"][0]["observation_sha256"] == observation(family=family)["observation_sha256"]


def transport(row):
    return json.loads(json.dumps(row, default=lambda value: value.isoformat()))


def registered_handler(adapter):
    registrations = []
    retention.register_jobs(SimpleNamespace(register=lambda **kwargs: registrations.append(kwargs)),
                            history=adapter)
    return registrations[0]["handlers"][retention.HANDLER_ID]


@pytest.mark.parametrize("family", ["processes", "usb"])
def test_registered_retention_and_configured_report_read_evidence_older_than_a_year(stores, monkeypatch, family):
    ch, adapter = stores
    handler = registered_handler(adapter)
    assert ch.calls == [] and ch.inserts == 0
    old = observation(1, age=366, family=family)
    recent = observation(2, age=100, family=family)
    pg = PG([old, recent], days=180)
    outcome = handler(pg, now=NOW)
    assert outcome["moved"] == 1 and outcome["retention_days"] == 180
    assert pg.rows == [recent] and ch.inserts == 1
    assert adapter.preserve(transport(old)) == importer.digest(transport(old))
    assert ch.inserts == 1
    monkeypatch.setattr(reports, "connect", lambda: nullcontext(pg))
    monkeypatch.setattr(history.ch, "configured_read_port", lambda: 8123)
    ctx = context(adapter, family)
    ctx = replace(ctx, params={"period": {
        "from_utc": (NOW - timedelta(days=730)).isoformat(), "to_utc": NOW.isoformat()}},
        runtime={"workstation_scope_adapter": ctx.runtime["workstation_scope_adapter"]})
    definition = reports.make_report(family)
    page = definition.query(ctx)
    assert page["coverage"]["history"] == "loaded"
    assert [row["id"] for row in page["items"]] == [old["id"], recent["id"]]
    detail = definition.detail.query(ctx, old["id"])
    assert detail["items"][0]["source_xml"] == old["source_xml"]
    assert detail["items"][0]["source_sha256"] == old["observation"]["source_sha256"]


@pytest.mark.parametrize("failure", ["corrupt", "unavailable", "durable"])
def test_registered_retention_failure_keeps_postgres_evidence(stores, failure):
    ch, adapter = stores
    setattr(ch, failure, failure != "durable")
    pg = PG([observation(age=366)], days=180)
    with pytest.raises((ValueError, RuntimeError)):
        registered_handler(adapter)(pg, now=NOW)
    assert len(pg.rows) == 1
    assert not any(sql.startswith("delete") for sql, _ in pg.calls)


def test_registered_retention_without_adapter_stays_blocked(stores, monkeypatch):
    ch, _ = stores
    monkeypatch.setattr(history.ch, "configured_read_port", lambda: 8123)
    pg = PG([observation(age=366)])
    assert registered_handler(None)(pg, now=NOW) == {
        "status": "blocked", "reason": "history_adapter_unavailable", "moved": 0}
    assert not pg.calls and not ch.calls and ch.inserts == 0


def test_rollback_retry_is_idempotent_and_duplicate_hot_row_pages_once(stores, monkeypatch):
    ch, adapter = stores
    pg = PG([observation()])
    saved = copy.deepcopy(pg.rows)
    retention.retain_batch(pg, history=adapter, now=NOW)
    pg.rows = saved  # Simulate a caller-owned PG rollback after CH acknowledgement.
    monkeypatch.setattr(reports, "connect", lambda: nullcontext(pg))
    page = reports.make_report("processes").query(context(adapter))
    assert len(page["items"]) == 1 and not page["has_more"]
    retention.retain_batch(pg, history=adapter, now=NOW)
    assert pg.rows == [] and len(ch.rows) == 1 and ch.inserts == 1


@pytest.mark.parametrize("failure", ["corrupt", "unavailable"])
def test_failed_readback_keeps_pg_and_audit_contains_no_evidence(stores, failure):
    ch, adapter = stores
    pg = PG([observation()])
    adapter.preserve(transport(pg.rows[0]))
    setattr(ch, failure, True)
    with pytest.raises((ValueError, RuntimeError, OSError)):
        retention.retain_batch(pg, history=adapter, now=NOW)
    assert len(pg.rows) == 1 and not any(sql.startswith("delete") for sql, _ in pg.calls)
    receipt = purge_audit.last_purge_runs()["runs"][0]
    assert receipt["status"] == "blocked" and "fixture.exe" not in json.dumps(receipt)
    assert receipt["reason"] in {"workstation_history_receipt_mismatch", "workstation_history_unavailable"}


def test_first_insert_readback_mismatch_never_deletes_pg(stores):
    ch, adapter = stores
    ch.corrupt = True
    pg = PG([observation()])
    with pytest.raises(ValueError, match="history_receipt_mismatch"):
        retention.retain_batch(pg, history=adapter, now=NOW)
    assert ch.inserts == 1 and len(pg.rows) == 1
    assert not any(sql.startswith("delete") for sql, _ in pg.calls)


def test_lost_insert_ack_is_retried_without_overwriting_or_losing_pg(stores):
    ch, adapter = stores
    ch.lost_ack = True
    pg = PG([observation()])
    with pytest.raises(RuntimeError, match="history_unavailable"):
        retention.retain_batch(pg, history=adapter, now=NOW)
    assert ch.inserts == 1 and len(pg.rows) == 1
    assert retention.retain_batch(pg, history=adapter, now=NOW)["moved"] == 1
    assert not pg.rows and ch.inserts == 1


def test_holds_and_other_families_remain_in_pg(stores):
    ch, adapter = stores
    rows = [observation(1), observation(2, family="usb"), observation(3, family="logons"),
            observation(4, family="protection")]
    pg = PG(rows, holds=[rows[0]["id"], rows[1]["id"]])
    assert retention.retain_batch(pg, history=adapter, now=NOW)["moved"] == 0
    assert pg.rows == rows and ch.inserts == 0


@pytest.mark.parametrize("field,value", [("agent_key", "fixture-other"), ("family", "usb"),
                                         ("entity_id", 99), ("payload_sha256", "0" * 64)])
def test_exact_receipt_validates_metadata_and_entire_payload(stores, field, value):
    ch, adapter = stores
    row = transport(observation())
    adapter.preserve(row)
    ch.rows[row["id"]][field] = value
    with pytest.raises(ValueError, match="history_receipt_mismatch"):
        adapter.preserve(row)


def test_existing_different_payload_is_never_overwritten(stores):
    ch, adapter = stores
    row = transport(observation())
    adapter.preserve(row)
    changed = copy.deepcopy(row)
    changed["source_xml"] = "<Changed/>"
    with pytest.raises(ValueError):
        adapter.preserve(changed)
    assert ch.inserts == 1


def test_history_failure_is_explicit_and_pg_is_still_readable(stores, monkeypatch):
    ch, adapter = stores
    pg = PG([observation()])
    monkeypatch.setattr(reports, "connect", lambda: nullcontext(pg))
    ch.unavailable = True
    page = reports.make_report("processes").query(context(adapter))
    assert len(page["items"]) == 1 and page["coverage"]["history"] == "unavailable"
    assert any(item["code"] == "history_unavailable" for item in page["limitations"])


def test_history_and_detail_enforce_scope_family_period_and_usb_evidence(stores, monkeypatch):
    ch, adapter = stores
    for row in (observation(), observation(2, agent="fixture-other"), observation(3, family="usb"),
                observation(4, age=400)):
        adapter.preserve(transport(row))
    pg = PG([])
    monkeypatch.setattr(reports, "connect", lambda: nullcontext(pg))
    definition = reports.make_report("processes")
    assert len(definition.query(context(adapter))["items"]) == 1
    for index in (2, 3, 4):
        with pytest.raises(LookupError):
            definition.detail.query(context(adapter), f"{index:064x}")
    count = len(ch.calls)
    with pytest.raises(ValueError, match="id_invalid"):
        definition.detail.query(context(adapter), "fixture-invalid")
    assert len(ch.calls) == count
    assert any("FINAL" in sql for sql, _ in ch.calls)
    assert any("JSONExtract(base64Decode({keys:String}),'Array(String)')" in sql and "LIMIT {limit:UInt16}" in sql for sql, _ in ch.calls)
    usb = observation(5, family="usb")
    usb["observation"]["facts"]["storage_evidence"] = False
    usb["observation_sha256"] = importer.digest(usb["observation"])
    adapter.preserve(transport(usb))
    assert len(reports.make_report("usb").query(context(adapter, "usb"))["items"]) == 1


def test_conflicting_hot_and_history_copies_fail_closed(stores, monkeypatch):
    _ch, adapter = stores
    row = observation()
    adapter.preserve(transport(row))
    row["observation"]["facts"]["process_image"] = "changed.exe"
    row["observation_sha256"] = importer.digest(row["observation"])
    monkeypatch.setattr(reports, "connect", lambda: nullcontext(PG([row])))
    page = reports.make_report("processes").query(context(adapter))
    assert page["state"] == "error" and page["items"] == []


@pytest.mark.parametrize("family", ["processes", "usb"])
@pytest.mark.parametrize("agent", ["fixture-agent", "fixture'agent", 'fixture"agent',
                                   r"fixture\agent", "fixture-агент", "fixture');SELECT 1;--"])
def test_history_scope_json_uses_string_parameter_for_pages_and_evidence(stores, monkeypatch, family, agent):
    ch, adapter = stores
    row = transport(observation(1, age=366, family=family, agent=agent))
    other = transport(observation(2, age=366, family=family, agent="fixture-outside-scope"))
    adapter.preserve(row)
    adapter.preserve(other)
    original = ch.read
    scoped_calls = []

    def read(port, sql, *, query_params=None):
        # Model the HTTP parameter boundary the permissive store fake omits:
        # ClickHouse rejects JSON ["..."] as an Array(String) parameter.
        if "keys" in query_params:
            if "{keys:Array(String)}" in sql:
                raise RuntimeError("ClickHouse HTTP 400:request_failed")
            assert "JSONExtract(base64Decode({keys:String}),'Array(String)')" in sql
            assert json.loads(base64.b64decode(query_params["keys"], validate=True)) == [agent]
            assert agent not in sql and other["agent_key"] not in sql
            scoped_calls.append(query_params)
        return original(port, sql, query_params=query_params)

    monkeypatch.setattr(history.ch, "_rows", read)
    params = {"keys": (agent,), "family": family, "start": NOW - timedelta(days=730),
              "end": NOW, "cursor": "", "limit": 2}
    assert adapter.read(**params) == [history.report_row(row)]
    assert adapter.read(**params, observation_id=row["id"]) == [history.report_row(row, evidence=True)]
    assert len(scoped_calls) == 2 and scoped_calls[1]["id"] == row["id"]


def test_retention_requires_explicit_adapter_even_with_history_configured(stores, monkeypatch):
    monkeypatch.setattr(history.ch, "configured_read_port", lambda: 8123)
    pg = PG([observation()])
    assert retention.retain_batch(pg, now=NOW)["status"] == "blocked"
    assert not pg.calls


def test_unverified_durability_blocks_insert_and_delete(stores):
    ch, adapter = stores
    ch.durable = False
    pg = PG([observation()])
    with pytest.raises(ValueError, match="durability_unverified"):
        retention.retain_batch(pg, history=adapter, now=NOW)
    assert ch.inserts == 0 and len(pg.rows) == 1
    assert purge_audit.last_purge_runs()["runs"][0]["reason"] == "workstation_history_durability_unverified"


def test_clickhouse_quoted_uint64_readback_is_exact(stores):
    ch, adapter = stores
    row = transport(observation())
    adapter.preserve(row)
    ch.rows[row["id"]]["entity_id"] = str(row["entity_id"])
    assert adapter.preserve(row) == importer.digest(row)


def test_pg_timezone_change_after_rollback_keeps_retry_idempotent(stores):
    ch, adapter = stores
    pg = PG([observation()])
    retention.retain_batch(pg, history=adapter, now=NOW)
    row = observation()
    row["observed_at"] = row["observed_at"].astimezone(timezone(timedelta(hours=7)))
    pg.rows = [row]
    assert retention.retain_batch(pg, history=adapter, now=NOW)["moved"] == 1
    assert ch.inserts == 1


def test_setting_changes_affect_the_next_batch_without_losing_history(stores):
    ch, adapter = stores
    pg = PG([observation(1, age=100), observation(2, age=60)], days=180)
    assert retention.retain_batch(pg, history=adapter, now=NOW)["moved"] == 0
    pg.days = 90
    assert retention.retain_batch(pg, history=adapter, now=NOW)["moved"] == 1
    pg.days = 30
    assert retention.retain_batch(pg, history=adapter, now=NOW)["moved"] == 1
    assert not pg.rows and len(ch.rows) == 2


def test_history_schema_provisioning_is_explicit_and_never_deletes_pg(monkeypatch):
    calls = []
    monkeypatch.setattr(history.ch, "_http_query", lambda port, sql: calls.append(sql))
    history.ensure_schema(8123)
    assert len(calls) == 2 and all(sql.startswith("CREATE") for sql in calls)
    assert "ReplacingMergeTree" in calls[1] and "fsync_after_insert = 1" in calls[1]


@pytest.mark.parametrize("family", ["processes", "usb"])
def test_real_detail_route_uses_server_scope_and_exact_history(stores, monkeypatch, family):
    from server.api.routes import reports_v2
    from server.sli.plugins.workstations.scope import WorkstationScopeAdapter

    ch, adapter = stores
    rows = [observation(family=family), observation(2, family=family, agent="fixture-other")]
    pg = PG(rows)
    retention.retain_batch(pg, history=adapter, now=NOW)
    monkeypatch.setattr(reports, "connect", lambda: nullcontext(pg))
    monkeypatch.setattr(history, "configured_history", lambda: adapter)
    monkeypatch.setattr(WorkstationScopeAdapter, "agent_keys", lambda *args: ("fixture-agent",))
    monkeypatch.setattr(reports_v2, "report_plugin_state", lambda key: None)
    ctx = context(adapter, family)
    handler = SimpleNamespace(_access_decision=lambda: ctx.access)

    def send(payload, status=200):
        handler.payload, handler.status = payload, status

    handler._send_json = send
    query = {"period": ["custom"], "from": [ctx.params["period"]["from_utc"]],
             "to": [ctx.params["period"]["to_utc"]]}
    key = reports.REPORTS[family][0]
    url = f"/api/v2/reports/{key}/rows/{rows[0]['id']}/detail"
    assert reports_v2.try_handle_get(handler, url, query)
    assert handler.status == 200 and handler.payload["items"][0]["source_xml"] == rows[0]["source_xml"]
    foreign = f"/api/v2/reports/{key}/rows/{rows[1]['id']}/detail"
    assert reports_v2.try_handle_get(handler, foreign, query)
    assert handler.status == 404 and "source_xml" not in handler.payload
    calls = len(ch.calls)
    ctx.access["reports"][0]["grants"][0]["field_categories"] = ["technical"]
    assert reports_v2.try_handle_get(handler, url, query)
    assert handler.status == 403 and len(ch.calls) == calls
