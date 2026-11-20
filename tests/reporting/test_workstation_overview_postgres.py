"""Real projected overview reads on the CI-owned disposable migrated database."""

import hashlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from urllib.parse import quote

import pytest

from server.sli.plugins.workstations import overview
from server.sli.plugins.workstations.importer import digest
from server.sli.plugins.workstations.reports import FIELDS
from server.sli.reporting.v2.definition import QueryContext

pytestmark = pytest.mark.postgres_integration


@pytest.mark.parametrize("check_id", [None, "C05"])
def test_unbuilt_inventory_keeps_counts_unknown_on_runtime_role(monkeypatch, check_id):
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("CI-owned disposable migrated PostgreSQL required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    monkeypatch.setattr(overview, "connect", lambda: psycopg.connect(
        dsn, row_factory=dict_row, options="-c role=adlog_user"))
    access = {"capabilities": ["workstations.read"], "reports": [{
        "report_key": "workstations.overview", "allowed": True, "allowed_actions": ["view"],
        "grants": [{"scope": {"kind": "domain", "ids": [11]}, "allowed_actions": ["view"],
                    "field_categories": sorted(FIELDS)}]}]}
    body = overview.make_report().query(QueryContext(access=access, params={"check_id": check_id}, limit=50))
    assert body["items"] == []
    assert body["filtered_count"] is None
    assert body["coverage"]["population_status"] == "inventory_pending"
    assert [(metric["value"], metric["quality"]) for metric in body["metrics"]] == [
        (None, "unknown"), (None, "unknown")]


def test_scoped_pages_card_and_exact_evidence_on_runtime_role(monkeypatch):
    # tests/conftest.py clones an isolated sli_test_* database for this marker.
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("CI-owned disposable migrated PostgreSQL required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    suffix = uuid.uuid4().hex[:12]
    prefix = f"synthetic-ws-{suffix}"
    agent = str(uuid.uuid4())
    host = str(uuid.uuid4())
    now = datetime.now(UTC)
    xml = "<Event>synthetic-workstation-evidence</Event>"
    source_hash = hashlib.sha256(xml.encode()).hexdigest()
    observation_id = digest([suffix, "observation"])
    finding_id = digest([suffix, 0, "C05"])
    reference = {"kind": "workstation_observation", "agent_key": agent,
                 "observation_id": observation_id, "source_sha256": source_hash}
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        cur = conn.cursor()
        first_id = cur.execute("select coalesce(max(id),0)+1000 as id from entities_v2").fetchone()["id"]
        station_ids = [f"ws:ad:{first_id + number}" for number in range(14)]
        station_ids[0] = f"ws:agent:{agent}"
        # Migrated clones guarantee schema, not previously imported directory
        # types. Use the existing context_identity upsert convention explicitly.
        type_id = cur.execute("insert into storage_v2_entity_type(value) values(%s) "
                              "on conflict(value) do update set value=excluded.value returning id",
                              ("ad_computer",)).fetchone()["id"]
        cur.execute("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,instance_name) "
                    "values (%s,%s,%s,%s::jsonb,%s)",
                    (agent, host, "a" * 64, '[{"module_id":"sli.workstations"}]', prefix))
        for number, station in enumerate(station_ids):
            domain = 11 if number < 13 else 22
            cur.execute("insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256) "
                        "values (%s,%s,%s,%s,%s,%s)",
                        (first_id + number, type_id, station, station, domain, bytes(32)))
            cur.execute("insert into sli_plugin_workstations.station_inventory"
                        "(station_id,ad_computer_id,agent_key,domain_id,metadata) values (%s,%s,%s,%s,%s::jsonb)",
                        (station, first_id + number, agent if number == 0 else None, domain,
                         json.dumps({"display_name": f"{prefix}-{number:02}",
                                     "ip_addresses": ["192.0.2.77"] if number in (1, 13) else []})))
            if number in (1, 2, 3, 13):
                cur.execute("""insert into sli_plugin_workstations.station_summary
                    (station_id,last_interactive_login,as_of_utc) values(%s,%s::jsonb,%s)""",
                    (station, json.dumps({"observed_at": now.isoformat(), "logon_type": 2,
                        "account": {"name": f"{prefix}-userAX" if number == 3 else f"{prefix}-user_%", "domain": "EXAMPLE", "sid": "S-1-5-21-1-2-3-1001"},
                        "current_state": "unknown"}), now))
            if number in (1, 13):
                device_key = digest([suffix, "station-local-device"])
                cur.execute("""insert into sli_plugin_workstations.device_seen
                    (station_id,device_key,device_id,identity_quality,storage_evidence,
                     first_seen_at,last_seen_at,first_ref,last_ref)
                    values(%s,%s,%s,'station_instance',true,%s,%s,'{}','{}')""",
                    (station, device_key, "USBSTOR\\SYNTHETIC", now-timedelta(days=8), now+timedelta(days=1)))
                for at in (now-timedelta(days=8), now-timedelta(days=1), now-timedelta(hours=1), now+timedelta(days=1)):
                    cur.execute("""insert into sli_plugin_workstations.device_seen_occurrences
                        (station_id,device_key,observed_at) values(%s,%s,%s)""", (station, device_key, at))
            if number < 12:
                for check in (["C04", "C05"] if number == 0 else ["C05"]):
                    cur.execute("""insert into sli_plugin_workstations.check_findings
                        (id,station_id,check_id,rule_version,episode_id,revision,condition_sha256,status,severity,
                         first_detected_at,last_observed_at,materially_changed_at,reason_code,evidence_refs,subject_ref)
                        values (%s,%s,%s,1,%s,1,%s,'active','medium',%s,%s,%s,'service_or_task_changed',%s::jsonb,%s::jsonb)""",
                                (digest([suffix, number, check]), station, check, digest([suffix, number, check, "episode"]),
                                 "c" * 64, now, now, now, json.dumps([reference]) if number == 0 else "[]",
                                 json.dumps({"kind": "workstation_process_observation", "station_id": station,
                                    "path": r"C:\Windows\Temp\synthetic.exe", "process_id": "17", "signature_status": "not_received",
                                    "current_state": "unknown", "command_line": "PRIVATE-COMMAND"}) if check == "C04" else "{}"))
        # A positive mixed station needs a real current device -> exact AD
        # association. Merely storing agent_key beside an AD ID is not proof.
        device_type = cur.execute("insert into storage_v2_entity_type(value) values('device') "
            "on conflict(value) do update set value=excluded.value returning id").fetchone()['id']
        device = first_id + 100
        natural = 'core:' + hashlib.sha256(f'["device","sli.agent.key","agent-registry","{agent}"]'.encode()).hexdigest()
        cur.execute("insert into entities_v2(id,entity_type_id,natural_key,display_name,source_core_sha256) "
            "values(%s,%s,%s,'synthetic-device',%s)", (device, device_type, natural, hashlib.sha256(agent.encode()).digest()))
        cur.execute("""insert into core_entity_observations(observation_sha256,plugin_id,source_instance_id,
            entity_kind,entity_id,observed_at_utc,identifiers_json,evidence_refs,resolution)
            values(%s,'sli.workstations',%s,'device',%s,now(),'[{}]',array['synthetic'],'resolved')""",
            (hashlib.sha256(host.encode()).digest(), host, device))
        actor = cur.execute("insert into auth_users(username,password_hash,role) "
            "values(%s,'synthetic','viewer') returning id", (uuid.uuid4().hex,)).fetchone()['id']
        cur.execute("insert into core_entity_associations(source_entity_id,target_entity_id,relation,actor_id,evidence_refs) "
            "values(%s,%s,'directory_computer',%s,array['synthetic'])", (device, first_id, actor))
        body = {"agent_key": agent, "entity_id": first_id, "ad_computer_id": first_id,
                "family": "processes", "event_id": 4688, "observed_at": now.isoformat(), "source_sha256": source_hash}
        cur.execute("""insert into sli_plugin_workstations.observations
            (id,agent_key,entity_id,ad_computer_id,family,event_id,observed_at,observation,observation_sha256,source_xml)
            values (%s,%s,%s,%s,'processes',4688,%s,%s::jsonb,%s,%s)""",
                    (observation_id, agent, first_id, first_id, now, json.dumps(body), digest(body), xml))

    def grant(scope):
        return {"scope": scope, "allowed_actions": ["view"], "field_categories": sorted(FIELDS)}

    access = {"capabilities": ["workstations.read"], "reports": [{
        "report_key": "workstations.overview", "allowed": True, "allowed_actions": ["view"],
        "grants": [grant({"kind": "domain", "ids": [11, 22]}), grant({"kind": "agent", "ids": [agent]})],
    }]}
    # Exercise runtime SELECT privileges as well as real PostgreSQL CTE/paging.
    monkeypatch.setattr(overview, "connect", lambda: psycopg.connect(dsn, row_factory=dict_row, options="-c role=adlog_user"))
    definition = overview.make_report()
    ctx = QueryContext(access=access, params={"search": prefix, "domain": 11}, limit=5)
    first = definition.query(ctx)
    assert first["filtered_count"] == 13
    assert first["metrics"][1]["value"] == 12  # C04+C05 on one station is not two stations.
    assert len(first["collections"]["checks"]) == 10
    assert first["collections"]["checks"][2]["counts"]["stations"] == {"value": None, "relation": "unknown"}
    assert [item["station_id"] for item in first["items"]] == sorted(station_ids[:13])[:5]
    assert definition.detail.query(ctx, station_ids[12])["items"][0]["station_id"] == station_ids[12]
    with pytest.raises(PermissionError, match="workstation_access_denied"):
        definition.detail.query(ctx, station_ids[13])

    # Search uses last target account and observed inventory IP, not only name.
    # Literal wildcard characters stay literal and counts/page/card share scope.
    account_params = {"search": f"EXAMPLE\\{prefix}-user_%", "domain": 11}
    account_page = definition.query(QueryContext(access=access, params=account_params, limit=1))
    assert account_page["filtered_count"] == 2
    matching = sorted(station_ids[1:3])
    assert [row["station_id"] for row in account_page["items"]] == matching[:1]
    assert account_page["has_more"]
    account_next = definition.query(QueryContext(access=access, params=account_params, limit=1,
                                               cursor=account_page["next_cursor"]))
    assert account_next["filtered_count"] == 2
    assert [row["station_id"] for row in account_next["items"]] == matching[1:]
    assert account_next["collections"]["paging"][0]["start"] == 2
    for term, expected in (("192.0.2.77", [station_ids[1]]), (f"{prefix}-userX%", []),
                           ("S-1-5-21-1-2-3-1001", [])):
        found = definition.query(QueryContext(access=access, params={"search": term, "domain": 11}, limit=5))
        assert found["filtered_count"] == len(expected)
        assert [row["station_id"] for row in found["items"]] == expected
    account_ctx = QueryContext(access=access, params=account_params, limit=1)
    assert definition.detail.query(account_ctx, station_ids[1])["items"][0]["station_id"] == station_ids[1]
    with pytest.raises(PermissionError, match="workstation_access_denied"):
        definition.detail.query(account_ctx, station_ids[13])
    domain11_only = {"capabilities": ["workstations.read"], "reports": [{
        "report_key": "workstations.overview", "allowed": True, "allowed_actions": ["view"],
        "grants": [grant({"kind": "domain", "ids": [11]})]}]}
    hidden = definition.query(QueryContext(access=domain11_only,
        params={**account_params, "domain": 22}, limit=5))
    assert hidden["filtered_count"] == 0 and hidden["items"] == []

    observed_devices = definition.detail.query(ctx, station_ids[1])["items"][0]["devices"]
    assert observed_devices["devices_7d"] == {"value": 1, "relation": "at_least"}
    assert observed_devices["baseline_status"] == "unknown" and observed_devices["quality"]["status"] == "partial"
    assert definition.detail.query(ctx, station_ids[2])["items"][0]["devices"]["devices_7d"] == {
        "value": None, "relation": "unknown"}
    assert account_page["items"][0]["devices"]["devices_7d"]["relation"] in ("at_least", "unknown")
    assert all("devices" in row for row in first["items"])

    c04 = next(row for row in definition.detail.query(ctx, station_ids[0])["collections"]["findings"] if row["check_id"] == "C04")
    assert c04["process_details"] == {"path": r"C:\Windows\Temp\synthetic.exe", "process_id": "17",
                                      "signature_status": "not_received", "current_state": "unknown"}
    assert "subject_ref" not in c04 and "PRIVATE-COMMAND" not in repr(c04)

    check_ids = sorted(station_ids[:12])
    check = QueryContext(access=access, params={"search": prefix, "domain": 11, "check_id": "C05"}, limit=5, cursor=check_ids[9])
    third = definition.query(check)
    assert third["filtered_count"] == 12
    assert [item["station_id"] for item in third["items"]] == check_ids[10:12]
    assert third["collections"]["paging"] == [{"start": 11, "has_previous": True, "previous_cursor": check_ids[4]}]
    previous = definition.query(QueryContext(access=access, params=check.params, limit=5, cursor=check_ids[4]))
    assert [item["station_id"] for item in previous["items"]] == check_ids[5:10]
    assert previous["collections"]["paging"][0] == {"start": 6, "has_previous": True, "previous_cursor": None}

    source = QueryContext(access=access, params={"search": prefix, "domain": 11, "finding_id": finding_id, "evidence_index": 1}, limit=5)
    evidence = definition.detail.query(source, station_ids[0])
    assert evidence["items"][0]["source_xml"] == xml
    assert evidence["items"][0]["source_sha256"] == source_hash
    with pytest.raises(PermissionError, match="workstation_access_denied"):
        definition.detail.query(source, station_ids[1])
    denied = {**access, "capability_policies": [{"capability_key": "workstations.read", "effect": "deny",
                                                "valid": True, "scope": {"kind": "agent", "ids": [agent]}}]}
    with pytest.raises(PermissionError, match="workstation_access_denied"):
        definition.detail.query(QueryContext(access=denied, params=source.params, limit=5), station_ids[0])

    from server.api.routes import reports_v2
    from tests.reporting.test_workstation_access_contract import Handler

    monkeypatch.setattr(reports_v2, "report_plugin_state", lambda key: None)
    handler = Handler(access)
    root = "/api/v2/reports/workstations.overview"
    query = {"search": [prefix], "domain": ["11"], "limit": ["5"]}
    assert reports_v2.try_handle_get(handler, root + "/data", query)
    assert handler.status == HTTPStatus.OK
    assert handler.payload["filtered_count"] == 13  # Grant includes domain 22; selected domain must still restrict.
    assert len(handler.payload["collections"]["checks"]) == 10
    assert handler.payload["collections"]["paging"][0]["start"] == 1
    for station_id in (station_ids[0], station_ids[12]):
        path = root + f"/rows/{quote(station_id, safe='')}/detail"
        assert reports_v2.try_handle_get(handler, path, query)
        assert handler.status == HTTPStatus.OK
        assert handler.payload["items"][0]["station_id"] == station_id
        assert "findings" in handler.payload["collections"]
    path = root + f"/rows/{quote(station_ids[0], safe='')}/detail"
    assert reports_v2.try_handle_get(handler, path, {**query, "finding_id": [finding_id], "evidence_index": ["1"]})
    assert handler.status == HTTPStatus.OK
    assert handler.payload["items"][0]["source_xml"] == xml
    assert reports_v2.try_handle_get(handler, root + f"/rows/{quote(station_ids[13], safe='')}/detail", query)
    assert handler.status == HTTPStatus.FORBIDDEN
