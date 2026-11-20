"""Connected workstation overview uses projections, scoped before counts/pages."""

import hashlib
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from server.sli.plugins.workstations import overview
from server.sli.plugins.workstations.reports import FIELDS


def access():
    return {"capabilities": ["workstations.read"], "reports": [{
        "report_key": "workstations.overview", "allowed": True, "allowed_actions": ["view"],
        "grants": [{"scope": {"kind": "domain", "ids": [11]}, "allowed_actions": ["view"],
                    "field_categories": sorted(FIELDS)}],
    }]}


def context(**kwargs):
    return SimpleNamespace(access=access(), params={"search": "", "ou": "", "check_id": ""},
                           limit=50, cursor=None, tab="stations", **kwargs)


def test_report_has_registered_overview_identity_and_bounded_station_detail():
    definition = overview.make_report()
    assert definition.key == "workstations.overview"
    assert definition.access.required_fields == FIELDS
    assert definition.default_limit == 50
    assert definition.max_limit == 50
    assert callable(definition.query)
    assert callable(definition.detail.query)


@pytest.mark.parametrize("total,agents,observed,inventory_built,status", [
    (0, 0, 0, False, "inventory_pending"),
    (0, 0, 0, True, "no_agents"),
    (3, 0, 0, True, "no_agents"),
    (3, 1, 0, True, "awaiting_observations"),
    (3, 1, 1, True, "partial"),
])
@pytest.mark.parametrize("selected", ["", "C05"])
def test_population_state_and_unknown_counts_use_only_scoped_inventory(
        monkeypatch, total, agents, observed, inventory_built, status, selected):
    calls = []
    class Cursor:
        def execute(self, sql, params=()):
            calls.append((sql, params))
            self.sql = sql
        def fetchone(self):
            if "where check_id=%s" in self.sql:
                return {"total": observed}
            return {"total": total, "agent_stations": agents, "observed_stations": observed,
                    "inventory_built": inventory_built, "as_of": "2026-10-19T13:00:00Z"}
        def fetchall(self):
            return []
    cur = Cursor()
    monkeypatch.setattr(overview, "connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cur))))
    ctx = context()
    ctx.params["check_id"] = selected
    body = overview.read_overview(ctx, overview.make_report())
    assert body["coverage"]["population_status"] == status
    assert body["metrics"][0]["value"] == (total if inventory_built else None)
    assert body["metrics"][0]["quality"] == ("observed" if inventory_built else "unknown")
    assert body["metrics"][1]["value"] == (observed if inventory_built else None)
    assert body["metrics"][1]["quality"] == ("observed" if inventory_built else "unknown")
    assert body["filtered_count"] == ((observed if selected else total) if inventory_built else None)
    query, params = next((sql, args) for sql, args in calls if "as agent_stations" in sql)
    assert "from visible" in query and "station_resources" in query
    assert ["ad-domain:11"] in params


def test_overview_is_registered_on_the_real_report_catalog_path():
    from server.sli.reporting.v2.registry import registered_reports

    assert "workstations.overview" in {item.key for item in registered_reports(validate_intents=True)}


def test_report_catalog_title_is_localized_and_passport_describes_projection():
    from server.sli.core.messages import response_messages

    definition = overview.make_report()
    for locale, title in (("en", "Workstations"), ("ru", "\u0420\u0430\u0431\u043e\u0447\u0438\u0435 \u0441\u0442\u0430\u043d\u0446\u0438\u0438")):
        assert response_messages(definition.to_json(), locale, report=True)["title"] == title
    assert "projection" in definition.intent.sources[0]
    assert "PostgreSQL" in definition.intent.retention


def test_overview_metadata_vocabulary_matches_frontend_and_localizes_the_wire():
    import json
    import re
    from pathlib import Path

    from server.sli.core.messages import catalog, response_messages

    root = Path(__file__).resolve().parents[2]
    for locale in ("ru", "en"):
        source = (root / f"frontend/src/i18n/{locale}.ts").read_text(encoding="utf-8")
        frontend = {json.loads(key): json.loads(value) for key, value in re.findall(
            r'^\s*("(?:[^"\\]|\\.)*"):\s*("(?:[^"\\]|\\.)*")\s*,?\s*$', source, re.MULTILINE)}
        for code, text in catalog(locale).items():
            if code.startswith(("workstations.overview.", "reports.v2.workstations.overview.")):
                assert frontend.get(code) == text, (locale, code)
    wire = response_messages(overview.make_report().to_json(), "en", report=True)
    assert wire["title"] == "Workstations"
    labels = {param["key"]: param["label"] for param in wire["params"]}
    assert labels["period"] == "Period"
    assert labels["domain"] == labels["domain_id"] == "Domain"
    assert not re.search("[\u0400-\u04ff]", json.dumps(wire, ensure_ascii=False))


def test_registered_http_definition_data_and_detail_use_the_same_reader(monkeypatch):
    from http import HTTPStatus

    from server.api.routes import reports_v2
    from server.sli.reporting.v2.definition import result
    from tests.reporting.test_workstation_access_contract import Handler

    calls = []
    collections = {
        "checks": overview.check_rows([{"check_id": "C05", "stations": 1}]),
        "findings": [{"id": "a" * 64, "check_id": "C05", "reason_code": "service_or_task_changed",
                      "evidence_refs": [{"kind": "workstation_observation", "observation_id": "b" * 64}]}],
        "paging": [{"start": 6, "has_previous": True, "previous_cursor": None}],
    }

    def read(ctx, definition, station_id=None):
        calls.append((ctx, station_id))
        return result(definition, state="partial", items=[{"station_id": station_id or "ws:ad:123"}],
                      collections={**collections, "undeclared": [{"value": "must be removed"}]})

    monkeypatch.setattr(overview, "read_overview", read)
    monkeypatch.setattr(reports_v2, "report_plugin_state", lambda key: None)
    handler = Handler(access())
    root = "/api/v2/reports/workstations.overview"
    reports_v2.try_handle_get(handler, root, {})
    assert handler.status == HTTPStatus.OK
    reports_v2.try_handle_get(handler, root + "/data", {})
    assert handler.status == HTTPStatus.OK
    assert handler.payload["collections"] == collections
    reports_v2.try_handle_get(handler, root + "/rows/synthetic-station/detail", {})
    assert handler.status == HTTPStatus.OK
    assert handler.payload["collections"] == collections
    assert [station for _, station in calls] == [None, "synthetic-station"]

    blocked = Handler({"capabilities": ["workstations.read"], "reports": []})
    reports_v2.try_handle_get(blocked, root + "/data", {})
    assert blocked.status == HTTPStatus.FORBIDDEN
    assert len(calls) == 2


@pytest.mark.parametrize("station_id", ["ws:ad:123", "ws:agent:60f58b59-3811-4940-85db-a3de8ea664bb"])
def test_client_encoded_station_id_reaches_http_card_and_evidence_reader(monkeypatch, station_id):
    from http import HTTPStatus
    from urllib.parse import quote

    from server.api.routes import reports_v2
    from server.sli.reporting.v2.definition import result
    from tests.reporting.test_workstation_access_contract import Handler

    calls = []

    def read(ctx, definition, selected=None):
        calls.append((selected, ctx.params.get("finding_id")))
        return result(definition, state="partial", items=[{"station_id": selected}])

    monkeypatch.setattr(overview, "read_overview", read)
    monkeypatch.setattr(reports_v2, "report_plugin_state", lambda key: None)
    handler = Handler(access())
    # For these production ID characters quote(safe='') is encodeURIComponent.
    path = f"/api/v2/reports/workstations.overview/rows/{quote(station_id, safe='')}/detail"
    assert reports_v2.is_resource_aware(path)
    for query in ({}, {"finding_id": ["a" * 64], "evidence_index": ["1"]}):
        assert reports_v2.try_handle_get(handler, path, query)
        assert handler.status == HTTPStatus.OK
        assert handler.payload["items"][0]["station_id"] == station_id
    assert calls == [(station_id, None), (station_id, "a" * 64)]
    denied = Handler({"capabilities": ["workstations.read"], "reports": []})
    assert reports_v2.try_handle_get(denied, path, {})
    assert denied.status == HTTPStatus.FORBIDDEN
    assert len(calls) == 2


@pytest.mark.parametrize("encoded", ["ws%", "ws%3", "ws%3Gad", "ws%FFad", "ws%00ad", "ws%253Aad%253A123",
                                     "ws:ad/123", "ws%3Aad%2F123", "ws%3Aad%5C123", "ws%3Aad%252F123"])
def test_malformed_or_path_separator_row_ids_are_rejected_before_authorization(encoded):
    from server.api.routes import reports_v2

    handler = SimpleNamespace(_access_decision=lambda: pytest.fail("invalid route must not reach access or reader"))
    path = f"/api/v2/reports/workstations.overview/rows/{encoded}/detail"
    assert not reports_v2.is_resource_aware(path)
    assert not reports_v2.try_handle_get(handler, path, {})


def test_new_report_access_does_not_widen_legacy_family_grants():
    legacy = {**access(), "reports": [{**access()["reports"][0], "report_key": "workstations.logons"}]}
    with pytest.raises(PermissionError, match="workstation_access_denied"):
        overview.admission(legacy)
    predicate, params = overview.admission(access())
    assert "station_resources" in predicate
    assert "r.station_id=s.station_id" in predicate
    assert "ad-domain:11" in str(params)


def test_observed_counts_are_distinct_lower_bounds_and_absence_is_unknown():
    counts = overview.check_rows([
        {"check_id": "C01", "stations": 2}, {"check_id": "C02", "stations": 1},
    ])
    assert [row["check_id"] for row in counts] == [f"C{n:02}" for n in range(1, 11)]
    assert counts[0]["counts"]["stations"] == {"value": 2, "relation": "at_least"}
    assert counts[2]["counts"]["stations"] == {"value": None, "relation": "unknown"}
    assert all(row["counts"]["new_since_previous_login"] == {"value": None, "relation": "unknown"}
               for row in counts)


@pytest.mark.parametrize("limit", [0, True, 51])
def test_reader_rejects_invalid_page_bound_before_any_storage(limit):
    ctx = context()
    ctx.limit = limit
    with pytest.raises(ValueError, match="workstation_request_invalid"):
        overview.read_overview(ctx, overview.make_report())


def test_evidence_selection_must_be_one_of_the_server_finding_references():
    reference = {"kind": "workstation_observation", "agent_key": "synthetic-agent",
                 "observation_id": "a" * 64, "source_sha256": "b" * 64}
    assert overview.select_reference([reference], 0, "synthetic-agent") == reference
    for index in (True, -1, 1):
        with pytest.raises(ValueError, match="workstation_evidence_invalid"):
            overview.select_reference([reference], index, "synthetic-agent")
    with pytest.raises(PermissionError, match="workstation_access_denied"):
        overview.select_reference([reference], 0, "foreign-agent")


def test_exact_observation_verifies_xml_and_canonical_body_hashes():
    from server.sli.plugins.workstations.importer import digest

    xml = "<Event>synthetic</Event>"
    sha = hashlib.sha256(xml.encode()).hexdigest()
    body = {"agent_key": "synthetic-agent", "source_sha256": sha, "family": "processes"}
    row = {"id": "a" * 64, "agent_key": "synthetic-agent", "family": "processes",
           "observation": body, "observation_sha256": digest(body), "source_xml": xml}
    reference = {"kind": "workstation_observation", "agent_key": "synthetic-agent",
                 "observation_id": "a" * 64, "source_sha256": sha}
    assert overview.observation_evidence(row, reference)["source_xml"] == xml
    for changed in ({**row, "source_xml": xml + "changed"}, {**row, "observation_sha256": "f" * 64},
                    {**row, "agent_key": "foreign"}, {**row, "id": "c" * 64}):
        with pytest.raises(ValueError, match="workstation_evidence_mismatch"):
            overview.observation_evidence(changed, reference)


def test_first_evidence_reference_works_through_declared_detail_api(monkeypatch):
    from server.sli.plugins.workstations.importer import digest
    from server.sli.reporting.v2.definition import QueryContext, parse_params

    xml = "<Event>synthetic</Event>"
    sha = hashlib.sha256(xml.encode()).hexdigest()
    reference = {"kind": "workstation_observation", "agent_key": "synthetic-agent",
                 "observation_id": "a" * 64, "source_sha256": sha}
    body = {"agent_key": "synthetic-agent", "source_sha256": sha, "family": "processes"}
    row = {"id": "a" * 64, "agent_key": "synthetic-agent", "family": "processes",
           "observation": body, "observation_sha256": digest(body), "source_xml": xml}
    cursor = SimpleNamespace(execute=lambda *args: None,
                             fetchone=lambda: {"evidence_refs": [reference], "agent_key": "synthetic-agent"},
                             fetchall=lambda: [row])
    connection = SimpleNamespace(cursor=lambda: nullcontext(cursor))
    monkeypatch.setattr(overview, "connect", lambda: nullcontext(connection))
    definition = overview.make_report()
    params, _ = parse_params(definition, {"finding_id": ["b" * 64], "evidence_index": ["1"]})
    ctx = QueryContext(access=access(), params=params, limit=50)
    response = definition.detail.query(ctx, "synthetic-station")
    assert response["items"][0]["source_xml"] == xml
    assert response["items"][0]["source_sha256"] == sha


@pytest.mark.parametrize("index", [0, -1, True, 101])
def test_evidence_api_rejects_invalid_one_based_index_before_storage(index):
    ctx = context()
    ctx.params.update(finding_id="b" * 64, evidence_index=index)
    with pytest.raises(ValueError, match="workstation_evidence_invalid"):
        overview._evidence(None, "", [], ctx, overview.make_report())


@pytest.mark.parametrize("selected", [None, "synthetic-station"])
def test_last_login_summary_passes_through_scoped_existing_reader(monkeypatch, selected):
    """No new API/grant: existing list and card return this projected column."""
    login = {"observed_at": "2026-10-19T12:30:00+00:00", "logon_type": 2,
             "account": {"name": "synthetic-target", "domain": "EXAMPLE", "sid": None},
             "current_state": "unknown"}
    calls = []
    class Cursor:
        def execute(self, sql, params=()):
            calls.append((sql, params))
            self.sql, self.params = sql, params
        def fetchone(self):
            return {"total": 1, "agent_stations": 1, "observed_stations": 0,
                    "inventory_built": True, "as_of": "2026-10-19T13:00:00Z"}
        def fetchall(self):
            if self.sql.lstrip().startswith("with selected as"):
                return [{"station_id": key, "history_start_at": None, "value": 0} for key in self.params[0]]
            if "select v.*" in self.sql:
                return [{"station_id": "synthetic-station", "metadata": {}, "last_interactive_login": login}]
            return []
    cursor = Cursor()
    monkeypatch.setattr(overview, "connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    ctx = context()
    ctx.params["domain"] = 11
    response = overview.read_overview(ctx, overview.make_report(), selected)
    assert response["items"][0]["last_interactive_login"] == login
    query, params = next((sql, params) for sql, params in calls if "select v.*" in sql)
    assert "m.last_interactive_login" in query and "s.domain_id=%s" in query and 11 in params
    if selected:
        assert "s.station_id=%s" in query and selected in params


@pytest.mark.parametrize("missing", sorted(FIELDS))
def test_last_login_does_not_bypass_existing_atomic_field_category_admission(monkeypatch, missing):
    ctx = context()
    ctx.access["reports"][0]["grants"][0]["field_categories"].remove(missing)
    monkeypatch.setattr(overview, "connect", lambda: pytest.fail("denied fields must not read summary"))
    with pytest.raises(PermissionError, match="workstation_access_denied"):
        overview.read_overview(ctx, overview.make_report(), "synthetic-station")


def test_station_search_covers_native_last_account_and_inventory_ip_without_scope_widening():
    ctx = context()
    ctx.params.update(search=r"EXAMPLE\fixture_%", domain=11, ou="OU=Fixture,DC=example")
    predicate, params = overview._selection(ctx)
    assert "last_interactive_login" in predicate
    assert "{account,name}" in predicate and "{account,domain}" in predicate
    assert "ip_addresses" in predicate
    assert "station_resources" in predicate and "s.domain_id=%s" in predicate
    assert params.count(r"%EXAMPLE\\fixture\_\%%") == 1
    assert "EXAMPLE" not in predicate  # Values never interpolated into SQL.
    assert params[-2:] == ["OU=Fixture,DC=example", 11]
    assert "source_ip" not in predicate  # A logon source address is not the station IP.


@pytest.mark.parametrize("missing", sorted(FIELDS))
def test_account_ip_search_cannot_make_denied_fields_queryable(monkeypatch, missing):
    ctx = context()
    ctx.params.update(search="synthetic-target", domain=11)
    ctx.access["reports"][0]["grants"][0]["field_categories"].remove(missing)
    monkeypatch.setattr(overview, "connect", lambda: pytest.fail("search must not bypass field admission"))
    with pytest.raises(PermissionError, match="workstation_access_denied"):
        overview.read_overview(ctx, overview.make_report())



def test_registered_c06_summary_reaches_scoped_reader_page_and_card_in_one_batch(monkeypatch):
    from server.sli.plugins.workstations import devices, projection
    from tests.unit.test_workstation_devices import (
        DEVICE,
        NOW,
        STATION,
        BatchPG,
        native,
    )

    class PagePG(BatchPG):
        def execute(self, sql, params=()):
            if sql.startswith(("set transaction", "with registered")) or "station_resources as" in sql:
                self.calls.append((sql, params))
                self.query = sql
                if "select v.*" in sql:
                    self.rows = [{"station_id": STATION, "metadata": {}},
                                 {"station_id": "sentinel-not-returned", "metadata": {}}]
                else:
                    self.rows = []
                self.one = {"total": 2, "agent_stations": 2, "observed_stations": 1,
                            "inventory_built": True, "as_of": NOW}
            else:
                return super().execute(sql, params)
    pg = PagePG()
    rule = next(item for item in projection.projectors() if item.key == devices.PROJECTOR)
    for number in (1, 2):
        row = native(record=number, device=DEVICE+str(number))
        rule.apply(pg, STATION, {"kind": "observations", "payload": row})
    monkeypatch.setattr(overview, "connect", lambda: nullcontext(pg))
    ctx = context()
    ctx.limit = 1
    for selected in (None, STATION):
        before = len(pg.calls)
        response = overview.read_overview(ctx, overview.make_report(), selected)
        assert response["items"][0]["devices"]["devices_7d"] == {"value": 2, "relation": "at_least"}
        batches = [(sql, params) for sql, params in pg.calls[before:] if sql.lstrip().startswith("with selected as")]
        assert len(batches) == 1 and batches[0][1][0] == [STATION]
        assert response["items"][0]["devices"]["baseline_status"] == "unknown"


def test_registered_c04_metadata_reaches_existing_card_with_strict_redaction(monkeypatch):
    import json

    from server.sli.plugins.workstations import projection
    from tests.unit.test_workstation_password_failures import PG, STATION, native
    from tests.unit.test_workstation_projection import prepare, run

    row = native(number=4688, NewProcessName=r'C:\Windows\Temp\fixture.exe', NewProcessId='0x11',
                 SubjectUserName='native-creator-not-owner', CommandLine='PRIVATE-COMMAND')
    pg = PG(row)
    rules = tuple(rule for rule in projection.projectors() if rule.key == 'workstations.C04')
    prepare(pg, rules)
    pg.add_fact(row['id'], payload=json.loads(json.dumps(row, default=str)))
    run(pg, rules)
    finding = next(iter(pg.findings.values()))
    finding['subject_ref'].update(command_line='PRIVATE-COMMAND', raw_xml='PRIVATE-XML', signer='UNPROVEN-SIGNER')
    class Cursor:
        def execute(self, sql, params=()):
            self.sql, self.params = sql, params
        def fetchone(self):
            return {'total': 1, 'agent_stations': 1, 'observed_stations': 1,
                    'inventory_built': True, 'as_of': '2026-10-19T13:00:00Z'}
        def fetchall(self):
            if self.sql.lstrip().startswith('with selected as'):
                return [{'station_id': STATION, 'history_start_at': None, 'value': 0}]
            if 'select v.*' in self.sql:
                return [{'station_id': STATION, 'metadata': {}}]
            if 'select id,station_id,check_id' in self.sql:
                assert 'subject_ref' in self.sql
                return [finding]
            return []
    cur = Cursor()
    monkeypatch.setattr(overview, 'connect', lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cur))))
    response = overview.read_overview(context(), overview.make_report(), STATION)
    item = response['collections']['findings'][0]
    assert item['process_details'] == {'path': r'C:\Windows\Temp\fixture.exe', 'process_id': '17',
        'signature_status': 'not_received', 'current_state': 'unknown'}
    assert 'subject_ref' not in item
    for excluded in ('PRIVATE-COMMAND', 'PRIVATE-XML', 'UNPROVEN-SIGNER', 'native-creator-not-owner'):
        assert excluded not in repr(response)


@pytest.mark.parametrize('check,subject,expected', [
    ('C05', {'kind': 'workstation_process_observation', 'station_id': 's', 'path': 'unrelated'}, None),
    ('C04', {'kind': 'workstation_process_observation', 'station_id': 'foreign', 'path': 'foreign'}, None),
    ('C04', {'kind': 'arbitrary', 'station_id': 's', 'path': 'arbitrary'}, None),
    ('C04', {'kind': 'workstation_process_observation', 'station_id': 's', 'path': 'x'*513,
             'process_id': '4294967296', 'signature_status': 'signed', 'current_state': 'active'},
     {'path': None, 'process_id': None, 'signature_status': 'unknown', 'current_state': 'unknown'}),
])
def test_process_card_metadata_never_exposes_other_subjects_or_unproven_claims(check, subject, expected):
    item = overview.finding_card({'check_id': check, 'subject_ref': subject}, 's')
    assert 'subject_ref' not in item and item.get('process_details') == expected
