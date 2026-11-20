"""Workstation plugin contracts with synthetic evidence and no database."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from psycopg import OperationalError
from psycopg.errors import InsufficientPrivilege, QueryCanceled, UndefinedTable

from server.sli.core import platform_settings
from server.sli.plugins.workstations import importer, normalizers, reports, retention
from server.sli.plugins.workstations.contracts import Workstation
from server.sli.plugins.workstations.settings import SETTING_KEY, retention_days
from server.sli.reporting import navigation_registry as nav
from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.sources.collection_packet_import import import_workstation_packet
from server.sli.storage import purge_audit
from server.source_packs.registry import resolve_source_normalizer, resolve_source_pack
from sli_collect.eventlog import event_packet, parse_event_xml


@pytest.fixture(autouse=True)
def purge_receipts(tmp_path, monkeypatch):
    monkeypatch.setattr(purge_audit, "AUDIT_DIR", tmp_path / "purge")
    monkeypatch.setattr(reports.history, "configured_history", lambda: None)


STATION = Workstation("fixture-agent-key", 17)
NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)
SECURITY = normalizers.SECURITY_PROVIDER


@pytest.mark.parametrize("event_id,semantic_type", [
    (4624, "authentication.session.created"), (4625, "authentication.session.failed"),
    (4634, "authentication.session.ended"), (4647, "authentication.logout.requested"),
    (4688, "process.started.fragment"), (4697, "service.installed.fragment"),
    (7045, "service.installed.fragment"), (4698, "scheduled_task.created.fragment"),
    (4699, "scheduled_task.deleted.fragment"), (4700, "scheduled_task.enabled.fragment"),
    (4701, "scheduled_task.disabled.fragment"), (4702, "scheduled_task.updated.fragment"),
    (4732, "group.member.added"), (4733, "group.member.removed"), (4719, "audit.policy.changed"),
])
def test_shared_windows_normalizers_keep_semantics_and_agent_identity(event_id, semantic_type):
    row = {"event_id": event_id, "channel": "System" if event_id == 7045 else "Security",
           "provider_name": "Service Control Manager" if event_id == 7045 else SECURITY}
    data = {"TargetSid": "S-1-5-32-544", "MemberSid": "S-1-5-21-1-2-3-1001",
            "LogonType": "10", "NewProcessId": "0x20", "NewProcessName": r"C:\fixture\process.exe",
            "CommandLine": "fixture-process --fixture", "ServiceName": "fixture-service",
            "ServiceFileName": r"C:\fixture\service.exe", "TaskName": "fixture-task"}
    projected = normalizers.normalize(row, data, STATION)
    assert projected["semantic_type"] == semantic_type
    assert projected["agent_key"] == STATION.agent_key
    assert projected["entity_id"] == 17 and projected["ad_computer_id"] is None
    assert projected["quality"]["ad_enrichment"] == "not_collected"
    assert resolve_source_pack(row["channel"], row["provider_name"], str(event_id)).pack_id == "sli.windows.ad-dc"
    if event_id in (4624, 4625, 4634, 4647):
        assert projected["facts"]["logon_type"] == "10"
    if event_id == 4688:
        assert projected["facts"]["process_command_line"] == data["CommandLine"]
        without = normalizers.normalize(row, {**data, "CommandLine": None}, STATION)
        assert without["facts"].get("process_command_line") is None
    if event_id in (4697, 7045):
        assert projected["facts"]["service_name"] == "fixture-service"
    if 4698 <= event_id <= 4702:
        assert projected["facts"]["task_name"] == "fixture-task"


@pytest.mark.parametrize("identity,spec", list(normalizers.NEW_IDENTITIES.items()))
def test_new_normalizers_resolve_exact_identity_and_preserve_optional_ad_link(identity, spec):
    channel, provider, event_id = identity
    projected = normalizers.normalize({"channel": channel, "provider_name": provider, "event_id": event_id},
                                      {"DeviceId": r"USBSTOR\fixture-device", "ClassName": "DiskDrive"},
                                      replace(STATION, ad_computer_id=29))
    assert projected["family"] == spec[0]
    assert projected["semantic_type"] == spec[1]
    assert projected["quality"]["ad_enrichment"] == "available"
    owner = resolve_source_normalizer(channel, provider, str(event_id))
    assert owner.normalizer_id == "windows-workstations-v1"
    assert resolve_source_pack(channel, provider, str(event_id)).pack_id == "sli.windows.workstations"
    assert normalizers.new_projection(event_id=event_id, channel=channel,
                                      provider="fixture-wrong-provider", event_data={}) == {}


@pytest.mark.parametrize("group_sid", [None, "S-1-5-21-1-2-3-512", "S-1-5-32-545"])
def test_only_native_local_administrators_sid_is_included(group_sid):
    assert normalizers.normalize({"event_id": 4732, "channel": "Security", "provider_name": SECURITY},
                                 {"TargetSid": group_sid, "TargetUserName": "Administrators"}, STATION) is None


def test_usb_observation_does_not_claim_storage_activity():
    projected = normalizers.new_projection(event_id=6416, channel="Security", provider=SECURITY,
                                          event_data={"DeviceId": r"USB\fixture-keyboard"})
    assert projected["facts"]["storage_evidence"] is False
    assert projected["quality"]["observation_only"] is True
    assert normalizers.normalize({"event_id": 4688, "channel": "System", "provider_name": SECURITY}, {}, STATION) is None


class Cursor:
    def __init__(self, rows=(), settings=None, states=()):
        self.rows = list(rows)
        self.states = list(states)
        self.calls = []
        self.settings = settings
        self.sql = ""
        self.rowcount = 1
        self.stored = {}
        self.one = None
        self.protection = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        self.sql = " ".join(sql.split())
        self.calls.append((self.sql, params))
        if self.sql.startswith("insert into sli_plugin_workstations.observations"):
            key = params[0]
            self.one = None if key in self.stored else {"id": key}
            self.stored.setdefault(key, {"observation_sha256": params[8], "observation": json.loads(params[7])})
        elif self.sql.startswith("select observation_sha256"):
            self.one = self.stored.get(params[0])
        elif self.sql.startswith("insert into sli_plugin_workstations.protection_state"):
            key, at = params[1], datetime.fromisoformat(params[4])
            old = self.protection.get(key)
            self.one = None
            if old is None or old["observed_at"] < at:
                self.protection[key] = {"observed_at": at, "state_sha256": params[6], "state": json.loads(params[5])}
                self.one = {"id": params[0]}
        elif self.sql.startswith("select observed_at,state_sha256"):
            self.one = self.protection.get(params[0])
        elif self.sql.startswith("select value"):
            self.one = None if self.settings is None else {"value": self.settings}
        elif "workstation_delete_readback" in self.sql:
            self.one = None
            self.rowcount = 0

    def fetchone(self):
        return self.one

    def fetchall(self):
        if "enrolled.host_name as enrolled_name" in self.sql:
            return []
        return self.states if "from sli_plugin_workstations.protection_state" in self.sql else self.rows


def connection(cursor):
    # No commit method: domain handlers must use the caller's transaction.
    return SimpleNamespace(cursor=lambda: cursor, __enter__=lambda self: self)


def packet(command="fixture --one"):
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
           f'<System><Provider Name="{SECURITY}"/><EventID>4688</EventID><EventRecordID>12</EventRecordID>'
           '<Channel>Security</Channel><TimeCreated SystemTime="2026-10-06T00:00:00Z"/></System>'
           f'<EventData><Data Name="CommandLine">{command}</Data></EventData></Event>')
    row = parse_event_xml(xml, source_name="fixture-source", connect_address="fixture-address", channel="Security")
    return event_packet(row, generation="fixture-generation", after_record_id=11)


def test_packet_import_round_trip_replay_and_conflict():
    cur = Cursor()
    identity = SimpleNamespace(workstation=lambda conn, key: STATION)
    conn = connection(cur)
    first = import_workstation_packet(conn, packet(), agent_key=STATION.agent_key, identity=identity)
    assert first == {"observed": 1, "inserted": 1, "ignored": 0}
    assert import_workstation_packet(conn, packet(), agent_key=STATION.agent_key, identity=identity)["inserted"] == 0
    enriched = SimpleNamespace(workstation=lambda conn, key: replace(STATION, ad_computer_id=29))
    assert import_workstation_packet(conn, packet(), agent_key=STATION.agent_key, identity=enriched)["inserted"] == 0
    with pytest.raises(ValueError, match="replay_conflict"):
        import_workstation_packet(conn, packet("fixture --two"), agent_key=STATION.agent_key, identity=identity)
    observation = json.loads(cur.calls[0][1][7])
    assert observation["agent_key"] == STATION.agent_key
    assert observation["agent_key"] != "fixture-source"
    assert observation["facts"]["process_command_line"] == "fixture --one"
    assert cur.calls[0][1][9].startswith("<Event")


def protection_packet(at=NOW, enabled=True):
    from sli_agent.workstations import DEFENDER_CHANNEL, PROTECTION_COMPONENTS
    from sli_collect.packets import make_packet

    return make_packet(source="fixture-source", channel=DEFENDER_CHANNEL, generation="fixture-generation",
        cursor={"after_record_id": None, "last_record_id": None}, records=[],
        continuity={"status": "not_proven"}, observed_at=at,
        context={"workstations": {"protection_state": {
            "state": "available", "components": dict.fromkeys(PROTECTION_COMPONENTS, enabled)}}})


def test_protection_snapshot_imports_without_events_and_old_replay_cannot_replace_current_state():
    cur = Cursor()
    conn = connection(cur)
    identity = SimpleNamespace(workstation=lambda conn, key: STATION)
    publish = lambda p: import_workstation_packet(conn, p, agent_key=STATION.agent_key, identity=identity)
    assert publish(protection_packet()) == {"observed": 0, "inserted": 0, "ignored": 0}
    assert cur.calls[0][1][0] == importer.digest([STATION.agent_key, "protection_state"])
    assert not cur.stored  # No fabricated native event or XML.
    publish(protection_packet())
    publish(protection_packet(NOW + timedelta(minutes=1), False))
    publish(protection_packet())
    stored = cur.protection[STATION.agent_key]
    assert stored["observed_at"] == NOW + timedelta(minutes=1)
    assert stored["state"]["components"]["real_time_protection_enabled"] is False
    with pytest.raises(ValueError, match="protection_replay_conflict"):
        publish(protection_packet(NOW + timedelta(minutes=1), True))


@pytest.mark.parametrize("mutation", [
    lambda p: p["header"].update(channel="Security"),
    lambda p: p["context"]["workstations"]["protection_state"]["components"].update(antivirus_enabled="true"),
    lambda p: p["context"]["workstations"]["protection_state"].update(state="healthy"),
])
def test_untrusted_protection_snapshot_is_rejected_before_writes(mutation):
    p = protection_packet()
    mutation(p)
    cur = Cursor()
    with pytest.raises(ValueError, match="protection_.*invalid"):
        import_workstation_packet(connection(cur), p, agent_key=STATION.agent_key,
                                  identity=SimpleNamespace(workstation=lambda conn, key: STATION))
    assert not cur.calls


@pytest.mark.parametrize("mutation,error", [
    (lambda p: p["header"].update(generation=None), "generation_required"),
    (lambda p: p["records"][0]["payload"].update(event_id=4624), "xml_identity_mismatch"),
])
def test_packet_invalid_identity_never_writes(mutation, error):
    cur = Cursor()
    p = packet()
    mutation(p)
    with pytest.raises(ValueError, match=error):
        import_workstation_packet(connection(cur), p, agent_key=STATION.agent_key,
                                  identity=SimpleNamespace(workstation=lambda conn, key: STATION))
    assert not cur.calls


def context(family, keys=(STATION.agent_key,), **kwargs):
    key = reports.REPORTS[family][0]
    grant = {"report_key": key, "allowed": True, "allowed_actions": ["view"],
             "grants": [{"allowed_actions": ["view"], "field_categories": list(reports.FIELDS),
                         "scope": {"kind": "all"}}]}
    scope = SimpleNamespace(agent_keys=lambda access, report_key, action, fields: keys)
    return QueryContext(access={"reports": [grant]}, params={"period": {
        "from_utc": "2026-10-01T00:00:00Z", "to_utc": "2026-10-06T00:00:00Z"}},
        domain_ids=None, action="view", cursor=None, limit=2, timezone="UTC",
        runtime={"workstation_scope_adapter": scope}, **kwargs)


class ReportConnection:
    def __init__(self, cur):
        self.cur = cur

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return self.cur


@pytest.mark.parametrize("family,expected_detail", [
    ("logons", "fields"), ("protection", "fields"),
    ("processes", "sub"), ("usb", "sub"),
])
def test_report_detail_serializes_a_supported_frontend_contract(family, expected_detail):
    detail = reports.make_report(family).to_json()["detail"]
    if expected_detail == "fields":
        assert detail == "fields"
    else:
        assert isinstance(detail, dict)
        assert detail["kind"] == "sub"


def test_process_report_default_page_bounds_cold_reads_and_keeps_continuation(monkeypatch):
    definition = reports.make_report("processes")
    params, options = parse_params(definition, {}, now=NOW)
    assert options["limit"] == definition.to_json()["limits"]["default"] == 25
    cur = Cursor([{"id": f"{value:064x}"} for value in range(1, 27)])
    monkeypatch.setattr(reports, "connect", lambda: ReportConnection(cur))
    first = definition.query(replace(context("processes"), params=params, limit=options["limit"]))
    assert len(first["items"]) == 25 and first["has_more"]
    assert first["next_cursor"] == f"{25:064x}"
    assert cur.calls[-1][1][-1] == 26
    cur.rows = [{"id": f"{26:064x}"}]
    second = definition.query(replace(context("processes"), params=params, limit=options["limit"],
                                      cursor=first["next_cursor"]))
    assert second["items"] == cur.rows and not second["has_more"]
    assert cur.calls[-1][1][4] == first["next_cursor"]


@pytest.mark.parametrize("family", list(reports.REPORTS))
def test_each_report_uses_scoped_bounded_half_open_query_and_keyset_page(monkeypatch, family):
    cur = Cursor([{"id": digit * 64} for digit in "123"])
    monkeypatch.setattr(reports, "connect", lambda: ReportConnection(cur))
    definition = reports.make_report(family)
    outcome = definition.query(context(family))
    sql, params = next(call for call in cur.calls if "with candidates" in call[0])
    assert "agent_key=any(%s)" in sql and "family=%s" in sql
    assert "observed_at>=%s and observed_at<%s" in sql and "id>%s" in sql
    assert "order by id limit %s" in sql and "count(" not in sql.lower() and "offset" not in sql.lower()
    assert ("storage_evidence" in sql) is (family == "usb")
    assert params[0] == [STATION.agent_key] and params[1] == family and params[-1] == 3
    assert outcome["state"] == "partial" and outcome["has_more"] is True
    assert outcome["next_cursor"] == "2" * 64
    assert outcome["coverage"]["state"] == "not_proven"
    definition.query(replace(context(family), cursor=outcome["next_cursor"]))
    assert [call for call in cur.calls if "with candidates" in call[0]][-1][1][4] == "2" * 64


@pytest.mark.parametrize("family", list(reports.REPORTS))
@pytest.mark.parametrize("detail", [False, True])
def test_report_bounds_ids_before_loading_observation_json(monkeypatch, family, detail):
    cur = Cursor(rows=[{"id": "1" * 64}])
    monkeypatch.setattr(reports, "connect", lambda: ReportConnection(cur))
    definition = reports.make_report(family)
    reports.read_report(context(family), family, definition, "1" * 64 if detail else None)
    sql, params = next(call for call in cur.calls if "with candidates" in call[0])
    materialization = "not materialized" if family == "processes" else "materialized"
    assert f"with candidates as {materialization}" in sql.lower()
    page, projection = sql.lower().split(") select", 1)
    assert "page as materialized" in page
    assert "select id" in page and "order by id limit %s" in page
    assert "agent_key=any(%s) and family=%s" in page
    assert "observed_at>=%s and observed_at<%s and id>%s" in page
    # USB admission must still happen before paging. Other JSON/evidence reads
    # must happen afterwards, so a cold page cannot detoast the whole window.
    assert ("storage_evidence" in page) is (family == "usb")
    assert "semantic_type" not in page and "source_xml" not in page
    assert "join page using(id)" in projection and "order by id" in projection
    assert "observation->'facts'" in projection
    assert ("source_xml" in projection) is detail
    assert ("and id=%s" in page) is detail
    assert params[-1] == context(family).limit + 1


@pytest.mark.parametrize("family", ["logons", "processes"])
@pytest.mark.parametrize("cursor", [None, "e" * 64])
def test_workstation_page_keeps_scope_and_window_before_bounded_projection(monkeypatch, family, cursor):
    cur = Cursor()
    monkeypatch.setattr(reports, "connect", lambda: ReportConnection(cur))
    outcome = reports.make_report(family).query(replace(context(family), cursor=cursor))
    sql, params = next(call for call in cur.calls if "with candidates" in call[0])
    # Dense process windows must allow LIMIT pushdown; materializing all IDs
    # before top-N ordering caused the report's five-second timeout on stand.
    # The planner can still choose the window index for sparse process periods.
    candidates, page = sql.lower().split("), page as materialized", 1)
    materialization = "not materialized" if family == "processes" else "materialized"
    assert f"with candidates as {materialization}" in candidates
    assert "agent_key=any(%s) and family=%s" in candidates
    assert "observed_at>=%s and observed_at<%s and id>%s" in candidates
    assert "order by" not in candidates and "observation->" not in candidates
    assert "from candidates order by id limit %s" in page
    assert params[4] == (cursor or "")
    assert outcome["items"] == [] and outcome["state"] == "partial"


@pytest.mark.parametrize("error,reason", [
    (QueryCanceled, "source_timeout"),
    (UndefinedTable, "source_not_initialized"),
    (InsufficientPrivilege, "source_access_denied"),
    (OperationalError, "source_unavailable"),
])
@pytest.mark.parametrize("stage", ["scope", "observations"])
def test_report_source_failures_explain_reason_without_driver_details(monkeypatch, error, reason, stage):
    def fail(*_args):
        raise error("fixture-private-driver-detail")

    ctx = context("processes")
    if stage == "scope":
        ctx = replace(ctx, runtime={"workstation_scope_adapter": SimpleNamespace(agent_keys=fail)})
        monkeypatch.setattr(reports, "connect", lambda: pytest.fail("scope failure must stop reads"))
    else:
        cur = Cursor()
        original_execute = cur.execute

        def execute(sql, params=()):
            if "from sli_plugin_workstations.observations" in sql:
                fail()
            original_execute(sql, params)

        monkeypatch.setattr(cur, "execute", execute)
        monkeypatch.setattr(reports, "connect", lambda: ReportConnection(cur))
    outcome = reports.make_report("processes").query(ctx)
    assert outcome["state"] == "error" and outcome["items"] == []
    assert outcome["coverage"]["reason"] == reason
    assert outcome["state_details"]["reason"] == reason
    assert outcome["limitations"] == [{
        "code": reason, "text": reports.message(f"reports.workstations.{reason}")["text"],
    }]
    assert "fixture-private-driver-detail" not in json.dumps(outcome)


def test_protection_report_shows_current_snapshot_outside_event_period_without_events(monkeypatch):
    state = {"id": "0" * 64, "agent_key": STATION.agent_key, "observed_at": NOW + timedelta(hours=1),
             "event_id": None, "semantic_type": "security.protection.state",
             "facts": {"real_time_protection_enabled": False}, "quality": {"snapshot": True, "state": "available"}}
    cur = Cursor(states=[state])
    monkeypatch.setattr(reports, "connect", lambda: ReportConnection(cur))
    result = reports.make_report("protection").query(context("protection"))
    assert result["items"] == [{**state, "host_name": None, "host_name_source": "unknown"}]
    assert not result["has_more"] and result["state"] == "partial"
    sql, params = next(call for call in cur.calls if "from sli_plugin_workstations.protection_state" in call[0])
    assert "agent_key=any(%s) order by id limit %s" in sql
    assert "observed_at>=" not in sql
    assert params == ([STATION.agent_key], reports.MAX_STATIONS)


def test_protection_state_and_event_pages_share_one_bounded_cursor(monkeypatch):
    cur = Cursor(rows=[{"id": "1" * 64}, {"id": "2" * 64}], states=[{"id": "0" * 64}])
    monkeypatch.setattr(reports, "connect", lambda: ReportConnection(cur))
    definition = reports.make_report("protection")
    first = definition.query(context("protection"))
    assert [row["id"] for row in first["items"]] == ["0" * 64, "1" * 64]
    assert first["has_more"] and first["next_cursor"] == "1" * 64
    definition.query(replace(context("protection"), cursor=first["next_cursor"]))
    assert cur.calls[-1][1][4] == "1" * 64


def test_cursor_after_snapshot_starts_events_before_its_hash_and_never_repeats_states(monkeypatch):
    cur = Cursor(rows=[{"id": "1" * 64}, {"id": "2" * 64}], states=[{"id": "f" * 64}])
    monkeypatch.setattr(reports, "connect", lambda: ReportConnection(cur))
    definition = reports.make_report("protection")
    ctx = replace(context("protection"), limit=1)
    first = definition.query(ctx)
    assert first["items"] == [{"id": "f" * 64}]
    second = definition.query(replace(ctx, cursor=first["next_cursor"]))
    assert second["items"] == [{"id": "1" * 64}]
    assert cur.calls[-1][1][4] == ""
    third = definition.query(replace(ctx, cursor=second["next_cursor"]))
    assert all(row["id"] != "f" * 64 for row in third["items"])
    assert cur.calls[-1][1][4] == "1" * 64


@pytest.mark.parametrize("change,error", [
    ({"limit": 501}, "limit_invalid"), ({"cursor": "fixture-invalid"}, "cursor_invalid"),
    ({"params": {"period": {"from_utc": "2026-01-01T00:00:00Z", "to_utc": "2026-10-01T00:00:00Z"}}}, "period_invalid"),
    ({"params": {"agent_key": "fixture-other"}}, "scope_denied"),
])
def test_report_rejects_limits_and_scope_before_connect(monkeypatch, change, error):
    monkeypatch.setattr(reports, "connect", lambda: pytest.fail("unexpected database call"))
    with pytest.raises((ValueError, PermissionError), match=error):
        reports.make_report("logons").query(replace(context("logons"), **change))


def test_report_missing_adapter_and_empty_result_are_not_clean_coverage(monkeypatch):
    definition = reports.make_report("logons")
    blocked = definition.query(replace(context("logons"), runtime={}))
    assert blocked["state"] == "error" and blocked["coverage"]["state"] == "blocked"
    monkeypatch.setattr(reports, "connect", lambda: ReportConnection(Cursor()))
    empty = definition.query(context("logons"))
    assert empty["items"] == [] and empty["state"] == "partial"
    assert empty["state_details"]["reason"] == "agent_import_state_unknown"
    with pytest.raises(ValueError, match="scope_invalid"):
        definition.query(context("logons", keys=tuple(f"fixture-{i}" for i in range(501))))


def test_report_cannot_combine_disjoint_field_grants():
    ctx = context("logons")
    grant = ctx.access["reports"][0]
    grant["grants"] = [{"allowed_actions": ["view"], "field_categories": [field],
                        "scope": {"kind": "all"}} for field in reports.FIELDS]
    with pytest.raises(PermissionError, match="field_categories_not_allowed"):
        reports.make_report("logons").query(ctx)


@pytest.mark.parametrize("value", ["0", "-1", "3651", "1.5", "", "false", "９０"])
def test_retention_setting_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="retention_days_invalid"):
        retention_days(value)


def test_retention_setting_default_and_database_override(monkeypatch):
    monkeypatch.setattr(platform_settings, "_stored_row", lambda key: None)
    monkeypatch.delenv("SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS", raising=False)
    assert platform_settings.get_setting(SETTING_KEY) == "90"
    assert next(item for item in platform_settings.list_settings() if item["key"] == SETTING_KEY)["source"] == "default"
    monkeypatch.setenv("SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS", "180")
    assert platform_settings.get_setting(SETTING_KEY) == "180"
    monkeypatch.setattr(platform_settings, "_stored_row", lambda key: {"value": "365"} if key == SETTING_KEY else None)
    assert platform_settings.get_setting(SETTING_KEY) == "365"


def retained_row():
    source_xml = "<Event/>"
    observation = {"source_sha256": hashlib.sha256(source_xml.encode()).hexdigest()}
    return {"id": "1" * 64, "observation": observation,
            "observation_sha256": importer.digest(observation), "source_xml": source_xml,
            "observed_at": NOW - timedelta(days=100), "purge_row_bytes": 256}


def test_retention_deletes_only_after_exact_history_ack_and_uses_configured_cutoff():
    cur = Cursor([retained_row()], settings="180")
    calls = []
    def preserve(row):
        calls.append(row)
        assert not any(sql.startswith("delete") for sql, _ in cur.calls)
        return importer.digest(row)
    outcome = retention.retain_batch(connection(cur), history=SimpleNamespace(preserve=preserve), now=NOW)
    assert outcome["status"] == "success" and outcome["moved"] == 1
    assert outcome["continuation"] is None
    assert outcome["tables"]["sli_plugin_workstations.observations"]["deleted_count"] == 1
    assert outcome["bytes_reclaimed"] == 0
    assert purge_audit.last_purge_runs()["runs"][0]["transaction"] == "caller_owned_unconfirmed"
    selection = next((sql, params) for sql, params in cur.calls if sql.startswith("select observation.*"))
    assert "for update skip locked limit %s" in selection[0]
    assert "family in ('processes','usb')" in selection[0]
    assert selection[1] == (NOW - timedelta(days=180), 50)
    assert calls[0]["source_xml"] == "<Event/>"


def test_retention_missing_or_invalid_history_never_deletes():
    cur = Cursor([retained_row()])
    assert retention.retain_batch(connection(cur), history=None, now=NOW)["status"] == "blocked"
    assert not cur.calls
    with pytest.raises(ValueError, match="history_receipt_mismatch"):
        retention.retain_batch(connection(cur), history=SimpleNamespace(preserve=lambda row: "wrong"), now=NOW)
    assert not any(sql.startswith("delete") for sql, _ in cur.calls)


def test_retention_full_batch_returns_continuation_and_invalid_source_blocks_delete():
    cur = Cursor([retained_row()])
    history = SimpleNamespace(preserve=importer.digest)
    outcome = retention.retain_batch(connection(cur), history=history, now=NOW, limit=1)
    assert outcome["status"] == "partial"
    assert outcome["continuation"]["before_utc"] == (NOW - timedelta(days=90)).isoformat()
    row = retained_row()
    row["source_xml"] = "<Changed/>"
    cur = Cursor([row])
    with pytest.raises(ValueError, match="source_hash_mismatch"):
        retention.retain_batch(connection(cur), history=history, now=NOW)
    assert not any(sql.startswith("delete") for sql, _ in cur.calls)


def test_retention_delete_count_mismatch_requires_core_rollback():
    cur = Cursor([retained_row()])
    cur.rowcount = 0
    with pytest.raises(ValueError, match="workstation_delete_count_mismatch"):
        retention.retain_batch(connection(cur), history=SimpleNamespace(preserve=importer.digest), now=NOW)
    receipt = purge_audit.last_purge_runs()["runs"][0]
    assert receipt["status"] == "blocked"
    assert receipt["reason"] == "workstation_delete_count_mismatch"
    assert receipt["transaction"] == "caller_rollback_required"


def test_retention_delete_readback_mismatch_is_recorded():
    class StaleCursor(Cursor):
        def execute(self, sql, params=()):
            super().execute(sql, params)
            if "workstation_delete_readback" in sql:
                self.one = {"id": params[0]}

    with pytest.raises(ValueError, match="workstation_delete_readback_mismatch"):
        retention.retain_batch(connection(StaleCursor([retained_row()])),
                              history=SimpleNamespace(preserve=importer.digest), now=NOW)
    assert purge_audit.last_purge_runs()["runs"][0]["reason"] == "workstation_delete_readback_mismatch"


def test_retention_observation_hash_mismatch_never_preserves_or_deletes():
    row = retained_row()
    row["observation"]["kind"] = "changed"
    cur = Cursor([row])
    with pytest.raises(ValueError, match="workstation_observation_hash_mismatch"):
        retention.retain_batch(connection(cur), now=NOW,
                              history=SimpleNamespace(preserve=lambda row: pytest.fail("corrupt observation preserved")))
    assert not any(sql.startswith("delete") for sql, _ in cur.calls)
    assert purge_audit.last_purge_runs()["runs"][0]["reason"] == "workstation_observation_hash_mismatch"


def test_usb_internal_storage_and_identity_mismatch_are_not_admitted():
    assert normalizers.new_projection(event_id=410, channel=normalizers.PNP_CHANNEL,
        provider=normalizers.PNP_PROVIDER, event_data={"DeviceId": r"SCSI\fixture-disk", "ClassName": "DiskDrive"}) == {}
    cur = Cursor()
    with pytest.raises(ValueError, match="agent_mismatch"):
        import_workstation_packet(connection(cur), packet(), agent_key="fixture-other",
                                  identity=SimpleNamespace(workstation=lambda conn, key: STATION))
    assert not cur.calls


def test_missing_native_record_id_is_rejected_before_writes():
    cur = Cursor()
    p = packet()
    row = {**p["records"][0]["payload"], "record_id": None}
    with pytest.raises(ValueError, match="record_id_required"):
        importer.project_packet(connection(cur), p, [row], agent_key=STATION.agent_key,
                                identity=SimpleNamespace(workstation=lambda conn, key: STATION))
    assert not cur.calls


@pytest.mark.parametrize("key,entity_id,ad_id", [("", 17, None), ("fixture-key", True, None),
                                               ("fixture-key", 17, 0)])
def test_adapter_identity_requires_an_opaque_key_and_positive_core_ids(key, entity_id, ad_id):
    with pytest.raises(ValueError, match="identity_invalid"):
        Workstation(key, entity_id, ad_id)


def test_manifest_and_navigation_register_four_reports_without_widening_access():
    _registry, owners = nav.load_registry()
    access = {"reports": [{"report_key": "workstations.logons", "allowed": True}]}
    shown = nav.navigation(access)
    assert any(section["id"] == "workstations" for section in shown["sections"])
    assert not any(section["id"] == "workstations" for section in nav.navigation({})["sections"])
    hidden = nav.navigation(access, [{"plugin_id": "sli.workstations", "enabled": False}])
    assert not any(section["id"] == "workstations" for section in hidden["sections"])
    assert all(owners[key]["owner_id"] == "sli.workstations" for key, _ in reports.REPORTS.values())
    registrations = []
    retention.register_jobs(SimpleNamespace(register=lambda **kwargs: registrations.append(kwargs)))
    assert registrations[0]["manifest"]["own_permanent_workers"] is False
    assert list(registrations[0]["handlers"]) == [retention.HANDLER_ID]



def test_agent_identity_is_hidden_but_retained_in_report_details():
    for family in reports.REPORTS:
        definition = reports.make_report(family)
        assert next(c for c in definition.columns if c.key == "host_name").optional is None
        assert next(c for c in definition.columns if c.key == "agent_key").optional is True
        assert definition.row_key == "id"


def test_report_names_enrich_only_authorized_rows_without_changing_evidence(monkeypatch):
    row = {"id": "1" * 64, "agent_key": STATION.agent_key, "observed_at": NOW}
    cur = Cursor([row])
    monkeypatch.setattr(reports, "connect", lambda: ReportConnection(cur))
    seen = []
    def names(cursor, keys):
        seen.append(tuple(keys))
        return {STATION.agent_key: {"name": "pc.example.invalid", "source": "ad_enrollment"}}
    monkeypatch.setattr(reports, "read_agent_name_details", names)
    outcome = reports.make_report("logons").query(context("logons"))
    assert seen == [(STATION.agent_key,)]
    assert outcome["items"] == [{**row, "host_name": "pc.example.invalid", "host_name_source": "ad_enrollment"}]
    assert outcome["state"] == "partial"


@pytest.mark.parametrize("family", list(reports.REPORTS))
@pytest.mark.parametrize("enrolled,claim,expected,source", [
    (None, "PC-01.example.invalid", "PC-01.example.invalid", "agent_reported"),
    ("AD-PC.example.invalid", "claim.example.invalid", "AD-PC.example.invalid", "ad_enrollment"),
    (None, "<script>bad</script>", None, "unknown"),
])
def test_station_reports_use_registered_name_with_provenance_after_scope(monkeypatch, family, enrolled, claim, expected, source):
    class NamedCursor(Cursor):
        def fetchall(self):
            if "enrolled.host_name as enrolled_name" in self.sql:
                assert "registration_host_name" in self.sql
                assert self.calls[-1][1] == ([STATION.agent_key],)
                return [{"agent_id": STATION.agent_key, "enrolled_name": enrolled,
                         "registration_host_name": claim, "assigned_modules": []}]
            return super().fetchall()
    row = {"id": "1" * 64, "agent_key": STATION.agent_key, "entity_id": 17, "ad_computer_id": None}
    cur = NamedCursor([row])
    monkeypatch.setattr(reports, "connect", lambda: ReportConnection(cur))
    ctx = context(family)
    ctx.runtime["workstation_history_adapter"] = None
    outcome = reports.make_report(family).query(ctx)
    assert outcome["items"][0]["host_name"] == expected
    assert outcome["items"][0]["host_name_source"] == source
    assert outcome["items"][0]["agent_key"] == STATION.agent_key
    assert outcome["items"][0]["ad_computer_id"] is None


@pytest.mark.parametrize("family", list(reports.REPORTS))
def test_legacy_station_name_comes_from_bounded_event_metadata_in_every_report(monkeypatch, family):
    class EventNameCursor(Cursor):
        def fetchall(self):
            if self.sql.startswith("select wanted.agent_key, recent.source_xml"):
                assert self.calls[-1][1] == ([STATION.agent_key],)
                return [{"agent_key": STATION.agent_key, "source_xml":
                    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                    '<System><Computer>PC-LEGACY.example.invalid</Computer></System></Event>'}]
            return super().fetchall()
    cur = EventNameCursor([{"id": "1" * 64, "agent_key": STATION.agent_key}])
    monkeypatch.setattr(reports, "connect", lambda: ReportConnection(cur))
    outcome = reports.make_report(family).query(context(family))
    assert outcome["items"][0]["host_name"] == "PC-LEGACY.example.invalid"
    assert outcome["items"][0]["host_name_source"] == "event_reported"
    assert "source_xml" not in outcome["items"][0]


@pytest.mark.parametrize("computers,expected", [
    (["PC-01", "pc-01"], "PC-01"), (["PC-01", "PC-02"], None),
    (["<script>"], None), (["00000000-0000-4000-8000-000000000001"], None),
])
def test_legacy_event_name_never_resolves_conflicts_or_invalid_hostnames(monkeypatch, computers, expected):
    from xml.sax.saxutils import escape
    monkeypatch.setattr(reports, "read_agent_name_details", lambda cur, keys: {})
    cur = SimpleNamespace(execute=lambda *args: None, fetchall=lambda: [
        {"agent_key": STATION.agent_key, "source_xml":
         '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
         f'<System><Computer>{escape(name)}</Computer></System></Event>'} for name in computers
    ] + [{"agent_key": "foreign-agent", "source_xml": '<Event/>'}])
    assert reports._report_names(cur, [STATION.agent_key]).get(STATION.agent_key, {}).get("name") == expected


@pytest.mark.parametrize("xml", ['<!DOCTYPE Event><Event/>', '<Event>', 'x' * 1048577],
                         ids=["dtd", "malformed", "oversize"])
def test_unsafe_optional_event_name_does_not_break_station_reports(monkeypatch, xml):
    monkeypatch.setattr(reports, "read_agent_name_details", lambda cur, keys: {})
    cur = SimpleNamespace(execute=lambda *args: None, fetchall=lambda: [
        {"agent_key": STATION.agent_key, "source_xml": xml}])
    assert reports._report_names(cur, [STATION.agent_key]) == {}
