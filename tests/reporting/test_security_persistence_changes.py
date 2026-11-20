from datetime import datetime, timedelta, timezone

import pytest

from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.reporting.v2.reports import security_events
from server.sli.reports import security_persistence_changes as reporting

START = datetime(2026, 10, 1, tzinfo=timezone.utc)
SID = "S-1-5-21-100-200-300-1001"


def event(identifier, code=4697, minute=0, **fields):
    return {"event_db_id": identifier, "event_id": code, "domain_id": 7, "server_id": 11,
            "dc": "synthetic-dc", "time_created_utc": START + timedelta(minutes=minute),
            "normalized_event_id": str(identifier), "service_name": "synthetic-service",
            "service_file": "C:\\synthetic\\agent.exe", "service_account": "synthetic-account",
            "service_start_type": "2", "process_user_sid": SID, "process_user_name": "synthetic-actor",
            **fields}


def access(domain=7, fields=("security", "technical", "raw_evidence"), actions=("view",)):
    return {"platform_owner": False, "capabilities": ["events.view"], "capability_policies": [],
            "reports": [{"report_key": "security.events.chains", "allowed": True, "allowed_actions": list(actions),
                         "grants": [{"allowed_actions": list(actions), "field_categories": list(fields),
                                     "scope": {"kind": "domain", "ids": [domain]}}]}]}


def arguments(**overrides):
    return {"domain_id": 7, "time_from": START.isoformat(), "time_to": (START + timedelta(hours=1)).isoformat(),
            "limit": 100, **overrides}


class FakeCursor:
    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def cursor(self):
        return self

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return {"source_present": True}


def test_report_source_discovery_includes_domains_with_only_service_or_task_events(monkeypatch):
    cur = FakeCursor([])
    monkeypatch.setattr(reporting.security, "_connect", lambda: cur)
    assert reporting.security._has_security_event_source(7)
    sql, params = cur.calls[-1]
    assert set(reporting.EVENT_IDS) <= set(params[1])
    assert "System" in params and "Service Control Manager" in params
    assert "Security" in params and "server.role='domain_controller'" in sql


def test_exact_install_pair_is_linked_once_and_previous_is_observed():
    events = [event(1), event(2, 7045, process_user_sid=None, process_user_name=None),
              event(3, minute=10, service_file="C:\\synthetic\\new.exe")]
    rows = reporting.shape_history([*reversed(events), events[0]])
    assert len(rows) == 2
    latest, first = rows
    assert first["event_ids"] == [1, 2] and first["linked_event"] == 2
    assert first["quality"] == "exact_link" and first["previous"] is None
    assert latest["previous"]["action"] == events[0]["service_file"]
    assert latest["frequency"] == first["frequency"] == 2
    assert latest["first_seen"] == "2026-10-01T00:00:00Z"
    assert latest["last_seen"] == "2026-10-01T00:10:00Z"
    assert len(first["observations"]) == 2
    assert first["observations"][1]["initiator_sid"] is None
    assert first["initiator_quality"] == "partially_known"


@pytest.mark.parametrize("different", [
    {"minute": 1}, {"server_id": 12}, {"domain_id": 8}, {"service_name": "other"},
    {"service_file": "other"}, {"service_account": "other"}, {"service_start_type": "3"},
    {"service_account": None}, {"normalized_event_id": None},
])
def test_nearby_incomplete_or_different_installs_are_never_linked(different):
    rows = reporting.shape_history([event(1), event(2, 7045, **different)])
    assert len(rows) == 2 and all(row["linked_event"] is None for row in rows)


def test_ambiguous_pairs_same_code_and_truncated_slices_are_not_linked():
    assert len(reporting.shape_history([event(1), event(2), event(3, 7045)])) == 3
    assert len(reporting.shape_history([event(1), event(2, 7045)], truncated=True)) == 2
    rows = reporting.shape_history([event(1), event(2, service_file="other"), event(3, minute=1)])
    assert rows[0]["previous"] is None
    assert rows[1]["quality"] == "ambiguous_order"


def test_unknown_objects_and_missing_semantics_do_not_share_history():
    rows = reporting.shape_history([event(1, service_name=None), event(2, service_name=None),
                                   event(3, normalized_event_id=None), event(4, minute=1)])
    assert all(row["frequency"] == 1 and row["previous"] is None for row in rows)
    assert {row["quality"] for row in rows} == {"unknown_object", "missing_semantics", "exact_object"}


TASK = '<Task xmlns="urn:synthetic"><Principals><Principal><UserId>synthetic-run-as</UserId></Principal></Principals><Actions><Exec><Command>C:\\synthetic\\task.exe</Command><Arguments>--check</Arguments></Exec></Actions></Task>'


def task(identifier, code, minute, content=TASK, **fields):
    return event(identifier, code, minute, task_name="\\synthetic-task", task_content=content,
                 task_change={4698: "created", 4699: "deleted", 4700: "enabled", 4701: "disabled", 4702: "updated"}[code], **fields)


def test_task_history_extracts_all_actions_run_as_and_preserves_missing_values():
    rows = reporting.shape_history([task(1, 4698, 0), task(2, 4702, 5, TASK.replace("--check", "--new")),
                                   task(3, 4701, 10, None), task(4, 4699, 15, None)])
    assert len(rows) == 4 and all(row["frequency"] == 4 for row in rows)
    assert rows[2]["previous"]["action"] == "C:\\synthetic\\task.exe --check"
    assert rows[2]["run_as"] == "synthetic-run-as"
    assert rows[1]["action"] is None and rows[0]["previous"]["action"] is None
    assert {row["change"] for row in rows} == {"created", "updated", "disabled", "deleted"}
    assert all(row["task_content"] is None for row in rows)


@pytest.mark.parametrize("content", ["<Task>", '<!DOCTYPE Task [<!ENTITY x "unsafe">]><Task>&x;</Task>', "x" * 8193])
def test_invalid_task_xml_stays_unknown_without_dumping_content(content):
    row = reporting.shape_history([task(1, 4698, 0, content)])[0]
    assert row["action"] is None and row["run_as"] is None and row["task_content"] is None


def test_task_actions_do_not_fall_back_to_truncated_xml_and_keep_multiple_actions():
    row = reporting.shape_history([task(1, 4698, 0, None, task_action="<Task>truncated")])[0]
    assert row["action"] is None
    content = TASK.replace("</Actions>", "<Exec><Command>synthetic-second</Command></Exec></Actions>")
    row = reporting.shape_history([task(2, 4698, 0, content)])[0]
    assert row["action"] == "C:\\synthetic\\task.exe --check; synthetic-second"


def test_unknown_initiators_in_linked_evidence_and_missing_semantics_remain_explicit(monkeypatch):
    events = [event(1), event(2, 7045, process_user_sid=None, process_user_name=None)]
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor(events))
    raw = reporting.get_persistence_changes(access(), **arguments())
    assert raw["totals"]["unknown_initiator"] == 1 and raw["rows"][0]["frequency"] == 1
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor([event(3, normalized_event_id=None)]))
    raw = reporting.get_persistence_changes(access(), **arguments())
    assert raw["state"] == "partial" and raw["coverage"]["missing_current_semantics"] == 1
    assert raw["totals"]["new_services"] == 0
    monkeypatch.setattr(reporting, "MAX_SOURCE_ROWS", 1)
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor([event(3, normalized_event_id=None), event(4)]))
    raw = reporting.get_persistence_changes(access(), **arguments())
    assert raw["coverage"]["source_truncated"] and raw["totals"]["new_services"] == 0


def test_filters_keep_previous_values_and_frequency_from_full_object_history():
    events = [task(1, 4698, 0), task(2, 4702, 5, TASK.replace("--check", "--new"))]
    rows = reporting.shape_history(events, object_type="task", path="--new", initiator=SID, change="updated", max_frequency=2)
    assert len(rows) == 1 and rows[0]["frequency"] == 2 and rows[0]["previous"]["action"].endswith("--check")
    assert reporting.shape_history(events, max_frequency=1) == []
    assert reporting.shape_history(events, source="other") == []
    assert reporting.shape_history(events, object_type="service") == []


def test_reader_is_bounded_and_uses_correct_provider_channel_and_current_semantics():
    cur = FakeCursor([event(1), event(2)])
    rows, cut = reporting._read_events(cur, domain_id=7, start=START, end=START + timedelta(hours=1), limit=1)
    sql, params = cur.calls[0]
    assert len(rows) == 1 and cut
    assert "event.domain_id=%s" in sql and "event.event_id=any(%s)" in sql
    assert "event.time_created_utc>=%s and event.time_created_utc<%s" in sql
    assert "server.role='domain_controller'" in sql and "channel.value=%s" in sql and "provider.value=%s" in sql
    assert "normalized.semantic_contract_version=%s" in sql
    assert "normalized.normalizer_id=%s and normalized.normalizer_version=%s" in sql
    assert "normalized.processing_status='normalized'" in sql and "limit %s" in sql
    assert params[:3] == [reporting.SEMANTIC_CONTRACT_VERSION, reporting.NORMALIZER_ID, reporting.NORMALIZER_VERSION]
    assert params[3:7] == [7, [4697, 4698, 4699, 4700, 4701, 4702, 7045], START, START + timedelta(hours=1)]
    assert "System" in params and "Service Control Manager" in params and "Security" in params
    assert params[-1] == 2


@pytest.mark.parametrize("decision", [{}, access(8), access(fields=("security",))])
def test_denies_before_database_read(monkeypatch, decision):
    monkeypatch.setattr(reporting.security, "_connect", lambda: pytest.fail("unauthorized read"))
    assert reporting.get_persistence_changes(decision, **arguments()) == {"state": "denied", "rows": []}


@pytest.mark.parametrize("overrides", [{"time_to": START.isoformat()}, {"time_to": (START + timedelta(days=32)).isoformat()},
                                      {"limit": 501}, {"domain_id": 0}, {"max_frequency": 0},
                                      {"object_type": "invalid"}, {"change": "invalid"}, {"action": "delete"}])
def test_invalid_filters_rejected_before_read(monkeypatch, overrides):
    monkeypatch.setattr(reporting.security, "_connect", lambda: pytest.fail("invalid read"))
    with pytest.raises(ValueError):
        reporting.get_persistence_changes(access(), **arguments(**overrides))


def test_service_metrics_coverage_limits_and_empty_window(monkeypatch):
    cur = FakeCursor([event(1), event(2, 7045), event(3, minute=10, service_file="other"),
                      task(4, 4698, 20, process_user_sid=None, process_user_name=None)])
    monkeypatch.setattr(reporting.security, "_connect", lambda: cur)
    raw = reporting.get_persistence_changes(access(), **arguments(limit=1))
    assert raw["state"] == "partial" and raw["coverage"]["rows_truncated"]
    assert raw["totals"] == {"new_services": 1, "new_tasks": 1, "changed_actions": 1, "rare_paths": 3,
                             "repeated_objects": 1, "unknown_initiator": 1}
    assert raw["filtered_count"] == 3 and len(raw["rows"]) == 1
    assert raw["window"]["idea_key"] == "security.persistence-changes"
    assert cur.calls[:2] == [("set transaction read only", None), ("set local statement_timeout='3000ms'", None)]
    monkeypatch.setattr(reporting, "MAX_SOURCE_ROWS", 1)
    raw = reporting.get_persistence_changes(access(), **arguments())
    assert raw["coverage"]["source_truncated"] and raw["state"] == "partial"
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor([]))
    raw = reporting.get_persistence_changes(access(), **arguments())
    assert raw["state"] == "empty" and raw["coverage"]["completeness"] == "not_proven"


def test_tab_dispatch_metadata_and_export_use_own_query(monkeypatch):
    params, _ = parse_params(security_events.REPORT, {"domain": ["7"], "tab": ["persistence-changes"]}, now=START)
    monkeypatch.setattr(security_events, "get_security_events_report", lambda *_a, **_kw: pytest.fail("main query"))
    monkeypatch.setattr(security_events, "_domain_options", lambda _access: [])
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor([event(1)]))
    ctx = QueryContext(access=access(actions=("view", "export")), params=params, domain_ids=None, action="view",
                       cursor=None, limit=100, timezone="UTC", tab="persistence-changes")
    raw = security_events._query(ctx)
    assert raw["report_key"] == "security.events.chains" and raw["items"] == []
    assert len(raw["collections"]["persistence_changes"]) == 1 and len(raw["metrics"]) == 6
    tab = next(view for view in security_events.REPORT.views if view.key == ctx.tab)
    assert tab.source == "persistence_changes" and tab.kind == "table"
    assert {col.key for col in tab.columns} >= {"dc", "object", "change", "action", "run_as", "initiator", "first_seen",
                                              "last_seen", "frequency", "previous_value", "evidence"}
    assert next(col for col in tab.columns if col.key == "event_db_id").link == "/app/events/{event_db_id}"
    assert any(col.optional for col in tab.columns)
    body, meta = security_events._export(ctx)
    assert "synthetic-service" in body and meta["rows"] == 1
    denied = QueryContext(**{**ctx.__dict__, "access": access(actions=("view",))})
    with pytest.raises(PermissionError):
        security_events._export(denied)
