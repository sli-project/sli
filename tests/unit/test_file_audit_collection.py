"""Synthetic local Security capture; no Windows service or database."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from sli_agent.envelope import canonical
from sli_agent.modules import configured_modules
from tests.unit.test_file_audit_contracts import AGENT, settings

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_initial_window_is_frozen_on_empty_read_and_survives_restart():
    cursors = []
    config = {**settings(), 'initial_read_hours': 0}
    module = collector(config, reader=lambda _c, cursor, _n: cursors.append(cursor) or [])
    first = module.collect(now=NOW)
    assert json.loads(first.cursor_after['token'])['since_utc'] == NOW.isoformat()
    from datetime import timedelta
    module.collect({'generation': first.generation, 'cursor_after': first.cursor_after},
                   now=NOW + timedelta(minutes=10))
    assert cursors[1]['since_utc'] == cursors[0]['since_utc']


def test_proven_journal_gap_restarts_with_bounded_window():
    from sli_agent.file_audit_journal import JournalGap
    first = collector(reader=lambda *_: [(xml(1), 'b1')], path_check=lambda *_: 'file').collect(now=NOW)
    def gap(*_):
        raise JournalGap()
    module = collector({**settings(), 'initial_read_hours': 0}, reader=gap)
    reset = module.collect({'generation': first.generation, 'cursor_after': first.cursor_after}, now=NOW)
    assert reset.continuity_state == 'gap' and reset.lost_count is None
    assert json.loads(reset.cursor_after['token'])['since_utc'] == NOW.isoformat()
    assert reset.generation != first.generation


def xml(record, event=4663, *, path=r"C:\synthetic\item", mask="0x2", keywords="0x8020000000000000", **fields):
    from xml.sax.saxutils import escape
    data = {"ObjectName": path, "SubjectUserSid": "S-1-5-18", "SubjectLogonId": "0x10",
            "ProcessId": "0x20", "HandleId": "0x30", "AccessMask": mask, **fields}
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{event}</EventID><Version>0</Version>'
            f'<Keywords>{keywords}</Keywords><EventRecordID>{record}</EventRecordID><Channel>Security</Channel>'
            '<TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Computer>synthetic</Computer></System><EventData>'
            + ''.join(f'<Data Name="{key}">{escape(value)}</Data>' for key, value in data.items())
            + '</EventData></Event>')


def collector(config=None, **kwargs):
    from sli_agent.file_audit_collection import FileAuditModule
    return FileAuditModule(AGENT, config or settings(), **kwargs)


def test_read_diagnostics_reach_independent_health_before_packet_delivery(tmp_path):
    from sli_agent.eventlog_health import EventLogHealth
    from sli_collect.eventlog_diagnostics import EventLogReadError, diagnostic
    details = diagnostic(OSError("synthetic-private-path"), "Security",
                         {"record_id": None, "bookmark": ""}, "query")

    def failed(*_):
        raise EventLogReadError("file_audit_read_failed", details)

    module = collector(reader=failed)
    sample = module.collect(now=NOW)
    assert sample.payload["context"]["read_error"] == "file_audit_read_failed"
    health = EventLogHealth(tmp_path)
    health.observe(module, 1)
    assert health.observations()[0]["error"] == details
    assert "synthetic-private" not in health.path.read_text()
    module.reader = lambda *_: []
    module.collect(now=NOW)
    health.observe(module, 1)
    assert health.observations()[0]["error"] is None


def test_journal_gap_is_visible_independently_of_the_gap_packet():
    from sli_collect.eventlog_diagnostics import validate_observations
    from sli_agent.file_audit_journal import JournalGap

    def gap(*_):
        raise JournalGap()

    module = collector(reader=gap)
    module.collect(now=NOW)
    row = validate_observations([{**module.read_observation, "policy_revision": 1}])[0]
    assert row["error"]["exception_class"] == "JournalGap"
    assert row["error"]["stage"] == "anchor"


def test_explicit_assignment_enables_local_collector_without_audit_writes():
    modules = configured_modules(SimpleNamespace(collection_enabled=False), AGENT,
        [{"module_id": "sli.file-audit", "enabled": True, "config": settings()}])
    assert [m.module_id for m in modules] == ["sli.heartbeat", "sli.file-audit"]


def test_security_channel_has_one_agent_reader():
    with pytest.raises(ValueError, match="channel_owner_conflict"):
        configured_modules(SimpleNamespace(collection_enabled=False), AGENT,
            [{"module_id": "sli.file-audit", "enabled": True, "config": settings()},
             {"module_id": "sli.workstations", "enabled": True, "config": {}}])


@pytest.mark.parametrize("reverse", [False, True])
def test_pack_filtered_dc_reader_can_coexist_with_file_audit(reverse):
    from sli_agent.file_audit_policy import EVENT_IDS, OPTIONAL_EVENT_IDS
    assignments = [
        {"module_id": "sli.file-audit", "enabled": True, "config": settings()},
        {"module_id": "sli.windows.ad-dc", "enabled": True,
         "config": {"source_name": "synthetic", "connect_address": "synthetic"}},
    ]
    modules = configured_modules(SimpleNamespace(collection_enabled=False), AGENT,
                                 assignments[::-1] if reverse else assignments)
    assert {module.module_id for module in modules} == {"sli.heartbeat", "sli.file-audit", "sli.windows.ad-dc"}
    dc = next(module for module in modules if module.module_id == "sli.windows.ad-dc")
    assert not {identity[2] for identity in dc.identities} & set(EVENT_IDS + OPTIONAL_EVENT_IDS)


def test_scope_filter_cursor_and_read_profile_preserve_handle_chain():
    rows = [(xml(1, path=r"C:\synthetic-other\item"), "b1"), (xml(2, mask="0x1"), "b2"),
            (xml(3, 4660, path=""), "b3"), (xml(4, 5145, path="", ShareName=r"\\*\other",
             ShareLocalPath=r"C:\synthetic", RelativeTargetName="item"), "b4")]
    sample = collector(reader=lambda *_: rows, path_check=lambda *_: "file").collect(now=NOW)
    assert [r["record_id"] for r in sample.payload["records"]] == [1, 2, 3]
    assert r"synthetic-other" not in sample.payload["records"][0]["payload"]["xml"]
    assert sample.filtered_count == 1 and sample.cursor_after != sample.cursor_before
    assert sample.payload["header"]["cursor"]["last_record_id"] == 4


def test_reparse_rejection_and_traversal_do_not_disclose_paths():
    def blocked(*_):
        raise ValueError("synthetic-private-diagnostic")
    sample = collector(reader=lambda *_: [(xml(1), "b1"), (xml(2, path=r"C:\synthetic\..\other"), "b2")],
                       path_check=blocked).collect(now=NOW)
    assert len(sample.payload["records"]) == 1
    assert "other" not in sample.payload["records"][0]["payload"]["xml"]
    assert sample.lost_count == 1 and sample.filtered_count == 0
    assert b"synthetic-private" not in canonical(sample.payload)


def test_bytes_stop_before_advancing_unspooled_evidence():
    config = {**settings(), "max_bytes": 3000}
    rows = [(xml(i, ProcessName="x" * 300), f"b{i}") for i in range(1, 4)]
    sample = collector(config, reader=lambda *_: rows, path_check=lambda *_: "file").collect(now=NOW)
    assert 0 < len(sample.payload["records"]) < 3
    assert len(canonical(sample.payload)) <= config["max_bytes"]
    assert sample.payload["header"]["cursor"]["last_record_id"] == sample.payload["records"][-1]["record_id"]


def test_read_error_keeps_cursor_and_reports_unknown_loss():
    def failure(*_):
        raise RuntimeError("synthetic-private-diagnostic")
    sample = collector(reader=failure).collect(now=NOW)
    assert sample.lost_count is None and sample.continuity_state == "gap"
    assert sample.payload["context"]["read_error"] == "file_audit_read_failed"
    assert sample.payload["records"] == []


@pytest.mark.parametrize("modules", [[{"module_id": "sli.file-audit", "enabled": 1}],
    [{"module_id": "sli.file-audit", "enabled": True, "config": settings()}] * 2])
def test_invalid_assignment_is_rejected(modules):
    with pytest.raises(ValueError):
        configured_modules(SimpleNamespace(collection_enabled=False), AGENT, modules)


def test_native_reader_filters_provider_event_ids_before_rendering(monkeypatch):
    from sli_agent.file_audit_collection import read_local
    calls = []
    monkeypatch.setattr("sli_collect.bookmarked_eventlog.read_local", lambda *args, **kwargs: calls.append(kwargs) or [])
    assert read_local("Security", {"record_id": None, "bookmark": ""}, 32) == []
    selector = calls[0]["system_filter"]
    assert "Microsoft-Windows-Security-Auditing" in selector
    assert "EventID=4660" in selector and "EventID=4624" in selector
    assert "Microsoft-Windows-Eventlog" in selector and "EventID=1102" in selector


def test_source_name_is_owner_policy_and_collection_never_uses_xml_computer():
    sample = collector({**settings(), "source_name": "synthetic-source"},
                       reader=lambda *_: [(xml(1), "b1")], path_check=lambda *_: "file").collect(now=NOW)
    assert sample.payload["header"]["source"] == "synthetic-source"
    assert sample.payload["records"][0]["payload"]["computer_name"] == "synthetic-source"


def test_native_path_check_rejects_reparse_and_requires_existing_root(monkeypatch):
    import sys

    from sli_agent.file_audit_collection import check_path
    constants = SimpleNamespace(FILE_SHARE_READ=1, FILE_SHARE_WRITE=2,
        FILE_SHARE_DELETE=4, OPEN_EXISTING=3, FILE_FLAG_BACKUP_SEMANTICS=0x02000000,
        FILE_ATTRIBUTE_REPARSE_POINT=0x400,
        FILE_ATTRIBUTE_DIRECTORY=0x10)
    handles, missing, reparse = [], set(), set()
    class Handle:
        def __init__(self, path):
            self.path, self.closed = path, False
        def Close(self):
            self.closed = True
    def open_path(path, access, share, security, disposition, flags, template):
        assert access == 128
        assert flags & 0x00200000
        if path in missing:
            error = OSError("synthetic-private-diagnostic")
            error.winerror = 3
            raise error
        handle = Handle(path)
        handles.append(handle)
        return handle
    monkeypatch.setitem(sys.modules, "win32con", constants)
    monkeypatch.setitem(sys.modules, "ntsecuritycon", SimpleNamespace(FILE_READ_ATTRIBUTES=128))
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(FILE_FLAG_OPEN_REPARSE_POINT=0x00200000, CreateFile=open_path,
        GetFileInformationByHandle=lambda handle: (0x400 if handle.path in reparse else 0x10,)))
    root, target = r"C:\synthetic", r"C:\synthetic\item"
    reparse.add(root)
    with pytest.raises(ValueError, match="reparse_point"):
        check_path(target, root)
    reparse.clear()
    missing.add(target)
    assert check_path(target, root) == "unknown"
    missing.add(root)
    with pytest.raises(RuntimeError, match="path_unavailable"):
        check_path(target, root)
    assert all(handle.closed for handle in handles)


def test_source_xml_drops_unreviewed_system_and_event_data(monkeypatch):
    raw = xml(1, UnreviewedField="synthetic-private-diagnostic").replace(
        "</System>", '<Unreviewed>synthetic-private-diagnostic</Unreviewed></System>')
    sample = collector(reader=lambda *_: [(raw, "b1")], path_check=lambda *_: "file").collect(now=NOW)
    assert b"synthetic-private" not in canonical(sample.payload)


def test_file_spool_budget_pauses_capture_at_strictest_limit():
    from sli_agent.policies import spool_limit
    config = SimpleNamespace(spool_max_bytes=8 * 1024 * 1024)
    module = collector({**settings(), "spool_bytes": 1024 * 1024})
    assert spool_limit(config, [module], None) == 1024 * 1024
    assert spool_limit(config, [module], {"spool_max_bytes": 512 * 1024}) == 512 * 1024
    assert spool_limit(config, [], None) == config.spool_max_bytes


def test_close_events_are_collected_only_in_optional_profile():
    rows = [(xml(1, 4658, path=""), "b1")]
    default = collector(reader=lambda *_: rows).collect(now=NOW)
    optional = collector({**settings(), "optional_events": True}, reader=lambda *_: rows).collect(now=NOW)
    assert default.payload["records"] == [] and default.filtered_count == 1
    assert len(optional.payload["records"]) == 1


@pytest.mark.parametrize("important", [False, True])
def test_both_profiles_filter_sibling_sysvol_and_traversal_without_losing_denials(important):
    config = settings()
    config["roots"][0]["important"] = important
    def smb(record, share, path, relative, keywords="0x8020000000000000"):
        return xml(record, 5145, path="", ShareName="\\\\*\\" + share,
                   ShareLocalPath=path, RelativeTargetName=relative, keywords=keywords)
    rows = [(smb(1, "synthetic", r"C:\synthetic-other", "item"), "b1"),
            (smb(2, "SYSVOL", r"C:\synthetic", "item"), "b2"),
            (smb(3, "synthetic", r"C:\synthetic", r"..\other"), "b3"),
            (smb(4, "synthetic", r"C:\synthetic", "item"), "b4"),
            (smb(5, "synthetic", r"C:\synthetic", "item", "0x8010000000000000"), "b5")]
    sample = collector(config, reader=lambda *_: rows, path_check=lambda *_: "file").collect(now=NOW)
    assert [r["record_id"] for r in sample.payload["records"]] == ([4, 5] if important else [5])
    assert sample.filtered_count == (3 if important else 4) and sample.lost_count == 0
    assert sample.payload["header"]["cursor"]["last_record_id"] == 5


@pytest.mark.parametrize("record", [1, 1000, 10000])
def test_deferred_clear_event_does_not_mark_the_previous_packet_as_a_gap(record):
    clear = xml(record + 1, 1102, path="").replace("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Eventlog")
    raw = xml(record)
    initial = collector(reader=lambda *_: [(raw, "b1")], path_check=lambda *_: "file").collect(now=NOW)
    # Admission budgets the packet before advancing the cursor to the event.
    initial.payload["header"]["cursor"]["last_record_id"] = None
    budget = len(canonical(initial.payload)) + 128
    sample = collector({**settings(), "max_bytes": budget},
        reader=lambda *_: [(raw, "b1"), (clear, "b2")], path_check=lambda *_: "file").collect(now=NOW)
    assert [row["record_id"] for row in sample.payload["records"]] == [record]
    assert len(canonical(sample.payload)) <= budget
    assert sample.payload["context"]["read_error"] is None and sample.continuity_state == "not_proven"
    assert sample.lost_count == 0
    checkpoint = json.loads(sample.cursor_after["token"])
    assert checkpoint["record_id"] == record and checkpoint["bookmark"] == "b1"
    resumed = collector(reader=lambda *_: [(clear, "b2")]).collect(
        {"generation": sample.generation, "cursor_after": sample.cursor_after}, now=NOW)
    assert [row["record_id"] for row in resumed.payload["records"]] == [record + 1]
    assert resumed.payload["context"]["read_error"] == "file_audit_journal_gap"
    assert resumed.continuity_state == "gap" and resumed.lost_count is None
