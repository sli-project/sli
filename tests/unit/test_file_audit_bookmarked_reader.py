"""Bounded Windows query selectors with fake native handles."""
import sys
from types import SimpleNamespace

from sli_collect import bookmarked_eventlog


def test_dc_missing_bookmark_recovery_keeps_record_bound_without_reapplying_live_time_window(monkeypatch):
    from sli_agent.ad_dc import read_local
    from tests.unit.test_sli_agent_ad_dc import xml

    class NativeError(Exception):
        def __init__(self, code):
            self.winerror = code
    class Handle:
        closed = False
        def Close(self):
            self.closed = True
    handles, selectors = [], []
    failure_code = [1168]
    def handle(*_):
        value = Handle()
        handles.append(value)
        return value
    def query(_api, _session, _channel, selector):
        selectors.append(selector)
        return handle()
    def seek(*_a, **_k):
        raise NativeError(failure_code[0])
    monkeypatch.setattr(bookmarked_eventlog, "query_event_source", query)
    monkeypatch.setattr(bookmarked_eventlog, "render_event_source", lambda *_:
        xml(4624, 9).replace("2026-10-07T00:00:00Z", "2026-10-06T23:00:00Z"))
    monkeypatch.setitem(sys.modules, "win32evtlog", SimpleNamespace(
        EvtCreateBookmark=handle, EvtSeek=seek, EvtSeekRelativeToBookmark=1, EvtSeekStrict=2,
        EvtNext=lambda *_: [handle()], EvtUpdateBookmark=lambda *_: None,
        EvtRender=lambda *_: "bookmark-9", EvtRenderBookmark=1, error=NativeError))
    cursor = {"record_id": 7, "bookmark": "bookmark-7", "generation": "fixture",
              "since_utc": "2026-10-07T00:00:00Z"}
    rows = read_local("Security", cursor, 2)
    assert isinstance(rows, bookmarked_eventlog.BookmarkRecoveryBatch) and len(rows) == 1
    assert len(selectors) == 2
    assert "EventRecordID=7" in selectors[0]
    assert "EventRecordID > 7" in selectors[1]
    assert all("EventID" in selector for selector in selectors)
    assert cursor["bookmark"] == "bookmark-7" and "since_utc" in cursor
    assert all(value.closed for value in handles)

    # History's fixed upper bound survives the same missing-anchor recovery.
    selectors.clear()
    historical = {**cursor, "before_utc": "2026-10-08T00:00:00Z"}
    del historical["since_utc"]
    read_local("Security", historical, 2)
    assert "TimeCreated[@SystemTime < '2026-10-08T00:00:00Z']" in selectors[-1]
    assert "EventRecordID > 7" in selectors[-1]
    assert all(value.closed for value in handles)

    # Access failures never become a recovery or consume a bookmark.
    import pytest
    selectors.clear()
    failure_code[0] = 5
    with pytest.raises(RuntimeError, match="agent_ad_dc_read_failed") as error:
        read_local("Security", cursor, 2)
    assert error.value.diagnostic["winerror"] == 5
    assert error.value.diagnostic["stage"] == "seek"
    assert len(selectors) == 1 and "EventRecordID=7" in selectors[0]
    assert cursor["record_id"] == 7
    assert all(value.closed for value in handles)


def test_system_filter_keeps_cursor_bound_and_default_reader_unchanged(monkeypatch):
    class Empty(Exception):
        winerror = 259
    class Handle:
        closed = False
        def Close(self):
            self.closed = True
    handles, selectors = [], []
    def query(_api, session, channel, selector):
        assert session is None and channel == "Security"
        selectors.append(selector)
        handle = Handle()
        handles.append(handle)
        return handle
    def bookmark(_value):
        handle = Handle()
        handles.append(handle)
        return handle
    def empty(*_args):
        assert _args[2] == (5000 if 'TimeCreated[' in selectors[-1] else 1000)
        raise Empty()
    monkeypatch.setattr(bookmarked_eventlog, "query_event_source", query)
    monkeypatch.setitem(sys.modules, "win32evtlog", SimpleNamespace(
        EvtCreateBookmark=bookmark, EvtNext=empty, error=Empty))
    cursor = {"record_id": 5, "bookmark": ""}
    assert bookmarked_eventlog.read_local("Security", cursor, 32, system_filter="EventID=4660") == []
    assert selectors[-1] == "*[System[(EventID=4660) and EventRecordID > 5]]"
    assert bookmarked_eventlog.read_local("Security", cursor, 32) == []
    assert selectors[-1] == "*[System[EventRecordID > 5]]"
    assert all(handle.closed for handle in handles)
    bounded = {**cursor, "since_utc": "2026-10-06T00:00:00+00:00"}
    assert bookmarked_eventlog.read_local("Security", bounded, 32) == []
    assert selectors[-1] == "*[System[TimeCreated[@SystemTime >= '2026-10-06T00:00:00Z'] and EventRecordID > 5]]"
    historical = {"record_id": None, "bookmark": "", "before_utc": "2026-10-06T00:00:00Z"}
    assert bookmarked_eventlog.read_local("Security", historical, 4) == []
    assert selectors[-1] == "*[System[TimeCreated[@SystemTime < '2026-10-06T00:00:00Z']]]"
    assert all(handle.closed for handle in handles)


def test_reused_record_id_with_different_anchor_fails_before_capture(monkeypatch):
    from sli_agent.file_audit_journal import anchor_hash
    from tests.unit.test_file_audit_collection import xml
    class Handle:
        closed = False
        def Close(self):
            self.closed = True
    handles = [Handle(), Handle(), Handle()]
    monkeypatch.setattr(bookmarked_eventlog, "query_event_source", lambda *_: handles[0])
    monkeypatch.setattr(bookmarked_eventlog, "render_event_source", lambda *_: xml(5, mask="0x1"))
    monkeypatch.setitem(sys.modules, "win32evtlog", SimpleNamespace(
        EvtCreateBookmark=lambda *_: handles[1], EvtSeek=lambda *_a, **_k: None,
        EvtSeekRelativeToBookmark=1, EvtSeekStrict=2, EvtNext=lambda *_: [handles[2]]))
    import pytest
    with pytest.raises(RuntimeError, match="agent_eventlog_read_failed"):
        bookmarked_eventlog.read_local("Security", {"record_id": 5, "bookmark": "b5",
            "anchor_sha256": anchor_hash(xml(5))}, 32)
    assert all(handle.closed for handle in handles)


def test_live_bookmark_uses_record_progress_while_history_keeps_time_ceiling(monkeypatch):
    from tests.unit.test_sli_agent_ad_dc import xml
    class Handle:
        closed = False
        def __init__(self, raw=None):
            self.raw = raw
        def Close(self):
            self.closed = True
    selectors, handles = [], []
    def query(_api, _session, _channel, selector):
        selectors.append(selector)
        handle = Handle()
        handles.append(handle)
        return handle
    def bookmark(_):
        handle = Handle()
        handles.append(handle)
        return handle
    calls = []
    def next_event(*_):
        n = len(calls) % 2 + 1
        raw = xml(4624, n)
        if n == 2:
            raw = raw.replace("2026-10-07T00:00:00Z", "2026-10-06T23:00:00Z")
        handle = Handle(raw)
        calls.append(n)
        handles.append(handle)
        return [handle]
    monkeypatch.setattr(bookmarked_eventlog, "query_event_source", query)
    monkeypatch.setattr(bookmarked_eventlog, "render_event_source", lambda _api, handle: handle.raw)
    monkeypatch.setitem(sys.modules, "win32evtlog", SimpleNamespace(
        EvtCreateBookmark=bookmark, EvtSeek=lambda *a, **k: None, EvtSeekRelativeToBookmark=1,
        EvtSeekStrict=2, EvtNext=next_event, EvtUpdateBookmark=lambda *_: None,
        EvtRender=lambda *_: "bookmark-2", EvtRenderBookmark=1, error=OSError))
    cursor = {"record_id": 1, "bookmark": "bookmark-1", "since_utc": "2026-10-07T00:00:00Z"}
    assert len(bookmarked_eventlog.read_local("Security", cursor, 32)) == 1
    assert selectors[-1] == "*"
    history = {"record_id": 1, "bookmark": "bookmark-1", "before_utc": "2026-10-08T00:00:00Z"}
    assert len(bookmarked_eventlog.read_local("Security", history, 4)) == 1
    assert selectors[-1] == "*[System[TimeCreated[@SystemTime < '2026-10-08T00:00:00Z']]]"
    assert all(handle.closed for handle in handles)


def test_gap_probe_requires_proven_bounds_or_changed_anchor(monkeypatch):
    from sli_agent import file_audit_journal as journal
    from tests.unit.test_file_audit_collection import xml
    class Handle:
        def __init__(self, raw=None):
            self.raw, self.closed = raw, False
        def Close(self):
            self.closed = True
    handles = []
    bounds = [2, 1]
    def query(*args):
        selector = args[-1]
        raw = xml(5, mask="0x1") if "EventRecordID=" in selector else xml(bounds[1])
        handle = Handle(raw)
        handles.append(handle)
        return handle
    def reverse(*_):
        handle = Handle(xml(bounds[0]))
        handles.append(handle)
        return handle
    def next_event(query, *_):
        handle = Handle(query.raw)
        handles.append(handle)
        return [handle]
    monkeypatch.setattr(journal, "query_event_source", query)
    monkeypatch.setattr(journal, "render_event_source", lambda _api, handle: handle.raw)
    monkeypatch.setitem(sys.modules, "win32evtlog", SimpleNamespace(
        EvtQuery=reverse, EvtQueryChannelPath=1, EvtQueryReverseDirection=2,
        EvtNext=next_event, error=OSError))
    cursor = {"record_id": 5, "bookmark": "b5"}
    assert journal.prove_gap("Security", cursor)  # cleared log: high watermark dropped
    bounds[:] = [10, 7]
    assert journal.prove_gap("Security", cursor)  # overwrite removed the anchor
    bounds[:] = [10, 1]
    assert not journal.prove_gap("Security", cursor)
    cursor["anchor_sha256"] = journal.anchor_hash(xml(5))
    assert journal.prove_gap("Security", cursor)  # same RecordID, different source
    monkeypatch.setattr(journal, "query_event_source", lambda *_: (_ for _ in ()).throw(OSError("private")))
    assert not journal.prove_gap("Security", cursor)
    assert all(handle.closed for handle in handles)
