"""Focused guards for the collector cursor/message/partial-failure contract.

Scope: only the logic that is provable WITHOUT a Windows host and WITHOUT
PostgreSQL.  The `EvtQuery`/`EvtNext` probe itself is Windows-only and is
verified separately when collection is restored — see
`docs/CURRENT_ROADMAP.md` 6.16.

Covered defects:
  1. Saved cursor above the newest available record id must fall back to the
     time window instead of querying `EventRecordID > saved` forever.
  2. `--collect-message true` must fail closed instead of silently emitting
     `message=None`.
  3. The batch maximum record id must be a real maximum, not "last seen".
  4. A partial FAILURE must be attributed to a stage and must not authorise a
     cursor commit.
  5. A broken partial read must not be reported as a benign timeout warning.

Design note: the wire status stays `partial_timeout` deliberately.  Introducing
a new status value would make a broken read invisible to `archive_state`,
`collector_adaptive`, the `collector_health` SQL aggregates and the i18n label
map.  The distinction travels in `partial_kind` / `cursor_commit_allowed`.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.collect.collect_windows_events import (  # noqa: E402
    CURSOR_FALLBACK_BEFORE_SAVED,
    MESSAGE_RENDERING_UNSUPPORTED,
    build_event_xpath,
    collect_channel,
    parse_event_xml,
    resolve_cursor_strategy,
)
from server.sli.sources.collection_failure_policy import (  # noqa: E402
    classify_collection_failure,
    classify_partial_failure,
)

pytestmark = pytest.mark.core


# ---------------------------------------------------------------------------
# 0. Windows channel-state probe contract (no Windows host/DC required)
# ---------------------------------------------------------------------------


def _install_channel_state_probe_stub(
    monkeypatch: pytest.MonkeyPatch,
    *,
    get_log_info,
) -> tuple[object, object, list[tuple[object, ...]], list[object]]:
    """Install the smallest pywin32 surface used by `probe_channel_state`."""
    import scripts.collect.collect_windows_events as collector

    session = object()
    open_log_calls: list[tuple[object, ...]] = []
    closed_handles: list[object] = []

    class LogHandle:
        def Close(self) -> None:
            closed_handles.append(self)

    log_handle = LogHandle()

    def open_log(*args: object) -> object:
        open_log_calls.append(args)
        return log_handle

    monkeypatch.setattr(
        collector,
        "win32evtlog",
        SimpleNamespace(
            EvtOpenChannelPath=0x1,
            EvtLogCreationTime=0x2,
            EvtLogOldestRecordNumber=0x3,
            EvtOpenLog=open_log,
            EvtGetLogInfo=get_log_info,
        ),
    )
    monkeypatch.setattr(collector, "probe_latest_record_id", lambda *_args: 9001)
    return session, log_handle, open_log_calls, closed_handles


def test_probe_channel_state_uses_evt_open_log_contract_and_extracts_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EvtOpenLog is channel/flags/session; creation and oldest values are retained."""
    import scripts.collect.collect_windows_events as collector

    creation_time = "2026-09-03T01:02:03+00:00"

    def get_log_info(_handle: object, info_id: int) -> object:
        return {
            0x2: (creation_time, 0),
            0x3: ("8765", 0),
        }[info_id]

    session, log_handle, open_log_calls, closed_handles = _install_channel_state_probe_stub(
        monkeypatch,
        get_log_info=get_log_info,
    )

    result = collector.probe_channel_state(session, "Security")

    assert open_log_calls == [("Security", 0x1, session)]
    expected_generation_payload = json.dumps(
        {"channel": "Security", "creation_time": creation_time},
        sort_keys=True,
        separators=(",", ":"),
    )
    assert result == {
        "latest_record_id": 9001,
        "oldest_record_id": 8765,
        "generation_identity": (
            "sli.windows-event-channel-generation.v1:"
            + hashlib.sha256(expected_generation_payload.encode("utf-8")).hexdigest()
        ),
    }
    assert closed_handles == [log_handle]


def test_probe_channel_state_rejects_malformed_evt_get_log_info_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pywin32 `(value, type)` contract must not silently accept bad shapes."""
    import scripts.collect.collect_windows_events as collector

    def get_log_info(_handle: object, info_id: int) -> object:
        return {
            0x2: ("2026-09-03T01:02:03+00:00", 0, "unexpected"),
            0x3: ("8765", 0),
        }[info_id]

    session, log_handle, _open_log_calls, closed_handles = _install_channel_state_probe_stub(
        monkeypatch,
        get_log_info=get_log_info,
    )

    with pytest.raises(ValueError):
        collector.probe_channel_state(session, "Security")

    assert closed_handles == [log_handle]


def test_probe_channel_state_rejects_scalar_evt_get_log_info_stub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The old scalar-only stub was not the documented pywin32 contract."""
    import scripts.collect.collect_windows_events as collector

    def get_log_info(_handle: object, info_id: int) -> object:
        return {
            0x2: "2026-09-03T01:02:03+00:00",
            0x3: ("8765", 0),
        }[info_id]

    session, log_handle, _open_log_calls, closed_handles = _install_channel_state_probe_stub(
        monkeypatch,
        get_log_info=get_log_info,
    )

    with pytest.raises(TypeError, match="EvtGetLogInfo must return"):
        collector.probe_channel_state(session, "Security")

    assert closed_handles == [log_handle]


def test_probe_channel_state_closes_log_handle_when_metadata_read_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed EvtGetLogInfo must not leak the channel log handle."""
    import scripts.collect.collect_windows_events as collector

    def get_log_info(_handle: object, _info_id: int) -> object:
        raise RuntimeError("EvtGetLogInfo failed")

    session, log_handle, _open_log_calls, closed_handles = _install_channel_state_probe_stub(
        monkeypatch,
        get_log_info=get_log_info,
    )

    with pytest.raises(RuntimeError, match="EvtGetLogInfo failed"):
        collector.probe_channel_state(session, "Security")

    assert closed_handles == [log_handle]


# ---------------------------------------------------------------------------
# 1. Cursor reset / cleared-channel fallback
# ---------------------------------------------------------------------------


def test_cleared_channel_falls_back_to_time_window():
    """Journal cleared: newest available id is far below the saved cursor."""
    strategy, effective_after, reason = resolve_cursor_strategy(
        after_record_id=500_000,
        latest_available_record_id=42,
    )
    assert strategy == "time_window_fallback"
    assert effective_after is None, "must not keep EventRecordID > 500000"
    assert reason == CURSOR_FALLBACK_BEFORE_SAVED


def test_cleared_channel_fallback_produces_time_predicate():
    """The resulting XPath must select by time, not by the stale record id."""
    strategy, effective_after, _ = resolve_cursor_strategy(
        after_record_id=500_000,
        latest_available_record_id=42,
    )
    assert strategy == "time_window_fallback"
    xpath = build_event_xpath(
        after_record_id=effective_after,
        start_time_utc="2026-07-25T00:00:00+00:00",
    )
    assert "EventRecordID" not in xpath
    assert "TimeCreated" in xpath


def test_healthy_channel_keeps_record_id_cursor():
    strategy, effective_after, reason = resolve_cursor_strategy(
        after_record_id=500_000,
        latest_available_record_id=500_123,
    )
    assert strategy == "record_id"
    assert effective_after == 500_000
    assert reason is None


def test_equal_record_id_is_not_a_reset():
    """latest == saved means "nothing new", not a cleared log."""
    strategy, effective_after, reason = resolve_cursor_strategy(
        after_record_id=500_000,
        latest_available_record_id=500_000,
    )
    assert strategy == "record_id"
    assert effective_after == 500_000
    assert reason is None


def test_unknown_probe_result_does_not_invent_a_fallback():
    """A failed/empty probe is "unknown", never "cursor is fine to reset"."""
    strategy, effective_after, reason = resolve_cursor_strategy(
        after_record_id=500_000,
        latest_available_record_id=None,
    )
    assert strategy == "record_id"
    assert effective_after == 500_000
    assert reason is None


def test_first_run_without_cursor_uses_time_window():
    strategy, effective_after, reason = resolve_cursor_strategy(
        after_record_id=None,
        latest_available_record_id=None,
    )
    assert strategy == "time_window"
    assert effective_after is None
    assert reason is None


# ---------------------------------------------------------------------------
# 2. collect_message contract
# ---------------------------------------------------------------------------

_MINIMAL_EVENT_XML = """<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-07-25T10:00:00.000000000Z"/>
    <EventRecordID>777</EventRecordID>
    <Computer>DC1.host13.example.invalid</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">someone</Data>
  </EventData>
</Event>
"""


def _parse(**kwargs):
    return parse_event_xml(
        _MINIMAL_EVENT_XML,
        source_name="DC1",
        connect_address="192.0.2.1",
        channel="Security",
        **kwargs,
    )


def test_collect_message_true_fails_closed():
    """The old code returned None on both branches and lost the field silently."""
    with pytest.raises(RuntimeError) as excinfo:
        _parse(collect_message=True)
    assert MESSAGE_RENDERING_UNSUPPORTED in str(excinfo.value)


def test_collect_message_false_parses_and_reports_no_message():
    row = _parse(collect_message=False)
    assert row["message"] is None
    assert row["record_id"] == 777
    assert row["event_id"] == 4624
    # record_xml must still carry the payload: this is why the defect is P1, not P0.
    assert "TargetUserName" in row["xml"]
    assert row["properties"] == ["someone"]


# ---------------------------------------------------------------------------
# 3. Batch maximum record id
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("record_ids", "expected"),
    [([500, 400, 300], 500), ([0], 0), ([0, 5], 5),
     ([None, 7, None, 3], 7), ([None, None], None)],
    ids=["out-of-order", "zero", "zero-then-positive", "missing", "all-missing"],
)
def test_batch_max_tracks_collected_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    record_ids: list[int | None], expected: int | None,
) -> None:
    result = _run_bounded_security_capture(
        monkeypatch, tmp_path, source_boundary=500, record_ids=record_ids,
        max_events=0,
    )

    assert result["status"] == "completed"
    assert result["count"] == len(record_ids)
    assert result["latest_available_record_id"] == expected
    packets = [json.loads(line) for line in (tmp_path / "Security.jsonl").read_text().splitlines()]
    assert [packet["records"][0]["record_id"] for packet in packets] == record_ids


def _security_xml(record_id: int | None) -> str:
    if record_id is None:
        return _MINIMAL_EVENT_XML.replace("<EventRecordID>777</EventRecordID>", "")
    return _MINIMAL_EVENT_XML.replace(
        "<EventRecordID>777</EventRecordID>",
        f"<EventRecordID>{record_id}</EventRecordID>",
    )


_TIMEOUT = object()  # sentinel: lookahead call times out (next_event_batch -> None)


def _run_bounded_security_capture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    source_boundary: int,
    record_ids: list[int | None],
    generation_after_read: str = "generation-stable",
    second_batch: list[int] | object = (),
    max_events: int = 3,
    selector_event_ids: tuple[int, ...] = (),
) -> dict:
    """Drive `collect_channel` with a scripted sequence of EvtNext batches.

    `record_ids` is delivered as the single first batch.  `second_batch` is
    delivered on the NEXT `next_event_batch` call, whichever one that turns
    out to be: the natural "is the query exhausted" check (when `max_events`
    is not reached) or the bounded lookahead probe (when it is).  `()` means
    "explicitly exhausted"; `_TIMEOUT` means "EvtNext timed out"; a non-empty
    list means "another event is available".
    """
    import scripts.collect.collect_windows_events as collector

    second = None if second_batch is _TIMEOUT else list(second_batch)
    batches = [record_ids, second]
    observed_xpath: list[str] = []
    monkeypatch.setattr(collector, "open_remote_session", lambda _computer: object())
    generation_probes = iter(("generation-stable", generation_after_read))
    monkeypatch.setattr(
        collector,
        "probe_channel_state",
        lambda _session, _channel: {
            "latest_record_id": source_boundary,
            "oldest_record_id": 1,
            "generation_identity": next(generation_probes),
        },
    )
    monkeypatch.setattr(
        collector,
        "query_events",
        lambda _session, _channel, xpath: observed_xpath.append(xpath) or object(),
    )
    monkeypatch.setattr(
        collector,
        "next_event_batch",
        lambda _query, _size, _timeout: batches.pop(0),
    )
    monkeypatch.setattr(collector, "render_event_xml", _security_xml)
    monkeypatch.setattr(collector, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(collector, "log_performance_stage", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(collector, "safe_print", lambda *_args, **_kwargs: None)

    result = collect_channel(
        computer_name="192.0.2.1",
        source_name="DC1",
        channel="Security",
        out_file=tmp_path / "Security.jsonl",
        start_time_utc="2026-07-25T00:00:00+00:00",
        after_record_id=100,
        saved_channel_generation_identity="generation-stable",
        event_ids=selector_event_ids,
        max_events=max_events,
        timeout_seconds=30,
        collect_message=False,
        progress_every=0,
    )
    result["observed_xpath"] = observed_xpath[0]
    return result


def test_positive_limit_is_complete_when_it_reaches_frozen_source_boundary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    result = _run_bounded_security_capture(
        monkeypatch, tmp_path, source_boundary=103, record_ids=[101, 102, 103],
    )

    assert result["continuity"]["status"] == "complete"
    assert result["continuity"]["truncated"] is False
    assert "EventRecordID <= 103" in result["observed_xpath"]


def test_limit_reached_below_boundary_with_overflow_lookahead_is_not_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The runtime limit hit below the frozen boundary; the lookahead proves
    there really is more to read, so the read stays truncated/not_proven."""
    result = _run_bounded_security_capture(
        monkeypatch, tmp_path, source_boundary=110, record_ids=[101, 102, 103],
        second_batch=[104],
    )

    assert result["continuity"]["status"] == "not_proven"
    assert result["continuity"]["truncated"] is True
    assert result["continuity"]["query_exhausted"] is False
    # The lookahead event is proof-only: never written, never advances the cursor.
    assert result["latest_available_record_id"] == 103
    assert result["count"] == 3


def test_limit_reached_below_boundary_with_lookahead_timeout_is_not_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """EvtNext timing out on the lookahead is not proof of exhaustion either."""
    result = _run_bounded_security_capture(
        monkeypatch, tmp_path, source_boundary=110, record_ids=[101, 102, 103],
        second_batch=_TIMEOUT,
    )

    assert result["continuity"]["status"] == "not_proven"
    assert result["continuity"]["truncated"] is True
    assert result["continuity"]["query_exhausted"] is False
    assert result["latest_available_record_id"] == 103


def test_limit_reached_exactly_at_query_exhaustion_is_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The runtime limit hit exactly where the filtered query was already
    exhausted, below the channel-wide boundary: the bounded lookahead comes
    back empty, which is proof of completeness on its own."""
    result = _run_bounded_security_capture(
        monkeypatch, tmp_path, source_boundary=110, record_ids=[101, 102, 103],
        second_batch=(),
    )

    assert result["continuity"]["status"] == "complete"
    assert result["continuity"]["truncated"] is False
    assert result["continuity"]["query_exhausted"] is True


def test_sparse_matches_below_boundary_is_complete_when_query_explicitly_exhausts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Filtered Event ID reads are sparse: the last matching record id almost
    never equals the channel-wide upper bound.  Requiring that equality made
    an ordinary, fully-read filtered query report not_proven forever.  The
    runtime limit is never reached here (500), so completeness must come from
    the query returning explicitly empty, not from reaching the boundary."""
    result = _run_bounded_security_capture(
        monkeypatch, tmp_path, source_boundary=150, record_ids=[101, 105, 110],
        second_batch=(), max_events=500,
    )

    assert result["continuity"]["status"] == "complete"
    assert result["continuity"]["truncated"] is False
    assert result["continuity"]["query_exhausted"] is True
    assert result["latest_available_record_id"] == 110


def test_zero_matching_events_is_complete_when_query_explicitly_exhausts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A bounded filtered query that legitimately matches nothing must still
    be able to reach `complete`, not be stuck at not_proven forever."""
    result = _run_bounded_security_capture(
        monkeypatch, tmp_path, source_boundary=103, record_ids=[],
        max_events=500,
    )

    assert result["count"] == 0
    assert result["continuity"]["status"] == "complete"
    assert result["continuity"]["truncated"] is False
    assert result["continuity"]["query_exhausted"] is True


def test_continuity_selector_event_ids_are_sorted_unique_and_stable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    result = _run_bounded_security_capture(
        monkeypatch,
        tmp_path,
        source_boundary=150,
        record_ids=[101, 105],
        second_batch=(),
        max_events=500,
        selector_event_ids=(4672, 4624, 4634, 4608, 4624),
    )

    assert result["continuity"]["selector_event_ids"] == [4608, 4624, 4634, 4672]
    assert result["event_ids"] == [4608, 4624, 4634, 4672]


def test_generation_change_during_bounded_read_is_not_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    result = _run_bounded_security_capture(
        monkeypatch,
        tmp_path,
        source_boundary=103,
        record_ids=[101, 102, 103],
        generation_after_read="generation-recreated",
    )

    assert result["continuity"]["status"] == "not_proven"
    assert result["continuity"]["generation_stable_during_read"] is False
    assert result["channel_generation_identity_after_read"] == "generation-recreated"


def test_refilled_recreated_channel_cannot_reuse_numeric_cursor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import scripts.collect.collect_windows_events as collector

    monkeypatch.setattr(collector, "open_remote_session", lambda _computer: object())
    monkeypatch.setattr(
        collector,
        "probe_channel_state",
        lambda _session, _channel: {
            "latest_record_id": 150,
            "oldest_record_id": 1,
            "generation_identity": "generation-new",
        },
    )
    observed: dict[str, str] = {}

    def query_events(_session, _channel, xpath):
        observed["xpath"] = xpath
        return object()

    monkeypatch.setattr(collector, "query_events", query_events)
    monkeypatch.setattr(collector, "next_event_batch", lambda *_args: [])
    monkeypatch.setattr(collector, "log_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(collector, "log_performance_stage", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(collector, "safe_print", lambda *_args, **_kwargs: None)

    result = collect_channel(
        computer_name="192.0.2.1",
        source_name="DC1",
        channel="Security",
        out_file=tmp_path / "Security.jsonl",
        start_time_utc="2026-07-25T00:00:00+00:00",
        after_record_id=100,
        saved_channel_generation_identity="generation-old",
        max_events=500,
        timeout_seconds=60,
        collect_message=False,
        progress_every=0,
    )

    assert result["cursor_strategy"] == "time_window_fallback"
    assert result["cursor_fallback_reason"] == "channel_generation_changed"
    assert result["channel_generation_identity"] == "generation-new"
    assert result["continuity"]["status"] == "not_proven"
    assert "EventRecordID &gt; 100" not in observed["xpath"]


# ---------------------------------------------------------------------------
# 4. Partial failure attribution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "expected_stage"),
    [
        (RuntimeError("EvtOpenSession failed for DC2"), "open_session"),
        (RuntimeError("EvtQuery rejected the xpath"), "query"),
        (RuntimeError("EvtNext: the handle is invalid"), "next"),
        (RuntimeError("EvtRender could not render the event"), "render"),
        (RuntimeError("not well-formed (invalid token)"), "parse"),
        (PermissionError("permission denied"), "write"),
    ],
)
def test_partial_failure_is_attributed_to_a_stage(error, expected_stage):
    fields = classify_partial_failure(error, events_written=12)
    assert fields["failure_stage"] == expected_stage
    assert fields["partial_failure_code"] == f"partial_failure_{expected_stage}"
    assert fields["partial_kind"] == "failure"
    assert fields["partial_events_written"] == 12


def test_partial_failure_never_authorises_cursor_commit():
    """This is the whole point: the channel tail was never read."""
    fields = classify_partial_failure(RuntimeError("EvtNext exploded"), events_written=99)
    assert fields["cursor_commit_allowed"] is False


def test_unrecognised_partial_failure_is_honest_not_guessed():
    fields = classify_partial_failure(RuntimeError("something entirely new"), events_written=1)
    assert fields["failure_stage"] == "unknown"
    assert fields["cursor_commit_allowed"] is False


def test_partial_failure_classifier_ignores_none():
    assert classify_partial_failure(None, events_written=0) == {}


def test_terminal_security_context_still_blocks():
    """The pre-existing fail-closed contract must be untouched by this change."""
    decision = classify_collection_failure([RuntimeError("(1749, 'EvtOpenSession', ...)")])
    assert decision.blocked is True
    assert decision.code == "windows_security_context_invalid"


def test_ordinary_failure_is_not_a_terminal_block():
    decision = classify_collection_failure([RuntimeError("EvtNext exploded")])
    assert decision.blocked is False


# ---------------------------------------------------------------------------
# 5. Batch-scoped cursor watermark (no PostgreSQL required)
# ---------------------------------------------------------------------------


def test_cursor_never_runs_ahead_of_the_batch():
    """Published read may hold a higher id than this run imported."""
    from server.sli.core.postgres_runtime_pipeline import resolve_cursor_watermark

    watermark, bound = resolve_cursor_watermark(
        batch_max_record_id=1_000,
        published_record_id=9_999,
    )
    assert watermark == 1_000, "must not commit events this run never read"
    assert bound == "batch_scoped"


def test_cursor_clamped_when_publication_lags():
    """Batch wrote more than V2 has published yet: commit only what is readable."""
    from server.sli.core.postgres_runtime_pipeline import resolve_cursor_watermark

    watermark, bound = resolve_cursor_watermark(
        batch_max_record_id=9_999,
        published_record_id=1_000,
    )
    assert watermark == 1_000
    assert bound == "published_clamped"


def test_cursor_falls_back_to_published_without_batch_proof():
    from server.sli.core.postgres_runtime_pipeline import resolve_cursor_watermark

    watermark, bound = resolve_cursor_watermark(
        batch_max_record_id=None,
        published_record_id=500,
    )
    assert watermark == 500
    assert bound == "published_only"


def test_cursor_uses_batch_when_nothing_published_yet():
    from server.sli.core.postgres_runtime_pipeline import resolve_cursor_watermark

    watermark, bound = resolve_cursor_watermark(
        batch_max_record_id=500,
        published_record_id=None,
    )
    assert watermark == 500
    assert bound == "batch_only"


def test_cursor_is_none_when_nothing_is_known():
    from server.sli.core.postgres_runtime_pipeline import resolve_cursor_watermark

    watermark, bound = resolve_cursor_watermark(
        batch_max_record_id=None,
        published_record_id=None,
    )
    assert watermark is None
    assert bound == "published_only"


def test_filtered_exhaustion_cursor_uses_frozen_boundary_only_after_durable_import():
    from server.sli.core.postgres_runtime_pipeline import filtered_continuity_boundary

    item = {
        "cursor_strategy": "record_id",
        "channel_latest_record_id_before_read": 175,
        "continuity": {
            "status": "complete",
            "selector_event_ids": [4608, 4624, 4634, 4672],
            "query_exhausted": True,
        },
    }

    assert filtered_continuity_boundary(
        item, {"source_capture_continuity_persisted": True},
    ) == 175
    assert filtered_continuity_boundary(
        item, {"source_capture_continuity_persisted": False},
    ) is None
    item["continuity"]["query_exhausted"] = False
    assert filtered_continuity_boundary(
        item, {"source_capture_continuity_persisted": True},
    ) is None


def test_import_stats_carries_durable_continuity_ack_to_cursor_call_site() -> None:
    from scripts.run_dc_log_pilot import parse_import_stats

    stats = parse_import_stats(
        "Security.jsonl: inserted=0, skipped=0, "
        "source_capture_continuity_persisted=1"
    )

    assert stats["Security"] == {
        "inserted": 0,
        "skipped": 0,
        "source_capture_continuity_persisted": True,
    }


# ---------------------------------------------------------------------------
# 6. A broken partial read is not a benign warning
# ---------------------------------------------------------------------------


def _summarize(channels):
    from scripts.run_dc_log_pilot import summarize_channel_status

    return summarize_channel_status({"channels": channels})


def test_broken_partial_read_is_reported_as_failure_not_warning():
    status = _summarize([
        {
            "channel": "Security",
            "status": "partial_timeout",
            "count": 10,
            "error": "EvtNext exploded",
            "partial_kind": "failure",
            "cursor_commit_allowed": False,
        }
    ])
    assert status["channels_failed"] == 1
    assert status["channels_partial"] == 0
    assert status["partial_warning"] is False
    assert any("EvtNext exploded" in message for message in status["errors"])


def test_limit_stopped_channel_is_partial_even_when_wire_status_is_completed():
    status = _summarize([
        {
            "channel": "System",
            "status": "completed",
            "count": 100,
            "max_events": 100,
            "continuity": {
                "contract": "sli.source-capture-continuity.v1",
                "status": "not_proven",
                "truncated": True,
            },
        }
    ])

    assert status["channels_completed"] == 0
    assert status["channels_partial"] == 1
    assert status["partial_warning"] is True
    assert any("System" in message and "limit" in message for message in status["warnings"])


def test_workspace_survives_recent_objects_timeout():
    """GET /api/v1/workspace returned HTTP 500 because of an auxiliary list.

    `reporting_v4.workspace()` read `entities_v2` ordered by
    `last_seen_utc desc nulls last, id desc` with a 3000 ms budget and no
    matching composite index, and did not catch `QueryTimeoutError`.  The main
    screen died because of the "recent objects" block.  Migration 044 removes
    the cause; this guards the fail-soft.
    """
    from server.sli.core.database import QueryTimeoutError as _QTE
    import server.sli.reporting.reporting_v4 as r4

    access = {
        "capabilities": ["workspace.view", "objects.view"],
        "reports": [{"allowed": True, "pinned": False, "name": "AD", "sources": [{"source_type": "direct"}]}],
        "subject": {"login": "platform-owner"},
        "packages": [],
        "groups": [],
        "explicit_denies": {},
    }

    def _timeout(*_args, **_kwargs):
        raise _QTE("cancelled after 3000 ms", timeout_ms=3000, cancelled=True)

    original = r4.query_rows_bounded
    r4.query_rows_bounded = _timeout
    try:
        payload = r4.workspace(None, access=access)
    finally:
        r4.query_rows_bounded = original

    assert payload["recent_objects"] == []
    assert payload["recent_objects_state"] == "temporarily_unavailable"
    # The rest of the workspace contract must remain intact.
    assert payload["state"] == "available"
    assert payload["reports"]
    assert "composition" in payload


def test_workspace_recent_objects_normal_path():
    import server.sli.reporting.reporting_v4 as r4

    access = {
        "capabilities": ["workspace.view", "objects.view"],
        "reports": [{"allowed": True, "pinned": False, "name": "AD", "sources": [{"source_type": "direct"}]}],
        "subject": {"login": "platform-owner"},
        "packages": [],
        "groups": [],
        "explicit_denies": {},
    }
    original = r4.query_rows_bounded
    r4.query_rows_bounded = lambda *a, **k: [{
        "id": 7, "object_type": "account", "display_name": "DC1",
        "natural_key": "dc1", "last_seen_utc": "2026-07-25T10:00:00Z",
        "domain_id": 1, "server_id": 7,
    }]
    try:
        payload = r4.workspace(None, access=access)
    finally:
        r4.query_rows_bounded = original

    assert payload["recent_objects_state"] == "available"
    assert payload["recent_objects"][0]["display_name"] == "DC1"


def test_genuine_partial_timeout_is_still_a_warning():
    """The pre-existing contract must not regress."""
    status = _summarize([
        {
            "channel": "Security",
            "status": "partial_timeout",
            "count": 10,
            "error": "Channel timed out after 120 seconds.",
        }
    ])
    assert status["channels_partial"] == 1
    assert status["channels_failed"] == 0
    assert status["partial_warning"] is True
    assert status["errors"] == []
    assert any("timed out" in message for message in status["warnings"])
