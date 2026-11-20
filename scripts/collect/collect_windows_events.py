from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.paths import RAW_SPOOL_DIR
from server.sli.ops.logging_config import log_event, log_internal_error
from server.sli.ops.performance import log_performance_stage, monotonic_ms
from server.sli.plugins.registry import require_plugin
from server.sli.storage.xml_safety import parse_bounded_xml
from server.source_packs.adapters import parse_bounded_eventlog_selection
from sli_collect.eventlog import (
    MESSAGE_RENDERING_UNSUPPORTED,
    channel_summary_packet,
    event_packet,
    parse_event_xml,
    query_event_source,
    render_event_source,
    xml_int,
)
from sli_collect.packets import AUTHENTICATION_EVENT_KEYS

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
resolve_nps_eventlog_endpoint = partial(require_plugin, "sli.remote-access", "resolve_nps_eventlog_endpoint")
validate_continuous_nps_admission = partial(require_plugin, "sli.remote-access", "validate_continuous_nps_admission")


def safe_print(*args: Any, **kwargs: Any) -> None:
    """Best-effort print for collector subprocess progress.

    Windows service/process-group handoffs can invalidate stdout/stderr while the
    collector is still running.  Progress logging must not fail collection, so
    OSError/ValueError/BrokenPipeError are intentionally swallowed after writing
    an internal diagnostic event when possible.
    """
    try:
        print(*args, **kwargs)
    except (OSError, ValueError, BrokenPipeError) as exc:
        try:
            log_internal_error(
                "pycollector",
                "progress_output_failed",
                "Collector progress output stream is unavailable; continuing collection.",
                exc=exc,
            )
        except Exception:
            pass

PYWIN32_ERROR = ""
try:  # pragma: no cover - pywin32 is only available on Windows collector hosts.
    import win32evtlog  # type: ignore
except Exception as exc:  # pragma: no cover
    win32evtlog = None  # type: ignore[assignment]
    PYWIN32_ERROR = str(exc)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_utc(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc) - timedelta(hours=1)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def safe_name(value: str) -> str:
    return re.sub(r'[\\/:*?"<>| ]+', "_", value)


def load_json_object(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        loaded = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def get_map_value(mapping: dict[str, Any], key: str, default: Any = None) -> Any:
    value = mapping.get(key, default)
    return default if value in (None, "") else value


def validate_source_continuity_canary_cursor_admission(
    *,
    source_continuity_canary: bool,
    bounded_selection: Any,
    channels: list[str],
    record_ids: dict[str, Any],
    cursor_generations: dict[str, Any],
    collect_message: bool,
    max_events_per_channel: int,
    channel_timeout_seconds: int,
    channel_limits: dict[str, Any],
    channel_timeouts: dict[str, Any],
) -> None:
    """Keep bounded record cursors exclusive to the explicit Security canary."""
    if not source_continuity_canary:
        if bounded_selection is not None and record_ids:
            raise ValueError("record-id cursor is forbidden")
        return

    if bounded_selection is None:
        raise ValueError("source-continuity canary requires a bounded selection")
    if tuple(bounded_selection.event_ids) != tuple(sorted(AUTHENTICATION_EVENT_KEYS)):
        raise ValueError("source-continuity canary Event ID selector mismatch")
    if channels != ["Security"]:
        raise ValueError("source-continuity canary requires only the Security channel")
    if set(record_ids) != {"Security"} or type(record_ids["Security"]) is not int or record_ids["Security"] < 1:
        raise ValueError("source-continuity canary requires a saved Security record-id cursor")
    if not isinstance(cursor_generations.get("Security"), str) or not cursor_generations["Security"].strip():
        raise ValueError("source-continuity canary requires a saved Security generation")
    if collect_message:
        raise ValueError("source-continuity canary forbids message collection")
    effective_max_events = get_map_value(channel_limits, "Security", max_events_per_channel)
    effective_timeout = get_map_value(channel_timeouts, "Security", channel_timeout_seconds)
    if type(effective_max_events) is not int or not 1 <= effective_max_events <= 5000:
        raise ValueError("source-continuity canary event limit is invalid")
    if type(effective_timeout) is not int or not 1 <= effective_timeout <= 120:
        raise ValueError("source-continuity canary channel timeout is invalid")


def build_event_xpath(
    *,
    after_record_id: int | None = None,
    through_record_id: int | None = None,
    start_time_utc: str | None = None,
    event_ids: tuple[int, ...] = (),
    end_time_utc: str | None = None,
    provider_name: str | None = None,
) -> str:
    predicates: list[str] = []
    if event_ids:
        event_predicates = [f"EventID={int(event_id)}" for event_id in event_ids]
        predicates.append(
            event_predicates[0]
            if len(event_predicates) == 1
            else f"({' or '.join(event_predicates)})"
        )
    if provider_name:
        predicates.append(f"Provider[@Name='{provider_name}']")
    if after_record_id is not None:
        predicates.append(f"EventRecordID > {int(after_record_id)}")
        if through_record_id is not None:
            predicates.append(f"EventRecordID <= {int(through_record_id)}")
    elif start_time_utc:
        start = parse_utc(start_time_utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        time_predicates = [f"@SystemTime >= '{start}'"]
        if end_time_utc:
            end = parse_utc(end_time_utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            time_predicates.append(f"@SystemTime <= '{end}'")
        predicates.append(f"TimeCreated[{' and '.join(time_predicates)}]")
        if through_record_id is not None:
            predicates.append(f"EventRecordID <= {int(through_record_id)}")
    elif end_time_utc:
        raise ValueError("end_time_utc requires start_time_utc")
    if not predicates:
        return "*"
    return f"*[System[{' and '.join(predicates)}]]"


def validate_bounded_event_row(
    row: dict[str, Any],
    *,
    event_ids: tuple[int, ...],
    start_time_utc: str,
    end_time_utc: str | None,
    provider_name: str | None = None,
) -> None:
    if not event_ids and end_time_utc is None:
        return
    if row.get("event_id") not in event_ids:
        raise RuntimeError("bounded_selection_event_id_mismatch")
    if provider_name is not None and row.get("provider_name") != provider_name:
        raise RuntimeError("bounded_selection_provider_mismatch")
    try:
        event_time = datetime.fromisoformat(str(row.get("time_created") or "").replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("bounded_selection_event_time_invalid") from exc
    if event_time.tzinfo is None or event_time.utcoffset() != timezone.utc.utcoffset(event_time):
        raise RuntimeError("bounded_selection_event_time_invalid")
    start = parse_utc(start_time_utc)
    end = parse_utc(end_time_utc) if end_time_utc else None
    event_time = event_time.astimezone(timezone.utc)
    if event_time < start or (end is not None and event_time > end):
        raise RuntimeError("bounded_selection_event_time_out_of_range")


def open_remote_session(
    computer_name: str, *, ad_source_credential_mode: str = "process", nps_continuous: bool = False,
):
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.sources.ad_source_auth import (
        AD_EVENTLOG_CREDENTIAL_PROFILE_ENV,
        DPAPI_CURRENT_USER,
        load_ad_source_login,
        resolve_ad_source_endpoint,
        sanitized_ad_source_error,
        validate_ad_source_credential_mode,
    )

    mode = validate_ad_source_credential_mode(ad_source_credential_mode)
    if nps_continuous:
        if mode != DPAPI_CURRENT_USER:
            raise RuntimeError("continuous_nps_dpapi_required")
        target = resolve_nps_eventlog_endpoint(computer_name)
        if win32evtlog is None:
            raise RuntimeError("ad_source_backend_unsupported")
        login = load_ad_source_login(
            target, getattr(win32evtlog, "EvtRpcLoginAuthDefault", 0), credential_profile="vpn",
        )
        try:
            return win32evtlog.EvtOpenSession(login, win32evtlog.EvtRpcLogin, 0, 0)
        except Exception as exc:
            raise sanitized_ad_source_error(exc) from None
    if mode == DPAPI_CURRENT_USER:
        target = resolve_ad_source_endpoint(computer_name)
        if win32evtlog is None:
            raise RuntimeError("ad_source_backend_unsupported")
        login = load_ad_source_login(
            target, getattr(win32evtlog, "EvtRpcLoginAuthDefault", 0),
            credential_profile=os.environ.get(AD_EVENTLOG_CREDENTIAL_PROFILE_ENV, "ad"),
        )
        try:
            return win32evtlog.EvtOpenSession(login, win32evtlog.EvtRpcLogin, 0, 0)
        except Exception as exc:
            raise sanitized_ad_source_error(exc) from None

    if win32evtlog is None:
        raise RuntimeError(f"pywin32/win32evtlog is not available: {PYWIN32_ERROR or 'not installed'}")

    local_names = {"", ".", "localhost", "127.0.0.1", os.environ.get("COMPUTERNAME", "").lower()}
    target = (computer_name or "").strip()
    if target.lower() in local_names:
        return None

    # pywin32 EvtOpenSession signature is:
    #   EvtOpenSession(Login, LoginClass=EvtRpcLogin, Timeout=0, Flags=0)
    # where Login must be an EVT_RPC_LOGIN tuple:
    #   (Server, User, Domain, Password, Flags)
    # EvtRpcLogin is a login-class constant, not a callable, and not the first
    # positional argument. Keep User/Domain/Password as None to use the current
    # process credentials for read-only remote collection.
    auth_default = getattr(win32evtlog, "EvtRpcLoginAuthDefault", 0)
    login = (target, None, None, None, auth_default)
    return win32evtlog.EvtOpenSession(login, win32evtlog.EvtRpcLogin, 0, 0)


def query_events(session, channel: str, xpath: str):  # pragma: no cover - Windows only
    return query_event_source(win32evtlog, session, channel, xpath)


ERROR_TIMEOUT = 1460
ERROR_NO_MORE_ITEMS = 259


def winerror_from_exception(exc: BaseException) -> int | None:
    value = getattr(exc, "winerror", None)
    if isinstance(value, int):
        return value
    if exc.args and isinstance(exc.args[0], int):
        return int(exc.args[0])
    return None


def sanitized_collection_error(
    exc: BaseException,
    *,
    ad_source_credential_mode: str,
) -> BaseException:
    """Keep source credentials and native account text out of collector evidence."""
    if ad_source_credential_mode != "dpapi_current_user":
        return exc
    from server.sli.sources.ad_source_auth import sanitized_ad_source_error

    return sanitized_ad_source_error(exc)


def next_event_batch(query, batch_size: int, timeout_ms: int):  # pragma: no cover - Windows only
    try:
        return win32evtlog.EvtNext(query, batch_size, max(1, timeout_ms), 0)
    except Exception as exc:
        code = winerror_from_exception(exc)
        if code == ERROR_TIMEOUT:
            return None
        if code == ERROR_NO_MORE_ITEMS:
            return []
        raise


def render_event_xml(event) -> str:  # pragma: no cover - Windows only
    return render_event_source(win32evtlog, event)


CURSOR_FALLBACK_BEFORE_SAVED = "latest_record_id_before_saved_cursor"
CURSOR_FALLBACK_GENERATION_MISSING = "channel_generation_missing"
CURSOR_FALLBACK_GENERATION_CHANGED = "channel_generation_changed"
CURSOR_FALLBACK_OLDEST_AFTER_SAVED = "oldest_record_id_after_saved_cursor"


def probe_latest_record_id(session, channel: str, *, timeout_ms: int = 5000) -> int | None:  # pragma: no cover - Windows only
    """Read the newest EventRecordID currently present in the channel.

    One bounded reverse-direction read of a single event.  Used to detect a
    cleared or recreated log whose record ids restarted below the saved cursor.
    Returns None when the channel is empty or the probe cannot answer; callers
    must treat None as "unknown", never as "cursor is fine".
    """
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    query = win32evtlog.EvtQuery(channel, flags, "*", session)
    batch = next_event_batch(query, 1, timeout_ms)
    if not batch:
        return None
    root = parse_bounded_xml(render_event_xml(batch[0]))
    return xml_int(root, ".//e:System/e:EventRecordID")


def resolve_cursor_strategy(
    *,
    after_record_id: int | None,
    latest_available_record_id: int | None,
) -> tuple[str, int | None, str | None]:
    """Decide the cursor strategy from the saved cursor and the probed maximum.

    Returns (strategy, effective_after_record_id, fallback_reason).

    A saved cursor above the newest available record id means the remote channel
    was cleared or recreated.  Keeping `EventRecordID > saved` would return zero
    rows forever while every cycle still reports success, so we fall back to the
    time window.  Pure function so it is testable without Windows.
    """
    if after_record_id is None:
        return "time_window", None, None
    if latest_available_record_id is None:
        # Probe could not answer.  Keep the requested contract unchanged rather
        # than inventing a fallback on unknown state.
        return "record_id", after_record_id, None
    if int(latest_available_record_id) < int(after_record_id):
        return "time_window_fallback", None, CURSOR_FALLBACK_BEFORE_SAVED
    return "record_id", after_record_id, None


def _evt_get_log_info_value(result: Any) -> Any:
    """Unwrap pywin32's required `(value, EvtVarType)` response."""
    if not isinstance(result, tuple):
        raise TypeError("EvtGetLogInfo must return a (value, EvtVarType) tuple")
    value, value_type = result
    if not isinstance(value_type, int):
        raise TypeError("EvtGetLogInfo must return an integer EvtVarType")
    return value


def probe_channel_state(session, channel: str) -> dict[str, Any]:  # pragma: no cover - Windows only
    """Freeze the numeric boundary and immutable Event Log generation identity."""
    latest = probe_latest_record_id(session, channel)
    log_handle = win32evtlog.EvtOpenLog(
        channel, win32evtlog.EvtOpenChannelPath, session,
    )
    try:
        creation = _evt_get_log_info_value(win32evtlog.EvtGetLogInfo(
            log_handle, win32evtlog.EvtLogCreationTime,
        ))
        oldest = _evt_get_log_info_value(win32evtlog.EvtGetLogInfo(
            log_handle, win32evtlog.EvtLogOldestRecordNumber,
        ))
    finally:
        log_handle.Close()
    creation_value = (
        creation.isoformat() if hasattr(creation, "isoformat") else str(creation)
    )
    generation_payload = json.dumps(
        {"channel": channel, "creation_time": creation_value},
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "latest_record_id": latest,
        "oldest_record_id": int(oldest) if oldest is not None else None,
        "generation_identity": (
            "sli.windows-event-channel-generation.v1:"
            + hashlib.sha256(generation_payload.encode("utf-8")).hexdigest()
        ),
    }


def resolve_channel_cursor_strategy(
    *,
    after_record_id: int | None,
    latest_available_record_id: int | None,
    oldest_available_record_id: int | None,
    saved_generation_identity: str | None,
    observed_generation_identity: str | None,
) -> tuple[str, int | None, str | None]:
    strategy, effective_after, reason = resolve_cursor_strategy(
        after_record_id=after_record_id,
        latest_available_record_id=latest_available_record_id,
    )
    if after_record_id is None or reason is not None:
        return strategy, effective_after, reason
    if not saved_generation_identity or not observed_generation_identity:
        return "time_window_fallback", None, CURSOR_FALLBACK_GENERATION_MISSING
    if saved_generation_identity != observed_generation_identity:
        return "time_window_fallback", None, CURSOR_FALLBACK_GENERATION_CHANGED
    if (
        oldest_available_record_id is not None
        and int(oldest_available_record_id) > int(after_record_id) + 1
    ):
        return "time_window_fallback", None, CURSOR_FALLBACK_OLDEST_AFTER_SAVED
    return strategy, effective_after, None


def _stage_metric(stage: str, duration_ms: int, *, events_count: int | None = None, bytes_count: int | None = None, status: str = "completed", error: str | None = None) -> dict[str, Any]:
    return {
        "stage": stage,
        "duration_ms": max(0, int(duration_ms)),
        "events_count": events_count,
        "bytes_count": bytes_count,
        "status": status,
        "error": error,
        "backend": "python",
    }


def collect_channel(
    *,
    computer_name: str,
    source_name: str,
    channel: str,
    out_file: Path,
    start_time_utc: str,
    event_ids: tuple[int, ...] = (),
    end_time_utc: str | None = None,
    after_record_id: int | None,
    saved_channel_generation_identity: str | None = None,
    max_events: int,
    timeout_seconds: int,
    collect_message: bool,
    progress_every: int,
    ad_source_credential_mode: str = "process",
    nps_continuous: bool = False,
) -> dict[str, Any]:
    if any(isinstance(value, bool) for value in event_ids):
        raise ValueError("selector_event_ids_invalid")
    event_ids = tuple(sorted({int(value) for value in event_ids}))
    if any(value <= 0 for value in event_ids):
        raise ValueError("selector_event_ids_invalid")
    started = time.monotonic()
    status = "completed"
    error = None
    count = 0
    latest_record_id = None
    requested_cursor_strategy = "record_id" if after_record_id is not None else "time_window"
    cursor_strategy = requested_cursor_strategy
    effective_after_record_id = after_record_id
    cursor_fallback_reason = None
    cursor_probe_error = None
    latest_available_before_read = None
    oldest_available_before_read = None
    channel_generation_identity = None
    channel_generation_identity_after_read = None
    cursor_post_probe_error = None
    query_exhausted = False
    stopped_due_to_max_events = False
    xpath = build_event_xpath(
        after_record_id=after_record_id,
        start_time_utc=start_time_utc,
        event_ids=event_ids,
        end_time_utc=end_time_utc,
        provider_name=("Microsoft-Windows-Security-Auditing" if nps_continuous else None),
    )
    out_file.parent.mkdir(parents=True, exist_ok=True)
    stage_metrics: list[dict[str, Any]] = []
    evt_next_ms = 0
    render_parse_write_ms = 0
    bytes_written = 0
    log_event(
        "pycollector",
        "channel_started",
        "Python Windows Event collector channel started.",
        server=source_name,
        channel=channel,
        path=str(out_file),
        cursor_strategy=cursor_strategy,
        after_record_id=after_record_id,
        timeout_seconds=timeout_seconds,
        max_events=max_events,
    )
    try:
        stage_started = monotonic_ms()
        session = (
            open_remote_session(
                computer_name, ad_source_credential_mode=ad_source_credential_mode,
                nps_continuous=nps_continuous,
            )
            if nps_continuous or ad_source_credential_mode != "process"
            else open_remote_session(computer_name)
        )
        stage_metrics.append(_stage_metric("open_remote_session", monotonic_ms() - stage_started))

        # Detect a cleared/recreated channel before issuing the real query.
        # Without this the saved cursor stays above every available record id,
        # `EventRecordID > saved` returns zero rows, and the pipeline still marks
        # the channel as successfully collected on every cycle - a silent and
        # self-reinforcing blind spot.  PowerShell backend already does this.
        # NPS must establish the immutable channel generation even on its first,
        # cursorless cycle.  It also freezes the upper record ID so that events
        # appended while the bounded query is running cannot be mistaken for this
        # cycle's covered window.
        if after_record_id is not None or nps_continuous:
            stage_started = monotonic_ms()
            probe_status = "completed"
            try:
                channel_state = probe_channel_state(session, channel)
                latest_available_before_read = channel_state.get("latest_record_id")
                oldest_available_before_read = channel_state.get("oldest_record_id")
                channel_generation_identity = channel_state.get("generation_identity")
            except Exception as probe_exc:  # bounded unless source authorization is terminal
                probe_exc = sanitized_collection_error(
                    probe_exc,
                    ad_source_credential_mode=ad_source_credential_mode,
                )
                from server.sli.sources.collection_failure_policy import (
                    classify_collection_failure,
                )

                if classify_collection_failure([probe_exc]).blocked:
                    raise probe_exc
                cursor_probe_error = str(probe_exc)
                probe_status = "failed"
                latest_available_before_read = None
            stage_metrics.append(
                _stage_metric(
                    "cursor_probe_latest_record_id",
                    monotonic_ms() - stage_started,
                    status=probe_status,
                    error=cursor_probe_error,
                )
            )
            cursor_strategy, effective_after_record_id, cursor_fallback_reason = resolve_channel_cursor_strategy(
                after_record_id=after_record_id,
                latest_available_record_id=latest_available_before_read,
                oldest_available_record_id=oldest_available_before_read,
                saved_generation_identity=saved_channel_generation_identity,
                observed_generation_identity=channel_generation_identity,
            )
            if cursor_fallback_reason:
                log_event(
                    "pycollector",
                    "cursor_fallback_activated",
                    "Saved cursor is above the newest available record id; falling back to the time window.",
                    level=30,
                    server=source_name,
                    channel=channel,
                    saved_after_record_id=after_record_id,
                    latest_available_record_id=latest_available_before_read,
                    cursor_strategy=cursor_strategy,
                    cursor_fallback_reason=cursor_fallback_reason,
                )
            elif cursor_probe_error:
                log_event(
                    "pycollector",
                    "cursor_probe_failed",
                    "Could not probe the newest available record id; keeping the requested cursor contract.",
                    level=30,
                    server=source_name,
                    channel=channel,
                    saved_after_record_id=after_record_id,
                    error=cursor_probe_error,
                )
            xpath = build_event_xpath(
                after_record_id=effective_after_record_id,
                through_record_id=(
                    latest_available_before_read
                    if cursor_strategy == "record_id" or nps_continuous
                    else None
                ),
                start_time_utc=start_time_utc,
                event_ids=event_ids,
                end_time_utc=end_time_utc,
                provider_name=("Microsoft-Windows-Security-Auditing" if nps_continuous else None),
            )

        stage_started = monotonic_ms()
        query = query_events(session, channel, xpath)
        stage_metrics.append(_stage_metric("evt_query_open", monotonic_ms() - stage_started))
        evt_next_timeout_ms = int(os.environ.get("ADLOG_PY_COLLECTOR_EVTNEXT_TIMEOUT_MS", "15000"))
        idle_timeout_seconds = int(os.environ.get("ADLOG_PY_COLLECTOR_IDLE_TIMEOUT_SECONDS", "45"))
        last_activity = time.monotonic()
        consecutive_timeouts = 0
        with out_file.open("w", encoding="utf-8") as f:
            while True:
                elapsed = time.monotonic() - started
                if timeout_seconds > 0 and elapsed > timeout_seconds:
                    status = "partial_timeout" if count else "timeout"
                    error = f"Channel timed out after {timeout_seconds} seconds."
                    break
                if max_events > 0 and count >= max_events:
                    stopped_due_to_max_events = True
                    break
                batch_size = min(64, max(1, max_events - count if max_events else 64))
                stage_started = monotonic_ms()
                batch = next_event_batch(query, batch_size, evt_next_timeout_ms)
                evt_next_ms += monotonic_ms() - stage_started
                if batch is None:
                    consecutive_timeouts += 1
                    idle_for = time.monotonic() - last_activity
                    if consecutive_timeouts == 1 or consecutive_timeouts % 4 == 0:
                        log_event(
                            "pycollector",
                            "evt_next_timeout",
                            "EvtNext timed out without a batch; waiting before declaring the channel idle.",
                            server=source_name,
                            channel=channel,
                            count=count,
                            consecutive_timeouts=consecutive_timeouts,
                            idle_seconds=round(idle_for, 3),
                            evt_next_timeout_ms=evt_next_timeout_ms,
                            idle_timeout_seconds=idle_timeout_seconds,
                        )
                    if idle_timeout_seconds > 0 and idle_for >= idle_timeout_seconds:
                        error = None
                        status = "completed"
                        break
                    continue
                if not batch:
                    query_exhausted = True
                    break
                last_activity = time.monotonic()
                consecutive_timeouts = 0
                for event in batch:
                    stage_started = monotonic_ms()
                    xml = render_event_xml(event)
                    row = parse_event_xml(xml, source_name=source_name, connect_address=computer_name, channel=channel, collect_message=collect_message)
                    validate_bounded_event_row(
                        row,
                        event_ids=event_ids,
                        start_time_utc=start_time_utc,
                        end_time_utc=end_time_utc,
                        provider_name=("Microsoft-Windows-Security-Auditing" if nps_continuous else None),
                    )
                    # Track the true MAXIMUM record id of this batch, not the last
                    # one seen.  `x or latest` also discarded a legitimate 0 and
                    # relied on the query always returning ascending record ids,
                    # which does not hold for a cleared/recreated channel.
                    row_record_id = row.get("record_id")
                    if row_record_id is not None:
                        latest_record_id = (
                            int(row_record_id)
                            if latest_record_id is None
                            else max(int(latest_record_id), int(row_record_id))
                        )
                    packet = event_packet(
                        row, generation=channel_generation_identity,
                        after_record_id=effective_after_record_id,
                    )
                    encoded = json.dumps(packet, ensure_ascii=False, separators=(",", ":")) + "\n"
                    f.write(encoded)
                    bytes_written += len(encoded.encode("utf-8", errors="replace"))
                    render_parse_write_ms += monotonic_ms() - stage_started
                    count += 1
                    if progress_every > 0 and count % progress_every == 0:
                        safe_print(f"Progress channel: {channel} count={count} record_id={latest_record_id}", flush=True)
                        log_event("pycollector", "channel_progress", "Python collector channel progress.", server=source_name, channel=channel, count=count, latest_event_record_id=latest_record_id)
                    if max_events > 0 and count >= max_events:
                        stopped_due_to_max_events = True
                        break
            if (
                stopped_due_to_max_events
                and not query_exhausted
                and not (
                    latest_available_before_read is not None
                    and latest_record_id == latest_available_before_read
                )
            ):
                # The bounded read stopped exactly at the runtime limit, below the
                # frozen channel-wide boundary.  A single bounded lookahead read
                # distinguishes "the filtered query was exactly exhausted at the
                # limit" (empty) from "there is more to read" (another event or a
                # timeout).  The lookahead event, if any, is never written and
                # never advances latest_record_id: it is proof-only.
                stage_started = monotonic_ms()
                lookahead_batch = next_event_batch(query, 1, evt_next_timeout_ms)
                lookahead_exhausted = (
                    lookahead_batch is not None and len(lookahead_batch) == 0
                )
                lookahead_status = (
                    "completed" if lookahead_exhausted
                    else "timeout" if lookahead_batch is None
                    else "overflow"
                )
                stage_metrics.append(
                    _stage_metric(
                        "cursor_lookahead_probe",
                        monotonic_ms() - stage_started,
                        events_count=0,
                        status=lookahead_status,
                    )
                )
                if lookahead_exhausted:
                    query_exhausted = True
    except Exception as exc:
        from server.sli.sources.collection_failure_policy import (
            classify_collection_failure,
            classify_partial_failure,
            collection_failure_fields,
        )

        # A partial FAILURE is not a partial TIMEOUT.  The wire status stays
        # `partial_timeout` on purpose: a brand-new status value would silently
        # disappear from archive_state, collector_adaptive, the collector_health
        # SQL aggregates and the i18n label map.  The distinction travels in
        # `partial_kind` / `cursor_commit_allowed` instead, which is what the
        # cursor decision actually needs.
        public_exc = sanitized_collection_error(
            exc,
            ad_source_credential_mode=ad_source_credential_mode,
        )
        status = "failed" if count == 0 else "partial_timeout"
        error = str(public_exc)
        failure_fields = collection_failure_fields(classify_collection_failure([public_exc]))
        failure_fields.update(classify_partial_failure(public_exc, events_written=count))
        log_internal_error("pycollector", "channel_failed", "Python Windows Event collector channel failed.", exc=public_exc, server=source_name, channel=channel, path=str(out_file), count=count)
        if not out_file.exists():
            out_file.write_text("", encoding="utf-8")
    if (
        (after_record_id is not None or nps_continuous)
        and channel_generation_identity is not None
        and "session" in locals()
        and locals().get("failure_fields", {}).get("retryable") is not False
    ):
        stage_started = monotonic_ms()
        post_probe_status = "completed"
        try:
            post_read_channel_state = probe_channel_state(session, channel)
            channel_generation_identity_after_read = post_read_channel_state.get(
                "generation_identity"
            )
        except Exception as post_probe_exc:
            post_probe_exc = sanitized_collection_error(
                post_probe_exc,
                ad_source_credential_mode=ad_source_credential_mode,
            )
            cursor_post_probe_error = str(post_probe_exc)
            post_probe_status = "failed"
            from server.sli.sources.collection_failure_policy import (
                classify_collection_failure,
                classify_partial_failure,
                collection_failure_fields,
            )

            decision = classify_collection_failure([post_probe_exc])
            if decision.blocked:
                status = "failed" if count == 0 else "partial_timeout"
                error = str(post_probe_exc)
                failure_fields = collection_failure_fields(decision)
                failure_fields.update(
                    classify_partial_failure(post_probe_exc, events_written=count)
                )
        stage_metrics.append(
            _stage_metric(
                "cursor_probe_generation_after_read",
                monotonic_ms() - stage_started,
                status=post_probe_status,
                error=cursor_post_probe_error,
            )
        )
    stage_metrics.append(_stage_metric("evt_next_read", evt_next_ms, events_count=count, status=status if status != "completed" else "completed", error=error))
    stage_metrics.append(_stage_metric("render_parse_write_jsonl", render_parse_write_ms, events_count=count, bytes_count=bytes_written, status=status if status != "completed" else "completed", error=error))
    for metric in stage_metrics:
        log_performance_stage(
            metric["stage"],
            server=source_name,
            channel=channel,
            backend="python",
            status=str(metric.get("status") or "completed"),
            duration_ms=int(metric.get("duration_ms") or 0),
            events_count=metric.get("events_count"),
            bytes_count=metric.get("bytes_count"),
            error=metric.get("error"),
        )
    duration = round(time.monotonic() - started, 3)
    if status == "partial_timeout" and count == 0:
        status = "timeout"
    safe_print(("Completed" if status == "completed" else "Timed out" if "timeout" in status else "Failed") + f" channel: {channel} count={count}", flush=True)
    result = {
        "channel": channel,
        "start_time_utc": start_time_utc,
        "end_time_utc": end_time_utc,
        "event_ids": list(event_ids),
        "after_record_id": after_record_id,
        "max_events": max_events,
        "timeout_seconds": timeout_seconds,
        "file": str(out_file),
        "status": status,
        "count": count,
        "error": error,
        "started_at": None,
        "finished_at": utc_now(),
        "duration_seconds": duration,
        "cursor_strategy": cursor_strategy,
        "requested_cursor_strategy": requested_cursor_strategy,
        "cursor_fallback_reason": cursor_fallback_reason,
        "cursor_probe_error": cursor_probe_error,
        "effective_after_record_id": effective_after_record_id,
        "saved_channel_generation_identity": saved_channel_generation_identity,
        "channel_generation_identity": channel_generation_identity,
        "channel_generation_identity_after_read": channel_generation_identity_after_read,
        "cursor_post_probe_error": cursor_post_probe_error,
        "channel_oldest_record_id_before_read": oldest_available_before_read,
        # Newest record id present in the channel BEFORE this read (probe result).
        "channel_latest_record_id_before_read": latest_available_before_read,
        # Maximum record id actually written by THIS run. Used as the batch-scoped
        # cursor proof by the import pipeline.
        "latest_available_record_id": latest_record_id,
        "batch_max_record_id": latest_record_id,
        "collector_backend": "python",
        "evt_next_timeout_ms": int(os.environ.get("ADLOG_PY_COLLECTOR_EVTNEXT_TIMEOUT_MS", "15000")),
        "idle_timeout_seconds": int(os.environ.get("ADLOG_PY_COLLECTOR_IDLE_TIMEOUT_SECONDS", "45")),
        "stage_metrics": stage_metrics,
        "bytes_written": bytes_written,
    }
    # A returned matching event reaching the channel-wide upper bound is one
    # proof of completeness.  It is NOT the only one: for a filtered Event ID
    # query the matching events are sparse, so the last matching record id
    # almost never equals the channel-wide latest record id even when the
    # bounded query was read to explicit exhaustion (EvtNext returned empty).
    # `query_exhausted` carries that second, independent proof.
    source_boundary_reached = bool(
        latest_available_before_read is not None
        and latest_record_id == latest_available_before_read
    )
    query_proven_complete = bool(query_exhausted or source_boundary_reached)
    limit_stopped_before_boundary = bool(
        stopped_due_to_max_events and not query_proven_complete
    )
    continuity_complete = bool(
        status == "completed"
        and cursor_strategy == "record_id"
        and after_record_id is not None
        and latest_available_before_read is not None
        and query_proven_complete
        and saved_channel_generation_identity is not None
        and channel_generation_identity == saved_channel_generation_identity
        and channel_generation_identity_after_read == channel_generation_identity
        and cursor_fallback_reason is None
        and cursor_probe_error is None
        and cursor_post_probe_error is None
    )
    result["continuity"] = {
        "contract": "sli.source-capture-continuity.v1",
        "status": "complete" if continuity_complete else "not_proven",
        "after_record_id": after_record_id,
        "latest_record_id": latest_available_before_read,
        "channel_generation_identity": channel_generation_identity,
        "channel_generation_identity_after_read": channel_generation_identity_after_read,
        "generation_stable_during_read": bool(
            channel_generation_identity is not None
            and channel_generation_identity_after_read == channel_generation_identity
            and cursor_post_probe_error is None
        ),
        "oldest_record_id": oldest_available_before_read,
        "truncated": limit_stopped_before_boundary,
        "selector_event_ids": list(event_ids),
        # This means the frozen bounded selector was fully exhausted. Reaching
        # the frozen channel upper bound is equivalent proof even when EvtNext
        # was not called once more after the final matching row.
        "query_exhausted": query_proven_complete,
    }
    result.update(locals().get("failure_fields", {}))
    result["collection_packet"] = channel_summary_packet(source=source_name, summary=result)
    return result


def main() -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    parser = argparse.ArgumentParser(description="Python-first Windows Event Log collector (central host, no Python required on DC).")
    parser.add_argument("--computer-name", required=True)
    parser.add_argument("--ad-source-credential-mode", default="process")
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--hours", type=int, default=1)
    parser.add_argument("--max-events-per-channel", type=int, default=500)
    parser.add_argument("--channel-timeout-seconds", type=int, default=300)
    parser.add_argument("--output-root", type=Path, default=RAW_SPOOL_DIR)
    parser.add_argument("--channels", default="Security")
    parser.add_argument("--channel-limits-json")
    parser.add_argument("--channel-timeouts-json")
    parser.add_argument("--start-time-utc")
    parser.add_argument("--end-time-utc")
    parser.add_argument("--event-ids-json")
    parser.add_argument("--channel-start-times-json")
    parser.add_argument("--channel-after-record-ids-json")
    parser.add_argument("--channel-cursor-generations-json")
    parser.add_argument("--collection-mode", default="auto")
    parser.add_argument("--source-continuity-canary", action="store_true")
    parser.add_argument("--nps-continuous", action="store_true")
    parser.add_argument("--collect-message", default="false")
    parser.add_argument("--progress-every", type=int, default=int(os.environ.get("ADLOG_PY_COLLECTOR_PROGRESS_EVERY", "500")))
    args = parser.parse_args()

    try:
        bounded_selection = parse_bounded_eventlog_selection(
            event_ids_json=args.event_ids_json,
            start_time_utc=args.start_time_utc,
            end_time_utc=args.end_time_utc,
        )
    except (TypeError, ValueError) as exc:
        safe_print(f"bounded_selection_invalid: {exc}", file=sys.stderr)
        return 12
    record_ids = load_json_object(args.channel_after_record_ids_json)
    cursor_generations = load_json_object(args.channel_cursor_generations_json)
    channels = [item.strip() for item in args.channels.split(",") if item.strip()]
    limits = load_json_object(args.channel_limits_json)
    timeouts = load_json_object(args.channel_timeouts_json)
    starts = load_json_object(args.channel_start_times_json)
    collect_message = str(args.collect_message).lower() in {"1", "true", "yes", "on", "$true"}
    if args.source_continuity_canary and args.nps_continuous:
        safe_print("bounded_selection_invalid: mutually exclusive bounded modes", file=sys.stderr)
        return 12
    if not args.nps_continuous:
        try:
            validate_source_continuity_canary_cursor_admission(
                source_continuity_canary=args.source_continuity_canary,
                bounded_selection=bounded_selection,
                channels=channels,
                record_ids=record_ids,
                cursor_generations=cursor_generations,
                collect_message=collect_message,
                max_events_per_channel=args.max_events_per_channel,
                channel_timeout_seconds=args.channel_timeout_seconds,
                channel_limits=limits,
                channel_timeouts=timeouts,
            )
        except ValueError as exc:
            safe_print(f"bounded_selection_invalid: {exc}", file=sys.stderr)
            return 12

    if args.nps_continuous:
        try:
            if set(record_ids) - {"Security"} or set(cursor_generations) - {"Security"}:
                raise ValueError("continuous_nps_cursor_channels_invalid")
            if set(limits) - {"Security"} or set(timeouts) - {"Security"} or set(starts) - {"Security"}:
                raise ValueError("continuous_nps_channel_overrides_invalid")
            if bounded_selection is None:
                raise ValueError("continuous_nps_selection_missing")
            if bool(record_ids) != bool(cursor_generations):
                raise ValueError("continuous_nps_cursor_generation_pair_required")
            if record_ids and (
                type(record_ids.get("Security")) is not int or int(record_ids["Security"]) < 1
            ):
                raise ValueError("continuous_nps_record_id_invalid")
            if cursor_generations and (
                not isinstance(cursor_generations.get("Security"), str)
                or not cursor_generations["Security"].strip()
            ):
                raise ValueError("continuous_nps_generation_invalid")
            if not 1 <= args.max_events_per_channel <= 50_000:
                raise ValueError("continuous_nps_global_event_limit_invalid")
            if not 1 <= args.channel_timeout_seconds <= 60:
                raise ValueError("continuous_nps_global_channel_timeout_invalid")
            effective_max_events = get_map_value(limits, "Security", args.max_events_per_channel)
            effective_timeout = get_map_value(timeouts, "Security", args.channel_timeout_seconds)
            if (
                type(effective_max_events) is not int
                or not 1 <= effective_max_events <= args.max_events_per_channel
            ):
                raise ValueError("continuous_nps_effective_event_limit_invalid")
            if (
                type(effective_timeout) is not int
                or not 1 <= effective_timeout <= args.channel_timeout_seconds
            ):
                raise ValueError("continuous_nps_effective_channel_timeout_invalid")
            selection_start = parse_utc(bounded_selection.start_time_utc)
            selection_end = parse_utc(bounded_selection.end_time_utc)
            for value in starts.values():
                parsed = parse_utc(str(value))
                if parsed < selection_start or parsed > selection_end:
                    raise ValueError("continuous_nps_channel_start_out_of_range")
            validate_continuous_nps_admission(
                event_ids_json=args.event_ids_json, start_time_utc=args.start_time_utc,
                end_time_utc=args.end_time_utc, requested_backend="python",
                server=args.source_name, connect_address=args.computer_name,
                channels=tuple(channels), archive=True, use_record_id_cursor=True,
                adaptive_state_mode="observe", collect_message=collect_message,
                max_events_per_channel=effective_max_events,
                channel_timeout_seconds=effective_timeout,
                command_timeout_seconds=90, ad_source_credential_mode=args.ad_source_credential_mode,
                allow_source_contact=True,
            )
        except (RuntimeError, TypeError, ValueError) as exc:
            safe_print(f"continuous_nps_admission_failed: {exc}", file=sys.stderr)
            return 12

    if os.name != "nt" or win32evtlog is None:
        message = f"Python collector requires Windows + pywin32 on the central collector host. Details: {PYWIN32_ERROR or 'not Windows'}"
        log_event("pycollector", "backend_unavailable", message, level=40, server=args.source_name, error=message)
        safe_print(message, file=sys.stderr)
        return 10

    if collect_message:
        # The Python backend has no provider message rendering.  Previously the
        # flag was accepted and every row silently carried message=None, which
        # reached events.message_text and the UI/search built on it.  Fail closed
        # before any DC contact instead of returning a degraded collection.
        message = (
            f"{MESSAGE_RENDERING_UNSUPPORTED}: --collect-message is not supported by the "
            "Python backend. Use the PowerShell backend for rendered messages, or rerun "
            "with --collect-message false (record_xml still carries full EventData)."
        )
        log_event(
            "pycollector",
            "collect_message_unsupported",
            message,
            level=40,
            server=args.source_name,
            failure_code=MESSAGE_RENDERING_UNSUPPORTED,
            error=message,
        )
        safe_print(message, file=sys.stderr)
        return 11

    default_start = (
        bounded_selection.start_time_utc
        if bounded_selection is not None
        else args.start_time_utc or (datetime.now(timezone.utc) - timedelta(hours=args.hours)).isoformat()
    )
    event_ids = bounded_selection.event_ids if bounded_selection is not None else ()
    end_time_utc = bounded_selection.end_time_utc if bounded_selection is not None else None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = args.output_root / f"{safe_name(args.source_name)}-{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "collection-summary.json"
    summary: dict[str, Any] = {
        "computer_name": args.source_name,
        "connect_address": args.computer_name,
        "started_at": utc_now(),
        "start_time_utc": default_start,
        "end_time_utc": end_time_utc,
        "event_ids": list(event_ids),
        "collection_mode": "python_eventlog",
        "requested_collection_mode": args.collection_mode,
        "collector_backend": "python",
        "collect_message": collect_message,
        "hours": args.hours,
        "max_events_per_channel": args.max_events_per_channel,
        "channel_timeout_seconds": args.channel_timeout_seconds,
        "channels": [],
    }

    def save_summary() -> None:
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    save_summary()
    safe_print(f"Collection output: {out_dir}", flush=True)
    safe_print(f"Summary: {summary_path}", flush=True)

    exit_code = 0
    for channel_index, channel in enumerate(channels):
        safe_print(f"Starting channel: {channel}", flush=True)
        start = str(get_map_value(starts, channel, default_start))
        after = get_map_value(record_ids, channel)
        after_id = int(after) if after not in (None, "") else None
        saved_generation = get_map_value(cursor_generations, channel)
        max_events = int(get_map_value(limits, channel, args.max_events_per_channel))
        timeout = int(get_map_value(timeouts, channel, args.channel_timeout_seconds))
        out_file = out_dir / f"{safe_name(channel)}.jsonl"
        channel_info = {
            "channel": channel,
            "start_time_utc": start,
            "after_record_id": after_id,
            "max_events": max_events,
            "timeout_seconds": timeout,
            "file": str(out_file),
            "status": "started",
            "count": 0,
            "error": None,
            "started_at": utc_now(),
            "collector_backend": "python",
        }
        summary["channels"].append(channel_info)
        save_summary()
        result = collect_channel(
            computer_name=args.computer_name,
            source_name=args.source_name,
            channel=channel,
            out_file=out_file,
            start_time_utc=start,
            end_time_utc=end_time_utc,
            event_ids=event_ids,
            after_record_id=after_id,
            saved_channel_generation_identity=(
                str(saved_generation) if saved_generation not in (None, "") else None
            ),
            max_events=max_events,
            timeout_seconds=timeout,
            collect_message=collect_message,
            progress_every=args.progress_every,
            ad_source_credential_mode=args.ad_source_credential_mode,
            nps_continuous=args.nps_continuous,
        )
        result["started_at"] = channel_info["started_at"]
        summary["channels"][-1] = result
        if result.get("retryable") is False:
            summary.update({
                "terminal_block": True,
                "failure_code": result["failure_code"],
                "failure_scope": "worker_identity",
                "retryable": False,
                "retry_policy": "operator_recovery_required",
                "pipeline_disposition": "blocked_pre_import",
                "import_attempted": False,
                "cursor_advanced": False,
                "operator_action": result.get("operator_action"),
            })
            for blocked_channel in channels[channel_index + 1:]:
                summary["channels"].append({
                    "channel": blocked_channel,
                    "status": "not_attempted",
                    "count": 0,
                    "error": None,
                    "blocked_by": result["failure_code"],
                    "collector_backend": "python",
                })
            exit_code = 74
            save_summary()
            break
        save_summary()
        if result["status"] in {"failed", "timeout"}:
            exit_code = 3
    summary["finished_at"] = utc_now()
    save_summary()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
