"""Bounded local Windows reads shared by plugin collection modules."""
from sli_collect.eventlog import (
    parse_event_xml,
    query_event_source,
    render_event_source,
)
from sli_collect.eventlog_diagnostics import EventLogReadError, diagnostic


class BookmarkRecoveryBatch(list):
    """Rows after a missing anchor; continuity across that anchor is unknown."""


def read_local(channel, cursor, limit, *, error_code="agent_eventlog_read_failed", system_filter=None,
               recover_missing_bookmark=False):
    import win32evtlog

    after = cursor["record_id"]
    selector = "*" if cursor["bookmark"] or after is None else f"*[System[EventRecordID > {after}]]"
    if system_filter is not None:
        bound = "" if cursor["bookmark"] or after is None else f" and EventRecordID > {after}"
        selector = f"*[System[({system_filter}){bound}]]"
    bounds = []
    # Freeze the query window in the durable cursor, including empty reads.
    # After the first live bookmark, RecordID owns progress even if the source
    # clock moves back. History keeps its fixed upper bound across bookmarks.
    from sli_agent.envelope import timestamp
    for key, operator in (("since_utc", ">="), ("before_utc", "<")):
        if key in cursor and (key != "since_utc" or not cursor["bookmark"]):
            value = timestamp(cursor[key]).isoformat().replace("+00:00", "Z")
            bounds.append(f"TimeCreated[@SystemTime {operator} '{value}']")
    if bounds:
        if after is not None and not cursor["bookmark"]:
            bounds.append(f"EventRecordID > {after}")
        if system_filter is not None:
            bounds.append(f"({system_filter})")
        selector = "*[System[" + " and ".join(bounds) + "]]"
    query = None
    bookmark = None
    events = []
    stage = "query"
    try:
        query = query_event_source(win32evtlog, None, channel, selector)
        stage = "bookmark"
        bookmark = win32evtlog.EvtCreateBookmark(cursor["bookmark"] or None)
        if cursor["bookmark"]:
            stage = "seek"
            # Seek/validate the anchor; offset one with Strict fails at the tail.
            try:
                win32evtlog.EvtSeek(query, 0,
                    Flags=win32evtlog.EvtSeekRelativeToBookmark | win32evtlog.EvtSeekStrict,
                    Bookmark=bookmark, Timeout=0)
            except win32evtlog.error as exc:
                # A retained channel can overwrite the anchor. Only opt-in
                # consumers may resume by RecordID and publish an unknown gap.
                # Access errors and other native failures remain fail-closed.
                if not recover_missing_bookmark or exc.winerror != 1168 or after is None:
                    raise
                bookmark.Close()
                bookmark = None
                query.Close()
                query = None
                retry_cursor = {**cursor, "bookmark": ""}
                # Once a live anchor existed, RecordID still owns recovery even
                # if newer records have timestamps before the initial window.
                retry_cursor.pop("since_utc", None)
                return BookmarkRecoveryBatch(read_local(channel, retry_cursor, limit,
                    error_code=error_code, system_filter=system_filter))
            stage = "anchor"
            anchor = win32evtlog.EvtNext(query, 1, 1000, 0)
            events.extend(anchor)
            raw_anchor = render_event_source(win32evtlog, anchor[0]) if len(anchor) == 1 else None
            if raw_anchor is None or parse_event_xml(raw_anchor,
                    source_name="bookmark", connect_address="", channel=channel)["record_id"] != after:
                raise RuntimeError(error_code)
            if cursor.get("anchor_sha256"):
                from hashlib import sha256
                if sha256(raw_anchor.encode("utf-8")).hexdigest() != cursor["anchor_sha256"]:
                    raise RuntimeError(error_code)
        try:
            stage = "read"
            # An initial time-filtered Security query may need to scan a large
            # retained log. Keep the wait bounded without restarting it every
            # second; live bookmarks retain the shorter tail-poll wait.
            batch = win32evtlog.EvtNext(query, limit, 5000 if bounds else 1000, 0)
            events.extend(batch)
        except win32evtlog.error as exc:
            if exc.winerror == 259:
                return []
            raise
        rows = []
        stage = "render"
        for event in batch:
            raw = render_event_source(win32evtlog, event)
            win32evtlog.EvtUpdateBookmark(bookmark, event)
            rows.append((raw, win32evtlog.EvtRender(bookmark, win32evtlog.EvtRenderBookmark)))
        return rows
    except EventLogReadError:
        # Preserve the actual retry stage/code rather than replacing it with
        # the already diagnosed missing-anchor seek.
        raise
    except Exception as exc:  # noqa: BLE001 - redact native messages/XML at the source boundary
        raise EventLogReadError(error_code, diagnostic(exc, channel, cursor, stage)) from None
    finally:
        for event in events:
            event.Close()
        if bookmark is not None:
            bookmark.Close()
        if query is not None:
            query.Close()
