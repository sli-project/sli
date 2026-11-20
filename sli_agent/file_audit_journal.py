# SPDX-License-Identifier: Apache-2.0
"""Prove a missing Security anchor before permitting a new generation."""
from hashlib import sha256
import re
from uuid import UUID

from sli_collect.eventlog import parse_event_xml, query_event_source, render_event_source


class JournalGap(RuntimeError):
    def __init__(self):
        super().__init__("file_audit_journal_gap")


def valid_generation(value, host):
    if value == host:
        return True  # pre-stage-5 checkpoints
    if not isinstance(value, str) or not value.startswith(host + ":"):
        return False
    suffix = value[len(host) + 1:]
    try:
        return str(UUID(suffix)) == suffix
    except ValueError:
        return False


def anchor_hash(raw):
    return sha256(raw.encode("utf-8")).hexdigest()


def valid_anchor(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def prove_gap(channel, cursor):
    """Access errors and an empty log alone never authorize a cursor reset."""
    import win32evtlog

    def read_one(selector, *, reverse=False):
        query = None
        handles = []
        try:
            if reverse:
                query = win32evtlog.EvtQuery(channel,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, selector)
            else:
                query = query_event_source(win32evtlog, None, channel, selector)
            try:
                handles = win32evtlog.EvtNext(query, 1, 1000, 0)
            except win32evtlog.error as exc:
                if exc.winerror == 259:
                    return None
                raise
            return render_event_source(win32evtlog, handles[0]) if handles else None
        finally:
            for handle in handles:
                handle.Close()
            if query is not None:
                query.Close()

    def record(raw):
        return parse_event_xml(raw, source_name="journal", connect_address="", channel=channel)["record_id"]

    after = cursor["record_id"]
    if after is None:
        return False
    try:
        newest, oldest = read_one("*", reverse=True), read_one("*")
        if not newest or not oldest:
            return False
        if record(newest) < after or record(oldest) > after:
            return True
        expected = cursor.get("anchor_sha256")
        if expected:
            anchor = read_one(f"*[System[EventRecordID={after}]]")
            return anchor is not None and anchor_hash(anchor) != expected
    except Exception:  # noqa: BLE001 - no native paths or diagnostic text
        return False
    return False
