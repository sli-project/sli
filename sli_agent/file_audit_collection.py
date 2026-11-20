# SPDX-License-Identifier: Apache-2.0
"""Bounded local capture; the core spool owns all durable progress."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import ntpath
import time
from uuid import uuid4

from sli_agent.envelope import canonical, timestamp
from sli_agent.file_audit_events import admitted_event, masked_event, native_event
from sli_agent.file_audit_journal import JournalGap, anchor_hash, prove_gap, valid_anchor, valid_generation
from sli_agent.file_audit_policy import CONTEXT_EVENT_IDS, EVENT_IDS, OPTIONAL_EVENT_IDS, PROVIDER, policy
from sli_agent.modules import Sample
from sli_collect.packets import make_packet
from sli_collect.eventlog_diagnostics import EventLogReadError, diagnostic

WIRE_BYTES = 44 * 1024


def read_local(channel, cursor, limit):
    from sli_collect.bookmarked_eventlog import read_local as read
    ids = " or ".join(f"EventID={event}" for event in (*EVENT_IDS, *OPTIONAL_EVENT_IDS, *CONTEXT_EVENT_IDS) if event != 1102)
    selector = (f"(Provider[@Name='{PROVIDER}'] and ({ids})) or "
                "(Provider[@Name='Microsoft-Windows-Eventlog'] and EventID=1102)")
    try:
        return read(channel, cursor, limit, error_code="file_audit_read_failed", system_filter=selector)
    except RuntimeError:
        if prove_gap(channel, cursor):
            raise JournalGap() from None
        raise


def check_path(path, root):
    """Open every component without following reparse points or reading data.

    A deleted object's existing ancestors still need verification. Sharing
    violation/access denial is a coverage gap, never permission to follow it.
    """
    import ntsecuritycon
    import win32con
    import win32file
    from contextlib import ExitStack
    with ExitStack() as stack:
        verified_root = False
        drive, tail = ntpath.splitdrive(path)
        components = [drive + "\\"]
        for part in tail.strip("\\").split("\\"):
            if part:
                components.append(ntpath.join(components[-1], part))
        for component in components:
            try:
                handle = win32file.CreateFile(component, ntsecuritycon.FILE_READ_ATTRIBUTES,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                    None, win32con.OPEN_EXISTING,
                    win32con.FILE_FLAG_BACKUP_SEMANTICS | win32file.FILE_FLAG_OPEN_REPARSE_POINT, None)
                stack.callback(handle.Close)
                flags = win32file.GetFileInformationByHandle(handle)[0]
            except Exception as exc:  # native exceptions must not expose paths
                if getattr(exc, "winerror", None) in (2, 3) and verified_root:
                    return "unknown"
                raise RuntimeError("file_audit_path_unavailable") from None
            if flags & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
                raise ValueError("file_audit_reparse_point")
            if ntpath.normcase(component) == ntpath.normcase(root):
                verified_root = True
        return "directory" if flags & win32con.FILE_ATTRIBUTE_DIRECTORY else "file"


class FileAuditModule:
    module_id = "sli.file-audit"

    def __init__(self, host_id, config, *, reader=None, path_check=None, account_check=None, clock=time.monotonic):
        self.host_id, self.policy = host_id, policy(config)
        self.source_name = self.policy.get("source_name", host_id)
        self.reader, self.path_check, self.clock = reader or read_local, path_check or check_path, clock
        self.account_check = account_check

    def state(self, cursor):
        if cursor == {"strategy": "bookmark", "token": ""}:
            return {"record_id": None, "bookmark": "", "generation": self.host_id}
        try:
            value = json.loads(cursor["token"])
            if (cursor["strategy"] != "bookmark"
                    or set(value) - {"record_id", "bookmark", "generation", "anchor_sha256", "since_utc"}
                    or not {"record_id", "bookmark", "generation"}.issubset(value)
                    or not valid_generation(value["generation"], self.host_id) or not isinstance(value["bookmark"], str)
                    or len(value["bookmark"]) > 3000
                    or (value["record_id"] is None and value["bookmark"] != "")
                    or (value["record_id"] is not None and (type(value["record_id"]) is not int
                        or value["record_id"] <= 0 or not value["bookmark"]))
                    or "anchor_sha256" in value and not valid_anchor(value["anchor_sha256"])):
                raise ValueError()
            if 'since_utc' in value:
                timestamp(value['since_utc'])
            return value
        except (ValueError, KeyError, TypeError):
            raise ValueError("file_audit_cursor_invalid") from None

    def collect(self, captured=None, *, now=None):
        account_check = self.account_check
        if self.policy.get("source_kind") == "workstation" and account_check is None:
            from sli_agent.file_audit_accounts import UserAccountFilter
            account_check = UserAccountFilter()
        now = now or datetime.now(timezone.utc)
        before = deepcopy(captured["cursor_after"]) if captured else {"strategy": "bookmark", "token": ""}
        if captured and not valid_generation(captured["generation"], self.host_id):
            raise ValueError("file_audit_generation_invalid")
        progress = self.state(before)
        if captured and progress["generation"] != captured["generation"]:
            raise ValueError("file_audit_generation_invalid")
        generation = progress["generation"]
        start = progress["record_id"]
        depth = self.policy.get('initial_read_hours', 'all')
        if start is None and 'since_utc' not in progress and depth != 'all':
            progress['since_utc'] = (now - timedelta(hours=depth)).isoformat()
        records, filtered, lost, error = [], 0, 0, None
        deadline = self.clock() + self.policy["wall_seconds"]
        self.read_observation = {"channel": "Security", "observed_at_utc": now.isoformat(), "error": None}
        try:
            rows = self.reader("Security", deepcopy(progress), min(self.policy["max_events"], 256))
        except JournalGap as exc:
            self.read_observation["error"] = diagnostic(exc, "Security", progress, "anchor")
            # Emit and spool the break before reading the new log. The next
            # heartbeat resumes even when the service restarts before its ACK.
            generation = self.host_id + ":" + str(uuid4())
            before = {"strategy": "bookmark", "token": ""}
            progress = {"record_id": None, "bookmark": "", "generation": generation}
            if depth != 'all':
                progress['since_utc'] = (now - timedelta(hours=depth)).isoformat()
            start = None
            rows, error = [], "file_audit_journal_gap"
        except (OSError, RuntimeError) as exc:
            self.read_observation["error"] = (exc.diagnostic if isinstance(exc, EventLogReadError)
                                              else diagnostic(exc, "Security", progress, "collect"))
            rows, error = [], "file_audit_read_failed"
        if len(rows) > min(self.policy["max_events"], 256):
            raise ValueError("file_audit_range_invalid")
        previous = start
        def packet(items):
            return make_packet(source=self.source_name, channel="Security", generation=generation,
                cursor={"after_record_id": start, "last_record_id": progress["record_id"]}, records=items,
                continuity={"status": "not_proven"}, observed_at=now,
                context={"policy_revision": self.policy["policy_revision"], "filtered_count": filtered,
                         "lost_count": None if error else lost, "read_error": error})
        for raw, bookmark in rows:
            if self.clock() >= deadline:
                break
            row, data = native_event(raw, self.source_name)
            record = row["record_id"]
            if (type(record) is not int or record <= 0 or previous is not None and record <= previous
                    or not isinstance(bookmark, str) or not 0 < len(bookmark) <= 3000):
                raise ValueError("file_audit_range_invalid")
            previous = record
            allowed, scopes, path = admitted_event(row, data, self.policy)
            if allowed and account_check is not None and row["event_id"] not in CONTEXT_EVENT_IDS:
                try:
                    allowed = account_check(data["SubjectUserSid"])
                except Exception:  # noqa: BLE001 - unavailable identity is a gap; never expose native diagnostics
                    lost += 1
                    progress = {**progress, "record_id": record, "bookmark": bookmark, "generation": generation,
                                "anchor_sha256": anchor_hash(raw)}
                    continue
            if allowed and path:
                try:
                    for scope in scopes:
                        self.path_check(path, scope["path"])
                except (OSError, RuntimeError, ValueError):
                    allowed = False
                    lost += 1
                    # This is unavailable evidence, not a policy exclusion.
                    progress = {**progress, "record_id": record, "bookmark": bookmark, "generation": generation,
                                "anchor_sha256": anchor_hash(raw)}
                    continue
            if allowed:
                previous_error = error
                if row["event_id"] == 1102:
                    error = "file_audit_journal_gap"
                masked = masked_event(raw, self.policy)
                row, _ = native_event(masked, self.source_name)
                candidate = {"format": "event_xml", "record_id": record, "payload": row}
                if len(canonical(packet(records + [candidate]))) + 128 > min(self.policy["max_bytes"], WIRE_BYTES):
                    if not records and not filtered and not lost:
                        raise ValueError("file_audit_event_size_limit")
                    error = previous_error
                    break
                records.append(candidate)
            else:
                filtered += 1
            progress = {**progress, "record_id": record, "bookmark": bookmark, "generation": generation,
                        "anchor_sha256": anchor_hash(raw)}
        payload = packet(records)
        if len(canonical(payload)) > min(self.policy["max_bytes"], WIRE_BYTES):
            raise ValueError("file_audit_event_size_limit")
        after = ({"strategy": "bookmark", "token": canonical(progress).decode()}
                 if progress["record_id"] or generation != self.host_id or 'since_utc' in progress else before)
        return Sample(self.module_id, self.host_id, "Security", generation, before, after, payload,
            policy_revision=self.policy["policy_revision"], filtered_count=filtered, lost_count=None if error else lost,
            continuity_state="gap" if error or lost else "filtered" if filtered else "not_proven")
