# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``security_event_reporting`` at call time.
from __future__ import annotations

"""Bounded read-only projection of source-native DC security events.

This service is intentionally a pre-authorized boundary: callers supply the
domain-scoped access decision and the service never interprets that decision as
a new capability.  It reads Storage V2 core rows and warm facts only.
"""

import base64
import csv
import hashlib
import io
import json
from functools import partial
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from server.sli.access.access_control_v4 import (
    capability_decision_for_resource_groups,
    report_action_decision,
)
from server.sli.core.time_contract import TimeRangeError, normalize_utc_range
from server.sli.core.time_format import parse_event_time
from server.sli.events.event_details import (
    MAX_BATCH_EVENT_IDS,
    get_v2_event_details_by_ids,
)
from server.sli.reporting.reporting_common import (
    build_domain_resource_groups,
    clean_text,
    format_csv_cell,
    format_iso,
    get_runtime_connection,
    parse_utc,
    sanitize_public,
)
from server.sli.plugins.registry import require_plugin
from server.sli.storage.storage_v2_archive import ArchiveIntegrityError
from server.source_packs.windows_ad_dc import (
    AD_ACCOUNT_CHANGE_EVENT_IDS,
    SECURITY_AUDIT_FAILURE_KEYWORDS,
    SECURITY_AUDIT_SUCCESS_KEYWORDS,
    SECURITY_EVENTS_CONTEXT_EVENT_IDS,
    SECURITY_EVENTS_EVENTLOG_EVENT_ID,
    SECURITY_EVENTS_FAILURE_EVENT_IDS,
    SECURITY_EVENTS_GROUP_EVENT_IDS,
    SECURITY_EVENTS_MIXED_OUTCOME_EVENT_IDS,
    SECURITY_EVENTS_REPORT_AUDITING_PROVIDER,
    SECURITY_EVENTS_REPORT_DEFAULT_EVENT_IDS,
    SECURITY_EVENTS_REPORT_EVENT_IDS,
    SECURITY_EVENTS_REPORT_EVENTLOG_PROVIDER,
    SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS,
    SECURITY_EVENTS_SUCCESS_EVENT_IDS,
    security_audit_outcome,
    security_event_change_kind,
    security_event_family,
    security_event_has_caller_computer,
    security_event_ids_for_family,
    security_event_observed_change,
    security_event_static_outcome,
)

CONTRACT_ID = "sli.security-events.v1"
account_change_observation = partial(require_plugin, "sli.ad", "account_change_observation")


def apply_observed_account_history(
    items: Sequence[dict[str, Any]], *, account_field: str = "account",
    sid_field: str = "target_user_sid", observation_field: str | None = None,
) -> None:
    if items:
        require_plugin("sli.ad", "apply_observed_account_history", items, account_field=account_field,
                       sid_field=sid_field, observation_field=observation_field)


REPORT_KEY = "security.events.chains"
EVENT_VIEW_CAPABILITY = "events.view"
SECURITY_CHANNEL = "Security"
SECURITY_AUDITING_PROVIDER = SECURITY_EVENTS_REPORT_AUDITING_PROVIDER
EVENTLOG_PROVIDER = SECURITY_EVENTS_REPORT_EVENTLOG_PROVIDER
MAX_PERIOD_DAYS = 31
MAX_ROWS = 500
DEFAULT_ROWS = 200
DISCOVERY_BATCH_LIMIT = 256
DISCOVERY_SCAN_LIMIT = 10_000
_CURSOR_VERSION = "v1"
_CURSOR_PREFIX = b"sli.security-events.v1\0"
REQUIRED_FIELD_CATEGORIES = frozenset({
    "security", "technical", "raw_evidence",
})
_ARCHIVE_FIELD_NAMES = {
    "CallerComputerName": "caller_computer",
    "CallerComputer": "caller_computer",
    "MemberSid": "membership_member_sid",
    "MemberName": "membership_member_name",
    "TargetSid": "target_user_sid",
    "TargetUserSid": "target_user_sid",
    "TargetUserName": "target_user_name",
    "GroupName": "target_user_name",
    "OldTargetUserName": "account_name_before",
    "NewTargetUserName": "account_name_after",
    "OldAccountName": "account_name_before",
    "NewAccountName": "account_name_after",
}


_utc = parse_utc
_iso = format_iso
_text = clean_text
_domain_resource_groups = build_domain_resource_groups


def _read_access_allowed(access: Mapping[str, Any], domain_id: int, *, action: str = "view") -> bool:
    resource_groups = _domain_resource_groups(domain_id)
    return bool(
        report_action_decision(
            access,
            REPORT_KEY,
            action,
            resource_groups=resource_groups,
            required_field_categories=REQUIRED_FIELD_CATEGORIES,
        )["allowed"]
        and capability_decision_for_resource_groups(
            access, EVENT_VIEW_CAPABILITY, resource_groups=resource_groups
        )["allowed"]
    )


def _clean_filter_text(value: Any, name: str) -> str | None:
    clean = _text(value)
    if clean is not None and len(clean) > 256:
        raise ValueError("security_events_filter_invalid")
    return clean


def normalize_security_event_filters(
    *, category: Any = None, event_id: Any = None, outcome: Any = None,
    actor: Any = None, target_account: Any = None, group: Any = None,
    source_host: Any = None, q: Any = None, entity_id: Any = None,
    event_db_id: Any = None,
) -> dict[str, Any]:
    clean_category = _text(category)
    if clean_category is not None:
        clean_category = clean_category.casefold()
        if not security_event_ids_for_family(clean_category):
            raise ValueError("security_events_filter_invalid")
    clean_event_id: int | None = None
    if event_id not in (None, ""):
        try:
            clean_event_id = int(event_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("security_events_filter_invalid") from exc
        if clean_event_id not in SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS:
            raise ValueError("security_events_filter_invalid")
        if clean_category and clean_event_id not in security_event_ids_for_family(clean_category):
            raise ValueError("security_events_filter_invalid")
    clean_outcome = _text(outcome)
    if clean_outcome is not None:
        clean_outcome = clean_outcome.casefold()
        if clean_outcome not in {"success", "failure", "unknown"}:
            raise ValueError("security_events_filter_invalid")
    candidates = {
        "category": clean_category,
        "event_id": clean_event_id,
        "outcome": clean_outcome,
        "actor": _clean_filter_text(actor, "actor"),
        "target_account": _clean_filter_text(target_account, "target_account"),
        "group": _clean_filter_text(group, "group"),
        "source_host": _clean_filter_text(source_host, "source_host"),
        "q": _clean_filter_text(q, "q"),
    }
    if entity_id not in (None, ""):
        try:
            candidates["entity_id"] = int(entity_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("security_events_filter_invalid") from exc
        if candidates["entity_id"] <= 0:
            raise ValueError("security_events_filter_invalid")
    if event_db_id not in (None, ""):
        try:
            candidates["event_db_id"] = int(event_db_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("security_events_filter_invalid") from exc
        if candidates["event_db_id"] <= 0:
            raise ValueError("security_events_filter_invalid")
    return {key: value for key, value in candidates.items() if value is not None}




_public = sanitize_public


def _principal(
    event: Mapping[str, Any], *, sid_key: str, name_key: str,
    entity_id_key: str | None = None,
) -> dict[str, Any]:
    sid, name = _text(event.get(sid_key)), _text(event.get(name_key))
    if not sid and not name:
        return {"state": "unknown"}
    result: dict[str, Any] = {"state": "observed", "sid": sid, "name": name}
    entity_id = event.get(entity_id_key) if entity_id_key else None
    if entity_id is not None and int(entity_id) > 0:
        result["entity_id"] = int(entity_id)
    return result


def _target_principal(event: Mapping[str, Any]) -> dict[str, Any]:
    sid = _text(event.get("target_user_sid")) or _text(event.get("account_target_sid"))
    name = _text(event.get("target_user_name")) or _text(event.get("account_target_name"))
    if not sid and not name:
        return {"state": "unknown"}
    result: dict[str, Any] = {"state": "observed", "sid": sid, "name": name}
    if event.get("target_entity_id") is not None and int(event["target_entity_id"]) > 0:
        result["entity_id"] = int(event["target_entity_id"])
    return result


def _affected_account(event: Mapping[str, Any], event_id: int) -> dict[str, Any]:
    if event_id in SECURITY_EVENTS_GROUP_EVENT_IDS:
        return {"state": "unknown"}
    return _target_principal(event)


def _group(event: Mapping[str, Any], event_id: int) -> dict[str, Any]:
    if event_id not in SECURITY_EVENTS_GROUP_EVENT_IDS:
        return {"state": "unknown"}
    return _target_principal(event)


def _outcome(event: Mapping[str, Any], event_id: int) -> dict[str, Any]:
    static = security_event_static_outcome(event_id)
    if static is not None:
        return {"state": "observed", "value": static, "basis": "event_id"}
    result_code = _text(event.get("result_code"))
    audit_outcome = security_audit_outcome(event.get("audit_keywords"))
    if event_id in SECURITY_EVENTS_MIXED_OUTCOME_EVENT_IDS and audit_outcome is not None:
        outcome = {
            "state": "observed",
            "value": audit_outcome,
            "basis": "audit_keywords",
        }
        if result_code is not None:
            outcome["result_code"] = result_code
        return outcome
    outcome: dict[str, Any] = {
        "state": "unknown",
        "reason": "event_outcome_not_proven_by_scoped_contract",
    }
    if result_code is not None:
        outcome["result_code"] = result_code
    return outcome


def _evidence(event: Mapping[str, Any], event_db_id: int) -> dict[str, Any]:
    fields = {
        "event_db_id": event_db_id,
        "event_record_id": event.get("event_record_id"),
        "source_core_sha256": _public(event.get("source_core_sha256")),
        "source_facts_sha256": _public(event.get("source_facts_sha256")),
    }
    missing = [key for key, value in fields.items() if value is None]
    return {"state": "partial" if missing else "complete", "missing_fields": missing, **fields}


def _archive_field_state(event: Mapping[str, Any]) -> dict[str, str] | None:
    state = _text(event.get("archive_field_state"))
    if state == "partial_archive_unavailable":
        return {"state": "partial", "reason": "archive_unavailable"}
    if state == "partial_archive_missing":
        return {"state": "partial", "reason": "archive_missing"}
    if state == "partial_archive_corrupt":
        return {"state": "partial", "reason": "archive_corrupt"}
    return None


def _change(event: Mapping[str, Any], event_id: int) -> dict[str, Any]:
    source_change = event.get("source_native_change")
    if isinstance(source_change, Mapping):
        return dict(source_change)
    source_change = security_event_observed_change(event_id, event)
    if source_change is not None:
        return source_change
    source_kind = security_event_change_kind(event_id)
    account = account_change_observation(event).get("change") if event_id in AD_ACCOUNT_CHANGE_EVENT_IDS else None
    if isinstance(account, Mapping) and account.get("kind"):
        return {"state": "observed", **dict(account)}
    if source_kind is not None:
        return {"state": "observed", "kind": source_kind}
    return {"state": "unknown", "reason": "source_change_not_established"}


def _hydrate_security_event_fields(events: Sequence[Mapping[str, Any]]) -> dict[int, dict[str, Any]]:
    """Read selected exact originals through the existing bounded details owner.

    This boundary deliberately returns only allowlisted scalar source fields;
    no archive message, XML, JSON object or raw event body crosses into the
    report projection.
    """
    event_ids = [int(event["event_db_id"]) for event in events]
    source_event_ids = {
        int(event["event_db_id"]): int(event.get("event_id") or 0)
        for event in events
    }
    hydrated: dict[int, dict[str, Any]] = {}
    for offset in range(0, len(event_ids), MAX_BATCH_EVENT_IDS):
        batch_ids = event_ids[offset:offset + MAX_BATCH_EVENT_IDS]
        try:
            details = get_v2_event_details_by_ids(batch_ids)
        except ArchiveIntegrityError:
            hydrated.update({event_id: {"archive_field_state": "partial_archive_corrupt"} for event_id in batch_ids})
            continue
        except KeyError:
            hydrated.update({event_id: {"archive_field_state": "partial_archive_missing"} for event_id in batch_ids})
            continue
        except (OSError, RuntimeError, ValueError):
            hydrated.update({event_id: {"archive_field_state": "partial_archive_unavailable"} for event_id in batch_ids})
            continue
        for event_id in batch_ids:
            detail = details.get(event_id)
            if detail is None:
                hydrated[event_id] = {"archive_field_state": "partial_archive_missing"}
                continue
            event_data = detail.get("event_data")
            if not isinstance(event_data, Mapping):
                hydrated[event_id] = {"archive_field_state": "partial_archive_missing"}
                continue
            public_fields = {
                destination: value
                for source, destination in _ARCHIVE_FIELD_NAMES.items()
                if (value := _text(event_data.get(source))) is not None
            }
            source_change = security_event_observed_change(
                source_event_ids[event_id], event_data,
            )
            if source_change is not None:
                public_fields["source_native_change"] = source_change
            hydrated[event_id] = public_fields
    return hydrated


def _merge_hydrated_fields(events: Sequence[dict[str, Any]]) -> None:
    hydrated = _hydrate_security_event_fields(events)
    for event in events:
        event_db_id = int(event["event_db_id"])
        for field, value in hydrated.get(event_db_id, {}).items():
            if field == "archive_field_state" or _text(event.get(field)) is None:
                event[field] = value


def _collection_coverage(
    coverage: Mapping[str, Any], *, observed_event_count: int
) -> tuple[str, dict[str, Any]]:
    history_event_present = bool(coverage.get("history_event_present"))
    if observed_event_count < 0 or (observed_event_count and not history_event_present):
        raise ValueError("security_events_collection_coverage_invalid")
    state = "available" if observed_event_count else "empty_unverified" if history_event_present else "not_collected"
    return state, {
        "state": state,
        "history_event_present": history_event_present,
        "source_completeness": "not_proven",
    }


def _encode_cursor(
    *, source_domain_id: int, period_start: datetime, period_end: datetime,
    event_time: datetime, event_db_id: int, filters: Mapping[str, Any] | None = None,
) -> str:
    body = [
        _CURSOR_VERSION, int(source_domain_id), _iso(period_start), _iso(period_end),
        _iso(event_time), int(event_db_id), dict(filters or {}),
    ]
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    signature = hashlib.sha256(_CURSOR_PREFIX + payload).digest()[:12]
    return base64.urlsafe_b64encode(signature + payload).decode("ascii").rstrip("=")


def _decode_cursor(
    value: str, *, source_domain_id: int, period_start: datetime, period_end: datetime,
    filters: Mapping[str, Any] | None = None,
) -> tuple[datetime, int]:
    try:
        raw = base64.urlsafe_b64decode(str(value) + "=" * (-len(str(value)) % 4))
        signature, payload = raw[:12], raw[12:]
        if hashlib.sha256(_CURSOR_PREFIX + payload).digest()[:12] != signature:
            raise ValueError
        version, domain_id, start, end, event_time, event_db_id, cursor_filters = json.loads(payload.decode("utf-8"))
        parsed_time = _utc(event_time)
        if (
            version != _CURSOR_VERSION or int(domain_id) != int(source_domain_id)
            or start != _iso(period_start) or end != _iso(period_end)
            or cursor_filters != dict(filters or {})
            or parsed_time is None or int(event_db_id) <= 0
        ):
            raise ValueError
        return parsed_time, int(event_db_id)
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid_cursor") from exc


def compose_security_events_page(
    *, source_domain_id: int | None, period_start: datetime, period_end: datetime,
    events: Sequence[Mapping[str, Any]], collection_coverage: Mapping[str, Any],
    display_limit: int = DEFAULT_ROWS, has_more: bool = False,
    filters: Mapping[str, Any] | None = None,
    source_domain_ids: Sequence[int] | None = None,
) -> dict[str, Any]:
    """Compose one reverse-ordered page without inferring missing source facts."""

    if not period_start.tzinfo or not period_end.tzinfo or period_start >= period_end:
        raise ValueError("security_events_period_invalid")
    if not 1 <= int(display_limit) <= MAX_ROWS or len(events) > int(display_limit):
        raise ValueError("security_events_input_bound_exceeded")
    start, end = _utc(period_start), _utc(period_end)
    assert start is not None and end is not None
    items: list[dict[str, Any]] = []
    seen: set[int] = set()
    for event in events:
        event_id = int(event.get("event_id") or 0)
        family = security_event_family(event_id)
        if event_id not in SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS or family is None:
            raise ValueError("security_events_event_invalid")
        observed_at = _utc(event.get("time_created_utc"))
        if observed_at is None or not start <= observed_at < end:
            raise ValueError("security_events_event_outside_bounds")
        event_db_id = int(event.get("event_db_id") or 0)
        if event_db_id <= 0 or event_db_id in seen:
            raise ValueError("security_events_event_identity_invalid")
        seen.add(event_db_id)
        source_host = _text(event.get("source_host"))
        item = {
            "domain_id": event.get("domain_id", source_domain_id),
            "event_db_id": event_db_id,
            "event_record_id": event.get("event_record_id"),
            "event_id": event_id,
            "event_family": family,
            "time_created_utc": _iso(observed_at),
            "actor": _principal(
                event, sid_key="subject_user_sid", name_key="subject_user_name",
                entity_id_key="actor_entity_id",
            ),
            "affected_account": _affected_account(event, event_id),
            "member": _principal(
                event, sid_key="membership_member_sid", name_key="membership_member_name",
                entity_id_key="member_entity_id",
            ),
            "group": _group(event, event_id),
            "source_host": (
                {"state": "observed", "hostname": source_host}
                if source_host else {"state": "unknown"}
            ),
            "outcome": _outcome(event, event_id),
            "evidence": _evidence(event, event_db_id),
            "change": _change(event, event_id),
        }
        if security_event_has_caller_computer(event_id):
            caller = _text(event.get("caller_computer"))
            item["caller_computer"] = (
                {"state": "observed", "hostname": caller}
                if caller is not None else {"state": "unknown"}
            )
        archive_fields = _archive_field_state(event)
        if archive_fields is not None:
            item["archive_fields"] = archive_fields
        if event_id in AD_ACCOUNT_CHANGE_EVENT_IDS:
            item["account_change"] = account_change_observation(event)
        items.append(item)
    for row_domain_id in {item["domain_id"] for item in items}:
        apply_observed_account_history(
            [item for item in items if item["domain_id"] == row_domain_id and item.get("account_change") is not None],
            account_field="affected_account", sid_field="sid", observation_field="account_change",
        )
    items.sort(key=lambda item: (item["time_created_utc"], item["event_db_id"]), reverse=True)
    state, public_coverage = _collection_coverage(coverage=collection_coverage, observed_event_count=len(items))
    category_coverage = collection_coverage.get("category_coverage")
    next_cursor = (
        _encode_cursor(
            source_domain_id=source_domain_id or 0, period_start=start, period_end=end,
            event_time=_utc(items[-1]["time_created_utc"]) or start,
            event_db_id=int(items[-1]["event_db_id"]),
            filters={**(filters or {}), "source_domain_ids": list(source_domain_ids or [])} if source_domain_id is None else filters,
        )
        if has_more and items else None
    )
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "source_domain_id": source_domain_id,
        "state": state,
        "time_bounds": {"from_utc": _iso(start), "to_utc_exclusive": _iso(end)},
        "filters": dict(filters or {}),
        "items": items,
        "has_more": bool(has_more),
        "next_cursor": next_cursor,
        "collection_coverage": public_coverage,
        "category_coverage": dict(category_coverage) if isinstance(category_coverage, Mapping) else {},
        "limits": {"max_period_days": MAX_PERIOD_DAYS, "row_limit": int(display_limit), "max_row_limit": MAX_ROWS, "bounded": True},
        "limitations": [
            "Rows are source-event observations, not reconstructed account, membership, or audit state.",
            "Unknown identity and outcome fields were not present in the scoped Storage V2 contract.",
            "An empty window does not prove complete source coverage.",
        ],
    }


def _not_authorized_payload(
    domain_id: int | None, period_start: datetime, period_end: datetime, limit: int
) -> dict[str, Any]:
    return {
        "contract_id": CONTRACT_ID, "report_key": REPORT_KEY, "source_domain_id": domain_id,
        "state": "not_authorized",
        "time_bounds": {"from_utc": _iso(period_start), "to_utc_exclusive": _iso(period_end)},
        "items": [], "has_more": False, "next_cursor": None,
        "limits": {"max_period_days": MAX_PERIOD_DAYS, "row_limit": limit, "max_row_limit": MAX_ROWS, "bounded": True},
    }


def get_security_event_sources(access: Mapping[str, Any]) -> dict[str, Any]:
    """Discover only domains authorized for this report and ``events.view``."""

    discovered = 0
    authorized = 0
    items: list[dict[str, int]] = []
    after_domain_id = 0
    while len(items) <= 100:
        domains = _read_security_event_domain_batch(
            after_domain_id=after_domain_id, limit=DISCOVERY_BATCH_LIMIT
        )
        if not domains:
            break
        discovered += len(domains)
        if discovered > DISCOVERY_SCAN_LIMIT:
            raise ValueError("security_events_source_discovery_scan_limit")
        for domain_id in domains:
            if not _read_access_allowed(access, domain_id):
                continue
            authorized += 1
            if _has_security_event_source(domain_id):
                items.append({"source_domain_id": domain_id})
        after_domain_id = domains[-1]
        if len(domains) < DISCOVERY_BATCH_LIMIT:
            break
    visible = items[:100]
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "state": "available" if visible else "not_collected" if authorized else "not_authorized",
        "items": visible,
        "bounded": True,
        "limit": 100,
        "has_more": len(items) > 100,
    }


def _authorized_security_event_domains(access: Mapping[str, Any], *, action: str) -> list[int]:
    """Discover the complete bounded domain scope before any event read."""
    allowed: list[int] = []
    after_domain_id = 0
    scanned = 0
    while True:
        domains = _read_security_event_domain_batch(after_domain_id=after_domain_id, limit=DISCOVERY_BATCH_LIMIT)
        if not domains:
            return allowed
        scanned += len(domains)
        if scanned > DISCOVERY_SCAN_LIMIT:
            raise ValueError("security_events_source_discovery_scan_limit")
        allowed.extend(domain_id for domain_id in domains if _read_access_allowed(access, domain_id, action=action))
        after_domain_id = domains[-1]
        if len(domains) < DISCOVERY_BATCH_LIMIT:
            return allowed


def get_security_event_domain_ids(access: Mapping[str, Any]) -> list[int]:
    """Authorized selector metadata, not a claim of retained event coverage.

    Unlike source discovery, filter options must not probe event history: an
    unrelated domain's expensive or failing presence query must not prevent a
    selected-domain report from opening. Keep the same bounded authorization
    scan used by the all-domain reader, including its explicit scan-limit error.
    """
    return _authorized_security_event_domains(access, action="view")


def get_security_events_report(
    access: Mapping[str, Any], *, source_domain_id: int | None,
    time_from: str | None, time_to: str | None, timezone_name: str = "UTC",
    limit: int = DEFAULT_ROWS, cursor: str | None = None, category: str | None = None,
    event_id: int | None = None, outcome: str | None = None, actor: str | None = None,
    target_account: str | None = None, group: str | None = None,
    source_host: str | None = None, q: str | None = None,
    entity_id: int | None = None, event_db_id: int | None = None,
    action: str = "view",
) -> dict[str, Any]:
    """Read one page after existing report and capability decisions allow it."""

    domain_id = int(source_domain_id) if source_domain_id is not None else None
    if domain_id is not None and domain_id <= 0:
        raise ValueError("security_events_domain_invalid")
    if not time_from or not time_to:
        raise TimeRangeError("security_events_requires_time_bounds")
    start_raw, end_raw = normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    period_start, period_end = _utc(start_raw), _utc(end_raw)
    if period_start is None or period_end is None or period_start >= period_end:
        raise TimeRangeError("empty_or_reversed_time_range")
    if period_end - period_start > timedelta(days=MAX_PERIOD_DAYS):
        raise ValueError("security_events_period_too_wide")
    clean_limit = int(limit)
    if not 1 <= clean_limit <= MAX_ROWS:
        raise ValueError("security_events_limit_invalid")
    if action not in {"view", "export"}:
        raise ValueError("security_events_action_invalid")
    filters = normalize_security_event_filters(
        category=category, event_id=event_id, outcome=outcome, actor=actor,
        target_account=target_account, group=group, source_host=source_host, q=q,
        entity_id=entity_id, event_db_id=event_db_id,
    )
    domain_ids = _authorized_security_event_domains(access, action=action) if domain_id is None else None
    cursor_filters = {**filters, "source_domain_ids": domain_ids} if domain_id is None else filters
    before = (
        _decode_cursor(
            cursor, source_domain_id=domain_id or 0, period_start=period_start,
            period_end=period_end, filters=cursor_filters,
        )
        if cursor else None
    )
    if (domain_id is None and not domain_ids) or (domain_id is not None and not _read_access_allowed(access, domain_id, action=action)):
        return _not_authorized_payload(domain_id, period_start, period_end, clean_limit)
    events, coverage, has_more = _read_security_events_page(
        domain_id=domain_ids if domain_id is None else domain_id, period_start=period_start, period_end=period_end,
        limit=clean_limit, before=before, filters=filters,
    )
    _merge_hydrated_fields(events)
    return compose_security_events_page(
        source_domain_id=domain_id, period_start=period_start, period_end=period_end,
        events=events, collection_coverage=coverage, display_limit=clean_limit, has_more=has_more,
        filters=filters, source_domain_ids=domain_ids,
    )












def _read_security_events_page(
    *, domain_id: int | list[int], period_start: datetime, period_end: datetime,
    limit: int, before: tuple[datetime, int] | None, filters: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any], bool]:
    """Read a single Storage V2 reverse-keyset page and its source witness."""

    domain_sql = "event.domain_id=any(%s)" if isinstance(domain_id, list) else "event.domain_id=%s"
    keyset_sql, keyset_params = ("", [])
    if before is not None:
        keyset_sql = " and (event.time_created_utc,event.id)<(%s,%s)"
        keyset_params = [before[0], before[1]]
    (
        event_ids, provider_predicate, provider_params,
        target_identity_sql, target_name_sql, filter_sql, filter_params,
    ) = security_event_read_contract(filters)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        cur.execute(
            """select event.id as event_db_id,event.domain_id,event.event_record_id,event.event_id,
                      event.time_created_utc,server.hostname as source_host,
                      keywords.value as audit_keywords,
                      event.subject_user_sid,event.subject_user_name,
                      """ + target_identity_sql + """ as target_user_sid,
                      """ + target_name_sql + """ as target_user_name,
                      facts.membership_member_sid,facts.membership_member_name,
                      facts.account_name_before,facts.account_name_after,facts.result_code,
                      event.source_core_sha256,facts.source_facts_sha256
                 from events_v2_core event
                 join servers server on server.id=event.server_id
                 join storage_v2_channel channel on channel.id=event.channel_id
                 join storage_v2_provider provider on provider.id=event.provider_id
                 left join storage_v2_keywords keywords on keywords.id=event.keywords_id
                 left join event_facts_v2 facts on facts.event_id=event.id
                where """ + domain_sql + """ and server.role='domain_controller'
                  and event.event_id=any(%s) and channel.value=%s and """
            + provider_predicate
            + " and event.time_created_utc>=%s and event.time_created_utc<%s"
            + filter_sql
            + keyset_sql
            + " order by event.time_created_utc desc,event.id desc limit %s",
            [
                domain_id, event_ids, SECURITY_CHANNEL, *provider_params,
                period_start, period_end, *filter_params, *keyset_params, limit + 1,
            ],
        )
        rows = [dict(row) for row in cur.fetchall()]
        has_more = len(rows) > limit
        events = rows[:limit]
        if isinstance(domain_id, list):
            for row_domain_id in sorted({int(event["domain_id"]) for event in events}):
                _resolve_security_event_entity_ids(cur, domain_id=row_domain_id, events=[event for event in events if event["domain_id"] == row_domain_id])
        else:
            _resolve_security_event_entity_ids(cur, domain_id=domain_id, events=events)
        if events:
            coverage = {"history_event_present": True}
        else:
            cur.execute(
                """select exists(
                       select 1 from events_v2_core event
                       join servers server on server.id=event.server_id
                       join storage_v2_channel channel on channel.id=event.channel_id
                       join storage_v2_provider provider on provider.id=event.provider_id
                      where """ + domain_sql + """ and server.role='domain_controller'
                        and event.event_id=any(%s) and channel.value=%s and """
                + provider_predicate
                + ") as history_event_present",
                [domain_id, event_ids, SECURITY_CHANNEL, *provider_params],
            )
            coverage = dict(cur.fetchone() or {})
        coverage["category_coverage"] = _read_security_event_category_coverage(
            cur,
            domain_id=domain_id,
            period_start=period_start,
            period_end=period_end,
            event_ids=event_ids,
            provider_predicate=provider_predicate,
            provider_params=provider_params,
            filter_sql=filter_sql,
            filter_params=filter_params,
        )
    return events, coverage, has_more


def _read_security_event_category_coverage(
    cur: Any,
    *,
    domain_id: int | list[int],
    period_start: datetime,
    period_end: datetime,
    event_ids: Sequence[int],
    provider_predicate: str,
    provider_params: Sequence[Any],
    filter_sql: str,
    filter_params: Sequence[Any],
) -> dict[str, dict[str, str]]:
    """Summarize the whole authorized filter domain, never a display page."""
    families = sorted({
        family for event_id in SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS
        if (family := security_event_family(event_id)) is not None
    })
    selected_families = {
        family for event_id in event_ids
        if (family := security_event_family(event_id)) is not None
    }
    domain_sql = "event.domain_id=any(%s)" if isinstance(domain_id, list) else "event.domain_id=%s"
    try:
        cur.execute(
            """select event.event_id,
                      bool_or(job.status in ('queued','leased')) as processing_unfinished
                 from events_v2_core event
                 join servers server on server.id=event.server_id
                 join storage_v2_channel channel on channel.id=event.channel_id
                 join storage_v2_provider provider on provider.id=event.provider_id
                 left join storage_v2_keywords keywords on keywords.id=event.keywords_id
                 left join event_facts_v2 facts on facts.event_id=event.id
                 left join semantic_processing_outbox job
                   on job.source_event_id=event.id and job.job_kind='normalize_event'
                where """ + domain_sql + """ and server.role='domain_controller'
                  and event.event_id=any(%s) and channel.value=%s and """
            + provider_predicate
            + " and event.time_created_utc>=%s and event.time_created_utc<%s"
            + filter_sql
            + " group by event.event_id",
            [
                domain_id, list(event_ids), SECURITY_CHANNEL, *provider_params,
                period_start, period_end, *filter_params,
            ],
        )
        rows = [dict(row) for row in cur.fetchall()]
    except Exception:
        return {
            family: {"state": "coverage_unavailable" if family in selected_families else "not_selected"}
            for family in families
        }
    unfinished_by_family: dict[str, bool] = {}
    present_families: set[str] = set()
    for row in rows:
        family = security_event_family(row.get("event_id"))
        if family is None:
            continue
        present_families.add(family)
        unfinished_by_family[family] = bool(unfinished_by_family.get(family) or row.get("processing_unfinished"))
    return {
        family: {
            "state": (
                "not_selected" if family not in selected_families
                else "processing_unfinished" if unfinished_by_family.get(family)
                else "retained_match_present" if family in present_families
                else "no_retained_match"
            )
        }
        for family in families
    }


def _normalized_object_sid(value: Any) -> str | None:
    clean = _text(value)
    return clean.lower() if clean else None










_csv_cell = format_csv_cell


def _read_security_event_domain_batch(*, after_domain_id: int, limit: int) -> list[int]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            "select id as domain_id from domains where id>%s order by id limit %s",
            (after_domain_id, limit),
        )
        return [int(row["domain_id"]) for row in cur.fetchall()]


def _has_security_event_source(domain_id: int) -> bool:
    # Discovery covers the persistence tab too; the main event vocabulary stays
    # unchanged. 7045 is a System/SCM event, not a Security auditing event.
    discovery_event_ids = SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS | {4697, 4698, 4699, 4700, 4701, 4702, 7045}
    provider_predicate = (
        "((event.event_id=%s and provider.value=%s) "
        "or (event.event_id<>%s and provider.value=%s))"
    )
    provider_params = [
        SECURITY_EVENTS_EVENTLOG_EVENT_ID,
        EVENTLOG_PROVIDER,
        SECURITY_EVENTS_EVENTLOG_EVENT_ID,
        SECURITY_AUDITING_PROVIDER,
    ]
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute("set local statement_timeout='3000ms'")
        cur.execute(
            """select exists(
                   select 1 from events_v2_core event
                   join servers server on server.id=event.server_id
                   join storage_v2_channel channel on channel.id=event.channel_id
                   join storage_v2_provider provider on provider.id=event.provider_id
                  where event.domain_id=%s and server.role='domain_controller'
                    and event.event_id=any(%s)
                    and ((event.event_id=7045 and channel.value=%s and provider.value=%s)
                      or (event.event_id<>7045 and channel.value=%s and """
            + provider_predicate
            + ")) limit 1) as source_present",
            [
                domain_id, sorted(discovery_event_ids), "System", "Service Control Manager", SECURITY_CHANNEL,
                *provider_params,
            ],
        )
        return bool((cur.fetchone() or {}).get("source_present"))


_connect = get_runtime_connection


from server.sli.reports.security_event_reporting_candidates import (
    _read_security_event_candidate_ids,
    get_security_event_candidate_ids,
)
from server.sli.reports.security_event_reporting_csv import (
    render_security_events_csv,
)
from server.sli.reports.security_event_reporting_daily import (
    _read_security_events_daily,
    get_security_events_daily,
)
from server.sli.reports.security_event_reporting_predicate import (
    _query_event_ids,
    _resolve_security_event_entity_ids,
    security_event_filter_predicate,
    security_event_read_contract,
)


# Compatibility aliases for focused consumers that predate the public shared
# filter/identity contract. New consumers import the explicit public names.
_normalize_filters = normalize_security_event_filters
_security_event_read_contract = security_event_read_contract
_filter_predicate = security_event_filter_predicate
