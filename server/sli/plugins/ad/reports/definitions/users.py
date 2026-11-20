"""«Пользователи» (ad.users.v2) on the v2 report framework (plan 5.5).

Replaces the standalone iframe page: the snapshot pair comes from the
unchanged ``users_v2_reporting`` engine, and the reference page's rules run
server-side in ``users_v2_views``. Building the snapshot is expensive, so the
pair is cached per domain scope for a short time.
"""

from __future__ import annotations

import threading
import time
import unicodedata
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Detail,
    Param,
    QueryContext,
    ReportDefinition,
    ReportIntent,
    View,
    csv_from_columns,
    result,
    sort_rows,
    source_state,
)
from server.sli.plugins.ad.reports import ad_hygiene_policy, report_additions, review_catalog, review_checks, users_activity, users_tabs
from server.sli.core import ad_service_exceptions
from server.sli.core.messages import message
from server.sli.plugins.ad.reports.users_v2_reporting import load_users_v2_snapshots
from server.sli.plugins.ad.reports.users_v2_views import (
    INFORMATION_KEYS,
    REASON_LABELS,
    compare,
    group_member_ids,
    is_account_expired,
    quality_issues,
    user_row,
)

REPORT_KEY = "ad.users.v2"
ALL_FIELDS = frozenset({"identity_basic", "technical", "security", "privilege", "hr", "contact"})
REASON_FIELDS = frozenset({"technical", "security", "privilege"})
# Raw dependencies are removed before search, comparison and derived counts.
RAW_FIELDS = {
    "hr": frozenset({"department", "title", "company", "manager", "employeeID"}),
    "contact": frozenset({"mail", "telephoneNumber", "mobile", "ipPhone"}),
    "technical": frozenset({"ou", "distinguishedName", "sid", "objectGuid", "description", "whenCreated", "whenChanged", "servicePrincipalNames", "objectClasses"}),
    "privilege": frozenset({"memberships", "privilegedMemberships", "adminCount"}),
    "security": frozenset({"enabled", "lockedOut", "accountExpirationDate", "exactLastLogon", "lastLogonTimestamp", "passwordExpiry",
                            "passwordLastSet", "passwordExpired", "passwordNeverExpires", "passwordNotRequired", "cannotChangePassword",
                            "smartcardLogonRequired", "accountNotDelegated", "allowReversiblePasswordEncryption", "trustedForDelegation",
                            "trustedToAuthForDelegation", "doesNotRequirePreAuth", "useDesKeyOnly", "userAccountControl"}),
}
ROW_FIELDS = {
    "hr": frozenset({"department", "title", "company", "manager", "employee_id"}),
    "contact": frozenset({"mail", "phones"}),
    "technical": frozenset({"ou", "dn", "sid", "guid", "description", "created", "changed", "spn", "service_account_type"}),
    "privilege": frozenset({"direct_groups", "effective_count", "watch_groups", "admin_count"}),
    "security": frozenset({"enabled", "locked", "account_expired", "activity_at", "activity_source", "password_last_set", "password_never_expires", "flags", "password_age_policy", "inactivity_policy", "hygiene", "password_not_required", "kerberos_no_preauth", "reversible_encryption", "smartcard_required", "account_not_delegated"}),
}
ROW_CATEGORIES = {path: frozenset({category}) for category, paths in ROW_FIELDS.items() for path in paths}
ROW_CATEGORIES.update({path: REASON_FIELDS for path in ("reasons", "reason_text", "reason_keys", "information_limitations", "information_keys", "information_text", "review_details")})
ROW_CATEGORIES.update(users_tabs.ROW_CATEGORIES)
ROW_CATEGORIES["last_workplace"] = frozenset({"security", "technical"})
ROW_CATEGORIES["membership_paths"] = frozenset({"privilege"})
ROW_CATEGORIES.update({path: REASON_FIELDS for path in ("severity", "service_exception")})
ROW_CATEGORIES.update({f"service_exception.{field}": REASON_FIELDS for field in ("excluded_by", "excluded_at")})
PARAM_CATEGORIES = {"department": frozenset({"hr"}), "company": frozenset({"hr"}), "ou": frozenset({"technical"}),
                    "group": frozenset({"privilege"}), "relation": frozenset({"privilege"}),
                    "view": REASON_FIELDS, "reason": REASON_FIELDS, "information": REASON_FIELDS, "period": frozenset({"security"}),
                    "max_minutes": REASON_FIELDS, "min_repeats": REASON_FIELDS, "activity_type": frozenset({"security"}),
                    "check": review_catalog.FIELDS, "as_of": frozenset({"security", "privilege"}),
                    "account_state": frozenset({"security"})}
ACTIVITY_FIELDS = frozenset({"technical", "security"})
ACTIVITY_TABS = frozenset({"disabled_active", "temporary_memberships"})
ACTIVITY_LIMITATIONS = [
    {"code": "activity_not_proof", "text": "Наблюдаемая последовательность не доказывает злоупотребление или использование выданного права. 6272 — разрешение NPS, а не подтверждённая VPN-сессия; 4624 на DC не доказывает интерактивный вход на рабочую станцию."},
    {"code": "activity_coverage", "text": "Полнота источников не подтверждена. События без точного SID и домена учитываются отдельно; время отключения известно только при наблюдаемом 4725. Повторное включение, репликация и рассинхронизация часов требуют проверки."},
]
VIEWS = (
    ("attention", "Требуют внимания"), ("information", "С ограничениями сведений"), ("all", "Все пользователи"), ("enabled", "Включённые"),
    ("disabled", "Отключённые"), ("locked", "Заблокированные"), ("expired", "Истёкшие учётные записи"),
)
RELATIONS = (("effective", "Эффективное членство"), ("direct", "Прямое членство"))
CACHE_SECONDS = 120
_cache: dict[tuple[int, ...] | None, tuple[float, dict[str, Any]]] = {}
_lock = threading.Lock()
_condition = threading.Condition(_lock)
_building: set[tuple[int, ...] | None] = set()


def _snapshots(domain_ids: list[int] | None, *, with_previous: bool = False) -> dict[str, Any]:
    key = None if domain_ids is None else tuple(sorted(domain_ids))
    with _condition:
        while True:
            cached = _cache.get(key)
            # A valid current snapshot remains readable during comparison loads.
            if cached and time.monotonic() - cached[0] < CACHE_SECONDS and (not with_previous or cached[1].get("previous_state") in {"loaded", "none"}):
                return cached[1]
            if key not in _building:
                _building.add(key)
                break
            # Coalesce this scope only; unrelated scopes never wait for its SQL.
            _condition.wait()
    try:
        payload = load_users_v2_snapshots(domain_ids=domain_ids, include_previous=with_previous)
        with _condition:
            _cache[key] = (time.monotonic(), payload)
        return payload
    finally:
        # A failed build must not leave this scope permanently blocked.
        with _condition:
            _building.remove(key)
            _condition.notify_all()


def _fold(value: Any) -> str:
    """Case-insensitive comparison key: casefold, Cyrillic yo=ye, NFKC, collapsed spaces."""
    text = unicodedata.normalize("NFKC", str(value or "")).casefold().replace("ё", "е")
    return " ".join(text.split())


def _in_view(view: str, user: dict[str, Any], row: dict[str, Any], observed_at: Any) -> bool:
    if view == "attention":
        return bool(row["reasons"])
    if view == "information":
        return bool(row["information_limitations"])
    if view == "enabled":
        return user.get("enabled") is True
    if view == "disabled":
        return user.get("enabled") is False
    if view == "locked":
        return user.get("lockedOut") is True
    if view == "expired":
        return is_account_expired(user, observed_at)
    return True


def _matches(user: dict[str, Any], row: dict[str, Any], params: dict[str, Any]) -> bool:
    q = _fold(params.get("q"))
    if q:
        haystack = _fold(" ".join(str(value) for value in (
            row["display_name"], row["sam"], row["upn"], row["mail"], row["phones"], row["department"], row["company"],
            row["title"], row["manager"], row["ou"], user.get("employeeID"), user.get("sid"), user.get("objectGuid"),
        ) if value))
        if q not in haystack:
            return False
    for key in ("department", "company", "ou"):
        if params.get(key) and row[key] != params[key]:
            return False
    if params.get("reason") and params["reason"] not in row["reason_keys"]:
        return False
    if params.get("information") and params["information"] not in row["information_keys"]:
        return False
    group = params.get("group")
    return not group or group in group_member_ids(user, params.get("relation") or "effective")


def _options(values: Any) -> list[dict[str, str]]:
    return [{"value": value, "label": value} for value in sorted({str(item) for item in values if item}, key=str.casefold)]


def _dated_snapshot(context: QueryContext) -> dict[str, Any]:
    """Use the accepted daily source at that date; never substitute current AD."""
    day = date.fromisoformat(str(context.params["as_of"]))
    zone = ZoneInfo(context.timezone)
    today = datetime.now(zone).date()
    if day > today or day < today - timedelta(days=365):
        raise ValueError("report_as_of_invalid")
    cutoff = (datetime.combine(day + timedelta(days=1), datetime.min.time(), zone) - timedelta(microseconds=1)).astimezone(timezone.utc)
    bundles = review_checks.load_snapshots("users", context.domain_ids, cutoff.isoformat())
    snapshots = [bundle.get("baseline") for bundle in bundles]
    if not any(snapshots):
        return {"state": "not_collected"}
    domains = [{"domain_id": bundle["domain_id"], "domain_name": bundle["domain_name"],
                "observed_at_utc": (bundle.get("baseline") or {}).get("observed_at"),
                "state": (bundle.get("baseline") or {}).get("state", "not_collected")} for bundle in bundles]
    complete = bool(bundles) and all(snapshot and snapshot.get("state") in review_checks.COMPLETE
                                     and review_checks._time(snapshot.get("observed_at")) for snapshot in snapshots)
    current = {"users": [{**obj, "domainId": bundle["domain_id"], "domainName": bundle["domain_name"],
                          "sourceStates": {**(obj.get("sourceStates") or {}), "directory": {
                              **((obj.get("sourceStates") or {}).get("directory") or {}),
                              "observed_at": bundle["baseline"]["observed_at"]}}}
                         for bundle in bundles if bundle.get("baseline") for obj in bundle["baseline"]["objects"]],
               "groups": [], "metadata": {"observed_at": min((str(domain["observed_at_utc"]) for domain in domains if domain["observed_at_utc"]), default=None),
                   "collection_status": "complete" if complete else "partial", "coverage": {
                       "state": "complete" if complete else "partial", "domains": domains,
                       "privilege_state": "complete" if complete else "partial"}}}
    return {"state": "ok", "current": current, "previous_state": "not_requested"}


def _prepare(context: QueryContext) -> dict[str, Any]:
    payload = _dated_snapshot(context) if context.tab == "privileged" and context.params.get("as_of") else _snapshots(context.domain_ids, with_previous=context.tab == "changes")
    current = payload.get("current")
    if not current:
        state = source_state(payload.get("state"))
        return {"state": state if state in {"denied", "not_collected", "processing", "error"} else "error"}
    observed_at = (current.get("metadata") or {}).get("observed_at")
    allowed = context.field_access or (lambda _: True)
    def project(snapshot):
        if not snapshot:
            return snapshot
        denied = set().union(*(paths for category, paths in RAW_FIELDS.items() if not allowed(frozenset({category}))))
        projected = {**snapshot, "users": [{key: value for key, value in user.items() if key not in denied} for user in snapshot.get("users") or []]}
        if not allowed(frozenset({"privilege"})):
            projected["groups"] = []
        if not allowed(ALL_FIELDS):
            for user in projected["users"]:
                states = user.get("sourceStates") or {}
                user["sourceStates"] = {key: {field: (states.get(key) or {}).get(field) for field in ("status", "observed_at")} for key in ("directory", "exact_last_logon", "password_last_set", "last_logon_timestamp")} if allowed(frozenset({"security"})) else {}
        return projected

    current = project(current)
    payload = {**payload, "current": current, "previous": project(payload.get("previous"))}
    policy = ad_hygiene_policy.thresholds()
    service_exceptions = ad_service_exceptions.configured() if allowed(REASON_FIELDS) else {}
    view = str(context.params.get("view") or ("attention" if allowed(REASON_FIELDS) else "all"))
    users = list(current.get("users") or [])
    activity = None
    if context.tab in {None, "users"} and allowed(REASON_FIELDS) and (current.get("metadata") or {}).get("watch_groups"):
        activity = users_activity.load(current, context.domain_ids, context.params)
        episodes: dict[int, list[dict]] = {}
        for episode in activity["temporary_memberships"]:
            episodes.setdefault(episode["entity_id"], []).append(episode)
        users = [{**user, "temporaryMemberships": episodes.get(user.get("entityId"), [])} for user in users]
    rows = [(user, user_row(user, (user.get("sourceStates") or {}).get("directory", {}).get("observed_at") or observed_at,
                           policy, service_exceptions=service_exceptions)) for user in users]
    historical = context.tab == "privileged" and bool(context.params.get("as_of"))
    workplaces = report_additions.last_workplaces(users, context.domain_ids, context=context) if not historical and allowed(ROW_CATEGORIES["last_workplace"]) else {}
    selection = context.runtime.get("domain_selection")
    qualify = selection.domain_id is None if selection is not None else context.domain_ids is None or len(context.domain_ids) > 1
    for user, row in rows:
        if allowed(ROW_CATEGORIES["membership_paths"]):
            row["membership_paths"] = (user.get("memberships") or {}).get("paths")
        if allowed(ROW_CATEGORIES["last_workplace"]):
            row["last_workplace"] = workplaces.get(user.get("entityId"))
        if user.get("domainId") is not None:
            row["domain_id"] = user["domainId"]
            row["domain_name"] = user.get("domainName")
            row["observed_at_utc"] = (user.get("sourceStates") or {}).get("directory", {}).get("observed_at") or observed_at
        if qualify and user.get("domainId") is not None:
            name = user.get("domainName") or str(user["domainId"])
            row["display_name"] = f"{name}\\{row.get('sam') or row['display_name']}"
            if row.get("sam"):
                row["sam"] = f"{name}\\{row['sam']}"
    counts = {key: sum(1 for user, row in rows if _in_view(key, user, row, observed_at)) for key, _ in VIEWS}
    selected = [row for user, row in rows if _in_view(view, user, row, observed_at) and _matches(user, row, context.params)]
    reason_counts = {key: sum(1 for _, row in rows if key in row["reason_keys"]) for key in REASON_LABELS}
    groups = {str(group.get("id")): str(group.get("name")) for group in current.get("groups") or [] if group.get("id")}
    return {
        "state": "ok", "payload": payload, "current": current, "observed_at": observed_at, "users": users, "rows": rows,
        "policy": policy, "selected": sort_rows(REPORT, selected, context.sort or ("reason" if view == "attention" else "name"), context.direction),
        "counts": counts, "reason_counts": reason_counts, "groups": groups, "activity": activity,
    }


def _activity_query(context: QueryContext) -> dict[str, Any]:
    fields = REASON_FIELDS if context.tab == "temporary_memberships" else ACTIVITY_FIELDS
    if context.field_access and not context.field_access(fields):
        return result(REPORT, state="denied")
    payload = _snapshots(context.domain_ids)
    current = payload.get("current")
    if payload.get("state") == "not_collected":
        return result(REPORT, state="not_collected", limitations=[{"code": "not_collected", "text": "Снимок пользователей для разрешённых доменов ещё не собран."}])
    if not current:
        state = source_state(payload.get("state"))
        return result(REPORT, state=state if state in {"denied", "processing", "error"} else "error",
                      coverage={"reason": "users_snapshot_unavailable"})
    data = users_activity.load(current, context.domain_ids, context.params, disabled=context.tab == "disabled_active")
    known = {user.get("entityId"): user for user in current.get("users") or []}
    selected = []
    policy = ad_hygiene_policy.thresholds()
    for row in data[str(context.tab)]:
        user = known[row["entity_id"]]
        # Apply only declared, authorised inventory fields. Group filtering in
        # this tab uses the observed episode, even if membership is gone now.
        filters = {key: value for key, value in context.params.items() if key in {"q", "department", "company", "ou"}}
        safe = {key: value for key, value in user.items() if all(
            key not in paths or not context.field_access or context.field_access(frozenset({category}))
            for category, paths in RAW_FIELDS.items())}
        if not _matches(safe, user_row(safe, (current.get("metadata") or {}).get("observed_at"), policy), filters):
            continue
        if context.params.get("group") and context.params["group"] != row.get("group_id"):
            continue
        if context.params.get("activity_type") and context.params["activity_type"] != row.get("activity_type"):
            continue
        selected.append(row)
    selected.sort(key=lambda row: (row.get("added_at") or row.get("activity_at"), row["id"]), reverse=True)
    limitations = list(ACTIVITY_LIMITATIONS)
    if data["truncated"] or len(selected) > context.limit:
        limitations.append({"code": "activity_bounded", "text": "Достигнут предел выборки событий или строк; сузьте период и фильтры. Счётчики отражают только ограниченную наблюдаемую выборку."})
    if data["state"] == "unavailable":
        limitations.append({"code": "activity_unavailable", "text": "Хранилище событий или корреляций недоступно для чтения; отсутствие строк не означает отсутствие активности."})
        return result(REPORT, state="error", limitations=limitations, window=data["window"],
                      coverage={"state": "unavailable", "completeness": "not_proven"})
    return result(
        REPORT, state="partial",
        collections={str(context.tab): selected[:context.limit]}, filtered_count=len(selected),
        metrics=[
            {"key": "activity_observations", "label": "Наблюдения в выборке", "value": len(selected)},
            {"key": "activity_accounts", "label": "Сопоставленные аккаунты", "value": len({row["entity_id"] for row in selected})},
            {"key": "activity_repeated", "label": "Повторные краткие включения", "value": sum(row.get("repeats", 0) > 1 for row in selected)},
            {"key": "activity_ambiguous", "label": "Неоднозначные продолжения", "value": sum(row["quality"] == "ambiguous" for row in selected)},
            {"key": "activity_unknown", "label": "События без точной идентичности", "value": data["unknown_identity_events"]},
        ],
        coverage={"state": data["state"], "completeness": "not_proven", "truncated": data["truncated"],
                  "unknown_identity_events": data["unknown_identity_events"], "unprocessed_events": data["unprocessed_events"],
                  "observed_at_utc": (current.get("metadata") or {}).get("observed_at")},
        limitations=limitations, window=data["window"],
        filter_options={"group": [{"value": group["id"], "label": group["name"]} for group in (current.get("metadata") or {}).get("watch_groups") or []]},
    )


def _query(context: QueryContext) -> dict[str, Any]:
    if context.tab in {None, "checks"}:
        return review_checks.query(REPORT, context, "users")
    if context.tab is None or context.tab in users_tabs.TABS:
        return users_tabs.query(REPORT, context, _prepare, _matches)
    if context.tab in ACTIVITY_TABS:
        return _activity_query(context)
    data = _prepare(context)
    if data["state"] == "not_collected":
        return result(REPORT, state="not_collected", limitations=[{"code": "not_collected", "text": "Снимок пользователей для разрешённых доменов ещё не собран."}])
    if data["state"] != "ok":
        return result(REPORT, state=data["state"], coverage={"reason": "users_snapshot_unavailable"})
    current, metadata = data["current"], data["current"].get("metadata") or {}
    try:
        offset = int(context.cursor or 0)
    except ValueError as exc:
        raise ValueError("report_cursor_invalid") from exc
    page = data["selected"][offset:offset + context.limit]
    has_more = offset + context.limit < len(data["selected"])
    collections: dict[str, list[dict[str, Any]]] = {}
    if context.tab == "changes":
        collections["changes"] = [{**row, "observed_at_utc": metadata.get("observed_at")}
                                  for row in compare(current, data["payload"].get("previous"))
                                  if not context.params.get("q") or _fold(context.params["q"]) in _fold(f"{row.get('display_name')} {row.get('sam')}")]
    if context.tab == "quality":
        collections["quality"] = [
            {**issue, "display_name": row["display_name"], "entity_id": row["entity_id"]}
            for user, row in data["rows"] for issue in quality_issues(user)
        ]
    status = str(metadata.get("collection_status") or "")
    state = "ok" if page else "empty"
    if status and status not in {"complete", "completed"}:
        state = "partial"
    limitations = [
        {"code": "threshold", "text": f"Принятая политика: возраст пароля > {data['policy']['password_age']} дней; неактивность > {data['policy']['inactivity']} дней. {ad_hygiene_policy.REPLICATION_CAVEAT}"},
        {"code": "not_proof", "text": "Причины внимания — наблюдения по атрибутам AD; они не доказывают злоупотребление и не заменяют решение владельца."},
    ]
    if data["activity"]:
        limitations.extend(ACTIVITY_LIMITATIONS)
        if data["activity"]["truncated"]:
            limitations.append({"code": "activity_bounded", "text": "Достигнут предел выборки событий или строк; сузьте период и фильтры. Счётчики отражают только ограниченную наблюдаемую выборку."})
        if data["activity"]["state"] == "unavailable":
            limitations.append({"code": "activity_unavailable", "text": "Хранилище событий или корреляций недоступно для чтения; отсутствие строк не означает отсутствие активности."})
        if state in {"ok", "empty"}:
            state = "partial"
    if status and status not in {"complete", "completed"}:
        limitations.append({"code": "partial_snapshot", "text": "Снимок собран частично: часть атрибутов или связей групп может отсутствовать."})
    previous_state = data["payload"].get("previous_state")
    if previous_state == "unavailable":
        limitations.append({"code": "comparison_unavailable", "text": "Сравнение с прошлым снимком сейчас недоступно: хранилище не отдало сохранённые снимки. Текущий список построен полностью."})
    elif previous_state != "not_requested" and not data["payload"].get("previous"):
        limitations.append({"code": "single_snapshot", "text": "Есть только один снимок: изменения между снимками пока не вычисляются."})
    if context.tab == "changes" and not data["payload"].get("previous"):
        state = "error" if previous_state == "unavailable" else "partial"
    counts = data["counts"]
    return result(
        REPORT, state=state, items=page, has_more=has_more, next_cursor=str(offset + len(page)) if has_more else None,
        filtered_count=len(collections["changes"]) if context.tab == "changes" else len(data["selected"]),
        metrics=[
            {"key": key, "label": label, "value": counts[key], "filter": {"view": key},
             "tone": "warning" if key == "attention" and counts[key] else "danger" if key == "locked" and counts[key] else "accent" if key == "all" else "neutral"}
            for key, label in VIEWS
        ],
        coverage={**(metadata.get("coverage") or {}), "hygiene_policy": data["policy"], "state": status or "unknown", "observed_at_utc": metadata.get("observed_at"), "users": len(data["users"]),
                  "missing_sources": [source["name"] for source in metadata.get("sources") or [] if source.get("name") and source.get("status") not in {"observed", "no_record", "not_applicable"}],
                  **({"completeness": "not_proven", "activity": {key: data["activity"][key] for key in
                      ("state", "truncated", "window", "unknown_identity_events", "unprocessed_events")}} if data["activity"] else {})},
        filter_options={
            "department": _options(row["department"] for _, row in data["rows"]),
            "company": _options(row["company"] for _, row in data["rows"]),
            "ou": _options(row["ou"] for _, row in data["rows"]),
            "group": sorted(({"value": gid, "label": name} for gid, name in data["groups"].items()), key=lambda item: item["label"].casefold()),
            "reason": [{"value": key, "label": label, "count": data["reason_counts"][key]} for key, label in REASON_LABELS.items() if data["reason_counts"][key]],
        },
        collections=collections, limitations=limitations,
        window={"from_utc": ((data["payload"].get("previous") or {}).get("metadata") or {}).get("observed_at") if context.tab == "changes" else metadata.get("observed_at"),
                "to_utc": metadata.get("observed_at")},
    )


def _export(context: QueryContext) -> tuple[str, dict[str, Any]]:
    if context.tab in {None, "checks", "changes"}:
        payload = _query(replace(context, cursor=None, limit=100_000))
        if payload["state"] in {"error", "not_collected", "denied"}:
            raise PermissionError("report_access_denied")
        view = next(view for view in REPORT.views if view.key == (context.tab or "checks"))
        rows = [row for row in payload.get("collections", {}).get(view.source, payload["items"]) if row.get("section") != "not_evaluated"]
        return csv_from_columns(view.columns, rows), {"rows": len(rows), "truncated": bool(payload["coverage"].get("truncated") or payload["coverage"].get("events_truncated"))}
    if context.tab in users_tabs.TABS:
        payload = _query(replace(context, cursor=None, limit=100_000))
        if payload["state"] in {"error", "not_collected", "denied"}:
            raise PermissionError("report_access_denied")
        return csv_from_columns(REPORT.columns, payload["items"]), {"rows": len(payload["items"]), "truncated": payload["coverage"].get("truncated", False)}
    data = _prepare(context)
    rows = data.get("selected") or []
    return csv_from_columns(REPORT.columns, rows), {"rows": len(rows), "truncated": False}


REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="AD account reviewer",
        question="Какие учётные записи AD требуют внимания в выбранном срезе?",
        action="Review account state, reasons and evidence before deciding on account maintenance.",
        scope="Server-authorized domains; one AD account per row in the latest snapshot; bounded comparison and activity tabs.",
        exclusions="Not an HR person census; enabled does not prove activity; event gaps do not prove inactivity.",
        sources=(
            "Canonical: current and optional previous AD user snapshots within granted domains.",
            "Supplemental: current semantic account and group activity facts in the selected window.",
        ),
        freshness_expectation="Время последнего снимка AD; для активности — подтверждение источников выбранного окна.",
        rights="ad.users.v2 view grant and server domain scope; optional categories checked atomically over the scope; export separately granted.",
        field_classes=(
            "identity_basic",
            "technical",
            "security",
            "privilege",
            "hr",
            "contact",
        ),
        coverage="Snapshot source quality and available attributes for AD accounts; event coverage is separate.",
        completeness="Source-confirmed AD accounts divided by expected accounts in the authorized snapshot population before pagination; missing attributes and event continuity are separate quality dimensions. Unknown without a confirmed population.",
        denominator="Все учётные записи AD ожидаемого снимка в разрешённом срезе; кадровый список не является знаменателем.",
        retention="Derived account history follows the storage policy; snapshot and source-event evidence may expire independently.",
        provenance="Snapshot pair, account identity and source timestamps; exact event IDs for activity; missing source attributes remain unknown.",
        primary_archetype="list",
        product_archetype="inventory-status",
        deterministic_policy="Use observed AD account state, membership and activity reasons; lifecycle and accepted-risk records stay separate from observations.",
        result_limits="Account pages, changes period and source sections have independent bounds; missing activity is unknown.",
        fallback="Missing attributes and incomplete snapshots remain quality gaps; absence of accounts does not establish a complete directory.",
        acceptance_lanes={
            "product_user": "Account filters and reasons support a manual account review.",
            "authorization": "ad.users.v2 grant, field categories, domain scope and independent export grant constrain all views.",
            "deterministic_interpretation": "Observed state, privileged membership, activity reasons and risk decisions are not conflated.",
            "api_view_model": "User rows and change collections preserve the existing filters, limits and row identities.",
            "ui_honest_states": "Partial sections, stale snapshots, unknown activity and unavailable history stay explicit.",
            "evidence_audit": "Account identity, relation observations and lifecycle author/time remain attributable.",
        },
    ),
    key=REPORT_KEY,
    section="reports/identity",
    title="Пользователи",
    description="Учётные записи пользователей домена по последнему снимку AD: причины внимания, состояние, организация, группы и активность.",
    archetype="inventory-status",
    access=AccessRule(REPORT_KEY, frozenset({"identity_basic"})),
    row_categories=ROW_CATEGORIES,
    metric_categories={**{key: REASON_FIELDS for key, _ in VIEWS if key != "all"},
                       "unknown": frozenset({"security"}),
                       **{key: ACTIVITY_FIELDS for key in ("activity_observations", "activity_accounts", "activity_unknown")},
                       **{key: REASON_FIELDS for key in ("activity_repeated", "activity_ambiguous")}},
    params=(
        Param("domain_id", "Домен", "domain", hidden=True),
        Param("domain", "Домен", "domain", hidden=True),
        Param.choice("view", "Срез", VIEWS, default="attention"),
        Param.text("q", "Поиск"),
        Param.choice("reason", "Причина", options_from="reason"),
        Param.choice("information", "Ограничение сведений", tuple((key, REASON_LABELS[key]) for key in REASON_LABELS if key in INFORMATION_KEYS)),
        Param.choice("department", "Подразделение", options_from="department"),
        Param.choice("company", "Компания", options_from="company"),
        Param.choice("ou", "OU", options_from="ou"),
        Param.choice("group", "Группа", options_from="group"),
        Param.choice("relation", "Членство", RELATIONS, default="effective"),
        Param.period(max_days=31, presets=("24h", "7d", "30d", "custom")),
        Param.integer("max_minutes", "Максимальный интервал членства, мин"),
        Param.integer("min_repeats", "Минимум кратких включений"),
        Param.choice("activity_type", "Тип активности", (("4624", "Успешная аутентификация Windows (4624)"), ("6272", "Разрешение NPS (6272)"))),
    ),
    columns=(
        Column("name", "Пользователь", path="display_name", sortable=True, link="/app/entities/{entity_id}"),
        Column("reason", "Требует внимания", path="reason_text", sortable=True),
        Column("information", "Ограничения сведений", path="information_text"),
        Column("state", "Включена", "boolean", path="enabled", sortable=True),
        Column("department", "Подразделение", sortable=True),
        Column("title", "Должность", sortable=True),
        Column("activity", "Последняя активность", "datetime", path="activity_at", sortable=True),
        Column("last_workplace", "Последнее рабочее место", component="ad.last-workplace"),
        Column("sam", "Логин", "code", sortable=True, optional=False),
        Column("groups", "Прямые группы", "list", path="direct_groups", optional=True),
        Column("effective", "Эффективных групп", "number", path="effective_count", sortable=True, optional=True),
        Column("watch", "Контрольные группы", "list", path="watch_groups", optional=True),
        Column("locked", "Заблокирована", "boolean", optional=True),
        Column("upn", "UPN", "code", optional=True),
        Column("mail", "Почта", optional=True),
        Column("phones", "Телефоны", optional=True),
        Column("company", "Компания", optional=True),
        Column("manager", "Руководитель", optional=True),
        Column("ou", "OU", optional=True),
        Column("activity_source", "Источник активности", optional=True),
        Column("password_age_policy", "Возраст пароля по политике", "state", labels={"unknown": "Неизвестно", "exceeded": "Порог превышен", "within_policy": "В пределах политики"}),
        Column("inactivity_policy", "Неактивность по политике", "state", labels={"unknown": "Неизвестно", "exceeded": "Порог превышен", "within_policy": "В пределах политики"}),
        Column("password_last_set", "Пароль изменён", "datetime", optional=True),
        Column("password_never_expires", "Пароль бессрочный", "boolean", optional=True),
        Column("password_not_required", "Пароль не требуется", "boolean", optional=True),
        Column("kerberos_no_preauth", "Kerberos без предварительной аутентификации", "boolean", optional=True),
        Column("reversible_encryption", "Обратимое шифрование пароля", "boolean", optional=True),
        Column("smartcard_required", "Требуется смарт-карта", "boolean", optional=True),
        Column("account_not_delegated", "Чувствительная учётная запись, не делегируется", "boolean", optional=True),
        Column("service_account_type", "Тип сервисной учётной записи", "state", optional=True, labels={"spn": "SPN", "msa": "MSA", "gmsa": "gMSA"}),
        Column("admin_count", "adminCount (исторический признак защиты)", "number", optional=True),
        Column("severity", "Уровень внимания", "state", labels={"high": "Высокий", "medium": "Средний"}),
        Column("service_exception_by", "Исключение сервиса: кто добавил", path="service_exception.excluded_by", optional=True),
        Column("service_exception_at", "Исключение сервиса: когда добавлено", "datetime", path="service_exception.excluded_at", optional=True),
        Column("flags", "Security-флаги", "list", optional=True),
        Column("spn", "SPN", "list", optional=True),
        Column("created", "Создана", "datetime", optional=True),
        Column("changed", "Изменена", "datetime", optional=True),
        Column("employee_id", "Табельный номер", optional=True),
        Column("description", "Описание", optional=True),
        Column("dn", "DN", "code", optional=True),
        Column("sid", "SID", "code", optional=True),
    ),
    views=(
        View("table", "users", "Пользователи"),
        View("table", "disabled_active", "Отключены, но активны", source="disabled_active", access=AccessRule(REPORT_KEY, ACTIVITY_FIELDS),
             note="Отключены в последнем снимке AD; наблюдались 4624 или разрешение NPS 6272 после последнего 4725 без наблюдаемого повторного включения.", columns=(
                 Column("name", "Пользователь", path="display_name", link="/app/entities/{entity_id}"),
                 Column("disabled_at", "Отключение (4725)", "datetime"), Column("activity_at", "Последующая активность", "datetime"),
                 Column("activity_type", "Тип активности", "code"), Column("delay_minutes", "Задержка, мин", "number"),
                 Column("source_id", "Источник", "code"), Column("logon_type", "Тип входа", "code"),
                 Column("evidence", "События", "list"), Column("quality", "Качество", "state", labels={"exact_sid": "Точный SID и домен"}),
             )),
        View("table", "temporary_memberships", "Краткое членство в контрольных группах", source="temporary_memberships", access=AccessRule(REPORT_KEY, REASON_FIELDS),
             note="Наблюдаемые добавление → удаление (4728/4729, 4732/4733, 4756/4757); короткий интервал и повторы не доказывают злоупотребление.", columns=(
                 Column("name", "Участник", path="display_name", link="/app/entities/{entity_id}"), Column("group", "Контрольная группа"),
                 Column("added_at", "Добавление", "datetime"), Column("removed_at", "Удаление", "datetime"),
                 Column("interval_minutes", "Наблюдаемый интервал, мин", "number"), Column("repeats", "Кратких включений", "number"),
                 Column("added_by", "Добавивший субъект", "code"), Column("removed_by", "Удалившие субъекты", "list"),
                 Column("activity_count", "Аутентификации внутри интервала", "number"), Column("activity_evidence", "События аутентификации", "list"),
                 Column("evidence", "События членства", "list"), Column("candidate_id", "Корреляция", "code"),
                 Column("quality", "Качество", "state", labels={"observed_pair": "Наблюдаемая пара", "ambiguous": "Неоднозначное продолжение"}),
             )),
        View("table", "changes", "Изменения", source="changes", note="Сравнение двух последних снимков; отсутствие объекта не доказывает его удаление.", columns=(
            Column("name", "Пользователь", path="display_name", link="/app/entities/{entity_id}"), Column("change", "Изменение", path="label"),
            Column("field", "Поле / связь", path="field"), Column("before", "Было", path="before"), Column("after", "Стало", path="after"),
            Column("group", "Категория", path="change_group"), Column("note", "Примечание", path="note"),
        )),
        View("table", "quality", "Качество источников", source="quality", access=AccessRule(REPORT_KEY, ALL_FIELDS), note="Что источник не смог подтвердить; это не отсутствие значения.", columns=(
            Column("name", "Пользователь", path="display_name", link="/app/entities/{entity_id}"), Column("status", "Состояние", "code", path="status"),
            Column("kind", "Тип", path="kind"), Column("field", "Источник / связь", path="field"), Column("detail", "Наблюдение", path="detail"),
        )),
    ),
    query=_query,
    export_csv=_export,
    row_key="id",
    detail=Detail(
        title="Основания проверки и ограничения сведений",
        key="id",
        inline="review_details",
        columns=(
            Column("category", "Основание", "state", labels={"confirmed": "Подтверждённая причина", "information": "Ограничение сведений"}),
            Column("severity", "Уровень внимания", "state", labels={"high": "Высокий", "medium": "Средний", "info": "Информация"}),
            Column("label", "Причина"), Column("observed", "Наблюдалось"), Column("condition", "Условие"),
            Column("qualification", "Квалификация"), Column("limitation", "Ограничение"), Column("next", "Безопасный следующий шаг"),
        ),
    ),
    presets=(
        ("Заблокированные", {"view": "locked"}),
        ("Контрольные группы", {"view": "attention", "reason": "watch_group_membership"}),
        ("Давно не входили", {"view": "attention", "reason": "inactive_threshold"}),
    ),
    row_links=(("Карточка пользователя", "/app/entities/{entity_id}"),),
    default_limit=100,
    max_limit=500,
    home_order=30,
)

# Keep field dependencies next to the raw/derived mappings so all surfaces
# (table, details, filters, metrics and CSV) share the same classification.
REPORT = replace(
    REPORT,
    views=(View("table", "checks", message(review_catalog.PREFIX + "tab")["text"],
                source="checks", columns=review_catalog.columns(), access=AccessRule(REPORT_KEY, review_catalog.FIELDS)),
           View("table", "privileged", "Привилегированные", access=AccessRule(REPORT_KEY, users_tabs.FIELDS["privileged"])),
           replace(next(view for view in REPORT.views if view.key == "changes"),
                   columns=(Column("observed_at_utc", "Наблюдение снимка", "datetime"),
                            *next(view for view in REPORT.views if view.key == "changes").columns,
                            Column("actor", "Исполнитель"))),
           View("table", "all", "Все учётки", access=AccessRule(REPORT_KEY, users_tabs.FIELDS["all"]))),
    params=tuple(param for param in REPORT.params if param.key in {"domain_id", "domain", "q", "reason", "information", "department", "company", "ou", "group", "relation"}) + (
        Param("check", "Проверка", "text", hidden=True), Param("as_of", "Состав на дату", "text", hidden=True),
        Param.choice("account_state", "Состояние", (("enabled", "Включена"), ("disabled", "Отключена"), ("unknown", "Нет данных"))),
    ),
    default_limit=50,
    presets=(),
    columns=tuple(column for column in REPORT.columns if column.key not in {extra.key for extra in users_tabs.COLUMNS}) + users_tabs.COLUMNS,
)
REPORT = replace(
    REPORT,
    columns=tuple(replace(column, field_categories=ROW_CATEGORIES.get(column.path or column.key, frozenset({"identity_basic"}))) for column in REPORT.columns),
    params=tuple(replace(param, field_categories=PARAM_CATEGORIES.get(param.key, frozenset({"identity_basic"}))) for param in REPORT.params),
    views=tuple(replace(view, columns=tuple(replace(column, field_categories=REASON_FIELDS if view.key == "temporary_memberships" else ACTIVITY_FIELDS)
                                          for column in view.columns)) if view.key in ACTIVITY_TABS else view for view in REPORT.views),
)
