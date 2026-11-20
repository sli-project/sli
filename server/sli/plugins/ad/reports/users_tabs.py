"""Independent owner-requested user slices over the authorised AD snapshot."""
from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import replace

from psycopg.errors import InsufficientPrivilege

from server.sli.core.database import query_rows_bounded
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import AccessRule, Column, result, sort_rows
from server.sli.plugins.ad.reports import ad_hygiene_policy, users_security
from server.sli.plugins.ad.reports.users_reporting import USERS_INPUT_LIMIT
from server.sli.plugins.ad.reports.users_v2_views import INFORMATION_KEYS, REASON_LABELS
from server.sli.semantic.findings import _semantic_runtime_projection

TABS = {"all": "Все учётки", "active": "Активные", "disabled": "Отключённые", "privileged": "Привилегированные",
        "risk": "Риск", "semantic": "Семантика"}
FIELDS = {key: frozenset({"security", "privilege"} if key == "privileged" else {"security"}) for key in TABS}
ROW_CATEGORIES = {"privilege_basis": frozenset({"privilege"}),
                  "nested_privilege_groups": frozenset({"privilege"}),
                  "password_age_policy": frozenset({"security"}), "inactivity_policy": frozenset({"security"}),
                  "finding_count": frozenset({"security"}), "queue_entity_id": frozenset({"security"})}
POLICY_LABELS = {"unknown": "Неизвестно", "exceeded": "Порог превышен", "within_policy": "В пределах политики"}
COLUMNS = (
    Column("privilege_basis", "Основание привилегий", "list"),
    Column("nested_privilege_groups", "Известные вложенные привилегированные группы", "list"),
    Column("password_age_policy", "Возраст пароля по политике", "state", labels=POLICY_LABELS),
    Column("inactivity_policy", "Неактивность по политике", "state", labels=POLICY_LABELS),
    Column("finding_count", "Открытых находок", "number"),
    Column("queue", "Очередь проблем", path="queue_entity_id", link="/app/report/security.problems?entity_id={queue_entity_id}"),
)


def _semantic(entity_ids):
    rows = query_rows_bounded(
        """select linked.entity_id,count(distinct finding.id) as finding_count
           from findings_active finding
           join finding_entities linked on linked.finding_id=finding.id
           where linked.entity_id=any(?)
             and finding.status in ('new','repeated','confirmed','active','review')
             and is_semantic_finding_published_v1(finding.id)
             and not semantic_finding_suppressed_v160(finding.id,finding.rule_code)
           group by linked.entity_id""", (entity_ids,), statement_timeout_ms=5000,
    ) if entity_ids else []
    heartbeat = query_rows_bounded(
        """select status,phase,heartbeat_at,expected_interval_seconds,details_json
           from runtime_worker_heartbeats where worker_name='semantic' limit 1""",
        statement_timeout_ms=5000,
    )
    runtime = _semantic_runtime_projection(dict(heartbeat[0]) if heartbeat else {}, generated=datetime.now(timezone.utc))
    return {int(row["entity_id"]): int(row["finding_count"]) for row in rows}, runtime["findings_state"]


def query(report, context, prepare, matches):
    tab = context.tab or "active"
    if context.field_access and not context.field_access(FIELDS[tab]):
        return result(report, state="denied")
    if tab == "semantic":
        decision = ReportAccess(report, context.access).rule_decision(AccessRule("security.queue", scope="delegated"))
        if not decision["allowed"]:
            return result(report, state="denied")
    data = prepare(replace(context, tab=tab))
    if data["state"] != "ok":
        return result(report, state=data["state"], coverage={"reason": "users_snapshot_unavailable"})
    metadata = data["current"].get("metadata") or {}
    coverage = metadata.get("coverage") or {}
    directory_state = coverage.get("state") or next((source.get("status") for source in metadata.get("sources") or [] if source.get("name") == "directory"), None)
    directory_state = directory_state or metadata.get("collection_status")
    state = {"observed": "ok", "complete": "ok", "completed": "ok", "stale": "stale",
             "failed": "error", "unavailable": "error", "error": "error",
             "not_collected": "not_collected", "processing": "processing", "denied": "denied"}.get(directory_state, "partial")
    if state in {"error", "not_collected", "denied"}:
        return result(report, state=state, coverage={**coverage, "state": directory_state})
    limitations = []
    truncated = len(data["users"]) >= USERS_INPUT_LIMIT
    if truncated:
        state = "partial" if state == "ok" else state
        limitations.append({"code": "users_bounded", "text": "Выборка пользователей ограничена; счётчики отражают доступную часть снимка."})
    policy = data["policy"] if tab == "risk" else None
    findings = {}
    if tab == "semantic":
        try:
            findings, semantic_state = _semantic([user["entityId"] for user in data["users"] if user.get("entityId")])
        except InsufficientPrivilege:
            return result(report, state="denied")
        except Exception:
            return result(report, state="error", coverage={"reason": "semantic_unavailable"})
        if semantic_state != "active":
            state = "stale" if semantic_state == "stale" or state == "stale" else "partial"
            limitations.append({"code": "semantic_incomplete", "text": "Актуальность семантического анализа не подтверждена; ноль находок не означает отсутствие проблем."})
    selected = []
    unknown = 0
    group_options = dict(data["groups"])
    match_params = {key: value for key, value in context.params.items() if tab != "privileged" or key != "group"}
    for user, original in data["rows"]:
        row = {**original, "enabled": user.get("enabled")}
        included = user.get("enabled") is (tab == "active") if tab in {"active", "disabled"} else tab == "all"
        account_state = context.params.get("account_state")
        if tab == "all" and account_state:
            included = user.get("enabled") is {"enabled": True, "disabled": False, "unknown": None}[account_state]
        if tab == "privileged":
            direct = user.get("privilegedMemberships")
            effective = [group for group in (user.get("memberships") or {}).get("effective") or [] if group.get("watchGroup")]
            row["privilege_basis"] = [entry.get("group") or str(entry.get("group_id")) for entry in direct or [] if entry.get("relation") == "direct"]
            row["nested_privilege_groups"] = [group.get("name") for group in effective if group.get("relation") == "nested"]
            row["privilege_basis"] += [group.get("name") or group.get("id") for group in effective if group.get("relation") in {"direct", "primary"} and group.get("name") not in row["privilege_basis"]]
            included = bool(row["privilege_basis"] or row["nested_privilege_groups"])
            direct_ids = set()
            for entry in direct or []:
                if entry.get("relation") == "direct" and entry.get("group_id"):
                    group_id = str(entry["group_id"])
                    direct_ids.update({group_id, f"group:{group_id}"})
                    group_options[f"group:{group_id}"] = entry.get("group") or group_id
            for group in effective:
                group_id = str(group.get("id") or "")
                if group_id:
                    direct_ids.update({group_id, group_id.removeprefix("group:")})
                    group_options[group_id] = group.get("name") or group_id
            if context.params.get("group"):
                included = included and context.params["group"] in direct_ids
            unknown += direct is None
        elif tab == "risk":
            hygiene = ad_hygiene_policy.for_user(user, data["observed_at"], policy)
            row.update(password_age_policy=hygiene["password_age"]["status"], inactivity_policy=hygiene["inactivity"]["status"])
            included = bool(set(row["reason_keys"]) & (users_security.RISK_KEYS | {"password_age", "inactive_threshold", "sensitive_uac_flag"}))
            if "unknown" in {row["password_age_policy"], row["inactivity_policy"]} and matches(user, row, match_params):
                unknown += 1
        elif tab == "semantic":
            row.update(finding_count=findings.get(user.get("entityId"), 0), queue_entity_id=user.get("entityId"))
            included = bool(row["finding_count"])
        if tab in {"active", "disabled"}:
            unknown += user.get("enabled") is None
        if included and matches(user, row, match_params):
            selected.append(row)
    if tab == "privileged" and coverage.get("privilege_state") != "complete":
        state = "partial" if state == "ok" else state
        limitations.append({"code": "privilege_incomplete", "text": "Полнота привилегированного членства не подтверждена; показаны известные прямые, основные и вложенные связи."})
    if unknown:
        state = "partial" if state == "ok" else state
        limitations.append({"code": "unknown_accounts", "text": f"Недостаточно данных для классификации: {unknown}."})
    if policy:
        limitations.append({"code": "hygiene_policy", "text": f"Пороги политики: пароль > {policy['password_age']} дней; неактивность > {policy['inactivity']} дней. lastLogonTimestamp — приблизительный реплицируемый атрибут; это не доказательство отсутствия входов."})
    selected = sort_rows(report, selected, context.sort or "name", context.direction)
    try:
        offset = int(context.cursor or 0)
        if offset < 0:
            raise ValueError
    except ValueError as exc:
        raise ValueError("report_cursor_invalid") from exc
    page = selected[offset:offset + context.limit]
    more = offset + len(page) < len(selected)
    return result(report, state="empty" if state == "ok" and not selected else state, items=page,
                  metrics=[{"key": "attention", "label": "Подтверждённые причины проверки", "value": sum(bool(row["reasons"]) for row in selected)},
                           {"key": "information", "label": "С ограничениями сведений", "value": sum(bool(row["information_limitations"]) for row in selected)},
                           *([{"key": "unknown", "label": "Оценка по политике неизвестна", "value": unknown}] if tab == "risk" else [])],
                  filtered_count=len(selected), has_more=more, next_cursor=str(offset + len(page)) if more else None,
                  coverage={**coverage, "state": directory_state, "observed_at_utc": metadata.get("observed_at"), "tab": tab,
                            "as_of": context.params.get("as_of") if tab == "privileged" else None, "population": len(data["users"]),
                            "unknown_accounts": unknown, "hygiene_policy": policy, "truncated": truncated,
                            **({"risk_accounts": len(selected)} if tab == "risk" else {}),
                            "disabled_privileged": sum(row.get("enabled") is False for row in selected) if tab == "privileged" else None},
                  filter_options={
                      "reason": [{"value": key, "label": label} for key, label in REASON_LABELS.items() if key not in INFORMATION_KEYS and any(key in row["reason_keys"] for row in selected)],
                      **{key: [{"value": value, "label": value} for value in sorted({row[key] for _, row in data["rows"] if row[key]})] for key in ("department", "company", "ou")},
                      "group": [{"value": key, "label": value} for key, value in group_options.items()],
                  },
                  limitations=limitations)
