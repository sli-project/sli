"""«VPN-подключения» (vpn.connections) on the v2 report framework (plan 5.2).

Each source enforces its own access and degrades independently. Accounting
provides employees, analytics and entitlements; NPS and Windows views are
loaded only when requested.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from psycopg import OperationalError
from psycopg import errors as psycopg_errors

from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.core.database import QueryTimeoutError
from server.sli.core.time_contract import TimeRangeError
from server.sli.ops.logging_config import log_internal_error
from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Detail,
    Param,
    QueryContext,
    ReportDefinition,
    ReportIntent,
    View,
    result,
    source_state,
)
from server.sli.plugins.remote_access.reports import nps_policy_denials
from server.sli.plugins.remote_access.reports.vpn_connections_reporting import (
    MAX_EMPLOYEE_PAGE,
    MAX_PERIOD_DAYS,
    get_vpn_authorization_timeline,
    get_vpn_connections_report,
)
from server.sli.plugins.remote_access.reports.vpn_connections_reporting import (
    _coverage_state as engine_coverage_state,
)
from server.sli.plugins.remote_access.reports.vpn_session_reporting import get_vpn_session_sources
from server.sli.plugins.remote_access.session_overlap import MAX_PERIOD_DAYS as OVERLAP_MAX_PERIOD_DAYS
from server.sli.plugins.remote_access.session_overlap import get_overlaps
from server.sli.plugins.remote_access.home import CLOSED_SESSIONS
from server.sli.reports.windows_authentication_reporting import (
    MAX_PERIOD_DAYS as WINDOWS_MAX_PERIOD_DAYS,
)
from server.sli.reports.windows_authentication_reporting import (
    get_windows_authentication_failure_grid,
    get_windows_authentication_report,
)

REPORT_KEY = "vpn.connections"
ACCESS_KEY = "vpn.audit"
STATUSES = (("all", "Все сотрудники"), ("closed", "С завершёнными сессиями"), ("open", "С незавершёнными сессиями"))
LIFECYCLE = (("closed", "Завершена"), ("open_observed", "Не завершена (наблюдается)"), ("open", "Не завершена"), ("incomplete", "Неполная"))
_COVERAGE_NOTE = {
    "processing": "Часть событий RADIUS ещё обрабатывается.",
    "identity_incomplete": "Для части сессий не удалось определить учётную запись.",
    "partial": "Часть событий не сопоставлена с учётной записью или временем.",
    "not_collected": "События RADIUS для этого домена не собраны.",
}


#: The RADIUS read views may be unreadable or absent (clean install, a role
#: without grants on the underlying tables). That is an unavailable source, not
#: a server error: the report must still open and say so honestly.
_SOURCE_UNREADABLE = (psycopg_errors.InsufficientPrivilege, psycopg_errors.UndefinedTable, psycopg_errors.UndefinedColumn, OperationalError)


def _log_source_unreadable(event: str, exc: BaseException) -> None:
    if isinstance(exc, OperationalError) and exc.sqlstate and not exc.sqlstate.startswith("08") and not isinstance(exc, psycopg_errors.QueryCanceled):
        raise exc
    log_internal_error("reports", event, "VPN source read model is not readable; its branch is shown as unavailable.", exc=exc, level=logging.WARNING, report=REPORT_KEY)


def _branch(raw: Mapping[str, Any], notes: list[dict[str, Any]], *, empty: bool = False) -> dict[str, Any]:
    engine_state = str(raw.get("state") or "unavailable")
    state = _source_result_state(raw)
    if state == "ok" and (raw.get("result_window") or {}).get("truncated"):
        state = "partial"
    if state == "ok" and empty:
        state = "empty"
    reason = raw.get("unavailable_reason") or ("result_truncated" if (raw.get("result_window") or {}).get("truncated") else engine_state)
    if reason == "source_read_timeout":
        notes = [{"code": "source_read_timeout", "text": "Чтение заняло слишком много времени. Результат неполный; показаны только полученные данные. Повторите попытку или сократите период."}, *notes]
    elif reason == "result_truncated":
        notes = [{"code": "result_truncated", "text": "Событий больше, чем можно показать за один раз. Список неполный; сократите период, чтобы увидеть остальные события."}, *notes]
    elif reason == "review_input_limit":
        notes = [{"code": "review_input_limit", "text": "Событий слишком много для полной проверки сигналов. История показана частично; сократите период. Отсутствие сигналов не означает отсутствия атак."}, *notes]
    return {"state": state, "reason": reason,
            "limitations": notes, "limits": dict(raw.get("limits") or {})}


def _source_result_state(raw: Mapping[str, Any]) -> str:
    state = source_state(raw.get("state"))
    if state == "partial" and raw.get("unavailable_reason") == "source_read_timeout":
        return state
    coverage = raw.get("coverage") or {}
    if state in {"ok", "empty", "partial"} and "total_delivery_count" in coverage:
        coverage_state = source_state(engine_coverage_state(coverage))
        if coverage_state in {"processing", "not_collected", "partial"}:
            return coverage_state
    return state


def _read_source(reader: Any, context: QueryContext, branch: str, **kwargs: Any) -> dict[str, Any]:
    period = context.params["period"]
    try:
        raw = reader(context.access, source_domain_id=int(context.params["domain"]),
                     time_from=period["from_utc"], time_to=period["to_utc"], **kwargs)
    except (QueryTimeoutError, psycopg_errors.QueryCanceled):
        raw = {"state": "partial", "unavailable_reason": "source_read_timeout",
               "coverage": {"state": "partial", "completeness": "not_proven"}}
    except _SOURCE_UNREADABLE as exc:
        _log_source_unreadable(f"{branch}_source_unreadable", exc)
        raw = {"state": "unavailable", "unavailable_reason": "source_unreadable"}
    except (TimeRangeError, ValueError):
        raw = {"state": "unavailable", "unavailable_reason": "window_or_input_limit"}
    return {**raw, "limits": {"max_period_days": WINDOWS_MAX_PERIOD_DAYS if branch in {"windows", "windows_heatmap"} else MAX_PERIOD_DAYS,
                              **(raw.get("limits") or {})}}


def _accounting_domain_options(access: Mapping[str, Any]) -> list[dict[str, str]]:
    try:
        ids = [int(item["source_domain_id"]) for item in get_vpn_session_sources(access).get("items") or []]
        if not ids:
            return []
        with connect() as conn, conn.cursor() as cur:
            cur.execute("select id, fqdn from domains where id = any(%s) order by fqdn", (ids,))
            names = {int(row["id"]): str(row["fqdn"]) for row in cur.fetchall()}
    except _SOURCE_UNREADABLE as exc:
        _log_source_unreadable("domain_options_unreadable", exc)
        return []
    return [{"value": str(domain_id), "label": names.get(domain_id, f"Домен {domain_id}")} for domain_id in ids]


def _domain_options(access: Mapping[str, Any]) -> list[dict[str, str]]:
    options = _accounting_domain_options(access) + nps_policy_denials.domain_options(access)
    return list({option["value"]: option for option in options}.values())


def _optional_domain_options(access: Mapping[str, Any]) -> list[dict[str, str]]:
    """An exhausted optional lookup must not discard already-read report rows."""
    try:
        return _domain_options(access)
    except (QueryTimeoutError, psycopg_errors.QueryCanceled):
        return []


WEEKDAYS = ("Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс")


def _failure_heatmap(cells: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The engine's weekday × hour failure counts as the full 7×24 grid, in order.

    ``isodow`` is 1 (Monday) … 7 (Sunday). Every cell is present (zeros included)
    so the chart axes are stable; hours are the x axis, weekdays the y axis.
    """
    counts = [[0] * 24 for _ in WEEKDAYS]
    for cell in cells:
        day, hour = int(cell.get("isodow") or 0), int(cell.get("hour") if cell.get("hour") is not None else -1)
        if 1 <= day <= 7 and 0 <= hour <= 23:
            counts[day - 1][hour] += int(cell.get("failures") or 0)
    return [
        {"hour": f"{hour:02d}", "weekday": weekday, "failures": counts[index][hour]}
        for index, weekday in enumerate(WEEKDAYS)
        for hour in range(24)
    ]


def _failure_grid(context: QueryContext) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = _read_source(get_windows_authentication_failure_grid, context, "windows_heatmap", timezone_name=context.timezone or "UTC")
    if raw.get("state") != "available":
        notes = [{"code": "windows_heatmap_unavailable", "text": "Тепловая карта недоступна: проверьте доступ, источник и окно не шире 90 дней. Отсутствие данных не означает отсутствия отказов."}]
        return [], _branch(raw, notes)
    return _failure_heatmap(raw.get("cells") or []), _branch(raw, [
        {"code": "windows_heatmap_meaning", "text": "Отказы посчитаны за всё окно (не шире 90 дней), а не по показанной странице событий; это наблюдаемые факты, а не вывод об атаке."},
    ])


def _hours(minutes: Any) -> float | None:
    return None if minutes is None else round(int(minutes) / 60, 1)


def _employee(item: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(item)
    # Only open sessions: confirmed time is unknown, not zero.
    row["confirmed_hours"] = None if not item.get("closed_session_count") and item.get("open_session_count") else _hours(item.get("confirmed_minutes"))
    row["sessions"] = [
        {**session, "duration_minutes": None if session.get("duration_seconds") is None else round(int(session["duration_seconds"]) / 60)}
        for session in item.get("sessions") or []
    ]
    return row


_IDENTITY = {"resolved": "определена", "ambiguous": "неоднозначна"}
_WINDOWS_STATE = {
    "not_authorized": "Назначение не включает одновременно vpn.audit и просмотр событий Windows в этом домене.",
    "not_collected": "Сбор подходящих событий Windows Security для домена не подтверждён.",
    "empty_unverified": "В сохранённых данных окна факты не найдены, но полнота источника не подтверждена.",
    "coverage_unverified": "Полнота источника в выбранном окне не подтверждена.",
}
_WINDOWS_LIMITATION = {
    "source_events_not_windows_sessions": "Строки — самостоятельные события источника; Windows-сессия и длительность из них не восстановлены.",
    "manual_review_signal_not_attack_verdict": "Сигнал ручной проверки не является выводом об атаке.",
    "empty_window_source_completeness_not_proven": "Пустое окно не доказывает полноту источника.",
    "unknown_results_remain_unknown": "Если код результата не сохранён, результат неизвестен и не считается отказом.",
    "source_completeness_not_proven": "Полнота источника за выбранный период не подтверждена.",
    "earlier_failure_context_displayed_sample_only": "Связи с более ранними отказами относятся только к показанной выборке.",
}


def _authorizations(context: QueryContext) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = _read_source(get_vpn_authorization_timeline, context, "nps", failed_only=context.tab == "failed")
    notes = [{"code": "authorizations_meaning", "text": "6272 — разрешено, 6273 — отказано; это самостоятельные факты NPS, а не начало или конец VPN-сессии."}]
    if raw.get("state") not in {"available", "partial"}:
        notes.append({"code": "authorizations_unavailable", "text": "Решения NPS для этого окна недоступны или не собраны; отсутствие строк не означает отсутствия попыток."})
    rows = [
        {
            **item,
            "decision": "разрешено" if item.get("authorization_result") == "allowed" else "отказано",
            "identity_text": (item.get("identity") or {}).get("display_name") or (item.get("identity") or {}).get("account_name") or (item.get("identity") or {}).get("observed_subject_sid"),
            "identity_state_text": _IDENTITY.get(str(item.get("identity_state")), "не определена"),
            "reason": item.get("reason_code") if item.get("event_id") == 6273 else None,
        }
        for item in raw.get("items") or []
    ]
    return rows, _branch(raw, notes, empty=not rows)


#: The engine states the result through the observed fact (it has no ``outcome``
#: object); only facts that are a success or a failure by definition map here.
_FACT_OUTCOME = {
    "observed_successful_logon": "успех",
    "observed_failed_logon": "отказ",
    "observed_kerberos_preauth_failure": "отказ",
    "observed_kerberos_service_ticket_failure": "отказ",
}


def _outcome_text(outcome: Mapping[str, Any], item: Mapping[str, Any]) -> str:
    explicit = {"success": "успех", "failure": "отказ"}.get(str(outcome.get("result")))
    if explicit:
        return explicit
    fact = str(item.get("authentication_fact") or "")
    if fact in _FACT_OUTCOME:
        return _FACT_OUTCOME[fact]
    if fact == "observed_credential_validation":
        # 4776: the source result code decides; 0x0 is success, any other code a failure.
        code = str((item.get("source_native") or {}).get("result_code") or "").strip().lower()
        if code:
            return "успех" if code in {"0x0", "0"} else "отказ"
    return "не зафиксирован"


def _windows(context: QueryContext) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = _read_source(get_windows_authentication_report, context, "windows")
    notes = [{"code": "windows_meaning", "text": "Независимые наблюдаемые факты Windows Security; строки не образуют сессии и не связаны с NPS или RADIUS Accounting."}]
    if raw.get("state") in _WINDOWS_STATE:
        notes.append({"code": f"windows_{raw['state']}", "text": _WINDOWS_STATE[raw["state"]]})
    elif raw.get("state") not in {"available", "partial"}:
        notes.append({"code": "windows_unavailable", "text": "Факты аутентификации Windows недоступны: проверьте источник и окно не шире 90 дней. Отсутствие строк не означает отсутствия событий."})
    window = raw.get("result_window") or {}
    if window.get("truncated"):
        notes.append({"code": "windows_truncated", "params": {"count": window.get("returned_event_count")},
                      "text": f"В показанной выборке первые {window.get('returned_event_count')} событий; список обрезан. Сигналы рассчитываются отдельно; отсутствие события в выборке не является отрицательным выводом."})
    policy = raw.get("manual_review_policy") or {}
    whole_period = policy.get("coverage_scope") == "whole_period"
    if policy and policy.get("coverage_scope") == "not_evaluated":
        notes.append({"code": "windows_review_unavailable", "text": "Проверка сигналов за весь период не завершена. Показанные события сохранены; отсутствие сигналов не означает отсутствия атак."})
    elif policy:
        notes.append({"code": "windows_review_whole_period" if whole_period else "windows_review_sample",
                      "text": "Сигналы рассчитаны по всему периоду сохранённых данных." if whole_period else "Сигналы рассчитаны только в показанной выборке."})
        if policy.get("state") == "no_observed_signal_unverified":
            notes.append({"code": "windows_review_no_signal", "text": "Пороги правил не достигнуты; это не доказывает отсутствия подбора паролей."})
        if policy.get("signals_truncated"):
            notes.append({"code": "windows_review_truncated", "text": "Список сигналов обрезан; охват расчёта указан отдельно."})
        if whole_period:
            notes.append({"code": "windows_review_first_windows", "text": "Показано первое подходящее окно для каждого IP и первое распределённое окно. Правила не доказывают использование одного пароля."})
    minutes = (policy.get("conditions") or {}).get("rolling_window_minutes")
    for signal in policy.get("signals") or []:
        params = {"source": signal.get("source_ip") or "", "failures": signal.get("failure_fact_count"),
                  "accounts": signal.get("distinct_target_sid_count"), "minutes": minutes,
                  "sources": signal.get("distinct_source_count"),
                  "hours": (policy.get("distributed_conditions") or {}).get("rolling_window_hours"),
                  "maximum": (policy.get("distributed_conditions") or {}).get("maximum_failures_per_target"),
                  "from": (signal.get("window") or {}).get("from_utc"),
                  "to": (signal.get("window") or {}).get("to_utc_exclusive"),
                  "event": signal.get("evidence_event_db_id") or ""}
        if signal.get("rule") == "distributed":
            notes.append({"code": "windows_distributed_review", "params": params, "text": (
                f"Распределённый подбор паролей: сигнал для ручной проверки, не вердикт. "
                f"{params['accounts']} SID, {params['failures']} отказов, {params['sources']} источников за окно до {params['hours']} ч, "
                f"не более {params['maximum']} отказов на SID. Окно {params['from']} — {params['to']}. Событие {params['event']}."
            )})
            continue
        notes.append({"code": "windows_manual_review", "params": params, "text": (
            f"Сигнал для ручной проверки: IP {signal.get('source_ip')} — {signal.get('failure_fact_count')} наблюдаемых отказов по "
            f"{signal.get('distinct_target_sid_count')} SID за {minutes} мин. Не вердикт; это не вывод об атаке. "
            f"Окно {params['from']} — {params['to']}. Событие {params['event']}."
        )})
    notes.extend({"code": f"windows_{code}", "text": _WINDOWS_LIMITATION[code]} for code in raw.get("limitations") or [] if code in _WINDOWS_LIMITATION)
    rows = []
    for item in raw.get("items") or []:
        principal = item.get("principal") or {}
        source = item.get("source") or {}
        evidence = item.get("evidence") or {}
        outcome = item.get("outcome") or {}
        earlier = item.get("earlier_observed_failures_in_window") or {}
        rows.append({
            **item,
            "account_text": principal.get("principal_user_name") if principal.get("state") != "unknown" else None,
            "account_sid": principal.get("principal_user_sid"),
            "source_text": " · ".join(str(value) for value in (source.get("source_ip"), source.get("workstation_name")) if value) or None,
            "outcome_text": _outcome_text(outcome, item),
            "native_text": "; ".join(f"{key}: {value}" for key, value in (item.get("source_native") or {}).items()) or None,
            "evidence_id": evidence.get("event_db_id"),
            "earlier_failures": len(earlier.get("event_references") or []) if earlier.get("state") == "observed" else None,
        })
    return rows, _branch(raw, notes, empty=not rows)


def _query(context: QueryContext) -> dict[str, Any]:
    if context.tab == "session_overlap":
        return _overlap_query(context)
    if context.tab in nps_policy_denials.TAB_KEYS:
        return nps_policy_denials.query_tabs(context, REPORT)
    period = context.params["period"]
    try:
        offset = int(context.cursor or 0)
    except ValueError as exc:
        raise ValueError("report_cursor_invalid") from exc
    # Read the requested source before optional Accounting/header work.
    branches: dict[str, dict[str, Any]] = {}
    extra: dict[str, list[dict[str, Any]]] = {}
    if context.tab in {"authorizations", "failed"}:
        authorizations, branches["nps"] = _authorizations(context)
        if context.tab == "authorizations":
            extra["authorizations"] = authorizations
        else:
            extra["failed"] = [
                {**row, "display_name": (row.get("identity") or {}).get("display_name"),
                 "account_name": (row.get("identity") or {}).get("account_name")}
                for row in authorizations if row.get("event_id") == 6273
            ]
    if context.tab == "windows":
        extra["windows"], branches["windows"] = _windows(context)
    if context.tab == "windows_heatmap":
        extra["windows_heatmap"], branches["windows_heatmap"] = _failure_grid(context)
    raw = _read_source(
        get_vpn_connections_report, context, "accounting",
        search=context.params.get("q"), department=context.params.get("department"),
        status=context.params.get("status") or "all", employee_limit=context.limit, employee_offset=offset,
        include_failed_authorizations=False,
    )
    engine_state = str(raw.get("state") or "unavailable")
    employees = [_employee(item) for item in raw.get("employees") or []]
    page = raw.get("employee_page") or {}
    analytics = raw.get("analytics") or {}
    coverage = raw.get("coverage") or {}
    coverage_state = engine_coverage_state(coverage) if coverage else "unavailable"
    limitations = [{"code": "vpn_note", "text": str(text)} for text in raw.get("limitations") or []]
    if coverage_state in _COVERAGE_NOTE:
        limitations.append({"code": f"coverage_{coverage_state}", "text": _COVERAGE_NOTE[coverage_state]})
    if engine_state in {"not_authorized", "unavailable", "not_collected"}:
        limitations.append({"code": "vpn_source_unreadable", "text": "Источник VPN-сессий сейчас не читается (нет собранных данных RADIUS или прав на их чтение). Отсутствие строк не означает отсутствия подключений."})
    branches = {
        "accounting": _branch(raw, limitations.copy(), empty=not employees),
        **{key: {"state": "not_requested", "reason": "load_on_open", "limitations": [], "limits": {}}
           for key in ("nps", "windows", "windows_heatmap")},
        **branches,
    }
    limitations = branches["accounting"]["limitations"].copy()
    loaded = [branch for branch in branches.values() if branch["state"] != "not_requested"]
    states = {branch["state"] for branch in loaded}
    if any(branch["reason"] == "source_read_timeout" for branch in loaded):
        state = "partial"
    elif "processing" in states:
        state = "processing"
    elif "stale" in states:
        state = "stale"
    elif "partial" in states or (states & {"ok", "empty"} and states & {"error", "denied", "not_collected"}):
        state = "partial"
    elif "ok" in states:
        state = "ok"
    elif "empty" in states:
        state = "empty"
    else:
        state = "denied" if states == {"denied"} else "not_collected" if states == {"not_collected"} else "error"
    for key, branch in branches.items():
        if key != "accounting":
            limitations.extend(branch["limitations"])
    payload = result(
        REPORT, state=state, items=employees,
        has_more=bool(page.get("has_more")), next_cursor=str(offset + len(employees)) if page.get("has_more") else None,
        filtered_count=page.get("filtered_count"),
        metrics=[
            {"key": "employees", "label": "Сотрудников с VPN", "value": analytics.get("employee_count"), "tone": "accent"},
            {"key": "closed", "label": "Завершённых сессий", "value": analytics.get("closed_session_count")},
            {"key": "hours", "label": "Подтверждено часов", "value": _hours(analytics.get("confirmed_minutes"))},
            {"key": "open", "label": "Незавершённых сессий", "value": analytics.get("open_session_count"), "tone": "warning" if analytics.get("open_session_count") else "neutral", "filter": {"status": "open"}},
            {"key": "overlap", "label": "С пересечением сессий", "value": analytics.get("employees_with_overlap"), "tone": "danger" if analytics.get("employees_with_overlap") else "neutral"},
        ],
        coverage={**coverage, "state": state, "source": "accounting", "stage": "session_projection",
                  "missing_sources": [key for key, branch in branches.items() if branch["state"] in {"error", "denied", "not_collected"}],
                  "history_from_utc": coverage.get("history_available_from_utc"), "history_to_utc": coverage.get("history_available_to_utc")},
        collections={
            "daily": [{**day, "confirmed_hours": _hours(day.get("confirmed_minutes"))} for day in analytics.get("daily") or []],
            "departments": [{**department, "confirmed_hours": _hours(department.get("confirmed_minutes"))} for department in analytics.get("departments") or []],
            "entitlements": list((raw.get("entitlements") or {}).get("items") or []),
            "failed": [],
            **extra,
        },
        filter_options={"domain": _optional_domain_options(context.access)},
        limitations=limitations,
        window={**{key: (raw.get("period") or {}).get(key) for key in ("local_from_date", "local_to_date")}, "from_utc": period["from_utc"], "to_utc_exclusive": period["to_utc"], "timezone": raw.get("office_timezone") or context.timezone, "source_domain_id": int(context.params["domain"]), "generated_at_utc": raw.get("generated_at_utc")},
    )
    if (branches["accounting"]["state"] not in {"ok", "empty", "partial", "processing", "stale"}
            or branches["accounting"]["reason"] == "source_read_timeout" and not employees):
        payload["metrics"] = []
    else:
        _qualify_accounting_metrics(payload, branches["accounting"]["state"])
    payload["branches"] = branches
    return payload


def _qualify_accounting_metrics(payload: dict[str, Any], state: str) -> None:
    """Counts of observed sessions are not totals for an unconfirmed period."""
    complete = state in {"ok", "empty"} and payload["coverage"].get("completeness") in {"complete", "proven"}
    for metric in payload["metrics"]:
        value = metric.get("value")
        if complete and value is not None:
            metric["quality"] = "complete"
        elif isinstance(value, (int, float)) and value > 0:
            metric["quality"] = "observed"
        else:
            metric.update(value=None, quality="unknown")


def _overlap_query(context: QueryContext) -> dict[str, Any]:
    raw = _read_source(get_overlaps, context, "accounting", params=context.params, action=context.action)
    raw["limits"]["max_period_days"] = OVERLAP_MAX_PERIOD_DAYS
    notes = [{"code": "overlap_meaning", "text": "Перекрытие — наблюдение Accounting, а не вывод об атаке или разных устройствах. Незакрытые интервалы ограничены последним наблюдением; поколения и неизвестные аккаунты не объединяются."}]
    if raw.get("reason") == "no_accounting_data":
        notes.append({"code": "overlap_no_accounting", "text": "Нет данных Accounting: сессионная проекция пуста или недоступна. Решения NPS не заменяют VPN-сессии."})
    if raw.get("truncated") and raw.get("unavailable_reason") != "source_read_timeout":
        notes.append({"code": "overlap_truncated", "text": "Предел чтения сессий или пар достигнут: список неполный, итоговые счётчики неизвестны. Уточните период или аккаунт."})
    if raw.get("state") == "unavailable":
        notes.append({"code": "overlap_unavailable", "text": "Accounting недоступен или окно превышает 90 дней. Отсутствие строк не доказывает отсутствие перекрытий."})
    if raw.get("state") == "partial":
        notes.append({"code": "overlap_partial", "text": "Покрытие Accounting неполное: есть необработанные данные, неизвестные идентичности или достигнут предел чтения. Счётчики относятся к доступным наблюдениям."})
    rows = list(raw.get("items") or [])
    branch = _branch(raw, notes, empty=not rows)
    metrics = raw.get("metrics") or {}
    payload = result(
        REPORT, state=branch["state"], collections={"session_overlap": rows}, coverage=raw.get("coverage"),
        metrics=[
            {"key": "overlap_accounts", "label": "Аккаунтов с перекрытиями", "value": metrics.get("accounts")},
            {"key": "overlap_concurrent", "label": "Максимум одновременных сессий", "value": metrics.get("max_concurrent")},
            {"key": "overlap_seconds", "label": "Подтверждённое перекрытие, с", "value": metrics.get("confirmed_seconds")},
            {"key": "overlap_incomplete", "label": "Неполных сессий", "value": metrics.get("incomplete_sessions")},
        ], limitations=branch["limitations"],
        window={"from_utc": context.params["period"]["from_utc"], "to_utc_exclusive": context.params["period"]["to_utc"],
                "source_domain_id": int(context.params["domain"])},
    )
    payload["branches"] = {"accounting": branch}
    _qualify_accounting_metrics(payload, branch["state"])
    return payload


REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="Remote access investigator",
        question="Какие VPN-сессии подтверждены в выбранном периоде?",
        action="Inspect Accounting session evidence and independently available access/authorization context.",
        scope="Server-authorized domain and bounded period; Accounting session population with separately loaded NPS, Windows and AD views.",
        exclusions="NPS 6272/6273 are not session start/stop; Windows authentication is not an Accounting session; no guessed duration.",
        sources=(
            "Canonical: RADIUS Accounting session observations in the granted domain/window.",
            "Supplemental: NPS decisions, Windows authentication and AD access context; each source keeps its own coverage.",
        ),
        freshness_expectation="Подтверждение Accounting, NPS, Windows и AD — раздельно; свежесть одной ветки не переносится на другую.",
        rights="vpn.audit view grant plus per-source capabilities and domain/resource/field scope enforced by each reader; export separately granted.",
        field_classes=(
            "identity_basic",
            "technical",
            "security",
            "privilege",
        ),
        coverage="Expected configured Accounting sources and session intervals; NPS/Windows/AD have independent source coverage.",
        completeness="Confirmed Accounting source intervals divided by expected configured source-window duration; lifecycle completeness remains per session. No source coverage inferred from session count, NPS or Windows rows.",
        denominator="Ожидаемые источники Accounting × период; у NPS, Windows и AD собственные знаменатели и доказательства.",
        retention="Permanent derived sessions/actions follow storage policy; raw Accounting/NPS/Windows evidence has bounded retention.",
        provenance="Session identity, Accounting source/lifecycle observations and independently attributed NPS/Windows/AD evidence.",
        primary_archetype="timeline",
        product_archetype="investigation-evidence",
        deterministic_policy="Accounting Start/Interim/Stop defines sessions; NPS 6272/6273 and Windows authentication are independent context, never session proof.",
        result_limits="Accounting period and employee pages are bounded; NPS policy tabs have a 31-day window and 500-group/event caps.",
        fallback="Accounting, NPS, Windows and AD failures stay independent; missing lifecycle does not invent duration or traffic.",
        acceptance_lanes={
            "product_user": "Observed Accounting sessions answer the VPN-use question separately from entitlement.",
            "authorization": "vpn.audit and per-source capabilities, domain/resource/field scopes constrain each branch.",
            "deterministic_interpretation": "Session lifecycle, deduplication and duration use Accounting evidence only.",
            "api_view_model": "Employee pages and source collections preserve independent caps, cursors and truncation.",
            "ui_honest_states": "Unavailable NPS, Windows or AD does not erase available Accounting or imply source completeness.",
            "evidence_audit": "Session identity and lifecycle retain Accounting provenance; NPS and Windows evidence are separately attributed.",
        },
    ),
    key=REPORT_KEY,
    section="reports/remote-access",
    title="VPN-подключения",
    description="Кто и сколько был подключён по VPN: сессии RADIUS Accounting, подтверждённое время, доступы по данным AD и неудачные авторизации.",
    archetype="inventory-status",
    access=AccessRule(ACCESS_KEY, scope="delegated"),
    params=(
        Param.domain(),
        Param.period(default="7d", max_days=MAX_PERIOD_DAYS, presets=("24h", "7d", "30d", "90d", "custom")),
        Param.text("q", "Сотрудник"),
        Param.text("department", "Подразделение"),
        Param.choice("status", "Сессии", STATUSES),
        Param.integer("overlap_account", "Аккаунт для перекрытий (ID)"),
        Param.integer("overlap_min_seconds", "Минимальное перекрытие, с"),
        Param.choice("overlap_complete", "Только полные интервалы", (("true", "Да"), ("false", "Нет")), default="false"),
        *nps_policy_denials.PARAMS,
    ),
    columns=(
        Column("name", "Сотрудник", path="display_name", link="/app/entities/{entity_id}"),
        Column("account", "Учётная запись", path="account_name", optional=True),
        Column("department", "Подразделение", path="department"),
        Column("activity", "Активность по дням", path="sessions", component="vpn.activity-strip"),
        Column("sessions", "Сессий", "number", path="session_count"),
        Column("hours", "Подтверждено, ч", "number", path="confirmed_hours"),
        Column("open", "Незавершённых", "number", path="open_session_count"),
        Column("days", "Дней с подключением", "number", path="days_with_observed_start", optional=False),
        Column("overlap", "Пересечения", "number", path="overlap_count", optional=True),
        Column("last_logon", "Последний вход в AD", "datetime", path="last_logon_utc", optional=True),
    ),
    views=(
        View("table", "employees", "Сотрудники"),
        View("table", "session_overlap", "Перекрывающиеся сессии", source="session_overlap",
             note="Пары отдельных канонических сессий одного аккаунта с сохранением поколения каждой. Подтверждённое время относится к полным интервалам; остальные пары ограничены последним наблюдением. Максимальное окно — 90 дней.", columns=(
            Column("entity_id", "Аккаунт", "number", link="/app/entities/{entity_id}"),
            Column("generation_a", "Поколение A", "number"), Column("generation_b", "Поколение B", "number"),
            Column("session_a", "Сессия A / Accounting evidence", "code", link="/api/v1/reports/vpn.audit/sessions/evidence?domain_id={domain_id}&session_row_id={session_a}"),
            Column("session_b", "Сессия B / Accounting evidence", "code", link="/api/v1/reports/vpn.audit/sessions/evidence?domain_id={domain_id}&session_row_id={session_b}"),
            Column("start_a", "Начало A", "datetime"), Column("end_a", "Конец A", "datetime"),
            Column("start_b", "Начало B", "datetime"), Column("end_b", "Конец B", "datetime"),
            Column("completeness_a", "Полнота A", "code"), Column("completeness_b", "Полнота B", "code"),
            Column("last_a", "Последнее наблюдение A", "datetime"), Column("last_b", "Последнее наблюдение B", "datetime"),
            Column("overlap_start_utc", "Начало перекрытия", "datetime"),
            Column("overlap_end_utc", "Конец перекрытия", "datetime"),
            Column("overlap_seconds", "Перекрытие, с", "number"),
            Column("interval_quality", "Качество интервала", "state", labels={"confirmed": "Подтверждённый", "observed": "Неполный, наблюдаемый"}),
        )),
        View("chart", "daily", "Динамика по дням", source="daily", chart="timeseries", x="date",
             series=(("Подтверждено часов", "confirmed_hours"), ("Сотрудников с подключением", "employees_with_observed_start")),
             note="Подтверждённое время VPN-подключения не является показателем рабочего времени."),
        View("table", "departments", "По подразделениям", source="departments", columns=(
            Column("department", "Подразделение"),
            Column("employees", "Сотрудников", "number", path="employee_count"),
            Column("sessions", "Завершённых сессий", "number", path="closed_session_count"),
            Column("hours", "Подтверждено, ч", "number", path="confirmed_hours"),
            Column("open", "С незавершёнными", "number", path="employees_with_open_sessions"),
            Column("overlap", "С пересечениями", "number", path="employees_with_overlap"),
        )),
        View("table", "entitlements", "Доступ по данным AD", source="entitlements", note="Учётные записи, которым VPN разрешён в AD, независимо от фактических подключений.", columns=(
            Column("name", "Сотрудник", path="display_name", link="/app/entities/{entity_id}"),
            Column("account", "Учётная запись", path="account_name"),
            Column("department", "Подразделение", path="department"),
            Column("enabled", "Включена", "boolean"),
            Column("privileged", "Привилегированная", "boolean"),
            Column("last_logon", "Последний вход в AD", "datetime", path="last_logon_utc"),
        )),
        View("table", "failed", "Неудачные авторизации", source="failed", note="Отказы NPS (6273) — факты, а не вывод об атаке.", columns=(
            Column("time", "Время", "datetime", path="time_created_utc"),
            Column("name", "Сотрудник", path="display_name"),
            Column("account", "Учётная запись", path="account_name"),
            Column("reason", "Код причины", "code", path="reason_code"),
            Column("event", "Событие", "code", path="event_db_id", link="/app/events/{event_db_id}"),
        )),
        View("table", "authorizations", "Решения NPS", source="authorizations", note="6272 — разрешено, 6273 — отказано. Связь с конкретной Accounting-сессией не заявляется.", columns=(
            Column("time", "Время", "datetime", path="time_created_utc"),
            Column("decision", "Решение"),
            Column("identity", "Идентичность", path="identity_text"),
            Column("identity_state", "Идентичность определена", path="identity_state_text"),
            Column("source_ip", "Источник", "code"),
            Column("correlation", "Correlation ID", "code", path="correlation_id"),
            Column("reason", "ReasonCode", "code"),
            Column("event", "Событие", "code", path="event_db_id", link="/app/events/{event_db_id}"),
        )),
        *nps_policy_denials.VIEWS,
        View("table", "windows", "Аутентификация Windows", source="windows", note="Наблюдаемые факты Windows Security на контроллерах домена; окно не шире 90 дней.", columns=(
            Column("time", "Время", "datetime", path="time_created_utc"),
            Column("dc", "DC", "code", path="domain_controller"),
            Column("event_id", "Event ID", "code"),
            Column("fact", "Факт", path="authentication_fact"),
            Column("outcome", "Результат", path="outcome_text"),
            Column("account", "Учётная запись", path="account_text"),
            Column("source", "Источник", path="source_text"),
            Column("earlier", "Ранее отказов в окне", "number", path="earlier_failures"),
            Column("native", "Поля источника", path="native_text"),
            Column("evidence", "Доказательство", "code", path="evidence_id", link="/app/events/{evidence_id}"),
        )),
        View("chart", "windows_heatmap", "Отказы входа: день × час", source="windows_heatmap", chart="heatmap",
             x="hour", y="weekday", series=(("Отказов", "failures"),),
             note="Наблюдаемые отказы аутентификации Windows по дням недели и часам в вашем часовом поясе. "
                  "Считается по всему выбранному окну (не шире 90 дней), а не по первым событиям вкладки «Аутентификация Windows». "
                  "Скопление отказов — повод для ручной проверки, а не вывод об атаке."),
    ),
    query=_query,
    home_order=60,
    home_contributions=(CLOSED_SESSIONS,),
    home_view="daily",
    row_key="entity_id",
    detail=Detail(
        title="Сессии сотрудника",
        key="entity_id",
        inline="sessions",
        row_component="vpn.session-evidence",
        columns=(
            Column("start", "Начало", "datetime", path="started_at_utc"),
            Column("stop", "Окончание", "datetime", path="stopped_at_utc"),
            Column("last", "Последнее наблюдение", "datetime", path="last_observed_at_utc"),
            Column("minutes", "Длительность, мин", "number", path="duration_minutes"),
            Column("state", "Состояние", "state", path="lifecycle_state", labels=dict(LIFECYCLE)),
        ),
    ),
    options=lambda access: {"domain": _domain_options(access)},
    presets=(("Незавершённые сессии", {"status": "open"}),),
    page_actions="vpn.print-sheet",
    default_limit=100,
    max_limit=MAX_EMPLOYEE_PAGE,
)
