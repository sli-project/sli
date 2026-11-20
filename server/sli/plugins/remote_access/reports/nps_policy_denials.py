"""NPS policy tabs contributed by the Remote access plugin to VPN connections."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from psycopg import OperationalError, errors

from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.reporting.v2.access import resolve_domain_scope
from server.sli.reporting.v2.definition import AccessRule, Column, Param, QueryContext, ReportDefinition, View, result, source_state
from server.sli.plugins.remote_access.reports.nps_policy_denials_reporting import MAX_PERIOD_DAYS, get_policy_denials
from server.sli.reporting.reporting_common import format_iso, parse_utc
from server.sli.reports.windows_authentication_reporting import _read_access_allowed

TAB_KEYS = frozenset({"policy_denials", "policy_denials_growth", "policy_denials_events"})
NOTE = "Показаны решения NPS. Полнота сбора не подтверждена."
QUALITY = {"observed_unverified": "Полнота не подтверждена", "truncated": "Выборка усечена", "empty_unverified": "Нет наблюдаемых фактов; полнота не подтверждена"}
DIMENSIONS = (
    Column("network_policy", "Политика NPS"), Column("nas_identifier", "NAS"),
    Column("reason_code", "Код причины", "code"), Column("authentication_type", "Метод аутентификации"),
    Column("authentication_provider", "Провайдер аутентификации"),
)
COUNTS = (
    Column("allowed", "Разрешений NPS", "number"), Column("denied", "Отказов NPS", "number"),
    Column("denial_share", "Доля отказов, %", "number"), Column("affected_accounts", "Аккаунтов с отказами", "number"),
    Column("unknown_identity_denials", "Отказы с неизвестной идентичностью", "number"),
)
GROWTH = (
    Column("previous_decisions", "Решений в предыдущем окне", "number"),
    Column("previous_denied", "Отказов в предыдущем окне", "number"),
    Column("growth", "Рост отказов, решений", "number"),
    Column("current_coverage", "Покрытие текущего окна", "state", labels=QUALITY),
    Column("previous_coverage", "Покрытие предыдущего окна", "state", labels=QUALITY),
)
VIEWS = (
    View("table", "policy_denials", "Политики и причины", source="policy_denials", note=NOTE,
         columns=(*DIMENSIONS, *COUNTS,
                  Column("first_denial_utc", "Первый отказ", "datetime"), Column("last_denial_utc", "Последний отказ", "datetime"),
                  *GROWTH,
                  Column("first_event_id", "Первое событие отказа", "code", link="/app/events/{first_event_id}"),
                  Column("last_event_id", "Последнее событие отказа", "code", link="/app/events/{last_event_id}"))),
    View("table", "policy_denials_growth", "Динамика отказов NPS", source="policy_denials_growth", note=NOTE,
         columns=(*DIMENSIONS, *COUNTS, *GROWTH)),
    View("table", "policy_denials_events", "События решений NPS", source="policy_denials_events", note=NOTE,
         columns=(Column("occurred_at_utc", "Время", "datetime"),
                  Column("event_id", "Event ID", "code"),
                  Column("decision", "Решение NPS", "state", labels={"allowed": "Разрешение NPS", "denied": "Отказ NPS"}),
                  *DIMENSIONS,
                  Column("identity_state", "Идентичность", "state", labels={"resolved": "Определена", "unknown": "Не определена"}),
                  Column("normalized_event_id", "Семантический факт", "code"),
                  Column("event_db_id", "Исходное событие", "code", link="/app/events/{event_db_id}"))),
)
PARAMS = (
    Param.text("policy", "Политика NPS"), Param.text("nas", "NAS"), Param.text("reason", "Код причины NPS"),
    Param.text("method", "Метод аутентификации NPS"), Param.integer("min_decisions", "Минимум решений NPS"),
    Param.integer("min_growth", "Минимальный рост отказов, решений"),
)


def domain_options(access: Any) -> list[dict[str, str]]:
    # Domains with event grants remain selectable without RADIUS Accounting or
    # surviving hot-core events. Bound catalogue discovery independently.
    try:
        scope = resolve_domain_scope(access, AccessRule("vpn.audit"))
    except PermissionError:
        return []
    try:
        with connect() as conn, conn.cursor() as cur:
            if scope is None:
                cur.execute("select id,fqdn from domains order by id limit 256")
            else:
                cur.execute("select id,fqdn from domains where id=any(%s) order by id limit 256", (scope,))
            rows = cur.fetchall()
    except (errors.InsufficientPrivilege, errors.UndefinedTable, OperationalError):
        return []
    return [{"value": str(row["id"]), "label": str(row["fqdn"])} for row in rows if _read_access_allowed(access, int(row["id"]))]


def query_tabs(context: QueryContext, definition: ReportDefinition) -> dict[str, Any]:
    period = context.params["period"]
    start, end = parse_utc(period["from_utc"]), parse_utc(period["to_utc"])
    clamped = start is not None and end is not None and end - start > timedelta(days=MAX_PERIOD_DAYS)
    time_from = format_iso(end - timedelta(days=MAX_PERIOD_DAYS)) if clamped else period["from_utc"]
    try:
        raw = get_policy_denials(
            context.access, source_domain_id=int(context.params["domain"]),
            time_from=time_from, time_to=period["to_utc"],
            **{key: context.params.get(key) for key in ("policy", "nas", "reason", "method")},
            min_decisions=context.params.get("min_decisions") or 0, min_growth=context.params.get("min_growth") or 0,
        )
    except (errors.InsufficientPrivilege, errors.UndefinedTable, errors.UndefinedColumn, errors.QueryCanceled, OperationalError):
        raw = {"state": "unavailable", "unavailable_reason": "source_unreadable"}
    except ValueError:
        raw = {"state": "unavailable", "unavailable_reason": "window_or_input_limit"}
    state = source_state(raw.get("state"))
    if state in {"ok", "empty"}:
        state = "partial"
    notes = [{"code": "nps_policy_meaning", "text": NOTE},
             {"code": "nps_policy_growth", "text": "Рост — разница числа отказов с предыдущим равным окном. При усечении любого окна рост неизвестен. Пороги применяются к группам; карточки описывают весь выбранный срез."},
             {"code": "nps_policy_missing", "text": "Решения без политики или причины остаются отдельными группами. Неизвестные идентичности не считаются аккаунтами. Отсутствие строк не доказывает отсутствие решений."},
             {"code": "nps_policy_evidence", "text": "Показаны сохранённые семантические факты. Исходное событие по ссылке может быть недоступно после удаления источника. События фильтруются по политике, NAS, причине и методу; пороги групп к ним не применяются."}]
    if state in {"error", "denied"}:
        notes.append({"code": "nps_policy_unavailable", "text": "Решения NPS недоступны: проверьте доступ к событиям домена и источник."})
    if raw.get("result_truncated") or raw.get("evidence_truncated"):
        notes.append({"code": "nps_policy_result_limit", "text": "Показано не более 500 групп и 500 событий текущего окна. Уточните фильтры для детализации."})
    coverage = raw.get("coverage") or {}
    if (coverage.get("current") or {}).get("truncated"):
        notes.append({"code": "nps_policy_current_sample", "text": "Текущее окно усечено до 10 000 решений: счётчики и доля отказов описывают выборку, рост неизвестен."})
    if (coverage.get("previous") or {}).get("truncated"):
        notes.append({"code": "nps_policy_previous_sample", "text": "Предыдущее окно усечено до 10 000 решений: сравнение и рост неизвестны."})
    rows = [{**row, "current_coverage": (coverage.get("current") or {}).get("state"),
             "previous_coverage": (coverage.get("previous") or {}).get("state")} for row in raw.get("items") or []]
    metrics = raw.get("metrics") or {}
    payload = result(
        definition, state=state, items=[], metrics=[
            {"key": "nps_allowed", "label": "Разрешений NPS", "value": metrics.get("allowed")},
            {"key": "nps_denied", "label": "Отказов NPS", "value": metrics.get("denied")},
            {"key": "nps_denial_share", "label": "Доля отказов, %", "value": metrics.get("denial_share")},
            {"key": "nps_affected_accounts", "label": "Аккаунтов с отказами", "value": metrics.get("affected_accounts")},
            {"key": "nps_unknown_identity", "label": "Отказы с неизвестной идентичностью", "value": metrics.get("unknown_identity_denials")},
            {"key": "nps_growing_policies", "label": "Политик с ростом отказов", "value": metrics.get("growing_policies")},
            {"key": "nps_growing_nas", "label": "NAS с ростом отказов", "value": metrics.get("growing_nas")},
            {"key": "nps_missing_policy", "label": "Решений без политики", "value": metrics.get("missing_policy")},
            {"key": "nps_missing_reason", "label": "Решений без причины", "value": metrics.get("missing_reason")},
        ] if metrics else [],
        collections={"policy_denials": rows,
                     "policy_denials_growth": sorted(rows, key=lambda row: -(row["growth"] or 0)),
                     "policy_denials_events": raw.get("events") or []},
        coverage={"state": "partial", "current": coverage.get("current"), "previous": coverage.get("previous")},
        limitations=notes,
        window={"from_utc": time_from, "to_utc_exclusive": period["to_utc"], "nps_period_clamped": clamped,
                "timezone": context.timezone, "source_domain_id": int(context.params["domain"])},
    )
    branch = {"state": state, "reason": raw.get("unavailable_reason") or "source_completeness_not_proven", "limitations": notes, "limits": raw.get("limits") or {"max_period_days": 31}}
    payload["branches"] = {key: branch if key in TAB_KEYS else {"state": "not_requested", "reason": "load_on_open", "limitations": [], "limits": {}}
                           for key in (*TAB_KEYS, "accounting", "nps", "windows", "windows_heatmap")}
    return payload
