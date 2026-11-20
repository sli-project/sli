"""«Входы на компьютеры» (ad.computer-logons) on the v2 report framework (plan 5.1).

The engine ``what_where_when_reporting`` is unchanged. Scope logic moved here
from the v1 route: every eligible grant is bounded to the one server-resolved
report domain.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from server.sli.reporting.v2.access import report_grant
from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Detail,
    Param,
    QueryContext,
    ReportDefinition,
    ReportIntent,
    result,
    source_state,
)
from server.sli.plugins.ad.reports.what_where_when_reporting import (
    MAX_DAYS,
    REPORT_KEY,
    InventoryUnavailableError,
    ObservationsUnavailableError,
    get_computer_logon_computers,
    get_computer_logon_observations,
    resolve_report_domain_id,
)

FIELD_CATEGORY = "computer_logon_observation"
OBSERVATION_STATES = (
    ("observed", "Входы наблюдались"),
    ("empty_unverified", "Не наблюдались (полнота не доказана)"),
    ("partial", "Данные частичные"),
    ("not_collected", "Данные не собраны"),
)


def _state(engine_state: Any, items: Any) -> str:
    state = source_state(engine_state)
    return "empty" if state == "ok" and not items else state


def logon_domain_scope(access: Mapping[str, Any], action: str = "view", *, domain_id: int | None = None) -> list[int]:
    report = report_grant(access, REPORT_KEY)
    if not report or action not in set(report.get("allowed_actions") or []):
        raise PermissionError("report_access_denied")
    target = int(domain_id if domain_id is not None else resolve_report_domain_id())
    for grant in report.get("grants") or []:
        if action not in set(grant.get("allowed_actions") or []) or FIELD_CATEGORY not in set(grant.get("field_categories") or []):
            continue
        scope = dict(grant.get("scope") or {})
        if scope.get("kind") == "all":
            return [target]
        if scope.get("kind") == "domain":
            try:
                if target in {int(value) for value in scope.get("ids") or []}:
                    return [target]
            except (TypeError, ValueError):
                continue
    raise PermissionError("report_scope_not_executable")


def _limitations(texts: Any) -> list[dict[str, str]]:
    return [{"code": f"logons_{index}", "text": str(text)} for index, text in enumerate(texts or [])]


def _window(context: QueryContext) -> tuple[str, str]:
    period = context.params["period"]
    return period["from_utc"], period["to_utc"]


def _query(context: QueryContext) -> dict[str, Any]:
    start, end = _window(context)
    try:
        raw = get_computer_logon_computers(
            domain_ids=logon_domain_scope(context.access), q=context.params.get("q"), user_q=context.params.get("user"),
            with_logons=context.params.get("with_logons") == "yes", from_utc=start, to_utc_exclusive=end,
            limit=context.limit, cursor=context.cursor,
        )
    except ObservationsUnavailableError:
        return result(REPORT, state="error", limitations=[{"code": "observations_unavailable", "text": "Фильтр по входам не успел выполниться: сузьте период или добавьте фильтр по компьютеру либо пользователю."}])
    except InventoryUnavailableError as exc:
        if str(exc) == "report_domain_not_configured":
            return result(REPORT, state="error", limitations=[{"code": "report_domain_not_configured", "text": "Домен отчётов не задан: укажите его в разделе «Настройки платформы»."}])
        return result(REPORT, state="error", limitations=[{"code": "inventory_unavailable", "text": "Инвентарь рабочих станций недоступен."}])
    coverage = dict(raw.get("coverage") or {})
    return result(
        REPORT, state=_state(raw.get("state"), raw.get("items")), items=raw.get("items") or [],
        has_more=bool(raw.get("has_more")), next_cursor=raw.get("next_cursor"),
        coverage={**coverage, "state": coverage.get("observation_state"), "inventory": coverage.get("inventory_state")},
        limitations=_limitations(coverage.get("limitations")),
        window={"from_utc": start, "to_utc_exclusive": end},
    )


def _observations(context: QueryContext, row_id: str) -> dict[str, Any]:
    start, end = _window(context)
    try:
        entity_id = int(row_id)
    except ValueError as exc:
        raise LookupError("report_row_not_found") from exc
    try:
        raw = get_computer_logon_observations(
            domain_ids=logon_domain_scope(context.access), entity_id=entity_id, user_q=context.params.get("user"),
            from_utc=start, to_utc_exclusive=end, limit=context.limit, cursor=context.cursor,
        )
    except KeyError as exc:
        raise LookupError("report_row_not_found") from exc
    except InventoryUnavailableError:
        return result(REPORT, state="error")
    items = []
    for item in raw.get("items") or []:
        row = dict(item)
        row["user_text"] = f"{item['user_display_name']} ({item['user_name']})" if item.get("user_display_name") else f"{item['user_name']} — имя в AD не найдено"
        items.append(row)
    return result(
        REPORT, state=_state(raw.get("state"), items), items=items,
        has_more=bool(raw.get("has_more")), next_cursor=raw.get("next_cursor"),
        limitations=_limitations(raw.get("limitations")), window={"from_utc": start, "to_utc_exclusive": end},
    )


REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="Security investigator",
        question="Какие входы на выбранные компьютеры наблюдались за период?",
        action="Inspect exact logon evidence and account context for an investigation.",
        scope="One server-resolved granted domain, selected computers and bounded observation window.",
        exclusions="Logons are not work duration; DC 4624 alone does not prove workstation interactive use.",
        sources=(
            "Canonical: successful computer-logon observations in the granted domain and window.",
            "Supplemental: latest AD computer inventory for the same domain.",
        ),
        freshness_expectation="Свежесть наблюдений входов и снимка инвентаря проверяется раздельно.",
        rights="ad.computer-logons view grant with computer_logon_observation; engine enforces domain and event scope; export separately granted.",
        field_classes=(
            "computer_logon_observation",
        ),
        coverage="Inventory coverage and logon observation coverage are separate source dimensions.",
        completeness="Duration of source-confirmed logon collection intervals divided by expected source-window duration; neither row count nor an empty result proves continuity. Currently not_proven without source evidence.",
        denominator="Ожидаемые источники входов выбранных компьютеров × период; без непрерывности сбора полнота не подтверждена.",
        retention="Derived logon observations follow the storage policy; exact source events may expire independently.",
        provenance="Computer entity, account identity, source event ID, domain and observation time.",
        primary_archetype="timeline",
        product_archetype="investigation-evidence",
        deterministic_policy="Present retained 4624/4634 observations against current AD inventory; logons do not establish work duration.",
        result_limits="Server-resolved report domain and declared period/page bounds apply; inventory and observation coverage are independent.",
        fallback="Keep empty_unverified, not_collected and partial observation coverage; inventory or observation reader failure is unavailable.",
        acceptance_lanes={
            "product_user": "Observed logons answer the selected computer/window question without estimating work duration.",
            "authorization": "computer_logon_observation grants resolve to the configured report domain and constrain detail.",
            "deterministic_interpretation": "Native observations and current inventory matching retain their separate meaning.",
            "api_view_model": "Computer pages and observation detail preserve reader states, cursors and UTC window.",
            "ui_honest_states": "Empty_unverified, partial, not_collected and unavailable observations remain honest states.",
            "evidence_audit": "Logon event identity, source channel and inventory matching provenance remain available.",
        },
    ),
    key=REPORT_KEY,
    section="reports/computers",
    title="Входы на компьютеры",
    description="Кто и когда входил на рабочие станции: наблюдения успешных входов, а не длительность работы.",
    archetype="investigation-evidence",
    access=AccessRule(REPORT_KEY, frozenset({FIELD_CATEGORY}), scope="delegated"),
    params=(
        Param.period(default="30d", max_days=MAX_DAYS, presets=("7d", "30d", "90d", "custom")),
        Param.text("q", "Компьютер"),
        Param.text("user", "Пользователь"),
        Param.choice("with_logons", "Показывать", (("yes", "Только ПК со входами"),)),
    ),
    columns=(
        Column("name", "Компьютер", path="display_name"),
        Column("count", "Входов за период", "number", path="login_count"),
        Column("last", "Последний вход", "datetime", path="last_observed_logon_at_utc"),
        Column("state", "Наблюдения", "state", path="observation_state", labels=dict(OBSERVATION_STATES)),
    ),
    query=_query,
    row_key="entity_id",
    detail=Detail(
        title="Входы на компьютер",
        key="entity_id",
        columns=(
            Column("user", "Пользователь", path="user_text"),
            Column("time", "Время входа", "datetime", path="observed_at_utc"),
            Column("event", "Исходное событие", "code", path="source_event_id", link="/app/events/{source_event_id}"),
        ),
        query=_observations,
        row_links=(("Исходное событие", "/app/events/{source_event_id}"),),
    ),
    presets=(("Только ПК со входами", {"with_logons": "yes"}),),
    row_links=(("Карточка компьютера", "/app/entities/{entity_id}"),),
    default_limit=50,
    max_limit=200,
)
