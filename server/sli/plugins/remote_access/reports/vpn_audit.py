"""«VPN-доступ и актуальность владельцев» (vpn.audit) on the v2 framework.

The published v4 report keeps its dataset, field policy and export policy;
this declaration only presents its rows and summary uniformly. Field
categories the user lacks are absent from the row and shown as
«Поле недоступно», never as «нет».
"""

from __future__ import annotations

from typing import Any

from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Param,
    QueryContext,
    ReportDefinition,
    ReportIntent,
    result,
    source_state,
)
from server.sli.reporting.reporting_v4 import (
    REPORT_LIMIT_MAX,
    execute_report,
    export_report_csv_document,
)

REPORT_KEY = "vpn.accounts"
ACCESS_KEY = "vpn.audit"
ACTIVITY = (("active", "Активна"), ("inactive", "Неактивна"), ("disabled", "Отключена"), ("unknown", "Не определено"))
UNAVAILABLE = "Поле недоступно"


def _privilege(row: dict[str, Any], coverage: str | None) -> str:
    if row.get("privileged_overlap") is True:
        return "Есть пересечение"
    if "privileged_overlap" not in row:
        return UNAVAILABLE
    return {"complete": "Не обнаружено", "partial": "Не обнаружено в неполном срезе"}.get(str(coverage), "Срез не собран")


def _row(item: dict[str, Any], coverage: str | None) -> dict[str, Any]:
    row = dict(item)
    row["activity"] = str(item.get("activity_state") or "unknown").casefold()
    row["department_text"] = (item.get("department") or "Не указано") if "department" in item else UNAVAILABLE
    row["password_text"] = (
        ("Без ограничения срока" if item.get("password_never_expires") else "С ограничением срока")
        if "password_never_expires" in item else UNAVAILABLE
    )
    row["privilege_text"] = _privilege(item, coverage)
    # Keep legacy labels for older clients; only computed presentation gets codes.
    row["department_text_code"] = (
        "unavailable" if "department" not in item else ("unspecified" if not item.get("department") else None)
    )
    row["password_text_code"] = (
        ("never_expires" if item.get("password_never_expires") else "expires")
        if "password_never_expires" in item else "unavailable"
    )
    row["privilege_text_code"] = (
        "overlap" if item.get("privileged_overlap") is True else
        "unavailable" if "privileged_overlap" not in item else
        {"complete": "not_detected", "partial": "not_detected_partial"}.get(str(coverage), "not_collected")
    )
    return row


def _coverage_state(collection: dict[str, Any]) -> str:
    states = {str((value or {}).get("state") or "") for value in collection.values() if isinstance(value, dict)}
    if "failed" in states:
        return "error"
    if states & {"partial", "skipped", "not_collected", ""}:
        return "partial"
    return "ok"


def _filters(context: QueryContext, *, cursor: bool) -> dict[str, Any]:
    # Entity IDs give the inventory a stable keyset order across pages.
    filters: dict[str, Any] = {"sort": "object_id", "direction": "asc"}
    for source, target in (("q", "q"), ("activity", "activity_state")):
        if context.params.get(source):
            filters[target] = context.params[source]
    if cursor and context.cursor:
        filters["cursor"] = context.cursor
    return filters


def _query(context: QueryContext) -> dict[str, Any]:
    raw = execute_report(ACCESS_KEY, None, limit=min(context.limit, REPORT_LIMIT_MAX), query_filters=_filters(context, cursor=True), access=context.access)
    summary = raw.get("summary") or {}
    collection = dict(summary.get("collection") or {})
    privilege_coverage = (collection.get("privileged_membership") or {}).get("state")
    rows = [_row(item, privilege_coverage) for item in raw.get("items") or []]
    state = source_state(raw.get("state"))
    if state == "ok":
        state = _coverage_state(collection) if collection else "ok"
    if state == "ok" and not rows:
        state = "empty"

    def metric(key: str, label: str, tone: str = "neutral", filter_: dict[str, str] | None = None) -> dict[str, Any]:
        value = summary.get(key)
        return {"key": key, "label": label, "value": value, "tone": tone if value else "neutral", **({"filter": filter_} if filter_ else {})}

    return result(
        REPORT, state=state, items=rows, has_more=bool(raw.get("has_more")), next_cursor=raw.get("next_cursor"), filtered_count=raw.get("filtered_count"),
        metrics=[
            metric("total_users", "Всего VPN-пользователей", "accent"),
            metric("active_users", "Активные", "success", {"activity": "active"}),
            metric("inactive_users", "Неактивные по входу", "warning", {"activity": "inactive"}),
            metric("disabled_users", "Отключённые", "warning", {"activity": "disabled"}),
            metric("privileged_overlap_users", "VPN и привилегии", "danger"),
        ],
        coverage={"state": state, "observed_at_utc": summary.get("latest_observed_at_utc"),
                  "missing_sources": [key for key, value in collection.items() if isinstance(value, dict) and value.get("state") not in {"complete", "completed", "available"}]},
        limitations=[{"code": f"vpn_accounts_{index}", "text": str(text)} for index, text in enumerate(summary.get("limitations") or [])],
    )


def _export(context: QueryContext) -> tuple[str, dict[str, Any]]:
    document = export_report_csv_document(ACCESS_KEY, None, query_filters=_filters(context, cursor=False), access=context.access)
    return str(document["csv"]), {"rows": int(document["row_count"]), "truncated": bool(document["truncated"])}


REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="Remote access reviewer",
        question="Какие учётные записи имеют VPN-доступ по явно заданным группам AD?",
        action="Review account ownership, state and privilege overlap before an access review decision.",
        scope="Explicit VPN groups and current AD membership in server-authorized domains.",
        exclusions="No gateway traffic or session proof; group membership is not actual VPN use.",
        sources=(
            "Canonical: AD VPN membership and directory account sections in the granted domains.",
            "Supplemental: AD privileged membership and observed account activity.",
        ),
        freshness_expectation="Подтверждение разделов VPN-членства, учётных записей и привилегий AD проверяется отдельно.",
        rights="vpn.audit view grant; engine-enforced AD domain and field scope; export separately granted.",
        field_classes=(
            "identity_basic",
            "technical",
            "security",
            "privilege",
            "hr",
            "contact",
        ),
        coverage="Configured VPN groups, account sections and privileged-membership sections per granted domain.",
        completeness="Source-confirmed VPN-group and account sections divided by expected configured group/section pairs in the authorized domains; privilege coverage is separate. Unknown without the expected configuration and section confirmation.",
        denominator="Явно заданные VPN-группы и ожидаемые разделы AD в разрешённых доменах; пользователи шлюза не подменяют этот состав.",
        retention="Derived AD membership/account facts follow the storage policy; exact snapshot evidence depends on retention.",
        provenance="Canonical account, configured VPN group, AD relation and section observation timestamp.",
        primary_archetype="list",
        product_archetype="inventory-status",
        deterministic_policy="Only explicitly configured VPN groups define AD entitlement; membership and privilege overlap are not observed VPN use.",
        result_limits="Configured group and AD section coverage is separate from bounded account pages and export.",
        fallback="Missing VPN configuration or AD sections remains unconfirmed; gateway users cannot replace the configured membership population.",
        acceptance_lanes={
            "product_user": "Configured AD VPN entitlement answers the access-review question.",
            "authorization": "vpn.audit grant and engine domain/field scope bound account rows and independent export.",
            "deterministic_interpretation": "Only configured VPN membership qualifies entitlement; no sessions are inferred.",
            "api_view_model": "Account filters and bounded export preserve AD membership reader semantics.",
            "ui_honest_states": "Unconfigured groups, partial sections, stale or unavailable AD observations remain explicit.",
            "evidence_audit": "Account, configured group, relation and section observation remain attributable.",
        },
    ),
    key=REPORT_KEY,
    section="reports/remote-access",
    title="VPN-доступ и актуальность владельцев",
    description="Участники явно заданных VPN-групп AD с состоянием учётной записи, последним входом и пересечением с привилегиями. События VPN-шлюза сюда не входят.",
    archetype="inventory-status",
    access=AccessRule(ACCESS_KEY, scope="delegated"),
    params=(
        Param.text("q", "Пользователь"),
        Param.choice("activity", "Состояние", ACTIVITY),
    ),
    columns=(
        Column("display_name", "Пользователь", link="/app/entities/{object_id}"),
        Column("natural_key", "Учётная запись", "code"),
        Column("activity", "Состояние", "state", labels=dict(ACTIVITY)),
        Column("last_logon_utc", "Последний вход", "datetime"),
        Column("department", "Подразделение", path="department_text"),
        Column("password", "Пароль", path="password_text"),
        Column("privilege", "Привилегии", path="privilege_text"),
        Column("title", "Должность", optional=True),
        Column("email", "Почта", optional=True),
        Column("observed_at", "Наблюдение", "datetime", optional=True),
    ),
    query=_query,
    export_csv=_export,
    row_key="object_id",
    presets=(("Неактивные", {"activity": "inactive"}), ("Отключённые", {"activity": "disabled"})),
    row_links=(("Карточка пользователя", "/app/entities/{object_id}"),),
    default_limit=200,
    max_limit=REPORT_LIMIT_MAX,
)
