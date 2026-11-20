"""«Компьютеры» (ad.computers.v6) on the v2 report framework (plan 5.4).

The engine ``computers_v6_reporting`` is unchanged and does filtering,
sorting and cursor paging itself; the adapter passes parameters through.
"""

from __future__ import annotations

from typing import Any

from dataclasses import replace

from server.sli.core.messages import message
from server.sli.plugins.ad.reports import computer_changes, report_additions, review_catalog, review_checks

from server.sli.plugins.ad.reports.computers_v6_reporting import (
    get_computers_v6_report,
    render_computers_v6_csv,
)
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
    source_state,
)

REPORT_KEY = "ad.computers.v6"
VIEWS = (
    ("attention", "Требуют внимания"), ("all", "Все компьютеры"),
    ("workstation_enabled", "Рабочие станции: включены"), ("workstation_disabled", "Рабочие станции: отключены"),
    ("server_enabled", "Серверы: включены"), ("server_disabled", "Серверы: отключены"),
    ("unknown_type", "Тип не определён"), ("data_quality", "Качество данных"), ("changes", "Изменения"),
    ("semantic", "Связанные находки"),
)
TYPES = (("workstation", "Рабочая станция"), ("server", "Сервер"),
         ("domain_controller", "Контроллер домена"), ("unknown", "Не определён"))
ACCOUNT = (("enabled", "Включена"), ("disabled", "Отключена"), ("unknown", "Не определено"))
ACTIVITY = (
    ("recent", "Активен"), ("stale", "Давно не входил"), ("missing", "Нет данных"), ("not_applicable", "Не оценивается"),
    ("within_threshold", "В пределах порога"), ("over_threshold", "Старше порога"),
)
ACTIVITY_FILTERS = (
    ("within_threshold", "В пределах порога"), ("over_threshold", "Старше порога"), ("missing", "Нет данных"),
    ("within_30_days", "До 30 дней"), ("days_31_to_90", "31–90 дней"), ("over_60_days", "Более 60 дней"),
)
THRESHOLDS = (("30", "30 дней"), ("60", "60 дней"), ("90", "90 дней"), ("180", "180 дней"))


def _row(item: dict[str, Any]) -> dict[str, Any]:
    row = dict(item)
    row["reason_text"] = ", ".join(str(reason.get("label")) for reason in item.get("reasons") or []) or None
    row["quality_text"] = ", ".join(str(issue.get("label")) for issue in item.get("quality_issues") or [] if issue.get("code") != "not_evaluated") or None
    row["age_days"] = (item.get("activity") or {}).get("age_days")
    row["ip_text"] = ", ".join(item.get("ip_addresses") or []) or None
    row["site_text"] = (item.get("ad_site") or {}).get("value")
    return row


def _options(values: Any) -> list[dict[str, str]]:
    if isinstance(values, dict):
        values = values.get("values") or []
    return [{"value": str(value), "label": "Нет данных" if value == "__missing__" else str(value)} for value in values or []]


def _engine(context: QueryContext, *, export: bool = False) -> dict[str, Any]:
    params = context.params
    selection = context.runtime.get("domain_selection")
    return get_computers_v6_report(
        domain_ids=context.domain_ids,
        **({"qualify_names": selection.domain_id is None} if selection is not None else {}),
        view="changes" if context.tab == "changes" else params.get("view") or ("all" if context.tab == "computers" else "attention"), reason_code=params.get("reason_code"), quality_code=params.get("quality_code"),
        enabled=params.get("enabled"), computer_type=params.get("type"), operating_system=params.get("os"),
        operating_system_version=params.get("os_version"), operating_system_family=params.get("os_family"),
        ou=params.get("ou"), ad_site=params.get("ad_site"), activity=params.get("activity"), q=params.get("q"),
        sort_by=context.sort or "display_name", sort_direction=context.direction,
        limit=10_000 if export else context.limit, cursor=None if export else context.cursor,
        threshold_days=int(params.get("threshold_days") or 90),
        **({"max_page_limit": 10_000} if export else {}),
    )


def _query(context: QueryContext, *, export: bool = False) -> dict[str, Any]:
    if context.tab == "checks":
        return review_checks.query(REPORT, context, "computers")
    if context.tab == "changes":
        return computer_changes.query(REPORT, replace(context, limit=10_000, cursor=None) if export else context)
    raw = _engine(context, export=export)
    items = [_row(item) for item in raw.get("items") or []]
    report_additions.enrich_computers(items, context.domain_ids)
    summary = raw.get("summary") or {}
    state = source_state(raw.get("state"))
    if state == "ok" and not items:
        state = "empty"
    options = raw.get("filter_options") or {}
    return result(
        REPORT, state=state, items=items, has_more=bool(raw.get("has_more")), next_cursor=raw.get("next_cursor"),
        filtered_count=raw.get("filtered_count"),
        metrics=[
            {"key": "all", "label": "Всего в AD", "value": summary.get("total_computers"), "tone": "accent", "filter": {"view": "all"}},
            {"key": "attention", "label": "Требуют внимания", "value": summary.get("attention"), "tone": "warning" if summary.get("attention") else "neutral", "filter": {"view": "attention"}},
            {"key": "ws", "label": "Рабочие станции (вкл.)", "value": summary.get("workstation_enabled"), "filter": {"view": "workstation_enabled"}},
            {"key": "srv", "label": "Серверы (вкл.)", "value": summary.get("server_enabled"), "filter": {"view": "server_enabled"}},
            {"key": "unknown", "label": "Тип не определён (вкл.)", "value": summary.get("unknown_type_enabled"), "filter": {"view": "all", "type": "unknown", "enabled": "enabled"}},
            {"key": "disabled", "label": "Отключены (все типы)", "value": summary.get("disabled"), "filter": {"view": "all", "enabled": "disabled"}},
            {"key": "unknown_state", "label": "Состояние учётной записи не определено", "value": summary.get("unknown_enabled"), "filter": {"view": "all", "enabled": "unknown"}},
        ],
        coverage={**(raw.get("coverage") or {}), "freshness_threshold_seconds": 86400,
                  **({"truncated": True} if (raw.get("limits") or {}).get("input_truncated") else {}),
                  "observed_at_utc": (raw.get("coverage") or {}).get("computer_snapshot_observed_at_utc") or min((str(domain["observed_at_utc"]) for domain in (raw.get("coverage") or {}).get("domains") or [] if domain.get("observed_at_utc")),
                                         default=(raw.get("coverage") or {}).get("latest_observed_at_utc"))},
        filter_options={
            "os": _options(options.get("operating_systems")),
            "os_version": _options(options.get("operating_system_versions")),
            "os_family": _options(options.get("operating_system_families")),
            "ou": _options(options.get("ous")),
            "ad_site": _options(options.get("ad_site")),
        },
        limitations=[{"code": f"computers_{index}", "text": str(text)} for index, text in enumerate(raw.get("limitations") or [])],
    )


def _export(context: QueryContext) -> tuple[str, dict[str, Any]]:
    if context.tab in {"checks", "changes"}:
        data = _query(context, export=True)
        if data["state"] not in {"ok", "partial", "stale", "empty"}:
            raise ValueError("computers_v6_export_unavailable")
        view = next(view for view in REPORT.views if view.key == context.tab)
        rows = data["items"]
        if context.tab == "checks":
            rows = [{**row, "objects": [obj.get("name") for obj in row.get("objects") or []]} for row in rows]
        return csv_from_columns(view.columns, rows), {"rows": len(rows), "truncated": bool(data.get("has_more"))}
    raw = _engine(context, export=True)
    if raw.get("state") not in {"available", "partial", "empty"}:
        raise ValueError("computers_v6_export_unavailable")
    body = render_computers_v6_csv(raw)
    text = body.decode("utf-8-sig") if isinstance(body, bytes) else body
    # Pagination covers only the bounded input. A filtered/empty page cannot
    # establish completeness when source rows were omitted before filtering.
    truncated = bool(raw.get("has_more") or (raw.get("limits") or {}).get("input_truncated"))
    return text, {"rows": len(raw.get("items") or []), "truncated": truncated}


REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="AD asset reviewer",
        question="Какие компьютеры AD требуют внимания в выбранном срезе?",
        action="Inspect activity, reasons and data quality before deciding on asset maintenance.",
        scope="Latest computer snapshot in server-authorized domains; type, OS, OU and attention filters.",
        exclusions="No proof of absence from partial snapshots; no invented activity, IP address or physical asset census.",
        sources=(
            "Canonical: AD computer snapshot within granted domains.",
            "Supplemental: retained computer observations and server-defined attention reasons.",
        ),
        freshness_expectation="Время последнего подтверждённого снимка компьютеров AD.",
        rights="ad.computers.v6 view grant; identity_basic, technical and security in server domain scope; export separately granted.",
        field_classes=(
            "identity_basic",
            "technical",
            "security",
        ),
        coverage="Computer snapshot sections and field quality in the selected authorized scope.",
        completeness="Source-confirmed AD computer objects divided by expected computer objects in the selected scope before pagination; missing attributes are separate quality gaps. Unknown without a confirmed population.",
        denominator="Ожидаемые объекты компьютеров AD в выбранном срезе; при неполном снимке состав не подтверждён.",
        retention="Derived computer facts follow the storage policy; retained snapshots bound exact source evidence.",
        provenance="Computer entity, AD snapshot identity and observation timestamp; reasons and quality issues retain their source.",
        primary_archetype="list",
        product_archetype="inventory-status",
        deterministic_policy="Compute only existing server-defined attention reasons from observed computer attributes and activity.",
        result_limits="Computer pages and logon detail are bounded separately; an incomplete snapshot is not an asset census.",
        fallback="Missing activity, address and snapshot sections remain unknown; never infer absent assets from missing rows.",
        acceptance_lanes={
            "product_user": "Computer type, OS, OU and attention filters support asset review.",
            "authorization": "ad.computers.v6 fields and domain scope constrain rows, detail and independently granted export.",
            "deterministic_interpretation": "Identical observed attributes retain the same existing attention reasons.",
            "api_view_model": "Rows, detail cursors and filter options preserve the v6 asset reader contract.",
            "ui_honest_states": "Missing attributes, partial snapshots, stale and unavailable inventory stay distinct.",
            "evidence_audit": "Computer entity, snapshot identity and reason provenance remain linked.",
        },
    ),
    key=REPORT_KEY,
    section="reports/computers",
    title="Компьютеры",
    description="Инвентарь компьютеров домена по последнему снимку AD: тип, ОС, активность, адреса, причины внимания и качество данных.",
    archetype="inventory-status",
    access=AccessRule(REPORT_KEY, frozenset({"identity_basic", "technical", "security"})),
    params=(
        Param("domain_id", "Домен", "domain", hidden=True),
        Param("domain", "Домен", "domain", hidden=True),
        replace(Param.choice("view", "Срез", VIEWS, default="all"), hidden=True),
        Param.text("q", "Поиск"),
        Param.choice("type", "Тип", TYPES),
        Param.choice("enabled", "Учётная запись", ACCOUNT),
        Param.choice("activity", "Активность", ACTIVITY_FILTERS),
        Param.choice("threshold_days", "Порог давности", THRESHOLDS, default="90"),
        Param.choice("os", "ОС", options_from="os"),
        Param.choice("os_family", "Семейство ОС", options_from="os_family"),
        Param.choice("os_version", "Версия ОС", options_from="os_version"),
        Param.choice("ou", "OU", options_from="ou"),
        Param.choice("ad_site", "AD-сайт", options_from="ad_site"),
        Param("reason_code", "Причина", "text", hidden=True),
        Param("quality_code", "Качество", "text", hidden=True),
    ),
    columns=(
        Column("display_name", "Компьютер", sortable=True),
        Column("computer_type", "Тип", "state", sortable=True, labels=dict(TYPES)),
        Column("enabled", "Учётная запись", "state", path="account_state", sortable=True, labels=dict(ACCOUNT)),
        Column("operating_system", "ОС", sortable=True),
        Column("activity_state", "Активность", "state", sortable=True, labels=dict(ACTIVITY)),
        Column("last_logon_utc", "Последний вход", "datetime", sortable=True),
        Column("reason", "Требует внимания", path="reason_text", sortable=True),
        Column("ip_addresses", "IP по DNS на дату снимка", path="dns_ip.addresses", component="ad.dns-ip"),
        Column("sli_agent", "Агент SLI", component="ad.agent"),
        Column("ou_path", "OU", sortable=True, optional=True),
        Column("quality", "Качество данных", path="quality_text", sortable=True, optional=True),
        Column("age", "Дней без входа", "number", path="age_days", optional=True),
        Column("version", "Версия ОС", path="operating_system_version", optional=True),
        Column("dns", "DNS-имя", path="dns_host_name", optional=True),
        Column("description", "Описание", optional=True),
        Column("site", "AD-сайт", path="site_text", optional=True),
        Column("canonical_name", "Каноническое имя", optional=True),
        Column("distinguished_name", "DN", "code", optional=True),
        Column("managed_by", "Управляет", optional=True),
        Column("location", "Расположение", optional=True),
        Column("created_utc", "Создан в AD", "datetime", optional=True),
        Column("when_changed_utc", "Изменён в AD", "datetime", optional=True),
        Column("password_last_set_utc", "Пароль компьютера изменён", "datetime", optional=True),
        Column("delegation", "Неограниченное делегирование", "boolean", path="trusted_for_delegation", optional=True),
        Column("delegation_auth", "Делегирование с проверкой подлинности", "boolean", path="trusted_to_auth_for_delegation", optional=True),
        Column("constrained_delegation", "Ограниченное делегирование", "boolean", optional=True),
        Column("resource_based_delegation_present", "Ресурсное делегирование (RBCD)", "boolean", optional=True),
        Column("laps_state", "Метаданные LAPS", "state", optional=True, labels={
            "metadata_present": "Метаданные есть", "expired": "Срок истёк", "unknown": "Нет доступных метаданных"}),
        Column("laps_password_expiration_utc", "Плановый срок Windows LAPS", "datetime", optional=True),
        Column("legacy_laps_password_expiration_utc", "Плановый срок Legacy LAPS", "datetime", optional=True),
        Column("spn", "SPN", "list", path="service_principal_names", optional=True),
        Column("object_sid", "SID", "code", optional=True),
        Column("object_guid", "GUID", "code", optional=True),
        Column("observed", "Наблюдение снимка", "datetime", path="observed_at_utc", optional=True),
    ),
    query=_query,
    export_csv=_export,
    row_key="entity_id",
    detail=Detail(
        title="Почему компьютер требует внимания",
        key="entity_id",
        inline="reasons",
        columns=(
            Column("label", "Причина"),
            Column("observed", "Наблюдалось"),
            Column("condition", "Условие"),
            Column("qualification", "Квалификация"),
            Column("limitation", "Ограничение"),
            Column("next", "Безопасный следующий шаг", path="next_action"),
        ),
    ),
    presets=(
        ("Давно не входили", {"view": "attention", "reason_code": "stale_activity"}),
        ("Серверы", {"view": "server_enabled"}),
        ("Тип не определён", {"view": "unknown_type"}),
    ),
    row_links=(("Карточка компьютера", "/app/entities/{entity_id}"),),
    default_limit=50,
    max_limit=200,
    home_order=40,
)

REPORT = replace(REPORT, views=(
    View("table", "checks", message(review_catalog.PREFIX + "tab")["text"],
         source="checks", columns=review_catalog.columns("computers"), access=AccessRule(REPORT_KEY, review_catalog.COMPUTER_FIELDS)),
    View("table", "changes", "Изменения", source="changes", columns=(
        Column("display_name", "Компьютер"),
        Column("computer_type", "Роль", "state", labels=dict(TYPES)),
        Column("observed_at_utc", "Наблюдение снимка", "datetime"),
        Column("change_type", "Изменение", "state", labels={
            "new_object": "Впервые обнаружен", "missing_current": "Отсутствует в текущем снимке",
            "enabled_changed": "Состояние учётной записи", "ou_changed": "Перенесён в OU",
            "os_changed": "Изменена ОС", "ip_changed": "Изменены адреса",
            "site_changed": "Изменён AD-сайт", "managed_by_changed": "Изменён управляющий",
            "classification_changed": "Изменена роль", "quality_changed": "Изменилось качество данных",
            "semantic_changed": "Изменились связанные находки",
            "delegation_changed": "Изменено делегирование", "laps_changed": "Изменены метаданные LAPS",
        }),
        Column("field", "Атрибут", "state", labels={
            "presence": "Наличие в снимке", "enabled": "Учётная запись включена", "ou_path": "OU",
            "operating_system": "ОС", "computer_type": "Роль", "laps_password_expiration_utc": "Срок LAPS",
            "unconstrained": "Неограниченное делегирование", "constrained": "Ограниченное делегирование",
            "resource_based": "Ресурсное делегирование (RBCD)",
        }),
        Column("before", "Было"), Column("after", "Стало"), Column("actor", "Исполнитель"),
        Column("limitation", "Ограничение", optional=True),
    )),
    View("table", "computers", "Все компьютеры"),
))
