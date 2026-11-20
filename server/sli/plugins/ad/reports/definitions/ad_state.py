"""«Состояние Active Directory» (ad.state) on the v2 report framework (plan 5.6).

Rows are the control ledger of ``active_directory_reporting``: one checked
parameter per row with its actual value, the explicit condition and the
qualification. Published semantic findings are a separate tab.
"""

from __future__ import annotations

import json
from typing import Any

from psycopg import OperationalError
from psycopg import errors as psycopg_errors

from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Detail,
    HomeContribution,
    Param,
    QueryContext,
    ReportDefinition,
    ReportIntent,
    View,
    csv_from_columns,
    result,
    source_state,
)
from server.sli.plugins.ad.reports.active_directory_reporting import (
    get_active_directory_report,
    render_active_directory_report_csv,
)
from server.sli.core.messages import catalog, message
from server.sli.plugins.ad.spn_collisions import get_collisions
from server.sli.plugins.ad.home import PRIVILEGED_CHANGES, read as read_membership_changes
from server.sli.plugins.ad.reports.ad_snapshot_change_reporting import change_view, query_history

REPORT_KEY = "ad.infrastructure"
ACCESS_KEY = "ad.state"
CATEGORIES = (
    ("overview", "Все параметры"), ("domain_controllers", "Контроллеры"), ("replication", "Репликация"),
    ("dns", "DNS"), ("policies", "Политики"), ("trusts", "Доверия"), ("risks", "Только непройденные"),
)
QUALIFICATIONS = (
    ("failed", "Не пройдено"), ("not_evaluated", "Не оценено"),
    ("policy_not_defined", "Требование не задано"), ("passed", "Пройдено"),
)
AUTHORITY = {
    "collector_diagnostic": "Диагностика сборщика",
    "report_rule_v1": "Правило отчёта v1",
    "not_defined": "Политика организации не задана",
}
ENTITY_TYPES = (
    ("domain", "Домен"), ("domain_controller", "Контроллер домена"), ("replication_link", "Связь репликации"),
    ("password_policy", "Политика паролей"), ("domain_trust", "Доверие"),
)
CONTEXT_LABELS = {
    "dns_host_name": "DNS", "site_name": "Сайт", "is_global_catalog": "Global Catalog", "is_read_only": "RODC",
    "operation_master_roles": "FSMO", "distinguished_name": "DN", "forest_name": "Лес", "netbios_name": "NetBIOS",
    "pdc_emulator": "PDC Emulator", "rid_master": "RID Master", "infrastructure_master": "Infrastructure Master",
    "schema_master": "Schema Master", "domain_naming_master": "Domain Naming Master", "source_dc": "Источник",
    "destination_dc": "Назначение", "naming_context": "Раздел каталога",
    "last_replication_attempt_utc": "Последняя попытка", "trust_partner": "Партнёр", "trust_flat_name": "Краткое имя",
}

ENUM_LABELS = {
    "passed": "Пройдено", "unknown": "Неизвестно", "inactive": "Неактивно",
    "BiDirectional": "Двустороннее", "Uplevel": "Доверие Active Directory",
    "Inbound": "Входящее", "Outbound": "Исходящее", "Downlevel": "Доверие старого типа",
}


def _text(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return "Да" if value else "Нет"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or None
    if isinstance(value, dict):
        if value.get("source") and value.get("destination"):
            return f"{value['source']} → {value['destination']}"
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


PREFIX = "reports.v2.ad.infrastructure."
ZERO_CONTROLS = ("replication.result_code", "replication.consecutive_failures")
LDAP_CONTROLS = ("domain.ldap_signing", "domain.ldap_channel_binding")
CONTEXT_ENUMS = ("trust_type", "trust_direction")


def _coded(code: str) -> dict[str, Any] | None:
    # Codes missing from the dictionary keep the source text; nothing is invented.
    return message(code) if code in catalog("ru") else None


def _value_code(value: Any) -> str | None:
    if isinstance(value, bool):
        return "reports.boolean.yes" if value else "reports.boolean.no"
    return f"reports.values.{value}" if isinstance(value, str) and f"reports.values.{value}" in catalog("ru") else None


def _presentation(control: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """Message codes for the fixed wording of one control; observed values stay as collected."""
    control_id = str(control.get("control_id"))
    unset = control.get("authority") == "not_defined"
    zero = control_id in ZERO_CONTROLS
    codes = {
        "label": f"controls.{control_id}.label",
        "expected_condition": f"controls.{'policy_unset' if unset else 'zero.expected' if zero else control_id + '.expected'}",
        "basis": f"controls.{'policy_basis' if unset else 'zero.basis' if zero else 'ldap_basis' if control_id in LDAP_CONTROLS else control_id + '.basis'}",
        "authority_text": f"authority.{control.get('authority')}",
    }
    envelopes = {field: _coded(PREFIX + code) for field, code in codes.items() if isinstance(row.get(field), str)}
    code = _value_code(control.get("actual_value"))
    if code and row.get("actual_text") is not None:
        envelopes["actual_text"] = message(code)
    return {field: envelope for field, envelope in envelopes.items() if envelope}


def _context(key: str, value: Any) -> dict[str, Any]:
    entry = {"code": key, "label": CONTEXT_LABELS.get(key, key), "value": _text(value)}
    messages = {}
    if _coded(PREFIX + f"context_labels.{key}"):
        messages["label"] = message(PREFIX + f"context_labels.{key}")
    code = _value_code(value) if isinstance(value, bool) or key in CONTEXT_ENUMS else None
    if code:
        messages["value"] = message(code)
    return {**entry, "presentation_messages": messages} if messages else entry


def _row(control: dict[str, Any]) -> dict[str, Any]:
    context = dict(control.get("object_context") or {})
    row = {
        **control,
        "row_id": f"{control.get('entity_id')}:{control.get('control_id')}",
        "actual_text": ENUM_LABELS.get(str(control.get("actual_value")), _text(control.get("actual_value"))),
        "expected_condition": "Проверка репликации должна завершиться успешно"
        if control.get("expected_condition") == "Сборщик должен вернуть passed" else control.get("expected_condition"),
        "authority_text": AUTHORITY.get(str(control.get("authority")), control.get("authority")),
        "context": [_context(key, value) for key, value in context.items()],
    }
    envelopes = _presentation(control, row)
    return {**row, "presentation_messages": envelopes} if envelopes else row


def _semantic(raw: dict[str, Any], params: dict[str, Any], controls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    eligible = {row.get("entity_id") for row in controls if _matches(row, {**params, "q": ""})}
    restrict_entities = params.get("qualification") or params.get("view", "overview") != "overview"
    needle = str(params.get("q") or "").strip().casefold()
    return [
        {**finding, "entity_name": item.get("display_name"), "entity_id": item.get("entity_id"),
         "domain_id": item.get("domain_id"), "domain_name": item.get("domain_name")}
        for item in raw.get("items") or [] for finding in item.get("semantic_findings") or []
        if (not restrict_entities or item.get("entity_id") in eligible)
        and (not params.get("entity_type") or item.get("entity_type") == params["entity_type"])
        and (not needle or needle in " ".join(str(value) for value in (
            item.get("display_name"), finding.get("title"), finding.get("summary"),
            finding.get("why_it_matters"), finding.get("recommended_action"),
        )).casefold())
    ]


def _matches(row: dict[str, Any], params: dict[str, Any]) -> bool:
    if params.get("qualification") and row.get("qualification") != params["qualification"]:
        return False
    if params.get("entity_type") and row.get("entity_type") != params["entity_type"]:
        return False
    needle = str(params.get("q") or "").strip().casefold()
    if needle:
        haystack = " ".join(str(value) for value in (row.get("label"), row.get("entity_name"), row.get("actual_text"), row.get("control_id")))
        return needle in haystack.casefold()
    return True


def _read(context: QueryContext, **params: Any) -> dict[str, Any]:
    selection = context.runtime.get("domain_selection")
    return get_active_directory_report(
        domain_ids=context.domain_ids,
        **({"qualify_names": selection.domain_id is None} if selection is not None else {}),
        **params,
    )


def _query(context: QueryContext) -> dict[str, Any]:
    if context.tab == "privileged_changes":
        raw = read_membership_changes(context, details=True)
        return result(REPORT, state=raw["state"], items=raw["items"], collections={"privileged_changes": raw["items"]},
                      coverage=raw["coverage"], limitations=raw["limitations"], has_more=raw["has_more"],
                      next_cursor=str(int(context.cursor or 0) + len(raw["items"])) if raw["has_more"] else None)
    if context.tab == "changes":
        return query_history(REPORT, context, ("users_v2", "computers_v6"))
    if context.tab == "spn_collisions":
        return _spn_query(context)
    params = context.params
    raw = _read(context, view=params.get("view") or "overview", limit=200)
    controls = list(map(_row, raw.get("controls") or []))
    rows = [row for row in controls if _matches(row, params)]
    if params.get("row_id"):
        rows = [row for row in rows if row["row_id"] == params["row_id"]]
    rows.sort(key=lambda row: ([code for code, _ in QUALIFICATIONS].index(row.get("qualification")) if row.get("qualification") in dict(QUALIFICATIONS) else 9, str(row.get("entity_name")), str(row.get("label"))))
    counts = (raw.get("summary") or {}).get("control_counts") or {}
    collections: dict[str, list[dict[str, Any]]] = {}
    if context.tab == "semantic":
        collections["semantic"] = _semantic(_read(context, view="semantic", limit=200), params, controls)
    state = source_state(raw.get("state"))
    if state == "ok" and not rows:
        state = "empty"
    coverage = raw.get("coverage") or {}
    limitations = [{"code": "unknown_not_safe", "text": "Отсутствующие и недоступные параметры не считаются безопасным нулём: «Не оценено» — не «Пройдено»."}]
    missing = sum(len(coverage.get(key) or []) for key in ("missing", "stale", "failed", "partial"))
    if missing:
        limitations.append({"code": "coverage", "params": {"count": missing},
                            "text": f"Ограничений покрытия источников: {missing}. Пустой список не доказывает безопасное состояние."})
    return result(
        REPORT, state=state, items=rows, filtered_count=len(rows),
        metrics=[
            {"key": "failed", "label": "Не пройдено", "value": counts.get("failed"), "tone": "danger" if counts.get("failed") else "neutral", "filter": {"qualification": "failed"}},
            {"key": "not_evaluated", "label": "Не оценено", "value": counts.get("not_evaluated"), "tone": "warning" if counts.get("not_evaluated") else "neutral", "filter": {"qualification": "not_evaluated"}},
            {"key": "policy_not_defined", "label": "Требование не задано", "value": counts.get("policy_not_defined"), "filter": {"qualification": "policy_not_defined"}},
            {"key": "passed", "label": "Пройдено", "value": counts.get("passed"), "tone": "success", "filter": {"qualification": "passed"}},
        ],
        coverage={**coverage, "state": raw.get("state"), "freshness_threshold_seconds": 86400,
                  "observed_at_utc": min((str(domain["observed_at_utc"]) for domain in coverage.get("domains") or [] if domain.get("observed_at_utc")), default=None),
                  "missing_sources": [str(item) for key in ("missing", "failed", "partial") for item in coverage.get(key) or []]},
        limitations=limitations,
        collections=collections,
    )


def _export(context: QueryContext) -> tuple[str, dict[str, Any]]:
    if context.tab == "privileged_changes":
        payload = _query(context)
        view = next(view for view in REPORT.views if view.key == context.tab)
        return csv_from_columns(view.columns, payload["items"]), {"rows": len(payload["items"]), "truncated": payload["has_more"]}
    if context.tab == "changes":
        payload = _query(context)
        if payload["state"] == "error":
            raise ValueError("active_directory_history_not_exportable")
        view = next(view for view in REPORT.views if view.key == "changes")
        rows = payload["collections"]["changes"]
        return csv_from_columns(view.columns, rows), {"rows": len(rows), "truncated": "history_truncated" in payload["coverage"].get("reasons", [])}
    if context.tab == "spn_collisions":
        payload = _spn_query(context)
        if payload["state"] == "error":
            raise ValueError("active_directory_evidence_not_exportable")
        view = next(view for view in REPORT.views if view.key == context.tab)
        rows = payload["collections"]["spn_collisions"]
        return csv_from_columns(view.columns, rows), {"rows": len(rows), "truncated": payload["coverage"].get("truncated", False)}
    raw = _read(context, view=context.params.get("view") or "overview", limit=10_000, max_page_limit=10_000)
    if raw.get("state") not in {"available", "partial", "empty"}:
        raise ValueError("active_directory_evidence_not_exportable")
    controls = list(map(_row, raw.get("controls") or []))
    view = next((view for view in REPORT.views if view.key == context.tab), REPORT.views[0])
    truncated = bool(raw.get("has_more"))
    if view.source == "semantic":
        semantic = _read(context, view="semantic", limit=200)
        if semantic.get("state") not in {"available", "partial", "empty"}:
            raise ValueError("active_directory_evidence_not_exportable")
        rows = _semantic(semantic, context.params, controls)
        # The underlying semantic query is bounded to 201 findings.
        truncated = truncated or bool(semantic.get("has_more")) or sum(len(item.get("semantic_findings") or []) for item in semantic.get("items") or []) >= 201
    else:
        rows = [row for row in controls if _matches(row, context.params)]
        body = render_active_directory_report_csv({**raw, "controls": rows, "items": []})
        text = body.decode("utf-8-sig") if isinstance(body, bytes) else body
        return text, {"rows": len(rows), "truncated": truncated}
    return csv_from_columns(view.columns or REPORT.columns, rows), {"rows": len(rows), "truncated": truncated}


def _spn_query(context: QueryContext) -> dict[str, Any]:
    try:
        raw = get_collisions(domain_ids=context.domain_ids, params=context.params)
    except (OperationalError, psycopg_errors.InsufficientPrivilege, psycopg_errors.UndefinedTable,
            psycopg_errors.UndefinedColumn, psycopg_errors.QueryCanceled):
        raw = {"state": "unavailable", "items": [], "metrics": {}, "coverage": {"state": "unavailable"}}
    metrics = raw.get("metrics") or {}
    return result(
        REPORT, state=source_state(raw["state"]), collections={"spn_collisions": raw["items"]},
        coverage=raw["coverage"], filtered_count=len(raw["items"]),
        metrics=[
            {"key": "spn_collisions", "label": "SPN с несколькими владельцами", "value": metrics.get("collisions")},
            {"key": "spn_disabled", "label": "Отключённых владельцев SPN", "value": metrics.get("disabled_owners")},
            {"key": "spn_flagged", "label": "Владельцев с delegation/preauth-флагами", "value": metrics.get("flagged_owners")},
            {"key": "spn_unknown", "label": "Владельцев с неизвестными параметрами", "value": metrics.get("unknown_owners")},
        ],
        limitations=[
            {"code": "spn_scope", "text": "Владельцы сравниваются только внутри одного запуска сбора directory_accounts и его SearchBase. Разные домены и снимки не объединяются; область сбора может быть неполной."},
            {"code": "spn_encryption", "text": "Поддерживаемое шифрование аккаунта не доказывает фактическое шифрование Kerberos-билета. Неизвестные атрибуты не считаются безопасными."},
            *([{"code": "spn_partial", "text": "Покрытие снимка неполное: часть областей, записей, идентичностей или атрибутов недоступна. Отсутствие коллизий в показанных данных не доказывает их отсутствие во всей области."}] if raw["state"] == "partial" else []),
            *([{"code": "spn_truncated", "text": "Предел чтения SPN достигнут: список неполный, итоговые счётчики неизвестны. Уточните область доступа."}] if raw.get("truncated") else []),
            *([{"code": "spn_unavailable", "text": "Сопоставимый снимок directory_accounts за последние 31 день недоступен. Отсутствие строк не доказывает отсутствие коллизий."}] if raw["state"] == "unavailable" else []),
        ],
    )


REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="AD administrator",
        question="Какие параметры AD требуют проверки в выбранных доменах?",
        action="Review parameter evidence and the stated condition before an administrative decision.",
        scope="Server-authorized domains; latest domain, controller, replication, DNS, policy and trust observations.",
        exclusions="No organization compliance verdict without an accepted policy; no inferred client GPO application.",
        sources=(
            "Canonical: AD Context sectional snapshots and collector diagnostics within granted domains.",
            "Supplemental: published deterministic findings and current AD SPN observations.",
        ),
        freshness_expectation="Последнее подтверждённое наблюдение разделов AD; неизвестная свежесть сохраняется.",
        rights="ad.state view grant; server-resolved domain scope; export requires its own action grant.",
        field_classes=(
            "identity_basic",
            "technical",
            "security",
            "privilege",
        ),
        coverage="Observed AD sections compared with the expected sections per authorized domain.",
        completeness="Source-confirmed object/parameter pairs divided by expected pairs in the authorized scope; passed conditions are not the numerator. Unknown when expected population is unconfirmed.",
        denominator="Ожидаемые разделы и объекты AD в разрешённых доменах; при неизвестном составе процент не вычисляется.",
        retention="Permanent derived AD facts follow the storage policy; exact snapshot evidence is available only while retained.",
        provenance="Domain, object, source section, observation timestamp, condition and authority in the control ledger.",
        primary_archetype="matrix",
        product_archetype="inventory-status",
        deterministic_policy="Retain report_rule_v1 and collector diagnostics separately; passed, failed, not_evaluated and policy_not_defined are distinct.",
        result_limits="Control rows, history and findings have separate bounds and source timestamps; report rules are not organization compliance.",
        fallback="Missing control values remain not_evaluated; absent organization policy remains policy_not_defined; partial snapshots cannot pass controls.",
        acceptance_lanes={
            "product_user": "Infrastructure parameters and stated conditions support manual AD review.",
            "authorization": "ad.state grant and authorized domain/field scope constrain controls, findings and history.",
            "deterministic_interpretation": "Identical control inputs retain report_rule_v1 qualification; undefined policy never becomes passed.",
            "api_view_model": "Control rows and supplemental collections preserve conditions, actual values and authority.",
            "ui_honest_states": "Missing values, partial snapshots, stale observations and unavailable history remain explicit.",
            "evidence_audit": "Each control retains source observation, rule authority and exact evidence context.",
        },
        qualification={"status": "measured", "definition": "Existing report_rule_v1 control conditions and collector diagnostics; organization policy may remain undefined."},
    ),
    key=REPORT_KEY,
    section="reports/identity",
    title="Состояние Active Directory",
    description="Фактические параметры домена, контроллеров, репликации, DNS, политик и доверий с явными условиями и основаниями оценки.",
    archetype="inventory-status",
    access=AccessRule(ACCESS_KEY, frozenset({"identity_basic", "technical", "security"})),
    params=(
        Param("domain_id", "Домен", "domain", hidden=True),
        Param("domain", "Домен", "domain", hidden=True),
        Param("row_id", "Параметр", "text", hidden=True),
        Param.period(max_days=3650),
        Param.choice("view", "Раздел", CATEGORIES, default="overview"),
        Param.choice("qualification", "Результат", QUALIFICATIONS),
        Param.choice("entity_type", "Тип объекта", ENTITY_TYPES),
        Param.text("q", "Поиск"),
        Param.integer("spn_domain", "Домен SPN (ID)"),
        Param.text("spn_service", "Класс сервиса SPN"),
        Param.choice("spn_collisions_only", "Только коллизии SPN", (("true", "Да"), ("false", "Нет")), default="true"),
        Param.choice("spn_enabled", "Владелец SPN включён", (("true", "Да"), ("false", "Нет"))),
        Param.choice("spn_delegation", "Delegation/preauth-флаги SPN", (("true", "Да"), ("false", "Нет"))),
        Param.integer("spn_password_days", "Минимальный возраст пароля SPN, дней"),
    ),
    columns=(
        Column("label", "Параметр", sortable=True),
        Column("entity_name", "Объект", sortable=True, link="/app/entities/{entity_id}"),
        Column("entity_type", "Тип объекта", "state", sortable=True, labels=dict(ENTITY_TYPES)),
        Column("actual", "Фактическое значение", path="actual_text"),
        Column("expected_condition", "Ожидаемое условие"),
        Column("qualification", "Результат", "state", sortable=True, labels=dict(QUALIFICATIONS)),
        Column("basis", "Основание"),
        Column("observed_at_utc", "Наблюдалось", "datetime", sortable=True),
        Column("authority", "Источник правила", path="authority_text", optional=True),
        Column("source_section", "Секция сбора", "code", optional=True),
        Column("control_id", "Код параметра", "code", optional=True),
    ),
    views=(
        View("table", "controls", "Параметры"),
        View("table", "privileged_changes", "Изменения привилегированного членства", source="privileged_changes",
             access=AccessRule(ACCESS_KEY, frozenset({"privilege", "technical"})), columns=(
                 Column("entity_id", "Участник (ID)", "number", link="/app/entities/{entity_id}"),
                 Column("group_id", "Группа (ID)", "number", link="/app/entities/{group_id}"),
                 Column("kind", "Изменение", "state", labels={"added": "Добавление", "removed": "Удаление"}),
                 Column("observed_at_utc", "Наблюдалось", "datetime"),
             )),
        change_view("Изменения AD", access=AccessRule(ACCESS_KEY, frozenset({"identity_basic", "technical", "security", "privilege"}))),
        View("table", "spn_collisions", "Коллизии SPN", source="spn_collisions",
             note="Одна строка на владельца SPN. Снимки старше 36 часов отмечаются как устаревшие; данные ограничены последними 31 сутками.", columns=(
            Column("spn", "SPN", "code"),
            Column("owner_count", "Владельцев", "number"),
            Column("domain_id", "Домен (ID)", "number"),
            Column("entity_id", "Владелец", "number", link="/app/entities/{entity_id}"),
            Column("entity_type", "Тип объекта", "state", labels={"ad_user": "Пользователь", "ad_computer": "Компьютер"}),
            Column("enabled", "Включён", "boolean"),
            Column("password_age_days", "Возраст пароля, дней", "number"),
            Column("password_last_set_utc", "Пароль изменён", "datetime"),
            Column("trusted_for_delegation", "TrustedForDelegation", "boolean"),
            Column("trusted_to_auth_for_delegation", "TrustedToAuthForDelegation", "boolean"),
            Column("does_not_require_preauth", "Без preauth", "boolean"),
            Column("msds_supported_encryption_types", "Поддерживаемое шифрование (маска)", "number"),
            Column("owner_quality", "Параметры владельца", "state", labels={"known": "Известны", "unknown": "Часть неизвестна"}),
            Column("observed_at_utc", "Наблюдалось", "datetime"),
            Column("source_freshness", "Свежесть источника", "state", labels={"fresh": "Свежий", "stale": "Устаревший", "unknown": "Неизвестна"}),
            Column("run_id", "Снимок", "code"),
        )),
        View("table", "semantic", "Связанные находки", source="semantic", note="Только опубликованные находки, точно связанные с инфраструктурной сущностью AD. Пустой список не доказывает отсутствие рисков.", columns=(
            Column("title", "Находка"),
            Column("entity_name", "Объект", link="/app/entities/{entity_id}"),
            Column("severity", "Важность", "state"),
            Column("summary", "Описание"),
            Column("why_it_matters", "Почему важно"),
            Column("recommended_action", "Следующее действие"),
            Column("last_seen_utc", "Последнее наблюдение", "datetime"),
        )),
    ),
    query=_query,
    export_csv=_export,
    row_key="row_id",
    detail=Detail(
        title="Контекст объекта",
        key="row_id",
        inline="context",
        columns=(Column("label", "Атрибут"), Column("value", "Значение")),
    ),
    presets=(
        ("Непройденные", {"view": "risks"}),
        ("Не оценено", {"qualification": "not_evaluated"}),
        ("Репликация", {"view": "replication"}),
    ),
    row_links=(("Карточка объекта", "/app/entities/{entity_id}"),),
    default_limit=200,
    max_limit=200,
    home_order=20,
    home_contributions=(HomeContribution(key="ad_failed", metric_key="failed", label_code="home.kpi.ad_failed",
                                         unit_code="home.unit.checks", meaning="lower_is_better", order=20,
                                         filters={"qualification": "failed"}), PRIVILEGED_CHANGES),
)
