"""«Действия безопасности» on the v2 report framework (pilot, plan 4.5).

The engine ``security_event_reporting`` enforces the grant
and domain scope itself (``AccessRule.scope == "delegated"``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Param,
    QueryContext,
    ReportDefinition,
    ReportIntent,
    View,
    csv_from_columns,
    result,
    source_state,
)
from server.sli.reports.account_revocation_reporting import get_account_revocation
from server.sli.reports.security_event_reporting import (
    MAX_PERIOD_DAYS,
    REPORT_KEY,
    REQUIRED_FIELD_CATEGORIES,
    get_security_event_domain_ids,
    get_security_events_daily,
    get_security_events_report,
    render_security_events_csv,
)
from server.sli.reports.security_lockout_recurring import get_recurring_lockouts
from server.sli.reports.security_persistence_changes import get_persistence_changes

FAMILIES: tuple[tuple[str, str], ...] = (
    ("authentication", "Аутентификация"),
    ("account_lock", "Блокировка и разблокировка"),
    ("password_operation", "Изменение пароля"),
    ("account_lifecycle", "Жизненный цикл учётной записи"),
    ("account_change", "Изменение учётной записи"),
    ("group_membership", "Членство в группах"),
    ("group_lifecycle", "Изменение групп"),
    ("audit_configuration", "Изменения аудита"),
)
OUTCOMES: tuple[tuple[str, str], ...] = (("success", "Успех"), ("failure", "Отказ"), ("unknown", "Не определён"))

_LIMITATION_TEXT = {
    "Rows are source-event observations, not reconstructed account, membership, or audit state.":
        ("observations_only", "Строки — наблюдения событий источника, а не восстановленное состояние учётных записей, членства или аудита."),
    "Unknown identity and outcome fields were not present in the scoped Storage V2 contract.":
        ("unknown_fields", "Поля «не определён» отсутствовали в сохранённых данных события."),
    "An empty window does not prove complete source coverage.":
        ("empty_not_proof", "Пустой результат не доказывает, что источник собран полностью."),
}


_STATE_WORD = {
    "present": "запись создана", "enabled": "включена", "disabled": "отключена",
    "deleted": "удалена", "locked": "заблокирована", "unlocked": "разблокирована",
}
_CHANGE_KIND = {
    "created": "создание", "enabled": "включение", "disabled": "отключение", "deleted": "удаление",
    "locked": "блокировка", "unlocked": "разблокировка", "renamed": "переименование",
    "password_changed": "смена пароля", "password_reset": "сброс пароля", "attributes_changed": "изменение атрибутов",
    "member_added": "добавление в группу", "member_removed": "удаление из группы",
}


def _change_text(item: Mapping[str, Any]) -> str | None:
    """Human "before → after" for account changes, only as far as the event proves it."""
    transition = ((item.get("account_change") or {}).get("observed_transition") or {})
    before, after = transition.get("before") or {}, transition.get("after") or {}
    if before or after:
        left = _STATE_WORD.get(str(before.get("value")), before.get("value")) if before.get("state") == "observed" else "не подтверждено"
        right = _STATE_WORD.get(str(after.get("value")), after.get("value")) if after.get("state") == "observed" else "не подтверждено"
        return f"{left} → {right}"
    change = item.get("change") or {}
    if change.get("state") == "observed" and change.get("kind"):
        return _CHANGE_KIND.get(str(change["kind"]), str(change["kind"]))
    return None


def _with_derived(item: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(item)
    outcome = item.get("outcome")
    # Evidence quality is not the outcome; retain the source object unchanged.
    row["outcome_code"] = (
        outcome["value"] if isinstance(outcome, Mapping) and outcome.get("state") == "observed"
        and outcome.get("value") in ("success", "failure") else "unknown"
    )
    row["change_text"] = _change_text(item)
    member = item.get("member") or {}
    row["member_text"] = member.get("name") or member.get("sid") if member.get("state") == "observed" else None
    return row


def _limitations(raw: Any) -> list[dict[str, str]]:
    out = []
    for text in raw or []:
        code, label = _LIMITATION_TEXT.get(str(text), ("engine_note", str(text)))
        out.append({"code": code, "text": label})
    return out


def _domain_options(access: Mapping[str, Any]) -> list[dict[str, Any]]:
    ids = get_security_event_domain_ids(access)
    if not ids:
        return []
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select id, fqdn from domains where id = any(%s) order by fqdn", (ids,))
        names = {int(row["id"]): str(row["fqdn"]) for row in cur.fetchall()}
    return [{"value": str(domain_id), "label": names.get(domain_id, f"Домен {domain_id}")} for domain_id in ids]


def _engine_arguments(context: QueryContext) -> dict[str, Any]:
    params = context.params
    period = params["period"]
    return {
        "source_domain_id": int(params["domain"]) if params.get("domain") else None,
        "time_from": period["from_utc"],
        "time_to": period["to_utc"],
        "timezone_name": "UTC",
        "category": params.get("category"),
        "event_id": params.get("event_id"),
        "outcome": params.get("outcome"),
        "actor": params.get("actor"),
        "target_account": params.get("target"),
        "group": params.get("group"),
        "source_host": params.get("source"),
        "q": params.get("q"),
        "entity_id": params.get("entity_id"),
        "event_db_id": params.get("event_db_id"),
    }


def _daily(context: QueryContext) -> list[dict[str, Any]]:
    """Per-day counts by family over the whole filter window (the «Динамика» tab only)."""
    arguments = {key: value for key, value in _engine_arguments(context).items() if key != "event_db_id"}
    arguments["timezone_name"] = context.timezone or "UTC"
    raw = get_security_events_daily(context.access, **arguments)
    counted = {day["date"]: day for day in raw.get("days") or []}
    if raw.get("state") != "available":
        return []
    zone = ZoneInfo(raw.get("timezone") or "UTC")
    period = context.params["period"]
    first = datetime.fromisoformat(period["from_utc"].replace("Z", "+00:00")).astimezone(zone).date()
    last = (datetime.fromisoformat(period["to_utc"].replace("Z", "+00:00")) - timedelta(seconds=1)).astimezone(zone).date()
    rows = []
    day = first
    while day <= last:
        entry = counted.get(day.isoformat()) or {"total": 0, "families": {}}
        rows.append({"date": day.isoformat(), "total": entry["total"], **{key: entry["families"].get(key, 0) for key, _ in FAMILIES}})
        day += timedelta(days=1)
    return rows


def _query(context: QueryContext) -> dict[str, Any]:
    if context.tab in {"persistence-changes", "account-revocation", "lockout-recurring"} and not context.params.get("domain"):
        raise ValueError("report_parameter_required:domain")
    if context.tab == "persistence-changes":
        return _persistence(context)
    if context.tab == "account-revocation":
        return _revocation(context)
    if context.tab == "lockout-recurring":
        return _recurring(context)
    options = {"domain": _domain_options(context.access)}
    raw = get_security_events_report(context.access, **_engine_arguments(context), limit=context.limit, cursor=context.cursor)
    engine_state = str(raw.get("state") or "")
    items = [_with_derived(item) for item in raw.get("items") or []]
    coverage = dict(raw.get("collection_coverage") or {})
    state = source_state(engine_state)
    if state == "ok" and not items:
        state = "empty"
    # Source-audit completeness is distinct from completing the bounded query.
    # The reader emits empty_unverified only for a window without observations.
    coverage_state = coverage.get("state") or engine_state
    if engine_state == "available" and items and coverage_state == "empty_unverified":
        coverage_state = engine_state
    collections = {"daily": _daily(context)} if context.tab == "daily" and state != "denied" else {}
    return result(
        REPORT, state=state, items=items, has_more=bool(raw.get("has_more")), next_cursor=raw.get("next_cursor"),
        coverage={**coverage, "state": coverage_state,
                  "completeness": coverage.get("completeness") or (coverage.get("source_completeness") if engine_state == "empty_unverified" else None),
                  "categories": raw.get("category_coverage") or {}},
        filter_options=options, limitations=_limitations(raw.get("limitations")), window=raw.get("time_bounds") or {},
        collections=collections,
    )


def _persistence(context: QueryContext) -> dict[str, Any]:
    params = context.params
    period = params["period"]
    raw = get_persistence_changes(
        context.access, domain_id=int(params["domain"]), time_from=period["from_utc"], time_to=period["to_utc"],
        limit=context.limit, source=params.get("source"), object_type=params.get("persistence_type"),
        path=params.get("persistence_path"), initiator=params.get("actor"), change=params.get("persistence_change"),
        max_frequency=params.get("persistence_rarity"), action=context.action,
    )
    if raw["state"] == "denied":
        return result(REPORT, state="denied")
    totals = raw["totals"]
    notes = [
        {"code": "persistence_observations", "text": "История содержит наблюдения в выбранном окне, а не восстановленное состояние или доказательство закрепления. Предыдущее значение — только предыдущее наблюдение; при неоднозначном порядке оно неизвестно. Обновления ПО могут быть легитимными."},
        {"code": "persistence_linking", "text": "4697 и 7045 связаны только при точном совпадении DC, времени, имени, файла, RunAs и типа запуска и единственной паре. Связь не доказывает одну установку. Частота — число наблюдений объекта (точная пара считается один раз), а не число установок. Неизвестные объекты и события без текущей семантики не объединяются; имена инициаторов не доказывают идентичность."},
        {"code": "persistence_coverage", "text": "Полнота источников не подтверждена. Карточки относятся к отфильтрованному ограниченному срезу: новые объекты означают наблюдавшееся создание/установку в окне, редкие пути/action — значения с частотой не выше заданного порога (по умолчанию 1). Отсутствие событий не доказывает отсутствие изменений или исполнения. XML задач не исполняется; неизвестные action и RunAs не восстанавливаются."},
    ]
    if raw["coverage"]["source_truncated"] or raw["coverage"]["rows_truncated"]:
        notes.append({"code": "persistence_truncated", "text": "Достигнут лимит событий или строк. История и счётчики частичные; при лимите событий связь 4697/7045 отключена. Сузьте период."})
    return result(
        REPORT, state=source_state(raw["state"]), collections={"persistence_changes": raw["rows"]}, filtered_count=raw["filtered_count"],
        metrics=[
            {"key": "persistence_services", "label": "Службы с наблюдаемой установкой", "value": totals["new_services"]},
            {"key": "persistence_tasks", "label": "Задачи с наблюдаемым созданием", "value": totals["new_tasks"]},
            {"key": "persistence_actions", "label": "Объекты с изменённым action", "value": totals["changed_actions"]},
            {"key": "persistence_paths", "label": "Редкие пути / action в срезе", "value": totals["rare_paths"]},
            {"key": "persistence_repeated", "label": "Объекты с повторными наблюдениями", "value": totals["repeated_objects"]},
            {"key": "persistence_unknown", "label": "Исходные события без SID инициатора", "value": totals["unknown_initiator"]},
        ],
        coverage=raw["coverage"], limitations=notes, window=raw["window"],
        filter_options={"domain": _domain_options(context.access)},
    )


def _recurring(context: QueryContext) -> dict[str, Any]:
    params = context.params
    period = params["period"]
    raw = get_recurring_lockouts(
        context.access, domain_id=int(params["domain"]), time_from=period["from_utc"], time_to=period["to_utc"],
        limit=context.limit, account=params.get("target"), caller=params.get("caller"), failure_code=params.get("failure_code"),
        minimum_repeats=int(params.get("min_repeats", 2)), failure_window_minutes=int(params.get("failure_window", 15)),
        action=context.action,
    )
    if raw["state"] == "denied":
        return result(REPORT, state="denied")
    totals = raw["totals"]
    notes = [
        {"code": "recurring_correlation", "text": "Точный SID и близость времени связывают наблюдения, но не доказывают причину блокировки. События без SID не объединяются по имени; автоматическое снятие блокировки может не создавать 4767."},
        {"code": "recurring_coverage", "text": "Полнота источника не подтверждена. Отсутствие сопоставленных ошибок или разблокирования не доказывает их отсутствие. Используется только текущая версия семантики; недостающие факты не восстанавливаются из старых версий."},
        {"code": "recurring_metrics", "text": "Карточки относятся к аккаунтам, прошедшим фильтры, в ограниченном срезе событий. Источники — различные значения caller, IP и workstation по отдельности, а не число устройств."},
    ]
    if raw["coverage"]["source_truncated"] or raw["coverage"]["accounts_truncated"]:
        notes.append({"code": "recurring_truncated", "text": "Достигнут лимит событий или аккаунтов. Счётчики событий — нижняя граница по прочитанному срезу; сузьте период. Строки за пределами лимита не показаны."})
    return result(
        REPORT, state=source_state(raw["state"]), collections={"lockout_recurring": raw["rows"]}, filtered_count=raw["filtered_count"],
        metrics=[
            {"key": "recurring_accounts", "label": "Аккаунты с повторными блокировками", "value": totals["accounts"]},
            {"key": "recurring_lockouts", "label": "Наблюдаемые блокировки", "value": totals["lockouts"]},
            {"key": "recurring_relocked", "label": "Повтор после наблюдаемого unlock", "value": totals["relocked_accounts"]},
            {"key": "recurring_caller", "label": "Блокировки с caller, %", "value": totals["caller_percent"]},
            {"key": "recurring_sources", "label": "Различные значения источников", "value": totals["sources"]},
        ],
        coverage=raw["coverage"], limitations=notes, window=raw["window"],
        filter_options={"domain": _domain_options(context.access)},
    )


def _revocation(context: QueryContext) -> dict[str, Any]:
    params = context.params
    period = params["period"]
    raw = get_account_revocation(
        context.access, domain_id=int(params["domain"]), time_from=period["from_utc"], time_to=period["to_utc"],
        limit=context.limit, follow_minutes=int(params.get("revocation_window", 1440)),
        minimum_delay=int(params.get("minimum_delay", 0)), account=params.get("target"), source=params.get("source"),
        activity_type=params.get("activity_type"), exact_only=params.get("identity_scope") == "exact", action=context.action,
    )
    if raw["state"] == "denied":
        return result(REPORT, state="denied")
    totals = raw["totals"]
    notes = [
        {"code": "revocation_candidate", "text": "Это кандидаты, а не доказательство обхода отключения. Учитывайте репликацию, существующие токены и погрешность часов (задержка до 60 с отмечена отдельно). 4624 на DC не доказывает интерактивный вход человека; 6272 — решение NPS, а не VPN-сессия."},
        {"code": "revocation_coverage", "text": "Полнота источников не подтверждена. Сопоставление — только точный SID в одном домене и текущая семантика. Неизвестные идентичности и события без текущей семантики показаны отдельно без связи по имени. Отсутствие 4722 не доказывает отсутствие повторного включения."},
        {"code": "revocation_window", "text": "Период задаёт время отключения/удаления. Новая аутентификация ищется в выбранном окне после него; карточки относятся к отфильтрованному ограниченному срезу. Accounting показывает отдельно старые сессии, пересекающие момент отключения; время последнего наблюдения сессии может выходить за окно аутентификации. Источник продолжения — RADIUS Accounting; полнота сессии сохранена отдельно."},
    ]
    if raw["coverage"]["accounting_state"] in {"unavailable", "empty_unverified", "not_checked"}:
        notes.append({"code": "revocation_accounting", "text": "Accounting недоступен, не содержит сопоставленных строк или не проверен без точных якорей. Отсутствие продолжавшихся VPN-сессий не установлено."})
    if raw["coverage"]["source_truncated"] or raw["coverage"]["rows_truncated"]:
        notes.append({"code": "revocation_truncated", "text": "Достигнут лимит событий, сессий или строк. Счётчики — нижняя граница прочитанного среза; сузьте период."})
    return result(
        REPORT, state=source_state(raw["state"]), collections={"account_revocation": raw["rows"]}, filtered_count=raw["filtered_count"],
        metrics=[
            {"key": "revocation_logons", "label": "Аккаунты с последующей 4624 (кандидаты)", "value": totals["logon_accounts"]},
            {"key": "revocation_nps", "label": "Разрешения NPS после отключения (кандидаты)", "value": totals["nps_allows"]},
            {"key": "revocation_vpn", "label": "Старые сессии Accounting (кандидаты)", "value": totals["vpn_sessions"]},
            {"key": "revocation_unknown", "label": "Наблюдения без точного сопоставления", "value": totals["insufficient"]},
        ],
        coverage=raw["coverage"], limitations=notes, window=raw["window"],
        filter_options={"domain": _domain_options(context.access)},
    )


def _export(context: QueryContext) -> tuple[str, dict[str, Any]]:
    if context.tab == "persistence-changes":
        if not context.params.get("domain"):
            raise ValueError("report_parameter_required:domain")
        data = _persistence(replace(context, action="export", limit=REPORT.max_limit))
        if data["state"] == "denied":
            raise PermissionError("report_export_not_authorized")
        view = next(view for view in REPORT.views if view.key == context.tab)
        rows = data["collections"][view.source]
        return csv_from_columns(view.columns, rows), {"rows": len(rows), "truncated": data["state"] == "partial"}
    raw = get_security_events_report(context.access, **_engine_arguments(context), limit=500, cursor=None, action="export")
    if raw.get("state") == "not_authorized":
        raise PermissionError("report_export_not_authorized")
    rows = len(raw.get("items") or [])
    return render_security_events_csv(raw), {"rows": rows, "truncated": bool(raw.get("has_more"))}


REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="Security investigator",
        question="Какие действия безопасности наблюдались в выбранном срезе?",
        action="Review exact observations and deterministic chains before an investigation decision.",
        scope="Granted DC Security event sources and retained current semantic facts in the selected bounded window.",
        exclusions="No inferred misuse, missing actions, AI authority or complete source coverage from an empty result.",
        sources=(
            "Canonical: source-native DC Security events and retained current semantic action facts.",
            "Supplemental: deterministic chains, account state and policy evidence within the same granted scope.",
        ),
        freshness_expectation="Подтверждение каждого источника в выбранном окне; факты текущей семантики не восстанавливают пропуски.",
        rights="security.events.chains view grant with security, technical and raw_evidence; engine-enforced source domain scope; export separately granted.",
        field_classes=(
            "security",
            "technical",
            "raw_evidence",
        ),
        coverage="Authorized source/category intervals for the selected event window, separate from semantic applicability.",
        completeness="Source-confirmed Security category intervals divided by expected source-category-window duration, with current-semantic truncation reported separately. Unknown without confirmed continuity.",
        denominator="Ожидаемые источники Security и категории событий × период; без подтверждения непрерывности процент неизвестен.",
        retention="Derived action history follows the storage policy; exact raw events/XML may expire and cannot be fabricated.",
        provenance="Exact source event IDs, domain, timestamp and current semantic/policy identity for each derived chain.",
        primary_archetype="timeline",
        product_archetype="investigation-evidence",
        deterministic_policy="Current semantic action facts and source-native events build deterministic chains within the same granted scope.",
        result_limits="Bounded event window and pages; current-semantic truncation is separate from source/category continuity.",
        fallback="Expose per-source limitations and expired exact evidence; do not infer missing actions or malicious intent.",
        acceptance_lanes={
            "product_user": "Observed security actions answer the bounded investigation question.",
            "authorization": "security.events.chains fields and domain scope also constrain chains and evidence.",
            "deterministic_interpretation": "Repeated identical event facts produce the same chains without AI interpretation.",
            "api_view_model": "Items, chain collections, window and cursors retain independent source limitations.",
            "ui_honest_states": "Empty chains do not imply safety; incomplete, stale or unavailable sources stay explicit.",
            "evidence_audit": "Each chain retains native event IDs and current semantic/policy provenance.",
        },
    ),
    key=REPORT_KEY,
    section="investigation",
    title="Действия безопасности",
    description="События безопасности контроллеров домена: блокировки, изменения учётных записей и групп, пароли, аудит, службы и задачи.",
    archetype="investigation-evidence",
    access=AccessRule(REPORT_KEY, frozenset(REQUIRED_FIELD_CATEGORIES), scope="delegated"),
    params=(
        replace(Param.domain(), required=False),
        Param.period(default="7d", max_days=MAX_PERIOD_DAYS, presets=("24h", "7d", "30d", "custom")),
        Param.choice("category", "Категория", FAMILIES),
        Param.choice("outcome", "Результат", OUTCOMES),
        Param.integer("event_id", "Код события"),
        Param.text("actor", "Кто выполнил"),
        Param.text("target", "Учётная запись"),
        Param.text("caller", "Caller / IP / workstation (повторные блокировки)"),
        Param.text("failure_code", "Код отказа (повторные блокировки)"),
        Param("min_repeats", "Минимум блокировок", "int", default=2),
        Param.choice("failure_window", "Окно предшествующих ошибок", (("5", "5 минут"), ("15", "15 минут"), ("60", "1 час"), ("1440", "24 часа")), default="15"),
        Param.text("group", "Группа"),
        Param.text("source", "Контроллер домена"),
        Param.choice("persistence_type", "Объект закрепления", (("service", "Служба"), ("task", "Задача"))),
        Param.text("persistence_path", "Файл / action службы или задачи"),
        Param.choice("persistence_change", "Изменение службы или задачи", (
            ("installed", "Установка"), ("created", "Создание"), ("updated", "Обновление"),
            ("deleted", "Удаление"), ("enabled", "Включение"), ("disabled", "Отключение"),
        )),
        Param.integer("persistence_rarity", "Максимум наблюдений (редкость)"),
        Param.choice("activity_type", "Тип активности после отключения", (
            ("logon", "Новая аутентификация 4624"), ("nps_allow", "Разрешение NPS 6272"),
            ("vpn_continuation", "Продолжение старой VPN-сессии"), ("insufficient", "Недостаточно данных"),
        )),
        Param.integer("minimum_delay", "Минимальная задержка, с"),
        Param.choice("revocation_window", "Окно после отключения", (("15", "15 минут"), ("60", "1 час"), ("1440", "24 часа")), default="1440"),
        Param.choice("identity_scope", "Сопоставление идентичности", (("all", "Все наблюдения"), ("exact", "Только точная идентичность")), default="all"),
        Param.text("q", "Поиск"),
        Param.integer("entity_id", "Сущность", hidden=True),
        Param.integer("event_db_id", "Событие", hidden=True),
    ),
    columns=(
        Column("time", "Время", "datetime", path="time_created_utc"),
        Column("event_id", "Код", "code"),
        Column("family", "Категория", "state", path="event_family", labels=dict(FAMILIES)),
        Column("actor", "Кто", path="actor.name"),
        Column("account", "Учётная запись", path="affected_account.name", link="/app/entities/{affected_account.entity_id}"),
        Column("member", "Участник", path="member_text", optional=True),
        Column("group", "Группа", path="group.name", optional=True),
        Column("source", "Контроллер", path="source_host.hostname"),
        Column("outcome", "Результат", "state", path="outcome_code", labels=dict(OUTCOMES)),
        Column("change", "Изменение", path="change_text"),
    ),
    views=(
        View("table", "events", "События"),
        View("table", "persistence-changes", "Службы и задачи", source="persistence_changes",
             note="История служб и задач на DC из 4697, 7045 и 4698–4702. Фильтры: домен, период, DC, задача/служба, файл/action, инициатор, изменение и порог редкости. Значения и частота относятся только к наблюдениям в окне; связь событий не доказывает закрепление или исполнение.",
             columns=(
                 Column("dc", "DC"),
                 Column("object", "Объект"),
                 Column("object_type", "Тип объекта", "state", labels={"service": "Служба", "task": "Задача"}),
                 Column("change", "Изменение", "state", labels={
                     "installed": "Наблюдение установки", "created": "Создание", "updated": "Обновление",
                     "deleted": "Удаление", "enabled": "Включение", "disabled": "Отключение",
                 }),
                 Column("action", "Файл / action"),
                 Column("run_as", "RunAs"),
                 Column("service_start_type", "Тип запуска службы", optional=True),
                 Column("initiator", "Инициатор (SID / наблюдаемое имя)"),
                 Column("initiator_quality", "Качество инициатора", "state", labels={
                     "exact_sid": "SID наблюдался", "partially_known": "Часть связанных наблюдений без SID",
                     "unknown_sid": "SID неизвестен: имя не доказывает идентичность",
                 }),
                 Column("observed_at", "Время наблюдения", "datetime"),
                 Column("first_seen", "Первое наблюдение объекта", "datetime"),
                 Column("last_seen", "Последнее наблюдение объекта", "datetime"),
                 Column("frequency", "Частота наблюдений объекта", "number"),
                 Column("previous_value", "Предыдущее наблюдаемое значение"),
                 Column("previous_run_as", "Предыдущий наблюдаемый RunAs", path="previous.run_as", optional=False),
                 Column("previous_start_type", "Предыдущий тип запуска", path="previous.service_start_type", optional=True),
                 Column("event_db_id", "Событие", "code", link="/app/events/{event_db_id}"),
                 Column("linked_event", "Точно совпавшее наблюдение", "code", link="/app/events/{linked_event}", optional=False),
                 Column("evidence", "Evidence: события наблюдений", "list"),
                 Column("quality", "Качество истории", "state", labels={
                     "exact_object": "Точный объект; покрытие не подтверждено",
                     "exact_link": "Точно совпавшая пара наблюдений; не доказательство одной установки",
                     "unknown_object": "Объект неизвестен: отдельное наблюдение",
                     "missing_semantics": "Текущая семантика отсутствует: отдельное наблюдение",
                     "ambiguous_order": "Одинаковое время: порядок неизвестен", "partial": "Частичный срез",
                 }),
             )),
        View("table", "account-revocation", "Активность после отключения", source="account_revocation",
             note="Кандидаты после 4725/4726: новая аутентификация и продолжение старой VPN-сессии показаны отдельно. Фильтры: домен, период отключения, аккаунт, источник DC/NPS, тип активности, минимальная задержка, окно и точность идентичности. Повторное включение 4722 учитывается как наблюдение, а не восстановленное состояние.",
             columns=(
                 Column("account", "Учётная запись"),
                 Column("sid", "SID", "code", optional=True),
                 Column("qualification", "Квалификация", "state", labels={"candidate": "Кандидат", "insufficient": "Недостаточно данных: отдельное наблюдение"}),
                 Column("disable_code", "Код отключения/удаления", "number"),
                 Column("disable_event", "Событие отключения", "code", link="/app/events/{disable_event}"),
                 Column("disabled_at", "Время отключения", "datetime"),
                 Column("activity_at", "Последующая активность", "datetime"),
                 Column("activity_type", "Тип активности", "state", labels={
                     "logon": "Новая аутентификация 4624", "nps_allow": "Разрешение NPS 6272",
                     "vpn_continuation": "Продолжение старой VPN-сессии", "insufficient": "Недостаточно данных",
                 }),
                 Column("delay_seconds", "Задержка, с", "number"),
                 Column("source", "Источник DC/NPS/Accounting"),
                 Column("logon_type", "Тип входа"),
                 Column("reenabled_at", "Наблюдаемое включение 4722", "datetime"),
                 Column("reenable_relation", "Включение относительно активности", "state", labels={
                     "not_observed": "Не наблюдалось в окне", "before_activity": "До активности",
                     "same_time": "В то же время: порядок неизвестен", "after_activity": "После активности",
                 }),
                 Column("reenable_event", "Событие включения", "code", link="/app/events/{reenable_event}", optional=False),
                 Column("activity_event", "Событие активности", "code", link="/app/events/{activity_event}", optional=False),
                 Column("evidence", "Доказательства: ссылки на события / сессия", "list"),
                 Column("quality", "Качество идентичности", "state", labels={
                     "exact_sid": "Точный SID и домен; покрытие не подтверждено", "unknown_sid": "SID неизвестен: без сопоставления",
                     "partial": "Частичный срез или текущая семантика отсутствует",
                 }),
                 Column("clock_quality", "Качество временного порядка", "state", labels={
                     "uncertain": "До 60 с: возможна погрешность часов", "unverified": "Синхронизация часов не подтверждена",
                 }, optional=True),
                 Column("session_id", "Сессия Accounting", "code", optional=True),
                 Column("session_started_at", "Начало старой сессии", "datetime", optional=False),
                 Column("session_completeness", "Полнота сессии Accounting", "state", optional=False, labels={
                     "complete": "Наблюдались начало и конец", "missing_start": "Начало не наблюдалось",
                     "missing_stop": "Конец не наблюдался", "middle_only": "Только промежуточные наблюдения",
                 }),
             )),
        View("chart", "daily", "Динамика по дням", source="daily", chart="timeseries", x="date", stacked=True,
             series=tuple((label, key) for key, label in FAMILIES),
             note="Число событий по дням в вашем часовом поясе и категориям — за всё окно с текущими фильтрами, а не только за показанную страницу. "
                  "Рост числа событий — повод посмотреть строки, а не вывод."),
        View("custom", "chains", "Связанные последовательности", component="security.chains",
             note="Сохранённые связи между точными событиями и сессии VPN Accounting; связь не доказывает причинность."),
        View("table", "lockout-recurring", "Повторные блокировки", source="lockout_recurring",
             note="Блокировки 4740 по точному SID за выбранный период (до 31 дня). Ошибки 4625/4771/4776 — в заданном окне перед каждой блокировкой; повтор после 4767 — наблюдаемая последовательность, не доказанная причина. Фильтры вкладки: домен, период, учётная запись, caller/IP/workstation, код отказа, минимум блокировок и окно ошибок.",
             columns=(
                 Column("account", "Учётная запись"),
                 Column("sid", "SID", "code", optional=True),
                 Column("first_lockout", "Первая блокировка", "datetime"),
                 Column("last_lockout", "Последняя блокировка", "datetime"),
                 Column("lockouts", "Блокировок", "number"),
                 Column("relocks", "Повторов после unlock", "number"),
                 Column("unlocks", "Наблюдаемых разблокирований", "number", optional=False),
                 Column("callers", "Caller", "list"),
                 Column("ips", "IP", "list"),
                 Column("workstations", "Workstation", "list", optional=False),
                 Column("failure_codes", "Коды отказов", "list"),
                 Column("failures", "Предшествующих отказов", "number"),
                 Column("matched_lockouts", "Блокировок с отказами", "number", optional=True),
                 Column("last_interval_seconds", "Последний интервал между блокировками, с", "number"),
                 Column("intervals_seconds", "Интервалы между блокировками, с", "list", optional=True),
                 Column("matching", "Полнота сопоставления", "state", labels={
                     "unknown_sid": "SID неизвестен: отдельное событие",
                     "partial": "Частичный срез или текущая семантика отсутствует",
                     "all_with_failures": "Ошибки сопоставлены перед каждой блокировкой; покрытие не подтверждено",
                     "some_with_failures": "Ошибки сопоставлены перед частью блокировок",
                     "no_failures": "Предшествующие ошибки не сопоставлены",
                 }),
                 Column("first_event", "Первое событие 4740", "code", link="/app/events/{first_event}"),
                 Column("last_event", "Последнее событие 4740", "code", link="/app/events/{last_event}"),
                 Column("unlock_event", "Последнее событие 4767", "code", link="/app/events/{unlock_event}", optional=False),
                 Column("failure_event", "Последний сопоставленный отказ", "code", link="/app/events/{failure_event}", optional=False),
                 Column("event_ids", "События среза", "list", optional=True),
             )),
    ),
    query=_query,
    home_order=15,
    home_view="daily",
    export_csv=_export,
    presets=(
        ("Блокировки учётных записей", {"category": "account_lock", "event_id": "4740"}),
        ("Изменения групп", {"category": "group_membership"}),
        ("Смена и сброс паролей", {"category": "password_operation"}),
        ("Изменения аудита", {"category": "audit_configuration"}),
        ("Неудачные действия", {"outcome": "failure"}),
    ),
    row_links=(("Карточка события", "/app/events/{event_db_id}"),),
    options=lambda access: {"domain": _domain_options(access)},
    row_key="event_db_id",
    default_limit=100,
    max_limit=500,
    intent_ref="docs/REPORTING_PRODUCT_CONTRACT.md",
)
