from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import urlencode

from server.sli.core.database import query_rows
from server.sli.events.event_details import make_event_detail_url
from server.sli.semantic.event_card_semantics import CompiledRiskSql, build_event_card, compile_catalog_risk_sql
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.storage.runtime_storage import StorageRouteConsumer, resolve_storage_route
from server.sli.storage.storage_v2_transition_controller import CutoverAuthorization
from server.sli.core.time_format import format_event_time
from server.sli.reporting.ui_labels import event_id_label, severity_label
from server.source_packs.registry import resolve_source_normalizer

_MONITOR_NORMALIZER = resolve_source_normalizer("Security")
if _MONITOR_NORMALIZER is None:
    raise RuntimeError("Security monitor requires the registered Security source normalizer")
_MONITOR_GROUP_CONTRACTS = _MONITOR_NORMALIZER.security_monitor_groups()
SECURITY_EVENT_GROUPS: dict[str, dict[str, Any]] = {
    group.key: {
        "label": group.label,
        "event_ids": list(group.event_ids),
        "severity": group.severity,
        "hint": group.hint,
        "card_hint": group.card_hint,
        "check": group.check,
    }
    for group in _MONITOR_GROUP_CONTRACTS
}
EVENT_ID_TO_GROUP = {eid: key for key, group in SECURITY_EVENT_GROUPS.items() for eid in group["event_ids"]}
DEFAULT_IMPORTANT_EVENT_IDS = sorted({
    eid
    for key, group in SECURITY_EVENT_GROUPS.items()
    if key != "all_logons"
    for eid in group["event_ids"]
})
MONITOR_EVENT_IDS = frozenset(EVENT_ID_TO_GROUP)
FALLBACK_HIGH_EVENT_IDS = frozenset(
    event_id
    for event_id, group_key in EVENT_ID_TO_GROUP.items()
    if SECURITY_EVENT_GROUPS[group_key]["severity"] == "high"
)
FALLBACK_MEDIUM_EVENT_IDS = frozenset(
    event_id
    for event_id, group_key in EVENT_ID_TO_GROUP.items()
    if SECURITY_EVENT_GROUPS[group_key]["severity"] == "medium"
)
FALLBACK_INFO_EVENT_IDS = frozenset(
    event_id
    for event_id, group_key in EVENT_ID_TO_GROUP.items()
    if SECURITY_EVENT_GROUPS[group_key]["severity"] == "info"
)
PRIVILEGED_EVENT_IDS = frozenset(_MONITOR_NORMALIZER.monitor_privileged_event_ids())
DEFAULT_NOISE_EVENT_IDS = tuple(SECURITY_EVENT_GROUPS["all_logons"]["event_ids"])
DEFAULT_NOISE_EVENT_IDS_LABEL = "/".join(str(value) for value in DEFAULT_NOISE_EVENT_IDS)
PRIVILEGED_HINTS = {"admin", "administrator", "domain admins", "enterprise admins", "schema admins", "администратор", "администраторы"}
PERIODS: dict[str, tuple[str, timedelta | None]] = {
    "": ("весь импортированный период", None),
    "24h": ("последние 24 часа", timedelta(hours=24)),
    "7d": ("последние 7 дней", timedelta(days=7)),
    "30d": ("последние 30 дней", timedelta(days=30)),
}
TIER_LABELS = {"critical": "Критическое", "important": "Важное", "technical": "Техническое"}


def _monitor_event_source() -> str:
    """Storage V2 core under the alias ``e`` (the only route, plan 6.5)."""
    return """
        (
            select core.id, core.event_id, channel.value as channel,
                   provider.value as provider_name, core.time_created_utc,
                   core.event_record_id, core.subject_user_name,
                   subject_domain.value as subject_domain_name,
                   core.target_user_name,
                   target_domain.value as target_domain_name,
                   core.ip_address, core.workstation_name,
                   computer.value as computer, core.logon_id,
                   jsonb_build_object(
                     'TaskName', facts.task_name, 'Action', facts.task_action,
                     'Author', facts.task_author, 'RunAs', facts.run_as,
                     'ProcessName', facts.process_name, 'Message', facts.message_sample
                   )::text as event_data_json,
                   facts.message_sample as message_text, core.server_id
            from events_v2_core core
            join storage_v2_channel channel on channel.id=core.channel_id
            left join event_facts_v2 facts on facts.event_id=core.id
            left join storage_v2_provider provider on provider.id=core.provider_id
            left join storage_v2_computer computer on computer.id=core.computer_id
            left join storage_v2_domain_name subject_domain on subject_domain.id=core.subject_domain_id
            left join storage_v2_domain_name target_domain on target_domain.id=core.target_domain_id
        ) e join servers s on s.id=e.server_id
    """


def get_security_events_monitor_data(
    *,
    group: str | None = None,
    event_id: str | int | None = None,
    account: str | None = None,
    source: str | None = None,
    target: str | None = None,
    server: str | None = None,
    risk: str | None = None,
    only_privileged: bool | str | None = None,
    only_service: bool | str | None = None,
    period: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    limit: int = 300,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    """Return the bounded InfoSec event monitor view.

    The row list is limited, while category totals are calculated by a separate
    aggregate query and therefore do not silently stop at the row limit.
    """
    limit = max(1, min(int(limit or 300), 2000))
    resolve_storage_route(
        authorization=authorization, consumer=StorageRouteConsumer.SECURITY_EVENTS_MONITOR
    )
    source_sql = _monitor_event_source()
    event_ids = _event_ids_for_filter(group=group, event_id=event_id)
    period_key, effective_time_from = _period_time_from(period, explicit_time_from=time_from)
    normalized_risk = _risk_filter(risk)
    privileged_only = _truthy(only_privileged)
    service_only = _truthy(only_service)

    clauses = [f"e.event_id in ({','.join('?' for _ in event_ids)})"]
    params: list[Any] = list(event_ids)
    if account:
        like = f"%{account}%"
        clauses.append("(lower(coalesce(e.subject_user_name,'')) like lower(?) or lower(coalesce(e.target_user_name,'')) like lower(?) or lower(coalesce(e.subject_domain_name,'')) like lower(?) or lower(coalesce(e.target_domain_name,'')) like lower(?) or lower(coalesce(e.event_data_json,'')) like lower(?) or lower(coalesce(e.message_text,'')) like lower(?))")
        params.extend([like, like, like, like, like, like])
    if source:
        like = f"%{source}%"
        clauses.append("(lower(coalesce(e.ip_address,'')) like lower(?) or lower(coalesce(e.workstation_name,'')) like lower(?) or lower(coalesce(e.computer,'')) like lower(?))")
        params.extend([like, like, like])
    if target:
        like = f"%{target}%"
        clauses.append("(lower(coalesce(e.target_user_name,'')) like lower(?) or lower(coalesce(e.target_domain_name,'')) like lower(?) or lower(coalesce(e.event_data_json,'')) like lower(?) or lower(coalesce(e.message_text,'')) like lower(?))")
        params.extend([like, like, like, like])
    if server:
        clauses.append("s.hostname = ?")
        params.append(server)
    if effective_time_from:
        clauses.append("e.time_created_utc >= ?")
        params.append(effective_time_from)
    if time_to:
        clauses.append("e.time_created_utc <= ?")
        params.append(time_to)
    if privileged_only:
        clauses.append(_privileged_sql())
    if service_only:
        clauses.append(_service_sql())
    if normalized_risk:
        risk_sql, risk_params = _risk_sql(normalized_risk)
        clauses.append(risk_sql)
        params.extend(risk_params)

    where = " and ".join(clauses)
    rows = query_rows(
        f"""
        select e.id as event_db_id, e.event_id, e.channel, e.provider_name, e.time_created_utc, e.event_record_id,
               e.subject_user_name, e.subject_domain_name, e.target_user_name, e.target_domain_name,
               e.ip_address, e.workstation_name, e.computer, e.logon_id, e.event_data_json, e.message_text,
               s.hostname as server
        from {source_sql}
        where {where}
        order by e.time_created_utc desc, e.event_record_id desc, e.id desc
        limit ?
        """,
        tuple(params + [limit]),
    )
    summary_rows = query_rows(
        f"""
        select e.event_id, count(*) as count
        from {source_sql}
        where {where}
        group by e.event_id
        order by count(*) desc, e.event_id asc
        """,
        tuple(params),
    )
    category_counts = _aggregate_category_counts(
        where=where, params=params, source_sql=source_sql,
    )
    matched_total = int(category_counts.get("important_total") or 0)
    items = [_decorate(row) for row in rows]
    compiled_risk = _compiled_monitor_risk_sql()
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "items": items,
        "summary": summary_rows,
        "category_counts": category_counts,
        "matched_total": matched_total,
        "returned_count": len(items),
        "truncated": matched_total > len(items),
        "groups": SECURITY_EVENT_GROUPS,
        "filters": {
            "group": group,
            "event_id": event_id,
            "account": account,
            "source": source,
            "target": target,
            "server": server,
            "risk": normalized_risk,
            "only_privileged": privileged_only,
            "only_service": service_only,
            "period": period_key,
            "period_label": PERIODS.get(period_key, PERIODS[""])[0],
            "time_from": effective_time_from,
            "time_to": time_to,
            "limit": limit,
        },
        "data_quality": {
            "aggregate_counts_exact": compiled_risk.exact,
            "row_limit_applies_only_to_items": True,
            "semantic_projection": "catalog_event_card_v1",
            "semantic_filter_mode": "catalog_compiled_exact" if compiled_risk.exact else "catalog_compiled_with_fallback",
            "semantic_filter_exact": compiled_risk.exact,
            "semantic_filter_limitations": list(compiled_risk.limitations),
            "default_noise_event_ids_excluded": list(DEFAULT_NOISE_EVENT_IDS) if not group and not event_id else [],
            "evidence_link_mode": "exact_event_db_id",
        },
        "quick_links": _quick_links(),
        "what_to_check": _what_to_check(category_counts),
    }


def get_security_events_24h_summary(
    *,
    authorization: object | None = None,
) -> dict[str, int]:
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    data = get_security_events_monitor_data(
        time_from=since, limit=1,
        authorization=authorization,
    )
    counts = data.get("category_counts") or {}
    keys = [*SECURITY_EVENT_GROUPS.keys(), "important_total", "high", "medium", "privileged", "service"]
    return {key: int(counts.get(key) or 0) for key in keys}


def render_security_events_monitor_report(data: dict[str, Any]) -> str:
    filters = data.get("filters") or {}
    tabs = _tabs_html(filters)
    rows = "".join(_row(item) for item in data.get("items") or []) or _empty_rows_html(filters)
    summary_rows = "".join(f'<tr><td>{html.escape(event_id_label(row["event_id"]))}</td><td>{row["count"]}</td></tr>' for row in data.get("summary") or []) or '<tr><td colspan="2">Нет данных</td></tr>'
    category_cards = _category_cards(data.get("category_counts") or {})
    what_next = "".join(f"<li>{html.escape(item)}</li>" for item in data.get("what_to_check") or []) or "<li>По выбранному срезу нет явных действий.</li>"
    csv_url = "/reports/security-events-monitor.csv?" + urlencode(_clean_query_params(filters))
    html_url = "/reports/security-events-monitor.html?" + urlencode(_clean_query_params(filters))
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>ИБ-мониторинг событий</title>{report_style(extra_css=".tabrow{display:flex;gap:8px;flex-wrap:wrap}.tabrow a{border:1px solid var(--line);border-radius:999px;padding:8px 11px;background:var(--panel);color:var(--text);font-weight:700}.tabrow a.active{background:color-mix(in srgb,var(--blue) 12%,var(--panel));border-color:var(--blue)}.wide-form input{min-width:180px}.export-row{justify-content:flex-end}")}</head>
<body>{report_controls()}<main class="wrap">
<header class="hero"><div class="eyebrow">ИБ-мониторинг</div><h1>Ключевые события безопасности</h1><p class="subtitle">По умолчанию показаны важные события: пароли, блокировки, группы, привилегии, ошибки входа, Kerberos/NTLM и явные учетные данные. Массовые {DEFAULT_NOISE_EVENT_IDS_LABEL} доступны только через вкладку “Все входы/выходы”.</p><div class="pillrow"><span class="pill">Сформирован: {html.escape(format_event_time(data.get('generated_at_utc')))}</span><span class="pill">Показано: {len(data.get('items') or [])} из {int(data.get('matched_total') or 0)}</span><span class="pill">Период: {html.escape(str(filters.get('period_label') or '—'))}</span><span class="pill">Режим: {html.escape(_mode_label(filters))}</span></div></header>
<section><h2>Вкладки ИБ</h2><div class="tabrow">{tabs}</div><p class="muted">Из каждой строки можно открыть подробности события или перейти к его расследованию.</p></section>
<section><h2>Фильтры</h2><form class="search-form wide-form" method="get" action="/reports/security-events-monitor.html"><input type="hidden" name="group" value="{html.escape(str(filters.get('group') or ''))}"><select name="period"><option value="" {"selected" if not filters.get('period') else ""}>Весь период</option><option value="24h" {"selected" if filters.get('period')=='24h' else ""}>24 часа</option><option value="7d" {"selected" if filters.get('period')=='7d' else ""}>7 дней</option><option value="30d" {"selected" if filters.get('period')=='30d' else ""}>30 дней</option></select><input name="account" placeholder="учетная запись" value="{html.escape(str(filters.get('account') or ''))}"><input name="target" placeholder="цель" value="{html.escape(str(filters.get('target') or ''))}"><input name="source" placeholder="IP / host" value="{html.escape(str(filters.get('source') or ''))}"><input name="server" placeholder="DC" value="{html.escape(str(filters.get('server') or ''))}"><input name="event_id" placeholder="Event ID" value="{html.escape(str(filters.get('event_id') or ''))}"><select name="risk"><option value="">Любой риск</option><option value="high" {"selected" if filters.get('risk')=='high' else ""}>Высокий</option><option value="medium" {"selected" if filters.get('risk')=='medium' else ""}>Средний</option><option value="info" {"selected" if filters.get('risk')=='info' else ""}>Инфо</option></select><label class="pill"><input type="checkbox" name="only_privileged" value="1" {"checked" if filters.get('only_privileged') else ""}> привилегированные</label><label class="pill"><input type="checkbox" name="only_service" value="1" {"checked" if filters.get('only_service') else ""}> служебные учётные записи</label><input name="limit" value="{html.escape(str(filters.get('limit') or 300))}"><button>Показать</button></form><div class="toolbar export-row"><a class="button" href="{html.escape(html_url)}">HTML</a><a class="button" href="{html.escape(csv_url)}">CSV</a></div></section>
<section><h2>Сводка по выбранному срезу</h2><div class="grid three">{category_cards}</div><div class="callout mt"><h3>Что проверить дальше</h3><ul>{what_next}</ul></div></section>
<section><h2>Event ID</h2><table><thead><tr><th>Событие</th><th>Количество</th></tr></thead><tbody>{summary_rows}</tbody></table></section>
<section><h2>События</h2><table><thead><tr><th>Время</th><th>Вкладка</th><th>Событие</th><th>Учетная запись</th><th>Инициатор</th><th>Цель</th><th>Источник</th><th>DC</th><th>Риск</th><th>Подробности</th><th>Расследование</th></tr></thead><tbody>{rows}</tbody></table></section>
</main></body></html>'''


def render_security_events_monitor_csv(data: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([
        "record_type", "time", "group", "event_id", "event_label", "account",
        "actor", "target", "source", "server", "risk", "event_record_id",
        "matched_total", "returned_count", "truncated", "filters_json",
    ])
    writer.writerow([
        "metadata", data.get("generated_at_utc") or "", "", "", "", "", "",
        "", "", "", "", "", int(data.get("matched_total") or 0),
        int(data.get("returned_count") or 0),
        str(bool(data.get("truncated"))).lower(),
        json.dumps(data.get("filters") or {}, ensure_ascii=False, sort_keys=True),
    ])
    for item in data.get("items") or []:
        writer.writerow([
            "event",
            format_event_time(item.get("time_created_utc")),
            item.get("group_label") or "",
            item.get("event_id") or "",
            event_id_label(item.get("event_id")),
            item.get("account") or "",
            item.get("actor") or "",
            item.get("target_principal") or "",
            item.get("source") or "",
            item.get("server") or "",
            item.get("severity") or "",
            item.get("event_record_id") or "",
            "", "", "", "",
        ])
    return buffer.getvalue()


def _event_ids_for_filter(*, group: str | None, event_id: str | int | None) -> list[int]:
    if event_id:
        values: list[int] = []
        for part in str(event_id).replace(";", ",").split(","):
            try:
                values.append(int(part.strip()))
            except (TypeError, ValueError):
                continue
        if values:
            return values
    if group and group in SECURITY_EVENT_GROUPS:
        return list(SECURITY_EVENT_GROUPS[group]["event_ids"])
    return list(DEFAULT_IMPORTANT_EVENT_IDS)


def _decorate(row: dict[str, Any]) -> dict[str, Any]:
    eid = int(row.get("event_id") or 0)
    group_key = EVENT_ID_TO_GROUP.get(eid, "other")
    group = SECURITY_EVENT_GROUPS.get(group_key, {"label": "Прочее", "severity": "info"})
    subject = _principal(row.get("subject_domain_name"), row.get("subject_user_name"))
    target = _principal(row.get("target_domain_name"), row.get("target_user_name"))
    account = target or subject or "—"
    source = row.get("ip_address") or row.get("workstation_name") or row.get("computer") or "—"
    try:
        event_data = json.loads(str(row.get("event_data_json") or "{}"))
    except json.JSONDecodeError:
        event_data = {}
    semantic = build_event_card({**row, "event_data": event_data})
    fallback = _severity_for_event(eid, group["severity"], account=account, actor=subject, target=target)
    event_db_id = int(row.get("event_db_id") or row.get("id") or 0)
    return {
        "event_db_id": event_db_id,
        "event_id": eid,
        "event_record_id": row.get("event_record_id"),
        "time_created_utc": row.get("time_created_utc"),
        "server": row.get("server"),
        "channel": row.get("channel"),
        "provider_name": row.get("provider_name"),
        "group": group_key,
        "group_label": group["label"],
        "severity": str(semantic.get("final_risk") if semantic.get("known") else fallback),
        "tier": str(semantic.get("purpose_tier") if semantic.get("known") else _tier_for_severity(fallback)),
        "assessment_confidence": str(semantic.get("assessment_confidence") or "unknown"),
        "assessment_confidence_label": str(
            semantic.get("assessment_confidence_label")
            or semantic.get("display_labels", {}).get("confidence")
            or "Не определено"
        ),
        "privileged_candidate": _looks_privileged(account) or _looks_privileged(subject) or eid in PRIVILEGED_EVENT_IDS,
        "service_candidate": _looks_service(account) or _looks_service(subject),
        "evidence_url": make_event_detail_url(event_db_id=event_db_id, limit=1),
        "investigation_url": "/reports/investigation.html?" + urlencode({"event_db_id": event_db_id, "scope": "important"}),
    }


def _row(item: dict[str, Any]) -> str:
    evidence_url = str(item.get("evidence_url") or "/reports/event-details.html")
    investigation_url = str(item.get("investigation_url") or "/reports/investigation.html")
    flags = []
    if item.get("privileged_candidate"):
        flags.append("privileged")
    if item.get("service_candidate"):
        flags.append("service")
    flag_html = "".join(f'<span class="badge warn">{html.escape(flag)}</span>' for flag in flags)
    tier = TIER_LABELS.get(str(item.get("tier") or ""), "Не определено")
    hidden = "Доступно в деталях"
    return f'<tr><td class="mono" title="{html.escape(str(item.get("time_created_utc") or ""))}">{html.escape(format_event_time(item.get("time_created_utc")))}</td><td>{html.escape(str(item.get("group_label")))}</td><td>{html.escape(event_id_label(item.get("event_id")))}</td><td>{hidden} {flag_html}</td><td>{hidden}</td><td>{hidden}</td><td>{hidden}</td><td>{html.escape(str(item.get("server")))}</td><td>{severity_label(item.get("severity"))}<div class="muted small-text">{html.escape(tier)}</div></td><td><a class="button" href="{html.escape(evidence_url)}">Открыть</a></td><td><a class="button" href="{html.escape(investigation_url)}">Цепочка</a></td></tr>'


def _empty_rows_html(filters: dict[str, Any]) -> str:
    group_key = str(filters.get("group") or "")
    group = SECURITY_EVENT_GROUPS.get(group_key, {})
    label = str(group.get("label") or "важных")
    period = str(filters.get("period") or "")
    base = _clean_query_params(filters)
    base.pop("group", None)
    base.pop("event_id", None)
    important_url = "/reports/security-events-monitor.html?" + urlencode(base)
    logons_url = "/reports/security-events-monitor.html?" + urlencode({**base, "group": "all_logons"})
    message = (
        f"В выбранном периоде не найдено событий категории «{label}». "
        "Это не означает, что сбор не работает: такой тип события просто не встретился в выбранном срезе."
    )
    return (
        '<tr><td colspan="11"><div class="callout">'
        f'<strong>{html.escape(message)}</strong> '
        f'<a class="button" href="{html.escape(important_url)}">Показать важные события</a> '
        f'<a class="button" href="{html.escape(logons_url)}">Показать входы и выходы</a>'
        "</div></td></tr>"
    )


def _principal(domain: Any, user: Any) -> str | None:
    u = str(user or "").strip()
    d = str(domain or "").strip()
    if not u:
        return None
    return f"{d}\\{u}" if d else u


def _mode_label(filters: dict[str, Any]) -> str:
    if filters.get("event_id"):
        return f"Event ID {filters.get('event_id')}"
    group = filters.get("group")
    if group and group in SECURITY_EVENT_GROUPS:
        return str(SECURITY_EVENT_GROUPS[group]["label"])
    return "только важные"


def _period_time_from(period: str | None, *, explicit_time_from: str | None) -> tuple[str, str | None]:
    if explicit_time_from:
        return (period or "", explicit_time_from)
    clean = str(period or "").strip().lower()
    if clean not in PERIODS:
        clean = ""
    delta = PERIODS[clean][1]
    if not delta:
        return clean, None
    return clean, (datetime.now(timezone.utc) - delta).isoformat()


def _truthy(value: bool | str | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "да"}


def _risk_filter(value: str | None) -> str | None:
    clean = str(value or "").strip().lower()
    return clean if clean in {"high", "medium", "info", "low"} else None


def _looks_privileged(value: Any) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return False
    name = raw.rsplit("\\", 1)[-1]
    return any(hint in raw for hint in PRIVILEGED_HINTS) or name.startswith(("adm_", "adm-")) or name in {"adm", "administrator"}


def _looks_service(value: Any) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return False
    name = raw.rsplit("\\", 1)[-1]
    return name.endswith("$") or name.startswith(("svc_", "svc-", "sa_")) or "service" in name or "служб" in name


def _severity_for_event(event_id: int, default: str, *, account: Any, actor: Any, target: Any) -> str:
    # A Windows Event ID or an account name is evidence, not a risk verdict.
    # Catalogue-owned events carry their declared contextual risk; unknown events
    # retain the caller's conservative fallback. Context-only observations must
    # never become high merely because they were observed.
    return default


def _tier_for_severity(severity: str) -> str:
    value = str(severity).lower()
    if value in {"critical", "high"}:
        return "critical"
    if value in {"medium", "important"}:
        return "important"
    return "technical"


def _principal_sql() -> str:
    return "lower(coalesce(e.subject_domain_name,'') || '\\' || coalesce(e.subject_user_name,'') || ' ' || coalesce(e.target_domain_name,'') || '\\' || coalesce(e.target_user_name,''))"


def _privileged_sql() -> str:
    principal = _principal_sql()
    hints = ["admin", "administrator", "domain admins", "enterprise admins", "schema admins", "администратор"]
    checks = [f"{principal} like '%{hint}%'" for hint in hints]
    checks.append(f"e.event_id in ({','.join(str(value) for value in sorted(PRIVILEGED_EVENT_IDS))})")
    return "(" + " or ".join(checks) + ")"


def _service_sql() -> str:
    subject = "lower(coalesce(e.subject_user_name,''))"
    target = "lower(coalesce(e.target_user_name,''))"
    checks = []
    for field in (subject, target):
        checks.extend([
            f"{field} like '%$'",
            f"substr({field}, 1, 4) = 'svc_'",
            f"substr({field}, 1, 4) = 'svc-'",
            f"substr({field}, 1, 3) = 'sa_'",
            f"{field} like '%service%'",
            f"{field} like '%служб%'",
        ])
    return "(" + " or ".join(checks) + ")"


def _risk_sql(risk: str) -> tuple[str, list[Any]]:
    normalized = str(risk or "").strip().lower()
    if normalized not in {"high", "medium", "info", "low"}:
        return "1 = 0", []
    compiled = _compiled_monitor_risk_sql()
    fallback = _fallback_risk_case_sql()
    final_risk = f"case when {compiled.matched_sql} then {compiled.case_sql} else {fallback} end"
    return f"(({final_risk}) = ?)", [*compiled.matched_params, *compiled.case_params, normalized]


@lru_cache(maxsize=1)
def _compiled_monitor_risk_sql() -> CompiledRiskSql:
    return compile_catalog_risk_sql(tuple(sorted(MONITOR_EVENT_IDS)))


def _fallback_risk_case_sql() -> str:
    high_ids = ",".join(str(value) for value in sorted(FALLBACK_HIGH_EVENT_IDS))
    medium_ids = ",".join(str(value) for value in sorted(FALLBACK_MEDIUM_EVENT_IDS))
    info_ids = ",".join(str(value) for value in sorted(FALLBACK_INFO_EVENT_IDS))
    return (
        "case "
        f"when e.event_id in ({high_ids}) then 'high' "
        f"when e.event_id in ({medium_ids}) then 'medium' "
        f"when e.event_id in ({info_ids}) then 'info' "
        "else 'info' end"
    )


def _aggregate_category_counts(
    *,
    where: str,
    params: list[Any],
    source_sql: str,
) -> dict[str, int]:
    expressions = []
    expression_params: list[Any] = []
    for key, group in SECURITY_EVENT_GROUPS.items():
        ids = sorted(set(int(value) for value in group["event_ids"]))
        expressions.append(f'sum(case when e.event_id in ({",".join(str(value) for value in ids)}) then 1 else 0 end) as "{key}"')
    high_sql, high_params = _risk_sql("high")
    medium_sql, medium_params = _risk_sql("medium")
    expression_params.extend(high_params)
    expression_params.extend(medium_params)
    expressions.extend([
        'count(*) as "important_total"',
        f'sum(case when {high_sql} then 1 else 0 end) as "high"',
        f'sum(case when {medium_sql} then 1 else 0 end) as "medium"',
        f'sum(case when {_privileged_sql()} then 1 else 0 end) as "privileged"',
        f'sum(case when {_service_sql()} then 1 else 0 end) as "service"',
    ])
    rows = query_rows(
        f"select {', '.join(expressions)} from {source_sql} where {where}",
        tuple(expression_params + params),
    )
    row = rows[0] if rows else {}
    keys = [*SECURITY_EVENT_GROUPS.keys(), "important_total", "high", "medium", "privileged", "service"]
    return {key: int(row.get(key) or 0) for key in keys}


def _category_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {key: 0 for key in SECURITY_EVENT_GROUPS}
    counts["important_total"] = len(items)
    counts["high"] = 0
    counts["medium"] = 0
    counts["privileged"] = 0
    counts["service"] = 0
    for item in items:
        key = str(item.get("group") or "")
        if key in counts:
            counts[key] += 1
        if item.get("severity") in {"high", "medium"}:
            counts[str(item.get("severity"))] += 1
        if item.get("privileged_candidate"):
            counts["privileged"] += 1
        if item.get("service_candidate"):
            counts["service"] += 1
    return counts


def _category_cards(counts: dict[str, int]) -> str:
    cards = [
        (
            "Всего важных",
            counts.get("important_total", 0),
            f"без {DEFAULT_NOISE_EVENT_IDS_LABEL} по умолчанию",
        ),
        *[
            (
                str(SECURITY_EVENT_GROUPS[key]["label"]),
                counts.get(key, 0),
                str(SECURITY_EVENT_GROUPS[key].get("card_hint") or SECURITY_EVENT_GROUPS[key]["hint"]),
            )
            for key in ("failed_logons", "passwords", "lockouts", "groups", "privileges")
        ],
    ]
    return "".join(f'<div class="card"><div class="muted">{html.escape(name)}</div><h3>{int(value or 0)}</h3><p class="muted">{html.escape(hint)}</p></div>' for name, value, hint in cards)


def _what_to_check(counts: dict[str, int]) -> list[str]:
    actions: list[str] = []
    for key in ("groups", "privileges", "passwords", "lockouts", "failed_logons"):
        check = str(SECURITY_EVENT_GROUPS[key].get("check") or "")
        if counts.get(key) and check:
            actions.append(check)
    if counts.get("service"):
        actions.append("Отдельно проверить service-account: интерактивный вход сервисной учеткой может быть высоким риском.")
    if not actions:
        actions.append("Открыть вкладки ИБ или расширить период, если за выбранный срез важных событий нет.")
    return actions[:6]


def _tabs_html(filters: dict[str, Any]) -> str:
    base = {k: v for k, v in _clean_query_params(filters).items() if k != "group"}
    tabs = [('', 'Только важные')]
    tabs.extend((key, str(group["label"])) for key, group in SECURITY_EVENT_GROUPS.items())
    links = []
    active = str(filters.get("group") or "")
    for key, label in tabs:
        params = {**base}
        if key:
            params["group"] = key
        href = "/reports/security-events-monitor.html?" + urlencode(params)
        cls = "active" if active == key else ""
        links.append(f'<a class="{cls}" href="{html.escape(href)}">{html.escape(label)}</a>')
    return "".join(links)


def _quick_links() -> list[dict[str, str]]:
    return [
        {"label": "Важные за 24 часа", "url": "/reports/security-events-monitor.html?period=24h"},
        {"label": "Ошибки входа", "url": "/reports/security-events-monitor.html?group=failed_logons&period=24h"},
        {"label": "Группы", "url": "/reports/security-events-monitor.html?group=groups&period=7d"},
        {"label": "Сервисные учётные записи", "url": "/reports/security-events-monitor.html?only_service=1&period=24h"},
        {"label": "Все входы/выходы", "url": "/reports/security-events-monitor.html?group=all_logons&period=24h"},
    ]


def _clean_query_params(filters: dict[str, Any]) -> dict[str, str]:
    allowed = ["group", "event_id", "account", "source", "target", "server", "risk", "period", "time_from", "time_to", "limit"]
    params = {key: str(filters.get(key)) for key in allowed if filters.get(key) not in (None, "", False)}
    if filters.get("only_privileged"):
        params["only_privileged"] = "1"
    if filters.get("only_service"):
        params["only_service"] = "1"
    # A rolling period must stay rolling when the person changes a tab, exports
    # or follows an internal link.  ``time_from`` was an implementation detail
    # of the current render and previously froze a page at an old timestamp.
    if params.get("period") in {"24h", "7d", "30d"}:
        params.pop("time_from", None)
        params.pop("time_to", None)
    return params
