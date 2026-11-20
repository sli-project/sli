from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from server.sli.sources.collector_health import get_collector_health, render_collector_health_report
from server.sli.core.database import is_postgres_runtime_db, query_rows
from server.sli.ops.logging_config import log_event
from server.sli.core.paths import REPORTS_DIR
from server.sli.reporting.report_template import render_target_report
from server.sli.storage.runtime_storage import StorageRouteConsumer, resolve_storage_route
from server.sli.storage.storage_v2_transition_controller import CutoverAuthorization
from server.source_packs.registry import resolve_source_normalizer
from server.sli.reports.analysis_render import (  # noqa: F401
    _correlation_table,
    _criticality_table,
    _event_detail_url,
    _event_table_rows,
    _gap_table,
    _links_table,
    _recommendations_table,
    _safe_name,
    _server_links,
    _style,
    _table,
)
from server.sli.reports.analysis_rules import (  # noqa: F401
    _assumptions,
    _channel_hint,
    _confidence_for_risk,
    _display_risk,
    _duration_hint,
    _main_conclusion,
    _main_limitation,
    _missing_fields_for_event,
    _parse_iso,
    _period_text,
    _risk_class,
    _short_list,
    _source_facts,
    _threat_note,
    _threat_score,
    _top_noise_text,
    _why_event_matters,
)
from server.sli.reports.analysis_findings import (  # noqa: F401
    _event_criticality,
    _expand_time_window,
    _extract_fact_time_range,
    _finding,
    _finding_evidence_refs,
    _format_utc,
    _kpis,
    _normalize_report_time,
    _priority_actions,
    _recommendation_evidence_refs,
)


_ANALYSIS_SOURCE_NORMALIZER = resolve_source_normalizer("Security")
if _ANALYSIS_SOURCE_NORMALIZER is None:
    raise RuntimeError("Security source pack normalizer is required")


def _analysis_event_ids(family: str) -> tuple[int, ...]:
    return _ANALYSIS_SOURCE_NORMALIZER.event_ids_for_analysis_family(family)


def _analysis_event_id(family: str) -> int:
    values = _analysis_event_ids(family)
    if len(values) != 1:
        raise RuntimeError(f"analysis family {family!r} must contain exactly one Event ID")
    return values[0]


def _analysis_event_id_sql(family: str) -> str:
    values = _analysis_event_ids(family)
    if not values:
        raise RuntimeError(f"analysis family {family!r} must not be empty")
    return ",".join(str(value) for value in values)


def generate_recommendation_report(
    job_id: int,
    servers: list[str],
    *,
    authorization: CutoverAuthorization | None = None,
    report_writer: Callable[[Path, str], None] | None = None,
) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    log_event("reports", "report_generation_started", "Recommendation report generation started.", job_id=job_id)
    report_path = REPORTS_DIR / "domain-security-overview.html"

    server_reports = []
    for server in servers:
        summary = _collect_summary([server], authorization=authorization)
        recommendations = _build_recommendations(summary)
        server_reports.append(
            _write_server_profile_report(
                server,
                summary,
                recommendations,
                authorization=authorization,
                report_writer=report_writer,
            )
        )

    summary = _collect_summary(servers, authorization=authorization)
    recommendations = _build_recommendations(summary)

    correlations = _correlate_events(servers, summary, authorization=authorization)
    logging_gap = _logging_gap_rows(summary)
    context = _build_report_context(
        title="Локальный аналитический отчёт: обзор контроллеров домена",
        scope_name=", ".join(servers),
        servers=servers,
        summary=summary,
        recommendations=recommendations,
        correlations=correlations,
        logging_gap=logging_gap,
        criticality=_criticality_rows_for_servers(servers, authorization=authorization),
        first_last=_time_bounds_for_servers(servers, authorization=authorization),
        server_reports=server_reports,
        job_id=job_id,
    )
    _write_report_content(report_path, render_target_report(context), report_writer)
    if report_writer is None:
        _write_collector_health_static_report()
    else:
        _write_collector_health_static_report(report_writer=report_writer)
    log_event("reports", "report_generation_completed", "Recommendation report generated.", job_id=job_id, path=str(report_path))
    if len(server_reports) == 1:
        return server_reports[0]
    return report_path


def _write_report_content(
    path: Path, content: str, writer: Callable[[Path, str], None] | None,
) -> None:
    if writer is None:
        path.write_text(content, encoding="utf-8")
    else:
        writer(path, content)


def _write_collector_health_static_report(
    *, report_writer: Callable[[Path, str], None] | None = None,
) -> Path:
    report_path = REPORTS_DIR / "collector-health.html"
    data = get_collector_health()
    _write_report_content(report_path, render_collector_health_report(data), report_writer)
    log_event("reports", "collector_health_report_generated", "Collector health report generated.", path=str(report_path))
    return report_path


def _write_server_profile_report(
    server: str,
    summary: dict,
    recommendations: list[dict],
    *,
    authorization: CutoverAuthorization | None = None,
    report_writer: Callable[[Path, str], None] | None = None,
) -> Path:
    report_path = REPORTS_DIR / f"server-{_safe_name(server)}-security-profile.html"
    criticality = _criticality_rows(server, authorization=authorization)
    first_last = _server_time_bounds(server, authorization=authorization)
    logging_gap = _logging_gap_rows(summary)
    correlations = _correlate_events([server], summary, authorization=authorization)
    context = _build_report_context(
        title=f"Локальный аналитический отчёт: контроллер домена {server}",
        scope_name=server,
        servers=[server],
        summary=summary,
        recommendations=recommendations,
        correlations=correlations,
        logging_gap=logging_gap,
        criticality=criticality,
        first_last=first_last,
    )
    _write_report_content(report_path, render_target_report(context), report_writer)
    log_event("reports", "server_profile_generated", "Server profile report generated.", server=server, path=str(report_path))
    return report_path


def _build_report_context(
    *,
    title: str,
    scope_name: str,
    servers: list[str],
    summary: dict,
    recommendations: list[dict],
    correlations: list[dict],
    logging_gap: list[dict],
    criticality: list[dict],
    first_last: dict,
    server_reports: list[Path] | None = None,
    job_id: int | None = None,
) -> dict:
    total_events = int(summary.get("total_events") or 0)
    missing_controls = sum(1 for row in logging_gap if row["status"] != "Собирается")
    top_event = summary["top_event_ids"][0] if summary["top_event_ids"] else None
    top_noise = _top_noise_text(summary)
    coverage_status = "полное" if missing_controls == 0 else f"неполное: {missing_controls} не видно"
    coverage_class = "ok" if missing_controls == 0 else "danger"
    threat_score = _threat_score(summary, correlations, criticality)
    period_text = _period_text(first_last)
    channel_rows = [{"channel": row["channel"], "count": row["count"]} for row in summary["by_channel"]]

    return {
        "title": title,
        "subtitle": (
            "Цель отчета - быстро ответить, что требует внимания, почему это важно, "
            "какие факты есть, каких данных не хватает и какие действия выполнить в первую очередь."
        ),
        "scope_name": scope_name,
        "servers": servers,
        "period_text": period_text,
        "total_events": total_events,
        "main_noise": top_noise,
        "main_noise_class": "warn" if top_event else "",
        "coverage_status": coverage_status,
        "coverage_class": coverage_class,
        "analysis_mode": "local_rules",
        "risk_score": threat_score,
        "risk_note": _threat_note(threat_score, total_events),
        "kpis": _kpis(summary, logging_gap, criticality, first_last),
        "main_conclusion": _main_conclusion(total_events, recommendations, correlations, top_noise),
        "main_limitation": _main_limitation(total_events, missing_controls),
        "channel_rows": channel_rows,
        "actions": _priority_actions(recommendations, correlations, logging_gap),
        "findings": _finding_cards_data(recommendations, correlations, servers),
        "coverage_rows": logging_gap,
        "correlation_rows": correlations,
        "event_rows": _event_table_rows(criticality, servers),
        "source_facts": _source_facts(summary, first_last, job_id),
        "assumptions": _assumptions(),
        "server_links": _server_links(server_reports or []),
    }


def _finding_cards_data(recommendations: list[dict], correlations: list[dict], servers: list[str]) -> list[dict]:
    findings = []
    for item in correlations:
        related = item.get("related_event_ids") or []
        related_text = f" Связанные Event ID: {', '.join(str(value) for value in related)}." if related else ""
        findings.append(
            {
                "title": item["scenario"],
                "severity": "unknown",
                "provenance": {"source": "deterministic_hint", "authority": "draft_only"},
                "facts": item["facts"],
                "why_it_matters": item["meaning"],
                "recommended_action": item["recommendation"],
                "confidence": "not_applicable",
                "missing_data": item.get("missing_data", _missing_for_scenario(item["scenario"])) + related_text,
                "evidence_refs": _finding_evidence_refs(item, servers),
            }
        )
    for item in recommendations:
        findings.append(
            {
                "title": item["title"],
                "severity": "unknown",
                "provenance": {"source": "deterministic_hint", "authority": "draft_only"},
                "facts": item["reason"],
                "why_it_matters": "Рекомендация сформирована из агрегатов Event ID, каналов и покрытия логирования.",
                "recommended_action": item["action"],
                "confidence": "not_applicable",
                "missing_data": "raw XML, EventData, пользователь, источник, процесс или baseline - если применимо",
                "evidence_refs": _recommendation_evidence_refs(item, servers),
            }
        )
    return findings[:6]


def _missing_for_scenario(scenario: str) -> str:
    lowered = scenario.lower()
    if "dns" in lowered:
        return "Client IP, QueryName, Zone, текст DNS-сообщения, raw XML"
    authentication_ids = {
        str(_analysis_event_id("failed_logon")),
        str(_analysis_event_id("successful_logon")),
    }
    if "вход" in lowered or any(event_id in lowered for event_id in authentication_ids):
        return "TargetUser, LogonType, IP/Workstation, LogonId, ProcessName"
    if "контроллер" in lowered or "нет событий" in lowered:
        return "ошибки задачи сбора, статус WinRM/RPC, права чтения Event Log"
    return "инициатор, целевой объект, raw XML, соседние события"


def _time_bounds_for_servers(
    servers: list[str], *, authorization: CutoverAuthorization | None = None
) -> dict:
    placeholders = ",".join(["?"] * len(servers))
    source, channel, _provider = _report_event_source(authorization=authorization)
    rows = query_rows(
        f"""
        select min(e.time_created_utc) as first_event, max(e.time_created_utc) as last_event
        from {source}
        join servers s on s.id = e.server_id
        where s.hostname in ({placeholders})
        """,
        tuple(servers),
    )
    return rows[0] if rows else {"first_event": None, "last_event": None}


def _criticality_rows_for_servers(
    servers: list[str], *, authorization: CutoverAuthorization | None = None
) -> list[dict]:
    placeholders = ",".join(["?"] * len(servers))
    source, channel, provider = _report_event_source(authorization=authorization)
    rows = query_rows(
        f"""
        select e.event_id, {channel} as channel, coalesce({provider}, '') as provider_name, count(*) as count
        from {source}
        join servers s on s.id = e.server_id
        where s.hostname in ({placeholders})
        group by e.event_id, {channel}, {provider}
        order by count(*) desc
        """,
        tuple(servers),
    )
    output = []
    for row in rows:
        output.append({**row, **_event_criticality(row["event_id"], row.get("channel"), row.get("provider_name"))})
    return output


def _collect_summary(
    servers: list[str], *, authorization: CutoverAuthorization | None = None
) -> dict:
    placeholders = ",".join(["?"] * len(servers))
    params = tuple(servers)
    source, channel, _provider = _report_event_source(authorization=authorization)
    by_channel = query_rows(
        f"""
        select {channel} as channel, count(*) as count
        from {source}
        join servers s on s.id = e.server_id
        where s.hostname in ({placeholders})
        group by {channel}
        order by count(*) desc
        """,
        params,
    )
    top_event_ids = query_rows(
        f"""
        select e.event_id, {channel} as channel, count(*) as count
        from {source}
        join servers s on s.id = e.server_id
        where s.hostname in ({placeholders})
        group by e.event_id, {channel}
        order by count(*) desc
        limit 20
        """,
        params,
    )
    event_ids = query_rows(
        f"""
        select e.event_id, count(*) as count
        from {source}
        join servers s on s.id = e.server_id
        where s.hostname in ({placeholders})
        group by e.event_id
        """,
        params,
    )
    total_events = query_rows(
        f"""
        select count(*) as count
        from {source}
        join servers s on s.id = e.server_id
        where s.hostname in ({placeholders})
        """,
        params,
    )
    return {
        "total_events": total_events[0]["count"] if total_events else 0,
        "by_channel": by_channel,
        "top_event_ids": top_event_ids,
        "event_ids": event_ids,
    }


def _build_recommendations(summary: dict) -> list[dict]:
    top = summary["top_event_ids"]
    channels = {row["channel"]: row["count"] for row in summary["by_channel"]}
    event_counts = {(row["event_id"], row["channel"]): row["count"] for row in top}
    dns_event_id = _analysis_event_id("dns_invalid")
    critical_account_ids = _analysis_event_ids("critical_account_top")

    recommendations = []
    if summary.get("total_events", 0) == 0:
        recommendations.append(
            {
                "risk": "high",
                "title": "Нет событий по выбранному контроллеру домена",
                "reason": "В PostgreSQL нет импортированных событий для этого DC. Анализ рисков по содержимому невозможен.",
                "action": "Проверить доступность DC по WinRM/RPC, права чтения Event Log, имя сервера в конфигурации и ошибки задачи сбора.",
            }
        )
        return recommendations

    if event_counts.get((dns_event_id, "DNS Server"), 0) > 0:
        recommendations.append(
            {
                "risk": "medium",
                "title": f"Проверить массовые события DNS Server {dns_event_id}",
                "reason": f"Event ID {dns_event_id} доминирует в выборке DNS Server.",
                "action": "Проверить текст события, источник запросов и ожидаемость такого объема DNS-событий.",
            }
        )
    if channels.get("Security", 0) > 0 and not any(
        row["event_id"] in critical_account_ids for row in top
    ):
        recommendations.append(
            {
                "risk": "low",
                "title": "Security log содержит входы/выходы без явных критичных Event ID в топе",
                "reason": (
                    "В текущем топе нет "
                    + ", ".join(str(event_id) for event_id in critical_account_ids)
                    + "."
                ),
                "action": "Расширить период анализа и добавить детекты по критичным Event ID, а не только по топу.",
            }
        )
    if "Directory Service" not in channels:
        recommendations.append(
            {
                "risk": "medium",
                "title": "Нет событий Directory Service в импортированной выборке",
                "reason": "Канал может не иметь событий за период или аудит изменений каталога не генерирует нужные записи.",
                "action": "Проверить период сбора, настройки аудита Directory Service Changes и ожидаемые сценарии изменений AD.",
            }
        )
    if "Microsoft-Windows-PowerShell/Operational" not in channels:
        recommendations.append(
            {
                "risk": "medium",
                "title": "Нет событий PowerShell Operational",
                "reason": "Для расследований полезно видеть PowerShell-активность администраторов.",
                "action": "Проверить, включен ли канал PowerShell Operational и используется ли PowerShell на DC в выбранный период.",
            }
        )
    if not recommendations:
        recommendations.append(
            {
                "risk": "low",
                "title": "Критичных наблюдений на текущей выборке нет",
                "reason": "Автоматический анализ не нашел известных первичных индикаторов.",
                "action": "Расширить окно анализа и подключить полноценные детекты.",
            }
        )
    return recommendations


def _server_time_bounds(
    server: str, *, authorization: CutoverAuthorization | None = None
) -> dict:
    source, _channel, _provider = _report_event_source(authorization=authorization)
    rows = query_rows(
        f"""
        select min(e.time_created_utc) as first_event, max(e.time_created_utc) as last_event
        from {source}
        join servers s on s.id = e.server_id
        where s.hostname = ?
        """,
        (server,),
    )
    return rows[0] if rows else {"first_event": None, "last_event": None}


def _criticality_rows(
    server: str, *, authorization: CutoverAuthorization | None = None
) -> list[dict]:
    source, channel, provider = _report_event_source(authorization=authorization)
    rows = query_rows(
        f"""
        select e.event_id, {channel} as channel, coalesce({provider}, '') as provider_name, count(*) as count
        from {source}
        join servers s on s.id = e.server_id
        where s.hostname = ?
        group by e.event_id, {channel}, {provider}
        order by count(*) desc
        """,
        (server,),
    )
    output = []
    for row in rows:
        info = _event_criticality(row["event_id"], row.get("channel"), row.get("provider_name"))
        output.append({**row, **info})
    return output


def _report_event_source(
    authorization: CutoverAuthorization | None = None,
) -> tuple[str, str, str]:
    """Return the compact source for aggregate report queries.

    Payload-dependent correlations intentionally keep their own route until
    they are hydrated from the verified archive.  These aggregate reports need
    only core fields, so they can move to V2 without a payload scan.
    """
    resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.ANALYSIS)
    if not is_postgres_runtime_db():
        raise RuntimeError("storage_v2_route_requires_postgres")
    return (
        "events_v2_core e join storage_v2_channel v2_channel on v2_channel.id=e.channel_id "
        "left join storage_v2_provider v2_provider on v2_provider.id=e.provider_id",
        "v2_channel.value",
        "v2_provider.value",
    )


def _logging_gap_rows(summary: dict) -> list[dict]:
    channels = {row["channel"] for row in summary["by_channel"]}
    event_ids = {row["event_id"] for row in summary["event_ids"]}
    expected_channels = [
        ("Security", None, "Базовый канал безопасности", "Должны быть видны входы, изменения учетных записей, групп и аудита."),
        ("System", None, "Системный журнал", "Нужен для системных ошибок и состояния служб."),
        ("Directory Service", None, "Directory Service", "Нужен для контроля событий AD DS."),
        ("DNS Server", None, "DNS Server", "Нужен для контроля DNS на DC."),
        ("Microsoft-Windows-PowerShell/Operational", None, "PowerShell Operational", "Нужен для расследований PowerShell-активности."),
        ("Microsoft-Windows-TaskScheduler/Operational", None, "Task Scheduler Operational", "Нужен для контроля задач планировщика."),
    ]
    audit_control_metadata = [
        ("Logon success", "Microsoft minimum audit policy: Logon Success."),
        ("Logon failure", "Microsoft minimum audit policy: Logon Failure."),
        ("Logoff", "Microsoft minimum audit policy: Logoff Success."),
        ("Special Logon", "Microsoft minimum audit policy: Special Logon."),
        ("Audit Policy Change", "Microsoft minimum audit policy: Audit Policy Change."),
        ("User Account Created", "Microsoft minimum audit policy: User Account Management."),
        ("User Account Enabled", "Microsoft minimum audit policy: User Account Management."),
        ("Member added to privileged global group", "Microsoft minimum audit policy: Security Group Management."),
        ("Member added to local/domain local group", "Microsoft minimum audit policy: Security Group Management."),
        ("Account Lockout", "Microsoft minimum audit policy: Account Lockout."),
        ("Kerberos Authentication Service", "DC additions: Kerberos Authentication Service."),
        ("Kerberos Service Ticket Operations", "DC additions: Kerberos Service Ticket Operations."),
        ("Security log cleared", "Критичный контроль целостности журналов."),
    ]
    audit_controls = _analysis_event_ids("audit_controls")
    if len(audit_controls) != len(audit_control_metadata):
        raise RuntimeError("audit control metadata does not match source pack")
    expected = [
        *expected_channels,
        *[
            ("Security", event_id, name, source)
            for event_id, (name, source) in zip(
                audit_controls,
                audit_control_metadata,
                strict=True,
            )
        ],
    ]
    rows = []
    for channel, event_id, name, source in expected:
        if event_id is None:
            present = channel in channels
        else:
            present = event_id in event_ids
        rows.append(
            {
                "channel": channel,
                "event_id": event_id if event_id is not None else "-",
                "name": name,
                "status": "Собирается" if present else "Не видно",
                "source": source,
                "recommendation": "Оставить контроль включенным." if present else "Проверить расширенное логирование и период сбора.",
            }
        )
    return rows


def _correlate_events(
    servers: list[str],
    summary: dict,
    *,
    authorization: CutoverAuthorization | None = None,
) -> list[dict]:
    if summary.get("total_events", 0) == 0:
        return [
            {
                "risk": "high",
                "scenario": "Нет данных для анализа",
                "facts": "В базе нет событий по выбранному серверу или группе серверов.",
                "meaning": "Система не может подтвердить состояние безопасности этого DC по журналам. Это чаще эксплуатационная проблема сбора, но для ИБ это слепая зона.",
                "recommendation": "Проверить сетевую доступность, имя DC, права чтения журналов, состояние служб Event Log/Remote Event Log Management и ошибки последней задачи.",
            }
        ]

    # Storage V2 is the only route (plan 6.5).  The payload-dependent
    # correlations read the V1 ``events`` relation, which migration 097
    # dropped; they are not computed until they are rebuilt on V2 facts.
    _report_event_source(authorization=authorization)
    return []

