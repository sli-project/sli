from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from server.sli.events.event_catalog import lookup_event_catalog
from server.sli.events.event_details import make_event_detail_url
from server.sli.reports.analysis_rules import (
    _channel_hint,
    _duration_hint,
    _missing_fields_for_event,
    _parse_iso,
    _period_text,
    _risk_class,
)


def _kpis(summary: dict, logging_gap: list[dict], criticality: list[dict], first_last: dict) -> list[dict]:
    total_events = int(summary.get("total_events") or 0)
    missing_controls = sum(1 for row in logging_gap if row["status"] != "Собирается")
    top_event = summary["top_event_ids"][0] if summary["top_event_ids"] else None
    top_share = "0%"
    top_hint = "нет событий"
    if top_event and total_events:
        top_share = f"{round(top_event['count'] * 100 / total_events)}%"
        top_hint = f"{top_event['channel']} / {top_event['event_id']} / {top_event['count']}"
    critical_count = sum(1 for row in criticality if row.get("severity") in ("critical", "high"))
    return [
        {"value": total_events, "name": "событий собрано", "hint": _channel_hint(summary), "risk": "info"},
        {"value": top_share, "name": "главный Event ID", "hint": top_hint, "risk": "medium" if top_event else "info"},
        {"value": _duration_hint(first_last), "name": "период наблюдения", "hint": _period_text(first_last), "risk": "info"},
        {"value": critical_count, "name": "High/Critical finding", "hint": "по текущим правилам критичности", "risk": "high" if critical_count else "low"},
        {"value": missing_controls, "name": "контролей не видно", "hint": "каналы и Event ID baseline", "risk": "medium" if missing_controls else "low"},
        {"value": len(summary["by_channel"]), "name": "каналов с данными", "hint": "факт по PostgreSQL", "risk": "info"},
    ]


def _priority_actions(recommendations: list[dict], correlations: list[dict], logging_gap: list[dict]) -> list[dict]:
    actions = []
    for item in correlations:
        if item["risk"] in ("critical", "high", "medium"):
            actions.append(
                {
                    "risk": _risk_class(item["risk"]),
                    "title": item["scenario"],
                    "body": item["meaning"],
                    "points": [item["facts"], item["recommendation"]],
                }
            )
    for item in recommendations:
        actions.append(
            {
                "risk": _risk_class(item["risk"]),
                "title": item["title"],
                "body": item["reason"],
                "points": [item["action"]],
            }
        )
    if any(row["status"] != "Собирается" for row in logging_gap):
        actions.append(
            {
                "risk": "medium",
                "title": "Улучшить покрытие логирования",
                "body": "Часть каналов или Event ID не видна в текущей базе. Это ограничивает уверенность анализа.",
                "points": [
                    "Проверить период сбора и ошибки последней задачи.",
                    "Сверить настройки с ручным скриптом расширения аудита.",
                    "Не трактовать 'не видно' как отсутствие угрозы.",
                ],
            }
        )
    return actions[:3] or [
        {
            "risk": "low",
            "title": "Расширить окно анализа",
            "body": "Текущая выборка не показывает явных сценариев риска.",
            "points": ["Собрать данные за больший период.", "Добавить baseline по часам и дням."],
        }
    ]


def _event_criticality(event_id: int, channel: str | None = None, provider_name: str | None = None) -> dict:
    catalog_entry = lookup_event_catalog(event_id, channel, provider_name)
    if catalog_entry:
        return {
            "severity": catalog_entry.get("severity", "info"),
            "title": catalog_entry.get("title", f"{channel or 'Event Log'} Event ID {event_id}"),
            "fix": catalog_entry.get("fix", "Проверить message/XML и соседние события."),
            "why": catalog_entry.get("why", "Событие описано в локальном справочнике."),
            "missing": catalog_entry.get("missing", _missing_fields_for_event(event_id)),
            "catalog_status": "catalog",
        }

    provider_hint = f"{provider_name}: " if provider_name else ""
    channel_hint = channel or "Event Log"
    return {
        "severity": "info",
        "title": f"{provider_hint}{channel_hint} Event ID {event_id}",
        "fix": "Добавить запись в config/event_catalog.json после проверки provider/message/XML.",
        "why": "Событие есть в журнале, но пока не классифицировано в локальном справочнике проекта.",
        "missing": "Provider, Level, Message, XML, EventData",
        "catalog_status": "gap",
    }


def _finding(
    *,
    risk: str,
    scenario: str,
    facts: str,
    meaning: str,
    recommendation: str,
    confidence: str,
    missing_data: str,
    related_event_ids: list[int] | None = None,
) -> dict:
    time_from, time_to = _extract_fact_time_range(facts)
    return {
        "risk": "unknown",
        "provenance": {"source": "deterministic_hint", "authority": "draft_only"},
        "scenario": scenario,
        "facts": facts,
        "meaning": meaning,
        "recommendation": recommendation,
        "confidence": "not_applicable",
        "missing_data": missing_data,
        "related_event_ids": related_event_ids or [],
        "time_from": time_from,
        "time_to": time_to,
    }


def _finding_evidence_refs(item: dict, servers: list[str]) -> list[dict]:
    event_ids = [int(value) for value in item.get("related_event_ids") or [] if str(value).isdigit()]
    if not event_ids:
        return []
    time_from = item.get("time_from")
    time_to = item.get("time_to")
    detail_url = make_event_detail_url(event_ids=event_ids, servers=servers, limit=500, time_from=time_from, time_to=time_to, order="desc")
    neighbor_from, neighbor_to = _expand_time_window(time_from, time_to, minutes=15)
    neighbor_url = make_event_detail_url(event_ids=event_ids, servers=servers, limit=500, time_from=neighbor_from, time_to=neighbor_to, order="desc")
    return [
        {
            "label": "Event ID " + ", ".join(str(value) for value in event_ids),
            "event_ids": event_ids,
            "channel": "любой",
            "servers": servers,
            "actor": "см. Subject/EventData",
            "target": "см. Target/EventData",
            "source": "см. Source/EventData",
            "detail_url": detail_url,
            "neighbors_url": neighbor_url,
            "time_from": time_from,
            "time_to": time_to,
        }
    ]


def _recommendation_evidence_refs(item: dict, servers: list[str]) -> list[dict]:
    event_ids = [int(value) for value in re.findall(r"\b(\d{3,5})\b", f"{item.get('title', '')} {item.get('reason', '')}")]
    if not event_ids:
        return []
    event_ids = list(dict.fromkeys(event_ids))[:5]
    return [
        {
            "label": "Event ID " + ", ".join(str(value) for value in event_ids),
            "event_ids": event_ids,
            "channel": "любой",
            "servers": servers,
            "actor": "см. Subject/EventData",
            "target": "см. Target/EventData",
            "source": "см. Source/EventData",
            "detail_url": make_event_detail_url(event_ids=event_ids, servers=servers, limit=500, order="desc"),
            "neighbors_url": make_event_detail_url(event_ids=event_ids, servers=servers, limit=500, order="desc"),
            "time_from": None,
            "time_to": None,
        }
    ]


def _extract_fact_time_range(facts: str) -> tuple[str | None, str | None]:
    match = re.search(r"между\s+([^.;]+?)\s+и\s+([^.;]+?)(?:\.|$)", facts or "", flags=re.IGNORECASE)
    if not match:
        return None, None
    return _normalize_report_time(match.group(1)), _normalize_report_time(match.group(2))


def _normalize_report_time(value: str | None) -> str | None:
    cleaned = str(value or "").strip()
    if not cleaned:
        return None
    return cleaned


def _expand_time_window(time_from: str | None, time_to: str | None, *, minutes: int) -> tuple[str | None, str | None]:
    start = _parse_iso(time_from)
    end = _parse_iso(time_to)
    if not start and not end:
        return time_from, time_to
    if not start:
        start = end
    if not end:
        end = start
    assert start is not None and end is not None
    return _format_utc(start - timedelta(minutes=minutes)), _format_utc(end + timedelta(minutes=minutes))


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
