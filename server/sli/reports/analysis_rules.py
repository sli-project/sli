from __future__ import annotations

from datetime import datetime


def _source_facts(summary: dict, first_last: dict, job_id: int | None) -> list[str]:
    facts = [
        f"Всего событий в PostgreSQL: {summary.get('total_events', 0)}.",
        f"Окно UTC: {_period_text(first_last)}.",
        f"Каналы: {_channel_hint(summary)}.",
    ]
    if summary["top_event_ids"]:
        top = summary["top_event_ids"][0]
        facts.append(f"Топ Event ID: {top['event_id']} в канале {top['channel']} ({top['count']} событий).")
    if job_id is not None:
        facts.append(f"Job ID анализа: {job_id}.")
    return facts


def _assumptions() -> list[str]:
    return [
        "Текущий слой анализа локальный; внешний ИИ-провайдер пока не подключен.",
        "Отсутствие события или канала означает 'не видно в текущей базе', а не доказанное отсутствие активности.",
        "Уверенность ограничена коротким периодом сбора и полнотой EventData/XML.",
        "Рекомендации являются read-only аналитикой и не выполняют действий в AD.",
    ]


def _threat_score(
    summary: dict,
    correlations: list[dict],
    criticality: list[dict],
) -> int | None:
    if summary.get("total_events", 0) == 0:
        return None
    score = 0
    weights = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
    for item in correlations:
        score += weights.get(str(item.get("risk") or "info"), 0)
    for item in criticality:
        score += weights.get(str(item.get("severity") or "info"), 0)
    return max(0, min(100, score))


def _threat_note(score: int | None, total_events: int) -> str:
    if score is None or total_events == 0:
        return "Оценка угрозы недоступна: событий нет; состояние видимости показано отдельно."
    if score >= 70:
        return "Высокая оценка угрозы по наблюдаемым событиям и корреляциям."
    if score >= 40:
        return "Средняя оценка угрозы: наблюдаемые признаки требуют проверки."
    if score > 0:
        return "Низкая оценка угрозы по доступным наблюдаемым признакам."
    return "Наблюдаемые признаки угроз не найдены; это не доказывает отсутствие активности."


def _main_conclusion(total_events: int, recommendations: list[dict], correlations: list[dict], top_noise: str) -> str:
    if total_events == 0:
        return "По выбранному контроллеру домена нет событий в базе. Главный вывод относится к качеству сбора: это слепая зона мониторинга."
    high = [item for item in correlations if item["risk"] in ("critical", "high")]
    if high:
        return f"Главное направление проверки: {high[0]['scenario']}. Нужно подтвердить факты и собрать недостающие поля события."
    if recommendations:
        return f"В текущей выборке нет доказательства инцидента, но нужно проверить: {recommendations[0]['title']}. Главный шум: {top_noise}."
    return "Явных первичных признаков риска в текущей выборке нет. Нужны более длинный период и baseline."


def _main_limitation(total_events: int, missing_controls: int) -> str:
    if total_events == 0:
        return "Отчет не может оценить состояние DC без событий. Нужно сначала устранить проблему сбора или доступа к журналам."
    if missing_controls:
        return f"Не видны {missing_controls} контрольных канала или Event ID. Это риск слепой зоны, а не доказательство отсутствия угроз."
    return "Анализ строится на текущем окне событий и локальных правилах. Для уверенных выводов нужны baseline и внешний ИИ-слой."


def _top_noise_text(summary: dict) -> str:
    if not summary["top_event_ids"]:
        return "нет событий"
    top = summary["top_event_ids"][0]
    return f"{top['channel']} {top['event_id']} / {top['count']}"


def _channel_hint(summary: dict) -> str:
    if not summary["by_channel"]:
        return "нет каналов с событиями"
    return ", ".join(f"{row['channel']} {row['count']}" for row in summary["by_channel"][:4])


def _short_list(values: list[str], limit: int) -> str:
    cleaned = []
    for value in values:
        item = str(value).strip()
        if item and item not in cleaned:
            cleaned.append(item)
    visible = cleaned[:limit]
    suffix = f" и еще {len(cleaned) - limit}" if len(cleaned) > limit else ""
    return ", ".join(visible) + suffix if visible else "нет данных"


def _period_text(first_last: dict) -> str:
    first = first_last.get("first_event")
    last = first_last.get("last_event")
    if not first or not last:
        return "нет данных"
    return f"{first} -> {last}"


def _duration_hint(first_last: dict) -> str:
    first = _parse_iso(first_last.get("first_event"))
    last = _parse_iso(first_last.get("last_event"))
    if not first or not last:
        return "-"
    seconds = max(0, int((last - first).total_seconds()))
    hours, rem = divmod(seconds, 3600)
    minutes, _ = divmod(rem, 60)
    if hours:
        return f"{hours}ч {minutes}м"
    return f"{minutes}м"


def _parse_iso(value: str | datetime | None) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _risk_class(value: str) -> str:
    value = str(value).lower()
    if value in ("critical", "high", "medium", "low", "info"):
        return value
    return "info"


def _display_risk(value: str) -> str:
    mapping = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
    return mapping.get(str(value).lower(), "Info")


def _confidence_for_risk(value: str) -> str:
    return {"critical": "высокая", "high": "высокая", "medium": "средняя", "low": "средняя", "info": "низкая"}.get(str(value).lower(), "средняя")


def _why_event_matters(event_id: int) -> str:
    del event_id
    return "Нет отдельного правила интерпретации; требуется provider/message/XML."


def _missing_fields_for_event(event_id: int) -> str:
    del event_id
    return "Provider, Level, Message, XML, EventData"
