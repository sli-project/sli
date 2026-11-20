from __future__ import annotations

from typing import Any

from server.sli.core.messages import catalog, message
from server.sli.events.event_catalog import lookup_event_catalog
from server.source_packs.registry import resolve_source_normalizer

DEFAULT_LANG = "ru"
SUPPORTED_LANGS = {"ru", "en"}

STATUS_LABELS: dict[str, dict[str, str]] = {
    "ru": {
        "completed": "завершено",
        "partial_timeout": "частичный сбор по таймауту",
        "timeout": "таймаут",
        "failed": "ошибка",
        "running": "выполняется",
        "queued": "в очереди",
        "stale": "устарело",
        "unknown": "неизвестно",
        "ok": "норма",
        "warn": "внимание",
        "high": "высокий риск",
        "critical": "критично",
        "info": "информация",
        "low": "низкий риск",
        "medium": "средний риск",
        "on": "включен",
        "off": "выключен",
        "new": "новый",
        "active": "активный",
        "repeated": "повторяется",
        "review": "проверяется",
        "confirmed": "подтвержден",
        "false_positive": "ложное срабатывание",
        "closed": "закрыт",
    },
    "en": {
        "completed": "completed",
        "partial_timeout": "partial timeout",
        "timeout": "timeout",
        "failed": "failed",
        "running": "running",
        "queued": "queued",
        "stale": "stale",
        "unknown": "unknown",
        "ok": "ok",
        "warn": "warning",
        "high": "high",
        "critical": "critical",
        "info": "info",
        "low": "low",
        "medium": "medium",
        "on": "on",
        "off": "off",
        "new": "new",
        "active": "active",
        "repeated": "repeated",
        "review": "in review",
        "confirmed": "confirmed",
        "false_positive": "false positive",
        "closed": "closed",
    },
}

SEVERITY_LABELS: dict[str, dict[str, str]] = {
    "ru": {
        "critical": "критично",
        "high": "высокий",
        "medium": "средний",
        "warn": "внимание",
        "low": "низкий",
        "info": "информация",
        "ok": "норма",
        "unknown": "неизвестно",
    },
    "en": {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "warn": "warning",
        "low": "low",
        "info": "info",
        "ok": "ok",
        "unknown": "unknown",
    },
}

ENTITY_ROLE_LABELS: dict[str, dict[str, str]] = {
    "ru": {
        "recorder": "источник записи",
        "actor": "кто выполнил действие",
        "target": "над кем/чем выполнено действие",
        "affected": "затронутый объект",
        "source": "откуда пришло действие",
        "context": "контекст",
        "executor": "исполнитель",
        "unknown": "роль не определена",
    },
    "en": {
        "recorder": "recorder",
        "actor": "actor",
        "target": "target",
        "affected": "affected",
        "source": "source",
        "context": "context",
        "executor": "executor",
        "unknown": "unknown role",
    },
}

ENTITY_TYPE_LABELS: dict[str, dict[str, str]] = {
    "ru": {
        "user": "учетная запись",
        "group": "группа",
        "computer": "компьютер",
        "server": "сервер",
        "domain_controller": "контроллер домена",
        "ip": "IP-адрес",
        "session": "сеанс / LogonId",
        "task": "задание планировщика",
        "service": "служба",
        "process": "процесс",
        "unknown": "объект",
    },
    "en": {
        "user": "user account",
        "group": "group",
        "computer": "computer",
        "server": "server",
        "domain_controller": "domain controller",
        "ip": "IP address",
        "session": "session / LogonId",
        "task": "scheduled task",
        "service": "service",
        "process": "process",
        "unknown": "object",
    },
}

CHANNEL_LABELS: dict[str, dict[str, str]] = {
    "ru": {
        "Security": "Безопасность",
        "System": "Система",
        "Directory Service": "Служба каталогов",
        "DNS Server": "DNS-сервер",
        "Microsoft-Windows-PowerShell/Operational": "PowerShell",
        "Microsoft-Windows-TaskScheduler/Operational": "Планировщик заданий",
    },
    "en": {
        "Security": "Security",
        "System": "System",
        "Directory Service": "Directory Service",
        "DNS Server": "DNS Server",
        "Microsoft-Windows-PowerShell/Operational": "PowerShell",
        "Microsoft-Windows-TaskScheduler/Operational": "Task Scheduler",
    },
}

FIELD_LABELS: dict[str, dict[str, str]] = {
    "ru": {
        "server": "Сервер",
        "channel": "Журнал",
        "status": "Статус",
        "severity": "Важность",
        "last_collection": "Последний сбор",
        "last_event": "Последнее событие",
        "record_id": "Record ID",
        "lag": "Отставание",
        "timeouts": "Таймауты",
        "partial": "Частичные",
        "inserted_skipped": "Добавлено / пропущено",
        "adaptive_limit": "Адаптивный лимит",
        "recovery": "Режим восстановления",
        "actions": "Действия",
        "time": "Время",
        "utc": "UTC",
        "local_time": "Локальное время",
        "event_id": "Event ID",
        "event_name": "Что это значит",
        "subject": "Инициатор",
        "target": "Цель",
        "source": "Источник",
        "details": "Детали",
        "role": "Роль",
        "confidence": "Уверенность",
        "user": "Учетная запись",
        "ip": "IP-адрес",
        "logon_id": "LogonId",
        "message": "Сообщение",
    },
    "en": {
        "server": "Server",
        "channel": "Channel",
        "status": "Status",
        "severity": "Severity",
        "last_collection": "Last collection",
        "last_event": "Last event",
        "record_id": "Record ID",
        "lag": "Lag",
        "timeouts": "Timeouts",
        "partial": "Partial",
        "inserted_skipped": "Inserted / skipped",
        "adaptive_limit": "Adaptive limit",
        "recovery": "Recovery",
        "actions": "Actions",
        "time": "Time",
        "utc": "UTC",
        "local_time": "Local time",
        "event_id": "Event ID",
        "event_name": "Meaning",
        "subject": "Subject",
        "target": "Target",
        "source": "Source",
        "details": "Details",
        "role": "Role",
        "confidence": "Confidence",
        "user": "User",
        "ip": "IP address",
        "logon_id": "LogonId",
        "message": "Message",
    },
}

UI_TEXT: dict[str, dict[str, str]] = {
    "ru": {
        "theme_light": "Тема: светлая",
        "theme_dark": "Тема: темная",
        "lang": "Язык: RU",
        "home": "На главную",
        "open_dashboard": "Открыть панель",
        "open_events": "Открыть события",
        "technical_details": "Технические детали",
        "account_chain": "Цепочка учетной записи",
        "same_user": "Тот же пользователь",
        "same_ip": "Тот же IP",
        "same_logon_id": "Тот же LogonId",
        "nearby_events": "Соседние события ±15 минут",
        "no_data": "Нет данных",
    },
    "en": {
        "theme_light": "Theme: light",
        "theme_dark": "Theme: dark",
        "lang": "Language: EN",
        "home": "Home",
        "open_dashboard": "Open dashboard",
        "open_events": "Open events",
        "technical_details": "Technical details",
        "account_chain": "Account chain",
        "same_user": "Same user",
        "same_ip": "Same IP",
        "same_logon_id": "Same LogonId",
        "nearby_events": "Nearby events ±15 minutes",
        "no_data": "No data",
    },
}


def normalize_lang(lang: str | None = None) -> str:
    clean = str(lang or DEFAULT_LANG).lower().strip()
    return clean if clean in SUPPORTED_LANGS else DEFAULT_LANG


def label(mapping: dict[str, dict[str, str]], key: Any, *, lang: str | None = None, default: str | None = None) -> str:
    clean_lang = normalize_lang(lang)
    clean_key = "unknown" if key is None or key == "" else str(key)
    by_lang = mapping.get(clean_lang, {})
    if clean_key in by_lang:
        return by_lang[clean_key]
    if clean_lang != DEFAULT_LANG and clean_key in mapping.get(DEFAULT_LANG, {}):
        return mapping[DEFAULT_LANG][clean_key]
    return default if default is not None else clean_key


def status_label(status: Any, *, lang: str | None = None) -> str:
    return label(STATUS_LABELS, status, lang=lang)


def severity_label(severity: Any, *, lang: str | None = None) -> str:
    return label(SEVERITY_LABELS, severity, lang=lang)


def entity_role_label(role: Any, *, lang: str | None = None) -> str:
    return label(ENTITY_ROLE_LABELS, role, lang=lang)


def entity_type_label(entity_type: Any, *, lang: str | None = None) -> str:
    return label(ENTITY_TYPE_LABELS, entity_type, lang=lang)


def channel_label(channel: Any, *, lang: str | None = None, with_original: bool = False) -> str:
    value = label(CHANNEL_LABELS, channel, lang=lang)
    original = "" if channel is None else str(channel)
    if with_original and original and value != original:
        return f"{value} ({original})"
    return value


def field_label(field: Any, *, lang: str | None = None) -> str:
    return label(FIELD_LABELS, field, lang=lang)


def event_id_label(
    event_id: Any,
    *,
    lang: str | None = None,
    prefix: bool = True,
    channel: str | None = None,
    provider_name: str | None = None,
) -> str:
    try:
        number = int(event_id)
    except (TypeError, ValueError):
        return "Event ID —" if prefix else "—"
    provider_name = str(provider_name or "").strip()
    normalizer = resolve_source_normalizer(
        channel if channel is not None else "Security",
        provider_name,
        str(number),
    )
    clean_lang = normalize_lang(lang)
    text = normalizer.event_label(number, clean_lang) if normalizer and (channel is None or provider_name) else None
    if not text and normalizer and channel and provider_name:
        # A source owner's short-label list may be incomplete. Only an exact
        # descriptor can fill that gap; never borrow meaning by numeric ID.
        entry = lookup_event_catalog(number, channel, provider_name)
        if entry and (
            str(entry.get("channel") or "").strip().casefold() == channel.strip().casefold()
            and str(entry.get("provider_name") or "").strip().casefold() == provider_name.strip().casefold()
        ):
            code = f"events.semantic.{entry['channel']}:{entry['provider_name']}:{number}.title"
            text = message(code, locale=clean_lang)["text"] if code in catalog(clean_lang) else entry.get("title") if clean_lang == "ru" else None
    if text:
        return f"Event ID {number}: {text}" if prefix else text
    return f"Event ID {number}" if prefix else message("events.unknown_type", locale=clean_lang)["text"]


def ui_text(key: Any, *, lang: str | None = None) -> str:
    return label(UI_TEXT, key, lang=lang)


def translate_warning(text: Any, *, lang: str | None = None) -> str:
    if normalize_lang(lang) != "ru":
        return "—" if text is None or text == "" else str(text)
    replacements = {
        "channel timeout": "таймаут канала",
        "Security lag > 2h": "отставание Security больше 2 часов",
        "Security lag > 30m": "отставание Security больше 30 минут",
        "possible repeated backlog read": "возможно повторное чтение backlog",
        "channel data stale": "данные канала давно не обновлялись",
    }
    value = "—" if text is None or text == "" else str(text)
    return replacements.get(value, value)
