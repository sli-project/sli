from __future__ import annotations

"""Windows AD/DC search/analysis families, labels, finding rules and contextual classification."""

from collections.abc import Mapping
from typing import Any

from server.source_packs.contracts import (
    FindingRule,
    SecurityMonitorGroup,
)
from server.sli.plugins.ad.windows_ad_dc.facts import (
    _is_privileged_group,
    _is_service_account,
    _parse_event_data,
)

_INTERACTIVE_LOGON_TYPES = frozenset({"2", "10", "11"})


_SEARCH_EVENT_FAMILIES = {
    "authentication": frozenset({4624, 4625, 4634, 4648, 4768, 4769, 4771, 4776}),
    "account_management": frozenset(
        {
            4720,
            4722,
            4723,
            4724,
            4725,
            4726,
            4728,
            4729,
            4732,
            4733,
            4738,
            4740,
            4767,
            4781,
            4756,
            4757,
        }
    ),
    "privilege_management": frozenset({4672}),
    "policy_change": frozenset({1102, 4719}),
    "service_task": frozenset({7036, 7040, 7045}),
}


_ANALYSIS_EVENT_FAMILIES = {
    "successful_logon": (4624,),
    "failed_logon": (4625,),
    "logoff": (4634,),
    "explicit_credentials": (4648,),
    "special_privileges": (4672,),
    "audit_policy_change": (4719,),
    "account_created": (4720,),
    "account_enabled": (4722,),
    "privileged_group_change": (4728, 4732),
    "lockout": (4740,),
    "kerberos": (4768, 4769, 4771),
    "kerberos_risky": (4769, 4771),
    "security_log_cleared": (1102,),
    "dns_invalid": (5504,),
    "context_security": (4624, 4728, 4732, 4756),
    "context_task": (100, 106, 129, 140, 200, 201),
    "scheduled_task": (100, 102, 106, 129, 140, 200, 201, 324),
    "scheduled_task_related": (100, 102, 106, 140, 200, 201),
    "gpo_application": (101, 103, 108, 1112),
    "critical_account_top": (4625, 4740, 4720, 4732, 1102),
    "audit_controls": (
        4624,
        4625,
        4634,
        4672,
        4719,
        4720,
        4722,
        4728,
        4732,
        4740,
        4768,
        4769,
        1102,
    ),
    "explicit_credentials_related": (4648, 4624, 4769),
    "failed_logon_related": (4625, 4624, 4740),
    "privileged_session_related": (4624, 4672),
    "security_attention": (1102, 4719, 4720, 4722, 4728, 4732),
}


_EVENT_LABELS = {
    4624: {"ru": "Успешный вход", "en": "Successful logon"},
    4625: {"ru": "Ошибка входа", "en": "Failed logon"},
    4634: {"ru": "Выход из системы", "en": "Logoff"},
    4647: {
        "ru": "Выход по инициативе пользователя",
        "en": "User initiated logoff",
    },
    4648: {
        "ru": "Вход с явным указанием учетных данных",
        "en": "Explicit credentials logon",
    },
    4672: {"ru": "Выданы специальные права", "en": "Special privileges assigned"},
    4720: {"ru": "Создана учетная запись", "en": "User account created"},
    4722: {"ru": "Учетная запись включена", "en": "User account enabled"},
    4723: {"ru": "Попытка смены пароля", "en": "Password change attempt"},
    4724: {"ru": "Попытка сброса пароля", "en": "Password reset attempt"},
    4725: {"ru": "Учетная запись отключена", "en": "User account disabled"},
    4726: {"ru": "Учетная запись удалена", "en": "User account deleted"},
    4728: {
        "ru": "Добавление в привилегированную группу",
        "en": "Added to privileged group",
    },
    4729: {
        "ru": "Удаление из привилегированной группы",
        "en": "Removed from privileged group",
    },
    4732: {"ru": "Добавление в локальную группу", "en": "Added to local group"},
    4733: {"ru": "Удаление из локальной группы", "en": "Removed from local group"},
    4740: {"ru": "Учетная запись заблокирована", "en": "Account locked out"},
    4767: {"ru": "Учетная запись разблокирована", "en": "Account unlocked"},
    4781: {"ru": "Переименована учетная запись", "en": "Account renamed"},
    4768: {"ru": "Запрошен Kerberos TGT", "en": "Kerberos TGT requested"},
    4769: {
        "ru": "Запрошен Kerberos service ticket",
        "en": "Kerberos service ticket requested",
    },
    4771: {
        "ru": "Ошибка предварительной проверки Kerberos",
        "en": "Kerberos pre-authentication failed",
    },
    4776: {"ru": "Проверка учетных данных", "en": "Credential validation"},
    5504: {
        "ru": "DNS-запрос/ответ с ошибкой",
        "en": "DNS invalid query/response",
    },
    7045: {"ru": "Установлена новая служба", "en": "New service installed"},
}


_FINDING_RULES = {
    4740: FindingRule(
        "account_lockout",
        "Блокировка учетной записи",
        "medium",
        "Пользовательская учетная запись была заблокирована.",
        "Проверить источник ошибок входа и связанный компьютер/IP.",
    ),
    4724: FindingRule(
        "password_reset",
        "Сброс пароля",
        "high",
        "Обнаружена попытка сброса пароля учетной записи.",
        "Проверить, кто инициировал смену/сброс пароля, и были ли рядом подозрительные входы.",
    ),
    4723: FindingRule(
        "password_change_attempt",
        "Попытка смены пароля",
        "medium",
        "Обнаружена попытка смены пароля.",
        "Проверить, кто инициировал смену/сброс пароля, и были ли рядом подозрительные входы.",
    ),
    4728: FindingRule(
        "group_global_add",
        "Добавление в глобальную группу",
        "high",
        "Учетная запись добавлена в глобальную группу.",
        "Проверить инициатора, целевую группу и обоснование изменения членства.",
    ),
    4732: FindingRule(
        "group_local_add",
        "Добавление в локальную группу",
        "high",
        "Учетная запись добавлена в локальную группу.",
        "Проверить инициатора, целевую группу и обоснование изменения членства.",
    ),
    4756: FindingRule(
        "group_universal_add",
        "Добавление в универсальную группу",
        "high",
        "Учетная запись добавлена в универсальную группу.",
        "Проверить инициатора, целевую группу и обоснование изменения членства.",
    ),
    7045: FindingRule(
        "service_installed",
        "Установлена служба",
        "high",
        "На сервере установлена новая служба.",
        "Проверить evidence-события и подтвердить легитимность действия.",
    ),
}


_SECURITY_MONITOR_GROUPS = (
    SecurityMonitorGroup(
        "passwords",
        "Пароли",
        (4723, 4724),
        "high",
        "смена и сброс пароля",
        "4723/4724",
        "Сопоставить сброс/смену пароля с последующим успешным входом и инициатором.",
    ),
    SecurityMonitorGroup(
        "lockouts",
        "Блокировки",
        (4740, 4767),
        "medium",
        "lockout и разблокировка учетных записей",
        "4740/4767",
        "Проверить источник блокировки: IP/host, повторяемость и связанные 4625.",
    ),
    SecurityMonitorGroup(
        "groups",
        "Группы",
        (4728, 4729, 4732, 4733, 4756, 4757),
        "high",
        "изменения членства в группах",
        "изменения членства",
        "Проверить, кто изменял группы, особенно привилегированные, и открыть evidence по строкам группы.",
    ),
    SecurityMonitorGroup(
        "accounts",
        "Учетные записи",
        (4720, 4722, 4725, 4726, 4738),
        "medium",
        "создание, включение, отключение и изменение учеток",
    ),
    SecurityMonitorGroup(
        "privileges",
        "Специальные привилегии",
        (4672,),
        "info",
        "наблюдение privileged session; не доказывает повышение прав",
        "4672",
        "Проверить 4672: учетная запись, хост, LogonId и соседние входы в investigation.",
    ),
    SecurityMonitorGroup(
        "failed_logons",
        "Ошибки входа",
        (4625,),
        "medium",
        "неуспешные входы",
        "4625",
        "Посмотреть массовые 4625 по одному источнику или учетной записи.",
    ),
    SecurityMonitorGroup(
        "auth",
        "Kerberos / NTLM",
        (4771, 4776),
        "medium",
        "ошибки Kerberos и NTLM validation",
    ),
    SecurityMonitorGroup(
        "explicit_credentials",
        "Явные учетные данные",
        (4648,),
        "info",
        "контекстное наблюдение, без высокого риска по одному событию",
    ),
    SecurityMonitorGroup(
        "all_logons",
        "Все входы/выходы",
        (4624, 4634),
        "info",
        "массовые 4624/4634 только по явному выбору",
    ),
    SecurityMonitorGroup(
        "services_tasks",
        "Службы и задачи",
        (7045, 106, 140, 141),
        "high",
        "установка служб и события планировщика",
    ),
)


_MONITOR_PRIVILEGED_EVENT_IDS = (4672, 4728, 4732, 4756)


def classify_contextual_event(row: Mapping[str, Any]) -> dict[str, Any]:
    """Apply Windows-only context that cannot be expressed as base risk alone."""

    try:
        event_id = int(row.get("event_id") or 0)
    except (TypeError, ValueError):
        event_id = 0
    channel = str(row.get("channel") or "")
    server_role = str(row.get("server_role") or "")
    server_name = str(row.get("server") or row.get("hostname") or "")
    event_data = _parse_event_data(row.get("event_data_json"))
    target_user = row.get("target_user_name") or event_data.get("TargetUserName")
    subject_user = row.get("subject_user_name") or event_data.get("SubjectUserName")
    target_group = (
        event_data.get("TargetUserName")
        or event_data.get("GroupName")
        or row.get("target_user_name")
    )
    is_dc = server_role == "domain_controller" or server_name.casefold().startswith("dc")
    logon_type = str(
        event_data.get("LogonType") or event_data.get("Logon Type") or ""
    ).strip()

    if channel == "Security" and event_id == 4624:
        if (
            is_dc
            and _is_service_account(target_user)
            and logon_type in _INTERACTIVE_LOGON_TYPES
        ):
            return {
                "severity": "critical",
                "title": "Интерактивный вход сервисной учеткой на DC",
                "reason": (
                    f"Успешный вход 4624: account={target_user}, "
                    f"LogonType={logon_type}, server={server_name}."
                ),
            }
        return {
            "severity": "info",
            "title": "Успешный вход",
            "reason": (
                "Базовый факт входа; критичность зависит от "
                "account/source/LogonType."
            ),
        }

    if channel == "Security" and event_id in {4728, 4732, 4756}:
        if _is_privileged_group(target_group):
            return {
                "severity": "critical",
                "title": "Изменение привилегированной группы",
                "reason": (
                    f"Затронута привилегированная группа {target_group}; "
                    f"actor={subject_user or '—'}."
                ),
            }
        return {
            "severity": "important",
            "title": "Изменение группы",
            "reason": "Изменение группы требует проверки actor/member/target group.",
        }

    if (
        "taskscheduler" in channel.casefold()
        and is_dc
        and event_id in {100, 106, 129, 140, 200, 201}
    ):
        return {
            "severity": "high",
            "title": "Активность Scheduled Task на DC",
            "reason": (
                f"Task Scheduler Event ID {event_id} на контроллере домена "
                "требует проверки task/action/run-as."
            ),
        }

    return {
        "severity": "info",
        "title": f"Event ID {event_id}",
        "reason": "Нет контекстного правила; используется базовая классификация.",
    }


def event_ids_for_search_family(family: str) -> tuple[int, ...]:
    return tuple(sorted(_SEARCH_EVENT_FAMILIES.get(str(family or "").strip(), ())))


def event_ids_for_analysis_family(family: str) -> tuple[int, ...]:
    return tuple(_ANALYSIS_EVENT_FAMILIES.get(str(family or "").strip(), ()))


def event_label(event_id: Any, lang: str) -> str | None:
    try:
        labels = _EVENT_LABELS.get(int(event_id))
    except (TypeError, ValueError):
        return None
    if not labels:
        return None
    normalized_lang = str(lang or "ru").strip().casefold()
    return labels.get(normalized_lang) or labels["ru"]


def finding_rules() -> Mapping[int, FindingRule]:
    return dict(_FINDING_RULES)


def security_monitor_groups() -> tuple[SecurityMonitorGroup, ...]:
    return _SECURITY_MONITOR_GROUPS


def monitor_privileged_event_ids() -> tuple[int, ...]:
    return _MONITOR_PRIVILEGED_EVENT_IDS
