from __future__ import annotations

"""Windows AD/DC entity, state and account-event semantics."""

from typing import Any

from server.source_packs.contracts import (
    AccountEventSemantics,
    EventEntitySemantics,
    EventStateSemantics,
)

_GROUP_MEMBERSHIP_EVENT_IDS = frozenset(
    {
        4727,
        4728,
        4729,
        4730,
        4731,
        4732,
        4733,
        4734,
        4735,
        4737,
        4754,
        4755,
        4756,
        4757,
        4758,
    }
)


_SERVICE_EVENT_IDS = frozenset({7035, 7036, 7040, 7045})


_TARGET_SERVER_EVENT_IDS = frozenset({4648, 4769})


_ACCOUNT_EVENT_SEMANTICS = {
    4624: AccountEventSemantics("Вход выполнен", "logon", "ok"),
    4625: AccountEventSemantics("Неудачный вход", "logon_failed", "warn"),
    4648: AccountEventSemantics(
        "Вход с явным указанием учетных данных",
        "explicit_credentials",
        "warn",
    ),
    4672: AccountEventSemantics(
        "Создана сессия со специальными привилегиями",
        "privileged_session",
        "info",
    ),
    4720: AccountEventSemantics(
        "Создана учетная запись",
        "account_lifecycle",
        "high",
    ),
    4722: AccountEventSemantics(
        "Учетная запись включена",
        "account_lifecycle",
        "warn",
    ),
    4723: AccountEventSemantics("Попытка смены пароля", "password", "warn"),
    4724: AccountEventSemantics("Сброс пароля", "password", "high"),
    4725: AccountEventSemantics(
        "Учетная запись отключена",
        "account_lifecycle",
        "warn",
    ),
    4726: AccountEventSemantics(
        "Учетная запись удалена",
        "account_lifecycle",
        "high",
    ),
    4728: AccountEventSemantics(
        "Добавление в глобальную группу",
        "group_change",
        "high",
    ),
    4729: AccountEventSemantics(
        "Удаление из глобальной группы",
        "group_change",
        "warn",
    ),
    4732: AccountEventSemantics(
        "Добавление в локальную группу",
        "group_change",
        "high",
    ),
    4733: AccountEventSemantics(
        "Удаление из локальной группы",
        "group_change",
        "warn",
    ),
    4738: AccountEventSemantics(
        "Изменена учетная запись",
        "account_change",
        "warn",
    ),
    4740: AccountEventSemantics(
        "Учетная запись заблокирована",
        "lockout",
        "high",
    ),
    4767: AccountEventSemantics(
        "Учетная запись разблокирована",
        "lockout",
        "info",
    ),
    4781: AccountEventSemantics(
        "Переименована учетная запись",
        "account_lifecycle",
        "warn",
    ),
    4756: AccountEventSemantics(
        "Добавление в универсальную группу",
        "group_change",
        "high",
    ),
    4757: AccountEventSemantics(
        "Удаление из универсальной группы",
        "group_change",
        "warn",
    ),
    4768: AccountEventSemantics(
        "Запрошен Kerberos TGT",
        "kerberos",
        "info",
    ),
    4769: AccountEventSemantics(
        "Запрошен Kerberos service ticket",
        "kerberos",
        "info",
    ),
    4771: AccountEventSemantics(
        "Ошибка предварительной проверки Kerberos",
        "kerberos_failed",
        "warn",
    ),
    4776: AccountEventSemantics(
        "Проверка учетных данных",
        "credential_validation",
        "info",
    ),
}


_EVENT_STATE_RULES = {
    ("security", 4720): EventStateSemantics(
        "account-created-4720",
        "account.lifecycle",
        "created",
    ),
    ("security", 4722): EventStateSemantics(
        "account-enabled-4722",
        "account.access",
        "enabled",
    ),
    ("security", 4740): EventStateSemantics(
        "account-locked-4740",
        "account.access",
        "locked",
    ),
    ("microsoft-windows-taskscheduler/operational", 140): EventStateSemantics(
        "scheduled-task-changed-140",
        "scheduled_task.configuration",
        "changed",
    ),
}


def entity_semantics_for_event(
    *,
    channel: str | None,
    event_id: Any,
) -> EventEntitySemantics:
    """Return Windows-only entity extraction switches for the generic linker."""

    try:
        numeric_event_id = int(event_id)
    except (TypeError, ValueError):
        return EventEntitySemantics()
    stream = str(channel or "").strip().casefold()
    legacy_without_stream = not stream
    return EventEntitySemantics(
        target_is_group=(
            (legacy_without_stream or stream == "security")
            and numeric_event_id in _GROUP_MEMBERSHIP_EVENT_IDS
        ),
        service_name_is_entity=(
            (legacy_without_stream or stream == "system")
            and numeric_event_id in _SERVICE_EVENT_IDS
        ),
        target_server_is_entity=(
            (legacy_without_stream or stream == "security")
            and numeric_event_id in _TARGET_SERVER_EVENT_IDS
        ),
    )


def state_semantics_for_event(
    *,
    channel: str | None,
    event_id: Any,
) -> EventStateSemantics | None:
    """Resolve an evidence-first Windows state projection rule."""

    try:
        numeric_event_id = int(event_id)
    except (TypeError, ValueError):
        return None
    return _EVENT_STATE_RULES.get(
        (str(channel or "").strip().casefold(), numeric_event_id)
    )


def account_event_semantics(event_id: Any) -> AccountEventSemantics | None:
    try:
        return _ACCOUNT_EVENT_SEMANTICS.get(int(event_id))
    except (TypeError, ValueError):
        return None


def important_account_event_ids() -> tuple[int, ...]:
    return tuple(sorted(_ACCOUNT_EVENT_SEMANTICS))
