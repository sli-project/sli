"""Users V2 views and rules, ported from the standalone reference page.

``frontend/public/ad-users-v2-reference.html`` computed attention reasons,
source-quality issues and snapshot changes in the browser. The same rules
now run on the server so the report can use the shared report framework.
Account hygiene follows the installation's owner-approved policy.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from server.sli.plugins.ad.reports import ad_hygiene_policy, users_security

REASON_ORDER = (
    "locked_out", "account_expired", "password_expired", "sensitive_uac_flag", "watch_group_membership",
    "temporary_membership", "password_age", "password_age_unknown", "inactive_threshold", "enabled_activity_unknown", "identity_key_missing", "group_graph_partial",
    "password_not_required", "kerberos_no_preauth", "spn_privileged", "spn_old_password", "privileged_password_never_expires",
)
REASON_LABELS = {
    "locked_out": "Учётная запись заблокирована",
    "account_expired": "Срок действия учётной записи истёк",
    "password_expired": "Пароль наблюдался истёкшим",
    "sensitive_uac_flag": "Наблюдался security-related флаг",
    "watch_group_membership": "Членство в контрольной группе",
    "temporary_membership": "Краткое членство в контрольной группе",
    "password_age": "Возраст пароля превышает политику",
    "password_age_unknown": "Возраст пароля: неизвестно",
    "inactive_threshold": "Активность старше порога политики",
    "enabled_activity_unknown": "Неактивность: неизвестно",
    "identity_key_missing": "Не заполнен ключевой идентификатор",
    "group_graph_partial": "Граф групп собран частично",
    "password_not_required": "Пароль не требуется",
    "kerberos_no_preauth": "Не требуется предварительная аутентификация Kerberos (AS-REP roasting)",
    "spn_privileged": "SPN у привилегированной учётной записи",
    "spn_old_password": "SPN и пароль старше 365 дней",
    "privileged_password_never_expires": "Пароль привилегированной учётной записи не истекает",
}
INFORMATION_KEYS = frozenset({"password_age_unknown", "enabled_activity_unknown", "identity_key_missing", "group_graph_partial"})
CHANGE_GROUPS = {
    "identity": "Учётная запись", "organization": "Организация", "contact": "Контакты", "groups": "Членство",
    "authentication": "Пароль и вход", "security": "Security-related", "quality": "Качество источников", "lifecycle": "Состав снимка",
}
_SIMPLE_CHANGES = (
    ("ou", "Перемещение между OU", "organization"), ("department", "Подразделение", "organization"), ("title", "Должность", "organization"),
    ("company", "Компания", "organization"), ("userPrincipalName", "UPN", "identity"), ("mail", "Электронная почта", "contact"),
    ("telephoneNumber", "Рабочий телефон", "contact"), ("mobile", "Мобильный телефон", "contact"),
    ("accountExpirationDate", "Срок учётной записи", "identity"), ("passwordExpiry", "Дата истечения пароля", "authentication"),
    ("passwordLastSet", "PasswordLastSet", "authentication"), ("passwordExpired", "PasswordExpired", "authentication"),
    ("passwordNeverExpires", "PasswordNeverExpires", "authentication"), ("passwordNotRequired", "PasswordNotRequired", "authentication"),
    ("cannotChangePassword", "CannotChangePassword", "authentication"), ("smartcardLogonRequired", "SmartcardLogonRequired", "security"),
    ("accountNotDelegated", "AccountNotDelegated", "security"), ("allowReversiblePasswordEncryption", "AllowReversiblePasswordEncryption", "security"),
    ("trustedForDelegation", "TrustedForDelegation", "security"), ("trustedToAuthForDelegation", "TrustedToAuthForDelegation", "security"),
    ("doesNotRequirePreAuth", "DoesNotRequirePreAuth", "security"), ("useDesKeyOnly", "UseDESKeyOnly", "security"),
)


def _arr(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [] if value is None else [value]


def _dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return stamp.astimezone(timezone.utc) if stamp.tzinfo is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


def _days(a: Any, b: Any) -> int | None:
    left, right = _dt(a), _dt(b)
    if left is None or right is None:
        return None
    return int((right - left).total_seconds() // 86400)


def _text(value: Any, fallback: str = "—") -> str:
    return fallback if value is None or str(value).strip() == "" else str(value)


def memberships(user: Mapping[str, Any]) -> dict[str, Any]:
    raw = user.get("memberships") or {}
    return {
        "status": raw.get("status") or "not_collected", "primary": raw.get("primary"),
        "direct": _arr(raw.get("direct")), "effective": _arr(raw.get("effective")),
        "paths": _arr(raw.get("paths")), "unresolved": _arr(raw.get("unresolved")),
    }


def is_account_expired(user: Mapping[str, Any], observed_at: Any) -> bool:
    expires, at = _dt(user.get("accountExpirationDate")), _dt(observed_at)
    return bool(expires and at and expires < at)


def password_expired(user: Mapping[str, Any], observed_at: Any) -> bool:
    if user.get("passwordExpired"):
        return True
    expires, at = _dt(user.get("passwordExpiry")), _dt(observed_at)
    return bool(expires and at and expires < at)


def security_flags(user: Mapping[str, Any], *, attention_only: bool = False) -> list[str]:
    user = users_security.facts(user)
    flags = []
    for field, label in (
        ("passwordNeverExpires", "Пароль не истекает"), ("passwordNotRequired", "Пароль не требуется"),
        ("smartcardLogonRequired", "Требуется смарт-карта"), ("accountNotDelegated", "Учётная запись чувствительна, не делегируется"),
    ):
        if not attention_only and user.get(field) is True:
            flags.append(label)
    if not attention_only and user.get("doesNotRequirePreAuth"):
        flags.append("Kerberos pre-authentication не требуется")
    if user.get("allowReversiblePasswordEncryption"):
        flags.append("Разрешено обратимое шифрование пароля")
    if user.get("trustedForDelegation"):
        flags.append("TrustedForDelegation = true")
    if user.get("trustedToAuthForDelegation"):
        flags.append("TrustedToAuthForDelegation = true")
    if user.get("useDesKeyOnly"):
        flags.append("UseDESKeyOnly = true")
    return flags


def best_activity(user: Mapping[str, Any]) -> dict[str, Any] | None:
    exact_state = (user.get("sourceStates") or {}).get("exact_last_logon") or {}
    exact, llt = _dt(user.get("exactLastLogon")), _dt(user.get("lastLogonTimestamp"))
    if exact and exact_state.get("status") == "observed":
        return {"value": exact.isoformat(), "source": "lastLogon across all discovered DCs", "status": "observed"}
    if exact_state.get("status") == "partial" and (exact or llt):
        candidates = [(value, source) for value, source in ((exact, "partial lastLogon across DCs"), (llt, "lastLogonTimestamp")) if value]
        candidates.sort(key=lambda item: item[0], reverse=True)
        source = "newest of partial lastLogon and lastLogonTimestamp" if len(candidates) > 1 else candidates[0][1]
        return {"value": candidates[0][0].isoformat(), "source": source, "status": "partial"}
    if llt:
        return {"value": llt.isoformat(), "source": "lastLogonTimestamp", "status": "observed"}
    return None


def _reason(key: str, summary: str, observed: str, condition: str, qualification: str, limitation: str, next_step: str, **extra: Any) -> dict[str, Any]:
    return {"key": key, "label": REASON_LABELS[key], "summary": summary, "observed": observed, "condition": condition,
            "qualification": qualification, "limitation": limitation, "next": next_step, "order": REASON_ORDER.index(key),
            "severity": "info" if key in INFORMATION_KEYS else "medium", **extra}


def _review_observations(user: Mapping[str, Any], observed_at: Any, policy: Mapping[str, int] | None = None) -> list[dict[str, Any]]:
    user = users_security.facts(user)
    out: list[dict[str, Any]] = []
    member = memberships(user)
    if user.get("lockedOut"):
        out.append(_reason("locked_out", "Заблокирована", f"Заблокирована; снимок: {_text(observed_at)}", "lockedOut === true",
                           "Учётная запись наблюдалась заблокированной.", "Причина блокировки и необходимость разблокировки из снимка не определяются.",
                           "Проверить события аутентификации и согласовать решение с ответственным администратором."))
    if is_account_expired(user, observed_at):
        out.append(_reason("account_expired", f"AccountExpirationDate: {_text(user.get('accountExpirationDate'))}",
                           f"AccountExpirationDate = {_text(user.get('accountExpirationDate'))}; снимок = {_text(observed_at)}",
                           "AccountExpirationDate < snapshot.observed_at", "Срок действия учётной записи истёк к моменту снимка.",
                           "Это не доказывает, что объект должен быть удалён или что сотрудник уволен.", "Сверить назначение учётной записи и решение владельца процесса."))
    if password_expired(user, observed_at):
        summary = "PasswordExpired = true" if user.get("passwordExpired") else f"Истечение: {_text(user.get('passwordExpiry'))}"
        out.append(_reason("password_expired", summary, f"PasswordExpired = {bool(user.get('passwordExpired'))}; вычисленная дата = {_text(user.get('passwordExpiry'))}",
                           "PasswordExpired === true OR passwordExpiry < snapshot.observed_at", "Пароль наблюдался истёкшим по доступным атрибутам AD.",
                           "Снимок не подтверждает успешность последующей смены пароля или фактическое использование учётной записи.",
                           "Проверить effective password policy и состояние пользователя на актуальном DC."))
    flags = security_flags(user, attention_only=True)
    if flags:
        out.append(_reason("sensitive_uac_flag", "; ".join(flags), "; ".join(flags), "Хотя бы один явно перечисленный security-related атрибут равен true",
                           "Наблюдалась конкретная настройка учётной записи, требующая осознанной проверки.",
                           "Наличие флага не доказывает злоупотребление и не заменяет анализ назначения учётной записи.",
                           "Подтвердить владельца, назначение и допустимость каждого конкретного флага.", flags=flags))
    watches = [group for group in member["effective"] if isinstance(group, Mapping) and group.get("watchGroup") is True]
    if watches:
        names = ", ".join(str(group.get("name")) for group in watches)
        out.append(_reason("watch_group_membership", names, f"Эффективные группы: {names}", "effectiveGroups ∩ metadata.watch_groups ≠ ∅",
                           "Пользователь входит в явно настроенную контрольную выборку групп.",
                           "Название группы и сам факт совпадения не являются автоматической оценкой привилегий.",
                           "Открыть путь членства и проверить актуальность доступа по утверждённому владельцу группы."))
    hygiene = ad_hygiene_policy.for_user(user, observed_at, policy or ad_hygiene_policy.thresholds())
    privileged = users_security.privileged(user)
    snapshot_at = (user.get("sourceStates") or {}).get("directory", {}).get("observed_at") or observed_at
    spn_password = ad_hygiene_policy.for_user(user, snapshot_at, {"password_age": 365, "inactivity": 90})["password_age"]
    for key, applies, severity, condition, next_step in (
        ("password_not_required", user.get("passwordNotRequired") is True, "high", "userAccountControl & 0x20 != 0",
         "Потребовать пароль; проверить назначение и действующие способы входа."),
        ("kerberos_no_preauth", user.get("doesNotRequirePreAuth") is True, "high", "userAccountControl & 0x400000 != 0",
         "Включить предварительную аутентификацию Kerberos и проверить стойкость пароля."),
        ("spn_privileged", bool(user.get("servicePrincipalNames")) and privileged, "high", "SPN присутствует; подтверждено членство в привилегированной группе",
         "Отделить сервисные права от административных; проверить необходимость SPN."),
        ("spn_old_password", bool(user.get("servicePrincipalNames")) and spn_password["status"] == "exceeded", "medium", "SPN присутствует; pwdLastSet старше 365 дней на дату снимка",
         "Согласовать ротацию пароля сервиса или переход на gMSA."),
        ("privileged_password_never_expires", user.get("passwordNeverExpires") is True and privileged, "high", "passwordNeverExpires = true; подтверждено членство в привилегированной группе",
         "Включить срок действия пароля или согласовать безопасную ротацию привилегированной учётной записи."),
    ):
        if applies:
            evidence = {"uac": user.get("userAccountControl"), "spn": user.get("servicePrincipalNames"),
                        "password_last_set": user.get("passwordLastSet"), "snapshot_at": snapshot_at}
            out.append(_reason(key, REASON_LABELS[key], f"{condition}; UAC = {_text(evidence['uac'])}; SPN = {'; '.join(evidence['spn']) or '—'}; pwdLastSet = {_text(evidence['password_last_set'])}; снимок: {_text(snapshot_at)}",
                               condition, REASON_LABELS[key], "Настройка из снимка требует проверки; это не доказательство компрометации.",
                               next_step, severity=severity, evidence=evidence,
                               **({"password_evaluation": spn_password} if key == "spn_old_password" else {})))
    episodes = user.get("temporaryMemberships") or []
    if episodes:
        out.append(_reason("temporary_membership", ", ".join(sorted({str(item["group"]) for item in episodes})),
                           str(len(episodes)), "Наблюдались добавление и последующее удаление в выбранном коротком окне",
                           "Наблюдаемая последовательность по точному SID участника и группы; неоднозначные удаления отмечены отдельно.",
                           "Корреляция и вход внутри интервала не доказывают использование выданного права; полнота источника не подтверждена.",
                           "Открыть вкладку краткого членства и проверить события, повторы и допустимость временного доступа.",
                           evidence=[item["evidence"] for item in episodes]))
    for kind, evaluation in hygiene.items():
        status, days = evaluation["status"], evaluation["threshold_days"]
        if status == "within_policy" or (kind == "inactivity" and status == "exceeded" and not user.get("enabled")):
            continue
        unknown = status == "unknown"
        key = ("password_age_unknown" if unknown else "password_age") if kind == "password_age" else ("enabled_activity_unknown" if unknown else "inactive_threshold")
        field = "pwdLastSet" if kind == "password_age" else "lastLogonTimestamp"
        detail = {
            "source_untrustworthy": "Источник неполон или недостоверен",
            "fact_missing_or_invalid": "Дата отсутствует или некорректна",
            "observation_time_missing_or_invalid": "Момент наблюдения отсутствует или некорректен",
            "fact_after_observation": "Дата позже момента наблюдения",
        }.get(evaluation["reason"], "Порог принятой политики превышен")
        out.append(_reason(key, f"Неизвестно: {detail}" if unknown else f"Более {days} дней",
                           f"{field} = {_text(evaluation['value'])}; снимок = {_text(observed_at)}",
                           f"Возраст наблюдаемого {field} > {days} дней",
                           f"Неизвестно: {detail}" if unknown else f"Наблюдаемый возраст превышает принятую политику {days} дней.",
                           evaluation.get("limitation") or "pwdLastSet подтверждает дату установки пароля, а не его стойкость.",
                           "Проверить источник и назначение учётной записи.", policy=evaluation))
    missing = [name for name, key in (("sAMAccountName", "samAccountName"), ("userPrincipalName", "userPrincipalName")) if not user.get(key)]
    if missing:
        out.append(_reason("identity_key_missing", ", ".join(missing), f"Отсутствующие поля: {', '.join(missing)}", "Хотя бы одно ключевое поле идентификации пусто",
                           "Не все ключевые идентификаторы пользователя доступны в снимке.",
                           "Некоторые типы учётных записей могут осознанно не использовать UPN; назначение из одного поля не определяется.",
                           "Проверить тип и назначение учётной записи, затем решить, требуется ли заполнение."))
    if member["status"] != "observed" or member["unresolved"]:
        out.append(_reason("group_graph_partial", f"{len(member['unresolved'])} неразрешённых связей",
                           f"groups.status = {member['status']}; unresolved = {'; '.join(map(str, member['unresolved'])) or 'не указано'}",
                           "groups.status !== observed OR unresolved.length > 0", "Эффективное членство вычислено не полностью.",
                           "Отсутствие группы в effective-списке нельзя считать доказанным, пока граф partial.",
                           "Проверить область сбора, доверия между доменами и неразрешённые DN/SID."))
    return sorted(out, key=lambda reason: (reason["order"], reason["summary"]))


def quality_issues(user: Mapping[str, Any]) -> list[dict[str, Any]]:
    out = []
    for name, state in (user.get("sourceStates") or {}).items():
        status = (state or {}).get("status") or "not_evaluated"
        optional = name == "manager_resolution" and status in {"missing_in_source", "no_record", "not_evaluated", "not_applicable"}
        if status not in {"observed", "not_applicable"} and not optional:
            detail = (state or {}).get("detail") or "; ".join(str((error or {}).get("message") or (error or {}).get("code") or error) for error in _arr((state or {}).get("error"))) or f"Состояние {status}"
            out.append({"status": status, "kind": "Источник", "field": name, "detail": detail})
    for unresolved in memberships(user)["unresolved"]:
        out.append({"status": "partial", "kind": "Связь групп", "field": "unresolved group", "detail": str(unresolved)})
    return out


def _key(user: Mapping[str, Any]) -> str:
    return str(user.get("objectGuid") or user.get("sid") or user.get("id"))


def _ids(values: Iterable[Any]) -> dict[str, str]:
    out = {}
    for item in values:
        if isinstance(item, Mapping):
            out[str(item.get("id") or item.get("sid") or item.get("distinguishedName"))] = str(item.get("name") or item.get("id"))
        else:
            out[str(item)] = str(item)
    return out


def compare(current: Mapping[str, Any], previous: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if not previous:
        return []
    now = {_key(user): user for user in current.get("users") or []}
    before = {_key(user): user for user in previous.get("users") or []}
    rows: list[dict[str, Any]] = []

    def push(user: Mapping[str, Any], kind: str, label: str, field: str, old: Any, new: Any, group: str, note: str = "") -> None:
        rows.append({"user_id": user.get("id"), "entity_id": user.get("entityId"), "display_name": user.get("displayName") or user.get("name"),
                     "sam": user.get("samAccountName"), "type": kind, "label": label, "field": field,
                     "before": old, "after": new, "change_group": CHANGE_GROUPS.get(group, group), "note": note})

    for key, user in now.items():
        if key not in before:
            push(user, "new_object", "Новый объект", "object", None, "Присутствует в текущем снимке", "lifecycle")
    for key, user in before.items():
        if key not in now:
            push(user, "missing_current", "Отсутствует в текущем снимке", "object", "Присутствовал в предыдущем", None, "lifecycle",
                 "Причина не установлена: объект мог быть удалён, выйти из SearchBase или не попасть в неполный сбор.")
    for key, user in now.items():
        old = before.get(key)
        if not old:
            continue
        if bool(user.get("enabled")) != bool(old.get("enabled")):
            push(user, "enabled_changed", f"Enabled: {bool(old.get('enabled'))} → {bool(user.get('enabled'))}", "enabled", str(bool(old.get("enabled"))), str(bool(user.get("enabled"))), "identity")
        if bool(user.get("lockedOut")) != bool(old.get("lockedOut")):
            push(user, "locked_changed", f"LockedOut: {bool(old.get('lockedOut'))} → {bool(user.get('lockedOut'))}", "lockedOut", str(bool(old.get("lockedOut"))), str(bool(user.get("lockedOut"))), "authentication")
        for field, label, group in _SIMPLE_CHANGES:
            a, b = old.get(field), user.get(field)
            if json.dumps(a, sort_keys=True, default=str) != json.dumps(b, sort_keys=True, default=str):
                push(user, f"{field}_changed", label, field, a, b, group)
        old_manager = (old.get("manager") or {}).get("distinguishedName") or (old.get("manager") or {}).get("name")
        new_manager = (user.get("manager") or {}).get("distinguishedName") or (user.get("manager") or {}).get("name")
        if old_manager != new_manager:
            push(user, "manager_changed", "Руководитель", "manager", (old.get("manager") or {}).get("name") or old_manager, (user.get("manager") or {}).get("name") or new_manager, "organization")
        old_m, new_m = memberships(old), memberships(user)
        for relation, added_label, removed_label in (("direct", "Добавлено прямое членство", "Удалено прямое членство"), ("effective", "Добавлено эффективное членство", "Удалено эффективное членство")):
            a, b = _ids(old_m[relation]), _ids(new_m[relation])
            for gid in b.keys() - a.keys():
                push(user, f"{relation}_group_added", added_label, b[gid], None, b[gid], "groups")
            for gid in a.keys() - b.keys():
                push(user, f"{relation}_group_removed", removed_label, a[gid], a[gid], None, "groups")
        old_primary = _ids(_arr(old_m["primary"])) if old_m["primary"] else {}
        new_primary = _ids(_arr(new_m["primary"])) if new_m["primary"] else {}
        if set(old_primary) != set(new_primary):
            push(user, "primary_group_changed", "Изменена основная группа", "primaryGroupID", next(iter(old_primary.values()), None), next(iter(new_primary.values()), None), "groups")
        names = set((old.get("sourceStates") or {}).keys()) | set((user.get("sourceStates") or {}).keys())
        for name in sorted(names):
            a = ((old.get("sourceStates") or {}).get(name) or {}).get("status")
            b = ((user.get("sourceStates") or {}).get(name) or {}).get("status")
            if a != b:
                push(user, "source_status_changed", "Состояние источника", name, a, b, "quality")
    return rows


def build_reasons(user: Mapping[str, Any], observed_at: Any, policy: Mapping[str, int] | None = None) -> list[dict[str, Any]]:
    """Only confirmed review reasons; missing information is not a verdict."""
    return [item for item in _review_observations(user, observed_at, policy) if item["key"] not in INFORMATION_KEYS]


def user_row(user: Mapping[str, Any], observed_at: Any, policy: Mapping[str, int] | None = None,
             *, service_exceptions: Mapping[str, Any] | None = None) -> dict[str, Any]:
    user = users_security.facts(user)
    member = memberships(user)
    policy = policy or ad_hygiene_policy.thresholds()
    observations = _review_observations(user, observed_at, policy)
    service_exception = users_security.exception(user, service_exceptions or {})
    if service_exception:
        observations = [item for item in observations if item["key"] not in users_security.HYGIENE_EXCEPTION_KEYS]
    reasons = [item for item in observations if item["key"] not in INFORMATION_KEYS]
    limitations = [item for item in observations if item["key"] in INFORMATION_KEYS]
    hygiene = ad_hygiene_policy.for_user(user, observed_at, policy)
    activity = best_activity(user)
    return {
        "id": user.get("id"), "entity_id": user.get("entityId"), "display_name": user.get("displayName") or user.get("name"),
        "sam": user.get("samAccountName"), "upn": user.get("userPrincipalName"), "enabled": user.get("enabled"),
        "locked": bool(user.get("lockedOut")), "account_expired": is_account_expired(user, observed_at),
        "department": user.get("department"), "company": user.get("company"), "title": user.get("title"), "ou": user.get("ou"),
        "manager": (user.get("manager") or {}).get("name"), "mail": user.get("mail"),
        "phones": ", ".join(str(value) for value in (user.get("telephoneNumber"), user.get("mobile"), user.get("ipPhone")) if value) or None,
        "direct_groups": [group.get("name") for group in member["direct"] if isinstance(group, Mapping)],
        "effective_count": len(member["effective"]),
        "watch_groups": [group.get("name") for group in member["effective"] if isinstance(group, Mapping) and group.get("watchGroup") is True],
        "activity_at": activity["value"] if activity else None, "activity_source": activity["source"] if activity else None,
        "reason_text": ", ".join(reason["label"] for reason in reasons) or None, "reason_keys": [reason["key"] for reason in reasons],
        "reasons": reasons, "hygiene": hygiene,
        "severity": "high" if any(item["severity"] == "high" for item in reasons) else "medium" if reasons else None,
        "service_account_type": user.get("serviceAccountType"), "service_exception": service_exception,
        "admin_count": user.get("adminCount"),
        **{target: user.get(source) for source, target in (
            ("passwordNotRequired", "password_not_required"), ("doesNotRequirePreAuth", "kerberos_no_preauth"),
            ("allowReversiblePasswordEncryption", "reversible_encryption"), ("smartcardLogonRequired", "smartcard_required"),
            ("accountNotDelegated", "account_not_delegated"))},
        "information_limitations": limitations, "information_keys": [item["key"] for item in limitations],
        "information_text": ", ".join(item["label"] for item in limitations) or None,
        "review_details": [{**item, "category": "information" if item["key"] in INFORMATION_KEYS else "confirmed"} for item in observations],
        **{f"{kind}_policy": evaluation["status"]
           for kind, evaluation in hygiene.items()},
        "password_last_set": user.get("passwordLastSet"), "password_never_expires": user.get("passwordNeverExpires"),
        "created": user.get("whenCreated"), "changed": user.get("whenChanged"), "sid": user.get("sid"), "guid": user.get("objectGuid"),
        "dn": user.get("distinguishedName"), "description": user.get("description"),
        "spn": _arr(user.get("servicePrincipalNames")), "flags": security_flags(user), "employee_id": user.get("employeeID"),
    }


def group_member_ids(user: Mapping[str, Any], relation: str) -> set[str]:
    member = memberships(user)
    source: Sequence[Any] = member["direct"] if relation == "direct" else member["effective"]
    return set(_ids(source))
