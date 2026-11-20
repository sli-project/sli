"""Plugin-owned declarations and typed adapters over existing platform_settings.

The legacy table remains canonical: ownership migration does not rewrite keys,
values, attribution, or timestamps. The old screen keeps its string contract.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass

from server.sli.core import ad_service_exceptions
from server.sli.plugin_validation import (
    load_package_manifest,
    load_package_settings_schema,
    validate_shape,
)
from server.sli.plugins.workstations import logon_policy
from server.sli.plugins.workstations.settings import (
    DEFAULT_DAYS,
    SETTING_KEY,
    retention_days,
)
from server.sli.sources import ad_snapshot_history_policy as ad_history

_DNS_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")


def _dns_name(value: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) > 253 or not _DNS_NAME.match(text):
        raise ValueError("value_must_be_dns_name")
    return text


def _policy_days(value: str) -> str:
    text = str(value).strip()
    if not text.isascii() or not text.isdecimal() or not 1 <= int(text) <= 3650:
        raise ValueError("value_must_be_days_1_3650")
    return str(int(text))


def _spray_threshold(value: str) -> str:
    text = str(value).strip()
    if not text.isascii() or not text.isdecimal() or not 1 <= int(text) <= 744:
        raise ValueError("value_must_be_integer_1_744")
    return str(int(text))


@dataclass(frozen=True)
class SettingSpec:
    key: str
    label: str
    description: str
    environment: str
    validate: Callable[[str], str]
    default: str | None = None


SETTINGS: dict[str, SettingSpec] = {
    spec.key: spec for spec in (
        SettingSpec(
            key="reports.domain_fqdn",
            label="Домен отчётов",
            description=(
                "DNS-имя домена Active Directory, по которому строятся отчёты каталога: "
                "пользователи, компьютеры, состояние AD, «кто, где, когда»."
            ),
            environment="",
            validate=_dns_name,
        ),
        SettingSpec(
            key=ad_history.SETTING_KEY,
            label="Хранение истории изменений AD/GPO, дней",
            description="Компактные изменения снимков в ClickHouse; допустимо от 7 до 3650 дней.",
            environment=ad_history.ENVIRONMENT,
            validate=ad_history.history_days,
            default=ad_history.DEFAULT_DAYS,
        ),
        SettingSpec(
            key=SETTING_KEY,
            label="Хранение доказательств процессов и USB, дней",
            description="Срок хранения в PostgreSQL до подтверждённого переноса в историю.",
            environment="SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS",
            validate=retention_days,
            default=DEFAULT_DAYS,
        ),
        SettingSpec(
            key="ad.password_max_age_days",
            label="Максимальный возраст пароля AD, дней",
            description="Принятая политика по наблюдаемому pwdLastSet. Допустимо 1–3650 дней.",
            environment="",
            validate=_policy_days,
            default="365",
        ),
        SettingSpec(
            key="ad.inactivity_days",
            label="Порог неактивности пользователей AD, дней",
            description="Принятая политика по lastLogonTimestamp с учётом задержки репликации. Допустимо 1–3650 дней.",
            environment="",
            validate=_policy_days,
            default="90",
        ),
        SettingSpec(
            key=ad_service_exceptions.SETTING_KEY,
            label="Исключения сервисных учётных записей AD",
            description="JSON-список SID: исключения возраста пароля и неактивности для SPN/MSA/gMSA. Автор и время сохраняются автоматически; опасные флаги и привилегии не исключаются.",
            environment="", validate=ad_service_exceptions.setting_value, default="[]",
        ),
        *(SettingSpec(
            key=f"windows_auth.{key}", label=label,
            description="Распределённый подбор паролей: сигнал для ручной проверки, не вердикт. Допустимо 1–744.",
            environment="", validate=_spray_threshold, default=default,
        ) for key, label, default in (
            ("distributed_window_hours", "Окно распределённого подбора, часов", "24"),
            ("distributed_min_accounts", "Минимум целевых SID", "10"),
            ("distributed_min_sources", "Минимум источников подбора", "5"),
            ("distributed_max_failures_per_account", "Максимум отказов на целевой SID", "3"),
        )),
        SettingSpec(
            key=logon_policy.SETTING_KEY,
            label="workstations.logon_policy.title",
            description="workstations.logon_policy.description",
            environment="", validate=logon_policy.setting_value,
        ),
    )
}


def metadata(plugin_id: str) -> dict:
    """Only bundled, validated declarations may address the legacy store."""
    from server.sli.plugins.registry import BUNDLED

    if plugin_id not in BUNDLED:
        raise LookupError("plugin_settings_not_found")
    load_package_manifest(plugin_id)
    result = load_package_settings_schema(plugin_id)
    properties = result["settings"]["properties"]
    # No bundled settings are secrets. Fail closed if a future manifest adds
    # one, rather than expose its default/value through this non-secret API.
    if any(node.get("x-secret") for node in properties.values()):
        raise ValueError("plugin_settings_secret_unsupported")
    if not properties.keys() <= SETTINGS.keys():
        raise ValueError("plugin_settings_storage_unmapped")
    return result


def typed_value(value: str, node: dict):
    if not value:
        return None
    types = node["type"] if isinstance(node["type"], list) else [node["type"]]
    return value if "string" in types else json.loads(value)


def read_settings(plugin_id: str) -> dict:
    from server.sli.core.platform_settings import _resolve

    declaration = metadata(plugin_id)
    schema = declaration["settings"]
    values, sources = {}, {}
    for key, node in schema["properties"].items():
        value, source, row = _resolve(SETTINGS[key])
        # Preserve legacy string/attributed exception representations on read.
        # Validation may normalize them, but GET must not rewrite their meaning.
        if row is not None:
            value = str(row["value"])
        values[key] = typed_value(value, node)
        sources[key] = source
    return {"plugin_id": plugin_id, "schema": schema, "values": values, "sources": sources,
            "rules": declaration["rules"]}


def encode_update(plugin_id: str, body: dict) -> tuple[str, str, dict]:
    schema = metadata(plugin_id)["settings"]
    if not isinstance(body, dict) or set(body) != {"key", "value"}:
        raise ValueError("invalid_plugin_setting_value")
    key, value = body["key"], body["value"]
    if not isinstance(key, str) or key not in schema["properties"]:
        raise ValueError("invalid_plugin_setting_value")
    validate_shape({key: value}, schema, schema)
    encoded = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    # Keep existing storage bounds, domain validation, exception attribution,
    # and monotonic workstation policy versions in the existing writer.
    return key, encoded, schema["properties"][key]

