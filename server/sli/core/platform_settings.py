"""Installation-wide settings edited on the «Настройки платформы» page.

Owner decision 2026-10-01: settings such as the report domain are a separate,
visible setting. The saved report preference comes only from ``platform_settings``
(owner decision 2026-10-02): an unset domain is listed with source
``not_configured`` and reading it raises. Effective report selection separately
excludes explicitly archived domains and may use confirmed AD observations.
Database setting values are cached briefly.
Workstation evidence retention retains its environment override and the
owner-approved default of 90 days.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from typing import Any

from server.sli.core import ad_service_exceptions, database
from server.sli.core.report_domain import ReportDomainNotConfiguredError
from server.sli.core import working_time
from server.sli.plugins.workstations import logon_policy
from server.sli.plugins.settings import SETTINGS as PLUGIN_SETTINGS, SettingSpec, _dns_name  # noqa: F401

_CACHE_SECONDS = 30.0
# Preserve the legacy screen order while declarations live with their owner.
SETTINGS: dict[str, SettingSpec] = {
    **{key: spec for key, spec in PLUGIN_SETTINGS.items() if key != logon_policy.SETTING_KEY},
    working_time.SETTING_KEY: SettingSpec(
        key=working_time.SETTING_KEY,
        label="Рабочее время для правил ИБ",
        description="JSON: часовой пояс, дни недели (0–6), начало/конец, исключённые даты и исключения SID.",
        environment="", validate=working_time.setting_value,
    ),
    logon_policy.SETTING_KEY: PLUGIN_SETTINGS[logon_policy.SETTING_KEY],
}

_lock = threading.Lock()
_cache: dict[str, tuple[float, dict[str, Any] | None]] = {}


def _stored_row(key: str) -> dict[str, Any] | None:
    """The administrator's value, or None if unset or the database is unreachable."""
    now = time.monotonic()
    with _lock:
        cached = _cache.get(key)
        if cached is not None and cached[0] > now:
            return cached[1]
    try:
        rows = database.query_rows(
            "select value, updated_by, updated_at from platform_settings where key = ?", (key,),
        )
        row = dict(rows[0]) if rows else None
    except Exception:
        # An unavailable database cannot supply a report domain. Other settings
        # retain only the fallback explicitly declared by their specification.
        row = None
    with _lock:
        _cache[key] = (now + _CACHE_SECONDS, row)
    return row


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def _resolve(spec: SettingSpec) -> tuple[str, str, dict[str, Any] | None]:
    row = _stored_row(spec.key)
    if row is not None:
        return spec.validate(str(row["value"])), "database", row
    environment = (os.environ.get(spec.environment) or "").strip() if spec.environment else ""
    if environment:
        return spec.validate(environment), "environment", None
    if spec.default is not None:
        return spec.validate(spec.default), "default", None
    return "", "not_configured", None


def get_setting(key: str) -> str:
    """Validated value of a declared setting; raises if it is not configured."""
    value, source, _row = _resolve(SETTINGS[key])
    if source == "not_configured":
        if key == "reports.domain_fqdn":
            raise ReportDomainNotConfiguredError()
        raise ValueError("setting_not_configured")
    return value


def list_settings() -> list[dict[str, Any]]:
    """Every declared setting with its value and where the value comes from."""
    items = []
    for spec in SETTINGS.values():
        value, source, row = _resolve(spec)
        items.append({
            "key": spec.key,
            "label": spec.label,
            "description": spec.description,
            "value": value,
            "source": source,
            "environment": spec.environment,
            "updated_by": (row or {}).get("updated_by"),
            "updated_at": str((row or {}).get("updated_at") or "") or None,
        })
    from server.sli.core.report_domain import effective_domain_fqdn

    report = next(item for item in items if item["key"] == "reports.domain_fqdn")
    try:
        report["effective_value"] = effective_domain_fqdn(report["value"] or None)
        report["effective_state"] = "available"
    except ReportDomainNotConfiguredError:
        report.update(effective_value=None, effective_state="unknown")
    except Exception:
        report.update(effective_value=None, effective_state="unavailable")
    return items


def set_setting(
    key: str,
    value: str,
    *,
    actor: str,
    audit: Callable[[Any, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Validate and store an administrator's value; returns old and new values.

    ``audit(cursor, result)`` runs in the same transaction, so a change is
    never stored without its audit record.
    """
    spec = SETTINGS.get(key)
    if spec is None:
        raise ValueError("unknown_setting")
    normalized = spec.validate(value)
    actor_name = str(actor or "").strip()[:256]
    if not actor_name:
        raise ValueError("actor_required")
    previous = _resolve(spec)[0] or None
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn, conn.cursor() as cur:
        if key == logon_policy.SETTING_KEY:
            cur.execute("select pg_advisory_xact_lock(hashtext(%s))", (key,))
            cur.execute("select value from platform_settings where key = %s for update", (key,))
            stored = cur.fetchone()
            previous = stored["value"] if stored else None
            logon_policy.validate_update(normalized, previous)
        if key == ad_service_exceptions.SETTING_KEY:
            # Serialize even the first write, then read attribution without cache.
            cur.execute("select pg_advisory_xact_lock(hashtext(%s))", (key,))
            cur.execute("select value from platform_settings where key = %s for update", (key,))
            stored = cur.fetchone()
            previous = stored["value"] if stored else "[]"
            normalized = ad_service_exceptions.attributed(normalized, previous, actor=actor_name)
        if key == "reports.domain_fqdn":
            cur.execute("select id from domains where lower(fqdn) = %s", (normalized,))
            if cur.fetchone() is None:
                raise ValueError("report_domain_not_registered")
        cur.execute(
            """
            insert into platform_settings(key, value, updated_by, updated_at)
            values (%s, %s, %s, now())
            on conflict (key) do update
              set value = excluded.value, updated_by = excluded.updated_by, updated_at = now()
            """,
            (key, normalized, actor_name),
        )
        result = {"key": key, "previous": previous, "value": normalized}
        if audit is not None:
            audit(cur, result)
        conn.commit()
    clear_cache()
    return result
