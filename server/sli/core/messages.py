"""Localized, additive message envelopes for API consumers."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from datetime import UTC, date, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

CATALOG_DIR = Path(__file__).resolve().parents[3] / "config" / "i18n"
# Shared vocabulary declared by the bundled plugin settings schemas.
PLUGIN_SETTINGS_MESSAGE_CODES = frozenset({
    "plugin_settings_not_found", "plugin_settings_unavailable", "invalid_plugin_setting_value",
    "plugins.sli.ad.name",
    "plugins.sli.ad.settings.reports.domain_fqdn.label",
    "plugins.sli.ad.settings.reports.domain_fqdn.help",
    "plugins.sli.ad.settings.ad.snapshot_history_days.label",
    "plugins.sli.ad.settings.ad.snapshot_history_days.help",
    "plugins.sli.ad.settings.ad.password_max_age_days.label",
    "plugins.sli.ad.settings.ad.password_max_age_days.help",
    "plugins.sli.ad.settings.ad.inactivity_days.label",
    "plugins.sli.ad.settings.ad.inactivity_days.help",
    "plugins.sli.ad.settings.ad.service_account_exceptions.label",
    "plugins.sli.ad.settings.ad.service_account_exceptions.help",
    "plugins.sli.ad.settings.windows_auth.distributed_window_hours.label",
    "plugins.sli.ad.settings.windows_auth.distributed_window_hours.help",
    "plugins.sli.ad.settings.windows_auth.distributed_min_accounts.label",
    "plugins.sli.ad.settings.windows_auth.distributed_min_accounts.help",
    "plugins.sli.ad.settings.windows_auth.distributed_min_sources.label",
    "plugins.sli.ad.settings.windows_auth.distributed_min_sources.help",
    "plugins.sli.ad.settings.windows_auth.distributed_max_failures_per_account.label",
    "plugins.sli.ad.settings.windows_auth.distributed_max_failures_per_account.help",
    "plugins.sli.ad.rules.password_age.name",
    "plugins.sli.ad.rules.inactivity.name",
    "plugins.sli.file-audit.name",
    "plugins.sli.file-audit.rules.file-audit.out-of-hours.name",
    "plugins.sli.file-audit.rules.file-audit.acl-review.name",
    "plugins.sli.file-audit.rules.file-audit.broad-write.name",
    "plugins.sli.file-audit.rules.file-audit.direct-user-rights.name",
    "plugins.sli.file-audit.rules.file-audit.disabled-account-rights.name",
    "plugins.sli.file-audit.rules.file-audit.mass-read.name",
    "plugins.sli.file-audit.rules.file-audit.mass-write.name",
    "plugins.sli.file-audit.rules.file-audit.mass-delete.name",
    "plugins.sli.gpo.name",
    "plugins.sli.remote-access.name",
    "plugins.sli.remote-access.rules.qw.nps-denials.name",
    "plugins.sli.sigma.name",
    "plugins.sli.workstations.name",
    "plugins.sli.workstations.settings.workstations.evidence_retention_days.label",
    "plugins.sli.workstations.settings.workstations.evidence_retention_days.help",
    "plugins.sli.workstations.settings.workstations.logon_policy.label",
    "plugins.sli.workstations.settings.workstations.logon_policy.help",
    "plugins.sli.workstations.rules.C07.name",
})
REPORT_STATES = frozenset({"ok", "empty", "partial", "stale", "unavailable", "denied", "not_collected", "processing", "error"})
AUTH_ERRORS = {
    "authentication_required": "login.error.authenticationRequired",
    "authentication_not_enabled": "login.error.disabled",
    "secure_transport_required": "login.error.https",
    "login_temporarily_locked": "login.error.retryAfter",
    "invalid_credentials": "login.error.credentials",
    "cross_origin_request_rejected": "login.error.origin",
}
WORKSTATION_ERRORS = {
    "workstation_access_denied": "workstations.access.denied",
    "workstation_request_invalid": "workstations.access.invalid",
    "workstation_source_unavailable": "workstations.access.unavailable",
    "workstation_plugin_unavailable": "workstations.access.pluginUnavailable",
}
LOGIN_INPUT_ERRORS = frozenset({
    "invalid_content_length", "request_body_too_large", "json_content_type_required",
    "invalid_json", "json_object_required",
})
LOGIN_SERVICE_ERRORS = frozenset({"internal_server_error", "server_busy"})
FINDING_STATUSES = ("new", "repeated", "confirmed", "active", "review", "false_positive", "closed")
FINDING_SEVERITIES = ("critical", "high", "medium", "low")
# Reports whose declared metadata is sent as catalog codes (key = ``reports.v2.<report>.<path>``).
CODED_REPORTS = frozenset({"security.problems", "ad.users.v2", "ad.computers.v6", "ad.infrastructure",
                           "workstations.logons", "workstations.processes", "workstations.usb", "workstations.protection",
                           "workstations.overview", "events.journal"})


def select_locale(accept_language: str | None = None, *, user_locale: str | None = None) -> str:
    """An explicit preference wins; otherwise honour language weights, defaulting to RU."""
    if user_locale in {"ru", "en"}:
        return user_locale
    candidates = []
    for index, entry in enumerate((accept_language or "").split(",")):
        language, *options = entry.strip().lower().split(";")
        locale = language.split("-", 1)[0]
        quality = 1.0
        try:
            for option in options:
                name, _, value = option.strip().partition("=")
                if name == "q":
                    quality = float(value)
        except ValueError:
            continue
        if locale in {"ru", "en"} and 0 < quality <= 1:
            candidates.append((quality, -index, locale))
    return max(candidates)[2] if candidates else "ru"


@lru_cache(maxsize=2)
def catalog(locale: str) -> dict[str, str]:
    return json.loads((CATALOG_DIR / f"server.{locale}.json").read_text(encoding="utf-8"))


EMPTY_VALUE = "—"
_EN_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


@lru_cache(maxsize=1)
def _date_params() -> dict[str, dict[str, str]]:
    return json.loads((CATALOG_DIR / "date-params.json").read_text(encoding="utf-8"))


def format_date_time(value: Any, locale: str, *, with_time: bool = True, keep_offset: bool = False) -> str:
    """Format presentation only; server instants use UTC, calendar days never shift."""
    if not isinstance(value, str) or not value.strip():
        return EMPTY_VALUE
    try:
        if with_time:
            instant = datetime.fromisoformat(value)
            if instant.tzinfo is None:
                return EMPTY_VALUE  # An unzoned value does not establish an instant.
            if not keep_offset:
                instant = instant.astimezone(UTC)
        else:
            instant = date.fromisoformat(value)
    except (ValueError, OverflowError):
        return EMPTY_VALUE
    if locale == "en":
        text = f"{_EN_MONTHS[instant.month - 1]} {instant.day}, {instant.year}"
        if with_time:
            text += f", {instant.hour % 12 or 12}:{instant.minute:02d} {'AM' if instant.hour < 12 else 'PM'}"
        return text
    text = f"{instant.day:02d}.{instant.month:02d}.{instant.year:04d}"
    return text + (f", {instant.hour:02d}:{instant.minute:02d}" if with_time else "")


def message(code: str, params: Mapping[str, str | int | float] | None = None, *, locale: str = "ru") -> dict[str, Any]:
    values = dict(params or {})
    locale = select_locale(user_locale=locale)
    template = catalog(locale)[code]
    display_values = dict(values)
    if code == 'events.catalog_title' and locale in values:
        display_values['label'] = values[locale]
    for name, kind in _date_params().get(code, {}).items():
        if name in values:
            display_values[name] = format_date_time(values[name], locale, with_time=kind != "date", keep_offset=kind == "local_datetime")
    text = re.sub(r"\{(\w+)\}", lambda match: str(display_values.get(match[1], match[0])), template)
    return {"code": code, "params": values, "text": text}


def localize_presentation(value: Any, locale: str) -> Any:
    """Resolve explicitly coded presentation fields, preserving source observations."""
    if isinstance(value, list):
        return [localize_presentation(item, locale) for item in value]
    if not isinstance(value, dict):
        return value
    localized = {key: localize_presentation(item, locale) for key, item in value.items()}
    envelopes = value.get("presentation_messages")
    if isinstance(envelopes, dict):
        resolved = {}
        for field, envelope in envelopes.items():
            if isinstance(envelope, dict) and isinstance(envelope.get("code"), str) and envelope["code"] in catalog(locale):
                resolved[field] = message(envelope["code"], envelope.get("params"), locale=locale)
                localized[field] = resolved[field]["text"]
            else:
                resolved[field] = envelope
        localized["presentation_messages"] = resolved
    for field in ("status_message", "severity_message"):
        envelope = value.get(field)
        if isinstance(envelope, dict) and isinstance(envelope.get("code"), str) and envelope["code"] in catalog(locale):
            localized[field] = message(envelope["code"], envelope.get("params"), locale=locale)
    if isinstance(value.get("labels_messages"), dict):
        localized["labels_messages"] = {key: message(item["code"], locale=locale) for key, item in value["labels_messages"].items()}
        # Labels without a code (source values) stay as they are.
        localized["labels"] = {**(value["labels"] if isinstance(value.get("labels"), dict) else {}),
                               **{key: item["text"] for key, item in localized["labels_messages"].items()}}
    if isinstance(value.get("entity_messages"), list):
        entities = [message(item["code"], item.get("params"), locale=locale) if isinstance(item, dict) and item.get("code") in catalog(locale) else item
                    for item in value["entity_messages"]]
        localized["entity_messages"] = entities
        localized["entity_text"] = ", ".join(item["text"] if isinstance(item, dict) else str(item) for item in entities) or None
    return localized


def _case_status_messages(value: Any, locale: str) -> Any:
    if isinstance(value, list):
        return [_case_status_messages(item, locale) for item in value]
    if not isinstance(value, dict):
        return value
    # Only case DTOs and their wrappers; notes, evidence and audit payloads are data.
    localized = dict(value)
    if isinstance(value.get("status"), str) and "id" in value:
        code = f"investigations.caseStatus.{value['status']}"
        if code in catalog(locale):
            localized["status_message"] = message(code, locale=locale)
    for field in ("items", "item", "linked_case"):
        if field in value:
            localized[field] = _case_status_messages(value[field], locale)
    return localized


def _report_metadata(value: dict, locale: str, prefix: str) -> dict:
    """Code only declared report vocabulary, using stable field/action identifiers."""
    localized = dict(value)
    envelopes = dict(value.get("presentation_messages") or {})
    for field in ("title", "description", "label", "note", "question", "denominator", "freshness_expectation", "caption"):
        keyed = field == "label" and any(part in prefix for part in (".row_links.", ".options.", ".series."))
        code = prefix if keyed else f"{prefix}.{field}"
        if isinstance(value.get(field), str) and code in catalog(locale):
            envelopes[field] = message(code, locale=locale)
            localized[field] = envelopes[field]["text"]
    if envelopes:
        localized["presentation_messages"] = envelopes
    if isinstance(value.get("labels"), dict):
        known = {key: f"{prefix}.labels.{key}" for key in value["labels"] if f"{prefix}.labels.{key}" in catalog(locale)}
        if known:
            messages = {key: message(code, locale=locale) for key, code in known.items()}
            localized["labels_messages"] = messages
            localized["labels"] = {key: messages[key]["text"] if key in messages else text for key, text in value["labels"].items()}
    for field, identifier in (("columns", "key"), ("params", "key"), ("metrics", "key"), ("options", "value"), ("row_links", "href"),
                              ("views", "key"), ("series", "path")):
        if isinstance(value.get(field), list):
            localized[field] = [_report_metadata(item, locale, f"{prefix}.{field}.{item[identifier]}")
                                if isinstance(item, dict) and isinstance(item.get(identifier), str) else item for item in value[field]]
    if isinstance(value.get("filter_options"), dict):
        localized["filter_options"] = {param: [_report_metadata(item, locale, f"{prefix}.params.{param}.options.{item['value']}")
                                               if isinstance(item, dict) and isinstance(item.get("value"), str) else item for item in items]
                                       if isinstance(items, list) else items for param, items in value["filter_options"].items()}
    if isinstance(value.get("detail"), dict):
        localized["detail"] = _report_metadata(value["detail"], locale, f"{prefix}.detail")
    if isinstance(value.get("intent"), dict):
        localized["intent"] = _report_metadata(value["intent"], locale, f"{prefix}.intent")
    if isinstance(value.get("presets"), list) and all(isinstance(item, dict) and isinstance(item.get("params"), dict) for item in value["presets"]):
        localized["presets"] = [dict(item) for item in value["presets"]]
        for item in localized["presets"]:
            code = f"{prefix}.presets.{json.dumps(item['params'], sort_keys=True, separators=(',', ':'))}"
            if code in catalog(locale):
                item["presentation_messages"] = {"label": message(code, locale=locale)}
                item["label"] = item["presentation_messages"]["label"]["text"]
    return localized


def _limitation_params(payload: dict) -> dict[str, Any]:
    """Counters the report's own coverage supplies to its limitation wording."""
    coverage = payload.get("coverage") if isinstance(payload.get("coverage"), dict) else {}
    policy = coverage.get("hygiene_policy") if isinstance(coverage.get("hygiene_policy"), dict) else {}
    params: dict[str, Any] = {}
    if policy:
        params.update(password_days=policy.get("password_age", ""), inactivity_days=policy.get("inactivity", ""))
    if payload.get("report_key") == "ad.users.v2":
        params.update(count=coverage.get("unknown_accounts", ""), password_age=policy.get("password_age", ""), inactivity=policy.get("inactivity", ""))
    return params


def _report_limitations(items: Any, locale: str, prefix: str, shared: Mapping[str, Any]) -> Any:
    """Code declared limitations; wording that cannot be completed from known counters keeps its source text."""
    if not isinstance(items, list):
        return items
    coded = []
    for item in items:
        code = f"{prefix}.limitations.{item.get('code')}" if isinstance(item, dict) else ""
        if code in catalog(locale):
            own = item["params"] if isinstance(item.get("params"), dict) else {}
            params = {**shared, **{key: "" if val is None else val for key, val in own.items()}}
            if set(re.findall(r"\{(\w+)\}", catalog(locale)[code])) <= set(params):
                envelope = message(code, params, locale=locale)
                item = {**item, "text": envelope["text"], "presentation_messages": {**item.get("presentation_messages", {}), "text": envelope}}
        coded.append(item)
    return coded


def _report_result_limitations(payload: dict, locale: str, prefix: str) -> dict:
    shared = _limitation_params(payload)
    localized = dict(payload)
    if "limitations" in payload:
        localized["limitations"] = _report_limitations(payload["limitations"], locale, prefix, shared)
    if isinstance(payload.get("state_details"), dict) and "limitations" in payload["state_details"]:
        localized["state_details"] = {**payload["state_details"], "limitations": _report_limitations(payload["state_details"]["limitations"], locale, prefix, shared)}
    if isinstance(payload.get("branches"), dict):
        localized["branches"] = {name: {**branch, "limitations": _report_limitations(branch.get("limitations"), locale, prefix, shared)}
                                 if isinstance(branch, dict) and "limitations" in branch else branch for name, branch in payload["branches"].items()}
    return localized


@lru_cache(maxsize=256)
def _builtin_message_codes(code: str) -> tuple[str, ...]:
    return (code, *sorted(key for key in catalog("ru") if key.startswith(code + ".alias.")))


def _builtin_field_message(code: str, value: str, locale: str) -> dict | None:
    if code not in catalog("ru") or code not in catalog("en"):
        return None
    for source_locale in ("ru", "en"):
        template = catalog(source_locale).get(code)
        if template is None:
            continue
        if "{domain}" not in template:
            if value == template:
                return message(code, locale=locale)
            continue
        # The registered system wording surrounds an opaque observed DNS value.
        if template.count("{domain}") != 1:
            continue
        before, after = template.split("{domain}")
        if value.startswith(before) and value.endswith(after):
            domain = value[len(before):len(value) - len(after) if after else None]
            if re.fullmatch(r"(?=.{1,253}\Z)[\w-]+(?:\.[\w-]+)+\.?", domain):
                return message(code, {"domain": domain}, locale=locale)
    return None


def _builtin_fields(value: dict, identity: str, prefix: str, fields: dict[str, str], locale: str) -> dict:
    """Only registered IDs with unchanged product wording receive message codes."""
    key = value.get(identity)
    if not isinstance(key, str):
        return value
    localized = dict(value)
    envelopes = dict(value["presentation_messages"]) if isinstance(value.get("presentation_messages"), dict) else {}
    for field, suffix in fields.items():
        code = f"access.builtin.{prefix}.{key}.{suffix}"
        text = value.get(field)
        if code not in catalog("ru") or code not in catalog("en") or not isinstance(text, str):
            continue
        for candidate in _builtin_message_codes(code):
            envelope = _builtin_field_message(candidate, text, locale)
            # Migration 183 uses the exact file-audit report ID as its default title.
            if envelope is None and prefix == "report" and suffix == "name" and key.startswith("file-audit.") and text == key:
                envelope = message(code, locale=locale)
            if envelope is not None:
                envelopes[field] = envelope
                localized[field] = envelope["text"]
                break
    if envelopes:
        localized["presentation_messages"] = envelopes
    return localized


def _builtin_access_metadata(payload: dict, locale: str, path: str) -> dict:
    """Visit declared metadata slots, never report rows, source facts or audit reasons."""
    localized = dict(payload)

    def packages(field: str, identity: str, labels: dict[str, str]) -> None:
        if isinstance(payload.get(field), list):
            localized[field] = [_builtin_fields(item, identity, "package", labels, locale) if isinstance(item, dict) else item
                                for item in payload[field]]

    def report(value: dict, *, version_key: str = "version", name_field: str = "name", presentation_only: bool = False) -> dict:
        # Later owner-authored versions and changed descriptions are source data.
        if type(value.get(version_key)) is not int or value[version_key] != 1:
            return value
        result = _builtin_fields(value, "report_key", "report", {name_field: "name", "purpose": "purpose"}, locale)
        if presentation_only:
            # Editing forms and save/preview fingerprints consume the raw values.
            result = {**result, **{field: value[field] for field in (name_field, "purpose") if field in value}}
        return result

    report_list = None
    report_options = {}
    if path == "/api/v1/access/subjects":
        packages("packages", "package_key", {"name": "name", "description": "description"})
        packages("package_assignments", "package_key", {"package_name": "name"})
    elif path in {"/api/v1/access/effective", "/api/v1/workspace"}:
        packages("packages", "key", {"name": "name"})
        report_list = "reports"
    elif path in {"/api/v1/access/grant-options", "/api/v1/reports/catalog"}:
        report_list = "items"
    elif path == "/api/v1/reports/definitions":
        report_list = "items"
        report_options = {"presentation_only": True}
    elif path == "/api/v1/ui/bootstrap":
        packages("packages", "key", {"name": "name"})
    elif path == "/api/v1/access/report-requests" or re.fullmatch(r"/api/v1/access/report-requests/\d+/decision", path):
        report_list = "items"
        report_options = {"version_key": "report_version", "name_field": "report_name"}
        if isinstance(payload.get("item"), dict):
            localized["item"] = report(payload["item"], **report_options)
    elif re.fullmatch(r"/api/v1/reports/[^/]+/access-summary", path):
        packages("packages", "package_key", {"name": "name"})
    elif re.fullmatch(r"/api/v1/reports/[^/]+/(?:data|access-trace)", path) and isinstance(payload.get("report"), dict):
        localized["report"] = report(payload["report"])
    if report_list and isinstance(payload.get(report_list), list):
        localized[report_list] = [report(item, **report_options) if isinstance(item, dict) else item for item in payload[report_list]]
    return localized


def response_messages(payload: dict, accept_language: str | None = None, *, login: bool = False, report: bool = False, investigation: bool = False, request_path: str = "") -> dict:
    """Keep legacy error/state fields and add localized catalog envelopes."""
    localized = dict(payload)
    locale = select_locale(accept_language)
    localized = _builtin_access_metadata(localized, locale, request_path)
    error = payload.get("error")
    code = AUTH_ERRORS.get(error) if isinstance(error, str) else None
    if isinstance(error, str) and error in WORKSTATION_ERRORS:
        code = WORKSTATION_ERRORS[error]
    if isinstance(error, str) and error in {"plugin_settings_not_found", "plugin_settings_unavailable", "invalid_plugin_setting_value"}:
        code = error
    if login and isinstance(error, str) and error in LOGIN_INPUT_ERRORS:
        code = "login.error.generic"
    if login and isinstance(error, str) and error in LOGIN_SERVICE_ERRORS:
        code = "login.error.unavailable"
    if error == "gpo_snapshot_unavailable":
        code = "reports.renderer.error_gpo_snapshot"
    if code:
        params = {}
        if error == "login_temporarily_locked":
            delay = payload.get("retry_after_seconds")
            if isinstance(delay, (int, float)) and math.isfinite(delay) and delay > 0:
                params = {"seconds": math.ceil(delay)}
            else:
                code = "login.error.locked"
        localized["message"] = message(code, params, locale=locale)
    state = payload.get("state")
    if (report or payload.get("contract_id") == "sli.report-result.v2") and isinstance(state, str) and state in REPORT_STATES:
        localized["state_message"] = message(f"reports.state.{state}", locale=locale)
    coded = next((name for name in (payload.get("report_key"), payload.get("key")) if isinstance(name, str) and name in CODED_REPORTS), None)
    if coded:
        localized = localize_presentation(_report_result_limitations(_report_metadata(localized, locale, f"reports.v2.{coded}"), locale, f"reports.v2.{coded}"), locale)
    if payload.get("report_key") == "file-audit.overview":
        localized = _report_result_limitations(localized, locale, "reports.v2.file-audit.overview")
    if coded == "ad.computers.v6" and isinstance(localized.get("items"), list):
        # Inventory aggregates follow explicitly coded reason labels. Other
        # rows (checks/changes), unknown reasons and source values stay intact.
        for row in localized["items"]:
            reasons = row.get("reasons") if isinstance(row, dict) else None
            if isinstance(reasons, list) and any(
                isinstance(reason, dict) and "label" in (reason.get("presentation_messages") or {})
                for reason in reasons
            ):
                row["reason_text"] = ", ".join(str(reason.get("label")) for reason in reasons) or None
    if coded == "security.problems" and isinstance(localized.get("items"), list):
        localized["items"] = [{**item, "linked_case": _case_status_messages(item["linked_case"], locale)} if "linked_case" in item else item for item in localized["items"]]
    if payload.get("contract_id") == "sli.report-catalog.v2":
        localized["items"] = [_report_metadata(item, locale, f"reports.v2.{item['key']}") if isinstance(item.get("key"), str) and item["key"] in CODED_REPORTS else item
                              for item in payload.get("items", [])]
    if investigation:
        localized = _case_status_messages(localized, locale)
    return localized
