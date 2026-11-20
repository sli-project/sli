"""Registry-owned compact Home contributions share the request's read budget."""
from __future__ import annotations

import logging

from server.sli.core.database import QueryTimeoutError
from server.sli.reporting.home_trends import compare, completed_windows, numeric
from server.sli.reporting.read_timeout import remaining_read_ms
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.registry import get_report

_LOG = logging.getLogger(__name__)
READABLE = {"ok", "empty", "partial", "stale", "processing"}


def read_pool(items, measured, access, authorization, context, now):
    from server.sli.reporting.home_summary import _context_filters, _href, _read

    declarations = sorted(((item, entry) for item in items for entry in get_report(item["key"]).home_contributions),
                          key=lambda pair: (pair[1].order, pair[1].key))
    kpis, readers, attention = [], [], []
    for item, entry in declarations:
        definition = get_report(item["key"])
        windows = None
        data = {"state": "denied"}
        try:
            if not item["executable"] or not ReportAccess(definition, access).fields_allowed(entry.required_fields):
                raise PermissionError("report_access_denied")
            if entry.period_kind == "observations":
                windows = completed_windows(context, now)
            if entry.reader is None and item["key"] in measured:
                data = measured[item["key"]]
            else:
                remaining_read_ms()
                data = _read(definition, access, authorization, context=context, contribution=entry, windows=windows)
        except PermissionError:
            data = {"state": "denied"}
        except QueryTimeoutError:
            data = {"state": "error", "reason": "read_timeout"}
        except ValueError as exc:
            incomplete = str(exc) == "home_window_incomplete"
            data = {"state": "partial" if incomplete else "error",
                    "reason": "home_window_incomplete" if incomplete else "reader_failed"}
        except Exception:  # noqa: BLE001 - optional reader failures never disclose source identifiers
            _LOG.warning("Home contribution reader unavailable")
            data = {"state": "error", "reason": "reader_failed"}
        filters = _context_filters(context, item["key"])
        if windows:
            filters.update(period="custom", **{"from": windows[0]["from_utc"], "to": windows[0]["to_utc"]})
        filters.update(entry.filters)
        href = _href(item["key"], filters)
        metric = _kpi(item, entry, data, href, context, windows)
        kpis.append(metric)
        if entry.reader is not None:
            readers.append({"key": item["key"], "contribution_key": entry.key, "title": item["title"], "href": href, "state": data["state"],
                            "reason": data.get("reason"), "observed_at_utc": metric["observed_at_utc"],
                            "limitation": next((note["text"] for note in data.get("limitations", []) if note.get("text")), None),
                            "period_kind": entry.period_kind, "scope": metric["scope"],
                            "message_code": metric["message_code"], "health": entry.health})
        if entry.attention and data["state"] in READABLE:
            try:
                attention.extend(entry.attention(data, href))
            except Exception:  # noqa: BLE001 - an optional attention hook cannot discard the other readers
                _LOG.warning("Home contribution attention unavailable")
    return kpis, readers, attention


def _kpi(report, entry, data, href, context, windows):
    metric = next((metric for metric in data.get("metrics", []) if metric.get("key") == entry.metric_key), {})
    state = data["state"]
    value = metric.get("value")
    if state not in READABLE or not numeric(value) or (state == "partial" and not data.get("scope")):
        value = None
    coverage = data.get("coverage") or {}
    metadata = {"scope": data.get("scope"), "time_zone": context["time_zone"], "unit": entry.unit_code,
                "definition_version": entry.definition_version}
    current = {**metadata, "value": value, "coverage": data.get("comparison_coverage", coverage), "window": windows[0] if windows else None}
    previous = {**metadata, "value": metric.get("previous_value"), "coverage": data.get("previous_coverage"),
                "window": windows[1] if windows else None}
    comparison = compare(current, previous, meaning=entry.meaning)
    message = {"plugin_disabled": "home.plugin.disabled", "plugin_state_unknown": "home.plugin.unknown",
               "home_window_incomplete": "home.comparison.incomplete"}.get(data.get("reason"), f"home.state.{state}")
    return {"key": entry.key, "report_key": report["key"], "label_code": entry.label_code,
            "unit_code": entry.unit_code, "value": value, "state": state, "message_code": message,
            "href": href if value is not None else None, "period_kind": entry.period_kind,
            "window": windows[0] if windows else None, "scope": data.get("scope") if state != "denied" else None,
            "observed_at_utc": coverage.get("observed_at_utc") if state != "denied" else None,
            "definition_version": entry.definition_version, "comparison": comparison}
