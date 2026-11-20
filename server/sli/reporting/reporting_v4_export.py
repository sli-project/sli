"""Split out of ``server.sli.reporting.reporting_v4`` (plan 7.2b).

Module-level names of ``reporting_v4`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.reporting.reporting_v4 as _src


def _workspace_focus_metrics(
    principal: _src.Mapping[str, _src.Any] | None,
    access: _src.Mapping[str, _src.Any],
    reports: _src.Sequence[_src.Mapping[str, _src.Any]],
) -> list[dict[str, _src.Any]]:
    """Resolve only publisher-declared metrics from the user's current report grants."""
    focus: list[dict[str, _src.Any]] = []
    for report in reports:
        try:
            definitions = _src._dashboard_metric_definitions(report.get("dashboard_metrics"))
        except ValueError:
            continue
        selected = {str(item) for item in report.get("selected_optional_metric_keys") or []}
        configured = bool(report.get("focus_preference_configured"))
        visible = [
            item for item in definitions
            if item["kind"] == "required"
            or (item["key"] in selected)
            or (not configured and item.get("default_selected"))
        ]
        if not visible:
            continue
        try:
            payload = _src.execute_report(
                str(report["report_key"]), principal, limit=1, access=access,
            )
        except (PermissionError, ValueError, RuntimeError):
            payload = {"state": "unavailable", "items": [], "summary": {}}
        for metric in visible:
            value = _src._metric_value(payload, str(metric["value_path"]))
            freshness_path = str(metric.get("freshness_path") or "")
            focus.append({
                "key": str(metric["key"]),
                "label": str(metric["label"]),
                "caption": str(metric.get("caption") or ""),
                "kind": str(metric["kind"]),
                "value": value,
                "unit": metric.get("unit"),
                "state": _src._metric_state(payload),
                "freshness": _src._metric_value(payload, freshness_path) if freshness_path else None,
                "source": str(report["dataset_key"]),
                "priority": int(metric["priority"]),
                "report_key": str(report["report_key"]),
                "target_path": str(metric["target_path"]),
                "filters": dict(metric.get("filters") or {}),
                "icon": str(metric["icon"]),
                "tone": str(metric["tone"]),
            })
    return sorted(
        focus,
        key=lambda item: (item["priority"], item["label"].casefold(), item["key"]),
    )


def export_report_csv_document(
    report_key: str, principal: _src.Mapping[str, _src.Any] | None, *,
    fields: _src.Sequence[str] | None = None, query_filters: _src.Mapping[str, _src.Any] | None = None,
    access: _src.Mapping[str, _src.Any] | None = None,
) -> dict[str, _src.Any]:
    """Render the authorized report slice as CSV **plus** its truncation facts.

    The export is bounded by `REPORT_LIMIT_MAX`.  Previously the caller received
    only the CSV text, so a 200-row slice of a larger result was indistinguishable
    from a complete export — a silent data loss in an audit deliverable.  The
    CSV payload itself stays pure (no synthetic marker rows that would corrupt
    parsing); the truncation facts are returned separately so the transport can
    carry them in the filename and headers.
    """
    data = _src.execute_report(
        report_key, principal, limit=_src.REPORT_LIMIT_MAX, fields=fields,
        action="export", query_filters=query_filters, access=access,
    )
    output = _src.io.StringIO(newline="")
    writer = _src.csv.writer(output, lineterminator="\r\n")
    field_defs = list(data["fields"])
    writer.writerow([_src._csv_cell(field.get("label") or field["key"]) for field in field_defs])
    rows = list(data["items"])
    for row in rows:
        writer.writerow([_src._csv_cell(row.get(str(field["key"]))) for field in field_defs])
    has_more = bool(data.get("has_more"))
    total_count = ((data.get("limits") or {}) if isinstance(data.get("limits"), _src.Mapping) else {}).get("total_count")
    total_exceeds_export = (
        isinstance(total_count, int)
        and not isinstance(total_count, bool)
        and total_count > len(rows)
    )
    return {
        "csv": output.getvalue(),
        "report_key": report_key,
        "row_count": len(rows),
        "row_limit": _src.REPORT_LIMIT_MAX,
        "has_more": has_more,
        # `truncated` is the honest operator-facing fact: the file does not
        # contain every authorized row.
        "truncated": has_more or total_exceeds_export,
        "total_count": total_count if total_count is not None else "not_calculated",
        "next_cursor": data.get("next_cursor"),
    }


def export_report_csv(
    report_key: str, principal: _src.Mapping[str, _src.Any] | None, *,
    fields: _src.Sequence[str] | None = None, query_filters: _src.Mapping[str, _src.Any] | None = None,
    access: _src.Mapping[str, _src.Any] | None = None,
) -> str:
    """Backward-compatible wrapper returning only the CSV text."""
    return str(_src.export_report_csv_document(
        report_key, principal, fields=fields, query_filters=query_filters, access=access,
    )["csv"])
