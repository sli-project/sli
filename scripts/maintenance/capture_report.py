#!/usr/bin/env python3
"""Capture a report/API snapshot for developer analysis.

This tool can work offline for built-in report names by calling project renderers,
or against a running HTTP server via --url.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.maintenance.bundle_common import (  # noqa: E402
    LOG_DIR,
    REPORT_CAPTURE_DIR,
    audit_action,
    basic_project_snapshot,
    tail_lines,
    timestamp,
    write_json,
    write_text,
    zip_dir,
)

REPORTS: dict[str, tuple[str, str]] = {
    "collector-health": ("/reports/collector-health.html", "/api/collector/health"),
    "system-health": ("/reports/system-health.html", "/api/system/health"),
    "findings": ("/reports/findings.html", "/api/findings"),
    "investigation": ("/reports/investigation.html", "/api/investigation/workspace"),
    "security-events-monitor": ("/reports/security-events-monitor.html", "/api/security/events-monitor"),
    "role-overview": ("/reports/role-overview.html", "/api/role-views"),
    "jobs": ("/", "/api/jobs"),
}


def _fetch(url: str, timeout: int = 15) -> dict[str, object]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            content_type = response.headers.get("Content-Type", "")
            body = response.read().decode("utf-8", errors="replace")
            return {"status": "ok", "url": url, "content_type": content_type, "body": body, "code": response.status}
    except Exception as exc:
        return {"status": "failed", "url": url, "error_type": type(exc).__name__, "error": str(exc)}


def _offline_capture(name: str) -> tuple[str, object]:
    if name == "collector-health":
        from server.sli.sources.collector_health import get_collector_health, render_collector_health_report
        data = get_collector_health()
        return render_collector_health_report(data), data
    if name == "system-health":
        from server.sli.ops.system_health import get_system_health, render_system_health_report
        data = get_system_health()
        return render_system_health_report(data), data
    if name == "findings":
        from server.sli.semantic.findings import get_findings_data, render_findings_report
        data = get_findings_data()
        return render_findings_report(data), data
    if name == "investigation":
        from server.sli.semantic.investigation import get_investigation_workspace_data, render_investigation_workspace_report
        data = get_investigation_workspace_data()
        return render_investigation_workspace_report(data), data
    if name == "security-events-monitor":
        from server.sli.events.security_events_monitor import get_security_events_monitor_data, render_security_events_monitor_report
        data = get_security_events_monitor_data()
        return render_security_events_monitor_report(data), data
    if name == "role-overview":
        from server.sli.access.role_views import get_role_views_data, render_role_overview_report
        data = get_role_views_data()
        return render_role_overview_report(data), data
    raise ValueError(f"Offline capture is not implemented for report name: {name}")


def build_report_capture(*, name: str, out_dir: Path = REPORT_CAPTURE_DIR, base_url: str = "http://127.0.0.1:8080", url: str | None = None, role: str | None = None, offline: bool = True) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    operation_id = f"OP-{timestamp()}-capture-report"
    safe_name = name.replace("/", "-").replace("\\", "-").replace("#", "")
    with __import__("tempfile").TemporaryDirectory(prefix="adlog-report-capture-") as tmp:
        staging = Path(tmp) / "adlog-report-capture"
        staging.mkdir(parents=True, exist_ok=True)
        html_status = "not_collected"
        api_status = "not_collected"
        if url:
            fetched = _fetch(url)
            html_status = str(fetched.get("status"))
            write_json(staging / "url_fetch.json", fetched)
            if fetched.get("body"):
                write_text(staging / "report.html", str(fetched["body"]))
        elif offline and name in REPORTS and name != "jobs":
            try:
                html_body, data = _offline_capture(name)
                html_status = "ok"
                api_status = "ok"
                write_text(staging / "report.html", html_body)
                write_json(staging / "api_response.json", data)
            except Exception as exc:
                html_status = "failed"
                write_json(staging / "offline_capture_error.json", {"error_type": type(exc).__name__, "error": str(exc)})
        elif name in REPORTS:
            report_path, api_path = REPORTS[name]
            report = _fetch(urljoin(base_url, report_path))
            api = _fetch(urljoin(base_url, api_path))
            html_status = str(report.get("status"))
            api_status = str(api.get("status"))
            write_json(staging / "report_fetch.json", report)
            write_json(staging / "api_fetch.json", api)
            if report.get("body"):
                write_text(staging / "report.html", str(report["body"]))
            if api.get("body"):
                try:
                    write_json(staging / "api_response.json", json.loads(str(api["body"])))
                except Exception:
                    write_text(staging / "api_response.txt", str(api["body"]))
        else:
            raise ValueError(f"Unknown report name: {name}. Known: {', '.join(sorted(REPORTS))}")

        write_text(staging / "logs_tail.txt", tail_lines(LOG_DIR / "adlog-monitor.log", 800))
        write_json(
            staging / "MANIFEST.json",
            {
                **basic_project_snapshot(),
                "package_type": "REPORT_CAPTURE",
                "operation_id": operation_id,
                "name": name,
                "role": role,
                "url": url,
                "base_url": base_url,
                "html_status": html_status,
                "api_status": api_status,
                "screenshot_included": False,
                "note": "Screenshot capture is intentionally optional; this package includes HTML/API/log context.",
            },
        )
        write_text(
            staging / "README_FOR_DEVELOPER.md",
            f"# Report capture: {name}\n\n"
            f"Role: {role or 'not specified'}\n\n"
            "Use report.html, api_response.json and logs_tail.txt to reproduce UI/report issues.\n",
        )
        zip_path = out_dir / f"adlog-report-capture-{safe_name}-{timestamp()}.zip"
        zip_dir(staging, zip_path)
    result = {"status": "ok", "operation_id": operation_id, "zip_path": str(zip_path), "html_status": html_status, "api_status": api_status}
    audit_action("capture_report", "completed", operation_id=operation_id, name=name, zip_path=str(zip_path), html_status=html_status, api_status=api_status)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture report/API/log context for developer analysis.")
    parser.add_argument("--name", default="collector-health", choices=sorted(REPORTS.keys()))
    parser.add_argument("--out", type=Path, default=REPORT_CAPTURE_DIR)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--url", help="Capture exact URL instead of known report")
    parser.add_argument("--role", help="Expected UI role: security, it, technical")
    parser.add_argument("--http", action="store_true", help="Fetch from running server instead of offline renderer")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = build_report_capture(name=args.name, out_dir=args.out, base_url=args.base_url, url=args.url, role=args.role, offline=not args.http)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Report capture created: {result['zip_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
