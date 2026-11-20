from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_PATHS = (
    "/",
    "/app/",
    "/api/health",
    "/api/runtime/status",
    "/api/dashboard/snapshot?force=1",
    "/api/dashboard/snapshot",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def probe_url(base_url: str, path: str, *, timeout: float) -> dict[str, Any]:
    url = base_url.rstrip("/") + path
    started = time.perf_counter()
    try:
        request = Request(url, headers={"Accept": "application/json,text/html,*/*", "User-Agent": "adlog-dashboard-probe/1"})
        with urlopen(request, timeout=timeout) as response:
            body = response.read()
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            content_type = str(response.headers.get("Content-Type") or "")
            item: dict[str, Any] = {
                "path": path,
                "url": url,
                "status": "ok",
                "http_status": int(response.status),
                "duration_ms": elapsed_ms,
                "bytes": len(body),
                "content_type": content_type,
            }
            if "json" in content_type or path.startswith("/api/"):
                try:
                    payload = json.loads(body.decode("utf-8"))
                    item["json_status"] = payload.get("status") if isinstance(payload, dict) else None
                    if path.startswith("/api/dashboard/snapshot") and isinstance(payload, dict):
                        item["snapshot_diagnostics"] = payload.get("diagnostics") or {}
                        item["snapshot_sections"] = sorted(k for k in payload if k not in {"diagnostics"})
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    item["status"] = "failed"
                    item["error"] = f"invalid_json: {exc}"
            return item
    except HTTPError as exc:
        return {
            "path": path,
            "url": url,
            "status": "failed",
            "http_status": int(exc.code),
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "error": str(exc),
        }
    except (URLError, TimeoutError, OSError) as exc:
        return {
            "path": path,
            "url": url,
            "status": "failed",
            "http_status": None,
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }


def run_probe(base_url: str, *, timeout: float = 60.0, wait_health_seconds: float = 30.0) -> dict[str, Any]:
    started = time.perf_counter()
    deadline = time.monotonic() + max(0.0, wait_health_seconds)
    health_attempts: list[dict[str, Any]] = []
    while True:
        health = probe_url(base_url, "/api/health", timeout=min(timeout, 5.0))
        health_attempts.append(health)
        if health.get("status") == "ok" and health.get("http_status") == 200:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(1.0)

    results = [probe_url(base_url, path, timeout=timeout) for path in DEFAULT_PATHS]
    failures = [item for item in results if item.get("status") != "ok" or item.get("http_status") != 200]
    forced = next((item for item in results if item.get("path") == "/api/dashboard/snapshot?force=1"), {})
    cached = next((item for item in results if item.get("path") == "/api/dashboard/snapshot"), {})
    forced_ms = int(forced.get("duration_ms") or 0)
    cached_ms = int(cached.get("duration_ms") or 0)
    forced_diagnostics = forced.get("snapshot_diagnostics") or {}
    component_timings = forced_diagnostics.get("components_ms") or {}
    slowest_components = sorted(
        ({"name": name, "duration_ms": int(duration or 0)} for name, duration in component_timings.items()),
        key=lambda item: item["duration_ms"],
        reverse=True,
    )[:8]
    forced_target_ms = 10_000
    cached_target_ms = 100
    performance_status = "ok" if forced_ms <= forced_target_ms and cached_ms <= cached_target_ms else "warn"
    return {
        "package_type": "DASHBOARD_STARTUP_PROBE",
        "generated_at_utc": _utc_now(),
        "status": "failed" if failures else "ok",
        "base_url": base_url,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "health_attempts": len(health_attempts),
        "health_wait_ms": sum(int(item.get("duration_ms") or 0) for item in health_attempts),
        "results": results,
        "summary": {
            "failures": len(failures),
            "forced_snapshot_ms": forced_ms,
            "cached_snapshot_ms": cached_ms,
            "cache_speedup_ratio": round(forced_ms / cached_ms, 2) if cached_ms > 0 else None,
            "main_page_ready": not failures,
            "performance_status": performance_status,
            "forced_snapshot_target_ms": forced_target_ms,
            "cached_snapshot_target_ms": cached_target_ms,
            "forced_snapshot_target_met": forced_ms <= forced_target_ms,
            "cached_snapshot_target_met": cached_ms <= cached_target_ms,
            "slowest_components": slowest_components,
            "snapshot_request_model": forced_diagnostics.get("request_model"),
            "snapshot_failures": forced_diagnostics.get("failures") or [],
        },
        "limitations": [
            "The probe measures HTTP readiness after an operator-controlled restart; it does not restart the server itself.",
            "Browser rendering/network waterfall is approximated by the main HTML and dashboard snapshot requests.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure server startup and main dashboard API latency.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--wait-health-seconds", type=float, default=30.0)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    result = run_probe(args.base_url, timeout=max(1.0, args.timeout), wait_health_seconds=max(0.0, args.wait_health_seconds))
    text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
