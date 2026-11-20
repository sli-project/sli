from __future__ import annotations

import copy
import logging
import os
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from typing import Any, Callable

from server.sli.ai.ai_reports import list_ai_runs
from server.sli.sources.collector_health import get_collector_health
from server.sli.reporting.dashboard_fast import get_dashboard_entity_summary, get_dashboard_event_summary
from server.sli.core.database import active_backend, get_sources
from server.sli.semantic.findings import get_findings_dashboard_data
from server.sli.ops.logging_config import log_event
from server.sli.reporting.reports import list_reports
from server.sli.access.role_views import get_role_views_data
from server.sli.storage.runtime_storage import StorageRouteConsumer, resolve_storage_route
from server.sli.storage.storage_v2_transition_controller import CutoverAuthorization
from server.jobs.collector import (
    get_collection_runtime_status,
    get_scheduler_runtime_status,
    list_jobs,
)

_CACHE_LOCK = threading.RLock()
_COMPONENT_FLIGHT_LOCK = threading.Lock()
_COMPONENT_FLIGHTS: dict[tuple[str, str], Future] = {}
_CACHE: dict[str, Any] = {
    "created_monotonic": 0.0,
    "payload": None,
    "refreshing": False,
    "last_error": None,
}


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _cache_ttl_seconds() -> float:
    return _env_float("ADLOG_DASHBOARD_CACHE_TTL_SECONDS", 5.0, minimum=1.0, maximum=60.0)


def _component_timeout_seconds() -> float:
    return _env_float("ADLOG_DASHBOARD_COMPONENT_TIMEOUT_SECONDS", 8.0, minimum=1.0, maximum=30.0)


def _snapshot_timeout_seconds() -> float:
    return _env_float("ADLOG_DASHBOARD_SNAPSHOT_TIMEOUT_SECONDS", 10.0, minimum=2.0, maximum=60.0)


def clear_dashboard_snapshot_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.update({"created_monotonic": 0.0, "payload": None, "refreshing": False, "last_error": None})


def _brief_system(collector: dict[str, Any]) -> dict[str, Any]:
    summary = collector.get("summary") or {}
    warning = int(summary.get("security_high") or 0) > 0 or int(summary.get("security_warn") or 0) > 0
    return {
        "status": "warn" if warning else "ok",
        "retention": {"candidates": 0, "source": "dashboard_brief"},
        "collector_summary": summary,
        "lightweight": True,
    }


def _runtime_payload() -> dict[str, Any]:
    backend = active_backend()
    return {
        "status": "ok",
        "active_backend": backend,
        "scheduler": get_scheduler_runtime_status(),
        "collection": get_collection_runtime_status(),
    }


def _archive_status_payload() -> dict[str, Any]:
    """Return the cursor state that backs the dashboard completeness cards."""
    backend = active_backend()
    if backend != "postgres":
        raise RuntimeError(f"Unsupported runtime DB backend {backend!r}: archive status is PostgreSQL-only")
    from server.sli.core.postgres_runtime_pipeline import get_archive_status_pg

    return get_archive_status_pg()


def _fallbacks() -> dict[str, Any]:
    return {
        "events_summary": {"total_events": 0, "by_channel": [], "top_event_ids": [], "by_server": [], "by_server_channel": [], "status": "unavailable"},
        "entity_summary": {"total_entities": 0, "total_event_entity_links": 0, "by_type": [], "by_role": [], "status": "unavailable"},
        "collector_health": {"summary": {}, "items": [], "post_collection": {"summary": {}, "items": []}, "status": "unavailable"},
        "sources": [],
        "findings": {"items": [], "summary": [], "status": "unavailable"},
        "ai_runs": {"items": [], "status": "unavailable"},
        "jobs": [],
        "reports": [],
        "archive_status": {"archive_start_utc": None, "channel_states": []},
    }


def _run_component(name: str, fn: Callable[[], Any]) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        value = fn()
        return {
            "name": name,
            "status": "ok",
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "value": value,
            "error": None,
        }
    except Exception as exc:
        return {
            "name": name,
            "status": "failed",
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "value": None,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _build_dashboard_snapshot(
    *, authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    # Validate the authority once before scheduling any component.
    resolve_storage_route(
        authorization=authorization, consumer=StorageRouteConsumer.DASHBOARD
    )
    kwargs = {"authorization": authorization} if authorization is not None else {}
    components: dict[str, Callable[[], Any]] = {
        "events_summary": lambda: get_dashboard_event_summary(**kwargs),
        "entity_summary": lambda: get_dashboard_entity_summary(**kwargs),
        "collector_health": lambda: get_collector_health(**kwargs),
        "sources": lambda: get_sources(**kwargs),
        "findings": lambda: get_findings_dashboard_data(**kwargs, limit=50),
        "ai_runs": lambda: list_ai_runs(**kwargs, limit=5),
        "jobs": list_jobs,
        "reports": list_reports,
        "archive_status": _archive_status_payload,
    }
    executor = ThreadPoolExecutor(max_workers=len(components), thread_name_prefix="dashboard")
    futures: dict[Future, str] = {}
    flight_keys: dict[Future, tuple[str, str]] = {}
    database_identity = "postgres"
    with _COMPONENT_FLIGHT_LOCK:
        for name, fn in components.items():
            key = (name, database_identity)
            future = _COMPONENT_FLIGHTS.get(key)
            if future is None:
                future = executor.submit(_run_component, name, fn)
                _COMPONENT_FLIGHTS[key] = future
            futures[future] = name
            flight_keys[future] = key
    done, pending = wait(futures, timeout=_snapshot_timeout_seconds())
    fallback = _fallbacks()
    results: dict[str, Any] = {}
    diagnostics: dict[str, dict[str, Any]] = {}
    failures: list[str] = []

    for future in done:
        name = futures[future]
        result = future.result()
        with _COMPONENT_FLIGHT_LOCK:
            if _COMPONENT_FLIGHTS.get(flight_keys[future]) is future:
                _COMPONENT_FLIGHTS.pop(flight_keys[future], None)
        diagnostics[name] = {
            "status": result["status"],
            "duration_ms": result["duration_ms"],
            "error": result["error"],
        }
        component_timeout_ms = int(_component_timeout_seconds() * 1000)
        if result["status"] == "ok" and int(result["duration_ms"] or 0) <= component_timeout_ms:
            results[name] = result["value"]
        else:
            if result["status"] == "ok":
                diagnostics[name]["status"] = "timeout"
                diagnostics[name]["error"] = "dashboard component exceeded its bounded execution target"
            results[name] = copy.deepcopy(fallback[name])
            failures.append(name)

    component_timeout_ms = int(_component_timeout_seconds() * 1000)
    for future in pending:
        name = futures[future]
        future.cancel()
        diagnostics[name] = {
            "status": "timeout",
            "duration_ms": component_timeout_ms,
            "error": "dashboard component exceeded the bounded snapshot window",
        }
        results[name] = copy.deepcopy(fallback[name])
        failures.append(name)

    # Running Python threads cannot be cancelled safely. Pending component
    # flights remain registered and are reused by later snapshots, preventing
    # duplicate work and unbounded thread growth until the original call ends.
    executor.shutdown(wait=False, cancel_futures=False)

    for name in components:
        results.setdefault(name, copy.deepcopy(fallback[name]))
        diagnostics.setdefault(name, {"status": "unavailable", "duration_ms": 0, "error": "component did not return"})

    collector = results["collector_health"]
    archive_status = results["archive_status"]
    system = _brief_system(collector)
    role_started = time.perf_counter()
    try:
        role_views = get_role_views_data(
            refresh_findings=False,
            authorization=authorization,
            consumer=StorageRouteConsumer.DASHBOARD,
            preloaded={
                "events": results["events_summary"],
                "entities": results["entity_summary"],
                "collector": collector,
                "system": system,
                "findings": results["findings"],
                "ai_runs": results["ai_runs"],
                "sources": results["sources"],
            },
        )
        diagnostics["role_views_compose"] = {
            "status": "ok",
            "duration_ms": int((time.perf_counter() - role_started) * 1000),
            "error": None,
        }
    except Exception as exc:
        role_views = {"views": [], "summary": {}, "status": "unavailable"}
        diagnostics["role_views_compose"] = {
            "status": "failed",
            "duration_ms": int((time.perf_counter() - role_started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }
        failures.append("role_views_compose")

    total_ms = int((time.perf_counter() - started) * 1000)
    status = "partial" if failures else "ok"
    timings = {name: int(item.get("duration_ms") or 0) for name, item in diagnostics.items()}
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "health": {
            "status": "warn" if failures else "ok",
            "service": "ad-log-reports",
            "mode": "real-readonly-archive-collector",
            "runtime": _runtime_payload(),
            "archive_start_utc": archive_status.get("archive_start_utc"),
            "archive_channel_states": archive_status.get("channel_states") or [],
            "archive_backend": archive_status.get("backend") or active_backend(),
        },
        "collector_health": collector,
        "sources": {"items": results["sources"]},
        "events_summary": results["events_summary"],
        "entity_summary": results["entity_summary"],
        "jobs": {"items": results["jobs"]},
        "reports": {"items": results["reports"]},
        "role_views": role_views,
        "diagnostics": {
            "cache_hit": False,
            "cache_age_ms": 0,
            "cache_ttl_seconds": _cache_ttl_seconds(),
            "stale": False,
            "refreshing": False,
            "total_duration_ms": total_ms,
            "build_duration_ms": total_ms,
            "response_duration_ms": total_ms,
            "components_ms": timings,
            "components": diagnostics,
            "failures": sorted(set(failures)),
            "request_model": "parallel_bounded_snapshot",
        },
    }


def _store_cache(payload: dict[str, Any]) -> None:
    with _CACHE_LOCK:
        _CACHE["created_monotonic"] = time.monotonic()
        _CACHE["payload"] = payload
        _CACHE["refreshing"] = False
        _CACHE["last_error"] = None


def _refresh_worker(*, authorization: CutoverAuthorization | None = None) -> None:
    try:
        payload = _build_dashboard_snapshot(authorization=authorization)
        _store_cache(payload)
        log_event(
            "dashboard",
            "snapshot_refreshed",
            "Dashboard snapshot refreshed in background.",
            status=payload.get("status"),
            duration_ms=(payload.get("diagnostics") or {}).get("total_duration_ms"),
        )
    except Exception as exc:  # defensive: background warmup must never stop HTTP startup
        with _CACHE_LOCK:
            _CACHE["refreshing"] = False
            _CACHE["last_error"] = f"{type(exc).__name__}: {exc}"
        log_event(
            "dashboard",
            "snapshot_refresh_failed",
            "Dashboard snapshot background refresh failed.",
            level=logging.WARNING,
            error_type=type(exc).__name__,
            error=str(exc),
        )


def warm_dashboard_snapshot_async(
    *, authorization: CutoverAuthorization | None = None
) -> bool:
    """Start one daemon refresh and return whether a new worker was started."""
    with _CACHE_LOCK:
        if _CACHE.get("refreshing"):
            return False
        _CACHE["refreshing"] = True
    thread = threading.Thread(
        target=_refresh_worker, kwargs={"authorization": authorization},
        name="dashboard-warmup", daemon=True,
    )
    thread.start()
    return True


def _cached_response(payload: dict[str, Any], *, age: float, stale: bool, refreshing: bool) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    diagnostics = dict(result.get("diagnostics") or {})
    diagnostics.update(
        {
            "cache_hit": True,
            "cache_age_ms": max(0, int(age * 1000)),
            "cache_ttl_seconds": _cache_ttl_seconds(),
            "stale": stale,
            "refreshing": refreshing,
            "response_model": "stale_while_revalidate" if stale else "fresh_cache",
            "build_duration_ms": diagnostics.get("build_duration_ms", diagnostics.get("total_duration_ms", 0)),
            "response_duration_ms": 0,
        }
    )
    result["diagnostics"] = diagnostics
    if stale and result.get("status") == "ok":
        result["status"] = "stale"
    return result


def _warming_response() -> dict[str, Any]:
    fallback = _fallbacks()
    runtime = _runtime_payload()
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "warming",
        "health": {
            "status": "warming",
            "service": "ad-log-reports",
            "mode": "real-readonly-archive-collector",
            "runtime": runtime,
        },
        "collector_health": fallback["collector_health"],
        "sources": {"items": []},
        "events_summary": fallback["events_summary"],
        "entity_summary": fallback["entity_summary"],
        "jobs": {"items": []},
        "reports": {"items": []},
        "role_views": {"views": [], "summary": {}},
        "diagnostics": {
            "cache_hit": False,
            "cache_age_ms": 0,
            "cache_ttl_seconds": _cache_ttl_seconds(),
            "stale": False,
            "refreshing": True,
            "total_duration_ms": 0,
            "build_duration_ms": 0,
            "response_duration_ms": 0,
            "components_ms": {},
            "components": {},
            "failures": [],
            "request_model": "startup_warming_response",
        },
    }


def build_dashboard_snapshot(
    *, force: bool = False, authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    """Return a fast dashboard response with parallel refresh and stale cache.

    - ``force=True`` performs one bounded synchronous build for diagnostics.
    - normal requests return a fresh cache immediately;
    - expired cache is served immediately while one daemon refresh runs;
    - before the first cache is ready, the UI receives a valid warming payload.
    """
    # Authorization is a sealed, request-scoped route choice.  It must never
    # be mixed with the process-wide V1 cache.
    if force or authorization is not None:
        payload = _build_dashboard_snapshot(authorization=authorization)
        _store_cache(payload)
        return payload

    now = time.monotonic()
    with _CACHE_LOCK:
        cached = _CACHE.get("payload")
        age = now - float(_CACHE.get("created_monotonic") or 0.0)
        refreshing = bool(_CACHE.get("refreshing"))

    if cached is not None and age < _cache_ttl_seconds():
        return _cached_response(cached, age=age, stale=False, refreshing=refreshing)

    started = (
        warm_dashboard_snapshot_async()
        if authorization is None
        else warm_dashboard_snapshot_async(authorization=authorization)
    )
    if cached is not None:
        return _cached_response(cached, age=age, stale=True, refreshing=(started or refreshing))
    return _warming_response()
