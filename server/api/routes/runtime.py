"""Runtime domain: server/runtime status, collector health, jobs, logs.

The shared POST mutation gate that used to sit in ``http_server.py`` around
``/api/jobs/collect`` and ``/api/jobs/analyze`` (plus the findings and
investigations routes already extracted in ticket 05) has no domain-specific
meaning of its own — it was infrastructure shared by whichever routes
happened to still be inline. Per spec.md's established contract, each
domain calls ``_authorize_mutation()`` itself inside ``try_handle_post``;
this module does the same for both job routes here, and this is the last
ticket that touches that former shared block. ``http_server.py`` keeps one
final ``_authorize_mutation()`` + 404 fallback for any POST path no domain
recognizes, preserving the original fail-closed behavior (an unmatched path
still requires mutation authorization before it is told "not found").

Shared ambient auth/authz machinery and response helpers stay on
``RequestHandler`` in ``server.api.http_server`` and are reached through the
``handler`` instance passed to every function here. This module never
imports ``server.api.http_server``.
"""
from __future__ import annotations

from http import HTTPStatus

from server.sli.core.app_config import load_config
from server.sli.sources.autocollection_report import render_autocollection_report
from server.sli.sources.collector_health import get_collector_health, render_collector_health_report
from server.sli.core.database import get_sources
from server.sli.plugins.registry import require_plugin
from server.sli.ops.logging_config import tail_log_lines
from server.sli.ops.runtime_identity import get_runtime_identity
from server.sli.storage.storage_v2_config import load_storage_v2_settings
from server.sli.storage.runtime_storage import (
    StorageRouteAuthorizationError,
    validate_storage_route_authorization,
)
from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
    is_controller_authorization,
)
from server.jobs.collector import (
    create_analysis_job,
    create_collect_job,
    get_autocollection_status,
    get_collection_runtime_status,
    get_job,
    get_scheduler_runtime_status,
    list_jobs,
)

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/autocollection/status"),
    ("GET", "/api/collector/health"),
    ("GET", "/api/domain-controllers"),
    ("GET", "/api/jobs"),
    ("GET", "/api/jobs/*"),
    ("GET", "/api/logs/tail"),
    ("GET", "/api/runtime/status"),
    ("GET", "/api/sources"),
    ("GET", "/reports/autocollection.html"),
    ("GET", "/reports/collector-health.html"),
    ("POST", "/api/jobs/analyze"),
    ("POST", "/api/jobs/collect"),
)


def discover_domain_controllers():
    """Expose configured targets; the API must not discover the host's domain."""
    return [item["hostname"] for item in require_plugin("sli.ad", "get_configured_domain_controller_targets")]


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/runtime/status":
        handler._send_json(_runtime_status())
        return True
    if path == "/api/sources":
        handler._send_json({"items": get_sources()})
        return True
    if path == "/api/domain-controllers":
        handler._send_json({"items": discover_domain_controllers()})
        return True
    if path == "/api/collector/health":
        handler._send_json(get_collector_health())
        return True
    if path == "/api/jobs":
        handler._send_json({"items": list_jobs()})
        return True
    if path == "/api/autocollection/status":
        handler._send_json(get_autocollection_status())
        return True
    if path.startswith("/api/jobs/"):
        _handle_get_job(handler, path)
        return True
    if path == "/api/logs/tail":
        handler._send_json({"items": tail_log_lines(100)})
        return True
    if path == "/reports/collector-health.html":
        _handle_collector_health_report(handler)
        return True
    if path == "/reports/autocollection.html":
        _handle_autocollection_report(handler)
        return True
    return False


def try_handle_post(handler, path: str) -> bool:
    if path == "/api/jobs/collect":
        if not handler._authorize_mutation() or not handler._require_capability("operations.view"):
            return True
        _handle_collect_job(handler)
        return True
    if path == "/api/jobs/analyze":
        if not handler._authorize_mutation() or not handler._require_capability("operations.view"):
            return True
        _handle_analysis_job(handler)
        return True
    return False


def _runtime_status() -> dict:
    cfg = load_config()
    return {
        "status": "ok",
        "active_backend": cfg.db_backend,
        "postgres_dsn_present": bool(cfg.postgres_dsn),
        "storage_v2": load_storage_v2_settings().public_dict(),
        "identity": get_runtime_identity(),
        "scheduler": get_scheduler_runtime_status(),
        "collection": get_collection_runtime_status(),
    }


def _archive_status_for_runtime() -> dict:
    backend = (load_config().db_backend or "postgres").strip().lower()
    if backend != "postgres":
        raise RuntimeError(f"Unsupported runtime DB backend {backend!r}: archive status is PostgreSQL-only")
    from server.sli.core.postgres_runtime_pipeline import get_archive_status_pg

    return get_archive_status_pg()


def _handle_get_job(handler, path: str) -> None:
    try:
        job_id = int(path.rsplit("/", 1)[1])
    except ValueError:
        handler._send_json({"error": "invalid_job_id"}, HTTPStatus.BAD_REQUEST)
        return
    job = get_job(job_id)
    if job is None:
        handler._send_json({"error": "job_not_found"}, HTTPStatus.NOT_FOUND)
        return
    handler._send_json(job)


def _handle_collect_job(handler) -> None:
    payload = handler._read_json_body()
    server = str(payload.get("server") or "all")
    hours = int(payload.get("hours") or 1)
    max_events = int(payload.get("max_events_per_channel") or 200)

    servers = None if server.lower() == "all" else [server]
    job = create_collect_job(servers=servers, hours=hours, max_events_per_channel=max_events, reason="manual")
    handler._send_json(job, HTTPStatus.ACCEPTED)


def _handle_analysis_job(handler) -> None:
    payload = handler._read_json_body()
    server = str(payload.get("server") or "all")
    servers = None if server.lower() == "all" else [server]
    authorization = _storage_route_authorization(handler)
    job = (
        create_analysis_job(servers=servers, reason="manual")
        if authorization is None
        else create_analysis_job(
            servers=servers,
            reason="manual",
            authorization=authorization,
        )
    )
    handler._send_json(job, HTTPStatus.ACCEPTED)


def _storage_route_authorization(
    handler,
) -> CutoverAuthorization | None:
    return validate_storage_route_authorization(
        getattr(handler, "storage_route_authorization", None)
    )


def _handle_collector_health_report(handler) -> None:
    data = get_collector_health()
    handler._send_html(render_collector_health_report(data))


def _handle_autocollection_report(handler) -> None:
    data = get_autocollection_status()
    handler._send_html(render_autocollection_report(data))
