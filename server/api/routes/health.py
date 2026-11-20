"""Health, liveness and readiness routes.

`/api/health` and `/api/health/live` (liveness) and `/api/health/ready`
(readiness) bypass ambient authentication entirely and must stay reachable
before any session/capability check runs. `/api/health/details` is gated
by the shared ambient `route_capability` -> `operations.view` gate in
`http_server.py`, exactly like every other capability-gated route, so it is
dispatched from that same later position in `_do_GET`'s chain -- only the
bypass routes get an earlier call. This split (an early
`try_handle_liveness_get` plus the standard, later `try_handle_get`) is the
pattern any future domain with its own pre-auth-gate routes should follow.

`_handle_health`'s deep-check payload is built from `routes/runtime.py`'s
`_runtime_status`/`_archive_status_for_runtime` -- a domain->domain
dependency, not a cycle (a cycle is `domain -> http_server -> domain`).
"""

from __future__ import annotations

from http import HTTPStatus

from server.api.routes import runtime as routes_runtime
from server.sli.core.app_config import load_config
from server.sli.ops.runtime_identity import get_runtime_identity

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/health/details"),
)


def _liveness_payload() -> dict[str, object]:
    """Return process liveness without touching access policy or PostgreSQL."""
    return {
        "status": "ok",
        "service": "ad-log-reports",
        "runtime_identity": get_runtime_identity(),
    }


def _readiness_probe() -> tuple[bool, str]:
    """Check PostgreSQL readiness while exposing only a stable machine code."""
    try:
        from server.sli.core.postgres_runtime_pipeline import connect

        with connect() as conn, conn.cursor() as cur:
            cur.execute("select 1 as ready")
            row = cur.fetchone() or {}
        return bool(row.get("ready") == 1), "ready" if row.get("ready") == 1 else "postgres_not_ready"
    except Exception:
        return False, "postgres_unavailable"


def _handle_health(handler: "RequestHandler", query: dict[str, list[str]]) -> None:
    runtime_status = routes_runtime._runtime_status()
    payload = {
        "status": "ok",
        "service": "ad-log-reports",
        "mode": "real-readonly-archive-collector",
        "runtime_identity": runtime_status.get("identity"),
        "runtime": runtime_status,
    }
    if query.get("deep", ["0"])[0].lower() in {"1", "true", "yes"}:
        archive_status = routes_runtime._archive_status_for_runtime()
        payload["archive_start_utc"] = archive_status["archive_start_utc"]
        payload["archive_channel_states"] = archive_status["channel_states"]
        payload["archive_backend"] = archive_status.get("backend") or (load_config().db_backend or "postgres")
    handler._send_json(payload)


def try_handle_liveness_get(handler: "RequestHandler", path: str) -> bool:
    """Serve `/api/health`, `/api/health/live` and `/api/health/ready`.

    Called before the ambient auth gate runs for anything else -- these
    routes must stay reachable with no session and no PostgreSQL access.
    """
    if path in {"/api/health", "/api/health/live"}:
        handler._send_json(_liveness_payload())
        return True
    if path == "/api/health/ready":
        ready, code = _readiness_probe()
        handler._send_json(
            {"ready": ready, "code": code},
            HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE,
        )
        return True
    return False


def try_handle_get(handler: "RequestHandler", path: str, query: dict) -> bool:
    """Serve `/api/health/details`, after the ambient capability gate has run."""
    if path == "/api/health/details":
        _handle_health(handler, query)
        return True
    return False
