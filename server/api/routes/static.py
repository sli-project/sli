"""Static asset and React app shell routes: `/`, `/app*`, `/investigations`, login static assets.

Login page delivery (`/login` plus its allow-listed static assets) is served
before the ambient auth gate runs, same as today; the React app shell routes
(`/`, `/investigations`, `/app`, `/app/`, `/app/<path>`) are served after it,
same as today too. Two functions mirror that split: `try_handle_login_get`
(early) and the standard `try_handle_get` (in the chain's original later
position) -- see `routes/health.py` for the same pattern applied to the
health domain.
"""

from __future__ import annotations

import os
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING

from server.sli.core.paths import WEB_DIR

if TYPE_CHECKING:
    from server.api.http_server import RequestHandler

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/"),
    ("GET", "/app"),
    ("GET", "/app/"),
    ("GET", "/app/*"),
    ("GET", "/investigations"),
    ("GET", "/ad-accounts"),
    ("GET", "/workstations"),
    ("GET", "/events"),
    ("GET", "/events/*"),
    ("GET", "/settings"),
    ("GET", "/settings/*"),
)


# Top-level React router paths (frontend/src/product-main.tsx) that may be opened
# without the /app basepath. A test keeps this list in sync with the router.
SPA_TOP_LEVEL_ROUTES: frozenset[str] = frozenset({
    "access", "access-center", "access-requests", "access-user", "admin", "ad-accounts", "ad-report", "agents", "cases", "computers-report",
    "computers-v5-report", "computers-v6-report", "entities", "events", "extensions", "gpo-report", "gpo-v2-report",
    "notifications", "objects", "operations", "platform-settings", "plugins", "privileged-report", "problems", "project-readiness",
    "report", "report-builder", "report-management", "report-editor", "report-studio", "reports", "scenarios", "security-events-report",
    "security-overview", "settings", "investigations", "setup", "ui-kit", "users-report", "users-v2-report",
    "vpn-connections", "vpn-report", "what-where-when-report", "workstations",
})


def _is_spa_path(path: str) -> bool:
    parts = path.strip("/").split("/")
    return path.startswith("/") and bool(parts[0]) and parts[0] in SPA_TOP_LEVEL_ROUTES


def _react_web_root() -> Path:
    """Resolve an optional isolated React build without changing production assets."""
    override = os.environ.get("ADLOG_REACT_WEB_DIR", "").strip()
    return Path(override).resolve() if override else (WEB_DIR / "react").resolve()


_LOGIN_STATIC_ASSETS: dict[str, tuple[Path, str]] = {
    "/sli-login.css": (WEB_DIR / "sli-login.css", "text/css; charset=utf-8"),
    "/sli-login.js": (WEB_DIR / "sli-login.js", "application/javascript; charset=utf-8"),
    # The sign-in scene is one flat illustration. The earlier assembled version —
    # a separate rays layer, collector, four node badges and a background map —
    # lives in archive/obsolete-repository-20260728. Its routes are gone with it:
    # a declared path whose file is missing is an invitation to a confusing 404.
    **{
        f"/assets/sli-login/{name}": (WEB_DIR / "assets" / "sli-login" / name, "image/svg+xml")
        for name in (
            "collector-server.svg",
            "feature-brain.svg",
            "feature-eye.svg",
            "feature-shield.svg",
            "sli-logo.svg",
        )
    },
}


def _login_static_asset(path: str) -> tuple[Path, str] | None:
    """Resolve only the public assets explicitly required by the sign-in page."""
    return _LOGIN_STATIC_ASSETS.get(str(path))


CACHE_REVALIDATE = "no-cache"
CACHE_IMMUTABLE = "public, max-age=31536000, immutable"


def _send_static_file(handler: "RequestHandler", path: Path, content_type: str, cache_control: str) -> None:
    """Send a file with a route-specific Cache-Control (applied in end_headers)."""
    if not path.is_file():
        # Missing file: _send_file answers with a JSON 404 that must stay no-store.
        handler._send_file(path, content_type)
        return
    handler._cache_control_override = cache_control
    try:
        handler._send_file(path, content_type)
    finally:
        handler._cache_control_override = None


def _handle_react_app(handler: "RequestHandler", relative_path: str) -> None:
    root = _react_web_root()
    candidate = (root / relative_path).resolve() if relative_path else (root / "index.html").resolve()
    if not candidate.is_relative_to(root):
        handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        return
    is_asset_request = bool(relative_path) and Path(relative_path).parts[0] == "assets"
    if not candidate.is_file() and relative_path and not is_asset_request:
        candidate = root / "index.html"
    if not candidate.is_file():
        handler._send_json({"error": "react_ui_not_built"}, HTTPStatus.SERVICE_UNAVAILABLE)
        return
    content_type = "text/html; charset=utf-8" if candidate.suffix == ".html" else "application/octet-stream"
    if candidate.suffix == ".js":
        content_type = "application/javascript; charset=utf-8"
    elif candidate.suffix == ".css":
        content_type = "text/css; charset=utf-8"
    # Hashed build assets never change under the same name; the shell and any
    # other file must be revalidated so a fresh build shows without hard reload.
    cache_control = CACHE_IMMUTABLE if is_asset_request else CACHE_REVALIDATE
    _send_static_file(handler, candidate, content_type, cache_control)


def try_handle_login_get(handler: "RequestHandler", path: str) -> bool:
    """Serve the sign-in page and its static assets before the ambient auth gate."""
    if path == "/login":
        handler._send_file(WEB_DIR / "login.html", "text/html; charset=utf-8")
        return True
    login_asset = _login_static_asset(path)
    if login_asset is not None:
        _send_static_file(handler, *login_asset, CACHE_REVALIDATE)
        return True
    return False


def try_handle_get(handler: "RequestHandler", path: str, query: dict) -> bool:
    """Serve the React/legacy shell, after the ambient auth gate, as before."""
    if path == "/":
        handler.send_response(HTTPStatus.FOUND)
        handler.send_header("Location", "/app/")
        handler.end_headers()
        return True
    if path in ("/investigations", "/ad-accounts", "/workstations", "/events", "/settings") or path.startswith("/events/") or path.startswith("/settings/"):
        # Keep query parameters from older/raw deep links while routing the
        # browser into the React base path.
        handler.send_response(HTTPStatus.FOUND)
        handler.send_header("Location", f"/app{handler.path}")
        handler.end_headers()
        return True
    if _is_spa_path(path):
        handler.send_response(HTTPStatus.FOUND)
        handler.send_header("Location", f"/app{handler.path}")
        handler.end_headers()
        return True
    if path == "/app" or path == "/app/":
        _handle_react_app(handler, "")
        return True
    if path.startswith("/app/"):
        _handle_react_app(handler, path.removeprefix("/app/"))
        return True
    return False
