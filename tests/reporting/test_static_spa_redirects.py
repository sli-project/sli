"""Bare SPA paths (without /app) redirect into the React base path."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from server.api.http_server import ROUTE_REGISTRY
from server.api.routes import static as routes_static

ROOT = Path(__file__).resolve().parents[2]


class _Handler:
    def __init__(self, path: str):
        self.path = path
        self.status = None
        self.headers: dict[str, str] = {}

    def send_response(self, status):
        self.status = int(status)

    def send_header(self, key, value):
        self.headers[key] = value

    def end_headers(self):
        pass


def _router_top_level_segments() -> set[str]:
    source = (ROOT / "frontend/src/product-main.tsx").read_text(encoding="utf-8")
    paths = re.findall(r'path:\s*"(/[^"]*)"', source)
    paths += re.findall(r'retiredRedirect\(\s*"(/[^"]*)"', source)
    if "AD_STATE_LEGACY_ROUTE" in source:
        label = (ROOT / "frontend/src/app/report-labels.ts").read_text(encoding="utf-8")
        paths.append(re.search(r'AD_STATE_LEGACY_ROUTE\s*=\s*"([^"]+)"', label).group(1))
    segments = {p.strip("/").split("/")[0] for p in paths}
    return {s for s in segments if s and s != "app" and not s.startswith("$")}


def test_every_top_level_router_path_is_redirectable():
    segments = _router_top_level_segments()
    assert segments, "no routes parsed from product-main.tsx"
    assert segments <= routes_static.SPA_TOP_LEVEL_ROUTES, sorted(segments - routes_static.SPA_TOP_LEVEL_ROUTES)
    assert routes_static.SPA_TOP_LEVEL_ROUTES <= segments, sorted(routes_static.SPA_TOP_LEVEL_ROUTES - segments)


@pytest.mark.parametrize("raw", ["/report/vpn.connections?domain=a&x=1", "/reports", "/settings", "/entities/42",
                                 "/workstations", "/workstations?domain_id=11&station=ws%3Aad%3A123",
                                 "/ad-accounts", "/ad-accounts?view=accounts",
                                 "/agents", "/agents?view=policy", "/agents/synthetic?view=policy",
                                 "/notifications", "/notifications?nav_view=journal&status=error",
                                 "/extensions/sli.remote-access/accounts"])
def test_bare_spa_path_redirects_to_app_with_query(raw):
    handler = _Handler(raw)
    assert routes_static.try_handle_get(handler, raw.split("?")[0], {}) is True
    assert handler.status == 302
    assert handler.headers["Location"] == f"/app{raw}"


@pytest.mark.parametrize("raw", ["/ad-accounts", "/ad-accounts?view=accounts",
                                 "/workstations?domain_id=11&station=ws%3Aad%3A123"])
def test_ad_accounts_redirect_is_reachable_through_registry(raw):
    handler = _Handler(raw)
    assert ROUTE_REGISTRY.dispatch_get(handler, raw.split("?")[0], {})
    assert handler.status == 302
    assert handler.headers["Location"] == f"/app{raw}"


@pytest.mark.parametrize("path", ["/api/v1/health", "/login", "/assets/x.js", "/nope", "/sli-login.css", "/reportx"])
def test_other_paths_are_not_redirected(path):
    handler = _Handler(path)
    assert routes_static.try_handle_get(handler, path, {}) is False
    assert handler.status is None
