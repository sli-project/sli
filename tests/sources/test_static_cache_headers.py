from __future__ import annotations

from http.server import BaseHTTPRequestHandler

import pytest

from server.api import http_server
from server.api.routes import static as routes_static


def _handler(captured: list):
    handler = object.__new__(http_server.RequestHandler)
    handler._send_json = lambda *args, **kwargs: captured.append(("json", args))
    handler._send_file = lambda path, content_type: captured.append(
        (path.name, getattr(handler, "_cache_control_override", None))
    )
    return handler


@pytest.fixture()
def react_build(tmp_path, monkeypatch):
    web = tmp_path / "web"
    root = web / "react"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("app", encoding="utf-8")
    (root / "assets" / "index-AbC123.js").write_text("x", encoding="utf-8")
    (web / "assets" / "sli-login").mkdir(parents=True)
    (web / "assets" / "sli-login" / "sli-logo.svg").write_text("<svg/>", encoding="utf-8")
    (web / "sli-login.css").write_text("a{}", encoding="utf-8")
    monkeypatch.delenv("ADLOG_REACT_WEB_DIR", raising=False)
    monkeypatch.setattr(routes_static, "WEB_DIR", web)
    monkeypatch.setattr(
        routes_static,
        "_LOGIN_STATIC_ASSETS",
        {
            "/sli-login.css": (web / "sli-login.css", "text/css; charset=utf-8"),
            "/assets/sli-login/sli-logo.svg": (web / "assets" / "sli-login" / "sli-logo.svg", "image/svg+xml"),
        },
    )
    return root


def test_index_html_is_revalidated(react_build) -> None:
    captured: list = []
    handler = _handler(captured)
    routes_static._handle_react_app(handler, "")
    assert captured == [("index.html", "no-cache")]
    assert handler._cache_control_override is None


def test_client_route_fallback_is_revalidated(react_build) -> None:
    captured: list = []
    routes_static._handle_react_app(_handler(captured), "reports/ad.gpo.review")
    assert captured == [("index.html", "no-cache")]


def test_hashed_asset_is_immutable(react_build) -> None:
    captured: list = []
    routes_static._handle_react_app(_handler(captured), "assets/index-AbC123.js")
    assert captured == [("index-AbC123.js", "public, max-age=31536000, immutable")]


def test_missing_asset_stays_uncached_json(react_build) -> None:
    captured: list = []
    routes_static._handle_react_app(_handler(captured), "assets/nope.js")
    assert captured[0][0] == "json"


def test_login_assets_are_revalidated(react_build) -> None:
    captured: list = []
    handler = _handler(captured)
    assert routes_static.try_handle_login_get(handler, "/sli-login.css")
    assert routes_static.try_handle_login_get(handler, "/assets/sli-login/sli-logo.svg")
    assert captured == [("sli-login.css", "no-cache"), ("sli-logo.svg", "no-cache")]


def test_end_headers_uses_override_and_defaults_to_no_store(monkeypatch) -> None:
    monkeypatch.setattr(BaseHTTPRequestHandler, "end_headers", lambda self: None)
    sent: list[tuple[str, str]] = []

    def make():
        handler = object.__new__(http_server.RequestHandler)
        handler.send_header = lambda k, v: sent.append((k, v))
        handler._secure_transport = lambda: False
        return handler

    handler = make()
    handler.end_headers()
    assert ("Cache-Control", "no-store, max-age=0") in sent

    sent.clear()
    handler = make()
    handler._cache_control_override = "no-cache"
    handler.end_headers()
    assert [v for k, v in sent if k == "Cache-Control"] == ["no-cache"]
