from __future__ import annotations

import logging
from http import HTTPStatus


def test_collector_health_fallbacks_log_numeric_warning_levels(monkeypatch) -> None:
    from server.sli.sources import collector_health
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.sources import runtime_collection_history

    calls: list[dict[str, object]] = []

    def capture_log_event(*args, **kwargs) -> None:
        calls.append(kwargs)

    def fail(*args, **kwargs):
        raise RuntimeError("expected fallback")

    monkeypatch.setattr(collector_health, "log_event", capture_log_event)
    monkeypatch.setattr(collector_health, "get_post_collection_overview", fail)
    monkeypatch.setattr(runtime_collection_history, "recent_collector_channel_cycles", fail)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", fail)

    post_collection = collector_health._safe_post_collection_overview(backend="postgres", limit=1)
    history = collector_health._safe_runtime_collection_history(backend="postgres")
    outbox = collector_health._safe_storage_v2_outbox(backend="postgres")

    assert post_collection["status"] == "unavailable"
    assert history["status"] == "unavailable"
    assert outbox["status"] == "unavailable"
    assert len(calls) == 3
    assert all(call["level"] == logging.WARNING for call in calls)
    assert all(isinstance(call["level"], int) for call in calls)


def test_dashboard_refresh_failure_logs_numeric_warning_level(monkeypatch) -> None:
    from server.sli.reporting import dashboard_snapshot

    captured: dict[str, object] = {}
    dashboard_snapshot.clear_dashboard_snapshot_cache()

    def fail(*args, **kwargs):
        raise RuntimeError("refresh failed")

    monkeypatch.setattr(dashboard_snapshot, "_build_dashboard_snapshot", fail)
    monkeypatch.setattr(dashboard_snapshot, "log_event", lambda *args, **kwargs: captured.update(kwargs))

    dashboard_snapshot._refresh_worker()

    assert captured["level"] == logging.WARNING
    assert isinstance(captured["level"], int)
    with dashboard_snapshot._CACHE_LOCK:
        assert dashboard_snapshot._CACHE["refreshing"] is False
        assert dashboard_snapshot._CACHE["last_error"] == "RuntimeError: refresh failed"
    dashboard_snapshot.clear_dashboard_snapshot_cache()


def test_react_static_handler_rejects_prefix_collision_outside_root(tmp_path, monkeypatch) -> None:
    from server.api import http_server
    from server.api.routes import static as routes_static

    react_root = tmp_path / "web" / "react"
    sibling = tmp_path / "web" / "react-backup"
    react_root.mkdir(parents=True)
    sibling.mkdir(parents=True)
    (react_root / "index.html").write_text("app", encoding="utf-8")
    secret = sibling / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    monkeypatch.setattr(routes_static, "WEB_DIR", tmp_path / "web")

    handler = object.__new__(http_server.RequestHandler)
    responses: list[tuple[dict[str, str], HTTPStatus]] = []
    sent_files: list[object] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: responses.append((payload, status))
    handler._send_file = lambda path, content_type: sent_files.append(path)

    routes_static._handle_react_app(handler, "../react-backup/secret.txt")

    assert responses == [({"error": "not_found"}, HTTPStatus.NOT_FOUND)]
    assert sent_files == []


def test_react_static_handler_still_serves_asset_inside_root(tmp_path, monkeypatch) -> None:
    from server.api import http_server
    from server.api.routes import static as routes_static

    react_root = tmp_path / "web" / "react"
    asset = react_root / "assets" / "app.js"
    asset.parent.mkdir(parents=True)
    asset.write_text("console.log('ok')", encoding="utf-8")
    monkeypatch.setattr(routes_static, "WEB_DIR", tmp_path / "web")
    monkeypatch.delenv("ADLOG_REACT_WEB_DIR", raising=False)

    handler = object.__new__(http_server.RequestHandler)
    responses: list[object] = []
    sent_files: list[tuple[object, str]] = []
    handler._send_json = lambda *args, **kwargs: responses.append((args, kwargs))
    handler._send_file = lambda path, content_type: sent_files.append((path, content_type))

    routes_static._handle_react_app(handler, "assets/app.js")

    assert responses == []
    assert sent_files == [(asset.resolve(), "application/javascript; charset=utf-8")]


def test_react_static_handler_serves_dotted_routes_but_not_missing_assets(tmp_path, monkeypatch) -> None:
    from server.api import http_server
    from server.api.routes import static as routes_static

    react_root = tmp_path / "web" / "react"
    react_root.mkdir(parents=True)
    index = react_root / "index.html"
    index.write_text("app", encoding="utf-8")
    monkeypatch.setattr(routes_static, "WEB_DIR", tmp_path / "web")
    monkeypatch.delenv("ADLOG_REACT_WEB_DIR", raising=False)

    handler = object.__new__(http_server.RequestHandler)
    responses: list[tuple[dict[str, str], HTTPStatus]] = []
    sent_files: list[tuple[object, str]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: responses.append((payload, status))
    handler._send_file = lambda path, content_type: sent_files.append((path, content_type))

    routes_static._handle_react_app(handler, "reports/ad.gpo.review")
    routes_static._handle_react_app(handler, "reports/security.queue")
    routes_static._handle_react_app(handler, "assets/nope.js")

    assert sent_files == [
        (index, "text/html; charset=utf-8"),
        (index, "text/html; charset=utf-8"),
    ]
    assert responses == [({"error": "react_ui_not_built"}, HTTPStatus.SERVICE_UNAVAILABLE)]


def test_react_static_handler_can_serve_isolated_build(tmp_path, monkeypatch) -> None:
    from server.api import http_server
    from server.api.routes import static as routes_static

    isolated_root = tmp_path / "http-check-build"
    asset = isolated_root / "assets" / "app.js"
    asset.parent.mkdir(parents=True)
    asset.write_text("console.log('isolated')", encoding="utf-8")
    monkeypatch.setenv("ADLOG_REACT_WEB_DIR", str(isolated_root))

    handler = object.__new__(http_server.RequestHandler)
    responses: list[object] = []
    sent_files: list[tuple[object, str]] = []
    handler._send_json = lambda *args, **kwargs: responses.append((args, kwargs))
    handler._send_file = lambda path, content_type: sent_files.append((path, content_type))

    routes_static._handle_react_app(handler, "assets/app.js")

    assert responses == []
    assert sent_files == [(asset.resolve(), "application/javascript; charset=utf-8")]
