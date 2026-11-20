from __future__ import annotations

import secrets
import io
import re
from pathlib import Path


def test_pg_sql_escapes_like_literals_before_psycopg_placeholders() -> None:
    from server.sli.core.database import _pg_sql

    converted = _pg_sql(
        "select * from events where lower(name) like '%service%' "
        "or lower(name) like '%schema admins%' or id = ?"
    )

    assert "like '%%service%%'" in converted
    assert "like '%%schema admins%%'" in converted
    assert "id = %s" in converted
    # Only the DB-API '?' marker may become an unescaped psycopg placeholder.
    assert len(re.findall(r"(?<!%)%s", converted)) == 1


def test_security_monitor_generated_sql_has_no_accidental_bind_markers() -> None:
    from server.sli.core.database import _pg_sql
    from server.sli.events.security_events_monitor import _privileged_sql, _service_sql

    converted = _pg_sql(
        f"select sum(case when {_privileged_sql()} then 1 else 0 end), "
        f"sum(case when {_service_sql()} then 1 else 0 end) "
        "from events where event_id = ?"
    )

    assert "'%%service%%'" in converted
    assert "'%%schema admins%%'" in converted
    assert len(re.findall(r"(?<!%)%s", converted)) == 1


class _DummyHandler:
    def __init__(self) -> None:
        self.status = None
        self.headers: list[tuple[str, str]] = []
        self.wfile = io.BytesIO()

    def send_response(self, status: int) -> None:
        self.status = int(status)

    def send_header(self, name: str, value: str) -> None:
        self.headers.append((name, value))

    def end_headers(self) -> None:
        return

    def _send_html(self, html_text: str, status: int = 200) -> None:
        """Mirror the real handler closely enough to keep the assertions honest.

        The report routes moved to _send_html, and this stub did not follow, so
        both tests failed on a missing attribute instead of on the behaviour they
        exist to protect. Reproducing the nonce injection matters: it is what
        turns the page into something a browser will actually execute under the
        Content-Security-Policy the server sends.
        """
        nonce = secrets.token_urlsafe(24)
        self._csp_nonce = nonce
        secured = re.sub(
            r"<(script|style)(?![^>]*\bnonce=)(?=[\s>])",
            lambda match: f'<{match.group(1)} nonce="{nonce}"',
            html_text,
            flags=re.IGNORECASE,
        )
        body = secured.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_autocollection_report_route_has_real_handler(monkeypatch) -> None:
    from server.api.routes import runtime as routes_runtime

    monkeypatch.setattr(routes_runtime, "get_autocollection_status", lambda: {"status": "idle"})
    monkeypatch.setattr(routes_runtime, "render_autocollection_report", lambda data: "<!doctype html><html><body>idle</body></html>")
    dummy = _DummyHandler()

    routes_runtime._handle_autocollection_report(dummy)

    assert dummy.status == 200
    assert dummy.wfile.getvalue().startswith(b"<!doctype html>")


def test_role_overview_report_reuses_bounded_dashboard_snapshot(monkeypatch) -> None:
    from server.api.routes import workspace as routes_workspace

    snapshot = {
        "generated_at_utc": "2026-07-12T00:00:00+00:00",
        "role_views": {
            "generated_at_utc": "2026-07-12T00:00:00+00:00",
            "principle": "bounded",
            "summary": {},
            "views": [],
        },
    }
    monkeypatch.setattr(routes_workspace, "build_dashboard_snapshot", lambda: snapshot)
    monkeypatch.setattr(
        routes_workspace,
        "render_role_overview_report",
        lambda data, selected=None: f"<!doctype html><html><body>{data['principle']}:{selected}</body></html>",
    )
    dummy = _DummyHandler()

    routes_workspace._handle_role_overview_report(dummy, {"view": ["security"]})

    assert dummy.status == 200
    assert b"bounded:security" in dummy.wfile.getvalue()


def test_domain_overview_get_does_not_generate_a_report(monkeypatch) -> None:
    from http import HTTPStatus
    from types import SimpleNamespace
    from server.api.routes import legacy_reports as routes_legacy_reports

    handler = SimpleNamespace()
    captured: dict[str, object] = {}
    handler._send_html = lambda body, status=HTTPStatus.OK: captured.update(body=body, status=status)
    monkeypatch.setattr(routes_legacy_reports, "resolve_report", lambda _name: None)

    routes_legacy_reports._handle_domain_security_overview_report(handler)

    assert captured["status"] == HTTPStatus.SERVICE_UNAVAILABLE
    assert "пока не сформирован" in str(captured["body"])
    assert "generate_recommendation_report" not in Path("server/api/routes/legacy_reports.py").read_text(encoding="utf-8")
