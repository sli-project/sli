from __future__ import annotations

from pathlib import Path


def test_postgres_schema_is_safe_and_contains_core_tables() -> None:
    text = Path("config/postgres_schema.sql").read_text(encoding="utf-8").lower()
    for table in (
        "schema_migrations",
        "log_sources",
        "collection_channel_state",
        "collector_channel_runs",
        "collector_stage_metrics",
        "events",
        "findings",
        "ai_api_runs",
    ):
        assert f"create table if not exists {table}" in text
    assert "datetime('now')" not in text
    assert "insert or ignore" not in text
    assert "on conflict" in text


def test_dsn_redaction_masks_password() -> None:
    from server.sli.core.app_config import redact_dsn

    from psycopg.conninfo import conninfo_to_dict

    cases = (
        ("postgresql://example_user:example_password@127.0.0.1:5432/example_db", "example_password"),
        ("host=127.0.0.1 password=secret dbname=adlog_reports", "secret"),
        ("host='db host' password='quoted secret' dbname=adlog_reports", "quoted secret"),
        ("host = 127.0.0.1 password = spaced-secret dbname = adlog_reports", "spaced-secret"),
        ("postgresql://example_user:example%40password@[2001:db8::1]:5432/example_db", "example%40password"),
        ("host=db user=adlog password=secret sslpassword=cert-secret", "cert-secret"),
    )
    for dsn, secret in cases:
        redacted = redact_dsn(dsn)
        assert redacted is not None
        assert secret not in redacted
        assert conninfo_to_dict(redacted)["password"] == "***"

    ssl_redacted = redact_dsn("host=db sslpassword=cert-secret")
    assert ssl_redacted is not None
    assert conninfo_to_dict(ssl_redacted)["sslpassword"] == "***"


def test_dsn_redaction_fails_closed_for_invalid_or_unparseable_input(monkeypatch) -> None:
    from server.sli.core import app_config

    invalid = "host='unterminated password=must-not-leak"
    assert app_config.redact_dsn(invalid) == "<invalid PostgreSQL DSN>"

    monkeypatch.setattr(app_config, "_parse_conninfo", lambda _value: (_ for _ in ()).throw(RuntimeError("unavailable")))
    assert app_config.redact_dsn("password=another-secret") == "<invalid PostgreSQL DSN>"


def test_postgres_readiness_no_connect_is_bounded_and_safe(monkeypatch) -> None:
    monkeypatch.delenv("ADLOG_PG_DSN", raising=False)
    from scripts.maintenance.postgres_readiness import run_readiness

    result = run_readiness(connect=False)
    assert result["stage"] == "DB-0.1"
    assert result["status"] in {"ok", "warn"}
    assert result["safety"]["switch_backend"] is False
    assert result["safety"]["migrate_data"] is False
    assert result["safety"]["move_cursor_or_watermark"] is False
    assert result["checks"]["schema_file"]["status"] == "ok"


def test_db_status_no_dsn_does_not_fail_or_leak(monkeypatch) -> None:
    monkeypatch.delenv("ADLOG_PG_DSN", raising=False)
    from server.sli.ops.db_status import get_db_status

    result = get_db_status(connect=False)
    assert result["mode"] == "db0_readiness"
    assert result["active_backend"] in {"sqlite", "postgres"}
    assert result["postgres"]["configured"] is False
    assert result["safety"]["backend_switched"] is False


def test_db_status_report_and_navigation_are_registered() -> None:
    from server.sli.ops.db_status import render_db_status_report
    from server.sli.reporting.reports import list_reports
    from server.sli.reporting.ui_navigation import get_ui_navigation_data

    html = render_db_status_report()
    assert "DB Backend Status" in html
    reports = {item["name"] for item in list_reports()}
    assert "db-status.html" in reports
    nav_urls = {item["url"].split("?", 1)[0] for item in get_ui_navigation_data()["items"]}
    assert "/reports/db-status.html" in nav_urls
