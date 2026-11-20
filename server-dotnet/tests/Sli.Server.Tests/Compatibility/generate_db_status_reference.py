"""Frozen Python diagnostics output using synthetic in-memory database fixtures."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from server.api.routes import diagnostics  # noqa: E402
from server.sli.core.app_config import redact_dsn  # noqa: E402
from server.sli.ops import db_status  # noqa: E402
from psycopg.errors import lookup  # noqa: E402


class OperationalError(Exception):
    pass


class LegacyFile:
    def __init__(self, size):
        self.size = size

    def exists(self):
        return self.size is not None

    def stat(self):
        return SimpleNamespace(st_size=self.size)

    def __str__(self):
        return "fixture/ad_logs.sqlite"


class Connection:
    def __init__(self, fixture):
        self.fixture = fixture
        self.sql = ""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return self

    def execute(self, sql):
        self.sql = sql
        stage = "tables" if "information_schema" in sql else "migrations" if "from schema_migrations" in sql else "identity"
        if self.fixture.get("error_stage") == stage:
            error = lookup(self.fixture["error_sqlstate"]) if "error_sqlstate" in self.fixture else OperationalError
            raise error("fixture <connection> & 'unavailable'")

    def fetchone(self):
        return ("PostgreSQL fixture <version>", "fixture", "fixture_reader")

    def fetchall(self):
        if "information_schema" in self.sql:
            return [(name,) for name in self.fixture["tables"]]
        return [(v["version"], v["name"]) for v in self.fixture["migrations"]]


def render(data):
    with patch.object(db_status, "get_db_status", return_value=data):
        class Handler:
            def _send_html(self, text):
                self.html = text

        handler = Handler()
        # These query values are deliberately ignored by this operation.
        assert diagnostics.try_handle_get(handler, "/reports/db-status.html", {"connect": ["false"], "limit": ["bad"]})
        return handler.html


def build():
    dsn = "host=192.0.2.10 user=fixture_reader password=fixture-password dbname=fixture"
    cases = [
        {"name": "no_dsn", "dsn": "", "size": None, "tables": [], "migrations": []},
        {"name": "complete", "dsn": dsn, "size": 1536, "tables": db_status.EXPECTED_TABLES + ["extra_fixture"], "migrations": [{"version": 1, "name": "fixture <start> & 'quoted'"}, {"version": 2, "name": "日本語 😀"}]},
        {"name": "empty_schema", "dsn": dsn, "size": 0, "tables": [], "migrations": []},
        {"name": "missing_table", "dsn": dsn, "size": 1024, "tables": db_status.EXPECTED_TABLES[:-1], "migrations": []},
        *[{"name": "failed_" + stage, "dsn": dsn, "size": None, "tables": db_status.EXPECTED_TABLES, "migrations": [], "error_stage": stage} for stage in ("identity", "tables", "migrations")],
        {"name": "schema_permission_denied", "dsn": dsn, "size": None, "tables": db_status.EXPECTED_TABLES, "migrations": [], "error_stage": "migrations", "error_sqlstate": "42501"},
        {"name": "connection_uri_failure", "dsn": "postgresql://example_fixture:fixture-password@192.0.2.10:5432/fixture", "size": None, "tables": [], "migrations": [], "error_stage": "identity"},
    ]
    for fixture in cases:
        cfg = SimpleNamespace(postgres_dsn=fixture["dsn"], postgres_connect_timeout_seconds=3, db_backend="postgres")
        with patch.object(db_status, "load_config", return_value=cfg), patch.object(db_status, "DB_PATH", LegacyFile(fixture["size"])), patch.object(db_status.time, "monotonic", return_value=0), patch.object(db_status, "get_release_metadata", return_value={}), patch.object(db_status, "_import_psycopg", return_value=(object(), {"status": "ok", "duration_ms": 0, "module": "psycopg"})), patch.object(db_status, "_connect", return_value=Connection(fixture)), patch.dict(db_status.os.environ, {"ADLOG_PG_DSN": "", "ADLOG_PG_CONNECT_TIMEOUT_SECONDS": "3"}):
            fixture["data"] = db_status.get_db_status()
        fixture["html"] = render(fixture["data"])
    unusual = copy.deepcopy(cases[1]["data"])
    unusual["status"] = '<script>"&\'</script>'
    unusual["postgres"]["dsn"] = ""
    unusual["checks"] = {"<check>&\"'": {"status": None, "values": [True, False, None, "a'b", 'a\'"b', "\n\r\t\x00\u200b\u00a0日本語😀", "long" * 100]}}
    renders = [{"data": data, "html": render(data)} for data in ({}, {"postgres": None, "sqlite": None, "checks": None}, unusual)]
    dsns = [
        "host=192.0.2.10 user=fixture password=fixture-password dbname=fixture",
        "host='db host' password='quoted secret' dbname=fixture",
        "host = 192.0.2.10 password = spaced-secret dbname = fixture",
        "postgresql://example_fixture:fixture%40password@192.0.2.10:5432/fixture",
        "postgresql://example_fixture:fixture%40password@[2001:db8::1]:5432/fixture?sslpassword=fixture-cert",
        "host=192.0.2.10 password=fixture-password sslpassword=fixture-cert",
        "host='unterminated password=must-not-leak",
        "unknown_option=must-not-leak",
        "host=192.0.2.10 application_name='a\\'b' options='a\\\\b c'",
    ]
    return {"cases": cases, "renders": renders, "dsns": [{"input": dsn, "expected": redact_dsn(dsn)} for dsn in dsns]}


if __name__ == "__main__":
    target = Path(__file__).with_name("db-status-reference.json")
    expected = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if "--check" in sys.argv:
        assert target.read_text(encoding="utf-8") == expected, "Regenerate the Python db-status fixtures"
        print("Python db-status fixtures verified")
    else:
        target.write_text(expected, encoding="utf-8")
