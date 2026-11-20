"""Actual migrated PostgreSQL archive control, audit and authorized scope.

Collected by the existing postgres CI job. Never uses a non-disposable DB.
"""
import os
from pathlib import Path

import pytest

from tests.postgres_integration_guard import assert_disposable_database


def test_archive_migration_is_discoverable_and_records_atomic_ledger():
    from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

    root = Path(__file__).resolve().parents[2] / "config" / "postgres_migrations"
    migration = next(item for item in forward_migration_inventory(root) if item.version == 277)
    assert migration.name == "domain_archive_selection"
    sql = migration.path.read_text(encoding="utf-8").lower()
    assert sql.count("insert into public.schema_migrations") == 1
    assert sql.index("begin;") < sql.index("alter table domains")
    assert sql.index("alter table domains") < sql.index("insert into public.schema_migrations") < sql.index("commit;")


@pytest.mark.postgres_integration
def test_archive_control_and_report_scope_use_real_postgres():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN required; disposable migrated PostgreSQL only")
    psycopg = pytest.importorskip("psycopg")
    from server.api.routes import setup
    from server.sli.access.domain_scope import resolve_report_domain_selection
    from server.sli.core.report_domain import effective_domain_fqdn, suggested_domain_fqdn
    from server.sli.core.setup_domains import update_archive
    from server.sli.plugins.ad.reports.definitions.computers import REPORT
    from tests.core.test_setup_domains import _Handler
    from tests.reporting.test_ad_report_domain_selection import Handler

    with psycopg.connect(dsn) as conn:
        assert_disposable_database(conn)
        assert conn.execute("select name from schema_migrations where version=277").fetchone() == ("domain_archive_selection",)
        forest = conn.execute("insert into forests(name) values ('archive-test.example.test') returning id").fetchone()[0]
        live, archive = [conn.execute(
            "insert into domains(forest_id,fqdn,netbios_name) values (%s,%s,%s) returning id",
            (forest, name, netbios),
        ).fetchone()[0] for name, netbios in (("current.example.test", "CURRENT"), ("historical.example.test", "HISTORICAL"))]
        assert conn.execute("select bool_or(is_archived) from domains where id=any(%s)", ([live, archive],)).fetchone() == (False,)

    denied = _Handler(capable=False, body={"is_archived": True})
    setup.try_handle_post(denied, "/api/v1/setup/domains/historical.example.test")
    with psycopg.connect(dsn) as conn:
        assert conn.execute("select is_archived from domains where id=%s", (archive,)).fetchone() == (False,)

    handler = _Handler(body={"is_archived": True})
    setup.try_handle_post(handler, "/api/v1/setup/domains/historical.example.test")
    assert handler.sent[0][1] == 200
    with psycopg.connect(dsn) as conn:
        assert conn.execute("select is_archived,netbios_name from domains where id=%s", (archive,)).fetchone() == (True, "HISTORICAL")
        details = conn.execute("select details_json from access_audit_v4 where action='setup_domain_update' and target_key='historical.example.test' order by id desc limit 1").fetchone()[0]
        assert details["is_archived"] is True and details["previous_is_archived"] is False

    access = Handler(REPORT, ids=(live, archive)).access
    assert resolve_report_domain_selection(access, REPORT.access, {}).domain_ids == [live]
    assert resolve_report_domain_selection(access, REPORT.access, {"domain_id": [str(archive)]}).domain_ids == [archive]
    restricted = Handler(REPORT, ids=(live,)).access
    with pytest.raises(PermissionError, match="domain_scope_denied"):
        resolve_report_domain_selection(restricted, REPORT.access, {"domain_id": [str(archive)]})
    assert effective_domain_fqdn("current.example.test") == "current.example.test"
    with psycopg.connect(dsn) as conn:
        conn.execute("""insert into ad_context_runs(
            run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,bundle_sha256,status)
            values ('00000000-0000-4000-8000-000000000277','synthetic','1',%s,'full',
                    now()-interval '1 day',%s,'completed')""", (live, bytes(32)))
    assert effective_domain_fqdn("historical.example.test") == "current.example.test"
    assert suggested_domain_fqdn("historical.example.test", 86430) == "current.example.test"
    assert suggested_domain_fqdn("historical.example.test", 60) is None
    assert suggested_domain_fqdn("current.example.test", 86430) is None
    with psycopg.connect(dsn) as conn:
        assert conn.execute("select is_archived from domains where id=%s", (archive,)).fetchone() == (True,)

    def broken_audit(*_):
        raise RuntimeError("synthetic audit failure")
    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        update_archive("historical.example.test", False, audit=broken_audit)
    with psycopg.connect(dsn) as conn:
        assert conn.execute("select is_archived from domains where id=%s", (archive,)).fetchone() == (True,)
    update_archive("historical.example.test", False)
    assert set(resolve_report_domain_selection(access, REPORT.access, {}).domain_ids) == {live, archive}
