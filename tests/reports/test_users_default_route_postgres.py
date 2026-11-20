"""T001: default AD users route, real migrated PostgreSQL and synthetic evidence.

This is not a browser/stand performance claim. No runtime tables, scopes, query
adapters or report implementation are replaced. The authenticated request boundary and parsed route dispatch are supplied
by the test; this is not the full HTTP URL parser or browser request stack. CI owns the disposable database lifecycle.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from datetime import datetime, timedelta, timezone
from time import monotonic
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.postgres_integration_guard import assert_disposable_database

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_historical(371, "password_domain_auto")]
REPORT = "ad.users.v2"
FIELDS = ["identity_basic", "technical", "security", "privilege", "hr", "contact"]


def _user(domain, number, observed):
    return {
        "entityId": domain * 100000 + number,
        "objectGuid": f"synthetic-{domain}-{number}",
        "sid": f"S-1-5-21-100-200-{domain}-{1000 + number}",
        "samAccountName": f"synthetic-account-{number}",
        "enabled": True, "userAccountControl": 512, "lockedOut": number == 1,
        "objectClasses": ["user"], "servicePrincipalNames": [],
        "passwordLastSet": (observed - timedelta(days=10)).isoformat(),
        "lastLogonTimestamp": (observed - timedelta(days=2)).isoformat(),
        "memberships": {"status": "observed", "effective": []},
    }


@pytest.fixture
def users_route_data():
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("isolated migrated PostgreSQL is required")
    # Relative UTC slots keep the fixture inside the actual 365-day reader.
    slot = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    domains = []
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        cur.execute("insert into forests(name) values ('synthetic-t001') returning id")
        forest = cur.fetchone()["id"]
        for name, archived, count in (
            ("demo.example.invalid", False, 1275),
            ("second.example.invalid", False, 1275),
            ("archive.example.invalid", True, 1275),
            ("ungranted.example.invalid", False, 1275),
        ):
            cur.execute("insert into domains(forest_id,fqdn,is_archived) values (%s,%s,%s) returning id",
                        (forest, name, archived))
            domain = cur.fetchone()["id"]
            domains.append({"id": domain, "name": name, "archived": archived, "count": count})
            scope = {"domain_ids": [domain]}
            scope_hash = hashlib.sha256(json.dumps(scope, sort_keys=True).encode()).digest()
            # Real retained payloads and predecessor slots, not mocked bundles.
            for age in range(8):
                observed = slot - timedelta(days=age)
                payload = {"metadata": {"collection_status": "complete", "user_count": count},
                           "users": [_user(domain, i, observed) for i in range(1, count + 1)]}
                digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).digest()
                cur.execute("""insert into users_report_v2_snapshots(
                    domain_id,contract_id,schema_version,scope_json,scope_sha256,
                    bucket_start_utc,captured_at_utc,source_observed_at_utc,
                    source_state,user_count,payload_json,payload_sha256)
                    values (%s,'sli.users-report.v2',1,%s,%s,%s,%s,%s,'complete',%s,%s,%s)
                    returning snapshot_id""",
                    (domain, Jsonb(scope), scope_hash, observed, observed, observed,
                     count, Jsonb(payload), digest))
                snapshot_id = cur.fetchone()["snapshot_id"]
                manifest = uuid4()
                cur.execute("""insert into ad_snapshot_manifests(
                    manifest_id,domain_id,domain_sid,domain_dns,slot_start_utc,
                    assembled_at_utc,contract_version,coverage_state,manifest_sha256)
                    values (%s,%s,%s,%s,%s,%s,'sli.ad-snapshot-manifest/1.0','complete',%s)""",
                    (manifest, domain, f"S-1-5-21-100-200-{domain}", name, observed, observed, digest))
                cur.execute("""insert into ad_snapshot_manifest_sources(
                    manifest_id,family,contract_id,source_id,observed_at_utc,
                    source_state,payload_sha256)
                    values (%s,'users_v2','sli.users-report.v2',%s,%s,'complete',%s)""",
                    (manifest, str(snapshot_id), observed, digest))
            cur.execute("insert into servers(domain_id,hostname,role) values (%s,%s,'domain_controller') returning id",
                        (domain, f"synthetic-dc-{domain}"))
            server = cur.fetchone()["id"]
            cur.execute("insert into storage_v2_channel(value) values ('Security') on conflict(value) do update set value=excluded.value returning id")
            channel = cur.fetchone()["id"]
            cur.execute("insert into storage_v2_provider(value) values ('Microsoft-Windows-Security-Auditing') on conflict(value) do update set value=excluded.value returning id")
            provider = cur.fetchone()["id"]
            # Auth traffic plus changes: both real review scans must execute.
            offset = 700000000 + domain * 100000
            cur.execute("""insert into events_v2_core(
                id,server_id,domain_id,log_source_id,event_record_id,event_id,
                provider_id,channel_id,time_created_utc,target_user_sid,
                normalized_at,normalized_hash,source_core_sha256)
                select %s+i,%s,%s,1,%s+i,case when i %% 20=0 then 4725 else 4624 end,
                    %s,%s,%s::timestamptz-i*interval '10 seconds',
                    'S-1-5-21-100-200-'||%s||'-'||(1001+(i %% %s)),
                    now(),decode(repeat('ab',32),'hex'),decode(repeat('cd',32),'hex')
                from generate_series(1,20000) i""",
                (offset, server, domain, offset, provider, channel, slot, domain, count))
        for table in ("domains", "ad_snapshot_manifests", "ad_snapshot_manifest_sources",
                      "users_report_v2_snapshots", "events_v2_core"):
            cur.execute(f"analyze {table}")  # Fixed local allowlist, disposable only.
    return domains


def _request(access, suffix, query):
    from server.api.http_server import RequestHandler
    from server.api.routes import reports_v2

    handler = object.__new__(RequestHandler)
    handler.path = f"/api/v2/reports/{REPORT}{suffix}"
    handler.command = "GET"
    handler.headers = {"Accept-Language": "en"}
    handler.wfile = io.BytesIO()
    handler._admit_request = lambda: True
    handler._access_decision = lambda: access
    statuses = []
    handler.send_response = lambda status: statuses.append(int(status))
    handler.send_header = lambda *_args: None
    handler.end_headers = lambda: None
    handler.server = SimpleNamespace(request_slots=SimpleNamespace(release=lambda: None))
    handler._do_GET = lambda: reports_v2.try_handle_get(handler, handler.path, query)
    started = monotonic()
    handler.do_GET()  # Real budget, handler, localization and JSON serialization.
    elapsed = monotonic() - started
    assert len(statuses) == 1
    return json.loads(handler.wfile.getvalue()), statuses[0], elapsed


def _access(ids, fields=FIELDS):
    return {"reports": [{"report_key": REPORT, "allowed": True,
        "allowed_actions": ["view"], "grants": [{"allowed_actions": ["view"],
        "field_categories": fields, "scope": {"kind": "domain", "ids": ids}}]}]}


def _plan_summary(plan):
    document = plan[0]
    pending, nodes = [document["Plan"]], []
    while pending and len(nodes) < 24:
        node = pending.pop()
        nodes.append({key: node[key] for key in (
            "Node Type", "Relation Name", "Index Name", "Actual Rows",
            "Actual Loops", "Actual Total Time", "Shared Hit Blocks",
            "Shared Read Blocks", "Temp Read Blocks", "Temp Written Blocks") if key in node})
        pending.extend(node.get("Plans", []))
    return {"planning_ms": document.get("Planning Time"),
            "execution_ms": document.get("Execution Time"), "nodes": nodes,
            "truncated": bool(pending)}


@pytest.fixture
def route_sql_probe(users_route_data, monkeypatch):
    """Measure actual read SQL and retain it only in memory for native EXPLAIN."""
    import psycopg

    connect, statements = psycopg.connect, []

    class CaptureCursor(psycopg.Cursor):
        def execute(self, query, params=None, **kwargs):
            self.profile_query = query if isinstance(query, str) and (
                "ad_review_snapshots" in query or "ad_review_events" in query
                or "from domains d" in query) else None
            self.profile_params, self.profile_started = params, monotonic()
            try:
                return super().execute(query, params, **kwargs)
            except Exception:
                self._record(-1)
                raise

        def _record(self, rows):
            if self.profile_query:
                statements.append((self.profile_query, self.profile_params,
                                   monotonic() - self.profile_started, rows))
                self.profile_query = None

        def fetchall(self):
            try:
                rows = super().fetchall()
            except Exception:
                self._record(-1)
                raise
            self._record(len(rows))
            return rows

    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: connect(
        *args, **{**kwargs, "cursor_factory": CaptureCursor}))
    return statements, connect


def test_default_users_route_real_sql_all_and_single_domains(
        users_route_data, route_sql_probe, capsys, record_property):
    from server.sli.plugins.ad.reports.definitions import users

    domains = users_route_data
    permitted = [row["id"] for row in domains[:3]]
    statements, connect = route_sql_probe
    observations = []
    diagnostic_errors = []
    try:
        for label, query, expected in (
            ("all_accessible_nonarchive", {}, domains[:2]),
            ("explicit_current", {"domain_id": [str(domains[0]["id"])]}, domains[:1]),
            ("explicit_archive", {"domain_id": [str(domains[2]["id"])]}, domains[2:3]),
        ):
            for repeat in range(2):
                users._cache.clear()
                start = len(statements)
                declaration, meta_status, meta_elapsed = _request(_access(permitted), "", {})
                assert declaration["views"][0]["key"] == "checks"
                payload, status, data_elapsed = _request(_access(permitted), "/data", query)
                item = {"scope": label, "repeat": repeat, "metadata_seconds": meta_elapsed,
                        "data_seconds": data_elapsed, "combined_seconds": meta_elapsed + data_elapsed,
                        "status": status, "sql_seconds": sum(row[2] for row in statements[start:]),
                        "queries": len(statements) - start,
                        "failed_queries": sum(row[3] == -1 for row in statements[start:])}
                observations.append(item)
                with capsys.disabled():
                    print("T001_ROUTE_TIMING " + json.dumps(item, sort_keys=True), flush=True)
                assert meta_status == status == 200
                assert payload["state"] not in {"error", "unavailable", "denied", "not_collected"}
                assert payload["coverage"]["population"] == sum(row["count"] for row in expected)
                assert set(payload["domain_scope"]["domain_ids"]) == {row["id"] for row in expected}
                assert payload["coverage"]["event_coverage"] == "unconfirmed"
                assert len(payload["collections"]["checks"]) == 13
                assert any("ad_review_snapshots" in row[0] for row in statements[start:])
                assert any("ad_review_events" in row[0] for row in statements[start:])
        # Error isolation is tested through the same actual route, not SQL stubs.
        denied, status, _ = _request(_access(permitted), "/data",
                                    {"domain_id": [str(domains[3]["id"])]})
        assert status == 403 and denied["state"] == "denied"
        restricted, status, _ = _request(_access(permitted, ["identity_basic"]), "/data", {})
        assert status == 403 or restricted["state"] == "denied"
    finally:
        # Separate plan executions are excluded from HTTP timings. No raw query
        # parameters, payloads, DSN or names are printed even for these fixtures.
        try:
            with connect(os.environ["ADLOG_TEST_PG_DSN"]) as conn:
                assert_disposable_database(conn)
                conn.execute("set transaction read only")
                conn.execute("set local statement_timeout='8s'")
                seen = set()
                for sql, params, _elapsed, _rows in statements:
                    key = (sql, repr(params))
                    if key in seen:
                        continue
                    seen.add(key)
                    plan = conn.execute("explain (analyze,buffers,format json) " + sql, params).fetchone()[0]
                    kind = "snapshot" if "ad_review_snapshots" in sql else "events" if "ad_review_events" in sql else "domains"
                    with capsys.disabled():
                        print("T001_NATIVE_PLAN " + json.dumps(
                            {"kind": kind, **_plan_summary(plan)}, sort_keys=True), flush=True)
        except Exception as exc:
            # Preserve an earlier assertion/route failure; never print DSN/SQL
            # from a driver error. A failed diagnostic still fails a green run.
            diagnostic_errors.append(type(exc).__name__)
            with capsys.disabled():
                print("T001_NATIVE_PLAN_FAILED " + type(exc).__name__, flush=True)
        record_property("t001_route_observations", json.dumps(observations))
        users._cache.clear()
    assert not diagnostic_errors, diagnostic_errors
    assert observations
    # Necessary server-side gate, not a claim about network/browser rendering.
    assert max(item["combined_seconds"] for item in observations) < 3.0, observations

