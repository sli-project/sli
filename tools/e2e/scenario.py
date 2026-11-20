"""Synchronous replay using the production import, worker and report seams."""
# ruff: noqa: BLE001 -- command boundary must redact private DB diagnostics
from __future__ import annotations

import argparse
import io
import json
import logging
import os
import re
import secrets
import shutil
import tempfile
import traceback
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import urlopen

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row

from tools.e2e.file_audit import REPORTS as FILE_REPORTS
from tools.e2e.file_audit import measure_reports, source_summary
from tools.e2e.file_audit import read_report as read_file_report

ROOT = Path(__file__).resolve().parents[2]
MODULES = {"ad-dc": "sli.windows.ad-dc", "file-audit": "sli.file-audit", "workstations": "sli.workstations"}
REPORTS = {"ad-dc": "events.journal", "file-audit": "file-audit.actions", "workstations": "workstations.logons"}
WORKSTATION_REPORTS = tuple("workstations." + family for family in ("logons", "processes", "usb", "protection"))
AD_REPORTS = ("events.journal", "security.events.chains", "ad.users.v2", "security.problems")
DOMAIN = 1275
FILE_COHORT_EVIDENCE_SQL = """with native as materialized (
    select distinct p.envelope->>'agent_id' as agent,p.envelope->>'generation' as generation,
        (r->>'record_id')::bigint as record_id from sli_e2e.cohort p
        cross join lateral jsonb_array_elements(p.event_rows) r where p.family=%s
), matched as materialized (
    select o.evidence_key from sli_plugin_file_audit.observations o join native n
        on o.agent_id::text=n.agent and o.generation=n.generation and o.record_id=n.record_id
) """


def prepare_runtime():
    # Per-plugin locks must be pre-existing inodes shared by API/import hooks.
    # This is our disposable volume, never the installation's plugin directory.
    directory = os.environ.get("SLI_PLUGIN_LOCK_DIR")
    if directory:
        from server.sli.plugins.registry import BUNDLED

        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        for plugin in BUNDLED:
            (root / (plugin + ".json")).touch(exist_ok=True)


def admin_connection(dsn):
    values = conninfo_to_dict(dsn)
    if values.get("dbname") != "sli_e2e" and not values.get("dbname", "").startswith("sli_test_"):
        raise ValueError("replay_target_not_disposable")
    return psycopg.connect(dsn, row_factory=dict_row)


def bootstrap(dsn):
    from scripts.maintenance import existing_postgres_bootstrap as b

    values = conninfo_to_dict(dsn)
    migrations = b.forward_migration_inventory(ROOT / "config/postgres_migrations")
    baseline = b.load_baseline(ROOT / "config/postgres_baseline", migrations)
    with admin_connection(dsn) as conn, tempfile.TemporaryDirectory(prefix="sli-e2e-") as directory:
        conn.autocommit = True
        conn.execute("create role adlog_user login nosuperuser noinherit")
        # Canonical baseline, exact migration ledger, no hand-written substitute.
        b.apply_baseline_sequence(baseline=baseline,
            rendered_schema_path=b.render_baseline_schema(baseline, "example.test", Path(directory) / "baseline.sql"),
            migrations=migrations, psql=Path(shutil.which("psql")), host=values["host"],
            port=int(values.get("port", 5432)), database=values["dbname"], admin_password="",
            runtime_password=secrets.token_urlsafe(32), platform_owner_password=secrets.token_urlsafe(32),
            admin_execute=conn.execute)
        expected = sorted([*b.base_schema_markers(ROOT / "config/postgres_schema.sql"),
                           *((m.version, m.name) for m in migrations)])
        actual = [(r["version"], r["name"]) for r in conn.execute("select version,name from schema_migrations order by version")]
        b.verify_exact_ledger(actual, expected)


def configure(dsn):
    os.environ.update({"ADLOG_PG_DSN": make_conninfo(dsn, user="adlog_user", password=""),
        "SLI_E2E_ADMIN_DSN": dsn, "ADLOG_DB_BACKEND": "postgres", "ADLOG_STORAGE_READ_MODE": "v2",
        "ADLOG_STORAGE_WRITE_MODE": "v2", "ADLOG_HISTORY_READ_MODE": "primary",
        "ADLOG_STORAGE_V2_WORKER_DSN": dsn,
        "ADLOG_SEMANTIC_WORKER_DSN": make_conninfo(dsn, user="sli_e2e_semantic", password=""),
        "ADLOG_SEMANTIC_RUNTIME_MODE": "facts-v1", "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
        "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1", "ADLOG_SEMANTIC_CORRELATION_ENABLED": "0",
        "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "0", "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
        "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0", "ADLOG_DISABLE_SCHEDULER": "1",
        "ADLOG_DISABLE_COLLECTION": "1", "ADLOG_ACQUISITION_DISABLED": "1"})
    with admin_connection(dsn) as conn:
        # Dedicated login satisfies the production semantic least-privilege gate.
        if not conn.execute("select 1 from pg_roles where rolname='sli_e2e_semantic'").fetchone():
            conn.execute("create role sli_e2e_semantic login noinherit")
            conn.execute("grant adlog_semantic_worker to sli_e2e_semantic with inherit false")
        conn.execute("create schema if not exists sli_e2e")
        conn.execute("create table sli_e2e.cohort (packet_id uuid primary key,family text,envelope jsonb,packet jsonb,event_rows jsonb)")


def migrate_copy(dsn):
    from deploy.linux.migrate import apply_pending
    from scripts.maintenance import existing_postgres_bootstrap as b

    # Validate the target before the canonical migration executor connects.
    with admin_connection(dsn):
        pass
    values = conninfo_to_dict(dsn)
    migrations = b.forward_migration_inventory(ROOT / "config/postgres_migrations")
    expected = dict(b.base_schema_markers(ROOT / "config/postgres_schema.sql"))
    expected.update((m.version, m.name) for m in migrations)
    def execute(paths):
        for path in paths:
            b.run_psql_file(psql=Path(shutil.which("psql")), host=values["host"],
                port=int(values.get("port", 5432)), user="postgres", database=values["dbname"],
                sql_path=path, password="")
    with psycopg.connect(dsn, autocommit=True) as conn:
        apply_pending(conn, migrations, expected, execute, baseline_version=0)


def select_cohort(conn, *, hours, family=None):
    from server.sli.storage.event_source_identity import (
        event_identity_hash,
        legacy_event_hash,
    )
    from server.sli.storage.storage_v2_models import parse_utc_timestamp

    conn.execute("insert into sli_e2e.cohort select packet_id,case envelope->>'module_id' "
        "when 'sli.windows.ad-dc' then 'ad-dc' when 'sli.file-audit' then 'file-audit' else 'workstations' end,"
        "envelope,packet,event_rows from sli_agent_packet_inbox "
        "where received_at>=now()-(%s * interval '1 hour') and envelope->>'module_id'=any(%s)",
        (hours, [MODULES[family]] if family else list(MODULES.values())))
    # Match both preserved v1 cores and new v2 publication without rewriting hashes.
    # SQL's timestamp text parser can round 100 ns ties differently.
    conn.execute("create table sli_e2e.native_identity(packet_id uuid,source_name text,channel text,"
                 "event_record_id bigint,at timestamptz,normalized_hashes bytea[])")
    with conn.cursor(name="replay_native_packets") as packets:
        packets.execute("select packet_id,packet->'header'->>'source' as source_name,event_rows "
                        "from sli_e2e.cohort where family='ad-dc'")
        while batch := packets.fetchmany(128):
            with conn.cursor() as cur, cur.copy("copy sli_e2e.native_identity from stdin") as writer:
                for packet in batch:
                    for row in packet["event_rows"]:
                        writer.write_row((packet["packet_id"], packet["source_name"], row["channel"],
                            row["record_id"], parse_utc_timestamp(row["time_created"]),
                            [bytes.fromhex(legacy_event_hash(row)), bytes.fromhex(event_identity_hash(row))]))
    # Only selected rows can be polled. This affects the copy, including inputs
    # which production has already acknowledged. Their attested bytes stay exact.
    conn.execute("update sli_agent_packet_inbox set imported_at=now() where imported_at is null")
    conn.execute("update sli_agent_packet_inbox set imported_at=null where packet_id in (select packet_id from sli_e2e.cohort)")
    conn.commit()


def cohort_core_ids(conn, family):
    if family == "ad-dc":
        return [r["id"] for r in conn.execute("select distinct e.id from events_v2_core e "
            "join servers s on s.id=e.server_id join storage_v2_channel c on c.id=e.channel_id "
            "join sli_e2e.native_identity n on n.source_name=s.hostname and n.channel=c.value "
            "and n.event_record_id=e.event_record_id and n.at=e.time_created_utc "
            "and e.normalized_hash=any(n.normalized_hashes) where e.domain_id=%s", (DOMAIN,))]
    return [r["id"] for r in conn.execute("select distinct e.id from events_v2_core e "
        "join servers s on s.id=e.server_id join storage_v2_channel c on c.id=e.channel_id "
        "join sli_e2e.cohort p on p.family=%s cross join lateral jsonb_array_elements(p.event_rows) r "
        "where s.hostname=p.packet->'header'->>'source' and c.value=r->>'channel' "
        "and e.event_record_id=(r->>'record_id')::bigint "
        "and e.time_created_utc=(r->>'time_created')::timestamptz and e.domain_id=%s", (family, DOMAIN))]


def agent_ids(conn, family):
    if family == "file-audit":
        return [r["id"] for r in conn.execute("select distinct p.envelope->>'agent_id' as id from sli_e2e.cohort p "
            "join servers s on s.hostname=p.packet->'header'->>'source' and s.domain_id=%s "
            "where p.family=%s", (DOMAIN, family))]
    return [r["id"] for r in conn.execute("select distinct p.envelope->>'agent_id' as id from sli_e2e.cohort p "
        "join sli_plugin_workstations.observations o on o.agent_key=p.envelope->>'agent_id' "
        "join entities_v2 e on e.id=coalesce(o.ad_computer_id,o.entity_id) "
        "where p.family=%s and e.domain_id=%s", (family, DOMAIN))]


def access_for(conn, family, report_key=None):
    fields = ["identity_basic", "technical", "security", "privilege", "raw_evidence"]
    if family == "ad-dc":
        scope = {"kind": "domain", "ids": [DOMAIN]}
        key = {"events.journal": "events.explorer", "security.problems": "security.queue"}.get(
            report_key, report_key or REPORTS[family])
    else:
        # Generic plugin reports do not accept a 'domain' URL parameter. Resolve
        # the domain to explicit agent IDs using retained server/core identity.
        from server.sli.access.scope import AccessScope, ScopeClause
        keys = agent_ids(conn, family)
        if family == "workstations":
            hosts = tuple(r["host"] for r in conn.execute("select host_id::text as host from sli_agents where id::text=any(%s)", (keys,)))
            clause = ScopeClause(plugin_ids=("sli.workstations",), source_instance_ids=hosts)
        else:
            clause = ScopeClause(device_ids=tuple(keys))
        scope = AccessScope("restricted", (clause,)).to_dict() if keys else {"mode": "none"}
        key = report_key or REPORTS[family]
    published = conn.execute("select version,definition_json from report_registry_v4 where report_key=%s order by version desc limit 1", (key,)).fetchone()
    capabilities = ["file-audit.view", "events.view", *((published or {}).get("definition_json", {}).get("required_capabilities", []))]
    return {"capabilities": capabilities, "reports": [{
        "report_key": key, "version": published["version"] if published else 1,
        "allowed": True, "allowed_actions": ["view"],
        "grants": [{"allowed_actions": ["view"], "field_categories": fields, "scope": scope}]}]}


class Handler(BaseHTTPRequestHandler):
    """Expose only the existing v2 report route, with a fixed replay read scope."""
    def log_message(self, *_):
        pass

    def _access_decision(self):
        with admin_connection(os.environ["SLI_E2E_ADMIN_DSN"]) as conn:
            return access_for(conn, self.family, self.report_key)

    def _send_json(self, payload, status=200):
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload, default=str).encode())

    def do_GET(self):
        from server.api.routes.reports_v2 import try_handle_get

        path = urlsplit(self.path)
        self.family = next((f for f, r in REPORTS.items() if path.path == f"/api/v2/reports/{r}/data"), None)
        if path.path in {f"/api/v2/reports/{r}/data" for r in WORKSTATION_REPORTS}:
            self.family = "workstations"
        if path.path in {f"/api/v2/reports/{r}/data" for r in FILE_REPORTS}:
            self.family = "file-audit"
        if path.path in {f"/api/v2/reports/{r}/data" for r in AD_REPORTS}:
            self.family = "ad-dc"
        self.report_key = path.path.split("/")[-2] if self.family else None
        if not self.family:
            self._send_json({"error": "replay_route_not_found"}, 404)
            return
        try:
            try_handle_get(self, path.path, parse_qs(path.query))
        except Exception:
            self._send_json({"error": "report_api_failed"}, 500)


def api_count(conn, family, *, base_url, report_key=None):
    if family == "workstations" and report_key is None:
        total = 0
        for key in WORKSTATION_REPORTS:
            count, reason = api_count(conn, family, base_url=base_url, report_key=key)
            if reason:
                return 0, reason
            total += count
        return total, None
    report_key = report_key or REPORTS[family]
    expected = set()
    if family == "ad-dc":
        expected = {str(value) for value in cohort_core_ids(conn, family)}
    elif family == "file-audit":
        expected = file_cohort_action_ids(conn, family)
    else:
        expected = {r["id"] for r in conn.execute("select o.id from sli_plugin_workstations.observations o "
            "join sli_e2e.cohort p on o.agent_key=p.envelope->>'agent_id' "
            "cross join lateral jsonb_array_elements(p.event_rows) r where p.family=%s "
            "and o.observation->>'generation'=p.envelope->>'generation' "
            "and (o.observation->>'record_id')::bigint=(r->>'record_id')::bigint "
            "and o.family=%s", (family, report_key.split('.')[-1]))}
        if report_key == "workstations.protection":
            expected.update(r["id"] for r in conn.execute("select s.id from sli_plugin_workstations.protection_state s "
                "join sli_e2e.cohort p on s.agent_key=p.envelope->>'agent_id' where p.family=%s "
                "and s.observed_at=(p.packet->'header'->>'observed_at_utc')::timestamptz "
                "and s.state=p.packet->'context'->'workstations'->'protection_state'", (family,)))
    period = {"period": "24h"}
    if family == "file-audit":
        # Generic cursors bind the resolved interval. A relative preset
        # advances between pages, so freeze this report's whole scan.
        end = conn.execute("select now() as at").fetchone()["at"]
        period = {"period": "custom", "from": (end - timedelta(hours=24)).isoformat(), "to": end.isoformat()}
    found, cursor = set(), None
    for _ in range(100):
        query = {**period, "limit": "100", "tz": "UTC"}
        if report_key == "security.events.chains":
            query["domain"] = str(DOMAIN)
        if cursor:
            query["cursor"] = cursor
        url = base_url + f"/api/v2/reports/{report_key}/data?" + urlencode(query)
        if family == "file-audit":
            data = read_file_report(url)
        else:
            with urlopen(url, timeout=30) as response:
                data = json.load(response)
        if data.get("state") in ("error", "denied", "not_collected", "not_installed"):
            return 0, "report_" + data["state"]
        found.update(str(row.get("event_db_id") if report_key == "security.events.chains" else row.get("id")) for row in data.get("items", []))
        # The journal check proves retained cohort attribution in a bounded
        # API sample; its count is not the whole report population.
        if family == "ad-dc" and found & expected:
            return len(found & expected), None
        if expected and expected.issubset(found):
            return len(expected), None
        if not data.get("has_more"):
            return len(found & expected), None
        cursor = data.get("next_cursor")
        if not cursor:
            return 0, "report_cursor_missing"
    return 0, "report_scan_limit"


def ad_report_checks(conn, *, base_url):
    from tools.e2e.ad_reports import check_reports

    return check_reports(conn, base_url=base_url, domain=DOMAIN)


def safe_error(stage, exc):
    # PostgreSQL messages can contain XML, account names and bind values.
    fixed_codes = {"agent_ad_dc_source_not_bound", "agent_ad_dc_source_not_configured",
        "agent_ad_dc_channel_not_configured", "agent_ad_dc_packet_invalid",
        "agent_packet_attestation_invalid", "storage_v2_admission_required",
        "workstation_packet_replay_conflict", "collection_packet_event_mismatch",
        "replay_target_not_disposable", "linux_migration_ledger_mismatch",
        "linux_baseline_ledger_incomplete", "plugin_update_draining",
        "file_audit_collection_not_admitted", "file_audit_projection_invalid",
        "file_audit_replay_conflict", "file_audit_projection_binding_invalid",
        "file_audit_action_scope_invalid", "file_audit_action_evidence_invalid"}
    primary = getattr(getattr(exc, "diag", None), "message_primary", None) or str(exc)
    if primary in fixed_codes:
        return stage + "_failed:" + primary
    if re.fullmatch(r"event \d+ idempotency (?:identity or )?hash mismatch", primary):
        return stage + "_failed:storage_v2_event_idempotency_mismatch"
    if re.fullmatch(r"(?:published )?source event allocation hash mismatch at ordinal \d+", primary):
        return stage + "_failed:immutable_source_identity_conflict"
    code = getattr(exc, "sqlstate", None)
    return stage + "_failed:" + type(exc).__name__ + (":" + code if code else "")


def run_replay(dsn, *, synthetic=False, hours=24, disabled_plugin=None, base_url=None, family=None):
    with admin_connection(dsn):
        pass
    configure(dsn)
    with admin_connection(dsn) as conn:
        if synthetic:
            from tools.e2e.synthetic import seed
            seed(conn, disabled_plugin=disabled_plugin)
        select_cohort(conn, hours=hours, family=family)
        cohort = conn.execute("select packet_id::text,family from sli_e2e.cohort order by packet_id").fetchall()
    reasons = {}
    failure_sites = Counter()
    from server.sli.agents.consumer import dispatch_packet
    from server.sli.agents.import_authorization import PacketPending
    from server.sli.core.postgres_runtime_pipeline import connect
    from server.sli.sources.collection_packet_import import consume_agent_packets

    def sink(connection, rows, **kwargs):
        try:
            with connection.transaction():
                dispatch_packet(connection, rows, **kwargs)
        except PacketPending as exc:
            reasons[kwargs["envelope"]["packet_id"]] = str(exc)
            return False
        except Exception as exc:
            reasons[kwargs["envelope"]["packet_id"]] = safe_error("agent_projection", exc)
            for frame in traceback.extract_tb(exc.__traceback__):
                try:
                    path = Path(frame.filename).resolve().relative_to(ROOT)
                except ValueError:
                    continue
                failure_sites[f"{path.as_posix()}:{frame.lineno}"] += 1
            return False
        return True

    # Walk once past deferred inputs. No periodic workers and no retry loop.
    after = None
    while True:
        scanned = []
        with connect() as conn:
            consume_agent_packets(conn, import_rows=sink, limit=128, after=after, on_scan=scanned.append)
        if not scanned:
            break
        after = scanned[-1]
    stage_errors = {}
    # Run the same durable post-collection handler, then selected semantic work
    # and entity-state projection. They retain their own transaction/lease rules.
    try:
        from server.jobs.collector import run_persisted_post_collection_worker_once
        result = run_persisted_post_collection_worker_once(worker_id="sli-e2e", limit=10) if family != "file-audit" else {}
        if result.get("failed"):
            stage_errors["post_collection"] = "post_collection_jobs_failed"
    except Exception as exc:
        stage_errors["post_collection"] = safe_error("post_collection", exc)
    try:
        from server.sli.semantic.semantic_processing_repository import (
            PROCESSOR_ID,
            PROCESSOR_VERSION,
        )
        from server.sli.semantic.semantic_producer import publish_semantic_candidates
        from server.sli.semantic.semantic_production_runtime import run_once
        from server.sli.semantic.semantic_worker_connection import (
            connect_semantic_worker,
        )
        from server.sli.storage.storage_v2_archive import ArchiveReader
        from server.sli.storage.storage_v2_repository import (
            PostgresArchiveManifestStore,
        )
        with admin_connection(dsn) as conn:
            # File audit and workstations own normalization/action projection
            # inside import; their normalizers declare no core semantic types.
            ids = cohort_core_ids(conn, "ad-dc") if family != "file-audit" else []
            with conn.cursor() as cur:
                for offset in range(0, len(ids), 5000):
                    publish_semantic_candidates(cur, ids[offset:offset + 5000], include_context=True)
                # A cloned completed job must actually execute current code.
                # Reset only exact selected normalization jobs in the copy.
                cur.execute("update semantic_processing_outbox set status='queued',attempt_count=0,"
                    "available_at=now(),lease_token=null,lease_until=null,heartbeat_at=null,completed_at=null,"
                    "last_error_code=null,last_error_detail=null where source_event_id=any(%s) "
                    "and job_kind='normalize_event' and processor_id=%s and processor_version=%s",
                    (ids, PROCESSOR_ID, PROCESSOR_VERSION))
        for offset in range(0, len(ids), 16):
            result = run_once(limit=16, connect_factory=connect_semantic_worker,
                archive=ArchiveReader(PostgresArchiveManifestStore(connect_semantic_worker)), source_event_ids=ids[offset:offset + 16])
            if result.get("failed"):
                # The durable log's error *code* is a Python exception class;
                # error_detail can contain private event values and stays local.
                with admin_connection(dsn) as diagnostic:
                    failed = diagnostic.execute("select last_error_code from semantic_processing_outbox "
                        "where source_event_id=any(%s) and status in ('failed','quarantined') "
                        "order by updated_at desc limit 1", (ids[offset:offset + 16],)).fetchone()
                code = (failed or {}).get("last_error_code", "")
                safe_code = code if code.isascii() and code.isidentifier() and len(code) <= 80 else "unknown"
                stage_errors["semantic"] = "semantic_jobs_failed:" + safe_code
    except Exception as exc:
        stage_errors["semantic"] = safe_error("semantic", exc)
    try:
        from server.sli.entities.entity_state_runtime import (
            run_entity_state_projection_cycle,
        )
        result = run_entity_state_projection_cycle(limit=max(1, len(cohort))) if family != "file-audit" else {}
        if result.get("failed"):
            stage_errors["projection"] = "projection_jobs_failed"
    except Exception as exc:
        stage_errors["projection"] = safe_error("projection", exc)
    server = None
    if base_url is None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        Thread(target=server.serve_forever, daemon=True).start()
        base_url = f"http://127.0.0.1:{server.server_port}"
    rows = []
    file_reports = []
    file_source = {}
    try:
        with admin_connection(dsn) as conn:
            for measured_family in ([family] if family else MODULES):
                count = lambda statement, params=(): conn.execute(statement, params).fetchone()["n"]
                row = {"family": measured_family, "inbox": count("select coalesce(sum(jsonb_array_length(event_rows)),0) as n "
                    "from sli_e2e.cohort where family=%s", (measured_family,)), "reason": None}
                row["imported"] = count("select coalesce(sum(jsonb_array_length(c.event_rows)),0) as n "
                    "from sli_e2e.cohort c join sli_agent_packet_inbox i using(packet_id) "
                    "where c.family=%s and i.imported_at is not null", (measured_family,))
                try:
                    if measured_family == "ad-dc":
                        from server.sli.semantic.semantic_processing import (
                            NORMALIZER_ID,
                            NORMALIZER_VERSION,
                        )

                        ids = cohort_core_ids(conn, measured_family)
                        row["core"] = len(ids)
                        row["facts"] = count("select count(*) as n from event_facts_v2 where event_id=any(%s)", (ids,))
                        row["normalized"] = count("select count(distinct source_event_id) as n from normalized_events "
                            "where source_event_id=any(%s) and processing_status='normalized' "
                            "and normalizer_id=%s and normalizer_version=%s", (ids, NORMALIZER_ID, NORMALIZER_VERSION))
                        row["projection"] = count("select count(distinct a.canonical_action_id) as n "
                            "from canonical_action_evidence a join normalized_events n using(normalized_event_id) "
                            "where n.source_event_id=any(%s) and n.normalizer_id=%s and n.normalizer_version=%s",
                            (ids, NORMALIZER_ID, NORMALIZER_VERSION))
                    elif measured_family == "file-audit":
                        row.update(file_cohort_evidence_counts(conn, measured_family))
                        row["normalized"] = row["facts"]  # File normalizer is part of import.
                    else:
                        row["facts"] = count("select count(distinct o.id) as n from sli_plugin_workstations.observations o "
                            "join sli_e2e.cohort p on o.agent_key=p.envelope->>'agent_id' "
                            "cross join lateral jsonb_array_elements(p.event_rows) r where p.family=%s "
                            "and o.observation->>'generation'=p.envelope->>'generation' "
                            "and (o.observation->>'record_id')::bigint=(r->>'record_id')::bigint", (measured_family,))
                        row["normalized"] = row["projection"] = row["facts"]  # Same transactional plugin projection.
                    row["api"], api_reason = api_count(conn, measured_family, base_url=base_url)
                    row["reason"] = api_reason
                    if measured_family == "file-audit":
                        end = conn.execute("select now() as at").fetchone()["at"]
                        file_reports = measure_reports(conn, agents=agent_ids(conn, measured_family),
                            start=end-timedelta(hours=hours), end=end, base_url=base_url)
                        file_source = source_summary(conn, agents=agent_ids(conn, measured_family),
                            start=end-timedelta(hours=hours), end=end)
                except Exception as exc:
                    conn.rollback()
                    row["reason"] = safe_error("report_measurement", exc)
                pending = [reasons[p["packet_id"]] for p in cohort if p["family"] == measured_family and p["packet_id"] in reasons]
                if pending:
                    row["reason"] = row["reason"] or min(pending)
                row["pending_reasons"] = {reason: pending.count(reason) for reason in sorted(set(pending))}
                row["pending_packets"] = len(pending)
                for step in ("facts", "normalized", "projection", "api"):
                    row.setdefault(step, 0)
                if not row["inbox"]:
                    row["reason"] = "no_packets_in_window"
                if any(row[s] == 0 for s in ("imported", "facts", "normalized", "projection", "api")):
                    first_zero = next(s for s in ("imported", "facts", "normalized", "projection", "api") if row[s] == 0)
                    related = stage_errors.get("semantic") if measured_family == "ad-dc" and first_zero in ("normalized", "projection") else None
                    row["reason"] = row["reason"] or related or f"{first_zero}_no_matching_rows_in_24h_domain_1275"
                rows.append(row)
    finally:
        if server:
            server.shutdown()
            server.server_close()
    # The HTTP surface must remain alive until all AD report checks finish.
    # A local fresh handler avoids pinning an older checkout during iteration.
    checks = []
    if any(row["family"] == "ad-dc" for row in rows):
        check_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        Thread(target=check_server.serve_forever, daemon=True).start()
        try:
            with admin_connection(dsn) as conn:
                checks = ad_report_checks(conn, base_url=f"http://127.0.0.1:{check_server.server_port}")
        finally:
            check_server.shutdown()
            check_server.server_close()
    retained_conflicts = [r for r in rows if r["family"] == "ad-dc" and is_retained_source_conflict(r)]
    failed = (stage_errors or any(r["reason"] and r not in retained_conflicts for r in rows)
              or any(c["failed"] for c in checks) or any(r["status"] == "failed" for r in file_reports))
    return {"status": replay_status(failed=failed, retained_conflicts=retained_conflicts, file_source=file_source),
            "domain": DOMAIN, "period": "24h", "rows": rows, "stage_errors": stage_errors, "reports": checks,
            "pending_reasons": dict(Counter(reasons.values())), "failure_sites": dict(failure_sites),
            "file_reports": file_reports, "file_source": file_source}


def file_cohort_evidence_counts(conn, family):
    # Expand each packet once, before matching retained observations. Joining
    # only agent/generation first multiplies every event by every packet.
    return conn.execute(FILE_COHORT_EVIDENCE_SQL + """
      select count(distinct m.evidence_key) as facts,count(distinct a.action_id) as projection
      from matched m left join sli_plugin_file_audit.action_evidence e using(evidence_key)
      left join sli_plugin_file_audit.actions a using(action_id)""", (family,)).fetchone()


def file_cohort_action_ids(conn, family):
    return {r["id"] for r in conn.execute(FILE_COHORT_EVIDENCE_SQL + """
        select distinct a.action_id as id from matched m
        join sli_plugin_file_audit.action_evidence e using(evidence_key)
        join sli_plugin_file_audit.actions a using(action_id)""", (family,))}


def replay_status(*, failed, retained_conflicts, file_source):
    if failed:
        return "failed"
    if retained_conflicts or any(file_source.get(key, {}).get("state") == "stale"
                                 for key in ("event_recency", "action_recency")):
        return "partial"
    return "verified"


def is_retained_source_conflict(row):
    reason = "agent_projection_failed:immutable_source_identity_conflict"
    return (row["reason"] == reason and set(row.get("pending_reasons", {})) == {reason}
            and all(row[step] > 0 for step in ("imported", "facts", "normalized", "projection", "api")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--mode", choices=("clone", "synthetic"), default="synthetic")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--family", choices=tuple(MODULES))
    args = parser.parse_args()
    prepare_runtime()
    if args.serve:
        ThreadingHTTPServer(("0.0.0.0", 18443), Handler).serve_forever()
        return
    logging.disable(logging.CRITICAL)
    # Raw diagnostics never reach docker logs/host output. Only fixed reason
    # codes and counts are returned; private logs live on the removed volume.
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        dsn = os.environ["SLI_E2E_ADMIN_DSN"]
        if args.mode == "synthetic":
            bootstrap(dsn)
        else:
            migrate_copy(dsn)
        result = run_replay(dsn, synthetic=args.mode == "synthetic", hours=args.hours,
                            base_url=None, family=args.family)
    print_result(result)


def print_result(result):
    print("family        inbox  import  facts  normalized  projection  API  reason")
    for row in result["rows"]:
        print(f"{row['family']:<13} {row['inbox']:>5} {row['imported']:>7} {row['facts']:>6} "
              f"{row['normalized']:>11} {row['projection']:>11} {row['api']:>4} {row['reason'] or '-'}")
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        reason = safe_error("replay", exc)
        print_result({"status": "failed", "reason": reason, "rows": [{
            "family": family, "inbox": 0, "imported": 0, "facts": 0,
            "normalized": 0, "projection": 0, "api": 0, "reason": reason} for family in MODULES]})
