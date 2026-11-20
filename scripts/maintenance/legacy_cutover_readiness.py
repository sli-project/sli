#!/usr/bin/env python3
"""Read-only, per-source evidence for the owner's legacy collection cutover."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.ad_jobs_parity import SOURCE_TABLES, compare_snapshot  # noqa: E402
from sli_agent.ad_dc import CHANNELS as DC_CHANNELS  # noqa: E402
from sli_agent.workstations import CHANNELS as WORKSTATION_CHANNELS  # noqa: E402

MODULE_CHANNELS = {"sli.windows.ad-dc": DC_CHANNELS, "sli.workstations": WORKSTATION_CHANNELS}
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def load_inventory(path: Path) -> list[dict]:
    """Expected sources are owner supplied, never inferred from received packets."""
    value = json.loads(path.read_text(encoding="utf-8"))
    sources = value.get("sources") if isinstance(value, dict) else None
    if not isinstance(sources, list) or not 1 <= len(sources) <= 10000:
        raise ValueError("inventory_invalid")
    identities = set()
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("inventory_invalid")
        for field in ("module_id", "source_instance_id"):
            if not isinstance(source.get(field), str) or not 1 <= len(source[field]) <= 512:
                raise ValueError("inventory_invalid")
        identity = (source["module_id"], source["source_instance_id"])
        if identity in identities:
            raise ValueError("inventory_invalid")
        identities.add(identity)
        if source["module_id"] == "sli.windows.ad-dc" and any(
            type(source.get(key)) is not int or source[key] < 1 for key in ("domain_id", "legacy_server_id")
        ):
            raise ValueError("inventory_invalid")
        probes = source.get("history_probes")
        if not isinstance(probes, list) or not 1 <= len(probes) <= 32:
            raise ValueError("inventory_invalid")
        for probe in probes:
            if (not isinstance(probe, dict) or not isinstance(probe.get("path"), str)
                    or not probe["path"].startswith("/api/") or urlsplit(probe["path"]).netloc
                    or not isinstance(probe.get("rows_key"), str) or not probe["rows_key"]):
                raise ValueError("inventory_invalid")
    return sources


def history_payload_readable(payload, probe: dict) -> bool:
    if not isinstance(payload, dict) or payload.get("error") or payload.get("status") in ("error", "failed"):
        return False
    rows = payload
    for key in probe["rows_key"].split("."):
        if not isinstance(rows, dict) or key not in rows:
            return False
        rows = rows[key]
    # Choose a known populated historical interval: an empty response proves
    # neither retained history nor a working report reader.
    return isinstance(rows, list) and bool(rows)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def read_history(probe: dict, *, api_base: str) -> bool:
    try:
        base = urlsplit(api_base)
        if (base.scheme not in {"http", "https"} or not base.hostname or base.username or base.password
                or base.path not in {"", "/"} or base.query or base.fragment
                or base.scheme == "http" and base.hostname not in {"127.0.0.1", "localhost", "::1"}):
            return False
        request = Request(api_base.rstrip("/") + probe["path"], method="GET",
                          headers={"Accept": "application/json"})
        token = os.environ.get("SLI_CUTOVER_API_TOKEN")
        if token:
            request.add_header("Authorization", "Bearer " + token)
        # Never forward authentication to another origin or accept a login page.
        with build_opener(_NoRedirect()).open(request, timeout=10) as response:
            if response.status != 200 or response.headers.get_content_type() != "application/json":
                return False
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        return len(raw) <= MAX_RESPONSE_BYTES and history_payload_readable(json.loads(raw), probe)
    except Exception:
        return False


def read_snapshot(conn, source: dict, *, now: datetime, cutoff: datetime) -> dict:
    """Pin parity to real, recent source members, rather than a supplied verdict."""
    from server.ad_context.repository import load_exact_projection_source, load_projection_manifest

    with conn.cursor() as cur:
        cur.execute("""select manifest_id from ad_snapshot_manifests
            where domain_id=%s and assembled_at_utc between %s and %s
            order by assembled_at_utc desc,manifest_id desc limit 1""",
                    (source["domain_id"], cutoff, now))
        row = cur.fetchone()
    if not row:
        raise ValueError("manifest_missing")
    manifest = load_projection_manifest(conn, str(row["manifest_id"]))
    sources = [{**member, "payload_json": load_exact_projection_source(conn, **member)}
               for member in manifest["members"] if member["family"] in SOURCE_TABLES]
    return {"manifest": manifest, "sources": sources}


def check_source(conn, source: dict, *, now: datetime, max_age_seconds: int,
                 history_reader, parity_compare=compare_snapshot) -> dict:
    checks = {"agent_enrolled": False, "recent_import": False,
              "ad_jobs_parity": "not_proven", "history_readable": False}
    reasons = []
    module = source["module_id"]
    if module not in MODULE_CHANNELS:
        return {"verdict": "NO-GO", "checks": checks, "reasons": ["replacement_module_unavailable"]}
    cutoff = now - timedelta(seconds=max_age_seconds)
    try:
        with conn.cursor() as cur:
            if module == "sli.workstations":
                # Workstation authority is the registry assignment, not a DC
                # binding row (the ingest/consumer deliberately use this seam).
                cur.execute("""select a.id as agent_id,a.host_id,a.assigned_modules from sli_agents a
                    where a.host_id::text=%s and a.status='active'
                      and exists(select 1 from sli_agent_certificates c where c.agent_id=a.id
                        and c.revoked_at is null and c.not_before<=%s and c.not_after>%s)""",
                            (source["source_instance_id"], now, now))
            else:
                cur.execute("""select a.id as agent_id,a.host_id,a.assigned_modules,
                    b.source_name,b.policy_revision from sli_agent_module_bindings b
                join sli_agents a on a.id=b.agent_id
                where b.module_id=%s and b.source_instance_id=%s and a.status='active'
                  and a.host_id::text=b.source_instance_id
                  and exists(select 1 from sli_agent_certificates c where c.agent_id=a.id
                    and c.revoked_at is null and c.not_before<=%s and c.not_after>%s)""",
                            (module, source["source_instance_id"], now, now))
            bindings = cur.fetchall()
            binding = bindings[0] if len(bindings) == 1 else None
            assignments = [item for item in binding["assigned_modules"]
                           if isinstance(item, dict) and item.get("module_id") == module] if binding else []
            checks["agent_enrolled"] = bool(len(assignments) == 1 and assignments[0].get("enabled") is True)
            if checks["agent_enrolled"]:
                config = assignments[0].get("config", {})
                policy_revision = config.get("policy_revision", "1")
                if module == "sli.windows.ad-dc":
                    checks["agent_enrolled"] = (
                        policy_revision == binding["policy_revision"]
                        and config.get("source_name") == binding["source_name"])
            if checks["agent_enrolled"] and module == "sli.windows.ad-dc":
                cur.execute("""select exists(select 1 from servers where id=%s and domain_id=%s
                    and lower(hostname)=lower(%s)) as present""",
                            (source["legacy_server_id"], source["domain_id"], binding["source_name"]))
                checks["agent_enrolled"] = bool(cur.fetchone()["present"])
            if checks["agent_enrolled"]:
                cur.execute("""select distinct i.packet->'header'->>'channel' as channel
                    from sli_agent_packet_inbox i join sli_agent_receipts r on r.packet_id=i.packet_id
                    where r.agent_id=%s and r.module_id=%s
                      and r.envelope->>'source_instance_id'=%s and r.envelope->>'policy_revision'=%s
                      and i.imported_at between %s and %s and r.received_at between %s and %s
                      and r.envelope->>'continuity_state'<>'gap'
                      and i.packet->'context'->%s->>'read_error' is null""",
                            (binding["agent_id"], module, source["source_instance_id"], policy_revision,
                             cutoff, now, cutoff, now, "ad_dc" if module == "sli.windows.ad-dc" else "workstations"))
                channels = {row["channel"] for row in cur.fetchall()}
                checks["recent_import"] = set(MODULE_CHANNELS[module]).issubset(channels)
        if not checks["agent_enrolled"]:
            reasons.append("agent_module_not_enrolled")
        if not checks["recent_import"]:
            reasons.append("recent_import_missing")
        if module == "sli.windows.ad-dc":
            parity = parity_compare(read_snapshot(conn, source, now=now, cutoff=cutoff))
            checks["ad_jobs_parity"] = "match" if (
                parity.get("status") == "match" and parity.get("coverage_state") == "complete") else "not_proven"
            if checks["ad_jobs_parity"] != "match":
                reasons.append("ad_jobs_parity_not_proven")
        else:
            checks["ad_jobs_parity"] = "not_applicable"
    except Exception:
        # A DB bind diagnostic or HTTP response may contain private source data.
        reasons.append("source_read_failed")
    try:
        probes = source.get("history_probes", [])
        checks["history_readable"] = bool(probes) and all(history_reader(probe) for probe in probes)
    except Exception:
        checks["history_readable"] = False
    if not checks["history_readable"]:
        reasons.append("history_unreadable")
    return {"verdict": "NO-GO" if reasons else "GO", "checks": checks, "reasons": reasons}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--api-base", required=True, help="Report API origin; authentication is supplied by environment")
    parser.add_argument("--max-age-seconds", type=int, default=86400)
    args = parser.parse_args(argv)
    try:
        sources = load_inventory(args.inventory)
        if not 1 <= args.max_age_seconds <= 7 * 86400:
            raise ValueError("age_invalid")
        dsn = os.environ.get("SLI_CUTOVER_PG_DSN")
        if not dsn:
            raise ValueError("dsn_missing")
        import psycopg
        from psycopg.rows import dict_row

        results = []
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5, row_factory=dict_row,
                             options="-c default_transaction_read_only=on -c statement_timeout=5000") as conn:
            conn.read_only = True
            for index, source in enumerate(sources, 1):
                with conn.transaction():
                    result = check_source(conn, source, now=datetime.now(timezone.utc),
                                          max_age_seconds=args.max_age_seconds,
                                          history_reader=lambda probe: read_history(probe, api_base=args.api_base))
                results.append({"source": f"source-{index:03d}", **result})
        verdict = "GO" if all(row["verdict"] == "GO" for row in results) else "NO-GO"
        print(json.dumps({"verdict": verdict, "scope": "supplied_inventory", "sources": results}, sort_keys=True))
        return 0 if verdict == "GO" else 1
    except Exception:
        print(json.dumps({"verdict": "NO-GO", "reason": "readiness_unavailable"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
