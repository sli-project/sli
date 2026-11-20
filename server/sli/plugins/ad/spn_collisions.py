"""Bounded SPN comparison inside a single directory-accounts collection run."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from server.sli.reporting.reporting_common import format_iso, get_runtime_connection, parse_utc

OWNER_ID = "sli.ad"
MAX_OWNERS = 5000
MAX_DOMAINS = 100
MAX_SPN_VALUES = 50000
STATE_FIELDS = ("enabled", "trusted_for_delegation", "trusted_to_auth_for_delegation",
                "does_not_require_preauth", "msds_supported_encryption_types")


def analyze(rows, *, now, params=None):
    params = params or {}
    groups = defaultdict(dict)
    unknown_identity = 0
    unknown_spn = 0
    value_count = 0
    truncated = False
    for row in rows:
        record = row.get("attributes_json") or {}
        attrs = record.get("attributes") or {}
        identity = record.get("identity") or {}
        stable = identity.get("object_guid") or identity.get("object_sid")
        if not stable or not row.get("entity_id") or not row.get("run_id"):
            unknown_identity += 1
            continue
        names = attrs.get("service_principal_names")
        if not isinstance(names, list):
            unknown_spn += 1
            continue
        password = parse_utc(attrs.get("password_last_set_utc"))
        age = (now - password).days if password and password <= now else None
        states = {key: attrs.get(key) for key in STATE_FIELDS}
        for key in STATE_FIELDS[:-1]:
            states[key] = states[key] if isinstance(states[key], bool) else None
        owner = {"entity_id": row["entity_id"], "entity_type": row.get("entity_type"),
                 "domain_id": row["domain_id"], "run_id": row["run_id"],
                 "password_last_set_utc": format_iso(password) if password else None,
                 "password_age_days": age, **states,
                 "observed_at_utc": format_iso(row.get("observed_at_utc")),
                 "source_freshness": "unknown" if parse_utc(row.get("observed_at_utc")) is None else "stale" if parse_utc(row["observed_at_utc"]) < now - timedelta(hours=36) else "fresh",
                 "owner_quality": "unknown" if age is None or any(value is None for value in states.values()) else "known"}
        # Only case changes. Ports, service classes, instance names, slashes,
        # whitespace and Unicode characters are never rewritten or stripped.
        for name in names:
            if not isinstance(name, str) or not name:
                continue
            value_count += 1
            if value_count > MAX_SPN_VALUES:
                truncated = True
                break
            key = (row["domain_id"], row["run_id"], name.lower())
            groups[key][row["entity_id"]] = {**owner, "spn": name}
        if truncated:
            break
    items = []
    for (domain, run, normalized), owners in sorted(groups.items()):
        if params.get("spn_collisions_only", "true") != "false" and len(owners) < 2:
            continue
        if params.get("spn_service") and normalized.split("/", 1)[0] != str(params["spn_service"]).lower():
            continue
        for owner in owners.values():
            if params.get("spn_enabled") in {"true", "false"} and owner["enabled"] is not (params["spn_enabled"] == "true"):
                continue
            flags = [owner[key] for key in STATE_FIELDS[1:4]]
            flagged = True if True in flags else False if all(value is False for value in flags) else None
            if params.get("spn_delegation") in {"true", "false"} and flagged is not (params["spn_delegation"] == "true"):
                continue
            if params.get("spn_password_days") is not None and (owner["password_age_days"] is None or owner["password_age_days"] < params["spn_password_days"]):
                continue
            if params.get("q") and str(params["q"]).lower() not in owner["spn"].lower():
                continue
            items.append({**owner, "owner_count": len(owners), "normalized_spn": normalized,
                          "row_id": f"{domain}:{run}:{normalized}:{owner['entity_id']}"})
    identities = {(item["domain_id"], item["run_id"], item["entity_id"]): item for item in items}
    truncated = truncated or len(items) > MAX_OWNERS
    metrics = {
        "collisions": len({(item["domain_id"], item["run_id"], item["normalized_spn"]) for item in items if item["owner_count"] > 1}),
        "disabled_owners": sum(item["enabled"] is False for item in identities.values()),
        "flagged_owners": sum(any(item[key] is True for key in STATE_FIELDS[1:4]) for item in identities.values()),
        "unknown_owners": sum(item["owner_quality"] == "unknown" for item in identities.values()),
    }
    return {"items": items[:MAX_OWNERS], "metrics": {} if truncated else metrics,
            "unknown_identity_count": unknown_identity, "unknown_spn_count": unknown_spn, "truncated": truncated}


def get_collisions(*, domain_ids, params=None, now=None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    params = params or {}
    if domain_ids == []:
        raise PermissionError("spn_domain_scope_required")
    if params.get("spn_domain") is not None:
        domain_id = int(params["spn_domain"])
        if domain_id <= 0 or (domain_ids is not None and domain_id not in domain_ids):
            raise PermissionError("report_scope_not_executable")
        domain_ids = [domain_id]
    with get_runtime_connection() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute("set local statement_timeout = '10s'")
        cur.execute(
            """select distinct on (run.domain_id) run.run_id::text, run.domain_id,
                      run.observed_at_utc, run.scope_json, run.status as run_status,
                      section.status as section_status, section.record_count
               from ad_context_runs run
               join ad_context_sections section on section.run_id=run.run_id
               where section.section_name='directory_accounts'
                 and run.mode in ('full','reconcile') and run.status<>'importing'
                 and run.observed_at_utc>=%s and run.observed_at_utc<=%s
                 and (%s::bigint[] is null or run.domain_id=any(%s))
               order by run.domain_id,run.observed_at_utc desc,run.created_at desc,run.run_id desc
               limit %s""", (now - timedelta(days=31), now, domain_ids, domain_ids, MAX_DOMAINS + 1),
        )
        sources = [dict(row) for row in cur.fetchall()]
        eligible = [row for row in sources[:MAX_DOMAINS] if row["run_status"] == "completed"
                    and row["section_status"] in {"complete", "partial"}
                    and (row.get("scope_json") or {}).get("search_base")]
        run_ids = [row["run_id"] for row in eligible]
        rows = []
        if run_ids:
            # Evidence identifies members of this run even when unchanged
            # versions retain the source_run_id of an older collection.
            cur.execute(
                """select entity.id as entity_id, entity.domain_id, kind.value as entity_type,
                          evidence.source_run_id::text as run_id, evidence.observed_at_utc,
                          version.attributes_json
                   from ad_context_evidence evidence
                   join ad_context_runs run on run.run_id=evidence.source_run_id
                   join entities_v2 entity on entity.domain_id=run.domain_id
                   join storage_v2_entity_type kind on kind.id=entity.entity_type_id
                   join ad_context_entity_versions version on version.entity_id=entity.id
                     and version.source_section='directory_accounts'
                     and version.attributes_json->>'record_key'=evidence.locator_json->>'record_key'
                     and version.valid_from_utc<=evidence.observed_at_utc
                     and (version.valid_to_utc is null or version.valid_to_utc>evidence.observed_at_utc)
                   where evidence.source_run_id=any(%s::uuid[])
                     and evidence.evidence_type='entity_observation'
                     and evidence.locator_json->>'section'='directory_accounts'
                     and kind.value in ('ad_user','ad_computer')
                   order by entity.domain_id,entity.id limit %s""", (run_ids, MAX_OWNERS + 1),
            )
            rows = [dict(row) for row in cur.fetchall()]
    data = analyze(rows[:MAX_OWNERS], now=now, params=params)
    truncated = len(sources) > MAX_DOMAINS or len(rows) > MAX_OWNERS or data["truncated"]
    missing_records = sum(int(row.get("record_count") or 0) for row in eligible) > len(rows)
    missing_domains = bool(domain_ids and set(domain_ids) - {row["domain_id"] for row in eligible})
    partial = truncated or missing_records or missing_domains or data["unknown_identity_count"] or data["unknown_spn_count"] or len(eligible) != len(sources) or any(row["section_status"] != "complete" for row in eligible)
    stale = any(parse_utc(row["observed_at_utc"]) < now - timedelta(hours=36) for row in eligible)
    state = "unavailable" if not eligible else "partial" if partial else "stale" if stale else "ok" if data["items"] else "empty"
    return {**data, "state": state, "truncated": truncated,
            "metrics": {} if truncated or missing_records or not eligible else data["metrics"],
            "coverage": {"state": state, "sources": [{"domain_id": row["domain_id"], "run_id": row["run_id"],
                         "observed_at_utc": format_iso(row["observed_at_utc"]), "section_status": row["section_status"], "run_status": row["run_status"],
                         "search_base": (row.get("scope_json") or {}).get("search_base")} for row in sources[:MAX_DOMAINS]],
                         "unknown_identity_count": data["unknown_identity_count"], "unknown_spn_count": data["unknown_spn_count"],
                         "missing_records": missing_records, "truncated": truncated}}
