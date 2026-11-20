"""Exact AD/GPO manifest storage; the caller owns authority and transactions."""
from __future__ import annotations

import json
from typing import Any

from server.sli.plugins.ad.snapshots.manifest import (
    SnapshotManifestError, snapshot_composition, validate_snapshot_manifest,
)
from server.sli.plugins.ad.snapshots.projection import insert_projection_receipts

def publish_snapshot_manifest(
    conn: Any,
    manifest: dict[str, Any],
    *,
    resolve_source: Any | None = None,
) -> dict[str, Any]:
    """Validate source readback and insert one immutable metadata receipt."""
    with conn.cursor() as cur:
        resolver = resolve_source or (
            lambda member: _resolve_manifest_source(cur, member)
        )
        normalized = validate_snapshot_manifest(manifest, resolve_source=resolver)
        cur.execute(
            """
            select manifest_id,manifest_sha256
            from ad_snapshot_manifests
            where domain_id=%s and slot_start_utc=%s and contract_version=%s
            """,
            (
                normalized["domain_id"], normalized["slot_start_utc"],
                normalized["contract_version"],
            ),
        )
        existing = cur.fetchone()
        if existing:
            existing_hash = bytes(existing["manifest_sha256"]).hex()
            if (
                str(existing["manifest_id"]) == normalized["manifest_id"]
                and existing_hash == normalized["manifest_sha256"]
            ):
                return {"manifest_id": normalized["manifest_id"], "replayed": 1}
            raise SnapshotManifestError(
                "conflicting manifest already exists for domain slot"
            )
        cur.execute(
            """
            insert into ad_snapshot_manifests(
              manifest_id,domain_id,domain_sid,domain_dns,slot_start_utc,
              assembled_at_utc,contract_version,coverage_state,manifest_sha256
            ) values(%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                normalized["manifest_id"], normalized["domain_id"],
                normalized["domain_sid"], normalized["domain_dns"],
                normalized["slot_start_utc"], normalized["assembled_at_utc"],
                normalized["contract_version"], normalized["coverage_state"],
                bytes.fromhex(normalized["manifest_sha256"]),
            ),
        )
        for member in normalized["members"]:
            cur.execute(
                """
                insert into ad_snapshot_manifest_sources(
                  manifest_id,family,contract_id,source_id,observed_at_utc,
                  source_state,payload_sha256,reason_code
                ) values(%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    normalized["manifest_id"], member["family"],
                    member["contract_id"], member["source_id"],
                    member["observed_at_utc"], member["source_state"],
                    bytes.fromhex(member["payload_sha256"]), member["reason_code"],
                ),
            )
        insert_projection_receipts(cur, manifest_id=normalized["manifest_id"])
    return {"manifest_id": normalized["manifest_id"], "replayed": 0}


def load_projection_manifest(conn: Any, manifest_id: str) -> dict[str, Any]:
    """Read one immutable manifest and its exact members by primary key."""
    with conn.cursor() as cur:
        cur.execute("""select manifest_id,domain_id,coverage_state,encode(manifest_sha256,'hex') as manifest_sha256 from ad_snapshot_manifests where manifest_id=%s::uuid""", (manifest_id,))
        manifest = cur.fetchone()
        if not manifest:
            raise SnapshotManifestError("projection manifest does not exist")
        cur.execute("""select family,source_id,encode(payload_sha256,'hex') as payload_sha256 from ad_snapshot_manifest_sources where manifest_id=%s::uuid order by family""", (manifest_id,))
        members = [dict(row) for row in cur.fetchall()]
    result = {**dict(manifest), "manifest_id": str(manifest["manifest_id"]), "members": members}
    return {**result, "composition": snapshot_composition(result)}


def load_exact_projection_source(conn: Any, *, family: str, source_id: str, payload_sha256: str) -> Any:
    """Load only the source ID/hash frozen in a manifest."""
    queries = {
        "users_v2": "select payload_json,encode(payload_sha256,'hex') as payload_sha256 from users_report_v2_snapshots where snapshot_id=%s::bigint",
        "computers_v6": "select payload_json,encode(payload_sha256,'hex') as payload_sha256 from computers_v6_source_snapshots where snapshot_uuid=%s::uuid",
        "gpo_v2": "select payload_json,encode(payload_sha256,'hex') as payload_sha256 from gpo_report_v2_source_snapshots where source_run_id=%s::uuid",
    }
    if family in {
        "ad_context_base", "ad_privileged_membership", "ad_vpn_membership",
        "ad_domain_posture", "ad_domain_health", "ad_gpo_governance",
    }:
        queries[family] = "select jsonb_build_object('run_id',run_id::text,'domain_id',domain_id,'observed_at_utc',observed_at_utc,'status',status) as payload_json,encode(bundle_sha256,'hex') as payload_sha256 from ad_context_runs where run_id=%s::uuid and status='completed'"
    query = queries.get(family)
    if query is None:
        raise SnapshotManifestError("projection source family is not allowlisted")
    with conn.cursor() as cur:
        cur.execute(query, (source_id,))
        row = cur.fetchone()
    if not row or str(row["payload_sha256"]).casefold() != payload_sha256.casefold():
        raise SnapshotManifestError("exact projection source hash mismatch or source missing")
    payload = row["payload_json"]
    return json.loads(payload) if isinstance(payload, str) else payload


def _resolve_manifest_source(
    cur: Any, member: dict[str, Any]
) -> dict[str, Any] | None:
    family = member["family"]
    ad_sections = {
        "ad_context_base": ("directory_accounts", "directory_group_graph", "directory_exact_logon"),
        "ad_privileged_membership": ("privileged_membership",),
        "ad_vpn_membership": ("vpn_membership",),
        "ad_domain_posture": ("domain_posture",),
        "ad_domain_health": ("domain_health",),
        "ad_gpo_governance": ("gpo_governance",),
    }
    queries = {
        "users_v2": """
            select snap.contract_id,snap.snapshot_id::text as source_id,
                   snap.domain_id,domain.domain_sid,domain.fqdn as domain_dns,
                   snap.source_observed_at_utc as observed_at_utc,
                   snap.source_state,encode(snap.payload_sha256,'hex') as payload_sha256
            from users_report_v2_snapshots snap
            join domains domain on domain.id=snap.domain_id
            where snap.snapshot_id=%s::bigint
        """,
        "computers_v6": """
            select 'sli.ad-computers.snapshot/2.0'::text as contract_id,
                   snap.snapshot_uuid::text as source_id,snap.domain_id,
                   domain.domain_sid,domain.fqdn as domain_dns,
                   snap.captured_at_utc as observed_at_utc,
                   snap.collection_status as source_state,
                   encode(snap.payload_sha256,'hex') as payload_sha256
            from computers_v6_source_snapshots snap
            join domains domain on domain.id=snap.domain_id
            where snap.snapshot_uuid=%s::uuid
        """,
        "gpo_v2": """
            select snap.schema_version as contract_id,
                   snap.source_run_id::text as source_id,snap.domain_id,
                   domain.domain_sid,domain.fqdn as domain_dns,
                   snap.source_observed_at_utc as observed_at_utc,
                   snap.collection_status as source_state,
                   encode(snap.payload_sha256,'hex') as payload_sha256
            from gpo_report_v2_source_snapshots snap
            join domains domain on domain.id=snap.domain_id
            where snap.source_run_id=%s::uuid and snap.import_status='completed'
        """,
    }
    query = queries.get(family)
    parameters: tuple[Any, ...] = (member["source_id"],)
    if family in ad_sections:
        expected = ad_sections[family]
        query = """
            select run.source_pack_id as contract_id,run.run_id::text as source_id,
                   run.domain_id,domain.domain_sid,domain.fqdn as domain_dns,
                   run.observed_at_utc,
                   case when bool_or(section.status='failed') then 'failed'
                        when bool_or(section.status in ('partial','skipped')) then 'partial'
                        else 'complete' end::text as source_state,
                   encode(run.bundle_sha256,'hex') as payload_sha256
            from ad_context_runs run
            join domains domain on domain.id=run.domain_id
            join ad_context_sections section on section.run_id=run.run_id
            where run.run_id=%s::uuid and run.status='completed'
              and section.section_name = any(%s)
            group by run.source_pack_id,run.run_id,run.domain_id,domain.domain_sid,
                     domain.fqdn,run.observed_at_utc,run.bundle_sha256
            having count(distinct section.section_name)=%s
        """
        parameters = (member["source_id"], list(expected), len(expected))
    if query is None:
        raise SnapshotManifestError("manifest source family has no resolver")
    cur.execute(query, parameters)
    row = cur.fetchone()
    if not row:
        return None
    return {"family": family, "import_state": "completed", **dict(row)}
