#!/usr/bin/env python3
from __future__ import annotations

"""Plan-bound repair of derived RADIUS sessions after an entities_v2 reset."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.stage10_radius_session_reconciliation_production_control import (
    _connect,
    _EvidenceManifest,
    _load_environment,
    _read_verified_record,
)
from server.source_packs.radius.accounting import (
    ACCESS_ACCEPT_PACKET_TYPE,
    parse_database_compatible_record,
)
from server.source_packs.radius.session_read_model import CONTRACT_ID
from server.source_packs.radius.session_rebind import (
    ImmutableStoredRadiusObservation,
    VerifiedRadiusEvidence,
    build_rebound_radius_projection,
)

CONFIRMATION = "APPLY-RADIUS-SESSION-V2-IDENTITY-REBIND"
MAXIMUM_MANIFESTS = 100_000
MAXIMUM_MANIFEST_BYTES = 64 * 1024 * 1024


class RadiusSessionV2IdentityRebindControlError(RuntimeError):
    pass


def validate_apply_request(plan: Mapping[str, Any], *, confirmation: str) -> None:
    if confirmation != CONFIRMATION:
        raise RadiusSessionV2IdentityRebindControlError("rebind_confirmation_required")
    value = dict(plan)
    claimed = str(value.pop("plan_sha256", ""))
    actual = sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if value.get("status") != "ready" or claimed != actual:
        raise RadiusSessionV2IdentityRebindControlError("rebind_plan_binding_invalid")


def _read_plan(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusSessionV2IdentityRebindControlError("rebind_plan_invalid") from exc
    if not isinstance(value, dict):
        raise RadiusSessionV2IdentityRebindControlError("rebind_plan_invalid")
    return value


def _manifest(row: Mapping[str, Any]) -> _EvidenceManifest:
    return _EvidenceManifest(
        str(row["evidence_uid"]),
        str(row["canonical_record_sha256"]),
        str(row["object_sha256"]),
        int(row["object_size_bytes"]),
        int(row["cursor_start_byte_offset"]),
        int(row["batch_record_ordinal"]),
    )


def _materialize(conn: Any) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            "select source_instance_id,organization_scope "
            "from acquisition_source_instances "
            "where source_kind='windows.nps.radius' order by source_instance_id"
        )
        sources = list(cur.fetchall())
        if len(sources) != 1:
            raise RadiusSessionV2IdentityRebindControlError("rebind_exact_source_required")
        source = str(sources[0]["source_instance_id"])
        organization = str(sources[0]["organization_scope"])
        cur.execute(
            "select revision from acquisition_stream_cursors "
            "where source_instance_id=%s and stream_id='radius-accounting' "
            "and transport_binding='windows-rpc-smb-readonly-tail-v1'",
            (source,),
        )
        cursor = cur.fetchone()
        if cursor is None:
            raise RadiusSessionV2IdentityRebindControlError("rebind_cursor_required")
        revision = int(cursor["revision"])
        cur.execute(
            "select evidence_uid::text,canonical_record_sha256,object_sha256,"
            "object_size_bytes,cursor_start_byte_offset,batch_record_ordinal "
            "from core_evidence_manifests where source_instance_id=%s "
            "and stream_id='radius-accounting' "
            "and transport_binding='windows-rpc-smb-readonly-tail-v1' "
            "order by cursor_start_byte_offset,batch_record_ordinal,evidence_uid",
            (source,),
        )
        manifests = list(cur.fetchall())
        total_bytes = sum(int(row["object_size_bytes"]) for row in manifests)
        if not 1 <= len(manifests) <= MAXIMUM_MANIFESTS or total_bytes > MAXIMUM_MANIFEST_BYTES:
            raise RadiusSessionV2IdentityRebindControlError("rebind_manifest_bound_exceeded")
        by_uid = {str(row["evidence_uid"]): row for row in manifests}
        cur.execute(
            "select observation.observation_id::text,observation.evidence_uid::text,"
            "observation.lifecycle_event,observation.timestamp_state,"
            "observation.observed_at_utc,manifest.canonical_record_sha256 "
            "from radius_accounting_session_observations observation "
            "join core_evidence_manifests manifest "
            "on manifest.evidence_uid=observation.evidence_uid "
            "order by observation.observation_id"
        )
        observation_rows = list(cur.fetchall())
        selected: dict[str, VerifiedRadiusEvidence] = {}
        classes: set[str] = set()
        for row in observation_rows:
            manifest = _manifest(by_uid[str(row["evidence_uid"])])
            record = _read_verified_record(manifest)
            selected[record.evidence_uid] = VerifiedRadiusEvidence(
                record.evidence_uid, record.canonical_record, manifest.canonical_record_sha256
            )
            parsed = parse_database_compatible_record(record.canonical_record)
            classes.add(str(parsed.class_attribute or ""))
        digest = sha256()
        selected_accepts = 0
        for row in manifests:
            digest.update(
                (
                    str(row["evidence_uid"])
                    + "\0"
                    + str(row["canonical_record_sha256"])
                    + "\0"
                    + str(row["object_sha256"])
                    + "\n"
                ).encode()
            )
            uid = str(row["evidence_uid"])
            if uid in selected:
                continue
            manifest = _manifest(row)
            record = _read_verified_record(manifest)
            parsed = parse_database_compatible_record(record.canonical_record)
            if (
                parsed.packet_type == ACCESS_ACCEPT_PACKET_TYPE
                and str(parsed.class_attribute or "") in classes
            ):
                selected[uid] = VerifiedRadiusEvidence(
                    uid, record.canonical_record, manifest.canonical_record_sha256
                )
                selected_accepts += 1
        stored = tuple(
            ImmutableStoredRadiusObservation(
                str(row["observation_id"]),
                str(row["evidence_uid"]),
                str(row["lifecycle_event"]),
                str(row["timestamp_state"]),
                row["observed_at_utc"],
                str(row["canonical_record_sha256"]),
            )
            for row in observation_rows
        )
        cur.execute("set local role adlog_radius_accounting_worker")

        def lookup(org: str, distinguished_name: str) -> str | None:
            cur.execute(
                "select sli_radius_resolve_principal_key(%s,%s) as key",
                (org, distinguished_name),
            )
            row = cur.fetchone()
            return str(row["key"]) if row and row["key"] is not None else None

        folded = build_rebound_radius_projection(
            evidence_records=tuple(selected.values()),
            stored_observations=stored,
            source_instance_id=source,
            organization_fqdn=organization,
            source_timezone_id="N. Central Asia Standard Time",
            source_utc_offset_minutes=420,
            exact_lookup=lookup,
        )
        cur.execute("reset role")
    return {
        "source": source,
        "cursor_revision": revision,
        "manifest_count": len(manifests),
        "manifest_bytes": total_bytes,
        "manifest_sha256": digest.hexdigest(),
        "selected_evidence_count": len(selected),
        "selected_access_accept_count": selected_accepts,
        "observation_count": len(observation_rows),
        "folded": folded,
    }


def _summary(folded: Any) -> dict[str, int]:
    return {
        "input_observations": folded.input_observations,
        "exact_ready_observations": folded.exact_ready_observations,
        "unresolved_identity_observations": folded.unresolved_identity_observations,
        "unresolved_timestamp_observations": folded.unresolved_timestamp_observations,
        "session_rows": len(folded.sessions),
        "complete_sessions": folded.complete_sessions,
        "partial_sessions": folded.partial_sessions,
        "open_observed_sessions": folded.open_observed_sessions,
    }


def _validate_materialized(plan: Mapping[str, Any], state: Mapping[str, Any]) -> None:
    expected = {
        "source_instance_sha256": sha256(str(state["source"]).encode()).hexdigest(),
        "cursor_revision": state["cursor_revision"],
        "manifest_count": state["manifest_count"],
        "manifest_bytes": state["manifest_bytes"],
        "manifest_sha256": state["manifest_sha256"],
        "selected_evidence_count": state["selected_evidence_count"],
        "rebound": _summary(state["folded"]),
    }
    for key, value in expected.items():
        if plan.get(key) != value:
            raise RadiusSessionV2IdentityRebindControlError("rebind_plan_input_drift")


def apply(plan: Mapping[str, Any]) -> dict[str, Any]:
    with _connect() as conn:
        state = _materialize(conn)
        _validate_materialized(plan, state)
        conn.rollback()
        baseline = dict(plan["baseline"])
        folded = state["folded"]
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute(
                    "select pg_advisory_xact_lock("
                    "hashtext('radius-vpn-session-v2-identity-rebind'))"
                )
                cur.execute(
                    "select revision from acquisition_stream_cursors "
                    "where source_instance_id=%s and stream_id='radius-accounting' "
                    "and transport_binding='windows-rpc-smb-readonly-tail-v1' for share",
                    (state["source"],),
                )
                if int(cur.fetchone()["revision"]) != int(plan["cursor_revision"]):
                    raise RadiusSessionV2IdentityRebindControlError("rebind_plan_input_drift")
                cur.execute(
                    "select (select count(*) from radius_vpn_session_projection) physical,"
                    "(select count(*) from radius_accounting_session_observations) observations,"
                    "(select count(*) from radius_session_projection_receipts) receipts"
                )
                locked = dict(cur.fetchone())
                if any(int(locked[key]) != int(baseline[key]) for key in locked):
                    raise RadiusSessionV2IdentityRebindControlError("rebind_plan_input_drift")
                cur.execute("set local role adlog_radius_session_consumer")
                cur.execute("delete from radius_vpn_session_projection")
                if cur.rowcount != int(baseline["physical"]):
                    raise RadiusSessionV2IdentityRebindControlError("rebind_delete_scope_invalid")
                for row in folded.sessions:
                    cur.execute(
                        "insert into radius_vpn_session_projection("
                        "session_row_id,session_identity_key,exact_principal_key,"
                        "generation,lifecycle_state,completeness,started_at_utc,"
                        "last_observed_at_utc,stopped_at_utc,duration_seconds,"
                        "observation_count,anomalies,read_model_contract_id,updated_at) "
                        "values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())",
                        (
                            row.session_row_id,
                            row.session_identity_key,
                            row.exact_principal_key,
                            row.generation,
                            row.lifecycle_state,
                            row.completeness,
                            row.started_at_utc,
                            row.last_observed_at_utc,
                            row.stopped_at_utc,
                            row.duration_seconds,
                            row.observation_count,
                            list(row.anomalies),
                            CONTRACT_ID,
                        ),
                    )
                cur.execute("reset role")
                cur.execute(
                    "select (select count(*) from radius_vpn_session_projection) physical,"
                    "(select count(*) from radius_vpn_session_rows_v1) visible,"
                    "(select count(*) from radius_accounting_session_observations) observations,"
                    "(select count(*) from radius_session_projection_receipts) receipts,"
                    "(select count(*) from radius_vpn_session_projection projection "
                    "join entities_v2 entity on entity.id="
                    "split_part(projection.exact_principal_key,':',2)::bigint) "
                    "current_entity_bound"
                )
                after = {key: int(value) for key, value in dict(cur.fetchone()).items()}
                expected_rows = len(folded.sessions)
                if (
                    after["physical"] != expected_rows
                    or after["visible"] != expected_rows
                    or after["current_entity_bound"] != expected_rows
                    or after["observations"] != int(baseline["observations"])
                    or after["receipts"] != int(baseline["receipts"])
                ):
                    raise RadiusSessionV2IdentityRebindControlError("rebind_postcondition_failed")
    return {
        "status": "passed",
        "plan_sha256": plan["plan_sha256"],
        "before": baseline,
        "after": after,
        "rebound": _summary(folded),
        "source_contacted": False,
        "cursor_changed": False,
        "immutable_rows_changed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--load-supervisor-environment", action="store_true")
    args = parser.parse_args(argv)
    if args.load_supervisor_environment:
        _load_environment()
    plan = _read_plan(args.plan)
    validate_apply_request(plan, confirmation=args.confirmation)
    if args.output.exists():
        raise RadiusSessionV2IdentityRebindControlError("rebind_output_exists")
    result = apply(plan)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
