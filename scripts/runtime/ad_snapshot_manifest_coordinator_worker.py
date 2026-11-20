#!/usr/bin/env python3
"""Own one exact 00/12 UTC acquisition, manifest, and in-process readback cycle.

It acquires the shared AD base exactly once, persists immutable exact source
IDs/hashes, then only for a published or same-slot replayed manifest invokes
manifest-bound compatibility projection and retention planning in-process.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops import shutdown
from server.ad_context.repository import publish_snapshot_manifest
from server.ad_context.snapshot_manifest import (
    SCHEDULE_LOCAL_HOURS,
    SCHEDULE_TIMEZONE,
    V1_CONTRACT_VERSION,
    V2_CONTRACT_VERSION,
    canonical_manifest_sha256,
    snapshot_composition,
    validate_snapshot_manifest,
)
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.ops.runtime_workers import record_worker_heartbeat
from server.sli.sources.acquisition_mode import acquisition_disabled
from server.sli.sources.ad_snapshot_projection import (
    run_exact_manifest_projection_cycle,
)
from server.sli.storage import ad_snapshot_change_history as ad_history
from server.sli.sources.collection_packet_import import (
    import_snapshot_packet,
    snapshot_bundle_from_packet,
)
from server.source_packs.adapters import AdContextRequest, build_ad_context_command
from sli_collect.snapshots import collect_snapshot_packet, snapshot_packet

from server.sli.plugins.ad.snapshots.coordinator import (
    _qualify_base_bundle,
    ScheduledSlot,
    slot_start_utc,
    scheduled_slot_from_local,
    scheduled_slot_from_utc,
    latest_due_scheduled_slot,
    next_scheduled_slot,
    seconds_until_next_scheduled_slot,
    _resolve_manifest_slot,
    _exact_manifest,
    _require_descriptor,
    run_one_shot,
    _iso_utc_to_windows_filetime,
    _computer_rows,
    _source_descriptor,
    BASE_PROFILE,
    BASE_SECTIONS,
    AD_FAMILY_SPECS,
    AD_FAMILIES,
    MAX_RECORDS,
    MAX_BUNDLE_BYTES,
    DEFAULT_MAX_DIRECTORY_USERS,
    DEFAULT_MAX_DIRECTORY_COMPUTERS,
    BASE_BLOCKING_QUALITY_CODES,
    TECHNICAL_INVENTORY_QUALITY_CODE
)

WORKER_NAME = "ad_snapshot_manifest_coordinator"
LOCK_NAME = "ad_log_reports_runtime_ad_snapshot_manifest_coordinator_worker"
INTERVAL_SECONDS = 43200
INITIAL_DELAY_SECONDS = 180
SCHEDULE_WAIT_HEARTBEAT_SECONDS = 300


def _csv_scope(env: Mapping[str, str], name: str) -> tuple[str, ...]:
    values = tuple(dict.fromkeys(item.strip() for item in env.get(name, "").split(",") if item.strip()))
    if not values:
        raise RuntimeError(f"{name}_required")
    return values


def _bounded_int(env: Mapping[str, str], name: str, default: int) -> int:
    try:
        value = int(env.get(name, str(default)).strip())
    except ValueError as exc:
        raise ValueError(f"{name}_must_be_integer") from exc
    if not 1 <= value <= MAX_RECORDS:
        raise ValueError(f"{name}_out_of_bounds")
    return value


def _collector_request(*, output: Path, run_id: str, family: str) -> AdContextRequest:
    env = os.environ
    if family not in AD_FAMILY_SPECS:
        raise ValueError("unsupported_ad_snapshot_family")
    profile, sections = AD_FAMILY_SPECS[family]
    server = (env.get("ADLOG_AD_CONTEXT_DIRECTORY_SERVER") or env.get("ADLOG_COLLECTION_PREFLIGHT_SERVER") or "").strip()
    domain = env.get("ADLOG_AD_CONTEXT_DOMAIN", "").strip()
    search_base = env.get("ADLOG_AD_CONTEXT_SEARCH_BASE", "").strip()
    powershell = env.get("ADLOG_AD_CONTEXT_POWERSHELL", "").strip() or str(
        Path(env.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    if not server or not domain or not search_base:
        raise RuntimeError("ad_snapshot_coordinator_configuration_missing")
    privileged = _csv_scope(env, "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS")
    vpn = _csv_scope(env, "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES")
    max_users = _bounded_int(env, "ADLOG_AD_SNAPSHOT_MAX_DIRECTORY_USERS", DEFAULT_MAX_DIRECTORY_USERS)
    max_computers = _bounded_int(env, "ADLOG_AD_SNAPSHOT_MAX_DIRECTORY_COMPUTERS", DEFAULT_MAX_DIRECTORY_COMPUTERS)
    if max_users + max_computers > MAX_RECORDS:
        raise ValueError("directory user/computer limit sum exceeds max_records")
    return AdContextRequest(
        powershell_executable=powershell,
        output_path=output, run_id=run_id, directory_server=server,
        search_base=search_base, domain=domain, sections=sections,
        collection_profile=profile, mode="reconcile", max_records=MAX_RECORDS,
        max_bundle_bytes=MAX_BUNDLE_BYTES, max_directory_accounts=MAX_RECORDS,
        max_directory_users=max_users, max_directory_computers=max_computers,
        max_directory_groups=10_000, max_directory_memberships=35_000,
        max_vpn_members=_bounded_int(env, "ADLOG_AD_SNAPSHOT_MAX_VPN_MEMBERS", 5_000),
        max_gpos=_bounded_int(env, "ADLOG_AD_SNAPSHOT_MAX_GPOS", 72),
        privileged_groups=privileged if family == "ad_privileged_membership" else (),
        vpn_groups=vpn if family == "ad_vpn_membership" else (),
    )


def _terminate_process_tree(process: Any) -> None:
    if os.name == "nt":
        try:
            completed = subprocess.run(
                ["taskkill", "/PID", str(int(process.pid)), "/T", "/F"],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                errors="replace", timeout=10, check=False,
            )
            if completed.returncode == 0:
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
        process.kill()
        return
    process.terminate()


def _run_collector_process(command: list[str], *, timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    from server.sli.sources.ad_source_auth import validate_ad_source_credential_mode
    mode = validate_ad_source_credential_mode(os.environ.get("ADLOG_AD_SOURCE_CREDENTIAL_MODE", "process"))
    if mode == "dpapi_current_user":
        from server.sli.sources.ad_source_process import run_ad_source_process
        server = (os.environ.get("ADLOG_AD_CONTEXT_DIRECTORY_SERVER")
                  or os.environ.get("ADLOG_COLLECTION_PREFLIGHT_SERVER") or "").strip()
        return run_ad_source_process(command, server=server, cwd=ROOT, timeout_seconds=timeout_seconds)
    process = subprocess.Popen(
        command, cwd=str(ROOT), stdin=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, errors="replace",
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as timeout:
        _terminate_process_tree(process)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
        stdout = str(stdout or timeout.output or "")[-1000:]
        stderr = str(stderr or timeout.stderr or "")[-1000:]
        raise RuntimeError(f"collector_timeout:stdout={stdout}:stderr={stderr}") from timeout
    return subprocess.CompletedProcess(command, int(process.returncode or 0), stdout, stderr)


def _collect(family: str) -> dict[str, Any]:
    run_id = str(uuid4())
    with tempfile.TemporaryDirectory(prefix="sli-ad-snapshot-") as directory:
        output = Path(directory) / f"{run_id}.json"
        command = build_ad_context_command(_collector_request(output=output, run_id=run_id, family=family))
        progress = Path(directory) / "p.json"
        audit_script = ROOT / "scripts/ad_context/Export-AdAuditContextBundle.ps1"
        if "-File" in command and Path(command[command.index("-File") + 1]).resolve() == audit_script.resolve():
            command.extend(("-ProgressPath", str(progress)))
        try:
            completed = _run_collector_process(command, timeout_seconds=900)
        except RuntimeError as exc:
            if not (str(exc) == "ad_source_process_timeout" or str(exc).startswith("collector_timeout:")):
                raise
            safe_progress: dict[str, Any] = {}
            try:
                with progress.open("rb") as stream:
                    raw = stream.read(4097)
                metadata = json.loads(raw) if len(raw) <= 4096 else None
                phases = {
                    "starting", "base_users_start", "base_users_end", "base_computers_start",
                    "base_computers_end", "raw_serialization_start", "raw_serialization_end",
                    "accounts_start", "accounts_end", "group_graph_start", "group_graph_end",
                    "exact_logon_start", "exact_logon_queries", "exact_logon_queried",
                    "exact_logon_end", "final_serialization_start", "final_serialization_end", "completed",
                }
                if isinstance(metadata, dict) and metadata.get("phase") in phases:
                    safe_progress["phase"] = metadata["phase"]
                    for key in ("elapsed_sec", "user_count", "computer_count", "record_count", "exact_queries_completed", "dc_count"):
                        value = metadata.get(key)
                        if type(value) is int and 0 <= value <= 10_000_000:
                            safe_progress[key] = value
            except (OSError, ValueError, TypeError, RecursionError):
                pass
            raise RuntimeError("ad_source_process_timeout:progress=" + json.dumps(safe_progress, separators=(",", ":"))) from None
        if not output.is_file():
            raise RuntimeError(f"{family}_collector_failed_without_bundle:{completed.returncode}:{completed.stderr[-1000:]}")
        # The source-side reader verifies bytes without importing repositories.
        # Domain validation and all database work stay on this server side.
        packet = collect_snapshot_packet(output, channel=family)
        bundle = snapshot_bundle_from_packet(packet)
        if completed.returncode != 0 and not bundle.get("sections"):
            raise RuntimeError(f"{family}_collector_failed:{completed.returncode}:{completed.stderr[-1000:]}")
        return bundle


def _default_cycle(
    now: datetime,
    *,
    domain_dns: str,
    scheduled_slot: ScheduledSlot | None = None,
    worker_id: str = f"{WORKER_NAME}:in-process",
) -> dict[str, Any]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from scripts.runtime.ad_context_snapshot_worker import (
        _import_connect as ad_context_import_connect,
    )
    from scripts.runtime.computers_v6_source_worker import capture_and_persist_once
    from scripts.runtime.users_report_v2_snapshot_worker import (
        _canonical as users_canonical,
    )
    from scripts.runtime.users_report_v2_snapshot_worker import (
        persist_users_v2_snapshot,
    )
    from server.sli.reports.users_v2_reporting import build_users_v2_snapshot
    from server.sli.sources.ad_gpo_jobs import gpo_snapshot_enabled

    scheduled_slot = scheduled_slot or latest_due_scheduled_slot(now)
    requested_domain_dns = str(domain_dns).strip().lower()
    configured_domain_dns = os.environ.get("ADLOG_AD_CONTEXT_DOMAIN", "").strip().lower()
    if not requested_domain_dns or requested_domain_dns != configured_domain_dns:
        raise RuntimeError("requested_domain_does_not_match_configured_domain")
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("select id,domain_sid,fqdn from domains where lower(fqdn)=lower(%s) order by id", (requested_domain_dns,))
        rows = [dict(row) for row in cursor.fetchall()]
    if len(rows) != 1:
        raise RuntimeError("coordinator_requires_one_exact_domain")
    domain = {"id": int(rows[0]["id"]), "sid": str(rows[0]["domain_sid"]), "dns": str(rows[0]["fqdn"])}

    def utc_text(value: Any) -> str:
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return str(value)

    def local_text(value: Any) -> str:
        return value.isoformat(timespec="seconds") if isinstance(value, datetime) else str(value or "")

    def hash_text(value: Any) -> str:
        return bytes(value).hex() if isinstance(value, (bytes, bytearray, memoryview)) else str(value)

    def lookup_existing(*, domain_id: int, slot_start_utc: str, contract_version: str) -> dict[str, Any] | None:
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """select manifest_id::text as manifest_id,domain_id,domain_sid,domain_dns,
                          slot_start_utc,assembled_at_utc,contract_version,coverage_state,
                          schedule_timezone,scheduled_local_at,
                          encode(manifest_sha256,'hex') as manifest_sha256
                   from ad_snapshot_manifests
                   where domain_id=%s and slot_start_utc=%s and contract_version=%s""",
                (domain_id, slot_start_utc, contract_version),
            )
            header = cursor.fetchone()
            if not header:
                return None
            cursor.execute(
                """select family,contract_id,source_id,observed_at_utc,source_state,
                          encode(payload_sha256,'hex') as payload_sha256,reason_code
                   from ad_snapshot_manifest_sources where manifest_id=%s::uuid order by family""",
                (str(header["manifest_id"]),),
            )
            members = [dict(item) for item in cursor.fetchall()]
        value = dict(header)
        value["manifest_id"] = str(value["manifest_id"])
        value["slot_start_utc"] = utc_text(value["slot_start_utc"])
        value["assembled_at_utc"] = utc_text(value["assembled_at_utc"])
        value["scheduled_local_at"] = local_text(value.get("scheduled_local_at"))
        value["manifest_sha256"] = hash_text(value["manifest_sha256"])
        for member in members:
            member["observed_at_utc"] = utc_text(member["observed_at_utc"])
            member["payload_sha256"] = hash_text(member["payload_sha256"])
        value["members"] = members
        return value

    def resolve_existing_source(member: dict[str, Any]) -> dict[str, Any] | None:
        from server.ad_context.repository import _resolve_manifest_source
        with connect() as connection, connection.cursor() as cursor:
            return _resolve_manifest_source(cursor, member)

    def verify_existing_base(members: list[dict[str, Any]]) -> dict[str, Any]:
        by_family = {str(item["family"]): item for item in members}
        base_member = by_family.get("ad_context_base") or {}
        computers_member = by_family.get("computers_v6") or {}
        if not base_member.get("source_id") or not computers_member.get("source_id"):
            return {"usable": False, "reason": "required_base_source_missing"}
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """select section_name as name,status,error_code
                   from ad_context_sections where run_id=%s::uuid order by section_name""",
                (base_member["source_id"],),
            )
            sections = [dict(row) for row in cursor.fetchall()]
            cursor.execute(
                """select locator_json->>'record_key' as record_key
                   from ad_context_evidence
                   where source_run_id=%s::uuid and evidence_type='data_quality'
                   order by evidence_key""",
                (base_member["source_id"],),
            )
            records = []
            for row in cursor.fetchall():
                parts = str(row["record_key"] or "").split(":", 2)
                if len(parts) == 3 and parts[0] == "dq":
                    records.append({"record_type": "data_quality", "section": parts[1], "code": parts[2]})
            cursor.execute(
                "select base_inventory_status from computers_v6_source_snapshots where snapshot_uuid=%s::uuid",
                (computers_member["source_id"],),
            )
            computers_row = cursor.fetchone()
        qualification = _qualify_base_bundle({"sections": sections, "records": records})
        computers_status = str(computers_row["base_inventory_status"]) if computers_row else None
        return {
            "usable": (
                qualification["usable"] is True
                and computers_status == "observed"
                and base_member.get("source_state") != "failed"
                and computers_member.get("source_state") != "failed"
            ),
            "base_qualification": qualification,
            "computers_base_inventory_status": computers_status,
        }

    def acquire_ad_family(family: str) -> dict[str, Any]:
        bundle = _collect(family)
        section_states = {str(item["name"]): str(item["status"]) for item in bundle.get("sections") or []}
        if family == "ad_context_base":
            qualification = _qualify_base_bundle(bundle)
            return {"acquisition": {"profile": BASE_PROFILE, "user_full_queries": 1, "computer_full_queries": 1},
                    "base_complete": qualification["usable"], "base_qualification": qualification,
                    "bundle": bundle, "computer_rows": _computer_rows(bundle)}
        return {"bundle": bundle}

    def import_family(bundle: Mapping[str, Any], family: str) -> dict[str, Any]:
        with ad_context_import_connect() as connection:
            packet = snapshot_packet(dict(bundle), source=bundle["domain"]["sid"], channel=family)
            import_snapshot_packet(connection, packet)
        return _source_descriptor_for_bundle(family, bundle)

    def _source_descriptor_for_bundle(family: str, bundle: Mapping[str, Any]) -> dict[str, Any]:
        with connect() as connection:
            return _source_descriptor(connection, family, str(bundle["run_id"]))

    def persist_users(_bundle: Mapping[str, Any]) -> dict[str, Any]:
        snapshot = build_users_v2_snapshot(domain_ids=[int(domain["id"])])
        payload_text, payload_hash = users_canonical(snapshot)
        del payload_text
        persist_at = now
        with connect() as connection:
            persisted = persist_users_v2_snapshot(connection, snapshot=snapshot, domain_id=int(domain["id"]), captured_at=persist_at)
        source_id = persisted.get("snapshot_id")
        if source_id is None:
            observed = dict(snapshot.get("metadata") or {}).get("observed_at")
            with connect() as connection, connection.cursor() as cursor:
                cursor.execute("select snapshot_id from users_report_v2_snapshots where domain_id=%s and contract_id='sli.users-report.v2' and source_observed_at_utc=%s and payload_sha256=%s order by snapshot_id", (int(domain["id"]), observed, payload_hash))
                exact = [dict(row) for row in cursor.fetchall()]
            if len(exact) != 1:
                raise RuntimeError("users_v2_exact_source_readback_ambiguous")
            source_id = exact[0]["snapshot_id"]
        with connect() as connection:
            return _source_descriptor(connection, "users_v2", str(source_id))

    def persist_computers(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
        persisted = capture_and_persist_once(
            connection_factory=connect, captured_at=None,
            powershell_executable=os.environ.get("ADLOG_AD_CONTEXT_POWERSHELL", "powershell.exe"),
            server=os.environ.get("ADLOG_AD_CONTEXT_DIRECTORY_SERVER") or os.environ.get("ADLOG_COLLECTION_PREFLIGHT_SERVER"),
            search_base=os.environ.get("ADLOG_AD_CONTEXT_SEARCH_BASE"), skip_dns=False,
            collect_ad_site=True, collect_exact_last_logon=True,
            coordinator_base_rows=rows,
        )
        if persisted.get("base_inventory_status") != "observed":
            raise RuntimeError("computers_v6_base_inventory_not_observed")
        with connect() as connection:
            return _source_descriptor(connection, "computers_v6", str(persisted["snapshot_uuid"]))

    def publish(manifest: dict[str, Any]) -> dict[str, Any]:
        with connect() as connection:
            result = publish_snapshot_manifest(connection, manifest)
            with connection.cursor() as cursor:
                cursor.execute(
                    """select manifest_id::text as manifest_id,domain_id,domain_sid,domain_dns,
                              slot_start_utc,contract_version,schedule_timezone,scheduled_local_at,
                              encode(manifest_sha256,'hex') as manifest_sha256
                       from ad_snapshot_manifests where manifest_id=%s::uuid""",
                    (manifest["manifest_id"],),
                )
                header = dict(cursor.fetchone() or {})
                cursor.execute(
                    "select family,source_id,encode(payload_sha256,'hex') as payload_sha256 from ad_snapshot_manifest_sources where manifest_id=%s::uuid order by family",
                    (manifest["manifest_id"],),
                )
                sources = [dict(row) for row in cursor.fetchall()]
            expected_sources = sorted(
                ({"family": item["family"], "source_id": item["source_id"], "payload_sha256": item["payload_sha256"]} for item in manifest["members"]),
                key=lambda item: item["family"],
            )
            readback_slot = (
                header["slot_start_utc"].astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                if isinstance(header.get("slot_start_utc"), datetime)
                else str(header.get("slot_start_utc") or "")
            )
            if (header.get("manifest_id") != manifest["manifest_id"]
                    or int(header.get("domain_id") or 0) != int(manifest["domain_id"])
                    or str(header.get("domain_sid") or "").casefold() != str(manifest["domain_sid"]).casefold()
                    or str(header.get("domain_dns") or "").casefold() != str(manifest["domain_dns"]).casefold()
                    or readback_slot != manifest["slot_start_utc"]
                    or str(header.get("contract_version") or "") != manifest["contract_version"]
                    or (
                        manifest["contract_version"] == V2_CONTRACT_VERSION
                        and (
                            str(header.get("schedule_timezone") or "") != manifest["schedule_timezone"]
                            or local_text(header.get("scheduled_local_at")) != manifest["scheduled_local_at"]
                        )
                    )
                    or str(header.get("manifest_sha256") or "") != manifest["manifest_sha256"]
                    or sources != expected_sources):
                raise RuntimeError("manifest_publication_database_readback_mismatch")
            return {**result, "readback_verified": True}

    include_gpo = gpo_snapshot_enabled()
    result = run_one_shot(
        slot_start_utc=scheduled_slot.slot_start_utc, domain=domain, execute=True,
        acquire_ad_family=acquire_ad_family,
        import_ad_family=lambda bundle, family: import_family(bundle, family),
        persist_users=persist_users, persist_computers=persist_computers,
        import_gpo=lambda bundle: _source_descriptor_for_bundle("gpo_v2", bundle), publish=publish,
        lookup_existing=lookup_existing, resolve_existing_source=resolve_existing_source,
        verify_existing_base=verify_existing_base,
        contract_version=V2_CONTRACT_VERSION,
        schedule_timezone=scheduled_slot.schedule_timezone,
        scheduled_local_at=scheduled_slot.scheduled_local_at,
        gpo_enabled=include_gpo,
    )
    if result.get("status") in {"published", "replayed_existing"} and result.get("manifest_id"):
        manifest_id = str(result["manifest_id"])
        projection_options = {} if include_gpo else {
            "projection_keys": ("ad.state", "ad.users.v2", "ad.computers.v6"),
        }
        with connect() as connection:
            projection_cycle = run_exact_manifest_projection_cycle(
                connection,
                manifest_id=manifest_id,
                worker_id=worker_id,
                **projection_options,
            )
            result["projection_cycle"] = projection_cycle
            result["projection_results"] = projection_cycle["projection_results"]
            if (projection_cycle.get("status") == "completed"
                    and "gpo" in result["composition"]["parts"]):
                port = ad_history.ch.configured_read_port()
                if port is None:
                    result["retention_execution"] = {
                        "status": "skipped", "reason": "history_clickhouse_port_missing",
                    }
                    return result
                ad_history.ensure_schema(port)
                result["history_publication"] = ad_history.publish_manifest(connection, port, manifest_id)
                connection.commit()
                with connection.cursor() as cursor:
                    cursor.execute(
                        "call public.expire_ad_snapshot_confirmed_ring_v165(%s::uuid)",
                        (manifest_id,),
                    )
                result["retention_execution"] = {
                    "status": "executed",
                    "procedure": "public.expire_ad_snapshot_confirmed_ring_v165",
                    "manifest_id": manifest_id,
                }
            else:
                result["retention_execution"] = {
                    "status": "skipped",
                    "reason": "projection_not_completed" if projection_cycle.get("status") != "completed"
                              else "retention_requires_full_composition",
                }
    return result


def main(argv: list[str] | None = None) -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.sources.ad_gpo_jobs import enabled

    if enabled():
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--no-initial-delay", action="store_true")
    args = parser.parse_args(argv)
    worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid4()}"
    started = datetime.now(timezone.utc)
    if acquisition_disabled():
        while not shutdown.requested():
            record_worker_heartbeat(
                worker_name=WORKER_NAME, worker_id=worker_id, status="idle",
                phase="acquisition_disabled", expected_interval_seconds=30,
                started_at=started, details={"acquisition_disabled": True},
            )
            if args.once:
                return 0
            shutdown.wait(30, sleep=time.sleep)
        return 0
    if not args.once and not args.no_initial_delay:
        record_worker_heartbeat(
            worker_name=WORKER_NAME, worker_id=worker_id, status="idle",
            phase="initial_delay", expected_interval_seconds=INTERVAL_SECONDS,
            started_at=started,
            details={"next_cycle_in_seconds": INITIAL_DELAY_SECONDS},
        )
        shutdown.wait(INITIAL_DELAY_SECONDS, sleep=time.sleep)
    while not shutdown.requested():
        try:
            with session_advisory_lock(connect, LOCK_NAME) as acquired:
                configured_domain = os.environ.get("ADLOG_AD_CONTEXT_DOMAIN", "").strip()
                cycle_now = datetime.now(timezone.utc)
                scheduled_slot = latest_due_scheduled_slot(cycle_now)
                result = (
                    _default_cycle(
                        cycle_now,
                        domain_dns=configured_domain,
                        scheduled_slot=scheduled_slot,
                        worker_id=worker_id,
                    )
                    if acquired else {"status": "skipped", "reason": "lock_busy"}
                )
            record_worker_heartbeat(worker_name=WORKER_NAME, worker_id=worker_id, status=str(result["status"]), phase="sleeping", expected_interval_seconds=INTERVAL_SECONDS, started_at=started, details=result)
            print(json.dumps(result, ensure_ascii=False, default=str), flush=True)
        except Exception as exc:
            result = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
            record_worker_heartbeat(worker_name=WORKER_NAME, worker_id=worker_id, status="failed", phase="failed", expected_interval_seconds=INTERVAL_SECONDS, started_at=started, details=result)
            print(json.dumps(result, ensure_ascii=False), file=sys.stderr, flush=True)
            if args.once:
                return 1
        if args.once:
            return 0
        next_slot = next_scheduled_slot(datetime.now(timezone.utc))
        target = datetime.fromisoformat(next_slot.slot_start_utc.replace("Z", "+00:00"))
        while not shutdown.requested():
            remaining_seconds = (target - datetime.now(timezone.utc)).total_seconds()
            if remaining_seconds <= 0:
                break
            remaining = max(1, math.ceil(remaining_seconds))
            record_worker_heartbeat(
                worker_name=WORKER_NAME,
                worker_id=worker_id,
                status="idle",
                phase="waiting_for_calendar_slot",
                expected_interval_seconds=INTERVAL_SECONDS,
                started_at=started,
                details={
                    "next_slot_start_utc": next_slot.slot_start_utc,
                    "schedule_timezone": next_slot.schedule_timezone,
                    "scheduled_local_at": next_slot.scheduled_local_at,
                    "next_cycle_in_seconds": remaining,
                },
            )
            shutdown.wait(min(SCHEDULE_WAIT_HEARTBEAT_SECONDS, remaining), sleep=time.sleep)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
