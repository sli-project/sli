#!/usr/bin/env python3
"""Plan or apply the exact disabled Stage 9 RADIUS registration."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping
from uuid import UUID, uuid4


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.ad_context_live_canary import (  # noqa: E402
    current_windows_account,
)
from scripts.maintenance.stage9_radius_postgres_production_preflight import (  # noqa: E402
    FOUNDATION_TABLES,
)
from scripts.maintenance.stage9_radius_postgres_migrate import (  # noqa: E402
    _hashes as current_058_hashes,
)
from server.sli.ops.worker_supervisor_secrets import (  # noqa: E402
    load_supervisor_environment,
)
from server.sli.sources.windows_runtime_identity import (  # noqa: E402
    expected_collection_identity,
    verify_collection_identity,
)
from server.source_packs.radius.accounting_registration import (  # noqa: E402
    RadiusCursorBootstrap,
    load_registration_contract,
    register_disabled_radius_source,
)


CONFIRMATION = "REGISTER-STAGE9-RADIUS-DISABLED"
LEGACY_REMEDIATION_CONFIRMATION = "REMEDIATE-STAGE9-RADIUS-LEGACY-DRIFT"
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
POSTGRES_APPLY = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-accounting-postgres58-production-apply.json"
)
POSTGRES_ATTESTATION = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-accounting-postgres58-production-attestation.json"
)
CURSOR_BOOTSTRAP = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-accounting-cursor-bootstrap-radius01.json"
)
ACL_READBACK = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-evidence-root-acl-readback.json"
)
READBACK_SCRIPT = (
    ROOT
    / "scripts/maintenance/"
    "Invoke-SLI-Stage9RadiusEvidenceRootV2.ps1"
)
DEFAULT_OUTPUT = (
    ROOT
    / "artifacts/stage9/evidence/"
    "radius-accounting-disabled-registration-radius01-production.json"
)


class RadiusProductionRegistrationError(RuntimeError):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusProductionRegistrationError(
            f"invalid prerequisite:{path.name}"
        ) from exc
    if not isinstance(value, dict):
        raise RadiusProductionRegistrationError(
            f"prerequisite_object_required:{path.name}"
        )
    return value


def _read_optional_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return _read_json(path)


def _valid_postgres_apply(value: Mapping[str, Any]) -> bool:
    return bool(
        value.get("status") == "passed"
        and value.get("action") == "apply"
        and dict(value.get("migration") or {}).get("version") == 58
        and value.get("production_database_changed") is True
        and value.get("source_instance_created") is False
        and value.get("runtime_enabled") is False
    )


def _valid_postgres_attestation(value: Mapping[str, Any]) -> bool:
    migration = dict(value.get("migration") or {})
    postcondition = dict(value.get("postcondition") or {})
    return bool(
        value.get("status") == "passed"
        and value.get("action") == "finalize_applied_readback"
        and value.get("evidence_kind") == "production_current_state_attestation"
        and migration == {"version": 58, **current_058_hashes()}
        and postcondition == {
            "marker": True,
            "worker_role": True,
            "evidence_insert": True,
            "evidence_delete": False,
            "cursor_update": True,
            "tables": sorted(FOUNDATION_TABLES),
        }
        and value.get("production_migration_applied") is True
        and value.get("production_database_changed") is False
        and value.get("source_instance_created") is False
        and value.get("runtime_enabled") is False
        and value.get("radius_source_contacted") is False
    )


def _validate_postgres_authority(
    apply_evidence: Mapping[str, Any] | None,
    attestation: Mapping[str, Any] | None,
) -> None:
    if apply_evidence is None and attestation is None:
        raise RadiusProductionRegistrationError("production_058_evidence_invalid")
    if apply_evidence is not None and not _valid_postgres_apply(apply_evidence):
        raise RadiusProductionRegistrationError("production_058_evidence_invalid")
    if attestation is not None and not _valid_postgres_attestation(attestation):
        raise RadiusProductionRegistrationError("production_058_attestation_invalid")
    if apply_evidence is not None and attestation is not None:
        legacy = dict(apply_evidence.get("migration") or {})
        current = dict(attestation.get("migration") or {})
        if any(
            legacy.get(key) != current.get(key)
            for key in ("forward_sha256", "rollback_sha256")
        ):
            raise RadiusProductionRegistrationError("production_058_evidence_hash_mismatch")


def validate_prerequisites(
    postgres_apply: Mapping[str, Any] | None,
    cursor_evidence: Mapping[str, Any],
    acl_evidence: Mapping[str, Any],
    postgres_attestation: Mapping[str, Any] | None = None,
) -> RadiusCursorBootstrap:
    _validate_postgres_authority(postgres_apply, postgres_attestation)
    if not (
        acl_evidence.get("status") == "accepted"
        and acl_evidence.get("classification") == "protected_acl_exact"
        and acl_evidence.get("contract_id")
        == "sli.radius-acquisition-evidence-root.v2"
        and acl_evidence.get("node_count") == 4
        and acl_evidence.get("acl_entry_count") == 12
        and acl_evidence.get("activation_enabled") is False
        and acl_evidence.get("raw_path_persisted") is False
    ):
        raise RadiusProductionRegistrationError(
            "protected_root_evidence_invalid"
        )
    if not (
        cursor_evidence.get("status") == "completed"
        and cursor_evidence.get("read_only") is True
        and cursor_evidence.get("cursor_updated") is False
        and cursor_evidence.get("source_instance_created") is False
        and cursor_evidence.get("worker_activated") is False
        and cursor_evidence.get("source_instance_id")
        == load_registration_contract()["source"]["source_instance_id"]
        and cursor_evidence.get("stream_id") == "radius-accounting"
        and cursor_evidence.get("transport_binding")
        == "windows-rpc-smb-readonly-tail-v1"
    ):
        raise RadiusProductionRegistrationError(
            "cursor_bootstrap_evidence_invalid"
        )
    cursor = dict(cursor_evidence.get("cursor_bootstrap") or {})
    try:
        return RadiusCursorBootstrap(
            cursor_epoch=UUID(str(cursor["cursor_epoch"])),
            file_generation=str(cursor["file_generation"]),
            byte_offset=int(cursor["byte_offset"]),
            last_record_sha256=str(cursor["last_record_sha256"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RadiusProductionRegistrationError(
            "cursor_bootstrap_values_invalid"
        ) from exc


def _load_environment() -> None:
    if not (
        os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
        and os.getenv("ADLOG_PG_DSN", "").strip()
        and os.getenv("ADLOG_COLLECTION_PRINCIPAL", "").strip()
        and os.getenv("ADLOG_COLLECTION_PRINCIPAL_SID", "").strip()
    ):
        load_supervisor_environment()


def _admin_dsn() -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    source = os.getenv("ADLOG_PG_DSN", "").strip()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not source or not user or not password:
        raise RadiusProductionRegistrationError(
            "protected_postgres_credentials_required"
        )
    values = conninfo_to_dict(source)
    values.update(user=user, password=password)
    return make_conninfo(**values)


def _connect():
    import psycopg

    return psycopg.connect(
        _admin_dsn(),
        autocommit=True,
        connect_timeout=5,
        application_name="sli_stage9_radius_disabled_registration",
        options="-c statement_timeout=30000 -c lock_timeout=5000",
    )


def _trusted_windows_powershell() -> Path:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve()
    executable = (
        system_root
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    if not executable.is_file():
        raise RadiusProductionRegistrationError(
            "trusted_windows_powershell_not_found"
        )
    return executable


def _live_acl_readback() -> dict[str, Any]:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    acl_environment = dict(os.environ)
    acl_environment["PSModulePath"] = os.pathsep.join(
        [
            str(
                Path(system_root)
                / "System32"
                / "WindowsPowerShell"
                / "v1.0"
                / "Modules"
            ),
            str(Path(program_files) / "WindowsPowerShell" / "Modules"),
        ]
    )
    result = subprocess.run(
        [
            str(_trusted_windows_powershell()),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(READBACK_SCRIPT),
            "-RootPath",
            r"C:\SLI",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=acl_environment,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RadiusProductionRegistrationError(
            "live_protected_root_readback_failed"
        )
    try:
        value = json.loads(result.stdout.lstrip("\ufeff").strip())
    except json.JSONDecodeError as exc:
        raise RadiusProductionRegistrationError(
            "live_protected_root_readback_invalid"
        ) from exc
    if not isinstance(value, dict):
        raise RadiusProductionRegistrationError(
            "live_protected_root_readback_invalid"
        )
    return value


def _inspect_rows() -> dict[str, Any]:
    contract = load_registration_contract()
    source_instance_id = str(contract["source"]["source_instance_id"])
    stream = dict(contract["stream"])
    subscription_id = str(contract["subscription"]["subscription_id"])
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("begin read only")
        cur.execute(
            """
            select exists(
                     select 1 from schema_migrations where version=58
                   ),
                   (select count(*) from acquisition_source_instances
                    where source_instance_id=%s),
                   (select count(*) from acquisition_stream_cursors
                    where source_instance_id=%s
                      and stream_id=%s
                      and transport_binding=%s),
                   (select count(*) from acquisition_consumer_subscriptions
                    where subscription_id=%s)
            """,
            (
                source_instance_id,
                source_instance_id,
                str(stream["stream_id"]),
                str(stream["transport_binding"]),
                subscription_id,
            ),
        )
        marker, source_count, cursor_count, subscription_count = cur.fetchone()
        cur.execute("rollback")
    return {
        "migration_58": bool(marker),
        "source_count": int(source_count),
        "cursor_count": int(cursor_count),
        "subscription_count": int(subscription_count),
    }


def _legacy_identifiers(contract: Mapping[str, Any]) -> tuple[str, str]:
    source_id = str(dict(contract["source"])["source_instance_id"])
    source_label = source_id.partition(".")[0]
    subscription_id = str(dict(contract["subscription"])["subscription_id"])
    marker = f"-{source_label}-"
    if not source_label or subscription_id.count(marker) != 1:
        raise RadiusProductionRegistrationError(
            "legacy_remediation_contract_identity_invalid"
        )
    return (
        f"radius.{source_id}",
        subscription_id.replace(marker, "-", 1),
    )


def _legacy_configuration_sha(
    contract: Mapping[str, Any],
    *,
    source_instance_id: str,
    subscription_id: str,
) -> str:
    value = dict(contract)
    source = dict(value["source"])
    subscription = dict(value["subscription"])
    source["source_instance_id"] = source_instance_id
    subscription["subscription_id"] = subscription_id
    value["source"] = source
    value["subscription"] = subscription
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def _valid_legacy_cursor(row: tuple[Any, ...], stream: Mapping[str, Any]) -> bool:
    if len(row) != 9 or tuple(row[:2]) != (
        stream["stream_id"], stream["transport_binding"],
    ):
        return False
    try:
        UUID(str(row[2]))
        byte_offset = int(row[4])
        revision = int(row[8])
    except (TypeError, ValueError):
        return False
    if byte_offset < 0 or revision < 0 or _TOKEN.fullmatch(str(row[3])) is None:
        return False
    for value in (row[5], row[7]):
        if value is not None and _SHA256.fullmatch(str(value)) is None:
            return False
    return row[6] is None or _TOKEN.fullmatch(str(row[6])) is not None


def _legacy_remediation_candidate(conn: Any) -> dict[str, Any]:
    """Read one endpoint-scoped disabled legacy registration candidate."""

    contract = load_registration_contract()
    source = dict(contract["source"])
    stream = dict(contract["stream"])
    subscription = dict(contract["subscription"])
    expected_legacy_source_id, expected_legacy_subscription_id = (
        _legacy_identifiers(contract)
    )
    legacy_configuration_sha = _legacy_configuration_sha(
        contract,
        source_instance_id=expected_legacy_source_id,
        subscription_id=expected_legacy_subscription_id,
    )
    selector_json = json.dumps(
        subscription["selector"],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    selector_sha = sha256(selector_json.encode("utf-8")).hexdigest()
    with conn.cursor() as cur:
        cur.execute("set local role adlog_storage_owner")
        cur.execute(
            """
            select source_instance_id,adapter_binding,credential_handle,
                   display_name,desired_activation,observed_health,
                   configuration_sha256
            from acquisition_source_instances
            where organization_scope=%s and source_kind=%s
              and endpoint_identity=%s
            limit 2
            for update
            """,
            (
                source["organization_scope"],
                source["source_kind"],
                source["endpoint_identity"],
            ),
        )
        source_rows = cur.fetchall()
        if len(source_rows) != 1:
            return {
                "source_contract_matches": False,
                "subscription_contract_matches": False,
                "cursor_contract_matches": False,
                "source_disabled": False,
                "subscription_disabled": False,
                "runtime_state_rows": -1,
            }
        source_row = source_rows[0]
        legacy_source_id = str(source_row[0])
        source_contract_matches = (
            legacy_source_id == expected_legacy_source_id
            and tuple(source_row[1:4])
            == (
                source["adapter_binding"],
                source["credential_handle"],
                source["display_name"],
            )
            and str(source_row[6]) == legacy_configuration_sha
        )
        source_disabled = (
            str(source_row[4]) == "disabled"
            and str(source_row[5]) == "unknown"
        )
        cur.execute(
            """
            select stream_id,transport_binding,cursor_epoch,file_generation,
                   byte_offset,last_record_sha256,previous_file_generation,
                   previous_generation_last_record_sha256,revision
            from acquisition_stream_cursors
            where source_instance_id=%s
            limit 2
            for update
            """,
            (legacy_source_id,),
        )
        cursor_rows = cur.fetchall()
        cursor_contract_matches = (
            len(cursor_rows) == 1
            and _valid_legacy_cursor(cursor_rows[0], stream)
        )
        cursor_revision = (
            int(cursor_rows[0][8]) if cursor_contract_matches else -1
        )
        cur.execute(
            """
            select subscription_id,stream_id,transport_binding,consumer_id,
                   consumer_component_id,consumer_component_version,
                   routing_contract_id,consumer_contract_version,replay_policy,
                   resource_profile_id,selector_json,selector_sha256,
                   authority_mode,desired_activation,partition_key
            from acquisition_consumer_subscriptions
            where source_instance_id=%s
            limit 2
            for update
            """,
            (legacy_source_id,),
        )
        subscription_rows = cur.fetchall()
        expected_subscription = (
            stream["stream_id"],
            stream["transport_binding"],
            subscription["consumer_id"],
            subscription["consumer_component_id"],
            subscription["consumer_component_version"],
            subscription["routing_contract_id"],
            subscription["consumer_contract_version"],
            subscription["replay_policy"],
            subscription["resource_profile_id"],
            subscription["selector"],
            selector_sha,
            subscription["authority_mode"],
            "disabled",
            subscription["partition_key"],
        )
        subscription_contract_matches = (
            len(subscription_rows) == 1
            and str(subscription_rows[0][0]) == expected_legacy_subscription_id
            and tuple(subscription_rows[0][1:]) == expected_subscription
        )
        legacy_subscription_id = (
            str(subscription_rows[0][0])
            if subscription_contract_matches
            else ""
        )
        subscription_disabled = (
            subscription_contract_matches
            and str(subscription_rows[0][13]) == "disabled"
        )
        cur.execute(
            """
            select
              (select count(*) from core_evidence_manifests
               where source_instance_id=%s)
            + (select count(*) from radius_accounting_session_observations o
               join core_evidence_manifests e on e.evidence_uid=o.evidence_uid
               where e.source_instance_id=%s)
            + (select count(*) from acquisition_delivery_outbox
               where subscription_id=%s)
            + (select count(*) from radius_accounting_class_cache
               where source_instance_id=%s)
            """,
            (
                legacy_source_id,
                legacy_source_id,
                legacy_subscription_id,
                legacy_source_id,
            ),
        )
        runtime_state_rows = int(cur.fetchone()[0])
    return {
        "legacy_source_instance_id": legacy_source_id,
        "legacy_subscription_id": legacy_subscription_id,
        "cursor": tuple(cursor_rows[0]) if cursor_contract_matches else (),
        "cursor_revision": cursor_revision,
        "source_contract_matches": source_contract_matches,
        "subscription_contract_matches": subscription_contract_matches,
        "cursor_contract_matches": cursor_contract_matches,
        "source_disabled": source_disabled,
        "subscription_disabled": subscription_disabled,
        "runtime_state_rows": runtime_state_rows,
    }


def _require_safe_legacy_remediation(
    candidate: Mapping[str, Any],
) -> dict[str, Any]:
    value = dict(candidate)
    expected_source_id, expected_subscription_id = _legacy_identifiers(
        load_registration_contract()
    )
    if value.get("legacy_source_instance_id") != expected_source_id:
        raise RadiusProductionRegistrationError(
            "legacy_remediation_source_identity_unexpected"
        )
    if value.get("legacy_subscription_id") != expected_subscription_id:
        raise RadiusProductionRegistrationError(
            "legacy_remediation_subscription_identity_unexpected"
        )
    if value.get("source_contract_matches") is not True:
        raise RadiusProductionRegistrationError(
            "legacy_remediation_source_contract_mismatch"
        )
    if value.get("subscription_contract_matches") is not True:
        raise RadiusProductionRegistrationError(
            "legacy_remediation_subscription_contract_mismatch"
        )
    if value.get("cursor_contract_matches") is not True:
        raise RadiusProductionRegistrationError(
            "legacy_remediation_cursor_contract_mismatch"
        )
    if value.get("source_disabled") is not True:
        raise RadiusProductionRegistrationError(
            "legacy_remediation_source_not_disabled"
        )
    if value.get("subscription_disabled") is not True:
        raise RadiusProductionRegistrationError(
            "legacy_remediation_subscription_not_disabled"
        )
    if int(value.get("runtime_state_rows", -1)) != 0:
        raise RadiusProductionRegistrationError(
            "legacy_remediation_runtime_state_present"
        )
    if not str(value.get("legacy_source_instance_id") or ""):
        raise RadiusProductionRegistrationError("legacy_remediation_source_missing")
    if not str(value.get("legacy_subscription_id") or ""):
        raise RadiusProductionRegistrationError(
            "legacy_remediation_subscription_missing"
        )
    if not _valid_legacy_cursor(
        tuple(value.get("cursor") or ()),
        dict(load_registration_contract()["stream"]),
    ):
        raise RadiusProductionRegistrationError(
            "legacy_remediation_cursor_values_invalid"
        )
    return value


def plan(*, prerequisites_dir: Path | None = None) -> tuple[dict[str, Any], RadiusCursorBootstrap]:
    cursor_evidence = Path(
        os.environ.get("ADLOG_RADIUS_CURSOR_BOOTSTRAP_EVIDENCE_PATH", "").strip()
        or CURSOR_BOOTSTRAP
    )
    paths = (POSTGRES_APPLY, cursor_evidence, ACL_READBACK, POSTGRES_ATTESTATION)
    if prerequisites_dir is not None:
        directory = prerequisites_dir.resolve()
        if (ROOT / "artifacts").resolve() not in directory.parents or not directory.is_dir():
            raise RadiusProductionRegistrationError("prerequisites_directory_invalid")
        paths = tuple(directory / path.name for path in paths)
    postgres_apply, cursor_path, acl_path, postgres_attestation = paths
    bootstrap = validate_prerequisites(
        _read_optional_json(postgres_apply),
        _read_json(cursor_path),
        _read_json(acl_path),
        _read_optional_json(postgres_attestation),
    )
    live_acl = _live_acl_readback()
    recorded_acl = _read_json(acl_path)
    if live_acl.get("readback_sha256") != recorded_acl.get("readback_sha256"):
        raise RadiusProductionRegistrationError(
            "protected_root_acl_changed"
        )
    rows = _inspect_rows()
    if rows["migration_58"] is not True:
        raise RadiusProductionRegistrationError("migration_58_missing")
    counts = {
        rows["source_count"],
        rows["cursor_count"],
        rows["subscription_count"],
    }
    if counts not in ({0}, {1}):
        raise RadiusProductionRegistrationError(
            "partial_registration_state_detected"
        )
    return (
        {
            "status": "ready",
            "action": "plan",
            "registration_already_exact_candidate": counts == {1},
            "migration_58": True,
            "protected_root": "accepted",
            "cursor_bootstrap": "accepted",
            "desired_activation": "disabled",
            "source_contacted": False,
            "worker_activated": False,
            "runtime_enabled": False,
            "required_confirmation": CONFIRMATION,
        },
        bootstrap,
    )


def apply_registration(*, prerequisites_dir: Path | None = None) -> dict[str, Any]:
    planned, bootstrap = plan() if prerequisites_dir is None else plan(prerequisites_dir=prerequisites_dir)
    with _connect() as conn:
        receipt = register_disabled_radius_source(
            conn,
            bootstrap=bootstrap,
        )
    rows = _inspect_rows()
    if rows != {
        "migration_58": True,
        "source_count": 1,
        "cursor_count": 1,
        "subscription_count": 1,
    }:
        raise RadiusProductionRegistrationError(
            "registration_postcondition_failed"
        )
    return {
        "status": "passed",
        "action": "disabled_registration",
        "source_instance_id": receipt.source_instance_id,
        "stream_id": receipt.stream_id,
        "transport_binding": receipt.transport_binding,
        "subscription_id": receipt.subscription_id,
        "desired_activation": receipt.desired_activation,
        "cursor_revision": receipt.cursor_revision,
        "created": {
            "source": receipt.created_source,
            "cursor": receipt.created_cursor,
            "subscription": receipt.created_subscription,
        },
        "prerequisite_plan": planned["status"],
        "source_contacted": False,
        "worker_activated": False,
        "runtime_enabled": False,
        "autostart_changed": False,
    }


def remediate_legacy_and_apply(*, prerequisites_dir: Path | None = None) -> dict[str, Any]:
    """Replace only one inert endpoint-scoped legacy registration atomically."""

    planned, bootstrap = plan() if prerequisites_dir is None else plan(prerequisites_dir=prerequisites_dir)
    contract = load_registration_contract()
    source = dict(contract["source"])
    stream = dict(contract["stream"])
    subscription = dict(contract["subscription"])
    selector_json = json.dumps(
        subscription["selector"],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    selector_sha = sha256(selector_json.encode("utf-8")).hexdigest()
    legacy_configuration_sha = _legacy_configuration_sha(
        contract,
        source_instance_id=_legacy_identifiers(contract)[0],
        subscription_id=_legacy_identifiers(contract)[1],
    )
    with _connect() as conn:
        with conn.transaction():
            candidate = _require_safe_legacy_remediation(
                _legacy_remediation_candidate(conn)
            )
            with conn.cursor() as cur:
                cur.execute(
                    """
                    delete from acquisition_consumer_subscriptions
                    where subscription_id=%s and source_instance_id=%s
                      and stream_id=%s and transport_binding=%s
                      and consumer_id=%s and consumer_component_id=%s
                      and consumer_component_version=%s
                      and routing_contract_id=%s
                      and consumer_contract_version=%s and replay_policy=%s
                      and resource_profile_id=%s
                      and selector_json=%s::jsonb and selector_sha256=%s
                      and authority_mode=%s and desired_activation='disabled'
                      and partition_key=%s
                    """,
                    (
                        candidate["legacy_subscription_id"],
                        candidate["legacy_source_instance_id"],
                        stream["stream_id"],
                        stream["transport_binding"],
                        subscription["consumer_id"],
                        subscription["consumer_component_id"],
                        subscription["consumer_component_version"],
                        subscription["routing_contract_id"],
                        subscription["consumer_contract_version"],
                        subscription["replay_policy"],
                        subscription["resource_profile_id"],
                        selector_json,
                        selector_sha,
                        subscription["authority_mode"],
                        subscription["partition_key"],
                    ),
                )
                if cur.rowcount != 1:
                    raise RadiusProductionRegistrationError(
                        "legacy_remediation_subscription_delete_failed"
                    )
                cur.execute(
                    """
                    delete from acquisition_stream_cursors
                    where source_instance_id=%s and stream_id=%s
                      and transport_binding=%s and cursor_epoch=%s
                      and file_generation=%s and byte_offset=%s
                      and last_record_sha256 is not distinct from %s
                      and previous_file_generation is not distinct from %s
                      and previous_generation_last_record_sha256
                          is not distinct from %s
                      and revision=%s
                    """,
                    (
                        candidate["legacy_source_instance_id"],
                        stream["stream_id"],
                        stream["transport_binding"],
                        candidate["cursor"][2],
                        candidate["cursor"][3],
                        candidate["cursor"][4],
                        candidate["cursor"][5],
                        candidate["cursor"][6],
                        candidate["cursor"][7],
                        candidate["cursor"][8],
                    ),
                )
                if cur.rowcount != 1:
                    raise RadiusProductionRegistrationError(
                        "legacy_remediation_cursor_delete_failed"
                    )
                cur.execute(
                    """
                    delete from acquisition_source_instances
                    where source_instance_id=%s and organization_scope=%s
                      and source_kind=%s and endpoint_identity=%s
                      and adapter_binding=%s
                      and credential_handle is not distinct from %s
                      and display_name=%s
                      and desired_activation='disabled'
                      and observed_health='unknown'
                      and configuration_sha256=%s
                    """,
                    (
                        candidate["legacy_source_instance_id"],
                        source["organization_scope"],
                        source["source_kind"],
                        source["endpoint_identity"],
                        source["adapter_binding"],
                        source["credential_handle"],
                        source["display_name"],
                        legacy_configuration_sha,
                    ),
                )
                if cur.rowcount != 1:
                    raise RadiusProductionRegistrationError(
                        "legacy_remediation_source_delete_failed"
                    )
            receipt = register_disabled_radius_source(
                conn,
                bootstrap=bootstrap,
            )
    rows = _inspect_rows()
    if rows != {
        "migration_58": True,
        "source_count": 1,
        "cursor_count": 1,
        "subscription_count": 1,
    }:
        raise RadiusProductionRegistrationError(
            "registration_postcondition_failed"
        )
    return {
        "status": "passed",
        "action": "disabled_registration",
        "source_instance_id": receipt.source_instance_id,
        "stream_id": receipt.stream_id,
        "transport_binding": receipt.transport_binding,
        "subscription_id": receipt.subscription_id,
        "desired_activation": receipt.desired_activation,
        "cursor_revision": receipt.cursor_revision,
        "created": {
            "source": receipt.created_source,
            "cursor": receipt.created_cursor,
            "subscription": receipt.created_subscription,
        },
        "prerequisite_plan": planned["status"],
        "remediation": {
            "legacy_endpoint_registration_replaced": True,
            "legacy_cursor_revision": candidate["cursor_revision"],
            "runtime_state_rows_before": candidate["runtime_state_rows"],
        },
        "source_contacted": False,
        "worker_activated": False,
        "runtime_enabled": False,
        "autostart_changed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--action",
        choices=("plan", "apply", "remediate-legacy-and-apply"),
        default="plan",
    )
    parser.add_argument("--confirmation", default="")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--load-supervisor-environment", action="store_true")
    parser.add_argument("--prerequisites-dir", type=Path,
                        help="Explicit fresh evidence directory under artifacts; historical evidence is never overwritten.")
    args = parser.parse_args()
    if args.load_supervisor_environment:
        _load_environment()
    prerequisite_options = {} if args.prerequisites_dir is None else {"prerequisites_dir": args.prerequisites_dir}
    expected_principal, expected_sid = expected_collection_identity()
    if not expected_principal or not expected_sid:
        raise PermissionError("configured_collection_identity_required")
    if verify_collection_identity()["status"] != "ok":
        raise PermissionError("current_windows_account_is_not_approved_owner")
    if args.action == "plan":
        result, _bootstrap = plan(**prerequisite_options)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    confirmation = (
        LEGACY_REMEDIATION_CONFIRMATION
        if args.action == "remediate-legacy-and-apply"
        else CONFIRMATION
    )
    if args.confirmation != confirmation:
        raise PermissionError(
            f"apply requires --confirmation {confirmation}"
        )
    output = args.output.resolve()
    if (ROOT / "artifacts").resolve() not in output.parents:
        raise ValueError("result must stay under artifacts")
    if output.exists():
        raise FileExistsError("registration evidence already exists")
    result = (
        remediate_legacy_and_apply(**prerequisite_options)
        if args.action == "remediate-legacy-and-apply"
        else apply_registration(**prerequisite_options)
    )
    temporary = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()
    print(json.dumps({"status": result["status"], "output": str(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
