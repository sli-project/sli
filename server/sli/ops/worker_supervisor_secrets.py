"""DPAPI-protected runtime environment for the local Windows worker supervisor.

The scheduled task does not inherit the transient Codex/terminal environment.
Persisting PostgreSQL credentials in Task Scheduler arguments or the user
environment would expose them as plaintext.  This module stores only the
worker-specific allowlist as a current-user DPAPI blob under ignored runtime
data and never prints values.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
from collections.abc import Collection, Mapping, MutableMapping
from contextlib import closing
from pathlib import Path

from server.sli.core.paths import DATA_DIR

SUPERVISOR_ENV_PATH = DATA_DIR / "runtime" / "worker-supervisor.env.dpapi"
_DESCRIPTION = "SLI worker supervisor environment v1"
_DPAPI_UI_FORBIDDEN = 0x1
_VERSION = 2
_LOG = logging.getLogger(__name__)


class _MigrationDeferred(RuntimeError):
    """The shared profile cannot safely switch Windows identities yet."""


# The sealed supervisor profile contains maintenance-only PostgreSQL
# credentials.  HTTP serves no consumer for them, so every HTTP child removes
# this exact set before server modules or the child process can consume it.
HTTP_FORBIDDEN_ENVIRONMENT = frozenset(
    {
        "ADLOG_PG_ADMIN_USER",
        "ADLOG_PG_ADMIN_PASSWORD",
        "ADLOG_STORAGE_V2_WORKER_DSN",
        "ADLOG_SEMANTIC_WORKER_DSN",
    }
)


def strip_http_forbidden_environment(
    destination: MutableMapping[str, str] | None = None,
) -> None:
    """Remove maintenance-only credentials from one HTTP process environment."""
    values = destination if destination is not None else os.environ
    for name in HTTP_FORBIDDEN_ENVIRONMENT:
        values.pop(name, None)

WORKER_ENV_ALLOWLIST = frozenset(
    {
        "ADLOG_CHANNEL_FAIRNESS_ENABLED",
        "ADLOG_CHANNEL_FAIRNESS_MAX_EVENTS",
        "ADLOG_CHANNEL_FAIRNESS_STALE_MINUTES",
        "ADLOG_CHANNEL_FAIRNESS_TIMEOUT_SECONDS",
        "ADLOG_CHANNEL_TIMEOUT_SECONDS",
        "ADLOG_AD_CONTEXT_DIRECTORY_SERVER",
        "ADLOG_AD_CONTEXT_DOMAIN",
        "ADLOG_AD_CONTEXT_INTERVAL_SECONDS",
        "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS",
        "ADLOG_AD_CONTEXT_SEARCH_BASE",
        "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES",
        "ADLOG_COLLECT_MESSAGE",
        "ADLOG_AD_SOURCE_CREDENTIAL_MODE",
        "ADLOG_AD_EVENTLOG_CREDENTIAL_PROFILE",
        "ADLOG_VPN_SOURCE_CREDENTIAL_MODE",
        "ADLOG_AUTH_REQUIRED",
        "ADLOG_ALLOW_UNAUTHENTICATED",
        "ADLOG_TRUSTED_PROXIES",
        "ADLOG_COLLECTION_MAX_EVENTS_PER_CHANNEL",
        "ADLOG_COLLECTION_MODE",
        "ADLOG_COLLECTION_NOT_BEFORE_UTC",
        "ADLOG_COLLECTION_PREFLIGHT_SERVER",
        "ADLOG_RADIUS_COLLECTION_ROUTES_PATH",
        "ADLOG_RADIUS_REGISTRATION_CONTRACT_PATH",
        "ADLOG_RADIUS_CURSOR_BOOTSTRAP_EVIDENCE_PATH",
        "ADLOG_RADIUS_REGISTRATION_APPLY_EVIDENCE_PATH",
        "ADLOG_RADIUS_SOURCE_NAME",
        "ADLOG_RADIUS_SOURCE_INSTANCE_ID",
        "ADLOG_RADIUS_OWNER_CONFIRMED_IP",
        "ADLOG_RADIUS_ACCOUNTING_SHARE_UNC",
        "ADLOG_COLLECTION_PRINCIPAL",
        "ADLOG_COLLECTION_PRINCIPAL_SID",
        "ADLOG_COLLECTION_TIMEOUT_SECONDS",
        "ADLOG_COLLECTOR_BACKEND",
        "ADLOG_COLLECTOR_INTERVAL_SECONDS",
        "ADLOG_CONTINUOUS_RECOVERY",
        "ADLOG_CONTINUOUS_RECOVERY_COOLDOWN_SECONDS",
        "ADLOG_CONTINUOUS_RECOVERY_MAX_CYCLES",
        "ADLOG_CONTINUOUS_RECOVERY_MAX_JOB_SECONDS",
        "ADLOG_DB_BACKEND",
        "ADLOG_ENABLE_POSTGRES_COLLECTION",
        "ADLOG_EXTERNAL_POST_COLLECTION_WORKER",
        "ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER",
        "ADLOG_LOG_DIR",
        "ADLOG_HISTORY_CLICKHOUSE_PORT",
        "ADLOG_HISTORY_CLICKHOUSE_USER",
        "ADLOG_HISTORY_CLICKHOUSE_PASSWORD",
        "ADLOG_HISTORY_READ_MODE",
        "ADLOG_NON_SECURITY_MAX_EVENTS",
        "ADLOG_NPS_EVENTLOG_ENABLED",
        "ADLOG_PARALLEL_DC_WORKERS",
        "ADLOG_PG_ADMIN_PASSWORD",
        "ADLOG_PG_ADMIN_USER",
        "ADLOG_PG_CONNECT_TIMEOUT_SECONDS",
        "ADLOG_PG_DSN",
        "ADLOG_PG_LOCK_TIMEOUT_MS",
        "ADLOG_PG_STATEMENT_TIMEOUT_MS",
        "ADLOG_POSTGRES_RUNTIME_COLLECTION",
        "ADLOG_RAW_ARCHIVE_COMPRESS",
        "ADLOG_RAW_ARCHIVE_ENABLED",
        "ADLOG_DELETE_IMPORTED_RAW",
        "ADLOG_RAW_RETENTION_DAYS",
        "ADLOG_SCOPED_ACTIVATION_GATE_PATH",
        "ADLOG_SCOPED_ACTIVATION_GATE_SHA256",
        "ADLOG_SECURITY_RECOVERY_COOLDOWN_SECONDS",
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED",
        "ADLOG_SEMANTIC_RUNTIME_MODE",
        "ADLOG_SEMANTIC_NORMALIZATION_ENABLED",
        "ADLOG_SEMANTIC_ASSEMBLY_ENABLED",
        "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED",
        "ADLOG_SEMANTIC_CORRELATION_ENABLED",
        "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED",
        "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED",
        "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST",
        "ADLOG_STOP_COLLECTION_IF_FREE_DISK_BYTES_BELOW",
        "ADLOG_STORAGE_CLEANUP_LIMIT",
        "ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED",
        "ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION",
        "ADLOG_STORAGE_LIFECYCLE_WARM_COPY_ADMISSION",
        "ADLOG_STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED",
        "ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION",
        "ADLOG_STORAGE_READ_MODE",
        "ADLOG_STORAGE_V2_SHADOW_SAMPLE_RATE",
        "ADLOG_STORAGE_V2_STAGING_CLEANUP_LIMIT",
        "ADLOG_STORAGE_V2_WORKER_DSN",
        "ADLOG_STORAGE_WRITE_MODE",
        "ADLOG_TLS_CERT_PATH",
        "ADLOG_TLS_KEY_PATH",
        "ADLOG_UI_MODE",
        "SLI_G11A3_DIRECTORY_SERVER",
        "SLI_G11A3_PROBE_PLAN_ID",
        "SLI_G11A3_VPN_GROUP_SID",
    }
)

_ENFORCED_VALUES = {
    "ADLOG_DB_BACKEND": "postgres",
    "ADLOG_ENABLE_POSTGRES_COLLECTION": "1",
    "ADLOG_DISABLE_SCHEDULER": "1",
    "ADLOG_EXTERNAL_POST_COLLECTION_WORKER": "1",
    "ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER": "1",
    "ADLOG_COLLECTION_MAX_EVENTS_PER_CHANNEL": "50000",
    "ADLOG_STOP_COLLECTION_IF_FREE_DISK_BYTES_BELOW": str(10 * 1024**3),
}


def supervisor_environment_payload(
    source: Mapping[str, str],
) -> dict[str, str]:
    payload = {
        name: str(source[name])
        for name in sorted(WORKER_ENV_ALLOWLIST)
        if str(source.get(name) or "").strip()
    }
    payload.update(_ENFORCED_VALUES)
    payload.setdefault("ADLOG_AUTH_REQUIRED", "1")
    if not payload.get("ADLOG_PG_DSN"):
        raise RuntimeError("ADLOG_PG_DSN is required to provision the supervisor")
    for name in ("ADLOG_COLLECTION_PRINCIPAL", "ADLOG_COLLECTION_PRINCIPAL_SID"):
        if not payload.get(name):
            raise RuntimeError(f"{name} is required to provision the supervisor")
    return payload


def provision_supervisor_environment(
    *,
    source: Mapping[str, str] | None = None,
    path: Path = SUPERVISOR_ENV_PATH,
) -> dict[str, object]:
    if os.name != "nt":
        raise RuntimeError("Windows DPAPI is required")
    payload = supervisor_environment_payload(source or os.environ)
    _store_supervisor_environment(payload, path=path)
    return {
        "status": "ok",
        "path": str(path),
        "keys": sorted(payload),
        "credential_values_exposed": False,
    }


def _current_user_sid() -> str:
    from server.sli.sources.ad_source_credentials import _current_sid, _windows

    return _windows()[4].ConvertSidToStringSid(_current_sid())


def _ensure_web_service_identity(owner_sid: str) -> None:
    """Do not strand the shared HTTP reader in another DPAPI user context."""
    import win32security
    import win32service

    manager = None
    try:
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            service = win32service.OpenService(manager, "SLIWebServer", win32service.SERVICE_QUERY_CONFIG)
        except Exception as exc:  # noqa: BLE001 -- Win32 errors must not disclose account details.
            if getattr(exc, "winerror", None) == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
                return
            raise _MigrationDeferred("worker supervisor web service identity check failed") from None
        try:
            account = win32service.QueryServiceConfig(service)[7]
            if account.casefold() == "localsystem":
                service_sid = "S-1-5-18"
            else:
                service_sid = win32security.ConvertSidToStringSid(
                    win32security.LookupAccountName(None, account)[0]
                )
            if service_sid != owner_sid:
                raise _MigrationDeferred("worker supervisor web service account must match the profile owner")
        finally:
            win32service.CloseServiceHandle(service)
    except _MigrationDeferred:
        raise
    except Exception:  # noqa: BLE001 -- Sanitize SCM and account lookup errors.
        raise _MigrationDeferred("worker supervisor web service identity check failed") from None
    finally:
        if manager is not None:
            win32service.CloseServiceHandle(manager)


def _write_protected_blob(path: Path, blob: bytes) -> None:
    # Use the same protected owner/SYSTEM DACL and handle verification as the
    # AD credential store. The temporary file is private from its creation.
    from server.sli.sources.ad_source_credentials import (
        _current_sid,
        _security_attributes,
        _verify_handle,
        _windows,
    )

    _, con, _, files, _, _ = _windows()
    sid = _current_sid()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(".pending-supervisor-" + secrets.token_hex(16))
    created = False
    try:
        with closing(files.CreateFile(
            str(temporary), con.GENERIC_WRITE | con.READ_CONTROL, 0,
            _security_attributes(sid, directory=False), con.CREATE_NEW,
            con.FILE_ATTRIBUTE_NORMAL | files.FILE_FLAG_OPEN_REPARSE_POINT, None,
        )) as handle:
            created = True
            _verify_handle(handle, sid, directory=False)
            _, written = files.WriteFile(handle, blob)
            if written != len(blob):
                raise RuntimeError("worker supervisor environment write failed")
            files.FlushFileBuffers(handle)
        files.MoveFileEx(
            str(temporary), str(path),
            files.MOVEFILE_WRITE_THROUGH | con.MOVEFILE_REPLACE_EXISTING,
        )
        created = False
    finally:
        if created:
            files.DeleteFile(str(temporary))


def _store_supervisor_environment(values: Mapping[str, str], *, path: Path) -> None:
    import win32crypt  # type: ignore

    sid = _current_user_sid()
    if values.get("ADLOG_COLLECTION_PRINCIPAL_SID") != sid:
        raise _MigrationDeferred("worker supervisor profile must be written by its configured user")
    _ensure_web_service_identity(sid)
    encoded = json.dumps(
        {"version": _VERSION, "owner_sid": sid, "environment": values},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        protected = win32crypt.CryptProtectData(
            encoded, _DESCRIPTION, None, None, None, _DPAPI_UI_FORBIDDEN,
        )
        _write_protected_blob(path, bytes(protected))
    except Exception:  # noqa: BLE001 -- Do not expose DPAPI or filesystem exception details.
        raise RuntimeError("worker supervisor environment protection or storage failed") from None


def _read_supervisor_environment(path: Path) -> dict:
    if os.name != "nt":
        raise RuntimeError("Windows DPAPI is required")
    if not path.is_file():
        raise RuntimeError("worker supervisor environment is not provisioned")
    import win32crypt  # type: ignore

    # CryptUnprotectData handles both historical machine and user scopes;
    # trying a different flag is neither necessary nor a scope detector.
    try:
        _description, clear = win32crypt.CryptUnprotectData(
            path.read_bytes(), None, None, None, _DPAPI_UI_FORBIDDEN,
        )
        loaded = json.loads(bytes(clear).decode("utf-8"))
    except Exception:  # noqa: BLE001 -- Do not expose DPAPI or decrypted payload details.
        raise RuntimeError("worker supervisor environment decryption failed") from None
    if (
        not isinstance(loaded, dict)
        or loaded.get("version") not in (1, _VERSION)
        or not isinstance(loaded.get("environment"), dict)
    ):
        raise RuntimeError("worker supervisor environment has an unsupported format")
    if loaded["version"] == _VERSION and loaded.get("owner_sid") != _current_user_sid():
        raise RuntimeError("worker supervisor environment owner mismatch")
    return loaded


def reencrypt_supervisor_environment(*, path: Path = SUPERVISOR_ENV_PATH) -> dict[str, object]:
    """Explicit local re-sealing under the configured supervisor user's DPAPI."""
    loaded = _read_supervisor_environment(path)
    _store_supervisor_environment(loaded["environment"], path=path)
    migrated = loaded["version"] == 1
    if migrated:
        _LOG.warning("Worker supervisor environment migrated to CurrentUser DPAPI with private DACL")
    return {
        "status": "ok",
        "dpapi_scope": "CurrentUser",
        "migrated": migrated,
        "credential_values_exposed": False,
    }


def load_supervisor_environment(
    *,
    target: MutableMapping[str, str] | None = None,
    path: Path = SUPERVISOR_ENV_PATH,
    override_existing: bool = False,
) -> dict[str, object]:
    loaded = _read_supervisor_environment(path)
    values = loaded["environment"]
    migrated = False
    migration_deferred = False
    if loaded["version"] == 1:
        try:
            _store_supervisor_environment(values, path=path)
        except _MigrationDeferred:
            # The service also reads this profile. Keep legacy readers running
            # until the owner explicitly aligns accounts; never reseal as SYSTEM.
            migration_deferred = True
            _LOG.warning("Worker supervisor environment migration deferred: align profile owner and web service account")
        else:
            migrated = True
            _LOG.warning("Worker supervisor environment migrated to CurrentUser DPAPI with private DACL")
    destination = target if target is not None else os.environ
    imported: list[str] = []
    for name, value in values.items():
        if name not in WORKER_ENV_ALLOWLIST and name not in _ENFORCED_VALUES:
            continue
        if not isinstance(value, str) or not value:
            continue
        if name in _ENFORCED_VALUES:
            destination[name] = _ENFORCED_VALUES[name]
        elif name in {"ADLOG_COLLECTION_PRINCIPAL", "ADLOG_COLLECTION_PRINCIPAL_SID"} or override_existing:
            destination[name] = value
        else:
            destination.setdefault(name, value)
        imported.append(name)
    # A disarmed recovery scope must not survive from a scheduler/task parent
    # environment.  Other allowlisted values deliberately retain their merge
    # semantics; this key is a single-use capability and is removed only when
    # the sealed payload is authoritative.
    if (
        override_existing
        and "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST" not in values
    ):
        destination.pop("ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST", None)
    if not destination.get("ADLOG_PG_DSN"):
        raise RuntimeError("worker supervisor environment does not contain ADLOG_PG_DSN")
    return {
        "status": "ok",
        "path": str(path),
        "keys": sorted(imported),
        "migrated": migrated,
        "migration_deferred": migration_deferred,
        "credential_values_exposed": False,
    }


def update_supervisor_environment_with_removals(
    updates: Mapping[str, str],
    *,
    remove_keys: Collection[str],
    path: Path = SUPERVISOR_ENV_PATH,
) -> dict[str, object]:
    """Atomically update flags and remove the one recovery capability."""
    unknown = sorted(set(updates) - WORKER_ENV_ALLOWLIST)
    if unknown:
        raise RuntimeError(f"supervisor environment update is not allowlisted: {unknown}")
    requested_removals = sorted(set(remove_keys))
    permitted_removals = {"ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST"}
    if set(requested_removals) - permitted_removals:
        raise RuntimeError("supervisor environment removal is not permitted")
    existing: dict[str, str] = {}
    load_supervisor_environment(target=existing, path=path, override_existing=True)
    for name, value in updates.items():
        clean = str(value).strip()
        if not clean:
            raise RuntimeError(f"supervisor environment update is empty: {name}")
        existing[name] = clean
    for name in requested_removals:
        existing.pop(name, None)
    result = provision_supervisor_environment(source=existing, path=path)
    return {
        **result,
        "updated_keys": sorted(updates),
        "removed_keys": requested_removals,
        "existing_payload_merged": True,
    }


def update_supervisor_environment(
    updates: Mapping[str, str],
    *,
    path: Path = SUPERVISOR_ENV_PATH,
) -> dict[str, object]:
    """Merge allowlisted values into the existing DPAPI payload without disclosure."""
    return update_supervisor_environment_with_removals(
        updates,
        remove_keys=(),
        path=path,
    )


def remove_supervisor_environment_keys(
    keys: Collection[str],
    *,
    path: Path = SUPERVISOR_ENV_PATH,
) -> dict[str, object]:
    """Remove the one armed recovery capability without exposing the payload."""
    return update_supervisor_environment_with_removals(
        {},
        remove_keys=keys,
        path=path,
    )
