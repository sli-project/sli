#!/usr/bin/env python3
"""Read-only PITR readiness preflight; it never changes PostgreSQL settings."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.app_config import load_config  # noqa: E402


def _volume_identity(value: str) -> tuple[str, str | int] | None:
    """Return a platform-independent volume identity, failing closed.

    ``Path.drive`` follows the host OS and therefore loses Windows drive and
    UNC share information when this read-only preflight is tested from Linux.
    """
    windows_drive = PureWindowsPath(value).drive.casefold()
    if windows_drive:
        return ("windows", windows_drive)
    try:
        return ("device", Path(value).stat().st_dev)
    except OSError:
        return None


def independent_destination(data_directory: str, destination: str) -> bool:
    source_volume = _volume_identity(data_directory)
    destination_volume = _volume_identity(destination)
    return bool(source_volume and destination_volume and source_volume != destination_volume)


def _connect_read_settings():
    import psycopg
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row

    parts = conninfo_to_dict(load_config().postgres_dsn or "")
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not user or not password:
        raise RuntimeError("local PostgreSQL admin credentials are required for settings preflight")
    parts.update(user=user, password=password, application_name="adlog_pitr_read_only_preflight")
    return psycopg.connect(**parts, row_factory=dict_row)


def _setting(cur: Any, name: str) -> str:
    cur.execute("select current_setting(%s) as value", (name,))
    return str(cur.fetchone()["value"])


def collect_preflight(
    *, destination: str | None, rpo_minutes: int | None, rto_minutes: int | None,
    retention_days: int | None, restore_evidence: Path | None,
) -> dict[str, Any]:
    with _connect_read_settings() as conn:
        with conn.cursor() as cur:
            settings = {
                name: _setting(cur, name)
                for name in (
                    "data_directory", "archive_mode", "archive_command", "archive_timeout",
                    "wal_level", "max_wal_senders", "max_replication_slots",
                )
            }
            cur.execute("select pg_database_size(current_database())::bigint as database_bytes,current_database() as database")
            database = dict(cur.fetchone())
            cur.execute(
                """
                select archived_count,failed_count,last_archived_wal,last_archived_time,
                       last_failed_wal,last_failed_time,stats_reset
                from pg_stat_archiver
                """
            )
            archiver = dict(cur.fetchone())
            wal_bytes = None
            wal_error = None
            try:
                cur.execute("select coalesce(sum(size),0)::bigint as bytes from pg_ls_waldir()")
                wal_bytes = int(cur.fetchone()["bytes"])
            except Exception as exc:
                conn.rollback()
                wal_error = type(exc).__name__

    data_directory = settings["data_directory"]
    disk = None
    try:
        usage = shutil.disk_usage(data_directory)
        disk = {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free, "free_percent": round(usage.free / usage.total * 100, 2)}
    except OSError:
        try:
            volume_root = Path(data_directory).anchor or f"{Path(data_directory).drive}\\"
            usage = shutil.disk_usage(volume_root)
            disk = {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free, "free_percent": round(usage.free / usage.total * 100, 2), "scope": "volume_root"}
        except OSError:
            disk = {"status": "unavailable"}

    destination_path = str(destination or "").strip()
    destination_state = {
        "configured": bool(destination_path),
        "path": destination_path or None,
        "exists": False,
        "is_directory": False,
        "independent_volume": False,
        "free_bytes": None,
    }
    if destination_path:
        path = Path(destination_path)
        destination_state["exists"] = path.exists()
        destination_state["is_directory"] = path.is_dir()
        destination_state["independent_volume"] = independent_destination(data_directory, destination_path)
        if path.is_dir():
            try:
                destination_state["free_bytes"] = shutil.disk_usage(path).free
            except OSError:
                pass

    restore_state = {"provided": bool(restore_evidence), "accepted": False, "path": str(restore_evidence) if restore_evidence else None}
    if restore_evidence and restore_evidence.is_file():
        try:
            evidence = json.loads(restore_evidence.read_text(encoding="utf-8"))
            restore_state["accepted"] = str(evidence.get("status") or "").lower() in {"accepted", "ok", "passed"}
        except (OSError, json.JSONDecodeError):
            restore_state["accepted"] = False

    blockers: list[str] = []
    if not destination_state["configured"]:
        blockers.append("independent_archive_destination_not_configured")
    elif not destination_state["exists"] or not destination_state["is_directory"]:
        blockers.append("archive_destination_not_accessible")
    elif not destination_state["independent_volume"]:
        blockers.append("archive_destination_is_not_independent_volume")
    if not rpo_minutes or rpo_minutes <= 0:
        blockers.append("rpo_not_decided")
    if not rto_minutes or rto_minutes <= 0:
        blockers.append("rto_not_decided")
    if not retention_days or retention_days <= 0:
        blockers.append("wal_retention_not_decided")
    if not restore_state["accepted"]:
        blockers.append("isolated_pitr_restore_not_accepted")

    archive_command = settings.pop("archive_command")
    settings["archive_command_present"] = bool(archive_command.strip())
    settings["archive_command_sha256"] = sha256(archive_command.encode("utf-8")).hexdigest() if archive_command else None
    return {
        "package_type": "PITR_ARCHIVE_READ_ONLY_PREFLIGHT",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "ready_for_controlled_enable_review" if not blockers else "blocked",
        "read_only": True,
        "postgres_settings_changed": False,
        "postgres_restarted": False,
        "surveyed_servers_contacted": False,
        "settings": settings,
        "database": {"name": str(database["database"]), "bytes": int(database["database_bytes"])},
        "wal": {"bytes": wal_bytes, "probe_error": wal_error, "archiver": archiver},
        "data_volume": disk,
        "destination": destination_state,
        "policy": {"rpo_minutes": rpo_minutes, "rto_minutes": rto_minutes, "retention_days": retention_days},
        "restore_evidence": restore_state,
        "blockers": blockers,
        "next_action": "provide independent destination and owner-approved RPO/RTO/retention, then run isolated restore" if blockers else "owner review before any restart or archive_mode change",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination")
    parser.add_argument("--rpo-minutes", type=int)
    parser.add_argument("--rto-minutes", type=int)
    parser.add_argument("--retention-days", type=int)
    parser.add_argument("--restore-evidence", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    try:
        result = collect_preflight(
            destination=args.destination, rpo_minutes=args.rpo_minutes,
            rto_minutes=args.rto_minutes, retention_days=args.retention_days,
            restore_evidence=args.restore_evidence,
        )
    except Exception as exc:
        result = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc), "read_only": True}
    payload = json.dumps(result, ensure_ascii=False, indent=2, default=str)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if result.get("status") in {"blocked", "ready_for_controlled_enable_review"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
