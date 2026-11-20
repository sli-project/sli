"""Fast reader for the operator-generated complete project footprint snapshot."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.sli.core.paths import ROOT

SNAPSHOT_PATH = ROOT / "artifacts" / "operations" / "project-storage-latest.json"
SNAPSHOT_SCHEMA = "sli.operations-storage-footprint.v1"
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024


def backup_summary() -> dict:
    default = ('/var/lib/sli/backup-status/summary.json' if os.environ.get('SLI_DEPLOYMENT_MODE') == 'native'
               else '/run/sli-backup-status/summary.json')
    path = Path(os.environ.get('SLI_BACKUP_SUMMARY_PATH', default))
    empty = {'last_backup_at_utc': None, 'last_verified_at_utc': None, 'capacity_days': None}
    try:
        with path.open('rb') as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            return empty
        value = json.loads(raw)
        result = dict(empty)
        for key in ('last_backup_at_utc', 'last_verified_at_utc'):
            if value.get(key) is not None:
                stamp = datetime.fromisoformat(value[key])
                if stamp.tzinfo is not None:
                    result[key] = stamp.isoformat()
        days = value.get('capacity_days')
        age = _age_seconds(value.get('observed_at_utc'))
        if type(days) is int and days >= 0 and age is not None and age <= 172800:
            result['capacity_days'] = days
        return result
    except (OSError, ValueError, TypeError, AttributeError):
        return empty


def _max_age_seconds() -> int:
    try:
        return max(300, min(int(os.getenv("ADLOG_OPERATIONS_STORAGE_MAX_AGE_SECONDS", "86400")), 604800))
    except ValueError:
        return 86400


def _age_seconds(value: object) -> int | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0, int((datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds()))
    except (TypeError, ValueError):
        return None


def _unavailable_raw_spool(*, error: str) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "path": None,
        "bytes": None,
        "human": None,
        "batch_count": None,
        "oldest_batch_at_utc": None,
        "oldest_batch_age_seconds": None,
        "scan": {"complete": False, "errors": 1, "error": error},
        "thresholds": {},
    }


def _validate_raw_spool(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _unavailable_raw_spool(error="raw_spool_missing")
    status = value.get("status")
    scan = value.get("scan")
    thresholds = value.get("thresholds")
    if status not in {"ok", "partial", "unavailable"} or not isinstance(scan, dict) or not isinstance(thresholds, dict):
        return _unavailable_raw_spool(error="raw_spool_contract_invalid")
    result = dict(value)
    if status == "unavailable":
        # Unknown values are never accepted as measured zeroes.
        if value.get("bytes") is not None or value.get("batch_count") is not None:
            return _unavailable_raw_spool(error="raw_spool_unavailable_has_measurements")
        result["bytes"] = None
        result["human"] = None
        result["batch_count"] = None
        result["oldest_batch_at_utc"] = None
        result["oldest_batch_age_seconds"] = None
    elif not isinstance(value.get("bytes"), int) or not isinstance(value.get("batch_count"), int):
        return _unavailable_raw_spool(error="raw_spool_measurements_invalid")
    if status == "ok" and scan.get("complete") is not True:
        result["status"] = "partial"
    return result


def load_operations_storage_snapshot(path: Path = SNAPSHOT_PATH) -> dict[str, Any]:
    """Read a bounded local snapshot; never start a filesystem or Docker scan."""
    try:
        stat = path.stat()
        if not path.is_file() or stat.st_size > MAX_SNAPSHOT_BYTES:
            raise ValueError("snapshot_size_invalid")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != SNAPSHOT_SCHEMA:
            raise ValueError("snapshot_schema_invalid")
        components = payload.get("components")
        if not isinstance(components, list) or len(components) > 100:
            raise ValueError("snapshot_components_invalid")
        age = _age_seconds(payload.get("generated_at_utc"))
        stale = age is None or age > _max_age_seconds()
        result = dict(payload)
        result['backups'] = backup_summary()
        raw_spool = _validate_raw_spool(payload.get("raw_spool"))
        result["raw_spool"] = raw_spool
        raw_contract_error = (raw_spool.get("scan") or {}).get("error")
        if raw_contract_error not in {None, "raw_spool_missing"}:
            result["status"] = "unavailable"
        elif raw_spool["status"] in {"partial", "unavailable"} and result.get("status") == "ok":
            result["status"] = "partial"
            result["warnings"] = [
                *(str(item) for item in (payload.get("warnings") or [])),
                "RAW spool measurements are incomplete or unavailable.",
            ]
        result["snapshot"] = {
            "path": str(path),
            "age_seconds": age,
            "max_age_seconds": _max_age_seconds(),
            "stale": stale,
            "available": True,
        }
        if stale:
            result["status"] = "stale"
            result["warnings"] = [
                *(str(item) for item in (payload.get("warnings") or [])),
                "Storage footprint snapshot is stale; run the documented read-only refresh.",
            ]
        return result
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "schema": SNAPSHOT_SCHEMA,
            "status": "unavailable",
            "generated_at_utc": None,
            "components": [],
            "backups": backup_summary(),
            "totals": {},
            "warnings": ["Complete storage footprint snapshot is unavailable."],
            "snapshot": {
                "path": str(path),
                "age_seconds": None,
                "max_age_seconds": _max_age_seconds(),
                "stale": False,
                "available": False,
                "error_type": type(exc).__name__,
            },
            "read_only": True,
        }
