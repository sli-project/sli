from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, Mapping

from server.sli.storage.storage_policy_format import _now_utc, fmt_bytes
from server.sli.storage.storage_policy_fs import _iter_files, _safe_stat

StorageCapacityProfile = Literal["economy", "extended"]


def _snapshot_total_for_recommendation(row: Mapping[str, Any]) -> int:
    return sum(
        int(row.get(name) or 0)
        for name in (
            "database_bytes", "raw_bytes", "raw_archive_bytes", "backups_bytes",
            "logs_bytes", "reports_bytes", "artifacts_bytes",
        )
    )


def _snapshot_at(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _load_storage_capacity_snapshots(*, limit: int = 120) -> list[dict[str, Any]]:
    """Read a bounded lifecycle history without validating or changing schema."""
    from server.sli.core.postgres_runtime_pipeline import connect
    from server.sli.storage.storage_lifecycle import SNAPSHOT_TABLE

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                select captured_at, database_bytes, raw_bytes, raw_archive_bytes,
                       logs_bytes, reports_bytes, disk_used_bytes
                from {SNAPSHOT_TABLE}
                order by captured_at desc
                limit %s
                """,
                (max(2, min(int(limit), 200)),),
            )
            return [dict(row) for row in cur.fetchall()]


def _growth_bytes_per_day(paths: list[Path], *, lookback_hours: int = 24, max_entries: int = 10000) -> dict[str, Any]:
    cutoff = _now_utc() - timedelta(hours=lookback_hours)
    total = 0
    seen = 0
    for root in paths:
        files, meta = _iter_files(root, max_entries=max_entries, max_seconds=3.0)
        seen += int(meta.get("files_seen") or 0)
        for file in files:
            st = _safe_stat(file)
            if not st:
                continue
            if datetime.fromtimestamp(st.st_mtime, tz=timezone.utc) >= cutoff:
                total += st.st_size
    return {"lookback_hours": lookback_hours, "bytes": total, "human": fmt_bytes(total), "files_seen": seen, "gb_per_day": round(total / 1024**3, 2)}


def _capacity_state(capacity: dict[str, Any]) -> dict[str, Any]:
    days = capacity.get("days_until_full")
    try:
        value = float(days) if days is not None else None
    except (TypeError, ValueError):
        value = None
    if value is None:
        status = "unknown"
    elif value < 2:
        status = "critical"
    elif value < 7:
        status = "high"
    elif value < 14:
        status = "warn"
    else:
        status = "ok"
    scale = []
    for item in capacity.get("server_model") or []:
        projected_days = item.get("projected_days_until_full")
        ready = projected_days is None or float(projected_days) >= 14
        scale.append({**item, "capacity_ready": ready})
    return {"status": status, "days_until_full": days, "scale_readiness": scale, "minimum_ready_days": 14}


def _project_scan_warning(project_overview: dict[str, Any]) -> str | None:
    scan = dict(project_overview.get("scan") or {})
    if not scan:
        return None
    errors = int(scan.get("errors") or 0)
    if bool(scan.get("complete_project_tree")) and errors == 0:
        return None
    return f"полный обход проекта неполон: ошибок чтения {errors}"


def _operator_guidance(pressure: dict[str, Any], cleanup_plan: dict[str, Any], postgres_operations: dict[str, Any] | None = None, storage_lifecycle: dict[str, Any] | None = None) -> list[str]:
    guidance: list[str] = []
    if not pressure.get("collection_allowed"):
        guidance.append("Новые collection jobs заблокированы disk pressure guard; выполните dry-run cleanup и освободите место.")
    elif pressure.get("status") == "warn":
        guidance.append("Диск в warning-зоне; запланируйте cleanup до масштабирования на 5–10 серверов.")
    if cleanup_plan.get("total_candidates"):
        guidance.append("Начните с dry-run: python scripts\\maintenance\\storage_cleanup.py --dry-run --json")
        guidance.append("Apply только явно: python scripts\\maintenance\\storage_cleanup.py --apply --confirm-apply --json")
    else:
        guidance.append("Автоматических кандидатов cleanup нет; проверьте raw_retention_days или deep diagnostics.")
    pg_ops = postgres_operations or {}
    if pg_ops.get("status") == "failed":
        guidance.append("Проверить подключение и права PostgreSQL: operations metrics недоступны.")
    elif pg_ops.get("long_running_queries"):
        guidance.append("Проверить долгие PostgreSQL-запросы перед увеличением batch/profile.")
    elif pg_ops.get("backend") == "postgres":
        guidance.append("PostgreSQL metrics доступны; VACUUM/ANALYZE здесь только наблюдаются и не запускаются автоматически.")
        backup_tools = pg_ops.get("backup_tools") or {}
        if not backup_tools.get("available"):
            guidance.append("pg_dump/pg_restore не найдены полностью в PATH; выполнить backup/restore drill по runbook до масштабирования.")
    lifecycle = storage_lifecycle or {}
    if lifecycle.get("status") == "pending":
        guidance.append("Накопить 24 часа storage snapshots и выполнить PostgreSQL backup/restore rehearsal.")
    elif lifecycle.get("status") in {"warn", "unavailable"}:
        guidance.append("Проверить /api/storage/lifecycle и последний backup/restore evidence до расширения каналов.")
    guidance.append("VACUUM/REINDEX/DROP не запускаются автоматически; bloat только наблюдается.")
    return guidance
