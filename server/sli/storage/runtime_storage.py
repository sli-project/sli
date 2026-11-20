from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from server.sli.core.paths import DATA_DIR, RAW_SPOOL_DIR, ROOT
from server.sli.storage.storage_v2_runtime_authorization import (
    is_persisted_runtime_authorization,
)
from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
    StorageRouteConsumer,  # noqa: F401 -- re-exported to route consumers
    is_controller_authorization,
)

RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
RAW_ARCHIVE_DIR = DATA_DIR / "raw_archive"
MAINTENANCE_DIR = DATA_DIR / "maintenance"
RAW_CLEANUP_METADATA_NAME = "raw_cleanup_last.json"
RAW_SPOOL_RELATIVE_PATH = Path("data") / "raw" / "pilot"
RAW_BYTES_WARNING = 500 * 1024 * 1024
RAW_BYTES_CRITICAL = 1024 * 1024 * 1024
# Existing policy boundaries: cleanup plans are bounded to 1000 candidates and
# raw transport retention defaults to two days.  Monitoring reports them; it
# does not authorize age-based cleanup.
RAW_BATCH_COUNT_WARNING = 1000
RAW_OLDEST_AGE_WARNING_SECONDS = 2 * 86400

class StorageRouteAuthorizationError(RuntimeError):
    """Raised when a declared transition cannot safely select a storage route."""


def validate_storage_route_authorization(authorization: object | None) -> object | None:
    if authorization is None:
        return None
    if (
        is_persisted_runtime_authorization(authorization)
        or is_controller_authorization(authorization)
    ):
        return authorization
    raise StorageRouteAuthorizationError("storage_transition_authorization_invalid")


def resolve_storage_route(
    *,
    authorization: CutoverAuthorization | object | None = None,
    transition_state: Mapping[str, object] | None = None,
    consumer: str | None = None,
) -> dict[str, str]:
    """Return the runtime storage route: always Storage V2 (plan 6.5).

    The V1 relations were dropped by migration 097, so there is no V1 route to
    select or to roll back to. A declared transition state without controller
    authority or a malformed authorization still
    stops the caller instead of being ignored.
    """
    if authorization is None:
        if transition_state is not None:
            raise StorageRouteAuthorizationError(
                "storage_transition_state_requires_controller_authorization"
            )
        return {
            "status": "READY",
            "route": "v2",
            "owner": "V2",
            "authorization": "configured",
        }
    if is_persisted_runtime_authorization(authorization):
        return {
            "status": "READY",
            "route": "v2",
            "owner": "V2",
            "authorization": "persisted-controller",
        }
    if is_controller_authorization(authorization):
        return {
            "status": "READY",
            "route": "v2",
            "owner": "V2",
            "authorization": "controller",
        }
    raise StorageRouteAuthorizationError("storage_transition_authorization_invalid")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def format_bytes(value: int | float | None) -> str:
    size = float(value or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if size < 1024 or unit == "ТБ":
            return f"{size:.1f} {unit}" if unit != "Б" else f"{int(size)} Б"
        size /= 1024
    return f"{int(value or 0)} Б"


def dir_size(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def file_count(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                count += 1
        except OSError:
            continue
    return count


def disk_info(path: Path = ROOT) -> dict[str, Any]:
    usage = shutil.disk_usage(path)
    free_pct = round((usage.free / usage.total) * 100, 2) if usage.total else 0
    return {
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "free_percent": free_pct,
        "total_human": format_bytes(usage.total),
        "used_human": format_bytes(usage.used),
        "free_human": format_bytes(usage.free),
    }


def _cleanup_metadata_path(root: Path = ROOT) -> Path:
    return root / "data" / "maintenance" / RAW_CLEANUP_METADATA_NAME


def _infer_root_from_raw_dir(raw_dir: Path) -> Path:
    # /project/data/raw -> /project. For custom temp dirs this keeps metadata
    # near the tested/runtime tree instead of the source checkout.
    if raw_dir.name == "raw" and raw_dir.parent.name == "data":
        return raw_dir.parent.parent
    return ROOT


def read_raw_cleanup_metadata(root: Path = ROOT) -> dict[str, Any] | None:
    path = _cleanup_metadata_path(root)
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
    except (OSError, json.JSONDecodeError):
        return None


def _write_raw_cleanup_metadata(root: Path, result: dict[str, Any]) -> None:
    path = _cleanup_metadata_path(root)
    payload = {
        "recorded_at_utc": _iso(_now_utc()),
        "mode": result.get("mode"),
        "archive_mode": result.get("archive_mode"),
        "raw_dir": result.get("raw_dir"),
        "archive_dir": result.get("archive_dir"),
        "zip_path": result.get("zip_path"),
        "older_than_days": result.get("older_than_days"),
        "total_raw_files": result.get("total_raw_files"),
        "total_candidates": result.get("total_candidates"),
        "total_bytes": result.get("total_bytes"),
        "total_human": result.get("total_human"),
        "moved_count": len(result.get("moved") or []),
        "archived_count": len(result.get("archived") or []),
        "error_count": len(result.get("errors") or []),
        "exclusion_summary": result.get("exclusion_summary") or {},
        "candidate_policy": result.get("candidate_policy"),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        # Maintenance metadata must never break cleanup itself.
        return


def _single_pass_storage_snapshot(root: Path) -> dict[str, Any]:
    """Collect category sizes in one traversal of the complete project tree."""
    started = time.perf_counter()
    sizes = {
        "project": 0,
        "data": 0,
        "raw": 0,
        "raw_archive": 0,
        "storage_v2_archives": 0,
        "processed": 0,
        "reports": 0,
        "logs": 0,
        "backups": 0,
        "maintenance": 0,
        "artifacts": 0,
        "archive": 0,
        "venv": 0,
        "frontend_node_modules": 0,
        "sqlite": 0,
    }
    counts = {
        "raw_files": 0,
        "raw_archive_files": 0,
        "processed_files": 0,
        "report_files": 0,
        "log_files": 0,
        "backup_files": 0,
        "maintenance_files": 0,
    }
    files_seen = 0
    errors = 0
    skipped_link_directories = 0
    skipped_generated_test_trees = 0
    error_paths: list[str] = []
    if root != ROOT:
        raw_spool_root = root / RAW_SPOOL_RELATIVE_PATH
    else:
        candidate_spool = root / RAW_SPOOL_RELATIVE_PATH
        raw_spool_root = RAW_SPOOL_DIR if (RAW_SPOOL_DIR.is_dir() or not candidate_spool.is_dir()) else candidate_spool
    raw_spool_exists = False
    raw_spool_bytes = 0
    raw_spool_batches = 0
    raw_spool_oldest: datetime | None = None
    raw_spool_errors = 0
    raw_spool_error_paths: list[str] = []

    try:
        raw_spool_exists = raw_spool_root.is_dir()
    except OSError as exc:
        raw_spool_errors += 1
        raw_spool_error_paths.append(str(getattr(exc, "filename", None) or raw_spool_root))

    def under_raw_spool(path: Path) -> bool:
        try:
            path.relative_to(raw_spool_root)
            return True
        except ValueError:
            return False

    def record_raw_spool_error(path: Path) -> None:
        nonlocal raw_spool_errors
        raw_spool_errors += 1
        if len(raw_spool_error_paths) < 50:
            raw_spool_error_paths.append(str(path))

    def generated_test_tree(path: Path) -> bool:
        try:
            parts = path.relative_to(root).parts
        except ValueError:
            return False
        if not parts:
            return False
        lowered = tuple(part.lower() for part in parts)
        name = lowered[-1]
        if lowered[0] == ".pytest_tmp":
            return True
        if "pytest-runs" in lowered:
            return True
        if name.startswith("pytest-") or name.startswith("pytest_"):
            return True
        if len(lowered) >= 3 and lowered[:2] == ("data", "tmp"):
            return name.startswith("stage0-hotfix-") or name.startswith("stage10-plugin-")
        return False

    def record_walk_error(exc: OSError) -> None:
        nonlocal errors, skipped_generated_test_trees
        path = getattr(exc, "filename", None)
        if path and generated_test_tree(Path(path)):
            skipped_generated_test_trees += 1
            return
        errors += 1
        if path and len(error_paths) < 50:
            error_paths.append(str(path))
        if path and under_raw_spool(Path(path)):
            record_raw_spool_error(Path(path))

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=record_walk_error):
        base = Path(dirpath)
        traversable: list[str] = []
        for dirname in dirnames:
            candidate = base / dirname
            if generated_test_tree(candidate):
                skipped_generated_test_trees += 1
                continue
            try:
                is_junction = bool(
                    getattr(candidate, "is_junction", lambda: False)()
                )
                if candidate.is_symlink() or is_junction:
                    skipped_link_directories += 1
                    if under_raw_spool(candidate):
                        record_raw_spool_error(candidate)
                    continue
                if base == raw_spool_root:
                    raw_spool_batches += 1
                    modified = datetime.fromtimestamp(candidate.stat().st_mtime, tz=timezone.utc)
                    if raw_spool_oldest is None or modified < raw_spool_oldest:
                        raw_spool_oldest = modified
                traversable.append(dirname)
            except OSError:
                errors += 1
                if len(error_paths) < 50:
                    error_paths.append(str(candidate))
                if under_raw_spool(candidate):
                    record_raw_spool_error(candidate)
        dirnames[:] = traversable
        for filename in filenames:
            path = base / filename
            try:
                size = int(path.stat().st_size)
                rel = path.relative_to(root)
            except (OSError, ValueError):
                errors += 1
                if len(error_paths) < 50:
                    error_paths.append(str(path))
                if under_raw_spool(path):
                    record_raw_spool_error(path)
                continue
            files_seen += 1
            sizes["project"] += size
            if under_raw_spool(path):
                raw_spool_bytes += size
            parts = rel.parts
            if not parts:
                continue
            if parts[0] == "data":
                sizes["data"] += size
                if len(parts) > 1:
                    category = parts[1]
                    if category == "raw":
                        sizes["raw"] += size
                        counts["raw_files"] += 1
                    elif category == "raw_archive":
                        sizes["raw_archive"] += size
                        counts["raw_archive_files"] += 1
                    elif category == "processed":
                        sizes["processed"] += size
                        counts["processed_files"] += 1
                        if rel.as_posix() == "data/processed/ad_logs.sqlite":
                            sizes["sqlite"] = size
                    elif category == "reports":
                        sizes["reports"] += size
                        counts["report_files"] += 1
                    elif category == "logs":
                        sizes["logs"] += size
                        counts["log_files"] += 1
                    elif category == "maintenance":
                        sizes["maintenance"] += size
                        counts["maintenance_files"] += 1
                    elif category == "storage_v2_archives":
                        sizes["storage_v2_archives"] += size
            elif parts[0] == "backups":
                sizes["backups"] += size
                counts["backup_files"] += 1
            elif parts[0] == "artifacts":
                sizes["artifacts"] += size
            elif parts[0] == "archive":
                sizes["archive"] += size
            elif parts[0] == ".venv":
                sizes["venv"] += size
            elif len(parts) > 1 and parts[0] == "frontend" and parts[1] == "node_modules":
                sizes["frontend_node_modules"] += size
    if raw_spool_exists:
        try:
            raw_spool_root.relative_to(root)
            is_under_root = True
        except ValueError:
            is_under_root = False
        if not is_under_root:
            for dirpath, dirnames, filenames in os.walk(raw_spool_root, followlinks=False):
                base = Path(dirpath)
                for dirname in dirnames:
                    if base == raw_spool_root:
                        raw_spool_batches += 1
                        try:
                            modified = datetime.fromtimestamp((base / dirname).stat().st_mtime, tz=timezone.utc)
                            if raw_spool_oldest is None or modified < raw_spool_oldest:
                                raw_spool_oldest = modified
                        except OSError:
                            raw_spool_errors += 1
                for filename in filenames:
                    try:
                        raw_spool_bytes += int((base / filename).stat().st_size)
                    except OSError:
                        raw_spool_errors += 1
    raw_spool_complete = raw_spool_exists and raw_spool_errors == 0
    raw_spool = {
        "status": "ok" if raw_spool_complete else ("partial" if raw_spool_exists else "unavailable"),
        "path": str(raw_spool_root),
        "bytes": raw_spool_bytes if raw_spool_exists else None,
        "human": format_bytes(raw_spool_bytes) if raw_spool_exists else None,
        "batch_count": raw_spool_batches if raw_spool_exists else None,
        "oldest_batch_at_utc": _iso(raw_spool_oldest) if raw_spool_oldest else None,
        "timestamp_basis": "direct_batch_directory_mtime_utc",
        "scan": {
            "complete": raw_spool_complete,
            "errors": raw_spool_errors,
            "error_paths": raw_spool_error_paths,
            "follow_symlinks": False,
        },
        "thresholds": {
            "bytes_warning": RAW_BYTES_WARNING,
            "bytes_critical": RAW_BYTES_CRITICAL,
            "batch_count_warning": RAW_BATCH_COUNT_WARNING,
            "oldest_age_warning_seconds": RAW_OLDEST_AGE_WARNING_SECONDS,
            "basis": "existing_raw_size_cleanup_candidate_and_retention_policy_boundaries",
        },
    }
    return {
        "sizes": sizes,
        "counts": counts,
        "raw_spool": raw_spool,
        "scan": {
            "mode": "single_pass",
            "scope": "project_tree",
            "complete_project_tree": errors == 0,
            "roots": [str(root)],
            "files_seen": files_seen,
            "errors": errors,
            "error_paths": error_paths,
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "follow_symlinks": False,
            "skipped_link_directories": skipped_link_directories,
            "skipped_generated_test_trees": skipped_generated_test_trees,
        },
    }


def get_runtime_storage_summary(root: Path = ROOT) -> dict[str, Any]:
    data_dir = root / "data"
    raw = data_dir / "raw"
    raw_archive = data_dir / "raw_archive"
    processed = data_dir / "processed"
    reports = data_dir / "reports"
    logs = data_dir / "logs"
    maintenance = data_dir / "maintenance"
    backups = root / "backups"
    sqlite = processed / "ad_logs.sqlite"
    snapshot = _single_pass_storage_snapshot(root)
    sizes = snapshot["sizes"]
    counts = snapshot["counts"]
    thresholds = {
        "raw_warn_bytes": RAW_BYTES_WARNING,
        "raw_high_bytes": RAW_BYTES_CRITICAL,
        "project_high_bytes": 5 * 1024 * 1024 * 1024,
        "free_disk_warn_percent": 15,
    }
    warnings: list[str] = []
    if sizes["raw"] > thresholds["raw_high_bytes"]:
        warnings.append("data/raw больше 1 ГБ — высокий приоритет обслуживания")
    elif sizes["raw"] > thresholds["raw_warn_bytes"]:
        warnings.append("data/raw больше 500 МБ — требуется плановая архивация")
    if sizes["project"] > thresholds["project_high_bytes"]:
        warnings.append("папка проекта больше 5 ГБ — высокий приоритет storage cleanup")
    if int(snapshot["scan"].get("errors") or 0):
        warnings.append(
            f"Полный снимок хранилища неполон: не удалось прочитать объектов: {snapshot['scan']['errors']}"
        )
    disk = disk_info(root)
    if disk["free_percent"] < thresholds["free_disk_warn_percent"]:
        warnings.append("свободное место на диске меньше 15% — высокий приоритет")
    last_cleanup = read_raw_cleanup_metadata(root)
    raw_spool = snapshot["raw_spool"]
    if raw_spool["status"] == "unavailable":
        warnings.append(f"RAW spool {raw_spool['path']} is unavailable; its size and batch count are unknown.")
    elif raw_spool["status"] == "partial":
        warnings.append("RAW spool scan is incomplete; measured values are lower bounds.")
    return {
        "generated_at_utc": _iso(_now_utc()),
        "paths": {
            "root": str(root),
            "raw": str(raw),
            "raw_archive": str(raw_archive),
            "processed": str(processed),
            "reports": str(reports),
            "logs": str(logs),
            "backups": str(backups),
            "maintenance": str(maintenance),
            "sqlite": str(sqlite),
        },
        "sizes": {k: {"bytes": v, "human": format_bytes(v)} for k, v in sizes.items()},
        "counts": counts,
        "scan": snapshot["scan"],
        "raw_spool": raw_spool,
        "disk": disk,
        "thresholds": {**thresholds, **{f"{k}_human": format_bytes(v) for k, v in thresholds.items() if k.endswith("bytes")}},
        "last_raw_cleanup": last_cleanup,
        "raw_cleanup_hint": "Запустите scripts/maintenance/raw_storage_cleanup.py без --apply для dry-run. --apply переносит файлы в data/raw_archive или архивирует их в zip; SQLite не затрагивается.",
        "warnings": warnings,
    }


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    for index in range(1, 10000):
        candidate = parent / f"{stem}.{index}{suffix}"
        if not candidate.exists():
            return candidate
    raise OSError(f"cannot create unique path for {path}")


def _default_zip_path(archive_dir: Path) -> Path:
    return archive_dir / f"raw_archive_{_now_utc().strftime('%Y%m%d_%H%M%S')}.zip"


def build_raw_cleanup_plan(
    *,
    raw_dir: Path = RAW_DIR,
    archive_dir: Path = RAW_ARCHIVE_DIR,
    older_than_days: int = 7,
    limit: int = 500,
    archive_mode: str = "move",
    zip_path: Path | None = None,
) -> dict[str, Any]:
    archive_mode = (archive_mode or "move").strip().lower()
    if archive_mode not in {"move", "zip"}:
        raise ValueError("archive_mode must be 'move' or 'zip'")
    raw_dir = Path(raw_dir)
    archive_dir = Path(archive_dir)
    cutoff = _now_utc() - timedelta(days=max(0, int(older_than_days)))
    candidate_limit = max(0, int(limit))
    zip_target = Path(zip_path) if zip_path else _default_zip_path(archive_dir)
    candidates: list[dict[str, Any]] = []
    excluded_samples: list[dict[str, Any]] = []
    exclusion_summary: dict[str, int] = {"recent_file": 0, "not_file": 0, "stat_error": 0, "over_limit": 0}
    total_raw_files = 0

    if not raw_dir.exists():
        exclusion_summary["raw_dir_missing"] = 1
    else:
        for item in sorted(raw_dir.rglob("*")):
            if not item.is_file():
                exclusion_summary["not_file"] += 1
                continue
            total_raw_files += 1
            try:
                stat = item.stat()
            except OSError as exc:
                exclusion_summary["stat_error"] += 1
                if len(excluded_samples) < 20:
                    excluded_samples.append({"path": str(item), "reason": "stat_error", "details": str(exc)})
                continue
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            rel = item.relative_to(raw_dir)
            if mtime > cutoff:
                exclusion_summary["recent_file"] += 1
                if len(excluded_samples) < 20:
                    age_days = max(0.0, (_now_utc() - mtime).total_seconds() / 86400)
                    excluded_samples.append({
                        "path": str(item),
                        "relative_path": str(rel),
                        "reason": "recent_file",
                        "details": f"файл моложе порога {older_than_days} дней",
                        "age_days": round(age_days, 2),
                        "modified_utc": _iso(mtime),
                    })
                continue
            if len(candidates) >= candidate_limit:
                exclusion_summary["over_limit"] += 1
                if len(excluded_samples) < 20:
                    excluded_samples.append({"path": str(item), "relative_path": str(rel), "reason": "over_limit", "details": f"лимит кандидатов {candidate_limit}"})
                continue
            target = archive_dir / rel if archive_mode == "move" else zip_target
            candidates.append({
                "path": str(item),
                "relative_path": str(rel),
                "target": str(target),
                "size_bytes": stat.st_size,
                "source_identity": _raw_source_identity(stat),
                "size_human": format_bytes(stat.st_size),
                "modified_utc": _iso(mtime),
                "reason": f"старше {older_than_days} дней",
            })
    total = sum(int(c["size_bytes"]) for c in candidates)
    return {
        "mode": "dry-run",
        "archive_mode": archive_mode,
        "raw_dir": str(raw_dir),
        "archive_dir": str(archive_dir),
        "zip_path": str(zip_target) if archive_mode == "zip" else None,
        "older_than_days": older_than_days,
        "cutoff_utc": _iso(cutoff),
        "limit": candidate_limit,
        "total_raw_files": total_raw_files,
        "candidates": candidates,
        "total_candidates": len(candidates),
        "total_bytes": total,
        "total_human": format_bytes(total),
        "exclusion_summary": {key: value for key, value in exclusion_summary.items() if value},
        "excluded_samples": excluded_samples,
        "candidate_policy": "кандидатами считаются только файлы из data/raw, которые старше порога older_than_days и попали в limit; SQLite, processed, reports и logs не затрагиваются",
        "safety": "по умолчанию файлы не удаляются; --apply переносит в data/raw_archive или упаковывает в zip-архив внутри data/raw_archive",
    }


def _raw_source_identity(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _raw_source_snapshot(src: Path, raw_dir: Path) -> list[int]:
    # Reject symlink components, traversal and non-regular files. Cleanup is for
    # quiescent raw files in operator-owned directories, not active writers.
    absolute = src.absolute()
    if absolute.resolve() != absolute or not absolute.is_relative_to(raw_dir):
        raise ValueError(f"unsafe raw source path: {src}")
    info = src.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"raw source is not a regular file: {src}")
    return _raw_source_identity(info)


def _raw_digest(stream: Any) -> str:
    digest = hashlib.sha256()
    while block := stream.read(1024 * 1024):
        digest.update(block)
    return digest.hexdigest()


def _archive_raw_zip(
    plan: dict[str, Any], destination: Path,
    archived: list[dict[str, Any]], errors: list[dict[str, Any]],
) -> Path:
    raw_dir = Path(plan["raw_dir"]).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    staged: Path | None = None
    stage_identity: tuple[int, int] | None = None
    snapshots: list[tuple[Path, str, list[int], str]] = []
    try:
        # Keep our exclusive temporary file open through validation/publication.
        with tempfile.NamedTemporaryFile(
            mode="w+b", prefix=".raw-archive-", suffix=".tmp",
            dir=destination.parent, delete=False,
        ) as output:
            staged = Path(output.name)
            info = os.fstat(output.fileno())
            stage_identity = (info.st_dev, info.st_ino)
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                names: set[str] = set()
                for item in plan.get("candidates") or []:
                    src = Path(item["path"])
                    identity = _raw_source_snapshot(src, raw_dir)
                    if identity != item.get("source_identity"):
                        raise ValueError(f"raw source changed since planning: {src}")
                    rel = src.absolute().relative_to(raw_dir).as_posix()
                    if rel in names:
                        raise ValueError(f"duplicate raw source: {src}")
                    names.add(rel)
                    digest = hashlib.sha256()
                    with src.open("rb") as source, zf.open(rel, "w", force_zip64=True) as member:
                        if _raw_source_identity(os.fstat(source.fileno())) != identity:
                            raise ValueError(f"raw source changed while opening: {src}")
                        while block := source.read(1024 * 1024):
                            digest.update(block)
                            member.write(block)
                        if _raw_source_identity(os.fstat(source.fileno())) != identity:
                            raise ValueError(f"raw source changed while archiving: {src}")
                    if _raw_source_snapshot(src, raw_dir) != identity:
                        raise ValueError(f"raw source replaced while archiving: {src}")
                    snapshots.append((src, rel, identity, digest.hexdigest()))
            # ZIP close writes the central directory. Read every member to EOF
            # (CRC validation), and compare cryptographic digests of streamed bytes.
            output.flush()
            output.seek(0)
            with zipfile.ZipFile(output, "r") as verified:
                if verified.namelist() != [entry[1] for entry in snapshots]:
                    raise ValueError("raw archive member mismatch")
                for src, rel, identity, digest in snapshots:
                    with verified.open(rel) as member:
                        if _raw_digest(member) != digest:
                            raise ValueError(f"raw archive content mismatch: {src}")
            os.fsync(output.fileno())
            if (staged.lstat().st_dev, staged.lstat().st_ino) != stage_identity:
                raise ValueError("raw archive staging path replaced")
            # link is atomic and never overwrites an existing name, unlike rename
            # on POSIX. Unsupported filesystems fail closed and keep all sources.
            target = destination
            for index in range(10000):
                if index:
                    target = destination.with_name(f"{destination.stem}.{index}{destination.suffix}")
                try:
                    os.link(staged, target)
                    break
                except FileExistsError:
                    continue
            else:
                raise OSError(f"cannot publish unique archive: {destination}")
            # Persist the published name and any newly-created parent directories.
            # Directory fsync unsupported on this platform => no source deletion.
            for directory in (target.parent, *target.parent.parents):
                fd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            if (target.lstat().st_dev, target.lstat().st_ino) != stage_identity:
                raise ValueError("raw archive publication path replaced")
            for src, rel, identity, digest in snapshots:
                try:
                    if _raw_source_snapshot(src, raw_dir) != identity:
                        raise ValueError("raw source changed after archiving")
                    with src.open("rb") as source:
                        if _raw_digest(source) != digest:
                            raise ValueError("raw source content changed after archiving")
                    if _raw_source_snapshot(src, raw_dir) != identity:
                        raise ValueError("raw source changed before removal")
                    src.unlink()
                    archived.append({"from": str(src), "zip": str(target),
                                     "archive_name": rel, "size_bytes": identity[2]})
                except (OSError, ValueError) as exc:
                    errors.append({"path": str(src), "error": str(exc)})
            return target
    finally:
        # Never clean up a destination or a temporary name we no longer own.
        if staged is not None:
            try:
                info = staged.lstat()
                if (info.st_dev, info.st_ino) == stage_identity:
                    staged.unlink()
            except OSError:
                pass


def apply_raw_cleanup_plan(plan: dict[str, Any], *, apply: bool = False, write_metadata: bool = True) -> dict[str, Any]:
    moved: list[dict[str, Any]] = []
    archived: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    archive_mode = str(plan.get("archive_mode") or "move")
    result_mode = "apply" if apply else "dry-run"
    result: dict[str, Any] = {**plan, "mode": result_mode, "moved": moved, "archived": archived, "errors": errors}
    root = _infer_root_from_raw_dir(Path(str(plan.get("raw_dir") or RAW_DIR)))

    if not apply:
        if write_metadata:
            _write_raw_cleanup_metadata(root, result)
        return result

    if archive_mode == "zip":
        zip_path = Path(str(plan.get("zip_path") or _default_zip_path(Path(str(plan.get("archive_dir") or RAW_ARCHIVE_DIR)))))
        try:
            zip_path = _archive_raw_zip(plan, zip_path, archived, errors)
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
            errors.append({"path": str(zip_path), "error": str(exc)})
        result["zip_path"] = str(zip_path)
    else:
        for item in plan.get("candidates") or []:
            src = Path(item["path"])
            dst = _unique_path(Path(item["target"]))
            try:
                if not src.exists() or not src.is_file():
                    errors.append({"path": str(src), "error": "source file missing"})
                    continue
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(src), str(dst))
                moved.append({"from": str(src), "to": str(dst), "size_bytes": item.get("size_bytes")})
            except OSError as exc:
                errors.append({"path": str(src), "error": str(exc)})

    if write_metadata:
        _write_raw_cleanup_metadata(root, result)
    return result
