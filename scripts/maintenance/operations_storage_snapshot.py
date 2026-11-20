"""Create one read-only, deduplicated storage footprint snapshot for Operations."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.sli.storage.operations_storage import SNAPSHOT_PATH, SNAPSHOT_SCHEMA
from server.sli.core.paths import ROOT
from server.sli.ops.postgres_operations import get_postgres_operations_status
from server.sli.storage.runtime_storage import disk_info, format_bytes, get_runtime_storage_summary

DEFAULT_EXTERNAL_ARCHIVE = ROOT.parent / f"{ROOT.name}_obsolete"
DEFAULT_EVIDENCE_ROOT = Path(r"C:\SLI")
DEFAULT_CLICKHOUSE_CONTAINER = "sli-warm-tier-step1"
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tree_size(path: Path) -> dict[str, Any]:
    started = time.perf_counter()
    total = 0
    files = 0
    errors = 0

    def on_error(_: OSError) -> None:
        nonlocal errors
        errors += 1

    if not path.exists():
        return {"status": "missing", "path": str(path), "bytes": None, "human": None, "files": 0, "errors": 0}
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False, onerror=on_error):
        base = Path(dirpath)
        dirnames[:] = [name for name in dirnames if not (base / name).is_symlink()]
        for name in filenames:
            try:
                total += int((base / name).stat().st_size)
                files += 1
            except OSError:
                errors += 1
    return {
        "status": "ok" if errors == 0 else "partial",
        "path": str(path),
        "bytes": total,
        "human": format_bytes(total),
        "files": files,
        "errors": errors,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "method": "single_pass_file_size_sum",
    }


def _docker(args: list[str], *, timeout: int = 60) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"docker_{args[0]}_failed:{result.stderr.strip()[-500:]}")
    return result.stdout.strip()


def _clickhouse(container: str) -> dict[str, Any]:
    if not CONTAINER_RE.fullmatch(container):
        raise ValueError("invalid_clickhouse_container")
    inspect = json.loads(_docker(["inspect", container]))[0]
    if not bool(((inspect.get("State") or {}).get("Running"))):
        raise RuntimeError("clickhouse_container_not_running")
    volume_bytes = int(_docker(["exec", container, "du", "-sx", "-B1", "/var/lib/clickhouse"]).split()[0])
    query = (
        "select database, sum(bytes_on_disk) bytes from system.parts "
        "where active group by database order by bytes desc format JSONEachRow"
    )
    rows_text = _docker(["exec", container, "clickhouse-client", "--readonly", "2", "--query", query])
    databases = [json.loads(line) for line in rows_text.splitlines() if line.strip()]
    logical_bytes = sum(int(row.get("bytes") or 0) for row in databases)
    mounts = inspect.get("Mounts") or []
    data_mount = next((item for item in mounts if item.get("Destination") == "/var/lib/clickhouse"), {})
    return {
        "status": "ok",
        "container": container,
        "image": ((inspect.get("Config") or {}).get("Image")),
        "volume_name": data_mount.get("Name"),
        "volume_bytes": volume_bytes,
        "volume_human": format_bytes(volume_bytes),
        "active_parts_bytes": logical_bytes,
        "active_parts_human": format_bytes(logical_bytes),
        "databases": [
            {"database": str(row.get("database")), "bytes": int(row.get("bytes") or 0), "human": format_bytes(int(row.get("bytes") or 0))}
            for row in databases
        ],
        "method": "docker_exec_du_and_readonly_system_parts",
    }


def _image_size(image: str) -> dict[str, Any]:
    try:
        size = int(_docker(["image", "inspect", image, "--format", "{{.Size}}"], timeout=30))
        return {"image": image, "status": "ok", "bytes": size, "human": format_bytes(size)}
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        return {"image": image, "status": "unavailable", "bytes": None, "human": None, "error_type": type(exc).__name__}


def _component(
    *,
    key: str,
    label: str,
    bytes_value: int | None,
    path: str | None,
    method: str,
    included: bool,
    parent: str | None = None,
    status: str = "ok",
    note: str | None = None,
) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "status": status,
        "bytes": bytes_value,
        "human": format_bytes(bytes_value) if bytes_value is not None else None,
        "path": path,
        "method": method,
        "included_in_accounted_total": included,
        "parent": parent,
        "note": note,
    }


def build_snapshot(
    *,
    external_archive: Path = DEFAULT_EXTERNAL_ARCHIVE,
    evidence_root: Path = DEFAULT_EVIDENCE_ROOT,
    clickhouse_container: str = DEFAULT_CLICKHOUSE_CONTAINER,
    include_docker: bool = True,
    platform_deps: Path | None = None,
    postgres_data: Path | None = None,
    postgres_bin: Path | None = None,
    sli_data_dir: Path | None = None,
    pnpm_store_dir: Path | None = None,
    clickhouse_history_container: str | None = None,
) -> dict[str, Any]:
    if "ADLOG_PG_DSN" not in os.environ:
        try:
            from server.sli.ops.worker_supervisor_secrets import (
                load_supervisor_environment,
                strip_http_forbidden_environment,
            )
            load_supervisor_environment(override_existing=True)
            strip_http_forbidden_environment()
        except Exception:
            pass

    generated_at = datetime.now(timezone.utc)
    project = get_runtime_storage_summary(ROOT)
    sizes = project.get("sizes") or {}
    raw_spool = dict(project.get("raw_spool") or {})
    oldest_raw = raw_spool.get("oldest_batch_at_utc")
    oldest_age: int | None = None
    if oldest_raw:
        try:
            parsed_oldest = datetime.fromisoformat(str(oldest_raw).replace("Z", "+00:00"))
            if parsed_oldest.tzinfo is None:
                parsed_oldest = parsed_oldest.replace(tzinfo=timezone.utc)
            oldest_age = max(0, int((generated_at - parsed_oldest.astimezone(timezone.utc)).total_seconds()))
        except ValueError:
            raw_spool["status"] = "partial"
            raw_spool.setdefault("scan", {})["complete"] = False
    raw_spool["oldest_batch_age_seconds"] = oldest_age
    external = _tree_size(external_archive)
    evidence = _tree_size(evidence_root)
    postgres = get_postgres_operations_status(table_limit=0)
    pg_database = postgres.get("database") or {}
    pg_bytes = int(pg_database.get("database_bytes") or 0) if postgres.get("available") else None
    warnings: list[str] = []
    raw_status = raw_spool.get("status")
    raw_scan = raw_spool.get("scan") or {}
    raw_thresholds = raw_spool.get("thresholds") or {}
    if raw_status == "unavailable":
        warnings.append("RAW spool is unavailable; bytes, batch count and oldest age are unknown.")
    elif raw_status == "partial" or raw_scan.get("complete") is not True:
        warnings.append("RAW spool scan is incomplete; measured bytes and batch count are lower bounds.")
    if raw_status in {"ok", "partial"}:
        raw_bytes = raw_spool.get("bytes")
        raw_batches = raw_spool.get("batch_count")
        if isinstance(raw_bytes, int) and raw_bytes >= int(raw_thresholds.get("bytes_critical") or 0):
            warnings.append("RAW spool bytes exceed the explicit critical threshold.")
        elif isinstance(raw_bytes, int) and raw_bytes >= int(raw_thresholds.get("bytes_warning") or 0):
            warnings.append("RAW spool bytes exceed the explicit warning threshold.")
        if isinstance(raw_batches, int) and raw_batches >= int(raw_thresholds.get("batch_count_warning") or 0):
            warnings.append("RAW spool batch count exceeds the explicit warning threshold.")
        if isinstance(oldest_age, int) and oldest_age >= int(raw_thresholds.get("oldest_age_warning_seconds") or 0):
            warnings.append("Oldest RAW spool batch exceeds the explicit age warning threshold; this is not cleanup authorization.")
    try:
        clickhouse = _clickhouse(clickhouse_container) if include_docker else {"status": "skipped"}
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        clickhouse = {"status": "unavailable", "error_type": type(exc).__name__}
        warnings.append("ClickHouse physical footprint is unavailable.")

    clickhouse_history = None
    if include_docker and clickhouse_history_container and clickhouse_history_container != clickhouse_container:
        try:
            clickhouse_history = _clickhouse(clickhouse_history_container)
        except Exception as exc:  # Never expose Docker output or credentials.
            clickhouse_history = {"status": "unavailable", "error_type": type(exc).__name__}
            warnings.append("ClickHouse history physical footprint is unavailable; accounting is incomplete.")

    def project_bytes(key: str) -> int:
        return int(((sizes.get(key) or {}).get("bytes")) or 0)

    components = [
        _component(key="project_root", label="Каталог проекта", bytes_value=project_bytes("project"), path=str(ROOT), method="single_pass_file_size_sum", included=True),
        _component(key="project_data", label="Рабочие данные проекта", bytes_value=project_bytes("data"), path=str(ROOT / "data"), method="project_scan_subtotal", included=False, parent="project_root"),
        _component(key="project_raw", label="Текущие RAW-файлы", bytes_value=project_bytes("raw"), path=str(ROOT / "data" / "raw"), method="project_scan_subtotal", included=False, parent="project_data"),
        _component(key="project_raw_archive", label="Архив RAW-файлов", bytes_value=project_bytes("raw_archive"), path=str(ROOT / "data" / "raw_archive"), method="project_scan_subtotal", included=False, parent="project_data"),
        _component(key="storage_v2_archive", label="Архив Storage V2", bytes_value=project_bytes("storage_v2_archives"), path=str(ROOT / "data" / "storage_v2_archives"), method="project_scan_subtotal", included=False, parent="project_data"),
        _component(key="project_processed", label="Обработанные локальные данные", bytes_value=project_bytes("processed"), path=str(ROOT / "data" / "processed"), method="project_scan_subtotal", included=False, parent="project_data"),
        _component(key="project_reports", label="Сформированные отчёты", bytes_value=project_bytes("reports"), path=str(ROOT / "data" / "reports"), method="project_scan_subtotal", included=False, parent="project_data"),
        _component(key="project_logs", label="Локальные журналы SLI", bytes_value=project_bytes("logs"), path=str(ROOT / "data" / "logs"), method="project_scan_subtotal", included=False, parent="project_data"),
        _component(key="project_maintenance", label="Maintenance-данные", bytes_value=project_bytes("maintenance"), path=str(ROOT / "data" / "maintenance"), method="project_scan_subtotal", included=False, parent="project_data"),
        _component(key="project_backups", label="Резервные копии внутри проекта", bytes_value=project_bytes("backups"), path=str(ROOT / "backups"), method="project_scan_subtotal", included=False, parent="project_root"),
        _component(key="project_artifacts", label="Артефакты и evidence", bytes_value=project_bytes("artifacts"), path=str(ROOT / "artifacts"), method="project_scan_subtotal", included=False, parent="project_root"),
        _component(key="project_archive", label="Внутренний архив исходников", bytes_value=project_bytes("archive"), path=str(ROOT / "archive"), method="project_scan_subtotal", included=False, parent="project_root"),
        _component(key="project_venv", label="Python-окружение", bytes_value=project_bytes("venv"), path=str(ROOT / ".venv"), method="project_scan_subtotal", included=False, parent="project_root"),
        _component(key="frontend_dependencies", label="Frontend dependencies", bytes_value=project_bytes("frontend_node_modules"), path=str(ROOT / "frontend" / "node_modules"), method="project_scan_subtotal", included=False, parent="project_root"),
        _component(key="external_archive", label="Внешний архив проекта", bytes_value=external.get("bytes"), path=str(external_archive), method=str(external.get("method") or "not_measured"), included=external.get("bytes") is not None, status=str(external.get("status")), note="Восстанавливаемое obsolete-дерево вне каталога проекта."),
        _component(key="evidence_root", label="Сырьё и evidence C:\\SLI", bytes_value=evidence.get("bytes"), path=str(evidence_root), method=str(evidence.get("method") or "not_measured"), included=evidence.get("bytes") is not None, status=str(evidence.get("status"))),
    ]

    has_platform_deps = False
    if platform_deps and platform_deps.is_dir():
        deps_stat = _tree_size(platform_deps)
        if deps_stat.get("status") != "missing":
            has_platform_deps = True
            components.append(
                _component(
                    key="platform_dependencies",
                    label="Внешние зависимости и среды (SLI_platform_deps)",
                    bytes_value=deps_stat.get("bytes"),
                    path=str(platform_deps),
                    method="single_pass_file_size_sum",
                    included=deps_stat.get("bytes") is not None,
                    status=str(deps_stat.get("status")),
                    note="Внешние среды выполнения (Docker, Python, Playwright, дистрибутивы).",
                )
            )
            deps_subdirs = [
                ("deps_docker_data", "Образ диска Docker Desktop WSL (ext4.vhdx)", platform_deps / "docker-data"),
                ("deps_docker_desktop", "Приложение Docker Desktop", platform_deps / "DockerDesktop"),
                ("deps_postgres_18", "Бинарники PostgreSQL 18 (deps)", platform_deps / "postgresql-18"),
                ("deps_pgadmin", "Инструменты pgAdmin 4", platform_deps / "pgAdmin4"),
                ("deps_playwright", "Браузеры Playwright (E2E тесты)", platform_deps / "playwright-browsers"),
                ("deps_installers", "Инсталляторы и дистрибутивы", platform_deps / "installers"),
                ("deps_python", "Базовый дистрибутив Python 3.14", platform_deps / "python"),
                ("deps_npm_cache", "Кэш пакетов npm", platform_deps / "npm-cache"),
            ]
            for sub_key, sub_label, sub_path in deps_subdirs:
                if sub_path.exists():
                    sub_stat = _tree_size(sub_path)
                    components.append(
                        _component(
                            key=sub_key,
                            label=sub_label,
                            bytes_value=sub_stat.get("bytes"),
                            path=str(sub_path),
                            method="single_pass_file_size_sum",
                            included=False,
                            parent="platform_dependencies",
                            status=str(sub_stat.get("status")),
                            note="Уже входит в состав внешних зависимостей платформы.",
                        )
                    )

    if postgres_data and postgres_data.is_dir():
        pg_data_stat = _tree_size(postgres_data)
        if pg_data_stat.get("status") != "missing":
            components.append(
                _component(
                    key="postgres_physical_cluster",
                    label="Физический кластер PostgreSQL",
                    bytes_value=pg_data_stat.get("bytes"),
                    path=str(postgres_data),
                    method="single_pass_file_size_sum",
                    included=pg_data_stat.get("bytes") is not None,
                    status=str(pg_data_stat.get("status")),
                    note="Фактическое место на диске кластера PostgreSQL.",
                )
            )
            components.append(
                _component(
                    key="postgres_database",
                    label="Логическая база данных sli_local",
                    bytes_value=pg_bytes,
                    path=None,
                    method="pg_database_size_current_database",
                    included=False,
                    parent="postgres_physical_cluster",
                    status="ok" if pg_bytes is not None else "unavailable",
                    note="Логический размер базы данных; уже входит в физический кластер.",
                )
            )
    else:
        components.append(
            _component(
                key="postgres_database",
                label="PostgreSQL database",
                bytes_value=pg_bytes,
                path=None,
                method="pg_database_size_current_database",
                included=pg_bytes is not None,
                status="ok" if pg_bytes is not None else "unavailable",
                note="Логический размер database используется как proxy; физический data directory не измерен.",
            )
        )

    if postgres_bin and postgres_bin.is_dir():
        pg_bin_stat = _tree_size(postgres_bin)
        if pg_bin_stat.get("status") != "missing":
            components.append(
                _component(
                    key="postgres_server_install",
                    label="Установка сервера PostgreSQL 18",
                    bytes_value=pg_bin_stat.get("bytes"),
                    path=str(postgres_bin),
                    method="single_pass_file_size_sum",
                    included=pg_bin_stat.get("bytes") is not None,
                    status=str(pg_bin_stat.get("status")),
                    note="Каталог установки PostgreSQL 18.",
                )
            )

    if sli_data_dir and sli_data_dir.is_dir():
        sli_data_stat = _tree_size(sli_data_dir)
        if sli_data_stat.get("status") != "missing":
            components.append(
                _component(
                    key="sli_data_root",
                    label="Рабочие данные и логи (sli_data)",
                    bytes_value=sli_data_stat.get("bytes"),
                    path=str(sli_data_dir),
                    method="single_pass_file_size_sum",
                    included=sli_data_stat.get("bytes") is not None,
                    status=str(sli_data_stat.get("status")),
                    note="Локальное хранилище логов, DPAPI и промежуточных данных.",
                )
            )
            for sub_name, sub_label in [("runtime", "Данные рантайма и DPAPI"), ("logs", "Логи веб-сервера и служб"), ("reports", "Сформированные отчёты")]:
                sub_p = sli_data_dir / sub_name
                if sub_p.exists():
                    sub_stat = _tree_size(sub_p)
                    components.append(
                        _component(
                            key=f"sli_data_{sub_name}",
                            label=sub_label,
                            bytes_value=sub_stat.get("bytes"),
                            path=str(sub_p),
                            method="single_pass_file_size_sum",
                            included=False,
                            parent="sli_data_root",
                            status=str(sub_stat.get("status")),
                        )
                    )

    if pnpm_store_dir and pnpm_store_dir.is_dir():
        pnpm_stat = _tree_size(pnpm_store_dir)
        if pnpm_stat.get("status") != "missing":
            components.append(
                _component(
                    key="pnpm_store",
                    label="Глобальное хранилище пакетов pnpm",
                    bytes_value=pnpm_stat.get("bytes"),
                    path=str(pnpm_store_dir),
                    method="single_pass_file_size_sum",
                    included=pnpm_stat.get("bytes") is not None,
                    status=str(pnpm_stat.get("status")),
                    note="Общий кэш пакетов frontend-зависимостей.",
                )
            )

    ch_parent = "deps_docker_data" if has_platform_deps else None
    ch_included = not has_platform_deps and clickhouse.get("volume_bytes") is not None
    components.append(
        _component(
            key="clickhouse_volume",
            label="ClickHouse data volume (warm)",
            bytes_value=clickhouse.get("volume_bytes"),
            path=clickhouse.get("volume_name"),
            method=str(clickhouse.get("method") or "not_measured"),
            included=ch_included,
            parent=ch_parent,
            status=str(clickhouse.get("status")),
            note="Физический объём /var/lib/clickhouse, включая system logs; входит в образ Docker WSL." if has_platform_deps else "Физический объём /var/lib/clickhouse, включая system logs.",
        )
    )
    components.append(
        _component(
            key="clickhouse_active_parts",
            label="ClickHouse active parts (warm)",
            bytes_value=clickhouse.get("active_parts_bytes"),
            path=None,
            method="readonly_system_parts",
            included=False,
            parent="clickhouse_volume",
            status=str(clickhouse.get("status")),
            note="Логическая детализация активных частей; уже входит в ClickHouse volume.",
        )
    )

    if clickhouse_history is not None:
        ch_hist_included = not has_platform_deps and clickhouse_history.get("volume_bytes") is not None
        components.append(
            _component(
                key="clickhouse_volume_history",
                label="ClickHouse data volume (facts history)",
                bytes_value=clickhouse_history.get("volume_bytes"),
                path=clickhouse_history.get("volume_name"),
                method=str(clickhouse_history.get("method") or "not_measured"),
                included=ch_hist_included,
                parent=ch_parent,
                status=str(clickhouse_history.get("status")),
                note="Физический объём фактов sli-history; входит в образ Docker WSL." if has_platform_deps else None,
            )
        )
        components.append(
            _component(
                key="clickhouse_active_parts_history",
                label="ClickHouse active parts (history)",
                bytes_value=clickhouse_history.get("active_parts_bytes"),
                path=None,
                method="readonly_system_parts",
                included=False,
                parent="clickhouse_volume_history",
                status=str(clickhouse_history.get("status")),
            )
        )

    if pg_bytes is None and (not postgres_data or not postgres_data.is_dir()):
        warnings.append("PostgreSQL database footprint is unavailable.")
    if external.get("status") == "partial" or evidence.get("status") == "partial" or not (project.get("scan") or {}).get("complete_project_tree"):
        warnings.append("At least one filesystem tree scan is incomplete.")

    included = [item for item in components if item["included_in_accounted_total"] and item.get("bytes") is not None]
    accounted = sum(int(item["bytes"]) for item in included)
    physical_known = sum(int(item["bytes"]) for item in included if item["key"] != "postgres_database")
    images = []
    if include_docker:
        images = [_image_size(name) for name in ("clickhouse/clickhouse-server:25.8", "postgres:18-alpine", "postgres:16-alpine")]
    for database in clickhouse.get("databases") or []:
        components.append(
            _component(
                key=f"clickhouse_database:{database.get('database')}",
                label=f"ClickHouse database {database.get('database')}",
                bytes_value=int(database.get("bytes") or 0),
                path=None,
                method="readonly_system_parts",
                included=False,
                parent="clickhouse_active_parts",
                status="ok",
                note="Active parts detail; already included in ClickHouse volume.",
            )
        )
    if clickhouse_history and clickhouse_history.get("status") == "ok":
        for database in clickhouse_history.get("databases") or []:
            components.append(
                _component(
                    key=f"clickhouse_history_database:{database.get('database')}",
                    label=f"ClickHouse history database {database.get('database')}",
                    bytes_value=int(database.get("bytes") or 0),
                    path=None,
                    method="readonly_system_parts",
                    included=False,
                    parent="clickhouse_active_parts_history",
                    status="ok",
                )
            )
    for image in images:
        components.append(
            _component(
                key=f"docker_image:{image.get('image')}",
                label=f"Docker image {image.get('image')}",
                bytes_value=image.get("bytes"),
                path=str(image.get("image")),
                method="docker_image_inspect_raw_size",
                included=False,
                status=str(image.get("status")),
                note="Excluded from total because image layers may be shared.",
            )
        )
    image_raw_sum = sum(int(item.get("bytes") or 0) for item in images)
    disk = disk_info(ROOT)
    return {
        "schema": SNAPSHOT_SCHEMA,
        "generated_at_utc": generated_at.isoformat(),
        "status": "partial" if warnings else "ok",
        "components": components,
        "totals": {
            "accounted_bytes": accounted,
            "accounted_human": format_bytes(accounted),
            "known_physical_bytes": physical_known,
            "known_physical_human": format_bytes(physical_known),
            "postgres_proxy_included": pg_bytes is not None and (not postgres_data or not postgres_data.is_dir()),
            "accounting_quality": "partial" if (clickhouse_history or {}).get("status") == "unavailable" else "measured" if (postgres_data and postgres_data.is_dir()) else ("estimated" if pg_bytes is not None else "partial"),
            "docker_images_raw_sum_bytes": image_raw_sum,
            "docker_images_raw_sum_human": format_bytes(image_raw_sum),
            "docker_images_included": False,
        },
        "disk": disk,
        "postgres": {"status": postgres.get("status"), "database": pg_database},
        "clickhouse": clickhouse,
        "external_archive": external,
        "evidence_root": evidence,
        "docker_images": images,
        "project_scan": project.get("scan"),
        "raw_spool": raw_spool,
        "warnings": warnings,
        "read_only": True,
        "accounting_notes": [
            "Nested project rows and ClickHouse active parts are excluded from the total.",
            "PostgreSQL contributes physical cluster or pg_database_size.",
            "Docker image raw sizes are excluded because shared layers cannot be safely attributed by summation.",
        ],
    }


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    def encode(value: object) -> str:
        if isinstance(value, datetime):
            current = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
            return current.astimezone(timezone.utc).isoformat()
        raise TypeError(f"unsupported_snapshot_value:{type(value).__name__}")

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=encode) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> int:
    default_platform_deps = Path(r"D:\SLI_platform_deps") if Path(r"D:\SLI_platform_deps").is_dir() else None
    default_pg_data = Path(r"D:\postgresql-data-official") if Path(r"D:\postgresql-data-official").is_dir() else None
    default_pg_bin = Path(r"D:\PostgreSQL") if Path(r"D:\PostgreSQL").is_dir() else None
    default_sli_data = (ROOT.parent / "sli_data") if (ROOT.parent / "sli_data").is_dir() else None
    default_pnpm_store = (ROOT.parent / ".pnpm-store") if (ROOT.parent / ".pnpm-store").is_dir() else None

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=SNAPSHOT_PATH)
    parser.add_argument("--external-archive", type=Path, default=DEFAULT_EXTERNAL_ARCHIVE)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--clickhouse-container", default=DEFAULT_CLICKHOUSE_CONTAINER)
    parser.add_argument("--clickhouse-history-container", default="sli-history")
    parser.add_argument("--platform-deps", type=Path, default=default_platform_deps)
    parser.add_argument("--postgres-data", type=Path, default=default_pg_data)
    parser.add_argument("--postgres-bin", type=Path, default=default_pg_bin)
    parser.add_argument("--sli-data", type=Path, default=default_sli_data)
    parser.add_argument("--pnpm-store", type=Path, default=default_pnpm_store)
    parser.add_argument("--skip-docker", action="store_true")
    args = parser.parse_args()
    payload = build_snapshot(
        external_archive=args.external_archive,
        evidence_root=args.evidence_root,
        clickhouse_container=args.clickhouse_container,
        clickhouse_history_container=args.clickhouse_history_container,
        include_docker=not args.skip_docker,
        platform_deps=args.platform_deps,
        postgres_data=args.postgres_data,
        postgres_bin=args.postgres_bin,
        sli_data_dir=args.sli_data,
        pnpm_store_dir=args.pnpm_store,
    )
    _write_atomic(args.output, payload)
    print(json.dumps({"status": payload["status"], "output": str(args.output), "totals": payload["totals"], "warnings": payload["warnings"]}, ensure_ascii=False))
    return 0 if payload["status"] in {"ok", "partial"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
