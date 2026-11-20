from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from server.sli.core.paths import CONFIG_DIR, DATA_DIR, LOG_DIR, REPORTS_DIR
from server.sli.core.secret_files import secret_value

CONFIG_PATH = CONFIG_DIR / "adlog_config.yaml"


def _parse_scalar(value: str) -> Any:
    raw = value.strip().strip('"').strip("'")
    if raw.lower() in {"true", "yes", "on"}:
        return True
    if raw.lower() in {"false", "no", "off"}:
        return False
    if raw.lower() in {"none", "null", ""}:
        return None
    try:
        return int(raw)
    except ValueError:
        return raw


def _read_simple_yaml(path: Path) -> dict[str, Any]:
    """Read a deliberately small YAML subset: section: / key: value.

    The project avoids adding PyYAML only for configuration. This parser is enough
    for the generated config/adlog_config.example.yaml and returns an empty dict
    for missing files. It does not execute tags, anchors, includes or templates.
    """
    if not path.is_file():
        return {}
    root: dict[str, Any] = {}
    current: dict[str, Any] | None = None
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        stripped = line.split("#", 1)[0].rstrip()
        if not stripped:
            continue
        if not line.startswith((" ", "\t")) and stripped.endswith(":"):
            key = stripped[:-1].strip()
            current = root.setdefault(key, {})
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        target = current if line.startswith((" ", "\t")) and current is not None else root
        target[key.strip()] = _parse_scalar(value)
    return root



_INVALID_DSN_PLACEHOLDER = "<invalid PostgreSQL DSN>"


def _parse_conninfo(value: str) -> str:
    """Parse and canonically rebuild libpq conninfo with any password masked."""
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    fields = conninfo_to_dict(value)
    for secret_key in ("password", "sslpassword"):
        if secret_key in fields:
            fields[secret_key] = "***"
    return make_conninfo(**fields)


def redact_dsn(value: str | None) -> str | None:
    """Return a DSN safe for logs/reports by masking passwords.

    Examples:
    - postgresql://example_user:example_password@db.example.invalid/db -> postgresql://example_user:***@db.example.invalid/db
    - host=... password=secret -> host=... password=***
    """
    if not value:
        return None
    try:
        return _parse_conninfo(str(value))
    except Exception:  # noqa: BLE001 - redaction must fail closed for every parser failure
        # Redaction is a security boundary: malformed input, a missing parser,
        # or a future unsupported conninfo form must never fall back to the
        # original credential-bearing text.
        return _INVALID_DSN_PLACEHOLDER


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_optional_int(name: str, configured: Any = None) -> int | None:
    """Return an explicitly configured integer without choosing a default."""
    value = os.getenv(name)
    if value in (None, ""):
        value = configured
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _env_optional_bool(name: str, configured: Any = None) -> bool | None:
    """Return an explicitly configured boolean without choosing a default."""
    value = os.getenv(name)
    if value in (None, ""):
        value = configured
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    return value.lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AdLogConfig:
    reports_dir: str
    log_dir: str
    db_backend: str = "postgres"
    postgres_dsn: str | None = None
    postgres_connect_timeout_seconds: int = 3
    postgres_statement_timeout_ms: int = 900000
    postgres_lock_timeout_ms: int = 3000
    backup_dir: str = "data/backups"
    health_lag_warn_minutes: int = 30
    health_lag_high_minutes: int = 120
    dashboard_refresh_seconds: int = 5
    collector_interval_seconds: int = 600
    retention_apply_by_default: bool = False
    storage_capacity_profile: str | None = None
    storage_capacity_profile_overrides: tuple[str, ...] = ()
    storage_policy_override_fields: tuple[str, ...] = ()
    raw_retention_days: int | None = None
    raw_archive_enabled: bool = True
    raw_archive_compress: bool = True
    db_retention_days: int | None = None
    warm_retention_days: int | None = None
    backup_retention_days: int | None = None
    log_retention_days: int | None = None
    artifact_retention_days: int | None = None
    post_collection_retention_days: int | None = None
    archive_auto_delete_enabled: bool | None = None
    min_free_disk_percent: int = 15
    stop_collection_if_free_disk_percent_below: int = 10
    stop_collection_if_free_disk_bytes_below: int = 10 * 1024**3
    critical_free_disk_percent: int = 5
    channel_fairness_enabled: bool = True
    channel_fairness_stale_minutes: int = 360
    channel_fairness_max_events: int = 100
    channel_fairness_timeout_seconds: int = 120
    ai_provider: str = "openai_api"
    ai_model: str = "gpt-5.5"
    ai_execute_enabled: bool = False
    ai_timeout_seconds: int = 60
    http_max_connections: int = 64
    tls_handshake_timeout_seconds: int = 30

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        dsn = data.get("postgres_dsn")
        data["postgres_dsn_present"] = bool(dsn)
        data["postgres_dsn"] = redact_dsn(dsn)
        return data


def require_postgres_runtime(config: AdLogConfig | None = None) -> AdLogConfig:
    """Validate the only supported production runtime before any DB access."""
    resolved = config or load_config()
    backend = str(resolved.db_backend or "").strip().lower()
    if backend != "postgres":
        raise RuntimeError(f"PostgreSQL is the only supported runtime backend; configured backend={backend or 'missing'}")
    if not str(resolved.postgres_dsn or "").strip():
        raise RuntimeError("PostgreSQL runtime requires a non-empty ADLOG_PG_DSN/postgres_dsn")
    return resolved


def load_config(path: Path = CONFIG_PATH) -> AdLogConfig:
    payload = _read_simple_yaml(path)
    storage = payload.get("storage") or {}
    database = payload.get("database") or {}
    retention = payload.get("retention") or {}
    health = payload.get("health") or {}
    ui = payload.get("ui") or {}
    collector = payload.get("collector") or {}
    backup = payload.get("backup") or {}
    ai = payload.get("ai") or {}
    autocollection = payload.get("autocollection") or {}
    http = payload.get("http") or {}
    profile_override_text = str(
        os.getenv("ADLOG_STORAGE_CAPACITY_PROFILE_OVERRIDES")
        or retention.get("storage_capacity_profile_overrides")
        or ""
    )
    profile_overrides = tuple(
        field.strip() for field in profile_override_text.split(",") if field.strip()
    )
    postgres_dsn = secret_value("ADLOG_PG_DSN") or database.get("postgres_dsn") or None
    postgres_password = secret_value("ADLOG_PG_PASSWORD")
    if postgres_password is not None:
        from psycopg import ProgrammingError
        from psycopg.conninfo import make_conninfo

        # Keep the password in memory only, never in os.environ or child argv.
        try:
            postgres_dsn = make_conninfo(postgres_dsn or "", password=postgres_password)
        except (ProgrammingError, ValueError):
            raise ValueError("invalid PostgreSQL connection configuration") from None
    return AdLogConfig(
        db_backend=str(os.getenv("ADLOG_DB_BACKEND") or database.get("backend") or "postgres").lower(),
        postgres_dsn=postgres_dsn,
        postgres_connect_timeout_seconds=_env_int("ADLOG_PG_CONNECT_TIMEOUT_SECONDS", int(database.get("postgres_connect_timeout_seconds") or 3)),
        postgres_statement_timeout_ms=_env_int("ADLOG_PG_STATEMENT_TIMEOUT_MS", int(database.get("postgres_statement_timeout_ms") or 900000)),
        postgres_lock_timeout_ms=_env_int("ADLOG_PG_LOCK_TIMEOUT_MS", int(database.get("postgres_lock_timeout_ms") or 3000)),
        reports_dir=str(storage.get("reports_dir") or os.getenv("ADLOG_REPORTS_DIR") or REPORTS_DIR),
        log_dir=str(storage.get("log_dir") or os.getenv("ADLOG_LOG_DIR") or LOG_DIR),
        backup_dir=str(backup.get("dir") or os.getenv("ADLOG_BACKUP_DIR") or DATA_DIR / "backups"),
        health_lag_warn_minutes=_env_int("ADLOG_HEALTH_LAG_WARN_MINUTES", int(health.get("lag_warn_minutes") or 30)),
        health_lag_high_minutes=_env_int("ADLOG_HEALTH_LAG_HIGH_MINUTES", int(health.get("lag_high_minutes") or 120)),
        dashboard_refresh_seconds=_env_int("ADLOG_DASHBOARD_REFRESH_SECONDS", int(ui.get("dashboard_refresh_seconds") or 5)),
        collector_interval_seconds=_env_int("ADLOG_COLLECTOR_INTERVAL_SECONDS", int(collector.get("interval_seconds") or 600)),
        retention_apply_by_default=_env_bool("ADLOG_RETENTION_APPLY_BY_DEFAULT", bool(retention.get("apply_by_default") or False)),
        storage_capacity_profile=(
            os.getenv("ADLOG_STORAGE_CAPACITY_PROFILE")
            or retention.get("storage_capacity_profile")
            or None
        ),
        storage_capacity_profile_overrides=profile_overrides,
        storage_policy_override_fields=profile_overrides,
        raw_retention_days=_env_optional_int("ADLOG_RAW_RETENTION_DAYS", retention.get("raw_retention_days")),
        raw_archive_enabled=_env_bool("ADLOG_RAW_ARCHIVE_ENABLED", bool(retention.get("raw_archive_enabled") if retention.get("raw_archive_enabled") is not None else True)),
        raw_archive_compress=_env_bool("ADLOG_RAW_ARCHIVE_COMPRESS", bool(retention.get("raw_archive_compress") if retention.get("raw_archive_compress") is not None else True)),
        db_retention_days=_env_optional_int("ADLOG_DB_RETENTION_DAYS", retention.get("db_retention_days")),
        warm_retention_days=_env_optional_int("ADLOG_WARM_RETENTION_DAYS", retention.get("warm_retention_days")),
        backup_retention_days=_env_optional_int("ADLOG_BACKUP_RETENTION_DAYS", retention.get("backup_retention_days")),
        log_retention_days=_env_optional_int("ADLOG_LOG_RETENTION_DAYS", retention.get("log_retention_days")),
        artifact_retention_days=_env_optional_int("ADLOG_ARTIFACT_RETENTION_DAYS", retention.get("artifact_retention_days")),
        post_collection_retention_days=_env_optional_int(
            "ADLOG_POST_COLLECTION_RETENTION_DAYS",
            retention.get("post_collection_retention_days"),
        ),
        archive_auto_delete_enabled=_env_optional_bool(
            "ADLOG_ARCHIVE_AUTO_DELETE_ENABLED",
            retention.get("archive_auto_delete_enabled"),
        ),
        min_free_disk_percent=_env_int("ADLOG_MIN_FREE_DISK_PERCENT", int(retention.get("min_free_disk_percent") or 15)),
        stop_collection_if_free_disk_percent_below=_env_int("ADLOG_STOP_COLLECTION_IF_FREE_DISK_PERCENT_BELOW", int(retention.get("stop_collection_if_free_disk_percent_below") or 10)),
        stop_collection_if_free_disk_bytes_below=_env_int(
            "ADLOG_STOP_COLLECTION_IF_FREE_DISK_BYTES_BELOW",
            int(retention.get("stop_collection_if_free_disk_bytes_below") or 10 * 1024**3),
        ),
        critical_free_disk_percent=_env_int("ADLOG_CRITICAL_FREE_DISK_PERCENT", int(retention.get("critical_free_disk_percent") or 5)),
        channel_fairness_enabled=_env_bool("ADLOG_CHANNEL_FAIRNESS_ENABLED", bool(autocollection.get("channel_fairness_enabled") if autocollection.get("channel_fairness_enabled") is not None else True)),
        channel_fairness_stale_minutes=_env_int("ADLOG_CHANNEL_FAIRNESS_STALE_MINUTES", int(autocollection.get("channel_fairness_stale_minutes") or 360)),
        channel_fairness_max_events=_env_int("ADLOG_CHANNEL_FAIRNESS_MAX_EVENTS", int(autocollection.get("channel_fairness_max_events") or 100)),
        channel_fairness_timeout_seconds=_env_int("ADLOG_CHANNEL_FAIRNESS_TIMEOUT_SECONDS", int(autocollection.get("channel_fairness_timeout_seconds") or 120)),
        ai_provider=str(ai.get("provider") or os.getenv("ADLOG_AI_PROVIDER") or "openai_api"),
        ai_model=str(ai.get("model") or os.getenv("ADLOG_AI_MODEL") or "gpt-5.5"),
        ai_execute_enabled=_env_bool("ADLOG_AI_EXECUTE_ENABLED", bool(ai.get("execute_enabled") or False)),
        ai_timeout_seconds=_env_int("ADLOG_AI_TIMEOUT_SECONDS", int(ai.get("timeout_seconds") or 60)),
        http_max_connections=max(1, min(
            _env_int("ADLOG_HTTP_MAX_CONNECTIONS", int(http.get("max_connections") or 64)), 256,
        )),
        tls_handshake_timeout_seconds=max(15, min(
            _env_int("ADLOG_TLS_HANDSHAKE_TIMEOUT_SECONDS", int(http.get("tls_handshake_timeout_seconds") or 30)), 30,
        )),
    )
