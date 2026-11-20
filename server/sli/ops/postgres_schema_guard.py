from __future__ import annotations

import threading
from typing import Iterable


OPS_STABILITY_SCHEMA_VERSION = 8

_cache_lock = threading.Lock()
_verified: set[tuple[str, tuple[str, ...], int]] = set()


def clear_schema_guard_cache() -> None:
    with _cache_lock:
        _verified.clear()


def require_table_columns(
    table: str,
    columns: Iterable[str],
    *,
    minimum_schema_version: int = OPS_STABILITY_SCHEMA_VERSION,
) -> dict[str, object]:
    """Read-only runtime schema contract check.

    Runtime helpers must never repair schema from GET/read paths.  Updates are
    applied by the versioned maintenance migration before the server restarts.
    This function only verifies the contract and caches the successful result.
    """
    expected = tuple(sorted({str(item) for item in columns if str(item)}))
    key = (str(table), expected, int(minimum_schema_version))
    with _cache_lock:
        if key in _verified:
            return {
                "status": "ok",
                "table": table,
                "columns": list(expected),
                "minimum_schema_version": minimum_schema_version,
                "cached": True,
            }

    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select coalesce(max(version), 0)::integer as version from schema_migrations")
            row = cur.fetchone() or {}
            version = int(row.get("version") or 0)
            cur.execute(
                """
                select column_name
                from information_schema.columns
                where table_schema = current_schema() and table_name = %s
                """,
                (str(table),),
            )
            present = {str(item["column_name"]) for item in cur.fetchall()}

    missing = [item for item in expected if item not in present]
    if version < minimum_schema_version or missing:
        raise RuntimeError(
            "PostgreSQL runtime schema is not ready: "
            f"table={table}, version={version}, required_version={minimum_schema_version}, "
            f"missing_columns={missing}. Run ops_stability1_migrate.py before restart."
        )

    with _cache_lock:
        _verified.add(key)
    return {
        "status": "ok",
        "table": table,
        "columns": list(expected),
        "minimum_schema_version": minimum_schema_version,
        "schema_version": version,
        "cached": False,
    }
