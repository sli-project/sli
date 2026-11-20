from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def assert_disposable_database(conn: Any) -> dict[str, object]:
    """Refuse PostgreSQL integration work outside the dedicated test namespace."""

    with conn.cursor() as cur:
        cur.execute(
            "select current_database() as name,"
            "inet_server_port() as port,"
            "current_setting('server_encoding') as encoding"
        )
        row = cur.fetchone()
        identity = dict(row) if isinstance(row, Mapping) else dict(
            zip((column.name for column in cur.description), row, strict=True)
        )
    if not str(identity["name"]).startswith("sli_test_"):
        raise AssertionError(
            "PostgreSQL integration refuses a non-disposable database: "
            f"database={identity['name']}, port={identity['port']}"
        )
    if identity["encoding"] != "UTF8":
        raise AssertionError(
            f"PostgreSQL integration requires UTF8, got {identity['encoding']}"
        )
    return identity
