"""Session advisory locks that never retain a PostgreSQL transaction snapshot."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Iterator


@contextmanager
def session_advisory_lock(
    connection_factory: Callable[[], object],
    lock_name: str,
    *,
    prepare: Callable[[object], None] | None = None,
) -> Iterator[bool]:
    """Hold a session lock on a dedicated autocommit connection.

    PostgreSQL session advisory locks survive transaction boundaries.  Keeping
    the dedicated connection in autocommit mode prevents a continuous worker
    from also retaining an old transaction snapshot for its whole lifetime.
    """
    conn = connection_factory()
    acquired = False
    try:
        # A connection factory may perform session setup such as SET ROLE.
        # Finish that setup transaction before changing the autocommit flag.
        conn.commit()
        conn.autocommit = True
        if prepare is not None:
            prepare(conn)
        with conn.cursor() as cur:
            cur.execute(
                "select pg_try_advisory_lock(hashtext(%s)) as acquired",
                (lock_name,),
            )
            acquired = bool(dict(cur.fetchone() or {}).get("acquired"))
        yield acquired
    finally:
        try:
            if acquired:
                with conn.cursor() as cur:
                    cur.execute(
                        "select pg_advisory_unlock(hashtext(%s))",
                        (lock_name,),
                    )
        finally:
            conn.close()
