"""Domain-scoped typed Accounting evidence validation for cases."""
from typing import Any


def _vpn_session_exists(cur: Any, *, source_domain_id: int, session_row_id: str) -> bool:
    cur.execute(
        """select exists(
               select 1 from radius_vpn_session_rows_v1
               where domain_id=%s and session_row_id=%s
           ) as present""",
        (int(source_domain_id), str(session_row_id)),
    )
    return bool((cur.fetchone() or {}).get("present"))


