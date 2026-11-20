"""Reference-only priority projection after the existing event access boundary."""
from server.sli.core.database import query_rows_bounded


def attach_event_priorities(rows):
    """One bounded lookup; native identity includes the immutable event hash."""
    # Event search requests limit+1 to establish its keyset continuation.
    if len(rows) > 1001:
        raise ValueError("account_watch_projection_limit")
    identities = {}
    for row in rows:
        digest = row.get("normalized_hash")
        if isinstance(digest, (bytes, bytearray, memoryview)):
            digest = bytes(digest).hex()
        elif isinstance(digest, str):
            digest = digest.lower().removeprefix("\\x")
        if (row.get("id") and isinstance(digest, str) and len(digest) == 64
                and all(c in "0123456789abcdef" for c in digest)):
            identities[int(row["id"])] = digest
    if not identities:
        return rows
    placeholders = ",".join("(?::bigint,?::text)" for _ in identities)
    result = query_rows_bounded(
        f"""select i.id,public.account_watch_event_priority(i.id,i.sha256) as watch_priority
            from (values {placeholders}) i(id,sha256)""",
        tuple(value for pair in identities.items() for value in pair), statement_timeout_ms=3000,
    )
    priorities = {int(row["id"]): row["watch_priority"] for row in result}
    return [{**row, "watch_priority": priorities.get(int(row.get("id") or 0))} for row in rows]
