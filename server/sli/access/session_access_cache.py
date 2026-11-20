"""Bounded session cache; authentication is still checked on every request."""
from __future__ import annotations

import hashlib
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from time import monotonic

from server.sli.core.database import query_rows_bounded

_cache: OrderedDict[str, tuple] = OrderedDict()
_lock = RLock()
_MAX_SESSIONS = 256
_MAX_AGE_SECONDS = 60


def _policy_stamp():
    # Audit revision invalidates assignments/preferences across server processes.
    # Upcoming starts AND expirations include denies and inactive future grants.
    boundaries = " union all ".join(
        f"select {column} as boundary from {table} where {column}>now()"
        for table in ("access_group_members", "access_subject_packages", "access_capability_assignments", "access_report_assignments")
        for column in ("valid_from", "valid_until")
    )
    row = query_rows_bounded(
        "select (select coalesce(max(id),0) from access_audit_v4) as revision, "
        "(select count(*) from access_audit_v4) as revision_count, "
        f"(select min(boundary) from ({boundaries}) changes) as next_change"
    )[0]
    # Count also detects a lower sequence ID committed after the current max.
    return (row["revision"], row["revision_count"]), row.get("next_change")


def invalidate_session(token: str | None = None, *, user_id: int | None = None) -> None:
    with _lock:
        if token:
            _cache.pop(hashlib.sha256(token.encode()).hexdigest(), None)
        elif user_id is not None:
            for key, entry in list(_cache.items()):
                if entry[0][0] == user_id:
                    _cache.pop(key, None)
        else:
            _cache.clear()


def session_access(principal, token, loader):
    if not token or not principal or principal.get("type") != "session":
        return loader(principal)
    key = hashlib.sha256(token.encode()).hexdigest()
    revision, next_change = _policy_stamp()
    identity = (principal["id"], principal.get("role"), revision)
    now = monotonic()
    with _lock:
        entry = _cache.get(key)
        if entry and entry[0] == identity and now < entry[1]:
            _cache.move_to_end(key)
            return deepcopy(entry[2])
        _cache.pop(key, None)
    decision = loader(principal)
    lifetime = _MAX_AGE_SECONDS
    if next_change is not None:
        lifetime = min(lifetime, max(0, (next_change - datetime.now(timezone.utc)).total_seconds()))
    with _lock:
        _cache[key] = (identity, now + lifetime, deepcopy(decision))
        while len(_cache) > _MAX_SESSIONS:
            _cache.popitem(last=False)
    return decision
