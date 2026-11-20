from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from server.sli.access import auth
from server.sli.access import session_access_cache as cache


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    cache.invalidate_session()
    monkeypatch.setattr(cache, "query_rows_bounded", Mock(return_value=[{"revision": 1, "revision_count": 1, "next_change": None}]))
    yield
    cache.invalidate_session()


def principal(role="viewer", user_id=1):
    return {"type": "session", "id": user_id, "role": role}


def test_cache_is_per_session_role_and_returns_independent_copies():
    loader = Mock(return_value={"reports": [{"allowed": True}]})
    p = principal()
    cache.session_access(p, "synthetic-session-a", loader)
    returned = cache.session_access(p, "synthetic-session-a", loader)
    returned["reports"].clear()
    assert cache.session_access(p, "synthetic-session-a", loader)["reports"]
    assert loader.call_count == 1
    cache.session_access(p, "synthetic-session-b", loader)
    cache.session_access(principal("operator"), "synthetic-session-a", loader)
    cache.session_access(principal("operator", 2), "synthetic-session-a", loader)
    assert loader.call_count == 4


def test_policy_changes_and_temporal_boundaries_invalidate(monkeypatch):
    loader = Mock(return_value={})
    p = principal()
    cache.session_access(p, "synthetic-session", loader)
    monkeypatch.setattr(cache, "_policy_stamp", lambda: (2, None))
    cache.session_access(p, "synthetic-session", loader)
    assert loader.call_count == 2
    monkeypatch.setattr(cache, "_policy_stamp", lambda: (3, datetime.now(timezone.utc) + timedelta(seconds=1)))
    tick = [100.0]
    monkeypatch.setattr(cache, "monotonic", lambda: tick[0])
    cache.session_access(p, "synthetic-session", loader)
    tick[0] += 2
    cache.session_access(p, "synthetic-session", loader)
    assert loader.call_count == 4


def test_logout_and_user_invalidation_do_not_affect_other_sessions(monkeypatch):
    loader = Mock(return_value={})
    for token, user_id in (("synthetic-a", 1), ("synthetic-b", 2)):
        cache.session_access(principal(user_id=user_id), token, loader)
    cache.invalidate_session(user_id=1)
    cache.session_access(principal(), "synthetic-a", loader)
    cache.session_access(principal(user_id=2), "synthetic-b", loader)
    assert loader.call_count == 3
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=False)
    cursor = Mock()
    cursor.__enter__ = Mock(return_value=cursor)
    cursor.__exit__ = Mock(return_value=False)
    connection.cursor.return_value = cursor
    monkeypatch.setattr(auth, "ensure_auth_schema", lambda: None)
    monkeypatch.setattr(auth, "_connect", lambda: connection)
    auth.revoke_session("synthetic-a")
    cache.session_access(principal(), "synthetic-a", loader)
    assert loader.call_count == 4


def test_cache_is_bounded_and_non_session_principals_are_not_cached(monkeypatch):
    monkeypatch.setattr(cache, "_MAX_SESSIONS", 2)
    loader = Mock(return_value={})
    for i in range(3):
        cache.session_access(principal(), f"synthetic-{i}", loader)
    assert len(cache._cache) == 2
    for _ in range(2):
        cache.session_access(None, None, loader)
    assert loader.call_count == 5


def test_policy_stamp_checks_audit_revision_and_all_future_boundaries(monkeypatch):
    read = Mock(return_value=[{"revision": 7, "revision_count": 6, "next_change": None}])
    monkeypatch.setattr(cache, "query_rows_bounded", read)
    assert cache._policy_stamp() == ((7, 6), None)
    sql = read.call_args.args[0]
    assert "max(id)" in sql
    for table in ("access_group_members", "access_subject_packages", "access_capability_assignments", "access_report_assignments"):
        assert f"valid_from as boundary from {table}" in sql
        assert f"valid_until as boundary from {table}" in sql


def test_request_handlers_share_cache_only_after_live_authentication(monkeypatch):
    from server.api import http_server

    loader = Mock(return_value={"reports": []})
    monkeypatch.setattr(http_server, "effective_access", loader)
    for _ in range(2):
        handler = object.__new__(http_server.RequestHandler)
        handler._principal = principal()
        handler.headers = {"Cookie": "adlog_session=synthetic-session"}
        assert handler._access_decision() == {"reports": []}
    loader.assert_called_once()


def test_user_role_update_explicitly_evicts_existing_session(monkeypatch):
    from contextlib import nullcontext

    loader = Mock(return_value={})
    cache.session_access(principal(), "synthetic-session", loader)
    cursor = Mock()
    cursor.fetchone.side_effect = [
        {"id": 1, "username": "synthetic-user", "role": "viewer", "is_active": True},
        {"id": 1, "username": "synthetic-user", "role": "operator", "is_active": True},
    ]
    connection = SimpleConnection(cursor)
    monkeypatch.setattr(auth, "_connect", lambda: nullcontext(connection))
    monkeypatch.setattr(auth, "ensure_auth_schema", lambda: None)
    monkeypatch.setattr(auth, "_audit", Mock())
    auth.update_user(user_id=1, role="operator")
    cache.session_access(principal(), "synthetic-session", loader)
    assert loader.call_count == 2


class SimpleConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        from contextlib import nullcontext

        return nullcontext(self._cursor)


def test_global_logout_clears_all_permission_entries(monkeypatch):
    from contextlib import nullcontext

    loader = Mock(return_value={})
    cache.session_access(principal(), "synthetic-a", loader)
    cache.session_access(principal(user_id=2), "synthetic-b", loader)
    cursor = Mock(rowcount=2)
    monkeypatch.setattr(auth, "_connect", lambda: nullcontext(SimpleConnection(cursor)))
    assert auth.revoke_all_sessions() == 2
    assert not cache._cache
