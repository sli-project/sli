"""Snapshot builds must only block requests for the same authorized scope."""
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event, Lock

import pytest

from server.sli.plugins.ad.reports.definitions import users


@pytest.fixture(autouse=True)
def empty_cache():
    users._cache.clear()
    yield
    users._cache.clear()


def payload(scope, previous=False):
    return {"current": {"users": [{"domainId": scope}]},
            "previous_state": "none" if previous else "not_requested"}


@pytest.mark.parametrize("warm", [False, True])
def test_unrelated_scope_is_not_blocked_by_slow_build(monkeypatch, warm):
    entered, release = Event(), Event()
    expected = payload(22)
    if warm:
        users._cache[(22,)] = (time.monotonic(), expected)

    def build(*, domain_ids, include_previous):
        if domain_ids == [11]:
            entered.set()
            assert release.wait(5)
        return expected if domain_ids == [22] else payload(11)

    monkeypatch.setattr(users, "load_users_v2_snapshots", build)
    with ThreadPoolExecutor(max_workers=2) as executor:
        slow = executor.submit(users._snapshots, [11])
        try:
            assert entered.wait(2)
            fast = executor.submit(users._snapshots, [22])
            assert fast.result(timeout=1) is expected
        finally:
            release.set()
            slow.result(timeout=2)


def test_same_scope_coalesces_normalized_concurrent_requests(monkeypatch):
    barrier, entered, release = Barrier(5), Event(), Event()
    calls, guard = [], Lock()
    expected = payload(11)

    def build(**kwargs):
        with guard:
            calls.append(kwargs)
        entered.set()
        assert release.wait(5)
        return expected

    def request(scope):
        barrier.wait(timeout=2)
        return users._snapshots(scope)

    monkeypatch.setattr(users, "load_users_v2_snapshots", build)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(request, scope) for scope in ([11, 22], [22, 11]) * 2]
        try:
            barrier.wait(timeout=2)
            assert entered.wait(2)
        finally:
            release.set()
        assert all(future.result(timeout=2) is expected for future in futures)
    assert len(calls) == 1


def test_failed_build_releases_scope_for_retry(monkeypatch):
    entered, release, waiting = Event(), Event(), Event()
    original_wait = users._condition.wait

    def wait(*args, **kwargs):
        waiting.set()
        return original_wait(*args, **kwargs)

    monkeypatch.setattr(users._condition, "wait", wait)
    expected, calls = payload(11), []

    def build(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            entered.set()
            assert release.wait(5)
            raise RuntimeError("synthetic read failure")
        return expected

    monkeypatch.setattr(users, "load_users_v2_snapshots", build)
    with ThreadPoolExecutor(max_workers=2) as executor:
        failed = executor.submit(users._snapshots, [11])
        try:
            assert entered.wait(2)
            retry = executor.submit(users._snapshots, [11])
            assert waiting.wait(2)
        finally:
            release.set()
        with pytest.raises(RuntimeError, match="synthetic read failure"):
            failed.result(timeout=2)
        assert retry.result(timeout=2) is expected
    assert len(calls) == 2


def test_warm_current_remains_readable_while_comparison_builds(monkeypatch):
    entered, release = Event(), Event()
    current, comparison = payload(11), payload(11, previous=True)
    users._cache[(11,)] = (time.monotonic(), current)

    def build(**kwargs):
        assert kwargs["include_previous"] is True
        entered.set()
        assert release.wait(5)
        return comparison

    monkeypatch.setattr(users, "load_users_v2_snapshots", build)
    with ThreadPoolExecutor(max_workers=2) as executor:
        pending = executor.submit(users._snapshots, [11], with_previous=True)
        try:
            assert entered.wait(2)
            assert executor.submit(users._snapshots, [11]).result(timeout=1) is current
        finally:
            release.set()
        assert pending.result(timeout=2) is comparison
    assert users._snapshots([11], with_previous=True) is comparison


def test_expired_scope_rebuilds_and_none_is_distinct_from_empty(monkeypatch):
    calls = []
    users._cache[None] = (time.monotonic() - users.CACHE_SECONDS - 1, payload("expired"))

    def build(**kwargs):
        calls.append(kwargs)
        return payload(kwargs["domain_ids"])

    monkeypatch.setattr(users, "load_users_v2_snapshots", build)
    unrestricted = users._snapshots(None)
    denied = users._snapshots([])
    assert unrestricted is not denied
    assert users._snapshots(None) is unrestricted
    assert users._snapshots([]) is denied
    assert [call["domain_ids"] for call in calls] == [None, []]
