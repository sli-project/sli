"""ES04 bounded materialization, isolation and invalidation; no database."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from server.sli.events import evsearch_snapshot as snapshots
from server.sli.events.evsearch_normalizer import normalize_request


NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


def search(**overrides):
    return normalize_request({"contract_version": "evsearch.v1", **overrides}, now=NOW)


def access():
    return {
        "policy_revision": "policy-v1", "decision_id": "decision-v1",
        "reports": [{"report_key": "events.explorer", "allowed": True,
                     "allowed_actions": ["view"], "grants": [{
                         "scope": {"kind": "domain", "ids": [7]},
                         "field_categories": ["technical"], "allowed_actions": ["view"],
                     }]}],
    }


def publication():
    return {
        "dataset_key": "events.v2", "revision": "publication-v1",
        "fields_json": [{"key": key, "category": "technical"} for key in ("id", "channel")],
        "definition_json": {"columns": ["id", "channel"], "actions": ["view"]},
    }


class Source:
    def __init__(self):
        self.rows = [{"id": 1, "channel": "Security", "unpublished": "not retained"}]
        self.open = False
        self.calls = 0
        self.limits = []
        self.fail = False

    @contextmanager
    def __call__(self, query, policy, limit, timeout_ms):
        assert policy.scope.allows(domain_id=7)
        assert query.period.end == NOW
        assert 0 < timeout_ms <= 8000
        self.calls += 1
        self.limits.append(limit)
        self.open = True
        try:
            if self.fail:
                raise RuntimeError("synthetic failure")
            yield iter(self.rows)
        finally:
            self.open = False


@pytest.fixture
def setup():
    tick = [0.0]
    store = snapshots.SnapshotStore(clock=lambda: tick[0], utcnow=lambda: NOW)
    source = Source()
    args = dict(owner_id=11, search=search(), access=access(), publication=publication(),
                fields=("id", "channel"), revision="projection-v1")
    return store, source, args, tick


def start(setup):
    store, source, args, _ = setup
    return store.start(open_rows=source, **args)


def test_import_update_and_consumer_mutation_do_not_change_open_snapshot(setup):
    store, source, args, _ = setup
    first = start(setup)
    assert not source.open
    assert first.items == [{"id": 1, "channel": "Security"}]
    source.rows[0]["channel"] = "System"
    source.rows.append({"id": 2, "channel": "System"})
    first.items[0]["channel"] = "changed by consumer"
    reopened = store.get(first.execution_id, **args)
    assert reopened.items == [{"id": 1, "channel": "Security"}]
    assert reopened.as_of == NOW
    assert reopened.expires_at.timestamp() - reopened.as_of.timestamp() == 300
    assert source.calls == 1 and not source.open
    fresh = start(setup)
    assert fresh.execution_id != first.execution_id
    assert [row["id"] for row in fresh.items] == [1, 2]


@pytest.mark.parametrize("elapsed", [300, 301])
def test_expiry_requires_new_run_and_does_not_extend_on_read(setup, elapsed):
    store, _, args, tick = setup
    first = start(setup)
    tick[0] = 299
    assert store.get(first.execution_id, **args).expires_at == first.expires_at
    tick[0] = elapsed
    with pytest.raises(snapshots.SnapshotError, match="evsearch.snapshot_expired"):
        store.get(first.execution_id, **args)
    assert start(setup).execution_id != first.execution_id


def test_other_user_cannot_read_or_invalidate_execution_even_with_same_grants(setup):
    store, _, args, _ = setup
    first = start(setup)
    for execution_id in (first.execution_id, "missing"):
        with pytest.raises(snapshots.SnapshotError, match="evsearch.snapshot_expired"):
            store.get(execution_id, **{**args, "owner_id": 12})
    assert store.get(first.execution_id, **args).items


@pytest.mark.parametrize("change", ["policy_revision", "scope", "field_category", "revoke", "action",
                                   "publication_revision", "publication_fields", "projection_revision", "query", "sort"])
def test_current_policy_publication_semantics_and_query_are_rechecked(setup, change):
    store, _, args, _ = setup
    first = start(setup)
    current = deepcopy(args)
    if change == "policy_revision":
        current["access"]["policy_revision"] = "policy-v2"
    elif change == "scope":
        current["access"]["reports"][0]["grants"][0]["scope"]["ids"] = [8]
    elif change == "field_category":
        current["access"]["reports"][0]["grants"][0]["field_categories"] = []
    elif change == "revoke":
        current["access"]["reports"] = []
    elif change == "action":
        current["access"]["reports"][0]["allowed_actions"] = []
    elif change == "publication_revision":
        current["publication"]["revision"] = "publication-v2"
    elif change == "publication_fields":
        current["publication"]["definition_json"]["columns"] = ["id"]
    elif change == "projection_revision":
        current["revision"] = "projection-v2"
    elif change == "query":
        current["search"] = search(conditions=[{"field": "channel", "operator": "eq", "value": "System"}])
    else:
        current["search"] = search(sort="time_asc")
    with pytest.raises(snapshots.SnapshotError, match="evsearch.snapshot_invalidated"):
        store.get(first.execution_id, **current)
    with pytest.raises(snapshots.SnapshotError, match="evsearch.snapshot_expired"):
        store.get(first.execution_id, **args)


def test_new_decision_and_page_size_keep_same_execution_but_projection_does_not(setup):
    store, _, args, _ = setup
    first = start(setup)
    current = deepcopy(args)
    current["access"]["decision_id"] = "decision-v2"
    current["search"] = search(page_size=100)
    assert store.get(first.execution_id, **current).query_hash == first.query_hash
    with pytest.raises(snapshots.SnapshotError, match="snapshot_invalidated"):
        store.get(first.execution_id, **{**current, "fields": ("id",)})


def test_denied_start_never_opens_reader(setup):
    store, source, args, _ = setup
    with pytest.raises(PermissionError):
        store.start(open_rows=source, **{**args, "access": {"reports": []}})
    assert source.calls == 0


@pytest.mark.parametrize("kind", ["events", "bytes", "reader"])
def test_limit_or_reader_failure_closes_source_and_publishes_nothing(setup, kind):
    _, source, args, _ = setup
    store = snapshots.SnapshotStore(max_events=1, max_snapshot_bytes=64)
    if kind == "events":
        source.rows.append({"id": 2, "channel": "Security"})
    elif kind == "bytes":
        source.rows[0]["channel"] = "x" * 100
    else:
        source.fail = True
    with pytest.raises((snapshots.SnapshotError, RuntimeError)):
        store.start(open_rows=source, **args)
    assert not source.open
    assert source.limits == [2]
    assert store.size_bytes == 0
    assert store.execution_count == 0


def test_global_byte_and_entry_limits_evict_with_explicit_expiry(setup):
    _, source, args, _ = setup
    # Each serialized result fits separately, but two do not.
    store = snapshots.SnapshotStore(max_snapshot_bytes=64, max_total_bytes=50, max_executions=2)
    first = store.start(open_rows=source, **args)
    second = store.start(open_rows=source, **args)
    assert store.size_bytes <= 50
    with pytest.raises(snapshots.SnapshotError, match="snapshot_expired"):
        store.get(first.execution_id, **args)
    assert store.get(second.execution_id, **args).items
    source.rows.clear()
    for _ in range(3):
        store.start(open_rows=source, **args)
    assert store.execution_count == 2


def test_expired_entries_are_removed_before_capture(setup):
    store, _, _, tick = setup
    start(setup)
    tick[0] = 300
    start(setup)
    assert store.execution_count == 1


def test_capture_deadline_includes_reader_and_closes_before_timeout(setup):
    _, source, args, tick = setup
    store = snapshots.SnapshotStore(clock=lambda: tick[0], utcnow=lambda: NOW)

    @contextmanager
    def slow(*reader_args):
        with source(*reader_args) as rows:
            tick[0] = 8
            yield rows

    with pytest.raises(snapshots.SnapshotError, match="evsearch.snapshot_timeout"):
        store.start(open_rows=slow, **args)
    assert not source.open and store.execution_count == 0


def test_capture_cannot_publish_an_already_expired_snapshot(setup):
    _, source, args, tick = setup
    store = snapshots.SnapshotStore(ttl_seconds=1, clock=lambda: tick[0], utcnow=lambda: NOW)

    @contextmanager
    def slow(*reader_args):
        with source(*reader_args) as rows:
            tick[0] = 2
            yield rows

    with pytest.raises(snapshots.SnapshotError, match="snapshot_timeout"):
        store.start(open_rows=slow, **args)
    assert not source.open and store.execution_count == 0


def test_postgres_adapter_releases_real_database_wrapper_context_before_publication(setup, monkeypatch):
    from server.sli.core import database, postgres_runtime_pipeline

    store, _, args, _ = setup
    state = {"connection_open": False, "cursor_open": False, "connections": 0, "sql": []}

    class Cursor:
        def __enter__(self):
            state["cursor_open"] = True
            return self

        def __exit__(self, *exc):
            state["cursor_open"] = False

        def execute(self, sql, params=()):
            state["sql"].append((sql, params))

        def fetchall(self):
            return [{"id": 1, "channel": "Security"}]

    class Connection:
        def __enter__(self):
            state["connection_open"] = True
            state["connections"] += 1
            return self

        def __exit__(self, *exc):
            state["connection_open"] = False

        def cursor(self):
            return Cursor()

    def compile_query(query, policy, limit):
        assert query == args["search"]
        assert policy.scope.allows(domain_id=7)
        assert limit == snapshots.MAX_EVENTS + 1
        return "select id, channel from synthetic_projection where domain_id = ? limit ?", (7, limit)

    monkeypatch.setattr(database, "_require_runtime_db", lambda: None)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", Connection)
    reader = snapshots.PostgresSnapshotReader(compile_query)
    first = store.start(open_rows=reader, **args)
    assert first.items == [{"id": 1, "channel": "Security"}]
    assert not state["connection_open"] and not state["cursor_open"]
    assert state["sql"][-1] == (
        "select id, channel from synthetic_projection where domain_id = %s limit %s", (7, snapshots.MAX_EVENTS + 1),
    )
    assert store.get(first.execution_id, **args).items == first.items
    assert state["connections"] == 1


def test_postgres_timeout_is_localizable_and_does_not_publish(setup, monkeypatch):
    from server.sli.core import database

    store, _, args, _ = setup

    def timeout(sql, params, **budgets):
        assert 0 < budgets["statement_timeout_ms"] < budgets["wall_timeout_ms"] <= 8000
        raise database.QueryTimeoutError("synthetic timeout", timeout_ms=100)

    monkeypatch.setattr(database, "query_rows_bounded", timeout)
    reader = snapshots.PostgresSnapshotReader(lambda *args: ("select id from synthetic_projection limit ?", (2,)))
    with pytest.raises(snapshots.SnapshotError, match="evsearch.snapshot_timeout"):
        store.start(open_rows=reader, **args)
    assert store.execution_count == 0


@pytest.mark.parametrize("kwargs", [
    {"ttl_seconds": 301}, {"ttl_seconds": 0}, {"max_events": 250001},
    {"max_snapshot_bytes": 16 * 1024 * 1024 + 1}, {"max_total_bytes": 128 * 1024 * 1024 + 1},
    {"max_executions": 0}, {"timeout_seconds": 9},
])
def test_configuration_cannot_relax_hard_budgets(kwargs):
    with pytest.raises(ValueError):
        snapshots.SnapshotStore(**kwargs)


def test_snapshot_codes_have_both_server_translations():
    root = Path(__file__).resolve().parents[2]
    keys = ("snapshot_expired", "snapshot_invalidated", "snapshot_limit_exceeded", "snapshot_timeout")
    for locale in ("ru", "en"):
        messages = json.loads((root / f"config/i18n/server.{locale}.json").read_text(encoding="utf-8"))
        assert all(messages.get(f"evsearch.{key}") for key in keys)
