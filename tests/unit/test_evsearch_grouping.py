"""ES07 synthetic projections and SQL/CH fakes; no database connections."""
from collections import defaultdict
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re

import pytest

from server.sli.events import evsearch_grouping as grouping
from server.sli.events.evsearch_contract import ContractError
from server.sli.events.evsearch_normalizer import normalize_request
from server.sli.events.evsearch_ownership import EventIdentity, StoreCapture, capture_binding
from server.sli.events.evsearch_snapshot import SnapshotError, _authorization, _query_hash


END = datetime(2026, 10, 19, tzinfo=timezone.utc)
START = END - timedelta(days=1)
MID = START + timedelta(hours=12)


def search(**changes):
    return normalize_request({"contract_version": "evsearch.v1", **changes}, now=END)


def event(**changes):
    return {
        "action": "authentication.logon", "provider": "synthetic-provider", "channel": "Security",
        "event_id": 4625, "outcome": "failure", "reason": "invalid_credentials", "logon_type": "3",
        "account": [{"role": "target", "entity_id": 11}], "source_station": [21],
        "ip": "192.0.2.1", "related_object": [31], "server_id": 7, "domain_id": 8,
        "task_identity": None, "process_identity": None, "file_identity": None,
        "group_identity_complete": True, **changes,
    }


def arguments(**changes):
    fields = grouping.PROJECTION_FIELDS
    return {
        "owner_id": 1, "search": search(page_size=2), "fields": fields, "revision": "projection-v1",
        "access": {
            "decision_id": "synthetic-decision",
            "reports": [{"report_key": "events.explorer", "allowed": True, "allowed_actions": ["view"],
                         "grants": [{"scope": {"kind": "domain", "ids": [8]},
                                     "field_categories": ["technical"], "allowed_actions": ["view"]}]}],
        },
        "publication": {
            "dataset_key": "events.v2", "fields_json": [{"key": key, "category": "technical"} for key in fields],
            "definition_json": {"columns": list(fields), "actions": ["view"]},
        }, **changes,
    }


def capture(store, rows, args):
    policy, _, _ = _authorization(**args)
    return StoreCapture(store, capture_binding(args["search"], policy, args["fields"], args["publication"]),
                        _query_hash(args["search"]), f"{store}-watermark",
                        tuple(projection for _, _, projection in rows),
                        tuple(EventIdentity.from_values(event_id, "AB" * 32, stamp) for event_id, stamp, _ in rows))


class AggregateFake:
    def __init__(self):
        self.calls = []
        self.corrupt = None

    def __call__(self, query, timeout_ms):
        assert 0 < timeout_ms <= 8000
        self.calls.append((query.store, timeout_ms))
        assert "LIMIT" not in query.sql.upper()
        assert "GROUP BY GROUP_KEY" in query.sql.upper()
        assert "min(" in query.sql and "max(" in query.sql
        assert "synthetic-provider" not in query.sql and "192.0.2.1" not in query.sql
        if query.store == "postgres":
            assert "jsonb_to_recordset(?::jsonb)" in query.sql
            rows = json.loads(query.params[0])
        else:
            assert "format(JSONEachRow" in query.sql
            encoded = re.search(r"stamp String','(.*)'\) GROUP BY group_key$", query.sql, re.S).group(1)
            rows = [json.loads(line) for line in encoded.splitlines()]
        stamps = defaultdict(list)
        for row in rows:
            stamps[row["group_key"]].append(datetime.fromisoformat(row["stamp"]))
        result = [{"group_key": key, "count": len(times), "first_seen": min(times), "last_seen": max(times)}
                  for key, times in stamps.items()]
        if query.store == "clickhouse":
            for row in result:
                row["count"] = str(row["count"])
                for name in ("first_seen", "last_seen"):
                    row[name] = row[name].replace(tzinfo=None).isoformat(sep=" ")
        return self.corrupt(result) if self.corrupt else list(reversed(result))


def start(hot=(), cold=(), *, store=None, args=None, aggregate=None, **options):
    args = arguments() if args is None else args
    store = grouping.GroupSnapshotStore() if store is None else store
    aggregate = aggregate or AggregateFake()
    page = store.start(**args, hot=capture("postgres", hot, args), cold=capture("clickhouse", cold, args),
                       aggregate=aggregate, **options)
    return store, page, args, aggregate


def test_cross_store_group_deduplicates_overlap_and_merges_count_min_max():
    early, late = MID - timedelta(hours=2), MID + timedelta(hours=2)
    store, page, args, fake = start(
        [(2, MID, event()), (3, late, event())], [(1, early, event()), (2, MID, event())],
        retention_boundary=MID,
    )
    assert page.items == ({"group_key": grouping.group_key(event(), 99), "count": 3,
                           "first_seen": early.isoformat(), "last_seen": late.isoformat()},)
    assert page.coverage == page.storage_coverage.status == "unknown"
    assert page.storage_coverage.unconfirmed == ((START, END),)
    assert not page.has_more and page.next_cursor is None
    assert [call[0] for call in fake.calls] == ["postgres", "clickhouse"]
    assert store.page(page.execution_id, **args).items == page.items
    members = store.get(page.execution_id, **args).items[0]["members"]
    assert sorted(member["event_db_id"] for member in members) == [1, 2, 3]
    assert {member["group_key"] for member in members} == {page.items[0]["group_key"]}


@pytest.mark.parametrize("field,value", [
    ("action", "authentication.logout"), ("provider", "different-provider"), ("channel", "System"),
    ("event_id", 4624), ("outcome", "success"), ("reason", "locked"), ("logon_type", "10"),
    ("account", [{"role": "actor", "entity_id": 11}]),
    ("account", [{"role": "target", "entity_id": 12}]), ("source_station", [22]),
    ("ip", "192.0.2.2"), ("related_object", [32]), ("server_id", 9), ("domain_id", 9),
    ("task_identity", "task:2"), ("process_identity", "process:2"), ("file_identity", "file:2"),
])
def test_different_reasons_roles_native_kinds_and_objects_never_merge(field, value):
    _, page, _, _ = start([(1, MID, event()), (2, MID, event(**{field: value}))])
    assert len(page.items) == 2
    assert [row["count"] for row in page.items] == [1, 1]


def test_canonical_identity_ignores_labels_link_order_and_store_encoding():
    first = event(account=[{"role": "target", "entity_id": 11}, {"role": "actor", "entity_id": 12}],
                  source_station=[21, 22], ip="2001:db8::1")
    second = event(account=[{"role": "actor", "entity_id": 12}, {"role": "target", "entity_id": 11},
                            {"role": "actor", "entity_id": 12}], source_station=[22, 21, 21],
                   ip="2001:0db8:0:0:0:0:0:1", title="Translated display label")
    assert grouping.group_key(first, 1) == grouping.group_key(second, 2)
    assert first["account"][0]["role"] == "target"


@pytest.mark.parametrize("change", ["proof", "absent", "unknown_account", "display_name", "malformed_ids", "native"])
def test_missing_or_unresolved_identity_keeps_each_event_separate(change):
    projection = event()
    if change == "proof":
        projection["group_identity_complete"] = False
    elif change == "absent":
        projection.pop("file_identity")
    elif change == "unknown_account":
        projection["account"] = [{"role": "target", "entity_id": None}]
    elif change == "display_name":
        projection["account"] = [{"role": "target", "entity_id": "same-label"}]
    elif change == "malformed_ids":
        projection["source_station"] = [True]
    else:
        projection["provider"] = None
    _, page, _, _ = start([(1, MID, projection)], [(2, MID, projection)])
    assert len(page.items) == 2 and all(row["count"] == 1 for row in page.items)


@pytest.mark.parametrize("sort", ["time_desc", "time_asc", "count_desc"])
def test_all_keyset_pages_have_no_duplicates_or_gaps_including_ties(sort):
    args = arguments(search=search(sort=sort, page_size=2))
    hot = [(event_id, MID + timedelta(microseconds=event_id % 3), event(reason=f"reason:{event_id % 7}"))
           for event_id in range(1, 31)]
    store, page, args, fake = start(hot, args=args)
    all_rows = list(page.items)
    while page.has_more:
        page = store.page(page.execution_id, **args, cursor=page.next_cursor)
        all_rows.extend(page.items)
    assert len(all_rows) == len({row["group_key"] for row in all_rows}) == 7
    assert sum(row["count"] for row in all_rows) == 30
    expected = sorted(all_rows, key=lambda row: row["group_key"])
    expected.sort(key=lambda row: datetime.fromisoformat(row["last_seen"]), reverse=sort != "time_asc")
    if sort == "count_desc":
        expected.sort(key=lambda row: row["count"], reverse=True)
    assert all_rows == expected
    assert len(fake.calls) == 1  # Following pages never re-read or reaggregate.


def test_snapshot_is_detached_from_import_and_page_mutation_and_page_size_can_change():
    rows = [(i, MID, event(reason=f"reason:{i}")) for i in range(1, 6)]
    store, first, args, fake = start(rows)
    rows[0][2]["reason"] = "changed after capture"
    rows.append((6, MID, event()))
    first.items[0]["count"] = 99
    reopened = store.page(first.execution_id, **args)
    assert reopened.items[0]["count"] == 1
    larger = store.page(first.execution_id, **{**args, "search": search(page_size=100)})
    assert len(larger.items) == 5
    members = store.get(first.execution_id, **args).items[0]["members"]
    assert {member["fields"]["reason"] for member in members} == {f"reason:{i}" for i in range(1, 6)}
    assert len(fake.calls) == 1
    assert "changed after capture" not in repr(larger)


def test_cursor_is_signed_not_just_context_hashed_and_cannot_cross_executions():
    rows = [(i, MID, event(reason=f"reason:{i}")) for i in range(1, 5)]
    store, first, args, _ = start(rows)
    import base64

    decoded = bytearray(base64.urlsafe_b64decode(first.next_cursor + "=" * (-len(first.next_cursor) % 4)))
    decoded[-5] ^= 1
    forged = base64.urlsafe_b64encode(decoded).decode().rstrip("=")
    for token in (forged, "not-a-cursor", "x" * 2049, ""):
        with pytest.raises(ContractError, match="evsearch.invalid_cursor"):
            store.page(first.execution_id, **args, cursor=token)
    _, second, _, _ = start(rows, store=store, args=args)
    with pytest.raises(ContractError, match="invalid_cursor"):
        store.page(second.execution_id, **args, cursor=first.next_cursor)


@pytest.mark.parametrize("change", ["owner", "scope", "publication", "revision", "query", "sort", "revoke"])
def test_each_page_rechecks_owner_query_scope_publication_and_semantic_revision(change):
    rows = [(i, MID, event(reason=f"reason:{i}")) for i in range(1, 4)]
    store, page, args, fake = start(rows)
    current = deepcopy(args)
    if change == "owner":
        current["owner_id"] = 2
    elif change == "scope":
        current["access"]["reports"][0]["grants"][0]["scope"]["ids"] = [9]
    elif change == "publication":
        current["publication"]["revision"] = "new"
    elif change == "revision":
        current["revision"] = "projection-v2"
    elif change == "query":
        current["search"] = search(conditions=[{"field": "channel", "operator": "eq", "value": "System"}])
    elif change == "sort":
        current["search"] = search(sort="count_desc")
    else:
        current["access"]["reports"] = []
    with pytest.raises(SnapshotError, match="snapshot_(expired|invalidated)"):
        store.page(page.execution_id, **current, cursor=page.next_cursor)
    assert len(fake.calls) == 1


def test_expiry_and_eviction_have_no_retained_coverage_or_groups():
    tick = [0.0]
    store = grouping.GroupSnapshotStore(clock=lambda: tick[0], utcnow=lambda: END, max_executions=1)
    _, first, args, _ = start([(1, MID, event())], store=store)
    start([(2, MID, event())], store=store)
    assert store.execution_count == 1
    with pytest.raises(SnapshotError, match="snapshot_expired"):
        store.page(first.execution_id, **args)
    tick[0] = 300
    assert store.execution_count == 1  # Purged on access/start, no background task.
    with pytest.raises(SnapshotError, match="snapshot_expired"):
        store.page(first.execution_id, **args)
    assert store.execution_count == store.size_bytes == 0


def test_undeclared_adapter_columns_do_not_influence_groups():
    args = arguments(fields=("channel",))
    _, page, _, _ = start([(1, MID, event()), (2, MID, event())], args=args)
    assert len(page.items) == 2


def test_denied_fields_and_unbound_or_incomplete_captures_never_aggregate():
    args, fake = arguments(), AggregateFake()
    hot, cold = capture("postgres", [(1, MID, event())], args), capture("clickhouse", [], args)
    store = grouping.GroupSnapshotStore()
    for replacement in (replace(hot, binding="another-scope"), replace(hot, exhaustive=False)):
        with pytest.raises(ContractError, match="storage_"):
            store.start(**args, hot=replacement, cold=cold, aggregate=fake)
    args["publication"]["definition_json"]["columns"].remove("reason")
    with pytest.raises(PermissionError):
        store.start(**args, hot=hot, cold=cold, aggregate=fake)
    assert not fake.calls and store.execution_count == 0


@pytest.mark.parametrize("corrupt", [
    lambda rows: [], lambda rows: rows + rows, lambda rows: [{**rows[0], "count": 99}],
    lambda rows: [{**rows[0], "first_seen": (MID - timedelta(hours=1)).isoformat()}],
    lambda rows: [{**rows[0], "last_seen": "invalid-time"}],
])
def test_incomplete_or_corrupt_partial_aggregates_are_never_published(corrupt):
    fake = AggregateFake()
    fake.corrupt = corrupt
    store = grouping.GroupSnapshotStore()
    with pytest.raises(ContractError, match="storage_integrity_error"):
        start([(1, MID, event())], aggregate=fake, store=store)
    assert store.execution_count == 0


@pytest.mark.parametrize("budget", ["events", "groups", "bytes", "deadline"])
def test_limits_fail_without_publishing_partial_sorted_top(monkeypatch, budget):
    options = {}
    tick = [0.0]
    fake = AggregateFake()
    if budget == "events":
        options["max_events"] = 1
    elif budget == "groups":
        monkeypatch.setattr(grouping, "MAX_GROUPS", 1)
    elif budget == "bytes":
        options["max_snapshot_bytes"] = 10
    else:
        def slow(query, timeout_ms):
            result = AggregateFake()(query, timeout_ms)
            tick[0] = 9
            return result
        fake = slow
    store = grouping.GroupSnapshotStore(clock=lambda: tick[0], **options)
    with pytest.raises(SnapshotError, match="snapshot_(limit_exceeded|timeout)"):
        start([(1, MID, event()), (2, MID, event(reason="different"))], store=store, aggregate=fake)
    assert store.execution_count == 0


def test_empty_and_unavailable_store_never_claim_collection_complete():
    args, store, fake = arguments(), grouping.GroupSnapshotStore(), AggregateFake()
    page = store.start(**args, hot=capture("postgres", [], args),
                       cold=replace(capture("clickhouse", [], args), status="unavailable", watermark=""), aggregate=fake)
    assert page.items == () and not page.has_more and page.next_cursor is None
    assert page.coverage == page.storage_coverage.status == "unknown"
    assert fake.calls == []


def test_both_sql_adapters_share_one_remaining_deadline():
    tick = [0.0]
    fake = AggregateFake()

    def aggregate(query, timeout_ms):
        result = fake(query, timeout_ms)
        tick[0] += 3
        return result

    store = grouping.GroupSnapshotStore(clock=lambda: tick[0])
    _, page, _, _ = start([(1, MID, event())], [(2, MID, event())], store=store, aggregate=aggregate)
    assert page.items[0]["count"] == 2
    assert fake.calls == [("postgres", 8000), ("clickhouse", 5000)]


def test_new_error_is_translated_in_both_server_and_frontend_dictionaries():
    root = Path(__file__).resolve().parents[2]
    for locale in ("ru", "en"):
        messages = json.loads((root / f"config/i18n/server.{locale}.json").read_text(encoding="utf-8"))
        assert messages["evsearch.invalid_cursor"]
        frontend = (root / f"frontend/src/i18n/{locale}.ts").read_text(encoding="utf-8")
        assert json.dumps("evsearch.invalid_cursor") in frontend
