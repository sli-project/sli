"""T004 comparison query budget and synthetic PostgreSQL selection parity."""
from __future__ import annotations

import os
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from server.sli.plugins.ad.reports import computers_v6_reporting as reporting


def snapshot(domain, identity, *, scope="a", state="available", enabled=True):
    return {"snapshot_id": identity, "domain_id": domain, "scope_sha256": scope,
                "contract_id": reporting.CONTRACT_ID, "schema_version": 1,
                "captured_at_utc": "2026-01-01T00:00:00Z", "bucket_start_utc": None,
                "source_observed_at_utc": None, "source_state": state, "object_count": 1,
                "payload_json": {"contract_id": reporting.CONTRACT_ID, "state": state,
                              "items": [{"object_guid": f"synthetic-{domain}",
                                         "entity_id": domain, "enabled": enabled}]}}


def select_pair(rows, domain):
    history = sorted((r for r in rows if r["domain_id"] == domain),
                     key=lambda r: (r["captured_at_utc"], r["snapshot_id"]), reverse=True)
    if not history:
        return []
    latest = history[0]
    compatible = [dict(r, domain_snapshot_count=len(history)) for r in history
                  if all(r[k] == latest[k] for k in ("scope_sha256", "contract_id", "schema_version"))]
    return deepcopy(compatible[:2])


def recorder(monkeypatch, rows=(), catalog=()):
    calls = []

    def query(sql, params=(), **kwargs):
        calls.append((sql, params, kwargs))
        if sql == "select id from domains order by id":
            return [{"id": d} for d in catalog]
        return [r for d in dict.fromkeys(params[0]) for r in select_pair(rows, d)]

    monkeypatch.setattr(reporting, "query_rows_bounded", query)
    return calls


@pytest.mark.parametrize("scope,budget", [([], 0), ([1], 1), ([1, 2], 1), (list(range(1, 11)), 1)])
def test_explicit_scope_has_one_comparison_read(monkeypatch, scope, budget):
    calls = recorder(monkeypatch)
    result = reporting._load_snapshot_comparison(scope)
    assert len(calls) == budget
    assert result["deletion_claim_allowed"] is False
    if scope:
        assert calls[0][1] == (scope,)


@pytest.mark.parametrize("catalog,budget", [([], 1), ([1], 2), ([1, 2], 2), (list(range(1, 11)), 2)])
def test_none_scope_adds_only_catalog_read(monkeypatch, catalog, budget):
    calls = recorder(monkeypatch, catalog=catalog)
    reporting._load_snapshot_comparison(None)
    assert len(calls) == budget


def test_batch_preserves_single_domain_results_order_duplicates_and_unknown(monkeypatch):
    rows = [snapshot(1, 10, enabled=False), snapshot(1, 11),
            snapshot(2, 20), snapshot(2, 21, scope="incompatible"),
            snapshot(3, 30), snapshot(4, 40), snapshot(4, 41, state="partial")]
    scope = [4, 2, 1, 3, 5, 1]
    recorder(monkeypatch, rows)
    expected = [{"domain_id": d, **reporting._load_snapshot_comparison([d])} for d in scope]
    calls = recorder(monkeypatch, rows)
    actual = reporting._load_snapshot_comparison(scope)
    assert actual["domains"] == expected
    assert actual["items"] == [{**item, "domain_id": d["domain_id"]}
                                for d in expected for item in d["items"]]
    assert actual["state"] == "partial"
    assert actual["change_count"] == len(actual["items"])
    assert actual["deletion_claim_allowed"] is False
    assert len(calls) == 1
    assert actual["domains"][1]["reason"] == "incompatible_snapshot_pair_not_compared"
    assert actual["domains"][3]["reason"] == "previous_compatible_snapshot_not_collected"
    assert actual["domains"][4]["reason"] == "snapshot_history_not_collected"


def test_complete_pairs_remain_available_and_payload_errors_propagate(monkeypatch):
    rows = [snapshot(1, 10), snapshot(1, 11), snapshot(2, 20), snapshot(2, 21)]
    recorder(monkeypatch, rows)
    assert reporting._load_snapshot_comparison([2, 1])["state"] == "available"
    rows[-1]["payload_json"]["contract_id"] = "synthetic.invalid"
    recorder(monkeypatch, rows)
    with pytest.raises(ValueError, match="incompatible_computers_v6_snapshots"):
        reporting._load_snapshot_comparison([1, 2])


def test_query_failure_propagates(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic read failure")
    monkeypatch.setattr(reporting, "query_rows_bounded", fail)
    with pytest.raises(RuntimeError, match="synthetic read failure"):
        reporting._load_snapshot_comparison([1, 2])


@pytest.mark.postgres_integration
@pytest.mark.skipif(not os.environ.get("ADLOG_TEST_PG_DSN"), reason="disposable PostgreSQL CI required")
def test_postgres_batch_selects_latest_compatible_pair_per_authorized_domain(monkeypatch):
    """Execute actual production SQL, not a fake SQL evaluator, in CI's clone."""
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb

    rows = [snapshot(1, 10), snapshot(1, 11, scope="other"), snapshot(1, 12, enabled=False),
            snapshot(2, 20), snapshot(2, 21), snapshot(2, 22), snapshot(3, 30),
            snapshot(4, 40), snapshot(4, 41, scope="other"),
            snapshot(99, 990), snapshot(99, 991)]
    # A later incompatible schema and contract must not become the previous pair.
    rows.extend([dict(snapshot(1, 8), schema_version=2),
                 dict(snapshot(1, 9), contract_id="synthetic.other")])
    # Timestamp precedence must beat a larger ID; equal timestamps must use ID.
    rows.append(snapshot(1, 13))
    offsets = {10: 20, 11: 25, 12: 30, 13: 10, 8: 28, 9: 29,
               20: 30, 21: 30, 22: 20}
    for row in rows:
        row["captured_at_utc"] = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(
            hours=offsets.get(row["snapshot_id"], 0),
        )
    assert [r["snapshot_id"] for r in select_pair(rows, 1)] == [12, 10]
    assert [r["snapshot_id"] for r in select_pair(rows, 2)] == [21, 20]
    scope = [4, 1, 5, 2, 3, 1]
    recorder(monkeypatch, rows)
    expected = [{"domain_id": d, **reporting._load_snapshot_comparison([d])} for d in scope]
    with psycopg.connect(os.environ["ADLOG_TEST_PG_DSN"], row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute("create temporary table domains(id bigint primary key)")
            cur.execute("""create temporary table computers_report_v6_snapshots (
                snapshot_id bigint,domain_id bigint,scope_sha256 text,contract_id text,schema_version integer,
                captured_at_utc timestamptz,bucket_start_utc timestamptz,source_observed_at_utc timestamptz,
                source_state text,object_count integer,payload_json jsonb)""")
            cur.executemany("insert into domains values (%s)", [(d,) for d in [1, 2, 3, 4, 5, 99]])
            for row in rows:
                values = dict(row, payload_json=Jsonb(row["payload_json"]))
                cur.execute("insert into computers_report_v6_snapshots values (" + ",".join(["%s"] * len(values)) + ")", tuple(values.values()))
            calls = []

            def query(sql, params=(), **kwargs):
                calls.append(sql)
                cur.execute(sql.replace("?", "%s"), params)
                return cur.fetchall()

            monkeypatch.setattr(reporting, "query_rows_bounded", query)
            actual = reporting._load_snapshot_comparison(scope)
            assert actual["domains"] == expected
            assert len(calls) == 1
            assert all(d["domain_id"] != 99 for d in actual["domains"])
            calls.clear()
            assert reporting._load_snapshot_comparison([])["state"] == "not_collected"
            assert calls == []
            calls.clear()
            all_domains = reporting._load_snapshot_comparison(None)
            assert [d["domain_id"] for d in all_domains["domains"]] == [1, 2, 3, 4, 5, 99]
            assert len(calls) == 2
        conn.rollback()
