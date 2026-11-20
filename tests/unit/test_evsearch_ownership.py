"""ES06 storage ownership and coverage with detached synthetic captures only."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from server.sli.events import evsearch_ownership as ownership
from server.sli.events.evsearch_normalizer import normalize_request
from server.sli.events.evsearch_snapshot import _query_hash


END = datetime(2026, 10, 19, tzinfo=timezone.utc)
START = END - timedelta(days=1)
MID = START + timedelta(hours=12)


def search(**changes):
    return normalize_request({"contract_version": "evsearch.v1", **changes}, now=END)


def capture(store, ids=(), *, query=None, timestamps=None, fingerprint="AB" * 32):
    query = query or search()
    timestamps = timestamps or [MID] * len(ids)
    return ownership.StoreCapture(
        store, "same-authorized-execution", _query_hash(query), f"{store}-watermark",
        tuple({"id": event_id, "message_sample": "synthetic retained fact"} for event_id in ids),
        tuple(ownership.EventIdentity.from_values(event_id, fingerprint, stamp)
              for event_id, stamp in zip(ids, timestamps)),
    )


def merge(hot=(), cold=(), **changes):
    return ownership.merge_captures(search(), hot=capture("postgres", hot), cold=capture("clickhouse", cold), **changes)


@pytest.mark.parametrize("hot,cold,expected", [
    ((1, 2), (), ((2, "postgres"), (1, "postgres"))),
    ((), (1, 2), ((2, "clickhouse"), (1, "clickhouse"))),
    ((2, 3), (1, 2), ((3, "postgres"), (2, "postgres"), (1, "clickhouse"))),
])
def test_full_hot_cold_and_overlap_have_one_owner_before_counting(hot, cold, expected):
    result = merge(hot, cold)
    assert result.manifest.owners == expected
    assert len(result.items) == len(set(hot) | set(cold))
    assert result.coverage == result.storage_coverage.status == "unknown"
    assert result.manifest.watermarks == (("postgres", "postgres-watermark"), ("clickhouse", "clickhouse-watermark"))
    assert "synthetic retained fact" not in repr(result)


def test_old_pg_rows_survive_a_publication_gap_and_retention_boundary():
    # Even an empty historical result cannot discard old surviving PG rows.
    result = merge((1,), (), retention_boundary=MID, evidence=(
        ownership.StorageInterval(MID, END, "postgres", "postgres-watermark"),
    ))
    assert result.items[0]["id"] == 1
    assert result.manifest.retention_boundary == MID
    assert result.storage_coverage.status == "partial"
    assert result.storage_coverage.unconfirmed == ((START, MID),)
    assert result.coverage == "unknown"


def test_empty_copy_gap_is_unknown_never_a_proven_zero():
    result = merge()
    assert result.items == ()
    assert result.storage_coverage.status == result.coverage == "unknown"
    assert result.storage_coverage.unconfirmed == ((START, END),)


def test_confirmed_intervals_are_clipped_unioned_and_do_not_prove_collection():
    result = merge(evidence=(
        ownership.StorageInterval(START - timedelta(hours=1), MID, "clickhouse", "clickhouse-watermark"),
        ownership.StorageInterval(MID - timedelta(hours=1), END, "postgres", "postgres-watermark"),
        ownership.StorageInterval(MID, END + timedelta(hours=1), "postgres", "postgres-watermark"),
    ))
    assert result.storage_coverage.status == "complete"
    assert result.storage_coverage.confirmed == ((START, END),)
    assert result.storage_coverage.unconfirmed == ()
    assert result.coverage == "unknown"


def test_surviving_pg_proof_can_close_copy_gap_but_one_pg_row_cannot():
    cold = ownership.StorageInterval(START, MID, "clickhouse", "clickhouse-watermark")
    assert merge((1,), evidence=(cold,)).storage_coverage.status == "partial"
    hot = ownership.StorageInterval(MID, END, "postgres", "postgres-watermark")
    assert merge((1,), evidence=(cold, hot)).storage_coverage.status == "complete"


@pytest.mark.parametrize("change", ["fingerprint", "timestamp"])
def test_conflicting_copies_fail_instead_of_choosing_a_store(change):
    cold = capture("clickhouse", (1,), fingerprint="CD" * 32 if change == "fingerprint" else "AB" * 32,
                   timestamps=[MID + timedelta(seconds=1)] if change == "timestamp" else None)
    with pytest.raises(ownership.OwnershipError) as error:
        ownership.merge_captures(search(), hot=capture("postgres", (1,)), cold=cold)
    assert str(error.value) == "evsearch.storage_integrity_error"
    assert "synthetic" not in str(error.value)


@pytest.mark.parametrize("store", ["postgres", "clickhouse"])
def test_duplicates_within_a_store_are_integrity_errors(store):
    args = {"hot": capture("postgres"), "cold": capture("clickhouse")}
    args["hot" if store == "postgres" else "cold"] = capture(store, (1, 1))
    with pytest.raises(ownership.OwnershipError, match="storage_integrity_error"):
        ownership.merge_captures(search(), **args)


def test_unavailable_cold_preserves_hot_rows_without_coverage_claims():
    cold = replace(capture("clickhouse"), status="unavailable", watermark="")
    result = ownership.merge_captures(search(), hot=capture("postgres", (1,)), cold=cold)
    assert len(result.items) == 1
    assert result.storage_coverage.status == "unknown"
    assert result.storage_coverage.unconfirmed == ((START, END),)
    assert result.manifest.statuses == (("postgres", "ready"), ("clickhouse", "unavailable"))


def test_fingerprint_case_bytes_and_equivalent_timezones_identify_the_same_copy():
    hot = capture("postgres", (1,))
    identity = ownership.EventIdentity.from_values(1, bytes.fromhex("ab" * 32),
                                                  MID.astimezone(timezone(timedelta(hours=2))))
    cold = replace(capture("clickhouse", (1,)), identities=(identity,))
    result = ownership.merge_captures(search(), hot=hot, cold=cold)
    assert result.manifest.owners == ((1, "postgres"),)


@pytest.mark.parametrize("change", ["binding", "query", "page", "identity", "projection", "unavailable_rows"])
def test_unbound_incomplete_or_inconsistent_capture_is_rejected(change):
    hot, cold = capture("postgres", (1,)), capture("clickhouse")
    if change == "binding":
        cold = replace(cold, binding="different-scope-or-publication")
    elif change == "query":
        cold = replace(cold, query_hash="different-query")
    elif change == "page":
        hot = replace(hot, exhaustive=False)
    elif change == "identity":
        hot = replace(hot, identities=())
    elif change == "projection":
        hot = replace(hot, items=({"id": 9},))
    else:
        hot = replace(hot, status="unavailable")
    with pytest.raises(ownership.OwnershipError, match="storage_(integrity_error|limit_exceeded)"):
        ownership.merge_captures(search(), hot=hot, cold=cold)


@pytest.mark.parametrize("start,end,store,watermark", [
    (MID, MID, "postgres", "postgres-watermark"),
    (END, START, "postgres", "postgres-watermark"),
    (START, END, "other", "postgres-watermark"),
    (START, END, "clickhouse", "newer-publication"),
])
def test_coverage_must_match_the_pinned_available_store(start, end, store, watermark):
    with pytest.raises(ownership.OwnershipError, match="storage_integrity_error"):
        merge(evidence=(ownership.StorageInterval(start, end, store, watermark),))


@pytest.mark.parametrize("stamp,accepted", [(START, True), (END, False), (START - timedelta(microseconds=1), False)])
def test_period_boundaries_are_half_open(stamp, accepted):
    hot = capture("postgres", (1,), timestamps=[stamp])
    if accepted:
        assert ownership.merge_captures(search(), hot=hot, cold=capture("clickhouse")).items
    else:
        with pytest.raises(ownership.OwnershipError, match="storage_integrity_error"):
            ownership.merge_captures(search(), hot=hot, cold=capture("clickhouse"))


def test_sort_and_hidden_identity_work_when_id_is_not_a_published_field():
    query = search(sort="time_asc", page_size=1)
    hot = capture("postgres", (3, 1), query=query)
    hot = replace(hot, items=({"channel": "Security"}, {"channel": "Security"}))
    cold = capture("clickhouse", (2,), query=query)
    cold = replace(cold, items=({"channel": "Security"},))
    result = ownership.merge_captures(query, hot=hot, cold=cold)
    assert result.manifest.owners == ((1, "postgres"), (2, "clickhouse"), (3, "postgres"))
    assert result.items == ({"channel": "Security"},) * 3


def test_result_is_detached_from_capture_mutations():
    hot = capture("postgres", (1,))
    result = ownership.merge_captures(search(), hot=hot, cold=capture("clickhouse"))
    hot.items[0]["id"] = 99
    assert result.items[0]["id"] == 1


def test_combined_budget_is_checked_after_deduplication(monkeypatch):
    monkeypatch.setattr(ownership, "MAX_EVENTS", 2)
    assert len(merge((1, 2), (1, 2)).items) == 2
    with pytest.raises(ownership.OwnershipError, match="storage_limit_exceeded"):
        merge((1, 2), (2, 3))
    monkeypatch.setattr(ownership, "MAX_SNAPSHOT_BYTES", 4)
    with pytest.raises(ownership.OwnershipError, match="storage_limit_exceeded"):
        merge((1,))


def test_merge_deadline_is_not_renewed_between_stores():
    tick = iter([0, 0.001, 0.002])
    with pytest.raises(ownership.OwnershipError, match="storage_timeout"):
        merge((1,), (2,), timeout_ms=2, clock=lambda: next(tick))


@pytest.mark.parametrize("event_id,fingerprint,stamp", [
    (True, "AB" * 32, MID), (0, "AB" * 32, MID), (1, None, MID),
    (1, "invalid", MID), (1, "AB" * 32, MID.replace(tzinfo=None)),
])
def test_invalid_storage_identity_is_never_used_for_deduplication(event_id, fingerprint, stamp):
    with pytest.raises(ownership.OwnershipError, match="storage_integrity_error"):
        ownership.EventIdentity.from_values(event_id, fingerprint, stamp)


def test_storage_error_codes_have_both_translations():
    root = Path(__file__).resolve().parents[2]
    dictionaries = [json.loads((root / f"config/i18n/server.{locale}.json").read_text(encoding="utf-8"))
                    for locale in ("ru", "en")]
    assert dictionaries[0].keys() == dictionaries[1].keys()
    for code in ("storage_integrity_error", "storage_limit_exceeded", "storage_timeout"):
        assert all(messages[f"evsearch.{code}"] for messages in dictionaries)
