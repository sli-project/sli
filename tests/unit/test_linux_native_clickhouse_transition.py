"""Transition admission with fake measured readbacks; no DB or VM required."""
from copy import deepcopy

import pytest

from deploy.linux import native_clickhouse_transition as ch


def receipt(version):
    return {name: {"version": version,
                  "inventory": [{"database": "sli_" + name, "name": "events", "engine": "ReplacingMergeTree",
                                 "create_table_query": "CREATE TABLE events (id UInt64) ENGINE=ReplacingMergeTree ORDER BY id"}],
                  "databases": [{"name": "sli_" + name, "engine": "Atomic"}],
                  "tables": {"sli_" + name + ".events": {"logical_rows": 2, "raw_count": 2, "digest": "a" * 64}},
                  "parts": [{"database": "sli_" + name, "table": "events", "rows": 2, "bytes_on_disk": 200}],
                  "queries": {"json_final": [{"at": "2026-10-26 00:00:00.123456", "id": "2147483648"}]}}
            for name in ch.INSTANCES}


def test_direct_path_requires_measured_readbacks_for_both_instances():
    before, after = receipt(ch.SOURCE_VERSION), receipt(ch.TARGET_VERSION)
    hop = ch.verify_hop(before, after, ch.SOURCE_VERSION, ch.TARGET_VERSION)
    assert ch.verify_path(ch.plan_transition(), [hop])["transition_path"] == [ch.SOURCE_VERSION, ch.TARGET_VERSION]
    assert before == receipt(ch.SOURCE_VERSION)


@pytest.mark.parametrize(("field", "value", "reason"), [
    ("digest", "b" * 64, "digest"), ("logical_rows", 3, "logical_rows"), ("raw_count", 3, "raw_count"),
])
def test_mismatch_rejected_even_with_same_inventory(field, value, reason):
    after = receipt(ch.TARGET_VERSION)
    after["warm"]["tables"]["sli_warm.events"][field] = value
    with pytest.raises(ch.TransitionMismatch, match="^transition_" + reason + "_mismatch$"):
        ch.verify_hop(receipt(ch.SOURCE_VERSION), after, ch.SOURCE_VERSION, ch.TARGET_VERSION)


@pytest.mark.parametrize(("field", "reason"), [("inventory", "inventory_ddl"), ("parts", "physical_sizes"),
                                               ("queries", "reader"), ("databases", "database")])
def test_schema_size_reader_and_database_changes_rejected(field, reason):
    after = receipt(ch.TARGET_VERSION)
    if field == "inventory":
        after["history"][field][0]["create_table_query"] += " SETTINGS index_granularity=8192"
    elif field == "parts":
        after["history"][field][0]["bytes_on_disk"] += 1
    elif field == "queries":
        after["history"][field]["json_final"][0]["at"] = "2026-10-26 00:00:00.123457"
    else:
        after["history"][field][0]["engine"] = "Ordinary"
    with pytest.raises(ch.TransitionMismatch, match="^transition_" + reason + "_mismatch$"):
        ch.verify_hop(receipt(ch.SOURCE_VERSION), after, ch.SOURCE_VERSION, ch.TARGET_VERSION)


@pytest.mark.parametrize("mutation", ["instance", "missing", "empty", "duplicate", "table", "digest", "version"])
def test_incomplete_readback_never_verifies(mutation):
    before, after = receipt(ch.SOURCE_VERSION), receipt(ch.TARGET_VERSION)
    if mutation == "instance":
        after.pop("warm")
    elif mutation == "missing":
        after["warm"].pop("parts")
    elif mutation == "empty":
        before["warm"]["inventory"] = after["warm"]["inventory"] = []
    elif mutation == "duplicate":
        after["warm"]["inventory"] *= 2
    elif mutation == "table":
        after["warm"]["tables"] = {}
    elif mutation == "digest":
        after["warm"]["tables"]["sli_warm.events"]["digest"] = "not-a-hash"
    else:
        after["warm"]["version"] = ch.SOURCE_VERSION
    with pytest.raises(ch.TransitionMismatch):
        ch.verify_hop(before, after, ch.SOURCE_VERSION, ch.TARGET_VERSION)


def test_proposed_fallback_is_unverified_until_every_hop_is_measured():
    plan = ch.plan_transition("26.3.9.1")
    assert plan.versions == (ch.SOURCE_VERSION, "26.3.9.1", ch.TARGET_VERSION)
    first = ch.verify_hop(receipt(ch.SOURCE_VERSION), receipt("26.3.9.1"), ch.SOURCE_VERSION, "26.3.9.1")
    with pytest.raises(ch.TransitionMismatch, match="transition_hop_missing"):
        ch.verify_path(plan, [first])
    second = ch.verify_hop(receipt("26.3.9.1"), receipt(ch.TARGET_VERSION), "26.3.9.1", ch.TARGET_VERSION)
    assert ch.verify_path(plan, [first, second])["status"] == "verified"
    corrupt = deepcopy(second)
    corrupt["status"] = "in_progress"
    with pytest.raises(ch.TransitionMismatch, match="transition_hop_unverified"):
        ch.verify_path(plan, [first, corrupt])


def test_intermediate_must_be_an_explicit_26_3_patch():
    with pytest.raises(ValueError, match="intermediate_not_26_3_lts"):
        ch.plan_transition("26.3")


@pytest.mark.parametrize("versions", [(), (ch.TARGET_VERSION,), (ch.TARGET_VERSION, ch.SOURCE_VERSION)])
def test_empty_or_reversed_custom_plan_cannot_verify_without_a_transition(versions):
    with pytest.raises(ch.TransitionMismatch, match="transition_path_invalid"):
        ch.verify_path(ch.TransitionPlan(versions), [])
