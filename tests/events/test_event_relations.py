"""Bounded relation truncation is reported after unique evidence selection."""

import pytest

from server.sli.events import event_relations


@pytest.mark.parametrize("count,truncated", [(0, False), (1, False), (2, False), (3, True)])
def test_relations_probe_one_extra_row_without_changing_items(monkeypatch, count, truncated):
    calls = []

    def query(sql, params, **_kwargs):
        if "base_event.id = ?" in sql:
            return [{"server_id": 7, "time_created_utc": "2026-10-01T00:00:00Z",
                     "logon_id": "0x123", "task_name": None}]
        calls.append(params)
        return [{"related_event_db_id": index + 2, "related_event_id": 4624,
                 "relation_rule": "same_logon_id_same_server", "time_delta_seconds": index}
                for index in range(count)][:params[-1]]

    monkeypatch.setattr(event_relations, "query_rows_bounded", query)
    response = event_relations._v2_relations_response(1, 2)
    assert calls[0][-1] == 3
    assert response["truncated"] is truncated
    assert [item["related_event_db_id"] for item in response["items"]] == list(range(2, min(count, 2) + 2))
    assert response["api_version"] == "v1"
    assert response["event_db_id"] == 1
    assert response["contract"] == "explicit_event_link_or_rule_based_correlation"
    assert "rule_policy_score" in response["confidence_contract"]


@pytest.mark.parametrize("task_ids,truncated", [([2, 3], False), ([3, 4], True)])
def test_truncation_uses_unique_union_of_both_bounded_keys(monkeypatch, task_ids, truncated):
    def query(sql, params, **_kwargs):
        if "base_event.id = ?" in sql:
            return [{"server_id": 7, "time_created_utc": "2026-10-01T00:00:00Z",
                     "logon_id": "0x123", "task_name": "fixture-task"}]
        assert params[-1] == 3
        ids = [2, 3] if "other_event.logon_id = ?" in sql else task_ids
        return [{"related_event_db_id": related, "time_delta_seconds": related}
                for related in ids]

    monkeypatch.setattr(event_relations, "query_rows_bounded", query)
    response = event_relations._v2_relations_response(1, 2)
    assert [item["related_event_db_id"] for item in response["items"]] == [2, 3]
    assert response["truncated"] is truncated


def test_invalid_self_and_duplicate_rows_do_not_imply_truncation():
    rows = [{"related_event_db_id": related} for related in [0, -1, 1, 2, 2, 3, 3]]
    response = event_relations._v2_relations_contract(1, rows, 2)
    assert [item["related_event_db_id"] for item in response["items"]] == [2, 3]
    assert response["truncated"] is False


@pytest.mark.parametrize("requested,bound", [(0, 1), (1, 1), (100, 100), (999, 200)])
def test_public_limit_is_still_clamped_and_only_probes_one_extra(monkeypatch, requested, bound):
    calls = []
    monkeypatch.setattr(event_relations, "_require_v2_relations_route", lambda *_args: None)

    def query(_event_id, limit):
        calls.append(limit)
        return [{"related_event_db_id": index + 2} for index in range(limit)]

    monkeypatch.setattr(event_relations, "_query_v2_relation_rows", query)
    response = event_relations.get_event_relations(1, limit=requested)
    assert calls == [bound + 1]
    assert len(response["items"]) == bound
    assert response["truncated"] is True
