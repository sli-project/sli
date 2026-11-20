"""ad.users.v2: Cyrillic search and honest degradation when saved snapshots cannot be loaded."""

from __future__ import annotations

import pytest

from server.sli.reporting.v2.reports import users as report
from server.sli.reports import users_v2_reporting as engine


def _row(**kw):
    base = {"display_name": "Пётр Иванов", "sam": "pivanov", "upn": "", "mail": "p.ivanov@example.test", "phones": "",
            "department": "Бухгалтерия", "company": "", "title": "", "manager": "", "ou": "", "reason_keys": []}
    base.update(kw)
    return base


@pytest.mark.parametrize("q", ["иванов", "ИВАНОВ", "Петр", "пётр", "иван", "бухгал", "PIVANOV", "P.Ivanov@", "  иванов  "])
def test_search_is_case_insensitive_for_cyrillic_and_latin(q):
    assert report._matches({}, _row(), {"q": q, "relation": "effective"})


def test_search_miss_and_wildcards_are_literal():
    assert not report._matches({}, _row(), {"q": "сидоров"})
    assert not report._matches({}, _row(), {"q": "%"})
    assert not report._matches({}, _row(), {"q": "_"})


def test_previous_snapshot_not_loaded_for_list(monkeypatch):
    monkeypatch.setattr(engine, "build_users_v2_snapshot", lambda domain_ids: {"users": [{"id": 1}], "metadata": {}})

    def boom(*args, **kwargs):
        raise AssertionError("saved snapshots must not be queried")

    monkeypatch.setattr(engine, "query_rows_bounded", boom)
    payload = engine.load_users_v2_snapshots(domain_ids=None, include_previous=False)
    assert payload["state"] == "available" and payload["previous_state"] == "not_requested"


def test_saved_snapshot_failure_degrades_instead_of_failing(monkeypatch):
    monkeypatch.setattr(engine, "build_users_v2_snapshot", lambda domain_ids: {"users": [{"id": 1}], "metadata": {}})

    def oom(*args, **kwargs):
        raise MemoryError("out of memory for query result")

    monkeypatch.setattr(engine, "query_rows_bounded", oom)
    payload = engine.load_users_v2_snapshots(domain_ids=None)
    assert payload["previous"] is None and payload["previous_state"] == "unavailable"
    assert payload["current"]["users"] == [{"id": 1}]
