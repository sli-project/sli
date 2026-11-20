from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from server.sli.access import auth, report_api_key


@pytest.mark.parametrize("service", [False, True])
def test_service_origin_is_persisted_in_the_user_creation_transaction(monkeypatch, service):
    calls = []
    cursor = SimpleNamespace(
        execute=lambda sql, params: calls.append((sql, params)),
        fetchone=lambda: {"id": 42, "username": "synthetic-user"},
    )
    monkeypatch.setattr(auth, "ensure_auth_schema", lambda: None)
    monkeypatch.setattr(auth, "_connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    monkeypatch.setattr(auth, "PASSWORD_HASHER", SimpleNamespace(hash=lambda _: "synthetic-hash"))
    audits = []
    monkeypatch.setattr(auth, "_audit", lambda cur, **kw: audits.append((cur, kw)))

    auth.create_user(username="synthetic-user", password="synthetic-password", role="viewer", is_service=service)

    sql, params = calls[0]
    assert "is_service" in sql
    assert params == ("synthetic-user", "synthetic-hash", "viewer", service)
    assert len(calls) == 1
    assert audits[0][0] is cursor
    assert audits[0][1]["action"] == "user_created:42:synthetic-user"


def test_report_subject_has_durable_origin_before_failed_issuance(monkeypatch):
    cursor = SimpleNamespace(
        execute=lambda *_: None,
        fetchone=lambda: {"id": 7},
        fetchall=lambda: [{"report_key": key, "definition_json": {}} for key in report_api_key.REPORTS],
    )
    monkeypatch.setattr(auth, "_connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    created, disabled = [], []
    monkeypatch.setattr(auth, "create_user", lambda **kw: created.append(kw.get("is_service")) or {"id": 42})
    monkeypatch.setattr(auth, "update_user", lambda **kw: disabled.append(kw))

    def fail(*args, **kwargs):
        assert created[0] is True
        raise RuntimeError("synthetic issuance failure")

    monkeypatch.setattr(report_api_key, "_issue_for_subject", fail)
    with pytest.raises(RuntimeError, match="synthetic issuance failure"):
        report_api_key.issue_report_key(label="synthetic", domain_id=7)
    assert disabled == [{"user_id": 42, "is_active": False, "actor_type": "local_operator"}]
