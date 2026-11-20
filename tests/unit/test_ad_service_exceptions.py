"""Settings validation and transactional attribution with PostgreSQL fakes."""
import json

import pytest

from server.sli.core import ad_service_exceptions as exceptions, platform_settings

SID = "S-1-5-21-1-2-3-1001"
SID2 = "S-1-5-21-1-2-3-1002"
NOW = "2026-10-16T00:00:00Z"


@pytest.mark.parametrize("value", ["", "{}", "null", '["fixture"]', '["S-1-5-32-544"]',
                                    json.dumps([SID, SID.lower()]), json.dumps([{"sid": SID, "unexpected": True}])])
def test_invalid_exception_lists_are_rejected_before_any_write(monkeypatch, value):
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: pytest.fail("no write"))
    with pytest.raises(ValueError, match=exceptions.ERROR):
        platform_settings.set_setting(exceptions.SETTING_KEY, value, actor="fixture-admin")


def test_attribution_is_server_owned_retained_and_reset_after_removal():
    old = [{"sid": SID, "excluded_by": "fixture-first", "excluded_at": NOW}]
    forged = [{"sid": SID, "excluded_by": "forged", "excluded_at": "forged"},
              {"sid": SID2, "excluded_by": "forged", "excluded_at": "forged"}]
    result = json.loads(exceptions.attributed(json.dumps(forged), json.dumps(old), actor="fixture-second"))
    assert result[0] == old[0]
    assert result[1]["excluded_by"] == "fixture-second" and result[1]["excluded_at"] != "forged"
    assert exceptions.attributed("[]", json.dumps(result), actor="fixture-third") == "[]"
    restored = json.loads(exceptions.attributed(json.dumps([SID]), "[]", actor="fixture-third"))
    assert restored[0]["excluded_by"] == "fixture-third"


def test_setting_serializes_updates_reads_current_attribution_and_audits_before_commit(monkeypatch):
    old = [{"sid": SID, "excluded_by": "fixture-first", "excluded_at": NOW}]
    calls = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return self

        def execute(self, sql, params=()):
            calls.append((" ".join(sql.split()), params))

        def fetchone(self):
            return {"value": json.dumps(old)}

        def commit(self):
            calls.append(("commit", ()))

    monkeypatch.setattr(platform_settings, "_stored_row", lambda _key: None)
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", Connection)
    result = platform_settings.set_setting(exceptions.SETTING_KEY, json.dumps([SID.lower(), SID2]), actor="fixture-second",
                                           audit=lambda cur, value: calls.append(("audit", value)))
    assert calls[0][0] == "select pg_advisory_xact_lock(hashtext(%s))"
    assert calls[1][0].endswith("for update")
    assert json.loads(result["previous"]) == old
    assert json.loads(result["value"])[0] == old[0]
    assert json.loads(result["value"])[1]["excluded_by"] == "fixture-second"
    assert calls[-2:] == [("audit", result), ("commit", ())]
    monkeypatch.setattr(platform_settings, "_stored_row", lambda key: {"value": result["value"], "updated_by": "fixture-second", "updated_at": NOW} if key == exceptions.SETTING_KEY else None)
    item = next(item for item in platform_settings.list_settings() if item["key"] == exceptions.SETTING_KEY)
    assert item["source"] == "database" and item["updated_by"] == "fixture-second"
    assert exceptions.configured()[SID]["excluded_by"] == "fixture-first"


def test_exception_setting_defaults_to_an_empty_list_without_a_database(monkeypatch):
    monkeypatch.setattr(platform_settings, "_stored_row", lambda _key: None)
    assert platform_settings.get_setting(exceptions.SETTING_KEY) == "[]"
    assert exceptions.configured() == {}
