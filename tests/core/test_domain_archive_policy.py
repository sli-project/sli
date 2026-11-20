"""Explicit archive metadata is independent of source freshness and grants."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from server.sli.core import report_domain
from server.sli.access import domain_scope


def row(id, archived=False, observed=None):
    return {"id": id, "display_name": f"domain-{id}.example.test", "is_archived": archived,
            "observed_at_utc": observed}


def test_archive_never_joins_implicit_ad_report_scope(monkeypatch):
    monkeypatch.setattr(domain_scope, "resolve_access_scope", lambda *_: type("S", (), {"domain_ids": lambda _: [1, 2]})())
    monkeypatch.setattr(domain_scope, "_domain_rows", lambda ids: [r for r in [row(1), row(2, True)] if r["id"] in ids])
    assert domain_scope.resolve_report_domain_selection({}, SimpleNamespace(report_key="ad.computers.v6"), {}).domain_ids == [1]
    assert domain_scope.resolve_report_domain_selection({}, SimpleNamespace(report_key="ad.computers.v6"), {"domain_id": ["2"]}).domain_ids == [2]


def test_archive_metadata_is_not_freshness():
    value = domain_scope._selection(2, [row(2, True)]).domains[0]
    assert value["is_archived"] is True
    assert "is_archived" not in value["freshness"]


def test_preferred_nonarchive_domain_is_not_overridden_by_age():
    rows = [row(1, observed="2000-01-01T00:00:00Z"), row(2, observed="2026-01-01T00:00:00Z")]
    assert report_domain.preferred_domain(rows, "domain-1.example.test")["id"] == 1


def test_archived_preference_uses_observed_not_published_or_event_time():
    rows = [row(1, True, "2026-01-01T00:00:00Z"), row(2, observed="2025-01-01T00:00:00Z"),
            {**row(3), "published_at_utc": "2026-02-01T00:00:00Z", "event_at_utc": "2026-02-01T00:00:00Z"}]
    assert report_domain.preferred_domain(rows, "domain-1.example.test")["id"] == 2


@pytest.mark.parametrize("rows", [[], [row(1, True)], [row(1)], [row(1, observed="bad")], [row(1, observed="2999-01-01T00:00:00Z")]])
def test_no_eligible_evidence_has_no_invented_default(rows):
    assert report_domain.preferred_domain(rows, None) is None


def test_datetime_and_iso_dates_compare_with_stable_tie():
    rows = [row(2, observed=datetime(2025, 1, 1, tzinfo=timezone.utc)), row(1, observed="2025-01-01T00:00:00Z")]
    assert report_domain.preferred_domain(rows, None)["id"] == 1


@pytest.mark.parametrize("value", [None, 1, 0, "true", [], {}])
def test_archive_mutation_rejects_nonboolean_before_connecting(monkeypatch, value):
    from server.sli.core import setup_domains
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: pytest.fail("must not connect"))
    with pytest.raises(ValueError, match="domain_archive_must_be_boolean"):
        setup_domains.update_archive("domain-1.example.test", value)


def test_archive_update_is_audited_in_same_transaction(monkeypatch):
    from server.sli.core import setup_domains
    log = []
    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def execute(self, sql, params=()): log.append((sql, params))
        def fetchone(self): return {"is_archived": False}
    class Connection(Cursor):
        def cursor(self): return Cursor()
        def commit(self): log.append(("commit", ()))
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", Connection)
    result = setup_domains.update_archive("Domain-1.Example.Test", True, audit=lambda cur, result: log.append(("audit", result)))
    assert result == {"fqdn": "domain-1.example.test", "is_archived": True, "previous_is_archived": False}
    assert [item[0] for item in log][-2:] == ["audit", "commit"]
    assert any("for update" in item[0] for item in log)
    assert not any("netbios_name" in item[0] for item in log)


def test_effective_default_keeps_saved_preference_but_never_rewrites_it(monkeypatch):
    from server.sli.core import database
    calls = []
    def query(sql, params=()):
        calls.append(sql)
        return [{"is_archived": True}] if params else [row(1, True), row(2, observed="2025-01-01T00:00:00Z")]
    monkeypatch.setattr(database, "query_rows", query)
    assert report_domain.effective_domain_fqdn("domain-1.example.test") == "domain-2.example.test"
    assert all("update " not in sql.lower() and "insert " not in sql.lower() for sql in calls)


def test_present_unknown_completed_observation_does_not_fall_back_to_manifest_clock():
    rows = [{**row(1, observed="2026-01-01T00:00:00Z"), "default_observed_at_utc": None}]
    assert report_domain.preferred_domain(rows, None) is None


def test_completed_observation_chooses_domain_without_published_manifest():
    rows = [{**row(1), "default_observed_at_utc": "2025-01-01T00:00:00Z"}]
    assert report_domain.preferred_domain(rows, None)["id"] == 1


def test_automatic_domain_is_dns_validated_before_legacy_sql_use(monkeypatch):
    from server.sli.core import database
    monkeypatch.setattr(database, "query_rows", lambda *_: [{**row(1, observed="2025-01-01T00:00:00Z"), "display_name": "bad'name.example.test"}])
    with pytest.raises(ValueError, match="value_must_be_dns_name"):
        report_domain.effective_domain_fqdn(None)


def test_archive_does_not_hide_security_findings_in_shared_home_resolver(monkeypatch):
    monkeypatch.setattr(domain_scope, "resolve_access_scope", lambda *_: type("S", (), {"domain_ids": lambda _: [1, 2]})())
    monkeypatch.setattr(domain_scope, "_domain_rows", lambda ids: [row(1), row(2, True)])
    rule = SimpleNamespace(report_key="security.problems")
    assert domain_scope.resolve_report_domain_selection({}, rule, {}).domain_ids == [1, 2]


@pytest.mark.parametrize("archived", [False, None])
def test_recommendation_never_replaces_nonarchive_or_unregistered_preference(monkeypatch, archived):
    from server.sli.core import database
    monkeypatch.setattr(database, "query_rows", lambda *_: [] if archived is None else [{"is_archived": archived}])
    assert report_domain.suggested_domain_fqdn("domain-1.example.test", 86430) is None


@pytest.mark.parametrize("observed", [None, "invalid", "2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z", "2026-01-01T00:00:00"])
def test_recommendation_rejects_untrusted_or_old_observation(monkeypatch, observed):
    from server.sli.core import database
    monkeypatch.setattr(database, "query_rows", lambda sql, params=(): [{"is_archived": True}] if params else [row(2, observed=observed)])
    assert report_domain.suggested_domain_fqdn("domain-1.example.test", 86430) is None


def test_recommendation_uses_completed_observation_and_never_writes(monkeypatch):
    from server.sli.core import database
    calls = []
    def query(sql, params=()):
        calls.append(sql)
        if params:
            return [{"is_archived": True}]
        assert "run.status = 'completed'" in sql
        assert "max(run.observed_at_utc)" in sql
        return [row(1, True), row(2, observed=datetime.now(timezone.utc) - timedelta(minutes=1))]
    monkeypatch.setattr(database, "query_rows", query)
    assert report_domain.suggested_domain_fqdn("domain-1.example.test", 86430) == "domain-2.example.test"
    assert all(sql.lstrip().startswith("select") for sql in calls)


@pytest.mark.parametrize("window", [None, 0, -1])
def test_recommendation_with_unknown_freshness_policy_is_absent(monkeypatch, window):
    from server.sli.core import database
    monkeypatch.setattr(database, "query_rows", lambda *_: pytest.fail("unknown policy must not select"))
    assert report_domain.suggested_domain_fqdn("domain-1.example.test", window) is None
