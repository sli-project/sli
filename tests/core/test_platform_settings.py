"""Report domain is DB-only; other settings retain their declared fallbacks."""

from __future__ import annotations

import pytest

from server.sli.core import platform_settings
from server.sli.core.report_domain import ReportDomainNotConfiguredError, report_domain_fqdn

ENV_NAME = "ADLOG_REPORT_DOMAIN_FQDN"


@pytest.fixture(autouse=True)
def _fresh_cache():
    platform_settings.clear_cache()
    yield
    platform_settings.clear_cache()


def _stored(monkeypatch: pytest.MonkeyPatch, value: str | None) -> list[tuple]:
    calls: list[tuple] = []

    def query_rows(sql, params=(), **_kwargs):
        if sql.startswith("select is_archived from domains") and value:
            return [{"is_archived": False}]
        calls.append((sql, params))
        return [] if value is None or params != ("reports.domain_fqdn",) else [{"value": value, "updated_by": "admin", "updated_at": "2026-10-01T00:00:00Z"}]

    monkeypatch.setattr(platform_settings.database, "query_rows", query_rows)
    return calls


def test_database_value_wins_over_environment_and_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _stored(monkeypatch, "Corp.Example.TEST")
    monkeypatch.setenv(ENV_NAME, "env.example.test")
    assert report_domain_fqdn() == "corp.example.test"
    item = platform_settings.list_settings()[0]
    assert item["key"] == "reports.domain_fqdn"
    assert item["source"] == "database"
    assert item["updated_by"] == "admin"


def test_environment_is_ignored_when_nothing_is_stored(monkeypatch: pytest.MonkeyPatch) -> None:
    _stored(monkeypatch, None)
    monkeypatch.setenv(ENV_NAME, "env.example.test")
    with pytest.raises(ReportDomainNotConfiguredError):
        report_domain_fqdn()
    assert platform_settings.list_settings()[0]["source"] == "not_configured"


def test_list_settings_marks_unset_setting_as_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    _stored(monkeypatch, None)
    monkeypatch.delenv(ENV_NAME, raising=False)
    item = platform_settings.list_settings()[0]
    assert item["key"] == "reports.domain_fqdn"
    assert item["source"] == "not_configured"
    assert item["value"] == ""
    assert item["environment"] == ""


def test_report_domain_has_no_non_database_default() -> None:
    spec = platform_settings.SETTINGS["reports.domain_fqdn"]
    assert spec.environment == ""
    assert spec.default is None


def test_unreachable_database_does_not_fall_back_to_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_args, **_kwargs):
        raise RuntimeError("relation platform_settings does not exist")

    monkeypatch.setattr(platform_settings.database, "query_rows", broken)
    monkeypatch.setenv(ENV_NAME, "env.example.test")
    monkeypatch.setenv("SLI_INSTALL_DOMAIN", "install.example.invalid")
    with pytest.raises(ReportDomainNotConfiguredError):
        report_domain_fqdn()
    item = platform_settings.list_settings()[0]
    assert (item["source"], item["value"]) == ("not_configured", "")


def test_ad_history_default_environment_override_and_validation(monkeypatch):
    _stored(monkeypatch, None)
    monkeypatch.delenv("SLI_AD_SNAPSHOT_HISTORY_DAYS", raising=False)
    assert platform_settings.get_setting("ad.snapshot_history_days") == "365"
    monkeypatch.setenv("SLI_AD_SNAPSHOT_HISTORY_DAYS", "730")
    assert platform_settings.get_setting("ad.snapshot_history_days") == "730"
    monkeypatch.setattr(platform_settings.database, "query_rows", lambda *a, **kw: [{"value": "180"}])
    platform_settings.clear_cache()
    assert platform_settings.get_setting("ad.snapshot_history_days") == "180"
    for invalid in ("6", "3651", "365.0"):
        with pytest.raises(ValueError, match="ad_snapshot_history_days"):
            platform_settings.set_setting("ad.snapshot_history_days", invalid, actor="synthetic-admin")


def test_database_value_is_cached_briefly(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _stored(monkeypatch, "corp.example.test")
    for _ in range(5):
        report_domain_fqdn()
    assert len(calls) == 1


def test_workstation_retention_keeps_its_environment_and_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _stored(monkeypatch, None)
    key = "workstations.evidence_retention_days"
    monkeypatch.setenv("SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS", "180")
    assert platform_settings.get_setting(key) == "180"
    monkeypatch.delenv("SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS")
    assert platform_settings.get_setting(key) == "90"


def test_workstation_logon_policy_version_is_locked_validated_and_audited(monkeypatch):
    from contextlib import nullcontext
    from server.sli.plugins.workstations import logon_policy

    _stored(monkeypatch, None)
    previous = '{"policies":[],"version":2}'
    calls = []

    class Cursor:
        def cursor(self):
            return nullcontext(self)

        def execute(self, sql, params=()):
            calls.append((" ".join(sql.split()), params))

        def fetchone(self):
            return {"value": previous}

        def commit(self):
            calls.append(("commit", ()))

    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: nullcontext(Cursor()))
    with pytest.raises(ValueError, match=logon_policy.ERROR):
        platform_settings.set_setting(logon_policy.SETTING_KEY, '{"version":1,"policies":[]}', actor="fixture-admin")
    assert len(calls) == 2
    assert "pg_advisory_xact_lock" in calls[0][0] and "for update" in calls[1][0]
    calls.clear()
    result = platform_settings.set_setting(logon_policy.SETTING_KEY, '{"version":3,"policies":[]}', actor="fixture-admin",
        audit=lambda _cur, change: calls.append(("audit", change)))
    assert result["previous"] == previous
    assert calls[2][0].startswith("insert into platform_settings")
    assert calls[-2:] == [("audit", result), ("commit", ())]


class _Cursor:
    def __init__(self, sink: list) -> None:
        self.sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        self.sink.append((" ".join(sql.split()), params))

    def fetchone(self):
        return {"id": 7} if self.sink[-1][1] == ("corp.example.test",) else None


class _Connection(_Cursor):
    def cursor(self):
        return _Cursor(self.sink)

    def commit(self):
        self.sink.append(("commit", ()))


def test_set_setting_validates_upserts_and_reports_previous_value(monkeypatch: pytest.MonkeyPatch) -> None:
    _stored(monkeypatch, None)
    monkeypatch.setenv(ENV_NAME, "env.example.test")
    sink: list = []
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: _Connection(sink))

    audited: list[dict] = []
    result = platform_settings.set_setting(
        "reports.domain_fqdn", " Corp.Example.TEST ", actor="admin",
        audit=lambda _cursor, change: (audited.append(change), sink.append(("audit", ()))),
    )

    assert result == {"key": "reports.domain_fqdn", "previous": None, "value": "corp.example.test"}
    assert sink[0] == ("select id from domains where lower(fqdn) = %s", ("corp.example.test",))
    assert sink[1][0].startswith("insert into platform_settings(key, value, updated_by, updated_at)")
    assert sink[1][1] == ("reports.domain_fqdn", "corp.example.test", "admin")
    assert audited == [result]
    assert sink[-2:] == [("audit", ()), ("commit", ())]


def test_unregistered_report_domain_is_rejected_without_write_or_audit(monkeypatch):
    _stored(monkeypatch, None)
    sink = []
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: _Connection(sink))
    with pytest.raises(ValueError, match="report_domain_not_registered"):
        platform_settings.set_setting(
            "reports.domain_fqdn", "unknown.example.test", actor="synthetic-admin",
            audit=lambda *_args: pytest.fail("no audit for rejected setting"),
        )
    assert sink == [("select id from domains where lower(fqdn) = %s", ("unknown.example.test",))]


def test_settings_api_rejects_unregistered_report_domain(monkeypatch):
    from server.api.routes import settings as routes_settings

    _stored(monkeypatch, None)
    sink = []
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: _Connection(sink))

    class Handler:
        _principal = {"username": "synthetic-admin"}

        def _authorize_mutation(self, **_kwargs):
            return True

        def _require_capability(self, _capability):
            return True

        def _read_json_body(self):
            return {"value": "unknown.example.test"}

        def _send_json(self, payload, status=200):
            self.sent = (payload, int(status))

    handler = Handler()
    assert routes_settings.try_handle_post(handler, "/api/v1/platform-settings/reports.domain_fqdn")
    assert handler.sent == ({"error": "report_domain_not_registered"}, 400)
    assert len(sink) == 1 and sink[0][0].startswith("select id from domains")


@pytest.mark.parametrize("value", ["", "example", "a'b.test", "a b.test"])
def test_set_setting_rejects_invalid_values_before_writing(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: pytest.fail("no write"))
    with pytest.raises(ValueError, match="value_must_be_dns_name"):
        platform_settings.set_setting("reports.domain_fqdn", value, actor="admin")


def test_unknown_setting_and_missing_actor_are_refused() -> None:
    with pytest.raises(ValueError, match="unknown_setting"):
        platform_settings.set_setting("reports.unknown", "x.test", actor="admin")
    with pytest.raises(ValueError, match="actor_required"):
        platform_settings.set_setting("reports.domain_fqdn", "corp.example.test", actor="")


def test_settings_api_requires_admin_mutation_and_access_manage(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.api.routes import settings as routes_settings

    calls: list[tuple] = []

    class Handler:
        client_address = ("127.0.0.1", 0)
        _principal = {"id": 1, "username": "admin"}

        def _authorize_mutation(self, *, required_role):
            calls.append(("role", required_role))
            return True

        def _require_capability(self, capability):
            calls.append(("capability", capability))
            return False

        def _send_json(self, *_args, **_kwargs):
            calls.append(("sent",))

    monkeypatch.setattr(routes_settings, "set_setting", lambda *_a, **_k: pytest.fail("no write without access.manage"))
    assert routes_settings.try_handle_post(Handler(), "/api/v1/platform-settings/reports.domain_fqdn") is True
    assert calls == [("role", "admin"), ("capability", "access.manage")]


@pytest.mark.parametrize("key,default", [("ad.password_max_age_days", "365"), ("ad.inactivity_days", "90")])
def test_ad_policy_default_and_audited_override(monkeypatch, key, default):
    _stored(monkeypatch, None)
    assert platform_settings.get_setting(key) == default
    sink = []
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: _Connection(sink))
    changes = []
    result = platform_settings.set_setting(key, " 120 ", actor="admin",
        audit=lambda _cur, change: (changes.append(change), sink.append(("audit", ()))))
    assert result == {"key": key, "previous": default, "value": "120"}
    assert changes == [result]
    assert sink[0][1] == (key, "120", "admin")
    assert sink[-2:] == [("audit", ()), ("commit", ())]


@pytest.mark.parametrize("key", ["ad.password_max_age_days", "ad.inactivity_days"])
@pytest.mark.parametrize("value", ["", "0", "3651", "-1", "1.5", "true", "1e2", "９０"])
def test_ad_policy_rejects_invalid_values_before_writing(monkeypatch, key, value):
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: pytest.fail("no write"))
    with pytest.raises(ValueError, match="value_must_be_days_1_3650"):
        platform_settings.set_setting(key, value, actor="admin")


@pytest.mark.parametrize("value", ["1", "3650"])
def test_ad_policy_accepts_range_boundaries(value):
    assert platform_settings.SETTINGS["ad.inactivity_days"].validate(value) == value


@pytest.mark.parametrize("suffix,default", [
    ("window_hours", "24"), ("min_accounts", "10"), ("min_sources", "5"),
    ("max_failures_per_account", "3"),
])
def test_distributed_spray_thresholds_have_validated_defaults_and_stored_overrides(monkeypatch, suffix, default):
    key = f"windows_auth.distributed_{suffix}"
    _stored(monkeypatch, None)
    assert platform_settings.get_setting(key) == default
    platform_settings.clear_cache()
    monkeypatch.setattr(platform_settings.database, "query_rows", lambda *_args, **_kwargs: [{"value": " 12 "}])
    assert platform_settings.get_setting(key) == "12"
    spec = platform_settings.SETTINGS[key]
    assert spec.validate("744") == "744"
    for invalid in ("", "0", "745", "-1", "1.5", "1e2", "１２"):
        with pytest.raises(ValueError, match="value_must_be_integer_1_744"):
            spec.validate(invalid)
