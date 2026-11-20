from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from server.sli.plugins.ad import spn_collisions as spn
from server.sli.plugins.remote_access import session_overlap as vpn


NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)


def owner(entity_id, names, *, domain_id=1, run_id="snapshot-1", **attrs):
    return {
        "entity_id": entity_id, "domain_id": domain_id, "run_id": run_id,
        "entity_type": "ad_user", "observed_at_utc": NOW,
        "attributes_json": {"identity": {"object_guid": f"synthetic-{entity_id}"},
                            "attributes": {"service_principal_names": names, **attrs}},
    }


def session(row_id, start, end=None, *, last=None, generation=1, entity_id=1):
    return {
        "session_row_id": row_id, "domain_id": 1, "entity_id": entity_id,
        "generation": generation, "started_at_utc": f"2026-01-01T{start}:00Z",
        "stopped_at_utc": f"2026-01-01T{end}:00Z" if end else None,
        "last_observed_at_utc": f"2026-01-01T{last or end or start}:00Z",
        "completeness": "complete" if end else "missing_stop",
    }


def test_spn_case_only_normalization_and_distinct_owners():
    rows = [owner(1, ["HTTP/synthetic:443/path", "http/SYNTHETIC:443/PATH"]),
            owner(2, ["http/synthetic:443/path", "http/synthetic/path"]),
            owner(3, ["HTTP/synthetic:443/path"], run_id="snapshot-2"),
            owner(4, ["HTTP/synthetic:443/path"], domain_id=2)]
    result = spn.analyze(rows, now=NOW)
    assert len(result["items"]) == 2
    assert {row["entity_id"] for row in result["items"]} == {1, 2}
    assert {row["owner_count"] for row in result["items"]} == {2}
    assert result["metrics"]["collisions"] == 1
    assert result["metrics"]["unknown_owners"] == 2


def test_spn_owner_state_and_password_age_do_not_invent_defaults():
    result = spn.analyze([
        owner(1, ["HTTP/synthetic"], enabled=False, trusted_for_delegation=True,
              trusted_to_auth_for_delegation=False, does_not_require_preauth=True,
              password_last_set_utc="2025-12-30T00:00:00Z", msds_supported_encryption_types=24),
        owner(2, ["http/SYNTHETIC"]),
    ], now=NOW)
    first, second = result["items"]
    assert first["enabled"] is False
    assert first["password_age_days"] == 3
    assert first["msds_supported_encryption_types"] == 24
    assert second["enabled"] is None
    assert second["password_age_days"] is None
    assert second["does_not_require_preauth"] is None
    assert second["owner_quality"] == "unknown"


def test_spn_missing_stable_identity_is_separate():
    unknown = owner(2, ["http/synthetic"])
    unknown["attributes_json"]["identity"] = {}
    result = spn.analyze([owner(1, ["HTTP/synthetic"]), unknown], now=NOW)
    assert result["items"] == []
    assert result["unknown_identity_count"] == 1


def test_vpn_open_sessions_end_at_last_observation_and_touch_is_not_overlap():
    result = vpn.analyze([
        session("a", "10:00", last="10:20"),
        session("b", "10:10", "10:30"),
        session("c", "10:30", "11:00"),
    ], "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    assert len(result["items"]) == 1
    assert result["items"][0]["overlap_seconds"] == 600
    assert result["items"][0]["interval_quality"] == "observed"
    assert result["metrics"]["confirmed_seconds"] == 0
    assert result["metrics"]["max_concurrent"] == 2


def test_vpn_generations_unknown_accounts_replays_and_window_are_separate():
    rows = [session("a", "10:00", "11:00"), session("b", "10:10", "10:40"),
            session("b", "10:10", "10:40"),
            session("c", "10:20", "10:50", generation=2),
            session("d", "10:20", "10:50", entity_id=None),
            session("e", "10:20", "10:50", entity_id=None)]
    result = vpn.analyze(rows, "2026-01-01T10:20:00Z", "2026-01-01T10:30:00Z")
    assert len(result["items"]) == 3
    assert any(row["generation_a"] != row["generation_b"] for row in result["items"])
    assert {(row["session_a"], row["session_b"]) for row in result["items"]} == {("a", "b"), ("a", "c"), ("b", "c")}
    assert result["items"][0]["overlap_seconds"] == 600
    assert result["metrics"]["confirmed_seconds"] == 600
    assert result["unknown_identity_count"] == 2
    assert result["metrics"]["accounts"] == 1


def test_vpn_confirmed_time_is_union_not_sum_of_pairs():
    rows = [session("a", "10:00", "11:00"), session("b", "10:10", "10:40"),
            session("c", "10:20", "10:30")]
    result = vpn.analyze(rows, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    assert len(result["items"]) == 3
    assert result["metrics"]["max_concurrent"] == 3
    assert result["metrics"]["confirmed_seconds"] == 1800


class Cursor:
    def __init__(self, batches):
        self.batches = iter(batches)
        self.sql = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=()):
        self.sql.append((sql, params))

    def fetchall(self):
        return next(self.batches)

    def fetchone(self):
        return next(self.batches)

    def cursor(self):
        return self


def test_spn_reader_pins_evidence_and_version_to_one_run(monkeypatch):
    source = {"run_id": "snapshot-1", "domain_id": 1, "observed_at_utc": NOW,
              "run_status": "completed", "section_status": "complete",
              "scope_json": {"search_base": "synthetic-scope"}}
    cur = Cursor([[source], [owner(1, ["HTTP/synthetic"]), owner(2, ["http/SYNTHETIC"])]])
    monkeypatch.setattr(spn, "get_runtime_connection", lambda: cur)
    data = spn.get_collisions(domain_ids=[1], now=NOW)
    assert len(data["items"]) == 2
    sql = " ".join(query for query, _ in cur.sql)
    assert "valid_from_utc" in sql and "valid_to_utc" in sql
    assert "source_run_id" in sql and "record_key" in sql
    assert "scope_json" in sql and "limit %s" in sql
    assert "any(%s)" in sql


def test_vpn_denied_does_not_open_connection(monkeypatch):
    monkeypatch.setattr(vpn, "vpn_report_composition_decision", lambda *a, **k:
                        SimpleNamespace(sessions=SimpleNamespace(allowed=False)))
    monkeypatch.setattr(vpn, "get_runtime_connection", lambda: pytest.fail("unauthorized read"))
    data = vpn.get_overlaps({}, source_domain_id=1, time_from="2026-01-01T00:00:00Z",
                            time_to="2026-01-02T00:00:00Z")
    assert data["state"] == "not_authorized"


def test_vpn_empty_projection_is_no_accounting_not_zero_overlap(monkeypatch):
    monkeypatch.setattr(vpn, "vpn_report_composition_decision", lambda *a, **k:
                        SimpleNamespace(sessions=SimpleNamespace(allowed=True)))
    cur = Cursor([{"total_delivery_count": 1, "projected_session_count": 0}, []])
    monkeypatch.setattr(vpn, "get_runtime_connection", lambda: cur)
    data = vpn.get_overlaps({}, source_domain_id=1, time_from="2026-01-01T00:00:00Z",
                            time_to="2026-01-02T00:00:00Z")
    assert data["state"] == "not_collected"
    assert data["reason"] == "no_accounting_data"
    assert data["metrics"] == {}
    sql = " ".join(query for query, _ in cur.sql)
    assert "radius_vpn_session_rows_v1" in sql
    assert "domain_id=%s" in sql and "limit %s" in sql


def test_vpn_refuses_unbounded_period():
    with pytest.raises(ValueError):
        vpn.get_overlaps({}, source_domain_id=1, time_from="2026-01-01T00:00:00Z",
                         time_to="2026-04-02T00:00:00Z")


def test_spn_filters_keep_total_owners_and_unknown_flag_is_not_false():
    rows = [owner(1, ["HTTP/synthetic"], enabled=False), owner(2, ["http/SYNTHETIC"], enabled=True)]
    result = spn.analyze(rows, now=NOW, params={"spn_service": "http", "spn_enabled": "false"})
    assert [row["entity_id"] for row in result["items"]] == [1]
    assert result["items"][0]["owner_count"] == 2
    assert spn.analyze(rows, now=NOW, params={"spn_delegation": "false"})["items"] == []


def test_vpn_minimum_and_complete_interval_filters():
    rows = [session("a", "10:00", "11:00"), session("b", "10:10", last="10:20")]
    assert vpn.analyze(rows, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z",
                       params={"overlap_complete": "true"})["items"] == []
    assert vpn.analyze(rows, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z",
                       params={"overlap_min_seconds": 601})["items"] == []


def test_vpn_pair_bound_marks_totals_unknown(monkeypatch):
    monkeypatch.setattr(vpn, "MAX_PAIRS", 1)
    result = vpn.analyze([session("a", "10:00", "11:00"), session("b", "10:10", "10:40"),
                          session("c", "10:20", "10:30")],
                         "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    assert len(result["items"]) == 1
    assert result["truncated"] is True
    assert result["metrics"] == {}


@pytest.mark.parametrize("section_status,state", [("complete", "stale"), ("partial", "partial"), ("failed", "unavailable")])
def test_spn_source_quality_is_not_empty_success(monkeypatch, section_status, state):
    source = {"run_id": "snapshot-1", "domain_id": 1, "observed_at_utc": "2025-12-28T00:00:00Z",
              "run_status": "completed", "section_status": section_status,
              "scope_json": {"search_base": "synthetic-scope"}}
    cur = Cursor([[source], []])
    monkeypatch.setattr(spn, "get_runtime_connection", lambda: cur)
    assert spn.get_collisions(domain_ids=[1], now=NOW)["state"] == state


def context(tab, *, action="view", **params):
    from server.sli.reporting.v2.definition import QueryContext

    return QueryContext(access={}, params=params, domain_ids=[1], action=action,
                        cursor=None, limit=50, timezone="UTC", tab=tab)


def test_spn_tab_uses_plugin_reader_and_exports_its_columns(monkeypatch):
    from server.sli.reporting.v2.reports import ad_state

    monkeypatch.setattr(ad_state, "get_active_directory_report", lambda **kw: pytest.fail("unrelated branch"))
    monkeypatch.setattr(ad_state, "get_collisions", lambda **kw: {
        "state": "partial", "items": [{"spn": "HTTP/synthetic", "entity_id": 1, "owner_count": 2}],
        "metrics": {}, "coverage": {"truncated": True}, "truncated": True,
    })
    query = context("spn_collisions", action="export", q="HTTP")
    assert ad_state._query(query)["collections"]["spn_collisions"][0]["entity_id"] == 1
    body, meta = ad_state._export(query)
    assert body.startswith("SPN,Владельцев,Домен (ID),Владелец,")
    assert meta == {"rows": 1, "truncated": True}


def test_vpn_overlap_tab_does_not_load_employee_or_authentication_branches(monkeypatch):
    from server.sli.reporting.v2.reports import vpn_connections

    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", lambda *a, **kw: pytest.fail("unrelated branch"))
    for reader in ("get_vpn_authorization_timeline", "get_windows_authentication_report", "get_windows_authentication_failure_grid"):
        monkeypatch.setattr(vpn_connections, reader, lambda *a, **kw: pytest.fail("unrelated branch"))
    monkeypatch.setattr(vpn_connections, "get_overlaps", lambda *a, **kw: {
        "state": "not_collected", "reason": "no_accounting_data", "items": [], "metrics": {}, "coverage": {},
    })
    data = vpn_connections._query(context("session_overlap", domain=1, period={
        "from_utc": "2026-01-01T00:00:00Z", "to_utc": "2026-01-02T00:00:00Z"}))
    assert data["state"] == "not_collected"
    assert data["collections"]["session_overlap"] == []
    assert all(metric["value"] is None for metric in data["metrics"])
    assert any(note["code"] == "overlap_no_accounting" and "Нет данных Accounting" in note["text"] for note in data["limitations"])


def test_tabs_inherit_their_plugin_navigation_owners():
    from server.sli.reporting.navigation_registry import load_registry
    from server.sli.reporting.v2.registry import get_report

    _, owners = load_registry()
    for key, tab, owner_id, section in (("ad.infrastructure", "spn_collisions", spn.OWNER_ID, "active-directory"),
                                       ("vpn.connections", "session_overlap", vpn.OWNER_ID, "remote-access")):
        assert owners[key]["owner_id"] == owner_id
        assert owners[key]["section_id"] == section
        assert any(view.key == tab for view in get_report(key).views)


def test_spn_requested_domain_cannot_widen_resolved_access(monkeypatch):
    monkeypatch.setattr(spn, "get_runtime_connection", lambda: pytest.fail("unauthorized read"))
    with pytest.raises(PermissionError):
        spn.get_collisions(domain_ids=[1], params={"spn_domain": 2}, now=NOW)


def test_spn_does_not_count_the_same_entity_twice():
    first = owner(1, ["HTTP/synthetic"])
    replay = owner(1, ["http/SYNTHETIC"])
    replay["attributes_json"]["identity"] = {"object_sid": "synthetic-sid"}
    assert spn.analyze([first, replay], now=NOW)["items"] == []


def test_spn_unreadable_source_is_unavailable_not_empty(monkeypatch):
    from psycopg.errors import InsufficientPrivilege
    from server.sli.reporting.v2.reports import ad_state

    def unreadable(**kwargs):
        raise InsufficientPrivilege()

    monkeypatch.setattr(ad_state, "get_collisions", unreadable)
    data = ad_state._query(context("spn_collisions"))
    assert data["state"] == "error"
    assert data["collections"]["spn_collisions"] == []
    assert all(metric["value"] is None for metric in data["metrics"])
    assert any(note["code"] == "spn_unavailable" and "не доказывает отсутствие коллизий" in note["text"] for note in data["limitations"])


def test_vpn_evidence_links_use_the_existing_api_domain_parameter():
    from server.sli.reporting.v2.reports import vpn_connections

    view = next(view for view in vpn_connections.REPORT.views if view.key == "session_overlap")
    for key in ("session_a", "session_b"):
        link = next(column.link for column in view.columns if column.key == key)
        assert "?domain_id={domain_id}&session_row_id=" in link


def test_spn_missing_attribute_is_not_an_empty_spn_list():
    unknown = owner(1, [])
    del unknown["attributes_json"]["attributes"]["service_principal_names"]
    data = spn.analyze([unknown, owner(2, [])], now=NOW)
    assert data["unknown_spn_count"] == 1


def test_vpn_missing_start_is_incomplete_not_an_infinite_interval():
    unknown = session("a", "10:00", "11:00")
    unknown["started_at_utc"] = None
    unknown["completeness"] = "missing_start"
    data = vpn.analyze([unknown, session("b", "10:10", "10:40")],
                       "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    assert data["items"] == []
    assert data["metrics"]["incomplete_sessions"] == 1
    assert data["invalid_interval_count"] == 1


def test_vpn_restarted_generation_does_not_extend_the_old_open_session():
    data = vpn.analyze([
        session("old-generation", "10:00", last="10:05", generation=1),
        session("new-generation", "10:10", "10:30", generation=2),
        session("independent-session", "10:15", "10:20", generation=1),
    ], "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    assert len(data["items"]) == 1
    pair = data["items"][0]
    assert pair["session_a"] == "new-generation"
    assert pair["generation_a"] == 2
    assert pair["session_b"] == "independent-session"
    assert pair["generation_b"] == 1
    assert pair["overlap_seconds"] == 300


def test_spn_retained_metadata_without_versions_does_not_claim_no_collisions(monkeypatch):
    source = {"run_id": "snapshot-1", "domain_id": 1, "observed_at_utc": NOW,
              "run_status": "completed", "section_status": "complete", "record_count": 2,
              "scope_json": {"search_base": "synthetic-scope"}}
    cur = Cursor([[source], []])
    monkeypatch.setattr(spn, "get_runtime_connection", lambda: cur)
    data = spn.get_collisions(domain_ids=[1], now=NOW)
    assert data["state"] == "partial"
    assert data["metrics"] == {}
    assert data["coverage"]["missing_records"] is True
