"""Retained infrastructure sections follow the server-authorized domain scope."""

from datetime import datetime, timezone
import csv
import io
import re

import pytest

from server.sli.plugins.ad.reports import active_directory_reporting as reporting
from server.sli.plugins.ad.reports.definitions import ad_state
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import QueryContext


class RetainedInfrastructure:
    """Apply the reader's domain, entity and section predicates to fake rows."""

    def __init__(self, *, retained=True):
        self.domains = {11: "installation.example.test", 22: "authorized.example.test"}
        self.retained = retained
        self.calls = []
        self.observed = datetime.now(timezone.utc)
        self.entities = []
        for domain_id in self.domains:
            for offset, entity_type, section, attributes in (
                (1, "domain", "domain_posture", {"ldap_signing_requirement": "required"}),
                (2, "ad_computer", "domain_health", {
                    "infrastructure_role": "domain_controller", "dns_state": "passed",
                }),
                (3, "domain", "directory_accounts", {"ldap_signing_requirement": "not_required"}),
                (4, "ad_user", "domain_posture", {"ldap_signing_requirement": "not_required"}),
                (5, "ad_computer", "domain_health", {"infrastructure_role": "workstation"}),
            ):
                self.entities.append({
                    "entity_id": domain_id * 100 + offset, "domain_id": domain_id,
                    "entity_type": entity_type, "source_section": section,
                    "domain_name": self.domains[domain_id],
                    "display_name": f"synthetic-object-{offset}",
                    "natural_key": f"synthetic-key-{domain_id}-{offset}",
                    "observed_at_utc": self.observed, "attributes": attributes,
                })

    def query(self, sql, params=(), **kwargs):
        self.calls.append((sql, params))
        coverage = "active_directory_report_coverage" in sql
        assert coverage or "active_directory_report_entities" in sql
        if not coverage:
            assert "report_domain.fqdn as domain_name" in sql
        domains = set(self.domains)
        fqdn = re.search(r"lower\(report_domain\.fqdn\)='([^']+)'", sql)
        if fqdn:
            domains &= {key for key, value in self.domains.items() if value == fqdn[1]}
        id_predicate = "report_domain.id=any(?)" if coverage else "entity.domain_id=any(?)"
        if id_predicate in sql:
            domains &= set(params[0] if coverage else params[2])
        assert fqdn or id_predicate in sql, "domain query must remain constrained"
        if coverage:
            assert params[-1] == list(reporting.ALLOWED_SECTIONS)
            return [
                {
                    "domain_id": domain_id, "domain_name": self.domains[domain_id],
                    "section_name": section, "run_status": "complete" if self.retained else None,
                    "section_status": "complete" if self.retained else None,
                    "record_count": 1 if self.retained else None,
                    "observed_at_utc": self.observed if self.retained else None,
                }
                for domain_id in sorted(domains) for section in params[-1]
            ]
        return [row for row in self.entities if self.retained
                and row["domain_id"] in domains and row["source_section"] in params[0]
                and row["entity_type"] in params[1]][:params[-1]]


@pytest.fixture
def retained(monkeypatch):
    fake = RetainedInfrastructure()
    monkeypatch.setattr(reporting, "query_rows_bounded", fake.query)
    monkeypatch.setattr(reporting, "report_domain_fqdn", lambda: "installation.example.test")
    return fake


@pytest.mark.parametrize("scope,expected_domains", [([22], {22}), ([11, 22], {11, 22}), ([11], {11}), (None, {11})])
def test_retained_sections_and_entities_share_domain_scope(retained, scope, expected_domains):
    payload = reporting.get_active_directory_report(domain_ids=scope)

    assert payload["state"] == "available"
    assert {(row["domain_id"], row["section_name"]) for row in payload["coverage"]["domains"]} == {
        (domain, section) for domain in expected_domains for section in reporting.ALLOWED_SECTIONS
    }
    assert payload["coverage"]["missing"] == []
    assert {row["domain_id"] for row in payload["items"]} == expected_domains
    assert {row["entity_id"] for row in payload["items"]} == {domain * 100 + 1 for domain in expected_domains}
    assert {row["entity_id"] for row in payload["controls"]} == {
        domain * 100 + offset for domain in expected_domains for offset in (1, 2)
    }
    assert {row["source_section"] for row in payload["controls"]} == set(reporting.ALLOWED_SECTIONS)
    assert {row["domain_id"] for row in payload["controls"]} == expected_domains
    assert all(row["domain_name"] == retained.domains[row["domain_id"]] for row in payload["controls"])
    assert payload["summary"]["domain_count"] == len(expected_domains)
    assert payload["summary"]["domain_controller_count"] == len(expected_domains)
    assert len(retained.calls) == 2


@pytest.mark.parametrize("scope", [[], [0, -1]])
def test_empty_explicit_scope_never_reads_domains(monkeypatch, scope):
    def unexpected_read(*args, **kwargs):
        pytest.fail("empty authorized scope must not read stored data or installation settings")

    monkeypatch.setattr(reporting, "query_rows_bounded", unexpected_read)
    monkeypatch.setattr(reporting, "report_domain_fqdn", unexpected_read)
    payload = reporting.get_active_directory_report(domain_ids=scope, view="semantic")

    assert payload["items"] == []
    assert payload["controls"] == []
    assert payload["coverage"]["domains"] == []
    assert payload["summary"]["domain_count"] == 0
    assert payload["has_more"] is False
    assert payload["next_cursor"] is None


def test_explicit_scope_does_not_require_installation_domain(retained, monkeypatch):
    def unexpected_setting():
        pytest.fail("authorized domain IDs must be sufficient for scoped reads")

    monkeypatch.setattr(reporting, "report_domain_fqdn", unexpected_setting)
    payload = reporting.get_active_directory_report(domain_ids=[22, 22, 0])
    assert payload["state"] == "available"
    assert {row["domain_id"] for row in payload["items"]} == {22}


def test_missing_retained_sections_remain_unavailable(retained):
    retained.retained = False
    payload = reporting.get_active_directory_report(domain_ids=[22])

    assert payload["items"] == payload["controls"] == []
    assert payload["state"] == "partial"
    assert payload["coverage"]["missing"] == ["22:domain_health", "22:domain_posture"]
    assert all(row["observed_at_utc"] is None for row in payload["coverage"]["domains"])


def test_absent_domain_coverage_remains_not_collected(retained):
    retained.domains.clear()
    payload = reporting.get_active_directory_report(domain_ids=[22])
    assert payload["state"] == "not_collected"
    assert payload["items"] == payload["controls"] == payload["coverage"]["domains"] == []


def test_adapter_reads_scope_resolved_from_server_grants(retained):
    access = {"reports": [{
        "report_key": "ad.state", "allowed": True, "allowed_actions": ["view"],
        "grants": [{
            "allowed_actions": ["view"], "field_categories": ["identity_basic", "technical", "security"],
            "scope": {"kind": "domain", "ids": [22]},
        }],
    }]}
    authorized = ReportAccess(ad_state.REPORT, access)
    assert authorized.domain_ids == [22]
    context = QueryContext(access=access, params={}, domain_ids=authorized.domain_ids, scope=authorized.scope)
    payload = ad_state._query(context)

    assert payload["state"] == "ok"
    assert {row["entity_id"] for row in payload["items"]} == {2201, 2202}
    assert {row["domain_id"] for row in payload["coverage"]["domains"]} == {22}


@pytest.mark.parametrize("scope", [[11, 22], [22]])
def test_infrastructure_counters_and_csv_share_selected_domains(retained, scope):
    context = QueryContext(access={}, params={}, domain_ids=scope)
    payload = ad_state._query(context)
    text, meta = ad_state._export(context)
    rows = list(csv.DictReader(io.StringIO(text), delimiter=";"))
    assert meta["rows"] == len(rows) == len(payload["items"])
    assert sum(metric["value"] for metric in payload["metrics"]) == len(rows)
    names = {row["Объект"] for row in rows}
    assert names == {
        (f"{retained.domains[key]}\\" if len(scope) > 1 else "") + f"synthetic-object-{offset}"
        for key in scope for offset in (1, 2)
    }
    assert {row["domain_id"] for row in payload["coverage"]["domains"]} == set(scope)


@pytest.mark.parametrize("selected", [None, 22])
def test_adapter_qualifies_names_from_domain_selection_including_one_accessible_domain(retained, selected):
    from types import SimpleNamespace

    context = QueryContext(access={}, params={}, domain_ids=[22],
                           runtime={"domain_selection": SimpleNamespace(domain_id=selected)})
    payload = ad_state._query(context)
    text, _ = ad_state._export(context)
    prefix = "authorized.example.test\\" if selected is None else ""
    assert {row["entity_name"] for row in payload["items"]} == {
        prefix + f"synthetic-object-{offset}" for offset in (1, 2)
    }
    assert {row["domain_id"] for row in payload["items"]} == {22}
    assert {row["domain_name"] for row in payload["items"]} == {retained.domains[22]}
    assert {row["Объект"] for row in csv.DictReader(io.StringIO(text), delimiter=";")} == {
        row["entity_name"] for row in payload["items"]
    }
