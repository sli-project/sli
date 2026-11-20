"""Synthetic configured-address and source-detail identity regressions."""
import json

import pytest

from server.sli.core import database
from server.sli.plugins.ad import targets
from server.sli.reporting import ui_operations


def registered(domain, fqdn=None, hostname="DC01"):
    return {"hostname": hostname, "domain_fqdn": domain, "fqdn": fqdn}


def sources(monkeypatch, rows, configured):
    monkeypatch.setattr(database, "query_rows", lambda *a, **k: rows)
    monkeypatch.setattr(database, "_enrich_sources_from_current_ad_context", lambda rows: rows)
    monkeypatch.setattr(database, "_configured_source_addresses", lambda: configured)
    return database.get_sources()


@pytest.mark.parametrize("file_backed", [False, True])
def test_configured_addresses_preserve_qualified_identity(tmp_path, file_backed):
    items = [
        {"hostname": " \\\\DC01.A.TEST. ", "owner_confirmed_ip": "192.0.2.1"},
        {"hostname": "dc01.b.test", "owner_confirmed_ip": "192.0.2.2"},
        {"hostname": "DC02", "owner_confirmed_ip": "bad"},
    ]
    (tmp_path / "domain_controllers.json").write_text(json.dumps({"domain_controllers": items}))
    assert targets.configured_source_addresses(config_dir=tmp_path, stored=None if file_backed else items) == {
        "dc01.a.test": ["192.0.2.1"], "dc01.b.test": ["192.0.2.2"],
    }


def test_exact_configured_fqdns_never_merge_across_domains(monkeypatch):
    result = sources(monkeypatch, [registered("a.test"), registered("b.test")], {
        "dc01.a.test": ["192.0.2.1"], "dc01.b.test": ["192.0.2.2"],
    })
    assert [r["ip_addresses"] for r in result] == [["192.0.2.1"], ["192.0.2.2"]]


def test_ambiguous_short_configured_address_is_unknown(monkeypatch):
    result = sources(monkeypatch, [registered("a.test"), registered("b.test")], {"dc01": ["192.0.2.1"]})
    assert [r["ip_addresses"] for r in result] == [[], []]


@pytest.mark.parametrize("row,key", [
    (registered("a.test"), "dc01"),
    (registered("a.test"), "dc01.a.test"),
    (registered("a.test", "dc01.child.a.test"), "dc01.child.a.test"),
    (registered(None, hostname="DC01.A.TEST."), "dc01.a.test"),
])
def test_unique_configured_address_compatibility(monkeypatch, row, key):
    assert sources(monkeypatch, [row], {key: ["192.0.2.1"]})[0]["ip_addresses"] == ["192.0.2.1"]


def test_conflicting_explicit_fqdn_is_not_derived_from_domain(monkeypatch):
    assert sources(monkeypatch, [registered("a.test", "dc01.child.a.test")], {
        "dc01.a.test": ["192.0.2.1"],
    })[0]["ip_addresses"] == []


def test_duplicate_exact_configured_owners_are_unknown(monkeypatch):
    rows = [registered("a.test", "shared.test"), registered("b.test", "shared.test")]
    assert [r["ip_addresses"] for r in sources(monkeypatch, rows, {"shared.test": ["192.0.2.1"]})] == [[], []]


def test_detail_rejects_duplicate_before_reading_channels(monkeypatch):
    monkeypatch.setattr(ui_operations, "get_sources", lambda: [registered("a.test"), registered("b.test")])
    def no_health():
        pytest.fail("Ambiguous registration must fail before channels are read")
    monkeypatch.setattr(ui_operations, "get_collector_health", no_health)
    with pytest.raises(ValueError, match="^ambiguous_source_hostname$"):
        ui_operations.get_source_detail(" dc01 ")


@pytest.mark.parametrize("ambiguous", [False, True])
def test_detail_route_compatibility_and_ambiguity(monkeypatch, ambiguous):
    from server.api.routes import operations
    rows = [registered("a.test")]
    if ambiguous:
        rows.append(registered("b.test"))
    monkeypatch.setattr(ui_operations, "get_sources", lambda: rows)
    monkeypatch.setattr(ui_operations, "get_collector_health", lambda: {"items": [{"server": "dc01", "channel": "Security"}]})
    class Handler:
        def _send_json(self, payload, status=200):
            self.payload, self.status = payload, status
    handler = Handler()
    assert operations.try_handle_get(handler, "/api/v1/operations/sources/DC01", {})
    if ambiguous:
        assert handler.status == 400
        assert handler.payload == {"error": "ambiguous_source_hostname"}
    else:
        assert handler.status == 200
        assert handler.payload["source"]["domain_fqdn"] == "a.test"
        assert handler.payload["channels"][0]["server"] == "dc01"
