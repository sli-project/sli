"""«Первичная настройка»: AD domains are listed and added by an administrator."""

from __future__ import annotations

from http import HTTPStatus

import pytest

from server.api.routes import setup as routes_setup
from server.sli.access.access_control_v4 import route_capability
from server.sli.core import setup_domains
from server.sli.sources.administrative_activity_producer import ACCESS_ACTIONS


class _Cursor:
    """Records SQL; answers selects from a tiny in-memory domain table."""

    def __init__(self, store: dict) -> None:
        self.store = store
        self._row = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        text = " ".join(sql.split())
        self.store["log"].append((text, params))
        self._row = None
        domains = self.store["domains"]
        if text.startswith("select 1 as found from domains where lower(fqdn)"):
            self._row = {"found": 1} if params[0] in domains else None
        elif text.startswith("select 1 as found from domains where upper(netbios_name)"):
            hits = [f for f, n in domains.items() if n and n.upper() == params[0] and (len(params) < 2 or f != params[1])]
            self._row = {"found": 1} if hits else None
        elif text.startswith("select netbios_name from domains"):
            self._row = {"netbios_name": domains[params[0]]} if params[0] in domains else None
        elif text.startswith("insert into forests"):
            self._row = {"id": 7}
        elif text.startswith("insert into domains"):
            domains[params[1]] = params[2]
        elif text.startswith("update domains"):
            domains[params[1]] = params[0]

    def fetchone(self):
        return self._row


class _Connection:
    def __init__(self, store: dict) -> None:
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def cursor(self):
        return _Cursor(self.store)

    def commit(self):
        self.store["log"].append(("commit", ()))


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> dict:
    data = {"domains": {"corp.example.test": "CORP"}, "log": []}
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: _Connection(data))
    return data


def test_add_domain_normalizes_derives_forest_and_audits_in_the_same_transaction(store: dict) -> None:
    audited: list[dict] = []
    result = setup_domains.add_domain(
        " Branch.Example.TEST ", "branch", audit=lambda _cur, change: (audited.append(change), store["log"].append(("audit", ()))),
    )
    assert result == {"fqdn": "branch.example.test", "netbios_name": "BRANCH", "forest": "branch.example.test", "server_count": 0}
    assert store["domains"]["branch.example.test"] == "BRANCH"
    assert audited[0]["previous_netbios_name"] is None
    assert [entry[0] for entry in store["log"]][-2:] == ["audit", "commit"]


def test_add_domain_uses_given_forest(store: dict) -> None:
    result = setup_domains.add_domain("child.corp.example.test", None, "Corp.Example.Test")
    assert result["forest"] == "corp.example.test"
    assert result["netbios_name"] is None


def test_duplicates_are_conflicts_and_nothing_is_committed(store: dict) -> None:
    with pytest.raises(setup_domains.DomainConflictError, match="domain_already_exists"):
        setup_domains.add_domain("CORP.example.test", "OTHER")
    with pytest.raises(setup_domains.DomainConflictError, match="netbios_already_exists"):
        setup_domains.add_domain("other.example.test", "corp")
    assert ("commit", ()) not in store["log"]


@pytest.mark.parametrize(
    ("fqdn", "netbios", "code"),
    [
        ("example", None, "value_must_be_dns_name"),
        ("a b.test", None, "value_must_be_dns_name"),
        ("ok.example.test", "TOOLONGNETBIOSNAME", "netbios_must_be_up_to_15_letters_digits_hyphen"),
        ("ok.example.test", "BAD_NAME", "netbios_must_be_up_to_15_letters_digits_hyphen"),
        ("ok.example.test", "-BAD", "netbios_must_be_up_to_15_letters_digits_hyphen"),
    ],
)
def test_invalid_input_is_rejected_before_connecting(monkeypatch: pytest.MonkeyPatch, fqdn, netbios, code) -> None:
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: pytest.fail("no connection"))
    with pytest.raises(ValueError, match=code):
        setup_domains.add_domain(fqdn, netbios)


def test_update_netbios_reports_previous_value_and_missing_domain(store: dict) -> None:
    audited: list[dict] = []
    result = setup_domains.update_netbios("corp.example.test", "corp2", audit=lambda _c, change: audited.append(change))
    assert result["previous_netbios_name"] == "CORP" and store["domains"]["corp.example.test"] == "CORP2"
    assert audited == [result]
    with pytest.raises(setup_domains.DomainNotFoundError):
        setup_domains.update_netbios("missing.example.test", "X")


def test_list_domains_shapes_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(setup_domains.database, "query_rows", lambda *_a, **_k: [
        {"fqdn": "corp.example.test", "netbios_name": None, "forest": "corp.example.test", "server_count": 2},
    ])
    assert setup_domains.list_domains() == [
        {"fqdn": "corp.example.test", "netbios_name": None, "forest": "corp.example.test", "server_count": 2, "is_archived": False, "observed_at_utc": None},
    ]


class _Handler:
    client_address = ("127.0.0.1", 0)
    _principal = {"id": 1, "username": "admin", "type": "session"}

    def __init__(self, *, allowed=True, capable=True, body=None) -> None:
        self.allowed, self.capable, self.body, self.sent, self.calls = allowed, capable, body or {}, [], []

    def _authorize_mutation(self, *, required_role):
        self.calls.append(("role", required_role))
        return self.allowed

    def _require_capability(self, capability):
        self.calls.append(("capability", capability))
        return self.capable

    def _read_json_body(self):
        return self.body

    def _send_json(self, payload, status=HTTPStatus.OK):
        self.sent.append((payload, status))


def test_post_requires_admin_and_access_manage_before_writing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes_setup, "add_domain", lambda *_a, **_k: pytest.fail("no write"))
    handler = _Handler(capable=False)
    assert routes_setup.try_handle_post(handler, "/api/v1/setup/domains") is True
    assert handler.calls == [("role", "admin"), ("capability", "access.manage")]
    assert handler.sent == []
    assert routes_setup.try_handle_post(_Handler(allowed=False), "/api/v1/setup/domains") is True


def test_post_maps_results_to_status_codes_and_audit_action(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple] = []

    def fake_add(fqdn, netbios, forest, *, audit):
        seen.append((fqdn, netbios, forest))
        if fqdn == "dup.example.test":
            raise setup_domains.DomainConflictError("domain_already_exists")
        if fqdn == "bad":
            raise ValueError("value_must_be_dns_name")
        audited = []
        audit(type("C", (), {"execute": lambda *_a: audited.append(1), "fetchone": lambda *_a: {}})(), {"fqdn": fqdn, "netbios_name": netbios})
        return {"fqdn": fqdn, "netbios_name": netbios, "forest": fqdn, "server_count": 0}

    monkeypatch.setattr(routes_setup, "add_domain", fake_add)
    recorded: list[dict] = []
    monkeypatch.setattr(routes_setup, "record_access_audit_with_cursor", lambda **kw: recorded.append(kw))

    ok = _Handler(body={"fqdn": "new.example.test", "netbios_name": "NEW"})
    routes_setup.try_handle_post(ok, "/api/v1/setup/domains")
    assert ok.sent[0][1] == HTTPStatus.CREATED
    assert recorded[0]["action"] == "setup_domain_add" and recorded[0]["target_key"] == "new.example.test"
    assert recorded[0]["actor"]["username"] == "admin"

    dup = _Handler(body={"fqdn": "dup.example.test"})
    routes_setup.try_handle_post(dup, "/api/v1/setup/domains")
    assert dup.sent == [({"error": "domain_already_exists"}, HTTPStatus.CONFLICT)]

    bad = _Handler(body={"fqdn": "bad"})
    routes_setup.try_handle_post(bad, "/api/v1/setup/domains")
    assert bad.sent == [({"error": "value_must_be_dns_name"}, HTTPStatus.BAD_REQUEST)]


def test_update_route_maps_missing_domain_to_404(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*_a, **_k):
        raise setup_domains.DomainNotFoundError("domain_not_found")

    monkeypatch.setattr(routes_setup, "update_netbios", missing)
    handler = _Handler(body={"netbios_name": "X"})
    routes_setup.try_handle_post(handler, "/api/v1/setup/domains/missing.example.test")
    assert handler.sent == [({"error": "domain_not_found"}, HTTPStatus.NOT_FOUND)]


def test_domain_routes_are_registered_and_need_access_manage() -> None:
    assert ("GET", "/api/v1/setup/domains") in routes_setup.ROUTES
    assert ("POST", "/api/v1/setup/domains") in routes_setup.ROUTES
    assert route_capability("/api/v1/setup/domains") == "access.manage"
    assert {"setup_domain_add", "setup_domain_update"} <= set(ACCESS_ACTIONS)


def test_archive_route_requires_same_admin_and_capability_guard(monkeypatch):
    monkeypatch.setattr(routes_setup, "update_archive", lambda *_a, **_k: pytest.fail("no write"))
    for handler in (_Handler(allowed=False, body={"is_archived": True}), _Handler(capable=False, body={"is_archived": True})):
        assert routes_setup.try_handle_post(handler, "/api/v1/setup/domains/old.example.test")
        assert handler.sent == []


def test_archive_route_rejects_mixed_updates_without_clearing_netbios(monkeypatch):
    monkeypatch.setattr(routes_setup, "update_archive", lambda *_a, **_k: pytest.fail("no write"))
    monkeypatch.setattr(routes_setup, "update_netbios", lambda *_a, **_k: pytest.fail("no write"))
    handler = _Handler(body={"is_archived": True, "netbios_name": "OTHER"})
    routes_setup.try_handle_post(handler, "/api/v1/setup/domains/old.example.test")
    assert handler.sent == [({"error": "domain_archive_update_fields_invalid"}, HTTPStatus.BAD_REQUEST)]
