"""«Первичная настройка»: domain controller targets in the database."""

from __future__ import annotations

import importlib.util
import json
from http import HTTPStatus
from pathlib import Path

import pytest

from server.api.routes import setup as routes_setup
from server.sli.access.access_control_v4 import route_capability
from server.sli.core import setup_domain_controllers as dcs
from server.sli.sources import dc_discovery
from server.sli.sources.administrative_activity_producer import ACCESS_ACTIONS

ROOT = Path(__file__).resolve().parents[2]


class _Cursor:
    """Records SQL; answers selects from in-memory domains and targets."""

    def __init__(self, store: dict) -> None:
        self.store = store
        self._rows: list[dict] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        text = " ".join(sql.split())
        self.store["log"].append((text, params))
        self._rows = []
        if text.startswith("select id from domains where lower(fqdn)"):
            domain_id = self.store["domains"].get(params[0])
            self._rows = [{"id": domain_id}] if domain_id else []
        elif text.startswith("select id, lower(fqdn) as fqdn from domains"):
            self._rows = [{"id": i, "fqdn": f} for f, i in self.store["domains"].items()]
        elif text.startswith("select lower(hostname) as key from domain_controller_targets"):
            self._rows = [{"key": key} for key in self.store["targets"]]
        elif text.startswith("select hostname, enabled from domain_controller_targets"):
            row = self.store["targets"].get(params[0])
            self._rows = [{"hostname": row["hostname"], "enabled": row["enabled"]}] if row else []
        elif text.startswith("insert into domain_controller_targets"):
            hostname, address, domain_id, *rest = params
            ip = rest[0] if len(rest) == 3 else None
            self.store["targets"][hostname.lower()] = {
                "hostname": hostname, "connect_address": address, "domain_id": domain_id,
                "owner_confirmed_ip": ip, "enabled": True, "sql": text,
            }
        elif text.startswith("update domain_controller_targets"):
            self.store["targets"][params[2]]["enabled"] = params[0]

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


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
    data = {"domains": {"corp.example.test": 7, "example.test": 3}, "targets": {}, "log": []}
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: _Connection(data))
    return data


def _file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, targets: list) -> None:
    (tmp_path / "domain_controllers.json").write_text(json.dumps({"domain_controllers": targets}), encoding="utf-8")
    monkeypatch.setattr(dc_discovery, "CONFIG_DIR", tmp_path)


def _stored(monkeypatch: pytest.MonkeyPatch, rows: list[dict] | None) -> None:
    """Pretend the table holds ``rows`` (None: unreadable)."""

    def query() -> list[dict]:
        if rows is None:
            raise RuntimeError("relation does not exist")
        return rows

    monkeypatch.setattr(dc_discovery, "_query_target_rows", query)
    dc_discovery.clear_database_target_cache()


FILE_TARGETS = [
    {"hostname": "DC1", "connect_address": "dc1.corp.example.test", "owner_confirmed_ip": "198.51.100.23"},
    {"hostname": "DC2", "connect_address": "dc2.other.test"},
]


def test_resolution_prefers_enabled_database_rows_over_the_file(tmp_path, monkeypatch) -> None:
    _file(tmp_path, monkeypatch, FILE_TARGETS)
    _stored(monkeypatch, [
        {"hostname": "DB1", "connect_address": "db1.corp.example.test", "owner_confirmed_ip": None, "enabled": True},
        {"hostname": "DB2", "connect_address": "db2.corp.example.test", "owner_confirmed_ip": "198.51.100.5", "enabled": True},
        {"hostname": "DB3", "connect_address": "db3.corp.example.test", "owner_confirmed_ip": None, "enabled": False},
    ])
    assert dc_discovery.get_configured_domain_controller_targets() == [
        {"hostname": "DB1", "connect_address": "db1.corp.example.test"},
        {"hostname": "DB2", "connect_address": "db2.corp.example.test", "owner_confirmed_ip": "198.51.100.5"},
    ]
    assert dc_discovery.domain_controller_target_source() == "db"
    assert dc_discovery.resolve_domain_controller_connect_address("DB1") == "db1.corp.example.test"
    with pytest.raises(dc_discovery.DomainControllerConfigurationError):
        dc_discovery.resolve_domain_controller_connect_address("DB3")


def test_all_rows_disabled_means_no_targets_not_a_file_fallback(tmp_path, monkeypatch) -> None:
    _file(tmp_path, monkeypatch, FILE_TARGETS)
    _stored(monkeypatch, [{"hostname": "DB1", "connect_address": "db1.corp.example.test", "owner_confirmed_ip": None, "enabled": False}])
    assert dc_discovery.get_configured_domain_controller_targets() == []
    assert dc_discovery.discover_domain_controllers() == []


@pytest.mark.parametrize("rows", [None, []])
def test_file_is_the_fallback_while_the_table_is_missing_or_empty(tmp_path, monkeypatch, rows) -> None:
    _file(tmp_path, monkeypatch, FILE_TARGETS)
    _stored(monkeypatch, rows)
    targets = dc_discovery.get_configured_domain_controller_targets()
    assert [item["hostname"] for item in targets] == ["DC1", "DC2"]
    assert dc_discovery.domain_controller_target_source() == "file"


def test_database_targets_are_cached_briefly(monkeypatch) -> None:
    calls: list[int] = []

    def query() -> list[dict]:
        calls.append(1)
        return [{"hostname": "DB1", "connect_address": "db1.corp.example.test", "owner_confirmed_ip": None, "enabled": True}]

    monkeypatch.setattr(dc_discovery, "_query_target_rows", query)
    dc_discovery.clear_database_target_cache()
    dc_discovery.get_configured_domain_controller_targets()
    dc_discovery.get_configured_domain_controller_targets()
    assert len(calls) == 1
    dc_discovery.clear_database_target_cache()
    dc_discovery.get_configured_domain_controller_targets()
    assert len(calls) == 2


def test_list_targets_shapes_database_rows_and_hides_the_ip(monkeypatch) -> None:
    monkeypatch.setattr(dcs.database, "query_rows", lambda *_a, **_k: [
        {"hostname": "DC2", "connect_address": "dc2.corp.example.test", "domain": "corp.example.test", "enabled": False, "dns_readback": True},
    ])
    assert dcs.list_targets() == {"source": "db", "items": [{
        "hostname": "DC2", "connect_address": "dc2.corp.example.test", "domain": "corp.example.test",
        "enabled": False, "source": "db", "dns_readback": True,
    }]}


def test_list_targets_falls_back_to_the_file_without_the_ip(tmp_path, monkeypatch) -> None:
    _file(tmp_path, monkeypatch, FILE_TARGETS)
    monkeypatch.setattr(dcs.database, "query_rows", lambda *_a, **_k: [])
    result = dcs.list_targets()
    assert result["source"] == "file"
    assert result["items"][0] == {
        "hostname": "DC1", "connect_address": "dc1.corp.example.test", "domain": None,
        "enabled": True, "source": "file", "dns_readback": True,
    }
    assert "198.51" not in repr(result)


def test_list_targets_is_none_without_database_rows_and_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(dc_discovery, "CONFIG_DIR", tmp_path)

    def broken(*_a, **_k):
        raise RuntimeError("relation does not exist")

    monkeypatch.setattr(dcs.database, "query_rows", broken)
    assert dcs.list_targets() == {"source": "none", "items": []}


def test_add_target_registers_under_a_domain_and_audits_before_commit(store, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(dc_discovery, "CONFIG_DIR", tmp_path)
    audited: list[dict] = []
    result = dcs.add_target(
        " DC4.Corp.Example.TEST. ", "Corp.Example.Test", actor="admin",
        audit=lambda _cur, change: (audited.append(change), store["log"].append(("audit", ()))),
    )
    assert result == {
        "hostname": "dc4", "connect_address": "dc4.corp.example.test", "domain": "corp.example.test",
        "enabled": True, "source": "db", "dns_readback": False,
    }
    assert store["targets"]["dc4"]["domain_id"] == 7
    assert audited[0]["imported_from_file"] == 0
    assert [entry[0] for entry in store["log"]][-2:] == ["audit", "commit"]
    assert "advisory_xact_lock" in store["log"][0][0]


def test_first_add_copies_file_targets_so_they_are_not_replaced(store, tmp_path, monkeypatch) -> None:
    _file(tmp_path, monkeypatch, FILE_TARGETS)
    audited: list[dict] = []
    dcs.add_target("dc5.corp.example.test", "corp.example.test", actor="admin", audit=lambda _c, change: audited.append(change))
    assert set(store["targets"]) == {"dc1", "dc2", "dc5"}
    assert store["targets"]["dc1"]["domain_id"] == 7 and store["targets"]["dc1"]["owner_confirmed_ip"] == "198.51.100.23"
    assert store["targets"]["dc2"]["domain_id"] is None
    assert audited[0]["imported_from_file"] == 2


def test_duplicate_unknown_domain_and_bad_input_write_nothing(store, tmp_path, monkeypatch) -> None:
    _file(tmp_path, monkeypatch, FILE_TARGETS)
    with pytest.raises(dcs.DomainControllerConflictError, match="domain_controller_already_exists"):
        dcs.add_target("dc1.corp.example.test", "corp.example.test", actor="admin")
    with pytest.raises(dcs.DomainControllerNotFoundError, match="domain_not_found"):
        dcs.add_target("dc6.corp.example.test", "missing.example.test", actor="admin")
    assert ("commit", ()) not in store["log"]
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: pytest.fail("no connection"))
    for host, code in [("10.1.2.3", "connect_address_must_be_fqdn"), ("dc1", "connect_address_must_be_fqdn"), ("a b.test", "connect_address_must_be_fqdn")]:
        with pytest.raises(ValueError, match=code):
            dcs.add_target(host, "corp.example.test", actor="admin")
    with pytest.raises(ValueError, match="actor_required"):
        dcs.add_target("dc7.corp.example.test", "corp.example.test", actor=" ")


def test_set_enabled_reports_previous_value_and_missing_controller(store, monkeypatch) -> None:
    store["targets"]["dc2"] = {"hostname": "DC2", "enabled": True}
    audited: list[dict] = []
    result = dcs.set_enabled("DC2", False, actor="admin", audit=lambda _c, change: audited.append(change))
    assert result == {"hostname": "DC2", "enabled": False, "previous_enabled": True}
    assert store["targets"]["dc2"]["enabled"] is False and audited == [result]
    with pytest.raises(dcs.DomainControllerNotFoundError):
        dcs.set_enabled("missing", True, actor="admin")
    with pytest.raises(ValueError, match="enabled_must_be_boolean"):
        dcs.set_enabled("DC2", "yes", actor="admin")


def test_import_plan_is_read_only_and_apply_is_idempotent(store, tmp_path, monkeypatch) -> None:
    _file(tmp_path, monkeypatch, FILE_TARGETS)
    plan = dcs.import_from_file()
    assert plan == {"mode": "plan", "file_targets": 2, "already_present": 0, "to_import": 2}
    assert store["targets"] == {} and ("commit", ()) not in store["log"]
    applied = dcs.import_from_file(apply=True)
    assert applied == {
        "mode": "apply", "file_targets": 2, "already_present": 0, "to_import": 2,
        "imported": 2, "with_domain": 1, "without_domain": 1,
    }
    assert "'file_import'" in store["targets"]["dc1"]["sql"]
    again = dcs.import_from_file(apply=True)
    assert again["to_import"] == 0 and again["imported"] == 0 and again["already_present"] == 2


def test_import_cli_needs_the_confirmation_and_prints_counts_only(monkeypatch, capsys) -> None:
    spec = importlib.util.spec_from_file_location("import_dc_cli", ROOT / "scripts/maintenance/import_domain_controllers_from_file.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    calls: list[bool] = []
    monkeypatch.setattr(cli, "import_from_file", lambda *, apply: (calls.append(apply), {"mode": "x", "to_import": 1})[1])
    assert cli.main([]) == 0 and calls == [False]
    with pytest.raises(SystemExit, match="IMPORT-DOMAIN-CONTROLLERS"):
        cli.main(["apply", "--confirm", "nope"])
    assert calls == [False]
    assert cli.main(["apply", "--confirm", "IMPORT-DOMAIN-CONTROLLERS"]) == 0 and calls == [False, True]
    assert json.loads(capsys.readouterr().out.split("}\n", 1)[1])["to_import"] == 1


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


def test_post_requires_admin_and_access_manage_before_writing(monkeypatch) -> None:
    monkeypatch.setattr(routes_setup, "add_target", lambda *_a, **_k: pytest.fail("no write"))
    monkeypatch.setattr(routes_setup, "set_enabled", lambda *_a, **_k: pytest.fail("no write"))
    handler = _Handler(capable=False)
    assert routes_setup.try_handle_post(handler, "/api/v1/setup/domain-controllers") is True
    assert handler.calls == [("role", "admin"), ("capability", "access.manage")] and handler.sent == []
    assert routes_setup.try_handle_post(_Handler(allowed=False), "/api/v1/setup/domain-controllers/DC1") is True


def test_post_maps_results_to_status_codes_and_audit_actions(monkeypatch) -> None:
    def fake_add(hostname, domain, *, actor, audit):
        if hostname == "dup.corp.example.test":
            raise dcs.DomainControllerConflictError("domain_controller_already_exists")
        if hostname == "bad":
            raise ValueError("connect_address_must_be_fqdn")
        if domain == "missing.example.test":
            raise dcs.DomainControllerNotFoundError("domain_not_found")
        audit(type("C", (), {})(), {"hostname": "DC9", "connect_address": hostname, "domain": domain, "imported_from_file": 0})
        return {"hostname": "DC9", "actor": actor}

    def fake_toggle(hostname, enabled, *, actor, audit):
        audit(type("C", (), {})(), {"hostname": hostname, "enabled": enabled, "previous_enabled": True})
        return {"hostname": hostname, "enabled": enabled, "previous_enabled": True}

    monkeypatch.setattr(routes_setup, "add_target", fake_add)
    monkeypatch.setattr(routes_setup, "set_enabled", fake_toggle)
    recorded: list[dict] = []
    monkeypatch.setattr(routes_setup, "record_access_audit_with_cursor", lambda **kw: recorded.append(kw))

    ok = _Handler(body={"hostname": "dc9.corp.example.test", "domain": "corp.example.test"})
    routes_setup.try_handle_post(ok, "/api/v1/setup/domain-controllers")
    assert ok.sent[0][1] == HTTPStatus.CREATED and ok.sent[0][0]["item"]["actor"] == "admin"
    assert recorded[0]["action"] == "setup_dc_add" and recorded[0]["target_key"] == "DC9"
    assert recorded[0]["target_type"] == "domain_controller" and "hostname" not in recorded[0]["details"]

    for body, error, status in [
        ({"hostname": "dup.corp.example.test", "domain": "corp.example.test"}, "domain_controller_already_exists", HTTPStatus.CONFLICT),
        ({"hostname": "bad", "domain": "corp.example.test"}, "connect_address_must_be_fqdn", HTTPStatus.BAD_REQUEST),
        ({"hostname": "x.corp.example.test", "domain": "missing.example.test"}, "domain_not_found", HTTPStatus.NOT_FOUND),
    ]:
        handler = _Handler(body=body)
        routes_setup.try_handle_post(handler, "/api/v1/setup/domain-controllers")
        assert handler.sent == [({"error": error}, status)]

    toggle = _Handler(body={"enabled": False})
    routes_setup.try_handle_post(toggle, "/api/v1/setup/domain-controllers/DC2")
    assert toggle.sent == [({"item": {"hostname": "DC2", "enabled": False, "previous_enabled": True}}, HTTPStatus.OK)]
    assert recorded[-1]["action"] == "setup_dc_update"


def test_list_route_and_registration(monkeypatch) -> None:
    sent: list[dict] = []

    class Handler:
        def _send_json(self, payload, *_args):
            sent.append(payload)

    monkeypatch.setattr(routes_setup, "list_targets", lambda: {"source": "db", "items": []})
    assert routes_setup.try_handle_get(Handler(), "/api/v1/setup/domain-controllers", {}) is True
    assert sent == [{"source": "db", "items": []}]
    for route in [("GET", "/api/v1/setup/domain-controllers"), ("POST", "/api/v1/setup/domain-controllers"), ("POST", "/api/v1/setup/domain-controllers/*")]:
        assert route in routes_setup.ROUTES
    assert route_capability("/api/v1/setup/domain-controllers") == "access.manage"
    assert {"setup_dc_add", "setup_dc_update"} <= set(ACCESS_ACTIONS)


def test_migration_147_is_additive_reads_no_files_and_has_a_rollback() -> None:
    sql = (ROOT / "config/postgres_migrations/147_domain_controller_targets.sql").read_text(encoding="utf-8")
    code = " ".join(line for line in sql.splitlines() if not line.lstrip().startswith("--"))
    assert "requires exact migration 146 platform_settings" in code
    assert "references public.domains(id) on delete restrict" in code
    assert "grant select, insert, update on public.domain_controller_targets to adlog_user;" in code
    assert "values (147, 'domain_controller_targets')" in code
    assert "pg_read_file" not in code and "copy " not in code.lower()
    rollback = (ROOT / "config/postgres_migrations/147_domain_controller_targets.rollback.sql").read_text(encoding="utf-8")
    assert "drop table if exists public.domain_controller_targets;" in rollback
    assert "delete from schema_migrations where version = 147;" in rollback
