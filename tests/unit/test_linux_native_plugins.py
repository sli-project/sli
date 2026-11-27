"""Native bundled VPN registration and read-only registry acceptance contracts."""
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_HASH = "78ae9bcc2e65f54c8469dd0494f5c951df0cfa53ae33cff84478bc70eaa958bf"


def test_native_inventory_supplies_vpn_and_rejects_foreign_plugins():
    from deploy.linux import native_plugins as subject
    previous = {key: {"version": "1.0.0", "migrations": {}} for key in
                ("sli.ad", "sli.gpo", "sli.file-audit", "sli.workstations", "sli.sigma")}
    before = deepcopy(previous)
    result = subject.release_inventory(ROOT, previous)
    assert previous == before
    assert len(result) == 6 and result["sli.remote-access"]["version"] == "0.1.0"
    assert result["sli.remote-access"]["manifest_sha256"] == REGISTRY_HASH
    rows = [(key, value["version"], REGISTRY_HASH if key == "sli.remote-access" else "other-pinned-hash")
            for key, value in result.items()]
    subject.verify_registry(ROOT, result, rows)
    with pytest.raises(ValueError, match="native_plugins_mismatch"):
        subject.verify_registry(ROOT, result, rows + [("sli.unknown", "0.1.0", REGISTRY_HASH)])
    with pytest.raises(ValueError, match="native_plugins_inventory_mismatch"):
        subject.release_inventory(ROOT, dict(previous, **{"sli.unknown": {"version": "1.0.0"}}))


@pytest.mark.parametrize("bad", ["version", "hash", "duplicate", "missing", "asset"])
def test_native_registry_rejects_vpn_drift(tmp_path, bad):
    from deploy.linux import native_plugins as subject
    import shutil
    shutil.copytree(ROOT / "config/plugin_packages", tmp_path / "config/plugin_packages")
    plugins = subject.release_inventory(tmp_path, {key: {"version": "1.0.0"} for key in
                ("sli.ad", "sli.gpo", "sli.file-audit", "sli.workstations", "sli.sigma")})
    rows = [(key, value["version"], REGISTRY_HASH if key == "sli.remote-access" else "other")
            for key, value in plugins.items()]
    if bad in {"version", "hash"}:
        rows[-1] = ("sli.remote-access", "9.0.0" if bad == "version" else "0.1.0",
                    "0" * 64 if bad == "hash" else REGISTRY_HASH)
    elif bad == "duplicate":
        rows.append(rows[-1])
    elif bad == "missing":
        rows.pop()
    else:
        (tmp_path / "config/plugin_packages/sli.remote-access.json").write_text("{}")
    with pytest.raises(ValueError, match="native_plugins_.*mismatch"):
        subject.verify_registry(tmp_path, plugins, rows)


class Registry:
    def __init__(self, lifecycle="validated", checksum=REGISTRY_HASH):
        self.row = ["sli.remote-access.package.v1", checksum, "0.1.0", lifecycle,
                    "disabled", "stopped", "drained", 1]
        self.operations = []

    def transaction(self):
        return nullcontext()

    def execute(self, query, params=None):
        if "execute_bundled_plugin_install_v1" in query:
            self.operations.append(params)
            assert params[1:3] == ("sli.remote-access", 1)
            assert params[5:] == ("system", "native-bootstrap")
            assert len(params[3]) == 64 and params[4].startswith("PLUGIN-INSTALL-SLI-REMOTE-ACCESS-R1-")
            self.row[3] = "registered"
            self.row[-1] = 2
            return SimpleNamespace(fetchone=lambda: (1, 2, "registered", "disabled"))
        assert query.lstrip().lower().startswith("select ")
        assert params == ("sli.remote-access",)
        return SimpleNamespace(fetchone=lambda: tuple(self.row))


def test_native_bootstrap_registers_vpn_once_through_audited_executor():
    from deploy.linux import native_plugins as subject
    connection = Registry()
    subject.bootstrap(connection)
    subject.bootstrap(connection)
    assert len(connection.operations) == 1
    assert connection.row[3:] == ["registered", "disabled", "stopped", "drained", 2]


@pytest.mark.parametrize("lifecycle,checksum", [("detached", REGISTRY_HASH), ("validated", "0" * 64)])
def test_native_bootstrap_never_repairs_foreign_or_detached_vpn(lifecycle, checksum):
    from deploy.linux import native_plugins as subject
    connection = Registry(lifecycle, checksum)
    with pytest.raises(ValueError, match="native_plugins_bootstrap_mismatch"):
        subject.bootstrap(connection)
    assert not connection.operations


@pytest.mark.parametrize("mode,registrations", [("native", 1), ("docker", 0)])
def test_migrate_registers_bundled_vpn_only_for_native(tmp_path, monkeypatch, mode, registrations):
    from deploy.linux import backup, migrate

    class Connection(Registry):
        def execute(self, query, params=None):
            if "to_regclass" in query:
                return SimpleNamespace(fetchone=lambda: ("schema_migrations",))
            if "pg_advisory_lock" in query or query.startswith("revoke"):
                return None
            return super().execute(query, params)

    connection = Connection()
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", mode)
    monkeypatch.setenv("SLI_PG_ADMIN_PASSWORD_FILE", "synthetic-only")
    monkeypatch.setenv("SLI_PLATFORM_OWNER_PASSWORD_FILE", "synthetic-only")
    monkeypatch.setattr(backup, "helper_temporary_directory", lambda **kwargs: nullcontext(tmp_path))
    monkeypatch.setattr(backup, "pg_passfile", lambda **kwargs: nullcontext(tmp_path / "admin"))
    monkeypatch.setattr(migrate.psycopg, "connect", lambda **kwargs: nullcontext(connection))
    monkeypatch.setattr(migrate, "secret_value", lambda setting: "synthetic-only")
    for name in ("attest_ledger", "apply_pending", "create_platform_owner", "run_sql", "configure_worker_logins",
                 "configure_permanent_history"):
        monkeypatch.setattr(migrate, name, lambda *args, **kwargs: None)
    migrate.migrate()
    assert len(connection.operations) == registrations
