"""Clean-install boot contracts; no host services, packages or data are touched."""
from contextlib import nullcontext
import json
from types import SimpleNamespace

import pytest

from deploy.linux import native_backup, native_dotnet_generator, native_host as host
from deploy.linux import native_install as install, native_package as package
from deploy.linux import native_runtime as runtime


def values(body, directive):
    return {value for line in body.splitlines() if line.startswith(directive + "=")
            for value in line.split("=", 1)[1].split()}


@pytest.mark.parametrize("mode", ["native", "docker"])
def test_clean_install_units_have_complete_boot_chain(tmp_path, monkeypatch, mode):
    config = {"schema_version": 1, "profiles": ["light", "heavy", "long"], "radius_pilot": False,
              "bind": "192.0.2.10", "health_url": "https://192.0.2.10:8443/api/health/ready"}
    monkeypatch.setattr(runtime.clickhouse, "configured_mode", lambda: mode)
    monkeypatch.setattr(runtime, "CONFIG", tmp_path / "runtime.json")
    monkeypatch.setattr(runtime, "trusted", lambda path: path.read_bytes())
    rendered = {**host.units(mode), **runtime.units(config)}
    runtime.CONFIG.write_text(json.dumps(config))
    destination = tmp_path / "generator"
    destination.mkdir()
    native_dotnet_generator.generate(runtime, "test", destination)
    rendered.update({path.name: path.read_text() for path in destination.iterdir()})

    platform = rendered["sli.target"]
    assert values(platform, "WantedBy") == {"multi-user.target"}
    assert values(platform, "Also") == set(runtime.DATABASES)
    assert values(platform, "Requires") == values(platform, "After") == {"sli-dotnet.target"}
    for database in runtime.DATABASES:
        body = rendered[database]
        assert values(body, "WantedBy") == {"multi-user.target"}
        mount = r"srv-sli\x2ddb.mount"
        assert mount in values(body, "BindsTo") & values(body, "After")
        assert "/srv/sli-db" in values(body, "RequiresMountsFor")
        assert "check-mount" in body

    ready = rendered["sli-ready.service"]
    assert set(runtime.DATABASES) <= values(ready, "Wants") & values(ready, "After")
    target = rendered["sli-dotnet.target"]
    assert values(target, "PartOf") == {"sli.target"}
    names = set(map(runtime.dotnet_unit_name, runtime.selected(config)))
    assert not values(target, "Conflicts")
    assert "sli-ready.service" in values(target, "Requires") & values(target, "After")
    assert names <= values(target, "Wants")
    assert values(target, "Wants") - {"sli-health.timer"} == names
    for name in names:
        assert "sli-ready.service" in values(rendered[name], "Requires") & values(rendered[name], "After")


@pytest.mark.parametrize("accepted", [False, True])
def test_apt_clean_install_enables_boot_only_after_acceptance(tmp_path, monkeypatch, accepted):
    state, release = tmp_path / "state", tmp_path / "release"
    state.mkdir()
    release.mkdir()
    calls = []
    config = {"domain_fqdn": "example.test", "bind": "192.0.2.10"}
    manifest = {"schema_version": 1, "python": "/fake/python"}
    monkeypatch.setattr(install, "STATE", state)
    monkeypatch.setattr(install, "CURRENT", tmp_path / "unselected")
    monkeypatch.setattr(install, "inventory", lambda name: (release, manifest, "digest"))
    monkeypatch.setattr(install, "site_configuration", lambda: config)
    monkeypatch.setattr(install, "runtime_settings", lambda site: config)
    monkeypatch.setattr(install.platform, "freedesktop_os_release",
                        lambda: {"ID": "debian", "VERSION_ID": "13"}, raising=False)
    monkeypatch.setattr(install.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(install, "atomic", lambda path, value: path.write_text(json.dumps(value)))
    monkeypatch.setattr(install, "command", lambda argv, **kw: calls.append(argv))
    monkeypatch.setattr(install, "select", lambda root: None)
    monkeypatch.setattr(install, "wait_api", lambda settings: None)
    monkeypatch.setattr(install, "preserve_recovery", lambda *args: calls.append("recovery"))

    def health():
        calls.append("acceptance")
        if not accepted:
            raise RuntimeError("synthetic_health_failed")

    monkeypatch.setattr(install, "wait_health", health)
    monkeypatch.setattr(host, "Host", lambda: SimpleNamespace(receipt=lambda: None, configure=lambda: None))
    monkeypatch.setattr(host, "administrative_lock", nullcontext)
    monkeypatch.setattr(host, "validate_identity", lambda: None)
    monkeypatch.setattr(host, "MOUNT", str(tmp_path / "empty-data"))
    monkeypatch.setattr(runtime.clickhouse, "manifest_version", lambda *args: None)
    monkeypatch.setattr(runtime.clickhouse, "configured_mode", lambda: "native")
    monkeypatch.setattr(runtime, "no_transaction", lambda: None)
    monkeypatch.setattr(runtime, "wait_databases", lambda: None)
    monkeypatch.setattr(runtime, "configure", lambda settings: None)
    monkeypatch.setattr(runtime, "configuration", lambda: config)
    monkeypatch.setattr(runtime, "selected", lambda settings: ["api"])
    monkeypatch.setattr(runtime, "systemd", lambda name: {"ActiveState": "active", "MainPID": "42"})
    monkeypatch.setattr(runtime, "stop_writers", lambda: None)
    monkeypatch.setattr(native_backup, "configure", lambda: None)

    # The apt postinst stages the fresh installation through this coordinator.
    assert "else exec /usr/sbin/sli-native-install stage test" in package.scripts("test", "1.0-1~deb13")["postinst"]
    enable = ["systemctl", "enable", "sli.target"]
    if accepted:
        install.configure("test")
        assert calls.index("acceptance") < calls.index("recovery") < calls.index(enable)
        assert json.loads((state / "package-install.json").read_text())["status"] == "configured"
    else:
        with pytest.raises(RuntimeError, match="synthetic_health_failed"):
            install.configure("test")
        assert enable not in calls
        assert ["systemctl", "disable", "sli.target"] in calls


def test_dotnet_monitoring_and_stop_follow_the_boot_backend(tmp_path, monkeypatch):
    generator = tmp_path / "sli-dotnet-api"
    monkeypatch.setattr(runtime, "DOTNET_GENERATOR", generator)
    assert runtime.active_unit_name("api") == "sli-dotnet-api.service"
    generator.write_text("synthetic package generator")
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="ActiveState=inactive\nMainPID=0\nControlGroup=\n")

    monkeypatch.setattr(runtime.subprocess, "run", run)
    assert runtime.stop_writers()
    assert calls[0] == ["systemctl", "stop", "sli-runtime.target", *map(runtime.unit_name, runtime.SERVICES)]
    dotnet_stop = len(runtime.SERVICES) + 1
    assert calls[dotnet_stop] == ["systemctl", "stop", "sli-dotnet.target",
                        *map(runtime.dotnet_unit_name, (*runtime.SERVICES, *runtime.DOTNET_ONLY_SERVICES))]
    assert all("sli-dotnet-" not in argv[2] for argv in calls[1:dotnet_stop])
    assert all("sli-dotnet-" in argv[2] for argv in calls[dotnet_stop + 1:])
    assert not set(runtime.DATABASES).intersection(calls[0])
    assert not set(runtime.DATABASES).intersection(calls[dotnet_stop])
