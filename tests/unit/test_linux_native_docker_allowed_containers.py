"""EXTCH2 admission and site contracts; synthetic files/Docker, no daemon."""
import json
from types import SimpleNamespace

import pytest

from deploy.linux import native_clickhouse_endpoint as ch
from deploy.linux import native_host as host
from deploy.linux import native_install, native_runtime

VPN = "amnezia-gateway-client"
INVALID_LIST = "native_site_docker_allowed_containers_invalid"


@pytest.fixture
def site(tmp_path, monkeypatch):
    path = tmp_path / "etc/sli/site.toml"
    path.parent.mkdir(parents=True)
    monkeypatch.setattr(ch, "trusted_text", lambda path: path.read_text(encoding="utf-8"))
    monkeypatch.setattr(native_install, "SITE", path)
    monkeypatch.setattr(native_install, "trusted", lambda path: path.read_bytes())
    return path


@pytest.mark.parametrize("names", [[], [VPN], ["a0", "a" * 63, "vpn_2.test-3"],
                                   [f"vpn-{i}" for i in range(8)]])
def test_site_accepts_bounded_exact_names_in_both_modes(site, names):
    for mode in ("native", "docker"):
        site.write_text(f'clickhouse_mode = "{mode}"\ndocker_allowed_containers = {json.dumps(names)}\n')
        settings = native_install.site_configuration()
        assert settings["docker_allowed_containers"] == names
        assert settings["bind"] == "127.0.0.1"
        assert ch.configured_mode(site.parents[2]) == mode
        assert host.Host(site.parents[2]).clickhouse_mode() == mode


@pytest.mark.parametrize("value", [
    '"amnezia-gateway-client"', "true", "1", "{}", '["ok", 1]',
    '["a"]', '["' + "a" * 64 + '"]', '["Amnezia"]', '["/amnezia"]',
    '["vpn*"]', '["vpn\\n"]', '["vpn space"]', '["-vpn"]',
    '["vpn", "vpn"]', '["sli-clickhouse-history"]', '["sli-clickhouse-other"]',
    '["sli-drill-0123456789abcdef-warm"]', '["sli-drill-other"]',
    json.dumps([f"vpn-{i}" for i in range(9)]),
])
def test_invalid_allowlist_is_rejected_by_install_host_and_runtime(site, value):
    site.write_text('clickhouse_mode = "docker"\ndocker_allowed_containers = ' + value + "\n")
    for read in (native_install.site_configuration,
                 host.Host(site.parents[2]).clickhouse_mode,
                 lambda: native_runtime.clickhouse.configured_mode(site.parents[2])):
        with pytest.raises(ValueError, match="^" + INVALID_LIST + "$"):
            read()


def foreign_container(name=VPN):
    # Deliberately fails CH confinement: root VPN with NET_ADMIN/TUN and Compose.
    return {"Name": "/" + name, "Image": "sha256:" + "0" * 64,
            "State": {"Running": True},
            "Mounts": [{"Type": "bind", "Source": "/dev/net/tun", "Destination": "/dev/net/tun"}],
            "Config": {"User": "0:0", "Labels": {"com.docker.compose.project": "amnezia"}},
            "HostConfig": {"NetworkMode": "host", "RestartPolicy": {"Name": "always"},
                           "ReadonlyRootfs": False, "CapAdd": ["NET_ADMIN"]}}


def inventory(rows):
    def run(argv):
        if argv == ["/usr/bin/docker", "container", "ls", "--all", "--quiet", "--no-trunc"]:
            return " ".join(f"id{i}" for i in range(len(rows)))
        if argv == ["/usr/bin/docker", "container", "inspect", *[f"id{i}" for i in range(len(rows))]]:
            return json.dumps(rows)
        pytest.fail("unexpected command: " + repr(argv))
    return run


def test_exactly_allowed_vpn_passes_without_ch_configuration_checks():
    ch.check_containers(inventory([foreign_container()]), allowed_containers=[VPN])


def test_allowed_vpn_does_not_hide_another_foreign_container():
    rows = [foreign_container(), foreign_container("unlisted")]
    with pytest.raises(ValueError, match="^native_docker_foreign_container$"):
        ch.check_containers(inventory(rows), allowed_containers=[VPN])


@pytest.mark.parametrize("name", [VPN, VPN + "-other", "other-" + VPN, VPN.upper(), "/" + VPN])
def test_unlisted_or_inexact_foreign_container_is_rejected(name):
    allowed = [] if name == VPN else [VPN]
    with pytest.raises(ValueError, match="^native_docker_foreign_container$"):
        ch.check_containers(inventory([foreign_container(name)]), allowed_containers=allowed)


@pytest.mark.parametrize("socket", ["/run/docker.sock", "/var/run/docker.sock"])
@pytest.mark.parametrize("field", ["Source", "Destination"])
def test_allowed_container_cannot_mount_docker_socket_at_any_destination(socket, field):
    row = foreign_container()
    row["Mounts"] = [{"Source": "/tmp/renamed.sock", "Destination": "/tmp/renamed.sock", field: socket}]
    with pytest.raises(ValueError, match="^native_docker_foreign_container$"):
        ch.check_containers(inventory([row]), allowed_containers=[VPN])


@pytest.mark.parametrize("project", ["sli", "sli-linux-stand", "sli-dev", "sli-audit-test"])
def test_allowed_container_cannot_belong_to_sli_compose(project):
    row = foreign_container()
    row["Config"]["Labels"]["com.docker.compose.project"] = project
    with pytest.raises(ValueError, match="^native_docker_foreign_container$"):
        ch.check_containers(inventory([row]), allowed_containers=[VPN])


@pytest.mark.parametrize("name", ["sli-clickhouse-history", "sli-drill-0123456789abcdef-history"])
def test_allowlist_cannot_bypass_ch_or_drill_checks_even_for_direct_callers(name):
    with pytest.raises(ValueError, match="^" + INVALID_LIST + "$"):
        ch.check_containers(inventory([foreign_container(name)]), allowed_containers=[name])


def test_allowed_vpn_does_not_bypass_drill_ownership_check():
    name = "sli-drill-0123456789abcdef-history"
    docker = inventory([foreign_container(), foreign_container(name)])
    def run(argv):
        if argv == ["systemctl", "show", name + ".service", "-p", "ActiveState", "-p", "User", "-p", "RuntimeMaxUSec"]:
            return "ActiveState=inactive\nUser=root\nRuntimeMaxUSec=1h\n"
        return docker(argv)
    with pytest.raises(ValueError, match="^native_docker_unowned_drill$"):
        ch.check_containers(run, allowed_containers=[VPN])


def test_host_docker_check_reads_the_root_owned_site_list(site, monkeypatch):
    site.write_text('clickhouse_mode = "docker"\ndocker_allowed_containers = ["' + VPN + '"]\n')
    docker = inventory([foreign_container()])
    def run(argv):
        if argv[0] == "dpkg-query":
            return ch.pins()["docker"]["packages"][argv[-1]]["version"]
        return docker(argv)
    monkeypatch.setattr(host, "run", run)
    monkeypatch.setattr(host, "group", lambda name: None)
    host.check_docker(site.parents[2])


@pytest.mark.parametrize("primary", [False, True])
def test_allowlist_does_not_grant_sli_identities_docker_group_access(site, monkeypatch, primary):
    site.write_text('docker_allowed_containers = ["' + VPN + '"]\n')
    def run(argv):
        if argv[0] == "dpkg-query":
            return ch.pins()["docker"]["packages"][argv[-1]]["version"]
        pytest.fail("Docker inventory must not run after exposed identity")
    monkeypatch.setattr(host, "run", run)
    monkeypatch.setattr(host, "group", lambda name: SimpleNamespace(gr_gid=999, gr_mem=[] if primary else ["sli-api"]))
    monkeypatch.setattr(host, "account", lambda name: SimpleNamespace(pw_gid=999 if primary else 998))
    with pytest.raises(host.HostError, match="^native_docker_socket_exposed$"):
        host.check_docker(site.parents[2])


def test_empty_legacy_site_keeps_original_install_hash_input(site):
    site.write_text("")
    assert native_install.site_configuration() == {"domain_fqdn": "example.invalid", "bind": "127.0.0.1"}


@pytest.mark.parametrize("text,code", [
    ('unknown = "value"', "native_site_setting_unsupported"),
    ('bind = "not-an-address"', "native_site_bind_invalid"),
    ('bind = 123', "native_site_bind_invalid"),
    ('domain_fqdn = "invalid"', "native_site_domain_invalid"),
    ('clickhouse_mode = "auto"', "native_clickhouse_mode_invalid"),
    ('docker_allowed_containers = [', "native_site_toml_invalid"),
])
def test_shared_site_parser_preserves_fixed_diagnostics(site, text, code):
    site.write_text(text)
    for read in (native_install.site_configuration,
                 host.Host(site.parents[2]).clickhouse_mode):
        with pytest.raises(ValueError, match="^" + code + "$"):
            read()
