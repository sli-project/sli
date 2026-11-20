"""Portable EXTCH contracts: synthetic CPU/files/systemd/Docker, no daemon."""
import json
from pathlib import Path

import pytest

from deploy.linux import native_clickhouse_endpoint as ch


@pytest.mark.parametrize("settings,cpu,expected", [
    ({}, "flags : sse avx avx2\n", "native"),
    ({}, "flags : sse avx\n", "docker"),
    ({}, "flags : avx2\nflags : avx\n", "docker"),
    ({"clickhouse_mode": "docker"}, "flags : avx2", "docker"),
    ({"clickhouse_mode": "native"}, "flags : sse", "native"),
])
def test_mode_selection(settings, cpu, expected):
    assert ch.select_mode(settings, cpu) == expected


@pytest.mark.parametrize("mode", [None, "", "auto", "Docker", 1, [], "docker\n"])
def test_explicit_invalid_mode_fails_closed(mode):
    with pytest.raises(ValueError, match="clickhouse_mode_invalid"):
        ch.select_mode({"clickhouse_mode": mode}, "flags : avx2")


def test_missing_cpu_flags_does_not_assume_avx2():
    with pytest.raises(ValueError, match="cpu_flags_unavailable"):
        ch.select_mode({}, "processor : 0\n")


@pytest.mark.parametrize("mode", ["native", "docker"])
def test_endpoint_contract_and_version(mode):
    history, warm = [ch.endpoint(n, mode) for n in ch.INSTANCES]
    assert [(e.http, e.tcp, e.user) for e in (history, warm)] == [(8123, 9000, "sli_history"), (8124, 9001, "default")]
    assert history.unit == "sli-clickhouse-history.service"
    assert warm.unit == "sli-clickhouse-warm.service"
    assert history.version == ("25.8.33.6" if mode == "docker" else "26.8.35.10")
    assert history.backup_host == "/var/backups/sli/staging/history"
    assert history.backup_server == ("/var/lib/clickhouse/backups" if mode == "docker" else history.backup_host)


@pytest.mark.parametrize("name", ["history", "warm"])
def test_docker_run_is_offline_nonroot_confined_and_systemd_owned(name):
    e = ch.endpoint(name, "docker")
    argv = e.server_command(123, 456)
    assert argv[:2] == ["/usr/bin/docker", "run"]
    assert argv[argv.index("--user") + 1] == "123:456"
    assert argv[argv.index("--restart") + 1] == "no"
    assert argv[argv.index("--pull") + 1] == "never"
    assert argv[argv.index("--network") + 1] == "bridge"
    assert "--read-only" in argv and "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges" in argv
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--publish"] == [f"127.0.0.1:{e.http}:{e.http}", f"127.0.0.1:{e.tcp}:{e.tcp}"]
    assert e.image_id in argv and "--entrypoint=/usr/bin/clickhouse-server" in argv
    assert f"{e.config}:{e.config}:ro" in argv
    assert f"/run/sli-ch-{name}:/run/sli-ch-{name}:ro" in argv
    assert f"{e.backup_host}:/var/lib/clickhouse/backups:rw" in argv
    assert not any("docker.sock" in a or "password" in a for a in argv)
    assert "--memory" in argv and "--cpus" in argv


def test_native_command_never_uses_docker():
    assert ch.endpoint("history", "native").server_command() == [
        "/usr/bin/clickhouse-server", "--config-file=/etc/sli/clickhouse/history/config.xml"]


def test_mode_change_requires_separate_coordinator():
    for old, new in (("native", "docker"), ("docker", "native")):
        with pytest.raises(ValueError, match="mode_change_requires_migration"):
            ch.require_same_mode({"clickhouse_mode": old}, new)
    ch.require_same_mode({}, "native")  # Legacy receipt.
    ch.require_same_mode({"clickhouse_mode": "docker"}, "docker")


def test_pins_keep_original_authenticated_native_snapshot_and_add_docker():
    pins = json.loads(Path(ch.__file__).with_name("native_pins.json").read_text())
    docker = pins["clickhouse_modes"]["docker"]
    assert docker["version"] == "25.8.33.6"
    assert docker["image"]["reference"] == "clickhouse/clickhouse-server:25.8.33.6"
    assert docker["image"]["id"].startswith("sha256:")
    assert docker["packages"]["docker.io"]["version"] == "26.1.5+dfsg1-9+deb13u1"
    assert len(docker["packages"]["docker.io"]["sha256"]) == 64
    assert len(pins["packages"]) == 88
