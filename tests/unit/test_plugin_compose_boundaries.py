"""VP11: inspect declared container boundaries, without starting a container."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
STAND = ROOT / "deploy/linux"
EXECUTORS = tuple(f"executor-{profile}" for profile in ("light", "heavy", "long"))


def _assert_executor_plugin_mounts(volumes, profile):
    # Hot updates require shared generation pointers and admission-lock inodes.
    # Light also persists the workstation history transfer audit in sli-data.
    expected = {
        ("bind", str(ROOT / "runtime/plugins"), "/opt/sli/plugins", True),
        ("bind", str(ROOT / "config/plugin_packages/v3"), "/opt/sli/plugin-locks", True),
    }
    if profile == "light":
        expected.add(("volume", "sli-data", "/var/lib/sli", False))
    assert len(volumes) == len(expected)
    assert {(volume["type"], volume["source"], volume["target"], volume.get("read_only", False))
            for volume in volumes} == expected


@pytest.fixture(params=[(), ("executor",), ("ad-jobs",), ("executor", "ad-jobs", "agent")])
def compose_config(request):
    """Inspect Docker's resolved env/mount model, including overlay merge rules."""
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker Compose CLI required for resolved configuration inspection")
    env = {key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ}
    env.update({
        "SLI_SECRETS_DIR": "/tmp/sli-vp11-secrets",
        "SLI_BACKUP_DIR": "/tmp/sli-vp11-backups",
        "SLI_INSTALL_DOMAIN": "example.invalid",
        "SLI_HEALTH_URL": "https://example.invalid:8443/health",
        **{name: "/tmp/sli-vp11-certificate" for name in (
            "SLI_AGENT_CA_ROOT_CERT_FILE", "SLI_AGENT_CA_ISSUER_CERT_FILE",
            "SLI_AGENT_CA_ISSUER_KEY_FILE", "SLI_AGENT_MTLS_CA_FILE",
        )},
    })
    command = [docker, "compose", "--env-file", os.devnull, "-f", str(STAND / "docker-compose.yml")]
    for overlay in request.param:
        command.extend(["-f", str(STAND / f"docker-compose.{overlay}.yml")])
    command.extend(["--profile", "core-jobs", "--profile", "legacy-radius", "--profile", "legacy-ad",
                    "config", "--format", "json"])
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, "Docker Compose configuration inspection failed"
    return json.loads(result.stdout)


@pytest.mark.host_dependent  # requires the Docker Compose v2 CLI, not just docker
def test_only_api_publishes_ports(compose_config):
    services = compose_config["services"]
    assert {name for name, service in services.items() if service.get("ports")} == {"api"}
    assert [(port["target"], str(port["published"])) for port in services["api"]["ports"]] == [(8443, "8443")]
    for service in services.values():
        assert service.get("network_mode") != "host"
        assert not service.get("privileged")


@pytest.mark.host_dependent
def test_executor_environment_and_secret_mounts_are_profile_scoped(compose_config):
    for name in EXECUTORS:
        service = compose_config["services"][name]
        profile = name.removeprefix("executor-")
        expected = {f"job_{purpose}_{profile}" for purpose in ("dispatcher", "executor", "publisher")}
        if profile == "light":
            expected.add("history_password")
        secrets = service["secrets"]
        assert {secret["source"] for secret in secrets} == expected
        assert {secret["target"] for secret in secrets} == expected
        env = service["environment"]
        password_keys = {
            f"SLI_JOB_{purpose.upper()}_{profile.upper()}_PASSWORD_FILE"
            for purpose in ("dispatcher", "executor", "publisher")
        }
        if profile == "light":
            password_keys.add("ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE")
            assert env["ADLOG_HISTORY_READ_MODE"] == "primary"
            assert env["ADLOG_HISTORY_CLICKHOUSE_HOST"] == "clickhouse"
            assert env["ADLOG_HISTORY_CLICKHOUSE_PORT"] == "8123"
            assert env["ADLOG_DATA_DIR"] == "/var/lib/sli"
            assert env["SLI_CORE_JOB_WORKSTATIONS_RETENTION"] == "0"
        assert {key for key in env if "PASSWORD" in key} == password_keys
        assert {value for key, value in env.items() if key.endswith("_FILE")} == {
            f"/run/secrets/{secret}" for secret in expected
        }
        assert not any(key.endswith("_DSN") or key in {"PGPASSWORD", "PGPASSFILE", "SLI_JOB_CHILD_CONNECTION"}
                       for key in env)
        assert not service.get("env_file")
        _assert_executor_plugin_mounts(service["volumes"], profile)
        assert env["SLI_PLUGIN_RUNTIME_DIR"] == "/opt/sli/plugins"
        assert env["SLI_PLUGIN_LOCK_DIR"] == "/opt/sli/plugin-locks"
    legacy = compose_config["services"]["remote-access"]
    # Legacy is core-hosted, not the profile-restricted handler path. Keep its
    # known broader credentials visible in this test and the boundary document.
    assert {secret["source"] for secret in legacy["secrets"]} == {"runtime_password", "history_password"}


@pytest.mark.host_dependent
def test_handler_root_is_read_only_with_bounded_container_resources(compose_config):
    for name in (*EXECUTORS, "remote-access"):
        service = compose_config["services"][name]
        assert service["read_only"] is True
        assert "/tmp:mode=1777" in service["tmpfs"]
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
    for name in EXECUTORS:
        service = compose_config["services"][name]
        assert service["pids_limit"] == 64
        assert service["mem_limit"] > 0
        assert service["cpus"] == 1.0


@pytest.mark.host_dependent
def test_current_network_layout_has_no_egress_allowlist(compose_config):
    # Publishing no ports restricts ingress, not egress. This assertion records
    # the current limitation; change it alongside enforced egress policies.
    assert set(compose_config["networks"]) == {"default"}
    assert not compose_config["networks"]["default"].get("internal", False)
    for name in (*EXECUTORS, "remote-access"):
        assert set(compose_config["services"][name]["networks"]) == {"default"}


def test_source_compose_keeps_executor_boundaries_without_docker_cli():
    config = yaml.safe_load((STAND / "docker-compose.yml").read_text("utf-8"))
    services = config["services"]
    assert {name for name, service in services.items() if service.get("ports")} == {"api"}
    for name in EXECUTORS:
        service = services[name]
        profile = name.removeprefix("executor-")
        expected_secrets = {f"job_{purpose}_{profile}" for purpose in ("dispatcher", "executor", "publisher")}
        if profile == "light":
            expected_secrets.add("history_password")
        assert set(service["secrets"]) == expected_secrets
        assert service["read_only"] is True and "/tmp:mode=1777" in service["tmpfs"]
        # Keep the shared update fence/locks; only light writes the transfer audit.
        expected_volumes = [
            "${SLI_PLUGIN_DIR:-../../runtime/plugins}:/opt/sli/plugins:ro",
            "../../config/plugin_packages/v3:/opt/sli/plugin-locks:ro",
        ]
        if profile == "light":
            expected_volumes.insert(0, "sli-data:/var/lib/sli")
            assert service["environment"]["ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE"] == "/run/secrets/history_password"
            assert service["environment"]["ADLOG_DATA_DIR"] == "/var/lib/sli"
        assert service["volumes"] == expected_volumes
        assert service["environment"]["SLI_PLUGIN_RUNTIME_DIR"] == "/opt/sli/plugins"
        assert service["environment"]["SLI_PLUGIN_LOCK_DIR"] == "/opt/sli/plugin-locks"
        assert all(key.endswith("_FILE") for key in service["environment"] if "PASSWORD" in key)
