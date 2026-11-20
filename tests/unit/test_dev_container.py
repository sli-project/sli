"""Development container contracts; no Docker or database is needed."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DEV = ROOT / "deploy/dev"


def read(name: str) -> str:
    return (DEV / name).read_text(encoding="utf-8")


def compose() -> dict:
    return yaml.safe_load(read("docker-compose.yml"))


def test_default_services_bind_host_source_and_isolate_linux_dependencies():
    config = compose()
    assert config["name"] == "sli-dev"
    assert set(config["volumes"]) == {
        "sli-dev-venv", "sli-dev-node-modules", "sli-dev-frontend-node-modules",
        "sli-dev-npm-cache",
    }
    assert all(key == value["name"] for key, value in config["volumes"].items())
    services = config["services"]
    assert {name for name, service in services.items() if not service.get("profiles")} == {
        "dev", "pg-test",
    }
    dev = services["dev"]
    assert dev["user"] == "dev"
    assert dev["working_dir"] == "/workspace/sli-platform"
    assert dev["command"] == ["sleep", "infinity"]
    assert dev["init"] is True
    assert dev["volumes"] == [
        {
            "type": "bind",
            "source": "${SLI_DEV_SOURCE:?Set absolute path of the development clone}",
            "target": "/workspace/sli-platform",
            "bind": {"create_host_path": False},
        },
        "sli-dev-venv:/opt/venv",
        "sli-dev-node-modules:/workspace/sli-platform/node_modules",
        "sli-dev-frontend-node-modules:/workspace/sli-platform/frontend/node_modules",
        "sli-dev-npm-cache:/home/dev/.npm",
    ]
    assert dev["depends_on"] == {"pg-test": {"condition": "service_healthy"}}
    assert dev["build"] == {"context": ".", "dockerfile": "Dockerfile"}


def test_socket_is_only_mounted_in_opt_in_profile_without_root_or_privilege():
    services = compose()["services"]
    for name, service in services.items():
        assert not service.get("privileged")
        assert "network_mode" not in service
        if name != "dev-docker":
            assert "docker.sock" not in str(service)
            assert "group_add" not in service
    docker = services["dev-docker"]
    assert docker["profiles"] == ["docker-socket"]
    assert docker["user"] == "dev"
    assert docker["group_add"] == ["${SLI_DEV_DOCKER_GID:-65534}"]
    assert docker["volumes"][:-1] == services["dev"]["volumes"]
    assert docker["volumes"][-1] == {
        "type": "bind", "source": "/var/run/docker.sock",
        "target": "/var/run/docker.sock", "bind": {"create_host_path": False},
    }


def test_compose_env_has_no_credentials_and_integration_dsns_use_only_pg_test():
    config = compose()
    assert "secrets" not in config
    for service in config["services"].values():
        assert "secrets" not in service
        for key, value in service["environment"].items():
            assert not re.search(r"password|token|secret|api_key", key, re.IGNORECASE)
            if "DSN" in key:
                dsn = urlsplit(value)
                assert dsn.password is None
                if key.startswith("ADLOG_TEST_"):
                    assert dsn.hostname == "pg-test"
                    assert dsn.port == 5432
                    assert dsn.username == "postgres"
                    assert dsn.path in {"/sli_test_dev", "/sli_test_empty_dev"}
                else:
                    assert dsn.hostname == "sli-pytest.invalid"
    env = config["services"]["dev"]["environment"]
    assert env["ADLOG_DB_BACKEND"] == "postgres"
    assert {key for key in env if key.startswith("ADLOG_TEST_")} == {
        "ADLOG_TEST_PG_DSN", "ADLOG_TEST_PG_EMPTY_DSN",
    }


def test_pg18_is_disposable_without_host_ports_or_runtime_network():
    pg = compose()["services"]["pg-test"]
    assert pg["image"].startswith("postgres:18.")
    assert "ports" not in pg
    assert "volumes" not in pg
    assert pg["tmpfs"] == ["/var/lib/postgresql"]
    assert pg["networks"] == ["default"]
    assert pg["environment"]["POSTGRES_HOST_AUTH_METHOD"] == "trust"
    assert pg["healthcheck"]["test"] == [
        "CMD-SHELL", "pg_isready -U postgres -d postgres",
    ]


def test_runtime_network_requires_an_explicit_override_and_name():
    assert "networks" not in compose()
    override = yaml.safe_load(read("docker-compose.runtime.yml"))
    assert set(override["services"]) == {"dev", "dev-docker"}
    assert all(service["networks"] == ["default", "runtime"]
               for service in override["services"].values())
    assert override["networks"]["runtime"]["external"] is True
    assert override["networks"]["runtime"]["name"].startswith("${SLI_RUNTIME_NETWORK:?")


def test_dockerfile_versions_match_runtime_and_ci_and_install_required_tools():
    dockerfile = read("Dockerfile")
    runtime = (ROOT / "deploy/linux/Dockerfile").read_text(encoding="utf-8")
    ci = yaml.safe_load((ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8"))
    node_versions = {str(step["with"]["node-version"])
                     for job in ci["jobs"].values() for step in job.get("steps", [])
                     if "node-version" in step.get("with", {})}
    assert node_versions == {"22"}
    assert "FROM node:22-bookworm-slim AS node" in dockerfile
    runtime_python_images = re.findall(r"^FROM (python:\S+)$", runtime, re.MULTILINE)
    assert len(runtime_python_images) == 1
    assert f"FROM {runtime_python_images[0]}" in dockerfile.splitlines()
    for package in (
        "git", "postgresql-client-18", "build-essential", "libffi-dev",
        "libssl-dev", "libpq-dev", "pkg-config", "docker-ce-cli", "docker-compose-plugin",
    ):
        assert re.search(rf"\b{re.escape(package)}\b", dockerfile)
    assert not re.search(r"\b(?:gh|openssh-client)\b", dockerfile)
    assert "@openai/codex" not in dockerfile
    assert "@anthropic-ai/claude-code" not in dockerfile
    npm_version = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["packageManager"]
    assert f"--cache /tmp/npm-cache {npm_version}" in dockerfile
    assert "sudo" not in dockerfile
    assert "USER dev\nWORKDIR /workspace/sli-platform\n" in dockerfile
    directories = re.search(r"mkdir -p (.*?)\s+&& chown -R dev:dev", dockerfile, re.DOTALL)
    assert directories is not None
    for directory in (
        "/opt/venv", "/workspace/sli-platform/node_modules",
        "/workspace/sli-platform/frontend/node_modules", "/home/dev/.npm",
    ):
        assert directory in directories[1].replace("\\\n", "").split()
    assert "chown -R dev:dev /opt/venv /workspace /home/dev" in dockerfile
    assert dockerfile.index("chown -R dev:dev") < dockerfile.index("USER dev")
    assert 'VIRTUAL_ENV=/opt/venv PATH="/opt/venv/bin:${PATH}"' in dockerfile
    assert ".venv" not in dockerfile
    assert 'ENTRYPOINT ["bash", "/usr/local/bin/sli-dev-bootstrap"]' in dockerfile
    assert 'CMD ["sleep", "infinity"]' in dockerfile
    assert read("Dockerfile.dockerignore").splitlines() == ["**", "!Dockerfile", "!bootstrap.sh"]
    assert re.findall(r"^COPY (?!.*--from=).+$", dockerfile, re.MULTILINE) == [
        "COPY bootstrap.sh /usr/local/bin/sli-dev-bootstrap",
    ]


def test_bootstrap_guards_mount_and_venv_and_writes_stamps_only_after_install():
    script = read("bootstrap.sh")
    assert script.startswith("#!/usr/bin/env bash\nset -euo pipefail\numask 077\n")
    assert "repo=/workspace/sli-platform\nvenv=/opt/venv\n" in script
    for manifest in ("requirements.txt", "package-lock.json", "frontend/package-lock.json"):
        assert f'! -f "$repo/{manifest}"' in script
    assert script.index("exit 1") < script.index('cd "$repo"')
    assert re.search(
        r'if \[\[ ! -x "\$venv/bin/python" \]\]; then\s+python -m venv "\$venv"\s+fi',
        script,
    )
    assert "python_stamp=$venv/.sli-dev-requirements.sha256" in script
    assert '"$venv/bin/python" -m pip install --disable-pip-version-check -r requirements.txt ruff==0.16.9' in script
    assert ".venv" not in script
    assert 'requirements_hash=$(sha256sum requirements.txt)' in script
    assert '[[ ! -f "$python_stamp" ]] || [[ "$(cat "$python_stamp")" != "$requirements_hash" ]]' in script
    assert script.index("pip install ") < script.index('> "$python_stamp"')
    assert "sha256sum package.json package-lock.json" in script
    assert '[[ ! -f "$stamp" ]] || [[ "$(cat "$stamp")" != "$dependency_hash" ]]' in script
    assert script.index("npm ci") < script.index('> "$stamp"')
    assert "install_node_dependencies .\ninstall_node_dependencies frontend" in script
    assert 'exec "$@"' in script
    assert "\r" not in (DEV / "bootstrap.sh").read_bytes().decode("utf-8")
    assert "deploy/dev/*.sh text eol=lf" in (ROOT / ".gitattributes").read_text(encoding="utf-8")


def test_bootstrap_has_no_git_operations_or_container_logins():
    script = read("bootstrap.sh")
    assert "cat <<'NEXT_STEPS'" in script
    instructions = script.split("cat <<'NEXT_STEPS'", 1)[1].split("\nNEXT_STEPS", 1)[0]
    assert "Windows host with its existing auth" in instructions
    for command in ("gh auth", "codex login", "claude login", "git clone", ".git"):
        assert command not in script
    executable = script.replace(instructions, "")
    assert not re.search(r"\b(?:git|gh|codex|claude)\b|rm -|sudo|set -x|--with-token", executable)


@pytest.mark.skipif(os.name == "nt", reason="Linux development bootstrap")
@pytest.mark.parametrize(
    ("uid", "message"),
    [(0, "Run the development container as dev (--user dev), not root"),
     (1000, "Mount the development clone")],
)
def test_bootstrap_rejects_root_before_touching_dependency_volumes(tmp_path, uid, message):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_id = fake_bin / "id"
    fake_id.write_text(f"#!/bin/sh\nprintf '%s\\n' {uid}\n", encoding="utf-8")
    fake_id.chmod(0o755)
    # A missing checkout prevents any real dependency installation on regression.
    script = read("bootstrap.sh").replace(
        "repo=/workspace/sli-platform", f'repo="{tmp_path}/missing-checkout"',
    )
    result = subprocess.run(
        [shutil.which("bash"), "-c", script],
        env={**os.environ, "PATH": str(fake_bin)},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 1
    assert message in result.stderr
    assert result.stdout == ""
    assert sorted(path.name for path in tmp_path.iterdir()) == ["bin"]
