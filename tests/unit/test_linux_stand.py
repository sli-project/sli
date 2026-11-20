# ruff: noqa: F811 -- imported pytest fixtures are intentionally named as parameters
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from deploy.linux import entrypoint, healthcheck, migrate, restore_existing
from scripts.maintenance.existing_postgres_bootstrap import (
    forward_migration_inventory,
    load_baseline,
)
from tests.tooling.test_release_package import (
    signed_package,  # noqa: F401 - shared pytest fixture
)

ROOT = Path(__file__).resolve().parents[2]
STAND = ROOT / "deploy/linux"
MANIFEST_BASELINE = int(json.loads((ROOT / "config/postgres_baseline/manifest.json").read_text(encoding="utf-8"))["baseline_version"])


def test_linux_image_builds_and_publishes_frontend_from_source():
    dockerfile = (STAND / "Dockerfile").read_text(encoding="utf-8").replace("\\\n", "")
    build, separator, _ = dockerfile.partition("\nFROM python:")
    assert separator, "frontend build must precede the Python runtime stage"
    workflow = yaml.safe_load((ROOT / ".github/workflows/pr-gate.yml").read_text(encoding="utf-8"))
    node_major = next(step["with"]["node-version"] for step in workflow["jobs"]["frontend"]["steps"]
                      if step.get("uses") == "./artifacts/ci-actions/setup-node")
    assert build.startswith(f"FROM node:{node_major}-bookworm-slim AS frontend-build\n")
    assert "WORKDIR /opt/sli" in build
    assert "apt-get install -y --no-install-recommends python3" in build
    ordered_steps = [
        "COPY package.json package-lock.json ./",
        "RUN npm ci",
        "COPY frontend/package.json frontend/package-lock.json frontend/",
        "RUN npm --prefix frontend ci",
        "COPY frontend/ frontend/",
        "COPY scripts/maintenance/publish_react_build.py scripts/maintenance/publish_react_build.py",
        "COPY web/app/ /tmp/web-app/",
        # Same layer as the publisher: overlayfs cannot rename lower-layer directories.
        "cp -a /tmp/web-app/. web/app/",
        "npm --prefix frontend run build",
        "python3 scripts/maintenance/publish_react_build.py",
        "--source artifacts/frontend/react-build --apply --confirm PUBLISH-REACT-BUILD",
    ]
    positions = [build.index(step) for step in ordered_steps]
    assert positions == sorted(positions)


def test_linux_image_runtime_copies_published_assets_without_build_dependencies():
    dockerfile = (STAND / "Dockerfile").read_text(encoding="utf-8")
    runtime = dockerfile.rsplit("\nFROM ", 1)[-1]
    assert runtime.startswith("python:3.14.6-slim-bookworm")
    copies = [shlex.split(line)[1:] for line in runtime.splitlines() if line.startswith("COPY ")]
    assert ["--from=frontend-build", "/opt/sli/web/app/", "web/app/"] in copies
    assert all("frontend" not in source and "node_modules" not in source
               for sources in copies for source in sources if not source.startswith("--from="))
    assert ["web/app/", "web/app/"] not in copies
    assert "npm " not in runtime
    assert "USER sli\n" in runtime
    assert 'ENTRYPOINT ["python", "-m", "deploy.linux.entrypoint"]' in runtime


def test_linux_build_context_allows_frontend_sources_but_excludes_node_modules():
    patterns = (STAND / "Dockerfile.dockerignore").read_text(encoding="utf-8").splitlines()
    for included in ("!package.json", "!package-lock.json", "!frontend/", "!frontend/**",
                     "!scripts/maintenance/publish_react_build.py"):
        assert included in patterns
    # Later exclusions override the frontend allowlist, including nested installs.
    for excluded in ("**/node_modules", "**/node_modules/**"):
        assert patterns.index(excluded) > patterns.index("!frontend/**")


def test_linux_image_includes_dc_importer_and_its_build_context():
    patterns = (STAND / "Dockerfile.dockerignore").read_text(encoding="utf-8").splitlines()
    assert "!scripts/import/" in patterns
    assert "!scripts/import/**" in patterns
    dockerfile = (STAND / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY scripts/import/ scripts/import/" in dockerfile


def test_post_collection_dc_import_is_opt_in_with_storage_worker_credentials():
    compose = yaml.safe_load((STAND / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["post-collection"]
    assert service["environment"]["SLI_AD_DC_AGENT_IMPORT_ENABLED"] == "${SLI_AD_DC_AGENT_IMPORT_ENABLED:-0}"
    assert service["environment"]["ADLOG_STORAGE_V2_WORKER_DSN"] == "host=postgres port=5432 dbname=sli user=sli_storage_login"
    assert service["environment"]["ADLOG_STORAGE_V2_WORKER_PASSWORD_FILE"] == "/run/secrets/storage_password"
    assert "storage_password" in service["secrets"]


def test_snapshot_publication_credentials_are_scoped_to_post_collection_and_migrate():
    compose = yaml.safe_load((STAND / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["post-collection"]
    assert service["environment"]["ADLOG_AD_CONTEXT_WORKER_DSN"] == "host=postgres port=5432 dbname=sli user=sli_context_login"
    assert service["environment"]["ADLOG_AD_CONTEXT_WORKER_PASSWORD_FILE"] == "/run/secrets/context_password"
    assert ("sli_context_login", "adlog_context_worker", "ADLOG_AD_CONTEXT_WORKER_PASSWORD") in migrate.WORKER_LOGINS
    assert compose["services"]["migrate"]["environment"]["ADLOG_AD_CONTEXT_WORKER_PASSWORD_FILE"] == "/run/secrets/context_password"
    for name, settings in compose["services"].items():
        assert ("context_password" in settings.get("secrets", [])) == (name in {"migrate", "post-collection"})
    for override in ("docker-compose.ad-jobs.yml", "docker-compose.executor.yml"):
        settings = yaml.safe_load((STAND / override).read_text(encoding="utf-8"))
        assert "context_password" in settings["services"]["migrate"]["secrets"]


def test_server_and_stand_workers_import_with_windows_modules_unavailable(tmp_path):
    # Reproduce runtime source COPYs; built web assets are covered separately.
    allowed = (STAND / "Dockerfile.dockerignore").read_text(encoding="utf-8").splitlines()
    assert "!sli_collect/" in allowed and "!sli_collect/**" in allowed
    assert "!deploy/linux/restore_existing.py" in allowed
    image_root = tmp_path / "image"
    image_root.mkdir()
    runtime = (STAND / "Dockerfile").read_text(encoding="utf-8").rsplit("\nFROM ", 1)[-1]
    for line in runtime.splitlines():
        if not line.startswith("COPY ") or line.startswith("COPY --from="):
            continue
        *sources, destination = shlex.split(line)[1:]
        for source in sources:
            source_path = ROOT / source
            target = image_root / destination
            if source_path.is_dir():
                shutil.copytree(source_path, target, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            else:
                if destination.endswith("/"):
                    target = target / source_path.name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, target)
    assert not (image_root / "scripts/maintenance/release_package.py").exists()
    # Fresh interpreter: cached Windows modules cannot conceal accidental imports.
    script = r'''
import importlib
import importlib.abc
import ctypes
import sys
import psycopg

class NoWindows(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "scripts.maintenance.release_package":
            raise ModuleNotFoundError("release tooling unavailable in server runtime", name=fullname)
        root = fullname.split(".")[0]
        if root.startswith("win32") or root in {"msvcrt", "winreg", "ntsecuritycon", "pythoncom", "pywintypes"}:
            raise ModuleNotFoundError("Windows module unavailable on Linux", name=fullname)

for name in tuple(sys.modules):
    if name.startswith("win32") or name in {"msvcrt", "winreg", "ntsecuritycon", "pythoncom", "pywintypes"}:
        del sys.modules[name]
sys.meta_path.insert(0, NoWindows())
sys.platform = "linux"
if hasattr(ctypes, "windll"):
    del ctypes.windll
def no_db(*args, **kwargs):
    raise AssertionError("database access during import")
psycopg.connect = no_db
from deploy.linux.entrypoint import WORKERS
for module in ["server.api.http_server", "scripts.run_server", "deploy.linux.migrate", "deploy.linux.restore_existing", "deploy.linux.healthcheck", "scripts.import.import_event_jsonl_to_postgres", *WORKERS.values()]:
    importlib.import_module(module)
print("linux_imports_verified")
'''
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("ADLOG_", "SLI_", "PG"))}
    environment.pop("PYTHONPATH", None)
    environment.update(ADLOG_DATA_DIR=str(tmp_path), PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, "-c", script], cwd=image_root, env=environment,
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "linux_imports_verified"


def test_package_verification_image_can_verify_without_checkout(signed_package, tmp_path):
    """Catch missing runtime dependencies in the verification image's COPY list."""
    source = Path(__file__).resolve().parents[2]
    image = tmp_path / "image"
    image.mkdir()
    dockerfile = source / "deploy/Dockerfile.package-verification"
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        if not line.startswith("COPY "):
            continue
        *sources, destination = shlex.split(line)[1:]
        for name in sources:
            target = image / destination
            if (source / name).is_dir():
                shutil.copytree(source / name, target, dirs_exist_ok=True)
            else:
                if destination.endswith("/"):
                    target = target / Path(name).name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source / name, target)
    archive, trust = signed_package()
    script = f"""
import sys
from pathlib import Path
sys.path.insert(0, {str(image)!r})
from scripts.maintenance.release_package import verify_package
from server.sli import release_package
assert Path(release_package.__file__).resolve().is_relative_to(Path({str(image)!r}))
assert verify_package(Path({str(archive)!r}), Path({str(trust)!r})).manifest['package_id'] == 'sli.core'
print('package_image_verifier_verified')
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script], cwd=image,
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "package_image_verifier_verified"


class Ledger:
    def __init__(self, rows):
        self.rows = dict(rows)

    def execute(self, statement, params=None):
        if params:
            name = self.rows.get(params[0])
            return SimpleNamespace(fetchone=lambda: (name,) if name else None)
        return SimpleNamespace(fetchall=lambda: list(self.rows.items()))


def test_migrations_resume_only_missing_and_read_back_exact_marker():
    connection = Ledger({144: "baseline", 145: "first"})
    migrations = [SimpleNamespace(version=n, name=name, path=Path(str(n)))
                  for n, name in [(145, "first"), (146, "second")]]
    calls = []

    def execute(paths):
        calls.append(paths)
        connection.rows[146] = "second"

    migrate.apply_pending(connection, migrations, {144: "baseline", 145: "first", 146: "second"}, execute, baseline_version=144)
    assert calls == [[Path("146")]]
    calls.clear()
    migrate.apply_pending(connection, migrations, {144: "baseline", 145: "first", 146: "second"}, execute, baseline_version=144)
    assert calls == []


@pytest.mark.parametrize("failure", ["seed", "owner"])
@pytest.mark.parametrize("seed_domain", ["0", "1"])
def test_fresh_bootstrap_and_resume_after_setup_failure(tmp_path, monkeypatch, capsys, failure, seed_domain):
    inventory = forward_migration_inventory(ROOT / "config/postgres_migrations")
    expected = dict(migrate.base_schema_markers(ROOT / "config/postgres_schema_v8.sql"))
    expected.update((item.version, item.name) for item in inventory)
    owner_attempts = []
    bootstrap_attempts = []
    steps = []

    class Connection(Ledger):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def transaction(self):
            return self

        def execute(self, statement, params=None):
            if not isinstance(statement, str):
                return SimpleNamespace(fetchone=lambda: None)
            if "pg_advisory_lock" in statement or statement.startswith("revoke"):
                return None
            if "to_regclass" in statement:
                return SimpleNamespace(fetchone=lambda: ("schema_migrations" if self.rows else None,))
            return super().execute(statement, params)

    connection = Connection({})

    def run_sql(paths, *, passfile, atomic=False):
        assert passfile.is_file()
        steps.append((paths, atomic))
        if atomic:
            bootstrap_attempts.append(paths)
            assert paths[0].name == "roles.sql"
            assert "__SLI_REPORT_DOMAIN__" not in paths[1].read_text(encoding="utf-8")
            assert ("VALUES ('reports.domain_fqdn', 'stand.example.invalid', 'installer')" in paths[1].read_text(encoding="utf-8")) == (seed_domain == "1")
            assert paths[2].name == "runtime_grants.sql"
            assert paths[3] == STAND / "default_semantic_policy.sql"
            if failure == "seed" and len(bootstrap_attempts) == 1:
                raise RuntimeError("synthetic interruption")
            connection.rows.update({version: name for version, name in expected.items()
                                    if version <= MANIFEST_BASELINE})
        elif paths[0].name != "runtime_grants.sql":
            version = int(paths[0].name.split("_", 1)[0])
            connection.rows[version] = expected[version]

    def create_owner(conn, password):
        assert conn is connection
        owner_attempts.append(password)
        if failure == "owner" and len(owner_attempts) == 1:
            raise RuntimeError("synthetic interruption")

    temporary_directory = migrate.tempfile.TemporaryDirectory
    monkeypatch.setattr(migrate.tempfile, "TemporaryDirectory", lambda **kw: temporary_directory(dir=tmp_path, **kw))
    monkeypatch.setattr(migrate.psycopg, "connect", lambda **kw: connection)
    monkeypatch.setattr(migrate, "run_sql", run_sql)
    monkeypatch.setattr(migrate, "create_platform_owner", create_owner)
    monkeypatch.setattr(migrate, "attest_ledger", lambda *args, **kwargs: None)
    monkeypatch.setenv("SLI_INSTALL_DOMAIN", "stand.example.invalid")
    monkeypatch.setenv("SLI_INSTALL_SEED_REPORT_DOMAIN", seed_domain)
    for key in ("SLI_PG_ADMIN_PASSWORD", "SLI_PLATFORM_OWNER_PASSWORD",
                "ADLOG_SEMANTIC_WORKER_PASSWORD", "ADLOG_STORAGE_V2_WORKER_PASSWORD",
                "ADLOG_AD_CONTEXT_WORKER_PASSWORD", "SLI_NOTIFICATION_DB_PASSWORD"):
        secret = tmp_path / key
        secret.write_text("synthetic-only-password\n", encoding="utf-8")
        monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv(f"{key}_FILE", str(secret))
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        migrate.migrate()
    assert sum(atomic for _, atomic in steps) == 1
    assert connection.rows == (expected if failure == "owner" else {})
    steps.clear()
    migrate.migrate()
    assert len(owner_attempts) == (2 if failure == "owner" else 1)
    if failure == "owner":
        assert [(paths[0].name, atomic) for paths, atomic in steps] == [("runtime_grants.sql", False)]
    else:
        assert sum(atomic for _, atomic in steps) == 1
        assert connection.rows == expected
    assert capsys.readouterr().out == "linux_migrations_verified\n"


def test_migrate_rejects_invalid_report_domain_seed_before_connecting(monkeypatch):
    monkeypatch.setenv("SLI_INSTALL_SEED_REPORT_DOMAIN", "invalid")
    monkeypatch.setattr(migrate.psycopg, "connect", lambda **kw: pytest.fail("must not connect"))
    with pytest.raises(ValueError, match="linux_report_domain_seed_invalid"):
        migrate.migrate()


@pytest.mark.parametrize("rows", [{144: "wrong"}, {144: "baseline", 999: "foreign"}, {}])
def test_migrations_reject_foreign_or_incomplete_ledger(rows):
    with pytest.raises(RuntimeError):
        migrate.apply_pending(Ledger(rows), [], {144: "baseline"}, lambda _: pytest.fail("must not execute"), baseline_version=144)


def test_restored_database_catches_up_on_baseline_tail():
    connection = Ledger({148: "a", 149: "b"})
    migrations = [SimpleNamespace(version=n, name=name, path=Path(str(n)))
                  for n, name in [(148, "a"), (149, "b"), (150, "c"), (151, "d")]]
    executed = []

    def execute(paths):
        executed.extend(int(path.name) for path in paths)
        connection.rows[int(paths[0].name)] = {150: "c", 151: "d"}[int(paths[0].name)]

    migrate.apply_pending(connection, migrations, {148: "a", 149: "b", 150: "c", 151: "d"}, execute,
                          baseline_version=150)
    assert executed == [150, 151]


def test_restored_database_with_hole_is_rejected():
    with pytest.raises(RuntimeError, match="baseline_ledger_incomplete"):
        migrate.apply_pending(Ledger({147: "a", 149: "c"}), [], {147: "a", 148: "b", 149: "c"},
                              lambda _: pytest.fail("must not execute"), baseline_version=150)


def test_migration_requires_successful_readback():
    with pytest.raises(RuntimeError, match="readback_failed"):
        migrate.apply_pending(Ledger({144: "baseline"}),
                              [SimpleNamespace(version=145, name="first", path=Path("145"))],
                              {144: "baseline", 145: "first"}, lambda _: None, baseline_version=144)


def test_sql_uses_private_passfile_and_hides_error_output(monkeypatch, tmp_path):
    from deploy.linux import backup, operation_wait
    from tests.unit.linux_operation_process import completed
    captured = {}

    def run(command, **kwargs):
        captured.update(command=command, **kwargs)
        return SimpleNamespace(returncode=1, stderr=b"synthetic private database row")

    monkeypatch.setattr(migrate.subprocess, "run", run)
    monkeypatch.setattr(migrate.subprocess, 'Popen', lambda *a, **kw: completed(run(*a, **kw)))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: nullcontext(SimpleNamespace(
        execute=lambda *a: SimpleNamespace(fetchone=lambda: (4096,)))))
    monkeypatch.setattr(operation_wait, 'history_path', lambda: tmp_path / 'summary.json')
    monkeypatch.setenv("PGPASSWORD", "synthetic password")
    with pytest.raises(RuntimeError, match="^linux_sql_step_failed$"):
        migrate.run_sql([Path("baseline.sql")], passfile=tmp_path / "pgpass", atomic=True)
    assert "--single-transaction" in captured["command"]
    assert captured["env"]["PGPASSFILE"] == str(tmp_path / "pgpass")
    assert "PGPASSWORD" not in captured["env"]
    assert "synthetic password" not in " ".join(captured["command"])


def test_pgpass_escaping_and_line_injection():
    assert migrate.pgpass_escape(r"synthetic:back\slash") == r"synthetic\:back\\slash"
    with pytest.raises(ValueError):
        migrate.pgpass_escape("synthetic\nline")


def test_api_entrypoint_disables_acquisition_before_start(monkeypatch):
    monkeypatch.delenv("ADLOG_AUTH_REQUIRED", raising=False)
    monkeypatch.setattr(sys, "argv", ["entrypoint", "api", "--port", "8443"])
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER", "1")
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", "1")

    def run_api(arguments):
        assert arguments == ["--port", "8443"]
        assert os.environ["ADLOG_AUTH_REQUIRED"] == "1"
        assert os.environ["ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER"] == "0"
        assert os.environ["ADLOG_ENABLE_INPROCESS_POST_COLLECTION"] == "0"
        return 0

    monkeypatch.setattr(entrypoint, "run_api", run_api)
    assert entrypoint.main() == 0


def test_api_entrypoint_preserves_explicit_auth_setting(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["entrypoint", "api"])
    monkeypatch.setenv("ADLOG_AUTH_REQUIRED", "0")
    monkeypatch.setenv("ADLOG_ALLOW_UNAUTHENTICATED", "1")
    monkeypatch.setattr(entrypoint, "run_api", lambda arguments: 0)
    assert entrypoint.main() == 0
    assert os.environ["ADLOG_AUTH_REQUIRED"] == "0"
    assert os.environ["ADLOG_ALLOW_UNAUTHENTICATED"] == "1"


def test_compose_auth_default_and_proxy_trust_configuration():
    compose = yaml.safe_load((STAND / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose["services"]["api"]["environment"]["ADLOG_AUTH_REQUIRED"] == "1"
    assert compose["services"]["api"]["environment"]["ADLOG_TRUSTED_PROXIES"] == "${ADLOG_TRUSTED_PROXIES:-}"


def test_executor_entrypoint_forwards_profile_without_enabling_collection(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["entrypoint", "executor", "--profile", "heavy"])
    def import_module(name):
        assert name == "server.sli.core.job_executor"
        assert os.environ["ADLOG_ACQUISITION_DISABLED"] == "1"
        return SimpleNamespace(main=lambda: 0)
    monkeypatch.setattr(entrypoint.importlib, "import_module", import_module)
    assert entrypoint.main() == 0
    assert sys.argv == ["server.sli.core.job_executor", "--profile", "heavy"]


def test_executor_compose_keeps_default_path_and_separates_profile_secrets():
    compose = yaml.safe_load((STAND / "docker-compose.yml").read_text("utf-8"))
    for profile in ("light", "heavy", "long"):
        service = compose["services"][f"executor-{profile}"]
        assert service["profiles"] == ([] if profile == "light" else ["core-jobs"])
        assert service["command"] == ["executor", "--profile", profile]
        assert service["environment"]["SLI_CORE_JOB_RADIUS_PILOT"].endswith(":-0}")
        expected_secrets = {f"job_{purpose}_{profile}" for purpose in ("dispatcher", "executor", "publisher")}
        if profile == "light":
            expected_secrets.add("history_password")
        assert set(service["secrets"]) == expected_secrets
        assert "ADLOG_PG_DSN" not in service["environment"]
        expected_volumes = ["${SLI_PLUGIN_DIR:-../../runtime/plugins}:/opt/sli/plugins:ro",
                            "../../config/plugin_packages/v3:/opt/sli/plugin-locks:ro"]
        if profile == "light":
            expected_volumes.insert(0, "sli-data:/var/lib/sli")
        assert service["volumes"] == expected_volumes
        assert service["read_only"]
        assert service["environment"]["SLI_PLUGIN_RUNTIME_DIR"] == "/opt/sli/plugins"
        assert service["environment"]["SLI_PLUGIN_LOCK_DIR"] == "/opt/sli/plugin-locks"
        assert "healthcheck" in service
    assert "profiles" not in compose["services"]["remote-access"]
    migration = compose["services"]["migrate"]
    assert {name for name in migration["secrets"] if name.startswith("job_")} == {
        "job_dispatcher_light", "job_executor_light", "job_publisher_light"}
    assert "history_password" in migration["secrets"]
    assert migration["depends_on"]["clickhouse"]["condition"] == "service_healthy"
    assert compose["services"]["executor-light"]["environment"][
        "SLI_CORE_JOB_WORKSTATIONS_RETENTION"].endswith(":-0}")
    for service in ("executor-light", "migrate", "post-collection"):
        assert compose["services"][service]["environment"][
            "SLI_CORE_JOB_WORKSTATIONS_PROJECTION"].endswith(":-0}")


def test_optional_executor_login_provisioning_is_inert_when_disabled(monkeypatch):
    monkeypatch.delenv("SLI_CORE_JOB_RADIUS_PILOT", raising=False)
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "0")
    migrate.configure_job_logins(None)


def test_default_projection_without_executor_configuration_needs_no_logins(monkeypatch):
    for flag in ("RADIUS_PILOT", "AD_GPO_PILOT", "WORKSTATIONS_RETENTION", "WORKSTATIONS_PROJECTION"):
        monkeypatch.delenv("SLI_CORE_JOB_" + flag, raising=False)
    for purpose in ("DISPATCHER", "EXECUTOR", "PUBLISHER"):
        monkeypatch.delenv(f"SLI_JOB_{purpose}_LIGHT_PASSWORD_FILE", raising=False)
    migrate.configure_job_logins(None)


@pytest.mark.parametrize("configured", ["explicit", "DISPATCHER", "EXECUTOR", "PUBLISHER"])
def test_executor_configuration_cannot_silently_accept_missing_credentials(monkeypatch, configured):
    for flag in ("RADIUS_PILOT", "AD_GPO_PILOT", "WORKSTATIONS_RETENTION", "WORKSTATIONS_PROJECTION"):
        monkeypatch.delenv("SLI_CORE_JOB_" + flag, raising=False)
    for purpose in ("DISPATCHER", "EXECUTOR", "PUBLISHER"):
        monkeypatch.delenv(f"SLI_JOB_{purpose}_LIGHT_PASSWORD_FILE", raising=False)
    if configured == "explicit":
        monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "1")
    else:
        monkeypatch.setenv(f"SLI_JOB_{configured}_LIGHT_PASSWORD_FILE", "synthetic-file")
    with pytest.raises(ValueError, match="^missing executor secret file$"):
        migrate.configure_job_logins(None)


def test_executor_login_uses_its_profile_role_directly(monkeypatch):
    monkeypatch.setenv("SLI_CORE_JOB_RADIUS_PILOT", "1")
    monkeypatch.setattr(migrate, "secret_value", lambda _: "synthetic-password")
    for profile in ("light", "heavy", "long"):
        for purpose in ("dispatcher", "executor", "publisher"):
            monkeypatch.setenv(f"SLI_JOB_{purpose.upper()}_{profile.upper()}_PASSWORD_FILE", "synthetic-file")
    calls = []
    class Connection:
        def transaction(self):
            return nullcontext()
        def execute(self, statement, params=None):
            calls.append((statement, params))
            return SimpleNamespace(fetchone=lambda: (False,))
    migrate.configure_job_logins(Connection())
    role_checks = [params[0] for statement, params in calls if isinstance(statement, str) and "from pg_roles" in statement]
    assert len(role_checks) == 9 and len(set(role_checks)) == 9
    assert all(name.startswith("sli_job_") for name in role_checks)
    assert not any(isinstance(statement, str) and "set role" in statement.lower() for statement, _ in calls)


def test_executor_health_rejects_stale_or_wrong_profile_heartbeat(monkeypatch):
    from server.sli.core import job_executor
    stamp = datetime.now(timezone.utc)
    row = {"profile": "light", "pid": 1, "at_utc": stamp.isoformat()}
    status_path = SimpleNamespace(read_text=lambda *_args, **_kwargs: json.dumps(row))
    assert healthcheck.healthy("executor-light", status_path=status_path)
    assert not healthcheck.healthy("executor-heavy", status_path=status_path)
    row["at_utc"] = (stamp-timedelta(seconds=121)).isoformat()
    assert not healthcheck.healthy("executor-light", status_path=status_path)
    monkeypatch.setenv(job_executor.FLAG, "1")
    assert healthcheck.healthy("radius-session-observation")


def test_worker_health_requires_fresh_successful_heartbeat(monkeypatch):
    captured = {}

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def execute(self, statement, params):
            captured.update(statement=statement, params=params)
            return SimpleNamespace(fetchone=lambda: (False,))

    monkeypatch.setattr(healthcheck, "load_config", lambda: SimpleNamespace(postgres_dsn="host=database"))
    monkeypatch.setattr(migrate.psycopg, "connect", lambda *a, **kw: Connection())
    assert not healthcheck.healthy("post_collection")
    assert captured["params"] == ("post_collection", 120, 1, None, None)
    assert "heartbeat_at >" in captured["statement"]
    assert "status IN ('running', 'idle', 'warning')" in captured["statement"]
    assert "process_pid = %s" in captured["statement"]


def test_warm_healthcheck_allows_slow_disk_initialization():
    compose = yaml.safe_load((STAND / "docker-compose.yml").read_text(encoding="utf-8"))
    health = compose["services"]["warm-tier"]["healthcheck"]
    assert health["start_period"] == "180s"
    assert health["timeout"] == "10s"
    assert health["retries"] == 12
    assert health["interval"] == "10s"
    assert health["test"][-1] == "http://127.0.0.1:8123/ping"


def test_fresh_semantic_policy_matches_accepted_runtime_contract():
    from hashlib import sha256

    from scripts.maintenance.semantic_l1_shadow_control import POLICIES
    from server.sli.semantic.semantic_production_runtime import (
        ENABLED_POLICY_ID,
        POLICY_VERSION,
    )
    from server.sli.semantic.semantic_risk import ScenarioSourceKind
    from server.sli.semantic.semantic_risk_policy import (
        RiskPolicyDefinition,
        compile_risk_policy,
    )

    seed = (STAND / "default_semantic_policy.sql").read_text(encoding="utf-8")
    assert "SET LOCAL search_path = pg_catalog, public;" in seed.split("with definition", 1)[0]
    document = seed.split("$policy$")[1]
    policy = RiskPolicyDefinition(
        policy_id=ENABLED_POLICY_ID, policy_version=POLICY_VERSION,
        source_kind=ScenarioSourceKind.CANONICAL_ACTION, definition=json.loads(document),
    )
    compiled = compile_risk_policy(policy)
    assert policy.definition == dict(POLICIES)[ENABLED_POLICY_ID]
    assert document == policy.definition_json
    assert sha256(document.encode("utf-8")).digest() == compiled.definition_sha256
    assert "sha256(convert_to(document, 'UTF8'))" in seed
    assert f"select '{ENABLED_POLICY_ID}', {POLICY_VERSION}, 'canonical_action', 'draft'" in seed
    assert f"source_kind, '{compiled.selector_value}', definition_sha256" in seed
    assert seed.index("'draft'") < seed.index("insert into public.semantic_risk_policy_subscriptions")
    assert seed.index("insert into public.semantic_risk_policy_subscriptions") < seed.index("set lifecycle_status = 'enabled'")


def test_postgres_checkpoint_launch_parameters():
    compose = yaml.safe_load((STAND / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose["services"]["postgres"].get("command") == [
        "postgres", "-c", "max_wal_size=4GB", "-c", "checkpoint_timeout=15min",
        "-c", "checkpoint_completion_target=0.9",
    ]


def test_compose_secret_and_migration_boundaries():
    compose = yaml.safe_load((STAND / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert services["postgres"]["image"].startswith("postgres:18.")
    assert services["postgres"]["user"] == "999:999"
    assert services["postgres"]["group_add"] == ["10001"]
    assert services["migrate"]["pull_policy"] == "never"
    assert services["backup"]["pull_policy"] == "never"
    assert "postgres-data:/var/lib/postgresql" in services["postgres"]["volumes"]
    assert "ports" not in services["postgres"]
    for name in ("api", *entrypoint.WORKERS):
        service = services[name]
        assert service["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
        expected_secrets = {"runtime_password", "history_password"}
        if name == "api":
            expected_secrets.update({"tls_certificate", "tls_key", "tls_ca"})
        if name == "semantic":
            expected_secrets.add("semantic_password")
        if name in {"post-collection", "entity-state", "storage-lifecycle"}:
            expected_secrets.add("storage_password")
        if name == "post-collection":
            expected_secrets.add("context_password")
        if name == "storage-lifecycle":
            expected_secrets.add("warm_password")
        assert set(service["secrets"]) == expected_secrets
        assert "password=" not in service["environment"]["ADLOG_PG_DSN"]
        assert service["environment"]["ADLOG_PG_PASSWORD_FILE"] == "/run/secrets/runtime_password"
        assert "healthcheck" in service
    assert set(services["migrate"]["secrets"]) == {
        "postgres_password", "platform_owner_password", "semantic_password", "storage_password",
        "context_password", "job_dispatcher_light", "job_executor_light", "job_publisher_light",
        "history_password", "notification_db_password",
    }
    assert all("file" in secret for secret in compose["secrets"].values())
    grants = (STAND / "runtime_grants.sql").read_text(encoding="utf-8")
    assert "REASSIGN OWNED BY adlog_user TO sli_migration" in grants
    assert "REVOKE ALL ON public.schema_migrations FROM adlog_user" in grants
    assert "ALL TABLES IN SCHEMA" not in grants
    assert "GRANT SELECT ON public.finding_evidence TO adlog_storage_owner" in grants


def test_compose_warm_tier_reuses_external_volume_and_file_secret():
    compose = yaml.safe_load((STAND / "docker-compose.yml").read_text(encoding="utf-8"))
    warm = compose["services"]["warm-tier"]
    worker = compose["services"]["storage-lifecycle"]
    assert warm["image"] == "clickhouse/clickhouse-server:25.8"
    assert "ports" not in warm
    assert compose["volumes"]["warm-data"] == {
        "external": True,
        "name": "${SLI_WARM_CLICKHOUSE_VOLUME:-sli-warm-tier-step1-data}",
    }
    assert "warm-data:/var/lib/clickhouse" in warm["volumes"]
    for filename, directory in [("010_system_log_retention.xml", "config.d"),
                                ("011_disable_sampling_profiler.xml", "users.d")]:
        assert (
            f"../../config/clickhouse/{filename}:/etc/clickhouse-server/{directory}/{filename}:ro"
            in warm["volumes"]
        )
        assert (STAND / "../../config/clickhouse" / filename).is_file()
    assert warm["secrets"] == ["warm_password"]
    assert warm["environment"]["CLICKHOUSE_PASSWORD_FILE"] == "/run/secrets/warm_password"
    assert "CLICKHOUSE_PASSWORD" not in warm["environment"]
    assert compose["secrets"]["warm_password"] == {"file": "${SLI_SECRETS_DIR}/warm_password"}
    environment = worker["environment"]
    assert environment["ADLOG_WARM_CLICKHOUSE_HOST"] == "warm-tier"
    assert environment["ADLOG_WARM_CLICKHOUSE_PORT"] == "8123"
    assert environment["ADLOG_WARM_CLICKHOUSE_USER"] == warm["environment"]["CLICKHOUSE_USER"]
    assert environment["ADLOG_WARM_CLICKHOUSE_PASSWORD_FILE"] == "/run/secrets/warm_password"
    assert environment["ADLOG_HISTORY_CLICKHOUSE_HOST"] == "clickhouse"
    assert environment["ADLOG_HISTORY_CLICKHOUSE_PORT"] == "8123"
    assert environment["ADLOG_HISTORY_CLICKHOUSE_USER"] == compose["services"]["clickhouse"]["environment"]["CLICKHOUSE_USER"]
    assert environment["ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE"] == "/run/secrets/history_password"
    assert "history_password" in worker["secrets"]
    assert "warm_password" in worker["secrets"]
    assert worker["depends_on"]["warm-tier"]["condition"] == "service_healthy"
    assert worker["depends_on"]["clickhouse"]["condition"] == "service_healthy"
    assert set(worker["volumes"]) == {
        "sli-data:/var/lib/sli", "sli-data:/opt/sli/data", "storage-evidence:/opt/sli/artifacts",
        "${SLI_PLUGIN_DIR:-../../runtime/plugins}:/opt/sli/plugins:ro",
        "../../config/plugin_packages/v3:/opt/sli/plugin-locks:ro",
    }
    assert "docker.sock" not in json.dumps(compose)
    dockerfile = (STAND / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY config/ config/" in dockerfile or "COPY config/clickhouse/ config/clickhouse/" in dockerfile


def test_storage_lifecycle_entrypoint_routes_existing_worker(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["entrypoint", "storage-lifecycle", "--once"])
    imported = []
    monkeypatch.setattr(entrypoint.importlib, "import_module", lambda name: (
        imported.append(name) or SimpleNamespace(main=lambda: 0)
    ))
    assert entrypoint.main() == 0
    assert imported == ["scripts.runtime.storage_lifecycle_worker"]
    assert sys.argv == ["scripts.runtime.storage_lifecycle_worker", "--once"]


def test_compose_history_admission_publishes_without_enabling_deletion(monkeypatch):
    from scripts.runtime import storage_lifecycle_worker as worker

    compose = yaml.safe_load((STAND / "docker-compose.yml").read_text(encoding="utf-8"))
    environment = compose["services"]["storage-lifecycle"]["environment"]
    for key in (worker.ENABLE_ENV, worker.ADMISSION_ENV, worker.WARM_ADMISSION_ENV,
                worker.NO_ARCHIVE_ADMISSION_ENV, worker.DELETE_EXECUTION_ENV):
        monkeypatch.delenv(key, raising=False)
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(worker, "load_config", lambda: None)
    monkeypatch.setattr(worker, "get_storage_capacity_profile_resolution", lambda _: {})
    monkeypatch.setattr(worker, "load_storage_policy", lambda _: SimpleNamespace(
        db_retention_days=7, archive_auto_delete_enabled=False))
    calls = []

    def invoke(arguments, **kwargs):
        calls.append(arguments)
        return {"status": "ok", "history_rows_copied": 2, "deleted_rows": 0}

    result = worker.run_cycle(invoke=invoke)
    assert result == {"status": "ok", "history_rows_copied": 2, "deleted_rows": 0}
    assert len(calls) == 1
    assert calls[0][:2] == ["-m", "server.sli.storage.permanent_history_lifecycle"]
    assert "--apply-retention" not in calls[0]
    assert not worker.automation_admitted()
    assert not worker.no_archive_automation_admitted()
    assert not worker.delete_execution_admitted()
    # Only the lifecycle service receives admission after migrate succeeds.
    for name, service in compose["services"].items():
        if name != "storage-lifecycle":
            assert not worker.warm_automation_admitted(service.get("environment", {}))


@pytest.mark.parametrize("existing", [False, True])
def test_migrate_prepares_history_schema_and_retries_failure(monkeypatch, capsys, existing):
    from server.sli.storage import permanent_fact_history as history

    class Connection:
        def execute(self, statement):
            return SimpleNamespace(fetchone=lambda: ("schema_migrations" if existing else None,))

        def transaction(self):
            return nullcontext()

    steps = []
    monkeypatch.setattr(migrate.psycopg, "connect", lambda **kw: nullcontext(Connection()))
    monkeypatch.setattr(migrate, "secret_value", lambda _: "synthetic-only-password")
    for key in ("SLI_PG_ADMIN_PASSWORD_FILE", "SLI_PLATFORM_OWNER_PASSWORD_FILE"):
        monkeypatch.setenv(key, "synthetic-file")
    monkeypatch.setattr(migrate, "run_sql", lambda *a, **kw: None)
    monkeypatch.setattr(migrate, "attest_ledger", lambda *a, **kw: None)
    monkeypatch.setattr(migrate, "apply_pending", lambda *a, **kw: steps.append("postgres-migrations"))
    monkeypatch.setattr(migrate, "create_platform_owner", lambda *a: None)
    monkeypatch.setattr(migrate, "configure_worker_logins", lambda *a: steps.append("worker-logins"))
    monkeypatch.setattr(migrate, "configure_workstation_history", lambda: steps.append("workstation-history"))
    monkeypatch.setenv("SLI_INSTALL_DOMAIN", "stand.example.invalid")
    monkeypatch.setenv("ADLOG_HISTORY_READ_MODE", "primary")
    monkeypatch.setenv("ADLOG_HISTORY_CLICKHOUSE_PORT", "8123")
    monkeypatch.setattr(history, "_history_auth", lambda: ("history", "synthetic-only-password"))
    statements = []
    fail = True

    def execute_history(port, statement):
        nonlocal fail
        assert port == 8123
        assert "worker-logins" in steps
        statements.append(statement)
        if "CREATE TABLE IF NOT EXISTS sli_history.ad_snapshot_changes" in statement and fail:
            fail = False
            raise RuntimeError("synthetic_history_setup_failure")

    monkeypatch.setattr(history, "_http_query", execute_history)
    with pytest.raises(RuntimeError, match="synthetic_history_setup_failure"):
        migrate.migrate()
    assert capsys.readouterr().out == ""
    steps.clear()
    statements.clear()
    migrate.migrate()
    assert capsys.readouterr().out == "linux_migrations_verified\n"
    assert steps == ["postgres-migrations", "worker-logins", "workstation-history"]
    for table in ("events", "links", "published_batches", "ad_snapshot_changes"):
        assert any(f"CREATE TABLE IF NOT EXISTS sli_history.{table}" in sql for sql in statements)
    assert all("IF NOT EXISTS" in sql for sql in statements)


def test_stand_baseline_follows_verified_manifest():
    inventory = forward_migration_inventory(ROOT / "config/postgres_migrations")
    baseline = load_baseline(ROOT / "config/postgres_baseline", inventory)
    manifest = json.loads((ROOT / "config/postgres_baseline/manifest.json").read_text(encoding="utf-8"))
    assert baseline.version == int(manifest["baseline_version"])
    assert not (STAND / "migrations.json").exists()


def test_exact_worker_map_and_compose_commands():
    assert entrypoint.WORKERS == {
        "post-collection": "scripts.runtime.post_collection_worker",
        "what-where-when": "scripts.runtime.what_where_when_projection_worker",
        "semantic": "scripts.runtime.semantic_production_worker",
        "entity-state": "scripts.runtime.entity_state_worker",
        "storage-lifecycle": "scripts.runtime.storage_lifecycle_worker",
        "ad-snapshot-manifest-coordinator": "scripts.runtime.ad_snapshot_manifest_coordinator_worker",
        "remote-access": "scripts.runtime.remote_access_plugin_host",
    }
    compose_text = (STAND / "docker-compose.yml").read_text(encoding="utf-8")
    assert compose_text.count("\n  storage-lifecycle:\n") == 1
    assert (STAND / "entrypoint.py").read_text(encoding="utf-8").count('"storage-lifecycle":') == 1
    services = yaml.safe_load(compose_text)["services"]
    executors = {"executor-light", "executor-heavy", "executor-long"}  # stage 3 core job queue pools
    assert set(services) == {"postgres", "clickhouse", "warm-tier", "clickhouse-restore", "backup", "migrate", "api", *entrypoint.WORKERS, *entrypoint.NOTIFICATION_WORKERS, *executors}
    assert services["storage-lifecycle"]["command"] == ["storage-lifecycle", "--interval-seconds", "21600"]
    assert services["ad-snapshot-manifest-coordinator"]["command"] == ["ad-snapshot-manifest-coordinator", "--no-initial-delay"]
    assert services["remote-access"]["command"] == ["remote-access", "--component", "radius-session-observation"]
    for name in entrypoint.WORKERS:
        assert services[name]["command"][0] == name
        assert services[name]["depends_on"]["clickhouse"]["condition"] == "service_healthy"


def test_shared_runtime_configuration_and_external_history():
    compose = yaml.safe_load((STAND / "docker-compose.yml").read_text(encoding="utf-8"))
    environment = compose["x-runtime"]["environment"]
    expected = {
        "AUTH_REQUIRED": "1", "DB_BACKEND": "postgres", "UI_MODE": "postgres",
        "STORAGE_READ_MODE": "v2", "STORAGE_WRITE_MODE": "v2", "STORAGE_V2_SHADOW_SAMPLE_RATE": "0",
        "EXTERNAL_POST_COLLECTION_WORKER": "1", "EXTERNAL_STORAGE_V2_OUTBOX_WORKER": "1",
        "DISABLE_SCHEDULER": "1", "HISTORY_READ_MODE": "primary", "SEMANTIC_RUNTIME_MODE": "findings-v1",
        "SEMANTIC_PRODUCTION_ENABLED": "1", "SEMANTIC_NORMALIZATION_ENABLED": "1",
        "SEMANTIC_ASSEMBLY_ENABLED": "1", "SEMANTIC_CORRELATION_ENABLED": "1",
        "SEMANTIC_RISK_ENGINE_ENABLED": "1", "SEMANTIC_FINDING_CREATION_ENABLED": "1",
        "STORAGE_LIFECYCLE_AUTOMATION_ENABLED": "1", "STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED": "1",
        "STORAGE_LIFECYCLE_DELETE_ADMISSION": "0", "STORAGE_LIFECYCLE_WARM_COPY_ADMISSION": "0",
        "AD_CONTEXT_INTERVAL_SECONDS": "1800", "STOP_COLLECTION_IF_FREE_DISK_BYTES_BELOW": "10737418240",
        "ENABLE_POSTGRES_COLLECTION": "0", "POSTGRES_RUNTIME_COLLECTION": "0", "NPS_EVENTLOG_ENABLED": "0",
        "ACQUISITION_DISABLED": "1", "HISTORY_CLICKHOUSE_HOST": "clickhouse", "HISTORY_CLICKHOUSE_PORT": "8123",
        "DATA_DIR": "/var/lib/sli", "LOG_DIR": "/var/lib/sli/logs",
    }
    for key, value in expected.items():
        assert environment[f"ADLOG_{key}"] == value
    assert "ADLOG_STORAGE_ARCHIVE_ROOT" not in environment
    for service_name, service in compose["services"].items():
        for key, value in service.get("environment", {}).items():
            if "PASSWORD" in key:
                assert key.endswith("_FILE")
                if key == "SLI_NOTIFICATION_SMTP_PASSWORD_FILE":
                    assert service_name == "notification-delivery"
                    assert value == "/var/lib/notification-secrets/notification_smtp_password"
                    assert service["volumes"] == ["${SLI_SECRETS_DIR}/notifications:/var/lib/notification-secrets:ro"]
                else:
                    assert value.startswith("/run/secrets/")
            if key.endswith("_DSN"):
                from psycopg.conninfo import conninfo_to_dict

                assert "password" not in conninfo_to_dict(value)
        assert "postgres_password" not in service.get("secrets", []) or service in (
            compose["services"]["migrate"], compose["services"]["postgres"], compose["services"]["backup"],
        )
    clickhouse = compose["services"]["clickhouse"]
    assert clickhouse["image"] == "clickhouse/clickhouse-server:25.8"
    assert "ports" not in clickhouse
    assert "healthcheck" in clickhouse
    assert set(clickhouse["volumes"]) == {
        "history-data:/var/lib/clickhouse", "history-backups:/var/lib/clickhouse/backups",
        "../../config/clickhouse/012_backup_limits.xml:/etc/clickhouse-server/config.d/013_backup_limits.xml:ro",
        "${SLI_BACKUP_DIR:?Set absolute backup directory}:/var/lib/clickhouse/backups/scheduled",
        "../../config/clickhouse/010_system_log_retention.xml:/etc/clickhouse-server/config.d/010_system_log_retention.xml:ro",
        "../../config/stage7_clickhouse_backup.xml:/etc/clickhouse-server/config.d/012_history_backup.xml:ro",
        "../../config/clickhouse/011_disable_sampling_profiler.xml:/etc/clickhouse-server/users.d/011_disable_sampling_profiler.xml:ro",
    }
    for key, default in (("data", "sli-history-data"), ("backups", "sli-history-backups")):
        volume = compose["volumes"][f"history-{key}"]
        assert volume == {"external": True, "name": "${SLI_HISTORY_" + key.upper() + "_VOLUME:-" + default + "}"}


@pytest.mark.parametrize("worker", ["coordinator", "remote-access"])
@pytest.mark.parametrize("once", [True, False])
def test_disabled_workers_never_enter_windows_or_acquisition(worker, once, monkeypatch):
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator
    from scripts.runtime import remote_access_plugin_host as remote

    monkeypatch.setenv("ADLOG_ACQUISITION_DISABLED", "1")
    beats = []

    def forbidden(*a, **kw):
        pytest.fail("Windows/acquisition boundary reached")

    class LoopEnded(Exception):
        pass

    def sleep(seconds):
        assert seconds == 30
        raise LoopEnded

    monkeypatch.setattr(coordinator.time, "sleep", sleep)
    monkeypatch.setattr(coordinator, "session_advisory_lock", forbidden)
    monkeypatch.setattr(coordinator, "_default_cycle", forbidden)
    monkeypatch.setattr(coordinator, "record_worker_heartbeat", lambda **kw: beats.append(kw))
    monkeypatch.setattr(remote, "load_supervisor_environment", forbidden)
    monkeypatch.setattr(remote, "current_windows_account", forbidden)
    monkeypatch.setattr(remote, "_run_bounded_cycle", forbidden)
    monkeypatch.setattr(remote, "_write_heartbeat", lambda component, **kw: beats.append({"component": component, **kw}))
    run = (lambda: coordinator.main(["--no-initial-delay", *(["--once"] if once else [])])) if worker == "coordinator" else (
        lambda: remote.run_host("radius-session-observation", once=once)
    )
    if once:
        assert run() == 0
    else:
        with pytest.raises(LoopEnded):
            run()
    assert len(beats) == 1
    assert beats[0]["status"] == "idle"
    assert beats[0]["phase"] == "acquisition_disabled"


def test_linux_acquisition_fails_closed_without_env(monkeypatch):
    from server.sli.sources import acquisition_mode

    monkeypatch.delenv("ADLOG_ACQUISITION_DISABLED", raising=False)
    monkeypatch.setattr(acquisition_mode.sys, "platform", "linux")
    assert acquisition_mode.acquisition_disabled()
    monkeypatch.setattr(acquisition_mode.sys, "platform", "win32")
    assert not acquisition_mode.acquisition_disabled()


@pytest.mark.parametrize("age,status,pid,component,healthy", [
    (0, "idle", 1, "radius-session-observation", True),
    (0, "running", 1, "radius-session-observation", True),
    (121, "idle", 1, "radius-session-observation", False),
    (-60, "idle", 1, "radius-session-observation", False),
    (0, "blocked", 1, "radius-session-observation", False),
    (0, "stopped", 1, "radius-session-observation", False),
    (0, "idle", 2, "radius-session-observation", False),
    (0, "idle", 1, "radius-acquisition", False),
])
def test_plugin_health_checks_own_fresh_pid_one_heartbeat(age, status, pid, component, healthy, monkeypatch):
    monkeypatch.setattr(healthcheck, "read_plugin_heartbeat", lambda _: {
        "plugin_id": "sli.remote-access", "component_id": component,
        "process_pid": pid, "status": status,
        "heartbeat_at_utc": (datetime.now(timezone.utc) - timedelta(seconds=age)).isoformat(),
    })
    monkeypatch.setattr(migrate.psycopg, "connect", lambda *a, **kw: pytest.fail("plugin probe must use its file"))
    assert healthcheck.healthy("radius-session-observation") is healthy


@pytest.mark.parametrize("service", list(healthcheck.WORKER_MAX_AGES))
def test_every_db_worker_has_bounded_health_probe(service, monkeypatch):
    calls = []
    row = ("idle", None) if service == "storage_lifecycle" else (True,)
    connection = SimpleNamespace(execute=lambda sql, params: calls.append((sql, params)) or SimpleNamespace(fetchone=lambda: row))
    monkeypatch.setattr(healthcheck, "load_config", lambda: SimpleNamespace(postgres_dsn="host=database"))
    monkeypatch.setattr(migrate.psycopg, "connect", lambda *a, **kw: nullcontext(connection))
    assert healthcheck.healthy(service)
    assert calls[0][1] == (service, healthcheck.WORKER_MAX_AGES[service], 1, None, None)
    assert "LEAST(%s, GREATEST(120" in calls[0][0]
    assert "process_pid = %s" in calls[0][0]


@pytest.mark.parametrize("row,expected,diagnostic", [
    (("warning", "snapshot_history_migration_required"), True, "snapshot_history_migration_required"),
    (("warning", "ad_snapshot_history_coverage_partial"), True, "ad_snapshot_history_coverage_partial"),
    (("warning", "history_source_link_details_missing"), True, "history_source_link_details_missing"),
    (("warning", "history_clickhouse_unavailable"), True, "history_clickhouse_unavailable"),
    (("warning", "private AD source details"), True, "storage_lifecycle_condition_pending"),
    (("blocked", "snapshot_history_source_hash_mismatch"), False, ""),
    (("failed", "private exception"), False, ""),
    (None, False, ""),
])
def test_storage_health_reports_safe_warning_but_rejects_failure(row, expected, diagnostic, monkeypatch, capsys):
    connection = SimpleNamespace(execute=lambda *a: SimpleNamespace(fetchone=lambda: row))
    monkeypatch.setattr(healthcheck, "load_config", lambda: SimpleNamespace(postgres_dsn="host=database"))
    monkeypatch.setattr(migrate.psycopg, "connect", lambda *a, **kw: nullcontext(connection))
    assert healthcheck.healthy("storage_lifecycle") is expected
    output = capsys.readouterr().out
    assert "private" not in output
    assert output == (f"warning: storage_lifecycle: {diagnostic}\n" if diagnostic else "")


@pytest.mark.parametrize("nonempty,replace,allowed", [(False, False, True), (True, False, False), (True, True, True)])
def test_restore_requires_empty_database_or_explicit_flag(nonempty, replace, allowed):
    connection = SimpleNamespace(execute=lambda _: SimpleNamespace(fetchone=lambda: (nonempty,)))
    if allowed:
        restore_existing.require_empty_database(connection, replace_existing=replace)
    else:
        with pytest.raises(RuntimeError, match="^linux_restore_requires_empty_database$"):
            restore_existing.require_empty_database(connection)


def test_restore_command_preserves_ownership_parallel_jobs_and_private_password(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(restore_existing.operation_wait, 'native_rate', lambda _: 1)
    monkeypatch.setattr(restore_existing.operation_wait, 'history_path', lambda: tmp_path / 'summary.json')

    def run(command, **kwargs):
        captured.update(command=command, **kwargs)
        return SimpleNamespace(returncode=0, poll=lambda: 0, wait=lambda: 0)

    monkeypatch.setattr(restore_existing.subprocess, "Popen", run)
    monkeypatch.setenv("PGPASSWORD", "synthetic-private")
    restore_existing.run_restore(tmp_path, passfile=tmp_path / "pgpass", jobs=3, replace_existing=False)
    assert "--jobs=3" in captured["command"]
    assert "--format=directory" in captured["command"]
    assert not {"--no-owner", "--no-acl", "--clean", "--if-exists"}.intersection(captured["command"])
    assert captured["env"]["PGPASSFILE"] == str(tmp_path / "pgpass")
    assert "PGPASSWORD" not in captured["env"]
    assert captured["stdout"] == subprocess.DEVNULL
    assert captured["stderr"] is not None
    restore_existing.run_restore(tmp_path, passfile=tmp_path / "pgpass", jobs=3, replace_existing=True)
    assert {"--clean", "--if-exists"}.issubset(captured["command"])


def test_restore_cli_redacts_database_failure(tmp_path, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic private SQL row and password")

    monkeypatch.setattr(restore_existing, "restore_existing", fail)
    assert restore_existing.main([str(tmp_path)]) == 1
    assert capsys.readouterr().err == "linux_restore_failed\n"


@pytest.mark.parametrize("nonempty", [False, True])
def test_restore_flow_roles_then_dump_then_normal_migration(tmp_path, monkeypatch, nonempty):
    dump = tmp_path / "dump"
    dump.mkdir()
    (dump / "toc.dat").write_bytes(b"synthetic dump header")
    (tmp_path / "roles.sql").write_text("CREATE ROLE synthetic_role;\n")
    secret = tmp_path / "password"
    secret.write_text("synthetic-only-password", encoding="utf-8")
    monkeypatch.delenv("SLI_PG_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("SLI_PG_ADMIN_PASSWORD_FILE", str(secret))
    steps = []

    class Connection:
        def execute(self, query):
            return SimpleNamespace(fetchone=lambda: (nonempty,))

    monkeypatch.setattr(restore_existing.psycopg, "connect", lambda **kw: nullcontext(Connection()))
    original_temp = migrate.tempfile.TemporaryDirectory
    monkeypatch.setattr(migrate.tempfile, "TemporaryDirectory", lambda **kw: original_temp(dir=tmp_path, **kw))

    def roles(paths, **kwargs):
        steps.append("roles")
        text = paths[0].read_text(encoding="utf-8")
        assert "IF NOT EXISTS" in text
        assert "CREATE ROLE adlog_semantic_worker" in text
        assert kwargs["atomic"] is True
        assert kwargs["passfile"].is_file()

    monkeypatch.setattr(migrate, "run_sql", roles)
    monkeypatch.setattr(restore_existing, "run_restore", lambda *a, **kw: steps.append("dump"))
    monkeypatch.setattr(restore_existing, "restore_roles", lambda *a: steps.append("source_roles"))
    monkeypatch.setattr(restore_existing, "analyze_postgres", lambda *a: steps.append("analyze"))
    monkeypatch.setattr(restore_existing, "reconcile_owner", lambda *a, **kw: steps.append("owner"))
    monkeypatch.setattr(restore_existing.backup, "pg_connect", lambda *a, **kw: nullcontext(Connection()))
    monkeypatch.setattr(migrate, "migrate", lambda: steps.append("migrate_and_grants"))
    if nonempty:
        with pytest.raises(RuntimeError, match="requires_empty_database"):
            restore_existing.restore_existing(dump)
        assert steps == []
    else:
        restore_existing.restore_existing(dump)
        assert steps == ["roles", "source_roles", "dump", "migrate_and_grants", "owner", "analyze"]


def test_tls_consumes_certificate_and_key_files_directly(tmp_path, monkeypatch):
    from server.api import http_server

    certificate, key = tmp_path / "certificate", tmp_path / "key"
    certificate.write_text("synthetic certificate", encoding="utf-8")
    key.write_text("synthetic key", encoding="utf-8")
    for name, path in (("ADLOG_TLS_CERT", certificate), ("ADLOG_TLS_KEY", key)):
        monkeypatch.delenv(name + "_PATH", raising=False)
        monkeypatch.setenv(name + "_FILE", str(path))
    calls = []
    context = SimpleNamespace(load_cert_chain=lambda **kw: calls.append(kw))
    monkeypatch.setattr(http_server.ssl, "SSLContext", lambda _: context)
    assert http_server._load_server_tls_context() is context
    assert calls == [{"certfile": str(certificate), "keyfile": str(key)}]
    monkeypatch.setenv("ADLOG_TLS_KEY_PATH", str(key))
    with pytest.raises(RuntimeError, match="mutually exclusive"):
        http_server._load_server_tls_context()


@pytest.mark.parametrize("stream", [False, True])
def test_clickhouse_http_uses_service_host_and_hides_sql_errors(monkeypatch, stream):
    from server.sli.storage import storage_lifecycle_io as io

    calls = []
    response = SimpleNamespace(status=400, read=lambda: b"synthetic-private-row")
    connection = SimpleNamespace(request=lambda *a, **kw: None, getresponse=lambda: response,
                                 close=lambda: calls.append("closed"))
    monkeypatch.setenv("ADLOG_HISTORY_CLICKHOUSE_HOST", "clickhouse")
    monkeypatch.setattr(io.http.client, "HTTPConnection", lambda host, port, **kw: calls.append((host, port)) or connection)
    with pytest.raises(RuntimeError, match="^ClickHouse HTTP 400:request_failed$"):
        if stream:
            list(io._http_stream_json_rows(8123, "SELECT 1", auth=("history_reader", "synthetic-password")))
        else:
            io._http_query(8123, "SELECT 1", auth=("history_reader", "synthetic-password"))
    assert calls == [("clickhouse", 8123), "closed"]


def test_configured_semantic_worker_never_requests_admin_credentials(tmp_path, monkeypatch):
    from scripts.runtime import semantic_production_worker as worker

    secret = tmp_path / "password"
    secret.write_text("synthetic-only-password", encoding="utf-8")
    monkeypatch.setenv("ADLOG_SEMANTIC_WORKER_DSN", "host=database user=worker")
    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "findings-v1")
    monkeypatch.delenv("ADLOG_SEMANTIC_WORKER_DSN_FILE", raising=False)
    monkeypatch.delenv("ADLOG_SEMANTIC_WORKER_PASSWORD", raising=False)
    monkeypatch.setenv("ADLOG_SEMANTIC_WORKER_PASSWORD_FILE", str(secret))
    monkeypatch.setattr(worker, "validate_semantic_runtime_settings", lambda *a: None)
    monkeypatch.setattr(worker, "log_event", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "ephemeral_worker_environment", lambda: pytest.fail("admin credentials requested"))
    monkeypatch.setattr(worker, "_singleton_lock", lambda: nullcontext(False))
    assert worker.run(once=True, poll_seconds=30, limit=1) == 0


def test_worker_login_provisioning_is_bounded_and_uses_secret_files(tmp_path, monkeypatch):
    statements = []

    class Connection:
        def transaction(self):
            return nullcontext()

        def execute(self, query, params=None):
            statements.append(query.as_string() if hasattr(query, "as_string") else query)
            return SimpleNamespace(fetchone=lambda: None)

    for login, role, setting in migrate.WORKER_LOGINS:
        secret = tmp_path / setting
        secret.write_text("synthetic-only-password", encoding="utf-8")
        monkeypatch.delenv(setting, raising=False)
        monkeypatch.setenv(setting + "_FILE", str(secret))
    migrate.configure_worker_logins(Connection())
    for login, role, setting in migrate.WORKER_LOGINS:
        inheritance = "true" if role == "adlog_notification_worker" else "false"
        assert any(f'grant "{role}" to "{login}" with inherit {inheritance}' == sql for sql in statements)
        assert any(f'alter role "{login}" login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls' in sql for sql in statements)
        assert setting not in os.environ
    assert statements.count("set local log_statement = 'none'") == len(migrate.WORKER_LOGINS)
    assert statements.count("set local log_min_error_statement = 'panic'") == len(migrate.WORKER_LOGINS)


@pytest.mark.parametrize("unexpected_privileges", [False, True])
def test_existing_worker_login_cannot_keep_unbounded_privileges(tmp_path, monkeypatch, unexpected_privileges):
    changes = []

    class Connection:
        def transaction(self):
            return nullcontext()

        def execute(self, query, params=None):
            if not isinstance(query, str):
                changes.append(query.as_string())
            if isinstance(query, str) and "WITH login AS" in query:
                assert "aclexplode" in query and "rolsuper" in query and "pg_auth_members" in query
                return SimpleNamespace(fetchone=lambda: (unexpected_privileges,))
            return SimpleNamespace(fetchone=lambda: (1,))

    for login, role, setting in migrate.WORKER_LOGINS:
        secret = tmp_path / setting
        secret.write_text("synthetic-only-password", encoding="utf-8")
        monkeypatch.setenv(setting + "_FILE", str(secret))
        monkeypatch.delenv(setting, raising=False)
    if unexpected_privileges:
        with pytest.raises(RuntimeError, match="^linux_worker_login_privileges_mismatch$"):
            migrate.configure_worker_logins(Connection())
        assert changes == []
    else:
        migrate.configure_worker_logins(Connection())
        assert len(changes) == 3 * len(migrate.WORKER_LOGINS)

