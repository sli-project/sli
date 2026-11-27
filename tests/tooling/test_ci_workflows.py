#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from collections import Counter
from fnmatch import fnmatchcase
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
import yaml

from scripts.ci.pr_scope import plan_jobs, pytest_arguments
from scripts.ci.server_dotnet_shard import plan_profiles, read_rules
from scripts.maintenance import existing_postgres_bootstrap as bootstrap

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ("pr-gate.yml", "manual-full-gate.yml")
NATIVE_RESTORE_TEST = "tests/migrations/test_qw_restore_context_migration.py"
NATIVE_RESTORE_RUN = f"python -m pytest -q {NATIVE_RESTORE_TEST} -m postgres_integration"
POSTGRES_SUITE_STEP = "Remaining PostgreSQL integration tests"
PACKET = "Sli.Server.Tests.Agents.AgentPacketReportPostgresTests"
CHECKPOINT = "Sli.Server.Tests.InstallationSetup.NativeCheckpointCleanupTests"
VECTORS = {
    f"Sli.Server.Tests.Agents.Agent{family}ValidatorTests"
    for family in ("FileAudit", "Nps", "Workstation")
}


def workflow(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(("path", "expected"), [
    ("server-dotnet/tests/Sli.Server.Tests/Semantic/PasswordThroughputPostgresTests.cs", False),
    ("server-dotnet/tests/Sli.Server.Tests/Storage/ShortEventAdmissionPostgresTests.cs", True),
    ("server-dotnet/tests/Sli.Server.Tests/Workspace/BetaMenuWalkTests.cs", True),
    ("server-dotnet/src/Sli.Server/Auth/Access.cs", True),
    ("frontend/src/product-main.tsx", True),
    ("config/postgres_migrations/412_example.sql", True),
])
def test_beta_menu_walk_pull_request_path_filter(path, expected):
    # PyYAML's safe loader interprets the workflow's `on` key as a boolean.
    triggers = workflow("beta-menu-walk.yml")[True]
    assert "workflow_dispatch" in triggers
    filters = triggers["pull_request"]["paths"]
    last_match = next((rule for rule in reversed(filters) if fnmatchcase(path, rule.removeprefix("!"))), "")
    assert bool(last_match and not last_match.startswith("!")) == expected


def setup_steps(job: dict, action: str) -> list[dict]:
    return [step for step in job["steps"]
            if step.get("uses", "").startswith(f"actions/{action}@")
            or step.get("uses") == f"./artifacts/ci-actions/{action}"]


@pytest.mark.parametrize(("name", "job_name", "runner"), [
    ("beta-kit.yml", "release", "ubuntu-latest"),
    ("beta-kit-build.yml", "build", "ubuntu-latest"),
    ("agent-msi.yml", "msi", "windows-2025"),
])
def test_release_builds_use_fixed_hosted_runners(name, job_name, runner):
    source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    assert not any(re.search(r"\bvars\s*[.\[]", expression)
                   for expression in re.findall(r"\$\{\{(.*?)\}\}", source, re.DOTALL))
    jobs = workflow(name)["jobs"]
    assert jobs[job_name]["runs-on"] == runner
    assert all(job["runs-on"] == runner for job in jobs.values() if "runs-on" in job)
    if name == "beta-kit.yml":
        assert jobs["build"]["uses"] == "./.github/workflows/beta-kit-build.yml"
    elif name == "beta-kit-build.yml":
        assert jobs["agent-msi"]["uses"] == "./.github/workflows/agent-msi.yml"


@pytest.mark.parametrize(("selected_mode", "expected_flag"), [
    (None, "--draft"),
    ("prerelease", "--prerelease"),
])
def test_beta_kit_release_mode(selected_mode, expected_flag, tmp_path, monkeypatch):
    source = (ROOT / ".github/workflows/beta-kit.yml").read_text(encoding="utf-8")
    dispatch = yaml.load(source, Loader=yaml.BaseLoader)["on"]["workflow_dispatch"]
    publish = dispatch["inputs"]["publish"]
    assert publish["type"] == "choice"
    mode = selected_mode or publish["default"]
    assert mode in publish["options"]

    jobs = workflow("beta-kit.yml")["jobs"]
    step, = [step for step in jobs["release"]["steps"] if "run" in step]
    variable, = [name for name, value in step["env"].items() if value == "${{ inputs.publish }}"]
    commit = "0123456789abcdef0123456789abcdef01234567"
    archive = tmp_path / "sli-debian-beta-kit.tar.gz"
    archive.write_bytes(b"synthetic beta kit")
    monkeypatch.setenv(variable, mode)
    monkeypatch.setenv("KIT_COMMIT", commit)
    monkeypatch.setenv("GH_TOKEN", "synthetic-token")
    monkeypatch.setenv("GH_REPO", "example.test/example/sli")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://example.test")
    monkeypatch.setenv("GITHUB_REPOSITORY", "example/sli")
    monkeypatch.setenv("GITHUB_RUN_ID", "1")
    monkeypatch.delenv("BASH_ENV", raising=False)
    bash = shutil.which("bash")
    assert bash, "Bash is required to test the release step"
    script = """sha256sum sli-debian-beta-kit.tar.gz > SHA256SUMS || exit 1
gh() { printf '%s\\n' "$@"; }
""" + step["run"]
    result = subprocess.run([bash, "--noprofile", "--norc", "-c", script], cwd=tmp_path,
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    args = result.stdout.splitlines()
    assert args[:5] == ["release", "create", "beta-0123456789ab", archive.name, "SHA256SUMS"]
    assert args[args.index("--target") + 1] == commit
    assert {"--draft", "--prerelease"}.intersection(args) == {expected_flag}


@pytest.mark.parametrize(("name", "write_jobs"), [
    ("beta-kit.yml", {"release"}),
    ("beta-kit-build.yml", set()),
])
def test_beta_kit_contents_write_is_limited_to_publication(name, write_jobs):
    config = workflow(name)
    assert config["permissions"].get("contents") != "write"
    assert {
        job_name for job_name, job in config["jobs"].items()
        if job.get("permissions", {}).get("contents") == "write"
    } == write_jobs


@pytest.mark.parametrize(("case", "status"), [
    ("", 1),
    ('<test type="OtherTest" result="Pass"/>', 1),
    ('<test type="Sli.Server.Tests.Agents.AgentPacketReportPostgresTests" result="Skip"/>', 1),
    ('<test type="Sli.Server.Tests.Agents.AgentPacketReportPostgresTests" result="Pass"/>', 0),
])
def test_current_packet_report_requires_a_passing_xunit_case(tmp_path, case, status):
    step = next(step for step in workflow("pr-gate.yml")["jobs"]["postgres"]["steps"]
                if step.get("name") == "Signed AD packet reaches the journal on current PostgreSQL")
    guard = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    result = tmp_path / "report.xml"
    result.write_text(f"<assemblies><assembly>{case}</assembly></assemblies>", encoding="utf-8")
    check = subprocess.run([sys.executable, "-c", guard, str(result)], check=False)
    assert check.returncode == status


@pytest.mark.parametrize("name", WORKFLOWS)
def test_ci_gates_cover_locked_runtime_frontend_and_postgres(name: str) -> None:
    jobs = workflow(name)["jobs"]
    if name == "pr-gate.yml":
        assert {"source", "tests", "frontend"} <= jobs.keys()
        gate = jobs["gate"]
        assert gate["name"] == "source"
        assert {"changes", "source", "tests", "frontend", "postgres"} <= set(gate["needs"])
        assert gate["if"] == "${{ always() }}"
        guard, = gate["steps"]
        assert guard["env"]["SOURCE_RESULT"] == "${{ needs.source.result }}"
        assert guard["env"]["POSTGRES_RESULT"] == "${{ needs.postgres.result }}"
        assert any('not postgres_integration and not host_dependent' in step.get("run", "")
                   for step in jobs["tests"]["steps"])
        assert jobs["tests"]["runs-on"] == "ubuntu-latest"
    else:
        assert jobs["backend"]["runs-on"] == "windows-latest"

    for job_name in ("source", "frontend", "postgres"):
        if job_name in jobs:
            assert jobs[job_name]["runs-on"] == "ubuntu-latest"

    locked_python = re.search(r"Python (\d+\.\d+)", (ROOT / "requirements.lock.txt").read_text())[1]
    for job in jobs.values():
        for step in setup_steps(job, "setup-python"):
            assert step["with"]["python-version"] == locked_python
    frontend_runs = [step.get("run", "") for step in jobs["frontend"]["steps"]]
    assert "python -m pip install --disable-pip-version-check -r requirements.txt" in frontend_runs
    assert frontend_runs.index("python -m pip install --disable-pip-version-check -r requirements.txt") < frontend_runs.index("npm --prefix frontend exec vitest run src")
    assert setup_steps(jobs["frontend"], "setup-python")
    assert "npm --prefix frontend run lint" in frontend_runs
    assert "npm --prefix frontend exec vitest run src" in frontend_runs
    assert "npm --prefix frontend run build" in frontend_runs
    assert any("ruff check --config .github/ruff-ci.toml scripts tests" in step.get("run", "")
               for job in jobs.values() for step in job["steps"])

    postgres = jobs["postgres"]
    assert "services" not in postgres
    assert postgres["env"]["ADLOG_TEST_PG_DSN"] == postgres["env"]["ADLOG_PG_DSN"]
    assert postgres["env"]["ADLOG_TEST_PG_DSN"].endswith("/sli_test_ci")
    assert postgres["env"]["ADLOG_TEST_PG_EMPTY_DSN"].endswith("/sli_test_empty_ci")
    assert postgres["env"]["ADLOG_TEST_PG_EMPTY_DSN"] != postgres["env"]["ADLOG_TEST_PG_DSN"]
    runs = [step.get("run", "") for step in postgres["steps"]]
    assert runs.count(NATIVE_RESTORE_RUN) == 1
    packet_report, = [step for step in postgres["steps"]
                      if step.get("name") == "Signed AD packet reaches the journal on current PostgreSQL"]
    assert packet_report["shell"] == "bash"
    assert "continue-on-error" not in packet_report
    assert "--no-build -- -class Sli.Server.Tests.Agents.AgentPacketReportPostgresTests -failSkips" in packet_report["run"]
    assert '-result-xml "$result"' in packet_report["run"]
    assert not any("python -m pytest -q tests/e2e -m e2e" in run for run in runs)
    assert not any("docker" in run or "PG_CONTAINER" in run for run in runs)
    steps = {step.get("name"): step for step in postgres["steps"] if "name" in step}
    native_restore = steps["Verify full-schema ACL directory backup and parallel restore"]
    assert native_restore["run"] == NATIVE_RESTORE_RUN
    assert runs.index(steps["Bootstrap baseline and migrations"]["run"]) < runs.index(NATIVE_RESTORE_RUN)
    suite = steps[POSTGRES_SUITE_STEP]
    assert runs.index(NATIVE_RESTORE_RUN) < runs.index(suite["run"])
    filter_files, pytest_run = [
        shlex.split(line) for line in suite["run"].replace("\\\n", "").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert filter_files == [
        "grep", "-vxF", "-e", NATIVE_RESTORE_TEST,
        ".ci-shipped-python-tests.txt", ">", ".ci-shipped-postgres-tests.txt",
    ]
    pytest_options = []
    if name == "pr-gate.yml":
        assert suite["env"] == {"SHARD": "${{ matrix.shard }}", "SHARD_COUNT": "${{ strategy.job-total }}"}
        pytest_options = [
            "-p", "scripts.ci.postgres_test_shard", "--postgres-shard", "$SHARD", "$SHARD_COUNT",
            "-o", "junit_family=xunit1", "--junitxml=postgres-test-results.xml",
        ]
    assert pytest_run == [
        "python", "-m", "pytest", "-v", "-m", "postgres_integration and not e2e and not legacy",
        *pytest_options, "@.ci-shipped-postgres-tests.txt",
    ]
    install = steps["Ensure PostgreSQL 18 binaries"]["run"]
    assert 'if [ ! -d /usr/lib/postgresql/18/bin ]; then' in install
    assert "https://apt.postgresql.org/pub/repos/apt" in install
    assert "postgresql-18 postgresql-client-18" in install
    assert 'echo "/usr/lib/postgresql/18/bin" >> "$GITHUB_PATH"' in install
    start = steps["Start disposable PostgreSQL 18"]["run"]
    assert 'mktemp -d "$RUNNER_TEMP/sli-postgres.XXXXXX"' in start
    assert '>> "$GITHUB_ENV"' in start
    assert "initdb" in start and "--auth=trust" in start and "--username=postgres" in start
    assert "listen_addresses = '127.0.0.1'" in start and "port = 5432" in start
    assert "unix_socket_directories = ''" in start
    assert "pg_ctl" in start and "-w start" in start
    assert runs.index(install) < runs.index(start) < runs.index(steps["Bootstrap baseline and migrations"]["run"])
    stop = postgres["steps"][-1]
    assert stop["name"] == "Stop disposable PostgreSQL 18"
    assert stop["if"] == "${{ always() }}"
    assert '"$PGDATA/postmaster.pid"' in stop["run"]
    assert 'pg_ctl -D "$PGDATA" -m immediate -w stop' in stop["run"]
    assert not any("SLI_BOOTSTRAP_TEST_PG_DSN" in key for key in postgres["env"])


@pytest.mark.parametrize("paths", [["deploy/linux/native_host.py"], ["config/postgres_migrations/example.sql"]])
def test_pr_source_and_unit_collect_each_case_once(tmp_path, paths):
    selection = pytest_arguments(ROOT, paths)
    checkpoint_file = "tests/unit/test_linux_native_upgrade_prepare.py"
    checkpoint_case = f"{checkpoint_file}::test_integrity_receipt_rechecks_current_manifest"
    source_file = "tests/unit/test_sli_secrets.py"
    synthetic_cases = {
        source_file: ["test_secret_guard"],
        checkpoint_file: ["test_integrity_receipt_rechecks_current_manifest", "test_other_upgrade_behavior"],
    }
    for path, methods in synthetic_cases.items():
        file = tmp_path / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("".join(f"def {method}(): pass\n" for method in methods), encoding="utf-8")
    config = tmp_path / "pytest.ini"
    config.write_text("[pytest]\n", encoding="utf-8")
    collected = Counter()
    for suite in ("source", "checkpoint", "unit"):
        args = [selector for selector in selection[suite]
                if selector.removeprefix("--deselect=").split("::", 1)[0] in synthetic_cases
                and ("::" not in selector or selector.removeprefix("--deselect=") == checkpoint_case)]
        assert args
        argfile = tmp_path / f"{suite}.txt"
        argfile.write_text("\n".join(args) + "\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "-c", str(config), f"@{argfile}"],
            cwd=tmp_path, capture_output=True, text=True, check=True,
            env=os.environ | {"PYTEST_ADDOPTS": "", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
        )
        collected.update(line for line in result.stdout.splitlines() if line.startswith("tests/"))
    assert collected == Counter(f"{path}::{method}" for path, methods in synthetic_cases.items() for method in methods)


def test_auth_changes_keep_native_security_checks():
    cases = pytest_arguments(ROOT, ["server-dotnet/src/Sli.Server/Auth/Access.cs"])
    assert "tests/tooling/test_ui_domain_binding_guard.py" in cases["source"]
    assert "tests/unit/test_native_owner_hash.py" in pytest_arguments(ROOT, ["scripts/ci/pr_scope.py"])["unit"]


@pytest.mark.parametrize("paths", [
    ["server-dotnet/src/Sli.Server/Storage/Db.cs"],
    ["server-dotnet/src/Sli.Server/Installation/InstallationService.cs"],
    ["server-dotnet/src/Sli.Server/Jobs/Worker.cs"],
])
def test_pr_dotnet_cases_have_one_owner_even_when_python_jobs_are_skipped(paths):
    pr, dotnet = (workflow(name)["jobs"] for name in ("pr-gate.yml", "server-dotnet.yml"))
    tracked = VECTORS | {PACKET, CHECKPOINT}
    rules = [rule for rule in read_rules(ROOT / "scripts/ci/server_dotnet_ci_profiles.txt")
             if rule[1] == "class" and rule[2] in tracked]
    cases = [{"Class": name, "Method": "Scenario", "Explicit": False} for name in tracked]
    profiles = plan_profiles(cases, [], rules)
    shard_step, = [step for step in dotnet["server-tests"]["steps"]
                   if "python ../scripts/ci/server_dotnet_shard.py " in step.get("run", "")]
    assert shard_step["env"]["PR_POSTGRES"] == "${{ needs.changes.outputs.pr-postgres }}"
    assert shard_step["env"]["PR_CHECKPOINT"] == "${{ needs.changes.outputs.pr-checkpoint }}"
    for changes in (pr["changes"], dotnet["changes"]):
        assert any("python3 -m scripts.ci.pr_scope" in step.get("run", "")
                   for step in changes["steps"])
    jobs = plan_jobs(paths)
    env = os.environ | {
        "EVENT": "pull_request", "SHARD": "1", "SHARD_COUNT": "16", "PROFILE": "pr", "RISK_AREAS": "",
        "PR_POSTGRES": str(jobs["postgres"]).lower(), "PR_CHECKPOINT": str(jobs["checkpoint"]).lower(),
    }
    bash = shutil.which("bash")
    assert bash, "Bash is required to check workflow routing"
    command = subprocess.run(
        [bash, "-eo", "pipefail", "-c", "python() { printf '%s\\n' \"$@\"; }\n" + shard_step["run"]],
        capture_output=True, text=True, check=True, env=env,
    ).stdout.splitlines()
    sharded = profiles["pr"].copy()
    for flag, profile in zip(command, command[1:]):
        if flag == "--covered-by":
            sharded -= profiles[profile]
    vectors = [name for step in dotnet["source-vectors"]["steps"]
               for name in re.findall(r"-class (\S+)", step.get("run", ""))]
    assert set(vectors) == VECTORS
    assert set(dotnet["build-and-test"]["needs"]) == {"server-tests", "source-vectors"}
    actual = Counter(vectors)
    if jobs["checkpoint"]:
        actual[CHECKPOINT] += 1
    if jobs["postgres"]:
        actual.update(name for step in pr["postgres"]["steps"]
                      for name in re.findall(r"-class (\S+)", step.get("run", "")))
    actual.update(name.rsplit(".", 1)[0] for name in sharded)
    assert actual == Counter(tracked)


@pytest.mark.parametrize("missing_client", ("pg_dump", "pg_restore"))
def test_native_restore_requires_clients_for_a_configured_disposable_database(tmp_path, monkeypatch, missing_client):
    from tests.migrations import test_qw_restore_context_migration as restore

    monkeypatch.setenv("ADLOG_TEST_PG_DSN", "postgresql://postgres@127.0.0.1:5432/sli_test_ci")
    monkeypatch.setattr(restore.shutil, "which",
                        lambda tool: None if tool == missing_client else "/synthetic/" + tool)
    monkeypatch.setattr(psycopg, "connect", lambda *_args, **_kwargs: pytest.fail("must reject before connecting"))
    with pytest.raises(AssertionError, match="CI requires PostgreSQL client tools"):
        restore.test_full_migrations_acl_directory_dump_parallel_restore_and_runtime_guards(tmp_path)


@pytest.mark.parametrize(("job_name", "action", "revision"), [
    ("source", "setup-python", "a26af69be951a213d495a4c3e4e4022e16d87065"),
    ("frontend", "setup-python", "a26af69be951a213d495a4c3e4e4022e16d87065"),
    ("frontend", "setup-node", "49933ea5288caeca8642d1e84afbd3f7d6820020"),
])
def test_failed_jobs_fetch_pinned_setup_actions_over_git(job_name, action, revision):
    job = workflow("pr-gate.yml")["jobs"][job_name]
    steps = job["steps"]
    path = f"artifacts/ci-actions/{action}"
    setup, = setup_steps(job, action)
    assert setup["uses"] == f"./{path}"
    checkout, = [step for step in steps if step.get("with", {}).get("repository") == f"actions/{action}"]
    assert checkout["uses"] == "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
    assert checkout["with"] == {
        "repository": f"actions/{action}", "ref": revision, "path": path,
        "persist-credentials": False,
    }
    assert steps.index(checkout) < steps.index(setup)


def test_disposable_postgres_jobs_keep_shared_gates() -> None:
    pr, manual = (workflow(name)["jobs"]["postgres"] for name in WORKFLOWS)
    assert pr.pop("needs") == "changes"
    assert pr.pop("if") == "${{ needs.changes.outputs.postgres == 'true' }}"
    pr.pop("name")
    strategy = pr.pop("strategy")
    shards = strategy["matrix"]["shard"]
    assert shards == list(range(1, len(shards) + 1)) and len(shards) > 1
    assert strategy == {"fail-fast": False, "matrix": {"shard": shards}}

    pr_steps = {step.get("name"): step for step in pr["steps"] if "name" in step}
    upgrade_name = "Verify migrations and backup recovery on private PostgreSQL 18"
    kit_name = "Verify the beta kit migration path on private PostgreSQL 18"
    once_per_matrix = (
        upgrade_name,
        kit_name,
        "Signed AD packet reaches the journal on current PostgreSQL",
        "Verify full-schema ACL directory backup and parallel restore",
    )
    for step_name in once_per_matrix:
        step = pr_steps[step_name]
        assert step.pop("if") in {f"matrix.shard == {shard}" for shard in shards}
        assert "continue-on-error" not in step

    upgrade = pr_steps[upgrade_name]
    assert "tests/unit/test_linux_install_upgrade_checks.py" in upgrade["run"]
    assert "tests/unit/test_linux_native_pg_migrate.py" in upgrade["run"]
    pr["steps"].remove(upgrade)
    pr["steps"].remove(pr_steps[kit_name])
    pr["steps"].remove(pr_steps["Preserve per-case PostgreSQL test results"])

    # Compare all shared gates after accounting for the verified selection differences.
    for name, job in zip(WORKFLOWS, (pr, manual), strict=True):
        suite, = [step for step in job["steps"] if step.get("name") == POSTGRES_SUITE_STEP]
        assert "if" not in suite and "continue-on-error" not in suite
        if name == "pr-gate.yml":
            suite.pop("env")
        suite.pop("run")

    # Both the SDK and the server build must be available before every Python shard runs.
    sdk, = setup_steps(pr, "setup-dotnet")
    build = pr_steps["Build shipped server and packet report test"]
    assert all("if" not in step and "continue-on-error" not in step for step in (sdk, build))
    assert pr["steps"].index(sdk) < pr["steps"].index(build) < pr["steps"].index(pr_steps[POSTGRES_SUITE_STEP])
    assert pr == manual

@pytest.mark.parametrize("name", WORKFLOWS)
@pytest.mark.parametrize("failure", [None, "sql", "ledger", "version"])
def test_ci_bootstrap_uses_installer_roles_baseline_and_exact_ledger(
    name: str, failure: str | None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    steps = workflow(name)["jobs"]["postgres"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == "Bootstrap baseline and migrations")
    source = script.split("\n", 1)[1].rsplit("\nPY", 1)[0]
    migrations = bootstrap.forward_migration_inventory(ROOT / "config/postgres_migrations")
    baseline = bootstrap.load_baseline(ROOT / "config/postgres_baseline", migrations)
    expected = sorted([
        *bootstrap.base_schema_markers(ROOT / "config/postgres_schema.sql"),
        *((item.version, item.name) for item in migrations),
    ])
    statements = []
    connections = []
    sql_calls = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, statement, parameters=None):
            statements.append((statement, parameters))
            return SimpleNamespace(
                fetchone=lambda: (170009 if failure == "version" else 180006,),
                fetchall=lambda: expected[:-1] if failure == "ledger" else expected,
            )

    def connect(dsn, **kwargs):
        connections.append((dsn, kwargs))
        return Connection()

    def run(command, **kwargs):
        kwargs["sql"] = Path(command[-1]).read_text(encoding="utf-8")
        sql_calls.append((command, kwargs))
        return SimpleNamespace(returncode=1 if failure == "sql" else 0)

    monkeypatch.setenv("ADLOG_TEST_PG_DSN", "postgresql://postgres@127.0.0.1:5432/sli_test_ci")
    monkeypatch.setattr(psycopg, "connect", connect)
    monkeypatch.setattr(
        "deploy.linux.sli_core.auth.PASSWORD_HASHER",
        SimpleNamespace(hash=lambda _password: "synthetic-hash"),
    )
    monkeypatch.setattr("subprocess.run", run)
    monkeypatch.chdir(ROOT)
    if failure:
        errors = {
            "sql": "migration_apply_failed",
            "ledger": "migration_ledger_mismatch",
            "version": "postgresql_18_required",
        }
        with pytest.raises(bootstrap.BootstrapError, match=errors[failure]):
            exec(compile(source, f"{name}:bootstrap", "exec"), {})  # noqa: S102 - trusted workflow with fakes
        if failure == "sql":
            assert len(sql_calls) == 1
        if failure == "version":
            assert not sql_calls
            assert not any("CREATE ROLE" in sql for sql, _params in statements)
        if failure != "ledger":
            assert not any("select version, name" in sql for sql, _params in statements)
        return

    exec(compile(source, f"{name}:bootstrap", "exec"), {})  # noqa: S102 - trusted workflow with fakes
    assert connections[0][1]["dbname"] == "postgres"
    assert connections[1][0] == os.environ["ADLOG_TEST_PG_DSN"]
    assert any('CREATE ROLE "adlog_user" LOGIN NOSUPERUSER NOCREATEDB' in sql
               for sql, _params in statements)
    assert any('CREATE DATABASE "sli_test_ci"' in sql for sql, _params in statements)
    assert any("create database sli_test_empty_ci with template template0" in sql
               for sql, _params in statements)
    assert any("insert into public.auth_users" in sql for sql, _params in statements)
    assert any("select version, name" in sql for sql, _params in statements)
    assert sql_calls[0][0][-1] == str(baseline.roles_path)
    assert "__SLI_REPORT_DOMAIN__" not in sql_calls[1][1]["sql"]
    assert "example.test" in sql_calls[1][1]["sql"]
    assert [kwargs["sql"] for _cmd, kwargs in sql_calls[2:]] == [
        migration.path.read_text(encoding="utf-8")
        for migration in migrations if migration.version > baseline.version
    ]
    assert [command[command.index("--username") + 1] for command, _kwargs in sql_calls[2:]] == [
        "postgres" if bootstrap.migration_requires_admin(migration) else "adlog_user"
        for migration in migrations if migration.version > baseline.version
    ]
    for command, kwargs in sql_calls:
        assert Path(command[0]) == Path("/usr/lib/postgresql/18/bin/psql")
        assert command[-2] == "--file"
        assert kwargs["env"]["PATH"] == str(Path("/usr/lib/postgresql/18/bin"))
        assert kwargs["input"] is None
        assert "ON_ERROR_STOP=1" in command
        assert "--no-password" in command
        assert kwargs["capture_output"] is True
        assert kwargs["check"] is False
