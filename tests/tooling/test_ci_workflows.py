#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
import yaml

from scripts.maintenance import existing_postgres_bootstrap as bootstrap

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ("pr-gate.yml", "manual-full-gate.yml")
COLLECTION_EXPERIMENT_TEST = "tests/reporting/test_agent_collection_query_plan_postgres.py"
COLLECTION_EXPERIMENT_RUN = f"python -m pytest -q -s {COLLECTION_EXPERIMENT_TEST}"
RECEIPT_EXPERIMENT_TEST = "tests/reporting/test_plugin_receipts_query_plan_postgres.py"
RECEIPT_EXPERIMENT_RUN = f"python -m pytest -q -s {RECEIPT_EXPERIMENT_TEST}"
RECEIPT_PARITY_RUN = (
    f"python -m pytest -q {RECEIPT_EXPERIMENT_TEST}"
    "::test_split_candidate_preserves_exact_receipt_import_snapshot_facts"
)
RECEIPT_STEPS = {
    "pr-gate.yml": {"name": "Check plugin receipt fact parity", "run": RECEIPT_PARITY_RUN},
    "manual-full-gate.yml": {
        "name": "Measure synthetic plugin receipt plans", "run": RECEIPT_EXPERIMENT_RUN,
    },
}
NATIVE_RESTORE_TEST = "tests/migrations/test_qw_restore_context_migration.py"
NATIVE_RESTORE_RUN = f"python -m pytest -q {NATIVE_RESTORE_TEST} -m postgres_integration"
# --ignore does not drop explicitly listed files, so the shipped list is filtered.
POSTGRES_SUITE_RUN = (
    "# --ignore does not drop a file passed explicitly, so the three files run\n"
    "# in their own steps above are removed from the shipped list here.\n"
    f"grep -vxF -e {NATIVE_RESTORE_TEST} -e {COLLECTION_EXPERIMENT_TEST} "
    f"-e {RECEIPT_EXPERIMENT_TEST} .ci-shipped-python-tests.txt > .ci-shipped-postgres-tests.txt\n"
    'python -m pytest -v -m "postgres_integration and not e2e" @.ci-shipped-postgres-tests.txt\n'
)


def workflow(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))


def setup_steps(job: dict, action: str) -> list[dict]:
    return [step for step in job["steps"]
            if step.get("uses", "").startswith(f"actions/{action}@")
            or step.get("uses") == f"./artifacts/ci-actions/{action}"]


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
        assert jobs["source"]["needs"] == ["changes", "postgres"]
        assert jobs["source"]["if"] == "${{ always() }}"
        # postgres may be skipped only for a UI-only change detected by the changes job.
        assert 'test "$POSTGRES_RESULT" = success ||' in jobs["source"]["steps"][0]["run"]
        assert 'test "$CHANGES_RESULT" = success' in jobs["source"]["steps"][0]["run"]
        assert jobs["source"]["steps"][0]["env"]["POSTGRES_RESULT"] == "${{ needs.postgres.result }}"
        assert any('not postgres_integration and not host_dependent' in step.get("run", "")
                   for step in jobs["tests"]["steps"])
    else:
        assert "backend" in jobs

    tests_job = jobs["tests" if name == "pr-gate.yml" else "backend"]
    assert tests_job["runs-on"] == "${{ vars.SLI_TESTS_RUNNER || 'windows-latest' }}"
    for job_name in ("source", "frontend", "postgres"):
        if job_name in jobs:
            assert jobs[job_name]["runs-on"] == "${{ vars.SLI_LINUX_RUNNER || 'ubuntu-latest' }}"

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
    assert any("ruff check --config .github/ruff-ci.toml server scripts tests" in step.get("run", "")
               for job in jobs.values() for step in job["steps"])

    postgres = jobs["postgres"]
    assert "services" not in postgres
    assert postgres["env"]["ADLOG_TEST_PG_DSN"] == postgres["env"]["ADLOG_PG_DSN"]
    assert postgres["env"]["ADLOG_TEST_PG_DSN"].endswith("/sli_test_ci")
    assert postgres["env"]["ADLOG_TEST_PG_EMPTY_DSN"].endswith("/sli_test_empty_ci")
    assert postgres["env"]["ADLOG_TEST_PG_EMPTY_DSN"] != postgres["env"]["ADLOG_TEST_PG_DSN"]
    runs = [step.get("run", "") for step in postgres["steps"]]
    assert runs[-3] == NATIVE_RESTORE_RUN
    assert runs[-2] == POSTGRES_SUITE_RUN
    assert runs.count(NATIVE_RESTORE_RUN) == runs.count(POSTGRES_SUITE_RUN) == 1
    packet_report, = [step for step in postgres["steps"]
                      if step.get("name") == "Signed AD packet reaches the journal on current PostgreSQL"]
    assert packet_report["shell"] == "bash"
    assert "if" not in packet_report and "continue-on-error" not in packet_report
    assert "--no-build -- -class Sli.Server.Tests.Agents.AgentPacketReportPostgresTests -failSkips" in packet_report["run"]
    assert '-result-xml "$result"' in packet_report["run"]
    assert not any("python -m pytest -q tests/e2e -m e2e" in run for run in runs)
    assert not any("docker" in run or "PG_CONTAINER" in run for run in runs)
    steps = {step.get("name"): step for step in postgres["steps"] if "name" in step}
    experiment = steps["Measure synthetic collection aggregation equivalence"]
    assert experiment == {"name": "Measure synthetic collection aggregation equivalence", "run": COLLECTION_EXPERIMENT_RUN}
    assert runs.count(COLLECTION_EXPERIMENT_RUN) == 1
    assert runs.index(COLLECTION_EXPERIMENT_RUN) < runs.index(NATIVE_RESTORE_RUN)
    receipt_step = RECEIPT_STEPS[name]
    assert steps[receipt_step["name"]] == receipt_step
    receipt_run = receipt_step["run"]
    assert runs.count(receipt_run) == 1
    assert runs.index(COLLECTION_EXPERIMENT_RUN) < runs.index(receipt_run)
    assert runs.index(receipt_run) < runs.index(NATIVE_RESTORE_RUN)
    if name == "pr-gate.yml":
        # The volume test is manual-only; PRs retain exact fact-parity coverage.
        assert RECEIPT_EXPERIMENT_RUN not in runs
        assert "Measure synthetic plugin receipt plans" not in steps
    native_restore = steps["Verify full-schema ACL directory backup and parallel restore"]
    assert native_restore == {
        "name": "Verify full-schema ACL directory backup and parallel restore",
        "run": NATIVE_RESTORE_RUN,
    }  # No conditional skip, continue-on-error or fallback may hide this gate.
    assert runs.index(steps["Bootstrap baseline and migrations"]["run"]) < runs.index(NATIVE_RESTORE_RUN)
    assert runs.index(NATIVE_RESTORE_RUN) < runs.index(POSTGRES_SUITE_RUN)
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
    jobs = []
    for name in WORKFLOWS:
        job = workflow(name)["jobs"]["postgres"]
        # pr-gate skips postgres for UI-only changes; the job body stays identical.
        job.pop("needs", None)
        job.pop("if", None)
        # Assert the exact allowed difference, including absence of skip/failure
        # bypasses, then compare every other setting and ordered step unchanged.
        receipt_step = RECEIPT_STEPS[name]
        assert job["steps"].count(receipt_step) == 1
        job["steps"] = [
            {"name": "receipt diagnostic scope"} if step == receipt_step else step
            for step in job["steps"]
        ]
        if name == "pr-gate.yml":
            # The PR gate also verifies native package upgrade and recovery.
            upgrade = [step for step in job["steps"]
                       if step.get("name") == "Verify migrations and backup recovery on private PostgreSQL 18"]
            assert len(upgrade) == 1
            assert "if" not in upgrade[0] and "continue-on-error" not in upgrade[0]
            job["steps"].remove(upgrade[0])
        jobs.append(job)
    assert jobs[0] == jobs[1]




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
        "server.sli.access.auth.PASSWORD_HASHER",
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

