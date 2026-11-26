"""Plan PR jobs and pytest arguments from the same merge-base diff."""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
import subprocess

from scripts.ci import server_dotnet_risk, shipped_python_tests as shipped


SERVER = "server-dotnet/src/Sli.Server/"
API_CONTRACTS = (
    f"{SERVER}Program.cs", f"{SERVER}Compatibility/", "config/i18n/",
    f"{SERVER}Auth/Lifecycle/AuthResponse.cs", f"{SERVER}Reporting/V2/ReportDefinition.cs",
    f"{SERVER}Reporting/V2/ReportResult.cs", f"{SERVER}Reporting/V2/ReportV2Metadata.cs",
    f"{SERVER}Reporting/V2/report-definitions.json",
    "config/navigation_v3.json", "config/plugin_architecture_v3.json", "config/plugin_packages/",
    "config/plugin_settings_schema/", "config/plugin_settings_schema_v1.json",
)
AGENT_ONLY_ENDPOINTS = {
    f"{SERVER}Agents/Agent{name}Endpoints.cs" for name in ("Enrollment", "Packet", "Update")
} | {f"{SERVER}Agents/ClientControl/AgentClientControlEndpoints.cs"}
MIGRATIONS = (
    "config/postgres_migrations/", "config/postgres_baseline/", "config/postgres_schema.sql",
    "config/clickhouse/", "deploy/linux/native_pg_ledger.json", "tests/migrations/",
)
CI = (".github/", "scripts/ci/", "tests/tooling/test_ci_workflows.py", "tests/conftest.py")
DEPENDENCIES = ("requirements.txt", "requirements.lock.txt", "pytest.ini", "package.json", "package-lock.json")
AGENT = (
    "agent-dotnet/", "sli_agent/", "sli_collect/", "server/sli/agents/", "server/sli/agent_ingest.py",
    f"{SERVER}Agents/", "config/event_catalog.json", "config/source_packs/dc.json",
    "tests/unit/test_agent_dotnet_vectors.py",
)
AGENT_SECURITY_TESTS = {
    f"tests/unit/test_{name}.py" for name in (
        "agent_ca", "agent_tls", "agent_security_recovery", "agent_group_enrollment",
        "agent_packets_api", "agent_updates", "sli_agent_enrollment", "sli_agent_transport", "sli_agent_updates",
    )
}
UI_DOMAIN_TESTS = {
    "tests/tooling/test_ui_domain_binding_guard.py", "tests/unit/test_ui_domain_binding_api.py",
    "tests/core/test_report_domain.py",
}
SUITES = ("source", "checkpoint", "posix", "unit")
POSTGRES_INSTALLER_PATHS = (
    "deploy/linux/native_pg_", "deploy/linux/backup", "deploy/linux/native_package.py",
    "deploy/linux/native_backup.py", "deploy/linux/native_restore.py", "deploy/linux/native_upgrade.py",
    "deploy/linux/restore_existing.py", "deploy/linux/restore_sandbox.py",
    "tests/unit/test_linux_native_pg_", "tests/unit/test_linux_backup_", "tests/unit/test_linux_restore_",
    "tests/unit/test_linux_native_backup", "tests/unit/test_linux_native_restore", "tests/unit/test_linux_native_upgrade",
)


def matches(path: str, patterns: tuple[str, ...]) -> bool:
    return any(path.startswith(pattern) if pattern.endswith("/") else path == pattern for pattern in patterns)


def area(path: str) -> str:
    if matches(path, CI):
        return "ci"
    if matches(path, MIGRATIONS):
        return "migrations"
    if path in DEPENDENCIES or "/" not in path and path.startswith("requirements") and path.endswith(".txt"):
        return "dependencies"
    if matches(path, API_CONTRACTS) or (
        path.startswith(SERVER) and path.endswith("Endpoints.cs") and path not in AGENT_ONLY_ENDPOINTS
    ):
        return "api"
    if path.startswith("docs/") or path.endswith(".md") and "/" not in path:
        return "docs"
    if path.startswith("frontend/"):
        return "frontend"
    if matches(path, AGENT):
        return "agent-dotnet"
    if path.startswith("deploy/linux/") or path.startswith("tests/unit/test_linux_") and path.endswith(".py"):
        return "linux-installer"
    if path.startswith("server-dotnet/"):
        return "server-dotnet"
    return "unknown"


def plan_jobs(paths: list[str]) -> dict[str, bool]:
    areas = {area(path) for path in paths}
    risks = set(server_dotnet_risk.changed_areas(paths))
    broad = not areas or bool(areas & {"ci", "migrations", "dependencies", "api", "unknown"})
    # Recovery helpers, migration tooling and shared agent transport have live PG contracts.
    postgres = broad or bool(risks) or any(
        path.startswith(POSTGRES_INSTALLER_PATHS
                        + ("agent-dotnet/src/Sli.Agent.Protocol/", "agent-dotnet/src/Sli.Agent.Core/", f"{SERVER}Agents/"))
        or path in {"deploy/linux/native_install.py", "deploy/linux/sli_update.py",
                    "deploy/linux/build_beta_kit.py", "deploy/linux/migrate.py",
                    "deploy/linux/runtime_grants.sql", "deploy/linux/default_semantic_policy.sql",
                    "tests/unit/test_linux_install_upgrade_checks.py"}
        for path in paths
    )
    return {
        "broad": broad,
        "frontend": not paths or bool(areas & {"frontend", "api"})
        or any(path in {"package.json", "package-lock.json"} for path in paths),
        "postgres": postgres,
        "checkpoint": broad or "linux-installer" in areas or any(
            path.startswith((f"{SERVER}Installation/", "server-dotnet/tests/Sli.Server.Tests/InstallationSetup/"))
            for path in paths
        ),
        "unit": broad or areas != {"docs"},
    }


def installer_dependents(root: Path, changed: set[str], index: dict[str, str]) -> set[str]:
    modules = [path for path in index.values() if path.startswith("deploy/linux/") and (root / path).is_file()]
    if any(not path.endswith(".py") or path.endswith("/__init__.py") for path in changed):
        return set(modules)
    imports = {path: shipped.references(path, shipped.parse(root, path), index, embedded=True) for path in modules}
    affected = set(changed)
    while dependents := {path for path, refs in imports.items() if refs & affected} - affected:
        affected.update(dependents)
    return affected


def scoped_tests(root: Path, paths: list[str]) -> set[str]:
    areas = {area(path) for path in paths}
    selected = {path for path in paths if path.startswith("tests/") and path.endswith(".py") and (root / path).is_file()}
    literals = areas & {"frontend", "server-dotnet", "agent-dotnet"}
    if "frontend" in areas:
        selected.update(UI_DOMAIN_TESTS)
    if "agent-dotnet" in areas:
        selected.update(AGENT_SECURITY_TESTS)
    if any(path.startswith((f"{SERVER}Reporting/", f"{SERVER}Gpo/", f"{SERVER}Ad/")) for path in paths):
        selected.update(shipped.REPORT_ACCESS_TESTS)
    if set(server_dotnet_risk.changed_areas(paths)) & {"access", "storage"}:
        selected.update(shipped.REPORT_ACCESS_TESTS | UI_DOMAIN_TESTS)
    changed = {path for path in paths if path.startswith("deploy/linux/")}
    assets = changed - {path for path in changed if path.endswith(".py")}
    index = shipped.source_index(root) if changed else {}
    # Resolve imports of removed modules as well as modules in the checkout.
    index.update({shipped.module_name(path): path for path in changed if path.endswith(".py")})
    if changed:
        # Deleted paths are usable as reference targets, not AST inputs.
        changed = installer_dependents(root, changed, index)
    for file in shipped.python_files(root / "tests"):
        if not file.name.startswith("test_"):
            continue
        path = file.relative_to(root).as_posix()
        if literals or changed:
            source = file.read_text(encoding="utf-8-sig")
            if any(name in source for name in literals) or any(asset in source for asset in assets):
                selected.add(path)
            elif changed and "deploy" in source and (
                shipped.references(path, ast.parse(source, filename=path), index, embedded=True) & changed
            ):
                selected.add(path)
    return selected


def pytest_arguments(root: Path, paths: list[str], *, include_legacy_reports: bool = False) -> dict[str, list[str]]:
    jobs = plan_jobs(paths)
    if not jobs["unit"]:
        return {suite: [] for suite in SUITES}
    if jobs["broad"]:
        files, _, _, _ = shipped.select_tests(root, include_legacy_reports=include_legacy_reports)
        selected = set(files)
    else:
        selected = scoped_tests(root, paths)
    result = {}
    for suite in ("source", "checkpoint", "posix"):
        manifest = root / f"scripts/ci/pr_{suite}_tests.txt"
        selectors = manifest.read_text(encoding="utf-8").splitlines()
        result[suite] = [selector for selector in selectors if jobs["broad"]
                         or suite == "checkpoint" and jobs["checkpoint"]
                         or suite != "checkpoint" and selector.split("::", 1)[0] in selected]
    # POSIX and unit are separated by marker. Only source and checkpoint need deselects.
    source = result["source"] + result["checkpoint"]
    selected.difference_update(selector for selector in source if "::" not in selector)
    result["unit"] = sorted(selected)
    result["unit"].extend(f"--deselect={selector}" for selector in source
                          if selector.split("::", 1)[0] in selected)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diff", nargs=2, metavar=("BASE", "HEAD"))
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--argfiles", type=Path)
    args = parser.parse_args()
    paths = []
    if args.diff:
        base, head = args.diff
        # Count both paths on renames, including moves out of a protected area.
        raw = subprocess.check_output(["git", "diff", "--name-only", "--no-renames", "-z", f"{base}...{head}", "--"])
        paths = [path for path in raw.decode("utf-8", errors="surrogateescape").split("\0") if path]
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as output:
            for name, applies in plan_jobs(paths).items():
                print(f"{name}={str(applies).lower()}", file=output)
    if args.argfiles:
        args.argfiles.mkdir(parents=True, exist_ok=True)
        for suite, selectors in pytest_arguments(Path.cwd(), paths, include_legacy_reports=not args.diff).items():
            if any("\n" in selector or "\r" in selector for selector in selectors):
                parser.error("A pytest selector contains a line break")
            (args.argfiles / f"{suite}.txt").write_text("".join(f"{selector}\n" for selector in selectors),
                                                        encoding="utf-8")


if __name__ == "__main__":
    main()
