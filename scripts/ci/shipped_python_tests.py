"""Select tests of the Debian payload, its CI tools and shipped migrations.

Static references include deferred imports and test helpers. The output is a
pytest @argfile with one path per line.
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
import re
import sys
import textwrap
from functools import cache

from deploy.linux.build_beta_kit import RETIRED_LINUX_PATHS


PR_TEST_MANIFESTS = ("pr_source_tests.txt", "pr_checkpoint_tests.txt", "pr_posix_tests.txt")
BUILD_TOOLS = {"scripts/maintenance/publish_react_build.py", "scripts/maintenance/github_sanitary_check.py"}
SECURITY_TESTS = {"tests/tooling/test_sli_agent_local_install.py"}
# These suites use native helpers or real SQL as fixtures for retired services
# and their Compose installer. The helpers have their own native suites.
RETIRED_TESTS = {
    "tests/core/test_core_ops1_collector_storage_dashboard.py",
    "tests/core/test_findings_pg1_incremental_pipeline.py",
    "tests/core/test_nps_pipeline_runtime.py",
    "tests/reporting/test_agent_collection_query_plan_postgres.py",
    "tests/reporting/test_http_server_route_equivalence.py",
    "tests/reporting/test_navigation_registry.py",
    "tests/reporting/test_plugin_receipts_query_plan_postgres.py",
    "tests/storage/test_permanent_history_lifecycle.py",
    "tests/tooling/test_sli_install.py",
} | {f"tests/unit/test_{name}.py" for name in (
    "ad_gpo_core_jobs", "ad_snapshot_composition", "file_audit_registration", "gpo_plugin_reports",
    "linux_shutdown", "plugin_update", "release_artifacts", "report_producer_proposal",
    "sli_accept_candidate", "sli_installation", "sli_update", "sli_update_helper_preload",
    "smtp_setup_deployment", "stand_update", "telegram_proxy_installation", "telegram_setup",
    "update_acceptance_drill", "updater_component", "updater_isolated_closure", "updater_transition",
    "updater_transition_contract", "verify_offline_kit", "workstation_admin", "workstation_projection_jobs",
    "workstation_retention_jobs",
)}
SHIPPED_ASSET = re.compile(
    r"\b(?:postgres_migrations|postgres_baseline|postgres_schema(?:_v8)?\.sql|native_pg_ledger\.json"
    r"|deploy/linux/(?:runtime_grants|default_semantic_policy)\.sql|config/clickhouse/[\w./-]+)\b"
)
MIGRATION_TESTS = {
    "tests/access/test_existing_postgres_bootstrap.py",
    "tests/tooling/test_apply_selected_migrations.py",
    "tests/tooling/test_selected_migrations_postgres.py",
    "tests/unit/test_canonical_sql_chain.py",
    "tests/unit/test_linux_migration_transfer.py",
    "tests/unit/test_linux_native_pg_inventory.py",
    "tests/unit/test_migration_306_reconciliation.py",
    "tests/unit/test_report_producer_migration.py",
    "tests/unit/test_update_ledger_reconciliation.py",
}
SOURCE_ROOTS = ("server", "deploy", "scripts", "sli_agent", "sli_collect", "tools")
SKIP_DIRS = {"__pycache__", ".venv", "node_modules", ".git"}
MODULE_REFERENCE = re.compile(
    r"\b(?:server|deploy|scripts|sli|sli_agent|sli_collect|tools|tests)(?:\.[A-Za-z_]\w*)+"
)
SOURCE_REFERENCE = re.compile(
    r"\b(?:server|deploy|scripts|sli_agent|sli_collect|tools|tests)(?:/[\w.-]+)+\.py\b"
)


def python_files(directory: Path):
    return sorted(path for path in directory.rglob("*.py")
                  if not SKIP_DIRS.intersection(path.relative_to(directory).parts))


def module_name(path: str) -> str:
    name = path.removesuffix(".py").replace("/", ".")
    return name.removesuffix(".__init__")


def source_index(root: Path) -> dict[str, str]:
    return {module_name(path.relative_to(root).as_posix()): path.relative_to(root).as_posix()
            for directory in SOURCE_ROOTS for path in python_files(root / directory)}


def references(path: str, tree: ast.AST, index: dict[str, str], *, embedded=False) -> set[str]:
    found = set()

    def add(name):
        if name == "sli" or name.startswith("sli."):
            name = "server." + name
        if name in index:
            found.add(index[name])

    package = module_name(path).split(".")
    if not path.endswith("/__init__.py"):
        package.pop()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            prefix = package[:len(package) - node.level + 1] if node.level else []
            base = ".".join([*prefix, *([node.module] if node.module else [])])
            add(base)
            for alias in node.names:
                add(f"{base}.{alias.name}")
        elif isinstance(node, ast.Call) and node.args:
            function = node.func.attr if isinstance(node.func, ast.Attribute) else (
                node.func.id if isinstance(node.func, ast.Name) else ""
            )
            if function in {"import_module", "__import__", "_deferred"}:
                argument = node.args[0]
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    add(argument.value)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if not embedded:
                # Registry/deferred-hook module names are whole literals.
                # Documentation and example snippets are not import edges.
                if MODULE_REFERENCE.fullmatch(value):
                    add(value)
                continue
            for match in MODULE_REFERENCE.finditer(value):
                add(match.group())
            for match in SOURCE_REFERENCE.finditer(value.replace("\\", "/")):
                add(module_name(match.group()))
            if embedded and ("import " in value or "from " in value):
                try:
                    code = ast.parse(textwrap.dedent(value))
                except (SyntaxError, ValueError):
                    pass  # Not a complete Python snippet; literal matches still apply.
                else:
                    found.update(references(path, code, index))
    return found


def parse(root: Path, path: str) -> ast.AST:
    # Syntax/read failures must stop selection, never silently drop a test.
    return ast.parse((root / path).read_text(encoding="utf-8-sig"), filename=path)


def shipped_source(path: str) -> bool:
    if path.startswith("deploy/linux/"):
        return path.removeprefix("deploy/linux/") not in RETIRED_LINUX_PATHS
    return path.startswith("scripts/ci/") or path in BUILD_TOOLS


def required_test_paths(root: Path) -> set[str]:
    required = set(SECURITY_TESTS)
    for name in PR_TEST_MANIFESTS:
        manifest = root / "scripts/ci" / name
        if manifest.is_file():
            required.update(line.split("::", 1)[0] for line in manifest.read_text(encoding="utf-8").splitlines())
    return required


def select_tests(root: Path, *, candidates: set[str] | None = None):
    index = source_index(root)
    tests = [path.relative_to(root).as_posix() for path in python_files(root / "tests")]
    index.update({module_name(path): path for path in tests})
    required = required_test_paths(root)

    @cache
    def inspect_test(path: str) -> tuple[set[str], bool]:
        tree = parse(root, path)
        imports = {ref for ref in references(path, tree, index, embedded=True)
                   if not ref.endswith("/__init__.py") or ref.startswith("tests/")}
        assets = any(isinstance(node, ast.Constant) and isinstance(node.value, str)
                     and SHIPPED_ASSET.search(node.value.replace("\\", "/")) for node in ast.walk(tree))
        return imports, assets

    selected, excluded = [], []
    for path in tests:
        if not Path(path).name.startswith("test_"):
            continue
        if candidates is not None and path not in candidates:
            continue
        if path in RETIRED_TESTS:
            excluded.append(path)
            continue
        direct, direct_asset = inspect_test(path)
        imports = {ref for ref in direct if not ref.startswith("tests/")}
        dependencies = set(imports)
        asset = direct_asset
        pending = [ref for ref in direct if ref.startswith("tests/")]
        seen = {path}
        while pending:
            helper = pending.pop()
            if helper in seen:
                continue
            seen.add(helper)
            refs, helper_asset = inspect_test(helper)
            dependencies.update(ref for ref in refs if not ref.startswith("tests/"))
            pending.extend(ref for ref in refs if ref.startswith("tests/") and ref not in seen)
            # A general fixture can bootstrap the schema for a retired service.
            # Only the migration harness contributes inherited SQL coverage.
            if path.startswith("tests/migrations/") and helper.startswith("tests/migrations/"):
                asset |= helper_asset

        # Pure SQL migration tests can rely on conftest for the schema.
        # Mixed tests qualify through a shipped SQL asset or a native module.
        migration = path in MIGRATION_TESTS or (
            path.startswith("tests/migrations/") and not dependencies
        )
        if path in required or migration or asset or any(map(shipped_source, dependencies)):
            selected.append(path)
        else:
            excluded.append(path)
    return selected, excluded



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, help="Write pytest @argfile instead of stdout")
    parser.add_argument("--excluded", action="store_true", help="List excluded files instead")
    args = parser.parse_args()
    selected, excluded = select_tests(args.root.resolve())
    print(f"total={len(selected) + len(excluded)} selected={len(selected)} excluded={len(excluded)}", file=sys.stderr)
    paths = excluded if args.excluded else selected
    if not selected:
        parser.error("empty test selection")
    output = "".join(f"{path}\n" for path in paths)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
