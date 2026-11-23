"""Select beta Python tests without importing application code or dependencies.

Reproduce inventory A: imports (including deferred/conditional imports), literal
module/source references and embedded Python. Exclude tests referring exclusively
to server modules outside the installer's conservative closure. Pull requests
also omit reviewed legacy report tests with equivalent .NET coverage.
Unknown tests run by default. Package initializers alone do not identify the
code under test. Output is a pytest @argfile (pytest >= 8.2), one path per line.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
import re
import sys
import textwrap
from functools import cache


# Release-tree entry points used by the Debian package and its build, install,
# upgrade and recovery wrappers. The host package contributes its own HELPERS.
INSTALLER_ROOTS = (
    "backup", "backup_restore_check", "build_apt_repo", "build_beta_kit",
    "entrypoint", "healthcheck", "installed_state", "migrate", "native_backup",
    "native_dotnet_generator", "native_install", "native_package",
    "native_pg_inventory", "native_pg_migrate", "native_plugin_runtime",
    "native_plugins", "native_restore", "native_setup", "notification_delivery",
    "plugin_update", "restore_existing", "sli_secrets", "sli_update",
)
HOST_PACKAGE = "deploy/linux/native_package.py"
PR_TEST_MANIFESTS = ("pr_source_tests.txt", "pr_checkpoint_tests.txt", "pr_posix_tests.txt")
# Keep explicit trust boundaries while the old Python implementation is
# present, including installed-agent lifecycle, native fencing and manifests.
SECURITY_SOURCES = (
    "server/api/http_server.py", "server/api/proxy.py", "server/api/routes/auth.py",
    "server/sli/access/", "server/sli/agents/", "server/sli/ops/tls_client.py",
    "server/sli/sources/plugin_package_manifest.py", "server/sli/sources/plugin_worker_",
)
SECURITY_TESTS = {"tests/tooling/test_sli_agent_local_install.py"}
# Include path components used in Path(...)/"postgres_migrations" as well as
# joined strings. Tests can exercise the shipped ledger and SQL via a legacy adapter.
SHIPPED_ASSET = re.compile(
    r"\b(?:postgres_migrations|postgres_baseline|postgres_schema(?:_v8)?\.sql|native_pg_ledger\.json"
    r"|(?:server-dotnet|agent-dotnet|config/clickhouse)/[\w./-]+)\b"
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
# These exercise the retired Python reporting entry points. The installer
# closure also reaches them through shared reporting imports and registries.
PR_LEGACY_REPORT_TESTS = {
    # ComputersV6MetricsPartitionTests and AdComputerComparisonBatchTests.
    "tests/reporting/test_computers_v6_metrics_partition.py",
    "tests/reports/test_computers_v6_comparison_batch.py",
    # AdV2Tests.NewLogonPairs, NewLogonPairsContextFailuresTests,
    # and the .NET volume test runs nightly.
    "tests/reporting/test_new_logon_pairs_context_failures.py",
    # UiLabelsTests and UsersActivityV2Tests.
    "tests/reporting/test_ui_labels.py",
    "tests/reporting/test_users_activity_v2.py",
}
# The legacy dispatch paths still have distinct access, export and history guards.
REPORT_ACCESS_TESTS = {
    "tests/reporting/test_gpo_effective_access_v2.py",
    "tests/reporting/test_new_logon_pairs_report_path.py",
    "tests/reporting/test_new_logon_pairs_v2.py",
}
SOURCE_ROOTS = ("server", "deploy", "scripts", "sli_agent", "sli_collect", "tools")
SKIP_DIRS = {"__pycache__", ".venv", "node_modules", ".git"}
MODULE_REFERENCE = re.compile(
    r"\b(?:server|deploy|scripts|sli_agent|sli_collect|tools|tests)(?:\.[A-Za-z_]\w*)+"
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


def dynamic_references(root: Path, path: str, index: dict[str, str]) -> set[str]:
    """Static equivalents of the scanners/aliases described in inventory A."""
    found = set()
    if path == "server/sli/reporting/v2/registry.py":
        registry = parse(root, "server/sli/plugins/registry.py")
        excluded = set()
        for node in ast.walk(registry):
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "PLUGIN_REPORT_MODULES"
                for target in node.targets
            ):
                excluded = set(ast.literal_eval(node.value.args[0]))
        found.update(p for p in index.values()
                     if p.startswith("server/sli/reporting/v2/reports/")
                     and Path(p).stem not in excluded)
    if path == "server/sli/plugins/ad/registration.py":
        found.update(p for p in index.values()
                     if p.startswith("server/sli/plugins/ad/reports/definitions/"))
    if path == "server/source_packs/windows_ad_dc/__init__.py":
        found.update(p for p in index.values()
                     if p.startswith("server/sli/plugins/ad/windows_ad_dc/"))
    if path == "server/source_packs/registry.py":
        for config in sorted((root / "config/source_packs").rglob("*.json")):
            document = json.loads(config.read_text(encoding="utf-8-sig"))
            # Only resolve module literals; do not load executable plugin code.
            for match in MODULE_REFERENCE.finditer(json.dumps(document)):
                name = match.group()
                if name in index:
                    found.add(index[name])
    return found


def installer_roots(root: Path) -> set[str]:
    roots = {f"deploy/linux/{name}.py" for name in INSTALLER_ROOTS}
    if (root / HOST_PACKAGE).is_file():
        for statement in parse(root, HOST_PACKAGE).body:
            if isinstance(statement, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "HELPERS" for target in statement.targets
            ):
                roots.update(f"deploy/linux/{name}" for name in ast.literal_eval(statement.value) if name.endswith(".py"))
                break
        else:
            raise ValueError("Native package HELPERS inventory is missing")
    return roots


def installer_closure(root: Path, index: dict[str, str]) -> set[str]:
    pending = list(installer_roots(root))
    visited = set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        dependencies = references(path, parse(root, path), index)
        dependencies.update(dynamic_references(root, path, index))
        # Importing a module also executes its package initializers.
        for parent in Path(path).parents:
            initializer = (parent / "__init__.py").as_posix()
            if index.get(module_name(initializer)) == initializer:
                dependencies.add(initializer)
        pending.extend(dependencies - visited)
    return visited


def required_test_paths(root: Path) -> set[str]:
    required = REPORT_ACCESS_TESTS | SECURITY_TESTS
    for name in PR_TEST_MANIFESTS:
        manifest = root / "scripts/ci" / name
        if manifest.is_file():
            required.update(line.split("::", 1)[0] for line in manifest.read_text(encoding="utf-8").splitlines())
    return required


def select_tests(root: Path, *, include_legacy_reports: bool = False):
    index = source_index(root)
    closure = installer_closure(root, index)
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
    groups = {name: 0 for name in ("installer", "migrations", "closure", "protected",
                                   "transitive", "shipped", "mixed", "other", "retired", "legacy_reports")}
    for path in tests:
        if not Path(path).name.startswith("test_"):
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
            asset |= helper_asset

        installer = any(ref.startswith("deploy/linux/") for ref in dependencies)
        migrations = path.startswith("tests/migrations/") or path in MIGRATION_TESTS
        shipped = any(ref.startswith("server/") for ref in dependencies & closure)
        protected = (path in required or path.startswith("tests/access/")
                     or any(ref.startswith(SECURITY_SOURCES) for ref in dependencies))
        server_only = bool(imports) and all(ref.startswith("server/") for ref in dependencies)
        groups["installer"] += installer
        groups["migrations"] += migrations
        groups["closure"] += shipped
        groups["protected"] += protected
        groups["transitive"] += bool((dependencies - imports) & closure) or asset and not direct_asset
        if protected or migrations or asset:
            groups["shipped"] += 1
            selected.append(path)
        elif not include_legacy_reports and path in PR_LEGACY_REPORT_TESTS and server_only:
            groups["legacy_reports"] += 1
            excluded.append(path)
        elif installer or shipped:
            groups["shipped"] += 1
            selected.append(path)
        elif server_only:
            groups["retired"] += 1
            excluded.append(path)
        else:
            groups["mixed" if any(ref.startswith("server/") for ref in dependencies) else "other"] += 1
            selected.append(path)
    return selected, excluded, closure, groups


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, help="Write pytest @argfile instead of stdout")
    parser.add_argument("--excluded", action="store_true", help="List excluded files instead")
    args = parser.parse_args()
    selected, excluded, closure, groups = select_tests(
        args.root.resolve(), include_legacy_reports=os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
    )
    print(f"total={len(selected) + len(excluded)} selected={len(selected)} excluded={len(excluded)} "
          f"server_closure={sum(p.startswith('server/') for p in closure)} "
          + " ".join(f"{name}={count}" for name, count in groups.items()), file=sys.stderr)
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
