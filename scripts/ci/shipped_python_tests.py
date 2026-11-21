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


# The 15 beta helpers identified in 80-py-inventory (14 November 2026).
INSTALLER_ROOTS = (
    "backup", "backup_restore_check", "entrypoint", "healthcheck",
    "installed_state", "migrate", "native_backup", "native_install",
    "native_plugins", "native_setup", "notification_delivery", "plugin_update",
    "restore_existing", "sli_secrets", "sli_update",
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
    r"\b(?:server|deploy|scripts|sli_agent|sli_collect|tools)(?:\.[A-Za-z_]\w*)+"
)
SOURCE_REFERENCE = re.compile(
    r"\b(?:server|deploy|scripts|sli_agent|sli_collect|tools)(?:/[\w.-]+)+\.py\b"
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
                if value.startswith("server."):
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


def installer_closure(root: Path, index: dict[str, str]) -> set[str]:
    pending = [f"deploy/linux/{name}.py" for name in INSTALLER_ROOTS]
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
            if initializer in index.values():
                dependencies.add(initializer)
        pending.extend(dependencies - visited)
    return visited


def select_tests(root: Path, *, include_legacy_reports: bool = False):
    index = source_index(root)
    closure = installer_closure(root, index)
    selected, excluded = [], []
    groups = {"installer": 0, "migrations": 0, "closure": 0,
              "shipped": 0, "mixed": 0, "other": 0, "legacy_reports": 0}
    for file in python_files(root / "tests"):
        if not file.name.startswith("test_"):
            continue
        path = file.relative_to(root).as_posix()
        direct = {ref for ref in references(path, parse(root, path), index, embedded=True)
                  if not ref.endswith("/__init__.py")}
        installer = any(ref.startswith("deploy/linux/") for ref in direct)
        migrations = path.startswith("tests/migrations/") or path in MIGRATION_TESTS
        shipped = any(ref.startswith("server/") for ref in direct & closure)
        server_only = bool(direct) and all(ref.startswith("server/") for ref in direct)
        groups["installer"] += installer
        groups["migrations"] += migrations
        groups["closure"] += shipped
        if path in REPORT_ACCESS_TESTS:
            selected.append(path)
        elif not include_legacy_reports and path in PR_LEGACY_REPORT_TESTS and server_only and not migrations:
            groups["legacy_reports"] += 1
            excluded.append(path)
        elif installer or migrations or shipped:
            groups["shipped"] += 1
            selected.append(path)
        elif any(ref.startswith("server/") for ref in direct):
            if server_only:
                excluded.append(path)
            else:
                groups["mixed"] += 1
                selected.append(path)
        else:
            groups["other"] += 1
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
