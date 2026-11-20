"""Core import closure must stop at explicit, reviewed plugin loaders."""
from __future__ import annotations

import ast
from collections import deque
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CORE_PREFIXES = (
    "server.api", "server.sli.core", "server.sli.reporting", "server.sli.access",
    "server.sli.ops", "server.jobs",
)
# Only this loader imports reviewed registration entry points dynamically. Its
# declarations are code-reviewed, never executable strings from user manifests.
LOADERS = {"server.sli.plugins.registry": "reviewed bundled registration entry points"}


def vpn_module(name: str) -> bool:
    """Include legacy VPN implementations pending their physical VP07 move."""
    return name.startswith("server.sli.entities.entity_vpn_reporting") or any(
        part == "vpn" or part.startswith(("remote_access", "vpn_", "radius", "nps_", "windows_nps"))
        for part in name.split(".")
    )


def imported_modules(source: str, module: str, *, package: bool = False) -> set[str]:
    imports = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parent = module.split(".") if package else module.split(".")[:-1]
                base = ".".join(parent[:len(parent) - node.level + 1] + ([base] if base else []))
            imports.add(base)
            imports.update(f"{base}.{alias.name}" for alias in node.names if alias.name != "*")
        elif isinstance(node, ast.Call) and node.args:
            function = node.func
            dynamic = (
                isinstance(function, ast.Name) and function.id == "__import__"
                or isinstance(function, ast.Attribute) and function.attr == "import_module"
            )
            if dynamic and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                imports.add(node.args[0].value)
    return imports


def graph_violations(graph: dict[str, set[str]], roots: set[str]) -> list[str]:
    pending = deque((root, (root,)) for root in sorted(roots))
    visited = set()
    failures = []
    while pending:
        module, chain = pending.popleft()
        if module in visited:
            continue
        visited.add(module)
        for imported in sorted(graph.get(module, ())):
            if vpn_module(imported):
                if module not in LOADERS:
                    failures.append(" -> ".join((*chain, imported)))
                continue
            # An imported attribute has the same dependencies as its module.
            target = imported
            while target and target not in graph:
                target = target.rpartition(".")[0]
            if target:
                pending.append((target, (*chain, target)))
                # Python executes package initializers before a submodule too.
                parts = target.split(".")
                for length in range(1, len(parts)):
                    parent = ".".join(parts[:length])
                    if parent in graph:
                        pending.append((parent, (*chain, parent)))
    return failures


def test_core_does_not_import_vpn():
    graph = {}
    paths = [*(ROOT / "server").rglob("*.py"), *(ROOT / "scripts").rglob("*.py")]
    for path in sorted(paths):
        module = ".".join(path.relative_to(ROOT).with_suffix("").parts)
        package = path.name == "__init__.py"
        if package:
            module = module.removesuffix(".__init__")
        graph[module] = imported_modules(path.read_text(encoding="utf-8-sig"), module, package=package)
    roots = {module for module in graph if not vpn_module(module) and any(
        module == prefix or module.startswith(prefix + ".") for prefix in (*CORE_PREFIXES, "scripts.runtime")
    )}
    assert roots
    assert not graph_violations(graph, roots), "\n".join(graph_violations(graph, roots))


@pytest.mark.parametrize("source", [
    "import server.sli.plugins.remote_access.jobs",
    "from server.sli.plugins import remote_access",
    "from server.source_packs.radius import session_consumer",
    "from server.sli.reports.vpn_session_reporting import get_vpn_session_evidence",
    "from server.source_packs import windows_nps_radius",
    "from server.sli.entities.entity_vpn_reporting import get_entity_vpn_sessions",
    "from . import vpn_audit",
    "importlib.import_module('server.sli.plugins.remote_access.jobs')",
    "__import__('server.source_packs.radius.session_consumer')",
])
def test_guard_rejects_private_imports_including_lazy_and_relative(source):
    module = "server.sli.reporting.v2.reports.core_fixture"
    assert graph_violations({module: imported_modules(source, module)}, {module})


def test_guard_rejects_transitive_dependency():
    graph = {"server.api.fixture": {"server.shared.fixture"},
             "server.shared.fixture": {"server.source_packs.radius.session_consumer"}}
    failures = graph_violations(graph, {"server.api.fixture"})
    assert failures == ["server.api.fixture -> server.shared.fixture -> server.source_packs.radius.session_consumer"]


def test_only_explicit_loader_is_exempt():
    edge = {"server.sli.plugins.remote_access.registration"}
    assert not graph_violations({"server.sli.plugins.registry": edge}, {"server.sli.plugins.registry"})
    assert graph_violations({"server.sli.plugins.new_loader": edge}, {"server.sli.plugins.new_loader"})


def test_report_scanner_excludes_every_legacy_vpn_module():
    declaration = ast.parse((ROOT / "server/sli/plugins/registry.py").read_text(encoding="utf-8"))
    skipped = next(ast.literal_eval(node.value.args[0]) for node in declaration.body
                   if isinstance(node, ast.Assign) and any(
                       isinstance(target, ast.Name) and target.id == "PLUGIN_REPORT_MODULES"
                       for target in node.targets))
    reports = ROOT / "server/sli/reporting/v2/reports"
    private = {path.stem for path in reports.glob("*.py") if vpn_module(path.stem)}
    # The shared scanner exclusions also contain other plugins' reports.
    assert private
    assert private == {name for name in skipped if vpn_module(name)}
