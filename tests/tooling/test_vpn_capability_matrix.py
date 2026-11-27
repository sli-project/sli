"""Keep the pre-extraction VPN inventory complete without importing runtime code."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "config/plugin_packages/capability_matrix_vpn.json"
VPN_MARKER = re.compile(r"(?:^|[./_-])(?:vpn|radius|nps)(?:[./_-]|$)|remote[-_]access")


def _vpn(value: str) -> bool:
    return bool(VPN_MARKER.search(value.lower()))


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))


def _assignments(tree: ast.Module) -> dict[str, ast.expr]:
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            values[node.target.id] = node.value
    return values


def _string(node: ast.expr | None, values: dict[str, ast.expr]) -> str:
    if isinstance(node, ast.Name):
        node = values.get(node.id)
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _python_report_keys(paths: list[Path]) -> set[str]:
    keys = set()
    for path in paths:
        tree = _tree(path)
        values = _assignments(tree)
        for name in ("REPORT_KEY", "ACCESS_KEY"):
            value = _string(values.get(name), values)
            if _vpn(value):
                keys.add(value)
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if _string(key, values) == "report_key" and _vpn(_string(value, values)):
                        keys.add(_string(value, values))
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id != "ReportDefinition":
                continue
            kwargs = {item.arg: item.value for item in node.keywords}
            key = _string(kwargs.get("key"), values)
            section = _string(kwargs.get("section"), values)
            if _vpn(key) or _vpn(section):
                assert key, f"Unresolved remote-access report key in {path}"
                keys.add(key)
                access = kwargs.get("access")
                if isinstance(access, ast.Call) and access.args:
                    access_key = _string(access.args[0], values)
                    assert access_key, f"Unresolved remote-access access key in {path}"
                    keys.add(access_key)
    return keys


def _manifest_report_keys(value: object, *, remote: bool = False) -> set[str]:
    keys = set()
    if isinstance(value, dict):
        remote = remote or value.get("plugin_id") == "sli.remote-access" or value.get("id") == "remote-access"
        for name, child in value.items():
            if name in {"report_key", "access_key", "definition_id"} and isinstance(child, str) and (remote or _vpn(child)):
                keys.add(child)
            if name == "reports" and isinstance(child, list):
                for report in child:
                    if isinstance(report, str) and (remote or _vpn(report)):
                        keys.add(report)
                    elif isinstance(report, dict):
                        component = report.get("component_id")
                        if isinstance(component, str) and (remote or _vpn(component)):
                            keys.add(component)
            keys.update(_manifest_report_keys(child, remote=remote))
    elif isinstance(value, list):
        for child in value:
            keys.update(_manifest_report_keys(child, remote=remote))
    return keys


def _registered_routes(paths: list[Path]) -> set[str]:
    routes = set()
    for path in paths:
        tree = _tree(path)
        declaration = _assignments(tree).get("ROUTES")
        assert declaration is not None, f"Missing route declaration in {path}"
        for method, route in ast.literal_eval(declaration):
            if _vpn(route):
                routes.add(f"{method} {route}")
    return routes


def _registered_ui_routes(navigation: dict) -> set[str]:
    return {
        f"UI {entry['path']}"
        for section in navigation["sections"]
        for group in section["groups"]
        for entry in group["entries"]
        if entry.get("plugin_id") == "sli.remote-access" or _vpn(entry["path"])
    }


def _legacy_ui_routes(product_source: str, static_path: Path) -> set[str]:
    routes = set()
    for old, target in re.findall(r'retiredRedirect\("([^"]+)",\s*"([^"]+)"\)', product_source):
        if _vpn(old) or _vpn(target):
            routes.update({f"UI {old}", f"UI /app{old}", f"UI {target}"})
    declaration = _assignments(_tree(static_path))["SPA_TOP_LEVEL_ROUTES"]
    assert isinstance(declaration, ast.Call) and declaration.args
    for route in ast.literal_eval(declaration.args[0]):
        if _vpn(route):
            routes.update({f"UI /{route}", f"UI /app/{route}"})
    return routes


def _sql_report_keys(source: str) -> set[str]:
    # Legacy reports are registered by immutable migrations, not a Python
    # registry import. Read SQL declarations without executing any migration.
    return {
        key
        for statement in source.split(";")
        if re.search(r"\b(?:insert\s+into|update)\s+(?:public\.)?report_registry_v4\b", statement, re.I)
        for key in re.findall(r"'((?:vpn|radius|nps)\.[a-z0-9_.-]+)'", statement)
    }


def _covered(matrix: dict, field: str) -> set[str]:
    return {value for row in matrix["capabilities"] for value in row[field]}


def _require_coverage(discovered: set[str], documented: set[str]) -> None:
    assert not discovered - documented, f"VPN capabilities missing from matrix: {sorted(discovered - documented)}"




def test_every_vpn_table_view_and_schema_is_documented():
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    objects = set()
    for path in (ROOT / "config/postgres_migrations").glob("*.sql"):
        if "rollback" in path.name:
            continue
        source = path.read_text(encoding="utf-8-sig")
        for kind, name in re.findall(
            r"\bcreate\s+(?:or\s+replace\s+)?(table|view|schema)\s+(?:if\s+not\s+exists\s+)?([a-z0-9_.]+)",
            source, re.I,
        ):
            if _vpn(name):
                objects.add(name if kind.lower() == "schema" or "." in name else f"public.{name}")
    assert "public.radius_vpn_session_projection" in objects
    declared = _covered(matrix, "data")
    declared.update(obj for migration in matrix["migration_inventory"] for obj in migration["objects"])
    _require_coverage(objects, declared)






def test_matrix_migrations_are_available():
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    for migration in matrix["migration_inventory"]:
        assert (ROOT / migration["file"]).is_file(), migration["file"]


@pytest.mark.parametrize("declaration", [
    'REPORT_KEY = "vpn.future"',
    'REPORT = ReportDefinition(key="access.future", section="reports/remote-access", access=AccessRule("access.future"))',
    'ITEM = {"report_key": "nps.future"}',
])
def test_new_report_declarations_cannot_pass_with_an_old_matrix(tmp_path, declaration):
    path = tmp_path / "report.py"
    path.write_text(declaration, encoding="utf-8")
    discovered = _python_report_keys([path])
    assert discovered
    with pytest.raises(AssertionError, match="missing from matrix"):
        _require_coverage(discovered, {"vpn.audit"})


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_new_route_methods_cannot_pass_with_an_old_matrix(tmp_path, method):
    path = tmp_path / "routes.py"
    path.write_text(f'ROUTES = (("{method}", "/api/v1/reports/vpn.future/data"),)', encoding="utf-8")
    discovered = _registered_routes([path])
    assert discovered == {f"{method} /api/v1/reports/vpn.future/data"}
    with pytest.raises(AssertionError, match="missing from matrix"):
        _require_coverage(discovered, {"GET /api/v1/reports/vpn.audit/sessions"})


def test_new_plugin_report_without_a_vpn_prefix_is_still_discovered():
    manifest = {"plugin_id": "sli.remote-access", "reports": [{"report_key": "access.future", "access_key": "access.read"}]}
    discovered = _manifest_report_keys(manifest)
    assert discovered == {"access.future", "access.read"}
    with pytest.raises(AssertionError, match="missing from matrix"):
        _require_coverage(discovered, {"vpn.audit"})




def test_new_legacy_sql_report_cannot_pass_with_an_old_matrix():
    keys = _sql_report_keys("insert into public.report_registry_v4(report_key) values ('vpn.future');")
    assert keys == {"vpn.future"}
    with pytest.raises(AssertionError, match="missing from matrix"):
        _require_coverage(keys, {"vpn.audit"})


def test_hidden_legacy_ui_route_is_covered_even_without_navigation(tmp_path):
    path = tmp_path / "static.py"
    path.write_text('SPA_TOP_LEVEL_ROUTES = frozenset({"vpn-future"})', encoding="utf-8")
    routes = _legacy_ui_routes('const old = retiredRedirect("/vpn-future", "/report/vpn.future");', path)
    assert routes == {"UI /vpn-future", "UI /app/vpn-future", "UI /report/vpn.future"}
    with pytest.raises(AssertionError, match="missing from matrix"):
        _require_coverage(routes, {"UI /report/vpn.accounts"})
