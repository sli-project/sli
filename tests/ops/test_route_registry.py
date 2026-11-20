"""Реестр HTTP-маршрутов (ADR 0014, план 4.3).

Таблица ``ROUTES`` каждого модуля маршрутов сверяется с условиями пути в его
``try_handle_get``/``try_handle_post``: добавленный в код маршрут без строки в
таблице (или наоборот) ломает этот тест, а не запрос в рабочем контуре.
"""

from __future__ import annotations

import ast
import importlib
import re
from pathlib import Path

import pytest

from server.api import http_server
from server.api.route_registry import RouteRegistry, match_rank

ROOT = Path(__file__).resolve().parents[2]
ROUTES_DIR = ROOT / "server" / "api" / "routes"
_FUNCTIONS = {"try_handle_get": "GET", "try_handle_post": "POST", "try_handle_put": "PUT"}
_REGEX_SPECIAL = set("([.?*+\\{|$")


def _string_constants(tree: ast.Module) -> tuple[dict[str, str], dict[str, str]]:
    strings: dict[str, str] = {}
    regexes: dict[str, str] = {}
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)):
            continue
        name, value = node.targets[0].id, node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            strings[name] = value.value
        elif (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr == "compile"
              and value.args and isinstance(value.args[0], ast.Constant)):
            regexes[name] = value.args[0].value
    return strings, regexes


def _regex_prefix(pattern: str) -> str:
    literal = []
    for char in pattern.lstrip("^"):
        if char in _REGEX_SPECIAL:
            break
        literal.append(char)
    return "".join(literal)


def extract_routes(source: str) -> set[tuple[str, str]]:
    """Пары ``(метод, шаблон)`` из условий пути в обработчиках модуля."""
    tree = ast.parse(source)
    strings, regexes = _string_constants(tree)

    def value(node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in strings:
            return strings[node.id]
        raise AssertionError(f"unresolved path literal: {ast.unparse(node)}")

    def path_call(node: ast.AST, name: str) -> bool:
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == name
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "path")

    routes: set[tuple[str, str]] = set()
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef) or function.name not in _FUNCTIONS:
            continue
        method = _FUNCTIONS[function.name]
        consumed: set[int] = set()
        for node in ast.walk(function):
            if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
                starts = [item for item in node.values if path_call(item, "startswith")]
                ends = [item for item in node.values if path_call(item, "endswith")]
                if starts and ends:
                    routes.add((method, value(starts[0].args[0]) + "{}" + value(ends[0].args[0])))
                    consumed.update(id(item) for item in starts)
        for node in ast.walk(function):
            if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == "path":
                for op, comparator in zip(node.ops, node.comparators):
                    if isinstance(op, ast.Eq):
                        routes.add((method, value(comparator)))
                    elif isinstance(op, ast.In) and isinstance(comparator, (ast.Tuple, ast.List, ast.Set)):
                        routes.update((method, value(item)) for item in comparator.elts)
            elif path_call(node, "startswith") and id(node) not in consumed:
                routes.add((method, value(node.args[0]) + "*"))
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr in {"match", "fullmatch"} and isinstance(node.func.value, ast.Name)
                  and node.func.value.id in regexes and node.args
                  and isinstance(node.args[0], ast.Name) and node.args[0].id == "path"):
                routes.add((method, _regex_prefix(regexes[node.func.value.id]) + "*"))
    return routes


def _route_modules() -> list:
    return [importlib.import_module(f"server.api.routes.{path.stem}")
            for path in sorted(ROUTES_DIR.glob("*.py")) if path.stem != "__init__"]


@pytest.mark.parametrize("module", _route_modules(), ids=lambda module: module.__name__.rsplit(".", 1)[-1])
def test_routes_table_matches_handler_conditions(module) -> None:
    source = Path(module.__file__).read_text(encoding="utf-8")
    declaration = next(node.value for node in ast.parse(source).body
                       if (isinstance(node, ast.Assign)
                           and any(isinstance(target, ast.Name) and target.id == "ROUTES" for target in node.targets))
                       or (isinstance(node, ast.AnnAssign)
                           and isinstance(node.target, ast.Name) and node.target.id == "ROUTES"))
    assert ast.literal_eval(declaration) == module.ROUTES
    assert set(module.ROUTES) == extract_routes(source)
    assert len(module.ROUTES) == len(set(module.ROUTES))


def test_server_registers_every_route_module() -> None:
    registered = {module.__name__ for module in http_server.ROUTE_MODULES}
    assert registered == {module.__name__ for module in _route_modules()}


def test_no_two_modules_claim_the_same_route() -> None:
    owners: dict[tuple[str, str], str] = {}
    for module, method, pattern in RouteRegistry(http_server.ROUTE_MODULES).entries():
        key = (method, pattern)
        assert owners.setdefault(key, module.__name__) == module.__name__, key


@pytest.mark.parametrize("path", [
    "/api/v1/reports/vpn.audit/sessions",
    "/api/v1/reports/vpn.synthetic/status",
])
def test_missing_vpn_plugin_fallback_is_reachable_through_registry(monkeypatch, path) -> None:
    from server.api.routes import reports

    monkeypatch.setattr(reports, "plugin_installed", lambda _: False)

    class Handler:
        def __init__(self):
            self.sent = None

        def _send_json(self, payload):
            self.sent = payload

    handler = Handler()
    registry = RouteRegistry(http_server.ROUTE_MODULES)
    assert registry.dispatch_get(handler, path, {})
    assert handler.sent == {
        "state": "not_installed", "reason": "plugin_not_installed",
        "plugin_id": "sli.remote-access", "items": [],
    }


def _sample(pattern: str) -> str:
    if pattern.endswith("*"):
        return pattern[:-1] + "sample-x"
    return pattern.replace("{}", "sample-x")


def test_most_specific_pattern_wins_over_registration_order() -> None:
    assert match_rank("/api/v1/events/*", "/api/v1/events/9") == (2, -len("/api/v1/events/"))
    assert match_rank("/api/v1/events/{}/relations", "/api/v1/events/9/relations") < match_rank(
        "/api/v1/events/*", "/api/v1/events/9/relations")
    assert match_rank("/reports/x.html", "/reports/x.html") < match_rank("/reports/*", "/reports/x.html")
    registry = RouteRegistry(http_server.ROUTE_MODULES)
    for module, method, pattern in registry.entries():
        path = _sample(pattern)
        candidates = registry.candidates(method, path)
        assert module in candidates, (method, pattern)
        if "*" not in pattern and "{}" not in pattern:
            assert candidates[0] is module, (method, pattern, [item.__name__ for item in candidates])


def test_legacy_reports_fallback_never_shadows_specific_report_pages() -> None:
    registry = RouteRegistry(http_server.ROUTE_MODULES)
    for module, method, pattern in registry.entries():
        if method == "GET" and pattern.startswith("/reports/") and pattern.endswith(".html"):
            assert registry.candidates("GET", pattern)[0] is module, pattern
    assert re.fullmatch(r"server\.api\.routes\.legacy_reports",
                        registry.candidates("GET", "/reports/unknown-page.html")[-1].__name__)
