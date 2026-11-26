"""The installed health, readiness and worker setup paths must stand alone."""

import ast
from collections import deque
from functools import cache
from importlib.util import resolve_name
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEPLOY = "deploy.linux."
ENTRY_POINTS = {
    "native_runtime": ("health", "ready", "configure"),
    "healthcheck": ("native_healthy",),
    "installed_state": ("native_ledger_matches", "native_pointers_match"),
    "notification_health": ("healthy",),
    # Native setup delegates notification startup to the health unit and then
    # checks API readiness. Certificate issuance and migration have separate gates.
    "native_setup": ("configure",),
}


class Scope(ast.NodeVisitor):
    def __init__(self, package, *, importing=False):
        self.package = package
        self.importing = importing
        self.imports = {}
        self.references = set()
        self.dynamic_imports = set()

    def visit_FunctionDef(self, node):
        for expression in (*node.decorator_list, *node.args.defaults, *node.args.kw_defaults):
            if expression is not None:
                self.visit(expression)
        if not self.importing:
            for statement in node.body:
                self.visit(statement)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node):
        if self.importing and ast.unparse(node.test) == "__name__ == '__main__'":
            for statement in node.orelse:
                self.visit(statement)
        else:
            self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports[alias.asname or alias.name] = (alias.name, None)

    def visit_ImportFrom(self, node):
        base = resolve_name("." * node.level + (node.module or ""), self.package) if node.level else node.module
        for alias in node.names:
            self.imports[alias.asname or alias.name] = (base, alias.name)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self.references.add((node.id, None))

    def visit_Attribute(self, node):
        if isinstance(node.ctx, ast.Load):
            path = ast.unparse(node)
            if all(part.isidentifier() for part in path.split(".")):
                head, _, tail = path.rpartition(".")
                self.references.add((head, tail))
        self.generic_visit(node)

    def visit_Call(self, node):
        name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        if name in {"import_module", "__import__"} and node.args and isinstance(node.args[0], ast.Constant):
            target = node.args[0].value
            if isinstance(target, str):
                self.dynamic_imports.add(resolve_name(target, self.package) if target.startswith(".") else target)
        if name == "spec_from_file_location" and len(node.args) > 1:
            source = node.args[1]
            if (isinstance(source, ast.Call) and isinstance(source.func, ast.Attribute)
                    and source.func.attr == "with_name" and source.args
                    and isinstance(source.args[0], ast.Constant) and isinstance(source.args[0].value, str)):
                self.dynamic_imports.add(f"{self.package}.{Path(source.args[0].value).stem}")
        self.generic_visit(node)


@cache
def local_file(root, module):
    path = root.joinpath(*module.split("."))
    return next((file for file in (path.with_suffix(".py"), path / "__init__.py") if file.is_file()), None)


def server_imports(root, entries):
    pending = deque((DEPLOY + module, name, ()) for module, names in entries.items() for name in (None, *names))
    seen = set()
    violations = []
    while pending:
        module, name, parents = pending.popleft()
        label = module if name is None else f"{module}:{name}"
        chain = (*parents, label)
        if (module, name) in seen:
            continue
        seen.add((module, name))
        if module == "server" or module.startswith("server."):
            violations.append(" -> ".join(chain))
            continue
        file = local_file(root, module)
        if file is None:
            continue
        scope, definitions = parsed_module(file, module)
        active = scope
        if name is not None:
            if name not in definitions:
                continue
            active = Scope(scope.package)
            definition = definitions[name]
            for statement in definition.body:
                active.visit(statement)

        def follow(target, symbol=None):
            # Importing a function also executes the module and its initializers.
            parts = target.split(".")
            for depth in range(len(parts), 0, -1):
                candidate = ".".join(parts[:depth])
                if depth == len(parts) or local_file(root, candidate) is not None:
                    pending.append((candidate, None, chain))
            if symbol is not None:
                submodule = f"{target}.{symbol}"
                if local_file(root, submodule) is not None:
                    pending.append((submodule, None, chain))
                else:
                    pending.append((target, symbol, chain))

        for target, symbol in set(active.imports.values()):
            follow(target, symbol if symbol and local_file(root, f"{target}.{symbol}") else None)
        for target in active.dynamic_imports:
            follow(target)
        bindings = scope.imports | active.imports
        for identifier, attribute in sorted(active.references, key=lambda ref: (ref[0], ref[1] or "")):
            if identifier in bindings:
                target, symbol = bindings[identifier]
                if symbol is not None and local_file(root, f"{target}.{symbol}") is not None:
                    follow(f"{target}.{symbol}", attribute)
                else:
                    follow(target, symbol or attribute)
            elif identifier in definitions:
                pending.append((module, identifier, chain))
    return sorted(violations)


@cache
def parsed_module(file, module):
    tree = ast.parse(file.read_bytes(), filename=str(file))
    scope = Scope(module if file.name == "__init__.py" else module.rpartition(".")[0], importing=True)
    scope.visit(tree)
    definitions = {node.name: node for node in tree.body
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    return scope, definitions


def test_native_paths_do_not_import_python_server():
    violations = server_imports(ROOT, ENTRY_POINTS)
    assert not violations, "\n".join(violations)


def test_guard_follows_deferred_imports_through_relative_helper_alias(tmp_path):
    deploy = tmp_path / "deploy/linux"
    deploy.mkdir(parents=True)
    (deploy / "first.py").write_text(
        "def check():\n    from . import second as helper\n    return helper.probe()\n", encoding="utf-8")
    (deploy / "second.py").write_text(
        "def probe():\n"
        "    def load():\n        from server.sli import obsolete\n        return obsolete\n"
        "    return load()\n", encoding="utf-8")
    violations = server_imports(tmp_path, {"first": ("check",)})
    assert any("first:check" in chain and "second:probe" in chain and chain.endswith("server.sli")
               for chain in violations)
