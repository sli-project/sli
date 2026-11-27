"""The installed native paths must stand alone."""

import ast
import json
import os
import subprocess
import sys
import tarfile
from collections import deque
from functools import cache
from importlib.util import resolve_name
from pathlib import Path, PurePosixPath

import pytest

from deploy.linux import build_beta_kit


ROOT = Path(__file__).resolve().parents[2]
DEPLOY = "deploy.linux."
ENTRY_POINTS = {
    "native_install": ("main",),
    "native_setup": ("main", "configure"),
    "migrate": ("migrate",),
    "native_backup": ("main",),
    "native_restore": ("restore", "rollback"),
    "native_upgrade": ("main",),
    "native_plugins": ("bootstrap", "release_inventory", "verify_registry"),
    "native_pg_migrate": ("migrate",),
    "build_beta_kit": ("main",),
    "entrypoint": ("main",),
}
HEALTH_ENTRY_POINTS = {
    "native_runtime": ("health", "ready", "configure"),
    "healthcheck": ("native_healthy",),
    "installed_state": ("native_ledger_matches", "native_pointers_match"),
    "notification_health": ("healthy",),
}


def old_server_module(name):
    return name.split('.', 1)[0] in {'server', 'sli'}


def assert_native_payload(members):
    violations = []
    for path, read in members:
        if 'server' in path.parts or path.parts[:2] == ('scripts', 'runtime'):
            violations.append(str(path))
        elif path.suffix == '.py' and read is not None:
            for node in ast.walk(ast.parse(read(), filename=str(path))):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                    names = [node.module]
                elif isinstance(node, ast.Call) and node.args:
                    function = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, 'attr', '')
                    arg = node.args[0]
                    if (function in {'import_module', '__import__'} and isinstance(arg, ast.Constant)
                            and isinstance(arg.value, str)):
                        names = [arg.value]
                violations.extend(f'{path}:{node.lineno}: {name}' for name in names if old_server_module(name))
    assert not violations, '\n'.join(violations)


@pytest.fixture(scope='module')
def staged_payload(tmp_path_factory):
    release = tmp_path_factory.mktemp('beta-kit') / 'release'
    build_beta_kit.copy_release(ROOT, release)
    return release


def test_staged_kit_payload_has_no_python_server(staged_payload):
    assert (staged_payload / 'deploy/linux/native_install.py').is_file()
    assert_native_payload((path.relative_to(staged_payload), path.read_bytes if path.is_file() else None)
                          for path in sorted(staged_payload.rglob('*')))


def test_built_kit_payload_has_no_python_server():
    directory = os.environ.get('SLI_TEST_BETA_KIT')
    if not directory:
        pytest.skip('requires the built Debian beta kit')
    kit = Path(directory)
    manifest = json.loads((kit / 'manifest.json').read_bytes())
    release = manifest['release']
    prefix = PurePosixPath('opt/sli/releases', release)
    packages = {row['package']: row['filename'] for row in manifest['packages']}
    for name, root, required in (
        (f'sli-release-{release}', prefix, PurePosixPath('deploy/linux/native_install.py')),
        ('sli-host', PurePosixPath('usr/lib/sli'), PurePosixPath('native_install.py')),
    ):
        found = set()
        with subprocess.Popen(['dpkg-deb', '--fsys-tarfile', kit / packages[name]], stdout=subprocess.PIPE) as process:
            with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                for member in archive:
                    path = PurePosixPath(member.name)
                    if path.is_relative_to(root):
                        path = path.relative_to(root)
                        found.add(path)
                    read = (lambda: archive.extractfile(member).read()) if member.isfile() else None
                    assert_native_payload([(path, read)])
            # Drain any tar padding before checking the producer's exit status.
            process.stdout.read()
            assert process.wait() == 0
        assert required in found


def main_block(node):
    return isinstance(node, ast.If) and ast.unparse(node.test) == "__name__ == '__main__'"


class Scope(ast.NodeVisitor):
    def __init__(self, package, *, importing=False, migrate_cli=False):
        self.package = package
        self.importing = importing
        self.migrate_cli = migrate_cli
        self.imports = {}
        self.dependencies = set()
        self.commands = set()
        self.text_constants = {}
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
        condition = ast.unparse(node.test)
        if self.importing and main_block(node):
            reachable = node.orelse
        elif condition in {"_STANDALONE_UPDATER", "os.environ.get('SLI_DEPLOYMENT_MODE') != 'native'"}:
            reachable = node.orelse
        elif condition == "os.environ.get('SLI_DEPLOYMENT_MODE') == 'native'":
            reachable = node.body
        elif self.migrate_cli and condition == "args.service in {'migrate', 'restore'}":
            # This branch always returns before dispatching legacy workers.
            reachable = node.body
        elif self.migrate_cli and condition == "args.service == 'restore'":
            reachable = node.orelse
        else:
            self.generic_visit(node)
            return
        for statement in reachable:
            self.visit(statement)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports[alias.asname or alias.name] = (alias.name, None)
            self.dependencies.add((alias.name, None))

    def visit_ImportFrom(self, node):
        base = resolve_name("." * node.level + (node.module or ""), self.package) if node.level else node.module
        for alias in node.names:
            self.imports[alias.asname or alias.name] = (base, alias.name)
            self.dependencies.add((base, alias.name))

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

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.text_constants[target.id] = node.value.value
        self.generic_visit(node)

    def visit_Call(self, node):
        if (node.args and isinstance(node.args[0], (ast.List, ast.Tuple)) and node.args[0].elts
                and ast.unparse(node.args[0].elts[0]) in {"sys.executable", "python", "manifest['python']"}):
            argv = node.args[0].elts
            for flag, argument in zip(argv, argv[1:]):
                if not isinstance(flag, ast.Constant):
                    continue
                value = (argument.value if isinstance(argument, ast.Constant)
                         else self.text_constants.get(argument.id) if isinstance(argument, ast.Name) else None)
                if isinstance(value, str) and flag.value == "-m":
                    self.commands.add((value, "__main__"))
                if isinstance(value, str) and flag.value == "-c":
                    self.visit(ast.parse(value))
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
    pending = deque((DEPLOY + module, name, ()) for module, names in entries.items()
                    for name in (None, *names, *(("__main__",) if "main" in names else ())))
    seen = set()
    violations = []
    while pending:
        module, name, parents = pending.popleft()
        label = module if name is None else f"{module}:{name}"
        chain = (*parents, label)
        if (module, name) in seen:
            continue
        seen.add((module, name))
        if old_server_module(module):
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
            migrate_cli = module == DEPLOY + "entrypoint" and name == "main"
            active = Scope(scope.package, migrate_cli=migrate_cli)
            for statement in definitions[name].body:
                active.visit(statement)
                if (migrate_cli and isinstance(statement, ast.If)
                        and ast.unparse(statement.test) == "args.service in {'migrate', 'restore'}"):
                    break

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

        for target, symbol in sorted(active.dependencies, key=lambda item: (item[0], item[1] or "")):
            follow(target, symbol if symbol and local_file(root, f"{target}.{symbol}") else None)
        for target, symbol in sorted(active.commands):
            follow(target, symbol)
        for target in sorted(active.dynamic_imports):
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
    if entry := next((node for node in tree.body if main_block(node)), None):
        definitions["__main__"] = entry
    return scope, definitions


def test_native_paths_do_not_import_python_server():
    violations = server_imports(ROOT, {**HEALTH_ENTRY_POINTS, **ENTRY_POINTS})
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


def test_guard_follows_child_module_and_inline_python(tmp_path):
    deploy = tmp_path / "deploy/linux"
    deploy.mkdir(parents=True)
    (deploy / "parent.py").write_text(
        "import subprocess, sys\n"
        "def run():\n"
        "    subprocess.run([sys.executable, '-m', 'deploy.linux.child'])\n"
        "    code = 'import server.sli.inline'\n"
        "    subprocess.run([sys.executable, '-c', code])\n",
        encoding="utf-8",
    )
    (deploy / "child.py").write_text(
        "def main():\n    import server.sli.child\n"
        "if __name__ == '__main__':\n    import server.sli.bootstrap\n    main()\n",
        encoding="utf-8",
    )
    violations = server_imports(tmp_path, {"parent": ("run",)})
    assert any("child:main" in chain and chain.endswith("server.sli.child") for chain in violations)
    assert any("child:__main__" in chain and chain.endswith("server.sli.bootstrap") for chain in violations)
    assert any(chain.endswith("server.sli.inline") for chain in violations)


def test_native_entry_point_imports(staged_payload):
    subprocess.run(
        [sys.executable, "-I", "-B", "-c", """
import importlib
import os
import sys

class RejectServer:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.', 1)[0] in {'server', 'sli'}:
            raise AssertionError(f'native path tried importing {fullname}')

sys.path.insert(0, os.getcwd())
sys.meta_path.insert(0, RejectServer())
from deploy.linux import entrypoint, migrate

for name in sys.argv[1:]:
    importlib.import_module(f'deploy.linux.{name}')

os.environ['SLI_DEPLOYMENT_MODE'] = 'native'
os.environ['ADLOG_HISTORY_READ_MODE'] = ' Disabled '

def check_history():
    migrate.configure_permanent_history()

migrate.migrate = check_history
sys.argv = ['entrypoint', 'migrate']
assert entrypoint.main() == 0
""", *ENTRY_POINTS],
        cwd=staged_payload,
        check=True,
    )
