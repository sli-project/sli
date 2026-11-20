from __future__ import annotations

import gzip
import hashlib
import io
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import verify_offline_kit as verifier
from tools import release_artifacts as release

SHA = "a" * 40
ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_SQL = b"SELECT 1;\nINSERT INTO schema_migrations(version,name) VALUES (1, 'example');\n"


def workstation_payload():
    sql = "SELECT 1;\nINSERT INTO schema_migrations(version,name) VALUES (159, 'workstation_security');\n"
    migration = "config/postgres_migrations/159_workstation_security.sql"
    return {
        verifier.WORKSTATION_MANIFEST: json.dumps({"plugin_id": "sli.workstations", "data": {"migrations": [
            {"version": 159, "path": migration, "sha256": hashlib.sha256(sql.encode()).hexdigest()}]}}).encode(),
        migration: sql.encode(),
        "config/postgres_migrations/160_agent_workstation_dispatch.sql":
            b"SELECT 1;\nINSERT INTO schema_migrations(version,name) VALUES (160, 'agent_workstation_dispatch');\n",
        "sli_agent/workstations.py": b'class WorkstationsModule: module_id = "sli.workstations"\n',
        "sli_agent/modules.py": b"from sli_agent.workstations import WorkstationsModule\n",
    }


def write_workstations(root):
    for name, body in workstation_payload().items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)

class Metadata(dict):
    def get_all(self, name, default):
        return ["License :: OSI Approved :: MIT License"] if name == "Classifier" else default


def test_python_licenses_match_lock_and_keep_inactive_platform(monkeypatch):
    monkeypatch.setattr(release.sys, "platform", "linux")
    result = release.python_inventory('example==1.0\npywin32==312; sys_platform == "win32"',
        lambda name: SimpleNamespace(version="1.0", metadata=Metadata({"License-Expression": "MIT"})))
    assert result[0]["license"] == "MIT"
    assert result[0]["license_classifiers"]
    assert result[1] == {"ecosystem": "pypi", "name": "pywin32", "version": "312",
                         "active": False, "license": "NOASSERTION"}


@pytest.mark.parametrize("lock", ["example>=1", "example==1; python_version > '3'", "example==1\nExample==1",
                                  "example_pkg==1\nexample.pkg==1"])
def test_python_inventory_rejects_unlocked_or_ambiguous_input(lock):
    with pytest.raises(verifier.KitError):
        release.locked_python(lock)


def test_python_inventory_rejects_installed_version_drift():
    with pytest.raises(verifier.KitError, match="release_python_version_mismatch"):
        release.python_inventory("example==1", lambda name: SimpleNamespace(version="2"))


def test_python_legacy_license_text_is_not_dumped():
    result = release.python_inventory("example==1", lambda name: SimpleNamespace(
        version="1", metadata=Metadata({"License": "long\nlicense text"})))
    assert result[0]["license"] == "NOASSERTION"


def test_npm_inventory_includes_nested_dev_optional_and_unknown_license():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"version": "1"},
        "node_modules/@scope/example": {"version": "2", "integrity": "sha512-test", "license": "MIT", "dev": True},
        "node_modules/a/node_modules/example": {"version": "1", "integrity": "sha512-test", "optional": True},
    }}
    result = release.npm_inventory(lock, "frontend")
    assert result[0]["name"] == "@scope/example" and result[0]["development"]
    assert result[1]["name"] == "example" and result[1]["optional"]
    assert result[1]["license"] == "NOASSERTION"


def test_npm_inventory_rejects_missing_integrity():
    with pytest.raises(verifier.KitError, match="release_npm_dependency_unlocked"):
        release.npm_inventory({"lockfileVersion": 3, "packages": {"node_modules/example": {"version": "1"}}}, "root")


def test_release_notes_use_only_merged_pr_titles_inside_commit_range():
    pulls = [{"number": 4, "title": "Example\n fix", "merged_at": "date", "merge_commit_sha": SHA},
             {"number": 5, "title": "Unmerged", "merged_at": None, "merge_commit_sha": SHA},
             {"number": 6, "title": "Old", "merged_at": "date", "merge_commit_sha": "b" * 40}]
    assert release.merged_titles([SHA, "c" * 40], lambda commit: pulls) == ["- #4: Example fix"]


def test_previous_tag_excludes_current_commit_and_handles_first_release(monkeypatch):
    calls = []
    def git(root, *args):
        calls.append(args)
        return "b" * 40 if args[0] == "rev-parse" else "sli-1.0.0"
    monkeypatch.setattr(release, "git", git)
    assert release.previous_tag(Path("."), SHA) == "sli-1.0.0"
    assert calls[0] == ("rev-parse", SHA + "^")
    monkeypatch.setattr(release, "git", lambda *args: (_ for _ in ()).throw(subprocess.CalledProcessError(1, "git")))
    assert release.previous_tag(Path("."), SHA) is None


@pytest.mark.parametrize("path", ["config/secrets/password", "frontend/node_modules/example/index.js",
                                  "config/.env.local", "config/release.key", "server/__pycache__/cache.pyc"])
def test_source_export_excludes_local_and_secret_files(path):
    assert not release.allowed_source(path)


def test_source_export_reads_git_object_not_worktree(monkeypatch, tmp_path):
    def run(args, **kwargs):
        assert args[-1] == SHA
        with tarfile.open(args[args.index("--output") + 1], "w") as archive:
            add_tar(archive, "server/example.py", b"from_commit = True\n")
            add_tar(archive, "config/.env.local", b"excluded")
    monkeypatch.setattr(release.subprocess, "run", run)
    destination = tmp_path / "source"
    release.export_source(tmp_path, SHA, destination)
    assert (destination / "server/example.py").read_bytes() == b"from_commit = True\n"
    assert not (destination / "config/.env.local").exists()


def test_source_export_keeps_code_readable_and_scripts_executable_under_private_umask(monkeypatch, tmp_path):
    files = {"server/example.py": (b"from_commit = True\n", 0o644),
             "deploy/linux/sli-secrets": (b"#!/bin/sh\nexit 0\n", 0o755),
             "config/postgres_migrations/001_example.sql": (EXAMPLE_SQL, 0o644)}

    def run(args, **kwargs):
        with tarfile.open(args[args.index("--output") + 1], "w") as archive:
            for name, (body, mode) in files.items():
                item = tarfile.TarInfo(name)
                item.size, item.mode = len(body), mode
                archive.addfile(item, io.BytesIO(body))

    monkeypatch.setattr(release.subprocess, "run", run)
    destination = tmp_path / "source"
    previous = os.umask(0o077)
    try:
        release.export_source(tmp_path, SHA, destination)
    finally:
        os.umask(previous)
    for name, (body, mode) in files.items():
        path = destination / name
        assert path.read_bytes() == body
        assert path.stat().st_mode & 0o777 == mode
    assert all(path.stat().st_mode & 0o777 == 0o755
               for path in [destination, *destination.rglob("*")] if path.is_dir())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX source export permissions")
@pytest.mark.parametrize("mask", [0o022, 0o077])
def test_source_export_normalizes_modes_and_retains_executability(monkeypatch, tmp_path, mask):
    def run(args, **kwargs):
        with tarfile.open(args[args.index("--output") + 1], "w") as archive:
            for name, mode in [("server/nested/example.py", 0o600),
                               ("deploy/linux/example.sh", 0o7755)]:
                item = tarfile.TarInfo(name)
                item.mode, item.size = mode, 4
                archive.addfile(item, io.BytesIO(b"test"))
    monkeypatch.setattr(release.subprocess, "run", run)
    destination = tmp_path / "source"
    previous = os.umask(mask)
    try:
        release.export_source(tmp_path, SHA, destination)
    finally:
        os.umask(previous)
    assert (destination / "server/nested/example.py").stat().st_mode & 0o7777 == 0o644
    assert (destination / "deploy/linux/example.sh").stat().st_mode & 0o7777 == 0o755
    for directory in [destination, *(path for path in destination.rglob("*") if path.is_dir())]:
        assert directory.stat().st_mode & 0o7777 == 0o755


def mock_prepare(monkeypatch):
    def git(root, *args):
        return "100" if args[0] == "show" else SHA
    def export(root, sha, destination):
        destination.mkdir()
        for name, body in {
            "requirements.lock.txt": "cryptography==1\ncffi==1\npycparser==1\n",
            "package-lock.json": '{"lockfileVersion":3,"packages":{}}',
            "frontend/package-lock.json": '{"lockfileVersion":3,"packages":{}}',
            "config/postgres_migrations/001_example.sql": EXAMPLE_SQL.decode(),
            "deploy/linux/verify_offline_kit.py": "# example", "deploy/linux/build_offline_kit.sh": "# example",
            **{name: "# Installation guide\n" for name in (
                "docs/install/SERVER_INSTALL.ru.md", "docs/install/SERVER_INSTALL.en.md",
                "docs/install/AGENT_INSTALL.ru.md", "docs/install/AGENT_INSTALL.en.md",
                "docs/agent-enrollment.md")},
        }.items():
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8", newline="\n")
        write_workstations(destination)
    monkeypatch.setattr(release, "git", git)
    monkeypatch.setattr(release, "previous_tag", lambda *args: "sli-1.0.0")
    monkeypatch.setattr(release, "export_source", export)
    monkeypatch.setattr(release, "python_inventory", lambda lock: [])


def test_prepare_exact_sha_unsigned_outputs_with_fakes(monkeypatch, tmp_path):
    mock_prepare(monkeypatch)
    kit = tmp_path / "kit"
    release.prepare(tmp_path, kit, SHA, "1.1.0", None, "example/project", lambda commit: [])
    install = json.loads((kit / "manifests/install.unsigned.json").read_text())
    update = json.loads((kit / "manifests/update.unsigned.json").read_text())
    assert install["package_type"] == "core-install" and install["from_version"] is None
    assert update["from_version"] == "1.0.0" and update["source_commit"] == SHA
    assert update["image"]["digest"] is None
    assert update["migrations"]["config/postgres_migrations/001_example.sql"] == hashlib.sha256(EXAMPLE_SQL).hexdigest()
    assert update["migrations"] == {path.relative_to(kit / "source").as_posix(): verifier.digest(path)
                                    for path in (kit / "source/config/postgres_migrations").glob("*.sql")}
    assert json.loads((kit / "release-inputs.json").read_text())["release_eligible"] is True
    assert not (kit / "KIT_INVENTORY.json").exists()
    assert not list(kit.rglob("SLI_SIGNATURE.json"))
    assert not list(kit.rglob("*.zip"))
    assert not (kit / "images").exists()
    assert (kit / "START_HERE.md").is_file()
    for name in ("docs/install/SERVER_INSTALL.ru.md", "docs/install/SERVER_INSTALL.en.md", "docs/agent-enrollment.md"):
        assert (kit / name).read_bytes() == (kit / "source" / name).read_bytes()


@pytest.mark.parametrize("name", ["docs/install/SERVER_INSTALL.ru.md", "docs/install/SERVER_INSTALL.en.md", "docs/agent-enrollment.md"])
def test_source_export_includes_buyer_instructions(name):
    assert release.allowed_source(name)


def test_prepare_buyer_guide_links_resolve_to_exported_assets(monkeypatch, tmp_path):
    mock_prepare(monkeypatch)
    export = release.export_source
    def with_link(root, sha, destination):
        export(root, sha, destination)
        (destination / "docs/install/SERVER_INSTALL.ru.md").write_text(
            "[schema](../../config/postgres_migrations/001_example.sql)\n", encoding="utf-8")
    monkeypatch.setattr(release, "export_source", with_link)
    kit = tmp_path / "kit"
    release.prepare(tmp_path, kit, SHA, "1.1.0", None, None)
    assert "../../source/config/postgres_migrations/001_example.sql" in (
        kit / "docs/install/SERVER_INSTALL.ru.md").read_text()
    assert json.loads((kit / "inventories/source.json").read_text()) == verifier.file_inventory(kit / "source")


def test_prepare_local_checkout_needs_no_github_credentials(monkeypatch, tmp_path):
    mock_prepare(monkeypatch)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr(release, "github_pulls", lambda *args: pytest.fail("local build contacted GitHub"))
    kit = tmp_path / "kit"
    assert release.main(["prepare", "--root", str(tmp_path), "--output", str(kit),
                         "--sha", SHA, "--version", "1.1.0"]) == 0
    assert json.loads((kit / "release-inputs.json").read_text())["source_commit"] == SHA
    assert "not queried" in (kit / "RELEASE_NOTES.md").read_text()


@pytest.mark.parametrize("internal", [False, True])
@pytest.mark.parametrize("explicit_output", [False, True])
def test_offline_builder_prepares_checkout_before_docker(kit, tmp_path, monkeypatch, internal, explicit_output):
    monkeypatch.delenv("SLI_TEST_PYTHON", raising=False)
    root, _ = kit
    checkout = tmp_path / "checkout"
    shutil.copytree(root / "source", checkout)
    for name in ("deploy/linux/build_offline_kit.sh", "deploy/linux/verify_offline_kit.py",
                 "tools/release_artifacts.py"):
        target = checkout / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
    lock = "".join(f"{name}=={importlib.metadata.version(name)}\n"
                   for name in ("cryptography", "cffi", "pycparser"))
    (checkout / "requirements.lock.txt").write_text(lock)
    (checkout / "VERSION").write_text("1.1.0\n")
    for name in ("package-lock.json", "frontend/package-lock.json"):
        (checkout / name).write_text('{"lockfileVersion":3,"packages":{}}')
    archive = tmp_path / "checkout.tar"
    with tarfile.open(archive, "w") as output:
        for path in checkout.rglob("*"):
            if path.is_file():
                output.add(path, arcname=path.relative_to(checkout).as_posix())
    binaries = tmp_path / "bin"
    binaries.mkdir()
    scripts = {
        "git": '''#!/bin/bash
shift 2
case "$1" in
  rev-parse|rev-list) printf '%s\\n' "$TEST_SHA" ;;
  describe) exit 1 ;;
  show)
    case "$*" in
      *:VERSION) cat "$TEST_CHECKOUT/VERSION" ;;
      *:requirements.lock.txt) cat "$TEST_CHECKOUT/requirements.lock.txt" ;;
      *) echo 100 ;;
    esac ;;
  archive) cp "$TEST_ARCHIVE" "$4" ;;
  *) exit 99 ;;
esac
''',
        "python": '''#!/bin/bash
if [ "${1:-}" = -m ]; then
  case "$2" in
    venv) mkdir -p "$3/bin"; cp "$0" "$3/bin/python"; exit 0 ;;
    pip)
      while [ "$#" -gt 0 ]; do
        if [ "$1" = --target ]; then mkdir -p "$2"; echo bundled > "$2/test-library"; fi
        shift
      done
      exit 0 ;;
  esac
fi
if [[ "$1" = *.py ]]; then
  exec "$SLI_TEST_PYTHON" -c 'import runpy, sys; sys.executable=sys.argv.pop(1); sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0], run_name="__main__")' "$0" "$@"
fi
exec "$SLI_TEST_PYTHON" "$@"
''',
        # Stop at the external image boundary: no real Docker or network in unit tests.
        "docker": '#!/bin/bash\necho image-boundary-reached >&2\nexit 23\n',
    }
    for name, body in scripts.items():
        path = binaries / name
        path.write_text(body)
        path.chmod(0o755)
    output = tmp_path / ("output kit" if explicit_output else "sli-kit-1.1.0-aaaaaaaaaaaa")
    env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"],
               SLI_TEST_PYTHON=sys.executable,
               SLI_RELEASE_PYTHON=str(binaries / "python"), TEST_CHECKOUT=str(checkout),
               TEST_ARCHIVE=str(archive), TEST_SHA=SHA)
    env.pop("GH_TOKEN", None)
    args = ["bash", str(checkout / "deploy/linux/build_offline_kit.sh")]
    if explicit_output:
        args.extend(["--output", str(output)])
    if internal:
        args.append("--internal-test-build")
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 23, result.stdout + result.stderr
    assert "image-boundary-reached" in result.stderr
    inputs = json.loads((output / "release-inputs.json").read_text())
    assert inputs["source_commit"] == SHA and inputs["version"] == "1.1.0"
    assert inputs["release_eligible"] is not internal
    assert (output / "source/tools/release_artifacts.py").is_file()
    for minor in (11, 12, 13, 14):
        assert (output / f"host-libs/python3.{minor}/test-library").is_file()
    assert not (checkout / "deploy/linux/source").exists()


def test_offline_builder_still_builds_prepared_kit_in_place(kit, tmp_path, monkeypatch):
    monkeypatch.delenv("SLI_TEST_PYTHON", raising=False)
    root, _ = kit
    inputs = json.loads((root / "release-inputs.json").read_text())
    release.write_json(root / "release-inputs.json", {**inputs, "source_date_epoch": 100})
    for name in ("build_offline_kit.sh", "verify_offline_kit.py"):
        (root / name).write_bytes((ROOT / "deploy/linux" / name).read_bytes().replace(b"\r\n", b"\n"))
    for name in ("tools/release_artifacts.py", "deploy/linux/verify_offline_kit.py"):
        target = root / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
    binaries = tmp_path / "bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text('#!/bin/bash\necho image-boundary-reached >&2\nexit 23\n')
    docker.chmod(0o755)
    # Force the first image pull rather than reuse the fixture's placeholder lock.
    (root / "inventories/base-images.lock").unlink()
    env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"],
               SLI_RELEASE_PYTHON=sys.executable)
    result = subprocess.run(["bash", str(root / "build_offline_kit.sh")], env=env,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 23, result.stdout + result.stderr
    assert "image-boundary-reached" in result.stderr
    assert not (root / "host-libs/test-library").exists()


def test_prepare_rejects_other_commit_before_creating_output(monkeypatch, tmp_path):
    monkeypatch.setattr(release, "git", lambda *args: "b" * 40)
    with pytest.raises(verifier.KitError, match="release_exact_sha_required"):
        release.prepare(tmp_path, tmp_path / "kit", SHA, "1.0.0", None, "example/project")
    assert not (tmp_path / "kit").exists()


def add_tar(archive, name, body):
    item = tarfile.TarInfo(name)
    item.size = len(body)
    archive.addfile(item, io.BytesIO(body))


def image(path, tag, *, version=None, architecture="amd64", compressed=False, workstations=False, omit=None, whiteout=None,
          migration=EXAMPLE_SQL):
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as archive:
        add_tar(archive, "opt/sli/config/postgres_migrations/001_example.sql", migration)
        if workstations:
            for name, body in workstation_payload().items():
                if name != omit:
                    add_tar(archive, "opt/sli/" + name, body)
        if whiteout:
            add_tar(archive, whiteout, b"")
    body = layer.getvalue()
    config = {"os": "linux", "architecture": architecture, "config": {"Labels": {
        "org.opencontainers.image.version": version, "org.opencontainers.image.revision": SHA}},
        "rootfs": {"diff_ids": ["sha256:" + hashlib.sha256(body).hexdigest()]}}
    with tarfile.open(path, "w") as archive:
        add_tar(archive, "config.json", json.dumps(config).encode())
        add_tar(archive, "layer.tar", gzip.compress(body) if compressed else body)
        add_tar(archive, "manifest.json", json.dumps([{"Config": "config.json", "RepoTags": [tag], "Layers": ["layer.tar"]}]).encode())


@pytest.mark.parametrize("compressed", [False, True])
def test_compact_image_is_deterministic_and_matches_canonical_verifier(tmp_path, compressed):
    from deploy.linux.sli_update import image_inventory

    raw = tmp_path / "raw.tar"
    image(raw, "sli-release:1.1.0", version="1.1.0", compressed=compressed)
    compact = tmp_path / "compact.tar"
    again = tmp_path / "again.tar"
    release.compact_image(raw, compact)
    release.compact_image(raw, again)
    assert compact.read_bytes() == again.read_bytes()
    info = verifier.docker_archive(compact, "sli-release:1.1.0")
    metadata = release.manifest({"version": "1.1.0", "from_version": "1.0.0", "source_commit": SHA},
                                {"config/postgres_migrations/001_example.sql": hashlib.sha256(EXAMPLE_SQL).hexdigest()})
    metadata["image"]["digest"] = info["digest"]
    assert image_inventory(compact, metadata, tmp_path / "checked.tar") == [
        {"version": 1, "name": "example", "sha256": hashlib.sha256(EXAMPLE_SQL).hexdigest()},
    ]


@pytest.mark.parametrize("sql", [b"SELECT 1;", b"INSERT INTO schema_migrations(version,name) VALUES (2, 'example');"])
def test_compact_image_rejects_missing_or_wrong_migration_marker(tmp_path, sql):
    from deploy.linux.sli_update import image_inventory
    from server.sli.release_package import PackageError

    raw, compact = tmp_path / "raw.tar", tmp_path / "compact.tar"
    image(raw, "sli-release:1.1.0", version="1.1.0", migration=sql)
    release.compact_image(raw, compact)
    info = verifier.docker_archive(compact, "sli-release:1.1.0")
    metadata = release.manifest({"version": "1.1.0", "from_version": "1.0.0", "source_commit": SHA},
                                {"config/postgres_migrations/001_example.sql": hashlib.sha256(sql).hexdigest()})
    metadata["image"]["digest"] = info["digest"]
    with pytest.raises(PackageError, match="update_image_migration_invalid"):
        image_inventory(compact, metadata, tmp_path / "checked.tar")


@pytest.fixture
def kit(tmp_path):
    root = tmp_path / "kit"
    root.mkdir()
    files = ["verify_offline_kit.py", "build_offline_kit.sh", "RELEASE_NOTES.md", "inventories/licenses.json",
             "START_HERE.md", "docs/install/SERVER_INSTALL.ru.md", "docs/install/SERVER_INSTALL.en.md",
             "docs/agent-enrollment.md",
             "inventories/sbom.json", "inventories/base-images.lock", "inventories/os-packages.tsv",
             "packages/install.zip", "packages/update.zip", "host-requirements.lock.txt",
             "source/deploy/linux/docker-compose.yml", "source/deploy/linux/init.sql",
             "source/deploy/linux/sli_update.py", "source/deploy/linux/update_checkpoint.py",
             "source/deploy/linux/sli_install.py", "source/deploy/linux/installation.py",
             "source/deploy/linux/evaluation_package.py", "source/server/sli/release_package.py",
             "source/tools/build_update_package.py", "source/scripts/maintenance/release_package.py",
             "source/config/postgres_baseline/manifest.json", "source/config/postgres_baseline/baseline.sql",
             "source/config/postgres_baseline/roles.sql", "source/requirements.lock.txt",
             "source/package-lock.json", "source/frontend/package-lock.json",
             "source/config/postgres_migrations/001_example.sql"]
    for minor in (11, 12, 13, 14):
        prefix = f"host-libs/python3.{minor}/"
        files.extend(prefix + name for name in ("cryptography/__init__.py", "cffi/__init__.py",
                     "pycparser/__init__.py", "cryptography/hazmat/bindings/_rust.abi3.so",
                     f"_cffi_backend.cpython-3{minor}-x86_64-linux-gnu.so"))
    for name in files:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(EXAMPLE_SQL if name.endswith("001_example.sql") else b"example")
    for name in release.BUYER_DOCS:
        for prefix in ("", "source/"):
            path = root / (prefix + name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# Example installation guide\n", encoding="utf-8")
    write_workstations(root / "source")
    inputs = {"version": "1.1.0", "from_version": "1.0.0", "source_commit": SHA}
    release.write_json(root / "release-inputs.json", inputs)
    release.write_json(root / "inventories/sbom.json", {"components": []})
    (root / "inventories/os-packages.tsv").write_text("example\t1\n", encoding="utf-8")
    release.write_json(root / "inventories/source.json", verifier.file_inventory(root / "source"))
    images = root / "images"
    images.mkdir()
    metadata = {}
    for name, tag in (("server", "sli-release:1.1.0"), ("postgres", "postgres:18.6-bookworm"),
                      ("clickhouse", "clickhouse/clickhouse-server:25.8")):
        image(images / (name + ".tar"), tag, version="1.1.0", workstations=name == "server")
        metadata[name] = verifier.docker_archive(images / (name + ".tar"), tag)
    release.write_json(images / "metadata.json", metadata)
    migrations = {path.relative_to(root / "source").as_posix(): verifier.digest(path)
                  for path in (root / "source/config/postgres_migrations").glob("*.sql")}
    manifest = release.manifest(inputs, migrations, installing=True)
    manifest["image"]["digest"] = metadata["server"]["digest"]
    manifest["files"] = [{"path": "images/server.tar", "size": (images / "server.tar").stat().st_size,
                          "sha256": verifier.digest(images / "server.tar")}]
    release.write_json(root / "manifests/install.unsigned.json", manifest)
    update = release.manifest(inputs, manifest["migrations"])
    update.update(image=manifest["image"], files=manifest["files"])
    release.write_json(root / "manifests/update.unsigned.json", update)
    trust = tmp_path / "trust.json"
    release.write_json(trust, {"schema_version": 1, "keys": [{"revoked": False, "package_ids": ["sli.core"]}]})
    release.seal(root)
    return root, trust


def test_complete_kit_checks_hashes_and_does_not_claim_authentication(kit):
    root, trust = kit
    assert verifier.verify(root, trust) == {"status": "complete", "source_commit": SHA,
                                           "authenticated": False, "installed": False,
                                           "workstation_gate": {"status": "passed", "release_eligible": True,
                                                                "artifact_label": "release", "failures": []}}


@pytest.mark.parametrize("reference", ["config/plugin_packages/v3", "config/postgres_migrations/001_example.sql"])
def test_kit_verifies_compose_file_and_directory_mounts(kit, reference):
    root, trust = kit
    (root / "source/deploy/linux/docker-compose.yml").write_text(f"- ../../{reference}:/config:ro\n")
    release.write_json(root / "inventories/source.json", verifier.file_inventory(root / "source"))
    release.seal(root)
    assert verifier.verify(root, trust)["status"] == "complete"
    payload = root / "source" / reference
    if payload.is_dir():
        payload = root / "source" / verifier.WORKSTATION_MANIFEST
    payload.write_bytes(b"modified")
    with pytest.raises(verifier.KitError, match="kit_inventory_mismatch"):
        verifier.verify(root, trust)


@pytest.mark.parametrize("empty_directory", [False, True])
def test_kit_rejects_missing_or_empty_compose_mount_after_reseal(kit, empty_directory):
    root, trust = kit
    if empty_directory:
        (root / "source/config/empty").mkdir()
    (root / "source/deploy/linux/docker-compose.yml").write_text("- ../../config/empty:/config:ro\n")
    release.write_json(root / "inventories/source.json", verifier.file_inventory(root / "source"))
    release.seal(root)
    with pytest.raises(verifier.KitError, match="kit_file_missing"):
        verifier.verify(root, trust)


def test_finalize_images_fills_canonical_drafts_and_sbom(kit):
    root, trust = kit
    release.finalize_images(root)
    sbom = json.loads((root / "inventories/sbom.json").read_text())
    assert sbom["os_packages"] == [{"name": "example", "version": "1"}]
    assert set(sbom["images"]) == {"server", "postgres", "clickhouse"}
    release.seal(root)
    assert verifier.verify(root, trust)["status"] == "complete"


def test_kit_checks_update_base_version_after_reseal(kit):
    root, trust = kit
    path = root / "manifests/update.unsigned.json"
    manifest = json.loads(path.read_text())
    manifest["from_version"] = "0.0.0"
    release.write_json(path, manifest)
    release.seal(root)
    with pytest.raises(verifier.KitError, match="kit_source_mismatch"):
        verifier.verify(root, trust)


@pytest.mark.parametrize("name", ["images/postgres.tar", "images/clickhouse.tar", "packages/install.zip",
                                  "source/deploy/linux/sli_install.py",
                                  "host-libs/python3.13/_cffi_backend.cpython-313-x86_64-linux-gnu.so"])
def test_kit_rejects_missing_required_file_even_with_resealed_inventory(kit, name):
    root, trust = kit
    (root / name).unlink()
    # A fresh inventory must not hide a missing mandatory artifact.
    release.write_json(root / "inventories/source.json", verifier.file_inventory(root / "source"))
    release.seal(root)
    with pytest.raises(verifier.KitError):
        verifier.verify(root, trust)


def test_kit_rejects_modified_file(kit):
    root, trust = kit
    (root / "RELEASE_NOTES.md").write_text("modified")
    with pytest.raises(verifier.KitError, match="kit_inventory_mismatch"):
        verifier.verify(root, trust)


def test_evaluation_kit_is_complete_but_requires_explicit_opt_in(kit):
    from deploy.linux import evaluation_package
    root, trust = kit
    release.finalize_evaluation(root)
    inventory = json.loads((root / "KIT_INVENTORY.json").read_text())
    assert inventory["signing"] == "evaluation-unsigned"
    assert "для оценки, без подписи" in (root / "START_HERE.md").read_text()
    assert inventory["files"] == verifier.file_inventory(root)
    with pytest.raises(verifier.KitError, match="kit_evaluation_flag_required"):
        verifier.verify(root, trust)
    result = verifier.verify(root, evaluation=True, inventory_sha256=verifier.digest(root / "KIT_INVENTORY.json"))
    assert result["status"] == "complete" and result["authenticated"] is False
    assert result["signing"] == "evaluation-unsigned"
    package = evaluation_package.verify(root / "packages/install.zip", root, verifier.digest(root / "KIT_INVENTORY.json"))
    assert package.key_id == "evaluation-unsigned"
    assert package.manifest["package_type"] == "core-install"


@pytest.mark.parametrize("rollback", ["102_example_rollback.sql", "102_example.rollback.sql"])
def test_finalize_evaluation_preserves_legacy_rollback_and_roles_inventory(kit, rollback):
    from deploy.linux import evaluation_package

    root, _ = kit
    sql_files = {
        "102_example.sql": b"SELECT 1;\n",
        rollback: b"SELECT 2;\n",
        "storage_v2_roles.sql": b"SELECT 4;\n",
    }
    for name, body in sql_files.items():
        (root / "source/config/postgres_migrations" / name).write_bytes(body)
    for path in (root / "manifests").glob("*.unsigned.json"):
        manifest = json.loads(path.read_text())
        manifest["migrations"].update({"config/postgres_migrations/" + name: hashlib.sha256(body).hexdigest()
                                      for name, body in sql_files.items()})
        release.write_json(path, manifest)
    release.write_json(root / "inventories/source.json", verifier.file_inventory(root / "source"))

    release.finalize_evaluation(root)

    checksum = verifier.digest(root / "KIT_INVENTORY.json")
    package = evaluation_package.verify(root / "packages/install.zip", root, checksum)
    assert package.manifest["migrations"] == manifest["migrations"]
    assert package.key_id == "evaluation-unsigned"


@pytest.mark.parametrize("edits, reason", [
    ({"config/postgres_migrations/001_other.sql": "a" * 64}, "update_duplicate_migration_id"),
    ({"config/postgres_migrations/001_example.rollback.sql": "a" * 64,
      "config/postgres_migrations/001_example_rollback.sql": "b" * 64}, "update_duplicate_migration_id"),
    ({"config/postgres_migrations/002_example_rollback.sql": "a" * 64}, "update_invalid_migration_id"),
    ({"config/postgres_migrations/001_other_rollback.sql": "a" * 64}, "update_invalid_migration_id"),
    ({"config/postgres_migrations/other_roles.sql": "a" * 64}, "update_invalid_migration_id"),
    ({"config/postgres_migrations/storage_v2_roles.sql": "invalid"}, "update_invalid_migration_id"),
])
def test_evaluation_migration_inventory_still_fails_closed(kit, edits, reason):
    from deploy.linux import evaluation_package
    from server.sli.release_package import PackageError

    root, _ = kit
    path = root / "manifests/install.unsigned.json"
    manifest = json.loads(path.read_text())
    manifest["migrations"].update(edits)
    release.write_json(path, manifest)
    with pytest.raises(PackageError, match=reason):
        evaluation_package.build(root)


@pytest.mark.parametrize("error, reason, message", [
    (verifier.KitError("kit_file_missing"), "kit_file_missing", "kit_file_missing"),
    (OSError(28, "synthetic sensitive detail", "/private/example"), "OSError", "No space left on device"),
    (RuntimeError("synthetic sensitive detail"), "RuntimeError", "finalize-evaluation"),
])
def test_release_cli_reports_safe_failure_and_traceback(monkeypatch, tmp_path, capsys, error, reason, message):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(release, "finalize_evaluation", fail)
    assert release.main(["finalize-evaluation", "--kit", str(tmp_path)]) == 1
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["status"] == "failed"
    assert result["reason_code"] == reason
    assert message in result["message"]
    assert "Traceback (most recent call last):" in output.err
    assert type(error).__name__ in output.err
    assert "synthetic sensitive detail" not in output.out + output.err
    assert "/private/example" not in output.out + output.err


def test_release_cli_reports_manifest_validation_reason(monkeypatch, tmp_path, capsys):
    from server.sli.release_package import PackageError

    def fail(*args, **kwargs):
        raise PackageError("update_duplicate_migration_id")

    monkeypatch.setattr(release, "finalize_evaluation", fail)
    assert release.main(["finalize-evaluation", "--kit", str(tmp_path)]) == 1
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["reason_code"] == "PackageError"
    assert result["message"] == "update_duplicate_migration_id"
    assert "PackageError: update_duplicate_migration_id" in output.err


def test_current_source_sql_inventory_is_accepted_by_evaluation_manifest():
    from server.sli.release_package import PackageLimits, validate_manifest

    migrations = {path.relative_to(ROOT).as_posix(): verifier.digest(path)
                  for path in (ROOT / "config/postgres_migrations").glob("*.sql")}
    manifest = release.manifest({"version": "1.1.0", "source_commit": SHA}, migrations, installing=True)
    manifest["image"]["digest"] = "sha256:" + "b" * 64
    manifest["files"] = [{"path": "images/server.tar", "size": 87 * 1024 * 1024, "sha256": "c" * 64}]
    validate_manifest(manifest, PackageLimits())


def test_offline_builder_finishes_self_contained_evaluation_kit_with_fake_docker(kit, tmp_path):
    root, _ = kit
    inputs = json.loads((root / "release-inputs.json").read_text())
    release.write_json(root / "release-inputs.json", {**inputs, "source_date_epoch": 100})
    (root / "build_offline_kit.sh").write_bytes((ROOT / "deploy/linux/build_offline_kit.sh").read_bytes().replace(b"\r\n", b"\n"))
    for name in ("tools/release_artifacts.py", "deploy/linux/verify_offline_kit.py", "deploy/linux/evaluation_package.py",
                 "deploy/linux/sli_update.py", "deploy/linux/installed_state.py",
                 "scripts/maintenance/release_package.py", "server/sli/release_package.py",
                 "scripts/maintenance/existing_postgres_bootstrap.py",
                 "deploy/linux/Dockerfile", "deploy/linux/Dockerfile.dockerignore"):
        target = root / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
    release.write_json(root / "inventories/source.json", verifier.file_inventory(root / "source"))
    (root / "inventories/base-images.lock").write_text("node@sha256:" + "a" * 64 + "\npython@sha256:" + "b" * 64 + "\n")
    saved = tmp_path / "saved-images"
    saved.mkdir()
    for path in (root / "images").glob("*.tar"):
        shutil.copyfile(path, saved / path.name)
        path.unlink()
    binaries = tmp_path / "fake-bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text('''#!/bin/bash
case "$1" in
  pull|build) exit 0 ;;
  image)
    test "$2" = save || exit 99
    case "$5" in
      sli-release:*) name=server ;;
      postgres:*) name=postgres ;;
      clickhouse/*) name=clickhouse ;;
      *) exit 99 ;;
    esac
    cp "$TEST_IMAGES/$name.tar" "$4" ;;
  run) printf 'example\\t1\\n' ;;
  *) exit 99 ;;
esac
''')
    docker.chmod(0o755)
    env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"],
               SLI_RELEASE_PYTHON=sys.executable, TEST_IMAGES=str(saved))
    result = subprocess.run(["bash", str(root / "build_offline_kit.sh")], env=env, capture_output=True,
                            text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "для оценки, без подписи" in result.stdout
    checksum = verifier.digest(root / "KIT_INVENTORY.json")
    assert checksum in result.stdout
    assert verifier.verify(root, evaluation=True, inventory_sha256=checksum)["status"] == "complete"
    assert not list((root / "source").rglob("__pycache__"))


@pytest.mark.parametrize("checksum", [None, "0" * 64])
def test_evaluation_kit_requires_matching_external_inventory_checksum(kit, checksum):
    root, _ = kit
    release.finalize_evaluation(root)
    with pytest.raises(verifier.KitError, match="kit_inventory_sha256"):
        verifier.verify(root, evaluation=True, inventory_sha256=checksum)


@pytest.mark.parametrize("name", ["START_HERE.md", "docs/install/SERVER_INSTALL.ru.md",
                                  "docs/install/SERVER_INSTALL.en.md", "docs/agent-enrollment.md"])
def test_buyer_instructions_are_mandatory_even_after_resealing(kit, name):
    root, trust = kit
    (root / name).unlink()
    release.seal(root)
    with pytest.raises(verifier.KitError, match="kit_incomplete"):
        verifier.verify(root, trust)


def test_seal_rejects_modified_exact_sha_source(kit):
    root, trust = kit
    (root / "source/requirements.lock.txt").write_text("modified")
    with pytest.raises(verifier.KitError, match="release_source_modified"):
        release.seal(root)


def test_kit_rejects_trust_root_inside_payload(kit):
    root, trust = kit
    copied = root / "trust.json"
    shutil.copyfile(trust, copied)
    with pytest.raises(verifier.KitError, match="kit_trust_must_be_external"):
        verifier.verify(root, copied)


def test_kit_rejects_wrong_image_platform_after_reseal(kit):
    root, trust = kit
    image(root / "images/postgres.tar", "postgres:18.6-bookworm", architecture="arm64")
    release.seal(root)
    with pytest.raises(verifier.KitError, match="kit_image_platform_mismatch"):
        verifier.verify(root, trust)


def test_kit_rejects_symlink(tmp_path):
    root = tmp_path / "kit"
    root.mkdir()
    (root / "link").symlink_to(tmp_path / "outside")
    with pytest.raises(verifier.KitError, match="kit_link_forbidden"):
        verifier.file_inventory(root)


@pytest.mark.parametrize("name", ["../outside", "/outside", "a//b", "a/./b", "a\\b", "C:/outside"])
def test_plain_file_rejects_ambiguous_paths(tmp_path, name):
    with pytest.raises(verifier.KitError, match="kit_invalid_path"):
        verifier.plain_file(tmp_path, name)


def test_offline_signing_uses_existing_builder(monkeypatch, tmp_path):
    from tools import build_update_package as builder

    calls = []
    monkeypatch.setattr(builder, "build", lambda *args, **kwargs: calls.append((args, kwargs)))
    args = ["--manifest", str(tmp_path / "manifest.json"), "--payload-root", str(tmp_path),
            "--signing-key", str(tmp_path / "external.key"), "--key-id", "test-only", "--output", str(tmp_path / "package.zip")]
    assert builder.main(args) == 0
    assert len(calls) == 1


def test_sign_flag_uses_existing_builder_without_changing_default(monkeypatch, tmp_path):
    from tools import build_update_package as builder

    calls = []
    monkeypatch.setattr(builder, "build", lambda *args, **kwargs: calls.append((args, kwargs)))
    args = ["--manifest", str(tmp_path / "manifest.json"), "--payload-root", str(tmp_path),
            "--signing-key", str(tmp_path / "external.key"), "--key-id", "test-only", "--output", str(tmp_path / "package.zip")]
    assert builder.main(["--sign", *args]) == 0
    assert builder.main(args) == 0
    assert calls[0] == calls[1]


def test_workflow_is_unsigned_exact_sha_and_has_no_docker_step():
    import yaml

    workflow = yaml.safe_load((ROOT / ".github/workflows/release-artifacts.yml").read_text())
    trigger = workflow.get("on", workflow.get(True))
    assert trigger["push"]["tags"] == ["sli-*"] and "workflow_dispatch" in trigger
    job = workflow["jobs"]["prepare"]
    checkout = job["steps"][0]
    assert checkout["with"]["ref"] == "${{ github.sha }}" and checkout["with"]["fetch-depth"] == 0
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "requirements.lock.txt" in commands
    assert "docker " not in commands and "--signing-key" not in commands
    assert "bundle-host-libs" in commands

@pytest.mark.parametrize("name", verifier.WORKSTATION_FILES)
@pytest.mark.parametrize("empty", [False, True])
def test_source_gate_rejects_missing_or_empty_workstation_files(tmp_path, name, empty):
    write_workstations(tmp_path)
    if empty:
        (tmp_path / name).write_bytes(b"")
    else:
        (tmp_path / name).unlink()
    with pytest.raises(verifier.KitError, match="release_workstations_incomplete"):
        verifier.workstation_release_gate(tmp_path)


@pytest.mark.parametrize("change", ["plugin_id", "checksum", "json"])
def test_source_gate_rejects_invalid_workstation_manifest(tmp_path, change):
    write_workstations(tmp_path)
    path = tmp_path / verifier.WORKSTATION_MANIFEST
    data = json.loads(path.read_text())
    if change == "plugin_id":
        data["plugin_id"] = "sli.example"
    elif change == "checksum":
        data["data"]["migrations"][0]["sha256"] = "0" * 64
    path.write_text("invalid" if change == "json" else json.dumps(data))
    with pytest.raises(verifier.KitError, match="release_workstations_incomplete"):
        verifier.workstation_release_gate(tmp_path)


def test_source_gate_requires_declared_successor_migration(tmp_path):
    write_workstations(tmp_path)
    path = tmp_path / verifier.WORKSTATION_MANIFEST
    data = json.loads(path.read_text())
    name = "config/postgres_migrations/999_example.sql"
    data["data"]["migrations"].append({"version": 999, "path": name, "sha256": hashlib.sha256(b"SELECT 2;").hexdigest()})
    path.write_text(json.dumps(data))
    with pytest.raises(verifier.KitError, match="release_workstations_incomplete"):
        verifier.workstation_release_gate(tmp_path)
    (tmp_path / name).write_bytes(b"SELECT 2;")
    assert verifier.workstation_release_gate(tmp_path)["release_eligible"] is True


@pytest.mark.parametrize("missing", [False, True])
def test_source_gate_override_always_marks_internal_build(tmp_path, missing):
    if not missing:
        write_workstations(tmp_path)
    gate = verifier.workstation_release_gate(tmp_path, internal_test_build=True)
    assert gate["release_eligible"] is False
    assert gate["artifact_label"] == verifier.INTERNAL_LABEL
    assert bool(gate["failures"]) is missing


@pytest.mark.parametrize("name", verifier.WORKSTATION_FILES)
def test_prepare_blocks_incomplete_plugin_before_writing_release_manifests(monkeypatch, tmp_path, name):
    mock_prepare(monkeypatch)
    export = release.export_source
    def incomplete(root, sha, destination):
        export(root, sha, destination)
        (destination / name).unlink()
    monkeypatch.setattr(release, "export_source", incomplete)
    with pytest.raises(verifier.KitError, match="release_workstations_incomplete"):
        release.prepare(tmp_path, tmp_path / "kit", SHA, "1.1.0", None, "example/project", lambda commit: [])
    assert not (tmp_path / "kit/manifests").exists()
    assert not (tmp_path / "kit/release-inputs.json").exists()


@pytest.mark.parametrize("missing", [False, True])
def test_prepare_override_marks_metadata_manifests_and_notes(monkeypatch, tmp_path, missing):
    mock_prepare(monkeypatch)
    export = release.export_source
    def incomplete(root, sha, destination):
        export(root, sha, destination)
        if missing:
            (destination / "sli_agent/workstations.py").unlink()
    monkeypatch.setattr(release, "export_source", incomplete)
    root = tmp_path / "kit"
    release.prepare(tmp_path, root, SHA, "1.1.0", None, "example/project", lambda commit: [], internal_test_build=True)
    inputs = json.loads((root / "release-inputs.json").read_text())
    assert inputs["release_eligible"] is False
    assert inputs["artifact_label"] == verifier.INTERNAL_LABEL
    assert verifier.INTERNAL_LABEL in (root / "RELEASE_NOTES.md").read_text()
    for kind in ("install", "update"):
        draft = json.loads((root / "manifests" / (kind + ".unsigned.json")).read_text())
        assert draft["build_id"] == "internal-test-not-for-release-1.1.0"
    with pytest.raises(verifier.KitError, match="release_internal_test_not_for_release"):
        verifier.kit_release_gate(root)
    assert verifier.kit_release_gate(root, internal_test_build=True)["release_eligible"] is False


def reseal_inventory(root):
    # Simulate an incomplete kit from another producer; do not use the gated sealer.
    release.write_json(root / "inventories/source.json", verifier.file_inventory(root / "source"))
    release.write_json(root / "KIT_INVENTORY.json", {"schema_version": 1, "stage": "offline", "source_commit": SHA,
                                                   "files": verifier.file_inventory(root)})


@pytest.mark.parametrize("name", verifier.WORKSTATION_FILES)
def test_kit_verifier_rejects_incomplete_source_even_with_fresh_inventory(kit, name):
    root, trust = kit
    (root / "source" / name).unlink()
    reseal_inventory(root)
    with pytest.raises(verifier.KitError, match="release_workstations_incomplete"):
        verifier.verify(root, trust)
    with pytest.raises(verifier.KitError, match="release_workstations_incomplete"):
        verifier.verify(root, trust, internal_test_build=True)


@pytest.mark.parametrize("name", verifier.WORKSTATION_FILES)
def test_finalize_seal_and_verify_reject_incomplete_server_image(kit, name):
    root, trust = kit
    image(root / "images/server.tar", "sli-release:1.1.0", version="1.1.0", workstations=True, omit=name)
    with pytest.raises(verifier.KitError, match="release_workstations_image_incomplete"):
        release.finalize_images(root)
    with pytest.raises(verifier.KitError, match="release_workstations_image_incomplete"):
        release.seal(root)
    reseal_inventory(root)
    with pytest.raises(verifier.KitError, match="release_workstations_image_incomplete"):
        verifier.verify(root, trust)


@pytest.mark.parametrize("whiteout", ["opt/sli/.wh.sli_agent", "opt/sli/config/.wh..wh..opq", ".wh.opt"])
def test_image_gate_rejects_hidden_workstation_files(tmp_path, whiteout):
    write_workstations(tmp_path)
    archive = tmp_path / "image.tar"
    image(archive, "sli-release:1.1.0", version="1.1.0", workstations=True, whiteout=whiteout)
    with pytest.raises(verifier.KitError, match="release_workstations_image_whiteout"):
        verifier.workstation_release_gate(tmp_path, image=archive)


def test_internal_kit_requires_explicit_override_at_each_gate_and_stays_marked(kit):
    root, trust = kit
    path = root / "release-inputs.json"
    inputs = json.loads(path.read_text())
    inputs.update(release_eligible=False, artifact_label=verifier.INTERNAL_LABEL)
    release.write_json(path, inputs)
    for kind in ("install", "update"):
        draft_path = root / "manifests" / (kind + ".unsigned.json")
        draft = json.loads(draft_path.read_text())
        draft["build_id"] = "internal-test-not-for-release-1.1.0"
        release.write_json(draft_path, draft)
    (root / "source/sli_agent/workstations.py").unlink()
    release.write_json(root / "inventories/source.json", verifier.file_inventory(root / "source"))
    for operation in (release.finalize_images, release.seal):
        with pytest.raises(verifier.KitError, match="release_internal_test_not_for_release"):
            operation(root)
        operation(root, internal_test_build=True)
    assert json.loads((root / "KIT_INVENTORY.json").read_text())["artifact_label"] == verifier.INTERNAL_LABEL
    with pytest.raises(verifier.KitError, match="release_internal_test_not_for_release"):
        verifier.verify(root, trust)
    gate = verifier.verify(root, trust, internal_test_build=True)["workstation_gate"]
    assert gate["release_eligible"] is False and gate["failures"]


def test_cli_gate_cannot_verify_internal_kit_without_flag(kit, capsys):
    root, trust = kit
    path = root / "release-inputs.json"
    inputs = json.loads(path.read_text())
    inputs.update(release_eligible=False, artifact_label=verifier.INTERNAL_LABEL)
    release.write_json(path, inputs)
    for kind in ("install", "update"):
        draft_path = root / "manifests" / (kind + ".unsigned.json")
        draft = json.loads(draft_path.read_text())
        draft["build_id"] = "internal-test-not-for-release-1.1.0"
        release.write_json(draft_path, draft)
    release.seal(root, internal_test_build=True)
    assert release.main(["check-source", "--kit", str(root)]) == 1
    assert release.main(["check-source", "--kit", str(root), "--internal-test-build"]) == 0
    assert verifier.main(["--kit", str(root), "--trust-store", str(trust)]) == 1
    assert verifier.main(["--kit", str(root), "--trust-store", str(trust), "--internal-test-build"]) == 0
    result = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert result["workstation_gate"]["artifact_label"] == verifier.INTERNAL_LABEL


def test_workflow_override_is_manual_only_and_marks_artifact():
    import yaml
    workflow = yaml.safe_load((ROOT / ".github/workflows/release-artifacts.yml").read_text())
    trigger = workflow.get("on", workflow.get(True))
    assert trigger["workflow_dispatch"]["inputs"]["internal_test_build"]["default"] is False
    commands = "\n".join(step.get("run", "") for step in workflow["jobs"]["prepare"]["steps"])
    assert 'test "$GITHUB_EVENT_NAME" = workflow_dispatch' in commands
    assert 'test "$RELEASE_REF_TYPE" != tag' in commands
    upload = workflow["jobs"]["prepare"]["steps"][-1]
    assert "internal-test-not-for-release" in upload["with"]["name"]


def test_workstation_migration_contract_accepts_git_crlf_checkout(tmp_path):
    write_workstations(tmp_path)
    name = "config/postgres_migrations/159_workstation_security.sql"
    raw = b"SELECT 1;\n"
    path = tmp_path / verifier.WORKSTATION_MANIFEST
    data = json.loads(path.read_text())
    data["data"]["migrations"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    path.write_text(json.dumps(data))
    (tmp_path / name).write_bytes(raw.replace(b"\n", b"\r\n"))
    assert verifier.workstation_release_gate(tmp_path)["release_eligible"] is True


def mock_release_check(monkeypatch):
    from scripts.maintenance import release_check
    timed = release_check._timed
    data = {
        "required_files": [], "role_views": {"views": [{"id": "security"}, {"id": "it"}, {"id": "technical"}]},
        "reports": [], "release_metadata": {}, "runtime_source_warnings": [],
        "runtime_size_checks": ([], {"mode": "fake"}), "pg_runtime_parity_audit": {"status": "ok"},
    }
    def fake_timed(name, func):
        if name == "workstation_plugin":
            return timed(name, func)
        return data.get(name, {}), {"status": "ok", "duration_ms": 0}
    monkeypatch.setattr(release_check, "_timed", fake_timed)
    return release_check


@pytest.mark.parametrize("name", verifier.WORKSTATION_FILES)
def test_release_check_gate_blocks_missing_plugin_even_with_allow_warn(monkeypatch, tmp_path, name, capsys):
    rc = mock_release_check(monkeypatch)
    write_workstations(tmp_path)
    assert rc.run_release_check(tmp_path)["status"] == "ok"
    (tmp_path / name).unlink()
    run = rc.run_release_check
    result = run(tmp_path)
    assert result["status"] == "failed"
    assert result["release_eligible"] is False
    assert result["checks"]["workstation_plugin"]["status"] == "failed"
    monkeypatch.setattr(rc, "run_release_check", lambda **kwargs: run(tmp_path, **kwargs))
    monkeypatch.setattr(rc.sys, "argv", ["release_check.py", "--json", "--allow-warn"])
    assert rc.main() == 1
    assert json.loads(capsys.readouterr().out)["status"] == "failed"


@pytest.mark.parametrize("missing", [False, True])
def test_release_check_internal_override_is_explicit_and_marked(monkeypatch, tmp_path, capsys, missing):
    rc = mock_release_check(monkeypatch)
    if not missing:
        write_workstations(tmp_path)
    run = rc.run_release_check
    monkeypatch.setattr(rc, "run_release_check", lambda **kwargs: run(tmp_path, **kwargs))
    monkeypatch.setattr(rc.sys, "argv", ["release_check.py", "--json", "--internal-test-build"])
    assert rc.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["release_eligible"] is False
    assert result["artifact_label"] == verifier.INTERNAL_LABEL
    assert bool(result["workstation_gate"]["failures"]) is missing


def test_offline_builder_checks_gate_before_docker_and_forwards_override():
    script = (ROOT / "deploy/linux/build_offline_kit.sh").read_text()
    assert script.index("check-source --kit") < script.index("docker pull")
    assert 'finalize-images --kit "$kit" "${args[@]}"' in script
    assert "--internal-test-build" in script


@pytest.mark.parametrize("compressed", [False, True])
def test_image_gate_accepts_complete_workstation_payload(tmp_path, compressed):
    write_workstations(tmp_path)
    archive = tmp_path / "image.tar"
    image(archive, "sli-release:1.1.0", version="1.1.0", workstations=True, compressed=compressed)
    assert verifier.workstation_release_gate(tmp_path, image=archive)["release_eligible"] is True


def test_override_cannot_hide_an_unmarked_incomplete_kit(kit):
    root, trust = kit
    (root / "source/sli_agent/workstations.py").unlink()
    with pytest.raises(verifier.KitError, match="release_workstations_incomplete"):
        verifier.kit_release_gate(root, internal_test_build=True)


def test_internal_marker_cannot_be_removed_only_from_inputs(kit):
    root, trust = kit
    path = root / "manifests/install.unsigned.json"
    draft = json.loads(path.read_text())
    draft["build_id"] = "internal-test-not-for-release-1.1.0"
    release.write_json(path, draft)
    with pytest.raises(verifier.KitError, match="release_build_marker_invalid"):
        verifier.kit_release_gate(root)
