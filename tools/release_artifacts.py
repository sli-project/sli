"""Prepare unsigned release inputs from Git objects; seal an operator-built offline kit."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import traceback
from pathlib import Path
from urllib.request import Request, urlopen

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from deploy.linux.verify_offline_kit import (
    INTERNAL_LABEL, KitError, digest, file_inventory, kit_release_gate, require, workstation_release_gate,
)

VERSION_PATTERN = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
SOURCE_ROOTS = ("server", "sli_collect", "sli_agent", "frontend", "scripts", "config", "web/app", "deploy/linux", "tools")
SOURCE_FILES = {"requirements.lock.txt", "package.json", "package-lock.json", "VERSION"}
BUYER_DOCS = (
    "docs/install/SERVER_INSTALL.ru.md", "docs/install/SERVER_INSTALL.en.md",
    "docs/install/AGENT_INSTALL.ru.md", "docs/install/AGENT_INSTALL.en.md",
    "docs/agent-enrollment.md",
)
HOST_PACKAGES = {"cryptography", "cffi", "pycparser"}


def bundle_host_libraries(kit):
    """Resolve wheels for target interpreters on the connected build host only."""
    for version in ("3.11", "3.12", "3.13", "3.14"):
        target = kit / "host-libs" / ("python" + version)
        require(not target.exists(), "release_host_libraries_exist")
        subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
                        "--only-binary=:all:", "--no-deps", "--no-compile",
                        "--python-version", version, "--implementation", "cp",
                        "--abi", "cp" + version.replace(".", ""),
                        "--platform", "manylinux_2_28_x86_64",
                        "--platform", "manylinux_2_17_x86_64", "--platform", "manylinux2014_x86_64",
                        "--target", str(target), "-r", str(kit / "host-requirements.lock.txt")], check=True)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def locked_python(lock):
    result = []
    for line in lock.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s;]+)(?:;\s*(.*))?", line)
        require(match is not None, "release_python_dependency_unlocked")
        name, version, marker = match.groups()
        # The canonical lock currently has only this platform marker. Fail closed
        # on new marker syntax rather than silently omit a runtime dependency.
        require(marker is None or marker in {"sys_platform == \"win32\"", "sys_platform == 'win32'"},
                "release_python_marker_unsupported")
        result.append((name, version, marker is None or sys.platform == "win32"))
    require(result and len({re.sub(r"[-_.]+", "-", name).lower() for name, _, _ in result}) == len(result),
            "release_python_lock_invalid")
    return result


def python_inventory(lock, distribution=importlib.metadata.distribution):
    result = []
    for name, version, active in locked_python(lock):
        entry = {"ecosystem": "pypi", "name": name, "version": version, "active": active,
                 "license": "NOASSERTION"}
        if active:
            installed = distribution(name)
            require(installed.version == version, "release_python_version_mismatch")
            metadata = installed.metadata
            license_name = metadata.get("License-Expression") or metadata.get("License")
            classifiers = [value for value in metadata.get_all("Classifier", []) if value.startswith("License ::")]
            # Legacy License can contain an entire license text; keep that in
            # dist-info, not in the compact inventory.
            entry["license"] = license_name if license_name and "\n" not in license_name and len(license_name) <= 160 else "NOASSERTION"
            entry["license_classifiers"] = classifiers
        result.append(entry)
    return sorted(result, key=lambda entry: entry["name"].casefold())


def npm_inventory(lock, location):
    require(lock.get("lockfileVersion") in {2, 3} and isinstance(lock.get("packages"), dict),
            "release_npm_lock_invalid")
    result = []
    for path, package in sorted(lock["packages"].items()):
        if not path or package.get("link"):
            continue
        require(isinstance(package.get("version"), str) and isinstance(package.get("integrity"), str),
                "release_npm_dependency_unlocked")
        result.append({"ecosystem": "npm", "name": package.get("name") or path.rsplit("node_modules/", 1)[-1],
                       "version": package["version"], "license": package.get("license") or "NOASSERTION",
                       "integrity": package["integrity"], "location": location + "/" + path,
                       "development": bool(package.get("dev")), "optional": bool(package.get("optional"))})
    return result


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL).decode("utf-8").strip()


def previous_tag(root, sha):
    # Exclude the release commit's own tag, including on a rerun.
    try:
        parent = git(root, "rev-parse", sha + "^")
        return git(root, "describe", "--tags", "--abbrev=0", "--match", "sli-[0-9]*", parent)
    except subprocess.CalledProcessError:
        return None


def github_pulls(repository, commit):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "release_repository_invalid")
    request = Request(f"https://api.github.com/repos/{repository}/commits/{commit}/pulls?per_page=100",
                      headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                               "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    with urlopen(request, timeout=30) as response:
        result = json.load(response)
    require(isinstance(result, list) and len(result) < 100, "release_pr_inventory_incomplete")
    return result


def merged_titles(commits, pull_lookup):
    reachable = set(commits)
    titles = {}
    for commit in commits:
        for pull in pull_lookup(commit):
            if pull.get("merged_at") and pull.get("merge_commit_sha") in reachable:
                titles[pull["number"]] = " ".join(pull["title"].split())
    return [f"- #{number}: {title}" for number, title in sorted(titles.items())]


def allowed_source(name):
    parts = Path(name).parts
    excluded = {"node_modules", "__pycache__", "secrets", ".git", ".venv"}
    return (name in SOURCE_FILES or name in BUYER_DOCS or any(name.startswith(root + "/") for root in SOURCE_ROOTS)) and not (
        excluded.intersection(parts) or any(part.startswith(".env") for part in parts)
        or name.endswith((".pem", ".key", ".pyc")))


def export_source(root, sha, destination):
    destination.mkdir()
    with tempfile.TemporaryDirectory() as temporary:
        archive_path = Path(temporary) / "source.tar"
        subprocess.run(["git", "-C", str(root), "archive", "--format=tar", "--output", str(archive_path), sha],
                       check=True, stderr=subprocess.DEVNULL)
        with tarfile.open(archive_path) as archive:
            for item in archive:
                if item.isdir() or not allowed_source(item.name):
                    continue
                require(item.isfile() and not item.name.startswith("/")
                        and ".." not in Path(item.name).parts, "release_source_link_forbidden")
                target = destination / item.name
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                # Git tracks executability; exported code must also be readable
                # when the build host uses a private umask.
                target.chmod(0o755 if item.mode & 0o111 else 0o644)
    for path in [destination, *destination.rglob("*")]:
        if path.is_dir():
            path.chmod(0o755)


def manifest(inputs, migrations, *, installing=False):
    previous = None if installing else inputs["from_version"]
    version = inputs["version"]
    return {"schema_version": 2, "package_type": "core-install" if installing else "core-update",
            "package_id": "sli.core", "version": version, "platform": "linux-amd64",
            "source_commit": inputs["source_commit"],
            "build_id": ("release-" if inputs.get("release_eligible", True) else "internal-test-not-for-release-") + version,
            "minimum_updater": 1, "component": "server", "from_version": previous, "to_version": version,
            "compatibility": {"core_api": 1, "ui_api": 1, "from_version": previous,
                              "min_version": previous or version, "max_version": previous or version,
                              "os": "linux", "architecture": "amd64"},
            "required_free_disk": 10737418240, "image": {"path": "images/server.tar", "digest": None},
            "files": [{"path": "images/server.tar", "size": 0, "sha256": None}],
            "migrations": migrations, "deletions": [], "restart_profile": "docker-compose",
            "compose_delta": None, "config_delta": None}


def prepare(root, output, sha, version, from_version, repository, pull_lookup=None, *, internal_test_build=False):
    require(re.fullmatch(r"[0-9a-f]{40}", sha) and git(root, "rev-parse", "HEAD") == sha,
            "release_exact_sha_required")
    require(re.fullmatch(VERSION_PATTERN, version), "release_version_invalid")
    prior_tag = previous_tag(root, sha)
    if from_version is None and prior_tag:
        from_version = prior_tag.removeprefix("sli-")
    if from_version is not None:
        require(re.fullmatch(VERSION_PATTERN, from_version)
                and tuple(map(int, from_version.split("."))) < tuple(map(int, version.split("."))),
                "release_from_version_invalid")
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    export_source(root, sha, source)
    gate = workstation_release_gate(source, internal_test_build=internal_test_build)
    if (source / "VERSION").exists():
        require((source / "VERSION").read_text("utf-8").strip() == version, "release_version_mismatch")
    inputs = {"schema_version": 1, "source_commit": sha, "version": version, "from_version": from_version,
              "previous_tag": prior_tag, "platform": "linux-amd64", "signing": "offline-only",
              "image_build": "operator-host", "source_date_epoch": int(git(root, "show", "-s", "--format=%ct", sha))}
    inputs.update(release_eligible=gate["release_eligible"], artifact_label=gate["artifact_label"], workstation_gate=gate)
    write_json(output / "release-inputs.json", inputs)
    python = python_inventory((source / "requirements.lock.txt").read_text("utf-8"))
    npm = []
    for location in ("", "frontend"):
        lock_path = source / location / "package-lock.json"
        npm.extend(npm_inventory(json.loads(lock_path.read_text("utf-8")), location or "root"))
    write_json(output / "inventories/licenses.json", {"python": python, "npm": npm})
    write_json(output / "inventories/source.json", file_inventory(source))
    write_json(output / "inventories/sbom.json", {"schema_version": 1, "format": "sli-inventory",
               "source_commit": sha, "scope": "locked Python and npm dependencies, including build/dev; OS image inventory added by operator",
               "components": python + npm})
    host_lock = [f"{name}=={version}" for name, version, active in locked_python(
        (source / "requirements.lock.txt").read_text("utf-8")) if active and name.lower() in HOST_PACKAGES]
    require(len(host_lock) == len(HOST_PACKAGES), "release_host_lock_incomplete")
    (output / "host-requirements.lock.txt").write_text("\n".join(host_lock) + "\n", encoding="utf-8")
    migrations = {path.relative_to(source).as_posix(): digest(path)
                  for path in sorted((source / "config/postgres_migrations").glob("*.sql"))}
    require(migrations, "release_migrations_missing")
    write_json(output / "manifests/install.unsigned.json", manifest(inputs, migrations, installing=True))
    if from_version is not None:
        write_json(output / "manifests/update.unsigned.json", manifest(inputs, migrations))
    revision_range = f"{prior_tag}..{sha}" if prior_tag else sha
    label = INTERNAL_LABEL + "\n\n" if internal_test_build else ""
    commits = git(root, "rev-list", "--reverse", revision_range).splitlines()
    lookup = pull_lookup or ((lambda commit: github_pulls(repository, commit)) if repository else None)
    titles = merged_titles(commits, lookup) if lookup else []
    notes = titles or (["No merged PRs in this commit range."] if lookup else
                      ["PR inventory not queried (local checkout build); review release notes before signing."])
    (output / "RELEASE_NOTES.md").write_text(f"# SLI {version}\n\nSource: `{sha}`\n\n"
        + label + "\n".join(notes) + "\n", encoding="utf-8")
    shutil.copyfile(source / "deploy/linux/verify_offline_kit.py", output / "verify_offline_kit.py")
    shutil.copyfile(source / "deploy/linux/build_offline_kit.sh", output / "build_offline_kit.sh")
    for name in BUYER_DOCS:
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        # The buyer guides live at kit/docs; repository assets live at kit/source.
        text = (source / name).read_text("utf-8")
        if name.startswith("docs/install/"):
            text = re.sub(r"\(\.\./\.\./(config|deploy|tools|scripts)/", r"(../../source/\1/", text)
        target.write_text(text, encoding="utf-8", newline="\n")
    write_start_here(output)


def write_start_here(kit):
    (kit / "START_HERE.md").write_text(
        "# SLI offline kit / Офлайн-комплект SLI\n\n"
        "Без подписи: **для оценки, без подписи** / **evaluation only, unsigned**.\n"
        "A signed delivery requires separate offline owner signing and resealing.\n\n"
        "1. Получите SHA-256 `KIT_INVENTORY.json` от поставщика отдельным доверенным каналом. "
        "Obtain its SHA-256 from the supplier through a separate trusted channel.\n"
        "2. Сравните / compare `sha256sum KIT_INVENTORY.json`; then check every file:\n\n"
        "   ```sh\n"
        "   python3 -B verify_offline_kit.py --kit . --evaluation --inventory-sha256 <EXPECTED_SHA256>\n"
        "   ```\n\n"
        "   System python3 >=3.11 / системный python3 >=3.11; no host Python 3.14 required.\n"
        "   SHA-256 checks integrity, not supplier authentication / целостность, не подпись.\n"
        "   For signed deliveries use the external trust store procedure in the guide.\n\n"
        "3. Начните с [инструкции установки](docs/install/SERVER_INSTALL.ru.md) / "
        "[installation guide](docs/install/SERVER_INSTALL.en.md). "
        "Unsigned installation requires `--evaluation`; do not build on the target.\n",
        encoding="utf-8")


def finalize_images(kit, *, internal_test_build=False):
    from deploy.linux.verify_offline_kit import docker_archive

    inputs = json.loads((kit / "release-inputs.json").read_text("utf-8"))
    require(json.loads((kit / "inventories/source.json").read_text("utf-8")) == file_inventory(kit / "source"),
            "release_source_modified")
    kit_release_gate(kit, internal_test_build=internal_test_build, check_image=True)
    images = {}
    for name, tag in (("server", "sli-release:" + inputs["version"]), ("postgres", "postgres:18.6-bookworm"),
                      ("clickhouse", "clickhouse/clickhouse-server:25.8")):
        path = kit / "images" / (name + ".tar")
        images[name] = docker_archive(path, tag)
    require(images["server"]["version"] == inputs["version"]
            and images["server"]["source_commit"] == inputs["source_commit"], "release_image_identity_mismatch")
    write_json(kit / "images/metadata.json", images)
    sbom_path = kit / "inventories/sbom.json"
    sbom = json.loads(sbom_path.read_text("utf-8"))
    sbom["images"] = images
    sbom["os_packages"] = [{"name": name, "version": version} for name, version in (
        line.split("\t", 1) for line in (kit / "inventories/os-packages.tsv").read_text("utf-8").splitlines())]
    write_json(sbom_path, sbom)
    for path in sorted((kit / "manifests").glob("*.unsigned.json")):
        data = json.loads(path.read_text("utf-8"))
        data["image"]["digest"] = images["server"]["digest"]
        image = kit / data["image"]["path"]
        data["files"] = [{"path": data["image"]["path"], "size": image.stat().st_size, "sha256": digest(image)}]
        # The canonical updater independently verifies image layers and the exact
        # migration inventory again before signing/activation.
        from deploy.linux.sli_update import image_inventory
        with tempfile.TemporaryDirectory() as temporary:
            image_inventory(image, data, Path(temporary) / "checked.tar")
        write_json(path, data)


def seal(kit, *, internal_test_build=False, evaluation=False):
    inputs = json.loads((kit / "release-inputs.json").read_text("utf-8"))
    require(json.loads((kit / "inventories/source.json").read_text("utf-8")) == file_inventory(kit / "source"),
            "release_source_modified")
    gate = kit_release_gate(kit, internal_test_build=internal_test_build, check_image=True)
    write_json(kit / "KIT_INVENTORY.json", {"schema_version": 1, "stage": "offline",
               "signing": "evaluation-unsigned" if evaluation else "offline-only",
               "release_eligible": gate["release_eligible"], "artifact_label": gate["artifact_label"],
               "source_commit": inputs["source_commit"], "files": file_inventory(kit)})


def finalize_evaluation(kit, *, internal_test_build=False):
    from deploy.linux.evaluation_package import build

    build(kit)
    write_start_here(kit)
    seal(kit, internal_test_build=internal_test_build, evaluation=True)


def compact_image(source, output):
    """Keep the classic Docker-save envelope; gzip each layer with stable headers.

    The canonical updater accepts gzip layers, but requires an uncompressed
    outer tar. Avoid holding full image layers in RAM.
    """
    with tarfile.open(source, "r:") as archive, tarfile.open(output, "x") as target:
        record = json.load(archive.extractfile("manifest.json"))
        require(len(record) == 1, "release_single_image_required")
        record = record[0]
        def add(name, data):
            item = tarfile.TarInfo(name)
            item.size = len(data)
            target.addfile(item, io.BytesIO(data))
        raw = archive.extractfile(record["Config"]).read()
        config_name = hashlib.sha256(raw).hexdigest() + ".json"
        add(config_name, raw)
        layers = []
        for index, name in enumerate(record["Layers"]):
            layer_name = f"layers/{index}.tar.gz"
            with tempfile.TemporaryFile() as temporary:
                with archive.extractfile(name) as stream, gzip.GzipFile(fileobj=temporary, mode="wb", mtime=0, filename="") as compressed:
                    magic = stream.read(2)
                    stream.seek(0)
                    if magic == b"\x1f\x8b":
                        with gzip.GzipFile(fileobj=stream) as unpacked:
                            shutil.copyfileobj(unpacked, compressed)
                    else:
                        shutil.copyfileobj(stream, compressed)
                item = tarfile.TarInfo(layer_name)
                item.size = temporary.tell()
                temporary.seek(0)
                target.addfile(item, temporary)
            layers.append(layer_name)
        add("manifest.json", json.dumps([{"Config": config_name, "RepoTags": record.get("RepoTags", []),
                                         "Layers": layers}], sort_keys=True).encode())


def failure_message(exc, command):
    from deploy.linux.sli_update import UpdateError
    from server.sli.release_package import PackageError

    # These exception contracts contain diagnostics, never payloads or paths.
    if isinstance(exc, (KitError, PackageError, UpdateError)):
        return " ".join(str(exc).split())[:240]
    if isinstance(exc, OSError) and exc.errno is not None:
        return os.strerror(exc.errno)
    return f"Unexpected error during {command}; see stderr traceback."


def failure_traceback(exc, command):
    # Keep every stack frame without source lines, locals, operator directories
    # or arbitrary exception text, which can contain credentials/payload data.
    print("Traceback (most recent call last):", file=sys.stderr)
    root = Path(__file__).resolve().parents[1]
    for frame in traceback.extract_tb(exc.__traceback__):
        path = Path(frame.filename)
        name = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.name
        print(f'  File "{name}", line {frame.lineno}, in {frame.name}', file=sys.stderr)
    print(f"{type(exc).__name__}: {failure_message(exc, command)}", file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("prepare")
    create.add_argument("--root", type=Path, default=Path.cwd())
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--sha", required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--from-version")
    create.add_argument("--repository", help="GitHub owner/repository for merged PR notes (requires GH_TOKEN)")
    create.add_argument("--internal-test-build", action="store_true", help=INTERNAL_LABEL)
    for command in ("check-source", "bundle-host-libs", "finalize-images", "finalize-evaluation", "seal"):
        check = sub.add_parser(command)
        check.add_argument("--kit", type=Path, required=True)
        check.add_argument("--internal-test-build", action="store_true", help=INTERNAL_LABEL)
    compact = sub.add_parser("compact-image")
    compact.add_argument("--input", type=Path, required=True)
    compact.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            prepare(args.root, args.output, args.sha, args.version, args.from_version, args.repository,
                    internal_test_build=args.internal_test_build)
        elif args.command == "finalize-images":
            finalize_images(args.kit, internal_test_build=args.internal_test_build)
        elif args.command == "check-source":
            kit_release_gate(args.kit, internal_test_build=args.internal_test_build)
        elif args.command == "bundle-host-libs":
            bundle_host_libraries(args.kit)
        elif args.command == "finalize-evaluation":
            finalize_evaluation(args.kit, internal_test_build=args.internal_test_build)
        elif args.command == "compact-image":
            compact_image(args.input, args.output)
        else:
            seal(args.kit, internal_test_build=args.internal_test_build)
    except Exception as exc:
        failure_traceback(exc, args.command)
        print(json.dumps({"status": "failed",
                          "reason_code": str(exc) if isinstance(exc, KitError) else type(exc).__name__,
                          "message": failure_message(exc, args.command)}))
        return 1
    result = {"status": "prepared", "signed": False, "installed": False}
    if args.command != "compact-image":
        result["workstation_gate"] = kit_release_gate(
            args.output if args.command == "prepare" else args.kit, internal_test_build=args.internal_test_build)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
