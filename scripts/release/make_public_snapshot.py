#!/usr/bin/env python3
"""Build a checked, history-free public genesis tree; never modify its source.

Python 3.11+. Git access is read-only (archive/ls-files). Directory inputs without
Git must be exports, not working directories containing untracked local data.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

import tomllib

ROOT = Path(__file__).resolve().parents[2]
SCANNER = "scripts/maintenance/github_sanitary_check.py"
MANIFEST = "PUBLIC_SNAPSHOT.json"
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
             ".ruff_cache", ".mypy_cache", ".aws", ".ssh", ".codex", ".agents"}
BLOCKED_SUFFIXES = {".env", ".key", ".pem", ".pfx", ".p12", ".jks", ".pyc"}


class SnapshotError(RuntimeError):
    """Errors expose finding locations/IDs, never matched private values."""

    def __init__(self, code: str, report: dict | None = None):
        super().__init__(code)
        self.report = report or {"status": "failed", "error": code}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def safe_name(name: str) -> str:
    parts = PurePosixPath(name).parts
    if (not parts or "\\" in name or PurePosixPath(name).is_absolute()
            or any(part in {".", ".."} or ":" in part for part in parts)):
        raise SnapshotError("unsafe_source_path")
    return "/".join(parts)


def is_link(path: Path) -> bool:
    # On Windows junctions are reparse points but need not be symlinks.
    return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0)
                                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def blocked(name: str, excludes: list[str]) -> bool:
    path = PurePosixPath(name)
    return (any(part in SKIP_DIRS for part in path.parts)
            or path.name == ".env" or path.name.startswith(".env.")
            or path.suffix.lower() in BLOCKED_SUFFIXES
            or matches(name, excludes))


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "--literal-pathspecs", "-C", str(root), *args],
                            capture_output=True, check=False)
    if result.returncode:
        raise SnapshotError("git_source_unavailable")
    return result.stdout


def directory_files(root: Path):
    if (root / ".git").exists():
        names = [os.fsdecode(item) for item in git(root, "ls-files", "--cached", "-z").split(b"\0") if item]
    else:
        names = []
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS)
            if any(is_link(Path(directory) / name) for name in dirs):
                raise SnapshotError("source_symlink")
            names.extend((Path(directory) / name).relative_to(root).as_posix() for name in files)
    for name in sorted(set(names)):
        yield safe_name(name), root / name


def canonical(data: bytes) -> bytes:
    # Keep binaries intact; normalize text checkout differences for reproducibility.
    if b"\0" not in data:
        try:
            data.decode("utf-8")
            return data.replace(b"\r\n", b"\n")
        except UnicodeDecodeError:
            pass
    return data


def write_file(root: Path, name: str, data: bytes, executable: bool = False) -> None:
    path = root / safe_name(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(data))
    path.chmod(0o755 if executable or name.endswith(".sh") else 0o644)


def public_scanner(data: bytes) -> bytes:
    """Keep every detector and remove the private-tree infrastructure exception."""
    source = data.decode("utf-8")
    lines = source.splitlines(keepends=True)
    names = {"APPROVED_INFRASTRUCTURE_CONFIGS"}
    changes = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in names:
                changes.append((node.lineno - 1, node.end_lineno, target.id))
    if {item[2] for item in changes} != names or len(changes) != 1:
        raise SnapshotError("sanitary_policy_shape_changed")
    for start, end, name in reversed(changes):
        lines[start:end] = [f"{name} = frozenset()\n"]
    return "".join(lines).encode()


def load_patterns(path: Path) -> dict[str, re.Pattern]:
    try:
        values = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(values, dict) or not values:
            raise ValueError
        patterns = {}
        for name, value in values.items():
            if (not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name)
                    or not isinstance(value, str) or not value or len(value) > 4096):
                raise ValueError
            patterns[name] = re.compile(value, re.IGNORECASE)
            if patterns[name].search(""):
                raise ValueError
        return patterns
    except (OSError, ValueError, TypeError, re.error):
        raise SnapshotError("sensitive_values_invalid") from None


def redact_name(name: str, patterns: dict[str, re.Pattern]) -> str:
    for pattern in patterns.values():
        name = pattern.sub("[redacted]", name)
    return name


def private_findings(root: Path, patterns: dict[str, re.Pattern], *, paths: list[Path] | None = None) -> list[dict]:
    findings = []
    for path in sorted(root.rglob("*") if paths is None else paths):
        if not path.is_file():
            continue
        name = path.relative_to(root).as_posix()
        data = path.read_bytes()
        texts = [data.decode("utf-8", errors="ignore")]
        # Binary and UTF-16 fixtures are scanned too; there is no test exemption.
        texts.extend(data.decode(encoding, errors="ignore") for encoding in ("utf-16-le", "utf-16-be"))
        for label, pattern in patterns.items():
            if pattern.search(name):
                findings.append({"path_sha256": digest(name.encode()), "line": 0, "id": label})
            for text in texts:
                match = pattern.search(text)
                if match:
                    # A filename can itself contain PII, so redact it too.
                    findings.append({"path": redact_name(name, patterns), "line": text.count("\n", 0, match.start()) + 1,
                                     "id": label})
                    break
    return findings


def trusted_modules():
    # Import the reviewed tool's modules, never Python from the exported input.
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from deploy.linux import native_pg_inventory
    from scripts.maintenance import existing_postgres_bootstrap

    spec = importlib.util.spec_from_file_location("public_sanitary", ROOT / SCANNER)
    sanitary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sanitary)
    sanitary.APPROVED_INFRASTRUCTURE_CONFIGS = frozenset()
    return native_pg_inventory, existing_postgres_bootstrap, sanitary


def verify_sql(root: Path) -> None:
    inventory, bootstrap, _ = trusted_modules()
    try:
        manifest = json.loads((root / "deploy/linux/native_pg_ledger.json").read_text(encoding="utf-8"))
        inventory.verify_manifest(root, manifest)
        bootstrap.load_baseline(root / "config/postgres_baseline",
                                bootstrap.forward_migration_inventory(root / "config/postgres_migrations"))
    except (OSError, ValueError, RuntimeError):
        raise SnapshotError("source_sql_inventory_invalid") from None


def refresh_public_sql(root: Path) -> dict:
    inventory, bootstrap, _ = trusted_modules()
    migrations = bootstrap.forward_migration_inventory(root / "config/postgres_migrations")
    path = root / "config/postgres_baseline/manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["migrations"] = {str(item.version): bootstrap.normalized_sha256(item.path)
                              for item in migrations if item.version <= manifest["baseline_version"]}
    # Baseline schema/roles are preserved, not regenerated from an installation.
    path.write_bytes(json_bytes(manifest))
    native = inventory.build_manifest(root)
    (root / "deploy/linux/native_pg_ledger.json").write_bytes(json_bytes(native))
    fixture = root / "tests/fixtures/native_docker_ledger.txt"
    if fixture.exists():
        rows = [line.split("|") for line in fixture.read_text(encoding="utf-8").splitlines()]
        expected = {row["version"]: row for row in inventory.expected_ledger(root)}
        # This becomes a public synthetic attestation fixture, not a private DB export.
        fixture.write_text("".join(f"{v}|{name}|{expected[int(v)]['sha256']}\n" for v, name, _ in rows),
                           encoding="utf-8", newline="\n")
    verify_sql(root)
    expected = inventory.expected_ledger(root)
    return {"status": "verified", "pinned_files": len(native["files"]),
            "max_version": expected[-1]["version"], "baseline_version": manifest["baseline_version"]}


def make_snapshot(source: Path | str, output: Path, *, rules: Path,
                  sensitive_values: Path, repo: Path = ROOT, release_root: Path = ROOT) -> dict:
    output, rules, sensitive_values = output.resolve(), rules.resolve(), sensitive_values.resolve()
    source_path = Path(source).resolve()
    directory = source_path.is_dir()
    boundary = source_path if directory else repo.resolve()
    if (output.exists() or output.is_relative_to(boundary) or boundary.is_relative_to(output)
            or output.is_relative_to(ROOT) or sensitive_values.is_relative_to(boundary)
            or sensitive_values.is_relative_to(ROOT) or sensitive_values.is_relative_to(output)):
        raise SnapshotError("output_or_sensitive_values_location_invalid")
    patterns = load_patterns(sensitive_values)
    try:
        policy = tomllib.loads(rules.read_text(encoding="utf-8"))
        if policy["version"] != 1 or not isinstance(policy["exclude"], list):
            raise ValueError
        replacements = policy.get("replace", [])
        for rule in replacements:
            if (rule["pattern_id"] not in patterns or not isinstance(rule["to"], str)
                    or not isinstance(rule["paths"], list)):
                raise ValueError
    except (OSError, KeyError, ValueError, TypeError):
        raise SnapshotError("snapshot_rules_invalid_or_missing_pattern") from None
    excludes = policy["exclude"]
    report = {"status": "failed", "excluded": [], "replaced": [], "sql": {"status": "not_present"}}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".public-snapshot-", dir=output.parent) as temporary:
        stage = Path(temporary) / "tree"
        stage.mkdir()
        if directory:
            for name, path in directory_files(source_path):
                if blocked(name, excludes):
                    report["excluded"].append(name)
                    continue
                if is_link(path) or any(is_link(p) for p in path.parents if p.is_relative_to(source_path)):
                    raise SnapshotError("source_symlink")
                if not stat.S_ISREG(path.stat().st_mode):
                    raise SnapshotError("source_file_missing")
                write_file(stage, name, path.read_bytes(), bool(path.stat().st_mode & stat.S_IXUSR))
        else:
            # Resolve to an immutable object first; never accept an option as a ref.
            revision = git(repo, "rev-parse", "--verify", "--end-of-options", f"{source}^{{commit}}").decode().strip()
            archive = Path(temporary) / "source.tar"
            names = []
            for raw in git(repo, "ls-tree", "-r", "-z", "--full-tree", "--name-only", revision).split(b"\0"):
                if raw:
                    name = safe_name(os.fsdecode(raw))
                    if blocked(name, excludes):
                        report["excluded"].append(name)
                    else:
                        names.append(name)

            def export_batch(batch):
                # Exclude before Git reads blobs, including the temporary TAR.
                git(repo, "archive", "--format=tar", f"--output={archive}", revision, "--", *batch)
                with tarfile.open(archive) as contents:
                    for member in contents:
                        if member.isdir():
                            continue
                        name = safe_name(member.name)
                        if name not in batch or not member.isfile():
                            raise SnapshotError("source_symlink_or_special_file")
                        write_file(stage, name, contents.extractfile(member).read(), bool(member.mode & 0o111))
                archive.unlink()

            batch, length = [], 0
            for name in names:
                if len(name) > 8000:
                    raise SnapshotError("source_path_too_long")
                if batch and length + len(name) > 12000:
                    export_batch(batch)
                    batch, length = [], 0
                batch.append(name)
                length += len(name) + 3
            if batch:
                export_batch(batch)
        # Explicit versioned overlay makes a current-main rehearsal possible before
        # this release tooling has been merged. No implicit worktree files are added.
        for name in policy.get("publish", []):
            name = safe_name(name)
            if blocked(name, excludes):
                raise SnapshotError("published_asset_excluded")
            path = release_root / name
            if not path.resolve().is_relative_to(release_root.resolve()) or is_link(path):
                raise SnapshotError("published_asset_symlink")
            write_file(stage, name, path.read_bytes())
        has_sql = (stage / "deploy/linux/native_pg_ledger.json").exists()
        if has_sql:
            verify_sql(stage)  # Never bless pre-existing SQL drift by repinning it.
        for path in sorted(stage.rglob("*")):
            if not path.is_file():
                continue
            name = path.relative_to(stage).as_posix()
            data = path.read_bytes()
            if name == SCANNER:
                data = public_scanner(data)
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            for rule in replacements:
                if matches(name, rule["paths"]):
                    text, count = patterns[rule["pattern_id"]].subn(lambda _, to=rule["to"]: to, text)
                    if count:
                        report["replaced"].append({"path": name, "id": rule["pattern_id"], "count": count})
            path.write_bytes(text.encode())
        if has_sql:
            report["sql"] = refresh_public_sql(stage)
        missing = [name for name in policy.get("required", []) if not (stage / safe_name(name)).is_file()]
        if missing or not (stage / SCANNER).is_file():
            raise SnapshotError("required_public_file_missing")
        _, _, sanitary = trusted_modules()
        report["sanitary"] = sanitary.scan(stage)
        # Do not retain masked fragments of private values in release evidence.
        for finding in report["sanitary"]["findings"]:
            finding.pop("masked", None)
        for finding in [*report["sanitary"]["findings"], *report["replaced"]]:
            finding["path"] = redact_name(finding["path"], patterns)
        report["private_findings"] = private_findings(stage, patterns)
        report["excluded"] = sorted(redact_name(name, patterns) for name in report["excluded"])
        if report["sanitary"]["status"] != "ok" or report["private_findings"]:
            raise SnapshotError("snapshot_cleanliness_failed", report)
        files = {p.relative_to(stage).as_posix(): {"sha256": digest(p.read_bytes()),
                 "mode": "0755" if p.name.endswith(".sh") or p.stat().st_mode & stat.S_IXUSR else "0644"}
                 for p in sorted(stage.rglob("*")) if p.is_file()}
        manifest = {"format": 1, "kind": "public-genesis", "rules_sha256": digest(rules.read_bytes()),
                    "files": files, "sql": report["sql"]}
        (stage / MANIFEST).write_bytes(json_bytes(manifest))
        # Manifest is part of the checked output, although it cannot hash itself.
        if private_findings(stage, patterns, paths=[stage / MANIFEST]):
            raise SnapshotError("snapshot_manifest_contains_private_value")
        stage.rename(output)
    report.update(status="ok", files=len(files) + 1,
                  manifest_sha256=digest((output / MANIFEST).read_bytes()))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="main commit/ref or directory")
    parser.add_argument("--output", required=True, type=Path, help="new directory outside the repository")
    parser.add_argument("--rules", type=Path, default=ROOT / "config/release/public_snapshot.toml")
    parser.add_argument("--sensitive-values", type=Path, required=True, help="external JSON: label -> regex")
    parser.add_argument("--repo", type=Path, default=ROOT, help="read-only Git source for commit inputs")
    parser.add_argument("--release-root", type=Path, default=ROOT, help="reviewed versioned release assets")
    parser.add_argument("--report", type=Path, help="external JSON report; never contains matched values")
    args = parser.parse_args()
    if args.report and (args.report.resolve().is_relative_to(ROOT)
                        or args.report.resolve().is_relative_to(args.output.resolve())
                        or args.report.resolve().is_relative_to(Path(args.source).resolve())
                        or args.report.exists()):
        parser.error("report must be a new external file outside source/output")
    try:
        report = make_snapshot(args.source, args.output, rules=args.rules,
                               sensitive_values=args.sensitive_values, repo=args.repo,
                               release_root=args.release_root)
    except SnapshotError as error:
        report = error.report
    except (OSError, ValueError, RuntimeError):
        report = {"status": "failed", "error": "snapshot_input_or_io_error"}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_bytes(json_bytes(report))
    print(json.dumps({key: report[key] for key in ("status", "error", "files", "manifest_sha256") if key in report}))
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
