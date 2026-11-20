"""Public exports must fail closed without changing their private inputs."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from scripts.release import make_public_snapshot as subject
from scripts.release.make_public_snapshot import SnapshotError, make_snapshot

ROOT = Path(__file__).resolve().parents[2]


def put(root: Path, name: str, data: str | bytes) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    return path


@pytest.fixture
def mini(tmp_path):
    source = tmp_path / "main"
    put(source, "LICENSE", "Apache-2.0\n")
    put(source, "NOTICE", "Synthetic notice\n")
    put(source, "README.md", "English\n")
    put(source, "README.ru.md", "Русский\n")
    put(source, "server/main.py", 'DOMAIN = "previous.invalid"\r\n')
    # The real sanitary gate is an input, never executed from the source tree.
    put(source, "scripts/maintenance/github_sanitary_check.py",
        (ROOT / "scripts/maintenance/github_sanitary_check.py").read_bytes())
    rules = put(tmp_path, "rules.toml", '''version = 1
exclude = ["docs/AI_*.md", "docs/private/**", "internal/tasks/**", "*.zip"]
required = ["LICENSE", "NOTICE", "README.md", "README.ru.md"]
[[replace]]
paths = ["server/*.py"]
pattern_id = "old_domain"
to = "example.invalid"
''')
    values = put(tmp_path, "private.json", json.dumps({
        "old_domain": r"previous\.invalid", "person": "Secret Person",
    }))
    return source, rules, values


def build(mini, output):
    source, rules, values = mini
    return make_snapshot(source, output, rules=rules, sensitive_values=values)


def test_excludes_internal_data_but_keeps_native_handoff_component(mini, tmp_path):
    source, _, _ = mini
    for name in ("docs/AI_TEAM.md", "docs/private/deep/a.md", "internal/tasks/a.py", "duplicate.zip"):
        put(source, name, "Secret Person")
    put(source, "agent-dotnet/installer/native/Handoff.cpp", "// component\n")
    before = (source / "server/main.py").read_bytes()
    result = build(mini, tmp_path / "public")
    assert result["status"] == "ok"
    assert (tmp_path / "public/server/main.py").read_bytes() == b'DOMAIN = "example.invalid"\n'
    assert (source / "server/main.py").read_bytes() == before
    assert (tmp_path / "public/agent-dotnet/installer/native/Handoff.cpp").is_file()
    assert not (tmp_path / "public/docs").exists()
    assert not (tmp_path / "public/duplicate.zip").exists()


@pytest.mark.parametrize("path,content", [
    ("server/user.json", '"Secret Person"'),
    ("server/user.bin", b"\x00Secret Person\x00"),
    ("server/user.txt", "Secret Person".encode("utf-16")),
    ("Secret Person.txt", "safe"),
    ("Secret Person.txt", "host=10.23.45.67"),
    ("tests/identity.txt", "Secret Person"),
])
def test_private_value_in_any_path_or_content_blocks_publication(mini, tmp_path, path, content):
    put(mini[0], path, content)
    with pytest.raises(SnapshotError) as error:
        build(mini, tmp_path / "public")
    assert error.value.report["status"] == "failed"
    assert "Secret Person" not in str(error.value)
    assert "Secret Person" not in json.dumps(error.value.report)
    assert not (tmp_path / "public").exists()


def test_public_sanitary_gate_has_no_historical_domain_or_infrastructure_exemptions(mini, tmp_path):
    put(mini[0], "docs/SLI_OUTPUT_AND_INTERFACE_REGISTER.md", "host=10.23.45.67\n")
    put(mini[0], "config/postgres_migrations/100_old.sql", "host=tenant.internal\n")
    with pytest.raises(SnapshotError) as error:
        build(mini, tmp_path / "public")
    assert {item["type"] for item in error.value.report["sanitary"]["findings"]} == {
        "non_documentation_ip", "internal_domain",
    }


def test_deterministic_file_bytes_modes_and_manifest(mini, tmp_path):
    put(mini[0], "server/script.sh", "#!/bin/sh\r\ntrue\r\n")
    build(mini, tmp_path / "a")
    build(mini, tmp_path / "b")
    def hashes(root):
        return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in root.rglob("*") if p.is_file()}
    assert hashes(tmp_path / "a") == hashes(tmp_path / "b")
    manifest = json.loads((tmp_path / "a/PUBLIC_SNAPSHOT.json").read_text())
    assert manifest["files"]["server/main.py"]["sha256"] == hashlib.sha256(
        b'DOMAIN = "example.invalid"\n').hexdigest()
    assert "private.json" not in manifest["files"]


def test_cannot_overwrite_or_write_inside_source(mini, tmp_path):
    existing = tmp_path / "existing"
    put(existing, "keep", "preserve")
    for output in (existing, mini[0] / "public", mini[0]):
        with pytest.raises(SnapshotError):
            build(mini, output)
    assert (existing / "keep").read_text() == "preserve"


def test_sensitive_file_must_be_external_and_nonempty(mini, tmp_path):
    source, rules, _ = mini
    for values in (put(source, "private.json", '{"name":"Secret Person"}'),
                   put(tmp_path, "empty.json", "{}")):
        with pytest.raises(SnapshotError):
            make_snapshot(source, tmp_path / "public", rules=rules, sensitive_values=values)


def test_symlink_cannot_read_outside_source(mini, tmp_path, monkeypatch):
    secret = put(tmp_path, "outside.txt", "must not copy")
    def fake_git(repo, *args):
        if args[0] == "rev-parse":
            return b"a" * 40 + b"\n"
        if args[0] == "ls-tree":
            return b"link.txt\0"
        archive_path = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--output="))
        with tarfile.open(archive_path, "w") as archive:
            member = tarfile.TarInfo("link.txt")
            member.type = tarfile.SYMTYPE
            member.linkname = str(secret)
            archive.addfile(member)
        return b""
    monkeypatch.setattr(subject, "git", fake_git)
    _, rules, values = mini
    with pytest.raises(SnapshotError, match="source_symlink_or_special_file"):
        make_snapshot("main", tmp_path / "public", rules=rules, sensitive_values=values, repo=mini[0])


def test_missing_required_license_blocks_export(mini, tmp_path):
    (mini[0] / "LICENSE").unlink()
    with pytest.raises(SnapshotError):
        build(mini, tmp_path / "public")


def add_sql(mini):
    source, rules, _ = mini
    from deploy.linux import native_pg_inventory as inventory
    put(source, "config/postgres_schema_v8.sql",
        "INSERT INTO schema_migrations(version,name) VALUES (1,'base') ON CONFLICT(version) DO NOTHING;\n")
    put(source, "config/postgres_migrations/009_domain.sql",
        "SELECT 'previous.invalid';\nINSERT INTO schema_migrations(version,name) VALUES (9,'domain');\n")
    put(source, "config/postgres_migrations/009_domain.rollback.sql", "SELECT 'previous.invalid';\n")
    schema = put(source, "config/postgres_baseline/baseline.sql", "SELECT '__SLI_REPORT_DOMAIN__';\n")
    roles = put(source, "config/postgres_baseline/roles.sql", "SELECT 'synthetic roles';\n")
    put(source, "config/postgres_baseline/manifest.json", json.dumps({
        "baseline_version": 9, "domain_placeholder": "__SLI_REPORT_DOMAIN__",
        "files": {"baseline.sql": hashlib.sha256(schema.read_bytes()).hexdigest(),
                  "roles.sql": hashlib.sha256(roles.read_bytes()).hexdigest()},
        "migrations": {"9": hashlib.sha256((source / "config/postgres_migrations/009_domain.sql").read_bytes()).hexdigest()},
    }))
    put(source, "deploy/linux/native_pg_ledger.json", json.dumps(inventory.build_manifest(source)))
    rows = inventory.expected_ledger(source)
    put(source, "tests/fixtures/native_docker_ledger.txt",
        "".join(f"{r['version']}|{r['name']}|{r['sha256']}\n" for r in rows))
    with rules.open("a", encoding="utf-8") as handle:
        handle.write('''
[[replace]]
paths = ["config/postgres_migrations/*.sql"]
pattern_id = "old_domain"
to = "example.test"
''')
    return rows


def test_public_genesis_repins_forward_rollback_and_baseline_without_adopting_private_ledger(mini, tmp_path):
    from deploy.linux import native_pg_inventory as inventory
    from scripts.maintenance import existing_postgres_bootstrap as bootstrap
    private_rows = add_sql(mini)
    source = mini[0]
    original = (source / "config/postgres_migrations/009_domain.sql").read_bytes()
    result = build(mini, tmp_path / "public")
    public = tmp_path / "public"
    assert result["sql"]["status"] == "verified"
    assert (source / "config/postgres_migrations/009_domain.sql").read_bytes() == original
    assert (public / "config/postgres_migrations/009_domain.rollback.sql").read_text() == "SELECT 'example.test';\n"
    inventory.verify_manifest(public, json.loads((public / "deploy/linux/native_pg_ledger.json").read_text()))
    migrations = bootstrap.forward_migration_inventory(public / "config/postgres_migrations")
    baseline = bootstrap.load_baseline(public / "config/postgres_baseline", migrations)
    rendered = bootstrap.render_baseline_schema(baseline, "installation.example.invalid", tmp_path / "rendered.sql")
    assert rendered.read_text() == "SELECT 'installation.example.invalid';\n"
    with pytest.raises(ValueError, match="checksum"):
        inventory.verify_ledger(private_rows, inventory.expected_ledger(public), root=public)
    ledger = [line.split("|") for line in (public / "tests/fixtures/native_docker_ledger.txt").read_text().splitlines()]
    assert ledger[1][2] == hashlib.sha256((public / "config/postgres_migrations/009_domain.sql").read_bytes()).hexdigest()
    with (public / "config/postgres_migrations/009_domain.sql").open("a") as handle:
        handle.write("-- drift\n")
    with pytest.raises(ValueError, match="inventory_mismatch"):
        inventory.verify_manifest(public, json.loads((public / "deploy/linux/native_pg_ledger.json").read_text()))


def test_source_sql_drift_is_rejected_before_public_repinned_hashes(mini, tmp_path):
    add_sql(mini)
    with (mini[0] / "config/postgres_migrations/009_domain.sql").open("a") as handle:
        handle.write("-- unreviewed SQL\n")
    with pytest.raises(SnapshotError, match="source_sql_inventory_invalid"):
        build(mini, tmp_path / "public")


def test_commit_export_and_directory_export_have_identical_files(mini, tmp_path, monkeypatch):
    """Exercise the archive branch without initializing or modifying any Git repo."""
    source, rules, values = mini
    put(source, ".env", "must never enter Git's exported archive")
    def fake_git(repo, *args):
        if args[0] == "rev-parse":
            assert "--end-of-options" in args
            return b"a" * 40 + b"\n"
        if args[0] == "ls-tree":
            return b"\0".join(p.relative_to(source).as_posix().encode()
                               for p in source.rglob("*") if p.is_file()) + b"\0"
        assert args[0] == "archive"
        assert "--" in args, "export only admitted paths, never the entire tree"
        admitted = args[args.index("--") + 1:]
        assert ".env" not in admitted, "Git must not read blocked files into a temporary tar"
        archive_path = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--output="))
        with tarfile.open(archive_path, "w") as archive:
            for path in sorted(source.rglob("*")):
                if path.is_file() and path.relative_to(source).as_posix() in admitted:
                    data = path.read_bytes()
                    member = tarfile.TarInfo(path.relative_to(source).as_posix())
                    member.size = len(data)
                    member.mode = 0o644
                    archive.addfile(member, io.BytesIO(data))
        return b""
    monkeypatch.setattr(subject, "git", fake_git)
    make_snapshot("main", tmp_path / "commit", rules=rules, sensitive_values=values, repo=source)
    build(mini, tmp_path / "directory")
    assert {p.relative_to(tmp_path / "commit").as_posix(): p.read_bytes()
            for p in (tmp_path / "commit").rglob("*") if p.is_file()} == {
        p.relative_to(tmp_path / "directory").as_posix(): p.read_bytes()
        for p in (tmp_path / "directory").rglob("*") if p.is_file()}


def test_secret_names_and_dependency_trees_are_never_read(mini, tmp_path, monkeypatch):
    source = mini[0]
    secrets = {put(source, name, "Secret Person") for name in (
        ".env", ".env.example", "config/private.key", "config/private.pem", "node_modules/private.json")}
    read = Path.read_bytes
    def guarded_read(path):
        assert path not in secrets, "blocked inputs must not be opened"
        return read(path)
    monkeypatch.setattr(Path, "read_bytes", guarded_read)
    build(mini, tmp_path / "public")
    assert not (tmp_path / "public/config").exists()


def test_directory_reparse_point_is_rejected_before_reading(mini, tmp_path, monkeypatch):
    link = put(mini[0], "link.txt", "unreadable target")
    original = subject.is_link
    # Model Windows reparse metadata without requiring administrator link privileges.
    monkeypatch.setattr(subject, "is_link", lambda path: path == link or original(path))
    with pytest.raises(SnapshotError, match="source_symlink"):
        build(mini, tmp_path / "public")
