import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from scripts.maintenance.github_sanitary_check import FORBIDDEN_PATTERNS_ENV, PROJECT_ROOT, main, scan


def _types(result: dict[str, object]) -> set[str]:
    return {str(item["type"]) for item in result["findings"]}  # type: ignore[index]


@pytest.mark.parametrize("git_state", ["unavailable", "failed", "no_repository"])
def test_filesystem_fallback_prunes_dependencies_before_descent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_state: str,
) -> None:
    from scripts.maintenance import github_sanitary_check as sanitary

    if git_state != "no_repository":
        (tmp_path / ".git").write_text("gitdir: /missing/worktree\n", encoding="utf-8")

    def run_git(*args, **kwargs):
        assert git_state != "no_repository"
        if git_state == "unavailable":
            raise FileNotFoundError("git")
        return subprocess.CompletedProcess(args[0], 128, stdout="", stderr="")

    monkeypatch.setattr(sanitary.subprocess, "run", run_git)
    source = tmp_path / "frontend"
    source.mkdir()
    skipped = {source / name for name in sanitary.SKIP_DIRS}
    for directory in skipped:
        directory.mkdir()
        (directory / "unreadable.txt").write_text("ignored\n", encoding="utf-8")

    original_scandir = sanitary.os.scandir

    def guarded_scandir(path):
        assert Path(path) not in skipped, "excluded directories must never be traversed"
        return original_scandir(path)

    monkeypatch.setattr(sanitary.os, "scandir", guarded_scandir)
    (source / "source.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "untracked.txt").write_text("token=github_pat_" + "A" * 30, encoding="utf-8")
    artifacts = tmp_path / "artifacts/t03-restore-drill/20261008T214126Z"
    artifacts.mkdir(parents=True)
    for name in ("result.json", "source-inventory.json"):
        (artifacts / name).write_text("{}\n", encoding="utf-8")

    result = scan(tmp_path)

    assert result["files_scanned"] == 4
    assert {"github_token", "forbidden_root"} == _types(result)
    assert {item["path"] for item in result["findings"]} == {
        "untracked.txt",
        "artifacts/t03-restore-drill/20261008T214126Z/result.json",
        "artifacts/t03-restore-drill/20261008T214126Z/source-inventory.json",
    }


def test_safe_example_baseline_passes(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("host=dc01.example.invalid\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text(
        "ADLOG_PG_DSN=postgresql://example_user:example_password@127.0.0.1/example_db\n",
        encoding="utf-8",
    )

    assert scan(tmp_path)["status"] == "ok"


def test_archive_is_rejected_even_in_a_source_directory(tmp_path: Path) -> None:
    path = tmp_path / "source" / "export.zip"
    path.parent.mkdir()
    path.write_bytes(b"synthetic archive")
    assert "forbidden_extension" in _types(scan(tmp_path))


def test_pinned_container_image_version_is_not_treated_as_an_ip(tmp_path: Path) -> None:
    (tmp_path / "runtime.py").write_text(
        'IMAGE = "clickhouse/clickhouse-server:25.8.28.1"\n',
        encoding="utf-8",
    )

    assert scan(tmp_path)["status"] == "ok"


def test_native_pin_versions_are_not_addresses_only_in_the_pins_file(tmp_path: Path) -> None:
    line = '{"version": "26.8.35.10", "constraint": "zlib1g >= 1:1.2.3.4", "other": "0.99.7.1"}\n'
    pins = tmp_path / "deploy" / "linux"
    pins.mkdir(parents=True)
    (pins / "native_pins.json").write_text(line, encoding="utf-8")
    assert scan(tmp_path)["status"] == "ok"
    # The same numbers anywhere else are still treated as addresses.
    (pins / "native_pins.json").unlink()
    (tmp_path / "notes.json").write_text(line, encoding="utf-8")
    assert "non_documentation_ip" in _types(scan(tmp_path))


@pytest.mark.parametrize("line", [
    '"version": "5.6.3.6.20240818",',
    '"filename": "fixture-5.6.3.6.20240818-py3-none-any.whl",',
    '"source": "https://pypi.org/project/diskcache-stubs/5.6.3.6.20240818/",',
    '"url": "https://files.pythonhosted.org/packages/aa/bb/cc/fixture-5.6.3.6.20240818-py3-none-any.whl",',
    '"diskcache-stubs (>=5.6.3.6.20240818,<6.0.0.0.0)",',
    '"types-pyyaml (>=6.0.12.20250915,<7.0.0.0)",',
    '"brotlicffi>=1.2.0.0; (platform_python_implementation != \'CPython\') and extra == \'brotli\'",',
])
def test_sigma_software_versions_are_not_ip_addresses(tmp_path: Path, line: str) -> None:
    manifest = tmp_path / "config/sigma/software-manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(line + "\n", encoding="utf-8")

    assert scan(tmp_path)["status"] == "ok"

    # The same text outside the software manifest gets no exception.
    (tmp_path / "config/other.json").write_text(line + "\n", encoding="utf-8")
    assert {item["path"] for item in scan(tmp_path)["findings"]} == {"config/other.json"}


@pytest.mark.parametrize("line", [
    '"host": "10.1.2.3",',
    '"source": "https://10.1.2.3/project/fixture/5.6.3.6/",',
    '"source": "https://pypi.org/project/10.1.2.3/5.6.3.6/",',
    '"source": "https://pypi.org/project/fixture/5.6.3.6/?host=10.1.2.3",',
    '"url": "https://10.1.2.3/packages/aa/bb/cc/fixture-5.6.3.6-py3-none-any.whl",',
    '"url": "https://files.pythonhosted.org/packages/aa/bb/cc/fixture-5.6.3.6-py3-none-any.whl?host=10.1.2.3",',
    '"fixture>=1.2.0.0; extra == \'10.1.2.3\'",',
    '"fixture @ https://10.1.2.3/package",',
    '"fixture>=1.2.0.0,host=10.1.2.3",',
    '"fixture>=1.2.0.0; token=github_pat_' + "A" * 30 + '",',
])
def test_sigma_version_exception_keeps_other_values_scanned(tmp_path: Path, line: str) -> None:
    manifest = tmp_path / "config/sigma/software-manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(line + "\n", encoding="utf-8")

    assert scan(tmp_path)["status"] == "failed"


@pytest.mark.parametrize("name", ["software-manifest.json", "requirements.lock.txt"])
def test_pinned_sigma_software_manifest_passes_sanitation(tmp_path: Path, name: str) -> None:
    relative = Path("config/sigma") / name
    manifest = tmp_path / relative
    manifest.parent.mkdir(parents=True)
    manifest.write_bytes((PROJECT_ROOT / relative).read_bytes())

    assert scan(tmp_path)["status"] == "ok"


def test_sigma_requirements_exception_requires_a_hash_pin(tmp_path: Path) -> None:
    lock = tmp_path / "config/sigma/requirements.lock.txt"
    lock.parent.mkdir(parents=True)
    lock.write_text("fixture==5.6.3.6.20240818 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")
    assert scan(tmp_path)["status"] == "ok"

    lock.write_text("fixture==5.6.3.6.20240818\n", encoding="utf-8")
    assert _types(scan(tmp_path)) == {"non_documentation_ip"}

    lock.write_text("host=10.1.2.3\n", encoding="utf-8")
    assert _types(scan(tmp_path)) == {"non_documentation_ip"}


def test_secret_private_ip_and_archive_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "config.txt").write_text(
        "token=" + "github_pat_" + "A" * 30 + "\nhost=" + "10" + ".1.2.3\n",
        encoding="utf-8",
    )
    archive = tmp_path / "archive"
    archive.mkdir()
    (archive / "note.txt").write_text("generated evidence\n", encoding="utf-8")

    result = scan(tmp_path)

    assert result["status"] == "failed"
    assert {"github_token", "non_documentation_ip", "forbidden_root"} <= _types(result)


def test_radius_contract_rejects_internal_endpoints_and_private_addresses(
    tmp_path: Path,
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    route = config / "stage10_radius_collection_routes_v1.json"
    route.write_text(
        "source_name=radius-example" + ".internal\nowner_confirmed_ip=10.1.2." + "3\n",
        encoding="utf-8",
    )

    assert {"internal_domain", "non_documentation_ip"} <= _types(scan(tmp_path))

    route.write_text("token=github_pat_" + "A" * 30 + "\n", encoding="utf-8")
    assert "github_token" in _types(scan(tmp_path))


def test_historical_migrations_reject_internal_domains_but_allow_demo_domains(tmp_path: Path) -> None:
    migrations = tmp_path / "config/postgres_migrations"
    migrations.mkdir(parents=True)
    migration = migrations / "100_history.sql"
    migration.write_text("example.local DC01.EXAMPLE.LOCAL\n", encoding="utf-8")
    assert scan(tmp_path)["status"] == "ok"
    migration.write_text("example.local tenant.internal\n", encoding="utf-8")
    assert _types(scan(tmp_path)) == {"internal_domain"}


def test_internal_cli_attribute_is_not_treated_as_an_internal_domain(
    tmp_path: Path,
) -> None:
    (tmp_path / "cli.py").write_text("if args.internal:\n    pass\n", encoding="utf-8")
    (tmp_path / "host.txt").write_text("host=radius-live" + ".internal\n", encoding="utf-8")

    result = scan(tmp_path)

    assert _types(result) == {"internal_domain"}


def test_approved_product_domain_is_allowed_but_other_internal_domains_fail(
    tmp_path: Path,
) -> None:
    (tmp_path / "product.txt").write_text(
        "report=example.test\nhost=dc1.example.test\n",
        encoding="utf-8",
    )

    assert scan(tmp_path)["status"] == "ok"

    (tmp_path / "other.txt").write_text("host=other" + ".internal\n", encoding="utf-8")
    assert "internal_domain" in _types(scan(tmp_path))


def test_synthetic_test_data_allows_infrastructure_literals_but_not_tokens(
    tmp_path: Path,
) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    fixture = tests / "fixture.json"
    fixture.write_text(
        '{"host":"dc01.corp","ip":"10.1.2.3","sid":"S-1-5-21-1-2-3-4"}\n',
        encoding="utf-8",
    )

    assert scan(tmp_path)["status"] == "ok"

    fixture.write_text("token=github_pat_" + "A" * 30 + "\n", encoding="utf-8")
    assert "github_token" in _types(scan(tmp_path))


def test_gitignored_local_evidence_does_not_change_github_source_baseline(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text("artifacts/\n", encoding="utf-8")
    artifact = tmp_path / "artifacts"
    artifact.mkdir()
    (artifact / "local-evidence.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("safe\n", encoding="utf-8")

    assert scan(tmp_path)["status"] == "ok"

    (tmp_path / "untracked.txt").write_text("token=github_pat_" + "A" * 30, encoding="utf-8")
    assert "github_token" in _types(scan(tmp_path))


@pytest.mark.parametrize("filename", [
    "pyyaml-6.0.3-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl",
    "requests-2.34.2-py3-none-any.whl",
    "types_pyyaml-6.0.12.20260906-py3-none-any.whl",
    "typing_extensions-4.16.0-py3-none-any.whl",
    "urllib3-2.8.0-py3-none-any.whl",
])
def test_sigma_wheels_in_artifacts_fail_filesystem_sanitation(
    tmp_path: Path, filename: str,
) -> None:
    relative = Path("artifacts/sigma01/wheels") / filename
    wheel = tmp_path / relative
    wheel.parent.mkdir(parents=True)
    wheel.write_bytes(b"synthetic wheel fixture")

    result = scan(tmp_path)

    assert result["status"] == "failed"
    assert result["findings"] == [
        {"path": relative.as_posix(), "line": 0, "type": "forbidden_root"},
    ]


def test_git_archive_gate_scans_the_tracked_working_tree(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    archive = tmp_path / "tracked-source.tar"
    result = subprocess.run(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    archive.write_bytes(result.stdout)
    with tarfile.open(archive) as contents:
        contents.extractall(tmp_path / "tracked-source", filter="data")

    # A policy change and its sanitized files are tested together before commit.
    changed = subprocess.run(
        ["git", "diff", "HEAD", "--name-only", "--no-renames", "-z"],
        cwd=root, check=True, capture_output=True,
    )
    for relative in changed.stdout.decode("utf-8").split("\0"):
        if not relative:
            continue
        source = root / relative
        destination = tmp_path / "tracked-source" / relative
        if source.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        else:
            destination.unlink(missing_ok=True)

    assert scan(tmp_path / "tracked-source")["status"] == "ok"


@pytest.mark.parametrize("via_environment", [False, True])
def test_external_patterns_scan_migrations_and_fixtures_regardless_of_suffix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], via_environment: bool,
) -> None:
    root = tmp_path / "source"
    migration = root / "config/postgres_migrations/100_example.sql"
    fixture = root / "tests/fixtures/example.xml.snapshot"
    for path in (migration, fixture):
        path.parent.mkdir(parents=True)
    migration.write_text("select 'DemoMarker-123';\n", encoding="utf-8")
    fixture.write_text("DEMOMARKER-456 demomarker-789\n", encoding="utf-16")
    fixture.with_name("utf16-no-bom.fixture").write_text("demomarker-135\n", encoding="utf-16-le")
    (root / "binary.bin").write_bytes(b"\0random\0DemoMarker-777")
    patterns = tmp_path / "patterns.regex"
    patterns.write_text("# external publication patterns\n\ndemomarker-[0-9]+\n", encoding="utf-8-sig")

    assert scan(root)["status"] == "ok"
    argv = ["sanitary", "--root", str(root), "--json"]
    if via_environment:
        monkeypatch.setenv(FORBIDDEN_PATTERNS_ENV, str(patterns))
    else:
        monkeypatch.setenv(FORBIDDEN_PATTERNS_ENV, str(tmp_path / "absent.regex"))
        argv.extend(("--forbidden-patterns", str(patterns)))
    monkeypatch.setattr("sys.argv", argv)

    assert main() == 1
    output = capsys.readouterr().out
    assert "demomarker" not in output.casefold()
    assert json.loads(output)["findings"] == [
        {"path": migration.relative_to(root).as_posix(), "line": 1, "type": "forbidden_pattern", "pattern_line": 3},
        *[{"path": fixture.relative_to(root).as_posix(), "line": 1, "type": "forbidden_pattern", "pattern_line": 3}] * 2,
        {"path": "tests/fixtures/utf16-no-bom.fixture", "line": 1, "type": "forbidden_pattern", "pattern_line": 3},
    ]


@pytest.mark.parametrize("contents", ["# no patterns\n", "invalid-sensitive-source[\n", None])
def test_bad_external_pattern_file_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], contents: str | None,
) -> None:
    patterns = tmp_path / "patterns.regex"
    if contents is not None:
        patterns.write_text(contents, encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["sanitary", "--root", str(tmp_path), "--forbidden-patterns", str(patterns)])

    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 2
    assert "invalid-sensitive-source" not in capsys.readouterr().err
