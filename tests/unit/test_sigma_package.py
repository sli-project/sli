from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from uuid import UUID
from zipfile import ZipFile

import pytest
from packaging.requirements import Requirement
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

from scripts.dev import verify_sigma_package as sigma_package


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


@pytest.fixture
def package(tmp_path):
    """A local, synthetic 25-rule archive with no real authors or telemetry."""
    pytest.importorskip("sigma.collection", reason="Install the optional config/sigma/requirements.lock.txt")
    config = tmp_path / "config"
    shutil.copytree(sigma_package.CONFIG, config)
    lock, profile = sigma_package.load_config(config)
    root = lock["upstream"]["archive"]["root"]
    members = {f"{root}/LICENSE": b"Synthetic upstream license notice"}
    lock["upstream"]["license"]["sha256"] = digest(members[f"{root}/LICENSE"])
    for index, entry in enumerate(lock["rules"]):
        rule_id = str(UUID(int=index + 1))
        entry["id"] = rule_id
        profile["rules"][index]["id"] = rule_id
        raw = (
            f"title: Synthetic fixture\nid: {rule_id}\nauthor: Fixture Team\n"
            "logsource:\n  product: windows\n  service: security\n"
            "detection:\n  selection:\n    EventID: 1\n"
            "  filter_main_fixture:\n    EventID: 2\n"
            "  condition: selection and not 1 of filter_main_*\n"
            "level: low\n"
        ).encode()
        entry["sha256"] = digest(raw)
        members[f"{root}/{entry['path']}"] = raw
    write_json(config / lock["profile"]["path"], profile)
    lock["profile"]["sha256"] = digest((config / lock["profile"]["path"]).read_bytes())
    archive = tmp_path / "package.zip"

    def save():
        with ZipFile(archive, "w") as zipped:
            for name, raw in members.items():
                zipped.writestr(name, raw)
        lock["upstream"]["archive"]["sha256"] = digest(archive.read_bytes())
        write_json(config / "lock.json", lock)

    save()
    return config, archive, lock, members, save


def test_profile_is_the_reviewed_selection():
    lock, profile = sigma_package.load_config()
    assert lock["upstream"]["commit"] == "7d8b152a5fc062ebd309f62ae4d8276aca2786af"
    assert lock["parser"]["version"] == "1.3.3"
    assert len(profile["rules"]) == 25
    assert profile["rules"][0]["id"] == "d99b79d2-0a6f-4f46-ad8b-260b6e17f982"
    assert profile["rules"][-1]["id"] == "1d61f71d-59d2-479e-9562-4ff5f4ead16b"
    paths = [entry["path"] for entry in lock["rules"]]
    assert sum("/builtin/security/" in path for path in paths) == 16
    assert sum("/process_creation/" in path for path in paths) == 7
    assert sum("/builtin/system/" in path for path in paths) == 2


def test_software_lock_is_complete_compatible_and_hash_pinned():
    lock, _ = sigma_package.load_config()
    software = json.loads((sigma_package.CONFIG / lock["parser"]["software_manifest_path"]).read_bytes())
    assert software["target"]["python"] == "3.14.6"
    assert software["target"]["system"] == "Linux"
    assert software["backends"] == software["pipelines"] == []
    packages = {canonicalize_name(pkg["name"]): pkg for pkg in software["packages"]}
    # Newer pyparsing 3.3.3 breaks pySigma's compound-condition postprocessing.
    assert packages["pyparsing"]["version"] == "3.2.5"
    lines = (sigma_package.CONFIG / lock["parser"]["requirements_path"]).read_text().splitlines()
    expected = {
        f"{pkg['name']}=={pkg['version']} --hash=sha256:{pkg['artifact']['sha256']}"
        for pkg in packages.values()
    }
    assert {line for line in lines if line and not line.startswith("#")} == expected
    tags = set(sys_tags())
    for pkg in packages.values():
        assert pkg["license"]
        assert len(pkg["artifact"]["sha256"]) == 64
        assert Version("3.14.6") in Requirement(f"python{pkg['requires_python']}").specifier
        assert parse_wheel_filename(pkg["artifact"]["filename"])[3] & tags
        for value in pkg["requires_dist"]:
            requirement = Requirement(value)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                dependency = packages[canonicalize_name(requirement.name)]
                assert Version(dependency["version"]) in requirement.specifier
    runtime = sigma_package.CONFIG.parents[1] / "requirements.lock.txt"
    for line in runtime.read_text().splitlines():
        if line and not line.startswith("#"):
            requirement = Requirement(line)
            if canonicalize_name(requirement.name) in packages:
                assert Version(packages[canonicalize_name(requirement.name)]["version"]) in requirement.specifier


def test_synthetic_package_preserves_original_bytes_and_attribution(package):
    config, archive, lock, members, _ = package
    before = archive.read_bytes()
    rules = sigma_package.verify_package(archive, config)
    assert len(rules) == 25
    assert [rule.id for rule in rules] == [entry["id"] for entry in lock["rules"]]
    for rule, entry in zip(rules, lock["rules"]):
        assert rule.raw_yaml == members[f"{lock['upstream']['archive']['root']}/{entry['path']}"]
        assert rule.author == "Fixture Team"
        assert rule.source_uri == entry["source_uri"]
        assert rule.license == "DRL-1.1"
        assert rule.upstream_commit == lock["upstream"]["commit"]
        assert "Fixture Team" not in repr(rule)
    assert archive.read_bytes() == before


def test_archive_hash_is_checked_before_opening_zip(package):
    config, archive, _, _, _ = package
    archive.write_bytes(b"not a zip")
    with pytest.raises(sigma_package.PackageError, match="SHA-256"):
        sigma_package.verify_package(archive, config)


@pytest.mark.parametrize("target", ["profile-history-25.json", "requirements.lock.txt", "software-manifest.json", "licenses/DRL-1.1.txt", "licenses/LGPL-2.1.txt"])
def test_local_metadata_and_license_tampering_is_rejected(package, target):
    config, archive, _, _, _ = package
    with (config / target).open("ab") as changed:
        changed.write(b"changed")
    with pytest.raises(sigma_package.PackageError, match="SHA-256"):
        sigma_package.verify_package(archive, config)


@pytest.mark.parametrize("change", ["rule_hash", "uuid", "condition", "author", "yaml_tag", "license", "missing"])
def test_invalid_rule_is_rejected(package, change):
    config, archive, lock, members, save = package
    entry = lock["rules"][0]
    name = f"{lock['upstream']['archive']['root']}/{entry['path']}"
    if change == "missing":
        del members[name]
    else:
        raw = members[name]
        if change == "uuid":
            raw = raw.replace(entry["id"].encode(), str(UUID(int=99)).encode())
        elif change == "condition":
            raw = raw.replace(b"condition: selection", b"condition: missing_selection")
        elif change == "author":
            raw = raw.replace(b"author: Fixture Team\n", b"")
        elif change == "yaml_tag":
            raw = b"!!python/object:synthetic {}"
        elif change == "license":
            raw += b"license: MIT\n"
        else:
            raw += b"# changed\n"
        members[name] = raw
        if change != "rule_hash":
            entry["sha256"] = digest(raw)
    save()
    with pytest.raises(sigma_package.PackageError):
        sigma_package.verify_package(archive, config)


@pytest.mark.parametrize("change", ["duplicate_id", "duplicate_path", "profile", "source_uri", "upstream_license", "rule_license", "path", "parser"])
def test_manifest_mismatch_is_rejected(package, change, monkeypatch):
    config, archive, lock, _, save = package
    if change == "duplicate_id":
        lock["rules"][1]["id"] = lock["rules"][0]["id"]
    elif change == "duplicate_path":
        lock["rules"][1]["path"] = lock["rules"][0]["path"]
    elif change == "profile":
        lock["rules"] = list(reversed(lock["rules"]))
    elif change == "source_uri":
        lock["rules"][0]["source_uri"] = "https://example.invalid/unpinned"
    elif change == "upstream_license":
        lock["upstream"]["license"]["id"] = "MIT"
    elif change == "rule_license":
        lock["rules"][0]["license"] = "MIT"
    elif change == "path":
        lock["rules"][0]["path"] = "../outside.yml"
    else:
        monkeypatch.setattr(sigma_package, "version", lambda _: "0.0.0")
    save()
    with pytest.raises(sigma_package.PackageError):
        sigma_package.verify_package(archive, config)


def test_cli_failure_does_not_disclose_parser_metadata(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["verify", "--archive", "synthetic.zip"])

    def fail(_):
        raise ValueError("Fixture Team: internal rule values")

    monkeypatch.setattr(sigma_package, "verify_package", fail)
    assert sigma_package.main() == 1
    assert capsys.readouterr().out == "Sigma stage 01: FAILED (package, manifest or parser mismatch)\n"


def test_all_25_original_pinned_yaml_files():
    archive = os.environ.get("SLI_SIGMA_ARCHIVE")
    if not archive:
        pytest.skip("Set SLI_SIGMA_ARCHIVE to the separately obtained pinned ZIP")
    rules = sigma_package.verify_package(Path(archive))
    assert len(rules) == len({rule.id for rule in rules}) == 25
