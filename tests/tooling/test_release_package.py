from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import struct
import subprocess
import sys
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@pytest.fixture
def signed_package(tmp_path):
    key = Ed25519PrivateKey.generate()
    trust = tmp_path / "trust.json"
    trust.write_bytes(canonical({"schema_version": 1, "keys": [{
        "key_id": "test-only", "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "package_ids": ["sli.core", "sli.remote-access"], "revoked": False,
    }]}))

    def create(*, files=None, edits=None, extra=None, signature_edits=None):
        files = files if files is not None else {"server/example.py": b"raise RuntimeError('must never execute')\n"}
        manifest = {
            "schema_version": 1, "package_type": "core-install", "package_id": "sli.core",
            "version": "1.0.0", "platform": "windows-x64", "source_commit": "a" * 40,
            "build_id": "synthetic-1", "minimum_updater": 1,
            "compatibility": {"core_api": 1, "ui_api": 1, "from_version": None},
            "migrations": [], "deletions": [], "restart_profile": "none",
            "files": [{"path": p, "size": len(b), "sha256": hashlib.sha256(b).hexdigest()} for p, b in sorted(files.items())],
        }
        manifest.update(edits or {})
        raw = canonical(manifest)
        signature = {"algorithm": "ed25519", "key_id": "test-only", "signature": base64.b64encode(key.sign(b"SLI-RELEASE-V1\x00" + raw)).decode()}
        signature.update(signature_edits or {})
        archive = tmp_path / "release.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("SLI_RELEASE.json", raw)
            z.writestr("SLI_SIGNATURE.json", canonical(signature))
            for path, body in files.items():
                z.writestr("payload/" + path, body)
            for path, body in extra or []:
                z.writestr(path, body)
        return archive, trust

    return create


def verify(archive, trust, **kwargs):
    from deploy.linux.release_package import verify_package

    return verify_package(archive, trust, **kwargs)


@pytest.mark.parametrize("module_name", [
    "deploy.linux.release_package",
])
def test_verifies_real_signature_without_executing_payload(signed_package, tmp_path, module_name):
    from importlib import import_module

    archive, trust = signed_package()
    before = set(tmp_path.iterdir())
    result = import_module(module_name).verify_package(archive, trust)
    assert result.manifest["package_id"] == "sli.core"
    assert result.archive_sha256 == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("module_name", [
    "deploy.linux.release_package",
])
@pytest.mark.parametrize("component,kind,owner,restart", [
    ("server", "core-install", "sli.core", "docker-compose"),
    ("server", "core-update", "sli.core", "docker-compose"),
    ("agent", "plugin-update", "sli.agent", "none"),
    ("updater", "plugin-update", "sli.updater", "none"),
    ("plugin", "plugin-update", "sli.remote-access", "plugin-only"),
])
def test_v2_component_contracts_coexist(component, kind, owner, restart, module_name):
    from importlib import import_module

    package = import_module(module_name)

    previous = None if kind == "core-install" else "1.0.0"
    manifest = {
        "schema_version": 2, "component": component, "package_type": kind, "package_id": owner,
        "version": "1.1.0", "from_version": previous, "to_version": "1.1.0",
        "platform": "linux-amd64", "source_commit": "a" * 40, "build_id": "synthetic-1",
        "minimum_updater": 1, "required_free_disk": 1024, "migrations": {}, "deletions": [],
        "restart_profile": restart, "image": None, "compose_delta": None, "config_delta": None,
        "compatibility": {"core_api": 1, "ui_api": 1, "from_version": previous,
                          "min_version": "1.0.0", "max_version": "1.0.0",
                          "os": "linux", "architecture": "amd64"},
    }
    paths = ["backend/agent.py"]
    if component == "server":
        paths = ["image.tar"]
        manifest["image"] = {"path": "image.tar", "digest": "sha256:" + "a" * 64}
    elif component == "updater":
        paths = sorted(package.UPDATER_CLOSURE_FILES)
        manifest["from_version"] = "1.0.1"
        manifest["compatibility"].update(
            from_version="1.0.1", min_version="1.0.1", max_version="1.0.1",
        )
    elif component == "plugin":
        paths = ["backend/registration.py", "backend/jobs-v3.json", "ui/descriptor.json"]
        manifest.update(plugin_id=owner, plugin_version="1.1.0", handlers=["radius-acquisition"],
                        core_api={"minimum": "1.0.0", "maximum_exclusive": "2.0.0"},
                        ui_api={"minimum": "1.0.0", "maximum_exclusive": "2.0.0"})
    manifest["files"] = [{"path": path, "size": 1, "sha256": "a" * 64} for path in paths]
    package.validate_manifest(manifest, package.PackageLimits())
    with pytest.raises(package.PackageError, match="update_component_mismatch"):
        package.validate_manifest(dict(manifest, restart_profile="invalid"), package.PackageLimits())


@pytest.mark.parametrize("module_name", [
    "deploy.linux.release_package",
])
@pytest.mark.parametrize("installed_edits,error", [
    ({}, None),
    ({"plugin_id": "sli.other"}, "update_component_mismatch"),
    ({"core_api": "2.0.0"}, "update_plugin_api_incompatible"),
    ({"ui_api": "0.9.0"}, "update_plugin_api_incompatible"),
    ({"migrations": {"config/postgres_migrations/001_synthetic.sql": "a" * 64}},
     "update_plugin_migration_requires_core_maintenance"),
])
def test_signed_plugin_update_checks_installed_identity_apis_and_migrations(
    signed_package, module_name, installed_edits, error,
):
    from importlib import import_module

    package = import_module(module_name)
    archive, trust = signed_package(
        files={"backend/registration.py": b"x", "backend/jobs-v3.json": b"{}", "ui/descriptor.json": b"{}"},
        edits={
            "schema_version": 2, "component": "plugin", "package_type": "plugin-update",
            "package_id": "sli.remote-access", "version": "1.1.0", "platform": "linux-amd64",
            "from_version": "1.0.0", "to_version": "1.1.0", "required_free_disk": 1024,
            "migrations": {}, "restart_profile": "plugin-only",
            "image": None, "compose_delta": None, "config_delta": None,
            "plugin_id": "sli.remote-access", "plugin_version": "1.1.0",
            "handlers": ["radius-acquisition"],
            "core_api": {"minimum": "1.0.0", "maximum_exclusive": "2.0.0"},
            "ui_api": {"minimum": "1.0.0", "maximum_exclusive": "2.0.0"},
            "compatibility": {
                "core_api": 1, "ui_api": 1, "from_version": "1.0.0",
                "min_version": "1.0.0", "max_version": "1.0.0", "os": "linux", "architecture": "amd64",
            },
        },
    )
    installed = {
        "component": "plugin", "plugin_id": "sli.remote-access", "version": "1.0.0",
        "os": "linux", "architecture": "amd64", "core_api": "1.0.0", "ui_api": "1.0.0",
        "migrations": {}, **installed_edits,
    }
    if error:
        with pytest.raises(package.PackageError, match=error):
            package.verify_package(archive, trust, installed=installed, free_bytes=4096, component="plugin")
    else:
        verified = package.verify_package(archive, trust, installed=installed, free_bytes=4096, component="plugin")
        assert verified.manifest["plugin_version"] == "1.1.0"
        assert verified.summary()["installed"] is False


@pytest.mark.parametrize("path", [
    "../outside.py", "/absolute.py", "C:/evil.py", "a\\evil.py", "a//b.py",
    "a/./b.py", "a/b.py:stream", "a/CON.txt", "a/NUL", "a/LPT9.py", "a/COM1.py",
    "a/trailing. ", "a/space ", "a/CONIN$.txt", "a/COM¹.txt", "a/?.py",
])
def test_rejects_windows_ambiguous_paths(signed_package, path):
    archive, trust = signed_package(files={path: b"bad"})
    with pytest.raises(ValueError):
        verify(archive, trust)


@pytest.mark.parametrize("files", [
    {"server/A.py": b"1", "server/a.py": b"2"},
    {"server/x": b"1", "server/x/file.py": b"2"},
    {"server/A/x.py": b"1", "server/a/y.py": b"2"},
])
def test_rejects_case_and_file_directory_aliases(signed_package, files):
    archive, trust = signed_package(files=files)
    with pytest.raises(ValueError):
        verify(archive, trust)


@pytest.mark.parametrize("extra", [
    [("payload/unknown.py", b"x")], [("MANIFEST.json", b"{}")],
    [("payload/server/example.py", b"replaced")], [("folder/SLI_RELEASE.json", b"{}")],
])
@pytest.mark.filterwarnings("ignore:Duplicate name.*:UserWarning")
def test_rejects_unsigned_or_ambiguous_content(signed_package, extra):
    archive, trust = signed_package(extra=extra)
    with pytest.raises(ValueError):
        verify(archive, trust)


def test_rejects_tampered_payload(signed_package):
    archive, trust = signed_package(files={"server/example.py": b"same-size"}, edits={"files": [{"path": "server/example.py", "size": 9, "sha256": "0" * 64}]})
    with pytest.raises(ValueError, match="file hash differs"):
        verify(archive, trust)


@pytest.mark.parametrize("edits", [
    {"schema_version": 2}, {"schema_version": True}, {"package_type": "source"},
    {"source_commit": "abc"}, {"minimum_updater": 2}, {"platform": "unknown"},
    {"install_hook": "run.py"}, {"migrations": ["1.sql"]}, {"deletions": ["server/a.py"]},
    {"restart_profile": "shell"}, {"version": "../1"}, {"files": []},
])
def test_rejects_unsupported_contract(signed_package, edits):
    archive, trust = signed_package(edits=edits)
    with pytest.raises(ValueError):
        verify(archive, trust)


@pytest.mark.parametrize("signature_edits", [
    {"key_id": "unknown"}, {"algorithm": "none"}, {"signature": "bad"},
    {"signature": base64.b64encode(b"0" * 64).decode()},
])
def test_rejects_invalid_signer(signed_package, signature_edits):
    archive, trust = signed_package(signature_edits=signature_edits)
    with pytest.raises(ValueError):
        verify(archive, trust)


@pytest.mark.parametrize("key_edit", [{"revoked": True}, {"package_ids": ["sli.remote-access"]}])
def test_external_key_policy_is_enforced(signed_package, key_edit):
    archive, trust = signed_package()
    data = json.loads(trust.read_bytes())
    data["keys"][0].update(key_edit)
    trust.write_bytes(canonical(data))
    with pytest.raises(ValueError):
        verify(archive, trust)


def test_plugin_cannot_supply_core_files(signed_package):
    archive, trust = signed_package(edits={"package_type": "plugin-install", "package_id": "sli.remote-access"})
    with pytest.raises(ValueError):
        verify(archive, trust)


def test_plugin_payload_has_separate_ownership(signed_package):
    archive, trust = signed_package(files={"backend/plugin.py": b"x", "ui/module.js": b"x"}, edits={
        "package_type": "plugin-install", "package_id": "sli.remote-access",
    })
    assert verify(archive, trust).manifest["package_id"] == "sli.remote-access"


def test_rejects_symlink_archive_entry(signed_package):
    archive, trust = signed_package()
    link = zipfile.ZipInfo("payload/server/link.py")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "a") as z:
        z.writestr(link, "../../outside")
    with pytest.raises(ValueError):
        verify(archive, trust)


def test_limits_archive_before_payload_read(signed_package):
    from deploy.linux.release_package import PackageLimits

    archive, trust = signed_package()
    with pytest.raises(ValueError):
        verify(archive, trust, limits=PackageLimits(max_archive_bytes=1))


def test_unsigned_zip_fails_closed(tmp_path):
    archive = tmp_path / "legacy.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("server/example.py", "print('unsafe')")
    with pytest.raises(ValueError):
        verify(archive, tmp_path / "missing-trust.json")


def test_builder_creates_package_accepted_by_public_verifier(signed_package, tmp_path):
    from deploy.linux.release_package import build_package

    old_archive, trust = signed_package()
    with zipfile.ZipFile(old_archive) as z:
        manifest = json.loads(z.read("SLI_RELEASE.json"))
    root = tmp_path / "input"
    (root / "server").mkdir(parents=True)
    (root / "server/example.py").write_bytes(b"safe = True\n")
    key = Ed25519PrivateKey.generate()
    private = tmp_path / "external.key"
    private.write_bytes(key.private_bytes_raw())
    trust_data = json.loads(trust.read_bytes())
    trust_data["keys"][0]["public_key"] = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    trust.write_bytes(canonical(trust_data))
    output = tmp_path / "built.zip"
    build_package(root, output, manifest, signing_key=private, key_id="test-only")
    assert verify(output, trust).manifest["files"][0]["size"] == 12
    with zipfile.ZipFile(output) as z:
        assert "external.key" not in z.namelist()


def test_invalid_signature_does_not_read_payload(signed_package, monkeypatch):
    archive, trust = signed_package(signature_edits={"signature": base64.b64encode(b"0" * 64).decode()})
    original = zipfile.ZipFile.open

    def guarded(self, name, *args, **kwargs):
        path = name.filename if isinstance(name, zipfile.ZipInfo) else name
        assert not path.startswith("payload/"), "untrusted payload opened before signature"
        return original(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", guarded)
    with pytest.raises(ValueError, match="signature"):
        verify(archive, trust)


def test_count_limit_precedes_zipfile_allocation(signed_package, monkeypatch):
    from deploy.linux.release_package import PackageLimits

    archive, trust = signed_package()
    monkeypatch.setattr(zipfile, "ZipFile", lambda *a, **k: pytest.fail("directory allocated before count bound"))
    with pytest.raises(ValueError, match="entry count"):
        verify(archive, trust, limits=PackageLimits(max_entries=2))


def test_forged_directory_count_is_rejected(signed_package):
    archive, trust = signed_package()
    data = bytearray(archive.read_bytes())
    end = data.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", data, end + 8, 1, 1)
    archive.write_bytes(data)
    with pytest.raises(ValueError, match="entry count"):
        verify(archive, trust)


def test_compression_bomb_is_rejected(signed_package):
    archive, trust = signed_package(files={"server/bomb.py": b"0" * 1000000})
    with pytest.raises(ValueError, match="expansion"):
        verify(archive, trust)


@pytest.mark.parametrize("policy", [
    b'{"schema_version":1,"schema_version":1,"keys":[]}',
    b'{"schema_version":NaN,"keys":[]}',
    b'[]',
])
def test_malformed_external_trust_fails_closed(signed_package, policy):
    archive, trust = signed_package()
    trust.write_bytes(policy)
    with pytest.raises(ValueError):
        verify(archive, trust)


@pytest.mark.parametrize("path", ["config/LOCAL/settings.py", "config/Secrets/key.py",
                                  "scripts/MANUAL_DC_AUDIT/change.ps1", "scripts/DC_CLIENT/change.ps1"])
def test_signed_core_cannot_use_case_alias_to_mutable_or_admin_root(signed_package, path):
    archive, trust = signed_package(files={path: b"x"})
    with pytest.raises(ValueError, match="owned|immutable"):
        verify(archive, trust)


def test_builder_does_not_overwrite_existing_artifact(signed_package, tmp_path):
    from deploy.linux.release_package import build_package

    archive, _trust = signed_package()
    with zipfile.ZipFile(archive) as z:
        metadata = json.loads(z.read("SLI_RELEASE.json"))
    root = tmp_path / "input"
    (root / "server").mkdir(parents=True)
    (root / "server/example.py").write_bytes(b"ok")
    private = tmp_path / "external.key"
    private.write_bytes(Ed25519PrivateKey.generate().private_bytes_raw())
    output = tmp_path / "existing.zip"
    output.write_bytes(b"preserve")
    with pytest.raises(FileExistsError):
        build_package(root, output, metadata, signing_key=private, key_id="test-only")
    assert output.read_bytes() == b"preserve"


def test_builder_rejects_hard_link_to_external_signing_key(signed_package, tmp_path):
    from deploy.linux.release_package import build_package

    archive, _trust = signed_package()
    with zipfile.ZipFile(archive) as z:
        metadata = json.loads(z.read("SLI_RELEASE.json"))
    root = tmp_path / "input"
    (root / "server").mkdir(parents=True)
    private = tmp_path / "external.key"
    private.write_bytes(Ed25519PrivateKey.generate().private_bytes_raw())
    os.link(private, root / "server/example.py")
    output = tmp_path / "must-not-exist.zip"
    with pytest.raises(ValueError, match="hard.link"):
        build_package(root, output, metadata, signing_key=private, key_id="test-only")
    assert not output.exists()
