"""Offline publishing/trust contracts with fakes; no real APT, key or DB changes."""
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import json
import os
from pathlib import Path

import pytest

from deploy.linux import native_apt as apt

pytestmark = pytest.mark.posix_only

FPR = "A" * 40


def key_listing(*fingerprints):
    return "".join("pub:-:255:22:unused::::::::\nfpr:::::::::" + f + ":\nsub:-:::::::::\nfpr:::::::::" + "B" * 40 + ":\n"
                   for f in fingerprints).encode()


@pytest.mark.parametrize("uri", ["https://packages.example.invalid/snapshots/test", "file:/srv/sli/snapshots/test"])
def test_scoped_sources(uri):
    text = apt.source_text(uri)
    assert "Signed-By: /etc/apt/keyrings/sli-archive.gpg\n" in text
    assert "Check-Valid-Until: yes\n" in text
    assert "Components: candidate\n" in text and "Suites: sli-debian13\n" in text
    assert "trusted" not in text.lower()


@pytest.mark.parametrize("uri", ["http://example.invalid", "https://example.invalid\nTrusted: yes",
                               "https://user:password@example.invalid", "file://host/path", "file:relative",
                               "https://example.invalid/?x=1", "https://example.invalid/#fragment"])
def test_unsafe_uri_refused(uri):
    with pytest.raises(ValueError, match="apt_uri_invalid"):
        apt.source_text(uri)


def test_fingerprints_are_exact_and_overlap_is_explicit(monkeypatch):
    calls = []

    def command(argv, **kwargs):
        calls.append(argv)
        return key_listing(FPR, "C" * 40) if "--dry-run" in argv else b"public ring"

    monkeypatch.setattr(apt, "command", command)
    with pytest.raises(ValueError, match="apt_fingerprint_mismatch"):
        apt.public_keyring(b"public", [FPR])
    assert not any("--export" in argv for argv in calls)
    assert apt.public_keyring(b"public", [FPR, "C" * 40]) == b"public ring"
    assert all("--homedir" in argv and "--no-options" in argv for argv in calls)


@pytest.mark.parametrize("listing", [b"sec:-:::::::::\n", b"ssb:-:::::::::\n", b"pub:e:::::::::\n"])
def test_private_or_expired_keys_refused(monkeypatch, listing):
    monkeypatch.setattr(apt, "command", lambda *a, **kw: listing)
    with pytest.raises(ValueError, match="apt_private_key_forbidden|apt_key_unusable"):
        apt.public_keyring(b"key", [FPR])


def test_short_key_id_refused_before_gpg(monkeypatch):
    monkeypatch.setattr(apt, "command", lambda *a, **kw: pytest.fail("unexpected key access"))
    with pytest.raises(ValueError, match="apt_fingerprint_invalid"):
        apt.public_keyring(b"key", ["A" * 16])


@pytest.fixture
def snapshot(tmp_path):
    root = tmp_path / "unsigned"
    dist = root / f"dists/{apt.SUITE}"
    dist.mkdir(parents=True)
    package = root / "pool/test.deb"
    package.parent.mkdir()
    package.write_bytes(b"package")
    manifest = root / "snapshot.json"
    manifest.write_text(json.dumps({"files": {"pool/test.deb": apt.digest(package)}}))
    now = datetime.now(timezone.utc)
    (dist / "Release").write_text(f"X-SLI-Manifest-SHA256: {apt.digest(manifest)}\n"
                                f"Date: {format_datetime(now - timedelta(days=1))}\n"
                                f"Valid-Until: {format_datetime(now + timedelta(days=1))}\n")
    return root


@pytest.mark.parametrize("change", ["package", "manifest", "extra", "symlink", "expiry"])
def test_snapshot_tamper_and_expiry_refused(snapshot, change):
    apt.verify_snapshot(snapshot)
    if change == "package":
        (snapshot / "pool/test.deb").write_bytes(b"tamper")
    elif change == "manifest":
        (snapshot / "snapshot.json").write_text("{}")
    elif change == "extra":
        (snapshot / "private.key").write_text("extra")
    elif change == "symlink":
        (snapshot / "link").symlink_to("pool/test.deb")
    else:
        release = snapshot / f"dists/{apt.SUITE}/Release"
        release.write_text(release.read_text().replace("Valid-Until:", "Old-Until:")
                           + "Valid-Until: Wed, 01 Jan 2020 00:00:00 +0000\n")
    with pytest.raises(ValueError, match="apt_"):
        apt.verify_snapshot(snapshot)


def test_seal_verifies_both_signatures_and_preserves_payload(snapshot, tmp_path, monkeypatch):
    release = snapshot / f"dists/{apt.SUITE}/Release"
    key, inline, detached = (tmp_path / name for name in ("public.gpg", "InRelease", "Release.gpg"))
    for path in (key, inline, detached):
        path.write_bytes(b"public")
    inline.write_bytes(b"-----BEGIN PGP SIGNED MESSAGE-----\n")
    detached.write_bytes(b"-----BEGIN PGP SIGNATURE-----\n")
    monkeypatch.setattr(apt, "public_keyring", lambda *a: b"public")
    calls = []

    def command(argv, **kwargs):
        calls.append(argv)
        if "--output" in argv:
            Path(argv[argv.index("--output") + 1]).write_bytes(release.read_bytes())

    monkeypatch.setattr(apt, "command", command)
    before = apt.inventory(snapshot)
    apt.seal(snapshot, tmp_path / "signed", inline, detached, key, [FPR])
    assert apt.inventory(snapshot) == before
    assert (tmp_path / f"signed/dists/{apt.SUITE}/Release").read_bytes() == release.read_bytes()
    assert len(calls) == 2 and all(argv[0] == "gpgv" for argv in calls)
    with pytest.raises(ValueError, match="apt_output_invalid"):
        apt.seal(snapshot, tmp_path / "signed", inline, detached, key, [FPR])


def test_signature_over_different_release_refused(snapshot, tmp_path, monkeypatch):
    key = tmp_path / "public.gpg"
    key.write_bytes(b"public")
    inline, detached = tmp_path / "InRelease", tmp_path / "Release.gpg"
    inline.write_bytes(b"-----BEGIN PGP SIGNED MESSAGE-----\n")
    detached.write_bytes(b"-----BEGIN PGP SIGNATURE-----\n")
    monkeypatch.setattr(apt, "public_keyring", lambda *a: b"public")

    def command(argv, **kwargs):
        Path(argv[argv.index("--output") + 1]).write_bytes(b"different release")

    monkeypatch.setattr(apt, "command", command)
    output = tmp_path / "signed"
    with pytest.raises(ValueError, match="apt_signed_release_mismatch"):
        apt.seal(snapshot, output, inline, detached, key, [FPR])
    assert not output.exists()


@pytest.mark.parametrize("binary", ["inline", "detached"])
def test_seal_refuses_signature_formats_rejected_by_apt(snapshot, tmp_path, binary):
    inline, detached = tmp_path / "InRelease", tmp_path / "Release.gpg"
    inline.write_bytes(b"-----BEGIN PGP SIGNED MESSAGE-----\n")
    detached.write_bytes(b"-----BEGIN PGP SIGNATURE-----\n")
    (inline if binary == "inline" else detached).write_bytes(b"binary OpenPGP packet")
    with pytest.raises(ValueError, match="apt_signature_armor_required"):
        apt.seal(snapshot, tmp_path / "signed", inline, detached, tmp_path / "unused", [FPR])


def test_prepare_atomic_export_and_provenance(tmp_path, monkeypatch):
    package, acceptance = tmp_path / "test.deb", tmp_path / "acceptance.json"
    package.write_bytes(b"package")
    acceptance.write_text(json.dumps({"status": "verified", "source_sha": "a" * 40,
                                      "packages": {"test.deb": apt.digest(package)}}))
    calls = []

    def command(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "dpkg-deb":
            return b"test\n" if len(argv) == 4 else b"Package: test\nVersion: 1\nArchitecture: amd64\n"
        if "export" in argv:
            repo = Path(argv[2])
            dist = repo / f"dists/{apt.SUITE}"
            dist.mkdir(parents=True)
            (dist / "Release").write_text("Date: test\n")
            (repo / "pool").mkdir()
            (repo / "pool/test.deb").write_bytes(package.read_bytes())

    monkeypatch.setattr(apt, "command", command)
    output = tmp_path / "snapshot"
    apt.prepare([package], output, "trial", "a" * 40, acceptance)
    manifest = json.loads((output / "snapshot.json").read_text())
    assert manifest["acceptance_sha256"] == apt.digest(acceptance)
    assert manifest["input_packages"] == {"test.deb": apt.digest(package)}
    assert not (output / "conf").exists() and not (output / "db").exists()
    assert not any(argv[0] == "gpg" for argv in calls)
    with pytest.raises(ValueError, match="apt_output_invalid"):
        apt.prepare([package], output, "trial", "a" * 40, acceptance)
    receipt = json.loads(acceptance.read_text())
    receipt["packages"]["test.deb"] = "b" * 64
    acceptance.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="apt_acceptance_packages_changed"):
        apt.prepare([package], tmp_path / "unaccepted", "other", "a" * 40, acceptance)
    assert not (tmp_path / "unaccepted").exists()


def test_failed_bootstrap_does_not_change_trust(tmp_path, monkeypatch):
    key = tmp_path / "public.gpg"
    key.write_bytes(b"public")
    monkeypatch.setattr(apt.os, "geteuid", lambda: 0)
    monkeypatch.setattr(apt, "public_keyring", lambda *a: (_ for _ in ()).throw(ValueError("apt_fingerprint_mismatch")))
    with pytest.raises(ValueError, match="apt_fingerprint_mismatch"):
        apt.bootstrap(key, [FPR], "file:/srv/test", root=tmp_path)
    assert not (tmp_path / "etc").exists()


def test_bootstrap_atomic_overlap_and_permissions(tmp_path, monkeypatch):
    key = tmp_path / "public.gpg"
    key.write_bytes(b"public")
    monkeypatch.setattr(apt.os, "geteuid", lambda: 0)
    stat = Path.stat

    def root_owned(path, **kwargs):
        fields = list(stat(path, **kwargs))
        fields[4] = 0
        return os.stat_result(fields)

    monkeypatch.setattr(Path, "stat", root_owned)
    monkeypatch.setattr(apt, "public_keyring", lambda *a: b"old+new public keys")
    apt.bootstrap(key, [FPR, "C" * 40], "file:/srv/test", root=tmp_path)
    ring = tmp_path / "etc/apt/keyrings/sli-archive.gpg"
    assert ring.read_bytes() == b"old+new public keys"
    assert ring.stat().st_mode & 0o777 == 0o644
    source = tmp_path / "etc/apt/sources.list.d/sli.sources"
    assert source.read_text() == apt.source_text("file:/srv/test")
    assert source.stat().st_mode & 0o777 == 0o644
    monkeypatch.setattr(apt, "public_keyring", lambda *a: b"new public key")
    apt.bootstrap(key, ["C" * 40], "file:/srv/test", root=tmp_path)
    assert ring.read_bytes() == b"new public key"


def test_bootstrap_refuses_unprivileged_and_symlink_directory(tmp_path, monkeypatch):
    key = tmp_path / "public.gpg"
    key.write_bytes(b"public")
    monkeypatch.setattr(apt.os, "geteuid", lambda: 1000)
    with pytest.raises(ValueError, match="apt_bootstrap_requires_root"):
        apt.bootstrap(key, [FPR], "file:/srv/test", root=tmp_path)
    monkeypatch.setattr(apt.os, "geteuid", lambda: 0)
    monkeypatch.setattr(apt, "public_keyring", lambda *a: b"public")
    (tmp_path / "etc/apt").mkdir(parents=True)
    target = tmp_path / "other"
    target.mkdir()
    (tmp_path / "etc/apt/keyrings").symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="apt_trust_directory_unsafe"):
        apt.bootstrap(key, [FPR], "file:/srv/test", root=tmp_path)
    assert not list(target.iterdir())


def test_prepare_failure_leaves_no_public_snapshot(tmp_path, monkeypatch):
    package, acceptance = tmp_path / "test.deb", tmp_path / "acceptance.json"
    package.write_bytes(b"package")
    acceptance.write_text(json.dumps({"status": "verified", "source_sha": "a" * 40}))

    def command(argv, **kwargs):
        if argv[0] == "dpkg-deb":
            return b"test\n" if len(argv) == 4 else b"Architecture: amd64\n"
        raise RuntimeError("export failed")

    monkeypatch.setattr(apt, "command", command)
    output = tmp_path / "snapshot"
    with pytest.raises(RuntimeError, match="export failed"):
        apt.prepare([package], output, "trial", "a" * 40, acceptance)
    assert not output.exists() and not list(tmp_path.glob(".sli-apt-*"))


def test_prepare_refuses_unverified_or_different_source_receipt(tmp_path):
    package, acceptance = tmp_path / "test.deb", tmp_path / "acceptance.json"
    package.write_bytes(b"package")
    for receipt in ({"status": "failed", "source_sha": "a" * 40},
                    {"status": "verified", "source_sha": "b" * 40}):
        acceptance.write_text(json.dumps(receipt))
        with pytest.raises(ValueError, match="apt_acceptance_invalid"):
            apt.prepare([package], tmp_path / "out", "trial", "a" * 40, acceptance)


def test_cli_errors_do_not_expose_diagnostics(monkeypatch, capsys):
    monkeypatch.setattr(apt, "bootstrap", lambda **kw: (_ for _ in ()).throw(ValueError("private")))
    assert apt.main(["bootstrap", "--key", "/public", "--fingerprint", FPR, "--uri", "file:/test"]) == 1
    assert capsys.readouterr().out == "native_apt_failed\n"
