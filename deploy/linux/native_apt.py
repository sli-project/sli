"""Candidate snapshots and explicit public-key bootstrap; private signing is external."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit

SUITE = "sli-debian13"
FINGERPRINT = re.compile(r"[A-F0-9]{40}")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def command(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, timeout=300, **kwargs).stdout


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), "apt_special_file")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = digest(path)
    return result


def prepare(packages, output, snapshot, source_sha, acceptance, valid_days=7):
    """Export one new candidate. No key access and no modification of old snapshots."""
    require(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,63}", snapshot), "apt_snapshot_invalid")
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha), "apt_source_invalid")
    require(1 <= valid_days <= 30 and not output.exists() and not output.is_symlink(), "apt_output_invalid")
    require(packages and all(p.is_file() and not p.is_symlink() and p.suffix == ".deb" for p in packages),
            "apt_packages_invalid")
    acceptance_sha = digest(acceptance)
    receipt = json.loads(acceptance.read_text())
    require(receipt.get("status") == "verified" and receipt.get("source_sha") == source_sha,
            "apt_acceptance_invalid")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".sli-apt-", dir=output.parent) as temporary:
        staging = Path(temporary)
        repo = staging / "repo"
        (repo / "conf").mkdir(parents=True)
        (repo / "conf/distributions").write_text(
            f"Origin: SLI\nLabel: SLI\nSuite: {SUITE}\nCodename: {SUITE}\n"
            f"Architectures: amd64\nComponents: candidate main\nValidFor: {valid_days}d\n"
            "NotAutomatic: yes\nButAutomaticUpgrades: yes\n", encoding="utf-8")
        inputs = {}
        identities = set()
        for package in packages:
            fields = command(["dpkg-deb", "-f", str(package), "Package", "Version", "Architecture"]).decode()
            # reprepro retains only one version of each identity in a component.
            identity = command(["dpkg-deb", "-f", str(package), "Package"]).decode().strip()
            require(identity not in identities and package.name not in inputs, "apt_duplicate_package")
            require("Architecture: amd64" in fields or "Architecture: all" in fields, "apt_architecture_invalid")
            identities.add(identity)
            inputs[package.name] = digest(package)
            command(["reprepro", "-b", str(repo), "--export=never", "-C", "candidate",
                     "includedeb", SUITE, str(package.resolve())])
        command(["reprepro", "-b", str(repo), "export", SUITE])
        public = staging / "public"
        public.mkdir()
        for name in ("dists", "pool"):
            shutil.copytree(repo / name, public / name)
        require(sorted(inputs.values()) == sorted(digest(p) for p in (public / "pool").rglob("*.deb")),
                "apt_package_set_changed")
        require(receipt.get("packages") == inputs, "apt_acceptance_packages_changed")
        manifest = {"schema_version": 1, "snapshot": snapshot, "source_sha": source_sha,
                    "os": "debian13", "architecture": "amd64", "component": "candidate",
                    "acceptance_sha256": acceptance_sha, "input_packages": inputs,
                    "files": inventory(public)}
        # Release itself is bound below; exclude it to avoid a circular hash.
        del manifest["files"][f"dists/{SUITE}/Release"]
        manifest_path = public / "snapshot.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        release = public / f"dists/{SUITE}/Release"
        release.write_bytes(f"X-SLI-Manifest-SHA256: {digest(manifest_path)}\n".encode() + release.read_bytes())
        public.rename(output)
    return digest(output / f"dists/{SUITE}/Release")


def public_keyring(key, fingerprints):
    """Require independently supplied exact primary fingerprints, including overlap."""
    expected = set(fingerprints)
    require(expected and all(FINGERPRINT.fullmatch(f) for f in expected), "apt_fingerprint_invalid")
    with tempfile.TemporaryDirectory(prefix="sli-public-key-") as temporary:
        home = Path(temporary)
        home.chmod(0o700)
        base = ["gpg", "--homedir", str(home), "--batch", "--no-options"]
        listing = command(base + ["--with-colons", "--import-options", "show-only", "--dry-run", "--import"],
                          input=key).decode()
        found = set()
        primary = False
        for line in listing.splitlines():
            fields = line.split(":")
            require(fields[0] not in {"sec", "ssb"}, "apt_private_key_forbidden")
            if fields[0] == "pub":
                primary = True
                require(fields[1] not in {"r", "e", "d"}, "apt_key_unusable")
            elif fields[0] == "sub":
                primary = False
            elif fields[0] == "fpr" and primary:
                found.add(fields[9])
                primary = False
        require(found == expected, "apt_fingerprint_mismatch")
        command(base + ["--import"], input=key)
        return command(base + ["--export", *sorted(expected)])


def verify_snapshot(root):
    manifest_path = root / "snapshot.json"
    release = root / f"dists/{SUITE}/Release"
    lines = release.read_text().splitlines()
    require(lines[0] == f"X-SLI-Manifest-SHA256: {digest(manifest_path)}", "apt_manifest_changed")
    manifest = json.loads(manifest_path.read_text())
    expected = dict(manifest["files"])
    actual = inventory(root)
    for name in ("snapshot.json", f"dists/{SUITE}/Release", f"dists/{SUITE}/InRelease", f"dists/{SUITE}/Release.gpg"):
        actual.pop(name, None)
    require(actual == expected, "apt_snapshot_changed")
    dates = dict(line.split(": ", 1) for line in lines if line.startswith(("Date: ", "Valid-Until: ")))
    now = datetime.now(timezone.utc)
    require(parsedate_to_datetime(dates["Date"]) <= now < parsedate_to_datetime(dates["Valid-Until"]),
            "apt_metadata_expired")
    return release


def seal(unsigned, output, inrelease, detached, key, fingerprints):
    """Accept external signatures over the exact prepared Release, never re-sign."""
    require(not output.exists() and not output.is_symlink(), "apt_output_invalid")
    require(inrelease.read_bytes().splitlines()[:1] == [b"-----BEGIN PGP SIGNED MESSAGE-----"]
            and detached.read_bytes().splitlines()[:1] == [b"-----BEGIN PGP SIGNATURE-----"],
            "apt_signature_armor_required")
    release = verify_snapshot(unsigned)
    ring = public_keyring(key.read_bytes(), fingerprints)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".sli-seal-", dir=output.parent) as temporary:
        staging = Path(temporary)
        keyring = staging / "public.gpg"
        keyring.write_bytes(ring)
        base = ["gpgv", "--homedir", str(staging), "--keyring", str(keyring)]
        plaintext = staging / "plaintext"
        command(base + ["--output", str(plaintext), str(inrelease)])
        require(plaintext.read_bytes() == release.read_bytes(), "apt_signed_release_mismatch")
        command(base + [str(detached), str(release)])
        public = staging / "public"
        shutil.copytree(unsigned, public)
        dist = public / f"dists/{SUITE}"
        shutil.copyfile(inrelease, dist / "InRelease")
        shutil.copyfile(detached, dist / "Release.gpg")
        verify_snapshot(public)
        public.rename(output)


def source_text(uri, component="candidate"):
    parsed = urlsplit(uri)
    require(component in {"candidate", "main"} and not any(c.isspace() or ord(c) < 32 for c in uri)
            and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
            and ((parsed.scheme == "https" and parsed.hostname)
                 or (parsed.scheme == "file" and not parsed.netloc and parsed.path.startswith("/"))), "apt_uri_invalid")
    return (f"Types: deb\nURIs: {uri}\nSuites: {SUITE}\nComponents: {component}\nArchitectures: amd64\n"
            "Signed-By: /etc/apt/keyrings/sli-archive.gpg\nCheck-Valid-Until: yes\n")


def atomic_write(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            temporary.chmod(0o644)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def bootstrap(key, fingerprints, uri, component="candidate", root=Path("/")):
    require(os.geteuid() == 0, "apt_bootstrap_requires_root")
    source = source_text(uri, component).encode()
    ring = public_keyring(key.read_bytes(), fingerprints)
    for relative in ("etc/apt/keyrings", "etc/apt/sources.list.d"):
        directory = root / relative
        directory.mkdir(parents=True, exist_ok=True)
        for parent in (directory, *directory.parents):
            require(not parent.is_symlink() and parent.stat().st_uid == 0
                    and not parent.stat().st_mode & 0o022, "apt_trust_directory_unsafe")
            if parent == root:
                break
    # Install overlap keyring before switching metadata to the new signer.
    atomic_write(root / "etc/apt/keyrings/sli-archive.gpg", ring)
    atomic_write(root / "etc/apt/sources.list.d/sli.sources", source)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    prepare_parser = commands.add_parser("prepare")
    for name in ("output", "acceptance"):
        prepare_parser.add_argument("--" + name, required=True, type=Path)
    for name in ("snapshot", "source-sha"):
        prepare_parser.add_argument("--" + name, required=True)
    prepare_parser.add_argument("--valid-days", type=int, default=7)
    prepare_parser.add_argument("packages", nargs="+", type=Path)
    seal_parser = commands.add_parser("seal")
    for name in ("unsigned", "output", "inrelease", "detached", "key"):
        seal_parser.add_argument("--" + name, required=True, type=Path)
    bootstrap_parser = commands.add_parser("bootstrap")
    bootstrap_parser.add_argument("--key", required=True, type=Path)
    bootstrap_parser.add_argument("--uri", required=True)
    bootstrap_parser.add_argument("--component", choices=("candidate", "main"), default="candidate")
    for subparser in (seal_parser, bootstrap_parser):
        subparser.add_argument("--fingerprint", action="append", required=True)
    args = vars(parser.parse_args(argv))
    action = args.pop("action")
    if "fingerprint" in args:
        args["fingerprints"] = args.pop("fingerprint")
    try:
        globals()[action](**args)
    except Exception:  # noqa: BLE001 - never expose key material or private paths
        print("native_apt_failed")
        return 1
    print("native_apt_" + action + "_complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
