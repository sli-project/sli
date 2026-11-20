# SPDX-License-Identifier: Apache-2.0
"""Signed, immutable agent releases and a crash-recoverable activation pointer."""
from __future__ import annotations

import hashlib
import json
import platform
import re
import shutil
import tempfile
from pathlib import Path

from server.sli import release_package
from server.sli.release_package import PackageError, extract_payload, verify_package
from sli_agent.envelope import canonical
from sli_agent.protection import atomic_write, directory_lock, secure_directory

AGENT_API = 1
PACKAGE_SNAPSHOT = "SLI_AGENT_PACKAGE.zip"
STABLE_FILES = {"sli_agent/launcher.py", "sli_agent/service.py", "sli_agent/msi.py"}
REASONS = {"agent_update_verification_failed", "agent_update_stage_failed",
           "agent_update_start_failed", "agent_update_self_check_failed", "agent_update_timeout",
           "agent_update_incompatible_version", "agent_update_incompatible_platform", "agent_update_incompatible_api",
           "agent_update_insufficient_disk", "agent_update_download_failed", "agent_update_msi_required"}
PACKAGE_REASONS = {"update_incompatible_version": "agent_update_incompatible_version",
                   "update_incompatible_platform": "agent_update_incompatible_platform",
                   "update_incompatible_agent_api": "agent_update_incompatible_api",
                   "update_insufficient_disk": "agent_update_insufficient_disk"}
SHARED_FILES = {
                "server/__init__.py", "server/sli/__init__.py", "server/sli/release_package.py", "server/sli/storage/__init__.py",
                "server/sli/storage/xml_safety.py", "config/event_catalog.json",
                "scripts/ad_context/GpoReportContract.psm1",
                "config/source_packs/dc.json", "config/source_packs/workstations.json", "config/source_packs/radius.json"}
REQUIRED_FILES = SHARED_FILES | {"sli_agent/" + name + ".py" for name in (
    "__init__", "runtime", "config", "enrollment", "envelope", "modules", "protection", "spool",
    "transport", "updates", "workstations", "policies", "probe", "ad_dc", "snapshot_stream",
    "ad_snapshot", "ad_snapshot_security", "ad_snapshot_computers", "gpo_snapshot", "gpo_privacy")} | {"sli_agent/ad_snapshot.ps1", "sli_agent/gpo_snapshot.ps1", "sli_collect/__init__.py", "sli_collect/eventlog.py", "sli_collect/packets.py", "sli_collect/bookmarked_eventlog.py"}


def validate_payload(names):
    if not REQUIRED_FILES <= names or {p.casefold() for p in names} & STABLE_FILES or any(
            p not in SHARED_FILES and p.split("/")[0] not in {"sli_agent", "sli_collect"} for p in names):
        raise PackageError("agent_update_payload_invalid")


def machine():
    architecture = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    return {"os": platform.system().lower(), "architecture": architecture, "agent_api": AGENT_API}


class Updates:
    def __init__(self, config):
        self.config = config
        self.root = config.release_root
        self.pointer = self.root / "current.json"

    def read(self):
        return json.loads(self.pointer.read_bytes())

    def write(self, state):
        atomic_write(self.pointer, canonical(state))

    def release(self, current):
        name = current["directory"]
        if not isinstance(name, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-[a-z0-9]+", name):
            raise ValueError("agent_update_pointer_invalid")
        path = self.root / "versions" / name
        for part in (path, path.parent, self.root):
            if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
                raise ValueError("agent_update_pointer_invalid")
        if not path.is_dir():
            raise ValueError("agent_update_pointer_invalid")
        return path

    def initialize(self, version, directory):
        """Operator-provisioned initial release; never copy live files."""
        if self.pointer.exists() or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise ValueError("agent_update_initialization_invalid")
        current = {"version": version, "directory": directory}
        self.verified_release(current)
        self.write({"current": current, "previous": None, "pending": None, "result": None, "attempted": None})

    def verified_release(self, current):
        """SCM's installed verifier authenticates files before importing a release.

        The MSI/operator-installed bootstrap and its trust policy are separate
        from downloaded releases. Never import the candidate's verifier or use
        a policy shipped inside it, even if the child staged it successfully.
        """
        release = self.release(current)
        mutable = (self.config.update_root.resolve(), self.config.state_dir.resolve())
        for source in (Path(__file__), Path(release_package.__file__), self.config.update_trust_store):
            if any(source.resolve().is_relative_to(root) for root in mutable):
                raise PackageError("agent_update_external_bootstrap_required")
        names = set()
        directories = [release]
        while directories:
            for path in directories.pop().iterdir():
                if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                    raise PackageError("agent_update_payload_invalid")
                if path.is_dir():
                    directories.append(path)
                elif path.is_file():
                    names.add(path.relative_to(release).as_posix())
                else:
                    raise PackageError("agent_update_payload_invalid")
        if current["directory"] == current["version"] + "-initial":
            # An unsigned initial copy is trusted only while it exactly matches
            # the independently installed bootstrap's source inventory.
            validate_payload(names)
            installed_root = Path(__file__).resolve().parent.parent
            expected = {name: hashlib.sha256(release_package._bounded_read(
                release_package._plain_source(installed_root / name, installed_root),
                128 * 1024 * 1024, single_link=True)).hexdigest() for name in names}
        else:
            verified = verify_package(release / PACKAGE_SNAPSHOT, self.config.update_trust_store, component="agent")
            manifest = verified.manifest
            if (manifest["component"] != "agent" or manifest["version"] != current["version"] or
                    current["directory"] != manifest["version"] + "-" + verified.archive_sha256 or
                    "agent_api" not in manifest["compatibility"]):
                raise PackageError("agent_update_pointer_invalid")
            compatible = manifest["compatibility"]
            host = machine()
            if any(compatible[key] != host[key] for key in ("os", "architecture")):
                raise PackageError("agent_update_incompatible_platform")
            if not compatible["agent_api"]["min"] <= AGENT_API <= compatible["agent_api"]["max"]:
                raise PackageError("agent_update_incompatible_api")
            expected = {item["path"]: item["sha256"] for item in manifest["files"]}
            validate_payload(set(expected))
            if names != set(expected) | {PACKAGE_SNAPSHOT}:
                raise PackageError("agent_update_payload_invalid")
        for name, digest in expected.items():
            if hashlib.sha256(release_package._bounded_read(
                    release / name, 128 * 1024 * 1024, single_link=True)).hexdigest() != digest:
                raise PackageError("agent_update_payload_changed")
        return release

    def offer(self, offer, transport, identity):
        """Return True only after a durable switch; the old process then exits."""
        with directory_lock(self.root / "update-lock"):
            state = self.read()
            digest = offer.get("sha256") if isinstance(offer, dict) else None
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("agent_update_offer_invalid")
            if state["pending"] or state["attempted"] == digest:
                return False
            secure_directory(self.root / "downloads")
            phase = "agent_update_download_failed"
            try:
                with tempfile.TemporaryDirectory(dir=self.root / "downloads") as folder:
                    archive = Path(folder) / "agent.zip"
                    transport.download(digest, archive, identity=identity)
                    phase = "agent_update_stage_failed"
                    installed = {"component": "agent", "version": state["current"]["version"], **machine()}
                    verified = verify_package(archive, self.config.update_trust_store,
                        installed=installed, free_bytes=shutil.disk_usage(self.root).free, component="agent")
                    manifest = verified.manifest
                    if "agent_api" not in manifest["compatibility"]:
                        raise PackageError("update_incompatible_agent_api")
                    if verified.archive_sha256 != digest or manifest["version"] != offer.get("version"):
                        raise PackageError("agent_update_offer_mismatch")
                    names = {item["path"] for item in manifest["files"]}
                    validate_payload(names)
                    target = {"version": manifest["version"], "directory": manifest["version"] + "-" + digest}
                    secure_directory(self.root / "versions")
                    destination = self.root / "versions" / target["directory"]
                    if destination.exists():
                        # Never reuse an interrupted or locally modified stage.
                        raise OSError("agent_update_stage_exists")
                    secure_directory(destination)
                    extract_payload(verified, destination)
                    # Retain exactly the authenticated snapshot, rather than
                    # reopening the download. The independent launcher verifies
                    # its signature and extracted inventory before every start.
                    atomic_write(destination / PACKAGE_SNAPSHOT, verified.archive_bytes)
            except (PackageError, ValueError) as exc:
                state.update(attempted=digest, result={"sha256": digest, "status": "rejected",
                    "reason": PACKAGE_REASONS.get(str(exc), "agent_update_verification_failed"), "version": state["current"]["version"]})
                self.write(state)
                return False
            except OSError:
                state.update(attempted=state["attempted"] if phase == "agent_update_download_failed" else digest,
                    result={"sha256": digest, "status": "rejected",
                    "reason": phase, "version": state["current"]["version"]})
                self.write(state)
                return False
            # One atomic journal/pointer write: crashes cannot separate activation
            # from the previous release needed by the independent launcher.
            state.update(previous=state["current"], current=target, pending=digest, attempted=digest, result=None)
            self.write(state)
            return True

    def healthy(self, directory):
        with directory_lock(self.root / "update-lock"):
            state = self.read()
            if state["current"]["directory"] != directory:
                raise ValueError("agent_update_pointer_invalid")
            if state["pending"]:
                state.update(result={"sha256": state["pending"], "status": "updated", "reason": None,
                    "version": state["current"]["version"]}, pending=None)
                self.write(state)

    def rollback(self, reason):
        if reason not in REASONS:
            reason = "agent_update_start_failed"
        with directory_lock(self.root / "update-lock"):
            state = self.read()
            if not state["pending"]:
                return False
            self.release(state["previous"])
            state.update(result={"sha256": state["pending"], "status": "rolled_back", "reason": reason,
                "version": state["previous"]["version"]}, current=state["previous"], previous=None, pending=None)
            self.write(state)
            return True

    def report(self, transport, identity):
        result = self.read()["result"]
        if result:
            transport.post("/api/v1/agent/update-result", result, identity=identity)


def main():
    import argparse
    from sli_agent.config import AgentConfig
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    Updates(AgentConfig.load(Path(args.config))).initialize(args.version, args.directory)


if __name__ == "__main__":
    main()
