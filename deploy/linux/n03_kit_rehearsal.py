"""Private input staging for the exact n03 control-only Debian kit rehearsal."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import runpy
import shutil
import tarfile

from deploy.linux import build_beta_kit as kit


PREVIOUS_COMMIT = "1b5daf4e66640b7390105b4b5345332deca6f9ce"
PREVIOUS_KIT_SHA = "ae98209ccaa7d11ea5c322484d39076fd45c92ac00c9974b02ccbdfbfb56e4a6"
PREVIOUS_RELEASE = "beta1-1b5daf4e6664"
PREVIOUS_VERSION = "2026.10.16-17954427760459124558~deb13"
RUNTIME = "sli-runtime-cp3146-n03-20261026"
ORIGINAL_VERSION = "3.14.6-1~deb13"
ORIGINAL_SHA = "46986d230f363f3af7e2fd4c4f25ee3da9ae3964982812f404f24b6d654a44d9"
WRAPPER_VERSION = "3.14.6-3~deb13"
WRAPPER_SHA = "47c73edaaa05e8c429db44cb7d88a77f6224b1a9b1bd1aff3679a1de0dafb10f"
PAYLOAD_SHA = "6510d97a1a18f7c0f18e5182627fe8bf3d56b00d2f4cd4232a7fd43d1f0adad2"
BUILD_INPUTS_SHA = "bc98cdacefbed6e400c96fc8b885877df1cc71ed204f0f9cdfcc320fb7b602a7"
PRODUCER_SHA = "ffe460080197c0442736e417e974221ceea77737d1626e966cdcfccc1e679e69"
SYSTEM_LOCK_SHA = "4fe73ca3ea4f61e2383cc8812d08f460bc923ec3302790cb21261493bf79af7c"
SYSTEM_NAMES = {"libssl3t64", "openssl", "openssl-provider-legacy", "libc6", "libc-bin", "zlib1g"}
PREVIOUS = {"git_commit": PREVIOUS_COMMIT, "release": PREVIOUS_RELEASE,
            "version": PREVIOUS_VERSION, "sha256": PREVIOUS_KIT_SHA}


def verified(path, digest):
    if path.is_symlink() or not path.is_file() or kit.sha256(path) != digest:
        raise ValueError(f"Rehearsal input does not match its pin: {path.name}")


def system_inputs(checkout):
    lock = checkout / "scripts/ci/proofs/n03-apt/current-system-family-lock.json"
    verified(lock, SYSTEM_LOCK_SHA)
    return json.loads(lock.read_bytes())


def verify_manifest(manifest):
    info = manifest["rehearsal"]
    if not isinstance(info, dict) or not isinstance(info.get("control_only"), dict):
        raise ValueError("Beta kit rehearsal provenance must identify the exact wrapper")
    packages = manifest["packages"]
    if not isinstance(packages, list) or any(not isinstance(row, dict) or not isinstance(row.get("package"), str)
                                             for row in packages):
        raise ValueError("Beta kit rehearsal packages must identify their exact Debian package names")
    control = info["control_only"]
    if (info.get("release_eligible") is not False or info.get("source") != "local_n03_rehearsal"
            or info.get("build_pins_sha256") != BUILD_INPUTS_SHA or info.get("previous_kit") != PREVIOUS
            or info.get("apt_proof_job") != 137809451537 or control.get("package") != RUNTIME
            or control.get("architecture") != "amd64" or control.get("source_version") != ORIGINAL_VERSION
            or control.get("source_sha256") != ORIGINAL_SHA or control.get("version") != WRAPPER_VERSION
            or control.get("sha256") != WRAPPER_SHA or control.get("data_tar_gz_sha256") != PAYLOAD_SHA
            or control.get("provides") != f"{RUNTIME} (= {ORIGINAL_VERSION})"):
        raise ValueError("Beta kit rehearsal provenance does not match the tested n03 transition")
    filename = f"{RUNTIME}_{WRAPPER_VERSION}_amd64.deb"
    runtime_rows = [row for row in packages if row["package"].startswith("sli-runtime-")]
    if (len(runtime_rows) != 1 or runtime_rows[0]["package"] != RUNTIME
            or runtime_rows[0]["filename"] != filename or runtime_rows[0]["version"] != WRAPPER_VERSION
            or runtime_rows[0]["architecture"] != "amd64" or runtime_rows[0]["sha256"] != WRAPPER_SHA):
        raise ValueError("Beta kit rehearsal must include exactly one qualified n03 runtime")
    current = system_inputs(kit.ROOT)
    expected = {name: (Path(row["Filename"]).name, row["Version"], row["Architecture"], int(row["Size"]), row["SHA256"])
                for name, row in current["packages"].items()}
    installed = [row for row in packages if row["package"] in SYSTEM_NAMES]
    actual = {row["package"]: (row["filename"], row["version"], row["architecture"], row["size"], row["sha256"])
              for row in installed}
    if (len(installed) != len(actual) or actual != expected
            or info.get("system_index_sha256") != current["packages_index_sha256"]
            or info.get("system_inrelease_sha256") != current["inrelease_sha256"]):
        raise ValueError("Beta kit rehearsal system archives differ from the verified Debian pins")


def stage_previous(archive, locked, original_name, output):
    """Stage only verified historical input packages, never the old SLI .debs."""
    wanted = {f"sli-debian-beta-kit/{name}": digest for name, digest in locked.items()}
    original = None
    previous = None
    with tarfile.open(archive, "r|gz") as stream:
        for member in stream:
            if member.name == "sli-debian-beta-kit/manifest.json":
                with stream.extractfile(member) as contents:
                    previous = json.load(contents)
            if member.name not in wanted:
                continue
            if not member.isfile():
                raise ValueError("Rehearsal package must be a regular archive member")
            expected = wanted.pop(member.name)
            name = Path(member.name).name
            with stream.extractfile(member) as contents:
                if name == original_name:
                    original = contents.read()
                    if hashlib.sha256(original).hexdigest() != expected:
                        raise ValueError("Rehearsal original runtime digest mismatch")
                else:
                    staged = output / name
                    with staged.open("xb") as target:
                        shutil.copyfileobj(contents, target)
                    verified(staged, expected)
    if wanted or original is None or previous is None:
        raise ValueError("Rehearsal predecessor kit is incomplete")
    metadata = {(row["package"], row["version"]) for row in previous["packages"]}
    required = {"sli", "sli-host", "sli-rollback-hold", "sli-server-dotnet", f"sli-release-{PREVIOUS_RELEASE}"}
    if (previous["release"] != PREVIOUS_RELEASE or previous["version"] != PREVIOUS_VERSION
            or not {(name, PREVIOUS_VERSION) for name in required} <= metadata):
        raise ValueError("Rehearsal predecessor does not include the rollback packages")
    return original, (PREVIOUS_RELEASE, PREVIOUS_VERSION, ORIGINAL_VERSION)


def stage(checkout, cache, output, previous_kit):
    pins_path = checkout / "deploy/linux/native_pins.json"
    verified(pins_path, BUILD_INPUTS_SHA)
    pins = json.loads(pins_path.read_bytes())
    artifact, original_name, locked = kit.input_pins(pins)
    if artifact["version"] != ORIGINAL_VERSION or locked[original_name] != ORIGINAL_SHA:
        raise ValueError("Rehearsal requires the original n03 build input")

    proof = checkout / "scripts/ci/proofs/n03-apt"
    producer = proof / "repackage_runtime_control.py"
    verified(producer, PRODUCER_SHA)
    current = system_inputs(checkout)
    replaced = {row["name"]: Path(row["filename"]).name for row in kit.package_rows(pins)
                if row["name"] in SYSTEM_NAMES}
    if replaced.keys() != current["packages"].keys() or replaced.keys() != SYSTEM_NAMES:
        raise ValueError("Rehearsal system package names differ from the package closure")
    historical = {name: digest for name, digest in locked.items() if name not in replaced.values()}
    selected = {Path(row["Filename"]).name: row["SHA256"] for row in current["packages"].values()}
    files = kit.checked_inputs(cache, selected)
    for row in current["packages"].values():
        name = Path(row["Filename"]).name
        if files[name].stat().st_size != int(row["Size"]):
            raise ValueError(f"Rehearsal system archive size does not match its pin: {name}")

    verified(previous_kit, PREVIOUS_KIT_SHA)
    kit.verify_offline_kit(previous_kit, PREVIOUS_COMMIT)
    original, previous = stage_previous(previous_kit, historical, original_name, output)
    verified(previous_kit, PREVIOUS_KIT_SHA)
    kit.copy_inputs(cache, output, selected)
    wrapper, control = runpy.run_path(str(producer))["repack_runtime"](
        original, original_sha256=ORIGINAL_SHA, libssl_floor="3.5.7-1~deb13u3")
    if (control["version"] != WRAPPER_VERSION or control["sha256"] != WRAPPER_SHA
            or control["data_tar_gz_sha256"] != PAYLOAD_SHA):
        raise ValueError("Rehearsal wrapper differs from the tested control-only package")
    filename = f"{RUNTIME}_{WRAPPER_VERSION}_amd64.deb"
    with (output / filename).open("xb") as staged:
        staged.write(wrapper)
    verified(output / filename, WRAPPER_SHA)
    provenance = {
        "source": "local_n03_rehearsal",
        "release_eligible": False,
        "build_pins_sha256": BUILD_INPUTS_SHA,
        "control_only": control,
        "previous_kit": PREVIOUS,
        "system_index_sha256": current["packages_index_sha256"],
        "system_inrelease_sha256": current["inrelease_sha256"],
        "apt_proof_job": 137809451537,
    }
    return {**artifact, "version": WRAPPER_VERSION, "sha256": WRAPPER_SHA,
            "pin_source": provenance}, filename, previous
