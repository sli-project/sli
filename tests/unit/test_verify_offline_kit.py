"""Host-Python compatibility for the buyer's offline verification commands."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

import pytest

from deploy.linux import verify_offline_kit as verifier
from tests.unit.test_release_artifacts import kit  # noqa: F401 -- shared synthetic kit
from tools import release_artifacts as release


@pytest.fixture
def portable_kit(kit):
    root, _ = kit
    release.finalize_evaluation(root)
    return root, verifier.digest(root / "KIT_INVENTORY.json")


@pytest.mark.skipif(os.name == "nt", reason="Linux buyer shell and interpreter links")
def test_start_here_command_runs_with_only_system_python3(portable_kit, tmp_path):
    root, checksum = portable_kit
    binary = tmp_path / "bin"
    binary.mkdir()
    (binary / "python3").symlink_to(os.environ.get("SLI_KIT_TEST_PYTHON", sys.executable))
    command = re.search(r"^   (python\S+ .*verify_offline_kit\.py.*)$",
                        (root / "START_HERE.md").read_text(), re.MULTILINE).group(1)
    command = command.replace("<EXPECTED_SHA256>", checksum)
    shutil.copyfile(verifier.__file__, root / "verify_offline_kit.py")
    # Replacing the verifier changes the inventory, so reseal the synthetic kit.
    release.finalize_evaluation(root)
    command = command.replace(checksum, verifier.digest(root / "KIT_INVENTORY.json"))
    environment = dict(os.environ, PATH=str(binary), PYTHONDONTWRITEBYTECODE="1")
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(["/bin/sh", "-c", command], cwd=root, env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "complete"
    assert not list(root.rglob("__pycache__"))


@pytest.mark.parametrize("minor", [11, 12, 13, 14])
def test_verifier_requires_each_host_python_abi(portable_kit, minor):
    root, _ = portable_kit
    (root / f"host-libs/python3.{minor}/_cffi_backend.cpython-3{minor}-x86_64-linux-gnu.so").unlink()
    release.finalize_evaluation(root)
    with pytest.raises(verifier.KitError, match="kit_host_libraries_missing"):
        verifier.verify(root, evaluation=True, inventory_sha256=verifier.digest(root / "KIT_INVENTORY.json"))


def test_verifier_accepts_complete_portable_kit(portable_kit):
    root, checksum = portable_kit
    assert verifier.verify(root, evaluation=True, inventory_sha256=checksum)["status"] == "complete"


def test_bundle_host_libraries_refuses_overwriting_existing_libraries(tmp_path, monkeypatch):
    target = tmp_path / "host-libs/python3.11"
    target.mkdir(parents=True)
    (target / "preserved").write_bytes(b"existing")
    monkeypatch.setattr(release.subprocess, "run", lambda *a, **k: pytest.fail("pip must not run"))
    with pytest.raises(verifier.KitError, match="release_host_libraries_exist"):
        release.bundle_host_libraries(tmp_path)
    assert (target / "preserved").read_bytes() == b"existing"


def test_bundle_host_libraries_resolves_target_abis_without_source_builds(tmp_path, monkeypatch):
    (tmp_path / "host-requirements.lock.txt").write_text("cryptography==50.0.1\ncffi==2.1.0\npycparser==3.0\n")
    calls = []

    def pip(command, **options):
        assert command[:3] == [sys.executable, "-m", "pip"]
        assert "--only-binary=:all:" in command and "--no-deps" in command
        assert "--no-compile" in command
        version = command[command.index("--python-version") + 1]
        assert command[command.index("--abi") + 1] == "cp" + version.replace(".", "")
        assert command[command.index("--platform") + 1] == "manylinux_2_28_x86_64"
        target = tmp_path / "host-libs" / ("python" + version)
        assert command[command.index("--target") + 1] == str(target)
        target.mkdir(parents=True)
        (target / "resolved").write_text(version)
        calls.append(version)

    monkeypatch.setattr(release.subprocess, "run", pip)
    release.bundle_host_libraries(tmp_path)
    assert calls == ["3.11", "3.12", "3.13", "3.14"]
    assert (tmp_path / "host-libs/python3.13/resolved").read_text() == "3.13"
