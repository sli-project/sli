"""The backup helper runs in the previous image; newer helper modules must be preloaded there."""
import os
import subprocess
import sys
from pathlib import Path

from deploy.linux.sli_update import helper_preload_source

LINUX = Path(__file__).resolve().parents[2] / "deploy" / "linux"


def test_preload_provides_modules_missing_from_previous_image(tmp_path):
    # The "previous image" package knows neither backup_policy nor restore_sandbox.
    package = tmp_path / "deploy" / "linux"
    package.mkdir(parents=True)
    (tmp_path / "deploy" / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    program = helper_preload_source((LINUX / "backup_policy.py").read_text("utf-8"),
                                    (LINUX / "restore_sandbox.py").read_text("utf-8"))
    program += ("from deploy.linux import backup_policy, restore_sandbox\n"
                "print(backup_policy.retention_settings(), restore_sandbox.__name__)\n")
    result = subprocess.run([sys.executable, "-c", program], cwd=tmp_path, capture_output=True, text=True, timeout=60,
                            env={**os.environ, "PYTHONPATH": str(tmp_path)})
    assert result.returncode == 0, result.stderr
    assert "(7, 4) deploy.linux.restore_sandbox" in result.stdout


def test_without_preload_the_previous_image_cannot_import_new_helpers(tmp_path):
    package = tmp_path / "deploy" / "linux"
    package.mkdir(parents=True)
    (tmp_path / "deploy" / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    result = subprocess.run([sys.executable, "-c", "from deploy.linux import backup_policy"], cwd=tmp_path,
                            capture_output=True, text=True, timeout=60,
                            env={**os.environ, "PYTHONPATH": str(tmp_path)})
    assert result.returncode != 0 and "backup_policy" in result.stderr
