from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("installed, override, expected", [
    (("Scripts/python.exe",), None, "python"),
    (("bin/python",), None, "python"),
    (("Scripts/python.exe", "bin/python"), None, "python"),
    ((), None, "python"),
    (("Scripts/python.exe",), "/custom folder/python", "/custom folder/python"),
])
def test_review_launches_repository_module_independent_of_cwd(tmp_path, installed, override, expected):
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required to exercise the review launcher")
    root = tmp_path / "synthetic repo"
    script = root / "scripts/dev/ui_audit/run_review.sh"
    script.parent.mkdir(parents=True)
    for relative in installed:
        interpreter = root / ".venv" / relative
        interpreter.parent.mkdir(parents=True, exist_ok=True)
        interpreter.touch()
    shutil.copyfile(Path(__file__).resolve().parents[2] / "scripts/dev/ui_audit/run_review.sh", script)
    # Intercept execution in Bash startup, leaving the launcher intact and
    # avoiding Python/module dependencies in the synthetic repository.
    bash_env = tmp_path / "capture_exec.sh"
    bash_env.write_text('exec() { pwd -W 2>/dev/null || pwd; printf "%s\\n" "$@"; }\n',
                        encoding="utf-8", newline="\n")
    environment = dict(os.environ)
    environment.pop("SLI_AUDIT_PYTHON", None)
    environment.pop("SLI_AUDIT_ORIGIN", None)
    environment["BASH_ENV"] = bash_env.as_posix()
    if override:
        environment["SLI_AUDIT_PYTHON"] = override
    result = subprocess.run([bash, script.as_posix(), "unused"], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, check=True)
    working_directory, *arguments = result.stdout.splitlines()
    assert Path(working_directory) == root
    assert arguments == [
        expected, "-m", "scripts.dev.ui_audit.stand", "review",
        "--base", "", "--out", "unused",
    ]
