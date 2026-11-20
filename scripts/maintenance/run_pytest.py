from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.bundle_common import sanitized_pytest_env, unique_pytest_basetemp  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run pytest with a unique project-controlled basetemp.")
    parser.add_argument("--run-label", default="pytest")
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    pytest_args = list(args.pytest_args)
    if pytest_args and pytest_args[0] == "--":
        pytest_args = pytest_args[1:]

    basetemp = unique_pytest_basetemp(args.run_label)
    basetemp.parent.mkdir(parents=True, exist_ok=True)
    active_marker = basetemp.parent / f".active-{basetemp.name}.json"
    active_marker.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "started_at_utc": datetime.now(timezone.utc).isoformat(),
                "basetemp": str(basetemp),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    command = [sys.executable, "-m", "pytest", "-q", f"--basetemp={basetemp}", *pytest_args]
    print(f"PYTEST_BASETEMP={basetemp}", flush=True)
    env = sanitized_pytest_env(os.environ)
    env["PYTEST_ADDOPTS"] = "-p no:cacheprovider"
    try:
        completed = subprocess.run(command, cwd=ROOT, env=env, check=False)
        print(f"PYTEST_EXIT_CODE={completed.returncode}", flush=True)
        return int(completed.returncode)
    finally:
        active_marker.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
