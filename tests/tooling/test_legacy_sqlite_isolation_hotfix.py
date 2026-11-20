from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_safe_pytest_env_redirects_runtime_db_sentinel_to_disposable_path() -> None:
    from scripts.maintenance.bundle_common import PROJECT_ROOT, safe_pytest_env

    env = safe_pytest_env()
    redirected = Path(env["ADLOG_DB_PATH"]).resolve()
    primary = (PROJECT_ROOT / "data" / "processed" / "ad_logs.sqlite").resolve()
    assert env["ADLOG_DB_BACKEND"] == "postgres"
    assert redirected != primary
    assert "pytest_runtime" in redirected.parts


def test_paths_honours_adlog_db_path_in_fresh_process(tmp_path: Path) -> None:
    target = tmp_path / "isolated.sqlite"
    env = dict(os.environ)
    env["ADLOG_DB_PATH"] = str(target)
    code = "from server.sli.core.paths import DB_PATH; import json; print(json.dumps(str(DB_PATH)))"
    result = subprocess.run([sys.executable, "-c", code], text=True, capture_output=True, env=env, check=True)
    assert json.loads(result.stdout) == str(target)


def test_postgres_self_test_has_no_legacy_sqlite_probe() -> None:
    from scripts.maintenance import self_test as module

    assert not hasattr(module, "sqlite3")
    assert not hasattr(module, "_check_sqlite")
    assert hasattr(module, "_check_postgres_runtime_contract")
