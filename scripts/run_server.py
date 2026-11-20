from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.api.http_server import run_server
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.storage.storage_v2_runtime_authorization import (
    load_runtime_authorization_if_available,
)


def _load_storage_route_authorization():
    return load_runtime_authorization_if_available(connect)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run AD log reports web server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args()

    import os
    if "ADLOG_PG_DSN" not in os.environ:
        try:
            from server.sli.ops.worker_supervisor_secrets import (
                load_supervisor_environment,
                strip_http_forbidden_environment,
            )
            load_supervisor_environment(override_existing=True)
            strip_http_forbidden_environment()
        except Exception:
            pass

    os.environ.setdefault("ADLOG_AUTH_REQUIRED", "1")
    run_server(
        args.host,
        args.port,
        storage_route_authorization=_load_storage_route_authorization(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
