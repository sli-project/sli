"""One-shot import of config/domain_controllers.json into the database.

Domain controller collection targets are stored in ``domain_controller_targets``
(migration 147) and edited on the «Первичная настройка» page. This script copies
the targets of the old file once.

    plan   (default) read-only: prints counts only (file targets, already stored,
           to import); writes nothing
    apply  inserts the missing targets; requires
           ``--confirm IMPORT-DOMAIN-CONTROLLERS``; safe to repeat (hostnames
           already stored are skipped)

Connects with the runtime database settings (``ADLOG_PG_DSN``) or, with
``--load-supervisor-environment``, with the worker-supervisor environment of the
current Windows user. Host names, addresses and credentials are never printed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.setup_domain_controllers import IMPORT_CONFIRMATION, import_from_file  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("action", nargs="?", choices=("plan", "apply"), default="plan")
    parser.add_argument("--confirm")
    parser.add_argument("--load-supervisor-environment", action="store_true")
    args = parser.parse_args(argv)
    if args.action == "apply" and args.confirm != IMPORT_CONFIRMATION:
        raise SystemExit(f"apply requires --confirm {IMPORT_CONFIRMATION}")
    if args.load_supervisor_environment:
        from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment

        load_supervisor_environment(override_existing=True)
    result = import_from_file(apply=args.action == "apply")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
