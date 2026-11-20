"""Re-seal the supervisor profile as its installing Windows user.

Stop the supervisor and workers before running. A registered SLIWebServer must
use the same Windows account; CurrentUser does not let SYSTEM decrypt this
user's profile. This command never prints identities, paths or secret values.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops.worker_supervisor_secrets import (
    SUPERVISOR_ENV_PATH,
    reencrypt_supervisor_environment,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=SUPERVISOR_ENV_PATH)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    try:
        result = reencrypt_supervisor_environment(path=args.path)
    except Exception:  # noqa: BLE001 -- CLI failures must not print OS/DPAPI private details.
        # OS/DPAPI exception text can contain private paths and account names.
        print(json.dumps({
            "status": "failed",
            "reason": "reencryption_failed_check_profile_owner_and_web_service_account",
            "credential_values_exposed": False,
        }))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
