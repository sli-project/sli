#!/usr/bin/env python3
"""Merge portable AD snapshot settings into the current-user DPAPI environment.

Existing database credentials are decrypted only in-process and immediately
re-encrypted together with the validated non-secret AD scope.  Values are never
printed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.runtime.ad_context_snapshot_worker import (
    SnapshotConfig,
    _csv_values,
    _validate_config,
)
from server.sli.ops.worker_supervisor_secrets import (
    load_supervisor_environment,
    provision_supervisor_environment,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory-server", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--search-base", required=True)
    parser.add_argument("--privileged-group-sids", required=True)
    parser.add_argument("--vpn-group-references", required=True)
    parser.add_argument("--interval-seconds", type=int, default=1800)
    args = parser.parse_args(argv)

    _validate_config(
        SnapshotConfig(
            directory_server=args.directory_server,
            domain=args.domain,
            search_base=args.search_base,
            privileged_group_sids=_csv_values(args.privileged_group_sids),
            vpn_group_references=_csv_values(args.vpn_group_references),
            interval_seconds=args.interval_seconds,
        )
    )
    load_supervisor_environment()
    os.environ.update(
        {
            "ADLOG_AD_CONTEXT_DIRECTORY_SERVER": args.directory_server,
            "ADLOG_AD_CONTEXT_DOMAIN": args.domain,
            "ADLOG_AD_CONTEXT_SEARCH_BASE": args.search_base,
            "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS": args.privileged_group_sids,
            "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES": args.vpn_group_references,
            "ADLOG_AD_CONTEXT_INTERVAL_SECONDS": str(args.interval_seconds),
        }
    )
    result = provision_supervisor_environment()
    print(
        json.dumps(
            {
                "status": result["status"],
                "path": result["path"],
                "interval_seconds": args.interval_seconds,
                "sections": [
                    "privileged_membership",
                    "directory_accounts",
                    "vpn_membership",
                    "gpo_governance",
                ],
                "credential_values_exposed": False,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
