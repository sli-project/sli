# SPDX-License-Identifier: Apache-2.0
"""Local operator CLI; token input uses a hidden prompt, never arguments."""
import argparse
import getpass
import json
import threading
from dataclasses import replace
from pathlib import Path

from sli_agent.config import AgentConfig
from sli_agent.enrollment import IdentityStore
from sli_agent.probe import format_table, probe, report_write_failed, save_report
from sli_agent.runtime import run
from sli_agent.transport import Transport


def main():
    parser = argparse.ArgumentParser(description="SLI agent v1")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("command", choices=("prepare", "enroll", "enroll-group", "run", "probe"))
    parser.add_argument("--computer-entity-id", type=int, help="Computer ID from the accepted AD snapshot")
    parser.add_argument("--json", action="store_true", help="Machine-readable probe report")
    parser.add_argument("--service-identity-sid", help="Expected service SID for a pre-installation probe")
    args = parser.parse_args()
    try:
        config = AgentConfig.load(args.config)
        if args.command == "probe":
            if args.service_identity_sid:
                config = replace(config, service_identity_sid=args.service_identity_sid)
            report = probe(config)
            try:
                save_report(config, report)
            except Exception:
                # An installing administrator may not have service-state write
                # access. Still display the safe table/JSON and block readiness.
                report_write_failed(report)
            print(json.dumps(report, ensure_ascii=True) if args.json else format_table(report))
            if not report["ready"]:
                parser.exit(2)
            return
        store = IdentityStore(config)
        if args.command == "prepare":
            print(json.dumps(store.prepare()))  # public opaque host UUID and key fingerprint only
        elif args.command == "enroll":
            store.enroll(getpass.getpass("One-time enrollment token: "), Transport(config))
            print("agent_enrolled")
        elif args.command == "enroll-group":
            identity = store.enroll_group(getpass.getpass("Group enrollment token: "), args.computer_entity_id, Transport(config))
            print("agent_enrolled" if identity else "agent_approval_pending")
        else:
            stop = threading.Event()
            try:
                run(config, stop)
            except KeyboardInterrupt:
                stop.set()
    except Exception:
        # Never print arbitrary exception strings, account names or input paths.
        parser.exit(1, "agent_operation_failed\n")


if __name__ == "__main__":
    main()
