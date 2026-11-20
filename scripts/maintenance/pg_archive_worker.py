from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.sources.dc_discovery import verify_configured_domain_controller_dns_readback

STATUS_PATH = ROOT / "data" / "maintenance" / "pg_archive_worker_status.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def tail(text: str, limit: int = 4000) -> str:
    return (text or "")[-limit:]


def write_status(payload: dict[str, Any]) -> None:
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATUS_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(STATUS_PATH)


def parse_targets(raw_items: list[str] | None) -> dict[str, str]:
    configured = {
        target["hostname"].casefold(): target
        for target in verify_configured_domain_controller_dns_readback()
    }
    if not configured:
        raise SystemExit("No configured DC FQDN endpoints resolved")
    if not raw_items:
        return {
            target["hostname"]: target["connect_address"]
            for target in configured.values()
        }
    targets: dict[str, str] = {}
    for item in raw_items:
        value = item.strip()
        if not value:
            continue
        if "=" not in value:
            raise SystemExit(f"Invalid --target value {value!r}; expected DC1=dc1.example.test")
        name, address = value.split("=", 1)
        name = name.strip()
        address = address.strip()
        if not name or not address:
            raise SystemExit(f"Invalid --target value {value!r}; expected non-empty name/address")
        configured_target = configured.get(name.casefold())
        if (
            configured_target is None
            or address.casefold().rstrip(".")
            != configured_target["connect_address"].casefold().rstrip(".")
        ):
            raise SystemExit(
                f"Target {name!r} must match its configured FQDN endpoint"
            )
        targets[configured_target["hostname"]] = configured_target["connect_address"]
    if not targets:
        raise SystemExit("No targets resolved")
    return targets


def run_one(server: str, connect_address: str, args: argparse.Namespace, run_id: str, results_so_far: list[dict[str, Any]]) -> dict[str, Any]:
    env = os.environ.copy()
    env["ADLOG_DB_BACKEND"] = "postgres"
    env["ADLOG_DISABLE_SCHEDULER"] = "1"
    env["ADLOG_CONTINUOUS_RECOVERY"] = "false"
    env["ADLOG_ENABLE_POSTGRES_COLLECTION"] = "1"

    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "run_dc_log_pilot.py"),
        "--server",
        server,
        "--connect-address",
        connect_address,
        "--channels",
        args.channels,
        "--hours",
        str(args.hours),
        "--max-events-per-channel",
        str(args.max_events),
        "--collection-mode",
        args.collection_mode,
        "--collector-backend",
        args.collector_backend,
        "--collect-message",
        "true" if args.collect_message else "false",
        "--archive",
        "--command-timeout-seconds",
        str(args.command_timeout_seconds),
        "--channel-timeout-seconds",
        str(args.channel_timeout_seconds),
        "--no-technical-report",
    ]

    started = utc_now()
    status_payload: dict[str, Any] = {
        "status": "running",
        "run_id": run_id,
        "mode": "postgres_archive_worker",
        "active_server": server,
        "active_connect_address": connect_address,
        "started_at_utc": started,
        "updated_at_utc": started,
        "results": results_so_far,
        "command": cmd,
    }
    write_status(status_payload)

    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        timeout=args.command_timeout_seconds + 120,
        env=env,
    )
    finished = utc_now()
    output = proc.stdout or ""
    error = proc.stderr or ""
    result = {
        "server": server,
        "connect_address": connect_address,
        "status": "ok" if proc.returncode == 0 else "failed",
        "exit_code": proc.returncode,
        "started_at_utc": started,
        "finished_at_utc": finished,
        "stdout_tail": tail(output),
        "stderr_tail": tail(error),
        "archive_state_updated": f"PostgreSQL archive state updated for {server}." in output,
        "postgres_importer_used": "import_event_jsonl_to_postgres.py" in output,
    }
    print(output, end="")
    if error:
        print(error, end="", file=sys.stderr)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run bounded PostgreSQL archive/watermark collection outside the web scheduler.")
    parser.add_argument("--target", action="append", help="Optional exact configured FQDN mapping like DC1=dc1.example.test. Repeatable. Defaults to all configured targets.")
    parser.add_argument("--servers", help="Comma-separated logical servers to run from the resolved target map. Defaults to all targets.")
    parser.add_argument("--channels", default="Security")
    parser.add_argument("--hours", type=int, default=1)
    parser.add_argument("--max-events", type=int, default=1000)
    parser.add_argument("--collection-mode", default="current", choices=["auto", "current", "backfill", "recovery"])
    parser.add_argument("--collector-backend", default="auto", choices=["auto", "python", "powershell"])
    parser.add_argument("--collect-message", action="store_true")
    parser.add_argument("--command-timeout-seconds", type=int, default=300)
    parser.add_argument("--channel-timeout-seconds", type=int, default=180)
    parser.add_argument("--status", action="store_true", help="Print the last worker status and exit.")
    args = parser.parse_args(argv)

    if args.status:
        if not STATUS_PATH.exists():
            print(json.dumps({"status": "missing", "path": str(STATUS_PATH)}, ensure_ascii=False, indent=2))
            return 1
        print(STATUS_PATH.read_text(encoding="utf-8"))
        return 0

    targets = parse_targets(args.target)
    if args.servers:
        requested = [item.strip() for item in args.servers.split(",") if item.strip()]
        missing = [item for item in requested if item not in targets]
        if missing:
            raise SystemExit(f"No connect address for servers: {', '.join(missing)}")
        targets = {item: targets[item] for item in requested}

    run_id = f"pg-archive-worker-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    results: list[dict[str, Any]] = []
    write_status({
        "status": "running",
        "run_id": run_id,
        "mode": "postgres_archive_worker",
        "started_at_utc": utc_now(),
        "targets": targets,
        "channels": args.channels,
        "max_events": args.max_events,
        "hours": args.hours,
        "results": results,
    })

    failed = False
    for server, address in targets.items():
        try:
            result = run_one(server, address, args, run_id, results)
        except subprocess.TimeoutExpired as exc:
            failed = True
            result = {
                "server": server,
                "connect_address": address,
                "status": "timeout",
                "exit_code": 124,
                "finished_at_utc": utc_now(),
                "stdout_tail": tail(exc.stdout if isinstance(exc.stdout, str) else ""),
                "stderr_tail": tail(exc.stderr if isinstance(exc.stderr, str) else ""),
                "archive_state_updated": False,
                "postgres_importer_used": False,
            }
        results.append(result)
        if result.get("status") != "ok":
            failed = True
        write_status({
            "status": "failed" if failed else "running",
            "run_id": run_id,
            "mode": "postgres_archive_worker",
            "updated_at_utc": utc_now(),
            "targets": targets,
            "results": results,
        })
        if failed and not args.servers:
            # Keep this conservative: stop after the first failed default target.
            break

    final_status = "failed" if failed else "ok"
    final_payload = {
        "status": final_status,
        "run_id": run_id,
        "mode": "postgres_archive_worker",
        "finished_at_utc": utc_now(),
        "targets": targets,
        "results": results,
        "summary": {
            "servers_ok": [item["server"] for item in results if item.get("status") == "ok"],
            "servers_failed": [item["server"] for item in results if item.get("status") != "ok"],
            "archive_states_updated": [item["server"] for item in results if item.get("archive_state_updated")],
            "postgres_importer_used": all(item.get("postgres_importer_used") for item in results),
        },
    }
    write_status(final_payload)
    print(json.dumps(final_payload, ensure_ascii=False, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
