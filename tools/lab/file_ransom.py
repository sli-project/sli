"""One-shot native file operations inside an administrator-owned LAB audit root.

Provision C:/SLI-Lab/file-ransom-owned and the same marker in each selected
local root, then configure its audit through the normal administrator workflow.
Run --operation boundary --count 100 for N-1/N (a pause before the final file);
use --operation write --count 99 for an independent below-threshold control;
use --operation burst for the normal 110-file/5-minute workload (expected high
at the default 100/300 policy unless an explicit temporary approval applies).
Repeat under two administrator-provisioned synthetic identities and two audited
roots for isolation. Replay the retained collector packet through the normal
ingest path; generating new native actions is not evidence of packet replay.
No users, audit settings, services or background schedules are created here.
Read/delete prepare their own files, then wait one policy window before the
measured operation. Preparation can itself produce a write problem; distinguish
that earlier episode from the read/delete evidence during acceptance.
"""
import argparse
import json
import os
from pathlib import Path
import time
from uuid import uuid4


def generate(root, *, operation, count=100, window_seconds=300, pause=time.sleep):
    if (operation not in {"write", "boundary", "delete", "read", "repeat", "burst"}
            or type(count) is not int or not 1 <= count <= 1000
            or type(window_seconds) is not int or not 1 <= window_seconds <= 86400
            or operation == "burst" and count != 110):
        raise ValueError("file_ransom_lab_arguments_invalid")
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or not (root / "file-ransom-owned").is_file():
        raise ValueError("file_ransom_lab_not_owned")
    # A fresh directory ensures no pre-existing file can be overwritten/deleted.
    run_id = str(uuid4())
    target = root / ("ransom-" + run_id)
    target.mkdir()
    paths = [target / f"synthetic-{index:04d}.txt" for index in range(1 if operation == "repeat" else count)]
    prepared = operation in {"read", "delete", "repeat"}
    if prepared:
        for path in paths:
            with path.open("xb") as stream:
                stream.write(b"SLI synthetic file activity\n")
        if operation in {"read", "delete"}:
            pause(window_seconds + 1)
    started = time.monotonic()
    for index in range(count):
        path = paths[0] if operation == "repeat" else paths[index]
        if operation == "delete":
            path.unlink()
        elif operation == "read":
            path.read_bytes()
        else:
            with path.open("ab" if prepared else "xb") as stream:
                stream.write(b"SLI synthetic update\n")
        if operation == "burst" and index + 1 < count:
            pause(window_seconds / count)
        if operation == "boundary" and index + 1 == count - 1:
            pause(min(10, window_seconds / 2))
    return {"state": "native_operations_completed", "run_id": run_id, "operation": operation,
            "operations": count, "distinct_files": len(paths),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "setup_writes": len(paths) if prepared else 0,
            "setup_may_trigger_write": prepared and len(paths) >= 100,
            "first_phase_files": count - 1 if operation == "boundary" else None,
            "preparation_wait_seconds": window_seconds + 1 if operation in {"read", "delete"} else 0,
            "expected_default_burst": "high_or_explicit_temporary_exclusion" if operation == "burst" else None,
            "native_evidence": "not_proven", "sli_queue": "not_proven",
            "replay": "not_proven", "smtp": "not_proven", "telegram": "not_proven"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--operation", required=True, choices=("write", "boundary", "delete", "read", "repeat", "burst"))
    parser.add_argument("--count", type=int)
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args()
    try:
        root = Path(args.root).resolve(strict=True)
        lab = Path("C:/SLI-Lab").resolve(strict=True)
        if os.name != "nt" or not root.is_relative_to(lab) or not (lab / "file-ransom-owned").is_file():
            raise ValueError("file_ransom_lab_not_owned")
        count = args.count if args.count is not None else (110 if args.operation == "burst" else 100)
        result = generate(root, operation=args.operation, count=count, window_seconds=args.window_seconds)
    except Exception:
        result = {"state": "not_proven", "code": "file_ransom_lab_unavailable"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["state"] == "native_operations_completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
