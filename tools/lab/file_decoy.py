"""One-shot D03 LAB probe, using files and audit prepared by an administrator.

Under C:/SLI-Lab create file-decoy-owned in the selected audited root, then
prepare decoy-bait.txt and decoy-neighbor.txt. Register only decoy-bait.txt in
SLI. Run read and neighbor under a synthetic allowed identity; run denied
under a synthetic identity whose file read is already denied by the OS.
This probe never edits permissions, labels, sources or file contents. Validate
native evidence, the queue, readiness and both channels after normal collection.
Replay the retained packet through normal ingest for the separate replay check.
"""
import argparse
import json
import os
from pathlib import Path


def generate(root, *, operation):
    if operation not in ("read", "denied", "neighbor"):
        raise ValueError("file_decoy_lab_arguments_invalid")
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or not (root / "file-decoy-owned").is_file():
        raise ValueError("file_decoy_lab_not_owned")
    target = root / ("decoy-neighbor.txt" if operation == "neighbor" else "decoy-bait.txt")
    if target.is_symlink() or not target.resolve().is_relative_to(root):
        raise ValueError("file_decoy_lab_not_owned")
    try:
        with target.open("rb") as stream:
            stream.read(1)
    except PermissionError:
        observed = "denied"
    else:
        observed = "read"
    expected = "denied" if operation == "denied" else "read"
    return {"state": "native_operation_completed" if observed == expected else "unexpected_outcome",
            "operation": operation, "outcome": observed,
            "expected_detection": "no_match" if operation == "neighbor" else "high",
            "native_evidence": "not_proven", "sli_queue": "not_proven", "replay": "not_proven",
            "audit_loss": "not_proven", "smtp": "not_proven", "telegram": "not_proven"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--operation", required=True, choices=("read", "denied", "neighbor"))
    args = parser.parse_args()
    try:
        root, lab = Path(args.root).resolve(strict=True), Path("C:/SLI-Lab").resolve(strict=True)
        if os.name != "nt" or not root.is_relative_to(lab) or not (lab / "file-decoy-owned").is_file():
            raise ValueError("file_decoy_lab_not_owned")
        result = generate(root, operation=args.operation)
    except Exception:
        result = {"state": "not_proven", "code": "file_decoy_lab_unavailable"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["state"] == "native_operation_completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
