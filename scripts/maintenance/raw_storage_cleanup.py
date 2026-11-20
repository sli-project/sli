from __future__ import annotations

import argparse
import json
from pathlib import Path

from server.sli.storage.runtime_storage import apply_raw_cleanup_plan, build_raw_cleanup_plan, get_runtime_storage_summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Dry-run/apply safe raw storage archival for Security Log Intelligence.")
    parser.add_argument("--raw-dir", type=Path, default=None)
    parser.add_argument("--archive-dir", type=Path, default=None)
    parser.add_argument("--older-than-days", type=int, default=7)
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--archive-mode", choices=("move", "zip"), default="move", help="move = перенос в data/raw_archive; zip = упаковка в zip внутри data/raw_archive")
    parser.add_argument("--zip-path", type=Path, default=None, help="Optional explicit zip path for --archive-mode zip.")
    parser.add_argument("--apply", action="store_true", help="Apply archival. Without it only dry-run is performed.")
    parser.add_argument("--summary", action="store_true", help="Print storage summary instead of cleanup plan.")
    parser.add_argument("--no-metadata", action="store_true", help="Do not write data/maintenance/raw_cleanup_last.json metadata.")
    args = parser.parse_args()
    if args.summary:
        print(json.dumps(get_runtime_storage_summary(), ensure_ascii=False, indent=2))
        return 0
    kwargs = {"older_than_days": args.older_than_days, "limit": args.limit, "archive_mode": args.archive_mode}
    if args.raw_dir:
        kwargs["raw_dir"] = args.raw_dir
    if args.archive_dir:
        kwargs["archive_dir"] = args.archive_dir
    if args.zip_path:
        kwargs["zip_path"] = args.zip_path
    plan = build_raw_cleanup_plan(**kwargs)
    result = apply_raw_cleanup_plan(plan, apply=args.apply, write_metadata=not args.no_metadata)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
