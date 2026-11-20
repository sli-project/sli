from __future__ import annotations

"""Dormant manual compatibility shim for one exact immutable manifest."""

import argparse
import json

from server.sli.sources.ad_snapshot_projection import run_exact_manifest_projection_cycle
from server.sli.core.postgres_runtime_pipeline import connect


def run_once(
    *,
    manifest_id: str,
    worker_id: str = "ad-snapshot-projection-manual",
) -> dict[str, object]:
    """Delegate one exact manifest to the coordinator-owned common routine."""
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.sources.ad_gpo_jobs import enabled

    if enabled():
        return {"status": "skipped", "reason": "core_job_queue_owns_source"}
    if not manifest_id:
        raise ValueError("manifest_id is required")
    with connect() as connection:
        return run_exact_manifest_projection_cycle(
            connection,
            manifest_id=manifest_id,
            worker_id=worker_id,
        )


def main(argv: list[str] | None = None) -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.sources.ad_gpo_jobs import enabled

    if enabled():
        return 0
    parser = argparse.ArgumentParser(
        description="Run one exact-manifest compatibility projection readback cycle"
    )
    parser.add_argument("--once", action="store_true", required=True)
    parser.add_argument("--manifest-id", required=True)
    parser.add_argument("--worker-id", default="ad-snapshot-projection-manual")
    args = parser.parse_args(argv)
    result = run_once(manifest_id=args.manifest_id, worker_id=args.worker_id)
    print(json.dumps(result, ensure_ascii=False, default=str), flush=True)
    return 0 if result.get("status") in {"completed", "pending"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
