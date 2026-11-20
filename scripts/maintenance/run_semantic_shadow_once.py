"""Run one bounded semantic shadow batch; disabled unless explicitly executed."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.semantic.semantic_processing import SemanticFeatureSettings  # noqa: E402
from server.sli.storage.storage_v2_archive import ArchiveReader  # noqa: E402
from server.sli.storage.storage_v2_config import load_storage_v2_settings  # noqa: E402
from server.sli.storage.storage_v2_repository import PostgresArchiveManifestStore  # noqa: E402
from server.sli.semantic.semantic_worker_connection import (  # noqa: E402
    connect_semantic_worker,
)
from server.sli.semantic.semantic_worker_runtime import process_semantic_outbox  # noqa: E402


def _connect():
    return connect_semantic_worker()


def _archive_reader() -> ArchiveReader:
    load_storage_v2_settings(strict=True)
    return ArchiveReader(
        PostgresArchiveManifestStore(_connect),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run disabled semantic shadow processing.")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--limit", type=int, default=1)
    args = parser.parse_args()
    settings = SemanticFeatureSettings.from_env()
    if not args.execute or not settings.normalization_enabled:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "reason": "--execute and ADLOG_SEMANTIC_NORMALIZATION_ENABLED are required",
                    "connections": 0,
                }
            )
        )
        return 0

    archive = _archive_reader()
    conn = _connect()
    completed = 0
    failed = 0
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                select count(*) as count from schema_migrations
                where (version=25 and name='semantic_persistence_contract')
                   or (version=71 and name='semantic_source_retention_decoupling')
                """
            )
            if int(dict(cur.fetchone() or {}).get("count") or 0) != 2:
                raise RuntimeError("migrations 025 and 071 are required")
        # psycopg starts a transaction for the gate query. Commit it before
        # per-job transactions so accepted work survives connection close.
        conn.commit()
        outcome = process_semantic_outbox(
            conn,
            archive=archive,
            settings=settings,
            limit=args.limit,
        )
        completed = int(outcome["completed"])
        failed = int(outcome["failed"])
    finally:
        conn.close()
    print(
        json.dumps(
            {
                "status": "ok" if not failed else "partial",
                "completed": completed,
                "failed": failed,
            }
        )
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
