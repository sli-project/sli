from __future__ import annotations

import importlib
import os
import uuid

import pytest

from server.sli.storage.storage_v2_repository import PostgresStorageV2Repository

importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_direct_raw_file_reservation_and_finalization_reuse_canonical_digest() -> None:
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL integration tests")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    suffix = uuid.uuid4().hex
    digest = "a" * 64
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute("insert into forests(name) values (%s) returning id", (f"round2-{suffix}",))
        forest_id = int(cur.fetchone()["id"])
        cur.execute("insert into domains(forest_id,fqdn) values (%s,%s) returning id", (forest_id, f"{suffix}.invalid"))
        domain_id = int(cur.fetchone()["id"])
        cur.execute("insert into servers(domain_id,hostname) values (%s,%s) returning id", (domain_id, f"srv-{suffix}"))
        server_id = int(cur.fetchone()["id"])
        cur.execute("insert into log_sources(name) values (%s) returning id", (f"Security-{suffix}",))
        source_id = int(cur.fetchone()["id"])
        conn.commit()

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    repository = PostgresStorageV2Repository(connect)
    reservation = {
        "server_id": server_id, "log_source_id": source_id, "sha256": digest, "size_bytes": 10,
    }
    canonical = repository.reserve_raw_log_file(
        **reservation, file_path=f"canonical-{suffix}.jsonl",
    )
    repeated = repository.reserve_raw_log_file(
        **reservation, file_path=f"repeated-{suffix}.jsonl",
    )
    canonical_id = int(canonical["id"])
    assert int(repeated["id"]) == canonical_id

    with connect() as conn, conn.cursor() as cur:
        result_id = importer.finalize_raw_log_file(
            cur, raw_log_file_id=canonical_id, server_id=server_id,
            log_source_id=source_id, sha256_value=digest, rows_count=1,
        )
        assert result_id == canonical_id
        cur.execute(
            "select id,sha256,event_count from raw_log_files "
            "where server_id=%s and log_source_id=%s",
            (server_id, source_id),
        )
        assert cur.fetchall() == [{"id": canonical_id, "sha256": digest, "event_count": 1}]
