"""Readable policy metadata through the real PostgreSQL governance query."""
from datetime import datetime, timezone
import os
from uuid import uuid4

import pytest

from server.sli.semantic.semantic_governance import list_controls
from tests.postgres_integration_guard import assert_disposable_database


@pytest.mark.postgres_integration
@pytest.mark.skipif(not os.environ.get("ADLOG_TEST_PG_DSN"), reason="isolated PostgreSQL DSN not configured")
def test_policy_metadata_uses_version_registration_not_lifecycle_update(isolated_postgres_integration_database):
    # The isolation fixture rewrites this to a disposable migrated clone.
    # Administrative test connection: this is not a runtime-role privilege test.
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL tests")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    policy_id = f"000-t058-{uuid4()}"
    created = datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        try:
            with conn.cursor() as cur:
                cur.execute("""insert into semantic_risk_policies
                    (policy_id,policy_version,source_kind,lifecycle_status,definition_json,
                     definition_sha256,created_at,updated_at)
                    values (%s,1,'control_health','draft',%s::jsonb,%s,%s,%s)""",
                    (policy_id, '{"title":"Synthetic audit rule"}', bytes(32), created,
                     datetime(2026, 10, 1, tzinfo=timezone.utc)))
                policies = list_controls(cur)["policies"]
                policy = next(item for item in policies if item["policy_id"] == policy_id)
                assert policy["title"] == "Synthetic audit rule"
                assert datetime.fromisoformat(policy["version_created_at"]) == created
                assert policy["policy_version"] == 1
                assert "definition_json" not in policy
                assert "definition_sha256" not in policy
                assert "updated_at" not in policy
        finally:
            conn.rollback()
