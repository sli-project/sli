"""Exercise both production inventory reads on the CI-owned migrated schema."""

import hashlib
import os
import uuid

import pytest

from server.sli.access import access_control_v4, auth

pytestmark = pytest.mark.postgres_integration


def test_service_inventory_uses_key_relationship_after_revocation_and_expiry(monkeypatch):
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("Disposable migrated PostgreSQL required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    suffix = uuid.uuid4().hex[:12]
    expected = {}
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        # Names and active flags are deliberately misleading: neither is type evidence.
        for name, active, service in [
            ("person", True, False), ("report-key-person", False, False),
            ("renamed-reader", True, True), ("revoked-reader", False, True),
            ("expired-reader", True, True),
        ]:
            user_id = conn.execute(
                "insert into auth_users(username,password_hash,role,is_active) values (%s,'test-only','viewer',%s) returning id",
                (f"{name}-{suffix}", active),
            ).fetchone()["id"]
            expected[user_id] = service
            if not service:
                continue
            for number in range(2 if name == "renamed-reader" else 1):
                label = f"synthetic-{suffix}-{name}-{number}"
                conn.execute(
                    """insert into auth_api_keys(key_prefix,key_hash,label,role,is_active,report_subject_id,revoked_at,expires_at)
                       values (%s,%s,%s,'viewer',%s,%s,
                               case when %s then now() else null end,
                               now() + case when %s then interval '-1 day' else interval '1 day' end)""",
                    (label, hashlib.sha256(label.encode()).hexdigest(), label, active, user_id,
                     name == "revoked-reader", name == "expired-reader"),
                )
        # An ordinary key has no report subject and must not classify any person.
        label = f"synthetic-{suffix}-ordinary"
        conn.execute(
            "insert into auth_api_keys(key_prefix,key_hash,label,role) values (%s,%s,%s,'viewer')",
            (label, hashlib.sha256(label.encode()).hexdigest(), label),
        )
        conn.commit()
        before = conn.execute("select to_jsonb(u) as row from auth_users u where id=any(%s) order by id", (list(expected),)).fetchall()
        key_before = conn.execute("select to_jsonb(k) as row from auth_api_keys k order by id").fetchall()

        for owner in (auth, access_control_v4):
            monkeypatch.setattr(owner, "_connect", lambda: psycopg.connect(dsn, row_factory=dict_row))
        for rows in (auth.list_users(), access_control_v4.list_access_subjects()["users"]):
            observed = {row["id"]: row["is_service"] for row in rows if row["id"] in expected}
            assert observed == expected
            assert sum(row["id"] in expected for row in rows) == len(expected)
            assert all(type(value) is bool for value in observed.values())
            assert all("password_hash" not in row and "key_hash" not in row for row in rows)

        assert conn.execute("select to_jsonb(u) as row from auth_users u where id=any(%s) order by id", (list(expected),)).fetchall() == before
        assert conn.execute("select to_jsonb(k) as row from auth_api_keys k order by id").fetchall() == key_before


@pytest.mark.parametrize("majority_service", [False, True])
@pytest.mark.parametrize("marker_only", [False, True])
def test_subject_filter_precedes_cap_with_more_than_500_opposite_accounts(monkeypatch, majority_service, marker_only):
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("Disposable migrated PostgreSQL required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    suffix = uuid.uuid4().hex[:12]
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        majority_ids = [row["id"] for row in conn.execute(
            """insert into auth_users(username,password_hash,role)
               select %s || n::text, 'test-only', 'viewer' from generate_series(1,501) n returning id""",
            (f"aaaa-t007-{suffix}-",),
        ).fetchall()]
        minority_id = conn.execute(
            "insert into auth_users(username,password_hash,role) values (%s,'test-only','viewer') returning id",
            (f"zzzz-t007-{suffix}",),
        ).fetchone()["id"]
        service_ids = majority_ids if majority_service else [minority_id]
        if marker_only:
            conn.execute("update auth_users set is_service=true where id=any(%s)", (service_ids,))
        with conn.cursor() as cur:
            cur.executemany(
                """insert into auth_api_keys(key_prefix,key_hash,label,role,report_subject_id,revoked_at,is_active)
                   values (%s,%s,'synthetic','viewer',%s,now(),false)""",
                [(f"t007-{suffix}-{id_}", hashlib.sha256(f"{suffix}-{id_}".encode()).hexdigest(), id_) for id_ in ([] if marker_only else service_ids)],
            )
        conn.commit()
    monkeypatch.setattr(access_control_v4, "_connect", lambda: psycopg.connect(dsn, row_factory=dict_row))
    unfiltered = access_control_v4.list_access_subjects()["users"]
    assert len(unfiltered) == 500
    assert minority_id not in {row["id"] for row in unfiltered}
    for kind, service in [("people", False), ("service", True)]:
        filtered = access_control_v4.list_access_subjects(account_type=kind)["users"]
        assert len(filtered) <= 500
        assert all(row["is_service"] is service for row in filtered)
        if service != majority_service:
            assert minority_id in {row["id"] for row in filtered}
