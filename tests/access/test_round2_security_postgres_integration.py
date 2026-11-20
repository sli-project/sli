from __future__ import annotations

import os
import uuid

import pytest

from server.sli.access import access_control_v4
from server.sli.reporting import reporting_v4
from server.sli.access.access_control_v4 import capability_decision


@pytest.mark.postgres_integration
def test_viewer_explicit_grants_and_scoped_denies_on_disposable_postgres(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL integration tests")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    suffix = uuid.uuid4().hex[:12]
    username = f"round2-viewer-{suffix}"
    group_key = f"round2-group-{suffix}"
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute(
            "insert into auth_users(username,password_hash,role) values (%s,'test-only','viewer') returning id",
            (username,),
        )
        user_id = int(cur.fetchone()["id"])
        cur.execute(
            "insert into access_groups(group_key,name) values (%s,%s) returning id",
            (group_key, group_key),
        )
        group_id = int(cur.fetchone()["id"])
        cur.execute(
            "insert into access_group_members(group_id,user_id,source) values (%s,%s,'test')",
            (group_id, user_id),
        )
        cur.execute("select id,capability_key from access_capabilities where capability_key=any(%s)", (
            ["evidence.exact", "reports.export", "events.view", "tasks.create"],
        ))
        capability_ids = {str(row["capability_key"]): int(row["id"]) for row in cur.fetchall()}
        assignments = [
            ("user", user_id, capability_ids["evidence.exact"], "allow", "{}", "direct"),
            ("group", group_id, capability_ids["reports.export"], "allow", "{}", "group"),
            ("user", user_id, capability_ids["events.view"], "deny", '{"kind":"server","ids":[7]}', "direct"),
            ("user", user_id, capability_ids["tasks.create"], "allow", '{"ids":[7]}', "direct"),
        ]
        cur.executemany(
            """insert into access_capability_assignments(
                   subject_type,subject_id,capability_id,effect,scope_json,business_reason,source_type
               ) values (%s,%s,%s,%s,%s::jsonb,'round2 disposable test',%s)""",
            assignments,
        )
        conn.commit()

    monkeypatch.setattr(
        access_control_v4, "_connect",
        lambda: psycopg.connect(dsn, row_factory=dict_row),
    )
    access = access_control_v4.effective_access({
        "type": "session", "id": user_id, "username": username, "role": "viewer",
    })

    assert "evidence.exact" in access["capabilities"]
    assert "reports.export" in access["capabilities"]
    assert "tasks.create" not in access["capabilities"]
    assert any(item["reason"] == "invalid_scope" for item in access["quarantined_capability_assignments"])
    assert any(
        item["capability_key"] == "events.view" and item["effect"] == "deny"
        for item in access["resource_bound_capability_assignments"]
    )
    assert not any(
        item["capability_key"] == "events.view"
        for item in access["quarantined_capability_assignments"]
    )
    assert capability_decision(access, "events.view", resource={"kind": "server", "id": 7})["reason"] == "explicit_deny"
    assert capability_decision(access, "events.view", resource={"kind": "server", "id": 8})["allowed"] is True
    assert capability_decision(access, "events.view")["reason"] == "resource_context_required"
    assert access["capability_explain"]["evidence.exact"][0]["source"] == f"user:{user_id}"
    assert access["capability_explain"]["reports.export"][0]["source"] == f"group:{group_id}"


@pytest.mark.postgres_integration
def test_disjoint_report_grants_execute_as_separate_postgres_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL integration tests")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    suffix = uuid.uuid4().hex[:12]
    entity_base = 1_000_000 + int(suffix[:6], 16) * 2
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        cur.execute("insert into forests(name) values (%s) returning id", (f"report-{suffix}",))
        forest_id = int(cur.fetchone()["id"])
        cur.execute("insert into domains(forest_id,fqdn) values (%s,%s) returning id", (forest_id, f"report-{suffix}.invalid"))
        domain_id = int(cur.fetchone()["id"])
        cur.execute("insert into servers(domain_id,hostname) values (%s,%s) returning id", (domain_id, f"basic-{suffix}"))
        basic_server = int(cur.fetchone()["id"])
        cur.execute("insert into servers(domain_id,hostname) values (%s,%s) returning id", (domain_id, f"technical-{suffix}"))
        technical_server = int(cur.fetchone()["id"])
        cur.execute("insert into storage_v2_entity_type(value) values (%s) returning id", (f"round2-{suffix}",))
        entity_type_id = int(cur.fetchone()["id"])
        cur.execute("select coalesce(max(version),0)+1 as version from report_datasets_v4 where dataset_key='entities.v2'")
        dataset_version = int(cur.fetchone()["version"])
        cur.execute(
            """insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,server_id,source_core_sha256)
               values (%s,%s,'basic-secret','basic-visible',%s,%s,decode(repeat('11',32),'hex')),
                      (%s,%s,'technical-visible','technical-secret',%s,%s,decode(repeat('22',32),'hex'))""",
            (entity_base, entity_type_id, domain_id, basic_server, entity_base + 1, entity_type_id, domain_id, technical_server),
        )
        cur.execute(
            """insert into report_datasets_v4(
                   dataset_key,version,name,fields_json,filters_json,actions_json,status
               ) values ('entities.v2',%s,%s,%s::jsonb,'[]'::jsonb,'["view"]'::jsonb,'published') returning id""",
            (
                dataset_version,
                f"Round2 {suffix}",
                '[{"key":"display_name","label":"Name","category":"identity_basic"},'
                '{"key":"natural_key","label":"Key","category":"technical"}]',
            ),
        )
        dataset_id = int(cur.fetchone()["id"])
        report_key = f"round2.tuple.{suffix}"
        cur.execute(
            """insert into report_registry_v4(
                   report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status
               ) values (%s,1,%s,'round2','test',%s,%s::jsonb,'internal','published')""",
            (report_key, report_key, dataset_id, '{"columns":["display_name","natural_key"],"actions":["view"]}'),
        )
        conn.commit()

    monkeypatch.setattr(reporting_v4, "_connect", lambda: psycopg.connect(dsn, row_factory=dict_row))

    def query_rows(sql: str, params=(), **_kwargs):
        with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(sql.replace("?", "%s"), params)
            return [dict(row) for row in cur.fetchall()]

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", query_rows)
    access = {
        "capabilities": ["reports.catalog", "field.identity_basic", "field.technical"],
        "reports": [{
            "report_key": report_key, "version": 1, "allowed": True,
            "grants": [
                {"source": "A", "scope": {"kind": "server", "ids": [basic_server]}, "field_categories": ["identity_basic"], "allowed_actions": ["view"]},
                {"source": "B", "scope": {"kind": "server", "ids": [technical_server]}, "field_categories": ["technical"], "allowed_actions": ["view"]},
            ],
        }],
    }

    result = reporting_v4.execute_report(report_key, None, access=access)

    assert {tuple(sorted(row)) for row in result["items"]} == {("display_name",), ("natural_key",)}
    assert {next(iter(row.values())) for row in result["items"]} == {"basic-visible", "technical-visible"}
