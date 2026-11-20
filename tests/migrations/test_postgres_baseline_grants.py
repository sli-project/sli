"""Least-privilege invariants checked against the public PostgreSQL baseline.

The migrations that introduced these grants are folded into the baseline
(config/postgres_baseline, version 144); the old per-migration text tests were
removed, so the security-relevant parts are pinned here against the baseline.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASELINE_SQL = (ROOT / "config" / "postgres_baseline" / "baseline.sql").read_text(encoding="utf-8")

_TABLE_GRANT = re.compile(
    r"^GRANT (?P<privileges>[A-Z, ]+) ON TABLE public\.(?P<table>\w+) TO (?P<role>\w+);$",
    re.MULTILINE,
)


def _table_grants(table: str, role: str) -> set[str]:
    privileges: set[str] = set()
    for match in _TABLE_GRANT.finditer(BASELINE_SQL):
        if match["table"] == table and match["role"] == role:
            privileges.update(part.strip() for part in match["privileges"].split(","))
    return privileges


@pytest.mark.parametrize(
    ("table", "role", "expected"),
    [
        ("ad_snapshot_manifests", "adlog_user", {"SELECT", "INSERT"}),
        ("ad_snapshot_manifest_sources", "adlog_user", {"SELECT", "INSERT"}),
        ("ad_snapshot_projection_outputs", "adlog_user", {"SELECT", "INSERT"}),
        ("ad_snapshot_projection_receipts", "adlog_user", {"SELECT", "INSERT", "UPDATE"}),
        ("investigation_evidence_refs", "adlog_user", {"SELECT", "INSERT"}),
        ("storage_v2_runtime_authorizations", "adlog_user", {"SELECT"}),
        ("storage_v2_keywords", "adlog_user", {"SELECT"}),
        ("storage_v2_keywords", "adlog_semantic_worker", {"SELECT"}),
        ("storage_v2_event_identity_allocations", "adlog_storage_worker", {"SELECT", "INSERT"}),
        ("storage_v2_entity_identity_allocations", "adlog_storage_worker", {"SELECT", "INSERT"}),
        ("raw_log_files", "adlog_storage_worker", {"SELECT", "INSERT", "UPDATE"}),
        ("radius_vpn_session_rows_v1", "adlog_user", {"SELECT"}),
        ("radius_vpn_session_coverage_v1", "adlog_user", {"SELECT"}),
    ],
)
def test_baseline_table_grants_are_exactly_the_least_privilege_set(
    table: str, role: str, expected: set[str]
) -> None:
    assert _table_grants(table, role) == expected


def test_runtime_role_has_no_direct_access_to_the_vpn_session_projection() -> None:
    assert _table_grants("radius_vpn_session_projection", "adlog_user") == set()
    assert not re.search(
        r"^GRANT [^;]* ON TABLE public\.radius_vpn_session_projection TO adlog_user;",
        BASELINE_SQL,
        re.MULTILINE,
    )


def test_runtime_authority_and_identity_tables_are_owned_by_the_storage_owner() -> None:
    for table in (
        "storage_v2_runtime_authorizations",
        "storage_v2_event_identity_allocations",
        "storage_v2_entity_identity_allocations",
    ):
        assert f"ALTER TABLE public.{table} OWNER TO adlog_storage_owner;" in BASELINE_SQL


def test_snapshot_immutability_triggers_stay_fail_closed_for_the_runtime_role() -> None:
    for function in (
        "ad_snapshot_manifest_reject_mutation",
        "ad_snapshot_projection_output_reject_mutation",
    ):
        assert f"ALTER FUNCTION public.{function}() OWNER TO postgres;" in BASELINE_SQL
    for trigger in (
        "trg_ad_snapshot_manifests_immutable",
        "trg_ad_snapshot_manifest_sources_immutable",
        "trg_ad_snapshot_projection_outputs_immutable",
    ):
        assert f"CREATE TRIGGER {trigger} BEFORE DELETE OR UPDATE OR TRUNCATE" in BASELINE_SQL
    function_start = BASELINE_SQL.index("CREATE FUNCTION public.ad_snapshot_manifest_reject_mutation()")
    body = BASELINE_SQL[function_start : BASELINE_SQL.index("$$;", function_start)]
    assert "current_setting(" not in body
    assert "session_user = 'adlog_user'" in body
    assert "AD snapshot manifests are immutable" in body


@pytest.mark.parametrize(
    "signature",
    [
        "public.sli_g11a3_preflight_state_v1()",
        "public.expire_ad_snapshot_seven_day_ring(IN p_published_manifest_id uuid)",
    ],
)
def test_runtime_entrypoints_are_not_executable_by_public(signature: str) -> None:
    kind = "PROCEDURE" if "expire_" in signature else "FUNCTION"
    assert f"REVOKE ALL ON {kind} {signature} FROM PUBLIC;" in BASELINE_SQL
    assert f"GRANT ALL ON {kind} {signature} TO adlog_user;" in BASELINE_SQL
