"""Review regressions for the fixed SQL authority and current reader identity.

These source checks are paired with real-PG negative tests; they do not prove
runtime behavior while the shared resource gate prevents that test run.
"""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/287_workstation_inventory_job.sql").read_text("utf-8")


def test_reused_definer_role_rejects_unexpected_recipients_as_well_as_parent_roles():
    assert "m.member=owner_id" in SQL
    assert "m.roleid=owner_id" in SQL
    assert "m.member<>storage_owner_id" in SQL


def test_287_cannot_skip_the_separately_owned_286():
    assert "version=286 and name='sigma_rule_labels'" in SQL


def test_publication_has_a_nonoptional_commit_receipt_and_single_job_page():
    assert "create constraint trigger inventory_core_receipt" in SQL
    assert "deferrable initially deferred" in SQL
    assert "job_id uuid primary key" in SQL
    assert "for update" in SQL


def test_canonical_page_is_derived_inside_database_and_compared_in_full():
    assert "create function sli_plugin_workstations.inventory_page_v1" in SQL
    assert "p_rows is distinct from expected->'rows'" in SQL
    assert "p_cursor is distinct from expected->>'next_cursor'" in SQL


def test_identity_conflict_has_durable_bounded_retry_without_rewriting_old_ids():
    assert "create table sli_plugin_workstations.inventory_deferred" in SQL
    assert "identity_owner_conflict" in SQL and "source_identity_unavailable" in SQL
    assert "limit 81" in SQL and "limit 20" in SQL
    assert "interval '5 minutes'" in SQL
    assert "delete from sli_plugin_workstations.station_inventory" not in SQL
