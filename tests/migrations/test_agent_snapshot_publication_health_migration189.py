"""Forward-only publication constraints and narrow worker authority."""
import re
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

PATH = (Path(__file__).resolve().parents[2] /
        "config/postgres_migrations/189_agent_snapshot_publication_health.sql")
SQL = PATH.read_text("utf-8")


def test_publication_health_migration_follows_predecessor_and_versions_are_unique():
    inventory = forward_migration_inventory(PATH.parent)
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((189, "agent_snapshot_publication_health"))
    assert position > 0
    assert pairs[position - 1] == (188, "agent_group_deployment")
    assert len(pairs) == len({version for version, _ in pairs})
    assert max(version for version, _ in pairs[:position]) + 1 == 189
    assert inventory[position].path == PATH
    assert list(PATH.parent.glob("189_*.sql")) == [PATH]


def test_forward_migration_requires_exact_predecessors_and_preserves_legacy_slots():
    for version, name in ((188, "agent_group_deployment"), (128, "ad_snapshot_v2_schedule"),
                          (174, "agent_gpo_snapshot_import")):
        assert f"version={version} and name='{name}'" in SQL
    assert "version>=189" in SQL
    assert "values(189,'agent_snapshot_publication_health')" in SQL
    assert "pg_advisory_xact_lock(hashtext('sli_agent_snapshot_publication_health_v189'))" in SQL
    for version in (1, 2, 3):
        assert f"contract_version='sli.ad-snapshot-manifest/{version}.0'" in SQL
    assert "scheduled_local_at::time in (time '06:00:00',time '18:00:00')" in SQL
    assert "slot_start_utc=scheduled_local_at at time zone 'UTC'" in SQL
    assert "scheduled_local_at=date_trunc('minute',scheduled_local_at)" in SQL
    assert "before insert on public.ad_snapshot_manifests" in SQL
    assert not re.search(r"(?:update|delete from) public.ad_snapshot_manifests", SQL, re.IGNORECASE)


def test_terminal_receipt_requires_completed_transport_and_no_published_source():
    terminal = SQL.split("(publication_state='superseded'", 1)[1]
    for condition in ("transport_state='complete'", "manifest_id is null", "gpo_source_run_id is null",
                      "published_at is null", "superseded_at is not null", "superseded_reason is not null"):
        assert condition in terminal
    assert "module_id='sli.ad-snapshot' and superseded_reason='agent_ad_snapshot_superseded'" in terminal
    assert "module_id='sli.gpo-snapshot' and superseded_reason='agent_gpo_snapshot_superseded'" in terminal
    grants = re.findall(r"^grant .*?;", SQL, re.MULTILINE)
    assert grants == ["grant update(superseded_reason,superseded_at) on public.sli_agent_snapshot_cycles to adlog_context_worker;"]
    assert not re.search(r"grant .*?to (?:public|adlog_user)\s*;", SQL, re.IGNORECASE)
