"""Forward-only wave schema, reservations, immutable attempts and narrow grants."""
import re
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/184_agent_update_waves.sql").read_text("utf-8")


def test_exact_predecessor_and_unique_number():
    assert "version=183 and name='file_audit_contracts'" in SQL
    assert "version>=184" in SQL
    assert "values(184,'agent_update_waves')" in SQL
    assert "hashtext('sli_agent_update_waves_v184')" in SQL
    assert "migration 184 requires exact migration 183 file_audit_contracts and unused version 184" in SQL
    assert [p.name for p in (ROOT / "config/postgres_migrations").glob("184_*.sql")] == ["184_agent_update_waves.sql"]
    pairs = [(item.version, item.name) for item in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    position = pairs.index((184, "agent_update_waves"))
    assert position > 0
    assert pairs[position - 1] == (183, "file_audit_contracts")
    assert sum(version == 184 for version, _ in pairs) == 1


def test_wave_reserves_agents_and_pins_package_attempt_and_bounded_batches():
    assert "batch_size between 1 and 100" in SQL
    assert "error_threshold between 0 and 1000" in SQL
    assert "foreign key(wave_id,package_sha256)" in SQL
    assert "unique(agent_id,package_sha256)" in SQL
    assert "on public.sli_agent_update_wave_members(agent_id) where reserved" in SQL
    assert "had_error boolean not null default false" in SQL
    assert "check((state='failed')=(reason is not null))" in SQL
    assert "check((status='stopped')=(reason is not null))" in SQL


def test_runtime_can_only_change_progress_and_audit_actions_are_preserved():
    assert "grant update(current_batch,status,reason,finished_at)" in SQL
    assert "grant update(state,reason,had_error,reserved,issued_at,reported_at)" in SQL
    assert "pg_get_expr(conbin,conrelid)" in SQL
    for action in ("create", "batch", "stop", "complete", "list", "result"):
        assert "update_wave_" + action in SQL
    assert not re.search(r"grant (?:all|delete|truncate)|on delete cascade|delete from|truncate ", SQL, re.I)
    assert not re.search(r"insert into (?:public\.)?sli_agent_update_policy|update (?:public\.)?sli_agents set", SQL, re.I)
