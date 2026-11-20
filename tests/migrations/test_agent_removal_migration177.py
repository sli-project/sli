"""Forward-only removal queue with bounded runtime grants and exact predecessor."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "config/postgres_migrations"
SQL = (MIGRATIONS / "177_agent_removal.sql").read_text("utf-8").lower()


def test_exact_predecessor_and_unique_number():
    assert "version=176 and name='workstation_history'" in SQL
    assert "version>176" in SQL and "where version=177" in SQL
    assert "values(177,'agent_removal')" in SQL
    paths = list(MIGRATIONS.glob("[0-9]*_*.sql"))
    assert [path.name for path in paths if int(path.name.split("_", 1)[0]) == 177] == ["177_agent_removal.sql"]
    assert [path.name for path in paths if int(path.name.split("_", 1)[0]) == 176] == ["176_workstation_history.sql"]
    assert (MIGRATIONS / "176_workstation_history.sql").is_file()


def test_queue_preserves_history_and_prior_audit_actions():
    assert "agent_id uuid primary key references public.sli_agents(id)" in SQL
    assert "command_id uuid not null unique" in SQL
    assert "operation_id uuid not null" in SQL
    assert "'pending','cleanup_failed','state_cleaned'" in SQL
    assert "pg_get_expr(conbin,conrelid)" in SQL
    assert "removal_request" in SQL and "removal_result" in SQL
    assert "grant update(state,reason,reported_at)" in SQL
    assert not re.search(r"grant (?:all|delete|truncate)|on delete cascade|delete from|truncate ", SQL)
    assert "grant select,insert on public.sli_agent_removals to adlog_user" in SQL
