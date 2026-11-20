"""Static additive migration contract; does not apply SQL or need a database."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/157_agent_packets.sql").read_text(encoding="utf-8")


def test_exact_part_a_predecessor_and_owner_guard():
    assert "version=156 and name='agent_registry'" in SQL
    assert "pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER')" in SQL
    assert "set local role adlog_storage_owner" in SQL
    assert "version=157" in SQL
    assert "values(157,'agent_packets')" in SQL
    assert SQL.strip().startswith("begin;") and SQL.strip().endswith("commit;")


def test_sequence_and_packet_id_are_unique_and_evidence_is_durable():
    assert "primary key(agent_id,module_id,sequence)" in SQL
    assert "packet_id uuid not null unique" in SQL
    assert "references sli_agents(id)" in SQL
    assert "references sli_agent_receipts(packet_id)" in SQL
    assert "event_rows jsonb not null" in SQL
    assert "where imported_at is null" in SQL
    assert "delete from" not in SQL.lower()
    assert "drop " not in SQL.lower()


def test_collection_is_not_enabled_and_runtime_cannot_rewrite_receipts():
    grants = [line.strip() for line in SQL.splitlines() if line.startswith("grant ")]
    assert "grant select on sli_agent_module_bindings to adlog_user;" in grants
    assert not any("insert" in line and "sli_agent_module_bindings" in line for line in grants)
    assert not any("update" in line and "sli_agent_receipts" in line for line in grants)
    assert "grant update(imported_at) on sli_agent_packet_inbox to adlog_user;" in grants
    assert not any("delete" in line or "create" in line and "adlog_user" in line for line in grants)
    assert "insert into sli_agent_module_bindings" not in SQL
    assert "update sli_agents" not in SQL
