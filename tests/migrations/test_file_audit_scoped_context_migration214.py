"""Forward-only bounded correlation admission; no runtime database."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory


ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/214_file_audit_scoped_context.sql").read_text("utf-8")


def test_scoped_context_is_forward_only_and_keeps_attestation_and_bounds():
    inventory = forward_migration_inventory(ROOT / "config/postgres_migrations")
    pairs = [(m.version, m.name) for m in inventory]
    assert pairs[pairs.index((214, "file_audit_scoped_context")) - 1] == (213, "ad_directory_display_names")
    assert "version=213 and name='ad_directory_display_names'" in SQL
    assert "where version>=214" in SQL
    assert SQL.strip().endswith("commit;")
    assert "set local role adlog_file_audit_owner;" in SQL
    assert "security definer set search_path=pg_catalog,pg_temp" in SQL
    assert "r.agent_id=p_agent and r.packet_id=p_packet and r.module_id='sli.file-audit'" in SQL
    assert "a.status='active' and a.host_id::text=r.envelope->>'source_instance_id'" in SQL
    assert "i.imported_at is null" in SQL
    assert "jsonb_array_length(p_keys)>256" in SQL and "octet_length(p_keys::text)>1048576" in SQL
    assert "limit 1025" in SQL and "jsonb_array_length(v_rows)<=1024" in SQL
    assert "'observations',case when jsonb_array_length(v_rows)<=1024 then v_rows else '[]'::jsonb end" in SQL
    assert "revoke all on function" in SQL and "from public;" in SQL and "to adlog_user;" in SQL


def test_selector_preserves_every_correlation_boundary_and_does_not_narrow_gap_admission():
    selected = SQL.split("and exists(select 1 from jsonb_array_elements(p_keys) k", 1)[1].split("limit 1025", 1)[0]
    assert "o.normalized->>'policy_revision'=k->>'policy_revision'" in selected
    assert "o.event_id in (4608,1102)" in selected
    # Logoff can invalidate an IP even if its SID differs from the current SID.
    logoff = selected.split("or o.event_id=4634", 1)[1].split("or o.event_id=4624", 1)[0]
    assert "logon_id_numeric" in logoff and "subject_user_sid" not in logoff
    handle = selected.split("or o.event_id in (4656,4659,4663,4658,4660)", 1)[1]
    for field in ("subject_user_sid", "logon_id_numeric", "server_process_id", "handle_id"):
        assert f"o.normalized->'facts'->'{field}'=k->'facts'->'{field}'" in handle
    gap_window = SQL.split("select min(o.record_id)", 1)[1].split("v_complete :=", 1)[0]
    assert "p_keys" not in gap_window
    for binding in ("o.agent_id=p_agent", "o.source_instance_id=v_source", "o.generation=v_generation",
                    "o.observed_at between p_start and p_end"):
        assert binding in gap_window
    assert "r.envelope->>'continuity_state'='gap'" in SQL
    assert "(i.envelope->>'sequence')::bigint<v_sequence" in SQL
