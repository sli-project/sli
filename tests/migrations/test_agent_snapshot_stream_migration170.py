"""Migration 170 transport-only schema and narrow grants, without a real DB."""
from pathlib import Path
import re

SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/170_agent_snapshot_stream.sql").read_text("utf-8")


def test_reserved_predecessors_and_no_default_collection():
    header, body = SQL.split("set local role adlog_storage_owner;", 1)
    assert "requires membership in adlog_storage_owner" in header
    assert "where version=170" in header
    assert "where version=167 and name='agent_updates'" in header
    assert "where version=168" in header
    assert "where version=169 and name='agent_collection_control'" in header
    assert "where version>169" in header
    assert "values(170,'agent_snapshot_stream')" in body
    assert "enabled boolean not null default false" in body
    assert "unique index sli_agent_snapshot_domain_collector" in body and "where enabled" in body
    assert not re.search(r"insert into (?:public\.)?sli_agents", body)


def test_durable_chunks_receipts_membership_and_completion():
    for table in ("sli_agent_snapshot_bindings", "sli_agent_snapshot_policies", "sli_agent_snapshot_cycles", "sli_agent_snapshot_chunks"):
        assert f"create table public.{table}" in SQL
    assert "packet_id uuid primary key references public.sli_agent_receipts(packet_id)" in SQL
    assert "unique(cycle_id,family,chunk_index)" in SQL
    assert "unique(domain_sid,module_id,slot_start_utc)" in SQL
    assert "transport_state in ('pending','complete')" in SQL
    assert "octet_length(payload::text)<=61440" in SQL
    assert "sli.ad-snapshot.chunk.v1" in SQL and "sli.gpo-snapshot.chunk.v1" in SQL
    assert "ad_context_runs" not in SQL and "gpo_report_v2_source_snapshots" not in SQL


def test_no_raw_chunk_updates_deletes_or_public_grants():
    grants = re.findall(r"grant[^;]+;", SQL)
    assert len(grants) == 4
    assert "grant select,insert on public.sli_agent_snapshot_bindings" in grants[0]
    assert grants[1] == "grant update(config,enabled) on public.sli_agent_snapshot_bindings to adlog_user;"
    assert grants[2] == "grant update(superseded_at) on public.sli_agent_snapshot_policies to adlog_user;"
    assert grants[3] == "grant update(transport_state,completed_at) on public.sli_agent_snapshot_cycles to adlog_user;"
    assert "from public,adlog_user;" in SQL
    assert not any("delete" in grant or "to public" in grant for grant in grants)
