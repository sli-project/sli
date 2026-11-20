from pathlib import Path

SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/165_ad_snapshot_change_history.sql").read_text()


def test_exact_predecessor_and_durable_pair_hashes_without_hot_foreign_keys():
    assert "version=164 and name='agent_instances'" in SQL
    assert "version>164" in SQL
    assert "values(165,'ad_snapshot_change_history')" in SQL
    table = SQL.split("create table public.ad_snapshot_history_confirmations", 1)[1].split("alter table", 1)[0]
    assert "previous_manifest_id uuid" in table
    assert "previous_sha256" in table and "records_sha256" in table and "record_count" in table
    assert "references" not in table.lower()


def test_purge_is_versioned_and_refuses_unconfirmed_snapshots_before_old_expiry():
    procedure = SQL.split("create procedure public.expire_ad_snapshot_confirmed_ring_v165", 1)[1].split("alter procedure", 1)[0]
    assert "AD snapshot expiry refuses unconfirmed snapshots" in procedure
    assert "AD snapshot expiry refuses unconfirmed compatibility snapshots" in procedure
    assert procedure.index("unconfirmed snapshots") < procedure.index("call public.expire_ad_snapshot_seven_day_ring")
    assert "revoke all on procedure public.expire_ad_snapshot_seven_day_ring(uuid) from adlog_user" in SQL
    assert "where m.manifest_id=h.manifest_id or m.manifest_id=h.previous_manifest_id" in SQL
    assert "current_user='postgres' and session_user='adlog_user'" in SQL
