from pathlib import Path


GUARD = Path("scripts/maintenance/clickhouse_storage_guard.py").read_text(
    encoding="utf-8"
)
SERVER_CONFIG = Path(
    "config/clickhouse/010_system_log_retention.xml"
).read_text(encoding="utf-8")


def test_storage_guard_accepts_the_local_warm_tier_image() -> None:
    assert 'IMAGE = "clickhouse/clickhouse-server:25.8.28.1"' in GUARD


def test_remaining_clickhouse_system_logs_expire_after_one_day() -> None:
    assert "<query_log>\n        <ttl>event_date + INTERVAL 1 DAY DELETE</ttl>" in SERVER_CONFIG
    assert "<part_log>\n        <ttl>event_date + INTERVAL 1 DAY DELETE</ttl>" in SERVER_CONFIG
    assert "<error_log>\n        <ttl>event_date + INTERVAL 1 DAY DELETE</ttl>" in SERVER_CONFIG
