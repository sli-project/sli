"""Native ClickHouse render/receipt contracts; no services, DB or credentials."""
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from deploy.linux import native_clickhouse as ch

ROOT = Path(__file__).resolve().parents[2]


def test_isolated_units_share_binary_and_have_no_autostart():
    assert len({port for i in ch.INSTANCES for port in (i.http, i.native, i.interserver)}) == 6
    for field in ("user", "config", "data", "logs", "backup"):
        assert len({getattr(i, field) for i in ch.INSTANCES}) == 2
    for i in ch.INSTANCES:
        unit = ch.unit(i)
        assert "ExecStart=/usr/bin/clickhouse server " in unit
        assert "Environment=CLICKHOUSE_WATCHDOG_ENABLE=0\n" in unit
        assert f"User={i.user}\n" in unit
        assert f"MemoryMax={ch.MEMORY_BYTES}\n" in unit
        assert f"ReadWritePaths={i.data} {i.logs} {i.backup}\n" in unit
        assert "[Install]" not in unit and "password" not in unit


@pytest.mark.parametrize("instance", ch.INSTANCES)
def test_configuration_preserves_fragments_and_translates_backup_root(instance):
    files = ch.configuration(instance, "a" * 64, ROOT)
    config = ET.fromstring(files["config.xml"])
    assert config.findtext("listen_host") == "127.0.0.1"
    assert config.findtext("interserver_listen_host") == "127.0.0.1"
    assert config.findtext("path") == instance.data + "/"
    assert config.findtext("max_server_memory_usage") == str(ch.MEMORY_BYTES)
    assert [config.findtext(p) for p in ("http_port", "tcp_port", "interserver_http_port")] == [
        str(instance.http), str(instance.native), str(instance.interserver)]
    users = ET.fromstring(files["users.xml"])
    assert [node.tag for node in users.find("users")] == [instance.user]
    assert users.findtext(f"users/{instance.user}/password_sha256_hex") == "a" * 64
    for source, target in (("010_system_log_retention.xml", "config.d/010_system_log_retention.xml"),
                           ("011_disable_sampling_profiler.xml", "users.d/011_disable_sampling_profiler.xml"),
                           ("012_backup_limits.xml", "config.d/013_backup_limits.xml")):
        assert files[target] == (ROOT / "config/clickhouse" / source).read_text(encoding="utf-8")
    backup = ET.fromstring(files["config.d/012_history_backup.xml"])
    assert backup.findtext("storage_configuration/disks/backups/path") == instance.backup + "/"
    assert backup.findtext("backups/allowed_path") == instance.backup + "/"
    assert backup.findtext("backups/allowed_disk") == "backups"


def test_invalid_hash_rejected_without_echoing_input():
    with pytest.raises(ValueError, match="^native_clickhouse_configuration_invalid$"):
        ch.configuration(ch.INSTANCES[0], "synthetic-invalid-secret", ROOT)


def test_inventory_uses_only_injected_read_adapter():
    calls = []
    def fake(sql):
        calls.append(sql)
        return [{"database": "sli_history", "name": "events", "engine": "MergeTree"}]
    assert ch.inventory(fake)[0]["name"] == "events"
    assert len(calls) == 1 and calls[0].startswith("SELECT ")
    assert "create_table_query,total_rows,total_bytes" in calls[0]
    assert "ORDER BY database,name" in calls[0]


def test_digest_preserves_values_multiplicity_and_ignores_input_order():
    rows = [{"id": 2, "at": "2026-10-26 00:00:00.123456"}, {"id": 1, "value": None}]
    assert ch.digest_rows(rows) == ch.digest_rows(list(reversed(rows)))
    assert ch.digest_rows(rows) != ch.digest_rows(rows + rows[:1])
    assert ch.digest_rows(rows) != ch.digest_rows([rows[0] | {"at": "2026-10-26 00:00:00.123457"}, rows[1]])


def test_ddl_distribution_matches_native_endpoints():
    history, warm = ch.INSTANCES
    assert history.http == 8123 and warm.http == 8124
    assert warm.ddl == ("001_warm_session_lifecycle_revisions.sql",)
    assert history.ddl == ("002_permanent_fact_history.sql", "004_ad_snapshot_change_history.sql", "005_workstation_history.sql", "006_primary_authentication_sessions.sql")
