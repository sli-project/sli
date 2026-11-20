"""Pure renderers and read-only receipts for the two native ClickHouse instances.

No package installation, service activation, credentials or repository DDL are
changed here. The caller supplies a VM-generated password SHA256 and performs
administrative writes. Paths on the VM's system disk are a rehearsal profile;
production storage/mount admission remains the native host coordinator's job.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from deploy.linux import native_clickhouse_endpoint as clickhouse


@dataclass(frozen=True)
class Instance:
    name: str
    http: int
    native: int
    interserver: int
    database: str
    ddl: tuple[str, ...]

    @property
    def user(self):
        return f"sli-ch-{self.name}"

    @property
    def config(self):
        return f"/etc/sli/clickhouse/{self.name}"

    @property
    def data(self):
        return f"/srv/sli-db/clickhouse/{self.name}"

    @property
    def logs(self):
        return f"/var/log/sli-clickhouse/{self.name}"

    @property
    def backup(self):
        return f"/var/backups/sli/staging/{self.name}"


INSTANCES = (
    Instance("history", 8123, 9000, 9009, "sli_history", (
        "002_permanent_fact_history.sql", "004_ad_snapshot_change_history.sql", "005_workstation_history.sql",
        "006_primary_authentication_sessions.sql")),
    Instance("warm", 8124, 9001, 9010, "sli_warm", ("001_warm_session_lifecycle_revisions.sql",)),
)
MEMORY_BYTES = 768 * 1024 * 1024


def unit(instance: Instance, mode="native", *, uid=None, gid=None) -> str:
    """Both disabled-by-default services execute the same installed binary."""
    if mode == "docker":
        import shlex
        endpoint = clickhouse.endpoint(instance.name, mode)
        argv = endpoint.server_command(uid, gid, memory=MEMORY_BYTES)
        return (f"[Unit]\nDescription=SLI ClickHouse {instance.name}\nRequires=docker.service\nAfter=docker.service\n"
                f"RequiresMountsFor={instance.data} {instance.backup}\n[Service]\nType=simple\n"
                f"ExecStart={shlex.join(argv)}\nExecStop=/usr/bin/docker stop --time=120 {endpoint.container}\n"
                "Restart=on-failure\nRestartSec=5\nTimeoutStopSec=150\nKillMode=process\nNoNewPrivileges=yes\n")
    clickhouse.endpoint(instance.name, mode)  # Validate mode for both implementations.
    return f"""[Unit]
Description=SLI ClickHouse {instance.name}
After=network.target
RequiresMountsFor={instance.data} {instance.backup}
[Service]
Type=simple
User={instance.user}
Group={instance.user}
Environment=CLICKHOUSE_WATCHDOG_ENABLE=0
ExecStart=/usr/bin/clickhouse server --config-file={instance.config}/config.xml
Restart=on-failure
RestartSec=5
TimeoutStopSec=120
KillMode=control-group
UMask=0077
LimitNOFILE=262144
MemoryMax={MEMORY_BYTES}
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths={instance.data} {instance.logs} {instance.backup}
"""


def configuration(instance: Instance, password_sha256: str, root: Path, mode="native") -> dict[str, str]:
    """Render isolated configs; translate only the Compose backup disk roots.

    Retention, profiler, concurrency and disk allow-list semantics are retained.
    Credential-containing results must be written privately, never logged.
    """
    if instance not in INSTANCES or not re.fullmatch(r"[0-9a-f]{64}", password_sha256):
        raise ValueError("native_clickhouse_configuration_invalid")
    endpoint = clickhouse.endpoint(instance.name, mode)
    config = f"""<clickhouse>
<listen_host>{'0.0.0.0' if mode == 'docker' else '127.0.0.1'}</listen_host>
<http_port>{instance.http}</http_port><tcp_port>{instance.native}</tcp_port>
<interserver_http_port>{instance.interserver}</interserver_http_port>
<interserver_listen_host>127.0.0.1</interserver_listen_host>
<path>{instance.data}/</path><tmp_path>{instance.data}/tmp/</tmp_path>
<user_files_path>{instance.data}/user_files/</user_files_path>
<format_schema_path>{instance.data}/format_schemas/</format_schema_path>
<access_control_path>{instance.data}/access/</access_control_path>
<user_directories><users_xml><path>{instance.config}/users.xml</path></users_xml></user_directories>
<logger><log>{instance.logs}/server.log</log><errorlog>{instance.logs}/error.log</errorlog></logger>
<timezone>UTC</timezone><max_server_memory_usage>{MEMORY_BYTES}</max_server_memory_usage>
<max_thread_pool_size>128</max_thread_pool_size>
<background_pool_size>2</background_pool_size><background_schedule_pool_size>2</background_schedule_pool_size>
<background_buffer_flush_schedule_pool_size>1</background_buffer_flush_schedule_pool_size>
<background_message_broker_schedule_pool_size>1</background_message_broker_schedule_pool_size>
<background_distributed_schedule_pool_size>1</background_distributed_schedule_pool_size>
<mark_cache_size>16777216</mark_cache_size><uncompressed_cache_size>8388608</uncompressed_cache_size>
<merge_tree><number_of_free_entries_in_pool_to_execute_mutation>0</number_of_free_entries_in_pool_to_execute_mutation>
<number_of_free_entries_in_pool_to_execute_optimize_entire_partition>0</number_of_free_entries_in_pool_to_execute_optimize_entire_partition>
<number_of_free_entries_in_pool_to_lower_max_size_of_merge>0</number_of_free_entries_in_pool_to_lower_max_size_of_merge></merge_tree>
</clickhouse>
"""
    users = f"""<clickhouse>
<profiles><default><max_threads>2</max_threads><max_memory_usage>268435456</max_memory_usage>
<log_queries>0</log_queries><query_profiler_real_time_period_ns>0</query_profiler_real_time_period_ns>
<query_profiler_cpu_time_period_ns>0</query_profiler_cpu_time_period_ns></default></profiles>
<users><{instance.user}><password_sha256_hex>{password_sha256}</password_sha256_hex>
<networks><ip>{'0.0.0.0/0' if mode == 'docker' else '127.0.0.1'}</ip></networks><profile>default</profile><quota>default</quota>
<access_management>0</access_management></{instance.user}></users>
<quotas><default><interval><duration>3600</duration><queries>0</queries><errors>0</errors>
<result_rows>0</result_rows><read_rows>0</read_rows><execution_time>0</execution_time></interval></default></quotas>
</clickhouse>
"""
    fragments = {"config.xml": config, "users.xml": users}
    for source, target in (
        ("clickhouse/010_system_log_retention.xml", "config.d/010_system_log_retention.xml"),
        ("clickhouse/011_disable_sampling_profiler.xml", "users.d/011_disable_sampling_profiler.xml"),
        ("clickhouse/012_backup_limits.xml", "config.d/013_backup_limits.xml"),
    ):
        fragments[target] = (root / "config" / source).read_text(encoding="utf-8")
    backup = ET.fromstring((root / "config/stage7_clickhouse_backup.xml").read_text(encoding="utf-8"))
    for node in (backup.find("storage_configuration/disks/backups/path"), backup.find("backups/allowed_path")):
        if node is None or node.text != "/var/lib/clickhouse/backups/":
            raise ValueError("native_clickhouse_backup_template_changed")
        node.text = endpoint.backup_server + "/"
    fragments["config.d/012_history_backup.xml"] = ET.tostring(backup, encoding="unicode") + "\n"
    return fragments


def digest_rows(rows) -> str:
    """Order-independent SHA256 over canonical logical rows, preserving duplicates."""
    lines = sorted(json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")) for row in rows)
    return hashlib.sha256(("\n".join(lines) + ("\n" if lines else "")).encode()).hexdigest()


def inventory(query) -> list[dict]:
    """Injected query adapter keeps unit checks independent from installed DBs."""
    return query("SELECT database,name,engine,create_table_query,total_rows,total_bytes "
                 "FROM system.tables WHERE database NOT IN ('system','INFORMATION_SCHEMA','information_schema') "
                 "AND NOT is_temporary ORDER BY database,name")
