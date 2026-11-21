"""Native application units and bounded, read-only readiness/health adapters.

The release's root-owned native-runtime.json (schema_version=1) pins python,
python_sha256, postgres_version, migration_ledger, roles and plugins.
The installation coordinator publishes state/installed.json with the same
inventory plus release (absolute path), manifest_sha256 and roles (SQL rows).
It must stop sli-dotnet.target before publishing a transaction and start it
after acceptance. This module never migrates, installs packages or starts DBs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    from deploy.linux.native_preinstall import POSTGRES_DATA_DIRECTORY, ensure_directory
except ModuleNotFoundError:  # stdlib-only installed/recovery helper under -I.
    import importlib.util
    _permissions_spec = importlib.util.spec_from_file_location(
        "sli_native_preinstall", Path(__file__).with_name("native_preinstall.py"))
    _permissions = importlib.util.module_from_spec(_permissions_spec)
    _permissions_spec.loader.exec_module(_permissions)
    POSTGRES_DATA_DIRECTORY = _permissions.POSTGRES_DATA_DIRECTORY
    ensure_directory = _permissions.ensure_directory


try:
    from deploy.linux import native_clickhouse_endpoint as clickhouse
except ModuleNotFoundError:  # stdlib launcher with -I, before release imports.
    _spec = importlib.util.spec_from_file_location(
        "sli_clickhouse_endpoint", Path(__file__).with_name("native_clickhouse_endpoint.py"))
    clickhouse = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(clickhouse)

CURRENT = Path("/opt/sli/current")
# Only SLI units loaded by systemd, including failed one-shot backup services.
RESET_FAILED_UNITS = ("systemctl", "reset-failed", "sli[-.]*")
RELEASES = Path("/opt/sli/releases")
RUNTIMES = Path("/opt/sli/runtimes")
STATE = Path("/var/lib/sli/state")
RECOVERY = Path("/var/lib/sli/recovery")
TRANSACTIONS = Path("/var/lib/sli/transactions")
CONFIG = Path("/etc/sli/runtime.json")
RUN = Path("/run/sli")
HELPER = "/usr/lib/sli/native_runtime.py"
DOTNET_GENERATOR = Path("/usr/lib/systemd/system-generators/sli-dotnet-api")
ROOT_UID = 0
DATABASES = ("sli-postgresql.service",)
# Single source for namespace paths and the host/restore permission policy.
DATA_DIRECTORIES = {**{name: (0o2770, "sli-data") for name in
                      ("ingress", "spool", "evidence", "logs", "runtime")},
                    "plugins": (0o755, "root")}
IMPORT_QUEUE_LOCK = "/var/lib/sli/runtime/postgres-import.queue.lock"
PRESERVED_DATA_DIRECTORIES = frozenset({"state", "recovery", "drills", "transactions", "backup-status"})
SERVICES = {
    "api": ("sli-api", "api", ()),
    "post-collection": ("sli-post", "post_collection", ("--poll-seconds", "30")),
    "what-where-when": ("sli-projection", "what_where_when_projection", ()),
    "semantic": ("sli-semantic", "semantic", ()),
    "entity-state": ("sli-entity", "entity_state", ()),
    "storage-lifecycle": ("sli-storage", "storage_lifecycle", ("--interval-seconds", "21600")),
    "ad-snapshot-manifest-coordinator": ("sli-context", "ad_snapshot_manifest_coordinator", ("--no-initial-delay",)),
    "remote-access": ("sli-remote", "radius-session-observation", ("--component", "radius-session-observation")),
    "notification-delivery": ("sli-notify", "notification-delivery", ()),
    "notification-setup": ("root", "notification-setup", ()),
    **{f"executor-{p}": (f"sli-exec-{p}", f"executor-{p}", ("--profile", p)) for p in ("light", "heavy", "long")},
}
DOTNET_ONLY_SERVICES = {"report-producer": ("sli-report", "report-producer", ())}
BETA_EXCLUDED_SERVICES = frozenset({"what-where-when", "remote-access", "report-producer"})


class RuntimeErrorCode(RuntimeError):
    """Only fixed diagnostics cross the CLI boundary."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def require(condition, code):
    if not condition:
        raise RuntimeErrorCode(code)


def trusted(path):
    """Administrative files and all ancestors must be immutable to services."""
    require(path.is_absolute(), "native_path_invalid")
    for item in (path, *path.parents):
        info = item.lstat()
        require(not item.is_symlink() and info.st_uid == ROOT_UID and not info.st_mode & 0o022,
                "native_path_untrusted")
    require(path.is_file(), "native_file_invalid")
    return path.read_bytes()


def document(path):
    value = json.loads(trusted(path))
    require(isinstance(value, dict) and value.get("schema_version") == 1, "native_document_invalid")
    return value


def release_rendered_unit(path, body, *, state=STATE, recovery=RECOVERY, saved_directory="units"):
    """Allow a new release to re-render a unit the accepted release generated.

    Host.write never overwrites a differing file. A unit is replaced only when
    its current bytes equal the accepted release's sealed recovery copy, i.e.
    SLI rendered it and nobody edited it; overrides in /etc are untouched.
    """
    if path.is_symlink() or not path.is_file() or path.read_text() == body:
        return False
    try:
        accepted = Path(document(state / "installed.json")["release"]).name
        saved = trusted(recovery / accepted / saved_directory / path.name)
    except (OSError, ValueError, KeyError, RuntimeError):
        return False
    if path.read_bytes() != saved:
        return False
    path.unlink()
    return True


def release():
    root = CURRENT.resolve(strict=True)
    require(root.parent == RELEASES and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", root.name),
            "native_release_invalid")
    raw = trusted(root / "native-runtime.json")
    manifest = json.loads(raw)
    require(manifest.get("schema_version") == 1, "native_manifest_invalid")
    python = Path(manifest["python"])
    require(python.is_relative_to(RUNTIMES) and len(python.relative_to(RUNTIMES).parts) == 3
            and python.parent.name == "bin" and re.fullmatch(r"python3(?:\.14)?", python.name)
            and python == python.resolve(strict=True),
            "native_python_invalid")
    require(hashlib.sha256(trusted(python)).hexdigest() == manifest["python_sha256"]
            and os.access(python, os.X_OK), "native_python_mismatch")
    return root, manifest, hashlib.sha256(raw).hexdigest()


def configuration():
    config = document(CONFIG)
    clickhouse.notification_proxy(config.get("notification_proxy", ""))
    profiles = config.get("profiles")
    require(isinstance(profiles, list) and "light" in profiles and len(set(profiles)) == len(profiles)
            and set(profiles) <= {"light", "heavy", "long"}, "native_profiles_invalid")
    require(type(config.get("radius_pilot")) is bool, "native_pilot_invalid")
    require(type(config.get("agents", False)) is bool, "native_agents_invalid")
    require(type(config.get("ad_credentials", False)) is bool, "native_ad_credentials_invalid")
    require(type(config.get("owner_setup", False)) is bool, "native_site_owner_setup_invalid")
    port = config.get("https_port", 8443)
    require(type(port) is int and 1 <= port <= 65535, "native_site_port_invalid")
    require(not config["radius_pilot"] or (isinstance(config.get("radius_source_instance"), str)
            and re.fullmatch(r"[A-Za-z0-9._:-]{1,200}", config["radius_source_instance"])),
            "native_pilot_source_required")
    require(str(ipaddress.ip_address(config["bind"])) == config["bind"], "native_bind_invalid")
    require(config["health_url"] == f"https://{clickhouse.health_host(config['bind'])}:{port}/api/health/ready",
            "native_health_url_invalid")
    return config


def selected(config):
    return tuple(name for name in (*SERVICES, *DOTNET_ONLY_SERVICES) if name not in BETA_EXCLUDED_SERVICES
                 if (not name.startswith("executor-") or name[9:] in config["profiles"])
                 and (name != "remote-access" or not config["radius_pilot"]))


def unit_name(service):
    require(service in SERVICES or service in DOTNET_ONLY_SERVICES, "native_service_invalid")
    return "sli-" + (service.replace("executor-", "executor@") if service.startswith("executor-") else service) + ".service"


def data_group_id():
    from deploy.linux import native_host as host

    entry = host.group("sli-data")
    require(entry is not None, "native_data_group_missing")
    return entry.gr_gid


def restore_data_permissions(destination, gid):
    """Only application data becomes shared; host state remains untouched."""
    from itertools import chain
    from deploy.linux.operation_wait import made_progress

    os.chown(destination, 0, 0)
    destination.chmod(0o755)
    for child in destination.iterdir():
        if child.name in PRESERVED_DATA_DIRECTORIES | {"plugins"}:
            continue
        for item in chain((child,), child.rglob("*")) if child.is_dir() else (child,):
            os.chown(item, 0, gid)
            item.chmod(0o2770 if item.is_dir() else 0o660)
            made_progress()
    for name, (mode, group) in DATA_DIRECTORIES.items():
        directory = destination / name
        if name == "plugins" and directory.exists():
            continue
        ensure_directory(directory, mode, 0, gid if group == "sli-data" else 0)
        os.chown(directory, 0, gid if group == "sli-data" else 0)
        directory.chmod(mode)
        made_progress()


def environment(service, config, *, dotnet=False):
    """Values contain settings/credential paths only; no secret contents."""
    if service == "report-producer":
        return {
            "SLI_REPORT_PRODUCER_PG_DSN": "host=127.0.0.1 port=5432 dbname=sli user=sli_report_producer_login",
            "SLI_REPORT_PRODUCER_PG_PASSWORD_FILE": "%d/report_producer_password",
            "SLI_REPORT_PRODUCER_STATUS_FILE": "/run/sli/report-producer/heartbeat.json",
        }, {"report_producer_password"}
    env = {
        "SLI_DEPLOYMENT_MODE": "native", "ADLOG_DB_BACKEND": "postgres",
        "ADLOG_PG_DSN": "host=127.0.0.1 port=5432 dbname=sli user=adlog_user",
        "ADLOG_DATA_DIR": "/var/lib/sli", "ADLOG_LOG_DIR": "/var/lib/sli/logs",
        "SLI_PLUGIN_RUNTIME_DIR": "/var/lib/sli/plugins",
        "SLI_PLUGIN_LOCK_DIR": "/opt/sli/current/config/plugin_packages/v3",
        "ADLOG_AUTH_REQUIRED": "1", "ADLOG_UI_MODE": "postgres",
        "ADLOG_STORAGE_READ_MODE": "v2", "ADLOG_STORAGE_WRITE_MODE": "v2",
        "ADLOG_STORAGE_V2_SHADOW_SAMPLE_RATE": "0",
        "ADLOG_EXTERNAL_POST_COLLECTION_WORKER": "1", "ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER": "1",
        "ADLOG_DISABLE_SCHEDULER": "1", "ADLOG_HISTORY_READ_MODE": "disabled",
        "SLI_JOB_PG_HOST": "127.0.0.1",
        "SLI_CORE_JOB_RADIUS_PILOT": str(int(config["radius_pilot"])),
        "SLI_CORE_JOB_RADIUS_SOURCE_INSTANCE_ID": config.get("radius_source_instance", ""),
        "SLI_CORE_JOB_WORKSTATIONS_RETENTION": os.environ.get("SLI_CORE_JOB_WORKSTATIONS_RETENTION", "0"),
        "SLI_CORE_JOB_WORKSTATIONS_PROJECTION": os.environ.get("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "0"),
        "SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS": "90",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if service == "api" and dotnet:
        # The API role cannot read PostgreSQL's data_directory setting.
        env["SLI_POSTGRES_DATA_DIRECTORY"] = POSTGRES_DATA_DIRECTORY
    secrets = {"ADLOG_PG_PASSWORD": "runtime_password"}
    roles = []
    if service in {"post-collection", "entity-state"} or (service == "storage-lifecycle" and not dotnet):
        roles.append(("ADLOG_STORAGE_V2_WORKER", "sli_storage_login", "storage_password"))
    if service == "post-collection":
        roles.append(("ADLOG_AD_CONTEXT_WORKER", "sli_context_login", "context_password"))
        # Importers serialize on this file; it must sit in a ReadWritePaths directory of the unit.
        env["ADLOG_POSTGRES_IMPORT_QUEUE_LOCK"] = IMPORT_QUEUE_LOCK
    if service == "semantic":
        roles.append(("ADLOG_SEMANTIC_WORKER", "sli_semantic_login", "semantic_password"))
    # AgentWorkstationInboxConsumer -> DirectAdDcPacket / DirectNpsPacket;
    # both native entrypoints dispatch these writers from post-collection.
    if service in {"semantic", "post-collection"}:
        for name in ("PRODUCTION", "NORMALIZATION", "ASSEMBLY", "CORRELATION", "RISK_ENGINE", "FINDING_CREATION"):
            env[f"ADLOG_SEMANTIC_{name}_ENABLED"] = "1"
        env["ADLOG_SEMANTIC_RUNTIME_MODE"] = "findings-v1"
    for setting, user, secret in roles:
        env[setting + "_DSN"] = f"host=127.0.0.1 port=5432 dbname=sli user={user}"
        secrets[setting + "_PASSWORD"] = secret
    if service == "storage-lifecycle":
        if dotnet:
            env["ADLOG_PG_DSN"] = "host=127.0.0.1 port=5432 dbname=sli user=sli_storage_lifecycle_login"
            secrets["ADLOG_PG_PASSWORD"] = "storage_lifecycle_password"
            env["ADLOG_STORAGE_LIFECYCLE_DELETE_DSN"] = "host=127.0.0.1 port=5432 dbname=sli user=sli_storage_lifecycle_delete_login"
            secrets["ADLOG_STORAGE_LIFECYCLE_DELETE_PASSWORD"] = "storage_lifecycle_delete_password"
    if service == "ad-snapshot-manifest-coordinator":
        env["ADLOG_SNAPSHOT_HISTORY_DSN"] = "host=127.0.0.1 port=5432 dbname=sli user=sli_storage_lifecycle_login"
        secrets["ADLOG_SNAPSHOT_HISTORY_PASSWORD"] = "storage_lifecycle_password"
    if service.startswith("executor-"):
        profile = service[9:]
        secrets.pop("ADLOG_PG_PASSWORD")
        for purpose in ("dispatcher", "executor", "publisher"):
            secrets[f"SLI_JOB_{purpose.upper()}_{profile.upper()}_PASSWORD"] = f"job_{purpose}_{profile}"
        env["SLI_EXECUTOR_STATUS_DIR"] = f"/run/sli/{service}"
    if service == "remote-access":
        env["SLI_PLUGIN_HEARTBEAT_DIR"] = "/run/sli/remote-access"
    if service == "api":
        if config.get("owner_setup"):
            env["SLI_OWNER_SETUP"] = "1"
        env["SLI_TELEGRAM_SETUP_SOCKET"] = "/run/sli/notification-setup/control.sock"
        if config.get("ad_credentials"):
            secrets["SLI_AD_CREDENTIALS_MASTER_KEY"] = "ad_credentials_master_key"
        secrets.update(ADLOG_TLS_CERT="tls_certificate", ADLOG_TLS_KEY="tls_key", SLI_TLS_CA="tls_ca")
        if config.get("agents"):
            secrets.update(SLI_AGENT_CA_ROOT_CERT="agent_root_certificate",
                           SLI_AGENT_CA_ISSUER_CERT="agent_issuer_certificate",
                           SLI_AGENT_CA_ISSUER_KEY="agent_issuer_key", SLI_AGENT_MTLS_CA="agent_mtls_ca")
        env["SLI_HEALTH_URL"] = config["health_url"]
    if service.startswith("notification-"):
        env["SLI_NOTIFICATION_PROXY"] = config.get("notification_proxy", "")
    if service == "notification-delivery":
        # Reuse the existing bounded notification login, as Compose does.
        env["ADLOG_PG_DSN"] = "host=127.0.0.1 port=5432 dbname=sli user=sli_notification_login"
        secrets = {"ADLOG_PG_PASSWORD": "notification_db_password"}
        secrets["SLI_NOTIFICATION_TELEGRAM_TOKEN"] = "notifications_notification_telegram_token"
        secrets["SLI_NOTIFICATION_SMTP_PASSWORD"] = "notifications_notification_smtp_password"
        env.update(SLI_NOTIFICATION_TELEGRAM_CONFIG_FILE="%d/notifications_telegram.json",
                   SLI_NOTIFICATION_SMTP_CONFIG_FILE="%d/notifications_smtp.json",
                   SLI_NOTIFICATION_STATUS_FILE="/run/sli/notification-delivery/heartbeat.json")
    if service == "notification-setup":
        # The isolated writer has no DB credentials. Its only persistent write
        # access is the notification directory, published by sli_secrets.
        env = {"SLI_DEPLOYMENT_MODE": "native", "PYTHONDONTWRITEBYTECODE": "1",
               "SLI_NATIVE_NOTIFICATION_SETUP": "1",
               "SLI_TELEGRAM_SECRET_DIR": "/etc/sli/secrets/notifications",
               "SLI_TELEGRAM_SETUP_SOCKET": "/run/sli/notification-setup/control.sock",
               "SLI_PUBLIC_URL": config["health_url"].split("/api/")[0],
               "SLI_NOTIFICATION_PROXY": config.get("notification_proxy", "")}
        secrets = {}
    env.update({key + "_FILE": "%d/" + value for key, value in secrets.items()})
    delivered = set(secrets.values())
    if service == "notification-delivery":
        delivered -= {"notifications_notification_telegram_token", "notifications_notification_smtp_password"}
        delivered.add("notifications")
    return env, delivered


DOTNET_COMMANDS = {
    "api": (),
    "post-collection": ("post-collection-worker",),
    "what-where-when": ("what-where-when-projection-worker",),
    "semantic": ("semantic-production-worker",),
    "entity-state": ("entity-state-worker",),
    "storage-lifecycle": ("storage-lifecycle-worker",),
    "ad-snapshot-manifest-coordinator": ("ad-snapshot-manifest-coordinator-worker",),
    "remote-access": ("radius-session-observation",),
    "notification-delivery": ("notification-delivery-worker",),
    "notification-setup": ("notification-setup",),
    "report-producer": ("report-producer",),
    **{f"executor-{p}": ("core-job-executor",) for p in ("light", "heavy", "long")},
}


def dotnet_unit_name(service):
    require(service in SERVICES or service in DOTNET_ONLY_SERVICES, "native_service_invalid")
    return f"sli-dotnet-{service}.service"


def dotnet_unit(release, config, service="api"):
    """Render the native sandbox policy for the .NET application."""
    require(re.fullmatch(r"[a-z0-9][a-z0-9.+-]{0,63}", release), "native_release_invalid")
    require(service in selected(config), "native_profile_disabled")
    spec = (SERVICES | DOTNET_ONLY_SERVICES)[service]
    body = application_unit(config, service, spec, selected(config), dotnet=True)
    header, policy = body.split("[Service]\n", 1)
    header = header.replace("Description=SLI ", "Description=SLI .NET ")
    header = header.replace("sli-runtime.target", "sli-dotnet.target")
    for app in selected(config):
        header = header.replace(unit_name(app), dotnet_unit_name(app))
    command = " ".join((f"/opt/sli/dotnet/{release}/Sli.Server", *DOTNET_COMMANDS[service], *spec[2]))
    policy = policy.replace(f"ExecStart=/usr/bin/python3 -I -B {HELPER} launch {service}\n",
                            f"ExecStart={command}\n")
    policy = policy.replace("WorkingDirectory=/opt/sli/current\n", f"WorkingDirectory=/opt/sli/dotnet/{release}\n")
    # The Python entrypoint sets these before dispatching any native command.
    # Direct .NET ExecStart bypasses that entrypoint, so preserve its guards.
    for setting in ("ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER", "ADLOG_ENABLE_INPROCESS_POST_COLLECTION",
                    "ADLOG_ENABLE_POSTGRES_COLLECTION", "ADLOG_POSTGRES_RUNTIME_COLLECTION",
                    "ADLOG_NPS_EVENTLOG_ENABLED", "ADLOG_ACQUISITION_DISABLED"):
        policy += f'Environment="{setting}={int(setting == "ADLOG_ACQUISITION_DISABLED")}"\n'
    if service == "api":
        policy += f'Environment="SLI_BIND={config["bind"]}"\n'
    if service == "post-collection":
        # Python resolves the frozen source catalog relative to /opt/sli/current.
        policy += 'Environment="Sli__EventCatalogPath=/opt/sli/current/config/event_catalog.json"\n'
    return header + "[Service]\n" + policy


def dotnet_units(release, config):
    apps = selected(config)
    result = {dotnet_unit_name(service): dotnet_unit(release, config, service) for service in apps}
    result["sli-dotnet.target"] = (
        "[Unit]\nDescription=SLI .NET application writers\nPartOf=sli.target\n"
        "Requires=sli-ready.service\nAfter=sli-ready.service\n"
        "Wants=sli-health.timer " + " ".join(map(dotnet_unit_name, apps)) + "\n")
    return result


def application_unit(config, service, spec, apps, *, dotnet=False):
    user = spec[0]
    env, secrets = environment(service, config, dotnet=dotnet)
    before_api = "After=" + " ".join(unit_name(s) for s in apps if s != "api") + "\n" if service == "api" else ""
    setup = service == "notification-setup"
    writable = ("/etc/sli/secrets/notifications" if setup else " ".join(
        "/var/lib/sli/" + name for name, (_, group) in DATA_DIRECTORIES.items() if group == "sli-data"))
    if service in DOTNET_ONLY_SERVICES:
        writable = ""
    body = (
        f"[Unit]\nDescription=SLI {service}\nPartOf=sli-runtime.target\nBindsTo=sli-ready.service\n"
        "After=sli-ready.service\nRequires=sli-ready.service\n" + before_api +
        ("Requires=sli-notification-setup.service\nAfter=sli-notification-setup.service\n"
         if service in {"api", "notification-delivery"} else "") +
        "StartLimitIntervalSec=0\n[Service]\nType=simple\n"
        f"User={user}\nGroup={user}\nWorkingDirectory=/opt/sli/current\nSlice=sli.slice\n"
        f"RuntimeDirectory=sli/{service}\nRuntimeDirectoryMode=0700\n"
        f"ExecStart=/usr/bin/python3 -I -B {HELPER} launch {service}\n"
        "Restart=on-failure\nRestartSec=5s\nKillMode=control-group\nKillSignal=SIGTERM\n"
        f"TimeoutStopSec={900 if service in {'executor-heavy', 'executor-long'} else 60}s\n"
        "UMask=0027\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n"
        "PrivateTmp=yes\nPrivateDevices=yes\n" +
        ("CapabilityBoundingSet=CAP_CHOWN\n" if setup else "CapabilityBoundingSet=\n")
        + clickhouse.SOCKET_SANDBOX +
        f"ReadWritePaths=/run/sli/{service} {writable}\n"
        "InaccessiblePaths=/var/lib/sli/state /var/lib/sli/transactions /var/lib/sli/recovery\n" +
        ("TemporaryFileSystem=/etc/sli:ro\nBindReadOnlyPaths=/etc/sli/runtime.json\n"
         "BindPaths=/etc/sli/secrets/notifications\n" if setup else "InaccessiblePaths=/etc/sli/secrets\n") +
        "".join(f"LoadCredential={s}:/etc/sli/secrets/{s}\n" for s in sorted(secrets)) +
        "".join(f'Environment="{k}={v}"\n' for k, v in sorted(env.items())))
    if service == "api" and config.get("https_port", 8443) < 1024:
        body = body.replace("CapabilityBoundingSet=\n",
                            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n")
    return body


def units(config):
    db = " ".join(DATABASES)
    result = {
        "sli.target": "[Unit]\nDescription=SLI platform\nRequires=sli-dotnet.target\nAfter=sli-dotnet.target\n"
                      "[Install]\nWantedBy=multi-user.target\nAlso=" + db + "\n",
        "sli-runtime.target": "[Unit]\nDescription=SLI application compatibility target\nRequires=sli-dotnet.target\nAfter=sli-dotnet.target\nPartOf=sli.target\n",
        "sli.slice": "[Unit]\nDescription=SLI applications\n[Slice]\nTasksMax=2048\n",
        "sli-health.timer": "[Unit]\nDescription=SLI health schedule\nPartOf=sli-dotnet.target\n[Timer]\nOnActiveSec=30s\nOnUnitActiveSec=30s\nUnit=sli-health.service\n",
    }
    admin_credentials = {"postgres_password"}
    for command in ("ready", "health"):
        creds = admin_credentials | ({"runtime_password", "tls_ca"} if command == "health" else set())
        result[f"sli-{command}.service"] = (
            f"[Unit]\nDescription=SLI native {command}\nPartOf=sli-dotnet.target\nWants={db}\nAfter={db}\n" +
            ("Before=sli-dotnet.target\n" if command == "ready" else "After=sli-ready.service\n") +
            "[Service]\nType=oneshot\n" + ("RemainAfterExit=yes\n" if command == "ready" else "") +
            f"ExecStart=/usr/bin/python3 -I -B {HELPER} control {command}\n"
            "WorkingDirectory=/opt/sli/current\nTimeoutStartSec=12h\nUMask=0077\n"
            "ReadWritePaths=/run/sli-native-host.lock /var/lib/sli/backup-status /run/sli\n"
            "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n" +
            clickhouse.SOCKET_SANDBOX +
            "".join(f"LoadCredential={s}:/etc/sli/secrets/{s}\n" for s in sorted(creds)))
    return result


def configure_worker_accounts():
    """Reconcile candidate credentials even when the retained updater skips SQL.

    Use candidate settings/catalogs: the accepted coordinator may predate a
    service and its password-file environment. Schema migrations remain gated
    by the upgrade ledger; this only provisions existing worker roles.
    """
    from deploy.linux import backup, native_backup, native_install
    from deploy.linux.migrate import configure_worker_logins

    try:
        with native_backup.environment(native_install.environment()), backup.pg_passfile() as passfile:
            with backup.pg_connect(passfile, autocommit=True) as connection:
                connection.execute("select pg_advisory_lock(hashtext('sli_linux_stand_migrate'))")
                configure_worker_logins(connection)
    except Exception:
        raise RuntimeErrorCode("native_worker_logins_failed") from None


def configure(config):
    from deploy.linux import native_host as host

    # Candidate code can be invoked by an older retained upgrade coordinator.
    # Read the optional setting here as well, so its old runtime JSON cannot
    # silently discard a proxy explicitly configured on the destination host.
    if Path("/etc/sli/site.toml").exists():
        site = clickhouse.site_configuration()
        config = dict(config)
        if "notification_proxy" in site:
            config["notification_proxy"] = site["notification_proxy"]
        else:
            config.pop("notification_proxy", None)
    clickhouse.notification_proxy(config.get("notification_proxy", ""))
    with host.administrative_lock():
        machine = host.Host()
        machine.receipt()
        host.validate_identity()
        users = {item[0] for item in (SERVICES | DOTNET_ONLY_SERVICES).values()} - {"root"}
        data_group = host.group("sli-data")
        if data_group:
            require(set(data_group.gr_mem) <= users and not any(
                entry.pw_gid == data_group.gr_gid and entry.pw_name not in users
                for entry in host.pwd.getpwall()), "native_data_group_conflict")
        # No existing private directory is opened to runtime groups.
        machine.directory("/run/sli", 0o711)
        machine.directory("/var/lib/sli", 0o755)
        machine.directory('/var/lib/sli/backup-status', 0o755)
        if not data_group:
            host.run(["groupadd", "--system", "sli-data"])
        # Upgrades on a host prepared by an older package also need this user.
        for user in sorted(users):
            if not host.account(user):
                host.run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir",
                          "/nonexistent", "--shell", "/usr/sbin/nologin", user])
            if user not in {spec[0] for spec in DOTNET_ONLY_SERVICES.values()}:
                host.run(["usermod", "--append", "--groups", "sli-data", user])
        configure_worker_accounts()
        for name, (mode, group) in DATA_DIRECTORIES.items():
            machine.directory("/var/lib/sli/" + name, mode, group_name=group)
        machine.directory("/etc/sli/secrets/notifications", 0o750, group_name="sli-secrets")
        machine.write(str(CONFIG), json.dumps(config, sort_keys=True) + "\n", 0o644)
        machine.write(HELPER, Path(__file__).read_text(), 0o644)
        # Old enabled writers can otherwise return on reboot. Fence them before
        # daemon-reload changes dependencies; keep operator files untouched.
        stop_services(SERVICES, dotnet=False)
        legacy = [unit_name(service) for service in SERVICES
                  if systemd(service, dotnet=False).get("LoadState") != "not-found"]
        if legacy:
            host.run(["systemctl", "disable", *legacy])
        host.retire_clickhouse()
        # The database stays running during package updates. Re-render only its
        # sealed managed unit, without reconfiguring the cluster or credentials.
        for name in DATABASES:
            body = host.units()[name]
            release_rendered_unit(Path("/etc/systemd/system") / name, body, saved_directory="local-units")
            machine.write("/etc/systemd/system/" + name, body, 0o644)
        for name, body in units(config).items():
            release_rendered_unit(Path("/usr/lib/systemd/system") / name, body)
            machine.write("/usr/lib/systemd/system/" + name, body, 0o644)
        machine.write("/usr/lib/tmpfiles.d/sli-runtime.conf",
                      "d /run/sli 0711 root root -\nf /run/sli-native-host.lock 0600 root root -\n", 0o644)
        host.run(["systemd-tmpfiles", "--create", "/usr/lib/tmpfiles.d/sli-runtime.conf"])
        host.run(["systemctl", "daemon-reload"])
        host.run(list(RESET_FAILED_UNITS))


def launch(service, *, control=False):
    root, manifest, _ = release()
    config = configuration()
    if control:
        require(service in {"ready", "health", "stop-writers"}, "native_command_invalid")
        argv = [manifest["python"], "-B", "-m", "deploy.linux.native_runtime", service]
        env = dict(os.environ)
    else:
        require(service in selected(config), "native_profile_disabled")
        env = dict(os.environ)
        settings, _ = environment(service, config)
        credentials = os.environ.get("CREDENTIALS_DIRECTORY", "")
        env.update({k: v.replace("%d", credentials) for k, v in settings.items()})
        args = list(SERVICES[service][2])
        if service == "api":
            args = ["--host", config["bind"], "--port", str(config.get("https_port", 8443))]
        argv = [manifest["python"], "-B", "-m", "deploy.linux.entrypoint",
                "executor" if service.startswith("executor-") else service, *args]
    for key in ("PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH",
                "SLI_NOTIFICATION_TELEGRAM_TOKEN", "SLI_NOTIFICATION_SMTP_PASSWORD"):
        env.pop(key, None)
    os.chdir(root)
    os.execve(manifest["python"], argv, env)


def active_unit_name(service):
    return dotnet_unit_name(service)


def systemd(service, *, dotnet=None):
    fields = ("LoadState", "ActiveState", "SubState", "MainPID", "ExecMainStartTimestampMonotonic",
              "InvocationID", "NRestarts", "ControlGroup", "ExecMainStatus")
    name = active_unit_name(service) if dotnet is None else (dotnet_unit_name(service) if dotnet else unit_name(service))
    result = subprocess.run(["systemctl", "show", name, "--no-pager",
                             "--property=" + ",".join(fields)], capture_output=True, text=True,
                            timeout=5, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    row = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    require(result.returncode == 0 or row.get("LoadState") == "not-found", "native_systemd_query_failed")
    return row


def process_start(pid):
    # /proc comm may contain spaces or parentheses.
    value = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(value[19]) / os.sysconf("SC_CLK_TCK")


def healthy_service(service):
    from deploy.linux.healthcheck import healthy

    try:
        first = systemd(service)
        if (first["LoadState"], first["ActiveState"], first["SubState"]) != ("loaded", "active", "running"):
            return False
        pid = int(first["MainPID"])
        start = int(first["ExecMainStartTimestampMonotonic"]) / 1_000_000
        require(pid > 0 and start > 0 and re.fullmatch(r"[a-f0-9]{32}", first["InvocationID"])
                and (int(first["NRestarts"]) < 5 or time.monotonic() - start >= 300),
                "native_process_invalid")
        proc_start = process_start(pid)
        require(abs(proc_start - start) < 2 and 0 <= time.monotonic() - start,
                "native_process_identity_mismatch")
        stamp = datetime.now(UTC) - timedelta(seconds=time.monotonic() - start)
        status_path = None
        if service.startswith("executor-"):
            status_path = RUN / service / f"sli-executor-{service[9:]}.json"
        elif service == "remote-access":
            status_path = RUN / service / "plugin-radius-session-observation.json"
        elif service == "notification-delivery":
            status_path = RUN / service / "heartbeat.json"
        elif service == "notification-setup":
            status_path = RUN / service / "control.sock"
        success = healthy(SERVICES[service][1], process_pid=pid, started_at=stamp, status_path=status_path)
        return success and first == systemd(service) and proc_start == process_start(pid)
    except Exception:  # noqa: BLE001 - fixed success/failure only
        return False


def no_transaction(*, agents_reconfigure=False):
    intent = STATE / "agents-reconfigure.json"
    if not agents_reconfigure and (intent.exists() or intent.is_symlink()):
        require(document(intent).get("status") in {"applied", "configured"},
                "native_agents_reconfigure_pending")
    # Each transaction directory must have a durable terminal result. Unknown
    # layouts and interrupted writes fence startup, rather than imply success.
    for path in TRANSACTIONS.iterdir():
        require(path.is_dir() and not path.is_symlink(), "native_transaction_pending")
        result = document(path / "result.json")
        if result.get("status") == "aborted_before_checkpoint":
            require(result.get("terminal") is True, "native_transaction_pending")
        elif result.get("status") not in {"committed", "rolled_back"}:
            # Only the coordinator's volatile readiness/health unit overrides
            # admit candidate testing. Reboot removes them and closes the gate.
            require(os.environ.get("SLI_NATIVE_UPGRADE_TRANSACTION") == path.name, "native_transaction_pending")
            journal = document(path / "journal.json")
            require(journal.get("status") == "candidate_testing"
                    and journal.get("testing_release") == release()[0].name,
                    "native_transaction_pending")


def observe(root, installed):
    from urllib.request import urlopen

    import psycopg

    from deploy.linux.installed_state import pointers_match
    from deploy.linux.native_host import credential
    from deploy.linux.native_plugins import verify_registry

    with psycopg.connect(host="127.0.0.1", port=5432, dbname="sli", user="postgres",
                         password=credential("postgres_password"), connect_timeout=3,
                         options="-c statement_timeout=3000 -c default_transaction_read_only=on") as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        pg_version = conn.execute("SHOW server_version").fetchone()[0]
        rows = conn.execute("SELECT version, name, sha256 FROM public.schema_migrations ORDER BY version").fetchall()
        ledger = [{"version": v, "name": n, "sha256": h} for v, n, h in rows]
        roles = [list(row) for row in conn.execute("""SELECT rolname, rolsuper, rolcreaterole, rolcreatedb,
            rolreplication, rolbypassrls, rolinherit FROM pg_roles
            WHERE rolname = ANY(%s) ORDER BY rolname""", ([row[0] for row in installed["roles"]],)).fetchall()]
        plugins = conn.execute("""SELECT plugin_id, package_version, manifest_sha256 FROM public.plugin_installations_v1
            WHERE package_lifecycle = 'registered' ORDER BY plugin_id""").fetchall()
    require(roles == installed["roles"] and roles, "native_roles_mismatch")
    verify_registry(root, installed["plugins"], plugins)
    pointers_match(Path("/var/lib/sli"), installed)
    return pg_version, [], ledger


def wait_databases():
    """Read engine readiness before migration/DDL, shared with upgrade recovery."""
    import psycopg

    from deploy.linux import backup, native_backup
    from deploy.linux.operation_wait import Watch, readiness_history
    watch = Watch('postgres_ready', minimum=3600, history=readiness_history())
    with native_backup.environment(native_backup.settings()):
        while True:
            component = 'postgres'
            try:
                with backup.pg_passfile() as passfile, backup.pg_connect(passfile, "postgres") as connection:
                    require(connection.execute("SELECT 1").fetchone() == (1,), "native_database_unready")
                watch.success()
                return
            except (OSError, RuntimeError, psycopg.Error):
                watch.step = component + '_ready'
                watch.check(component, components=(component,))
                time.sleep(30)


def observe_when_available(root, installed):
    """Type=simple DB units can be active before their endpoints accept SQL."""
    import ssl
    from http.client import IncompleteRead
    from urllib.error import HTTPError, URLError

    import psycopg

    from deploy.linux.operation_wait import OperationTimeout, Watch, readiness_history
    watch = Watch('databases_ready', minimum=3600, history=readiness_history())
    while True:
        try:
            observed = observe(root, installed)
            watch.success()
            return observed
        except (psycopg.OperationalError, OSError, IncompleteRead) as exc:
            pg_starting = (isinstance(exc, psycopg.OperationalError) and (
                exc.sqlstate in {"57P03", "08001", "08006"} or exc.sqlstate is None and any(
                    text in str(exc).lower() for text in
                    ("connection refused", "database system is starting up", "timeout expired",
                     "server closed the connection unexpectedly", "connection reset by peer"))))
            transport = exc.reason if isinstance(exc, URLError) and not isinstance(exc, HTTPError) else exc
            transient = (pg_starting
                          or isinstance(exc, HTTPError) and exc.code in {502, 503, 504}
                          or isinstance(transport, (ConnectionError, TimeoutError, ssl.SSLEOFError, IncompleteRead)))
            if not transient:
                raise
            component = ('postgres' if isinstance(exc, psycopg.OperationalError)
                         else getattr(exc, 'component', 'databases'))
            try:
                watch.check(component, components=(component,))
            except OperationTimeout as error:
                raise RuntimeErrorCode('native_' + component + '_not_ready') from error
            time.sleep(30)


def ready():
    from deploy.linux import native_host as host
    from deploy.linux.installed_state import ledger_matches
    from deploy.linux.native_pg_inventory import verify_ledger

    with host.administrative_lock():
        host.Host().receipt()
        host.validate_identity()
        no_transaction()
        root, manifest, digest = release()
        installed = document(STATE / "installed.json")
        require(installed.get("release") == str(root) and installed.get("manifest_sha256") == digest,
                "native_registry_mismatch")
        require(all(installed.get(key) == manifest.get(key) for key in ("migration_ledger", "plugins", "roles")),
                "native_inventory_mismatch")
        pg, ch, ledger = observe_when_available(root, installed)
        require(pg == manifest["postgres_version"], "native_database_version_mismatch")
        require(str(pg).startswith("18."),
                "native_database_version_mismatch")
        checksums = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in (root / "config/postgres_migrations").glob("*.sql")}
        ledger_matches({**manifest, "migrations": checksums}, {
            "migration_ledger": manifest["migration_ledger"],
            "migration_ledger_max": max(row["version"] for row in manifest["migration_ledger"])})
        verify_ledger(ledger, manifest["migration_ledger"], root=root)
        return True


def health():
    ready()
    from deploy.linux import native_host as host

    config = configuration()
    directory = os.environ["CREDENTIALS_DIRECTORY"]
    os.environ.update(ADLOG_PG_DSN="host=127.0.0.1 port=5432 dbname=sli user=adlog_user",
                      ADLOG_PG_PASSWORD_FILE=directory + "/runtime_password",
                      SLI_TLS_CA_FILE=directory + "/tls_ca", SLI_HEALTH_URL=config["health_url"])
    host.credential("runtime_password")  # Validate the delivered credential before connecting.
    return all(healthy_service(service) for service in selected(config))


def stop_services(services, *, targets=(), timeout=1000, dotnet=None):
    # A failed stop job (including TimeoutStopSec/SIGKILL) is not proof of a
    # live writer. Always read back every MainPID and the entire cgroup.
    name = active_unit_name if dotnet is None else (dotnet_unit_name if dotnet else unit_name)
    subprocess.run(["systemctl", "stop", *targets, *map(name, services)], timeout=timeout, check=False,
                   capture_output=True)
    for service in services:
        row = systemd(service) if dotnet is None else systemd(service, dotnet=dotnet)
        if row.get("LoadState") == "not-found":
            continue
        require(row.get("ActiveState") in {"inactive", "failed"} and row.get("MainPID") == "0",
                "native_writers_still_running")
        group = row.get("ControlGroup")
        require(isinstance(group, str), "native_cgroup_invalid")
        if group:
            require(group.startswith("/sli.slice/") and ".." not in Path(group).parts,
                    "native_cgroup_invalid")
            path = Path("/sys/fs/cgroup") / group.lstrip("/")
            require(not path.exists() or not any(p.read_text().strip() for p in path.rglob("cgroup.procs")),
                    "native_writers_still_running")
    return True


def stop_writers():
    # Waiting for the target alone does not wait for every propagated PartOf
    # stop job. Name all writers so systemctl also waits for their stop jobs.
    stop_services(SERVICES, targets=("sli-runtime.target",), dotnet=False)
    return stop_services((*SERVICES, *DOTNET_ONLY_SERVICES), targets=("sli-dotnet.target",))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("configure", "launch", "control", "ready", "health", "stop-writers"))
    parser.add_argument("service", nargs="?")
    parser.add_argument("--profiles", nargs="+", default=["light"], choices=("light", "heavy", "long"))
    parser.add_argument("--radius-pilot", action="store_true")
    parser.add_argument("--radius-source-instance", default="")
    parser.add_argument("--agents", action="store_true")
    parser.add_argument("--ad-credentials", action="store_true")
    parser.add_argument("--bind", default="127.0.0.1")
    args = parser.parse_args(argv)
    try:
        if args.command == "launch":
            launch(args.service)
        elif args.command == "control":
            launch(args.service, control=True)
        else:
            require(os.geteuid() == ROOT_UID, "native_root_required")
            if args.command == "configure":
                os.umask(0o022)
                address = str(ipaddress.ip_address(args.bind))
                require("light" in args.profiles, "native_profiles_invalid")
                require(not args.radius_pilot or re.fullmatch(r"[A-Za-z0-9._:-]{1,200}", args.radius_source_instance),
                        "native_pilot_source_required")
                url_host = clickhouse.health_host(address)
                configure({"schema_version": 1, "profiles": sorted(set(args.profiles)),
                           "radius_pilot": args.radius_pilot, "radius_source_instance": args.radius_source_instance,
                           "agents": args.agents, "ad_credentials": args.ad_credentials, "bind": address,
                           "health_url": f"https://{url_host}:8443/api/health/ready"})
            else:
                require({"ready": ready, "health": health, "stop-writers": stop_writers}[args.command](),
                        "native_runtime_unhealthy")
    except Exception as error:  # noqa: BLE001 - never print DB, file or subprocess diagnostics
        reason = error.code if isinstance(error, RuntimeErrorCode) else type(error).__name__
        if not isinstance(reason, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,100}", reason):
            reason = "RuntimeErrorCode" if isinstance(error, RuntimeErrorCode) else "Exception"
        print("native_runtime_failed reason=" + reason, file=sys.stderr)
        return 1
    print("native_runtime_verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
