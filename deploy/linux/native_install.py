"""Bounded native fresh/reinstall/remove lifecycle; upgrades require N12 coordinator.

This file also runs with Debian's stdlib-only Python from /usr/lib/sli.
Never invoke APT/dpkg here: maintainer scripts already hold their locks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

try:
    from deploy.linux.native_preinstall import ensure_directory
except ModuleNotFoundError:  # stdlib-only installed/recovery helper under -I.
    import importlib.util
    _permissions_spec = importlib.util.spec_from_file_location(
        "sli_native_preinstall", Path(__file__).with_name("native_preinstall.py"))
    _permissions = importlib.util.module_from_spec(_permissions_spec)
    _permissions_spec.loader.exec_module(_permissions)
    ensure_directory = _permissions.ensure_directory


RELEASES = Path("/opt/sli/releases")
RUNTIMES = Path("/opt/sli/runtimes")
CURRENT = Path("/opt/sli/current")
STATE = Path("/var/lib/sli/state")
RECOVERY = Path("/var/lib/sli/recovery")
SECRETS = Path("/etc/sli/secrets")
SITE = Path("/etc/sli/site.toml")
AGENT_SECRETS = ("agent_root_certificate", "agent_issuer_certificate", "agent_issuer_key", "agent_mtls_ca")
FAILURE_CODES = frozenset({
    "native_site_operation_stall_invalid",
    "native_agents_secrets_missing", "native_agents_secrets_invalid", "native_site_agents_invalid",
    "native_site_backup_root_invalid", "native_site_toml_invalid", "native_site_setting_unsupported",
    "native_backup_root_invalid", "native_backup_root_untrusted", "native_backup_root_same_device",
    "native_backup_root_insufficient_space", "native_backup_root_mount_mismatch", "native_backup_root_target_not_empty",
    "native_agents_reconfigure_site_mismatch", "native_agents_reconfigure_pending",
    "native_agents_reconfigure_conflict", "native_site_reconfigure_requires_coordinator",
})


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def operations():
    try:
        from deploy.linux import operation_wait
    except ModuleNotFoundError:  # stdlib-only sli-setup helper under -I
        import importlib.util
        spec = importlib.util.spec_from_file_location('sli_operation_wait', Path(__file__).with_name('operation_wait.py'))
        operation_wait = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(operation_wait)
    return operation_wait


def setup_watch():
    """One migration pass over this dataset, followed by service acceptance.

    Inner migration watches account for individual SQL files. This outer watch
    covers orchestration which can otherwise block before reaching any of them.
    Its silence allowance matches migration's configured allowance, not apt's
    elapsed wall time. Real inner progress renews it.
    """
    try:
        from deploy.linux import native_host as host
    except ModuleNotFoundError:
        import importlib.util
        spec = importlib.util.spec_from_file_location('sli_native_host', Path(__file__).with_name('native_host.py'))
        host = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(host)
    size = host.Host().backup_space_estimate(Path('/var/backups/sli/native'))['source_bytes']
    return operations().Watch('migration_setup', minimum=0, size=size, native=True,
                              history=operations().readiness_history(), work_path=Path(host.MOUNT))


@contextmanager
def setup_deadline():
    with operations().deadline(setup_watch()):
        yield


def configure_guarded(release):
    """A timed out reinstall may restart only the same accepted, unchanged DB.

    First-start failures stay fenced. Schema-changing package upgrades use the
    upgrade journal/checkpoint recovery boundary instead of this narrow path.
    """
    previous = None
    if (STATE / 'installed.json').exists() and (STATE / 'package-install.json').exists():
        receipt = json.loads(trusted(STATE / 'package-install.json'))
        installed = json.loads(trusted(STATE / 'installed.json'))
        root, _, digest = inventory(release)
        if (receipt.get('status') == 'configured' and receipt.get('release') == release
                and installed.get('release') == str(root) and installed.get('manifest_sha256') == digest
                and CURRENT.resolve(strict=True) == root):
            previous = receipt
    try:
        with setup_deadline():
            configure(release)
    except operations().OperationTimeout:
        if previous is not None:
            from deploy.linux import native_runtime as runtime, native_upgrade
            runtime.no_transaction()
            atomic(STATE / 'package-install.json', previous)
            native_upgrade.start_checked()
            command(['systemctl', 'enable', '--now', 'sli.target', 'sli-backup.timer'])
        raise


def trusted_path(path):
    for item in (path, *path.parents):
        info = item.lstat()
        require(not item.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022,
                "native_install_untrusted_path")
    require(path.is_file(), "native_install_file_required")
    return path


def trusted(path):
    return trusted_path(path).read_bytes()


def atomic(path, value):
    ensure_directory(path.parent, 0o700)
    require(not path.is_symlink(), "native_install_symlink")
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def command(argv, *, cwd=None, env=None, timeout=120):
    if len(argv) >= 2 and argv[-2:] == ['deploy.linux.entrypoint', 'migrate']:
        from deploy.linux import backup, native_backup, operation_wait
        import uuid

        with native_backup.environment(env or environment()), backup.pg_passfile() as passfile:
            with backup.pg_connect(passfile, 'postgres', autocommit=True) as connection:
                size = connection.execute("SELECT pg_database_size('sli')").fetchone()[0]
            watch = operation_wait.Watch('migration_run', minimum=21600, size=size,
                                         history=operation_wait.history_path(), native=True)
            application = 'sli_migration_' + uuid.uuid4().hex
            child_env = dict(env or environment(), PGAPPNAME=application)
            with tempfile.TemporaryFile() as output:
                process = subprocess.Popen(argv, cwd=cwd, env=child_env, stdout=output, stderr=output,
                                           start_new_session=os.name == 'posix',
                                           **({'pass_fds': operations().progress_fds()} if os.name == 'posix' else {}))
                process.sli_process_group = os.name == 'posix'
                operation_wait.wait_process(process, watch,
                    lambda: operation_wait.postgres_probe(passfile, application))
                if process.returncode:
                    output.seek(0, os.SEEK_END)
                    output.seek(max(0, output.tell() - 4096))
                    codes = output.read(4096).decode('utf-8', errors='replace').splitlines()
                    for code in ('operation_stalled', 'operation_deadline_exceeded'):
                        if code in codes:
                            raise RuntimeError(code)
            require(process.returncode == 0, 'native_install_command_failed')
            watch.success()
        return
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=timeout, check=False,
                            **({'pass_fds': operations().progress_fds()} if os.name == 'posix' else {}))
    if result.returncode:
        # Name the program and its last error lines; arguments may carry
        # configuration, so they are never logged.
        program = Path(argv[0]).name + (" " + argv[1] if len(argv) > 1 and argv[1] in {"start", "stop", "restart",
                                                                                      "enable", "disable", "daemon-reload"} else "")
        lines = result.stderr[-4096:].decode("utf-8", errors="replace").strip().splitlines()
        # Only systemd's own messages are echoed verbatim; other programs
        # (psql, pg_restore, helpers) may print SQL rows, so only our reason
        # codes from them are kept.
        reason = re.compile(r"(?:[A-Za-z_.]+Error: )?native_[a-z_]+(?:: \S+)?")
        tail = [line for line in lines if reason.fullmatch(line.strip())][-3:]
        if Path(argv[0]).name in {"systemctl", "systemd-run", "systemd-tmpfiles"}:
            tail += lines[-3:]
        print("native_install_command_failed: " + program + " exit=" + str(result.returncode)
              + "".join("\n  " + line[:240] for line in tail), file=sys.stderr, flush=True)
    require(result.returncode == 0, "native_install_command_failed")
    operations().made_progress()


def inventory(release):
    require(re.fullmatch(r"[a-z0-9][a-z0-9.+-]{0,63}", release), "native_install_release_invalid")
    root = RELEASES / release
    raw = trusted(root / "native-runtime.json")
    manifest = json.loads(raw)
    require(manifest.get("schema_version") == 1 and manifest.get("migration_ledger")
            and manifest.get("plugins") and manifest.get("roles"), "native_install_inventory_invalid")
    python = Path(manifest["python"])
    require(python.is_relative_to(RUNTIMES) and len(python.relative_to(RUNTIMES).parts) == 3
            and python.parent.name == "bin" and python.name == "python3.14",
            "native_install_runtime_invalid")
    require(hashlib.sha256(trusted(python)).hexdigest() == manifest["python_sha256"]
            and os.access(python, os.X_OK), "native_install_runtime_mismatch")
    return root, manifest, hashlib.sha256(raw).hexdigest()


def environment():
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8",
           "SLI_DEPLOYMENT_MODE": "native", "ADLOG_DB_BACKEND": "postgres",
           "SLI_INSTALL_DOMAIN": "example.invalid",
           # The bootstrap placeholder is not an administrator-selected report domain.
           "SLI_INSTALL_SEED_REPORT_DOMAIN": "0",
           "SLI_CORE_JOB_WORKSTATIONS_RETENTION": os.environ.get("SLI_CORE_JOB_WORKSTATIONS_RETENTION", "0"),
           "SLI_CORE_JOB_WORKSTATIONS_PROJECTION": os.environ.get("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "0"),
           "ADLOG_HISTORY_READ_MODE": "disabled"}
    names = {"SLI_PG_ADMIN_PASSWORD": "postgres_password", "SLI_PLATFORM_OWNER_PASSWORD": "platform_owner_password",
             "SLI_NOTIFICATION_DB_PASSWORD": "notification_db_password",
             "SLI_REPORT_PRODUCER_PG_PASSWORD": "report_producer_password",
             "ADLOG_SEMANTIC_WORKER_PASSWORD": "semantic_password", "ADLOG_STORAGE_V2_WORKER_PASSWORD": "storage_password",
             "ADLOG_AD_CONTEXT_WORKER_PASSWORD": "context_password"}
    names.update(ADLOG_STORAGE_LIFECYCLE_PASSWORD="storage_lifecycle_password",
                 ADLOG_STORAGE_LIFECYCLE_DELETE_PASSWORD="storage_lifecycle_delete_password")
    names.update({f"SLI_JOB_{purpose.upper()}_LIGHT_PASSWORD": f"job_{purpose}_light"
                  for purpose in ("dispatcher", "executor", "publisher")})
    env.update({key + "_FILE": str(SECRETS / value) for key, value in names.items()})
    env.update({key: os.environ[key] for key in ('INVOCATION_ID', 'NOTIFY_SOCKET', 'WATCHDOG_PID', 'WATCHDOG_USEC')
                if key in os.environ})
    if operations().progress_fds():
        env[operations().PROGRESS_FD] = os.environ[operations().PROGRESS_FD]
    return env


def site_configuration():
    from deploy.linux.native_clickhouse_endpoint import parse_site
    return parse_site(trusted(SITE).decode("utf-8") if SITE.exists() or SITE.is_symlink() else "")


def site_digest(site):
    return hashlib.sha256(json.dumps(site, sort_keys=True).encode()).hexdigest()


def secret_metadata_valid(info):
    return (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 10001
            and stat.S_IMODE(info.st_mode) == 0o640 and 0 < info.st_size <= 1024 * 1024)


def validate_agents(site):
    if not site.get("agents", False):
        return
    for name in AGENT_SECRETS:
        path = SECRETS / name
        require(path.exists(), "native_agents_secrets_missing")
        require(not path.is_symlink() and secret_metadata_valid(path.lstat()), "native_agents_secrets_invalid")
        try:
            trusted(path)
        except (OSError, RuntimeError):
            raise RuntimeError("native_agents_secrets_invalid") from None


def runtime_settings(site):
    from deploy.linux.native_clickhouse_endpoint import health_host
    validate_agents(site)
    address = site["bind"]
    url_host = health_host(address)
    return {"schema_version": 1, "profiles": ["light"], "radius_pilot": False,
            "agents": site.get("agents", False), "bind": address,
            **({"https_port": site["https_port"]} if "https_port" in site else {}),
            **({"owner_setup": site["owner_setup"]} if "owner_setup" in site else {}),
            **({"notification_proxy": site["notification_proxy"]} if "notification_proxy" in site else {}),
            "health_url": f"https://{url_host}:{site.get('https_port', 8443)}/api/health/ready"}


def replace_managed(path, allowed, body):
    """Replace only a known rendered file; never remove configuration first."""
    info = path.lstat()
    require(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o644
            and trusted(path).decode("utf-8") in allowed, "native_agents_reconfigure_conflict")
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(body)
            stream.flush()
            os.fchown(stream.fileno(), 0, 0)
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def reconfigure_agents(release):
    """Bounded agents-only reconfiguration, without SQL or checkpoint restore.

    Durable intent closes readiness while runtime settings are being published.
    Repeat this command with the same site.toml after interruption. A coherent
    publication is allowed through readiness; autostart returns only after health.
    """
    from deploy.linux import native_backup, native_upgrade
    from deploy.linux import native_host as host
    from deploy.linux import native_runtime as runtime

    site = site_configuration()
    validate_agents(site)
    desired = site_digest(site)
    with native_upgrade.operation_lock(native_backup.ROOT):
        root, _ = native_upgrade.preflight()
        require(root.name == release, "native_agents_reconfigure_conflict")
        with host.administrative_lock():
            runtime.no_transaction(agents_reconfigure=True)
            receipt = json.loads(trusted(STATE / "package-install.json"))
            require(receipt.get("status") == "configured" and receipt.get("release") == release,
                    "native_agents_reconfigure_conflict")
            intent_path = STATE / "agents-reconfigure.json"
            intent = json.loads(trusted(intent_path)) if intent_path.exists() else None
            if intent and intent.get("status") != "configured":
                require(intent.get("release") == release and intent.get("site_sha256") == desired,
                        "native_agents_reconfigure_pending")
                require(receipt.get("site_sha256") in {intent["old_site_sha256"], desired},
                        "native_agents_reconfigure_conflict")
            else:
                old = runtime.configuration()
                previous_site = dict(site, agents=old.get("agents", False))
                hashes = {site_digest(previous_site)}
                if not old.get("agents", False):
                    previous_site.pop("agents")
                    hashes.add(site_digest(previous_site))
                require(receipt.get("site_sha256") in hashes, "native_agents_reconfigure_site_mismatch")
                new = dict(old, agents=site.get("agents", False))
                intent = {"schema_version": 1, "release": release, "site_sha256": desired,
                          "old_site_sha256": receipt["site_sha256"], "status": "applying",
                          "old_runtime": trusted(runtime.CONFIG).decode("utf-8"),
                          "new_runtime": json.dumps(new, sort_keys=True) + "\n"}
            # Refuse local edits before stopping anything, including after interruption.
            require(trusted(runtime.CONFIG).decode("utf-8") in {intent["old_runtime"], intent["new_runtime"]},
                    "native_agents_reconfigure_conflict")
            intent["status"] = "applying"
            atomic(intent_path, intent)
            command(["systemctl", "disable", "sli.target"])
            command(["systemctl", "stop", "sli-backup.timer", "sli-health.timer"])
            command(["systemctl", "stop", "sli-backup.service", "sli-backup-drill.service"], timeout=600)
            runtime.stop_writers()
            command(["systemctl", "stop", "sli-ready.service"])
            replace_managed(runtime.CONFIG, {intent["old_runtime"], intent["new_runtime"]}, intent["new_runtime"])
            receipt["site_sha256"] = desired
            atomic(STATE / "package-install.json", receipt)
            intent["status"] = "applied"
            atomic(intent_path, intent)
        try:
            command(["systemctl", "daemon-reload"])
            command(["systemctl", "start", "sli-ready.service"])
            command(["systemctl", "start", "sli-dotnet.target"])
            wait_api(runtime.configuration())
            wait_health()
            intent["status"] = "configured"
            atomic(intent_path, intent)
            command(["systemctl", "enable", "--now", "sli.target", "sli-backup.timer"])
        except Exception:
            runtime.stop_writers()
            raise


def select(root):
    require(not CURRENT.exists() and not CURRENT.is_symlink(), "native_install_foreign_current")
    CURRENT.symlink_to(root)


def wait_api(config):
    import ssl
    from urllib.error import URLError
    from urllib.request import urlopen

    context = ssl.create_default_context(cafile=str(SECRETS / "tls_ca"))
    operation = operations()
    watch = operation.Watch('api_ready', minimum=3600, history=operation.readiness_history(), native=True)
    while True:
        try:
            with urlopen(config["health_url"], context=context, timeout=3) as response:
                require(response.status == 200, "native_install_api_unready")
            watch.success()
            return
        except (URLError, TimeoutError, ssl.SSLCertVerificationError) as exc:
            if isinstance(exc, ssl.SSLCertVerificationError) or (
                isinstance(exc, URLError) and isinstance(exc.reason, ssl.SSLCertVerificationError)
            ):
                raise RuntimeError("native_api_tls_untrusted") from None
            try:
                watch.check()
            except RuntimeError:
                raise RuntimeError('native_install_api_unready') from None
            time.sleep(30)


def wait_health():
    operation = operations()
    watch = operation.Watch('workers_ready', minimum=3600, history=operation.readiness_history(), native=True)
    while True:
        try:
            command(["systemctl", "start", "sli-health.service"], timeout=30)
            watch.success()
            return
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            from deploy.linux import native_runtime as runtime
            try:
                pending = tuple(service for service in runtime.selected(runtime.configuration())
                                if not runtime.healthy_service(service)) or ('health',)
            except Exception:  # noqa: BLE001 - component names only, never configuration or SQL prose
                pending = ('workers',)
            try:
                watch.check(pending, components=pending)
            except RuntimeError:
                raise RuntimeError('native_install_workers_unhealthy') from None
            if not isinstance(error, subprocess.TimeoutExpired):
                time.sleep(30)


def configure(release):
    from deploy.linux import native_host as host
    from deploy.linux import native_runtime as runtime

    root, manifest, digest = inventory(release)
    operating_system = platform.freedesktop_os_release()
    require(operating_system.get("ID") == "debian" and operating_system.get("VERSION_ID") == "13"
            and platform.machine() == "x86_64", "native_debian13_amd64_required")
    site = site_configuration()
    config = runtime_settings(site)
    receipt_base = {"schema_version": 1, "release": release,
                    "site_sha256": site_digest(site), "first_start_pending": True}
    machine = host.Host()
    # Before any write: validate preparation, mount, service identities and inventory.
    with host.administrative_lock():
        machine.receipt()
        host.validate_identity()
        runtime.no_transaction()
        if "backup_root" in site:
            machine.validate_backup_root(site["backup_root"])
        installed_path = STATE / "installed.json"
        installed = json.loads(trusted(installed_path)) if installed_path.exists() else None
        if installed:
            require(installed.get("release") == str(root) and installed.get("manifest_sha256") == digest,
                    "native_upgrade_requires_coordinator")
            receipt = json.loads(trusted(STATE / "package-install.json"))
            require(receipt.get("status") in {"configured", "configuring", "failed"}
                    and receipt.get("release") == release,
                    "native_install_interrupted_requires_recovery")
            require(receipt.get("site_sha256") == receipt_base["site_sha256"], "native_site_reconfigure_requires_coordinator")
            require(CURRENT.resolve(strict=True) == root, "native_install_current_mismatch")
            receipt_base["first_start_pending"] = receipt.get("status") != "configured"
            if receipt_base["first_start_pending"]:
                # installed.json follows schema/runtime setup. Legacy receipts
                # lack the flag, but must match inventory/site and bootstrap owner.
                require(receipt.get("first_start_pending", True) is True and site.get("owner_setup"),
                        "native_install_interrupted_requires_recovery")
        else:
            require(not CURRENT.exists() and not CURRENT.is_symlink(), "native_install_foreign_current")
            require(not (STATE / "package-install.json").exists(), "native_install_interrupted_requires_recovery")
            # A pre-existing configured dataset is not implicitly adopted as fresh.
            require(not (Path(host.MOUNT) / "pgdata").exists()
                    and not (Path(host.MOUNT) / "clickhouse").exists(), "native_install_foreign_data")
            atomic(STATE / "package-install.json", dict(receipt_base, status="configuring"))
    resuming = bool(installed) and receipt_base["first_start_pending"]
    if resuming:
        # Fence any writers left by a killed first start before checking owner
        # activation. Do not hold the host lock while stopping dependent units.
        runtime.stop_writers()
        command(["systemctl", "stop", "sli-ready.service"])
        command(["systemctl", "start", *runtime.DATABASES])
        runtime.wait_databases()
        try:
            command([manifest["python"], "-I", "-B", str(root / "deploy/linux/native_setup.py"),
                     "--check-unclaimed-owner", release], cwd=root, env=environment())
        except RuntimeError:
            raise RuntimeError("native_install_interrupted_requires_recovery") from None
    writers_configured = bool(installed)
    try:
        if not installed:
            machine.configure()
            env = environment()
            if site.get("owner_setup"):
                env["SLI_NATIVE_OWNER_SETUP"] = "1"
            env["SLI_INSTALL_DOMAIN"] = site["domain_fqdn"]
            python = manifest["python"]
            tls_names = list(dict.fromkeys([site["bind"], site.get("server_name", site["domain_fqdn"])]))
            command([python, "-B", "-m", "deploy.linux.sli_secrets", "ensure", "--directory", str(SECRETS),
                     *[arg for name in tls_names for arg in ("--tls-name", name)]], cwd=root, env=env)
            command(["systemctl", "start", *runtime.DATABASES])
            command(["systemctl", "start", "sli-bootstrap-pg.service"])
            runtime.wait_databases()
            command([python, "-B", "-m", "deploy.linux.entrypoint", "migrate"], cwd=root, env=env, timeout=None)
            if "cold_tablespace_root" in site:
                # Only a fresh, fenced database: existing data moves exclusively
                # through the explicit reversible maintenance command.
                with host.administrative_lock():
                    machine.place_cold_tables("apply")
            runtime.configure(config)
            writers_configured = True
            select(root)
            atomic(installed_path, dict(manifest, release=str(root), manifest_sha256=digest))
        else:
            require(CURRENT.resolve(strict=True) == root, "native_install_current_mismatch")
            # RemainAfterExit readiness must run again on reinstall, not reuse old success.
            if not resuming:
                runtime.stop_writers()
                command(["systemctl", "stop", "sli-ready.service"])
        # The readiness adapter requires systemd-delivered administrative credentials.
        command(["systemctl", "start", "sli-ready.service"])
        # Fresh candidates may run for acceptance, but must not autostart on reboot yet.
        command(["systemctl", "start", "sli-dotnet.target"])
        config = runtime.configuration()
        wait_api(config)
        for service in runtime.selected(config):
            row = runtime.systemd(service)
            require(row.get("ActiveState") == "active" and int(row.get("MainPID", "0")) > 1,
                    "native_install_service_unready")
        wait_health()
        from deploy.linux import native_backup
        native_backup.configure()
        preserve_recovery(root, manifest, digest)
        atomic(STATE / "package-install.json", dict(receipt_base, status="configured", first_start_pending=False))
        command(["systemctl", "enable", "sli.target"])
        command(["systemctl", "start", "sli.target"])
        command(["systemctl", "enable", "--now", "sli-backup.timer"])
    except Exception:
        # Do not declare a partially accepted install reusable. No automatic destructive retry.
        try:
            if writers_configured:
                command(["systemctl", "disable", "--now", "sli-backup.timer"])
                command(["systemctl", "stop", "sli-backup.service", "sli-backup-drill.service"], timeout=600)
                runtime.stop_writers()
        finally:
            atomic(STATE / "package-install.json", dict(receipt_base, status="failed"))
            if writers_configured:
                command(["systemctl", "disable", "sli.target"])
        raise



def preserve_recovery(root, manifest, digest):
    release = root.name
    # Preserve the exact accepted management code and inventory for N12.
    recovery = RECOVERY / release
    ensure_directory(RECOVERY, 0o700)
    ensure_directory(recovery, 0o700)
    for name in ("native_host.py", "native_runtime.py", "native_install.py", "native_backup.py", "native_upgrade.py",
                 "native_clickhouse_endpoint.py", "native_preinstall.py", "native_pins.json", "backup_policy.py", "operation_wait.py"):
        destination = recovery / name
        body = trusted(root / "deploy/linux" / name)
        if destination.exists():
            require(trusted(destination) == body, "native_recovery_conflict")
        else:
            with destination.open("xb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            destination.chmod(0o600)
    atomic(recovery / "installed.json", dict(manifest, release=str(root), manifest_sha256=digest))
    from deploy.linux import native_upgrade
    native_upgrade.save_recovery(root, manifest, digest)

def remove():
    command(["/usr/sbin/sli-remove", "--stop-services"], timeout=None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("stage", "configure", "remove", "reconfigure-agents"))
    parser.add_argument("release", nargs="?")
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() == 0, "native_root_required")
        os.umask(0o022)
        release = args.release
        if args.action == "stage":
            inventory(release)
            atomic(STATE / "pending-release.json", {"schema_version": 1, "release": release})
            if (STATE / "installed.json").exists():
                print("Retained SLI installation. Run sudo sli-setup --reuse-existing / "
                      "Сохранена установка SLI: запустите sudo sli-setup --reuse-existing.")
            else:
                print("Packages installed. Run sudo sli-setup to configure and start SLI.")
            return 0
        if args.action == "reconfigure-agents" and release is None:
            installed = json.loads(trusted(STATE / "installed.json"))
            release = Path(installed["release"]).name
        if args.action == "remove":
            if any((STATE / name).exists() for name in ("installed.json", "host-prepared.json")) or CURRENT.is_symlink():
                remove()
            print("native_install_verified")
            return 0
        root, manifest, _ = inventory(release)
        # Privileged imports come only from the root-owned immutable release.
        trusted(root / "deploy/linux/native_install.py")
        if Path(sys.executable) != Path(manifest["python"]):
            # Replace the stdlib launcher: no unbounded waiting parent in apt.
            os.chdir(root)
            os.execve(manifest['python'], [manifest['python'], '-I', '-B',
                      str(root / 'deploy/linux/native_install.py'), args.action, release], environment())
        else:
            sys.path.insert(0, str(root))
            if args.action == "configure":
                configure_guarded(release)
            else:
                reconfigure_agents(release)
    except Exception as error:  # noqa: BLE001 - never echo file/subprocess diagnostics
        import importlib.util
        spec = importlib.util.spec_from_file_location('sli_diagnostics', Path(__file__).with_name('native_diagnostics.py'))
        diagnostics = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diagnostics)
        diagnostics.failure(error, default='native_install_failed')
        if str(error) in {'operation_stalled', 'operation_deadline_exceeded'}:
            print(str(error), file=sys.stderr)
        return 1
    print("native_install_verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
