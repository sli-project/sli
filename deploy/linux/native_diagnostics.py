"""Human CLI diagnostics and bounded journal records."""
import re
import sys

# Only these command names and fixed unit names may cross the subprocess boundary.
COMMAND_FAILURES = {
    'native_command_failed: ' + command for command in (
        'systemctl list-unit-files', 'systemctl list-units', 'systemctl stop',
        'systemctl disable', 'systemctl start', 'systemctl daemon-reload', 'systemctl reset-failed',
        'findmnt', 'runuser', 'dpkg-divert', 'groupadd', 'useradd', 'usermod',
        'postgres', 'pg_lsclusters', 'pg_createcluster', 'pg_controldata', 'dpkg-query', 'psql',
        'systemd-tmpfiles', 'ss', 'lsblk',
    )
}
COMMAND_FAILURES.update(
    f'native_command_failed: systemctl {action} {unit}'
    for action in ('stop', 'disable', 'reset-failed')
    for unit in ('sli-clickhouse-history.service', 'sli-clickhouse-warm.service', 'clickhouse-server.service')
)

MESSAGES = {
    'native_site_cold_tablespace_root_invalid': 'cold_tablespace_root: задайте отдельный каталог ёмкого диска под /mnt или /srv, без пробелов и ссылок.',
    'native_cold_root_invalid': 'Ёмкий диск отсутствует, доступен только для чтения или не является локальным ext4/XFS с UUID.',
    'native_cold_root_untrusted': 'Каталог ёмкого диска и его родители должны принадлежать root, запрещать запись группе/остальным и разрешать проход PostgreSQL.',
    'native_cold_root_same_device': 'Холодные таблицы требуют второго диска: выбранный каталог находится на диске основной БД.',
    'native_cold_mount_mismatch': 'Сохранённый ёмкий диск отсутствует или подменён. Верните исходный диск; данные не перемещены.',
    'native_cold_directory_conflict': 'Каталог pg-tablespace занят посторонними данными или имеет неверные права. Существующие данные сохранены.',
    'native_cold_not_configured': 'Укажите cold_tablespace_root в /etc/sli/site.toml. Для просмотра используйте sudo sli-cold-tables plan, для переноса sudo sli-cold-tables apply.',
    'native_cold_rollback_missing': 'Нет сохранённого исходного размещения: эта команда ещё не переносила таблицы.',
    'native_cold_journal_invalid': 'Сохранённый план возврата не соответствует холодным таблицам. Данные сохранены; перенос остановлен.',
    'native_cold_relation_changed': 'Состав таблиц изменился после сохранения плана. Перенос остановлен, чтобы не затронуть другую таблицу.',
    'native_cold_tablespace_conflict': 'Tablespace sli_temp_hdd уже существует с другим путём или владельцем. Он не изменён; выберите его исходный диск.',
    'native_cold_sql_failed': 'PostgreSQL не выполнил шаг. Незавершённая транзакция отменяется; исходное размещение сохранено. Проверьте журнал sli-postgresql и свободное место. Повторите sudo sli-cold-tables apply или sudo sli-cold-tables rollback.',
    'operation_stalled': 'No progress; inspect the reported step and last progress time / Нет прогресса: проверьте указанный шаг и время последнего прогресса.',
    'operation_deadline_exceeded': 'Machine safety limit reached; inspect the reported step / Достигнут страховочный предел машины: проверьте указанный шаг.',
    'native_site_operation_stall_invalid': 'operation_stall_minutes must be an integer from 1 to 180 / operation_stall_minutes: целое число от 1 до 180.',
    'native_owner_recovery_terminal_required': 'Run owner recovery at the server console in an interactive terminal.',
    'native_owner_recovery_failed': 'Owner recovery failed. Check the active owner name and installed database/schema; no account was unlocked or password reset.',
    'native_root_required': 'Run this command with sudo.',
    'native_debian13_amd64_required': 'SLI beta requires Debian 13 on amd64. Use a clean supported server.',
    'native_existing_database': 'Existing database files were found. Use a clean server; SLI will not adopt or erase another database.',
    'native_database_directory_invalid': 'Choose a dedicated directory under /var/lib, /srv or /mnt, or sli-db at the root of a dedicated mounted volume.',
    'native_database_filesystem_unsupported': 'Database storage must use a local ext4 or XFS filesystem. Network, temporary and overlay filesystems are unsupported.',
    'native_database_filesystem_readonly': 'The database filesystem is read-only. Mount it read-write before retrying.',
    'native_database_space_insufficient': 'At least 20 GiB must be free for the databases. Free space or choose a larger disk.',
    'native_database_mount_mismatch': 'The database volume is missing or differs from the prepared storage. Restore its mount before retrying.',
    'native_mount_uuid_invalid': 'Supply the filesystem UUID shown by lsblk -f, mounted at /srv/sli-db.',
    'native_database_port_busy': 'A database port is already in use. Use a clean server without another PostgreSQL or ClickHouse instance.',
    'native_setup_port_busy': 'The HTTPS port or bind address is unavailable. Choose this server’s local IP and a free port with --bind and --port.',
    'native_site_port_invalid': 'The HTTPS port must be an integer from 1 to 65535.',
    'native_site_server_name_invalid': 'Enter a DNS hostname or IP address, without https://, port or path.',
    'native_setup_dns_failed': 'The server name cannot be resolved. Correct DNS or supply its local IP with --server.',
    'native_setup_server_required': 'No usable server address was found. Configure a local IP address or specify the reachable address with --server.',
    'native_setup_mode_mismatch': 'The selected ClickHouse mode differs from the installed package set. Install a matching beta kit; do not switch an existing database mode.',
    'native_setup_configuration_conflict': 'SLI is already configured differently. Rerun without changed flags; use the reconfiguration procedure for an installed server.',
    'native_setup_storage_conflict': 'The requested storage differs from the prepared volume. Rerun with the original storage settings.',
    'native_install_interrupted_requires_recovery': 'Automatic continuation is unsafe: the initial registry is incomplete, the owner is activated, or the saved installation does not match. Preserve data and state files. Run sudo journalctl -t sli-setup -u sli-ready.service -u sli-health.service -n 80 --no-pager for diagnosis; manual recovery is required, not a database reset.',
    'native_setup_not_staged': 'No beta release is staged. Install the complete matching deb kit with apt, then run sudo sli-setup.',
    'native_reuse_installation_required': 'Retained SLI installation is incomplete. Preserve databases, secrets and registry; restore the missing configuration/recovery / Сохранённая установка SLI неполная. Сохраните БД, секреты и registry; восстановите недостающие настройки/recovery.',
    'native_setup_secrets_failed': 'TLS or agent certificate creation failed. Check journalctl -t sli-setup and protected directory permissions; do not delete existing keys.',
    'native_agents_secrets_missing': 'Agent certificates are missing. Run sudo sli-setup to generate the initial CA, or restore the complete protected issuer bundle.',
    'native_postgres_bootstrap_unready': 'PostgreSQL did not accept local connections for initial setup. Check sudo journalctl -u sli-postgresql.service -u sli-bootstrap-pg.service, then repeat sudo sli-setup with the same flags.',
    'native_setup_install_failed': 'SLI could not finish its first start. Check sudo journalctl -t sli-setup and sudo journalctl -u sli-postgresql.service -u sli-bootstrap-pg.service -u sli-ready.service -u sli-health.service. After fixing the cause, repeat sudo sli-setup with the same flags. Preserve the database and configuration.',
    'native_api_tls_untrusted': 'SLI HTTPS certificate is not trusted by /var/lib/sli/tls-ca.crt. Check the server name and run sudo sli-setup again.',
    'native_setup_health_failed': 'SLI services are not ready. Check systemctl --failed and journalctl -u sli-health.service.',
    'native_web_console_setup_failed': 'Could not set up Cockpit. Check APT, HTTPS port 9090 and sudo journalctl -u cockpit.socket -u cockpit.service.',
    'native_web_console_disable_failed': 'Could not stop Cockpit. Check sudo journalctl -u cockpit.socket -u cockpit.service.',
    'native_initial_admin_unavailable': 'The initial administrator password is unavailable. Run sudo sli-setup --reset-admin-password to set a new one.',
    'native_backup_root_same_device': 'The external backup directory must be on another device. Omit --backup-root to use local beta backups, or attach a separate backup disk.',
    'native_backup_root_insufficient_space': 'The backup filesystem lacks space for recovery. Free space or use a larger backup disk.',
    'native_host_busy': 'Another SLI administrative command is running. Retry after it finishes.',
    'native_setup_busy': 'Another sli-setup is running. Retry after it finishes.',
    'native_symlink_forbidden': 'An administrative path contains a symbolic link. Use a dedicated directory with trusted ownership and permissions.',
    'native_existing_configuration_conflict': 'An existing configuration differs from SLI’s managed file. Preserve it and resolve the conflict before retrying.',
    'native_install_inventory_invalid': 'The staged SLI release inventory is invalid. From the matching beta kit run sudo apt install --reinstall ./sli-release-*_amd64.deb, then sudo dpkg --configure -a.',
    'native_vendor_cluster_guard_missing': 'PostgreSQL startup guard is missing in /etc/postgresql-common/createcluster.conf. Inspect the file and run sudo dpkg --configure -a before retrying setup.',
}


def log_code(code):
    try:
        import syslog
        syslog.openlog('sli-setup')
        syslog.syslog(syslog.LOG_ERR, code)
    except (ImportError, OSError):
        pass


def failure(error, *, default='native_setup_failed'):
    candidate = str(error) if isinstance(error, (RuntimeError, ValueError)) else ''
    if candidate == 'native_command_failed':
        command = 'native_command_failed: ' + (getattr(error, 'command', None) or '')
        unit = getattr(error, 'unit', None)
        if unit and f'{command} {unit}' in COMMAND_FAILURES:
            candidate = f'{command} {unit}'
        elif command in COMMAND_FAILURES:
            candidate = command
    if candidate in COMMAND_FAILURES:
        log_code('native_command_failed')
        for line in getattr(error, 'stderr', ()):
            log_code(f'{candidate}: {line}')
        print(candidate, file=sys.stderr)
        return
    health_reason = re.fullmatch(r'native_setup_health_failed:[A-Za-z_][A-Za-z0-9_]{0,63}', candidate)
    if health_reason:
        log_code(candidate)
        print(MESSAGES['native_setup_health_failed'], file=sys.stderr)
        return
    code = candidate if candidate in MESSAGES or re.fullmatch(r'native_[a-z_]{1,100}', candidate) else default
    log_code(code)
    if code == 'native_postgres_bootstrap_unready':
        for line in getattr(error, 'stderr', ()):
            log_code(f'pg_isready: {line}')
    message = getattr(error, 'console_message', None) or MESSAGES.get(code)
    print(message or 'SLI could not complete this operation. Run sudo journalctl -t sli-setup -n 80 --no-pager and systemctl --failed; preserve existing data and configuration.', file=sys.stderr)
