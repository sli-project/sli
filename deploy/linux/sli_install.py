"""Fresh Linux/Docker install; unsigned kits require explicit evaluation opt-in."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Verification must not mutate the sealed source tree during imports.
sys.dont_write_bytecode = True

if __package__ in {None, ''}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from deploy.linux.installation import InstallationHost, install
from deploy.linux.sli_update import UpdateError


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--trust-store', type=Path)
    parser.add_argument('--evaluation', action='store_true', help='Accept an unsigned kit for evaluation only')
    parser.add_argument('--kit', type=Path)
    parser.add_argument('--inventory-sha256', help='Expected kit inventory SHA-256 from a separate trusted channel')
    parser.add_argument('--runtime', type=Path, default=Path('/srv/sli'))
    parser.add_argument('--compose', type=Path, action='append', required=True)
    parser.add_argument('--health-url', default='https://127.0.0.1:8443/api/health/ready')
    parser.add_argument('--ca-file', type=Path, required=True)
    parser.add_argument('--tls-certificate', type=Path, required=True)
    parser.add_argument('--tls-key', type=Path, required=True)
    parser.add_argument('--backup-directory', type=Path)
    parser.add_argument('--restore-check-directory', type=Path,
                        help='Каталог проверки на томе копий / Restore workspace on the backup volume')
    parser.add_argument('--backup-daily-retention', type=int, default=7)
    parser.add_argument('--backup-weekly-retention', type=int, default=4)
    parser.add_argument('--data-directory', type=Path, help='Host directory for PostgreSQL, history and warm data volumes')
    parser.add_argument('--agent-secrets-from', type=Path)
    parser.add_argument('--restore-from', type=Path, help='Complete recovery set; import before migrations/apps')
    parser.add_argument('--roles-file', type=Path, help='Protected roles export for a legacy recovery set')
    parser.add_argument('--sync-owner-password', action='store_true')
    parser.add_argument('--notification-proxy-url', default=None,
                        help='Optional Telegram HTTP proxy URL, http://host:port; empty selects direct connection')
    parser.add_argument('--health-timeout', type=int, default=300)
    args = parser.parse_args(argv)
    if (args.roles_file is not None or args.sync_owner_password) and args.restore_from is None:
        parser.error('--roles-file and --sync-owner-password require --restore-from')
    if args.evaluation:
        if args.kit is None or args.inventory_sha256 is None:
            parser.error('--evaluation requires --kit and --inventory-sha256')
    elif args.kit is not None or args.inventory_sha256 is not None:
        parser.error('--kit and --inventory-sha256 require --evaluation')
    elif args.trust_store is None:
        parser.error('--trust-store is required for signed installation')
    try:
        host = InstallationHost(args.compose, args.health_url, args.ca_file, args.health_timeout)
        host.restore_from = args.restore_from
        host.restore_roles_file = args.roles_file
        host.restore_sync_owner_password = args.sync_owner_password
        host.restore_check_agent_trust = args.agent_secrets_from is not None
        if args.backup_directory is not None:
            host.environment['SLI_BACKUP_DIR'] = str(args.backup_directory)
        if args.data_directory is not None:
            host.environment['SLI_DATA_DIR'] = str(args.data_directory)
        if args.restore_check_directory is not None:
            host.environment['SLI_RESTORE_CHECK_DIR'] = str(args.restore_check_directory)
        if args.backup_daily_retention < 1 or args.backup_weekly_retention < 0:
            raise UpdateError('install_invalid_backup_retention')
        host.environment['SLI_BACKUP_RETENTION'] = str(args.backup_daily_retention)
        host.environment['SLI_BACKUP_WEEKLY_RETENTION'] = str(args.backup_weekly_retention)
        options = {'evaluation_kit': args.kit, 'inventory_sha256': args.inventory_sha256} if args.evaluation else {}
        if args.agent_secrets_from is not None:
            options['agent_secrets_from'] = args.agent_secrets_from
        if args.notification_proxy_url is not None:
            options['notification'] = {'proxy_url': args.notification_proxy_url}
        result = install(args.package, args.trust_store, args.runtime, host,
                         {'tls_ca': args.ca_file, 'tls_certificate': args.tls_certificate, 'tls_key': args.tls_key},
                         **options)
        print(json.dumps(result))
        return 0
    except Exception as exc:  # noqa: BLE001 - fixed public diagnostics only
        from deploy.linux.sli_secrets import SecretError

        reason = str(exc) if isinstance(exc, (UpdateError, SecretError)) else 'install_failed'
        result = {'status': 'failed', 'reason_code': reason, 'installed': False}
        if reason == 'install_backups_require_separate_volume':
            result['message'] = ('Копии требуют отдельный том — укажите каталог на HDD / '
                                 'Backups require a separate volume; select an HDD directory')
        print(json.dumps(result))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
