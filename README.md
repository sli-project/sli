# SLI Platform — Security Log Intelligence

[Русская версия](README.ru.md)

> **Status: in development.** SLI is not ready for use yet. The first beta is planned for **1 December 2026**.

SLI collects and analyses Windows security events and Active Directory data.
The .NET server handles ingestion, access control, reports and alerts. The first
beta covers Active Directory checks, including Group Policy, and detects attacks
in domain controller logs.

Windows agents read approved sources and deliver bounded batches over HTTPS.
The core registers agents, authenticates them with mTLS and assigns modules.
SLI reads surveyed systems; source access and collection are explicitly
configured. Installing the server alone does not enable collection.

## Architecture

The first beta uses native Debian packages managed by systemd. PostgreSQL runs
on the host.
The stack includes the HTTPS API serving the React/TypeScript UI, migration and
backup services, and workers for post-collection processing, projections,
semantics, entity state, storage lifecycle, AD snapshots and remote access.

- **PostgreSQL 18** is the authoritative runtime database for operational data,
  identities, permissions, job state and migration history.
- **Agents** receive a server URL, public trust bundle and assigned policies;
  they need no database credentials.
- **Core and plugins** separate shared mechanisms from source-specific knowledge.

## Installation

Use clean **Debian 13 amd64** with sudo, network access to Debian repositories,
4 cores and 8 GB RAM. SLI needs **20 GiB free** on a local ext4 or XFS volume
after APT installs the packages. Allow inbound HTTPS on port 443 or the port
printed by the installer.

1. Get `sli-debian-beta-kit.tar.gz` through your beta provider's authenticated
   delivery channel and unpack it on Debian.
2. From the directory where you unpacked the archive, run:

   ```sh
   bash sli-debian-beta-kit/install-beta-kit
   ```

   The script verifies the kit checksums, installs the packages and runs setup
   without asking for a server address, port or disk.
3. Open the printed HTTPS address. For first-time access on Windows, paste the
   PowerShell line from your trusted server console to add the server's public CA
   to your Windows account and open the address. Sign in with `admin` / `admin` and
   set a new password of at least 12 characters.

### Optional setup settings

Pass these flags after `install-beta-kit`, or to `sudo sli-setup` if the
packages are already staged.

- `--server`, `--port`, `--bind` override the address, HTTPS port and listener.
  Setup uses a resolvable local hostname or a local IP. It prefers HTTPS port 443
  and selects a free port if 443 is busy. Use a stable DNS name or IP.
- `--directory /srv/sli-data` picks a dedicated data directory. By default SLI
  uses `/var/lib/sli-db` if it has room, then looks for the mounted volume with
  the most free space. `--uuid <UUID>` uses an ext4 volume already mounted at
  `/srv/sli-db`. Keep the selected volume mounted across reboots.
- `--backup-root /mnt/backup/sli` selects an existing directory on a separate disk
  for backups. `--cold-tablespace-root` selects an existing directory on a
  separate disk for cold PostgreSQL tables.
- `sudo sli-setup --reset-admin-password` sets the owner's password to `admin`,
  revokes existing sessions and requires a password change at the next sign-in.
  The owner's username stays the same.
- From the server's root terminal, run `sudo sli-setup --owner-recovery <owner-username>`
  for a locked-out owner. Use `admin` on a fresh installation or the existing
  username after an upgrade. Enter the single-use code within 10 minutes together
  with the current password. Issuing another code invalidates the previous one.
  Only an active platform owner can recover this way. The password and the
  regular login lockout stay in effect.

To open the server from another OS, import `/var/lib/sli/tls-ca.crt` from the
trusted server into the browser's trust store. Compare its SHA-256 DER
fingerprint with the one printed by setup. To display it again on Debian, run
`openssl x509 -in /var/lib/sli/tls-ca.crt -noout -fingerprint -sha256`. Repeating
`sudo sli-setup` preserves saved settings and keys. Inspect installation
diagnostics with `sudo journalctl -t sli-setup`.

The default listener covers IPv4 and, when available, IPv6. Health checks use
loopback with matching TLS certificate names. Use `--bind 192.0.2.10` to restrict
the listener to one local address, or `--bind 127.0.0.1` behind a local reverse
proxy with explicitly configured trusted proxies.

Use a stable DNS name or static IP. Setup includes the supplied name or IP and
the applicable resolved addresses in the certificate. After a DHCP address
change, update DNS and keep the same DNS URL with wildcard binding. Saved
server names, binds and ports are retained on retries. Changes fail with
`native_setup_configuration_conflict`. Keep the original static IP for an
IP-only installation.

If no eligible data directory has 20 GiB free, use `lsblk -f` to inspect the
volumes. Mount a dedicated volume persistently before rerunning setup with the
storage options above. Setup preserves existing filesystems and data.

### Windows agent

After signing in, open **Agents → Add agent** and run the PowerShell
command on the domain controller.

The MSI and its checksum are available at `/app/installers/SliAgent.msi`
and `/app/installers/SHA256SUMS` on the server's HTTPS address. If your kit
includes the portable ZIP, download it at `/app/installers/SliAgent-publish-win-x64.zip`
and use the same checksum file.
See [agent enrollment](docs/agent-enrollment.md) for registration and CA pinning.

### Native backups

Check the scheduled daily backup with `sudo systemctl list-timers sli-backup.timer`.
`sudo sli-backup` creates a backup now and prints its directory.
`sudo sli-restore <backup-directory>` restores data and settings on a server with the matching Debian kit installed.
`sudo sli-rollback [previous-kit-directory]` restores the previous version using the backup taken automatically before the update.

Keep the backup directory accessible to root only. On a new server, install the same
Debian kit version and keep the original connection address (DNS name or IP) so agents
reconnect with their existing certificates. If you saved AD credentials, provision
their original protected key on the new server. Rollback uses the official `.deb` kit
in the specified protected directory or the same version from APT. Both commands save
the current data under `/var/backups/sli/native/before-restore` before replacing it.
The result is `/var/backups/sli/native/last-result.json`; when an external backup
volume is configured, SLI mounts it under `/var/backups/sli`.
`backup_created` confirms capture and integrity checks; it does not mean that a full
isolated restore has passed. Keep older verified recovery sets until that is confirmed.

### Reinstallation with retained data

On the same prepared host, with the complete retained databases, configuration,
secrets, agent CA, `/var/lib/sli` registry and sealed recovery, install the complete
matching new Debian kit from its directory:

```bash
sudo apt remove sli
sudo apt install ./*.deb
sudo sli-setup --reuse-existing
```

Remove stops SLI and its databases and keeps their data. Packages only stage the
new candidate. Setup runs the new verified coordinator: it checks the saved
installation, fences writers, captures a complete checkpoint and verifies its
content and consistency, then migrates, tests and commits the candidate. Existing passwords,
certificates and agent registrations are reused. Repeating the command after
commit repeats acceptance without another migration or checkpoint.

If refused, preserve databases, secrets, registry, recovery and transaction
directories. Check `reason_code`, `sudo journalctl -t sli-setup`,
`sudo journalctl -u sli-reuse-check`, and the transaction's `result.json`.
Correct storage/identity/configuration conflicts; restore a missing complete
secret bundle from trusted recovery. Never rename registry/journal files or run
fresh bootstrap to bypass refusal. An unfinished transaction requires the
coordinator's `sudo sli-native-upgrade resume-package <target-version>`;
after automatic recovery from an APT failure, follow its package reconciliation procedure.
Use `sudo sli-rollback` after a successful update.

In `site.toml`, optional `operation_stall_minutes = 15` (integer 1–180) controls no-progress waits; migrations default to 30 minutes when omitted. Size/history estimate duration; work continues while confirmed progress arrives.

Directory mode keeps local copies under `/var/backups/sli/native` when an external
backup disk is absent. Restore verification requires a separate volume. Move
`/var/lib/sli-ca-offline` to protected offline storage and distribute only public
CA certificates to agents.

**Uninstall:** `sudo apt remove sli` stops applications, timers and databases.
Data, `/etc/sli`, secrets and recovery packages survive removal and purge;
`sli-host` is protected while installed database state remains. History/key
destruction is a separate operation. Remove the Windows agent through
**Installed apps → SLI Agent**. These procedures require clean-Debian acceptance;
source code and unit tests do not constitute deployment acceptance.

For development, use the separate [dev container workflow](CONTRIBUTING.md).

## Upgrade

For an installed beta, obtain the new complete kit described above and verify
`SHA256SUMS` through the trusted delivery channel. In its `.deb` directory run:

```sh
sudo apt install --fix-broken ./*.deb
```

No manual setup is needed.
The package hooks run preflight checks, create a complete recovery checkpoint and
verify its manifests, hashes and consistency before migrations, then migrate,
start and check health. New transactions record integrity verification; full
restore drills are a separate administrator operation. Transactions prepared by
an older coordinator keep their original full-restore requirement when resumed.
If preparation fails before the checkpoint is verified, SLI automatically restarts
the previous release; a failed restart is reported separately.

The upgrade runs as a `sli-upgrade-*` service; view its journal with `sudo journalctl -u 'sli-upgrade-*'`.

Free-space admission remains mandatory for the checkpoint and its capture staging.
Let **B** be the maximum of this machine's latest successful set's manifest size
and measured directory size, plus any positive increase over its previous set,
**P** be `pg_database_size`, **F**
the application files copied into capture staging, and **S** the protected
configuration/state/recovery companion. Historical set sizes are projected with
the current companion size before calculating positive data growth. Ordinary native capture needs
**B + F + 1 GiB** on the backup volume: the new set, its file-source copy, and a reserve.
Before the first backup, **B = P + F + S**, without assuming a compression ratio.
When PostgreSQL is stopped, its file sizes provide an upper estimate instead of
SQL. Live-data volumes retain the separate 1 GiB growth reserve. Refusals show
the volume, required bytes and free bytes; remove unneeded old backup sets to
free space.

To verify actual recovery from the latest completed native backup, explicitly run:

```bash
sudo systemctl start sli-backup-drill.service
sudo journalctl -u sli-backup-drill.service -f
```

This operation starts an isolated PostgreSQL instance and requires an
additional **2B + 1.2P + 10 GiB** beyond the saved set. With separate volumes,
one B belongs to the backup volume and the remainder to the workspace; on one
filesystem the requirements are added. The drill rechecks actual set and expanded
ZIP sizes before restoration. Service start is only launch confirmation: wait
for successful completion and `status=restore_verified`, `terminal=true` and
`databases_stopped=true` in `/var/backups/sli/native/restore-verified.json`.
An ordinary upgrade's `integrity_verified` receipt records the separate content
check level; successful candidate health and commit remain required.

After APT succeeds, check `sudo systemctl status sli.target sli-health.service`
and sign in. If APT reports an upgrade error, follow the single recovery command
printed with its reason code (repeat APT from the kit directory if instructed).
Diagnostics: `sudo journalctl -t sli-setup`.

After upgrading an old installation, the administrator may choose to delete retained ClickHouse data: `sudo rm -rf -- /srv/sli-db/clickhouse`.

## Security model

HTTPS protects operator and agent connections. Enrollment uses an owner-approved
key fingerprint and a short-lived, single-use token; agent requests require mTLS
and registry checks. Platform permissions and scope govern reports and evidence.
Runtime database roles have bounded privileges; migrations use a separate
administrative path. Keep passwords, tokens and private keys in protected files
outside the repository. Do not log secrets or private directory data.

Collection is read-only and bounded. Storage deletion and warm-copy admission
remain closed until explicitly approved through the operational gates.
See the [security policy](SECURITY.md) and the [administrator guide](docs/ADMIN_GUIDE.md).

## Documentation

| Topic | English | Русский |
| --- | --- | --- |
| Server installation | [Guide](docs/install/SERVER_INSTALL.en.md) | [Руководство](docs/install/SERVER_INSTALL.ru.md) |
| Agent installation | [Guide](docs/install/AGENT_INSTALL.en.md) | [Руководство](docs/install/AGENT_INSTALL.ru.md) |

- [Contributing, checks and migrations](CONTRIBUTING.md)
- [Agent enrollment and CA](docs/agent-enrollment.md)
- [Administrator guide](docs/ADMIN_GUIDE.md) and [user guide](docs/USER_GUIDE.md)

## License

SLI Platform and its agent are licensed under [Apache-2.0](LICENSE).
Separately licensed dependencies and Sigma content are listed in [NOTICE](NOTICE).
Public source snapshots start a new migration checksum lineage and are intended
for fresh installations. Do not use one to update a private-lineage database.
The public beta download channel and private security reporting channel must be
confirmed by the repository owner before publication; no public kit URL is
asserted here.
