# SLI Platform — Security Log Intelligence

[Русская версия](README.ru.md)

SLI collects and analyses security evidence for investigations: Windows events,
directory context, remote access and workstation observations. A Python core
provides ingestion, identities, storage, access control, job execution, reports
and investigations. Bundled plugins supply collection modules, normalization,
rules and views for AD/domain controllers, GPO, VPN/remote access (including
NPS/RADIUS), and workstations.

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

## Quick installation — first beta, Debian 13

Use a clean **Debian 13 amd64** server with sudo, 4 cores, 8 GB RAM, internet,
a local ext4 or XFS filesystem, a disk of at least 40 GB and **20 GiB free after
installing the packages**. No separate database partition is required. The server
name must resolve from your browser and agent; an IP address also works. Allow
inbound TCP 443 in your firewall. This fresh-install procedure does not adopt
another PostgreSQL installation. Collection requires one Windows
10 / Server 2016 or later computer with local administrator access.

1. Obtain the **complete Debian 13 amd64 beta kit** from the release provider;
   obtain or build the .NET agent separately in step 6. Check the supplied
   checksums through your trusted delivery channel. Extract it and enter the directory containing the `.deb`
   files: `sli-host`, `sli`, `sli-rollback-hold`, `sli-release-*`, `sli-runtime-*`,
   `sli-server-dotnet`, and pinned vendor dependencies including PostgreSQL 18.
   Source code alone is insufficient. A public APT repository and
   package signing are separate release work; do not add an unverified repository.
2. Update the distribution package index:

   ```sh
   sudo apt update
   ```

3. Install the full kit:

   ```sh
   sudo apt install --fix-broken ./*.deb
   ```

   APT installs the dependencies and startup guard before the database server.
   The guard prevents an automatic vendor `main` cluster;
   package installation stages SLI without starting it, creating an owner or
   formatting a disk.
4. Run **`sudo sli-setup`**. Enter the server name/IP and HTTPS port (Enter uses
   **443**). For automation:

   ```sh
   sudo sli-setup --non-interactive --server sli.example.org --port 443
   ```

   Replace these examples with your name and local IP; IP-only installation needs
   just `--server <IP>`. Setup creates site.toml, secrets, TLS SANs for the name
   and IP, the agent CA, services, and `/var/lib/sli-db` bound to `/srv/sli-db`.

   The database needs at least 20 GiB free. If `/var/lib/sli-db` is too small,
   setup reports the available space and lists candidate volumes. Use `lsblk -f`
   to identify an existing dedicated ext4 filesystem, mount it at `/srv/sli-db`,
   and add that mount to `/etc/fstab` so it survives reboot. Then run
   `sudo sli-setup --uuid <UUID>` with its filesystem UUID and any other setup
   flags. For an empty directory on an already mounted ext4 or XFS filesystem,
   use `sudo sli-setup --directory /mnt/sli-data` if that is the mount's directory.
   Setup does not format or relocate existing data.

   New setups listen on all IPv4 addresses (`0.0.0.0`), and IPv6 (`::`) when
   dual stack is available. DHCP changes do not pin the listener to an old IP.
   Health probes use loopback, with loopback SANs in the TLS certificate.
   Use `--bind 192.0.2.10` to restrict HTTPS to one address, or
   `--bind 127.0.0.1` behind a local reverse proxy; configure trusted proxies
   explicitly. Authentication and HTTPS requirements still apply.
   Use a static IP or stable DNS name for browsers and agents. Setup issues the
   certificate for the name/IP supplied at installation and the IPs resolved then.
   After an IP change, update DNS and retain the same DNS URL (with wildcard bind).
   **`sudo sli-setup --server <new-IP>` does not reissue certificates:** saved
   server name, bind and port changes fail with `native_setup_configuration_conflict`.
   IP-only installations must retain/restore their original static IP; changing
   the address/certificate of an installed server has no automated beta path.
   Existing installations retain their saved bind;
   do not change only `site.toml` or delete certificates/installation receipts.
5. Copy the **public** CA `/var/lib/sli/tls-ca.crt` to your computer through a
   trusted channel, compare the printed SHA-256 DER fingerprint and import it
   into your OS/browser's trusted root store. To print that fingerprint again on Debian:

   ```sh
   openssl x509 -in /var/lib/sli/tls-ca.crt -outform DER | sha256sum
   ```

   This hashes the DER certificate, not the PEM file bytes. Open the printed link,
   `https://<server>/api/auth/bootstrap`, enter the **one-time code** from setup
   and choose a new password of at least 12 characters. The account is
   `platform-owner`; SLI opens after activation. The code becomes unusable and
   cannot be used for ordinary login. Keep it out of shared logs/tickets.
   Repeating `sudo sli-setup` preserves settings and keys. If the first start
   failed after schema/runtime configuration and the owner is still unclaimed,
   repeat the same command: setup retries readiness and health without resetting
   the database or rerunning migrations. The one-time code is displayed once;
   use `sudo sli-setup --new-owner-code` if it was lost or expired.

   If password guessing locks the activated owner out, run this in the server's
   root terminal:

   ```sh
   sudo sli-setup --owner-recovery platform-owner
   ```

   Enter the displayed single-use code together with the owner's existing
   password in the login form. It expires after 10 minutes; issuing another
   invalidates the previous code. This does not reset the password or clear
   the regular login lockout. Only an active platform owner can recover.
6. **Agents → Add agent → run the command on the domain controller.**

### Native backups

Check the scheduled daily backup with `sudo systemctl list-timers sli-backup.timer`.
To create a recovery set now, run `sudo sli-native-backup capture`.
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
after rollback, follow its explicit package reconciliation procedure. A committed
transaction must never be rolled back to its old checkpoint. Use a full VM
snapshot for disposable rehearsal recovery.

In `site.toml`, optional `operation_stall_minutes = 15` (integer 1–180) controls no-progress waits; migrations default to 30 minutes when omitted. Size/history estimate duration; work continues while confirmed progress arrives.

Select another dedicated directory before initial setup with
`--directory /srv/sli-data`. An optional separate ext4 filesystem, already mounted
at `/srv/sli-db` with a persistent fstab entry, uses `--uuid <UUID>`; setup never
partitions or formats disks. An existing trusted directory on another backup
disk can be selected with `--backup-root /mnt/backup/sli`. Otherwise directory
mode keeps local copies under `/var/backups/sli/native`: these **do not protect
against disk failure**. Restore verification requires a separate volume; creating
a copy never implies a verified restore. Move the generated agent root-key
directory `/var/lib/sli-ca-offline` to protected offline storage; distribute only
public CA certificates to agents.

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
