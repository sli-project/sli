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

Start with the [beta archive](#install-from-the-archive). Use a clean
**Debian 13 amd64** host with sudo and access to its configured APT sources.
Plan for 4 cores and 8 GB RAM. Setup requires **20 GiB free** on a local,
writable ext4 or XFS data volume after package installation. PostgreSQL needs
local port 5432 free on IPv4 and IPv6. Check for listeners with
`sudo ss -ltn 'sport = :5432'`. If that port is in use, install on a clean host
and leave the existing database intact. Allow inbound HTTPS on port 443 or the
port printed by setup.

### Install from the APT repository

Use this path once the repository is published. Keep the standard Debian 13
sources enabled and have `curl` available. The signed SLI repository includes
the pinned PostgreSQL 18 packages and the libraries required by `sli-runtime`.
Use the published full signing key fingerprint for `<FINGERPRINT>`.

```sh
(
  set -eu
  keyring=$(mktemp)
  trap 'rm -f "$keyring"' EXIT
  curl -fsSL https://sli-project.github.io/sli/sli-archive-keyring.gpg -o "$keyring"
  sudo install -D -m 0644 "$keyring" /etc/apt/keyrings/sli-archive-keyring.gpg
)
printf '%s\n' 'deb [arch=amd64 signed-by=/etc/apt/keyrings/sli-archive-keyring.gpg,<FINGERPRINT>] https://sli-project.github.io/sli trixie main' | sudo tee /etc/apt/sources.list.d/sli.list >/dev/null
```

Install the packages and run first-time setup:

```sh
sudo apt update && sudo apt install sli && sudo sli-setup
```

Update an existing installation:

```sh
sudo apt update && sudo apt upgrade
```

The repository keeps the current and previous SLI releases. Run `sudo sli-rollback`
to restore the version installed before the update and its backup. If that version
has left the repository, pass its extracted archive directory to `sudo sli-rollback`.

### Install from the archive

Use a published beta release with both download files. Download into an empty
directory you control. Leave space for the download, the unpacked kit and a
temporary copy of the kit under `/tmp`.

1. Download `sli-debian-beta-kit.tar.gz` and `SHA256SUMS` from the same
   `beta-…` entry in [Releases](https://github.com/sli-project/sli/releases).
   The release notes link to the GitHub Actions run and identify its source commit.
   In the download directory, verify the archive before extracting it.

   ```sh
   sha256sum --check SHA256SUMS && tar -xzf sli-debian-beta-kit.tar.gz
   ```

2. From the directory where you unpacked the archive, run:

   ```sh
   bash sli-debian-beta-kit/install-beta-kit
   ```

   The script checks the unpacked manifest, scripts and `.deb` files against the
   kit's own `SHA256SUMS`, refreshes the configured APT sources and installs the
   packages. It keeps newer installed vendor packages and prevents PostgreSQL
   from creating a default cluster. Setup selects the address, port and disk
   automatically unless you pass the options below.

### First sign-in

Wait for setup to finish successfully, then open the printed HTTPS URL. On
Windows, run the PowerShell line from the trusted server console to trust the
public CA in your Windows account and open the URL. On other systems, copy
`/var/lib/sli/tls-ca.crt` from the trusted server, compare its SHA-256 fingerprint
with the one printed by setup and import it into your browser's trust store.
The following command displays the fingerprint again on Debian.

```sh
openssl x509 -in /var/lib/sli/tls-ca.crt -noout -fingerprint -sha256
```

Check that the printed address resolves and is reachable from your PC and the
domain controller. On a fresh installation, sign in with `admin` / `admin`,
set a password of at least 12 characters, then
[connect the domain controller](#windows-agent).

### Optional setup settings

Pass these flags after `install-beta-kit`, or to `sudo sli-setup` if the
packages are already staged.

- `--server`, `--port` and `--bind` set the advertised address, HTTPS port and
  listener. Before setup, check that a stable DNS name or static IP is reachable
  from your PC and the domain controller. Pass `--server` without a scheme or
  port. If a supplied name does not resolve, setup reports the fallback IP or
  stops if it cannot find an address.
  Setup selects a free port when 443 is busy on a fresh install without
  `--port`. A conflict on an explicit or saved port stops setup.
- Without storage flags, setup uses the eligible local ext4 or XFS volume with
  the most free space, preferring `/var/lib/sli-db` on a tie. It skips the backup
  volume and leaves existing data intact. For `--directory /mnt/data/sli-db`,
  mount the volume at `/mnt/data`, use an empty directory for SLI and leave
  `/srv/sli-db` free for SLI's bind mount. With `--uuid`, mount the writable ext4
  volume directly at `/srv/sli-db` and pass its filesystem UUID. Keep mounts
  persistent across reboots. Use `lsblk -f`, `findmnt` and `df -h` to check the
  reported volume, mount point and free space.
- Prepare external storage before the first setup. `--backup-root /mnt/backup/sli`
  needs an existing, protected directory on a filesystem separate from the data
  volume, room for the first backup and a free mount point at `/var/backups/sli`.
  `--cold-tablespace-root` needs an existing, protected directory under `/mnt`
  or `/srv` on a separate writable ext4 or XFS filesystem with a UUID. Keep the
  paths and their parents free of symlinks, owned by root and writable only by
  root. The cold tablespace path and its parents need search permission for
  PostgreSQL. With `--uuid`, put backups on a filesystem separate from the
  database. Use `--backup-root` if the default backup path shares the data volume.
- `sudo sli-setup --reset-admin-password` sets the owner's password to `admin`,
  revokes existing sessions and requires a password change at the next sign-in.
  The owner's username stays the same.
- From the server's root terminal, run `sudo sli-setup --owner-recovery <owner-username>`
  for a locked-out owner. Use `admin` on a fresh installation or the existing
  username after an upgrade. On the sign-in page, open **Owner emergency sign-in**
  and enter the single-use code in **Recovery code** with the current password
  within 10 minutes. Issuing another code invalidates the previous one.
  Only an active platform owner can recover this way. The password and the
  regular login lockout stay in effect.

The default listener covers IPv4 and, when available, IPv6. Its certificate
covers the advertised name, resolved addresses and loopback. A specific
`--bind 192.0.2.10` limits HTTPS to that local address and health checks use it.
For a local reverse proxy, use `--bind 127.0.0.1` and configure trusted proxies.
After a DHCP address change, update DNS and keep the same DNS URL with default
binding. Keep the original static IP for an IP-only installation.

Repeat setup with the same settings. Saved names, binds, ports and storage paths
are checked for conflicts (`native_setup_configuration_conflict`). If the first
run stops before publishing its installation record and a retry reports
`native_install_interrupted_requires_recovery`, keep the database and
installation state. Record the reason, setup flags and disk mounts. Collect the
setup and service journals.

```sh
sudo journalctl -b -t sli-setup
sudo journalctl -b -u sli-postgresql.service -u sli-bootstrap-pg.service -u sli-ready.service -u sli-health.service
```

### Windows agent

1. Sign in as the platform owner or with the `access.manage` permission.
   Choose **Add agent** on **Home** when no agent is registered, or open
   **Agents → Add agent**.
2. Enter the HTTPS origin reachable directly from Windows, for example
   `https://sli.example.test:8443`, without `/app`. The name or IP must be in
   the server certificate. The command connects without a proxy or redirects.
   Select 1–100 computers (default 1). Leave audit
   management on to let SLI configure Windows auditing on the domain controller.
   If the address is rejected, use a name or IP listed in the error. If the
   form cannot load settings or the package, check the server's MSI and
   certificate and reopen the form.
3. Select **Create command** and run the copied line in 64-bit PowerShell as
   administrator on the domain controller. The UI saves the address. The line
   contains a secret registration key valid for one hour, with one registration
   per computer up to the selected count. Share it only with the administrator
   installing the agent. Create a new command if it expires or reaches its limit.
   The script verifies TLS and the MSI hash before installing.
4. After the service starts, check **Last contact** in **Agents** to confirm
   registration. Then open **System status → First run** at `/app/admin/status`
   and wait for **First data: received at …**. Once first run is complete, check
   **Sources → Latest data** for that computer on the same page. Check AD and
   Group Policy reports separately. Their snapshots require a confirmed domain
   scope for the controller.
5. Open **Notifications → Channels** (`/app/notifications?tab=channels`), set up
   a channel, select **Send test** and confirm that the test message arrives.

On the server, `sudo sli-agent-command` uses the saved address. The example
sets an address for the current command only.

```sh
sudo sli-agent-command --server-url https://sli.example.test:8443 --count 1
```

Replace the example with your HTTPS origin. Pass `--server-url` each time if
no address is saved. `--count` accepts 1–100 and `--no-audit` leaves audit
management off.

Verify a standalone download in PowerShell on a computer that trusts the server
CA. Substitute your server's HTTPS origin in the URL.

```powershell
curl.exe -fsS -D - -o SliAgent.msi https://sli.example.test:8443/api/v1/agent/installer/SliAgent.msi
Get-FileHash .\SliAgent.msi -Algorithm SHA256
```

Compare the printed `X-SLI-Package-SHA256` header with the file hash. Use the
generated command for first registration.

For a planned replacement of a standard MSI installation, issue a new command
for that computer and verify its contact and first data again. If the existing
registration requires owner approval, obtain it before replacement. If the
script reports a custom state directory, `agent.json` or a remaining old
service, keep its configuration and state and resolve the reported conflict
before retrying. Keep the previous MSI available. If replacement fails after
removing it, restoring the old Windows service may require that MSI.

### Native backups

Check the daily timer, then take the first backup and read its result.

```sh
sudo systemctl list-timers sli-backup.timer
sudo sli-backup && sudo cat /var/backups/sli/native/last-result.json
```

The command prints the completed set's directory. Match its name to `backup_id`
with `status=backup_created` and `terminal=true`. Keep older verified sets until
the new set passes a [restore drill](#upgrade). Without an external backup volume,
directory mode allows local backups under `/var/backups/sli/native`. With an
external volume, SLI mounts it at `/var/backups/sli`. Check the [space requirements](#upgrade)
on the filesystem that actually holds the backups.

### Restore and rollback

Use `sudo sli-restore <backup-directory>` to restore data and settings with the
exact Debian kit that created the set. Keep the set and every entry owned by
root and inaccessible to other users. Use regular files with no additional hard
links and directories with no symlinks. Retry an unfinished restore with the
same set.

On a clean replacement server, verify and unpack the exact archive as above.
Stage only the packages from the unpacked kit directory.

```sh
sha256sum --check --strict SHA256SUMS && sudo apt-get update && sudo apt-get install --no-remove ./*.deb
```

Copy the complete backup directory, including `manifest.json`, to the replacement
server with the ownership and permissions above. Run `sli-restore` on that copy.
Leave initial setup to restore because `sli-setup` and `install-beta-kit` both
initialize a fresh installation. Restore
uses directory mode, local backups and the default PostgreSQL tablespace.
Keep the original DNS name or IP for existing agent certificates. If the set
uses saved AD credentials, provision their original protected key on the new
server before restoring.

Before an upgrade, keep the previous verified kit and retain the backup the
upgrade takes. After a completed upgrade, `sudo sli-rollback <previous-kit-directory>`
uses that checkpoint and the previous runtime. Without a kit directory,
`sudo sli-rollback` needs the exact previous versions of `sli`, `sli-host`,
`sli-rollback-hold` and `sli-server-dotnet` from APT. For a failed upgrade use
the [upgrade recovery procedure](#upgrade).

Before replacing existing data, both commands save it under
`/var/backups/sli/native/before-restore/<transaction-id>/<backup-id>`.
Read `/var/lib/sli/transactions/<transaction-id>/result.json`. Success is
`status=committed` for restore or `status=rolled_back` for rollback, with
`services_restored=true` in either case.

### Reinstallation with retained data

On the same prepared host, with the complete retained databases, configuration,
secrets, agent CA, `/var/lib/sli` registry and sealed recovery, keep the verified
previous kit and verify and unpack the complete new kit. In the new kit directory,
verify the inner checksums and
check APT's plan before removing `sli`.

```sh
sha256sum --check --strict SHA256SUMS && sudo apt-get update && sudo apt-get -s install --no-remove ./*.deb
```

Use a kit whose dependencies resolve without downgrading vendor packages. Run
the reinstallation from the same directory.

```bash
sudo apt remove sli && sudo apt-get install --no-remove ./*.deb && sudo sli-setup --reuse-existing
```

Remove stops SLI and its databases and keeps their data. Packages only stage the
new candidate. Setup runs the new verified coordinator: it checks the saved
installation, fences writers, captures a complete checkpoint and verifies its
content and consistency, then migrates, tests and commits the candidate. Run
the [restore drill](#upgrade) separately. Existing passwords,
certificates and agent registrations are reused. Repeating the command after
commit repeats acceptance without another migration or checkpoint.

If refused, preserve databases, secrets, registry, recovery and transaction
directories. Check `reason_code`, `sudo journalctl -t sli-setup`,
`sudo journalctl -u sli-reuse-check` and the transaction's `result.json`.
Correct storage, identity or configuration conflicts. Restore a missing secret
bundle from trusted recovery and keep the original registry and journal names.
An unfinished transaction requires the
coordinator's `sudo sli-native-upgrade resume-package <target-version>`;
after automatic recovery from an APT failure, follow its package reconciliation procedure.
Use `sudo sli-rollback` after a successful update.

`operation_stall_minutes` in `site.toml` accepts an integer from 1 to 180 and
controls waits without progress. Migrations default to 30 minutes. Use the
value recorded at installation. Editing the saved file by hand can make setup
and reuse reject its configuration. Move `/var/lib/sli-ca-offline` to protected
offline storage and distribute only public CA certificates to agents.

### Uninstall

`sudo sli-remove` stops SLI and removes its packages and systemd units. It
retains databases, configuration, keys and recovery files. On an older
installation without `sli-remove`, run `sudo python3 -I ./remove-beta-kit`
from inside the unpacked, verified current kit.

To erase local SLI data as well, run `sudo sli-remove --purge-data` or
`sudo python3 -I ./remove-beta-kit --purge-data` for the older installation.
Verify that the intended database and cold-storage volumes are mounted first.
The flag erases local databases, settings, keys, the offline CA on this host,
local backups and the managed cold tablespace directory. It keeps shared Debian
and database packages, external backup volumes and copies stored offline.

On Windows, remove **SLI Agent .NET** from **Installed apps**. Its service is
`SLIAgentNet`. The entry **SLI Agent** belongs to the older MSI. To revoke the
server registration as well, open the computer in **Agents** and choose
**Disable agent**.

For development, use the separate [dev container workflow](CONTRIBUTING.md).

## Upgrade

Public beta kits start a separate migration checksum lineage. Use a clean
installation for a database from the private lineage. For an installed public
beta, use the same delivery path as before. For APT, use the
[APT update command](#install-from-the-apt-repository). For an archive installation,
download and verify the new kit as above.
Run the installer from the unpacked directory containing the `.deb` files,
`SHA256SUMS` and `install-beta-kit`.

```sh
bash ./install-beta-kit
```

The archive helper runs `sli-setup` after APT. Wait for both to succeed. The archive
installation does not add an SLI APT source.
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
SQL. Live-data volumes retain the separate 1 GiB growth reserve. Check free space
on the actual backup and data filesystems.

```sh
df -h /var/backups/sli/native /srv/sli-db
```

Refusals show the volume, required bytes and free bytes. Preserve the recovery
set named by `backup_id` in `/var/backups/sli/native/restore-verified.json`.
Keep the rollback checkpoint identified by `checkpoint`
in the upgrade's `journal.json` for as long as you need to roll back. Current
checkpoints are under `/var/backups/sli/native/upgrade-checkpoints/<transaction-id>`.

For a restore drill, take at least one successful backup first. The backup and
workspace (by default `/var/backups/sli/restore-check`) must be on filesystems
separate from the live database. Note the latest set's `backup_id`, then start
the drill and follow its journal.

```bash
sudo systemctl start sli-backup-drill.service
sudo journalctl -u sli-backup-drill.service -f
```

This operation starts an isolated PostgreSQL instance and requires an
additional **2B + 1.2P + 10 GiB** beyond the saved set. With separate volumes,
one B belongs to the backup volume and the remainder to the workspace; on one
filesystem the requirements are added. After the run finishes, read
`sudo cat /var/backups/sli/native/drill-result.json`. Check the expected
`backup_id`, a `completed_at_utc` from this run, `status=restore_verified`,
`terminal=true` and `databases_stopped=true`. Compare `manifest_sha256` with
`sudo sha256sum /var/backups/sli/native/<backup-id>/manifest.json` for that set.
An ordinary upgrade's `integrity_verified` receipt records the separate content
check level; successful candidate health and commit remain required.

After the update completes, check `sudo systemctl status sli.target sli-health.service`
and confirm the expected version in **System status**. For a new release, check
`status=committed` and `services_restored=true` in its transaction result. If
the update fails, record the reason code, check the `sli-upgrade-*` and
`sli-setup` journals and look for the result for that attempt.

```sh
sudo find /var/lib/sli/transactions -name result.json -printf '%T@ %p\n' | sort -nr | head
```

If the coordinator reports `resume-package`, run the printed
`sudo sli-native-upgrade resume-package <target-version>` after APT exits.
Read `target_version` in the transaction's `journal.json`. In a kit directory,
`dpkg-deb -f ./sli_*.deb Version` shows the version of the `sli` package. For an
APT update, `apt-cache policy sli` shows the candidate version.
Restarting the previous runtime and reconciling installed packages are separate
steps. After a rollback, reconciliation can require previous `.deb` versions
available to APT. If no transaction was created, fix the reported error and
retry using your original delivery path.

When upgrading an older installation, keep its retained ClickHouse data through
the rollback window. Before any cleanup, verify that the directory belongs to
SLI on the intended mounted volume and that a separate recovery copy contains
the needed ClickHouse history.

## Administration

Run `sudo sli-setup --web-console` to enable **Server console** on the **System status** page, then sign in with a Linux account that has sudo access.

## Security model

HTTPS protects operator and agent connections. The generated installation command
uses a short-lived registration key with a per-computer limit. Manual enrollment
uses an owner-approved key fingerprint and a single-use token. Agent requests
require mTLS and registry checks. Platform permissions and scope govern reports
and evidence.
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
| Agent installation | [Windows agent](#windows-agent) | [Агент Windows](README.ru.md#агент-windows) |

- [Contributing, checks and migrations](CONTRIBUTING.md)
- [Administrator guide](docs/ADMIN_GUIDE.md) and [user guide](docs/USER_GUIDE.md)

## License

SLI Platform and its agent are licensed under [Apache-2.0](LICENSE).
Separately licensed dependencies and Sigma content are listed in [NOTICE](NOTICE).
