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
6. Use the **.NET agent**, service `SLIAgentNet`. The manual
   [agent-msi workflow](.github/workflows/agent-msi.yml) builds the ready unsigned
   MSI. Download `sli-agent-dotnet-msi-<full-commit>` from a successful run's
   **Artifacts** (retained for 14 days), or obtain the same kit from the beta provider.
   It contains `SliAgent.msi`, `SliAgent-publish-win-x64.zip` and `SHA256SUMS`.
   Verify both files against the trusted checksums; unpack the portable ZIP as
   `publish`, with `SliAgent.exe` directly inside. No public release download is configured.
   To build the matching kit yourself on Windows, use PowerShell 7,
   .NET SDK **10.0.113**, MSVC Build Tools **14.44.35207** and Windows SDK
   **10.0.26100.0** installed at the defaults in
   [Build-RegistrationCA.ps1](agent-dotnet/tools/Build-RegistrationCA.ps1).
   From the repository root (restore requires access to the package sources):

   ```powershell
   .\agent-dotnet\tools\Build-Msi.ps1
   .\agent-dotnet\tools\Test-MsiTables.ps1 -Msi .\artifacts\agent-dotnet\SliAgent.msi -PublishDirectory .\artifacts\agent-dotnet\publish
   Get-FileHash .\artifacts\agent-dotnet\SliAgent.msi -Algorithm SHA256
   ```

   The MSI is self-contained win-x64; the target needs no installed .NET runtime.
   It is unsigned; verify its SHA256 through the trusted delivery channel.
   On the **one target Windows computer**, use elevated PowerShell, with transcripts off:

   ```powershell
   $ErrorActionPreference = 'Stop'
   New-Item -ItemType Directory -Force C:\SLI-Bootstrap | Out-Null
   icacls.exe C:\SLI-Bootstrap /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
   if ($LASTEXITCODE -ne 0) { throw 'Cannot protect bootstrap directory' }
   ```

   Copy `SliAgent.msi`, the complete `publish` directory and the server's
   **public** `tls-ca.crt` into `C:\SLI-Bootstrap` through a trusted channel.
   Verify the copied CA against the setup fingerprint, then prepare the identity
   **on this target**, before installation:

   ```powershell
   $ca = [Security.Cryptography.X509Certificates.X509Certificate2]::new('C:\SLI-Bootstrap\tls-ca.crt')
   $sha = [Security.Cryptography.SHA256]::Create()
   ([BitConverter]::ToString($sha.ComputeHash($ca.RawData))).Replace('-', '').ToLowerInvariant()
   $sha.Dispose()
   $ca.Dispose()
   & C:\SLI-Bootstrap\publish\SliAgent.exe prepare
   ```

   Compare the printed CA hash with the SHA256 (DER) from step 5; stop on mismatch.
   `prepare` prints public `host_id` (UUID) and `key_fingerprint`; it keeps the key
   in `%ProgramData%\SLI\AgentNet\state`, shared with the future service. Do not
   run it on the build computer or copy a private identity between computers.
   As `platform-owner`, open **Agents → Manual registration for support → New agent enrollment**,
   enter those two public values and click **Create enrollment token** (default
   TTL 900 seconds). Leave the optional replacement name empty for this new agent.
   On the target, paste the token into the hidden prompt below within its TTL:

   ```powershell
   $token = Read-Host 'Enrollment token' -AsSecureString
   try {
       [IO.File]::WriteAllText('C:\SLI-Bootstrap\enrollment.token',
           [Net.NetworkCredential]::new('', $token).Password, [Text.Encoding]::ASCII)
   } finally { $token.Dispose(); Remove-Variable token }
   $msi = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
       '/i', 'C:\SLI-Bootstrap\SliAgent.msi', '/qn', '/norestart',
       'SERVER_URL=https://sli.example.test',
       'CA_FILE=C:\SLI-Bootstrap\tls-ca.crt',
       'TOKEN_FILE=C:\SLI-Bootstrap\enrollment.token'
   )
   if ($msi.ExitCode -notin 0, 3010) { throw "MSI exit code: $($msi.ExitCode)" }
   Get-Service SLIAgentNet
   ```

   Replace `SERVER_URL` with the HTTPS origin from setup (no `/app` or API path).
   MSI starts the service; it enrolls automatically and deletes the token file
   after saving its identity. Subsequent check-ins and delivery use mTLS.
   Supported connection properties are `SERVER_URL`, `TOKEN_FILE` or `ENROLL_TOKEN`,
   `CA_FILE` or `CA_FINGERPRINT` (the CA SHA256 DER, 64 hex), and optional
   `INSTANCE_NAME` (`[a-z0-9][a-z0-9_-]{0,47}`, must match the token).
   Omit `INSTANCE_NAME` for this single manual enrollment. `ENROLL_TOKEN` is
   supported but exposes the token to process-command-line recording; use the
   protected `TOKEN_FILE`. Keep `CA_FILE` in place: it remains the service's trust
   source. The program installs to `%ProgramFiles%\SLI\AgentNet`.
7. In **Agents**, find this host's row and a fresh **Last seen** time (heartbeat).
   In **Actions**, assign **Workstations** (`sli.workstations`) for a workstation,
   choose the required event categories and resume collection if paused. For a DC,
   use `sli.windows.ad-dc` and its permitted channels. Wait for matching desired
   and applied policy revisions and acknowledged active collection in the row.
   Ensure Windows auditing is enabled and the service can read the source;
   generate an authorized test logon event. Open **Event journal** for that interval
   and check your host's event. Heartbeat confirms connectivity; the received event
   confirms collection. If missing, inspect channel/delivery diagnostics in the row
   and Windows **Application** log, source `SLIAgentNet` (safe diagnostic codes).

8. To upgrade, run the higher-version MSI from elevated PowerShell:

   ```powershell
   msiexec.exe /i "C:\SLI-Bootstrap\update\SliAgent.msi" /qn /norestart
   ```

   Major upgrades keep the registration, certificate, pending packets and cursors.
   Do not supply another enrollment token. Downgrades are rejected.

   To uninstall, use **Installed apps → SLI Agent .NET**, or elevated PowerShell
   with the original matching MSI:

   ```powershell
   $remove = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
       '/x', 'C:\SLI-Bootstrap\SliAgent.msi', '/qn', '/norestart'
   )
   if ($remove.ExitCode -notin 0, 3010) { throw "MSI exit code: $($remove.ExitCode)" }
   ```

   MSI stops and removes `SLIAgentNet`; connection settings and the local identity
   remain for reinstallation. Exit code 3010 requires a reboot.

Operators and mTLS agents share HTTPS port **443**, so agents need no additional
open port. Include a custom port in the MSI URL when applicable. Check
`sudo systemctl status sli.target sli-health.service`, reboot, then verify login
again. Setup errors explain the next action; diagnostic codes go to
`sudo journalctl -t sli-setup`. Use `systemctl --failed` to inspect failed units.

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
