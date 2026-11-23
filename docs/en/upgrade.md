# Update, backups, rollback and restore

[Русская версия](../ru/upgrade.md) · [Guide index](README.md)

## Upgrade

Public beta kits start a separate migration checksum lineage. Use a clean
installation for a database from the private lineage. For an installed public
beta, use the same delivery path as before. For APT, use the
[APT update command](install.md#update-with-apt). For an archive installation,
[download and verify the new kit](install.md#download-and-verify-the-archive).
Run the installer from the unpacked directory containing the `.deb` files,
`SHA256SUMS` and `install-beta-kit`.

```sh
bash ./install-beta-kit
```

The archive helper runs `sli-setup` after APT. Wait for both to succeed. The archive
installation does not add an SLI APT source.
The package hooks run preflight checks, create a complete recovery checkpoint and
verify its manifests, hashes and consistency before migrations, then migrate,
start the services and check their health. New transactions record the integrity
check. Run full restore drills separately. Transactions prepared by an older
coordinator keep their original full-restore requirement when resumed.
If preparation fails before the checkpoint is verified, SLI automatically restarts
the previous release and reports any restart failure.

Follow the `sli-upgrade-*` service journal with `sudo journalctl -u 'sli-upgrade-*'`.

### Check free space

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

The `integrity_verified` receipt records the upgrade's content check. The
upgrade also requires a successful health check and commit.

### Verify or resume the update

After the update completes, check `sudo systemctl status sli.target sli-health.service`
and confirm the expected version in **System status**. For a new release, check
`status=committed` and `services_restored=true` in its transaction result. If
the update fails, record the reason code, check the `sli-upgrade-*` and
`sli-setup` journals and look for the result for that attempt.

```sh
sudo find /var/lib/sli/transactions -name result.json -printf '%T@ %p\n' | sort -nr | head
```

Wait for APT to exit before resuming a transaction or reconciling packages.
Use the target version from the installer's printed recovery command and
confirm it against `target_version` in that transaction's `journal.json`. In a
kit directory, `dpkg-deb -f ./sli_*.deb Version` shows the version of the `sli`
package. For an APT update, `apt-cache policy sli` shows the candidate version.

- If the transaction is unfinished and the coordinator reports
  `resume-package`, run the printed
  `sudo sli-native-upgrade resume-package <target-version>`.
- If `journal.json` records `status=rolled_back`, `step=after` and
  `services_restored=true` and `result.json` reports
  `package_reconciliation_required=true`, run
  `sudo sli-native-upgrade reconcile <target-version>`. Reconciliation
  requires the exact previous versions of `sli`, `sli-host` and
  `sli-rollback-hold` from configured APT sources. Keep the verified
  previous kit so you have those exact package files if needed. If those
  versions are unavailable to APT, package reconciliation remains pending.
- If no transaction was created, fix the reported error and retry using your
  original delivery path.

After reconciliation, check that both files have the same `transaction`,
`status=rolled_back` and the expected previous `accepted_release`. In
`journal.json`, verify `step=after` and `services_restored=true`. In
`result.json`, confirm `terminal=true` and `package_reconciliation_required=false`.
Check service health and the restored version in **System status** as above.

When upgrading an older installation, keep its retained ClickHouse data through
the rollback window. Before any cleanup, verify that the directory belongs to
SLI on the intended mounted volume and that a separate recovery copy contains
the needed ClickHouse history.

## Native backups

Check the daily timer, then take the first backup and read its result.

```sh
sudo systemctl list-timers sli-backup.timer
sudo sli-backup && sudo cat /var/backups/sli/native/last-result.json
```

The command prints the completed set's directory. Match its name to `backup_id`
with `status=backup_created` and `terminal=true`. Keep older verified sets until
the new set passes a [restore drill](#run-a-restore-drill). Without an external backup volume,
directory mode allows local backups under `/var/backups/sli/native`. With an
external volume, SLI mounts it at `/var/backups/sli`. Check the [space requirements](#check-free-space)
on the filesystem that actually holds the backups.

### Run a restore drill

For a restore drill, take at least one successful backup first. The backup and
workspace (by default `/var/backups/sli/restore-check`) must be on filesystems
separate from the live database. Note the latest set's `backup_id`, then start
the drill and follow its journal.

```bash
sudo systemctl start sli-backup-drill.service
sudo journalctl -u sli-backup-drill.service -f
```

This operation starts an isolated PostgreSQL instance and requires an
additional **2B + 1.2P + 10 GiB** beyond the saved set. For this check, B is the
measured size of the selected set and P is the PostgreSQL size recorded in its
manifest. With separate volumes, allow B on the backup volume and the remaining
space in the workspace. Add both requirements if the backup and workspace share
one filesystem. After the run finishes, read
`sudo cat /var/backups/sli/native/drill-result.json`. Check the expected
`backup_id`, a `completed_at_utc` from this run, `status=restore_verified`,
`terminal=true` and `databases_stopped=true`. Compare `manifest_sha256` with
`sudo sha256sum /var/backups/sli/native/<backup-id>/manifest.json` for that set.

## Restore and rollback

### Restore a backup

Use `sudo sli-restore <backup-directory>` to restore data and settings with the
exact Debian kit that created the set. Keep the set and every entry owned by
root and inaccessible to other users. Use regular files with no additional hard
links and directories with no symlinks. Retry an unfinished restore with the
same set.

On a clean replacement server, [verify and unpack the exact archive](install.md#download-and-verify-the-archive).
Stage only the packages from the unpacked kit directory.

```sh
sha256sum --check --strict SHA256SUMS && sudo apt-get update && sudo apt-get install --no-remove ./*.deb
```

Copy the complete backup directory, including `manifest.json`, to the replacement
server with the ownership and permissions above. Run `sudo sli-restore <backup-directory>` on that copy.
On the replacement server, let `sli-restore` initialize the installation.
Restore uses directory mode, local backups and the default PostgreSQL tablespace.
Keep the original DNS name or IP for existing agent certificates. If the set
uses saved AD credentials, provision their original protected key on the new
server before restoring.

### Roll back an upgrade

Before an upgrade, keep the previous verified kit and retain the backup the
upgrade takes. After a completed upgrade, `sudo sli-rollback <previous-kit-directory>`
uses that checkpoint and the previous runtime. Without a kit directory,
`sudo sli-rollback` needs the exact previous versions of `sli`, `sli-host`,
`sli-rollback-hold` and `sli-server-dotnet` from APT. For a failed upgrade use
the [upgrade recovery procedure](#verify-or-resume-the-update).

### Check the recovery result

Before replacing existing data, both commands save it under
`/var/backups/sli/native/before-restore/<transaction-id>/<backup-id>`.
Read `/var/lib/sli/transactions/<transaction-id>/result.json`. Success is
`status=committed` for restore or `status=rolled_back` for rollback, with
`services_restored=true` in either case.

## Reinstallation with retained data

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
the [restore drill](#run-a-restore-drill) separately. Existing passwords,
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

## Uninstall

`sudo sli-remove` stops SLI and removes its packages and systemd units. It
retains databases, configuration, keys and recovery files. On an older
installation without `sli-remove`, run `sudo ./remove-beta-kit`
from inside the unpacked, verified current kit.

To erase local SLI data as well, run `sudo sli-remove --purge-data` or
`sudo ./remove-beta-kit --purge-data` for the older installation.
Verify that the intended database and cold-storage volumes are mounted first.
The flag erases local databases, settings, keys, the offline CA on this host,
local backups and the managed cold tablespace directory. It keeps shared Debian
and database packages, external backup volumes and copies stored offline.

Verify the result of a Windows agent removal in the [agent guide](agents.md#remove-the-agent).

For development, use the separate [dev container workflow](../../CONTRIBUTING.md).
