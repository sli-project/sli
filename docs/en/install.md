# Server installation and first sign-in

[Русская версия](../ru/install.md) · [Guide index](README.md)

Start with the [beta archive](#install-from-the-archive). Use a clean
**Debian 13 amd64** host with sudo and access to its configured APT sources.
Plan for 4 cores and 8 GB RAM. Setup requires **20 GiB free** on a local,
writable ext4 or XFS data volume after package installation. PostgreSQL needs
local port 5432 free on IPv4 and IPv6. Check for listeners with
`sudo ss -ltn 'sport = :5432'`. If that port is in use, install on a clean host
and leave the existing database intact. Allow inbound HTTPS on port 443 or the
port printed by setup.

## Install from the archive

Use a published beta release with both download files. Download into an empty
directory you control. Leave space for the download, the unpacked kit and a
temporary copy of the kit under `/tmp`. Have `curl`, `sha256sum` and `tar`
available on the Debian host.

### Download and verify the archive

Copy the `beta-…` tag from the pre-release in
[Releases](https://github.com/sli-project/sli/releases) and replace
`beta-COMMIT12` in the command below. The release notes link to the GitHub
Actions run and identify its source commit. Run the command from the download
directory to fetch both files from that release and verify the archive before
extracting it.

```sh
tag=beta-COMMIT12
curl -LO --fail "https://github.com/sli-project/sli/releases/download/$tag/sli-debian-beta-kit.tar.gz" &&
curl -LO --fail "https://github.com/sli-project/sli/releases/download/$tag/SHA256SUMS" &&
sha256sum --check --strict SHA256SUMS && tar -xzf sli-debian-beta-kit.tar.gz
```

For a kit supplied through GitHub Actions, open the **Debian beta kit** run for
the intended source commit. Download and unpack its
`sli-debian-beta-kit-<full-commit-sha>` artifact, if the run uploaded one. In
the directory containing both files from that artifact, run:

```sh
sha256sum --check --strict SHA256SUMS && tar -xzf sli-debian-beta-kit.tar.gz
```

### Run the installer

Run the installer from the directory where you unpacked the archive.

```sh
bash sli-debian-beta-kit/install-beta-kit
```

The script checks the unpacked manifest, scripts and `.deb` files against the
kit's own `SHA256SUMS`, refreshes the configured APT sources and installs the
packages. It keeps newer installed vendor packages and prevents PostgreSQL
from creating a default cluster. Setup selects the address, port and disk
automatically unless you pass the options below.

## First sign-in

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
[connect the domain controller](agents.md).

## Optional setup settings

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
For a local reverse proxy, pass a loopback address with `--bind` and configure
trusted proxies.
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

## Install from the APT repository

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

Install the packages and run first-time setup.

```sh
sudo apt update && sudo apt install sli && sudo sli-setup
```

### Update with APT

```sh
sudo apt update && sudo apt upgrade
```

For rollback, use the [recovery guide](upgrade.md#roll-back-an-upgrade).
Check that APT has the exact previous package versions or keep the verified
archive for that release.
