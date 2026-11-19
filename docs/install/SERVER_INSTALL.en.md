# Server installation

[Русская версия](SERVER_INSTALL.ru.md) · [Agent installation](AGENT_INSTALL.en.md)

For the native Debian 13 beta, follow the [quick installation](../../README.md#quick-installation--first-beta-debian-13).

This guide is for an isolated evaluation on a Linux Docker host. Use Docker
Engine/Compose and the trusted SLI checkout or release. PostgreSQL 18 and
ClickHouse are required. [deploy/dev](../../deploy/dev/docker-compose.yml)
is only for development.

## How to obtain the delivery kit

Obtain the complete **signed, sealed offline kit** for the agreed version and
source SHA from the supplier's release channel.
An Actions `sli-unsigned-<SHA>` artifact still needs image building and offline
owner signing; it is not a ready buyer delivery.

Place the complete kit in `/release/kit`, outside `/srv/sli`, secrets and backups.
Obtain the external JSON trust store `/etc/sli/trust/release.json` and trusted
verification scripts/host-libs through a separate trusted channel. The kit's own
inventory cannot establish trust in those tools. Provision Docker/Compose and
system `python3` (Python ≥3.11) with glibc on the target Linux amd64 host beforehand.
Debian 13's Python 3.13 and Ubuntu 24.04's Python 3.12 are supported. The kit
bundles separate native libraries for CPython 3.11–3.14; host Python 3.14 is not required.
Compare the SHA-256 of `KIT_INVENTORY.json` with the supplier's value obtained
through a separate trusted channel: the inventory itself is unsigned.

```sh
sha256sum /release/kit/KIT_INVENTORY.json
export PYTHONPATH=/release/kit/host-libs/python$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'):/release/kit/source
export PYTHONDONTWRITEBYTECODE=1
python3 /release/kit/verify_offline_kit.py --kit /release/kit \
  --trust-store /etc/sli/trust/release.json
python3 - <<'PY'
from pathlib import Path
from server.sli.release_package import verify_package
verify_package(Path('/release/kit/packages/install.zip'), Path('/etc/sli/trust/release.json'))
print('signature_verified')
PY
```

Require exit code 0 from both checks. The first checks completeness and SHA-256
but reports `authenticated=false`; the second verifies the Ed25519 signature,
key policy and signed contents. For updates, also verify `packages/update.zip`.
Do not run the builder on the target. Installation checks the signature again;
follow the offline procedure.
The sections below describe an evaluation from a checkout.

## Unsigned offline evaluation kit

Without separate owner signing, `build_offline_kit.sh` produces an
**evaluation only, unsigned** kit (`signing: evaluation-unsigned` in inventory).
It contains three images, `packages/install.zip`, this guide and `START_HERE.md`.
Use it for a fresh isolated evaluation. It does not authenticate the supplier
and cannot update an existing installation.

1. Provision Linux amd64, Docker Engine/Compose and Python >=3.11 with glibc.
   Place the kit in `/release/kit`, outside runtime and secrets. Obtain the
   SHA-256 of `KIT_INVENTORY.json` through a separate trusted supplier channel.
   Compare it with `sha256sum /release/kit/KIT_INVENTORY.json` and replace
   `<EXPECTED_SHA256>` below with the expected 64 characters. A checksum
   supplied only inside the kit cannot establish trust.
2. Check the inventory and every file's SHA-256. Both verification modes report
   `authenticated=false`: SHA-256 checks integrity, not a supplier signature.

   ```sh
   export PYTHONPATH=/release/kit/host-libs/python$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'):/release/kit/source
   export PYTHONDONTWRITEBYTECODE=1
   python3 /release/kit/verify_offline_kit.py --kit /release/kit \
     --evaluation --inventory-sha256 <EXPECTED_SHA256>
   ```

   Continue only on exit 0 and `status=complete`. Without `--evaluation`, the
   verifier and installer reject unsigned kits. The flag does not bypass
   inventory, image, migration or TLS checks, or permit reusing existing data.
3. Prepare TLS using the [procedure below](#prepare-tls): an organization
   certificate or a local self-signed CA for evaluation. SANs must cover the
   client name/IP, DNS `api` and IP `127.0.0.1` used by `--health-url` below.
   Never print the private key. Choose new empty storage `/srv/sli-eval` with
   enough free capacity and a reachable trusted HTTPS endpoint. The Compose
   project is fixed to `sli`: its containers and volumes must not already exist.
   The installer creates secrets, backups and fresh volumes; do not create the
   volumes in the checkout startup section below beforehand.
4. After verification, load infrastructure images and run the installer from
   `source` as Linux root, using the prepared external TLS files. For access
   from another computer, explicitly set nonsecret `SLI_BIND_ADDRESS` and
   `SLI_HTTPS_PORT`; the default listener binds to loopback.

   ```sh
   docker load -i /release/kit/images/postgres.tar
   docker load -i /release/kit/images/clickhouse.tar
   cd /release/kit/source
   export SLI_INSTALL_DOMAIN=example.invalid
   export SLI_HEALTH_URL=https://api:8443/api/health/ready
   python3 deploy/linux/sli_install.py \
     --package /release/kit/packages/install.zip --kit /release/kit \
     --evaluation --inventory-sha256 <EXPECTED_SHA256> --runtime /srv/sli-eval \
     --compose deploy/linux/docker-compose.yml \
     --health-url https://127.0.0.1:8443/api/health/ready \
     --ca-file /etc/sli/tls/tls_ca --tls-certificate /etc/sli/tls/tls_certificate \
     --tls-key /etc/sli/tls/tls_key
   ```

   No build or network download is needed on the target. The installer checks
   the archive and server image before changing runtime, runs the migrator and
   checks health/HTTPS. On success, `state/installed.json` records
   `signing=evaluation-unsigned` and `authenticated=false`. Open
   `https://<client-name-or-IP>:8443/app` to verify the HTTPS endpoint.
   On `recovery_required`, preserve volumes and investigate the failure;
   retrying a fresh install automatically is refused.

For a signed delivery, follow the preceding external trust store procedure;
the owner signs separately offline. Evaluation opt-in does not permit unsigned
updates. The following sections describe startup from a checkout.

## Prepare TLS

After verifying the kit, run as root outside runtime and kit. Keep the selected
`PYTHONPATH` and `PYTHONDONTWRITEBYTECODE=1` from verification. Without an
organization certificate, the evaluation default is the built-in generation
of a local self-signed CA and a server certificate signed by it:

```sh
python3 /release/kit/source/deploy/linux/sli_secrets.py ensure \
  --directory /etc/sli/tls --tls-name example.invalid --tls-name api --tls-name 127.0.0.1
```

Replace `example.invalid` with the client-facing DNS name or IP; for access
using both, include both with `--tls-name`. The script creates protected
`tls_ca`, `tls_certificate`, `tls_key` and independent core secrets; the installer
imports only the three TLS files. Reruns preserve existing certificates:
changing `--tls-name` does not add SANs to an existing file. When changing the
address, use a new protected directory and retain the previous files.
Private keys and passwords are neither printed nor transferred to client PCs.

With an organization certificate, instead of generation put the trusted CA
chain, server certificate (including intermediate certificates) and matching
unencrypted PEM private key in a new protected directory:

```sh
install -d -m 0700 /etc/sli/tls
install -m 0600 /secure/input/ca.pem /etc/sli/tls/tls_ca
install -m 0600 /secure/input/server.pem /etc/sli/tls/tls_certificate
install -m 0600 /secure/input/server.key /etc/sli/tls/tls_key
```

Require DNS SAN `api`, IP SAN `127.0.0.1` and the client address SAN; IP addresses
must be IP SANs, not DNS SANs. The container healthcheck uses
`https://api:8443/api/health/ready`; the host installer uses
`https://127.0.0.1:8443/api/health/ready`. A different `--health-url` must match
a certificate SAN; do not disable TLS verification.

If system OpenSSL is available, check the public certificate without printing
the key (the installer always verifies TLS):

```sh
openssl x509 -in /etc/sli/tls/tls_certificate -noout -ext subjectAltName
openssl verify -CAfile /etc/sli/tls/tls_ca /etc/sli/tls/tls_certificate
```

For the self-signed CA, transfer **only the public** `/etc/sli/tls/tls_ca` to the
client PC through a trusted channel and import it into the OS/browser trusted
root certificate store (Windows: Install Certificate → Current User → Trusted
Root Certification Authorities). For an organization CA, confirm that its
chain is already trusted. After installation open
`https://<client-name-or-IP>:8443/app` (use `SLI_HTTPS_PORT` if changed);
the address must match a SAN.

## Prepare the host

1. Reserve persistent storage and capacity for the PostgreSQL, history and warm
   volumes, SLI filesystem evidence, a complete backup and a restore drill.
   Keep installation secrets and backups outside the checkout/build context.
2. Prepare protected secret files: `postgres_password`, `migration_password`,
   `runtime_password`, `semantic_password`,
   `storage_password`, `history_password`, `warm_password`, `tls_certificate`,
   `tls_key` and `tls_ca`, and the owner credential specified in the
   [Compose secret manifest](../../deploy/linux/secrets-manifest.json).
   Use independent generated passwords and choose at least 12 characters for the
   owner password. Follow the runbook's file
   permissions, container read-access and ClickHouse LF requirements.
3. Follow the TLS preparation procedure above for the chosen client-facing name and internal
   service name `api`, plus its trusted CA chain. In examples,
   `example.invalid` is a placeholder: replace it with your evaluation name.
   Restrict the published API listener and configure a proxy/firewall using the
   authentication and proxy guidance.
4. Prepare the backup directory and its shared-group permissions according to
   backup setup.
   Secrets must never appear in shell arguments, logs or deployment environment.

## Start a fresh evaluation

From the checkout root on the Linux host, set nonsecret settings. Create the
three external volumes below **only for a new, empty evaluation**. For existing
data, preserve/restore the volumes and SLI filesystem assets using the runbook;
do not replace them with empty volumes.

```sh
export SLI_SECRETS_DIR=/srv/sli/secrets
export SLI_BACKUP_DIR=/srv/sli/backups
export SLI_INSTALL_DOMAIN=example.invalid
export SLI_HEALTH_URL=https://api:8443/api/health/ready
export SLI_HISTORY_DATA_VOLUME=sli-eval-history
export SLI_HISTORY_BACKUPS_VOLUME=sli-eval-history-backups
export SLI_WARM_CLICKHOUSE_VOLUME=sli-eval-warm

docker volume create sli-eval-history
docker volume create sli-eval-history-backups
docker volume create sli-eval-warm
docker compose -p sli -f deploy/linux/docker-compose.yml up --build -d
docker compose -p sli -f deploy/linux/docker-compose.yml ps -a
docker compose -p sli -f deploy/linux/docker-compose.yml logs migrate
```

Use the same project, settings and Compose files for subsequent commands.
The API binds to loopback by default; explicitly choose `SLI_BIND_ADDRESS` and
`SLI_HTTPS_PORT` if remote access is needed. The migrator checks the baseline,
immutable SQL checksums and exact ledger before API/workers start. Do not edit
applied SQL or manually repair migration records.

## Verify and operate

Require `migrate` exit code 0 and healthy data/API/worker services. Check
`/api/health/ready` using the trusted HTTPS CA and configured endpoint, then
sign in as the platform owner using the prepared owner credential. Check safe
health/status information, without printing source records or secrets.

For new ClickHouse volumes, provision and verify the
[history schema](../../config/clickhouse/002_permanent_fact_history.sql) and the
warm-tier schema required by the selected release through its reviewed storage
setup. Container health alone does not establish schema or history readiness.

Collection is disabled initially. Enroll agents and explicitly enable approved
plugins/modules separately. Delete and warm-copy admission remain closed.
ClickHouse is mandatory; unavailable history must not be treated as no activity.
Confirm a complete backup set and a restore drill before relying on recovery;
service startup alone is not installation acceptance.

Updates require a signed package, a trusted host updater, an external trust
store and a verified installed inventory. Preserve the journal/checkpoint for resume or rollback. For moving
an existing database, follow restore guidance.
For a planned evaluation stop, use `docker compose -p sli -f deploy/linux/docker-compose.yml stop`;
retain all volumes, backups and evidence.
