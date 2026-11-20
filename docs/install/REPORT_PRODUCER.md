# Scheduled report producer: deployment status

The product deployment target is a clean Debian installation using `.deb`
packages, systemd and `apt install/upgrade`. On a native installation, `sli-dotnet-report-producer.service` is enabled
through `sli-dotnet.target`. It runs the .NET `Sli.Server report-producer` command
as `sli-report`, with a three-second cycle, a dedicated database login and only
its own password credential. Install/upgrade provisions that login and binds its
OID/name in `report_producer_principals`; service inventory and rollback include
the producer. The producer core remains deployment-neutral.

The historical Compose overlay remains inactive. It is
not the target production deployment or an endorsed activation path. Docker
feature work is frozen; only defects blocking updates of the current stand may
be fixed until its transfer. No further Compose feature expansion is planned.

The historical overlay describes a source-only proposal for T015. Adding that
overlay does not activate a Compose service or provision a Compose LOGIN,
password file or principal binding. The default Compose file and native
installation/provisioning hooks do not include this overlay. Native service
integration is independent of it.

The producer releases only the latest due saved schedule slot, computes a
bounded aggregate and publishes an immutable run plus durable notification
jobs. The existing isolated notification worker remains responsible for SMTP
and Telegram. This is not an API background loop or another task framework.

## Historical Compose service and image proposal

`deploy/linux/docker-compose.report-producer.json` is an optional Compose
overlay, expressed as JSON (valid Compose/YAML). Its `report-producer` service
has the additional `report-producer` profile. It invokes
`python -m server.sli.core.report_schedule_producer` directly, bypassing the API
entrypoint and its credential/configuration bootstrap. The existing runtime
image includes this module through `COPY server/ server/` and `!server/**`.
No image, dependencies or external service was built or installed here.

The service runs as UID/GID 10001, with a read-only root filesystem, dropped
capabilities, no-new-privileges, bounded CPU/memory/processes and only `/tmp`
writable. It has no host ports, Docker socket, data volume, plugin mounts,
history access or notification-secret directory. It does not inherit the
shared `x-runtime` definition, API DSN, delivery DSN or their secrets.

## Identity and secret reference

| Reference | Value |
| --- | --- |
| Native runtime LOGIN | `sli_report_producer_login` (provisioned by native install/upgrade) |
| Privilege role | `adlog_report_producer`, NOLOGIN |
| Logical secret reference in code | `postgres/report-producer` |
| Container DSN | `SLI_REPORT_PRODUCER_PG_DSN=host=postgres port=5432 dbname=sli user=sli_report_producer_login` |
| Container password file | `SLI_REPORT_PRODUCER_PG_PASSWORD_FILE=/run/secrets/report_producer_password` |
| Host file reference | `SLI_REPORT_PRODUCER_PASSWORD_SOURCE`, separately approved absolute path |

Native provisioning declares `report_producer_password` in the core-secret
manifest. Systemd delivers it only to `sli-dotnet-report-producer.service` with
`LoadCredential`; the service uses `%d/report_producer_password` and the local
PostgreSQL DSN for `sli_report_producer_login`. Other application services do not
receive this credential. Do not substitute an API, delivery, owner or migration
credential.

The historical overlay instead references a separately supplied host file and
mounts it as the `report_producer_password` container secret. It does not
generate that file or consume the native systemd credential.

The historical Python entry module requires both its explicit DSN and its explicit password-file
path. It reads at most 4097 bytes, rejects empty/oversize/NUL/multiline/invalid
UTF-8 contents, and passes the password explicitly to the PostgreSQL driver.
It does not fall back to API configuration, `PGPASSWORD` or a default libpq
password file. Connection failures return a fixed process failure without
printing DSNs, paths, passwords or database exception text.

Migration `285_report_producer.sql` defines the NOLOGIN roles and fixed APIs.
Native install/upgrade separately creates the LOGIN and binds its OID/name in
`report_producer_principals`. The LOGIN must have only the producer membership
and the fixed functions must accept its actual `session_user`. Broad API,
delivery, source-owner and all-data memberships are rejected by the gate.

## Historical Compose network and startup declaration

The overlay explicitly retains PostgreSQL's existing `default` network and
adds an internal `report-db` network. Only PostgreSQL and the producer are
attached to `report-db`; the producer is not attached to `default`. No API,
ClickHouse, SMTP or Telegram service is added to its network. Database traffic
targets PostgreSQL on port 5432. This is a Compose network boundary, not a claim
of a separately verified host firewall or TLS configuration. The existing
database authentication settings are unchanged.

The historical overlay declared dependencies on PostgreSQL health and
completion of the existing migration service. Its recorded command path was:

```sh
docker compose -f deploy/linux/docker-compose.yml \
  -f deploy/linux/docker-compose.report-producer.json \
  --profile report-producer up -d report-producer
```

This command has not been run and is retained only as historical reference,
not as native deployment instructions. It can start dependencies and apply
pending migrations; it is not a source-validation command or permission to
activate this candidate. The normal default Compose invocation does not select
this overlay/profile.

## Bounds, health and evidence limits

The historical Python process uses a 20-second cycle, batch of two, explicit two-second reads
(ten seconds for bounded claiming), 500-ms locks and 30-second leader/claim
leases. Shutdown is interruptible and the declaration allows 30 seconds to
stop. The historical overlay proposed container restart retries for failed
cycles. The native .NET service uses a three-second cycle and systemd
`Restart=on-failure`; its heartbeat is `/run/sli/report-producer/heartbeat.json`.
Historical Python health invokes the same module with `--health`; it reads only the local
pid/time/state file in `/tmp`, without a password read or database/network call.
Healthy state is not evidence of mail acceptance or report completeness.

Source tests cover the historical declaration, exclusive native credential
delivery, generated systemd units, explicit credential loading and value-free
health. The disposable CI migration/role/lifecycle cases remain in
`tests/migrations/test_report_producer_migration285.py`; both transports are
spies. No Compose daemon/network/service, migration or credential operation was
executed by these source checks. They do not establish installed runtime
acceptance, Compose runtime isolation or actual notification delivery.

Full T015 is still incomplete: open/new digest semantics, quiet hours,
importance acceptance and RU/EN screenshots remain unresolved.

The default published `security.queue` definition and `security.problems` dataset
do not authorize export. Consequently, security digests withhold the numerical
count by default, even when a participant has an export assignment and the
`reports.export` capability. Both published action lists and every participant's
effective permissions must authorize export before a digest can include counts.
An export-enabled synthetic CI policy does not change that production limit;
the default numerical security summary is not implemented by this candidate.

The proposed persisted three-alert/one-report fair share is operational policy, not an
accepted delivery-time guarantee. When both classes stay eligible, neither
monopolizes claims; report-only claims reset the streak so a newly arriving
alert is preferred next. Independent review precedes any publication.
