# Contributing

Make one scoped change, use synthetic fixtures and run the smallest sufficient
checks. Keep the English and Russian installation guides in sync. Do not create
navigation `README.md` files in subdirectories.

## Dev container workflow

Use [deploy/dev](deploy/dev/docker-compose.yml), separately from
[deploy/linux](deploy/linux/docker-compose.yml), the runtime deployment.
Docker and Compose run on the host; Linux checks use the non-root `dev` user,
Python at `/opt/venv/bin/python`, Node 22 and dependency volumes. Git and
authenticated tools stay on the host.

Set `SLI_DEV_SOURCE` to the absolute path of the checkout being checked. Once
the development image and dependency volumes are prepared, run one check
container at a time. For example, from the host checkout root in PowerShell:

```powershell
$env:SLI_DEV_SOURCE = (Get-Location).Path.Replace('\', '/')
docker compose -p sli-dev -f deploy/dev/docker-compose.yml run --rm --no-deps -T -e SLI_TEST_PYTHON=/opt/venv/bin/python dev bash -lc 'cd /workspace/sli-platform && /opt/venv/bin/python -m ruff check --config .github/ruff-ci.toml tests/unit/test_dev_container.py'
```

Replace the final command with the check for your change. `--no-deps` avoids
starting a database for unit tests. Python unit tests use fakes, not a real DB.
Integration tests require the explicitly configured disposable `pg-test` service;
never supply a production DSN. See [server installation](docs/install/SERVER_INSTALL.en.md)
for operator deployment instead of using the development stack as a server.

## Checks

Run focused checks locally. Before merge, GitHub Actions must pass the required
checks for every affected area.

| Change | Required checks before merge |
| --- | --- |
| Documentation, comments, typos | Markdown lint if configured |
| Isolated UI or styles | `npm --prefix frontend run lint` and targeted Vitest component tests |
| Linux installer | Targeted installer checks for the affected installation or update paths |
| .NET module | Build the .NET solution and run the affected module's tests |
| Authorization, mTLS or permissions | Targeted security and contract tests for allowed and denied operations |
| Database schema, storage or recovery | Targeted migration, storage or recovery tests on an authorized disposable database |
| Shared dependencies, CI or unclear scope | Broad CI profile |
| Release preparation | Install the release bundle on clean Debian 13 and verify an update to that bundle |

Full suites run nightly and on manual dispatch. Record the local commands,
results and anything still unverified.

### Test rules

1. Test observable behavior or data integrity when adding logic.
2. Add a regression test for a bug fix if existing tests do not cover the failure.
3. Run existing tests for a refactor that preserves behavior.
4. Documentation-only changes require no new tests.
5. Explain why any checks beyond the affected area are needed.
6. Avoid assertions on source text, migration numbers, or counts of migrations,
   keys or list items. Security tests may assert these details where required.

## PostgreSQL migrations

- Add SQL in [config/postgres_migrations](config/postgres_migrations/).
  Choose the next free number after the current maximum; new migrations must
  form a strict sequential chain, with no gaps or duplicate IDs.
- Declare and verify the exact predecessor, not merely a lower version or an
  assumed maximum. Coordinate numbering if another change takes the next ID.
- Never edit, rename or delete published/applied migrations, rollback files,
  or test reference checksums. Correct them with a new additive migration.
- Include the required rollback and targeted migration/contract tests.
  Use the standard executor and ledger readback; never repair the ledger manually.
- Keep DDL in the migration path, outside runtime/plugin handlers. Preserve
  bounded roles, ownership and source-data safety.

## Pull requests and commit attribution

Open pull requests from your fork. A maintainer must review and approve CI runs
from external contributors. CI uses GitHub-hosted runners and a read-only token
for fork pull requests. Keep credentials out of your changes and report security
issues privately as described in the [security policy](SECURITY.md).

Follow the [pull request template](.github/PULL_REQUEST_TEMPLATE.md). Keep a PR
focused on one coherent change. Describe the problem, resulting behavior, scope,
risk and exact verification results. Update affected documentation and follow the
[test rules](#test-rules). User-visible changes belong in [CHANGELOG.md](CHANGELOG.md).
Pass the [required checks for the affected areas](#checks) before merging. Do not
push directly to main or rewrite reviewed history without authorization.

Include `Co-authored-by` trailers only for actual contributors using attribution
they have approved. Do not put personal data or credentials in documentation
examples or test fixtures.

## Data, localization and license

Surveyed AD, GPO, DC, VPN and workstation sources are read-only and bounded;
development work does not authorize contacting them. Keep secrets, private
directory data, real names, domains, hosts, IP addresses and runtime artifacts
out of commits and logs. Use `example.invalid` in examples. New UI strings go
through [ru.ts](frontend/src/i18n/ru.ts) and [en.ts](frontend/src/i18n/en.ts), with
identical keys under the relevant `// pages:<area>` marker.

Keep platform versions aligned in the root/frontend package manifests and lock
files; see [version consistency](tests/tooling/test_version_consistency.py).
Contributions are licensed under [Apache-2.0](LICENSE). See the
[code of conduct](CODE_OF_CONDUCT.md) and [security policy](SECURITY.md).
