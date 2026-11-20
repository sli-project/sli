"""Build the PostgreSQL baseline for clean installs (plan 6.6).

The baseline is a dump of a database that went through the full fresh-install
sequence (``postgres_schema_v8.sql``, ``storage_v2_roles.sql`` and every
forward migration, see ``existing_postgres_bootstrap.apply_schema_sequence``)
on a disposable PostgreSQL 18. A clean install then restores one file instead
of replaying 130+ migrations and applies only migrations newer than the
baseline. Existing installations keep upgrading through the migrations.

Install-specific data is not part of the baseline: the platform owner
(``auth_users``, ``access_platform_owners``) is created by the bootstrap. The
report domain the migrations were written for is replaced with the
``__SLI_REPORT_DOMAIN__`` placeholder, which the bootstrap substitutes with
the installation's validated DNS domain.

Usage (password of the disposable cluster on stdin)::

    python scripts/maintenance/build_postgres_baseline.py --host 127.0.0.1 \
        --port 55441 --database sli_fresh --domain <domain used for the build> \
        --bin-dir "D:\\PostgreSQL\\18\\bin" < password.txt
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.existing_postgres_bootstrap import (  # noqa: E402
    forward_migration_inventory,
    normalized_sha256,
)

BASELINE_DIR = ROOT / "config" / "postgres_baseline"
MIGRATIONS_DIR = ROOT / "config" / "postgres_migrations"
DOMAIN_PLACEHOLDER = "__SLI_REPORT_DOMAIN__"
INSTALL_SPECIFIC_TABLES = ("public.auth_users", "public.access_platform_owners")
# Roles created before the baseline runs: the bootstrap superuser and the
# runtime login role made by ``create_target_database``.
PRECREATED_ROLES = ("postgres", "adlog_user")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_VOLATILE_LINE = re.compile(r"^(\\restrict |\\unrestrict |-- Dumped (from|by) )")


def _dump(binary: Path, args: list[str], password: str) -> str:
    environment = dict(os.environ, PGPASSWORD=password, PGCLIENTENCODING="UTF8")
    result = subprocess.run(
        [str(binary), *args], capture_output=True, env=environment, check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"{binary.name} failed with exit code {result.returncode}")
    # Windows pg_dump writes CRLF, and bodies of functions created from CRLF
    # migration files add one more CR: fold both so the baseline is plain LF.
    text = result.stdout.decode("utf-8")
    while "\r\n" in text:
        text = text.replace("\r\n", "\n")
    return text


def _stable(text: str) -> str:
    return "".join(line for line in text.splitlines(keepends=True) if not _VOLATILE_LINE.match(line))


def roles_sql(dumpall_output: str) -> str:
    """Cluster roles the migrations create, without passwords or pre-created roles."""
    kept = []
    for line in _stable(dumpall_output).splitlines(keepends=True):
        if line.startswith("CREATE ROLE ") and line[len("CREATE ROLE "):].strip().rstrip(";") in PRECREATED_ROLES:
            continue
        if line.startswith("ALTER ROLE postgres ") or line.startswith("SET default_transaction_read_only"):
            continue
        kept.append(line)
    return "".join(kept)


def reset_install_specific_sequences(text: str) -> str:
    """The excluded rows' id sequences start over, as in a migrated install."""
    for table in INSTALL_SPECIFIC_TABLES:
        sequence = re.escape(f"{table}_id_seq")
        text = re.sub(
            rf"SELECT pg_catalog\.setval\('{sequence}', \d+, (true|false)\);",
            f"SELECT pg_catalog.setval('{table}_id_seq', 1, false);",
            text,
        )
    return text


def replace_domain(text: str, domain: str) -> str:
    replaced = re.sub(re.escape(domain), DOMAIN_PLACEHOLDER, text, flags=re.IGNORECASE)
    label = domain.split(".", 1)[0]
    if re.search(r"(?<![a-z0-9])" + re.escape(label) + r"(?![a-z0-9])", replaced, re.IGNORECASE):
        raise SystemExit("domain label remains in the dump outside the full domain name")
    return replaced


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--domain", required=True, help="domain the disposable database was seeded with")
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, default=BASELINE_DIR)
    args = parser.parse_args(argv)
    domain = args.domain.strip().lower()
    if not all(_DNS_LABEL.match(label) for label in domain.split(".")) or "." not in domain:
        raise SystemExit("--domain must be a DNS name")
    password = sys.stdin.readline().rstrip("\r\n")
    connection = ["--host", args.host, "--port", str(args.port), "--username", "postgres"]

    migrations = forward_migration_inventory(MIGRATIONS_DIR)
    roles = roles_sql(_dump(args.bin_dir / "pg_dumpall.exe", [*connection, "--roles-only", "--no-role-passwords"], password))
    excluded = [f"--exclude-table-data={table}" for table in INSTALL_SPECIFIC_TABLES]
    database = _stable(_dump(args.bin_dir / "pg_dump.exe", [*connection, "--dbname", args.database, *excluded], password))
    database = replace_domain(reset_install_specific_sequences(database), domain)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    files = {"roles.sql": roles, "baseline.sql": database}
    for name, text in files.items():
        (args.out_dir / name).write_text(text, encoding="utf-8", newline="\n")
    manifest = {
        "contract_version": 1,
        "baseline_version": max(item.version for item in migrations),
        "domain_placeholder": DOMAIN_PLACEHOLDER,
        "install_specific_tables": list(INSTALL_SPECIFIC_TABLES),
        "files": {name: normalized_sha256(args.out_dir / name) for name in files},
        "migrations": {str(item.version): normalized_sha256(item.path) for item in migrations},
    }
    (args.out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"baseline_version={manifest['baseline_version']} migrations={len(migrations)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
