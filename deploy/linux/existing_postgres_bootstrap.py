"""PostgreSQL migration inventory, verified baseline and owner bootstrap for Debian."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from deploy.linux.release_package import MIGRATION_MARKER as _MARKER


_FORWARD_NAME = re.compile(r"^(\d{3})_([a-z0-9_]+)\.sql$")
_ROLLBACK_NAME = re.compile(r"(?:\.|_)rollback\.sql$")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_BASE_MARKER_BLOCK = re.compile(
    r"insert\s+into\s+(?:public\.)?schema_migrations\s*"
    r"\(\s*version\s*,\s*name\s*\)\s*values(?P<body>.*?)"
    r"on\s+conflict\s*\(\s*version\s*\)",
    re.IGNORECASE | re.DOTALL,
)
_MARKER_TUPLE = re.compile(r"\(\s*(\d+)\s*,\s*'([^']+)'\s*\)")


class BootstrapError(RuntimeError):
    """Expose only fixed diagnostic codes at the command boundary."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path
    sha256: str


def forward_migration_inventory(root: Path) -> tuple[Migration, ...]:
    migrations: list[Migration] = []
    for path in sorted(root.glob("*.sql"), key=lambda item: item.name):
        if _ROLLBACK_NAME.search(path.name):
            continue
        filename = _FORWARD_NAME.fullmatch(path.name)
        if filename is None:
            continue
        sql = path.read_text(encoding="utf-8")
        markers = _MARKER.findall(sql)
        if not markers:
            raise BootstrapError("migration_marker_missing")
        marker_version, marker_name = markers[-1]
        version = int(filename.group(1))
        if int(marker_version) != version:
            raise BootstrapError("migration_marker_mismatch")
        migrations.append(
            Migration(
                version=version,
                name=marker_name,
                path=path,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        )
    versions = [item.version for item in migrations]
    if len(versions) != len(set(versions)):
        raise BootstrapError("migration_version_duplicate")
    return tuple(migrations)


def base_schema_markers(schema_path: Path) -> tuple[tuple[int, str], ...]:
    sql = schema_path.read_text(encoding="utf-8")
    blocks = _BASE_MARKER_BLOCK.findall(sql)
    if not blocks:
        raise BootstrapError("base_schema_markers_missing")
    markers = tuple(
        (int(version), name) for version, name in _MARKER_TUPLE.findall(blocks[-1])
    )
    if not markers or len({version for version, _name in markers}) != len(markers):
        raise BootstrapError("base_schema_markers_invalid")
    return markers


def create_platform_owner(connection, password: str) -> None:
    """Create the exact product owner after the versioned auth schema exists."""
    if (
        not isinstance(password, str)
        or len(password) < 12
        or len(password) > 4096
        or "\x00" in password
    ):
        raise BootstrapError("platform_owner_password_invalid")
    from deploy.linux.sli_core.auth import PASSWORD_HASHER

    password_hash = PASSWORD_HASHER.hash(password)
    connection.execute(
        """
        insert into public.auth_users(username, password_hash, role)
        select %s, %s, %s
        where not exists(
          select 1 from public.auth_users where lower(username)='platform-owner'
        )
        """,
        ("platform-owner", password_hash, "admin"),
    )


BASELINE_DOMAIN_PLACEHOLDER = "__SLI_REPORT_DOMAIN__"


def normalized_sha256(path: Path) -> str:
    """SHA-256 of a text file with CRLF folded to LF (checkout line endings vary)."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


@dataclass(frozen=True)
class Baseline:
    version: int
    roles_path: Path
    schema_path: Path


def load_baseline(baseline_dir: Path, migrations: Sequence[Migration]) -> Baseline:
    """Verified clean-install baseline (plan 6.6, ``build_postgres_baseline.py``).

    The manifest pins the hash of each baseline file and of every migration
    the baseline covers; a covered migration edited afterwards invalidates
    the baseline instead of silently diverging from it.
    """
    try:
        manifest = json.loads((baseline_dir / "manifest.json").read_text(encoding="utf-8"))
        version = int(manifest["baseline_version"])
        files = dict(manifest["files"])
        covered = {int(key): str(value) for key, value in dict(manifest["migrations"]).items()}
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BootstrapError("baseline_manifest_invalid") from exc
    if manifest.get("domain_placeholder") != BASELINE_DOMAIN_PLACEHOLDER:
        raise BootstrapError("baseline_manifest_invalid")
    for name in ("roles.sql", "baseline.sql"):
        path = baseline_dir / name
        if not path.is_file() or normalized_sha256(path) != files.get(name):
            raise BootstrapError("baseline_file_mismatch")
    current = {item.version: normalized_sha256(item.path) for item in migrations if item.version <= version}
    if current != covered:
        raise BootstrapError("baseline_migrations_mismatch")
    return Baseline(version=version, roles_path=baseline_dir / "roles.sql", schema_path=baseline_dir / "baseline.sql")


def render_baseline_schema(
    baseline: Baseline, domain_fqdn: str, target: Path, *, seed_report_domain: bool = False,
) -> Path:
    """Render the installation domain; Linux may seed its DB setting at bootstrap."""
    domain = str(domain_fqdn or "").strip().lower()
    labels = domain.split(".")
    if len(labels) < 2 or len(domain) > 253 or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise BootstrapError("source_domain_config_invalid")
    sql = baseline.schema_path.read_text(encoding="utf-8")
    if domain == "example.invalid" and not seed_report_domain:
        # Native owner setup learns its directory from the first DC. Remove
        # only the baseline directory seed rows, leaving the schema intact.
        sql = re.sub(
            r"(?m)^(COPY public\.(?:domains|forests) \([^\n]*\) FROM stdin;\n)"
            rf"[0-9]+\t(?:[0-9]+\t)?{BASELINE_DOMAIN_PLACEHOLDER}\t[^\n]+\n",
            r"\1", sql,
        )
    sql = sql.replace(BASELINE_DOMAIN_PLACEHOLDER, domain)
    if seed_report_domain:
        # DNS validation above makes the literal safe. Linux runs this in the
        # baseline transaction, never on an existing installation or request.
        sql += (
            "\nINSERT INTO public.platform_settings (key, value, updated_by) "
            f"VALUES ('reports.domain_fqdn', '{domain}', 'installer') "
            "ON CONFLICT (key) DO NOTHING;\n"
        )
    target.write_text(sql, encoding="utf-8", newline="\n")
    return target
