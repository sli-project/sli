"""Read-only canonical SQL inventory and exact PostgreSQL ledger comparison.

SHA-256 uses repository LF bytes, as does the existing baseline manifest.
Only CRLF checkout conversion is folded; every other SQL byte is immutable.
Rollback/bootstrap SQL is pinned too, but only canonical forward migrations
contribute ledger entries. No database connection or migration is initiated here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from deploy.linux.existing_postgres_bootstrap import (
    BootstrapError,
    base_schema_markers,
    forward_migration_inventory,
)


def migration_checksum_variants(body: bytes) -> set[str]:
    """Accept only LF and CRLF bytes; preserve all other bytes, including lone CR."""
    lf = body.replace(b"\r\n", b"\n")
    return {hashlib.sha256(variant).hexdigest() for variant in (lf, lf.replace(b"\n", b"\r\n"))}


def _checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def build_manifest(root: Path) -> dict:
    """Pin the full SQL set, including baseline inputs and non-forward files."""
    paths = [root / "config/postgres_schema_v8.sql"]
    paths.extend(sorted((root / "config/postgres_migrations").glob("*.sql")))
    paths.extend(sorted((root / "config/postgres_baseline").glob("*.sql")))
    baseline_manifest = root / "config/postgres_baseline/manifest.json"
    if baseline_manifest.is_file():
        paths.append(baseline_manifest)
    return {
        "format": 1,
        "hash_mode": "sha256-lf",
        "files": {path.relative_to(root).as_posix(): _checksum(path) for path in sorted(paths)},
    }


def verify_manifest(root: Path, manifest: dict) -> None:
    """Reject content changes as well as missing or newly unpinned SQL files."""
    if manifest != build_manifest(root):
        raise ValueError("native_pg_sql_inventory_mismatch")


def expected_ledger(root: Path) -> list[dict]:
    """Use the bootstrap marker parser and forward admission rules."""
    schema = root / "config/postgres_schema_v8.sql"
    rows = {
        version: {"version": version, "name": name, "sha256": _checksum(schema)}
        for version, name in base_schema_markers(schema)
    }
    for item in forward_migration_inventory(root / "config/postgres_migrations"):
        rows[item.version] = {
            "version": item.version, "name": item.name, "sha256": _checksum(item.path),
        }
    return [rows[version] for version in sorted(rows)]


def read_ledger(connection) -> list[dict]:
    """Read every attested version/name/hash through a supplied connection."""
    return [dict(zip(("version", "name", "sha256"), row)) for row in connection.execute(
        "select version, name, to_jsonb(m)->>'sha256' "
        "from public.schema_migrations m order by version"
    ).fetchall()]


def verify_ledger(actual: list[dict], expected: list[dict], *, root: Path | None = None) -> dict:
    """Adopt only exact release SQL with LF/CRLF conversion, without DB writes.

    With no release tree the comparison stays byte-exact. With a tree, both
    digests must be proven against the SAME file and marker in that release;
    no historical digest, NULL attestation or schema guess is trusted.
    """
    for rows in (expected, actual):
        if not isinstance(rows, list) or any(
            not isinstance(row, dict) or set(row) != {"version", "name", "sha256"}
            or type(row["version"]) is not int or row["version"] < 1
            or not isinstance(row["name"], str) or not row["name"]
            or not isinstance(row["sha256"], str) or not re.fullmatch("[a-f0-9]{64}", row["sha256"])
            for row in rows
        ) or [row["version"] for row in rows] != sorted({row["version"] for row in rows}):
            raise ValueError("native_pg_ledger_mismatch_shape")
    if [(row["version"], row["name"]) for row in actual] != [
        (row["version"], row["name"]) for row in expected
    ]:
        raise ValueError("native_pg_ledger_mismatch_markers")
    differences = [(a, e) for a, e in zip(actual, expected) if a != e]
    if differences:
        if root is None:
            raise ValueError("native_pg_ledger_mismatch")
        schema = root / "config/postgres_schema_v8.sql"
        try:
            sources = {version: (name, schema) for version, name in base_schema_markers(schema)}
            sources.update((item.version, (item.name, item.path)) for item in
                           forward_migration_inventory(root / "config/postgres_migrations"))
            for row, pinned in differences:
                source = sources.get(row["version"])
                if source is None or source[0] != pinned["name"]:
                    raise ValueError("native_pg_ledger_mismatch_source")
                variants = migration_checksum_variants(source[1].read_bytes())
                if pinned["sha256"] not in variants or row["sha256"] not in variants:
                    raise ValueError("native_pg_ledger_mismatch_checksum")
        except (OSError, BootstrapError):
            raise ValueError("native_pg_ledger_mismatch_source") from None
    return {"policy": "release-sql-lf-crlf-v1", "newline_versions": [a["version"] for a, _ in differences],
            "ledger_sha256": hashlib.sha256(json.dumps(actual, sort_keys=True).encode()).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--ledger", type=Path, help="Compare a previously exported ledger JSON")
    args = parser.parse_args()
    manifest = json.loads((args.root / "deploy/linux/native_pg_ledger.json").read_text(encoding="utf-8"))
    verify_manifest(args.root, manifest)
    expected = expected_ledger(args.root)
    if args.ledger:
        verify_ledger(json.loads(args.ledger.read_text(encoding="utf-8")), expected, root=args.root)
    print(json.dumps({"status": "verified", "pinned_files": len(manifest["files"]),
                      "sql_files": sum(name.endswith(".sql") for name in manifest["files"]),
                      "ledger_verified": args.ledger is not None,
                      "ledger_entries": len(expected), "max_version": expected[-1]["version"]}))


if __name__ == "__main__":
    main()
