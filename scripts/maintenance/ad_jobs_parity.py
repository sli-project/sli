#!/usr/bin/env python3
"""Compare legacy and queued AD/GPO computations offline; never connect to a DB."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import logging
from pathlib import Path
import sys
from unittest.mock import patch
from uuid import UUID

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.sources import ad_gpo_jobs, ad_snapshot_projection as projection  # noqa: E402

SOURCE_TABLES = {
    "ad_context_base": "ad_context_runs",
    "users_v2": "users_report_v2_snapshots",
    "computers_v6": "computers_v6_source_snapshots",
    "gpo_v2": "gpo_report_v2_source_snapshots",
}


class SnapshotConnection:
    """Serve only the exact repository SELECTs from a detached JSON snapshot."""

    def __init__(self, snapshot: dict):
        self.manifest = deepcopy(snapshot["manifest"])
        manifest = self.manifest
        manifest["manifest_id"] = str(UUID(manifest["manifest_id"]))
        if type(manifest["domain_id"]) is not int or manifest["domain_id"] < 1:
            raise ValueError("snapshot_domain_invalid")
        digest = manifest["manifest_sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or len(bytes.fromhex(digest)) != 32:
            raise ValueError("snapshot_hash_invalid")
        if manifest["coverage_state"] not in {"complete", "partial"}:
            raise ValueError("snapshot_coverage_invalid")
        members = manifest["members"]
        if not isinstance(members, list) or len({row["family"] for row in members}) != len(members):
            raise ValueError("snapshot_members_invalid")
        indexed = {row["family"]: row for row in members}
        sources = snapshot["sources"]
        if not isinstance(sources, list):
            raise ValueError("snapshot_sources_invalid")
        self.sources = {}
        for source in sources:
            family = source["family"]
            if family not in SOURCE_TABLES or family in self.sources:
                raise ValueError("snapshot_sources_invalid")
            member = indexed[family]
            if (source["source_id"] != member["source_id"]
                    or source["payload_sha256"] != member["payload_sha256"]
                    or not isinstance(source["payload_json"], dict)):
                raise ValueError("snapshot_source_binding_invalid")
            self.sources[family] = deepcopy(source)
        if set(self.sources) != set(SOURCE_TABLES):
            raise ValueError("snapshot_sources_missing")

    def cursor(self, **_kwargs):
        return SnapshotCursor(self)


class SnapshotCursor:
    def __init__(self, connection: SnapshotConnection):
        self.connection = connection
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        sql = " ".join(sql.lower().split())
        conn = self.connection
        self.rows = []
        if not sql.startswith("select ") or ";" in sql:
            raise ValueError("parity_read_only")
        if "from ad_snapshot_manifest_sources " in sql:
            if params == (conn.manifest["manifest_id"],):
                self.rows = deepcopy(conn.manifest["members"])
        elif "from ad_snapshot_manifests " in sql:
            if params == (conn.manifest["manifest_id"],):
                self.rows = [{key: deepcopy(value) for key, value in conn.manifest.items() if key != "members"}]
        else:
            for family, table in SOURCE_TABLES.items():
                if f"from {table} " in sql:
                    source = conn.sources[family]
                    if params == (source["source_id"],):
                        self.rows = [{key: deepcopy(source[key]) for key in ("payload_json", "payload_sha256")}]
                    break
            else:
                raise ValueError("parity_read_only")

    def fetchone(self):
        return deepcopy(self.rows[0]) if self.rows else None

    def fetchall(self):
        return deepcopy(self.rows)


def _summary(result: dict, payload: dict | None, expected_identity: str) -> dict:
    # Source IDs and personal fields remain inside payload hashes.
    metadata = {key: result[key] for key in ("input_sha256", "output_sha256", "output_identity")}
    safe_hashes = {}
    for key in ("input_sha256", "output_sha256"):
        value = metadata[key]
        safe_hashes[key] = value if (
            isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value)
        ) else None
    return {
        **safe_hashes,
        "output_identity": expected_identity if metadata["output_identity"] == expected_identity else None,
        "identity_sha256": projection.canonical_output_sha256(metadata["output_identity"]),
        "metadata_sha256": projection.canonical_output_sha256(metadata),
        "payload_sha256": projection.canonical_output_sha256(payload),
        "record_count": sum(len(value) for value in (payload or {}).values() if isinstance(value, list)),
    }


def _table_summary(rows: dict) -> dict:
    return {
        "row_count": len(rows),
        "identifiers_sha256": projection.canonical_output_sha256(
            sorted(row["identity_sha256"] for row in rows.values())),
        "content_sha256": projection.canonical_output_sha256(rows),
    }


def _compare(snapshot: dict) -> dict:
    from server.ad_context.repository import load_exact_projection_source

    legacy_conn = SnapshotConnection(snapshot)
    manifest = legacy_conn.manifest
    legacy_payloads = projection._project_exact_manifest_payloads(
        manifest, load_exact=lambda family, source_id, payload_sha256: load_exact_projection_source(
            legacy_conn, family=family, source_id=source_id, payload_sha256=payload_sha256))
    if any(result.get("error") for result, _payload in legacy_payloads.values()):
        raise ValueError("legacy_projection_failed")
    identities = {key: f"{manifest['manifest_id']}:{key}:v{version}"
                  for key, version in projection.PROJECTION_ALLOWLIST.items()}
    legacy = {key: _summary(result, payload, identities[key])
              for key, (result, payload) in legacy_payloads.items()}
    queued = {}
    registry = ad_gpo_jobs.registry()
    for profile in ("heavy", "long"):
        for identity in registry.identities(profile):
            if identity["handler_id"] not in ad_gpo_jobs.PROJECTIONS:
                continue  # Acquisition must never run in this offline check.
            handler = registry.handlers[tuple(identity[key] for key in (
                "plugin_id", "handler_id", "handler_version", "plugin_version", "manifest_sha256"))]
            job = {
                **identity, "job_type": handler["kind"], "budget": handler["budget"],
                "result_contract": handler["result_contract"],
                "source_instance_id": f"ad-domain:{manifest['domain_id']}",
                "pinned_input": {"manifest_id": manifest["manifest_id"],
                                 "snapshot_sha256": manifest["manifest_sha256"],
                                 "domain_id": manifest["domain_id"]},
            }
            captured = {}
            pure_project = projection._pure_project

            def capture(key, exact_input):
                output = pure_project(key, exact_input)
                captured[key] = deepcopy(output)
                return output

            # Observe the actual projector called by stage(), without replacing its computation.
            # This script is a single-process CLI, never an application/runtime entrypoint.
            with patch.object(projection, "_pure_project", side_effect=capture):
                staged = ad_gpo_jobs.stage(SnapshotConnection(snapshot), job)
            if staged["status"] not in {"success", "partial"}:
                raise ValueError("queue_projection_blocked")
            for key, result in staged["projection_results"].items():
                if key not in projection.PROJECTION_ALLOWLIST or key in queued or result.get("error"):
                    raise ValueError("queue_projection_invalid")
                queued[key] = _summary(result, captured.get(key), identities[key])
    comparisons = {
        key: {"legacy": legacy.get(key), "queue": queued.get(key), "match": legacy.get(key) == queued.get(key)}
        for key in sorted(set(legacy) | set(queued))
    }
    old_table, new_table = _table_summary(legacy), _table_summary(queued)
    return {
        "status": "match" if all(row["match"] for row in comparisons.values()) else "mismatch",
        "scope": "offline_projection_computation", "coverage_state": manifest["coverage_state"],
        "projections": comparisons,
        "tables": {"ad_snapshot_projection_outputs": {
            "legacy": old_table, "queue": new_table, "match": old_table == new_table}},
    }


def compare_snapshot(snapshot: dict) -> dict:
    """Run both real computation paths, returning only a safe JSON verdict."""
    previous_logging = logging.root.manager.disable
    try:
        # Legacy diagnostics may include source values; do not expose them even on failure.
        logging.disable(logging.CRITICAL)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return _compare(snapshot)
    except Exception:
        return {"status": "error", "error_code": "snapshot_parity_failed"}
    finally:
        logging.disable(previous_logging)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path, help="Detached manifest and exact sources JSON")
    args = parser.parse_args(argv)
    try:
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        result = {"status": "error", "error_code": "snapshot_read_failed"}
    else:
        result = compare_snapshot(snapshot)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return {"match": 0, "mismatch": 1, "error": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
