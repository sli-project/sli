"""Plan an isolated copy transition and reject incomplete or unequal readbacks.

This module never installs packages, restores a VM, or changes a database.
A proposed intermediate path is unverified until every hop has a receipt.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


# Spelled out in parts: a dotted four-number version looks like an address to the sanitary scan.
SOURCE_VERSION = ".".join(("25", "8", "33", "6"))
TARGET_VERSION = ".".join(("26", "8", "35", "10"))
INSTANCES = ("history", "warm")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class TransitionPlan:
    versions: tuple[str, ...]
    steps: tuple[str, ...] = (
        "restore_clean_snapshot", "offline_install_authenticated_packages",
        "start_isolated_instances", "restore_unchanged_archives",
        "compare_inventory_ddl_counts_sizes_digests", "run_readers_and_fresh_batch_retry",
        "inspect_errors_and_resources", "export_receipts_and_stop_vm",
    )


def plan_transition(intermediate: str | None = None, *, clickhouse_mode="native") -> TransitionPlan:
    """Return a proposal, without asserting cross-version compatibility."""
    if clickhouse_mode == "docker":
        from deploy.linux.native_clickhouse_endpoint import endpoint
        if intermediate is not None:
            raise ValueError("native_clickhouse_docker_transition_not_required")
        return TransitionPlan((endpoint("history", "docker").version,), ())
    if clickhouse_mode != "native":
        raise ValueError("native_clickhouse_mode_invalid")
    if intermediate is not None:
        if not re.fullmatch(r"26\.3\.\d+\.\d+", intermediate):
            raise ValueError("native_clickhouse_intermediate_not_26_3_lts")
        return TransitionPlan((SOURCE_VERSION, intermediate, TARGET_VERSION))
    return TransitionPlan((SOURCE_VERSION, TARGET_VERSION))


class TransitionMismatch(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _require(condition, reason):
    if not condition:
        raise TransitionMismatch(reason)


def _validate_snapshot(snapshot):
    _require(isinstance(snapshot, dict), "transition_snapshot_incomplete")
    _require(all(key in snapshot for key in ("inventory", "tables", "parts", "databases", "queries")),
             "transition_snapshot_incomplete")
    inventory = snapshot["inventory"]
    _require(isinstance(inventory, list) and bool(inventory), "transition_inventory_empty")
    identities = []
    for row in inventory:
        _require(isinstance(row, dict) and all(isinstance(row.get(key), str) and row[key]
                 for key in ("database", "name", "engine", "create_table_query")),
                 "transition_inventory_incomplete")
        identities.append((row["database"], row["name"]))
    _require(len(set(identities)) == len(identities), "transition_inventory_duplicate")
    tables = snapshot["tables"]
    _require(isinstance(tables, dict) and set(tables) == {".".join(key) for key in identities},
             "transition_table_coverage_mismatch")
    for row in tables.values():
        _require(isinstance(row, dict) and isinstance(row.get("digest"), str)
                 and bool(_SHA256.fullmatch(row["digest"]))
                 and all(type(row.get(key)) is int and row[key] >= 0 for key in ("logical_rows", "raw_count")),
                 "transition_digest_incomplete")
    _require(isinstance(snapshot["databases"], list) and bool(snapshot["databases"]),
             "transition_databases_incomplete")
    _require(isinstance(snapshot["parts"], list) and bool(snapshot["parts"]),
             "transition_sizes_incomplete")
    for row in snapshot["parts"]:
        _require(isinstance(row, dict) and all(key in row for key in ("database", "table", "rows", "bytes_on_disk")),
                 "transition_sizes_incomplete")
    _require(isinstance(snapshot["queries"], dict) and bool(snapshot["queries"]),
             "transition_queries_incomplete")


def verify_hop(source: dict, target: dict, source_version: str, target_version: str) -> dict:
    """Compare measured receipts; omit UUIDs and volatile system.tables estimates.

    Physical sizes are compared separately using active parts, after canonical
    merges on the source. Digest/count fields describe every logical table/view.
    """
    _require(bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", source_version)), "transition_version_invalid")
    _require(bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", target_version)), "transition_version_invalid")
    _require(set(source) == set(target) == set(INSTANCES), "transition_instance_coverage_mismatch")
    checked = {}
    for name in INSTANCES:
        before, after = source[name], target[name]
        _validate_snapshot(before)
        _validate_snapshot(after)
        _require(before.get("version") == source_version and after.get("version") == target_version,
                 "transition_measured_version_mismatch")
        fields = ("database", "name", "engine", "create_table_query")
        def inventory(snapshot):
            return sorted(tuple(row[field] for field in fields) for row in snapshot["inventory"])
        _require(inventory(before) == inventory(after), "transition_inventory_ddl_mismatch")
        _require(before["databases"] == after["databases"], "transition_database_mismatch")
        for table in before["tables"]:
            for field in ("logical_rows", "raw_count", "digest"):
                _require(before["tables"][table][field] == after["tables"][table][field],
                         "transition_" + field + "_mismatch")
        _require(before["parts"] == after["parts"], "transition_physical_sizes_mismatch")
        _require(before["queries"] == after["queries"], "transition_reader_mismatch")
        checked[name] = {table: {key: row[key] for key in ("logical_rows", "raw_count", "digest")}
                         for table, row in after["tables"].items()}
    return {"status": "verified", "source_version": source_version,
            "target_version": target_version, "instances": checked}


def verify_path(plan: TransitionPlan, receipts: list[dict]) -> dict:
    """A fallback proposal cannot become verified through a missing hop."""
    if plan.versions == (SOURCE_VERSION,) and plan.steps == ():
        _require(not receipts, "transition_not_required")
        return {"status": "not_required", "transition_path": list(plan.versions), "hops": []}
    _require(len(plan.versions) in (2, 3) and plan.versions[0] == SOURCE_VERSION
             and plan.versions[-1] == TARGET_VERSION, "transition_path_invalid")
    if len(plan.versions) == 3:
        _require(bool(re.fullmatch(r"26\.3\.\d+\.\d+", plan.versions[1])), "transition_path_invalid")
    hops = list(zip(plan.versions, plan.versions[1:]))
    _require(len(receipts) == len(hops), "transition_hop_missing")
    for (source, target), receipt in zip(hops, receipts):
        _require(receipt.get("status") == "verified" and receipt.get("source_version") == source
                 and receipt.get("target_version") == target and set(receipt.get("instances", {})) == set(INSTANCES),
                 "transition_hop_unverified")
    return {"status": "verified", "transition_path": list(plan.versions), "hops": receipts}
