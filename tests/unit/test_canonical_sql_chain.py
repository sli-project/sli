from copy import deepcopy
import json
from pathlib import Path

import pytest

from deploy.linux import native_pg_inventory as inventory

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "config/postgres_migrations"
NAMES = ["identity_attack_rules", "attack_precursors", "evsearch_fact_publication", "nps_agent_row_lock", "agent_group_approval_delivery"]


def test_chain_pinned_and_ledger_rejects_missing_changed_and_future():
    manifest = json.loads((ROOT / "deploy/linux/native_pg_ledger.json").read_text(encoding="utf-8"))
    inventory.verify_manifest(ROOT, manifest)
    rows = inventory.expected_ledger(ROOT)
    assert [(r["version"], r["name"]) for r in rows if 301 <= r["version"] <= 305] == list(zip(range(301, 306), NAMES))
    inventory.verify_ledger(rows, rows, root=ROOT)
    for mode in ("missing", "hash", "future"):
        actual = deepcopy(rows)
        if mode == "missing":
            actual.pop(-4)
        elif mode == "hash":
            actual[-1]["sha256"] = "0" * 64
        else:
            actual.append({"version": 307, "name": "future", "sha256": "0" * 64})
        with pytest.raises(ValueError, match="native_pg_ledger_mismatch"):
            inventory.verify_ledger(actual, rows, root=ROOT)
