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


def test_reviewed_guards_and_caller_contract():
    lock = (MIGRATIONS / "304_nps_agent_row_lock.sql").read_text(encoding="utf-8").lower()
    assert "security definer set search_path=pg_catalog,pg_temp" in lock
    assert "from public.sli_agents a" in lock and "for update" in lock
    assert "revoke all on function public.lock_nps_import_agent_v304(uuid) from public" in lock
    assert "to adlog_nps_agent_import_worker,adlog_user" in lock
    assert "grant update" not in lock
    caller = (ROOT / "server/sli/sources/nps_agent_import.py").read_text(encoding="utf-8")
    assert "public.lock_nps_import_agent_v304(%s)" in caller
    rollback = (MIGRATIONS / "305_agent_group_approval_delivery.rollback.sql").read_text(encoding="utf-8").lower()
    for guard in ("version>305", "saved.installed_definition", "saved.installed_comment", "action='group_approval_delivery'"):
        assert guard in rollback and rollback.index(guard) < rollback.index("alter table public.sli_agent_audit drop constraint")
    assert rollback.strip().endswith("commit;")
