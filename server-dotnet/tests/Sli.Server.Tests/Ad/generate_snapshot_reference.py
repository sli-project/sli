"""Synthetic agent capture and exact projection; no source or database connection."""
from pathlib import Path
import sys
import json

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(ROOT), str(ROOT / "tests/unit")]
from test_agent_ad_snapshot_import import complete_families, cycle
from server.sli.plugins.ad.snapshot_import import prepare_ad_cycle, exact_directory_inputs
from server.sli.plugins.ad.directory_projection import build_directory_projection
from server.sli.plugins.ad.reports.users_v2_reporting import snapshot_from_directory_projection

policy, families = complete_families()
policy, families = json.loads(json.dumps([policy, families]).replace("S-1-5-21-1-2-3", "S-1-5-21-100000001-200000002-300000003").replace("s-1-5-21-1-2-3", "s-1-5-21-100000001-200000002-300000003"))
for family in families.values():
    family.pop("bundle_sha256", None)
bundles, computer = prepare_ad_cycle(cycle(policy), families)
guids = sorted({r["identity"]["object_guid"] for b in bundles.values()
                for r in b["records"] if r["record_type"] == "entity"})
ids = {guid: i + 1 for i, guid in enumerate(guids)}
items, inputs = exact_directory_inputs(bundles, domain_id=7, entity_ids=ids)
coverage = {"domains": [{"domain_id": 7, "domain_name": policy["domain_dns"]}],
            "latest_observed_at_utc": bundles["ad_context_base"]["observed_at_utc"]}
projection = build_directory_projection(items=items, coverage=coverage, requested_domain_ids=[7], exact_inputs=inputs)
users = snapshot_from_directory_projection(projection, coverage=coverage, active={"state": "ready", "limitations": []})
Path(__file__).with_name("snapshot-reference.json").write_text(json.dumps({
    "policy": policy, "families": families, "bundles": bundles, "ids": ids, "users": users,
}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
