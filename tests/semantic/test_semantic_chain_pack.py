from pathlib import Path
import json

from server.sli.semantic.semantic_chain_pack import load_dispatch_rule_pack


def test_chain_pack_loads_only_draft_dispatch_rules() -> None:
    root = Path(__file__).resolve().parents[2]
    rules = load_dispatch_rule_pack(root / "config" / "semantic_chain_pack_v1.json")

    assert [rule.rule_id for rule in rules] == [
        "auth.session.privileged-context",
        "auth.session.lifecycle",
        "investigation.account.lockout.preceded-by-failures",
        "investigation.account.unlock.after-lock",
        "investigation.account.unlock.after-lock",
        "investigation.group.membership.removed-after-add",
        "investigation.group.membership.removed-after-add",
        "investigation.account.created-then-group-add",
        "investigation.account.created-then-group-add",
        "investigation.password.reset-then-logon",
        "investigation.password.reset-then-logon",
    ]
    assert [rule.rule_kind for rule in rules] == [
        "sequence", "sequence", "count_then", "sequence", "sequence", "sequence", "sequence", "sequence", "sequence", "sequence", "sequence",
    ]


def test_investigation_sequence_rules_preserve_legacy_version_and_declare_anchor_ambiguity_policy() -> None:
    root = Path(__file__).resolve().parents[2]
    pack = json.loads((root / "config" / "semantic_chain_pack_v1.json").read_text(encoding="utf-8"))
    sequence_ids = {
        "investigation.account.unlock.after-lock",
        "investigation.group.membership.removed-after-add",
        "investigation.account.created-then-group-add",
        "investigation.password.reset-then-logon",
    }
    by_id = {
        rule_id: [item for item in pack["rules"] if item.get("rule_id") == rule_id]
        for rule_id in sequence_ids
    }

    assert all([item["rule_version"] for item in versions] == [1, 2] for versions in by_id.values())
    assert all(versions[0]["definition"].get("continuation_policy") is None for versions in by_id.values())
    assert all(versions[1]["definition"].get("continuation_policy") == "anchor_all_admissible" for versions in by_id.values())
