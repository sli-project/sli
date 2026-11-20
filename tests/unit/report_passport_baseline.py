"""Apply only PR541's reviewed additive passport delta to frozen baselines.

The original relocation fixtures remain immutable. Expectations come from a
separate capture of the PR commit, never from the implementation under test.
"""
from __future__ import annotations

import ast
import json
from copy import deepcopy
from pathlib import Path


FIXTURE = Path(__file__).with_name("fixtures") / "report_passport_extension_pr541.json"
REPORT_KEYS = {
    "ad_state": "ad.infrastructure",
    "users": "ad.users.v2",
    "computers": "ad.computers.v6",
    "computer_logons": "ad.computer-logons",
    "new_logon_pairs": "ad.new-logon-pairs",
    "gpo": "ad.gpo.v2",
}


def _capture():
    capture = json.loads(FIXTURE.read_text("utf-8"))
    assert capture["commit"] == "0f3e0603967fffa612d82b917d4c7d614b1709e3"
    return capture


def baseline_tree(source: str, name: str) -> ast.Module:
    """Keep every legacy AST node and append the reviewed intent keywords."""
    tree = ast.parse(source)
    if name not in REPORT_KEYS:
        return tree
    additions = _capture()["reports"][REPORT_KEYS[name]]
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "ReportIntent"]
    assert len(calls) == 1
    intent = calls[0]
    assert not set(additions).intersection(keyword.arg for keyword in intent.keywords)
    intent.keywords.extend(ast.keyword(arg=key, value=ast.parse(repr(value), mode="eval").body)
                           for key, value in additions.items())
    return ast.fix_missing_locations(tree)


def extended_metadata(metadata: dict) -> dict:
    """Extend an old JSON declaration without changing any existing field."""
    capture = _capture()
    expected = deepcopy(metadata)
    additions = {**capture["defaults"], **capture["reports"][expected["key"]]}
    assert not additions.keys() & expected["intent"].keys()
    expected["intent"].update(additions)
    return expected


def domain_selection_metadata(metadata: dict) -> dict:
    """Apply the explicit shared-selector contract delta, keeping frozen captures intact."""
    expected = deepcopy(metadata)
    if expected["key"] in {"ad.users.v2", "ad.computers.v6", "ad.infrastructure"}:
        keys = ("domain_id", "domain") if expected["key"] == "ad.users.v2" else ("domain_id",)
        expected["params"] = [{"key": key, "label": "Домен", "kind": "domain", "hidden": True}
                              for key in keys] + expected["params"]
    return expected
