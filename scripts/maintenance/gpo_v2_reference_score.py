#!/usr/bin/env python3
"""Mechanically score the frozen GPO V2 reference contract selectors."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "tests" / "fixtures" / "gpo_v2_reference_contract.json"


def pytest_results(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    root = ET.parse(path).getroot()
    for case in root.iter("testcase"):
        name = str(case.attrib.get("name", ""))
        if not name.startswith("test_"):
            continue
        failed = any(case.find(tag) is not None for tag in ("failure", "error", "skipped"))
        out[f"pytest::{name}"] = "FAIL" if failed else "PASS"
    return out


def vitest_results(path: Path) -> dict[str, str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for suite in payload.get("testResults", []):
        for case in suite.get("assertionResults", []):
            title = str(case.get("title") or "")
            if title:
                out[f"vitest::{title}"] = "PASS" if case.get("status") == "passed" else "FAIL"
    return out


def runtime_results(path: Path) -> dict[str, str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {name: str(detail.get("status", "NOT_PROVEN")) for name, detail in payload.get("selectors", {}).items()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pytest-junit", type=Path, required=True)
    parser.add_argument("--vitest-json", type=Path, required=True)
    parser.add_argument("--runtime-proof", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    selector_states = {
        **pytest_results(args.pytest_junit),
        **vitest_results(args.vitest_json),
        **runtime_results(args.runtime_proof),
    }
    clause_results = []
    for clause in matrix["clauses"]:
        states = {selector: selector_states.get(selector, "NOT_PROVEN") for selector in clause["selectors"]}
        status = "PASS" if states and all(state == "PASS" for state in states.values()) else "FAIL"
        clause_results.append({
            "id": clause["id"],
            "requirement": clause["requirement"],
            "non_waivable": bool(clause["non_waivable"]),
            "status": status,
            "selectors": states,
        })
    passed = sum(item["status"] == "PASS" for item in clause_results)
    total = len(clause_results)
    score = round(100.0 * passed / total, 2) if total else 0.0
    failed_non_waivable = [item["id"] for item in clause_results if item["non_waivable"] and item["status"] != "PASS"]
    accepted = score >= float(matrix["threshold_percent"]) and not failed_non_waivable
    report = {
        "contract_id": matrix["contract_id"],
        "threshold_percent": matrix["threshold_percent"],
        "score_percent": score,
        "passed_clauses": passed,
        "total_clauses": total,
        "failed_non_waivable": failed_non_waivable,
        "accepted": accepted,
        "clauses": clause_results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("contract_id", "score_percent", "passed_clauses", "total_clauses", "failed_non_waivable", "accepted")}, ensure_ascii=False))
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
