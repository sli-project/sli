"""L06-2 private oracle and deterministic transcript scoring; no model or DB.

The certified export contains scenario_data.json with problems, membership_changes,
lockout_events, sources and snapshots arrays. scope_id is a numeric collection
scope; identity strings are passport tokens. Source positions are monotonically
ordered read/delivered/imported/processed counters, not last-event timestamps.
Only `plan` output is crawler input. Expected answers never leave this evaluator.
UI answers are verbatim visible blocks: a claim must be supported within ONE
block (a table row, metric, or text line), not assembled from unrelated screens.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit
from zoneinfo import ZoneInfo

import yaml

from scripts.dev.ui_audit.stand import HERE, require_external_path, validate_gate

CATALOG = HERE / "scenarios.yaml"
ACCOUNTS = json.loads((HERE / "access_levels.json").read_text(encoding="utf-8"))["accounts"]
IDS = {"morning_decisions", "privileged_membership_24h", "account_lockout",
       "problem_next_step", "source_lag", "stale_ad_snapshot"}
TOKEN = re.compile(r"anon_(?:name|login|email|ip|dn|host|sid|domain|id)_\d+")
WORDS = {
    "scope": ("только в доступной области", "within the authorized scope"),
    "raw": ("нет доступа к сырым доказательствам", "raw evidence access denied"),
    "stale": ("устаревший снимок", "stale snapshot", "данные устарели", "data is stale"),
    "unknown": ("недостаточно данных", "insufficient data"),
    "correlation": ("не доказывает причину", "does not prove cause"),
    "review": ("проверить доказательства", "review evidence"),
    "request": ("запросить доказательства", "request evidence"),
    "visibility": ("восстановить наблюдение", "restore observation"),
    "collection": ("сбор", "collection"), "delivery": ("доставка", "delivery"),
    "import": ("импорт", "import"), "processing": ("обработка", "processing"),
    "lag_unknown": ("задержка неизвестна", "lag unknown"),
    "not_current": ("текущее состояние неизвестно", "current state unknown"),
}


def instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("scenario_time_requires_zone")
    return parsed


def catalog(path: Path = CATALOG) -> list[dict]:
    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    if (spec["schema"] != "sli.audit-scenarios.v1" or spec["persona"] != "information_security_specialist"
            or {s["id"] for s in spec["scenarios"]} != IDS or len(spec["scenarios"]) != len(IDS)):
        raise ValueError("invalid_scenario_catalog")
    result = []
    defaults = spec["defaults"]
    instant(defaults["fixed_time"])
    ZoneInfo(defaults["time_zone"])
    for scenario in spec["scenarios"]:
        for level, variant in spec["access_levels"].items():
            for locale in defaults["locales"]:
                entry = {**defaults, **scenario, "persona": spec["persona"], "access_level": level,
                         "account": variant["account"], "locale": locale,
                         "goal": scenario["goal"][locale], "run_id": f"{scenario['id']}:{level}:{locale}"}
                del entry["locales"]
                entry["route"] = scenario.get("route_overrides", {}).get(level, scenario["route"])
                result.append(entry)
    return result


def public_plan(scenario: dict) -> dict:
    """Explicit allowlist prevents future oracle fields reaching a participant."""
    keys = ("id", "run_id", "persona", "access_level", "account", "locale", "time_zone",
            "fixed_time", "data_snapshot_id", "start_page", "goal", "allowed_actions",
            "max_steps", "max_seconds", "completion_criteria", "route")
    plan = {key: scenario[key] for key in keys}
    start = (instant(scenario["fixed_time"]) - timedelta(hours=24)).isoformat()
    plan["route"] = [{**step, **({"target": step["target"].format(
        window_start=quote(start, safe=""), fixed_time=quote(scenario["fixed_time"], safe=""))}
        if "target" in step else {})} for step in scenario["route"]]
    return plan


def authorized_scopes(scenario: dict) -> set[int] | None:
    account = ACCOUNTS[scenario["account"]]
    return None if account["scope"]["mode"] == "all" else {
        int(code.removeprefix("ad-domain:")) for clause in account["scope"]["clauses"]
        for code in clause["collection_scope_ids"]}


def allowed_slice(dataset: dict, scenario: dict) -> dict:
    account = ACCOUNTS[scenario["account"]]
    scopes = authorized_scopes(scenario)

    def project(row):
        return {key: value for key, value in row.items()
                if "raw_evidence" in account["field_classes"] or key not in {"raw_evidence", "xml", "payload"}}

    return {key: [project(row) for row in dataset[key] if scopes is None or row["scope_id"] in scopes]
            for key in ("problems", "membership_changes", "lockout_events", "sources", "snapshots")}


def claim(key: str, *terms) -> dict:
    result = {"key": key, "terms": [list(term) if isinstance(term, tuple) else [str(term)] for term in terms]}
    if len(terms) >= 2 and isinstance(terms[-2], tuple) and isinstance(terms[-1], int):
        result["numeric_value"] = terms[-1]
    return result


def time_terms(value: str, scenario: dict) -> tuple:
    local = instant(value).astimezone(ZoneInfo(scenario["time_zone"]))
    # The application's formatDateTime uses ru-RU in both locales.
    return (value, local.strftime("%d.%m.%y, %H:%M:%S"), local.strftime("%d.%m.%Y, %H:%M:%S"))


def expected_answer(dataset: dict, scenario: dict) -> dict:
    data = allowed_slice(dataset, scenario)
    now = instant(scenario["fixed_time"])
    start = now - timedelta(hours=24)
    claims, limitations = [], []
    answer = {}
    refusal = None
    if scenario["access_level"] == "limited-scope":
        limitations.append("scope")
    raw = "raw_evidence" in ACCOUNTS[scenario["account"]]["field_classes"]
    if not raw:
        limitations.append("raw")
    problems = sorted((r for r in data["problems"] if r["state"] == "active" and instant(r["observed_at"]) <= now),
                      key=lambda r: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[r["severity"]],
                                     -instant(r["observed_at"]).timestamp(), r["id"]))
    kind = scenario["id"]
    if kind == "morning_decisions":
        decision_ids = [row["id"] for row in problems[:5]]
        incomplete = any(instant(r["observed_at"]) > now or
                         (now - instant(r["observed_at"])).total_seconds() > 86400 for r in data["snapshots"])
        incomplete |= not data["snapshots"] or not data["sources"] or any(not r["collection_running"] or
            r["read"] != r["processed"] for r in data["sources"])
        message = (f"Требует решения: {len(problems)}. Наблюдение: " + ("неполные данные." if incomplete else "сбор работает.")) if scenario["locale"] == "ru" else (
            f"Requires a decision: {len(problems)}. Observation: " + ("incomplete data." if incomplete else "collection running."))
        answer = {"decision_ids": decision_ids, "observation": "partial" if incomplete else "ok", "status_message": message}
        for row in problems[:5]:
            claims.append(claim(f"problem:{row['id']}", (f"#{row['id']}", f"№{row['id']}", f"problem {row['id']}")))
        claims.append(claim("status", ("требует решения", "requires a decision"), len(problems)))
        claims.append(claim("observation", ("неполные данные", "incomplete data") if incomplete else
                            ("сбор работает", "collection running")))
    elif kind == "privileged_membership_24h":
        rows = sorted((r for r in data["membership_changes"] if r["privileged"] and r["added"]
                       and start < instant(r["observed_at"]) <= now), key=lambda r: (r["observed_at"], r["id"]))
        answer = {"changes": [{key: row[key] for key in ("id", "member", "group", "observed_at")} for row in rows]}
        for row in rows:
            claims.append(claim(f"change:{row['id']}", row["member"], row["group"], time_terms(row["observed_at"], scenario)))
        if not rows:
            claims.append(claim("empty", ("нет изменений", "no changes")))
    elif kind == "account_lockout":
        events = [r for r in data["lockout_events"] if start < instant(r["observed_at"]) <= now]
        accounts = sorted({r["account"] for r in events if r["event_code"] == 4740})
        answer = {"accounts": []}
        for account in accounts:
            related = [r for r in events if r["account"] == account]
            locks = [r for r in related if r["event_code"] == 4740]
            failures = [r for r in related if r["event_code"] in {4625, 6273} and any(
                0 <= (instant(lock["observed_at"]) - instant(r["observed_at"])).total_seconds() <= 300
                and lock["caller"] == r["caller"] for lock in locks)]
            callers = sorted({r["caller"] for r in locks})
            answer["accounts"].append({"account": account, "lockouts": len(locks),
                                       "preceding_failures": len(failures), "callers": callers})
            claims.append(claim(f"lockouts:{account}", account, ("блокировок", "lockouts"), len(locks)))
            claims.append(claim(f"failures:{account}", account, ("отказов", "failures"), len(failures)))
            for caller in callers:
                claims.append(claim(f"caller:{account}:{caller}", account, caller))
        limitations.append("correlation")
        if not accounts:
            limitations.append("unknown")
        if not raw:
            refusal = "raw_evidence_denied"
        else:
            retained = [r for r in events if r["event_code"] == 4740 and r.get("raw_evidence")]
            if retained:
                claims.append(claim("exact_event", retained[0]["id"], 4740))
            else:
                limitations.append("unknown")
    elif kind == "problem_next_step":
        if problems:
            row = problems[0]
            step = "request" if not raw else {0: "review", 1: "request", 2: "visibility"}[row["next_step"]]
            answer = {"problem_id": row["id"], "next_step": step}
            claims.extend([claim("problem", (f"#{row['id']}", f"№{row['id']}", f"problem {row['id']}")),
                           claim("next_step", WORDS[step])])
        else:
            answer = {"problem_id": None, "next_step": "unknown"}
            limitations.append("unknown")
    elif kind == "source_lag":
        answer = {"sources": []}
        for row in sorted(data["sources"], key=lambda r: r["id"]):
            positions = [row.get(k) for k in ("read", "delivered", "imported", "processed")]
            if any(not isinstance(p, int) or isinstance(p, bool) or p < 0 for p in positions) or positions != sorted(positions, reverse=True):
                stages = None
                limitations.append("lag_unknown")
            else:
                stages = {"collection": not row["collection_running"] or row["pending_read"] > 0,
                          "delivery": row["read"] > row["delivered"],
                          "import": row["delivered"] > row["imported"],
                          "processing": row["imported"] > row["processed"]}
                for stage, lag in stages.items():
                    claims.append(claim(f"{row['id']}:{stage}", row["id"], WORDS[stage],
                                        ("отстаёт", "lagging") if lag else ("без задержки", "no lag")))
            answer["sources"].append({"id": row["id"], "stages": stages})
        if not data["sources"]:
            limitations.append("lag_unknown")
    elif kind == "stale_ad_snapshot":
        answer = {"snapshots": []}
        for row in sorted(data["snapshots"], key=lambda r: r["scope_id"]):
            age = (now - instant(row["observed_at"])).total_seconds()
            state = "unknown" if age < 0 else "stale" if age > 86400 else row["state"]
            answer["snapshots"].append({"scope_id": row["scope_id"], "observed_at": row["observed_at"],
                                        "state": state, "failed": row["failed"], "not_evaluated": row["not_evaluated"]})
            claims.append(claim(f"snapshot:{row['scope_id']}", time_terms(row["observed_at"], scenario)))
            claims.append(claim(f"failed:{row['scope_id']}", ("не пройдено", "failed"), row["failed"]))
            claims.append(claim(f"not_evaluated:{row['scope_id']}", ("не оценено", "not evaluated"), row["not_evaluated"]))
            if state in {"stale", "unknown"}:
                limitations.extend([state, "not_current"])
        if not data["snapshots"]:
            limitations.extend(["unknown", "not_current"])
    else:
        raise ValueError("unknown_scenario")
    limitations = sorted(set(limitations))
    return {"answer": answer, "claims": claims, "limitations": limitations, "refusal": refusal}


def contains(text: str, term: str) -> bool:
    # Complete tokens: 1 must not match 10, anon_id_1 must not match anon_id_10.
    return bool(re.search(r"(?<!\w)" + re.escape(term.casefold()) + r"(?!\w)", " ".join(text.casefold().split())))


def claim_matches(item: dict, blocks: list[str]) -> bool:
    return any(all(any(contains(block, term) for term in alternatives) for alternatives in item["terms"])
               for block in blocks)


def conflicting_value(item: dict, blocks: list[str]) -> bool:
    """A correct number elsewhere must not conceal a conflicting numeric answer."""
    if "numeric_value" not in item:
        return False
    for block in blocks:
        if not all(any(contains(block, term) for term in alternatives) for alternatives in item["terms"][:-2]):
            continue
        for label in item["terms"][-2]:
            pattern = r"(?<!\w)" + re.escape(label.casefold()) + r"(?!\w)\s*[:=]?\s*(-?\d+)(?!\d)"
            reverse = r"(?<!\w)(-?\d+)\s*" + re.escape(label.casefold()) + r"(?!\w)"
            if any(int(value) != item["numeric_value"] for value in re.findall(pattern, block.casefold()) + re.findall(reverse, block.casefold())):
                return True
    return False


def scope_leak(dataset: dict, scenario: dict, records: list[dict]) -> bool:
    allowed = allowed_slice(dataset, scenario)
    def tokens(value):
        return set(TOKEN.findall(json.dumps(value, ensure_ascii=False)))
    forbidden = tokens(dataset) - tokens(allowed)
    serialized = json.dumps(records, ensure_ascii=False)
    if forbidden & tokens(records):
        return True
    scopes = authorized_scopes(scenario)
    forbidden_problems = {r["id"] for r in dataset["problems"]} - {r["id"] for r in allowed["problems"]}
    for record in records:
        if forbidden_problems & set(record.get("observed_problem_ids", [])):
            return True
        if scopes is not None and any(scope not in scopes for scope in record.get("observed_scopes", [])):
            return True
        if scenario["account"] == "without_raw_evidence" and record.get("raw_evidence_observed"):
            return True
    return scenario["account"] == "without_raw_evidence" and bool(re.search(r'"(?:xml|payload|raw_evidence)"\s*:', serialized))


def metrics(dataset: dict, scenario: dict, records: list[dict], *, mode: str = "deterministic", duration_ms: int | None = None) -> dict:
    if mode not in {"deterministic", "model"}:
        raise ValueError("invalid_scenario_mode")
    expected = expected_answer(dataset, scenario)
    steps = len(records)
    elapsed = max((r.get("elapsed_ms", 0) for r in records), default=0)
    if duration_ms is not None:
        if type(duration_ms) is not int or duration_ms < 0:
            raise ValueError("invalid_scenario_duration")
        elapsed = max(elapsed, duration_ms)
    seen, backtracks = set(), 0
    for record in records:
        target = record.get("next_screen")
        if target in seen and record.get("screen") != target:
            backtracks += 1
        seen.add(record.get("screen"))
        seen.add(target)
    final = records[-1].get("answer") if records else None
    blocks = final.get("blocks", []) if isinstance(final, dict) else []
    matched = sum(claim_matches(c, blocks) for c in expected["claims"])
    accuracy = matched / len(expected["claims"]) if expected["claims"] else 1.0 if final else 0.0
    honest = all(claim_matches(claim(code, WORDS[code]), blocks) for code in expected["limitations"])
    leak = scope_leak(dataset, scenario, records)
    planned = [{"action": "goto", "target": scenario["start_page"]}, *public_plan(scenario)["route"]]
    def screen_key(value):
        parsed = urlsplit(value or "")
        if parsed.scheme or parsed.netloc or not re.fullmatch(r"/app(?:/.*)?", parsed.path):
            return None
        return parsed.path.rstrip("/"), sorted(parse_qsl(parsed.query))
    route_completed = len(records) == len(planned) and all(
        record.get("action") == step["action"] and screen_key(record.get("next_screen")) is not None
        and (step["action"] != "goto" or screen_key(record.get("next_screen")) == screen_key(step["target"]))
        and (index == 0 or screen_key(record.get("screen")) == screen_key(records[index - 1].get("next_screen")))
        for index, (record, step) in enumerate(zip(records, planned)))
    evidence_accuracy = accuracy
    observed = blocks
    evidence_honesty = honest
    if mode == "model":
        # A model may discover a different path; the fixed L06-2 route is not an oracle for navigation.
        route_completed = bool(records) and records[0].get("action") == "goto" and screen_key(records[0].get("next_screen")) == screen_key(scenario["start_page"]) and bool(final) and all(
            record.get("action") in scenario["allowed_actions"] and screen_key(record.get("next_screen")) is not None
            and (index == 0 or screen_key(record.get("screen")) == screen_key(records[index - 1].get("next_screen")))
            for index, record in enumerate(records))
        observed = [block for record in records for block in record.get("observation", {}).get("blocks", [])]
        allowed_problem_ids = {row["id"] for row in allowed_slice(dataset, scenario)["problems"]}
        leak |= any(claim_matches(claim("forbidden_problem", (f"#{row['id']}", f"№{row['id']}", f"problem {row['id']}")),
                                  [*blocks, *observed]) for row in dataset["problems"] if row["id"] not in allowed_problem_ids)
        supported = sum(claim_matches(c, blocks) and claim_matches(c, observed) for c in expected["claims"])
        evidence_accuracy = supported / len(expected["claims"]) if expected["claims"] else accuracy
        evidence_honesty = all(claim_matches(claim(code, WORDS[code]), observed) for code in expected["limitations"])
    blocked = (not final or not route_completed or steps > scenario["max_steps"] or elapsed > scenario["max_seconds"] * 1000
               or any(r.get("blocked") or r.get("error") for r in records))
    refusal_ok = expected["refusal"] == (final or {}).get("refusal")
    contradictions = any(conflicting_value(c, blocks) for c in expected["claims"]) or any(claim_matches(claim("safe", words), blocks) for words in (
        ("угроз нет", "no threats"), ("всё в порядке", "everything is fine"),
        ("причина доказана", "cause proven")))
    false_all_good = any(contains(block, term) for block in [*blocks, *observed] for term in (
        "всё хорошо", "все хорошо", "всё в порядке", "все в порядке", "everything is fine", "all is well", "no threats", "угроз нет"))
    contradictions |= false_all_good
    wrong = leak or contradictions or (bool(final) and (accuracy != 1 or evidence_accuracy != 1 or not honest or not evidence_honesty or not refusal_ok))
    outcome = "wrong" if wrong else "blocked" if blocked else "correct_refusal" if expected["refusal"] else "success"
    return {"outcome": outcome, "steps": steps, "backtracks": backtracks, "time_ms": elapsed,
            "accuracy": accuracy, "matched_claims": matched, "expected_claims": len(expected["claims"]),
            "honest_limitations": honest, "scope_leak": leak, "route_completed": route_completed,
            "evidence_accuracy": evidence_accuracy,
            "evidence_honesty": evidence_honesty,
            "violations": [code for code, present in (("scope_leak", leak), ("wrong_answer", wrong),
                            ("false_all_good", false_all_good),
                            ("dishonest_limitations", bool(final) and not honest), ("blocked", blocked)) if present]}


def load_dataset(candidate: Path, scenario: dict) -> dict:
    manifest = json.loads((candidate / "manifest.json").read_text(encoding="utf-8"))
    if scenario["data_snapshot_id"] != f"{manifest['dataset_id']}:{manifest['snapshot_version']}":
        raise ValueError("scenario_snapshot_mismatch")
    return json.loads((candidate / "scenario_data.json").read_text(encoding="utf-8"))


def main() -> int:
    import os
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "score"))
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--locale", required=True, choices=("ru", "en"))
    args = parser.parse_args()
    try:
        env = dict(os.environ)
        admission = validate_gate(args.base, args.out, env)
        if args.action == "score":
            metric_path = args.out / "metrics.json"
            if metric_path.is_symlink():
                raise ValueError("scenario_metrics_symlink")
            # A rejected retry must not leave a previous success as its result.
            metric_path.write_text(json.dumps({"outcome": "blocked", "model_status": "not_run",
                                               "reason": "scenario_scoring_not_completed"}) + "\n", encoding="utf-8")
        scenario = next(s for s in catalog() if s["id"] == args.scenario and s["locale"] == args.locale
                        and s["account"] == admission["access_level"])
        dataset = load_dataset(Path(env["SLI_AUDIT_DATASET"]), scenario)
        # Validate the private oracle even for plan, without disclosing its result.
        expected_answer(dataset, scenario)
        if args.action == "plan":
            print(json.dumps(public_plan(scenario), ensure_ascii=False))
            return 0
        evidence = require_external_path(args.out / "evidence.jsonl")
        run = json.loads((args.out / "run.json").read_text(encoding="utf-8"))
        digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
        if (run.get("status") not in {"completed", "blocked"} or
                any(run.get(key) != value for key, value in admission.items()) or
                run.get("scenario_id") != scenario["run_id"] or run.get("evidence_sha256") != digest):
            raise ValueError("scenario_run_mismatch")
        records = [json.loads(line) for line in evidence.read_text(encoding="utf-8").splitlines() if line.strip()]
        if any(r.get("scenario_id") != scenario["run_id"] or r.get("locale") != args.locale or
               r.get("fixed_time") != scenario["fixed_time"] or r.get("time_zone") != scenario["time_zone"] or
               r.get("data_snapshot_id") != scenario["data_snapshot_id"] for r in records):
            raise ValueError("scenario_evidence_mismatch")
        result = {**admission, "scenario_id": scenario["run_id"], "model_status": "not_run",
                  "evidence_sha256": digest,
                  **metrics(dataset, scenario, records)}
        (args.out / "metrics.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"outcome": result["outcome"]}))
        return 0 if result["outcome"] in {"success", "correct_refusal"} else 1
    except (OSError, ValueError, KeyError, TypeError, StopIteration):
        print(json.dumps({"outcome": "blocked", "reason": "scenario_admission_or_data_failed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
