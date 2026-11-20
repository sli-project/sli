"""Bounded, source-bound password attack signals over named Windows EventData."""
from collections import defaultdict
from dataclasses import asdict
from ipaddress import ip_address

from server.sli.semantic.qw_input import QWSignal, _digest
from server.sli.semantic.semantic_risk import ScenarioSourceKind
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition
from server.sli.storage.evidence_ref import EvidenceRef

WINDOW_SECONDS = 300
THRESHOLD = 10
RULES = {
    "qw.password-spray": "Passwords tried across several accounts",
    "qw.password-brute-force": "Repeated password attempts against one account",
    "qw.disabled-account-logon": "Sign-in attempted with a disabled account",
}


def execution(scope, rule_id):
    return {"version": "sli.qw.execution.v1", "kind": "threshold", "rule_id": rule_id,
            "rule_version": 1, "rule_sha256": _digest({"version": 1, "rule": rule_id,
                "window_seconds": WINDOW_SECONDS, "threshold": THRESHOLD, "spray_accounts": 5}),
            "scope": asdict(scope)}


def risk_policy(scope, rule_id, *, policy_id):
    return RiskPolicyDefinition(policy_id=policy_id, policy_version=1,
        source_kind=ScenarioSourceKind.QW_SIGNAL, definition={
            "type": "scenario_policy", "source_selector": {"rule_id": rule_id, "execution": execution(scope, rule_id)},
            "scenario_kind": rule_id, "result_class": "security_incident", "merge_window_seconds": WINDOW_SECONDS,
            "title": RULES[rule_id], "explanation": "Review the linked sign-in attempts and secure the affected accounts.",
            "risk": {"class": "high", "raw_score": "60", "display_points": 60,
                     "rationale": "Observed password attack evidence requires review."}})


def _code(value):
    try:
        return int(str(value), 16)
    except (ValueError, TypeError):
        return None


def evaluate(scope, rows, *, now):
    """Five-minute source-time buckets; native IDs deduplicate packet replays.

    Unknown users, missing client addresses and generic authentication failures
    cannot establish a spray. Disabled means a native Windows status, not a
    present-day directory lookup applied to an old event.
    """
    if len(rows) > 10000:
        raise ValueError("password_attack_window_truncated")
    groups, seen = defaultdict(list), set()
    for row in rows:
        native = str(row["source_event_id"])
        if native in seen:
            continue
        seen.add(native)
        at, fields = row["occurred_at_utc"], row["event_data"]
        if at > now:
            continue
        status, substatus = _code(fields.get("Status")), _code(fields.get("SubStatus"))
        event_id = row["event_id"]
        if event_id not in (4625, 4771, 4776):
            continue
        bucket = int(at.timestamp()) // WINDOW_SECONDS
        account = str(fields.get("TargetUserName") or "").strip().casefold()
        domain = str(fields.get("TargetDomainName") or "").strip().casefold()
        if account in {"", "-", "n/a"}:
            continue
        account = _digest([domain, account])
        if event_id in (4625, 4776) and 0xC0000072 in (status, substatus):
            groups[("qw.disabled-account-logon", account, bucket)].append(row)
        bad_password = (event_id in (4625, 4776) and 0xC000006A in (status, substatus)
                        or event_id == 4771 and status == 0x18)
        if not bad_password:
            continue
        groups[("qw.password-brute-force", account, bucket)].append(row)
        try:
            address = ip_address(fields.get("IpAddress", ""))
            if address.is_unspecified or address.is_loopback:
                continue
            if getattr(address, "ipv4_mapped", None):
                address = address.ipv4_mapped
        except ValueError:
            continue
        groups[("qw.password-spray", str(address), bucket)].append(row | {"account_key": account})
    signals = []
    for (rule_id, entity, bucket), members in sorted(groups.items()):
        if rule_id != "qw.disabled-account-logon" and len(members) < THRESHOLD:
            continue
        if rule_id == "qw.password-spray" and len({row["account_key"] for row in members}) < 5:
            continue
        pin = execution(scope, rule_id)
        refs = tuple(EvidenceRef("core_event", str(row["source_event_id"]), row["sha256"], scope)
                     for row in sorted(members, key=lambda row: row["source_event_id"]))
        for offset in range(0, len(refs), 256):
            signals.append(QWSignal(kind="threshold", rule_id=rule_id, rule_version=1,
                rule_sha256=pin["rule_sha256"], policy_revision=1, evaluation_mode="enabled",
                entity_key=_digest(entity), episode_key=_digest([rule_id, entity, bucket]),
                occurred_at_utc=max(row["occurred_at_utc"] for row in members), received_at_utc=now,
                evidence_refs=refs[offset:offset + 256], evidence_total=len(refs),
                base_severity="high", effective_severity="high"))
    return tuple(signals)
