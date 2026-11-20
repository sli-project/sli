"""W02: exact account watch, event-time severity and five-minute episodes."""
from dataclasses import asdict, dataclass
from datetime import timedelta
from uuid import UUID

from server.sli.semantic.account_decoy import AUTHENTICATION, utc
from server.sli.semantic.qw_input import QWSignal, SEVERITIES, _digest
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope

RULE_ID = "qw.account-watch"
ROLES = ("actor", "affected_entity", "session_principal")
EVENT_TYPES = {key: (value,) for key, value in AUTHENTICATION.items()} | {
    4634: ("authentication.session.ended",), 4647: ("authentication.logout.requested",),
    4648: ("authentication.explicit_credentials.used",), 4672: ("authentication.privileged_session.created",),
    4740: ("authentication.account.locked",), 4767: ("authentication.account.unlocked",),
    4770: ("authentication.kerberos.service_ticket.renewed",), 4773: ("authentication.kerberos.service_ticket.failed",),
    4720: ("directory.account.created",), 4722: ("directory.account.enabled",),
    4725: ("directory.account.disabled",), 4726: ("directory.account.deleted",),
    4738: ("directory.account.changed",), 4781: ("directory.account.renamed",),
    4723: ("account.password.changed.succeeded", "account.password.change.attempted"),
    4724: ("account.password.reset.succeeded", "account.password.reset.attempted"),
    4728: ("group.member.added",), 4732: ("group.member.added",), 4756: ("group.member.added",),
    4729: ("group.member.removed",), 4733: ("group.member.removed",), 4757: ("group.member.removed",),
}


def effective_severity(base):
    """One step, capped at critical; confidence is deliberately unchanged."""
    if base not in SEVERITIES:
        raise ValueError("account_watch_severity_invalid")
    return SEVERITIES[min(SEVERITIES.index(base) + 1, len(SEVERITIES) - 1)]


def family(row):
    semantic = row["semantic_type"]
    if semantic not in EVENT_TYPES.get(row["event_id"], ()):
        return None
    return "authentication" if semantic.startswith("authentication.") else "directory"


@dataclass(frozen=True, repr=False, kw_only=True)
class WatchRule:
    scope: EvidenceScope
    policy_revision: int = 1
    evaluation_mode: str = "shadow"
    processing_mode: str = "live"

    def __post_init__(self):
        if (not isinstance(self.scope, EvidenceScope) or self.scope.plugin_id != "sli.windows.ad-dc"
                or self.scope.collection_scope_id
                or type(self.policy_revision) is not int or not 0 < self.policy_revision < 2**31
                or self.evaluation_mode not in ("test", "shadow", "enabled")
                or self.processing_mode not in ("live", "historical_replay", "history_import")):
            raise ValueError("account_watch_rule_invalid")

    @property
    def rule_sha256(self):
        return _digest({"version": 1, "roles": ROLES, "events": EVENT_TYPES,
                        "window_seconds": 300, "severity": "one-step", "registry": "watch_entry_versions"})

    @property
    def execution(self):
        return {"version": "sli.qw.execution.v1", "kind": "watch", "rule_id": RULE_ID,
                "rule_version": 1, "rule_sha256": self.rule_sha256, "scope": asdict(self.scope)}

    @property
    def checkpoint_key(self):
        return _digest(asdict(self))


def validate_context(value):
    try:
        valid = (isinstance(value, dict) and set(value) == {
            "entry_id", "entry_revision", "normalized_event_id", "source_event_id", "identity_sha256", "family"}
            and str(UUID(value["entry_id"])) == value["entry_id"]
            and str(UUID(value["normalized_event_id"])) == value["normalized_event_id"]
            and type(value["entry_revision"]) is int and 0 < value["entry_revision"] < 2**53
            and type(value["source_event_id"]) is int and value["source_event_id"] > 0
            and value["family"] in ("authentication", "directory")
            and isinstance(value["identity_sha256"], str) and len(value["identity_sha256"]) == 64
            and all(c in "0123456789abcdef" for c in value["identity_sha256"]))
    except (ValueError, TypeError, KeyError, AttributeError):
        valid = False
    if not valid:
        raise ValueError("account_watch_context_invalid")


def evaluate(rule, row, *, now):
    """Only a bound native reader supplies historical identities and revisions."""
    now, occurred = utc(now), utc(row["occurred_at_utc"])
    event_family = family(row)
    if event_family is None or occurred > now:
        return (), "not_applicable"
    entries, identities = row["entries"], row["identities"]
    if len(entries) > 128 or len(identities) > 256:
        raise ValueError("account_watch_identity_limit")
    matched = {}
    for role in ROLES:
        key = row["roles_json"].get(role)
        metadata = row["quality_json"].get("identity_roles", {}).get(role, {})
        candidates = [item for item in identities if item["role"] == role and item["key"] == key]
        if (not key or metadata.get("key") != key or metadata.get("state") != "resolved"
                or metadata.get("provisional") is not False or len(candidates) != 1):
            continue
        identity = candidates[0]["identity"]
        if key not in ("sid:" + identity["sid"], "guid:" + identity["guid"]):
            continue
        for entry in entries:
            if (entry["identity"] == identity and entry["active"] is True
                    and utc(entry["active_from"]) <= occurred < utc(entry["expires_at"])
                    and utc(entry["valid_from"]) <= occurred
                    and (entry["valid_to"] is None or occurred < utc(entry["valid_to"]))):
                matched[(str(entry["id"]), entry["revision"])] = entry
    signals = []
    for entry in matched.values():
        context = {"entry_id": str(entry["id"]), "entry_revision": entry["revision"],
                   "normalized_event_id": str(row["normalized_event_id"]),
                   "source_event_id": row["source_event_id"],
                   "identity_sha256": _digest(entry["identity"]), "family": event_family}
        validate_context(context)
        from server.sli.semantic.event_card_semantics import build_event_card

        base = build_event_card(row["event_item"])["final_security_severity"]
        entity_key = _digest([asdict(rule.scope), entry["identity"]])
        # Event-time UTC buckets are stable across restarts and arrival order.
        bucket = occurred.replace(minute=occurred.minute // 5 * 5, second=0, microsecond=0)
        signals.append(QWSignal(kind="watch", rule_id=RULE_ID, rule_version=1,
            rule_sha256=rule.rule_sha256, policy_revision=rule.policy_revision,
            evaluation_mode=rule.evaluation_mode, entity_key=entity_key,
            episode_key=_digest([entity_key, event_family, bucket.isoformat(), (bucket + timedelta(minutes=5)).isoformat()]),
            occurred_at_utc=occurred, received_at_utc=now,
            evidence_refs=(EvidenceRef("core_event", str(row["source_event_id"]), row["sha256"], rule.scope),),
            base_severity=base, effective_severity=effective_severity(base), severity_reasons=("watch",),
            watch_context=context, processing_mode=rule.processing_mode))
    return tuple(signals), "observed" if signals else "no_match"


def risk_policy(rule, *, policy_id):
    """Draft admission caps this rule at critical; native input sets actual risk."""
    from server.sli.semantic.semantic_risk import ScenarioSourceKind
    from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition

    return RiskPolicyDefinition(policy_id=policy_id, policy_version=rule.policy_revision,
        source_kind=ScenarioSourceKind.QW_SIGNAL, definition={
            "type": "scenario_policy", "source_selector": {"rule_id": RULE_ID, "execution": rule.execution},
            "scenario_kind": RULE_ID, "result_class": "security_incident",
            "merge_window_seconds": 300, "expected_evidence_count": 1,
            "title": "Activity of an account under watch",
            "explanation": "Exact event-time account watch raises the source event severity by one level.",
            "risk": {"class": "critical", "raw_score": "80", "display_points": 80,
                     "rationale": "Account watch is priority context, not additional evidence of compromise."}})
