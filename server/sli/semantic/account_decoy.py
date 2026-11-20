"""D02: exact, event-time account decoys over admitted authentication evidence."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from uuid import UUID

from server.sli.semantic.qw_input import QWSignal, _digest
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope

RULE_ID = "qw.account-decoy"
AUTHENTICATION = {
    4624: "authentication.session.created",
    4625: "authentication.session.failed",
    4768: "authentication.kerberos.tgt.requested",
    4769: "authentication.kerberos.service_ticket.requested",
    4771: "authentication.kerberos.preauthentication.failed",
    4776: "authentication.credentials.validated",
}


def utc(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("account_decoy_time_invalid")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, repr=False, kw_only=True)
class DecoyRule:
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
            raise ValueError("account_decoy_rule_invalid")

    @property
    def rule_sha256(self):
        return _digest({"version": 1, "authentication": AUTHENTICATION,
                        "identity": "event-time-directory-version", "labels": "decoy_label_versions"})

    @property
    def execution(self):
        return {"version": "sli.qw.execution.v1", "kind": "decoy", "rule_id": RULE_ID,
                "rule_version": 1, "rule_sha256": self.rule_sha256, "scope": asdict(self.scope)}

    @property
    def checkpoint_key(self):
        document = asdict(self)
        if self.processing_mode == "live":
            document.pop("processing_mode")
        return _digest(document)


def validate_context(value):
    try:
        valid = (isinstance(value, dict)
                 and set(value) == {"label_id", "label_revision", "normalized_event_id", "identity_sha256"}
                 and str(UUID(value["label_id"])) == value["label_id"]
                 and str(UUID(value["normalized_event_id"])) == value["normalized_event_id"]
                 and type(value["label_revision"]) is int and 0 < value["label_revision"] < 2**53
                 and isinstance(value["identity_sha256"], str) and len(value["identity_sha256"]) == 64
                 and all(c in "0123456789abcdef" for c in value["identity_sha256"]))
    except (ValueError, TypeError, KeyError, AttributeError):
        valid = False
    if not valid:
        raise ValueError("account_decoy_context_invalid")


def evaluate(rule, row, *, now):
    """Only the capability reader supplies temporal identities and scoped labels.

    A provisional name is never promoted by its spelling alone. Both the
    historical directory match and the active label must identify one object.
    Readiness is not a veto: an observed touch is high even with partial audit.
    """
    now, occurred = utc(now), utc(row["occurred_at_utc"])
    if AUTHENTICATION.get(row["event_id"]) != row["semantic_type"] or occurred > now:
        return (), "not_applicable"
    labels, identities = row["labels"], row["identities"]
    if len(labels) > 128 or len(identities) > 256:
        raise ValueError("account_decoy_identity_limit")
    refs = (EvidenceRef("core_event", str(row["source_event_id"]), row["sha256"], rule.scope),)
    matched, review = {}, False
    for role in ("actor", "affected_entity"):
        key = row["roles_json"].get(role)
        metadata = row["quality_json"].get("identity_roles", {}).get(role, {})
        if not key or metadata.get("key") != key:
            continue
        exact = metadata.get("state") == "resolved" and metadata.get("provisional") is False
        fallback = (row["event_id"] == 4625 and key.startswith("sam:")
                    and metadata.get("state") == "provisional" and metadata.get("provisional") is True)
        candidates = [item for item in identities if item["role"] == role and item["key"] == key]
        for label in labels:
            if (label["kind"] != "account" or label["active"] is not True
                    or utc(label["active_from"]) > occurred
                    or label["active_to"] is not None and occurred >= utc(label["active_to"])):
                continue
            identity = label["identity"]
            matching = [item for item in candidates if item["identity"] == identity]
            if not matching:
                continue
            if len(candidates) != 1 or not (exact or fallback):
                review = True
                continue
            # The SQL reader checks the same values; retain the invariant in
            # the pure detector so accidental adapter broadening fails closed.
            if exact and key not in ("sid:" + identity["sid"], "guid:" + identity["guid"]):
                review = True
                continue
            matched[(label["id"], label["revision"])] = label
    signals = []
    for label in matched.values():
        context = {"label_id": str(label["id"]), "label_revision": label["revision"],
                   "normalized_event_id": str(row["normalized_event_id"]),
                   "identity_sha256": _digest(label["identity"])}
        validate_context(context)
        entity_key = _digest([asdict(rule.scope), label["identity"]])
        signals.append(QWSignal(kind="decoy", rule_id=RULE_ID, rule_version=1,
            rule_sha256=rule.rule_sha256, policy_revision=rule.policy_revision,
            evaluation_mode=rule.evaluation_mode, entity_key=entity_key,
            episode_key=_digest([context["label_id"], context["label_revision"], refs[0].params]),
            occurred_at_utc=occurred, received_at_utc=now, evidence_refs=refs,
            base_severity="high", effective_severity="high", severity_reasons=("decoy_authentication",),
            decoy_context=context, processing_mode=rule.processing_mode))
    return tuple(signals), "observed" if signals else "requires_review" if review else "no_match"


def risk_policy(rule, *, policy_id):
    """Draft only: administrator source binding and ENABLED admission are required."""
    from server.sli.semantic.semantic_risk import ScenarioSourceKind
    from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition

    return RiskPolicyDefinition(policy_id=policy_id, policy_version=rule.policy_revision,
        source_kind=ScenarioSourceKind.QW_SIGNAL, definition={
            "type": "scenario_policy", "source_selector": {"rule_id": RULE_ID, "execution": rule.execution},
            "scenario_kind": RULE_ID, "result_class": "security_incident",
            "merge_window_seconds": 1, "expected_evidence_count": 1,
            "title": "Registered decoy account used",
            "explanation": "Authentication evidence identifies an account labelled as a decoy at event time.",
            "risk": {"class": "high", "raw_score": "60", "display_points": 60,
                     "rationale": "Any observed use of a registered decoy requires investigation."},
        })
