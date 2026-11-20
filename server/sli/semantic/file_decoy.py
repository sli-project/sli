"""D03: exact file decoys over admitted observations, before activity filters."""
from dataclasses import asdict, dataclass
from datetime import timedelta
import ntpath
from uuid import UUID

from server.sli.plugins.file_audit.correlation import delete_context
from server.sli.semantic.account_decoy import utc
from server.sli.semantic.qw_input import QWSignal, _digest, _hash
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope
from sli_agent.file_audit_policy import local_path

RULE_ID = "qw.file-decoy"
EVENTS = (4656, 5145, 4663, 4660, 4670)
MEANINGS = ("access_check", "access_denied", "read", "file_action", "deleted", "permissions_changed")


@dataclass(frozen=True, repr=False, kw_only=True)
class FileDecoyRule:
    scope: EvidenceScope
    agent_id: str
    policy_revision: int = 1
    evaluation_mode: str = "shadow"
    processing_mode: str = "live"

    def __post_init__(self):
        try:
            valid_agent = str(UUID(self.agent_id)) == self.agent_id
        except (ValueError, TypeError, AttributeError):
            valid_agent = False
        if (not isinstance(self.scope, EvidenceScope) or self.scope.plugin_id != "sli.file-audit"
                or not self.scope.collection_scope_id or not valid_agent
                or type(self.policy_revision) is not int or not 0 < self.policy_revision < 2**31
                or self.evaluation_mode not in ("test", "shadow", "enabled")
                or self.processing_mode not in ("live", "historical_replay", "history_import")):
            raise ValueError("file_decoy_rule_invalid")

    @property
    def rule_sha256(self):
        return _digest({"version": 1, "agent_id": self.agent_id, "events": EVENTS,
                        "identity": "exact-event-time-path", "session_window_seconds": 300})

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
        valid = (isinstance(value, dict) and set(value) == {
            "label_id", "label_revision", "identity_sha256", "observation_key", "agent_id", "meaning", "outcome"}
            and str(UUID(value["label_id"])) == value["label_id"]
            and str(UUID(value["agent_id"])) == value["agent_id"]
            and type(value["label_revision"]) is int and 0 < value["label_revision"] < 2**53
            and _hash(value["identity_sha256"]) and _hash(value["observation_key"])
            and value["meaning"] in MEANINGS and value["outcome"] in ("success", "failure"))
    except (KeyError, TypeError, ValueError, AttributeError):
        valid = False
    if not valid:
        raise ValueError("file_decoy_context_invalid")


def _in_source(rule, obs):
    return (obs["agent_id"] == rule.agent_id and obs["source_instance_id"] == rule.scope.source_instance_id
            and obs["generation"] == rule.scope.source_generation)


def touch(rule, row):
    """Keep native meaning. A successful access check is never a completed read."""
    obs = row["observation"]
    facts, event = obs["facts"], obs["event_id"]
    if (not _in_source(rule, obs) or event not in EVENTS or facts.get("outcome") not in ("success", "failure")
            or str(facts.get("object_type", "File")).casefold() != "file"):
        return None
    chosen, witnesses = obs, [obs]
    if event == 4660:
        contexts = row["contexts"]
        if len(contexts) > 128:
            raise ValueError("file_decoy_context_limit")
        state, chosen = delete_context(obs, contexts)
        if state != "complete" or chosen is None:
            return None
        witnesses.append(chosen)
    if not chosen["path"] or rule.scope.collection_scope_id not in {
            scope["collection_scope_id"] for scope in chosen["scopes"]}:
        return None
    if str(chosen["facts"].get("object_type", "File")).casefold() != "file":
        return None
    try:
        path = ntpath.normcase(local_path(chosen["path"]))
    except ValueError:
        return None
    if facts["outcome"] == "failure":
        if event not in (4656, 5145):
            return None
        meaning = "access_denied"
    elif event in (4656, 5145):
        meaning = "access_check"
    elif event == 4660:
        meaning = "deleted"
    elif event == 4670:
        meaning = "permissions_changed"
    else:
        meaning = "read" if facts.get("access_mask", 0) & 1 and facts.get("object_type", "").casefold() == "file" else "file_action"
    return path, meaning, tuple(witnesses)


def evaluate(rule, row, *, now):
    now, obs = utc(now), row["observation"]
    occurred = utc(obs["observed_at"])
    touched = touch(rule, row)
    if occurred > now or touched is None:
        return (), "not_applicable"
    path, meaning, witnesses = touched
    labels = row["labels"]
    if len(labels) > 128:
        raise ValueError("file_decoy_label_limit")
    refs = tuple(EvidenceRef("file_audit_observation", item["evidence_key"], item["payload_sha256"], rule.scope)
                 for item in witnesses)
    identity = {"agent_id": rule.agent_id, "source_instance_id": rule.scope.source_instance_id,
                "collection_scope_id": rule.scope.collection_scope_id, "path": path}
    signals = []
    for label in labels:
        if (label["kind"] != "file" or label["identity"] != identity or label["active"] is not True
                or utc(label["active_from"]) > occurred
                or label["active_to"] is not None and occurred >= utc(label["active_to"])):
            continue
        context = {"label_id": str(label["id"]), "label_revision": label["revision"],
                   "identity_sha256": _digest(identity), "observation_key": obs["evidence_key"],
                   "agent_id": rule.agent_id, "meaning": meaning, "outcome": obs["facts"]["outcome"]}
        facts = obs["facts"]
        session = [facts.get(key) for key in ("subject_user_sid", "logon_id_numeric", "server_process_id", "handle_id")]
        # A handle groups its bounded witnesses, never an unbounded logon or a
        # missing identity. Independent no-handle checks remain separate touches.
        group = [session, int(occurred.timestamp()) // 300] if all(session) else obs["evidence_key"]
        signals.append(QWSignal(kind="decoy", rule_id=RULE_ID, rule_version=1, rule_sha256=rule.rule_sha256,
            policy_revision=rule.policy_revision, evaluation_mode=rule.evaluation_mode,
            entity_key=_digest([asdict(rule.scope), identity]),
            episode_key=_digest([asdict(rule.scope), label["id"], label["revision"], group]),
            occurred_at_utc=occurred, received_at_utc=now, evidence_refs=refs,
            base_severity="high", effective_severity="high", severity_reasons=("decoy_file_touch",),
            file_decoy_context=context, processing_mode=rule.processing_mode))
    return tuple(signals), "observed" if signals else "no_match"


def risk_policy(rule, *, policy_id):
    """Draft only; normal source binding and ENABLED admission still apply."""
    from server.sli.semantic.semantic_risk import ScenarioSourceKind
    from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition

    return RiskPolicyDefinition(policy_id=policy_id, policy_version=rule.policy_revision,
        source_kind=ScenarioSourceKind.QW_SIGNAL, definition={
            "type": "scenario_policy", "source_selector": {"rule_id": RULE_ID, "execution": rule.execution},
            "scenario_kind": RULE_ID, "result_class": "security_incident",
            "merge_window_seconds": int(timedelta(minutes=5).total_seconds()), "expected_evidence_count": 1,
            "title": "Registered decoy file touched",
            "explanation": "Native file audit evidence identifies a file labelled as a decoy at event time.",
            "risk": {"class": "high", "raw_score": "60", "display_points": 60,
                     "rationale": "Any observed touch of a registered decoy requires investigation."},
        })
