"""Connection-owned password-v2 producer for managed and standalone callers.

Working classification/completeness is the trusted Python boundary. Current SQL
source authority, reservations, queue guards and deferred COMMIT remain binding.
No connection is opened here and no native result survives a producer attempt.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, replace
from datetime import timedelta

from server.sli.semantic import password_attack_v2 as pure
from server.sli.semantic import password_attack_policy as managed_policies
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition
from server.sli.semantic.password_attack_v2_portions import (
    contexts_from_emission,
    reassemble,
)
from server.sli.semantic.qw_input import QWSignal
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope

VERSION = "sli.password.v2.producer-batch.1"
_WINDOW_KEYS = frozenset(("version", "read_from", "read_to", "finalizable_through", "candidate_count",
    "truncated", "native_checked_count", "native_checks_complete", "unverifiable_count", "oversized_count", "error_code"))
_LOSS_CODES = frozenset(("too_late", "coverage_gap", "episode_evidence_budget_exhausted", "missing_target",
    "unclassified_failure", "ambiguous_failure", "conflicting_client", "missing_client"))


class ProducerFailure(RuntimeError):
    """Fixed, non-identifying failure code only."""


class ProducerConnectionFatal(ValueError):
    """Uncertain caller-owned connection: the production owner must close it."""


def require_password_connection_idle(conn):
    try:
        idle = not getattr(conn, "closed", False) and conn.info.transaction_status == 0
    except Exception:  # noqa: BLE001 -- an unreadable connection is not known IDLE.
        idle = False
    if not idle:
        raise ProducerConnectionFatal("password_v2_connection_not_idle") from None


@dataclass(frozen=True)
class ProducerOutcome:
    jobs: int = 0
    failed: bool = True
    status: str = "failed"
    revision: int | None = None
    health: dict = field(default_factory=dict)
    failure_observed: bool = False
    work: dict = field(default_factory=dict)


def _json(value):
    return json.dumps(pure._pack(value), sort_keys=True, ensure_ascii=True, allow_nan=False)


def _call(cur, name, *args):
    signatures = {
        "begin_password_attempt": ("jsonb", "jsonb"),
        "read_password_checkpoint_v2": ("jsonb", "jsonb"),
        "prepare_password_producer_batch_v2": ("jsonb", "jsonb", "bigint", "bigint", "text[]"),
        "reserve_password_episode_emission": ("jsonb", "jsonb", "bigint", "bigint", "jsonb", "jsonb"),
        "track_password_frozen_entity_v2": ("jsonb", "jsonb", "bigint", "bigint", "text", "jsonb", "bigint", "timestamptz", "timestamptz"),
        "complete_password_producer_batch_v2": ("jsonb", "jsonb", "bigint", "bigint", "text", "jsonb"),
        "observe_password_failure_v2": ("jsonb", "jsonb", "bigint", "jsonb"),
    }
    types = signatures[name]
    if len(types) != len(args):
        raise ValueError("password_v2_call_invalid")
    cur.execute("select public." + name + "(" + ",".join("%s::" + t for t in types) + ") as result",
        tuple(_json(a) if t == "jsonb" and a is not None else a for a, t in zip(args, types)))
    row = cur.fetchone()
    if not row or "result" not in row:
        raise ProducerFailure("password_v2_storage_unavailable")
    return row["result"]


def _managed_admission(cur, rule, policy):
    expected = managed_policies.risk_policy(rule)
    if (type(policy) is not RiskPolicyDefinition or policy.policy_id != expected.policy_id
            or type(policy.policy_version) is not int or policy.policy_version != expected.policy_version
            or type(policy.source_kind) is not type(expected.source_kind)
            or policy.source_kind != expected.source_kind or policy.definition_json != expected.definition_json):
        raise ProducerFailure("password_v2_managed_policy_invalid")
    # Existing public wire: SQL275 independently proves the canonical definition,
    # locks family/policy then source, and freshly checks issued authority/domain.
    # Only its explicit boolean false is a confirmed intentional disable.
    cur.execute("select public.ensure_default_qw_policy(%s,%s,%s) as enabled",
                (policy.policy_id, policy.policy_version, policy.definition_json))
    decision = (cur.fetchone() or {}).get("enabled")
    if type(decision) is not bool:
        raise ProducerFailure("password_v2_policy_unconfirmed")
    return decision


def run_password_producer(conn, *, rule: pure.Rule,
                          managed_policy: RiskPolicyDefinition | None = None) -> ProducerOutcome:
    """Own TxA/TxB/TxC on a caller-supplied IDLE dict-row psycopg connection.

    None retains standalone admission. A managed decision is the first TxB
    statement; its family/policy/source locks survive until outer COMMIT.
    The caller supplies the normal least-privilege semantic-worker connection;
    this entry never opens a connection or changes source identity/privileges.
    Only an outer successful COMMIT makes returned jobs count as committed.
    """
    require_password_connection_idle(conn)
    if type(rule) is not pure.Rule:
        raise ValueError("password_v2_rule_invalid")
    scope, execution = asdict(rule.scope), rule.execution
    try:
        with conn.transaction(), conn.cursor() as cur:
            attempt = _call(cur, "begin_password_attempt", scope, execution)
            if (type(attempt) is not dict or type(attempt.get("token")) is not int
                    or attempt["token"] <= 0 or type(attempt.get("state_revision")) is not int
                    or attempt["state_revision"] < 0):
                raise ProducerFailure("password_v2_attempt_invalid")
            pure._utc(attempt["attempted_at"])
    except ProducerConnectionFatal:
        raise
    except Exception:  # noqa: BLE001 -- issuance/COMMIT failure is not a successful attempt.
        require_password_connection_idle(conn)
        return ProducerOutcome()
    require_password_connection_idle(conn)
    try:
        with conn.transaction(), conn.cursor() as cur:
            enabled = managed_policy is None or _managed_admission(cur, rule, managed_policy)
            if enabled:
                completed, jobs, work = _batch(cur, rule, attempt)
        require_password_connection_idle(conn)
        if not enabled:
            return ProducerOutcome(failed=False, status="disabled")
        return ProducerOutcome(jobs, False, "committed", completed["revision"], completed["health"], False, work)
    except ProducerConnectionFatal:
        raise
    except Exception:  # noqa: BLE001 -- includes driver and deferred COMMIT errors; never leak source contents.
        # A context must have restored known IDLE before this connection can
        # observe the same committed token. Otherwise its owner must close it.
        require_password_connection_idle(conn)
        observed = False
        try:
            with conn.transaction(), conn.cursor() as cur:
                observed = _call(cur, "observe_password_failure_v2", scope, execution, attempt["token"],
                    {"source_error": {"count": 1, "from": None, "to": None}}) is True
        except ProducerConnectionFatal:
            raise
        except Exception:  # noqa: BLE001 -- TxC cannot turn the original failure into success.
            observed = False
        require_password_connection_idle(conn)
        return ProducerOutcome(failure_observed=observed)


def _window_metadata(document, *, attempted_at):
    if type(document) is not dict or document.keys() != _WINDOW_KEYS:
        raise ProducerFailure("password_v2_window_invalid")
    result = dict(document)
    for name in ("candidate_count", "native_checked_count", "unverifiable_count", "oversized_count"):
        if type(result[name]) is not int or not 0 <= result[name] <= pure.MAX_ROWS:
            raise ProducerFailure("password_v2_window_invalid")
    if (result["version"] != "sli.password.v2.window.1" or result["truncated"] is not False
            or result["native_checks_complete"] is not True or result["error_code"] is not None
            or result["native_checked_count"] != result["candidate_count"]
            or result["unverifiable_count"] or result["oversized_count"]):
        raise ProducerFailure("password_v2_window_incomplete")
    try:
        stamps = {name: pure._utc(result[name]) for name in ("read_from", "read_to", "finalizable_through")}
        if (stamps["read_to"] < pure._utc(attempted_at)
                or stamps["read_from"] != stamps["read_to"] - timedelta(seconds=pure.HORIZON)
                or stamps["finalizable_through"] != stamps["read_to"] - timedelta(seconds=pure.HOLDBACK)):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise ProducerFailure("password_v2_window_invalid") from None
    result.update({name: stamp.isoformat() for name, stamp in stamps.items()})
    return result


class NativeBudget:
    """One attempt-local current native set, with reject-only commitment planning."""
    def __init__(self, events=()):
        self.records = {}
        self.count = self.xml_bytes = self.retained_reads = self.reservation_occurrences = 0
        self.reservation_calls = self.tracking_calls = self.completion_calls = 0
        for native in events:
            self.add(native)

    def add(self, native, expected=None):
        witness = native.member.witness
        if expected is not None and witness != expected:
            raise ProducerFailure("password_v2_native_content_conflict")
        identity = (native.ref.scope, native.ref.native_id)
        old = self.records.get(identity)
        if old is not None:
            if native != old:
                raise ProducerFailure("password_v2_native_content_conflict")
            return
        length = len(native.source_xml.encode("utf-8"))
        if length > 4194304 or self.count + 1 > pure.MAX_ROWS or self.xml_bytes + length > pure.MAX_XML_BYTES:
            raise ProducerFailure("password_v2_proof_bound")
        self.records[identity] = native
        self.count += 1
        self.xml_bytes += length

    def plan(self, witnesses):
        missing = {}
        for witness in witnesses:
            identity = (witness.ref.scope, witness.ref.native_id)
            old = self.records.get(identity)
            if old is not None:
                if old.member.witness != witness:
                    raise ProducerFailure("password_v2_native_content_conflict")
            elif identity in missing and missing[identity] != witness:
                raise ProducerFailure("password_v2_native_content_conflict")
            else:
                missing[identity] = witness
        if (self.count + len(missing) > pure.MAX_ROWS
                or self.xml_bytes + sum(w.xml_bytes for w in missing.values()) > pure.MAX_XML_BYTES):
            raise ProducerFailure("password_v2_proof_bound")
        return tuple(missing.values())

    def fetch(self, cur, scope, witnesses):
        missing = self.plan(witnesses)
        if not missing:
            return
        cur.execute("select * from public.read_password_retained_proof_v2(%s::jsonb,%s::jsonb)",
                    (_json(asdict(scope)), _json([asdict(w) for w in missing])))
        rows = cur.fetchall()
        self.retained_reads += 1
        if len(rows) != len(missing):
            raise ProducerFailure("password_v2_native_unavailable")
        for index, (row, witness) in enumerate(zip(rows, missing), 1):
            if (type(row.get("occurrence_index")) is not int or row["occurrence_index"] != index
                    or type(row.get("source_event_id")) is not int
                    or str(row["source_event_id"]) != witness.ref.native_id):
                raise ProducerFailure("password_v2_native_unavailable")
            native = pure.NativeEvent.from_row(scope, row)
            if (type(row.get("xml_bytes")) is not int or row["xml_bytes"] != native.member.witness.xml_bytes
                    or row.get("xml_sha256") != native.member.witness.xml_sha256):
                raise ProducerFailure("password_v2_native_content_conflict")
            self.add(native, witness)

    def native(self, witness):
        result = self.records.get((witness.ref.scope, witness.ref.native_id))
        if result is None or result.member.witness != witness:
            raise ProducerFailure("password_v2_native_unavailable")
        return result

    @property
    def work(self):
        return {"native_items": self.count, "xml_bytes": self.xml_bytes, "retained_queries": self.retained_reads,
                    "reservation_occurrences": self.reservation_occurrences, "window_queries": 1,
                    "reservation_calls": self.reservation_calls, "tracking_calls": self.tracking_calls,
                    "completion_calls": self.completion_calls}


def _signal(document):
    document = dict(document)
    refs = tuple(EvidenceRef(**(ref | {"scope": EvidenceScope(**ref["scope"])}))
                 for ref in document.pop("evidence_refs"))
    document["severity_reasons"] = tuple(document["severity_reasons"])
    for name in ("occurred_at_utc", "received_at_utc"):
        document[name] = pure._utc(document[name])
    return QWSignal(**document, evidence_refs=refs)


def _history(cur, rule, episode):
    cur.execute("select signal_id,document_json from public.read_password_episode_portions_v2(%s::jsonb,%s::jsonb,%s)",
                (_json(asdict(rule.scope)), _json(rule.execution), episode.key))
    rows = cur.fetchall()
    if not rows or len(rows) > pure.MAX_PORTIONS:
        raise ProducerFailure("password_v2_chain_unavailable")
    emissions, contexts = [], []
    for row in rows:
        item = _signal(row["document_json"])
        context = item.password_context
        if (item.signal_id != row["signal_id"] or item.execution != rule.execution or item.episode_key != episode.key
                or context["sequence"] != len(emissions) + 1 or context["portion_index"] != len(contexts)):
            raise ProducerFailure("password_v2_chain_invalid")
        contexts.append(context)
        if len(contexts) == context["portion_total"]:
            emissions.append(reassemble(rule.scope, tuple(contexts)))
            contexts = []
    if (contexts or emissions[-1].emission_id != episode.last_emission
            or emissions[-1].sequence != episode.sequence or emissions[0].emission_id != episode.root_id):
        raise ProducerFailure("password_v2_chain_invalid")
    return tuple(emissions)


def _barrier_episode(barrier):
    return pure.Episode(barrier["episode_key"], barrier["entity"], pure._witness(barrier["seed"]),
        pure._witness(barrier["tracking_endpoint"]), barrier["root_id"], barrier["last_emission_id"],
        barrier["last_sequence"], pure.Budget(**barrier["totals"]), True)


def _successor_allowed(barrier, seed, epoch, lower):
    endpoint = pure._witness(barrier["tracking_endpoint"])
    through = pure._utc(barrier["tracking_through"])
    return (barrier["tracking_epoch"] == epoch and lower <= through
            and seed.at > endpoint.at + timedelta(seconds=pure.WINDOW))


def _signals(rule, emission, root_id, observed_at):
    return tuple(QWSignal(kind="threshold", rule_id=rule.execution["rule_id"], rule_version=2,
        rule_sha256=rule.execution["rule_sha256"], policy_revision=1, evaluation_mode="enabled",
        entity_key=emission.entity, episode_key=emission.episode_key, occurred_at_utc=emission.endpoint.at,
        received_at_utc=observed_at, evidence_refs=tuple(w.ref for w in portion),
        base_severity="high", effective_severity="high", evidence_total=len(emission.occurrences),
        password_context=context) for context, portion in zip(
            contexts_from_emission(emission, original_root_id=root_id), emission.ref_portions))


def _complete(cur, rule, attempt, mode, payload):
    result = _call(cur, "complete_password_producer_batch_v2", asdict(rule.scope), rule.execution,
                   attempt["token"], attempt["state_revision"], mode, payload)
    if (type(result) is not dict or result.get("status") != "staged"
            or type(result.get("revision")) is not int or result["revision"] != attempt["state_revision"] + 1
            or type(result.get("health")) is not dict):
        raise ProducerFailure("password_v2_completion_invalid")
    return result


def _enqueue_all(cur, signals):
    """Queue through the existing050 semantic privileges on this same cursor."""
    if not signals:
        return 0
    from server.sli.semantic.semantic_risk import ScenarioSourceKind
    from server.sli.semantic.semantic_risk_runtime_repository import _enqueue_source
    return sum(len(_enqueue_source(cur, source_kind=ScenarioSourceKind.QW_SIGNAL, source_id=signal.signal_id))
               for signal in signals)


def _batch(cur, rule, attempt):
    scope, execution = asdict(rule.scope), rule.execution
    checkpoint = _call(cur, "read_password_checkpoint_v2", scope, execution)
    if (checkpoint["active_token"] != attempt["token"] or checkpoint["last_observed_token"] >= attempt["token"]
            or checkpoint["state_revision"] != attempt["state_revision"]):
        raise ProducerFailure("password_v2_attempt_conflict")
    state = pure.State.from_document(checkpoint["state_document"]) if checkpoint["state_document"] else pure.State()
    cur.execute("select * from public.read_default_password_window_v2(%s::jsonb)", (_json(scope),))
    rows = cur.fetchall()
    if not rows or rows[0].get("record_kind") != "metadata":
        raise ProducerFailure("password_v2_window_invalid")
    window = _window_metadata(rows[0]["metadata"], attempted_at=attempt["attempted_at"])
    if len(rows) - 1 != window["candidate_count"] or any(row.get("record_kind") != "event" for row in rows[1:]):
        raise ProducerFailure("password_v2_window_invalid")
    incoming = tuple(pure.NativeEvent.from_row(rule.scope, row) for row in rows[1:])
    budget = NativeBudget(incoming)
    if budget.count != len(incoming):
        raise ProducerFailure("password_v2_window_invalid")
    now, lower, final = (pure._utc(window[key]) for key in ("read_to", "read_from", "finalizable_through"))
    if any(not lower <= native.at <= now for native in incoming):
        raise ProducerFailure("password_v2_window_invalid")
    if state.watermark is not None and final < state.watermark:
        raise ProducerFailure("password_v2_clock_regression")
    entities = sorted({e.entity for e in state.episodes} | {m.entity(rule) for m in state.window if m.entity(rule)}
                      | {n.member.entity(rule) for n in incoming if n.member.entity(rule)})
    context = _call(cur, "prepare_password_producer_batch_v2", scope, execution,
                    attempt["token"], attempt["state_revision"], entities)
    if (context.get("status") != "prepared" or context.get("state_revision") != attempt["state_revision"]
            or type(context.get("barriers")) is not list or len(context["barriers"]) > pure.MAX_ROWS
            or len(_json(context).encode()) > 4194304):
        raise ProducerFailure("password_v2_context_invalid")
    prelocked = context.get("prelocked_entities")
    if (type(prelocked) is not list or len(prelocked) > pure.MAX_ROWS or prelocked != sorted(set(prelocked))
            or any(type(e) is not str or len(e) != 64 or any(c not in "0123456789abcdef" for c in e) for e in prelocked)
            or not set(entities) <= set(prelocked)):
        raise ProducerFailure("password_v2_context_invalid")
    barriers = {b["entity"]: b for b in context["barriers"]}
    if len(barriers) != len(context["barriers"]) or not barriers.keys() <= set(prelocked):
        raise ProducerFailure("password_v2_context_invalid")
    episodes = {e.entity: e for e in state.episodes}
    for entity, barrier in barriers.items():
        frozen = _barrier_episode(barrier)
        if frozen.sequence <= 0:
            raise ProducerFailure("password_v2_frozen_zero_unsupported")
        old = episodes.get(entity)
        if old is None or old.key == frozen.key:
            episodes[entity] = frozen
    working = replace(state, episodes=tuple(episodes[e] for e in sorted(episodes)))
    pending = [n.member for n in incoming] + list(state.window)
    affected = {m.entity(rule) for m in pending if m.entity(rule) and m.witness.at <= final
                and (state.watermark is None or m.witness.at > state.watermark)}
    needed, histories = [], []
    for entity, barrier in barriers.items():
        needed.extend((pure._witness(barrier["seed"]), pure._witness(barrier["tracking_endpoint"])))
    # Normal completion revalidates ALL preserved working commitments, including
    # inactive episodes outside the current reader window. They belong to this
    # SAME preflight, not a separate finalizer/episode proof allowance. Whole
    # immutable history is still needed only for affected qualified episodes.
    for episode in working.episodes:
        needed.extend((episode.seed, episode.last, *episode.prequalification))
    needed.extend(m.witness for m in state.window if m.witness.at >= lower)
    for episode in working.episodes:
        if episode.entity not in affected:
            continue
        if episode.frozen:
            continue
        if episode.root_id is not None and not (state.watermark and lower > state.watermark):
            new = [m.witness for m in pending if m.entity(rule) == episode.entity and m.witness.at <= final
                   and (state.watermark is None or m.witness.at > state.watermark)]
            if new and min(w.at for w in new) - episode.last.at <= timedelta(seconds=pure.WINDOW):
                chain = _history(cur, rule, episode)
                histories.extend(chain)
                needed.extend(w for emission in chain for w in emission.occurrences)
    needed.extend(m.witness for m in state.window if m.entity(rule) in affected)
    try:
        budget.plan(needed)
    except ProducerFailure as error:
        if str(error) != "password_v2_proof_bound":
            raise
        denied = _qualified_denial(cur, rule, attempt, state, incoming, budget, final)
        if denied is not None:
            budget.completion_calls += 1
            return denied, 0, budget.work
        raise
    budget.fetch(cur, rule.scope, needed)
    for entity, barrier in barriers.items():
        if any(budget.native(pure._witness(barrier[key])).member.entity(rule) != entity
               for key in ("seed", "tracking_endpoint")):
            raise ProducerFailure("password_v2_barrier_native_conflict")
    incoming_ids = {(item.ref.scope, item.ref.native_id) for item in incoming}
    retained = tuple(n for identity, n in budget.records.items() if identity not in incoming_ids)
    proposal = pure.advance(rule, working, incoming, now=now, history=histories, retained=retained)
    if proposal.state.watermark != final or any(code not in _LOSS_CODES and count for code, count in proposal.diagnostics):
        raise ProducerFailure("password_v2_proposal_unavailable")
    next_episodes = {e.entity: e for e in proposal.state.episodes}
    emissions = list(proposal.emissions)
    for entity, barrier in barriers.items():
        frozen = _barrier_episode(barrier)
        proposed = next_episodes.get(entity)
        if proposed is not None and proposed.key != frozen.key:
            if not _successor_allowed(barrier, proposed.seed, proposal.state.epoch, lower):
                emissions = [e for e in emissions if e.entity != entity]
                candidates = [n.member.witness for n in incoming if n.member.entity(rule) == entity and n.at <= final
                              and n.at >= frozen.last.at]
                next_episodes[entity] = replace(frozen, last=max(candidates, key=lambda w: (w.at, int(w.ref.native_id)))
                                                       if candidates else frozen.last)
        elif proposed is None:
            next_episodes[entity] = frozen
    next_state = replace(proposal.state, episodes=tuple(next_episodes[e] for e in sorted(next_episodes)))
    if any(e.frozen and not e.sequence for e in next_state.episodes):
        raise ProducerFailure("password_v2_frozen_zero_unsupported")
    # Mandatory SQL current-candidate costs are separate work, counted once per
    # real Emission, never once per immutable portion or full historical chain.
    proposed_occurrences = sum(len(e.occurrences) for e in emissions)
    proposed_bytes = sum(w.xml_bytes for e in emissions for w in e.occurrences)
    if proposed_occurrences > pure.MAX_ROWS or proposed_bytes > pure.MAX_XML_BYTES:
        raise ProducerFailure("password_v2_proof_bound")
    queued_signals = []
    touched = {e.key for e in next_state.episodes if e.frozen}
    for emission in emissions:
        barrier = barriers.get(emission.entity)
        if barrier is not None and emission.episode_key != barrier["episode_key"]:
            tracking = _call(cur, "track_password_frozen_entity_v2", scope, execution, attempt["token"],
                attempt["state_revision"], barrier["episode_key"], asdict(emission.seed),
                emission.epoch, lower, final)
            budget.tracking_calls += 1
            if tracking.get("status") != "successor_authorized" or tracking.get("successor_episode_key") != emission.episode_key:
                raise ProducerFailure("password_v2_successor_conflict")
        old = episodes.get(emission.entity)
        root_id = old.root_id if old and old.key == emission.episode_key else None
        signals = _signals(rule, emission, root_id, now)
        expected = None if emission.sequence == 1 else asdict(old.budget) | {
            "last_sequence": old.sequence, "last_emission_id": old.last_emission}
        reservation = _call(cur, "reserve_password_episode_emission", scope, execution, attempt["token"],
            attempt["state_revision"], expected, [s.document for s in signals])
        budget.reservation_calls += 1
        budget.reservation_occurrences += len(emission.occurrences)
        if reservation.get("status") != "reserved" or reservation.get("signal_ids") != [s.signal_id for s in signals]:
            raise ProducerFailure("password_v2_reservation_conflict")
        queued_signals.extend(signals)
        touched.add(emission.episode_key)
    # The guarded SQL finalizer owns ordered held endpoint tracking (e.g.
    # 500 then700). Coalescing to the last endpoint invents a >600-second gap.
    # The only Python tracking call above belongs to actual successor admission.
    jobs = _enqueue_all(cur, queued_signals)
    diagnostics = {code: {"count": count, "from": lower.isoformat(), "to": final.isoformat()}
                   for code, count in proposal.diagnostics if count}
    result = _complete(cur, rule, attempt, "advance", {"version": VERSION, "state": next_state.document,
        "window": window, "diagnostics": diagnostics, "touched_episode_keys": sorted(touched)})
    budget.completion_calls += 1
    return result, jobs, budget.work


def _qualified_denial(cur, rule, attempt, state, incoming, budget, final):
    for episode in state.episodes:
        if episode.sequence <= 0 or episode.frozen:
            continue
        candidates = sorted((n for n in incoming if n.member.entity(rule) == episode.entity and n.at <= final
            and (state.watermark is None or n.at > state.watermark)
            and (n.at, int(n.ref.native_id)) > (episode.last.at, int(episode.last.ref.native_id))),
            key=lambda n: (n.at, int(n.ref.native_id)))
        if not candidates or candidates[0].at - episode.last.at > timedelta(seconds=pure.WINDOW):
            continue
        endpoint = candidates[0].member.witness
        try:
            budget.fetch(cur, rule.scope, (episode.last,))
        except ProducerFailure:
            continue
        predecessor = budget.native(episode.last)
        if predecessor.member.entity(rule) != episode.entity:
            raise ProducerFailure("password_v2_native_content_conflict")
        if (episode.budget.ref_occurrences + 2 <= pure.MAX_ROWS and episode.budget.portions + 1 <= pure.MAX_PORTIONS
                and episode.budget.xml_bytes + episode.last.xml_bytes + endpoint.xml_bytes <= pure.MAX_XML_BYTES):
            continue
        return _complete(cur, rule, attempt, "qualified_denial", {"version": VERSION, "episode_key": episode.key,
            "predecessor": asdict(episode.last), "endpoint": asdict(endpoint)})
    return None
