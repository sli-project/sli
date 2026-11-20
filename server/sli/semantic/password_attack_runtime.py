"""Password v2 native adapter. Callers own transactions; no verified cache/flags.

SQL owns current source authority/commitments, costs, ledger and atomicity.
Python reparses current XML with the single pure semantic implementation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import json

from server.sli.semantic.password_attack_v2 import (
    MAX_PORTIONS, MAX_ROWS, MAX_XML_BYTES, NativeEvent, Rule, verify_chain,
)
from server.sli.semantic.password_attack_v2_portions import match_qw_refs, reassemble
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceRefError

RULES = frozenset(("qw.password-brute-force", "qw.password-spray"))


class PasswordEpisodeFrozen(RuntimeError):
    pass


class PasswordEvidencePending(RuntimeError):
    pass


def is_password_signal(signal):
    return signal.password_context is not None or (signal.rule_id in RULES and signal.rule_version == 2)


def validate_signal(signal):
    """Typed transport only. Scope is the independently validated execution scope."""
    try:
        if (signal.rule_id not in RULES or type(signal.rule_version) is not int
                or signal.rule_version != 2 or signal.kind != "threshold"
                or type(signal.password_context) is not dict
                or signal.base_severity != "high" or signal.effective_severity != "high"
                or any(value is not None for value in (signal.threshold_context, signal.decoy_context,
                    signal.file_decoy_context, signal.watch_context, signal.acl_context))
                or signal.conclusion_state != "observed" or signal.quality != "good"):
            raise ValueError
        scope = signal.evidence_refs[0].scope
        rule = Rule(scope, "brute" if signal.rule_id == "qw.password-brute-force" else "spray")
        if signal.execution != rule.execution:
            raise ValueError
        witnesses = match_qw_refs(scope, signal.password_context, signal.evidence_refs)
        context = signal.password_context
        if (context["pin"] != rule.pin or context["entity"] != signal.entity_key
                or context["episode_key"] != signal.episode_key
                or signal.evidence_total != context["occurrence_total"]
                or (context["portion_index"] == context["portion_total"] - 1
                    and signal.occurred_at_utc != witnesses[-1].at)):
            raise ValueError
        if len(json.dumps(signal.document, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()) > 524288:
            raise ValueError
    except (KeyError, TypeError, ValueError, RuntimeError, OverflowError):
        raise ValueError("password_v2_signal_invalid") from None
    return rule, witnesses


@dataclass(frozen=True)
class Episode:
    rule: Rule
    signals: tuple
    emissions: tuple


def _arguments(signal):
    rule, _ = validate_signal(signal)
    return (json.dumps(asdict(rule.scope)), json.dumps(rule.execution), signal.episode_key)


def load_episode(cur, signal):
    """Load the complete bounded immutable chain in SQL's binding order."""
    from server.sli.semantic.qw_input import QWSignal

    rule, _ = validate_signal(signal)
    cur.execute("select signal_id,document_json from public.read_password_episode_portions_v2(%s::jsonb,%s::jsonb,%s)",
                _arguments(signal))
    rows = list(cur.fetchall())
    if not rows or len(rows) > MAX_PORTIONS:
        raise PasswordEvidencePending("qw_evidence_pending")
    signals, emissions, contexts, group = [], [], [], []
    group_metadata = None
    for row in rows:
        try:
            document = row["document_json"]
            document = dict(json.loads(document) if isinstance(document, str) else document)
            from server.sli.storage.evidence_ref import EvidenceScope
            refs = tuple(EvidenceRef(**(ref | {"scope": EvidenceScope(**ref["scope"])}))
                         for ref in document.pop("evidence_refs"))
            document["severity_reasons"] = tuple(document["severity_reasons"])
            for name in ("occurred_at_utc", "received_at_utc"):
                document[name] = datetime.fromisoformat(document[name])
            item = QWSignal(**document, evidence_refs=refs)
            validate_signal(item)
            context = item.password_context
            if (item.signal_id != row["signal_id"] or item.execution != rule.execution
                    or item.episode_key != signal.episode_key or item.entity_key != signal.entity_key
                    or context["sequence"] != len(emissions) + 1 or context["portion_index"] != len(contexts)):
                raise ValueError
            metadata = {key: value for key, value in item.document.items()
                        if key not in {"evidence_refs", "password_context", "received_at_utc"}}
            if group_metadata is None:
                group_metadata = metadata
            elif metadata != group_metadata:
                raise ValueError
            signals.append(item)
            contexts.append(context)
            group.append(item)
            if len(contexts) == context["portion_total"]:
                emission = reassemble(rule.scope, tuple(contexts))
                if any(s.occurred_at_utc != emission.endpoint.at for s in group):
                    raise ValueError
                if emissions and (context["root_id"] != emissions[0].emission_id
                        or emission.previous_id != emissions[-1].emission_id
                        or emission.seed != emissions[0].seed or emission.epoch != emissions[0].epoch):
                    raise ValueError
                emissions.append(emission)
                contexts, group = [], []
                group_metadata = None
        except (KeyError, TypeError, ValueError, RuntimeError, OverflowError):
            raise RuntimeError("password_v2_chain_invalid") from None
    if contexts or signal.signal_id not in {s.signal_id for s in signals}:
        raise PasswordEvidencePending("qw_evidence_pending")
    if sum(len(e.occurrences) for e in emissions) > MAX_ROWS:
        raise RuntimeError("password_v2_proof_budget_exceeded")
    return Episode(rule, tuple(signals), tuple(emissions))


def _witness_document(witness):
    return {"ref": asdict(witness.ref), "at": witness.at.isoformat(),
            "xml_sha256": witness.xml_sha256, "xml_bytes": witness.xml_bytes}


def _read_native(cur, scope, witnesses):
    if len(witnesses) > MAX_ROWS or sum(w.xml_bytes for w in witnesses) > MAX_XML_BYTES:
        raise RuntimeError("password_v2_proof_budget_exceeded")
    cur.execute("select * from public.read_password_retained_proof_v2(%s::jsonb,%s::jsonb)",
                (json.dumps(asdict(scope)), json.dumps([_witness_document(w) for w in witnesses])))
    rows = list(cur.fetchall())
    if len(rows) != len(witnesses):
        raise RuntimeError("password_v2_native_unavailable")
    total, natives = 0, []
    for index, (row, expected) in enumerate(zip(rows, witnesses), 1):
        xml = row.get("source_xml")
        if type(xml) is not str:
            raise RuntimeError("password_v2_native_unavailable")
        length = len(xml.encode("utf-8"))
        total += length
        if length > 4194304 or total > MAX_XML_BYTES:
            raise RuntimeError("password_v2_proof_budget_exceeded")
        if (type(row.get("occurrence_index")) is not int or row["occurrence_index"] != index
                or type(row.get("source_event_id")) is not int
                or str(row["source_event_id"]) != expected.ref.native_id):
            raise RuntimeError("password_v2_native_unavailable")
        native = NativeEvent.from_row(scope, row)
        if (native.member.witness != expected or type(row.get("xml_bytes")) is not int
                or row["xml_bytes"] != length or row.get("xml_sha256") != native.member.witness.xml_sha256):
            raise RuntimeError("password_v2_native_content_conflict")
        natives.append(native)
    return tuple(natives)


def verify_signal(cur, signal):
    """Current portion only; producer/publisher prove the complete qualification."""
    rule, witnesses = validate_signal(signal)
    natives = _read_native(cur, rule.scope, witnesses)
    if any(native.member.entity(rule) != signal.entity_key for native in natives):
        raise ValueError("password_v2_continuity_native_conflict")
    return witnesses


def lock_publication(cur, signal):
    """Caller already holds scenario advisory lock. Never commit or lock checkpoint."""
    cur.execute("savepoint password_v2_publication_lock")
    try:
        cur.execute("select public.lock_password_publication_v2(%s::jsonb,%s::jsonb,%s) as publication", _arguments(signal))
        row = cur.fetchone()
    except Exception as error:
        cur.execute("rollback to savepoint password_v2_publication_lock")
        cur.execute("release savepoint password_v2_publication_lock")
        message = getattr(getattr(error, "diag", None), "message_primary", None) or str(error).splitlines()[0]
        if message == "episode_frozen":
            raise PasswordEpisodeFrozen("episode_frozen") from None
        raise
    cur.execute("release savepoint password_v2_publication_lock")
    if not row or type(row.get("publication")) is not dict:
        raise RuntimeError("password_v2_episode_invalid")
    if row["publication"].get("frozen") is True:
        raise PasswordEpisodeFrozen("episode_frozen")
    return row["publication"]


def _scenario_signals(cur, scenario_id):
    from server.sli.semantic.qw_input import load_qw_signal

    # A signal can contribute through several admitted policy steps. Reject
    # invalid members over the whole set before deduplicating immutable inputs.
    cur.execute("""select 1 as invalid from semantic_scenario_steps step
        left join semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
        where step.scenario_id=%s and (step.source_kind is distinct from 'qw_signal'
          or step.qw_signal_id is null or signal.signal_id is null) limit 1""", (scenario_id,))
    if cur.fetchone() is not None:
        raise RuntimeError("password_v2_scenario_invalid")
    cur.execute("""select distinct qw_signal_id from semantic_scenario_steps
        where scenario_id=%s order by qw_signal_id limit 257""", (scenario_id,))
    rows = list(cur.fetchall())
    if (not rows or len(rows) > MAX_PORTIONS
            or any(not row.get("qw_signal_id") for row in rows)):
        raise RuntimeError("password_v2_scenario_invalid")
    try:
        return tuple(load_qw_signal(cur, signal_id=row["qw_signal_id"]) for row in rows)
    except (LookupError, ValueError, RuntimeError):
        raise RuntimeError("password_v2_scenario_invalid") from None


def scenario_password_signal(cur, scenario_id):
    """A legacy current job cannot hide managed-v2 scenario members."""
    from server.sli.semantic.qw_input import load_qw_signal

    cur.execute("""select distinct signal.signal_id from semantic_scenario_steps step
        left join semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
        where step.scenario_id=%s and step.source_kind='qw_signal'
          and (signal.signal_id is null or signal.document_json ? 'password_context' or
            (signal.document_json->>'rule_id' in ('qw.password-brute-force','qw.password-spray')
             and signal.document_json->>'rule_version'='2'))
        order by signal.signal_id limit 1""", (scenario_id,))
    row = cur.fetchone()
    if not row:
        return None
    if not row.get("signal_id"):
        raise RuntimeError("password_v2_scenario_invalid")
    signal = load_qw_signal(cur, signal_id=row["signal_id"])
    if not is_password_signal(signal):
        raise RuntimeError("password_v2_scenario_invalid")
    return signal


def scenario_complete(cur, scenario_id, signal):
    episode = load_episode(cur, signal)
    steps = _scenario_signals(cur, scenario_id)
    if any(not is_password_signal(item) or item.execution != signal.execution
           or item.episode_key != signal.episode_key for item in steps):
        raise RuntimeError("password_v2_scenario_invalid")
    return {s.signal_id for s in steps} == {s.signal_id for s in episode.signals}


def _release_witness(document, scope):
    # Reuse the frozen codec's exact compact Witness validation without a parser copy.
    from server.sli.semantic.password_attack_v2_portions import _row
    if type(document) is not dict or set(document) != {"ref", "at", "xml_sha256", "xml_bytes"}:
        raise RuntimeError("password_v2_release_invalid")
    ref = document["ref"]
    if (type(ref) is not dict or set(ref) != {"storage_kind", "native_id", "sha256", "scope"}
            or ref["storage_kind"] != "core_event" or ref["scope"] != asdict(scope)):
        raise RuntimeError("password_v2_release_invalid")
    return _row(scope, [ref["native_id"], ref["sha256"], document["at"], document["xml_bytes"], document["xml_sha256"]])



def _historical_witness(ledger, episode):
    """Provisional metadata only; native proof and SQL assertion remain required."""
    descriptor = ledger.get("historical_barrier")
    if descriptor is None:
        return None
    fields = {"version", "barrier_episode_key", "barrier_first_ledger_revision", "barrier_seed",
              "target_last_admitted_revision", "target_last_sequence", "target_last_emission_id"}
    last = episode.emissions[-1]
    if (type(descriptor) is not dict or set(descriptor) != fields
            or descriptor["version"] != "sli.password.v2.historical-barrier.1"):
        raise RuntimeError("password_v2_historical_invalid")
    for field in ("barrier_episode_key", "target_last_emission_id"):
        value = descriptor[field]
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise RuntimeError("password_v2_historical_invalid")
    for field in ("barrier_first_ledger_revision", "target_last_admitted_revision", "target_last_sequence"):
        value = descriptor[field]
        if type(value) is not int or not 0 < value < 2**63:
            raise RuntimeError("password_v2_historical_invalid")
    if (descriptor["barrier_episode_key"] == last.episode_key
            or descriptor["target_last_admitted_revision"] >= descriptor["barrier_first_ledger_revision"]
            or descriptor["target_last_sequence"] != last.sequence
            or descriptor["target_last_emission_id"] != last.emission_id):
        raise RuntimeError("password_v2_historical_invalid")
    return _release_witness(descriptor["barrier_seed"], episode.rule.scope)

def verify_scenario(cur, *, scenario_id):
    """ONE whole-chain fresh pass, including external release proof within same cap."""
    signals = _scenario_signals(cur, scenario_id)
    signal = signals[0]
    if any(not is_password_signal(item) for item in signals):
        raise RuntimeError("password_v2_scenario_invalid")
    if any(item.evaluation_mode != "enabled" or item.conclusion_state != "observed" for item in signals):
        raise RuntimeError("qw_signal_source_mismatch")
    episode = load_episode(cur, signal)
    if {s.signal_id for s in signals} != {s.signal_id for s in episode.signals}:
        raise PasswordEvidencePending("qw_evidence_pending")
    ledger = lock_publication(cur, signal)
    witnesses = tuple(w for emission in episode.emissions for w in emission.occurrences)
    release = None
    if ledger.get("predecessor_episode_key") is not None:
        release = _release_witness(ledger.get("predecessor_endpoint"), episode.rule.scope)
        seed = _release_witness(ledger.get("successor_seed"), episode.rule.scope)
        from server.sli.semantic.password_attack_v2_portions import _stamp

        through = ledger.get("predecessor_tracking_through")
        if (seed != episode.emissions[0].seed or type(ledger.get("successor_epoch")) is not int
                or ledger["successor_epoch"] != episode.emissions[0].epoch or type(through) is not str
                or _stamp(through) < seed.at or seed.at - release.at <= timedelta(seconds=600)):
            raise RuntimeError("password_v2_release_invalid")
        if release not in witnesses:
            witnesses += (release,)
    historical = _historical_witness(ledger, episode)
    if historical is not None and historical not in witnesses:
        witnesses += (historical,)
    natives = _read_native(cur, episode.rule.scope, witnesses)
    budget = verify_chain(episode.rule, episode.emissions, natives[:sum(len(e.occurrences) for e in episode.emissions)])
    actual_entity = natives[0].member.entity(episode.rule)
    if release is not None and any(n.member.entity(episode.rule) != actual_entity for n in natives):
        raise RuntimeError("password_v2_release_invalid")
    last = episode.emissions[-1]
    if historical is not None:
        barrier_native = next(n for n in natives if n.member.witness == historical)
        endpoint_native = next(n for n in natives if n.member.witness == last.endpoint)
        if (barrier_native.member.entity(episode.rule) != actual_entity
                or endpoint_native.at + timedelta(seconds=600) >= barrier_native.at):
            raise RuntimeError("password_v2_historical_invalid")
    expected = {"episode_key": last.episode_key, "entity": actual_entity, "epoch": last.epoch,
        "root_id": episode.emissions[0].emission_id, "last_sequence": last.sequence,
        "last_emission_id": last.emission_id,
        "totals": {"ref_occurrences": budget.ref_occurrences, "portions": budget.portions, "xml_bytes": budget.xml_bytes}}
    if any(ledger.get(key) != value for key, value in expected.items()) or ledger.get("frozen") is not False:
        raise RuntimeError("password_v2_episode_invalid")
    if historical is None:
        cur.execute("select public.assert_password_publication_entity_v2(%s::jsonb,%s::jsonb,%s,%s) as publication",
                    (*_arguments(signal), actual_entity))
    else:
        cur.execute("select public.assert_password_publication_entity_v2(%s::jsonb,%s::jsonb,%s,%s,%s::jsonb) as publication",
                    (*_arguments(signal), actual_entity, json.dumps(ledger["historical_barrier"])))
    checked = cur.fetchone()
    if not checked or checked.get("publication") != ledger:
        raise RuntimeError("password_v2_episode_invalid")
    return tuple(tuple(w.ref for w in portion) for emission in episode.emissions for portion in emission.ref_portions)


def link_password_evidence(cur, *, finding_id, batches):
    """The existing SQL linker reauthorizes each ref; no redundant Python resolver loop."""
    if type(finding_id) is not int or not 0 < finding_id < 2**63:
        raise EvidenceRefError("evidence_finding_invalid")
    added = 0
    for batch in batches:
        if type(batch) is not tuple or len(batch) > 256 or any(type(ref) is not EvidenceRef for ref in batch):
            raise EvidenceRefError("evidence_reference_invalid")
        for ref in batch:
            try:
                cur.execute("select public.link_finding_evidence_ref(%s,%s,%s,%s,%s,%s,%s,%s,%s) as added",
                            (finding_id, *ref.params))
                row = cur.fetchone()
            except Exception:
                raise EvidenceRefError("evidence_link_failed") from None
            if not row or type(row.get("added")) is not bool:
                raise EvidenceRefError("evidence_link_failed")
            added += row["added"]
    return added
