"""Pure password v2 proposals. No DB, worker, admission or publication wiring.

The future adapter must obtain native rows through the admitted reader/resolver.
Parsing XML here does not grant source authority or verify a database core hash.
Retained native content is required again for every continuity proof.
"""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from ipaddress import ip_address
import json

from server.sli.semantic.qw_input import _digest
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope
from server.sli.storage.xml_safety import parse_bounded_xml

WINDOW = 600
HOLDBACK = 120
HORIZON = 720
MAX_ROWS = 10000
MAX_PORTIONS = 256
MAX_XML_BYTES = 33554432
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _utc(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, OverflowError):
            raise ValueError("password_v2_time_invalid") from None
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("password_v2_time_invalid")
    return value.astimezone(timezone.utc)


def _pack(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "__dataclass_fields__"):
        return _pack(asdict(value))
    if isinstance(value, dict):
        return {key: _pack(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_pack(item) for item in value]
    return value


@dataclass(frozen=True)
class Rule:
    scope: EvidenceScope
    kind: str

    def __post_init__(self):
        if (not isinstance(self.scope, EvidenceScope) or self.scope.plugin_id != "sli.windows.ad-dc"
                or self.scope.collection_scope_id or self.kind not in {"brute", "spray"}):
            raise ValueError("password_v2_rule_scope")

    @property
    def execution(self):
        rule_id = "qw.password-brute-force" if self.kind == "brute" else "qw.password-spray"
        return {"version": "sli.qw.execution.v1", "kind": "threshold", "rule_id": rule_id,
                "rule_version": 2, "scope": asdict(self.scope), "rule_sha256": _digest({
                    "contract": "sli.password.v2.phase-a.1", "rule": rule_id,
                    "window": WINDOW, "inclusive": True, "threshold": 10 if self.kind == "brute" else 5,
                    "holdback": HOLDBACK, "horizon": HORIZON, "rows": MAX_ROWS,
                    "lifetime_refs": MAX_ROWS, "lifetime_portions": MAX_PORTIONS,
                    "lifetime_xml_bytes": MAX_XML_BYTES, "classification": "bad-unknown-other/native-v1",
                    "client": "native-ip-mapped-or-explicit-workstation/v1",
                    "late": "drop-finalized/v1", "gap": "new-epoch/v1", "continuity": "native-adjacency/v1"})}

    @property
    def pin(self):
        return _digest(self.execution)


@dataclass(frozen=True, repr=False)
class Witness:
    ref: EvidenceRef
    at: datetime
    xml_sha256: str
    xml_bytes: int


@dataclass(frozen=True, repr=False)
class Member:
    witness: Witness
    client_kind: str | None
    client_key: str | None
    target_key: str | None
    failure: str | None
    reason: str | None = None

    def entity(self, rule):
        if self.reason or not self.failure or not self.client_key or not self.target_key:
            return None
        if rule.kind == "spray":
            return self.client_key if self.client_kind == "ip" else None
        return _digest([self.client_kind, self.client_key, self.target_key])


def _failure(fields, event_id):
    codes = {}
    for key in ("Status", "SubStatus", "FailureCode", "ResultCode"):
        if key in fields and fields[key].strip():
            try:
                codes[key] = int(fields[key], 16)
            except ValueError:
                return None, "unclassified_failure"
    aliases = ("FailureCode", "Status", "ResultCode") if event_id == 4771 else ("Status", "ResultCode")
    primary = [codes[key] for key in aliases if key in codes]
    if len(set(primary)) > 1:
        return None, "ambiguous_failure"
    if event_id != 4771 and "FailureCode" in codes:
        return None, "ambiguous_failure"
    substatus = codes.get("SubStatus", 0)
    if event_id != 4625 and substatus:
        return None, "ambiguous_failure"
    if not primary:
        return None, "unclassified_failure"
    effective = primary[0]
    if event_id == 4625 and substatus:
        if effective == 0xC000006D:
            effective = substatus
        elif effective != substatus:
            return None, "ambiguous_failure"
    if effective == 0:
        return None, "unclassified_failure"
    bad, unknown = (0x18, 0x6) if event_id == 4771 else (0xC000006A, 0xC0000064)
    category = "known_bad_password" if effective == bad else "unknown_account" if effective == unknown else "other_failure"
    return category, None


def _client(fields, event_id):
    addresses = set()
    for key in ("IpAddress", "ClientAddress", "SourceNetworkAddress"):
        try:
            address = ip_address(fields.get(key, "").strip())
        except ValueError:
            continue
        address = getattr(address, "ipv4_mapped", None) or address
        if not (address.is_unspecified or address.is_loopback or address.is_multicast):
            addresses.add(str(address))
    if len(addresses) > 1:
        return None, None, "conflicting_client"
    if addresses:
        return "ip", _digest(["ip", addresses.pop()]), None
    key = "Workstation" if event_id == 4776 else "WorkstationName" if event_id == 4625 else None
    host = fields.get(key, "").strip().lstrip("\\").casefold() if key else ""
    if host and host not in {"-", "n/a"} and len(host) <= 256:
        return "host", _digest(["host", host]), None
    return None, None, "missing_client"


@dataclass(frozen=True, repr=False)
class NativeEvent:
    ref: EvidenceRef
    event_id: int
    at: datetime
    source_xml: str
    member: Member

    @classmethod
    def from_row(cls, scope, row):
        ref = EvidenceRef("core_event", str(row["source_event_id"]), row["sha256"], scope)
        if scope.plugin_id != "sli.windows.ad-dc":
            raise ValueError("password_v2_source_scope")
        at, event_id, xml = _utc(row["occurred_at_utc"]), row["event_id"], row["source_xml"]
        if type(event_id) is not int or event_id not in {4625, 4771, 4776} or not isinstance(xml, str):
            raise ValueError("password_v2_native_invalid")
        root = parse_bounded_xml(xml)
        system = root.find(NS + "System")
        if (root.tag != NS + "Event" or system is None
                or system.findtext(NS + "EventID") != str(event_id)):
            raise ValueError("password_v2_native_event_mismatch")
        stamp = system.find(NS + "TimeCreated")
        if stamp is None or _utc(stamp.get("SystemTime")) != at:
            raise ValueError("password_v2_native_time_mismatch")
        data, fields = root.find(NS + "EventData"), {}
        if data is not None:
            for item in data:
                name = item.get("Name")
                if item.tag != NS + "Data" or not name or name in fields or len(item):
                    raise ValueError("password_v2_native_fields_invalid")
                fields[name] = item.text or ""
        payload = xml.encode("utf-8")
        witness = Witness(ref, at, sha256(payload).hexdigest(), len(payload))
        account = fields.get("TargetUserName", "").strip().casefold()
        domain = fields.get("TargetDomainName", "").strip().casefold()
        target = _digest([domain, account]) if account not in {"", "-", "n/a"} and max(len(account), len(domain)) <= 256 else None
        client_kind, client_key, reason = _client(fields, event_id)
        failure, status_reason = _failure(fields, event_id)
        reason = "missing_target" if target is None else status_reason if failure is None else reason
        return cls(ref, event_id, at, xml, Member(witness, client_kind, client_key, target, failure, reason))

    def checked(self):
        parsed = type(self).from_row(self.ref.scope, {"source_event_id": self.ref.native_id,
            "event_id": self.event_id, "occurred_at_utc": self.at, "sha256": self.ref.sha256,
            "source_xml": self.source_xml})
        if parsed != self:
            raise ValueError("password_v2_native_content_conflict")
        return parsed


@dataclass(frozen=True)
class Budget:
    ref_occurrences: int = 0
    portions: int = 0
    xml_bytes: int = 0

    def reserve(self, *, ref_occurrences, portions, xml_bytes):
        current = (self.ref_occurrences, self.portions, self.xml_bytes)
        delta = (ref_occurrences, portions, xml_bytes)
        limits = (MAX_ROWS, MAX_PORTIONS, MAX_XML_BYTES)
        if any(type(value) is not int or value < 0 for value in current + delta):
            raise ValueError("password_v2_budget_invalid")
        values = tuple(old + amount for old, amount in zip(current, delta))
        if any(value > limit for value, limit in zip(values, limits)):
            raise ValueError("password_v2_episode_budget_exhausted")
        return Budget(*values)


@dataclass(frozen=True, repr=False)
class Emission:
    episode_key: str
    pin: str
    epoch: int
    entity: str
    sequence: int
    seed: Witness
    root_proof: tuple[Witness, ...]
    new_events: tuple[Witness, ...]
    predecessor: Witness | None
    previous_id: str | None
    known_bad_password: int
    unknown_account: int
    other_failure: int
    distinct_names: int
    origin: tuple[Witness, ...] = ()

    @property
    def endpoint(self):
        return (self.new_events or self.root_proof)[-1]

    @property
    def occurrences(self):
        if self.predecessor is not None:
            return (self.predecessor,) + self.new_events
        return self.origin + self.new_events

    @property
    def portions(self):
        return (len(self.occurrences) + 255) // 256

    @property
    def ref_portions(self):
        occurrences = self.occurrences
        return tuple(occurrences[offset:offset + 256] for offset in range(0, len(occurrences), 256))

    @property
    def document(self):
        return _pack(self)

    @property
    def emission_id(self):
        return _digest(self.document)


@dataclass(frozen=True, repr=False)
class Episode:
    key: str
    entity: str
    seed: Witness
    last: Witness
    root_id: str | None = None
    last_emission: str | None = None
    sequence: int = 0
    budget: Budget = Budget()
    frozen: bool = False
    prequalification: tuple[Witness, ...] = ()


def _witness(document):
    ref = document["ref"]
    return Witness(EvidenceRef(ref["storage_kind"], ref["native_id"], ref["sha256"], EvidenceScope(**ref["scope"])),
                   _utc(document["at"]), document["xml_sha256"], document["xml_bytes"])


@dataclass(frozen=True, repr=False)
class State:
    pin: str | None = None
    watermark: datetime | None = None
    epoch: int = 0
    window: tuple[Member, ...] = ()
    episodes: tuple[Episode, ...] = ()

    @property
    def document(self):
        return {"version": "sli.password.v2.state.1", **_pack(self)}

    @classmethod
    def from_document(cls, document):
        if (document.get("version") != "sli.password.v2.state.1"
                or type(document.get("epoch")) is not int or document["epoch"] < 0
                or len(json.dumps(document).encode("utf-8")) > 4 * 1024 * 1024):
            raise ValueError("password_v2_state_invalid")
        window = tuple(Member(_witness(item["witness"]), item["client_kind"], item["client_key"],
            item["target_key"], item["failure"], item["reason"]) for item in document["window"])
        episodes = tuple(Episode(item["key"], item["entity"], _witness(item["seed"]), _witness(item["last"]),
            item["root_id"], item["last_emission"], item["sequence"], Budget(**item["budget"]), item["frozen"],
            tuple(_witness(witness) for witness in item.get("prequalification", ())))
            for item in document["episodes"])
        return cls(document["pin"], _utc(document["watermark"]) if document["watermark"] else None,
                   document["epoch"], window, episodes)


@dataclass(frozen=True, repr=False)
class Proposal:
    state: State
    emissions: tuple[Emission, ...]
    diagnostics: tuple[tuple[str, int], ...]


def _ordered(members):
    return sorted(members, key=lambda item: (item.witness.at, int(item.witness.ref.native_id)))


def _key(rule, epoch, entity, witness):
    return _digest([rule.pin, epoch, entity, witness.ref.params])


def _records(events):
    if len(events) > MAX_ROWS or sum(len(item.source_xml.encode("utf-8")) for item in events) > MAX_XML_BYTES:
        raise ValueError("password_v2_proof_bound")
    result, identities = {}, {}
    for event in events:
        parsed = event.checked()
        identity = (event.ref.scope, event.ref.native_id)
        if identity in identities and identities[identity] != parsed:
            raise ValueError("password_v2_native_content_conflict")
        identities[identity] = parsed
        result[event.ref] = parsed
    return result


def _chain_native(chain, records):
    refs = {witness.ref for emission in chain for witness in emission.occurrences}
    if any(ref not in records for ref in refs):
        raise ValueError("password_v2_native_unavailable")
    return tuple(records[ref] for ref in refs)


def _verify_native_path(rule, entity, path, records):
    if not path:
        raise ValueError("password_v2_continuity_origin_missing")
    previous = None
    for witness in path:
        native = records.get(witness.ref)
        if native is None:
            raise ValueError("password_v2_native_unavailable")
        if (native.member.witness != witness or native.ref.scope != rule.scope
                or native.member.entity(rule) != entity):
            raise ValueError("password_v2_continuity_native_conflict")
        if previous is not None:
            if ((witness.at, int(witness.ref.native_id)) <= (previous.at, int(previous.ref.native_id))
                    or witness.at - previous.at > timedelta(seconds=WINDOW)):
                raise ValueError("password_v2_continuity_origin_gap")
        previous = witness


def verify_chain(rule, chain, retained):
    """Reparse actual supplied native content, never a cached verified flag.

    Future DB adapter must resolve every retained ref again before this call.
    """
    records = _records(retained)
    chain = tuple(sorted(chain, key=lambda item: item.sequence))
    if not chain:
        raise ValueError("password_v2_continuity_missing")
    budget, previous = Budget(), None
    for number, emission in enumerate(chain, 1):
        if (emission.pin != rule.pin or emission.sequence != number
                or emission.episode_key != chain[0].episode_key
                or emission.entity != chain[0].entity or emission.epoch != chain[0].epoch):
            raise ValueError("password_v2_continuity_identity")
        witnesses = emission.occurrences
        if not witnesses:
            raise ValueError("password_v2_continuity_empty")
        budget = budget.reserve(ref_occurrences=len(witnesses), portions=emission.portions,
                                xml_bytes=sum(item.xml_bytes for item in witnesses))
        for witness in witnesses:
            native = records.get(witness.ref)
            if native is None:
                raise ValueError("password_v2_native_unavailable")
            if (native.member.witness != witness or native.ref.scope != rule.scope
                    or native.member.entity(rule) != emission.entity):
                raise ValueError("password_v2_continuity_native_conflict")
        if emission.episode_key != _key(rule, emission.epoch, emission.entity, emission.seed):
            raise ValueError("password_v2_continuity_seed")
        if previous is None:
            if emission.predecessor is not None or emission.previous_id is not None or not emission.root_proof:
                raise ValueError("password_v2_continuity_root")
            if (not emission.origin or emission.origin[0] != emission.seed
                    or emission.origin[-1] != emission.root_proof[-1]):
                raise ValueError("password_v2_continuity_origin_seed")
            _verify_native_path(rule, emission.entity, emission.origin, records)
            expected_window = tuple(item for item in emission.origin
                if item.at >= emission.origin[-1].at - timedelta(seconds=WINDOW))
            if emission.root_proof != expected_window:
                raise ValueError("password_v2_continuity_origin_window")
            proof = [records[item.ref].member for item in emission.root_proof]
            if proof != _ordered(proof):
                raise ValueError("password_v2_continuity_order")
            if len({item.witness.ref.native_id for item in proof}) != len(proof):
                raise ValueError("password_v2_continuity_duplicate")
            span = max(item.witness.at for item in proof) - min(item.witness.at for item in proof)
            enough = len(proof) >= 10 if rule.kind == "brute" else len({item.target_key for item in proof}) >= 5
            if span > timedelta(seconds=WINDOW) or not enough:
                raise ValueError("password_v2_continuity_threshold")
            endpoint = emission.root_proof[-1]
        else:
            if not emission.new_events:
                raise ValueError("password_v2_continuity_empty_continuation")
            if (emission.origin or emission.predecessor != previous.endpoint or emission.previous_id != previous.emission_id
                    or emission.root_proof or emission.seed != previous.seed):
                raise ValueError("password_v2_continuity_predecessor")
            endpoint = emission.predecessor
        for witness in emission.new_events:
            delta = witness.at - endpoint.at
            if (delta < timedelta(0) or delta > timedelta(seconds=WINDOW)
                    or (witness.at, int(witness.ref.native_id)) <= (endpoint.at, int(endpoint.ref.native_id))):
                raise ValueError("password_v2_continuity_gap")
            endpoint = witness
        counted = emission.root_proof if previous is None else emission.new_events
        members = [records[item.ref].member for item in counted]
        counts = tuple(sum(item.failure == kind for item in members)
                       for kind in ("known_bad_password", "unknown_account", "other_failure"))
        if (counts != (emission.known_bad_password, emission.unknown_account, emission.other_failure)
                or emission.distinct_names != len({item.target_key for item in members})):
            raise ValueError("password_v2_continuity_counters")
        previous = emission
    return budget


def advance(rule, state, events, *, now, history=(), retained=()):
    """Return an immutable proposal. Acceptance/atomic SQL reserve is Phase B."""
    now = _utc(now)
    if state.pin is not None and state.pin != rule.pin:
        raise ValueError("password_v2_state_scope")
    cutoff, lower = now - timedelta(seconds=HOLDBACK), now - timedelta(seconds=HORIZON)
    diagnostics = {}
    def note(code):
        diagnostics[code] = diagnostics.get(code, 0) + 1
    if state.watermark is not None and cutoff < state.watermark:
        return Proposal(state, (), (("clock_regression", 1),))
    if len(events) > MAX_ROWS or sum(len(event.source_xml.encode("utf-8")) for event in events) > MAX_XML_BYTES:
        return Proposal(state, (), (("reader_bound", 1),))
    records = _records(retained)
    incoming = _records(events)
    identities = {(ref.scope, ref.native_id): record for ref, record in records.items()}
    for ref, record in incoming.items():
        if (ref.scope, ref.native_id) in identities and identities[(ref.scope, ref.native_id)] != record:
            raise ValueError("password_v2_native_content_conflict")
        records[ref] = record
    for event in events:
        if event.ref.scope != rule.scope:
            raise ValueError("password_v2_native_scope")
    epoch, watermark = state.epoch, state.watermark
    old_window, episodes = state.window, {item.entity: item for item in state.episodes}
    if watermark is not None and lower > watermark:
        epoch += 1
        note("coverage_gap")
        old_window, episodes, watermark = (), {}, None
    if watermark is None:
        watermark = lower - timedelta(microseconds=1)
    seen = {item.witness.ref.native_id: item for item in old_window}
    pending = {key for key, item in seen.items() if item.witness.at > watermark}
    for event in events:
        member, native_id = event.member, event.ref.native_id
        if native_id in seen:
            if replace(seen[native_id], reason=member.reason) != member:
                raise ValueError("password_v2_native_conflict")
            continue
        if member.witness.at > now:
            note("future_event")
            continue
        if member.witness.at < lower:
            note("outside_horizon")
            continue
        if member.witness.at <= watermark:
            seen[native_id] = replace(member, reason="too_late")
            note("too_late")
        else:
            seen[native_id] = member
            pending.add(native_id)
    finalized = _ordered([seen[key] for key in pending if seen[key].witness.at <= cutoff])
    proposals, new_by_key, proof_by_key, origin_checked = [], {}, {}, set()
    queues, names = {}, {}
    for old in _ordered([item for item in old_window if item.witness.at <= watermark]):
        entity = old.entity(rule)
        if entity is not None:
            queues.setdefault(entity, deque()).append(old)
            names.setdefault(entity, Counter())[old.target_key] += 1
    for member in finalized:
        entity, witness = member.entity(rule), member.witness
        if entity is None:
            note(member.reason or "missing_client")
            continue
        episode = episodes.get(entity)
        if episode is None or witness.at - episode.last.at > timedelta(seconds=WINDOW):
            if episode is not None:
                old = records.get(episode.last.ref)
                if old is None:
                    return Proposal(state, (), (("gap_native_unavailable", 1),))
                if (old.member.witness != episode.last or old.ref.scope != rule.scope
                        or old.member.entity(rule) != entity):
                    raise ValueError("password_v2_continuity_native_conflict")
            episode = Episode(_key(rule, epoch, entity, witness), entity, witness, witness,
                              prequalification=(witness,))
            origin_checked.add(episode.key)
        else:
            if not episode.root_id and not episode.frozen and episode.key not in proof_by_key:
                if episode.key not in origin_checked:
                    if (not episode.prequalification or episode.prequalification[0] != episode.seed
                            or episode.prequalification[-1] != episode.last):
                        return Proposal(state, (), (("prequalification_native_unavailable", 1),))
                    try:
                        _verify_native_path(rule, entity, episode.prequalification, records)
                    except ValueError as exc:
                        if str(exc) != "password_v2_native_unavailable":
                            raise
                        return Proposal(state, (), (("prequalification_native_unavailable", 1),))
                    origin_checked.add(episode.key)
                origin = episode.prequalification + (witness,)
                try:
                    Budget().reserve(ref_occurrences=len(origin), portions=(len(origin) + 255) // 256,
                                     xml_bytes=sum(item.xml_bytes for item in origin))
                except ValueError as exc:
                    if str(exc) != "password_v2_episode_budget_exhausted":
                        raise
                    episodes[entity] = replace(episode, last=witness, frozen=True)
                    note("prequalification_proof_budget_exhausted")
                    continue
                episode = replace(episode, prequalification=origin)
            episode = replace(episode, last=witness)
        episodes[entity] = episode
        if episode.frozen:
            note("episode_evidence_budget_exhausted")
            continue
        if episode.root_id is not None:
            new_by_key.setdefault(episode.key, []).append(witness)
            continue
        candidates, targets = queues.setdefault(entity, deque()), names.setdefault(entity, Counter())
        while candidates and candidates[0].witness.at < witness.at - timedelta(seconds=WINDOW):
            removed = candidates.popleft()
            targets[removed.target_key] -= 1
            if not targets[removed.target_key]:
                del targets[removed.target_key]
        candidates.append(member)
        targets[member.target_key] += 1
        enough = len(candidates) >= 10 if rule.kind == "brute" else len(targets) >= 5
        if enough and episode.key not in proof_by_key:
            proof_by_key[episode.key] = tuple(item.witness for item in candidates)
        elif episode.key in proof_by_key:
            new_by_key.setdefault(episode.key, []).append(witness)
    for entity, episode in sorted(episodes.items()):
        root = proof_by_key.get(episode.key, ())
        new = tuple(new_by_key.get(episode.key, ()))
        if episode.frozen or not (root or new):
            continue
        chain = tuple(item for item in history if item.episode_key == episode.key)
        predecessor = None
        if episode.root_id is not None:
            verify_chain(rule, chain, _chain_native(chain, records))
            if chain[-1].emission_id != episode.last_emission:
                raise ValueError("password_v2_continuity_state")
            predecessor = chain[-1].endpoint
        counted = root or new
        counts = tuple(sum(records[item.ref].member.failure == kind for item in counted)
                       for kind in ("known_bad_password", "unknown_account", "other_failure"))
        emission = Emission(episode.key, rule.pin, epoch, entity, episode.sequence + 1,
            episode.seed, root, new, predecessor, episode.last_emission, *counts,
            len({records[item.ref].member.target_key for item in counted}),
            origin=episode.prequalification if root else ())
        try:
            budget = episode.budget.reserve(ref_occurrences=len(emission.occurrences), portions=emission.portions,
                xml_bytes=sum(item.xml_bytes for item in emission.occurrences))
        except ValueError as exc:
            if str(exc) != "password_v2_episode_budget_exhausted":
                raise
            episodes[entity] = replace(episode, frozen=True)
            note("episode_evidence_budget_exhausted")
            continue
        all_chain = chain + (emission,)
        verify_chain(rule, all_chain, _chain_native(all_chain, records))
        proposals.append(emission)
        episodes[entity] = replace(episode, root_id=episode.root_id or emission.emission_id,
            last_emission=emission.emission_id, sequence=emission.sequence, budget=budget, prequalification=())
    window = tuple(_ordered([item for item in seen.values() if item.witness.at >= cutoff - timedelta(seconds=WINDOW)]))
    next_state = State(rule.pin, cutoff, epoch, window, tuple(episodes[key] for key in sorted(episodes)))
    if (len(window) > MAX_ROWS or len(episodes) > MAX_ROWS
            or len(json.dumps(next_state.document).encode("utf-8")) > 4 * 1024 * 1024):
        return Proposal(state, (), (("state_bound", 1),))
    return Proposal(next_state, tuple(proposals), tuple(sorted(diagnostics.items())))
