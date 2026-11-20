"""Password v2 transport integrity only; no native verification or admission.

The 64 KiB context limit measures UTF-8 bytes of json.dumps(sort_keys=True,
separators=(",", ":"), ensure_ascii=True, allow_nan=False). It is independent
of State's default-spaced encoding and the future full QW document size gate.
original_root_id is caller-supplied continuity metadata, never ancestry proof.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta
import json
import re

from server.sli.semantic.password_attack_v2 import Emission, MAX_PORTIONS, MAX_ROWS, Witness
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceRefError, EvidenceScope

VERSION = "sli.password.v2.portion.1"
MAX_CONTEXT_BYTES = 65536
_KEYS = frozenset(("version", "episode_key", "pin", "epoch", "entity", "sequence",
    "emission_id", "root_id", "previous_id", "seed", "endpoint_ordinal", "origin_count",
    "root_from", "root_count", "new_from", "new_count", "occurrence_total", "portion_total",
    "known_bad_password", "unknown_account", "other_failure", "distinct_names",
    "portion_index", "occurrence_from", "occurrences"))
_LOCAL = frozenset(("portion_index", "occurrence_from", "occurrences"))


def _reject():
    raise ValueError("password_v2_portion_invalid")


def _integer(value, minimum=0, maximum=None):
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        _reject()
    # An integer this large cannot fit the declared context byte limit.
    if value.bit_length() > 4 * MAX_CONTEXT_BYTES:
        _reject()
    return value


def _hex(value):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        _reject()
    return value


def _scope(scope):
    if type(scope) is not EvidenceScope:
        _reject()
    try:
        if EvidenceScope(**asdict(scope)) != scope:
            _reject()
    except EvidenceRefError:
        _reject()
    if (any(type(value) is not str for value in asdict(scope).values())
            or scope.plugin_id != "sli.windows.ad-dc" or scope.collection_scope_id):
        _reject()
    return scope


def _stamp(value):
    if type(value) is not str or not 25 <= len(value) <= 32:
        _reject()
    try:
        stamp = datetime.fromisoformat(value)
        if stamp.utcoffset() != timedelta(0) or stamp.isoformat() != value:
            _reject()
    except (ValueError, OverflowError):
        _reject()
    return stamp


def _row(scope, value):
    if type(value) is not list or len(value) != 5:
        _reject()
    native_id, digest, at, xml_bytes, xml_digest = value
    if type(native_id) is not str:
        _reject()
    _hex(digest)
    _hex(xml_digest)
    _integer(xml_bytes, 1)
    try:
        ref = EvidenceRef("core_event", native_id, digest, scope)
    except EvidenceRefError:
        _reject()
    return Witness(ref, _stamp(at), xml_digest, xml_bytes)


def _compact(scope, witness):
    if type(witness) is not Witness or type(witness.ref) is not EvidenceRef:
        _reject()
    if witness.ref.scope != scope or witness.ref.storage_kind != "core_event" or type(witness.at) is not datetime:
        _reject()
    row = [witness.ref.native_id, witness.ref.sha256, witness.at.isoformat(), witness.xml_bytes, witness.xml_sha256]
    if _row(scope, row) != witness:
        _reject()
    return row


def _size(context):
    try:
        size = len(json.dumps(context, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True, allow_nan=False).encode("utf-8"))
    except (ValueError, TypeError, OverflowError):
        _reject()
    if size > MAX_CONTEXT_BYTES:
        _reject()


def _shape(scope, context):
    """Validate a single bounded portion, including its full common header."""
    _scope(scope)
    if type(context) is not dict or context.keys() != _KEYS:
        _reject()
    if type(context["version"]) is not str or context["version"] != VERSION:
        _reject()
    for name in ("episode_key", "pin", "entity", "emission_id", "root_id"):
        _hex(context[name])
    _integer(context["epoch"])
    sequence = _integer(context["sequence"], 1)
    total = _integer(context["occurrence_total"], 1, MAX_ROWS)
    portions = _integer(context["portion_total"], 1, MAX_PORTIONS)
    index = _integer(context["portion_index"], 0, portions - 1)
    offset = _integer(context["occurrence_from"], 0, total - 1)
    for name in ("origin_count", "root_from", "root_count", "new_from", "new_count",
                 "known_bad_password", "unknown_account", "other_failure", "distinct_names"):
        _integer(context[name], 0, MAX_ROWS)
    _integer(context["endpoint_ordinal"], total - 1, total - 1)
    if portions != (total + 255) // 256 or offset != 256 * index:
        _reject()
    rows = context["occurrences"]
    if type(rows) is not list or len(rows) != min(256, total - offset):
        _reject()
    # Bound nested shape before JSON encoding or reconstruction of full proposals.
    seed = _row(scope, context["seed"])
    witnesses = tuple(_row(scope, row) for row in rows)
    origin, root_from, root_count = (context[name] for name in ("origin_count", "root_from", "root_count"))
    if sequence == 1:
        if (context["previous_id"] is not None or context["root_id"] != context["emission_id"]
                or not 1 <= root_count <= origin <= total or root_from + root_count != origin
                or context["new_from"] != origin or context["new_count"] != total - origin):
            _reject()
    else:
        _hex(context["previous_id"])
        if (origin or root_from or root_count or context["new_from"] != 1
                or context["new_count"] != total - 1 or total < 2):
            _reject()
    _size(context)
    return seed, witnesses


def _emission(emission):
    if (type(emission) is not Emission or type(emission.seed) is not Witness
            or type(emission.seed.ref) is not EvidenceRef):
        _reject()
    scope = _scope(emission.seed.ref.scope)
    for name in ("origin", "root_proof", "new_events"):
        if type(getattr(emission, name)) is not tuple or len(getattr(emission, name)) > MAX_ROWS:
            _reject()
    count = len(emission.new_events) + (1 if emission.predecessor is not None else len(emission.origin))
    if not 1 <= count <= MAX_ROWS:
        _reject()
    for name in ("episode_key", "pin", "entity"):
        _hex(getattr(emission, name))
    _integer(emission.epoch)
    _integer(emission.sequence, 1)
    for name in ("known_bad_password", "unknown_account", "other_failure", "distinct_names"):
        _integer(getattr(emission, name), 0, MAX_ROWS)
    if emission.previous_id is not None:
        _hex(emission.previous_id)
    occurrences = emission.occurrences
    if not 1 <= len(occurrences) <= MAX_ROWS or emission.portions > MAX_PORTIONS:
        _reject()
    _compact(scope, emission.seed)
    for witness in occurrences + emission.root_proof:
        _compact(scope, witness)
    # Adjacency is wire order, not proof of a continuously covered native stream.
    order = tuple((w.at, int(w.ref.native_id)) for w in occurrences)
    if any(left >= right for left, right in zip(order, order[1:])) or len({w.ref for w in occurrences}) != len(occurrences):
        _reject()
    if emission.sequence == 1:
        if (emission.predecessor is not None or not emission.origin or not emission.root_proof
                or emission.previous_id is not None or emission.seed != emission.origin[0]
                or emission.origin[-len(emission.root_proof):] != emission.root_proof):
            _reject()
    elif (emission.origin or emission.root_proof or type(emission.predecessor) is not Witness
          or not emission.new_events):
        _reject()
    return scope


def contexts_from_emission(emission: Emission, *, original_root_id: str | None = None) -> tuple[dict, ...]:
    """Encode the exact pure slices, rejecting the whole proposal on any bound."""
    scope = _emission(emission)
    emission_id = emission.emission_id
    if emission.sequence == 1:
        if original_root_id is not None and original_root_id != emission_id:
            _reject()
        root_id = emission_id
    else:
        root_id = _hex(original_root_id)
    origin_count = len(emission.origin)
    common = dict(version=VERSION, episode_key=emission.episode_key,
        pin=emission.pin, epoch=emission.epoch, entity=emission.entity, sequence=emission.sequence,
        emission_id=emission_id, root_id=root_id, previous_id=emission.previous_id,
        seed=_compact(scope, emission.seed), endpoint_ordinal=len(emission.occurrences) - 1,
        origin_count=origin_count, root_from=origin_count - len(emission.root_proof),
        root_count=len(emission.root_proof), new_from=origin_count if emission.sequence == 1 else 1,
        new_count=len(emission.new_events), occurrence_total=len(emission.occurrences), portion_total=emission.portions,
        known_bad_password=emission.known_bad_password, unknown_account=emission.unknown_account,
        other_failure=emission.other_failure, distinct_names=emission.distinct_names)
    contexts = tuple(dict(common, portion_index=index, occurrence_from=256 * index,
                          occurrences=[_compact(scope, w) for w in portion])
                     for index, portion in enumerate(emission.ref_portions))
    # Run the same complete validation on both directions; never return a prefix.
    if reassemble(scope, contexts) != emission:
        _reject()
    return contexts


def reassemble(scope: EvidenceScope, contexts: tuple[dict, ...]) -> Emission:
    """Reconstruct exactly one bounded Emission; input portion order is binding."""
    _scope(scope)
    if type(contexts) is not tuple or not 1 <= len(contexts) <= MAX_PORTIONS:
        _reject()
    header = None
    occurrences = []
    seed = None
    for index, context in enumerate(contexts):
        current_seed, witnesses = _shape(scope, context)
        common = {name: value for name, value in context.items() if name not in _LOCAL}
        if index == 0:
            header, seed = common, current_seed
            if context["portion_total"] != len(contexts):
                _reject()
        if common != header or context["portion_index"] != index:
            _reject()
        occurrences.extend(witnesses)
    if len(occurrences) != header["occurrence_total"]:
        _reject()
    origin = tuple(occurrences[:header["origin_count"]])
    emission = Emission(episode_key=header["episode_key"], pin=header["pin"], epoch=header["epoch"],
        entity=header["entity"], sequence=header["sequence"], seed=seed,
        root_proof=origin[header["root_from"]:header["origin_count"]],
        new_events=tuple(occurrences[header["new_from"]:]),
        predecessor=occurrences[0] if header["sequence"] > 1 else None, previous_id=header["previous_id"],
        known_bad_password=header["known_bad_password"], unknown_account=header["unknown_account"],
        other_failure=header["other_failure"], distinct_names=header["distinct_names"], origin=origin)
    _emission(emission)
    if emission.emission_id != header["emission_id"]:
        _reject()
    return emission


def match_qw_refs(scope: EvidenceScope, context: dict, refs: tuple[EvidenceRef, ...]) -> tuple[Witness, ...]:
    """Match exact QW SET/cardinality; return the manifest's witness order.

    The supplied scope must come from independently validated execution.scope.
    One portion does not prove original scope, emission hash, ancestry or admission.
    """
    _, witnesses = _shape(scope, context)
    if (type(refs) is not tuple or len(refs) != len(witnesses)
            or any(type(ref) is not EvidenceRef for ref in refs)
            or len(set(refs)) != len(refs) or set(refs) != {w.ref for w in witnesses}):
        _reject()
    return witnesses