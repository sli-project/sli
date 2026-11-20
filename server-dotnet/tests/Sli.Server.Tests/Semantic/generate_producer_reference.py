"""Execute the unchanged Python producer; no database or production data."""
import hashlib
import json
from pathlib import Path

from server.sli.semantic.semantic_producer import select_semantic_queue_candidates
from server.sli.semantic.semantic_processing_repository import _identity
from server.source_packs.windows_ad_dc import security_audit_outcome


def main():
    root = Path(__file__).resolve().parents[4]
    rows = []
    for catalog in ("event_catalog", "file_audit_event_catalog", "radius_event_catalog", "workstations_event_catalog"):
        for entry in json.loads((root / "config" / f"{catalog}.json").read_text(encoding="utf-8"))["entries"]:
            rows.append(dict(source_event_id=len(rows)+1, event_key=str(entry.get("event_key", entry.get("event_id"))),
                             stream=entry.get("stream", entry.get("channel")), provider_name=entry.get("provider_name", "")))
    cases = []
    def case(name, inputs, include_context=False, context_ids=()):
        selected, counters = select_semantic_queue_candidates(inputs, include_context=include_context, context_event_ids=context_ids)
        cases.append(dict(name=name, rows=inputs, include_context=include_context, context_ids=context_ids,
                          jobs=[dict(id=j.source_event_id, reason=j.selection_reason) for j in selected], counters=counters))
    case("all_catalogs", rows)
    case("facts_context", rows, True)
    case("explicit_context", rows, context_ids=[r["source_event_id"] for r in rows])
    case("normalized_identity", [dict(r, stream=" "+r["stream"].swapcase()+" ", provider_name=" "+r["provider_name"].swapcase()+" ") for r in rows])
    unknown = [dict(source_event_id=i+1, event_key="999999", stream="Security", provider_name="synthetic") for i in range(5000)]
    for size in (0, 1, 19, 20, 21, 640, 5000):
        case(f"unknown_{size}", unknown[:size])
    case("unknown_related", unknown[:21], context_ids=(2, 4))
    case("missing_provider", [dict(r, provider_name="") for r in rows[:25]])
    identities = [dict(id=i, kind=k, hash=_identity(source_event_id=i, job_kind=k, processor_id="semantic-shadow", processor_version="1.4+identity-1.0").hex())
                  for i in (1, 14174682, 2147483650) for k in ("normalize_event", "investigation_context")]
    output = dict(cases=cases, identities=identities,
                  outcomes=[dict(value=value, outcome=security_audit_outcome(value)) for value in
                            (None, "", "Audit Success", "Audit Failure", "0x8020000000000001", "0x8030000000000000",
                             "0x0020000000000001", "9007199254740993", "-9214364837600034815", "0b10_000000000000000000000000000000000000000000000000000000",
                             "00", "09007199254740993", "0x_20_0000_0000_0001", "0o400000000000000001")],
                  source_sha256=hashlib.sha256((root / "server/sli/semantic/semantic_producer.py").read_bytes()).hexdigest())
    Path(__file__).with_name("producer-reference.json").write_text(json.dumps(output, ensure_ascii=True, separators=(",", ":"))+"\n", encoding="utf-8")
    print(f"Python producer: {len(cases)} cases; {sum(len(c['rows']) for c in cases)} rows; {len(identities)} identities")


if __name__ == "__main__":
    main()
